/*
 *  enumIAX
 *  Dustin D. Trammell
 *  <dtrammell@tippingpoint.com>
 *
 *  This tool will brute-force enumerate an IAX2 server's valid registration usernames
 *
 */

#include <errno.h>
#include <libgen.h>
#include <locale.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "enumiax.h"
#include "charmap.h"


#define BUFFSIZE 276

int verbosity;
FILE *file;
char username[256];
char passphrase[256];
short min_user_len, max_user_len;
char *target;
char *dict = NULL;
time_t start, finish, statetime;
int lower, upper;

struct iax2_header {
	unsigned int src_call : 15;
	unsigned int packet_type : 1;
	unsigned int dst_call : 15;
	unsigned int retransmission : 1;
	unsigned int timestamp;
	unsigned char outseq;
	unsigned char inseq;
	unsigned char type;
	unsigned char subclass;
};


int main( int argc, char *argv[] ) {
	FILE *f1;
	int seconds, minutes, hours, days, weeks, years;
	int loop_count, save_interval;
	int lkeys;
	int sock;
	int datalen;
	int retry;
	char ch;
	char *prog;
	char *statefile = NULL;
	char *resultfile = NULL;
	char *buff;
	unsigned char *iax2_send;
	unsigned char *iax2_recv;
	struct protoent *proto;
	struct iax2_header *iax2hdr_send, *iax2hdr_recv;
	unsigned short scall;
	unsigned long ratelimit = 500000;

	/* Signals */
	signal( SIGINT, state_exit );
	signal( SIGQUIT, state_exit );
	signal( SIGABRT, state_exit );
	signal( SIGTERM, state_exit );

	/* Defaults */
	verbosity = 0;
	lkeys = 0;
	prog = basename( argv[0] );
	target = NULL;
	start = finish = statetime = 0;
	seconds = minutes = hours = days = weeks = years = 0;
	loop_count = 0;
	save_interval = 50;
	memset( username, '\0', sizeof(username) );
	memset( passphrase, '\0', sizeof(passphrase) );
	min_user_len = MIN_USER_LEN;
	max_user_len = MAX_USER_LEN;
	buff = malloc(BUFFSIZE);
	memset( buff, 0, BUFFSIZE );
	lower = 0;
	upper = strlen(charmap) - 1;


	while( (ch = getopt(argc, argv, "+d:i:m:M:r:s:vVh")) != EOF ) {
		switch( ch ) {
			case 'd':
				dict = optarg;
				break;
			case 'i':
				save_interval = atoi(optarg);
				break;
			case 'm':
				min_user_len = atoi(optarg);
				break;
			case 'M':
				max_user_len = atoi(optarg);
				break;
			case 'r':
				ratelimit = atoi(optarg);
				break;
			case 's':
				statefile = optarg;
				break;
			case 'v':
				verbosity++;
				break;
			case 'V':
				version();
				exit(0);
			case 'h':
			default:
				usage( prog );
		}
	}
	/* not enough arguments */
	if( argv[optind] ) target = argv[optind];
	else usage( prog );

	/* too many arguments */
	if( argv[optind+1] ) usage( prog );

	version();
	srand(time(NULL));

	if( statefile ) {
		if( !(f1 = fopen( statefile, "r" )) ) {
			fprintf( stderr, "Unable to open statefile %s for reading... exiting.\n", statefile );
			exit(1);
		}
		if( !(fgets( buff, BUFFSIZE, f1 )) ) {
			fprintf( stderr, "Unable to read from open statefile %s... exiting.\n", statefile ); 
			exit(1);
		}
		if( strcmp( strsep( &buff, ":" ), target ) != 0 ) {
			fprintf( stderr, "State found in statefile %s does not match target of %s... exiting.\n", statefile, target );
			exit(1);
		}
		statetime = (time_t) atoi( strsep( &buff, ":" ) );
		snprintf( username, sizeof(username), "%s", strsep( &buff, "\n" ) );
	}

	if(verbosity) printf( "Target Aquired: %s\n", target );
	if(verbosity>=2) printf( "Save Interval: %d attempts\n", save_interval );
	if(verbosity>=2) printf( "Using Charmap (%d characters):\n  \"%s\"\n", strlen(charmap) - 1, charmap );

	/* Build result filename */
	resultfile = malloc(strlen(target)+8);
	snprintf( resultfile, (strlen(target)+8), "%s.result", target );

	/* Determine whether we're generating passphrases or using a dict file */
	if( dict ) {
		if( (file = fopen( dict, "r" )) == NULL ) {
			fprintf( stderr, "Error: Could not open dict file %s\n", dict );
			exit(-1);
		}
		if( statefile ) {
			/* Wind forward file pointer to current username in dict file */
			do {
				if( ! fgets( buff, BUFFSIZE, file ) ) {
					fprintf( stderr, "Error: State Mismatch:\n  Dict file (%s) did not contain word (%s) found in state file (%s), exiting.\n", dict, username, statefile );
					exit(-1);
				}
				buff[strlen(buff)-1] = '\0';
			} while( strcmp( buff, username ) != 0 );
		}
	}

	/* Build IAX2 REGREQ payloads (sans username) */
	iax2_send = malloc(256);
	iax2hdr_send = (struct iax2_header *)iax2_send;
	iax2_recv = malloc(256);
	iax2hdr_recv = (struct iax2_header *)iax2_recv;
	const char iax2userhdr[] = "\x06\x00";
	const char iax2trailer[] = "\x13\x02\x07\x08";

	/* Resolve target and set up UDP socket */
	if( !(proto = getprotobyname( "UDP" )) ) {
		fprintf( stderr, "Error: Protocol \"%s\" not recognized.\n", "UDP" );
		exit(-1);
	}
	if( (sock = socket_build( target, proto->p_proto, 4569 )) == -1 ) exit(-1);

	/* Start enum routine */
	start = time(NULL);
	if(verbosity) printf( "Starting enum process at: %s", ctime(&start) );

	/* Initialize username */
	if( dict ) nextdict();
	else nextword();

	while(1) {
		/* Update IAX2 REGREQ payload with current username */
		iax2hdr_send->packet_type = 1;
		scall = (rand()%32766)+1;
		iax2hdr_send->src_call = scall;
		iax2hdr_send->retransmission = 0;
		iax2hdr_send->dst_call = 0;
		ch = iax2_send[0]; iax2_send[0] = iax2_send[1]; iax2_send[1] = ch;
		ch = iax2_send[2]; iax2_send[2] = iax2_send[3]; iax2_send[3] = ch;
		iax2hdr_send->timestamp = time(NULL);
		iax2hdr_send->outseq = 0;
		iax2hdr_send->inseq = 0;
		iax2hdr_send->type = 6;
		iax2hdr_send->subclass = 13;

		memcpy( iax2_send+12, iax2userhdr, 2 );
		iax2_send[13] = strlen(username); /* Size of Username to try */
		memcpy( iax2_send+14, username, strlen(username) ); /* Username to try */
		memcpy( iax2_send+(14+strlen(username)), iax2trailer, 4 );
		datalen = 12 + 2 + strlen(username) + 4;

		/* Send payload to IAX server */
		if(verbosity>=2) printf( "\nSending %d byte REGREQ message:\n", datalen );
		if(verbosity>=3) printhex( iax2_send, datalen );
		retry = 0;
		while( (write( sock, iax2_send, datalen )) == -1 ) {
			fprintf( stderr, "write: %s\n", strerror(errno) );
			fprintf( stderr, "Sleeping 1 sec before retry...\n" );
			sleep(1);
			if( retry++ >= 3 ) {
				fprintf( stderr, "Retries exhausted, exiting.\n" );
				exit(-1);
			}
		}
		if(verbosity>=3) printf( "Send succeeded.\n" );

		/* Read response */
		readresponse:
		datalen = read( sock, iax2_recv, 256 );
		if( datalen == -1 ) {
			fprintf( stderr, "read: %s\n", strerror(errno) );
			exit(-1);
		}
		if(verbosity>=2) printf( "%d byte response received: (IAX2 type %d)\n", datalen, iax2_recv[11] );
		if(verbosity>=3) printhex( iax2_recv, datalen );

		/* Swap byte order for first four bytes */
		ch = iax2_recv[0]; iax2_recv[0] = iax2_recv[1]; iax2_recv[1] = ch;
		ch = iax2_recv[2]; iax2_recv[2] = iax2_recv[3]; iax2_recv[3] = ch;

		/* Verify IAX2 packet */
		if( iax2_recv[10] != 6 ) fprintf( stderr, "Error: Received packet is not IAX2!\n" );

		/* Send ACK for specific response types */
		if( iax2_recv[11] == 14 || iax2_recv[11] == 15 || iax2_recv[11] == 16 ) { /* REGAUTH || REGACK || REGREJ */
			iax2hdr_send->packet_type = 1;
			iax2hdr_send->src_call = iax2hdr_recv->dst_call;
			iax2hdr_send->retransmission = 0;
			iax2hdr_send->dst_call = iax2hdr_recv->src_call;
			ch = iax2_send[0]; iax2_send[0] = iax2_send[1]; iax2_send[1] = ch;
			ch = iax2_send[2]; iax2_send[2] = iax2_send[3]; iax2_send[3] = ch;
			iax2hdr_send->timestamp = time(NULL);
			iax2hdr_send->inseq = 1;
			iax2hdr_send->outseq = 1;
			iax2hdr_send->type = 6;
			iax2hdr_send->subclass = 4;
			datalen = sizeof(iax2hdr_send);
	
			if(verbosity>=2) printf( "Sending %d byte ACK message:\n", datalen );
			if(verbosity>=3) printhex( iax2_send, datalen );
			retry = 0;
			while( (write( sock, iax2_send, 12 )) == -1 ) {
				fprintf( stderr, "write: %s\n", strerror(errno) );
				fprintf( stderr, "Sleeping 1 sec before retry...\n" );
				sleep(1);
				if( retry++ >= 3 ) {
					fprintf( stderr, "Retries exhausted, exiting.\n" );
					exit(-1);
				}
			}
			if(verbosity>=3) printf( "Send succeeded.\n" );
		}

		/* Check for Lag Request (LAGRQ) */
		if( iax2_recv[11] == 11 ) {
			if(verbosity>=3) printf( "Received Lag Request (LAGRQ) from target, throttling...\n" );
			ratelimit += 100000;
		}

		/* Verify packet received is for current call */
		if( (unsigned short)iax2hdr_recv->dst_call != scall ) {
			if(verbosity>=3) printf( "Packet received (call %d) is not from current call (call %d).\n  Waiting for subsequent response...\n", iax2hdr_recv->dst_call, scall );
			goto readresponse;
		}

		/* Check Response IE type */
		if( iax2_recv[11] == 4 ) {
			if(verbosity>=3) printf( "Packet received is IAX2 ACK.  Waiting for subsequent response...\n" );
			goto readresponse;
		}

		/* SUCCESS */
		if( iax2_recv[11] == 14 || iax2_recv[11] == 15 ) { /* REGAUTH || REGACK */
			finish = time(NULL);
			if( iax2_recv[11] == 14 ) printf( "  !!! Found valid username (%s) at: %s\n", username, ctime(&finish) );
			if( iax2_recv[11] == 15 ) printf( "  !!! Found valid UNAUTHENTICATED username (%s) at: %s\n", username, ctime(&finish) );
			seconds = (int)(finish - start);
			if( seconds > 60 ) {
				minutes = seconds / 60;
				seconds = seconds % 60;
			}
			if( minutes > 60 ) {
				hours = minutes / 60;
				minutes = minutes % 60;
			}
			if( hours > 24 ) {
				days = hours / 24;
				hours = hours % 24;
			}
			if( days > 7 ) {
				weeks = days / 7;
				days = days % 7;
			}
			if( weeks > 52 ) {
				years = weeks / 52;
				weeks = weeks % 52;
			}
			if(verbosity) {
				printf( "Total time to find:" ); 
				if( years ) printf( " %d years", years );
				if( weeks ) printf( " %d weeks", weeks);
				if( days ) printf( " %d days", days );
				if( hours ) printf( " %d hours", hours );
				if( minutes ) printf( " %d minutes", minutes );
				printf( " %d seconds\n", seconds );
			}
			/* write valid out to file */
			f1 = fopen( resultfile, "a" );
			if( iax2_recv[11] == 14 ) fprintf( f1, "username: %s\n", username );
			if( iax2_recv[11] == 15 ) fprintf( f1, "unauthenticated username: %s\n", username );
			fclose(f1);
		} else {
			/* ERROR */
			if(verbosity>=2) printf( "IAX2 packet (Subclass %d) was not REGAUTH or REGACK, invalid username.\n", iax2_recv[11] );
		}

		/* FAILURE */
		loop_count++;
		if( loop_count >= save_interval) {
			save_state(0);
			loop_count = 0;
		}

		/* Rate Limiting */
		if( ratelimit ) {
			if(verbosity>=2) fprintf( stderr, "Rate-Limiting: Sleeping for %ld microseconds.\n", ratelimit );
			usleep(ratelimit);
			if( ratelimit >= 1000 ) ratelimit = ratelimit - 1000;
		}

		/* increment username */
		if( dict ) nextdict();
		else nextword();

	}

	/* Cleanup */
	if(dict) fclose(file);
	exit(-1);
}
