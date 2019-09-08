#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "enumiax.h"


int socket_build( char *target, int protocol, int port ) {
	extern int verbosity;
	struct protoent *proto;
	int sock;
	int type;

	/* Resolve target */
	struct in_addr address;
	address.s_addr = inet_hton(target);

	/* Create socket based on selected transport */
	proto = getprotobynumber(protocol);
	if(verbosity) printf( "Connecting to %s via %s on port %d...\n", inet_ntoa(address), proto->p_name, port ); 
	type = SOCK_STREAM;
	if( protocol == 6 ) type = SOCK_STREAM;
	if( protocol == 17 ) type = SOCK_DGRAM;
	if( (sock = socket( PF_INET, type, protocol )) == -1 ) {
		fprintf( stderr, "socket: %s\n", strerror(errno) );
		return -1;
	}

	/* Connect the socket */
	struct sockaddr_in addr;
	addr.sin_family = PF_INET;
	addr.sin_addr.s_addr = address.s_addr;
	addr.sin_port = htons(port);
	if( (connect( sock, (struct sockaddr *)&addr, sizeof(addr) )) == -1 ) {
		fprintf( stderr, "connect: %s\n", strerror(errno) );
		return -1;
	}

	if(verbosity>=2) fprintf( stderr, "Connected to: %s\n", inet_ntoa(address));

	return sock;
}
