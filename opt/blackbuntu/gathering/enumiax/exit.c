#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "enumiax.h"
#include "charmap.h"


void state_exit( int signum ) {
	extern int verbosity;

	/* For platforms that reset to SIG_DFL upon signal trap */
	signal( signum, state_exit );

	/* Save the state */
	fprintf( stderr, "Caught signal %d, saving state...\n", signum );
	verbosity++;
	save_state( signum );

	exit(0);
}

int save_state( int signum ) {
	FILE *f1;
	int x = 0;
	char filename[64];
	extern int verbosity;
	extern char username[256];	
	extern char *target;
	extern char *dict;
	extern time_t start, statetime;
	time_t now;

	now = time(NULL);

	if( signum && ! dict ) {
		/* If called from a sigtrap, and not dictionary mode, step username back one just in case the current one has not been tested yet */
		x = strlen(username) -1;
		username[x] = charmap[charmap_c_to_d(username[x]) - 1];
	}

	/* Create filename and open file */
	snprintf( filename, sizeof(filename), "%s.state", target );
	if( !(f1 = fopen( filename, "w" )) ) {
		fprintf( stderr, "Error opening file %s to save state, manually save the following state line:\n", filename );
		fprintf( stderr, "%s:%ld:%s\n", target, ((long)(now - start)) + statetime, username );
		exit(0);
	}
	/* Write to file and close */
	fprintf( f1, "%s:%ld:%s\n", target, ((long)(now - start)) + statetime, username );
	fclose(f1);

	if(verbosity) printf( "State (%s) saved in %s at: %s", username, filename, ctime(&now) );
	return(0);
}
