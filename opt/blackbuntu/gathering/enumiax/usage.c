#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "enumiax.h"


void version() {
	fprintf( stderr, "enumIAX %s\n", VERSION );
	fprintf( stderr, "Dustin D. Trammell <dtrammell@tippingpoint.com>\n\n" );
}

void usage( char *prog ) {
	version();
	fprintf( stderr, "Usage: %s [options] target\n", prog );
	fprintf( stderr, "  options:\n" );
	fprintf( stderr, "    -d <dict>   Dictionary attack using <dict> file\n" );
	fprintf( stderr, "    -i <count>  Interval for auto-save (# of operations, default 1000)\n" );
	fprintf( stderr, "    -m #        Minimum username length (in characters)\n" );
	fprintf( stderr, "    -M #        Maximum username length (in characters)\n" );
	fprintf( stderr, "    -r #        Rate-limit calls (in microseconds)\n" );
	fprintf( stderr, "    -s <file>   Read session state from state file\n" );
	fprintf( stderr, "    -v          Increase verbosity (repeat for additional verbosity)\n" );
	fprintf( stderr, "    -V          Print version information and exit\n" );
	fprintf( stderr, "    -h          Print help/usage information and exit\n" );
	exit(-1);
}

