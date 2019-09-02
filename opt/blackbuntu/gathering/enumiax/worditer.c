/*
 * passcb.c - GPGuess Passphrase Callback Functions
 *
 * These functions provide usernames for the GPGME crypto
 * operations.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "enumiax.h"
#include "charmap.h"


int nextword() {
	int x = 0, y = 0;
	extern int lower, upper;
	extern int verbosity;
	extern int min_user_len, max_user_len;
	extern char username[256];

	/* If username doesn't exist, build start username */
	if( ! username[0] ) {
		/* enforce minimum username length requirement */
		for( x = 0; x < min_user_len; x++ ) username[x] = charmap[lower];
		if(verbosity) printf( "Now working on %d character usernames...\n", min_user_len );
		goto ret;
	}

	/* Determine username's current length and set current char index at last char */
	y = x = strlen(username) - 1;

	for( ; x >= 0; x-- ) {
		if( username[x] != charmap[upper] ) { /* Has current char hit upper bound? */
			/* If not, iterate current char to next char in charmap and break */
			username[x] = charmap[charmap_c_to_d(username[x]) + 1];
			break;
		} else {
			/* If so, reset current char to lower bound */
			username[x] = charmap[lower];
			/* Check to see if we're resetting the first char in username */
			if( x == 0 ) {
				/* If so, check to see if adding another char would exceed max_user_length */
				if( y+1 == max_user_len ) { 
					printf( "Username combinations exausted, exiting...\n" );
					exit(-1);
				}
				/* Add another char to the username length */
				y++;
				username[y] = charmap[lower];
				if(verbosity) printf( "Now working on %d character usernames...\n", y+1 );
			}
		}
	}

	ret:
	if(verbosity) printf( "\n#################################\n" );
	if(verbosity>=1) printf( "Trying username: \"%s\"\n", username );
	return 0;
}

int nextdict() {
	extern int verbosity;
	extern FILE *file;
	extern char username[256];

	if( !(fgets( username, sizeof(username), file )) ) {
		if(verbosity) printf( "End of dictionary file reached, exiting.\n" );
		exit(0);
	}
	username[strlen(username)-1] = '\0';

	if(verbosity) printf( "\n#################################\n" );
	if(verbosity>=1) printf( "Trying username: \"%s\"\n", username );
	return 0;
}

