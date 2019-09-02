#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "enumiax.h"
#include "charmap.h"


int charmap_c_to_d( char ch ) {
	int d;

	for( d = 0; charmap[d] != '\0'; d++ )
		if( charmap[d] == ch ) break;

	return d;
}

