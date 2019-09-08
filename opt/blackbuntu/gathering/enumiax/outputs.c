#include <stdio.h>


void printbin( int buf, int bits ) {
	for( ; bits>0 ; bits-- ) {
		if( buf & 1 )
			printf( "1" );
		else
			printf( "0" );
	buf>>=1;
	}
}

void printhex( unsigned char *buf, int size ) {
	int x;
	for( x=0; x<size; x++ ) {
		if( x % 8 == 0 ) printf( " " );
		if( x % 16 == 0 ) printf( "\n%04x  ", x );
		printf( "%02x ", buf[x] );
	}
	printf( "\n\n" );
}

