/*
   SIDGuesser
   Copyright (c) 2006- Patrik Karlsson

   http://www.cqure.net

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

static FILE *pLog = NULL;

int logprintf( const char *format, ... ) {
	
	va_list args;
	int i;
	
	va_start( args, format );
	
	if ( pLog ) {
		i = vfprintf( pLog, format, args );
		vprintf( format, args );
	}
	else {
		i = vprintf( format, args );
	}
	
	va_end( args );
	
	return i;
}

int openlogfile( char *pFile ) {
	if ( pLog = fopen( pFile, "w+" ) )
		return 0;
	
	return -1;
}

void closelogfile() {
	if ( pLog )
		fclose( pLog );
}
