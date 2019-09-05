#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#endif

#include "tns.h"
#include "log.h"
#include "getopt.h"
#include "SIDGuesser.h"

#ifdef WIN32
#pragma comment(lib, "ws2_32.lib")
#endif
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

#ifndef WIN32

#include <termio.h>
#include <termios.h>

struct termios stored_settings;
/*
 * void set_keypress(void)
 * 
 * Terminal magic. Removes the need for <enter> when getchar is called
 * like getch() in Windows
 */
void set_keypress(void) {

     struct termios new_settings;
     tcgetattr(0,&stored_settings);
     new_settings = stored_settings;
     new_settings.c_lflag &= (~ICANON);
     new_settings.c_lflag &= (~ECHO);
     new_settings.c_cc[VTIME] = 0;
     tcgetattr(0,&stored_settings);
     new_settings.c_cc[VMIN] = 1;
     tcsetattr(0,TCSANOW,&new_settings);

}

/*
 * void reset_keypress(void)
 *
 * Resets the terminal back to stored_settings
 */
void reset_keypress(void) {
     tcsetattr(0,TCSANOW,&stored_settings);
}
#endif

int CreateTNSHeader( byte *pHdr, int *nSize, int nLen ) {

	struct tTNS_Header tnsh;
	
	if ( *nSize < sizeof( tnsh ) )
		return -1;

	*nSize = sizeof( tnsh );

	tnsh.nPacketLen = htons( (short)(nLen + sizeof( tnsh )) );
	tnsh.nPacketCSum = 0;
	tnsh.nPacketType = 1; /* CONNECT */
	tnsh.nReserved = 0;
	tnsh.nHeaderCSum = 0;
	tnsh.nVersion = htons(0x0134);
	tnsh.nVCompat = htons(0x012c);
	tnsh.nSOptions= htons(0x0000);
	tnsh.nUnitSize= htons(0x0800);
	tnsh.nMaxUSize= htons(0x7fff);
	tnsh.nProtoC = htons(0x4f98);
	tnsh.nLineTV = htons(0x0000);
	tnsh.nValOf1 = htons(0x0001);
	tnsh.nLenOfCD= htons(nLen);/* Length of connect data */
	tnsh.nOffCD  = htons( sizeof( tnsh ) );/* offset of connect data */
	tnsh.nMaxRecvData = 0;
	tnsh.bFlags0 = 0x01;
	tnsh.bFlags1 = 0x01;

	memcpy( pHdr, (byte *)&tnsh, sizeof( tnsh ) );

	return *nSize;
}

#ifdef WIN32
SOCKET ConnectSocket( char *pIP, int nPort ) {
	SOCKET s;
#else
int ConnectSocket( char *pIP, int nPort ) {
	int s;
#endif

	struct sockaddr_in sin;

	s = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr( pIP );
	sin.sin_port = htons( nPort );

	if ( SOCKET_ERROR == connect( s, ( const struct sockaddr * )&sin, sizeof( sin )) )
		return -1;
	
	return s;
}

void chomp( char *pStr ) {

	int n = (int)strlen( pStr ) - 1;

	while ( n>0 ) {
		if ( pStr[n] == '\n' || pStr[n] == '\r' )
			pStr[n] = 0;

		n--;
	}
}

#ifdef WIN32
DWORD WINAPI ShowStats( LPVOID lpParam ) {
#else
void *ShowStats( void *pArg ) {
#endif

	char ch;
	double nDeltaTM, nTPS;

	int nMinutes, nHours, nSeconds = 0;

#ifdef WIN32
	m_nStartTM = clock();
#else
	m_nStartTM = time(NULL);
#endif

	while( 1 && !m_bQuit ) {

		ch = getkey();

		if ( ' ' == ch ) {
#ifdef WIN32
			nDeltaTM = ( clock() - m_nStartTM ) / CLOCKS_PER_SEC;
#else
			nDeltaTM = ( time(NULL) - m_nStartTM );
#endif
			nTPS	 = m_nTries/nDeltaTM;

			nHours   = (int) ( nDeltaTM / 3600 );
			nMinutes = (int) ((nDeltaTM - ( nHours * 3600 )) / 60);
			nSeconds = (int) nDeltaTM - ( nHours * 3600 ) - nMinutes * 60;

			fprintf(stderr, "TME: %.2d:%.2d:%.2d ", 
						nHours, nMinutes, nSeconds);
			fprintf( stdout, "TPS: %.0f DONE: %.0f%% CUR: %s \n", nTPS, 
					m_nTries/m_nDicItems * 100, m_sCurrSID );
		}
		else if ( 'q' == ch ) {
			fprintf( stdout, "\nAbort? (Y/N)");
			ch = getkey();

			if ( 'y' == ch )
				m_bQuit = 1;
			else
				fprintf( stdout, "\ncontinuing ...\n");
		}
	}


	return 0;
}

int GuessSID(FILE *pDIC, char *pIP, int nPort ) {

	char hdr[34], pConnStr[1024], buf[1024];
	int nHdrSize, nRecv, nCStrLen;
#ifdef WIN32
	SOCKET s;
#else
	int s;
#endif
	char *pFmtStr = "(DESCRIPTION=(CONNECT_DATA=(SID=%s)" 
						"(CID=(PROGRAM=)(HOST=__jdbc__)(USER=)))"
						"(ADDRESS=(PROTOCOL=tcp)(HOST=%s)"
						"(PORT=%d)))";

	fprintf( stdout, "\nStarting Dictionary Attack (<space> for stats, Q for quit) ...\n\n" );

	while ( fgets( m_sCurrSID, sizeof( m_sCurrSID ) - 1, pDIC )  && !m_bQuit ) {

		chomp( m_sCurrSID );

		if ( m_bVerbose )
			fprintf(stderr,  "Trying: %s\n", m_sCurrSID );

		if ( SOCKET_ERROR == ( s = ConnectSocket( pIP, nPort ) ) ) {
			fprintf( stderr, "ERR: FAILED TO CONNECT SOCKET IP: %s, PORT: %d\n", pIP, nPort );
			continue;
		}

		nCStrLen = snprintf( pConnStr, sizeof( pConnStr ) - 1, pFmtStr, m_sCurrSID, pIP, nPort );
		
		if ( nCStrLen >= sizeof( pConnStr ) ) {
			logprintf("ERR: CONNECTION STRING BUFFER TO SMALL\n");
			continue;
		}
		
		nHdrSize = sizeof( hdr );
		CreateTNSHeader( (byte *)hdr, &nHdrSize, nCStrLen );
		
		if ( ( nHdrSize + nCStrLen ) > sizeof( buf ) ) {
			logprintf("ERR: BUFFER TO SMALL SID: %s\n", m_sCurrSID );
			continue;
		}

		memcpy(buf, hdr, nHdrSize );
		memcpy(buf + nHdrSize, pConnStr, nCStrLen );

		send( s, buf, (nCStrLen + nHdrSize), 0 );
		memset( buf, 0, (int)sizeof( buf ) );
		nRecv = recv( s, buf, (int)sizeof( buf ), 0 );

		if ( TNS_REDIRECT == buf[PACKET_TYPE_OFFSET] || 0 == buf[PACKET_TYPE_OFFSET] ||
			 TNS_RESEND == buf[PACKET_TYPE_OFFSET] ) {
			logprintf( "FOUND SID: %s\n", m_sCurrSID );

			if ( MODE_FIND_ALL == m_nMode )
				continue;
			else
				return(0);
		}

#ifdef WIN32
		closesocket( s );
#else
		close( s );
#endif

		m_nTries ++;
	}

	return 0;
}

void banner() {

	int i, nLen = 1;

	printf("\n");
	nLen = logprintf( "SIDGuesser %s by %s\n", VERSION, AUTHOR );
	for ( i = 0; i<nLen-1; i++ )
		logprintf("-");
	logprintf("\n");
}

void usage( char *pPrg ) {

	banner();
	printf( "%s -i <ip> -d <dictionary> [options]\n", pPrg );
	printf( "\noptions:\n");
	printf( "    -p <portnr> Use specific port (default 1521)\n");
	printf( "    -r <report> Report to file\n");
	printf( "    -m <mode>   findfirst OR findall(default)\n");
}

FILE *OpenDictionary( char *pFile ) {

	FILE *pF;
	char row[1024];

	if ( pF = fopen( pFile, "r" ) ) {

		while ( fgets( row, sizeof( row ), pF ) )
			m_nDicItems ++;

		rewind( pF );
	}
	else
		return NULL;

	return pF;

}

int main( int argc, char **argv ) {

	FILE *pF = NULL;
	char ip[16];
	int nPort = 1521, c=-1;

#ifdef WIN32
	WSADATA wsa;
	DWORD dwTID;

	WSAStartup( MAKEWORD(2,0), &wsa );
#else
	pthread_t th;
	pthread_attr_t attr;
#endif

	memset( ip, 0, sizeof( ip ) );
	m_nMode = MODE_FIND_ALL;

	while( TRUE ) {
	
		c = getopt( argc, argv, "d:i:p:vr:m:" );

		if ( -1 == c ) {
			break;
		}

		switch(c) {
			
			case 'd':
				if ( NULL == ( pF = OpenDictionary( optarg ) ) ) {
					fprintf( stderr, "ERR: Failed to open dictionary file\n");
					return -1;
				}
				break;
			case 'i':
				strncpy( ip, optarg, sizeof( ip ) );
				break;
			case 'p':
				nPort = atoi( optarg );
				break;
			case 'v':
				m_bVerbose++;
				break;
			case 'r':
				openlogfile( optarg );
				break;
			case 'm':
				if ( 0 == stricmp( "findfirst", optarg ) )
					m_nMode = MODE_FIND_FIRST;
				break;
			default:
				usage(argv[0]);
				exit(1);
		}

	}

	
	if ( NULL == pF || 0 == strlen( ip ) || -1 == nPort ) {
		usage( argv[0] );
		exit( 1 );
	}

#ifdef WIN32
	CreateThread( NULL, 0, ShowStats, NULL, 0, &dwTID );
#else
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    set_keypress();
	pthread_create( &th, &attr, ShowStats, NULL );
#endif

	banner();
	GuessSID( pF, ip, nPort );
	fclose( pF );
	closelogfile();

#ifdef WIN32
	WSACleanup();
#else
	reset_keypress();
#endif

}
