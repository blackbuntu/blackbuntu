/*
    This file is part of AirSnort.

    AirSnort is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    AirSnort is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with AirSnort; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    By Snax <snax@shmoo.com>
    Copyright (c) 2002 Snax
   
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>

#include <pcap.h>
#include "RC4.h"
#include "crc-32.h"

#define IV 24
#define FCS 120
#define DATALEN 92
#define PKTLEN 124

int xtoint(char xdigit);
int eatHexByte(char *x);
int eatHexString(char *dst, char *src, int maxlen);
void usage(char *cmd);

unsigned char echoRequest[] = {
   0x08, 0x02, 0x02, 0x01, 0x00, 0x02, 0x2d, 0x01, 0x23, 0x45, 0x00, 0x02, 0x2d, 0x98, 0x76, 0x54, 
   0x00, 0x04, 0x5a, 0xab, 0xcd, 0xef, 0xb0, 0xf8, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xaa, 0x03, 0x00,
   0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x54, 0x32, 0x6f, 0x00, 0x00, 0x40, 0x01, 0xc6, 0xdd,
   0xc0, 0xa8, 0x00, 0x02, 0xc0, 0xa8, 0x00, 0x0a, 0x08, 0x00, 0x5f, 0x36, 0x46, 0x13, 0xcd, 0x06,
   0x02, 0x28, 0x53, 0x3c, 0x38, 0x48, 0x0d, 0x00, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
   0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0xff, 0xff, 0xff, 0xff
};

//----------------------------------------------------------------
unsigned char echoReply[] = {
   0x08, 0x01, 0x02, 0x01, 0x00, 0x02, 0x2d, 0x98, 0x76, 0x54, 0x00, 0x02, 0x2d, 0x01, 0x23, 0x45, 
   0x00, 0x04, 0x5a, 0xab, 0xcd, 0xef, 0x80, 0x9f, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xaa, 0x03, 0x00, 
   0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x54, 0x1b, 0x04, 0x00, 0x00, 0x80, 0x01, 0x9e, 0x48,
   0xc0, 0xa8, 0x00, 0x0a, 0xc0, 0xa8, 0x00, 0x02, 0x00, 0x00, 0x67, 0x36, 0x46, 0x13, 0xcd, 0x06,
   0x02, 0x28, 0x53, 0x3c, 0x38, 0x48, 0x0d, 0x00, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
   0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0xff, 0xff, 0xff, 0xff
};

unsigned char *pkts[] = {echoRequest, echoReply};

int xtoint(char xdigit) {
   if (isxdigit(xdigit)) {
      if (xdigit <= '9') {
         return xdigit - '0';
      }
      return toupper(xdigit) - 'A' + 10;
   }
   return -1;
}

int eatHexByte(char *x) {
  int d1, d2;
  if ((d1 = xtoint(x[0])) >= 0) { 
     if ((d2 = xtoint(x[1])) >= 0) { 
        return d1 * 16 + d2;
     }
  }
  return -1;
}

int eatHexString(char *dst, char *src, int maxlen) {
  int l = 0;
  int r;
  while (l < maxlen) {
    r = eatHexByte(src);
    if (r < 0) return(-1);
    dst[l++] = r;
    src += 2;
    if (*src == 0) return(l);
    if (*src == ':') src++;
    else return (-1);
  }
  return(-1);
}

void usage(char *cmd) {
    fprintf(stderr, 
        "Usage: %s (-s <pw> | -h <pw>) [-n <numcases>] -f <outputfile>\n", cmd);
    exit(1);
}

int main(int argc,char *argv[]) {
   int r, plen, numcases = 100;
   unsigned char password[16];
   unsigned char packet[128];
   unsigned char *from;
   pcap_t *p;
   pcap_dumper_t *dump;
   char *casefile = NULL;
   RC4 rc;
   struct pcap_pkthdr pkt;
   int havePW = 0, haveFile = 0;
   struct timezone tz;
   int count = 0;
   int i, j, k;

   setupIdentity();
   plen = 13;
   memset(password, 0, 16);

   while (1) {
      r = getopt(argc,argv,"s:h:n:f:");
      if (r < 0) break;
      switch (r) {
      case 's':
         if (strlen(optarg) == 13) {
            memcpy(password + 3, optarg, 13);
         } else if (strlen(optarg) == 5) {
	    memcpy(password + 3, optarg, 5);
	    plen = 5;
         } else {
	    fprintf(stderr,
		"Invalid password length: must be 5 or 13 characters\n");
            exit(1);
         }
         havePW = 1;
         break;
      case 'h':
         r = eatHexString((char *) password + 3, optarg, 13);
         if (r != 13 && r != 5) {
	   fprintf(stderr, "Invalid password\n");
           exit(1);
         }
         plen = r;
         havePW = 1;
         break;
      case 'n':
         numcases = atoi(optarg);
         break;
      case 'f':
         casefile = optarg;
         haveFile = 1;
         break;
      default:
         usage(argv[0]);
      }
   } 
   if (!(haveFile && havePW)) {
      fprintf(stderr, "missing required argument\n");
      usage(argv[0]);
   }

   p = pcap_open_dead(DLT_IEEE802_11, 256);
   dump = pcap_dump_open(p, casefile);

   if (!dump) {
      perror("Unable to open casefile");
      exit(1);
   }
   pkt.caplen = PKTLEN;
   pkt.len = PKTLEN;

   *((int *) (pkts[0] + FCS)) = ~doFCS(pkts[0] + IV + 4, DATALEN);
   *((int *) (pkts[1] + FCS)) = ~doFCS(pkts[1] + IV + 4, DATALEN);

   for (i = 0; i < numcases; i++) {
      for (j = 0; j < plen; j++) {
         gettimeofday(&pkt.ts, &tz); 
         from = count & 1 ? pkts[1] : pkts[0];
         count++;
         for (k = 0; k < IV; k++) {
            packet[k] = from[k];
         }
         packet[IV] = password[0] = 3 + j;
         packet[IV + 1] = password[1] = 0xFF;
         packet[IV + 2] = password[2] = i;
         packet[IV + 3] = 0;
         RC4init(&rc);
         keyWith(&rc, password, 3 + plen);

         for (k = IV + 4; k < FCS + 4; k++) {
            packet[k] = from[k] ^ step(&rc);
         }
         pcap_dump((unsigned char*) dump, &pkt, packet);
      }
   }
   pcap_dump_close(dump);
   pcap_close(p);
   return 0;
}

