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
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <getopt.h>
#include <ctype.h>
#include <string.h>
#include <pcap.h>
#include "RC4.h"
#include "crc-32.h"

#ifndef DLT_IEEE802_11
#define DLT_IEEE802_11 105
#endif

#ifndef DLT_PRISM_HEADER
#define DLT_PRISM_HEADER 119
#endif

#ifndef DLT_AIRONET_HEADER
#define DLT_AIRONET_HEADER 120
#endif

//data that varies based on what type of packet it is
typedef struct PacketInfo_t {
  const unsigned char *raw;     //pointer to common data
  const unsigned char *bssid;  //pointer to the AP bssid
  const unsigned char *sta;    //pointer to the sta 
  const unsigned char *iv;     //pointer to the frame body
} PacketInfo;

int eatHexString(char *dst,char *src,int maxlen);
int xtoint(char xdigit);
void initCapRecs(PacketInfo *cr, unsigned char *packet, int offset);
int eatHexByte(char *x);
int matchMac(const unsigned char *bssid1, const unsigned char *bssid2);
void usage(char *cmd);
void setPointers(PacketInfo *cr, const unsigned char *pkt);

#define ADDR1(x) ((x)+4)
#define ADDR2(x) ((x)+10)
#define ADDR3(x) ((x)+16)

#define PRISM_HEADER_SIZE 144

char *pw = NULL;
int useFile = 0;
FILE *input = NULL;

//initialize pointers according to TO_DS,
//FROM_DS flags.  This saves time during packet decoding
void setPointers(PacketInfo *cr, const unsigned char *pkt) {
   cr->iv = pkt + 24;
   switch (pkt[1] & 0x03) {
      case 0:  //STA to STA, or management and control
         cr->bssid = ADDR3(pkt);
         cr->sta =  ADDR2(pkt);
         break;
      case 2:  //AP to STA data
         cr->bssid = ADDR2(pkt);
         cr->sta = ADDR1(pkt); 
         break;
      case 3:  //AP to AP 
         cr->iv += 6;
      case 1:  //STA to AP data
         cr->bssid = ADDR1(pkt);
         cr->sta = ADDR2(pkt); 
         break;
   }
}

//return a string version of the hex bytes held in key
//bytes are separated by a colon
char *toHex(unsigned char *key, int size) {
   static char str[50];
   char *ptr = str + 2;
   int i = 1;
   sprintf(str, "%2.2X", key[0]);
   for (; i < size; i++, ptr += 3) {
      sprintf(ptr, ":%2.2X", key[i]);
   }
   return str;
}

//return key as ascii. Non printable ascii characters are
//represented with a '.'
char *toAsc(unsigned char *key, int size) {
   static char str[15];
   char *ptr = str;
   int i = 0;
   for (; i < size; i++, ptr++) {
      sprintf(ptr, "%c", key[i] >= 32 && key[i] < 127 ? key[i] : '.');
   }
   return str;
}

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

int matchMac(const unsigned char *bssid1, const unsigned char *bssid2) {
   int i = 5;
   for (; i >= 0; i--) {
      if (bssid1[i] != bssid2[i]) return 0;
   }
   return 1;
}

void usage(char *cmd) {
    fprintf(stderr, 
        "Usage: %s (-p <pw> | -f <dictfile>) [-b] [-o <offset>] -m <bssid> -e <cryptfile> -d <decryptfile>\n", 
        cmd);
    fprintf(stderr, "   -p: single password to try\n   -f: dictionary, 1 password per line\n");
    fprintf(stderr, "   -b: skip beacons\n   -o: offset to frame control (default zero)\n");
    fprintf(stderr, "   -m: bssid to crack\n   -e: input pcap file\n   -d: output pcap file\n");
    exit(1);
}

int makePassword(char *pwOut, char *pwIn) {
   int len = strlen(pwIn);
   switch (len) {
      case 5: case 13: //treat as ascii string
         strcpy(pwOut + 3, pwIn);
         return len;
      case 10: case 26:
//         len = noColonHex(pwOut + 3, pwIn, 13);
//         return len == 5 || len == 13 ? len : 0;
         return 0;
      case 14: case 38:
         len = eatHexString(pwOut + 3, pwIn, 13);
         return len == 5 || len == 13 ? len : 0;
   }
   return 0;
}

int nextPassword(char *pwBuf) {
   char guess[64];
   char *temp;
   int len;
   if (!useFile) {
      if (pw) {   
         strncpy(guess, pw, 64);
         guess[63] = 0;
         pw = NULL;
         if ((len = makePassword(pwBuf, guess))) {
            return len;
         }
         fprintf(stderr, "Invalid password guess %s\n", guess);
      }
   }
   else {
      while (1) {
         if (input) {
            temp = fgets(guess, 64, input);
         }
         else {
            temp = fgets(guess, 64, stdin);
         }
         if (!temp) break;
         temp = guess;
         while (*temp && *temp != '\n') temp++;
         *temp = 0;
         if ((len = makePassword(pwBuf, guess))) {
            return len;
         }
         fprintf(stderr, "Invalid password guess %s\n", guess);
      }
   }
   return 0;  // end of file
}

int main(int argc,char *argv[]) {
   char errbuf[PCAP_ERRBUF_SIZE];
   int r, i, len, plen, offset = 0, pktLen;
   int index, header;
   unsigned char password[16];
   const unsigned char *packet;
   unsigned char outPacket[3000];
   pcap_t *pIn, *pOut;
   pcap_dumper_t *dump;
   char *cryptfile = NULL, *decryptfile = NULL;
   unsigned char bssid[6]; 
   RC4 rc;
   struct pcap_pkthdr pkt;
   int havePW = 0, haveMac = 0, haveIn = 0, haveOut = 0;
   int discardBeacons = 0;
   int goodkey = 0;
   int allF = 0xFFFFFFFF;

   int whichType;
   PacketInfo thePacket;
   unsigned char fc0 = 0, type = 0, subType = 0;

   setupIdentity();
   plen = 13;
   memset(password, 0, 16);

   while (1) {
      r = getopt(argc,argv,"bp:h:o:m:e:d:f:");
      if (r < 0) break;
      switch (r) {
      case 'b':
         discardBeacons = 1;
         break;
      case 'p':
         pw = optarg;
         havePW = 1;
         break;
      case 'h':
         pw = optarg;
         havePW = 1;
         break;
      case 'o':
         offset = atoi(optarg);
         break;
      case 'f':
         input = fopen(optarg, "r");
         if (!input) {
            fprintf(stderr, "File open failed for %s, using stdin\n", optarg);
         }
         havePW = useFile = 1;
         break;
      case 'm':
         if (eatHexString((char *) bssid, optarg, 6) != 6) {
	    fprintf(stderr, "Invalid bssid, quitting\n");
            exit(1);
         }
         haveMac = 1;
         break;
      case 'e':
         cryptfile = optarg;
         haveIn = 1;
         break;
      case 'd':
         decryptfile = optarg;
         haveOut = 1;
         break;
      default:
         usage(argv[0]);
      }
   } 
   if (!(haveIn && haveOut && haveMac && havePW)) {
      fprintf(stderr, "missing required argument\n");
      usage(argv[0]);
   }

   pIn = pcap_open_offline(cryptfile, errbuf);
   if (!pIn) {
      perror("Unable to open cryptfile");
      exit(1);
   }
   pOut = pcap_open_dead(DLT_IEEE802_11, 256);
   dump = pcap_dump_open(pOut, decryptfile);
   if (!pOut) {
      perror("Unable to open decryptfile");
      exit(1);
   }
   switch (pcap_datalink(pIn)) {
      case DLT_IEEE802_11:
         offset = 0;
         break;
      case DLT_PRISM_HEADER:
         offset = PRISM_HEADER_SIZE;
         break;
   }

   while ((packet = pcap_next(pIn, &pkt))) {
      packet += offset;
      len = pkt.len;
      whichType = packet[1] & 0x03;
      header = whichType == 3 ? 30 : 24;
      setPointers(&thePacket, packet);
      fc0 = packet[0];
      type = fc0 & 0x0C;
      subType = (fc0 >> 4);
      
      if (fc0 == 0x80 && discardBeacons) continue;
      if (type == 0x08) {
         if (subType == 0) {
            if (matchMac(bssid, thePacket.bssid)) {
               if (*((unsigned short *)thePacket.iv) != 0xAAAA || (packet[1] & 0x40)) {
                  while (!goodkey && (plen = nextPassword(password))) {
                     len -= memcmp(packet + len - offset - 4, &allF, 4) ? 0 : 4;
                     pktLen = len - header - offset;  //adjust len to size of frame body
                     RC4init(&rc);
                     memcpy(password, thePacket.iv, 3);
                     keyWith(&rc, password, 3 + plen);
                     for (i = 4; i < pktLen; i++) {
                        outPacket[i - 4] = thePacket.iv[i] ^ step(&rc);
                     }
                     if (memcmp(outPacket, "\xAA\xAA\x03\x00\x00\x00", 6) && 
                        (doFCS(outPacket, pktLen - 4) != 0xdebb20e3)) {
                        continue;
                     }
                     fprintf(stdout, "Found key: Hex - %s, ASCII - \"%s\"\n", toHex(password + 3, plen), 
                                                                              toAsc(password + 3, plen));
                     goodkey = 1;
                  } 
                  if (!goodkey) {
                     len = pkt.len; //force write of unaltered packet
                  }
                  else {
                     for (index = 0; index < header; index++) {
                        outPacket[index] = packet[index];
                     }
                     outPacket[1] &= ~0x40;   //turn off wep bit
                     len -= (header + 8);  //adjust len to size of frame body, cut off checksums
                     memcpy(password, thePacket.iv, 3);
                     RC4init(&rc);
                     keyWith(&rc, password, 3 + plen);
                     for (i = 4; i < len; i++) {
                        outPacket[index++] = thePacket.iv[i] ^ step(&rc);
                     }
                     for (i = 0; i < 4; i++) {
                        outPacket[index++] = 0xFF;
                     }
                     pkt.len -= 8;
                     pkt.caplen -= 8;
                  }
               }
            }
         }
      } //if
      if (len != pkt.len) {
         pcap_dump((unsigned char*)dump, &pkt, outPacket);
      }
      else {
         pcap_dump((unsigned char*)dump, &pkt, packet);
      }
   }
   if (!goodkey) {
      fprintf(stderr, "Could not find a key for %s\n", toHex(bssid, 6));
   }
   pcap_dump_close(dump);
   pcap_close(pIn);
   pcap_close(pOut);
   if (input && input != stdin) fclose(input);

   return 0;
}

