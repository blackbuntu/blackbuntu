/*
    This file is part of AirSnort.

    Copyright (C) 2002 Snax

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

/*
   11/09/03 - Fixed stack overflow problem with HOME environment variable reported
              by ghalen
   4/17/02 - Orinoco's now handle beacons properly thanks to monitor mode patch
             fix by johnp@chem...
*/
  

#include <stdio.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <pcap.h>
#include <semaphore.h>
#else
#include <windows.h>
#include <io.h>
#include "peek.h"
#endif

#include <signal.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include "capture.h"
#include "crack.h"
#include "bssidlist.h"
#include "utils.h"

//Frame Control Fields
#define FC_TYPE_MASK 0x0C
#define FC_SUBTYPE_MASK 0xF0
#define FC_PROTO_MASK 0x03
#define FC_MANAGEMENT 0x00
#define FC_CONTROL 0x04
#define FC_DATA 0x08
#define FC_RESERVED 0x0C

#define ADDR1(x) ((x)+4)
#define ADDR2(x) ((x)+10)
#define ADDR3(x) ((x)+16)

//PROTOTYPES
void quick_message(char *title, char *message);
void dump(unsigned char *pkt, int len);
void setPointers(PacketInfo *cr, const unsigned char *pkt);
#ifndef WIN32
sem_t capture_sem;
#else
HANDLE capture_sem;
#endif

extern int scan;
extern int doCapture;
extern int logfile;
extern int readPcapFile;
extern int oldscan;
extern int breadth40;
extern int breadth128;

extern char cmd[80];

//initialize pointers according to TO_DS,
//FROM_DS flags.  This saves time during packet decoding
void setPointers(PacketInfo *pi, const unsigned char *pkt) {
   pi->iv = pkt + 24;
   switch (pkt[1] & 0x03) {
      case 0:  //STA to STA, or management and control
         pi->bssid = ADDR3(pkt);
         pi->sta =  ADDR2(pkt);
         break;
      case 2:  //AP to STA data
         pi->bssid = ADDR2(pkt);
         pi->sta = ADDR1(pkt); 
         break;
      case 3:  //AP to AP 
         pi->iv += 6;
      case 1:  //STA to AP data
         pi->bssid = ADDR1(pkt);
         pi->sta = ADDR2(pkt); 
         break;
   }
}

void dump(unsigned char *pkt, int len) {
   int i = 0;
   int j = 0;
   for (i = 0; i < len; i += 16) {
      for (j = 0; j < 16; j++) {
         if (i + j >= len) {
            fprintf(stdout, "   "); 
         }
         else {
            fprintf(stdout, "%2.2x ", pkt[i + j]); 
         }
      }
      fprintf(stdout, "  "); 
      for (j = 0; j < 16; j++) {
         if (i + j >= len) break;
         if (isprint(pkt[i + j])) {
            fprintf(stdout, "%c", pkt[i + j]); 
         }
         else {
            fprintf(stdout, "."); 
         }
      }
      fprintf(stdout, "\n"); 
   }
   fprintf(stdout, "\n----------------------------------------------------------------\n\n"); 
}

 //Simple packet validation routine, designed to filter 
 //out invalid/noise packets.  Return 1 if packet is invalid
 //Return zero otherwise

int reject(const unsigned char *pkt, int len) {
   unsigned char fc = *pkt;
   unsigned char subtype = fc >> 4;
   if ((fc & FC_PROTO_MASK) != 0) return 1; //reject bad protocol
   switch (fc & FC_TYPE_MASK) {
   case FC_MANAGEMENT:
      if (subtype > 12) return 1;  //reject reserved subtype
      if (subtype == 6 || subtype == 7) return 1;  //reject reserved subtype
      break;
   case FC_CONTROL:
      if (subtype < 10 || len > 20) return 1;  //reject reserved subtype
      break;
   case FC_DATA:
      if (subtype > 7) return 1;  //reject reserved subtype
      break;
   case FC_RESERVED:
      return 1;
   }
   return 0;
}

//make sure all chars in str are Ascii printable. Replace non-printable
//chars with a '.'
int bssidcpy(char *dest, const unsigned char *bssid, int len) {
   int i = 0;
   while (len && *bssid == ' ') {
      len--;
      bssid++;
   }
   for (; i < len; i++) {
      dest[i] = (char) (isprint(bssid[i]) ? bssid[i] : '.');
   }
   dest[len] = 0;
   return i;
}

int isResolved(const unsigned char *p) {
   unsigned char sum;
   if (p[1] == 255 && p[0] > 2 && p[0] < 16) return 1;
   sum = p[0] + p[1];
   if (sum == 1 && (p[2] <= 0x0A || p[2] == 0xFF)) return 1;
   if (sum <= 0x0C && (p[2] >= 0xF2 && p[2] <= 0xFE && p[2] != 0xFD)) return 1;
   return 0;
//   return p[1] == 255 && p[0] > 2 && p[0] < 16;
}

//the thread function for the packet capture thread.
//It collects packets until instructed to stop. Packets are 
//parsed for interesting info and placed on the packet queue for consumption
//by the cracking thread
#ifndef WIN32
void *capture(void *arg) {
#else
DWORD WINAPI capture(void *arg) {
#endif
   CaptureArg *parms = (CaptureArg*) arg;
   unsigned int MIN_PACKET = parms->offset + 10;  //card header + minimum control frame
   int namelen, whichType, isData, crclen;
   unsigned int channelLoc;
   PacketInfo pi;
   BssidList *apNode = NULL;
   unsigned char fc0;
   unsigned char subtype;
   const unsigned char *pkt;
   struct pcap_pkthdr pktHdr;
   int allF = 0xFFFFFFFF;
   while (doCapture) {
      pi.pack = NULL;
      pi.name[0] = '\0';
      pi.wep = 0;
      apNode = NULL;
      isData = 0;

      pkt = nextPacket(parms->src, &pktHdr);
      if (pkt == NULL) {
         if (readPcapFile) break;  //reached end of file
         continue;
      }
      if (pktHdr.len < MIN_PACKET) {
         //sanity check, if we get here the header is messed up
         continue;
      }
      if (reject(pkt + parms->offset, pktHdr.len - parms->offset)) continue;
      if (parms->src->dump) {
         dumpPacket(parms->src, &pktHdr, pkt);
      }
      pktHdr.len -= parms->offset;  //subtract out card header bytes
      //test for prism2 appended dummy crc
      crclen = memcmp(pkt + pktHdr.len - 4, &allF, 4) ? 0 : 4;
      pktHdr.len -= crclen;
      pi.channel = -1;
      pkt += parms->offset;
      pi.raw = pkt;
      pi.rxTime = pktHdr.ts.tv_sec;

      whichType = pkt[1] & 0x03;
      setPointers(&pi, pkt);
      fc0 = pkt[0];
      subtype = fc0 >> 4;

      switch (fc0 & FC_TYPE_MASK) {
      case FC_MANAGEMENT:
         if ((subtype == 8) || (subtype == 5)) {
            //beacon or probe response frame
            if (pkt[36]) continue; //elementId must be ZERO for SSID
            if (pktHdr.len < 38) continue; //safety check
            namelen = pkt[37];
            if (namelen > 32) continue;  //invalid namelen, too long!
            channelLoc = 38 + namelen + 2;   //+2 skips to supported rates field
            if (pktHdr.len < channelLoc) continue; //safety check
            channelLoc += pkt[channelLoc - 1];  //length of supported rates
            if (pktHdr.len < (channelLoc + 1)) continue; //safety check
            if (pkt[channelLoc] == 3) {
               if (pktHdr.len < (channelLoc + 3)) continue; //safety check
               //DS Parameter Set element ID
               pi.channel = pkt[channelLoc + 2];
            }
            apNode = bssidFind(pkt + 16);  //ADDR3
            if (apNode) {
               if (!apNode->hasName && namelen > 0) {
                  if (bssidcpy(apNode->name, pkt + 38, namelen)) {
                     apNode->hasName = 1;
                  }
               }
               break;
            }
            bssidcpy(pi.name, pkt + 38, namelen);
            pi.wep = pkt[34] & 0x10;
         }
         break;
      case FC_CONTROL:
         //break;
         continue;
      case FC_DATA:
         if (subtype != 0) break;  //not a data frame
         isData = 1;

         //adjust len to size of frame body
         //32 here is 24 bytes of frame header + 4 bytes of IV data
         //and 4 bytes of 802.2 SNAP
         //need at least 8 bytes in a data frame for IV/SNAP if using WEP
         if (pktHdr.len < 32) continue; //safety check
         pktHdr.len -= 24;
         if (whichType == 3) {
            //14 here is for 6 bytes of ADDR3 4 bytes of IV data
            //and 4 bytes of 802.2 SNAP
            if (pktHdr.len < 14) continue;  //safety check
            pktHdr.len -= 6;
         }

         //this is a sloppy way to detect unencrypted packets, but since 0xAA is not
         //an IV byte of interest anyway, its probably not a big deal
         if (*((unsigned short *)pi.iv) != 0xAAAA || (pkt[1] & 0x40)) {
            pi.wep = 1;
            if (isResolved(pi.iv)) {
//fprintf(stderr, "%8.8X\n", (*(int*)(pi.iv)) & 0xFFFFFF);
              pi.pack = (Packet*) malloc_r(sizeof(Packet));
              pi.pack->len = pktHdr.len;  //i.e. 802.11b "Frame Body"
              pi.pack->buf = (unsigned char*) malloc_r(pktHdr.len);
              memcpy(pi.pack->buf, pi.iv, pktHdr.len);
              pi.pack->next = NULL;
            }
         }
      } //switch
      addPacket(apNode, &pi, isData);
   }
   closePacketSource(parms->src);
   free_r(parms);
   if (readPcapFile) {
      readPcapFile = 0;
      scan = oldscan;
   }
   doCapture = 0;
#ifndef WIN32
   sem_post(&capture_sem);
   pthread_exit(NULL);
#else
   ReleaseSemaphore(capture_sem, 1, NULL);
   ExitThread(0);
#endif
   return 0;
}

