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

    Copyright (c) 2003, Snax
*/

#ifndef __PACKET_SOURCE_H
#define __PACKET_SOURCE_H

#include <stdio.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <pcap.h>
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

#ifdef WIN32
/*
 * We will need some libpcap defines, which of course are:
 *
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 */

/*
 * The first record in the file contains saved values for some
 * of the flags used in the printout phases of tcpdump.
 * Many fields here are 32 bit ints so compilers won't insert unwanted
 * padding; these files need to be interchangeable across architectures.
 *
 * Do not change the layout of this structure, in any way (this includes
 * changes that only affect the length of fields in this structure).
 *
 * Also, do not change the interpretation of any of the members of this
 * structure, in any way (this includes using values other than
 * LINKTYPE_ values, as defined in "savefile.c", in the "linktype"
 * field).
 *
 * Instead:
 *
 *      introduce a new structure for the new format, if the layout
 *      of the structure changed;
 *
 *      send mail to "tcpdump-workers@tcpdump.org", requesting a new
 *      magic number for your new capture file format, and, when
 *      you get the new magic number, put it in "savefile.c";
 *
 *      use that magic number for save files with the changed file
 *      header;
 *
 *      make the code in "savefile.c" capable of reading files with
 *      the old file header as well as files with the new file header
 *      (using the magic number to determine the header format).
 *
 * Then supply the changes to "patches@tcpdump.org", so that future
 * versions of libpcap and programs that use it (such as tcpdump) will
 * be able to read your new capture file format.
 */
struct pcap_file_header {
        unsigned int magic;
        unsigned short version_major;
        unsigned short version_minor;
        int thiszone;     /* gmt to local correction */
        unsigned int sigfigs;    /* accuracy of timestamps */
        unsigned int snaplen;    /* max length saved portion of each pkt */
        unsigned int linktype;   /* data link type (LINKTYPE_*) */
};

/*
 * Each packet in the dump file is prepended with this generic header.
 * This gets around the problem of different headers for different
 * packet interfaces.
 */
struct pcap_pkthdr {
        struct timeval ts;      /* time stamp */
        unsigned int caplen;     /* length of portion present */
        unsigned int len;        /* length this packet (off wire) */
};

#define PCAP_ERRBUF_SIZE 256
/*
 * END OF LIBPCAP definitions
 */

//Windows specific definition

typedef struct PacketNode_t {
   struct pcap_pkthdr hdr;
   struct PacketNode_t *nxt;
   unsigned char pkt[0];
} PacketNode;

void initPktQueue();
void destroyPktQueue();
void queueRawPacket(PacketNode *node);
PacketNode *dequeueRawPacket();

#endif

#define PRISM 0
#define ORINOCO 1
#define OTHER 2

#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif

#ifndef DLT_IEEE802_11
#define DLT_IEEE802_11 105
#endif

#ifndef DLT_PRISM_HEADER
#define DLT_PRISM_HEADER 119
#endif

#ifndef DLT_AIRONET_HEADER
#define DLT_AIRONET_HEADER 120
#endif

typedef struct {
   u_int dlType;
   int driverType;
   int dump; 
#ifndef WIN32
   pcap_t *pcap;
   pcap_dumper_t *dumpFile;
#else
   Context *ctx;
   HANDLE hAdapter;
   FILE *dumpfd; //fd for pcap dump file
   FILE *readfd; //fd for pcap dump file
   unsigned int snaplen;
   unsigned char pbuf[0];
#endif
} PacketSource;

#ifndef WIN32
#define WLAN_DEVNAMELEN_MAX 16
#else
#define WLAN_DEVNAMELEN_MAX 128
#endif

extern char dev[WLAN_DEVNAMELEN_MAX];

PacketSource *openPacketSource(char *dev, int snaplen, int promisc, int to_ms, char *errbuf,
                               int driverType, unsigned int chan);
void closePacketSource(PacketSource *src);
PacketSource *openOfflinePacketSource(const char *name, char *errbuf);
void openPacketDumpFile(PacketSource *src, char *name);
const unsigned char *nextPacket(PacketSource *src, struct pcap_pkthdr *hdr);
void dumpPacket(PacketSource *src, struct pcap_pkthdr *hdr, const unsigned char *pkt);

int startMonitor(int driverType);
int stopMonitor(int driverType);
int setChannel(int driverType, unsigned int channel);

#endif
