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

#include <fcntl.h>
#include "PacketSource.h"
#include "utils.h"

char dev[WLAN_DEVNAMELEN_MAX];
extern char errbuf[PCAP_ERRBUF_SIZE];

#ifndef WIN32

#define P80211_IOCTL_MAGIC (0x4a2d464dUL)

#define P80211ENUM_truth_false			0
#define P80211ENUM_truth_true			1
#define P80211ENUM_msgitem_status_no_value		1

/*===============================================================*/
/* Types */

/*----------------------------------------------------------------*/
/* A ptr to the following structure type is passed as the third */
/*  argument to the ioctl system call when issuing a request to */
/*  the p80211 module. */

typedef struct p80211ioctl_req
{
	char 	name[WLAN_DEVNAMELEN_MAX];
	void	*data;
	unsigned int magic;
	unsigned short len;
	unsigned int result;
} p80211ioctl_req_t;

typedef struct p80211msg
{
	unsigned int msgcode;
	unsigned int msglen;
	unsigned char devname[WLAN_DEVNAMELEN_MAX];
} p80211msg_t;

/* message data item for INT, BOUNDEDINT, ENUMINT */
typedef struct p80211item_uint32
{
	unsigned int		did;
	unsigned short		status;
	unsigned short		len;
	unsigned int		data;
}  p80211item_uint32_t;

//THESE constants reflect the wlan-ng 0.1.13 values
#define DIDmsg_lnxreq_wlansniff 0x0083
#define DIDmsg_lnxreq_wlansniff_enable 0x1083
#define DIDmsg_lnxreq_wlansniff_channel 0x2083
#define DIDmsg_lnxreq_wlansniff_prismheader 0x3083
#define DIDmsg_lnxreq_wlansniff_keepwepflags 0x4083
#define DIDmsg_lnxreq_wlansniff_resultcode 0x5083

typedef struct p80211msg_lnxreq_wlansniff
{
	unsigned int		msgcode; //		__attribute__ ((packed));
	unsigned int		msglen; //		__attribute__ ((packed));
	unsigned char		    devname[WLAN_DEVNAMELEN_MAX]; //	__attribute__ ((packed));
	p80211item_uint32_t	enable; //	       __attribute__ ((packed));
	p80211item_uint32_t	channel; //	       __attribute__ ((packed));
	p80211item_uint32_t	prismheader; //	   __attribute__ ((packed));
	p80211item_uint32_t	keepwepflags; //   __attribute__ ((packed));
	p80211item_uint32_t	resultcode; //     __attribute__ ((packed));
} /* __attribute__ ((packed)) */ p80211msg_lnxreq_wlansniff_t;

#define DIDmsg_lnxind_wlansniffrm 0x0041
#define DIDmsg_lnxind_wlansniffrm_hosttime 0x1041
#define DIDmsg_lnxind_wlansniffrm_mactime 0x2041
#define DIDmsg_lnxind_wlansniffrm_channel 0x3041
#define DIDmsg_lnxind_wlansniffrm_rssi 0x4041
#define DIDmsg_lnxind_wlansniffrm_sq 0x5041
#define DIDmsg_lnxind_wlansniffrm_signal 0x6041
#define DIDmsg_lnxind_wlansniffrm_noise 0x7041
#define DIDmsg_lnxind_wlansniffrm_rate 0x8041
#define DIDmsg_lnxind_wlansniffrm_istx 0x9041
#define DIDmsg_lnxind_wlansniffrm_frmlen 0xA041

typedef struct p80211msg_lnxind_wlansniffrm
{
	unsigned int		msgcode;
	unsigned int		msglen;
	unsigned char		    devname[WLAN_DEVNAMELEN_MAX];
	p80211item_uint32_t	hosttime;
	p80211item_uint32_t	mactime;
	p80211item_uint32_t	channel;
	p80211item_uint32_t	rssi;
	p80211item_uint32_t	sq;
	p80211item_uint32_t	signal;
	p80211item_uint32_t	noise;
	p80211item_uint32_t	rate;
	p80211item_uint32_t	istx;
	p80211item_uint32_t	frmlen;
}  p80211msg_lnxind_wlansniffrm_t;

#ifndef SIOCIWFIRSTPRIV
#define SIOCIWFIRSTPRIV SIOCDEVPRIVATE
#endif
#define P80211_IFREQ (SIOCIWFIRSTPRIV  + 1)

#endif

int do_ioctl(unsigned char *userMsg);

static PacketSource *pSource = NULL;
static unsigned int driverOffset = 0;
static unsigned int packetOffset = 0;
extern int scan;
extern unsigned int chan;
extern int doCapture;
extern int cardType;

#ifdef WIN32
#include <sys/timeb.h>

static StringFunc PeekOpenAdapterA;
static CreateFunc PeekCreateCaptureContext;
static ContextFunc PeekStartCapture;
static RequestFunc PeekRequest;
static ContextFunc PeekStopCapture;
static AdapterFunc PeekCloseAdapter;
static ContextFunc PeekDestroyCaptureContext;

static HANDLE queueSem;
static HANDLE qtySem;
static PacketNode *pktHead;
static PacketNode *pktTail;
static is_init = 0;

void * __stdcall packetCallback(PeekPacket *ptr, unsigned int len, int val2, __int64 timeStamp, 
                     int val3, void *userPtr){
   //return NULL to pause the thread
   struct timeb timev;
   PacketNode *temp = NULL;
   
   if (val3 & 1) return (void*) 1;
   if (len <= packetOffset) return (void*) 1;

   len = len - packetOffset;
   temp = (PacketNode *) malloc_r(sizeof(PacketNode) + len);
   if (temp) {
      memcpy(temp->pkt, ptr->data + driverOffset, len);
      temp->nxt = NULL;
      temp->hdr.caplen = (len < pSource->snaplen) ? len : pSource->snaplen;
      temp->hdr.len = len;
      ftime(&timev);
      temp->hdr.ts.tv_sec = timev.time;
      temp->hdr.ts.tv_usec = timev.millitm * 1000;
      queueRawPacket(temp);
   }

   return (void*) 1;
}

int initPeek() {
   HANDLE lib;
   if ((lib = LoadLibrary("Peek.dll")) == 0) return 1;
   if ((PeekOpenAdapterA = (StringFunc)GetProcAddress(lib, "PeekOpenAdapterA")) == 0) return 1;
   if ((PeekCreateCaptureContext = (CreateFunc)GetProcAddress(lib, "PeekCreateCaptureContext")) == 0) return 1;
   if ((PeekStartCapture = (ContextFunc)GetProcAddress(lib, "PeekStartCapture")) == 0) return 1;
   if ((PeekRequest = (RequestFunc)GetProcAddress(lib, "PeekRequest")) == 0) return 1;
   if ((PeekDestroyCaptureContext = (ContextFunc)GetProcAddress(lib, "PeekDestroyCaptureContext")) == 0) return 1;
   if ((PeekStopCapture = (ContextFunc)GetProcAddress(lib, "PeekStopCapture")) == 0) return 1;
   if ((PeekCloseAdapter = (AdapterFunc)GetProcAddress(lib, "PeekCloseAdapter")) == 0) return 1;
   return 0;
}

void initPktQueue() {
   if (is_init) destroyPktQueue();
   pktHead = pktTail = NULL;
   queueSem = CreateSemaphore(NULL, 1, 1, NULL);
   qtySem = CreateSemaphore(NULL, 0, 0x7FFFFFFF, NULL);
   is_init = 1;
}

void destroyPktQueue() {
   if (is_init) {
      PacketNode *temp;
      while (temp = pktHead) {
         pktHead = pktHead->nxt;
         free_r(temp);
      }
      CloseHandle(queueSem);
      CloseHandle(qtySem);
   }
   is_init = 0;
}

void queueRawPacket(PacketNode *node) {
   if (!is_init || !node) return;
   WaitForSingleObject(queueSem, INFINITE);
   if (pktHead) {
      pktTail->nxt = node;
   }
   else {
      pktHead = node;
   }
   pktTail = node;
   pktTail->nxt = NULL;
   ReleaseSemaphore(qtySem, 1, NULL);
   ReleaseSemaphore(queueSem, 1, NULL);
}

PacketNode *dequeueRawPacket() {
   PacketNode *temp;
   if (!is_init) return NULL;
   if (WaitForSingleObject(qtySem, 1000) == WAIT_TIMEOUT) return NULL;
   WaitForSingleObject(queueSem, INFINITE);
   //pull a packet off the queue
   temp = pktHead;
   pktHead = pktHead->nxt;
   ReleaseSemaphore(queueSem, 1, NULL);
   return temp;
}

#endif

PacketSource *openPacketSource(char *dev, int snaplen, int promisc, int to_ms, char *errbuf,
                               int driverType, unsigned int chan) {
   PacketSource *src;
#ifndef WIN32
   src = (PacketSource*) calloc_r(sizeof(PacketSource), 1);
   src->driverType = driverType;  
   startMonitor(driverType);
   if (setChannel(driverType, chan)) {
      quick_message("Error", "Could not set monitor mode, make sure you are root.");
      return NULL;
   }  
   src->pcap = pcap_open_live(dev, snaplen, promisc, to_ms, errbuf);
   if (src->pcap) {
      src->dlType = pcap_datalink(src->pcap);
   }
   else {
      free_r(src);
      src = NULL;
   }
#else
   //init PacketSource structure including packet queue
   initPktQueue();
   src = (PacketSource*) calloc_r(sizeof(PacketSource) + snaplen, 1);
   src->driverType = driverType;
   driverOffset = driverType * 4; //offset 0 or 4 bytes for orinoco, dwl-650 respectively
   packetOffset = driverOffset + 8;
   src->snaplen = snaplen;
   src->dlType = DLT_IEEE802_11;
   if ((src->hAdapter = (*PeekOpenAdapterA)(dev)) == INVALID_HANDLE_VALUE) {
      free_r(src);
      src = NULL;
   }
   else {
      src->ctx = (*PeekCreateCaptureContext)(src->hAdapter, packetCallback, 0x10000, 0x21, NULL);
   //   src->ctx = (*PeekCreateCaptureContext)(src->hAdapter, packetCallback, 0x3E8000, 0x21, src);
      if ((*PeekStartCapture)(src->ctx)) {
         (*PeekCloseAdapter)(src->hAdapter);
         free_r(src);
         src = NULL;
      }
      
      setChannel(driverType, chan);
   }
#endif
   return pSource = src;
}

void closePacketSource(PacketSource *src) {
   if (!src) return;
   if (src->dump) {
#ifndef WIN32
      pcap_dump_close(src->dumpFile);
#else
      fclose(src->dumpfd);
#endif
   }
#ifndef WIN32
   pcap_close(src->pcap);
   if (src->driverType != -1) {
      stopMonitor(src->driverType);
   }
#else
   if (src->readfd) {
      fclose(src->readfd);
   }
   else {
//      (*PeekStopCapture)(src->ctx);
      (*PeekDestroyCaptureContext)(src->ctx);
      (*PeekCloseAdapter)(src->hAdapter);
      destroyPktQueue();
   }
#endif
   free_r(src);
   pSource = NULL;
}

PacketSource *openOfflinePacketSource(const char *name, char *errbuf) {
   PacketSource *src = NULL;
#ifndef WIN32
   src = (PacketSource*) calloc_r(sizeof(PacketSource), 1);
   src->pcap = pcap_open_offline(name, errbuf);
   if (src->pcap) {
      src->dlType = pcap_datalink(src->pcap);
      src->driverType = -1;
   }
   else {
      free_r(src);
      src = NULL;
   }
#else
   struct pcap_file_header hdr;
   FILE *fd = fopen(name, "rb");
   if (fd) {
      if (fread(&hdr, 1, sizeof(hdr), fd) == sizeof(hdr)) {
         src = (PacketSource*) calloc_r(sizeof(PacketSource) + hdr.snaplen, 1);
         src->readfd = fd;
         //need to check magic
         src->dlType = hdr.linktype;
         src->snaplen = hdr.snaplen;
      }
      else {
         fclose(fd);
      }
   }
#endif
   return src;
}

void openPacketDumpFile(PacketSource *src, char *name) {
#ifndef WIN32
   src->dumpFile = pcap_dump_open(src->pcap, name);
#else
   struct pcap_file_header hdr;
   src->dumpfd = fopen(name, "wb");
   hdr.magic = 0xA1B2C3D4;
   hdr.version_major = 4;
   hdr.version_minor = 2;
   hdr.thiszone = 0;
   hdr.sigfigs = 0;
   hdr.snaplen = src->snaplen;
   hdr.linktype = src->dlType;
   fwrite(&hdr, 1, sizeof(hdr), src->dumpfd);
#endif
   src->dump = 1;
}

const unsigned char *nextPacket(PacketSource *src, struct pcap_pkthdr *hdr) {
#ifndef WIN32
   return pcap_next(src->pcap, hdr);
#else
   if (src->readfd) {
      int len = fread(hdr, 1, sizeof(struct pcap_pkthdr), src->readfd);
      if (len == sizeof(struct pcap_pkthdr)) {
         if (hdr->caplen > src->snaplen) return NULL;
         len = fread(src->pbuf, 1, hdr->caplen, src->readfd);
         if (len != (int)hdr->caplen) return NULL;
      }
      else return NULL;
   }
   else {
      PacketNode *temp = dequeueRawPacket();
      if (temp) {
         memcpy(src->pbuf, temp->pkt, temp->hdr.caplen);
         *hdr = temp->hdr;
         free_r(temp);
      }
      else return NULL;
   }
   return src->pbuf;
#endif
}

void dumpPacket(PacketSource *src, struct pcap_pkthdr *hdr, const unsigned char *pkt) {
#ifndef WIN32
   pcap_dump((unsigned char*)src->dumpFile, hdr, pkt);
#else
   fwrite(hdr, 1, sizeof(struct pcap_pkthdr), src->dumpfd);
   fwrite(pkt, 1, hdr->caplen, src->dumpfd);
#endif
}

/* 
* The setChannel function was lifted from the wlanctl source file:
*
*src/wlanctl/wlanctl.c
*
* user utility for the wlan card
*
* Copyright (C) 1999 AbsoluteValue Systems, Inc.  All Rights Reserved.
* --------------------------------------------------------------------
*
* linux-wlan
*
    linux-wlan is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    linux-wlan is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with linux-wlan; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*
* --------------------------------------------------------------------
*
* Inquiries regarding the linux-wlan Open Source project can be
* made directly to:
*
* AbsoluteValue Systems Inc.
* info@linux-wlan.com
* http://www.linux-wlan.com
*
* --------------------------------------------------------------------
*/

/*
 * Set the NIC into promiscuous mode on the indicated channel
 * This code was distilled from wlanctl.c which is part of 
 * the linux-wlan-ng package.  This is the only wlanctl functionality
 * needed in airsnort, so I put it here rather than shelling out
 * to invoke wlanctl-ng every time I wanted to change channels. CSE.
 */

#define MAKE_SYS_CALL
/* 
 * as opposed to making ioctl calls directly.  We can make ioctls 
 * directly if we can tie into the linux-wlan-ng header files
 */

int setChannel(int driverType, unsigned int channel) {
   int result = 0;
#ifndef WIN32   
   static int fd = -1;
   struct iwreq ireq;  //for Orinoco
   unsigned int *ptr;
   if (driverType == OTHER) return 0; //don't mess with channels when using unknown drivers
   if (!doCapture) return 0;  //don't change channels if we are not capturing
   if (fd == -1) {
      fd = socket(AF_INET, SOCK_STREAM, 0);
   }
   if (driverType == ORINOCO) {  //assumes patched pcmcia-cs-3.1.31 and using orinoco_cs
      /* get a socket */
      if ( fd == -1 ) {
         return -1;
      }
      strncpy(ireq.ifr_ifrn.ifrn_name, dev, WLAN_DEVNAMELEN_MAX);
      ireq.ifr_ifrn.ifrn_name[WLAN_DEVNAMELEN_MAX - 1] = 0;
      //first see if latest orinoco drivers are installed
#ifdef IW_MODE_MONITOR
      ireq.u.mode = IW_MODE_MONITOR; 
      if (!ioctl( fd, SIOCSIWMODE, &ireq)) {
         ireq.u.freq.e = 0;
         ireq.u.freq.m = (int)channel;  
         result = ioctl(fd, SIOCSIWFREQ, &ireq);
      }
      else 
#endif
      { //fallback to old patched drivers

         ptr = (unsigned int *) ireq.u.name;
         ptr[0] = 1;
         ptr[1] = channel;
         result = ioctl(fd, SIOCIWFIRSTPRIV + 0x8, &ireq);
      }
   }
   else if (driverType == PRISM) {
#ifndef MAKE_SYS_CALL
      p80211msg_lnxreq_wlansniff_t sniff;
      memset(&sniff, 0, sizeof(p80211msg_lnxreq_wlansniff_t));
      sniff.msgcode = DIDmsg_lnxreq_wlansniff;
      sniff.msglen = sizeof(p80211msg_lnxreq_wlansniff_t);
      strncpy((char*) sniff.devname, dev, WLAN_DEVNAMELEN_MAX);
      sniff.devname[WLAN_DEVNAMELEN_MAX - 1] = 0;

      sniff.enable.did = DIDmsg_lnxreq_wlansniff_enable;
      sniff.enable.len = 4;
      sniff.enable.status = 0;
      sniff.enable.data = P80211ENUM_truth_true;

      sniff.channel.did = DIDmsg_lnxreq_wlansniff_channel;
      sniff.channel.len = 4;
      sniff.channel.status = 0;
      sniff.channel.data = channel;

      sniff.prismheader.did = DIDmsg_lnxreq_wlansniff_prismheader;
      sniff.prismheader.len = 4;
      sniff.prismheader.status = 0;
      sniff.prismheader.data = P80211ENUM_truth_false;

      sniff.keepwepflags.did = DIDmsg_lnxreq_wlansniff_keepwepflags;
      sniff.keepwepflags.len = 4;
      sniff.keepwepflags.status = 0;
      sniff.keepwepflags.data = P80211ENUM_truth_false;

      sniff.resultcode.did = DIDmsg_lnxreq_wlansniff_resultcode;
      sniff.resultcode.status = P80211ENUM_msgitem_status_no_value;
      sniff.resultcode.len = 4;

      result = do_ioctl((uint8_t*) &sniff);
#else
      char cmd[256];
      static char *parms = "keepwepflags=false prismheader=false";
      sprintf(cmd, "/sbin/wlanctl-ng %s lnxreq_wlansniff enable=true channel=%d %s > /dev/null", 
                    dev, channel, parms);
fprintf(stderr, "%s\n", cmd);
      result = system(cmd);
#endif
   }
#else  //must be WIN32
   if (pSource) {
      PeekReqBuffer prb;
      OVERLAPPED overlapped;
      memset(&prb, 0, sizeof(prb));
      memset(&overlapped, 0, sizeof(overlapped));
      overlapped.hEvent = CreateEvent(NULL, TRUE, 0, NULL);
      prb.pDest = &channel;
      prb.field_14 = 1;
      prb.command = 0xFF636713;
      prb.destLength = 4;
      result = (*PeekRequest)(pSource->hAdapter, &prb, &overlapped) ? 1 : 0;
      WaitForSingleObject(overlapped.hEvent, INFINITE);
      CloseHandle(overlapped.hEvent);
   }
#endif //WIN32
   return result;
}

#ifndef WIN32
void changeChannel(int x) {
#else
void CALLBACK changeChannel(HWND hWnd, UINT msg, UINT evt, DWORD dwTime) {
#endif
   if (scan) {
      chan = (chan % 11) + 1;
      setChannel(cardType, chan);
   }
}

int stopMonitor(int driverType) {
   int result = 0;
#ifndef WIN32
   int fd;
   if (driverType == ORINOCO) {  //assumes patched orinoco drivers using orinoco_cs
      struct iwreq ireq;
      /* get a socket */
      if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) return -1;
      strncpy(ireq.ifr_ifrn.ifrn_name, dev, WLAN_DEVNAMELEN_MAX);
      ireq.ifr_ifrn.ifrn_name[WLAN_DEVNAMELEN_MAX - 1] = 0;
      ireq.u.mode = IW_MODE_INFRA; 
      result = ioctl( fd, SIOCSIWMODE, &ireq);
      close(fd);
   }
   else if (driverType == PRISM) {
#ifndef MAKE_SYS_CALL
      p80211msg_lnxreq_wlansniff_t sniff;
      memset(&sniff, 0, sizeof(p80211msg_lnxreq_wlansniff_t));
      sniff.msgcode = DIDmsg_lnxreq_wlansniff;
      sniff.msglen = sizeof(p80211msg_lnxreq_wlansniff_t);
      strncpy((char*) sniff.devname, dev, WLAN_DEVNAMELEN_MAX);
      sniff.devname[WLAN_DEVNAMELEN_MAX - 1] = 0;

      sniff.enable.did = DIDmsg_lnxreq_wlansniff_enable;
      sniff.enable.len = 4;
      sniff.enable.data = P80211ENUM_truth_false;

      sniff.channel.did = DIDmsg_lnxreq_wlansniff_channel;
      sniff.channel.status = P80211ENUM_msgitem_status_no_value;
      sniff.channel.len = 4;

      sniff.resultcode.did = DIDmsg_lnxreq_wlansniff_resultcode;
      sniff.resultcode.status = P80211ENUM_msgitem_status_no_value;
      sniff.resultcode.len = 4;

      result = do_ioctl((uint8_t*) &sniff);
#else
      char cmd[256];
      sprintf(cmd, "/sbin/wlanctl-ng %s lnxreq_wlansniff enable=false > /dev/null", dev);
fprintf(stderr, "%s\n", cmd);
      result = system(cmd);
#endif
   }
#else //WIN32
#endif //WIN32
   return result;
}

int do_ioctl( unsigned char *userMsg ) {
   int result = -1;
#ifndef WIN32
   int fd;
   p80211ioctl_req_t req;
   p80211msg_t *msg = (p80211msg_t *) userMsg;

   strncpy(msg->devname, dev, WLAN_DEVNAMELEN_MAX);
   msg->devname[WLAN_DEVNAMELEN_MAX - 1] = 0;

   /* set the magic */
   req.magic = P80211_IOCTL_MAGIC;

   /* get a socket */
   fd = socket(AF_INET, SOCK_STREAM, 0);

   if ( fd == -1 ) {
      return result;
   }

   req.len = msg->msglen;
   req.data = msg;   
   strncpy( req.name, dev, WLAN_DEVNAMELEN_MAX);
   req.name[WLAN_DEVNAMELEN_MAX - 1] = 0;
   req.result = 0;

   result = ioctl( fd, P80211_IFREQ, &req);
   close(fd);
#else //WIN32
#endif  //WIN32
   return result;
}

int startMonitor(int driverType) {
#ifndef WIN32   
   if (driverType == PRISM) {
      char cmd[256];
      snprintf(cmd, sizeof(cmd), "/sbin/wlanctl-ng %s lnxreq_ifstate ifstate=enable > /dev/null", dev);
fprintf(stderr, "%s\n", cmd);
      system(cmd);
      snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s up", dev);
      system(cmd);
   }
#endif
   return 0;
}

