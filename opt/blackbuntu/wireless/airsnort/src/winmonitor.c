/*
    winmonitor.c (distributed as part of AirSnort)
 
    winmonitor is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
 
    winmonitor is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 
    You should have received a copy of the GNU General Public License
    along with winmonitor; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 
    Copyright (c) 2004, Snax
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>

typedef struct PeekPacket_t {
   unsigned char byte1;
   unsigned char channel;
   unsigned short pLen;
   unsigned char data[]; //last four bytes are zeroed out crc
} PeekPacket;

typedef struct RingBuffer_t {
   int size;
   int a;
   int b;
   int currentIndex;
   HANDLE hEvent;
   HANDLE hVxD;
   int dummy1;
   int dummy2;
   int stats[12];
   unsigned char data[];
} RingBuffer;

typedef void* (__stdcall *PeekCallback)(PeekPacket *ptr, unsigned int len, int val2, 
               __int64 timeStamp, int val3, void *userPtr); //return NULL to pause the thread

typedef struct Context_t {
   HANDLE hFileAdapter;
   PeekCallback cBack;
   int state;         //  2 = stopping, 0 = stopped, 3 = paused, 1 = running
   int ringSize;
   HANDLE hThread;
   HANDLE hEvent1;
   HANDLE hResumeEvent;
   RingBuffer *pRingBuffer;
   int PeekRequestResult1; 
   int PeekRequestResult2; 
   int channelMask;
   void *userData;
} Context;

typedef struct PeekReqBuffer_t {
   int result;
   unsigned char field_4[16];
   int field_14;
   int command;
   void *pDest;
   int destLength;
   int count;
   int field_28;
   unsigned char dataBuf[512];
} PeekReqBuffer;

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

typedef LONG (*AdapterFunc)(HANDLE);
typedef LONG (*ContextFunc)(Context*);
typedef HANDLE (*StringFunc)(char*);
typedef LONG (*RequestFunc)(HANDLE, PeekReqBuffer*, LPOVERLAPPED);
typedef Context* (*CreateFunc)(HANDLE, PeekCallback, int, int, void*);

/*
__declspec(dllimport) LONG PeekCloseAdapter(HANDLE hFileAdapter);
__declspec(dllimport) Context *PeekCreateCaptureContext(HANDLE hFileAdapter, PeekCallback arg1, 
                                              int ringSize, int channelMask, void *userPtr);
__declspec(dllimport) HANDLE PeekOpenAdapterA(char *adapterName); //returns -1 on fail
__declspec(dllimport) LONG PeekRequest(HANDLE hFile, PeekReqBuffer *prb, LPOVERLAPPED overlapped);
__declspec(dllimport) LONG PeekStartCapture(Context *pContext);
__declspec(dllimport) LONG PeekStopCapture(Context *pContext);
__declspec(dllimport) LONG PeekDestroyCaptureContext(Context *pContext);
*/

static StringFunc PeekOpenAdapterA;
static CreateFunc PeekCreateCaptureContext;
static ContextFunc PeekStartCapture;
static RequestFunc PeekRequest;
static ContextFunc PeekStopCapture;
static AdapterFunc PeekCloseAdapter;
static ContextFunc PeekDestroyCaptureContext;

HANDLE hAdapter;
Context *ctx = NULL;

int break_flag = 0;
int channel_array[14];
int channel_count;

#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define TCPDUMP_MAGIC 0xA1B2C3D4
#define LINKTYPE_IEEE802_11 105

void usage(void);
int get_device_name_from_index(int index, char *buf);
int initCapture(int nic_index, PeekCallback func, FILE *pcap_fd);
void stopCapture(void);
void listAdapters(void);
DWORD setChannel(int channel);

int parse_channels(char *list) {
   unsigned int x;
   channel_count = 0;
   while (sscanf(list, "%d", &x) == 1) {
      if (x < 1 || x > 14) return 1;
      channel_array[channel_count++] = x;
      if (channel_count == 14) break;
      while (isdigit(*list)) list++;
      while (*list && !isdigit(*list)) list++;
   }
   return channel_count == 0;
}

void usage() {
   printf("winmonitor - (C) 2004 Snax\n"
          "  usage: \n"
          "    winmonitor -i <nic index> -c <channel(s)> -f <output filename>\n"
          "       -i integer index of network adapter (see -l option)\n"
          "       -c channels to scan. ex: 1,6,8\n"
          "       -f pcap save file name (appends if file exists)\n"
          "    winmonitor -l\n"
          "       -l List available network adapters\n");
   exit(1);
}

void * __stdcall packetCallback(PeekPacket *pkt, unsigned int len, int val2, 
               __int64 timeStamp, int val3, void *pcap) {
   if ((val3 & 1) == 0) {
      struct pcap_pkthdr hdr;

      hdr.caplen = hdr.len = len - 8;

      hdr.ts.tv_usec = 0;
      hdr.ts.tv_sec = time(0);
 
      if (fwrite(&hdr, 1, sizeof(hdr), (FILE*)pcap) != sizeof(hdr)) {
          break_flag = 1;
          fprintf(stderr, "Error: failed to write packet header\n");
          return NULL;
      }
 
      if (fwrite(pkt->data, 1, hdr.len, (FILE*)pcap) != hdr.len) {
          break_flag = 1;
          fprintf(stderr, "Error: failed to write packet data\n");
          return NULL;
      }
   }
   return (void*)1; 
}

BOOL __stdcall handlerRoutine(DWORD x) {
   return break_flag = 1;
}

int main(int argc, char **argv) {
   DWORD current_channel;
   int i;
   FILE *pcap_fd;
   char *outfile_name;
   int iface, have_i = 0, have_c = 0, have_f = 0;
   struct pcap_file_header pfh;
   
   if (argc == 2 && strcmp(argv[1], "-l") == 0) {
      listAdapters();
      return 0;
   }

   if (argc != 7) usage();
   
   for (i = 1; i < argc; i += 2) {
      if (strcmp(argv[i], "-i") == 0) {
         if (sscanf(argv[i + 1], "%d", &iface) != 1) usage();
         if (get_device_name_from_index(iface, 0)) {
            fprintf(stderr, "Error: Invalid network card index (try the -l option)\n");
            return 1;
         }
         have_i = 1;
      }
      if (strcmp(argv[i], "-f") == 0) {
         outfile_name = argv[i + 1];
         have_f = 1;
      }
      if (strcmp(argv[i], "-c") == 0) {
         if (parse_channels(argv[i + 1])) {
            fprintf(stderr, "Wrror: Invalid wireless channel list\n");
            usage();
         }
         have_c = 1;
      }
   }
   if (!have_i || !have_c || !have_f) usage();

   pcap_fd = fopen(outfile_name, "rb+");
   if (!pcap_fd) {
      pcap_fd = fopen(outfile_name, "wb");
      if (!pcap_fd) {
         fprintf(stderr, "Error: failed to open pcap file\n");
         return 1;
      }
      pfh.magic = TCPDUMP_MAGIC;
      pfh.version_major = PCAP_VERSION_MAJOR;
      pfh.version_minor = PCAP_VERSION_MINOR;
      pfh.thiszone = 0;
      pfh.sigfigs = 0;
      pfh.snaplen = 65535;
      pfh.linktype = LINKTYPE_IEEE802_11;
      if (fwrite(&pfh, 1, sizeof(pfh), pcap_fd) != sizeof(pfh)) {
         fprintf(stderr, "Error: failed to write pcap file header\n");
         return 1;
      }
   }
   else { //read_existing
      if (fread(&pfh, 1, sizeof(pfh), pcap_fd) != sizeof(pfh)) {
         fprintf(stderr, "Error: failed to read pcap file header\n");
         return 1;
      }
      if (pfh.magic != TCPDUMP_MAGIC) {
         fprintf(stderr, "Error: bad tcpdump magic value in pcap file\n");
         return 1;
      }
      if (pfh.linktype != LINKTYPE_IEEE802_11) {
         fprintf(stderr, "Error: bad linktype in pcap file\n");
         return 1;
      }
      if (fseek(pcap_fd, 0, SEEK_END)) {
         fprintf(stderr, "Error: SEEK_END failed\n");
         return 1;
      }
   }
   //good_open_file
   SetConsoleCtrlHandler(handlerRoutine, 1);
   
   if (initCapture(iface, packetCallback, pcap_fd)) return 1;
   setChannel(channel_array[0]);
   
   current_channel = 0;
   
   while (1) {
      if (break_flag) {
         stopCapture();
         break;
      }
      Sleep(250);
      if (channel_count > 1) {
         current_channel = (current_channel + 1) % channel_count;
         setChannel(channel_array[current_channel]);
      }
   }
   fclose(pcap_fd);
   return 0;
}

void listAdapters() {
   char data[128];
   DWORD type;
   DWORD cbData;
   HKEY devKey;
   HKEY hKey;
   int i = 0;
   int idx;
   
   printf("Known network adapters:\n\n");
   
   if (RegOpenKeyA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards", &hKey)) {
      fprintf(stderr, "Error: Failed to open NetworkCards registry key\n");
      return;
   }
   while (RegEnumKeyA(hKey, i++, data, sizeof(data)) == 0) {
      idx = atoi(data);
      sprintf(data, "Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\%d", idx);
      if (RegOpenKeyA(HKEY_LOCAL_MACHINE, data, &devKey)) {
         fprintf(stderr, "Error: Failed to open NetworkCards\\%d registry key\n", idx);
         return;
      }
      cbData = sizeof(data);
      if (RegQueryValueExA(devKey, "Description", NULL, &type, data, &cbData)) {
         fprintf(stderr, "Error: Failed to query Description for NetworkCards\\%d\n", idx);
         return;
      }
      RegCloseKey(devKey);
      printf("  %2d  %s\n", idx, data);
   }
   RegCloseKey(hKey);
   printf("\n");
}

int get_device_name_from_index(int index, char *buf) {
   char data[128];
   DWORD type;
   DWORD cbData = sizeof(data);
   HKEY hKey;
   int result = 0;

   sprintf(data, "Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\%d", index);
   if (RegOpenKeyA(HKEY_LOCAL_MACHINE, data, &hKey)) return 2;
   if (RegQueryValueExA(hKey, "ServiceName", NULL, &type, data, &cbData)) result = 1;
   RegCloseKey(hKey);
   if (buf) sprintf(buf, "\\Device\\%s", data);
   return result;
}

DWORD setChannel(int channel) {
   PeekReqBuffer prb;
   OVERLAPPED o;
   memset(&prb, 0, sizeof(prb));
   memset(&o, 0, sizeof(o));
   o.hEvent = CreateEvent(NULL, 0, 0, NULL);
   prb.pDest = &channel;
   prb.field_14 = 1;
   prb.command = 0xFF636713;
   prb.destLength = 4;
   return (*PeekRequest)(hAdapter, &prb, &o);
}

int initCapture(int nic_index, PeekCallback func, FILE *pcap) {
   char dev[256];
   DWORD result;
   HANDLE lib;
   if ((lib = LoadLibrary("Peek.dll")) == 0) return 1;
   if ((PeekOpenAdapterA = (StringFunc)GetProcAddress(lib, "PeekOpenAdapterA")) == 0) return 1;
   if ((PeekCreateCaptureContext = (CreateFunc)GetProcAddress(lib, "PeekCreateCaptureContext")) == 0) return 1;
   if ((PeekStartCapture = (ContextFunc)GetProcAddress(lib, "PeekStartCapture")) == 0) return 1;
   if ((PeekRequest = (RequestFunc)GetProcAddress(lib, "PeekRequest")) == 0) return 1;
   if ((PeekDestroyCaptureContext = (ContextFunc)GetProcAddress(lib, "PeekDestroyCaptureContext")) == 0) return 1;
   if ((PeekStopCapture = (ContextFunc)GetProcAddress(lib, "PeekStopCapture")) == 0) return 1;
   if ((PeekCloseAdapter = (AdapterFunc)GetProcAddress(lib, "PeekCloseAdapter")) == 0) return 1;

   if (get_device_name_from_index(nic_index, dev)) {
      fprintf(stderr, "Invalid network card index\n");
      return 1;
   }
   if ((hAdapter = (*PeekOpenAdapterA)(dev)) == INVALID_HANDLE_VALUE) {
      fprintf(stderr, "PeekOpenAdapter() failed\n");
      return 1;
   }
   ctx = (*PeekCreateCaptureContext)(hAdapter, func, 0x10000, 0x21, pcap);
   if ((*PeekStartCapture)(ctx)) {
      (*PeekCloseAdapter)(hAdapter);
      fprintf(stderr, "PeekStartCapture() failed\n");
      return 1;
   }
   if ((result = setChannel(1)) == 0xC0010017) {
//      (*PeekStopCapture)(ctx);
      (*PeekDestroyCaptureContext)(ctx);
      (*PeekCloseAdapter)(hAdapter);
      fprintf(stderr, "Error: Network card not supported (see airopeek readme.txt)\n");
      return 1;
   }
   else if (result) {
//      (*PeekStopCapture)(ctx);
      (*PeekDestroyCaptureContext)(ctx);
      (*PeekCloseAdapter)(hAdapter);
      fprintf(stderr, "Error: faile to set wireless channel\n");
      return 1;
   }
   return 0;
}

void stopCapture() {
   if (ctx) {
//      (*PeekStopCapture)(ctx);
      (*PeekDestroyCaptureContext)(ctx);
      (*PeekCloseAdapter)(hAdapter);
   }
   ctx = NULL;
}

