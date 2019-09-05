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
 
    Copyright (c) 2004, Snax
*/
 
#ifndef __PEEK_HEADERS_H
#define __PEEK_HEADERS_H

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

#endif
