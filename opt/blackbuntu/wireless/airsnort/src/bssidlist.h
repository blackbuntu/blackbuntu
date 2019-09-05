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



#ifndef __BSSID_LIST_H
#define __BSSID_LIST_H

#include <gtk/gtk.h>
#include <glib.h>
#ifndef WIN32
#include <semaphore.h>
#include <pthread.h>
#else
#include <windows.h>
#endif
#include "RC4.h"
#include "Packet.h"
#include "crack.h"
#include "capture.h"

typedef struct BssidList_t {
   struct BssidList_t *next;
   unsigned int numPackets;
   unsigned int numEncrypted;
   unsigned int numUnique;
   unsigned int tried;
   unsigned int interesting;
   unsigned int lastInteresting;
   int channel;
   int newBreadth;
   time_t lastSeen;
   int rownum;
   int queueLen;
   int usingWep;
   unsigned char lastiv[3];
   unsigned char bssid[6];
   char name[33];
   unsigned char hasName;

#ifndef WIN32
   pthread_t crackerThread;
   sem_t crackSem;
#else
   HANDLE crackerThread;
   HANDLE crackSem;
#endif

   CrackNode *ap;

} BssidList;

extern BssidList *head, *tail;

void queueIt(unsigned char *bssid, Packet *p);
BssidList *ssidFind(const unsigned char *bssid);
BssidList *rowFind(int row);
BssidList *bssidFind(const unsigned char *bssid);
BssidList *addBssid(PacketInfo *pi);
void addPacket(BssidList *apNode, PacketInfo *pi, int isData);
void addWep(BssidList *apNode);
void clearList(void);
void checkThread(BssidList *apNode);

#endif
