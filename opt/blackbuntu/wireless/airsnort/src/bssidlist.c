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


#include <string.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <windows.h>
#endif
#include <stdio.h>
#include "bssidlist.h"
#include "crc-32.h"
#include "capture.h"
#include "crack.h"
#include "utils.h"

BssidList *head = 0;
BssidList *tail = 0;

extern int listCount;

void addKorekIV(BssidList *apNode, PacketInfo *pi);

BssidList *bssidFind(const unsigned char *bssid) {
   BssidList *temp = head;
   for (; temp; temp = temp->next) {
      if (!memcmp(temp->bssid, bssid, 6)) {
         break;
      }
   }
   return temp;
}

BssidList *rowFind(int row) {
   BssidList *temp = head;
   for (; temp; temp = temp->next) {
      if (row == temp->rownum) {
         break;
      }
   }
   return temp;
}

//the capture thread runs through here to see if it should try a new crack.
//A terminating crack thread also runs through here to see if enough new packets
//have been added to warrent starting a new thread.
void checkThread(BssidList *apNode) {
#ifndef WIN32
   sem_wait(&apNode->crackSem);
   if ((apNode->crackerThread == 0) && ((apNode->queueLen > 9) || (apNode->newBreadth))) {
      pthread_create(&apNode->crackerThread, NULL, cracker, apNode->ap);
   }
   sem_post(&apNode->crackSem);
#else
   WaitForSingleObject(apNode->crackSem, INFINITE);
   if ((apNode->crackerThread == 0) && ((apNode->queueLen > 9) || (apNode->newBreadth))) {
      apNode->crackerThread = CreateThread(NULL, 0, cracker, apNode->ap, 0, NULL);
   }
   ReleaseSemaphore(apNode->crackSem, 1, NULL);
#endif
}

//ap should be a valid BssidList node or NULL
void addPacket(BssidList *apNode, PacketInfo *pi, int isData) {
   if (!apNode) {
      apNode = bssidFind(pi->bssid);
      if (!apNode) {   
         apNode = addBssid(pi);
      }
   }
   if (apNode->ap && apNode->ap->cracked) return;   //save time if ap is already cracked
   if (!apNode->usingWep && pi->wep) {
      addWep(apNode);
   }
   if (pi->channel > 0) {
      apNode->channel = pi->channel;
   }
   if (apNode->usingWep && isData) {
      memcpy(apNode->lastiv, pi->iv, 3);
      apNode->numEncrypted++;
      if (pi->pack) {
         enqueuePacket(apNode->ap, pi->pack);
         checkThread(apNode);
      }
      addKorekIV(apNode, pi);
   }
   apNode->lastSeen = pi->rxTime;
   apNode->numPackets++;
}

void addWep(BssidList *apNode) {
   apNode->usingWep = 1;
   apNode->ap = newCrackNode(apNode);
#ifndef WIN32
   sem_init(&(apNode->crackSem), 0, 1);
#else
   apNode->crackSem = CreateSemaphore(NULL, 1, 1, NULL);
#endif
}

//check for non-existence of bssid prior to calling this please
BssidList *addBssid(PacketInfo *pi) {
   BssidList *temp = (BssidList*) calloc_r(1, sizeof(BssidList));
   memcpy(temp->bssid, pi->bssid, 6);
   temp->channel = pi->channel;
   strncpy(temp->name, pi->name, 33);
   temp->name[32] = 0;
   temp->hasName = temp->name[0] != 0;
   temp->rownum = tail ? tail->rownum + 1 : 0;
   if (tail) {
      tail->next = temp;
   }
   else {
      head = temp;
   }
   tail = temp;
   if (pi->wep) {
      temp->usingWep = 1;
      temp->ap = newCrackNode(temp);
#ifndef WIN32
      sem_init(&(temp->crackSem), 0, 1);
#else
      temp->crackSem = CreateSemaphore(NULL, 1, 1, NULL);
#endif
   }
   return temp;
}

void clearList() {
   BssidList *temp = head, *next;
#ifndef WIN32
   void *result;
#endif
   for (; temp; temp = next) {
      next = temp->next;
      if (temp->crackerThread) {
         temp->ap->die = 1;
#ifndef WIN32
         pthread_join(temp->crackerThread, &result);
#else
         WaitForSingleObject(temp->crackerThread, INFINITE);
#endif
         destroyCrackNode(temp->ap);
      }
      free_r(temp);
   }
   listCount = 0;
   head = tail = NULL;
}

