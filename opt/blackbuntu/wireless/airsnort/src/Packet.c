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

#ifndef WIN32
#include <semaphore.h>
#else
#include <windows.h>
#endif
#include "Packet.h"
#include "bssidlist.h"
#include "crack.h"

void enqueuePacket(CrackNode *ap, Packet *p) {
#ifndef WIN32
   sem_wait(&(ap->pktSem));
#else
   WaitForSingleObject(ap->pktSem, INFINITE);
#endif
   ap->data->queueLen++;
//fprintf(stderr, "queueLen = %d\n", ap->data->queueLen);
   p->next = ap->queue;
   ap->queue = p;
#ifndef WIN32
   sem_post(&(ap->pktSem));
#else
   ReleaseSemaphore(ap->pktSem, 1, NULL);
#endif
}

Packet *dequeuePacket(CrackNode *ap) {
   Packet *result;
#ifndef WIN32
   sem_wait(&(ap->pktSem));
#else
   WaitForSingleObject(ap->pktSem, INFINITE);
#endif
   result = ap->queue;
   if (result) {
      ap->queue = result->next;
      ap->data->queueLen--;
      result->next = NULL;
   }
#ifndef WIN32
   sem_post(&(ap->pktSem));
#else
   ReleaseSemaphore(ap->pktSem, 1, NULL);
#endif
   return result;
}
