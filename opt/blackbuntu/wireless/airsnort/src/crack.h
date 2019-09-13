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


#ifndef __CRACKER_H
#define __CRACKER_H

#include <gtk/gtk.h>
#ifndef WIN32
#include <semaphore.h>
#else
#include <windows.h>
#endif
#include "RC4.h"
#include "Packet.h"
#include "korek.h"

struct BssidList_t;

typedef struct CrackNode_t {
   int cracked;
   unsigned char ssid[6];
   int csamples[13];
   int ksamples;
   int tries;
   int die;

   Sample *samples[13];
   unsigned char curGuess[16]; //handle both key sizes
   unsigned char theKey[13]; //results of a crack
   char how[3];
   Packet *queue;
   Packet *pkts;

#ifndef WIN32
   sem_t node_sem;
   sem_t pktSem;
#else
   HANDLE node_sem;
   HANDLE pktSem;
#endif
   struct BssidList_t *data;

   //this is the aircrack implementation stuff
   buff_t ivbuf;
   int k_die;
   int nb_ivs, num_ivs;
   unsigned char *unique;
   byte_stat *wpoll;
   unsigned char *wepkey;       /* the current chosen WEP key */
   int *fudge;                  /* bruteforce level (1 to 256) */
   int *depth;                  /* how deep we are in the fudge */
} CrackNode;

void setKey(CrackNode *cn, unsigned char *key, int len, char how);
CrackNode *newCrackNode(struct BssidList_t *owner);
void destroyCrackNode(CrackNode *ap);
int addCrackPacket(CrackNode *ap, Packet *p);

int classify(unsigned char *p);
int freq_compare(const void *a,const void *b);
int tryByte(CrackNode *this, int which, int breadth);
int addSample(CrackNode *this, unsigned char *iv, unsigned char byte);
int checkKey(Packet *this, unsigned char *key, int len);
void destroyPacketList(Packet *p);
void destroySampleList(Sample *s);


#ifndef WIN32
void *cracker(void *);
#else
DWORD WINAPI cracker(void *);
#endif

#endif
