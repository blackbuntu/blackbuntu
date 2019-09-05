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
 * crackSem fix contributed by Nick Petroni
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#include <pcap.h>
#else
#include <windows.h>
#endif
#include "bssidlist.h"
#include "crack.h"
#include "crc-32.h"
#include "utils.h"

extern int breadth40;
extern int breadth128;
extern int maxBreadth;

int maxTries = 4;

//#define DEBUG_CRACK
#ifdef DEBUG_CRACK
//return a string version of the hex bytes held in key
//bytes are separated by a colon
char *hexKey(unsigned char *key, int size) {
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
char *ascKey(unsigned char *key, int size) {
   static char str[15];
   char *ptr = str;
   int i = 0;
   for (; i < size; i++, ptr++) {
      sprintf(ptr, "%c", key[i] >= 32 && key[i] < 127 ? key[i] : '.');
   }
   return str;
}
#endif

//call this to set the key after a successful crack
//how should be a character indicating what type of crack
//'A' indicates original airsnort weak IV method
//'K' indicates Korek/aircrack method
void setKey(CrackNode *cn, unsigned char *key, int len, char how) {
   if (len != 5 && len != 13) return;
#ifndef WIN32
   sem_wait(&cn->node_sem);
#else
   WaitForSingleObject(cn->node_sem, INFINITE);
#endif
   if (cn->cracked == 0) {
      cn->cracked = len;
      memcpy(cn->theKey, key, len);
      cn->how[0] = how;
   }
#ifndef WIN32
   sem_post(&cn->node_sem);   
#else
   ReleaseSemaphore(cn->node_sem, 1, NULL);
#endif
}

//deallocates a linked list of Packets
void destroyPacketList(Packet *p) {
   Packet *cur = p, *next;
   while (cur) {
      next = cur->next;
      free_r(cur->buf);
      free_r(cur);
      cur = next;
   }
}

//Deallocates a linked list of Samples
void destroySampleList(Sample *s) {
   Sample *cur = s, *next;
   while (cur) {
      next = cur->next;
      free_r(cur);
      cur = next;
   }
}

//Adds a packet from the packet queue into the data being maintained for
//a particular access point.  If the Packet* contained in the queued node
//is NULL, this is actually a signal from the gui to stop cracking that 
//particular access point.

int addCrackPacket(CrackNode *ap, Packet *pkt) {
   int isInteresting;
   if (!pkt->len) {
      //this is actually the signal to destroy the cracker thread
      free_r(pkt);
      return 1;     
   }
   isInteresting = addSample(ap, pkt->buf, (unsigned char)((pkt->buf)[4] ^ 0xAA));
   if (isInteresting != -1) {
      (ap->csamples)[isInteresting]++;
      ap->data->interesting++;
   }

   if (ap->ksamples < 10 && pkt->len > 5) {  
      //test for len > 5 to accomodate load from file
      pkt->next = ap->pkts;
      ap->pkts = pkt;
      ap->ksamples++;
   }
   else {
      free_r(pkt->buf);
      free_r(pkt);
   }
   return 0;
}

CrackNode *newCrackNode(struct BssidList_t *owner) {
   CrackNode *ap = (CrackNode *) calloc_r(1, sizeof(CrackNode));
   ap->data = owner;
#ifndef WIN32
   sem_init(&ap->pktSem, 0, 1);
   sem_init(&ap->ivbuf.sem, 0, 1);
   sem_init(&ap->node_sem, 0, 1);
#else
   ap->pktSem = CreateSemaphore(NULL, 1, 1, NULL);
   ap->ivbuf.sem = CreateSemaphore(NULL, 1, 1, NULL);
   ap->node_sem = CreateSemaphore(NULL, 1, 1, NULL);
#endif
   return ap;
}

void destroyCrackNode(CrackNode *ap) {
   int i = 0;
   destroyPacketList(ap->queue);
   destroyPacketList(ap->pkts);
   for (; i < 13; i++) {
      destroySampleList(ap->samples[i]);
   }
#ifdef WIN32
   CloseHandle(ap->pktSem);
   CloseHandle(ap->ivbuf.sem);
   CloseHandle(ap->node_sem);
#endif
}

//This is the thread function for the cracker thread.  Currently it sleeps until it
//recieves a signal from the capture thread that more interesting packets are 
//available.  The capture thread sends this signal every time it captures 10 new
//packets for a given AP.  The crack thread first reads all available packets 
//from the packet queue, then then tries a 40 bit crack followed by a 128 bit crack.
//If a key is cracked, the data is sent to the gui thread via the key queue 
#ifndef WIN32
void *cracker(void *arg) {
#else
DWORD WINAPI cracker(void *arg) {
#endif
   CrackNode *ap = (CrackNode *) arg;
   int r;
   Packet *p;
   while ((p = dequeuePacket(ap)) != NULL) {
      if (addCrackPacket(ap, p)) {
#ifndef WIN32
         sem_wait(&(ap->data->crackSem));
         ap->data->crackerThread = 0;
         sem_post(&(ap->data->crackSem));
         pthread_exit(NULL);
#else
         WaitForSingleObject(ap->data->crackSem, INFINITE);
         ap->data->crackerThread = 0;
         ReleaseSemaphore(ap->data->crackSem, 1, NULL);
         ExitThread(0);
#endif
      }
   }
   if (ap->data->newBreadth || ap->data->lastInteresting != ap->data->interesting) {
      ap->data->lastInteresting = ap->data->interesting;
      if (!(ap->cracked)) {
         r = tryByte(ap, 0, 0);
         if (r >= RES_SUCCESS) {
            setKey(ap, ap->curGuess+3, r, 'A');
         }
      }
      ap->data->newBreadth = 0;
   }
#ifndef WIN32
   sem_wait(&(ap->data->crackSem));
   ap->data->crackerThread = 0;
   sem_post(&(ap->data->crackSem));
   checkThread(ap->data);
   pthread_exit(NULL);
#else
   WaitForSingleObject(ap->data->crackSem, INFINITE);
   ap->data->crackerThread = 0;
   ReleaseSemaphore(ap->data->crackSem, 1, NULL);
   checkThread(ap->data);
   return 0;
#endif
}

/*
 * checkKey - determine whether a particular key guess represents an actual key
 * parm    - list, a list of packets encrypted with the same key 
 *         - k, the key we wish to try against the packet list
 *         - klen, the length of k
 * return  - RES_SUCCESS - the key successfully decrypted every packet in the list
 *         - RES_FAILURE - the key did not decrypt every packet in the list
 *
 * Decrypt sample packets with the supplied key checking the CRC value of each
 * decrypted packet.  If all CRCs are valid, we claim we have a valid key.
 */
int checkKey(Packet *list, unsigned char *k, int klen) {
   unsigned char key[16], *buf;
   unsigned char * data;
   RC4 rc;
   int i;
   Packet *cur = list;
  //debugging code to have airsnort report each key it is attempting
#ifdef DEBUG_CRACK
   fprintf(stderr, "Trying: %s - %s\n", ascKey(k, klen), hexKey(k, klen));
#endif
   memcpy(key+3, k, klen);
   while (cur) {  //loop through all packets
      data = cur->buf + 4;
      RC4init(&rc);
      buf = (unsigned char*) malloc_r(sizeof(unsigned char) * (cur->len - 4));
      memcpy(key, cur->buf, 3); //copy packet IV into key
      keyWith(&rc, key, klen+3); 
      for(i = 0; i < cur->len - 4; i++) {
         buf[i] = data[i] ^ step(&rc);
      }
//      if (doFCS(buf, cur->len - 8) != 0xdebb20e3) {
      if (memcmp(buf, "\xAA\xAA\x03\x00\x00\x00", 6) && 
          (doFCS(buf, cur->len - 4) != 0xdebb20e3)) {
         free_r(buf);
	 return(RES_FAILURE);
      }
      free_r(buf);
      cur = cur->next;
   }
   return klen;
}

typedef struct freq_t_t {
  int index;
  int score;
} freq_t;

int freq_compare(const void *a,const void *b) {
  return(((freq_t *) b)->score - ((freq_t *) a)->score);
} 

/*
 * tryByte - determine which key byte an iv is useful in resolving
 * parm    - this, a pointer to the BSSID data structure.  This is 
 *           the BSSID we are trying to crack.
 *         - which, the key byte that we are currently guessing
 *         - breadth, the width of the n-ary search tree (i.e. n)
 *         - keySize, the number of bytes in the key we are looking for
 *           also the maximum depth of the search tree.
 * return  - RES_SUCCESS - a key was found and resides in this->curGuess
 *         - RES_FAILURE - fewer than breadth valid key bytes gueses were
 *           found at depth which
 *         - RES_BREADTH_EXCEEDED - the maximum breadth has been reached
 *           without finding a key
 *
 * This is a recurssive funtion that searches for a valid key associated
 * with the specified BSSID (CrackNode).  It conducts a depth first search
 * for a key of length keySize by looking at the breadth most likely key
 * bytes at each key position.  As an n-ary tree with n == breadth is 
 * searched, the number of keys attempted is breadth ^ keySize (here ^ is
 * used for exponentiation).
 *
 */

int tryByte(CrackNode *this, int which, int outOfBounds) {
  freq_t freq[256];
  int i, r, r2;
  Sample *cur;
  RC4 rc;
  int treeBreadth = which >= 5 ? breadth128 : maxBreadth;

  //provide a means to terminate a search as threads spend a long time in 
  //this particular function
  if (this->die) return RES_FAILURE;

  //if we have developed an entire key, give it a try
  if (which == 5) {
     if ((r = checkKey(this->pkts, this->curGuess+3, 5)) >= RES_SUCCESS) {
        return r;  //found a 40 bit key
     }
  }
  else if (which == 13) {
     return checkKey(this->pkts, this->curGuess+3, 13);
  }

  if (which >= 5 && outOfBounds) return RES_BREADTH_EXCEEDED;

  //initialize frequency counting array
  for (i = 0; i < 256; i++) {
     freq[i].score = 0;
     freq[i].index = i;
  }
  //get the linked list of IV samples for this key byte
  cur = this->samples[which];
  while (cur) {
    //set the IV portion of the current key guess
    memcpy(this->curGuess, cur->iv, 3);
    RC4init(&rc);
    //run the RC4 setup
    r2 = tryIV(&rc, this->curGuess, which, cur->firstByte);
    if (r2 >= 0) {
       //RC4 setup resulted in a resolved condition and r2 is the the value
       //'Out' from FMS 7.1
       freq[r2].score += 1000;

       //show slight favoritism to ASCII printable key bytes
       if (r2 >= 32 && r2 <= 127) freq[r2].score += 5;
    }
    cur = cur->next;
  }
  //sort the scores for the most likely key bytes
  qsort(freq, 256, sizeof(freq_t), freq_compare);

  //in the resulting sorted array of likely key byte values we look at only the
  //first 'breadth' values.  This loop generates the depth first search for our
  //n-ary tree
  for(i = 0; i < treeBreadth; i++) {
    if (freq[i].score == 0) return RES_FAILURE;
    this->curGuess[3 + which] = freq[i].index;
    r = tryByte(this, which + 1, ((i + 1) > breadth128) || outOfBounds);
    if (r >= RES_SUCCESS) return r;
  }
  return RES_BREADTH_EXCEEDED;
}

/*
 * classify - determine which key byte an iv is useful in resolving
 * parm     - p, pointer to the first byte of an IV
 * return   -  n - this IV is weak for byte n of a WEP key
 *            -1 - this IV is not weak for any key bytes
 *
 * This function tests for IVs that are known to satisfy the criteria
 * for a weak IV as specified in FMS section 7.1
 *
 */
int classify(unsigned char *p) {
   unsigned char sum, k;

   //test for the FMS (A+3, N-1, X) form of IV
   if (p[1] == 255 && p[0] > 2 && p[0] < 16) {
      return p[0] - 3;
   }

   //test for other IVs for which it is known that
   // Si[1] < i and (Si[1] + Si[Si[1]]) = i + n  (see FMS 7.1)
   sum = p[0] + p[1];
   if (sum == 1) {
      if (p[2] <= 0x0A) {
         return p[2] + 2;
      }
      else if (p[2] == 0xFF) {
         return 0;
      }
   }
   k = 0xFE - p[2];
   if (sum == k && (p[2] >= 0xF2 && p[2] <= 0xFE && p[2] != 0xFD)) {
      return k;
   }
   return -1;
}

/*
 * addSample - determine if an IV is weak and if it is, add it to the
 *             collection of key byte samples for a particular BSSID
 * parm      - this, a pointer to the BSSID data structure
 *           - iv, the IV from the current packet
 *           - byte, the first data byte associated with the current packet
 * return    -  n - this IV was needed and weak for key byte n
 *             -1 - we have already seen this IV or it is not weak
 *
 */
int addSample(CrackNode *this, unsigned char *iv, unsigned char byte) {
  Sample *s;
 
  //determine whether this is a weak IV
  int loc = classify(iv);
  if (loc == -1) return -1;
  s = this->samples[loc];

  //check all other samples for this key byte to see if we have already
  //seen this particular IV
  while(s) {
    if (s->iv[0] == iv[0] && s->iv[1] == iv[1] && s->iv[2] == iv[2]) {
       return(-1);  //if we already have a sample at that spot return
    }
    s = s->next;
  }

  //We have not seen this IV before, save it in the list of samples for
  //key byte loc
  s = (Sample*) malloc_r(sizeof(Sample));
  memcpy(s->iv, iv, 3);
  s->firstByte = byte;
  s->next = this->samples[loc];
  this->samples[loc] = s;
  return(loc);
}

