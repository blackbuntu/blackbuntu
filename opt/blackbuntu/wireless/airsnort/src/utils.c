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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <semaphore.h>
#else
#include <windows.h>
#endif
#include "capture.h"

#ifndef WLAN_DEVNAMELEN_MAX
#ifndef WIN32
#define WLAN_DEVNAMELEN_MAX 16
#else
#define WLAN_DEVNAMELEN_MAX 128
#endif  //WIN32
#endif  //WLAN_DEVNAMELEN_MAX


static char rcname[] = "/.airsnortrc";

extern int breadth40;
extern int breadth128;
extern int cardType;
extern unsigned int chan;
extern unsigned int spinchan;
extern char *cards[];

#ifndef WIN32
sem_t malloc_sem; 
#else
HANDLE malloc_sem; 
#endif

void *malloc_r(unsigned int size) {
   void *result;
#ifndef WIN32
   sem_wait(&malloc_sem); 
#else
   WaitForSingleObject(malloc_sem, INFINITE); 
#endif
   result = malloc(size);
#ifndef WIN32
   sem_post(&malloc_sem);
#else
   ReleaseSemaphore(malloc_sem, 1, NULL); 
#endif
   return result;
}

void *calloc_r(unsigned int nmemb, unsigned int size) {
   void *result;
#ifndef WIN32
   sem_wait(&malloc_sem); 
#else
   WaitForSingleObject(malloc_sem, INFINITE); 
#endif
   result = calloc(nmemb, size);
#ifndef WIN32
   sem_post(&malloc_sem);
#else
   ReleaseSemaphore(malloc_sem, 1, NULL); 
#endif
   return result;
}

void free_r(void *ptr) {
#ifndef WIN32
   sem_wait(&malloc_sem); 
#else
   WaitForSingleObject(malloc_sem, INFINITE); 
#endif
   free(ptr);
#ifndef WIN32
   sem_post(&malloc_sem);
#else
   ReleaseSemaphore(malloc_sem, 1, NULL); 
#endif
}

//load user settings from $HOME/.airsnortrc
void loadOpts() {
   char *home = getenv("HOME");
   char *rcfile;
   char buf[128];
   FILE *rc;
   char *index;
   int r, i;
   unsigned int rclen;
   if (home) {
      rclen = strlen(home) + sizeof(rcname);
      rcfile = (char*) malloc_r(rclen);
      if (!rcfile) return;
#ifndef WIN32
      snprintf(rcfile, rclen, "%s%s", home, rcname);
#else
      _snprintf(rcfile, rclen, "%s%s", home, rcname);
#endif
      rc = fopen(rcfile, "r");
      if (rc) {
         while (fgets(buf, 128, rc)) {
            index = strchr(buf, '\n');
            if (index) *index = 0;
            index = strchr(buf, ':');
            if (index) {
               *index = 0;
               if (!strcmp(buf, "dev")) {
                  strncpy(dev, index + 1, WLAN_DEVNAMELEN_MAX);
                  dev[WLAN_DEVNAMELEN_MAX - 1] = 0;
               }
               else if (!strcmp(buf, "driver")) {
                  r = atoi(index + 1);
                  for (i = 0; cards[i]; i++);
                  cardType = (r < 0 || r >= i) ? 0 : r;
               }
               else if (!strcmp(buf, "breadth128")) {
                  r = atoi(index + 1);
                  breadth128 = (r < 1 || r > 20) ? 1 : r;
               }
               else if (!strcmp(buf, "breadth40")) {
                  r = atoi(index + 1);
                  breadth40 = (r < 1 || r > 20) ? 1 : r;
               }
               else if (!strcmp(buf, "channel")) {
                  r = atoi(index + 1);
                  chan = (r < 1 || r > 11) ? 6 : r;
                  spinchan = chan;
               }
            }
         }
         fclose(rc);
      }
      free_r(rcfile);
   }
}

//save user settings to $HOME/.airsnortrc
void saveOpts() {
   char *home = getenv("HOME");
   char *rcfile;
   FILE *rc;
   unsigned int rclen;
   if (home) {
      rclen = strlen(home) + sizeof(rcname);
      rcfile = (char*) malloc_r(rclen);
      if (!rcfile) return;
#ifndef WIN32
      snprintf(rcfile, rclen, "%s%s", home, rcname);
#else
      _snprintf(rcfile, rclen, "%s%s", home, rcname);
#endif
      rc = fopen(rcfile, "w");
      if (rc) {
         fprintf(rc, "dev:%s\n", dev);
         fprintf(rc, "driver:%d\n", cardType);
         fprintf(rc, "breadth128:%d\n", breadth128);
         fprintf(rc, "breadth40:%d\n", breadth40);
         fprintf(rc, "channel:%d\n", spinchan);
         fclose(rc);
      }
      free_r(rcfile);
   }
}
