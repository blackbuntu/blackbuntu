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

#include <glib.h>
#include <stdio.h>
#include "display.h"
#include "crack.h"
/*
enum {
   CRACK_COL, SSID_COL, NAME_COL, WEP_COL, TIME_COL,
   IV_COL, CHAN_COL, TOTAL_COL, ENCRYPTED_COL, INTERESTING_COL,
   UNIQUE_COL, PWHEX_COL, PWASC_COL, NUM_COLS
};
*/
int listCount;

extern GtkListStore *listStore;
extern GtkTreeModel *listModel;
extern GtkTreeView *listWidget;

//print n bytes of data into str_out as 2 hex digits per 
//byte, each byte separated by a colon 
char *toHex(unsigned char *key, char *str_out, int n) {
   char *ptr = str_out + 2;
   int i = 1;
   sprintf(str_out, "%2.2X", key[0]);
   for (; i < n; i++, ptr += 3) {
      sprintf(ptr, ":%2.2X", key[i]);
   }
   return str_out;
}

//return key as ascii. Non printable ascii characters are
//represented with a '.'
char *toAsc(unsigned char *key, char *key_out, int size) {
   char *ptr = key_out;
   int i = 0;
   for (; i < size; i++, ptr++) {
      sprintf(ptr, "%c", key[i] >= 32 && key[i] < 127 ? key[i] : '.');
   }
   return key_out;
}

char *bssidtostr(const unsigned char *bssid, char *bssid_out) {
   sprintf(bssid_out, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X", 
                    bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
   return bssid_out;
}

char *ivtostr(const unsigned char *iv, char *iv_out) {
   sprintf(iv_out, "%2.2X:%2.2X:%2.2X", iv[0], iv[1], iv[2]);
   return iv_out;
}

//add a new SSID to the list of displayed SSIDs
void addList(BssidList *ptr) {
   char chan[20];
   char pkts[20];
   char crypt[20];
   char resolved[20];
   char unique[20];
   char timeBuf[30];
   char iv[20];
   char bssid[20];
   char *text[NUM_COLS] = {0,bssid,0,0, timeBuf,iv,chan,pkts,crypt,resolved,unique,0,0};
   GtkTreeIter iter;
   int i = 0;

   gtk_list_store_append(listStore, &iter);

   strcpy(timeBuf, ctime(&ptr->lastSeen));
   timeBuf[24] = 0;
   bssidtostr(ptr->bssid, bssid);
   text[NAME_COL] = ptr->name;
   ivtostr(ptr->lastiv, iv);

   *chan = 0;
   if (ptr->channel != -1) {
      sprintf(chan, "%d", ptr->channel);
   }
   sprintf(pkts, "%d", ptr->numPackets);
   sprintf(crypt, "%d", ptr->numEncrypted);
   sprintf(resolved, "%d", ptr->interesting);
   sprintf(unique, "%d", ptr->numUnique);

   for (; i < NUM_COLS; i++) {
      if (text[i]) {
         gtk_list_store_set(listStore, &iter, i, text[i], -1);
      }
   }
}

//update an existing SSID with data collected over the last
//capture interval
void updateList(BssidList *ptr, GtkTreeIter *iter) {
   char buf[50];

   gtk_list_store_set(listStore, iter, NAME_COL, ptr->name, -1);

   gtk_list_store_set(listStore, iter, IV_COL, ivtostr(ptr->lastiv, buf), -1);

   sprintf(buf, "%d", ptr->numPackets);
   gtk_list_store_set(listStore, iter, TOTAL_COL, buf, -1);
   strcpy(buf, ctime(&ptr->lastSeen));
   buf[24] = 0;
   gtk_list_store_set(listStore, iter, TIME_COL, buf, -1);

   if (ptr->channel != -1) {
      sprintf(buf, "%d", ptr->channel);
      gtk_list_store_set(listStore, iter, CHAN_COL, buf, -1);
   }

   if (ptr->usingWep) {
     gtk_list_store_set(listStore, iter, WEP_COL, "Y", -1);
     sprintf(buf, "%d", ptr->numEncrypted);
     gtk_list_store_set(listStore, iter, ENCRYPTED_COL, buf, -1);
     sprintf(buf, "%d", ptr->interesting);
     gtk_list_store_set(listStore, iter, INTERESTING_COL, buf, -1);
     sprintf(buf, "%d", ptr->numUnique);
     gtk_list_store_set(listStore, iter, UNIQUE_COL, buf, -1);

     if (ptr->ap->cracked) {
        gtk_list_store_set(listStore, iter, CRACK_COL, ptr->ap->how, -1);
        gtk_list_store_set(listStore, iter, PWHEX_COL, 
                                 toHex(ptr->ap->theKey, buf, ptr->ap->cracked), -1);
        gtk_list_store_set(listStore, iter, PWASC_COL, 
                                 toAsc(ptr->ap->theKey, buf, ptr->ap->cracked), -1);
     }
   }
}

//The timer function installed to periodically update the capture
//statistics in the gui
int update(gpointer data) {
  int i = 0;
  BssidList *temp = head;
  GtkTreeIter iter;

  gtk_tree_model_get_iter_first(listModel, &iter);

  for (; i < listCount; i++, temp = temp->next) {
     updateList(temp, &iter);
     gtk_tree_model_iter_next(listModel, &iter);
  }

  for (; temp; temp = temp->next) {
     addList(temp);
     listCount++;
  }
  return 1;
}

