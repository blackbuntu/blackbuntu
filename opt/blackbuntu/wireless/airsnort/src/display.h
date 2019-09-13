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

#ifndef __DISPLAY_H
#define __DISPLAY_H

#include <gtk/gtk.h>
#include "bssidlist.h"

enum {
   CRACK_COL, SSID_COL, NAME_COL, WEP_COL, TIME_COL,
   IV_COL, CHAN_COL, TOTAL_COL, ENCRYPTED_COL, INTERESTING_COL,
   UNIQUE_COL, PWHEX_COL, PWASC_COL, NUM_COLS
};

void addList(BssidList *ptr);
void updateList(BssidList *ptr, GtkTreeIter *iter);
int update(gpointer data);

#endif
