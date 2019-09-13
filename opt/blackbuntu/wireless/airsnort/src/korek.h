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

#ifndef __KOREK_H
#define __KOREK_H

#ifdef WIN32
#include <windows.h>
#endif

typedef struct {
   unsigned char *buf;
   unsigned int alloc;
   unsigned int used;
#ifndef WIN32
   sem_t sem;
#else
   HANDLE sem;
#endif
} buff_t;

typedef struct {
   int index;
   int votes;
} byte_stat;               /* FMS + Korek attacks: stats.  */

#endif
