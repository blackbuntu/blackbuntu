/*
    This file is part of AirSnort.

    Copyright (C) 2004 Snax

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
 * This file gets us around the lack of unistd.h on Windows systems.
 * We could do this using appropriate ifndefs in all files requiring unistd.h
 * EXCEPT that glade-2 auto generates the interface and support files each
 * of which require unistd.h and every time the files are generated our
 * ifndefs get wiped out.  So we just let them include this instead.
 */

#ifndef __MY_UNISTD_H
#define __MY_UNISTD_H

#ifndef WIN32
#include "/usr/include/unistd.h"
#endif

#endif
