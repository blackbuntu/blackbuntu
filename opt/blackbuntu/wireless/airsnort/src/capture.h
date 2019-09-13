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


#ifndef __CAPTURE_H
#define __CAPTURE_H

#ifndef WIN32
#include <stdint.h>
#include <pcap.h>
#else
#include <windows.h>
#endif //WIN32

#include "PacketSource.h"
#include "Packet.h"

//data that is the same for all types of packets
typedef struct PacketInfo_t {
//data that varies based on what type of packet it is
  const unsigned char *raw;    //pointer to the start of the raw packet data
  const unsigned char *bssid;  //pointer to the AP bssid
  const unsigned char *sta;    //pointer to the sta 
  const unsigned char *iv;     //pointer to the frame body

  char name[33];            //ssid name if present
  int channel;           //receive channel for the packet
  time_t rxTime;
  int wep;               //was this packet encrypted?
  Packet *pack;          //bundled packet data for 'interesting' packets
} PacketInfo;

typedef struct CaptureArg_t {
   PacketSource *src;
   int offset;
} CaptureArg;

#ifndef WIN32
void *capture(void *arg);
#else
DWORD WINAPI capture(void *arg);
#endif

#endif
