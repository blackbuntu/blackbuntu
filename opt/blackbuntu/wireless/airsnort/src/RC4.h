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

#ifndef __RC4_H
#define __RC4_H

#define IV_SIZE 3

#define N 256

extern unsigned char Identity[N];

typedef struct RC4_t {
  unsigned char S[N];
  unsigned char i, j;
} RC4;

void RC4init(RC4 *this);
void keyStep(RC4 *this, unsigned char *K, int l);
void keyWith(RC4 *this, unsigned char *K, int l);
int step(RC4 *this);
int SInverse(RC4 *this, int x);
int keyGuess(RC4 *this, int B,int out);
int isOk(RC4 *this, int B);
int tryIV(RC4 *this, unsigned char *key, int B,int out);
void setupIdentity(void);

typedef struct Sample_t {
  unsigned char iv[3];
  unsigned char firstByte;
  struct Sample_t *next;
} Sample;

#define RES_BREADTH_EXCEEDED -1
#define RES_FAILURE 0
#define RES_SUCCESS 1

#endif

