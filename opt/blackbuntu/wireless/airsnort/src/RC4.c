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
#include <string.h>
#include <stdlib.h>
#include "RC4.h" 

#define NORM(x) ((x) & (N-1))
#define SWAP(i,j) do {int t = this->S[i]; this->S[i] = this->S[j]; this->S[j] = t;} while(0)

unsigned char Identity[N];

void RC4init(RC4 *this) {
  memcpy(this->S, Identity, sizeof(unsigned char) * N);
  this->i = this->j = 0;
}

void keyStep(RC4 *this, unsigned char *K,int l) {
  this->j += (this->S)[this->i] + K[this->i % l];
  SWAP(this->i, this->j);
  (this->i)++;
}

void keyWith(RC4 *this, unsigned char *K, int l) {
  int a;
  for (a = 0; a < N; a++) keyStep(this, K, l);
  this->i = this->j = 0;
}


int step(RC4 *this) {
  (this->i)++;
  this->j += this->S[this->i];
  SWAP(this->i, this->j);
  return (this->S[NORM(this->S[this->i] + this->S[this->j])]);
}

/*
 * The S ^ -1 function from FMS 7.1
 */
int SInverse(RC4 *this, int x) {
  int a;
  for(a = 0; a < N; a++) {
    if (this->S[a] == x) return(a);
  }
  printf("Reality Error #1");
  exit(1);
}

/* Returns the key guess, the assumptions are as follows:
   1. The IV is assumed to be IV_SIZE bytes, B is which byte of the key we seek
   2. The system is in a 'resolved state' and is at time IV_SIZE+B of keying
   3. out is the first output byte of the cypher 
   This function returns the value 'Out' from FMS 7.1
*/
int keyGuess(RC4 *this, int B,int out) { 
  return(NORM(SInverse(this, out) - this->j - this->S[IV_SIZE+B]));
}

/* Checks if the system is in a state where we can use keyGuess. This is from
   paragraph 1 of FMS section 7.1
   Assumptions:
   1. The IV is IV_SIZE bytes
   2. B is byte of the key we seek
   3. In key setup as of time IV+B 
*/
int isOk(RC4 *this, int B) {
  return(this->S[1] < IV_SIZE &&
	 NORM(this->S[1] + this->S[this->S[1]]) == IV_SIZE + B);
}

/* Trys to guess key at location B, Assumptions:
   IV_SIZE is the size of the initialization vector.
   key is the Initialization Vector+Key
   key[x] where x<B+IV_SIZE is known, and in unsigned char *key.
   out is the first byte of the cypher output.

   This function returns -1 if no guess can be made (often), and even
   is made it might be wrong, but the chances of it being right are >= 5%, so
   just get a bunch of guesses and look for the answer that shows up the most
*/
int tryIV(RC4 *this, unsigned char *key, int B, int out) {
  int a;
  for(a = 0; a < IV_SIZE; a++) {
    keyStep(this, key, 16);
  }
  if (!isOk(this, B)) return(-1);
  for(a = IV_SIZE; a < IV_SIZE+B; a++) {
    keyStep(this, key, 16);
  }
  return keyGuess(this, B, out);
}

void setupIdentity() {
  int a;
  for(a = 0; a < N; a++) {
    Identity[a] = a;
  }
}
 

