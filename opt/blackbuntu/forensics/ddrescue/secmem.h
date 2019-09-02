/** secmem.h
 *
 * Declare functions and structures for secure storage 
 */

#ifndef _SECMEM_H
#define _SECMEM_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

typedef struct _roundkey {
	unsigned char data[16];
} roundkey;

typedef struct _ciphblk {
	unsigned char data[32];
} ciphblk;

typedef struct _sec_fields {
	/* PRNG state */
	unsigned char prng_state[256];
	/* Up to 256 bit symmetric keys */
	unsigned char userkey1[32];
	unsigned char userkey2[32];
	/* @320: Enough for 38 rounds of en/decryption with 16byte roundkeys */
	roundkey ekeys[40];
	roundkey dkeys[40];
	roundkey xkeys[40];
	/* @2240: Hashing buffer */
	unsigned char hashbuf1[128];
	unsigned char hashbuf2[128];
	/* @2496: IVs */
	unsigned char nonce1[32];
	unsigned char nonce2[32];
	ciphblk iv1;	/* ctr */
	ciphblk iv2;
	/* @2624: Salt + Password for pbkdf2 ... */
	unsigned char salt[64];
	unsigned char passphr[128];
	/* @2816: char buffer, enough for 512bit hash/key in hex */
	char charbuf1[144];
	/* @2960: one block */
	unsigned char blkbuf1[16];
	/* @2976: data buffer for incomplete blocks */
	unsigned char databuf1[32];
	/* @3008: four blocks (64B) */
	unsigned char blkbuf2[64];
	/* @3072: buffer up to 512 bytes */
	unsigned char databuf2[512];
	
} sec_fields;

sec_fields* secmem_init();
void secmem_release(sec_fields*);

extern sec_fields *crypto;

#endif
