#ifndef _HASH_H
#define _HASH_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <sys/types.h>

#ifdef __GNUC__
#define ALIGNED(x) __attribute__((aligned(x)))
#else
#define ALIGNED(x)
#endif


typedef struct {
	union {
		uint32_t md5_h[4];
		uint32_t sha1_h[5];
		uint32_t sha256_h[8];
		uint64_t sha512_h[8];
		//uint64_t sha3_h[25];
	};
} hash_t ALIGNED(32);

typedef void (hash_init_fn)(hash_t*);
typedef void (hash_block_fn)(const uint8_t* ptr, hash_t*);
typedef void (hash_calc_fn)(const uint8_t* ptr, size_t chunk, size_t final, hash_t*);
typedef char* (hash_hexout_fn)(char* buf, const hash_t*);
typedef unsigned char* (hash_beout_fn)(unsigned char* buf, const hash_t*);

typedef struct {
	const char* name;
	hash_init_fn *hash_init;
	hash_block_fn *hash_block;
	hash_calc_fn *hash_calc;
	hash_hexout_fn *hash_hexout;
	hash_beout_fn *hash_beout;
	unsigned int blksz;
	unsigned int hashln; /* in bytes */
} hashalg_t;

#include <string.h>
static inline 
int cmp_hash(const hash_t *h1, const hash_t *h2, int bits)
{	
	return memcmp((unsigned char*)(h1->sha512_h), (unsigned char*)(h2->sha512_h), bits/8);
}

#endif
