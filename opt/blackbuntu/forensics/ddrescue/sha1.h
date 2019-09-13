#ifndef _SHA1_H
#define _SHA1_H

#include "hash.h"

void sha1_init(hash_t *ctx);
void sha1_64(const uint8_t* msg, hash_t* ctx);
void sha1_calc(const uint8_t *ptr, size_t chunk_ln, size_t final_len, hash_t *ctx);
char* sha1_hexout(char *buf, const hash_t* ctx);
unsigned char* sha1_beout(unsigned char *buf, const hash_t* ctx);

#define SHA1_HALG_T { "sha1", sha1_init, sha1_64, sha1_calc, sha1_hexout, sha1_beout, 64, 20 }

#endif
