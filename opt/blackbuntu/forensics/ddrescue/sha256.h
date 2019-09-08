#ifndef _SHA256_H
#define _SHA256_H

#include "hash.h"

void sha256_init(hash_t *ctx);
void sha224_init(hash_t *ctx);
void sha256_64(const uint8_t* msg, hash_t* ctx);
void sha256_calc(const uint8_t *ptr, size_t chunk_ln, size_t final_len, hash_t *ctx);
char* sha256_hexout(char *buf, const hash_t* ctx);
char* sha224_hexout(char *buf, const hash_t* ctx);
unsigned char* sha256_beout(unsigned char *buf, const hash_t* ctx);
unsigned char* sha224_beout(unsigned char *buf, const hash_t* ctx);

#define SHA256_HALG_T { "sha256", sha256_init, sha256_64 , sha256_calc, sha256_hexout, sha256_beout,  64, 32 }
#define SHA224_HALG_T { "sha224", sha224_init, sha256_64 , sha256_calc, sha224_hexout, sha224_beout,  64, 28 }

#endif
