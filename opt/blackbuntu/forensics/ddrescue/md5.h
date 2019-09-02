#ifndef _MD5_H
#define _MD5_H

#include "hash.h"
#include <stdint.h>
#include <sys/types.h>

#define MD5_BLKSZ 64

void md5_init(hash_t* ctx);
void md5_64(const uint8_t *ptr, hash_t* ctx);
void md5_calc(const uint8_t *ptr, size_t chunk_ln, size_t final_ln, hash_t* ctx);
char* md5_hexout(char *buf, const hash_t* ctx);
unsigned char* md5_beout(unsigned char *buf, const hash_t* ctx);

#define MD5_HALG_T { "md5", md5_init, md5_64, md5_calc, md5_hexout, md5_beout, 64, 16 }

#endif

