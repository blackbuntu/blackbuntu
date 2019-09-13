#ifndef _PBKDF2_H
#define _PBKDF2_H

#include "hash.h"

void memxor(unsigned char* p1, const unsigned char *p2, ssize_t ln);
int hidden_input(int fd, char *buf, int bufln, int stripcrlf);
int hmac(hashalg_t* hash, unsigned char* pwd, int plen,
			  unsigned char* msg, ssize_t mlen,
			  hash_t *hval);
int pbkdf2(hashalg_t *hash,   unsigned char* pwd,  int plen,
			      unsigned char* salt, int slen,
	   unsigned int iter, unsigned char* key,  int klen);

void gensalt(unsigned char* salt, unsigned int slen, const char* fn, const char* ext, size_t flen);
#endif

