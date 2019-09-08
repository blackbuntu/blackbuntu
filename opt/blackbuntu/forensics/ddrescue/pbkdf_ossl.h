/* pbkdf_ossl.h
 * 
 * header for (weak!) openSSL compatible key derivation
 */

#ifndef _PBKDF_OSSL_H
#define _PBKDF_OSSL_H

#include "hash.h"

int pbkdf_ossl(hashalg_t *hash, unsigned char* pwd,  int plen,
				unsigned char* salt, int slen,
	     unsigned int iter, unsigned char* key,  int klen,
				unsigned char* iv,   int ivlen);

#endif

