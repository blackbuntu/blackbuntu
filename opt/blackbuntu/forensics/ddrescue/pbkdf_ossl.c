/* openSSL key derivation: pbkdf_ossl.c
 * 
 * not recommended; weak and so fast that it can be easily
 * brute-forced. Provided for compatibility.
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 9/2015
 * License: GNU GPL v2 or v3 (at your option)
 */

#include "pbkdf_ossl.h"
#include "md5.h"
#include <stdlib.h>
#include <assert.h>
#include <endian.h>
#include <stdint.h>

#define MIN(a,b) ((a)<(b)? (a): (b))

static inline void memcpy_nhash(hashalg_t *hash, uint8_t *buf, hash_t *hv, size_t hln, size_t off)
{
	if (off == 0 && hln == hash->hashln)
		hash->hash_beout(buf, hv);
	else {
		uint8_t tmp[64];
		hash->hash_beout(tmp, hv);
		memcpy(buf, tmp+off, hln);
		memset(tmp, 0, hash->hashln);
		asm("":::"memory");
	}
}

int pbkdf_ossl(hashalg_t *hash, unsigned char* pwd,  int plen,
				unsigned char* salt, int slen,
	     unsigned int iter, unsigned char* key,  int klen,
				unsigned char* iv,   int ivlen)
{
	unsigned char* hbuf = malloc(hash->hashln+plen+slen);
	unsigned int off = 0;
	unsigned cnt = 0;
	assert(iter == 1);
	hash_t hv;
	while (off < klen+ivlen) {
		int hbln = plen+slen;
		/* Compose buffer to be hashed */
		if (!cnt) {
			memcpy(hbuf, pwd, plen);
			if (slen)
				memcpy(hbuf+plen, salt, slen);
		} else {
			hbln = plen+slen+hash->hashln;
			hash->hash_beout(hbuf, &hv);
			memcpy(hbuf+hash->hashln, pwd, plen);
			if (slen)
				memcpy(hbuf+hash->hashln+plen, salt, slen);
		}
		hash->hash_init(&hv);
		//for (int i = 0; i <= cnt; ++i)
		hash->hash_calc(hbuf, hbln, hbln, &hv);
		/* Fill in result */
		if (off+hash->hashln < klen)
			memcpy_nhash(hash, key+off, &hv, hash->hashln, 0);
		else if (off >= klen) {
			memcpy_nhash(hash, iv+off-klen, &hv, MIN(hash->hashln, ivlen+klen-off), 0);
		} else {
			memcpy_nhash(hash, key+off, &hv, klen-off, 0);
			memcpy_nhash(hash, iv, &hv, MIN(hash->hashln-klen+off, ivlen), klen-off);
		}
		off += hash->hashln;
		++cnt;
	}
	memset(hbuf, 0, hash->hashln+plen+slen);
	asm("":::"memory");
	free(hbuf);
	return 0;
}
