/** pbkdf2.c
 * 
 * memxor helper
 * hidden input helper
 * calculate hmac of data
 * use it to stretch a password-phrase with salt into
 * a key (using pbkdf2 (pkcs5))
 * gen a salt from a file and a size
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 9/2014
 * License: GPLv2 or v3, at your option
 */

#include "pbkdf2.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <termios.h>

#define MIN(a,b) ((a)<(b)? (a): (b))
#define MAX(a,b) ((a)<(b)? (b): (a))

void memxor(unsigned char* p1, const unsigned char *p2, ssize_t ln)
{
	while ((size_t)ln >= sizeof(unsigned long)) {
		*(unsigned long*)p1 ^= *(unsigned long*)p2;
		ln -= sizeof(unsigned long);
		p1 += sizeof(unsigned long); p2 += sizeof(unsigned long);
	}
	while (ln-- > 0) 
		*p1++ ^= *p2++;
}

int hidden_input(int fd, char *buf, int bufln, int stripcrlf)
{
	struct termios tcflags, tcflags2;
	tcgetattr(fd, &tcflags);
	memcpy(&tcflags2, &tcflags, sizeof(struct termios));
	tcflags2.c_lflag |= ICANON | ECHONL;
	tcflags2.c_lflag &= ~ECHO;
	tcsetattr(fd, TCSANOW, &tcflags2);
	int ln = read(fd, buf, bufln);
	tcsetattr(fd, TCSANOW, &tcflags);
	if (ln <= 0 || !stripcrlf)
		return ln;
	if (buf[ln-1] == '\n')
		--ln;
	if (buf[ln-1] == '\r')
		--ln;
	return ln;
}


int hmac(hashalg_t* hash, unsigned char* pwd, int plen,
			  unsigned char* msg, ssize_t mlen,
			  hash_t *hval)
{
	const unsigned int hlen = hash->hashln; 
	const unsigned int blen = hash->blksz;
	unsigned char ibuf[blen], obuf[blen];
	memset(ibuf, 0x36, blen);
	memset(obuf, 0x5c, blen);
	if ((unsigned)plen > blen) {
		hash_t hv;
		unsigned char pcpy[2*blen];
		memcpy(pcpy, pwd, plen);
		hash->hash_init(&hv);
		hash->hash_calc(pcpy, plen, plen, &hv);
		//memcpy(pwd, &hv, hlen); 
		hash->hash_beout(pwd, &hv);
		pwd[hlen] = 0;
		plen = hlen;
	}
	memxor(ibuf, pwd, plen);
	memxor(obuf, pwd, plen);
	assert(blen >= hlen);
	hash_t ihv;
	hash->hash_init(&ihv);
	hash->hash_block(ibuf, &ihv);
	hash->hash_calc(msg, mlen, blen+mlen, &ihv);
	unsigned char ibe[blen];
	hash->hash_beout(ibe, &ihv);
	hash->hash_init(hval);
	hash->hash_block(obuf, hval);
	hash->hash_calc(ibe, hlen, blen+hlen, hval);
	/* hash->hash_beout(hout, hval); */
#if 0
	fprintf(stderr, "Inner (%i): (%02x %02x %02x %02x %02x %02x ..., %s) = %s\n",
		blen+mlen, ibuf[0], ibuf[1], ibuf[2], ibuf[3], ibuf[4], ibuf[5], msg,
		hash->hash_hexout(0, &ihv));
	fprintf(stderr, "Outer (%i): (%02x %02x %02x %02x %02x %02x ..., %02x %02x %02x %02x ...)\n",
		blen+hlen, obuf[0], obuf[1], obuf[2], obuf[3], obuf[4], obuf[5],
		ibe[0], ibe[1], ibe[2], ibe[3]);
	fprintf(stderr, "HMAC(%s, %s(%i), %s(%i)) = %s\n",
		hash->name, pwd, plen, msg, mlen, hash->hash_hexout(0, hval);
#endif
	return 0;
}



int pbkdf2(hashalg_t *hash,   unsigned char* pwd,  int plen,
			      unsigned char* salt, int slen,
	   unsigned int iter, unsigned char* key,  int klen)
{
	/* TODO: Use secure buffer */
	hash_t hashval;
	const unsigned int hlen = hash->hashln;
	const unsigned int khrnd = 1+(klen-1)/hlen;
	const unsigned int khlen = hlen*khrnd;
	const unsigned int bflen = MAX((unsigned)slen+4, hlen)+hash->blksz;
	unsigned char* buf = (unsigned char*)malloc(bflen);
	unsigned char* khash = (unsigned char*)malloc(khlen);
	memset(buf, 0, bflen); memset(khash, 0, khlen);
	if ((unsigned)plen > hlen) {
		hash_t hv;
		hash->hash_init(&hv);
		hash->hash_calc(pwd, plen, plen, &hv);
		//memcpy(pwd, &hv, hlen); 
		hash->hash_beout(pwd, &hv);
		pwd[hlen] = 0;
		plen = hlen;
	}
	/* TODO: Input validation */
	unsigned int i, p;
	memcpy(buf, salt, slen);
	for (p = 0; p < khrnd; ++p) {
		const unsigned int ctr = htonl(p+1);
		memcpy(buf+slen, &ctr, 4);
		if (iter) 
			hmac(hash, pwd, plen, buf, slen+4, &hashval);
		else 
			memcpy(&hashval, buf, hlen);
		//memcpy(khash+p*hlen, &hashval, hlen);
		hash->hash_beout(khash+p*hlen, &hashval);
		memcpy(key+p*hlen, khash+p*hlen, MIN(hlen, klen-p*hlen));
	}
	for (i = 1; i < iter; ++i) {
		for (p = 0; p < khrnd; ++p) {
			hash_t hv;
			memcpy(buf, khash+p*hlen, hlen);
			hmac(hash, pwd, plen, buf, hlen, &hv);
			/* Store as init val for next iter */
			hash->hash_beout(khash+p*hlen, &hv);
			memxor(key+p*hlen, khash+p*hlen, MIN(hlen, klen-p*hlen));
		}
	}
	memset(khash, 0, khlen);
	memset(buf, 0, bflen);
	asm("":::"memory");
	free(khash);
	free(buf);
	return 0;
}

#include "sha256.h"

void gensalt(unsigned char* salt, unsigned int slen, const char* fn, const char* ext, size_t flen)
{	
	const int ln = strlen(fn) + (ext? strlen(ext): 0) + 18;
	char hashnm[ln+2];
	if (ext)
		sprintf(hashnm, "%s%s=%016zx", fn, ext, flen);
	else if (flen)
		sprintf(hashnm, "%s=%016zx", fn, flen);
	else
		sprintf(hashnm, "%s", fn);
	int sln = strlen(hashnm);
	//printf("%s\n", hashnm);
	hash_t hv;
	sha256_init(&hv);
	sha256_calc((unsigned char*)hashnm, sln, sln, &hv);
	uint i;
	for (i = 0; i < slen/4; ++i)
		*((unsigned int*)salt+i) = htonl(hv.sha256_h[i%8]);
}

