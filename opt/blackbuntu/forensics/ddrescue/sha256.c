/** sha256.c
 *
 * Algorithm translated to C from pseudocode at Wikipedia
 * by Kurt Garloff <kurt@garloff.de>
 * License: GNU GPL v2 or v3, at your option.
 * Source:
 * http://en.wikipedia.org/wiki/SHA-2
 * Copyright: CC-BY-SA 3.0/GFDL
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "sha256.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <assert.h>
#include <unistd.h>

/*
Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 2^32 
Note 2: For each round; there is one round constant k[i] and one entry in the message schedule array w[i]; 0 ≤ i ≤ 63 
Note 3: The compression function uses 8 working variables, a through h 
Note 4: Big-endian convention is used when expressing the constants in this pseudocode, and when parsing message block data i
	from bytes to words, for example, the first word of the input message "abc" after padding is 0x61626380 
*/

/*
 * Initialize hash values: (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19): 
 */
void sha256_init(hash_t *ctx)
{
	memset((uint8_t*)ctx, 0, sizeof(hash_t));
	ctx->sha256_h[0] = 0x6a09e667;
	ctx->sha256_h[1] = 0xbb67ae85;
	ctx->sha256_h[2] = 0x3c6ef372;
	ctx->sha256_h[3] = 0xa54ff53a;
	ctx->sha256_h[4] = 0x510e527f;
	ctx->sha256_h[5] = 0x9b05688c;
	ctx->sha256_h[6] = 0x1f83d9ab;
	ctx->sha256_h[7] = 0x5be0cd19;
}

void sha224_init(hash_t *ctx)
{
	memset((uint8_t*)ctx, 0, sizeof(hash_t));
	ctx->sha256_h[0] = 0xc1059ed8;
	ctx->sha256_h[1] = 0x367cd507;
	ctx->sha256_h[2] = 0x3070dd17;
	ctx->sha256_h[3] = 0xf70e5939;
	ctx->sha256_h[4] = 0xffc00b31;
	ctx->sha256_h[5] = 0x68581511;
	ctx->sha256_h[6] = 0x64f98fa7;
	ctx->sha256_h[7] = 0xbefa4fa4;
}

/* 
 * Initialize array of round constants: (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
 */
static const
uint32_t k[] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
		 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};


#define  LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
#define RIGHTROTATE(x, c) (((x) >> (c)) | ((x) << (32 - (c))))
/* 
 * Process the message in successive 512-bit chunks: 
 * break message into 512-bit chunks 
 * (The initial values in w[0..63] don't matter, so many implementations zero them here) 
 */
void sha256_64(const uint8_t* msg, hash_t* ctx)
{
	int i;
 	/* for each chunk create a 64-entry message schedule array w[0..63] of 32-bit words */
	uint32_t w[64];
 	/* copy chunk into first 16 words w[0..15] of the message schedule array */
#if 0
	memcpy(w, msg, 64);
#else
	for (i = 0; i < 16; ++i)
		w[i] = htonl(*(uint32_t*)(msg+4*i));
#endif
	/* Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array: */
	for (i = 16; i < 64;  ++i) {
		uint32_t s0 = RIGHTROTATE(w[i-15], 7) ^ RIGHTROTATE(w[i-15], 18) ^ (w[i-15] >> 3);
		uint32_t s1 = RIGHTROTATE(w[i-2], 17) ^ RIGHTROTATE(w[i-2] , 19) ^ (w[i-2] >> 10);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	/* Initialize working variables to current hash value:*/
	uint32_t a = ctx->sha256_h[0], b = ctx->sha256_h[1], c = ctx->sha256_h[2], d = ctx->sha256_h[3];
	uint32_t e = ctx->sha256_h[4], f = ctx->sha256_h[5], g = ctx->sha256_h[6], h = ctx->sha256_h[7];
	/* Compression function main loop: */
	for (i = 0; i < 64; ++i) {
		uint32_t S1 = RIGHTROTATE(e, 6) ^ RIGHTROTATE(e, 11) ^ RIGHTROTATE(e, 25);
		//uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t ch = g ^ (e & (f ^ g));
		uint32_t temp1 = h + S1 + ch + k[i] + w[i];
		uint32_t S0 = RIGHTROTATE(a, 2) ^ RIGHTROTATE(a, 13) ^ RIGHTROTATE(a, 22);
		//uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t maj = (a & b) | (c & (a | b));
		uint32_t temp2 = S0 + maj;

		h = g; g = f; f = e;
		e = d + temp1;
		d = c; c = b; b = a;
		a = temp1 + temp2;
	}
	/* Add the compressed chunk to the current hash value: */
	ctx->sha256_h[0] += a; ctx->sha256_h[1] += b; ctx->sha256_h[2] += c; ctx->sha256_h[3] += d;
	ctx->sha256_h[4] += e; ctx->sha256_h[5] += f; ctx->sha256_h[6] += g; ctx->sha256_h[7] += h;
}

static char _sha256_res[65];
static inline 
char* sha2xx_hexout(char *buf, const hash_t* ctx, int wd)
{
	/* Produce the final hash value (big-endian): */ 
	//digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
	if (!buf)
		buf = _sha256_res;
	int i;
	*buf = 0;
	for (i = 0; i < wd; ++i) {
		char res[9];
		sprintf(res, "%08x", ctx->sha256_h[i]);
		strcat(buf, res);
	}
	return buf;
}

char* sha256_hexout(char *buf, const hash_t* ctx)
{
	return sha2xx_hexout(buf, ctx, 8);
}
char* sha224_hexout(char *buf, const hash_t* ctx)
{
	return sha2xx_hexout(buf, ctx, 7);
}

/* Big endian byte output */
static inline
unsigned char* sha2xx_beout(unsigned char* buf, const hash_t* ctx, int wd)
{
	assert(buf);
	int i;
	for (i = 0; i < wd; ++i)
		*((uint32_t*)buf+i) = htonl(ctx->sha256_h[i]);
	return buf;
}

unsigned char* sha256_beout(unsigned char *buf, const hash_t *ctx)
{
	return sha2xx_beout(buf, ctx, 8);
}

unsigned char* sha224_beout(unsigned char *buf, const hash_t *ctx)
{
	return sha2xx_beout(buf, ctx, 7);
}


#ifdef DEBUG
static void output(unsigned char* ptr, int ln)
{
	int i;
	for (i = 0; i < ln; ++i) {
		printf("%02x ", ptr[i]);
		if (!((i+1)%16))
			printf("\n");
	}
	if (i%16)
		printf("\n");
}
#endif

/*
 * Pre-processing: 
 * append the bit '1' to the message 
 * append k bits '0', where k is the minimum number >= 0 such that the resulting message length (modulo 512 in bits) is 448. 
 * append length of message (without the '1' bit or padding), in bits, as 64-bit big-endian integer 
 * (this will make the entire post-processed length a multiple of 512 bits)
 */
void sha256_calc(const uint8_t *ptr, size_t chunk_ln, size_t final_len, hash_t *ctx)
{
	size_t offset;
	for (offset = 0; offset+64 <= chunk_ln; offset += 64)
		sha256_64(ptr + offset, ctx);
	if (offset == chunk_ln && final_len == (size_t)-1)
		return;
	const int remain = chunk_ln - offset;
	uint8_t sha256_buf[64];
	if (remain)
		memcpy(sha256_buf, ptr+offset, remain);
	memset(sha256_buf+remain, 0, 64-remain);
	if (final_len == (size_t)-1) {
		sha256_64(sha256_buf, ctx);
		fprintf(stderr, "sha256: WARN: Incomplete block without EOF!\n");
		return;
	}
	/* EOF */
	sha256_buf[remain] = 0x80;
	if (remain >= 56) {
		sha256_64(sha256_buf, ctx);
		memset(sha256_buf, 0, 56);
	}
	*(uint32_t*)(sha256_buf+56) = htonl(final_len >> 29);
	*(uint32_t*)(sha256_buf+60) = htonl(final_len <<  3);
	sha256_64(sha256_buf, ctx);
}

#ifdef SHA256_MAIN
#include <sys/stat.h>
#include <libgen.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#define BUFSIZE 65536
int main(int argc, char **argv)
{
	hash_t ctx;

	char is_sha224 = 0;
	if (!strcmp(basename(argv[0]), "sha224"))
	       is_sha224 = 1;

	if (argc < 2) {
		printf("usage: %s file [file [..]]\n", argv[0]);
		return 1;
	}


	uint8_t *obf = (uint8_t *)malloc(BUFSIZE + 128);
	uint8_t *bf = obf;
#if defined(HAVE___BUILTIN_PREFETCH) && !defined(NO_ALIGN)
	bf += 63;
	bf -= ((unsigned long)bf % 64);
#endif

	if (!bf) {
		fprintf(stderr, "sha256: Failed to allocate buffer of size %i\n",
			BUFSIZE);
		exit(2);
	}

	int arg;
	for (arg = 1; arg < argc; ++arg) {
		//uint8_t result[16];
		struct stat stbf;
		if (strcmp(argv[arg], "-") && stat(argv[arg], &stbf)) {
			fprintf(stderr, "sha256: Can't stat %s: %s\n", argv[arg],
				strerror(errno));
			free(obf);
			exit(1);
		}
		//size_t len = stbf.st_size;

		int fd;
		if (strcmp(argv[arg], "-"))
			fd = open(argv[arg], O_RDONLY);
		else {
			fd = 0;
			//len = 0;
		}

		if (fd < 0) {
			fprintf(stderr, "sha256: Failed to open %s for reading: %s\n",
				argv[arg], strerror(errno));
			free(obf);
			exit(3);
		}

#ifdef BENCH
		int i;
		for (i = 0; i < 10000; ++i) {
#endif
		size_t clen = 0;
		if (is_sha224)
			sha224_init(&ctx);
		else
			sha256_init(&ctx);
		while (1) {
			ssize_t rd = read(fd, bf, BUFSIZE);
			if (rd == 0) {
				sha256_calc(bf, 0, clen, &ctx);
				break;
			}
			if (rd < 0) {
				fprintf(stderr, "sha256: Error reading %s: %s\n",
					argv[arg], strerror(errno));
				free(bf);
				exit(4);
			}
			clen += rd;
			if (rd < BUFSIZE) {
				sha256_calc(bf, rd, clen, &ctx);
				break;
			} else
				sha256_calc(bf, BUFSIZE, -1, &ctx);
		}

#ifdef BENCH
		lseek(fd, 0, SEEK_SET);
		}
#endif
		if (fd)
			close(fd);

		// display result
		printf("%s *%s\n", is_sha224? sha224_hexout(NULL, &ctx): sha256_hexout(NULL, &ctx), 
				argv[arg]);
	}
	free(obf);

	return 0;
}
#endif
