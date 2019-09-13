/** sha1.c
 *
 * Algorithm translated to C from pseudocode at Wikipedia
 * by Kurt Garloff <kurt@garloff.de>
 * License: GNU GPL v2 or v3, at your option.
 * Source:
 * http://en.wikipedia.org/wiki/SHA-1
 * Copyright: CC-BY-SA 3.0/GFDL
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "sha1.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <assert.h>
#include <unistd.h>

/*
 * Initialize hash values: (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19): 
 */
void sha1_init(hash_t *ctx)
{
	memset((uint8_t*)ctx, 0, sizeof(hash_t));
	ctx->sha1_h[0] = 0x67452301;
	ctx->sha1_h[1] = 0xefcdab89;
	ctx->sha1_h[2] = 0x98badcfe;
	ctx->sha1_h[3] = 0x10325476;
	ctx->sha1_h[4] = 0xc3d2e1f0;
}

/* 
 * Initialize array of round constants (each used 20x)
 */
static const
uint32_t k[] = { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };

#define  LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
#define RIGHTROTATE(x, c) (((x) >> (c)) | ((x) << (32 - (c))))

// Implicit: f, w[], i
#define SHA1_SWAP(a,b,c,d,e,k)	\
	const uint32_t _temp = LEFTROTATE(a, 5) + f + e + k + w[i];	\
	e = d; d = c;		\
	c = RIGHTROTATE(b, 2);	\
	b = a; a = _temp

/* 
 * Process the message in successive 512-bit chunks: 
 * break message into 512-bit chunks 
 * (The initial values in w[0..63] don't matter, so many implementations zero them here) 
 */
void sha1_64(const uint8_t* msg, hash_t* ctx)
{
	int i;
 	/* for each chunk create a 80-entry message schedule array w[0..79] of 32-bit words */
	uint32_t w[80];
 	/* copy chunk into first 16 words w[0..15] of the message schedule array */
#if 0
	memcpy(w, msg, 64);
#else
	for (i = 0; i < 16; ++i)
		w[i] = htonl(*(uint32_t*)(msg+4*i));
#endif
	/* Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array: */
	for (i = 16; i < 32;  ++i)
		w[i] = LEFTROTATE(w[i-3] ^  w[i-8] ^ w[i-14] ^ w[i-16], 1);
	for (; i < 80;  ++i)
		w[i] = LEFTROTATE(w[i-6] ^ w[i-16] ^ w[i-28] ^ w[i-32], 2);
	
	/* Initialize working variables to current hash value:*/
	uint32_t a = ctx->sha1_h[0], b = ctx->sha1_h[1], c = ctx->sha1_h[2];
	uint32_t d = ctx->sha1_h[3], e = ctx->sha1_h[4];
	/* Compression function main loops: */
	for (i = 0; i < 20; ++i) {
		const uint32_t f = d ^ (b & (c ^ d));
		SHA1_SWAP(a,b,c,d,e,k[0]);
	}
	for (; i < 40; ++i) {
		const uint32_t f = b ^ c ^ d;
		SHA1_SWAP(a,b,c,d,e,k[1]);
	}
	for (; i < 60; ++i) {
		const uint32_t f = (b & c) | (d & (b | c));
		SHA1_SWAP(a,b,c,d,e,k[2]);
	}
	for (; i < 80; ++i) {
		const uint32_t f = b ^ c ^ d;
		SHA1_SWAP(a,b,c,d,e,k[3]);
	}

	/* Add the compressed chunk to the current hash value: */
	ctx->sha1_h[0] += a; ctx->sha1_h[1] += b; ctx->sha1_h[2] += c;
       	ctx->sha1_h[3] += d; ctx->sha1_h[4] += e;
}

static char _sha1_res[41];
char* sha1_hexout(char *buf, const hash_t* ctx)
{
	/* Produce the final hash value (big-endian): */ 
	//digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
	if (!buf)
		buf = _sha1_res;
	int i;
	*buf = 0;
	for (i = 0; i < 5; ++i) {
		char res[9];
		sprintf(res, "%08x", ctx->sha1_h[i]);
		strcat(buf, res);
	}
	return buf;
}

unsigned char* sha1_beout(unsigned char *buf, const hash_t* ctx)
{
	//digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
	assert(buf);
	int i;
	for (i = 0; i < 5; ++i) 
		*((uint32_t*)buf+i) = htonl(ctx->sha1_h[i]);		
	return buf;
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
void sha1_calc(const uint8_t *ptr, size_t chunk_ln, size_t final_len, hash_t *ctx)
{
	size_t offset;
	for (offset = 0; offset+64 <= chunk_ln; offset += 64)
		sha1_64(ptr + offset, ctx);
	if (offset == chunk_ln && final_len == (size_t)-1)
		return;
	const int remain = chunk_ln - offset;
	uint8_t sha1_buf[64];
	if (remain)
		memcpy(sha1_buf, ptr+offset, remain);
	memset(sha1_buf+remain, 0, 64-remain);
	if (final_len == (size_t)-1) {
		sha1_64(sha1_buf, ctx);
		fprintf(stderr, "sha1: WARN: Incomplete block without EOF!\n");
		return;
	}
	/* EOF */
	sha1_buf[remain] = 0x80;
	if (remain >= 56) {
		sha1_64(sha1_buf, ctx);
		memset(sha1_buf, 0, 56);
	}
	*(uint32_t*)(sha1_buf+56) = htonl(final_len >> 29);
	*(uint32_t*)(sha1_buf+60) = htonl(final_len <<  3);
	sha1_64(sha1_buf, ctx);
}

#ifdef SHA1_MAIN
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#define BUFSIZE 65536
int main(int argc, char **argv)
{
	hash_t ctx;

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
		fprintf(stderr, "sha1: Failed to allocate buffer of size %i\n",
			BUFSIZE);
		exit(2);
	}

	int arg;
	for (arg = 1; arg < argc; ++arg) {
		//uint8_t result[16];
		struct stat stbf;
		if (strcmp(argv[arg], "-") && stat(argv[arg], &stbf)) {
			fprintf(stderr, "sha1: Can't stat %s: %s\n", argv[arg],
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
			fprintf(stderr, "sha1: Failed to open %s for reading: %s\n",
				argv[arg], strerror(errno));
			free(obf);
			exit(3);
		}

#ifdef BENCH
		int i;
		for (i = 0; i < 10000; ++i) {
#endif
		size_t clen = 0;
		sha1_init(&ctx);
		while (1) {
			ssize_t rd = read(fd, bf, BUFSIZE);
			if (rd == 0) {
				sha1_calc(bf, 0, clen, &ctx);
				break;
			}
			if (rd < 0) {
				fprintf(stderr, "sha1: Error reading %s: %s\n",
					argv[arg], strerror(errno));
				free(bf);
				exit(4);
			}
			clen += rd;
			if (rd < BUFSIZE) {
				sha1_calc(bf, rd, clen, &ctx);
				break;
			} else
				sha1_calc(bf, BUFSIZE, -1, &ctx);
		}

#ifdef BENCH
		lseek(fd, 0, SEEK_SET);
		}
#endif
		if (fd)
			close(fd);

		// display result
		printf("%s *%s\n", sha1_hexout(NULL, &ctx), argv[arg]);
	}
	free(obf);

	return 0;
}
#endif
