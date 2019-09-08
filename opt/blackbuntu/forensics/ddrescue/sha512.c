/** sha512.c
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

#include "sha512.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <assert.h>
#include <unistd.h>
#include <endian.h>

/*
Note 1: All variables are 64 bit unsigned integers and addition is calculated modulo 2^64 
Note 2: For each round; there is one round constant k[i] and one entry in the message schedule array w[i]; 0 ≤ i ≤ 79 
Note 3: The compression function uses 8 working variables, a through h 
Note 4: Big-endian convention is used when expressing the constants in this pseudocode, and when parsing message block data i
	from bytes to words, for example, the first word of the input message "abc" after padding is 0x6162638000000000
*/

/*
 * Initialize hash values: (first 64 bits of the fractional parts of the square roots of the first 8 primes 2..19): 
 */
void sha512_init(hash_t *ctx)
{
	//memset((uint8_t*)ctx, 0, sizeof(hash_t));
	ctx->sha512_h[0] = 0x6a09e667f3bcc908ULL;
	ctx->sha512_h[1] = 0xbb67ae8584caa73bULL;
	ctx->sha512_h[2] = 0x3c6ef372fe94f82bULL;
	ctx->sha512_h[3] = 0xa54ff53a5f1d36f1ULL;
	ctx->sha512_h[4] = 0x510e527fade682d1ULL;
	ctx->sha512_h[5] = 0x9b05688c2b3e6c1fULL;
	ctx->sha512_h[6] = 0x1f83d9abfb41bd6bULL;
	ctx->sha512_h[7] = 0x5be0cd19137e2179ULL;
}

void sha384_init(hash_t *ctx)
{
	//memset((uint8_t*)ctx, 0, sizeof(hash_t));
	ctx->sha512_h[0] = 0xcbbb9d5dc1059ed8ULL;
	ctx->sha512_h[1] = 0x629a292a367cd507ULL;
	ctx->sha512_h[2] = 0x9159015a3070dd17ULL;
	ctx->sha512_h[3] = 0x152fecd8f70e5939ULL;
	ctx->sha512_h[4] = 0x67332667ffc00b31ULL;
	ctx->sha512_h[5] = 0x8eb44a8768581511ULL;
	ctx->sha512_h[6] = 0xdb0c2e0d64f98fa7ULL;
	ctx->sha512_h[7] = 0x47b5481dbefa4fa4ULL;
}

/* 
 * Initialize array of round constants: (first 64 bits of the fractional parts of the cube roots of the first 80 primes 2..409):
 */
static const
uint64_t k[] ={ 0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 
		0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	       	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 
		0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL, 
		0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 
		0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 
		0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 
		0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 
		0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL, 
		0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL, 
		0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 
		0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 
		0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 
		0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 
		0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL, 
		0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 
		0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 
		0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 
		0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL, 
		0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(const uint64_t x)
{
#ifdef HAVE_HTOBE64
	return htobe64(x);
#else
	const uint32_t hi = x>>32;
	const uint32_t lo = x;
	return htonl(hi) + ((uint64_t)htonl(lo) << 32);
#endif
}
#else
static inline uint64_t htonll(const uint64_t x)
{ return x; }
#endif

#define  LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (64 - (c))))
#define RIGHTROTATE(x, c) (((x) >> (c)) | ((x) << (64 - (c))))
/* 
 * Process the message in successive 1024-bit chunks: 
 * break message into 1024-bit chunks 
 * (The initial values in w[0..79] don't matter, so many implementations zero them here) 
 */
void sha512_128(const uint8_t* msg, hash_t* ctx)
{
	int i;
 	/* for each chunk create a 80-entry message schedule array w[0..79] of 64-bit words */
	uint64_t w[80];
 	/* copy chunk into first 16 words w[0..15] of the message schedule array */
#if 0
	memcpy(w, msg, 64);
#else
	for (i = 0; i < 16; ++i)
		w[i] = htonll(*(uint64_t*)(msg+8*i));
#endif
	/* Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array: */
	for (i = 16; i < 80;  ++i) {
		uint64_t s0 = RIGHTROTATE(w[i-15], 1) ^ RIGHTROTATE(w[i-15], 8) ^ (w[i-15] >> 7);
		uint64_t s1 = RIGHTROTATE(w[i-2], 19) ^ RIGHTROTATE(w[i-2] ,61) ^ (w[i-2]  >> 6);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	/* Initialize working variables to current hash value:*/
	uint64_t a = ctx->sha512_h[0], b = ctx->sha512_h[1], c = ctx->sha512_h[2], d = ctx->sha512_h[3];
	uint64_t e = ctx->sha512_h[4], f = ctx->sha512_h[5], g = ctx->sha512_h[6], h = ctx->sha512_h[7];
	/* Compression function main loop: */
	for (i = 0; i < 80; ++i) {
		uint64_t S1 = RIGHTROTATE(e, 14) ^ RIGHTROTATE(e, 18) ^ RIGHTROTATE(e, 41);
		//uint64_t ch = (e & f) ^ ((~e) & g);
		uint64_t ch = g ^ (e & (f ^ g));
		uint64_t temp1 = h + S1 + ch + k[i] + w[i];
		uint64_t S0 = RIGHTROTATE(a, 28) ^ RIGHTROTATE(a, 34) ^ RIGHTROTATE(a, 39);
		//uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint64_t maj = (a & b) | (c & (a | b));
		uint64_t temp2 = S0 + maj;

		h = g; g = f; f = e;
		e = d + temp1;
		d = c; c = b; b = a;
		a = temp1 + temp2;
	}
	/* Add the compressed chunk to the current hash value: */
	ctx->sha512_h[0] += a; ctx->sha512_h[1] += b; ctx->sha512_h[2] += c; ctx->sha512_h[3] += d;
	ctx->sha512_h[4] += e; ctx->sha512_h[5] += f; ctx->sha512_h[6] += g; ctx->sha512_h[7] += h;
}

#if __WORDSIZE == 64
#define LL "l"
#elif __WORDSIZE == 32
#define LL "ll"
#else
#error __WORDSIZE unknown
#endif

static char _sha512_res[129];
static inline 
char* sha5xx_hexout(char *buf, const hash_t *ctx, int wd)
{
	/* Produce the final hash value (big-endian): */ 
	//digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
	if (!buf)
		buf = _sha512_res;
	int i;
	*buf = 0;
	for (i = 0; i < wd; ++i) {
		char res[17];
		sprintf(res, "%016" LL "x", ctx->sha512_h[i]);
		strcat(buf, res);
	}
	return buf;
}

char* sha512_hexout(char *buf, const hash_t* ctx)
{
	return sha5xx_hexout(buf, ctx, 8);
}

char* sha384_hexout(char *buf, const hash_t* ctx)
{
	return sha5xx_hexout(buf, ctx, 6);
}

static inline
unsigned char* sha5xx_beout(unsigned char *buf, const hash_t *ctx, int wd)
{
	assert(buf);
	int i;
	for (i = 0; i < wd; ++i) 
		*((uint64_t*)buf+i) = htonll(ctx->sha512_h[i]);
	return buf;
}

unsigned char* sha512_beout(unsigned char *buf, const hash_t *ctx)
{
	return sha5xx_beout(buf, ctx, 8);
}

unsigned char* sha384_beout(unsigned char *buf, const hash_t *ctx)
{
	return sha5xx_beout(buf, ctx, 6);
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
 * append k bits '0', where k is the minimum number >= 0 such that the resulting message length (modulo 1024 in bits) is 896. 
 * append length of message (without the '1' bit or padding), in bits, as 128-bit big-endian integer 
 * (this will make the entire post-processed length a multiple of 1024 bits)
 */
void sha512_calc(const uint8_t *ptr, size_t chunk_ln, size_t final_len, hash_t *ctx)
{
	size_t offset;
	for (offset = 0; offset+128 <= chunk_ln; offset += 128)
		sha512_128(ptr + offset, ctx);
	if (offset == chunk_ln && final_len == (size_t)-1)
		return;
	const int remain = chunk_ln - offset;
	uint8_t sha512_buf[128];
	if (remain)
		memcpy(sha512_buf, ptr+offset, remain);
	memset(sha512_buf+remain, 0, 128-remain);
	if (final_len == (size_t)-1) {
		sha512_128(sha512_buf, ctx);
		fprintf(stderr, "sha512: WARN: Incomplete block without EOF!\n");
		return;
	}
	/* EOF */
	sha512_buf[remain] = 0x80;
	if (remain >= 112) {
		sha512_128(sha512_buf, ctx);
		memset(sha512_buf, 0, 116);
	}
	*(uint32_t*)(sha512_buf+116) = htonl(final_len >> 61);
	*(uint32_t*)(sha512_buf+120) = htonl(final_len >> 29);
	*(uint32_t*)(sha512_buf+124) = htonl(final_len <<  3);
	sha512_128(sha512_buf, ctx);
}

#ifdef SHA512_MAIN
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

	char is_sha384 = 0;
	if (!strcmp(basename(argv[0]), "sha384"))
	       is_sha384 = 1;

	if (argc < 2) {
		printf("usage: %s file [file [..]]\n", argv[0]);
		return 1;
	}


	uint8_t *obf = (uint8_t *)malloc(BUFSIZE + 256);
	uint8_t *bf = obf;
#if defined(HAVE___BUILTIN_PREFETCH) && !defined(NO_ALIGN)
	bf += 127;
	bf -= ((unsigned long)bf % 128);
#endif

	if (!bf) {
		fprintf(stderr, "sha512: Failed to allocate buffer of size %i\n",
			BUFSIZE);
		exit(2);
	}

	int arg;
	for (arg = 1; arg < argc; ++arg) {
		//uint8_t result[16];
		struct stat stbf;
		if (strcmp(argv[arg], "-") && stat(argv[arg], &stbf)) {
			fprintf(stderr, "sha512: Can't stat %s: %s\n", argv[arg],
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
			fprintf(stderr, "sha512: Failed to open %s for reading: %s\n",
				argv[arg], strerror(errno));
			free(obf);
			exit(3);
		}

#ifdef BENCH
		int i;
		for (i = 0; i < 10000; ++i) {
#endif
		size_t clen = 0;
		if (is_sha384)
			sha384_init(&ctx);
		else
			sha512_init(&ctx);
		while (1) {
			ssize_t rd = read(fd, bf, BUFSIZE);
			if (rd == 0) {
				sha512_calc(bf, 0, clen, &ctx);
				break;
			}
			if (rd < 0) {
				fprintf(stderr, "sha512: Error reading %s: %s\n",
					argv[arg], strerror(errno));
				free(bf);
				exit(4);
			}
			clen += rd;
			if (rd < BUFSIZE) {
				sha512_calc(bf, rd, clen, &ctx);
				break;
			} else
				sha512_calc(bf, BUFSIZE, -1, &ctx);
		}

#ifdef BENCH
		lseek(fd, 0, SEEK_SET);
		}
#endif
		if (fd)
			close(fd);

		// display result
		printf("%s *%s\n", is_sha384? sha384_hexout(NULL, &ctx): sha512_hexout(NULL, &ctx), 
				argv[arg]);
	}
	free(obf);

	return 0;
}
#endif
