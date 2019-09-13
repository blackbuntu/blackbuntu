/*
 * Simple MD5 implementation
 * Source: http://en.wikipedia.org/wiki/MD5
 * Copyright: CC-BY-SA 3.0 / GFDL
 *
 * Implementation adjusted by Kurt Garloff<kurt@garloff.de>, 3-5/2014
 * License: GNU GPL v2 or v3, at your option.
 */
#include "md5.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <endian.h>
#include <assert.h>
#include <netinet/in.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Constants are the integer part of the sines of integers (in radians) * 2^32.
static const uint32_t k[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
	0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
	0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
	0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
	0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
	0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

// r specifies the per-round shift amounts
static const uint32_t r[] = { 7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17,
			      22, 7,  12, 17, 22, 5,  9,  14, 20, 5,  9,
			      14, 20, 5,  9,  14, 20, 5,  9,  14, 20, 4,
			      11, 16, 23, 4,  11, 16, 23, 4,  11, 16, 23,
			      4,  11, 16, 23, 6,  10, 15, 21, 6,  10, 15,
			      21, 6,  10, 15, 21, 6,  10, 15, 21 };

// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline void to_bytes(uint32_t val, uint8_t *bytes)
{
	*(uint32_t *)bytes = val;
}
#if 0	// Unused
static inline uint32_t to_int32(const uint8_t *bytes)
{
	return *(const uint32_t *)bytes;
}
#endif
#else
/* Store val into bytes in little endian fmt */
static inline void to_bytes(uint32_t val, uint8_t *bytes)
{
	bytes[0] = (uint8_t)val;
	bytes[1] = (uint8_t)(val >> 8);
	bytes[2] = (uint8_t)(val >> 16);
	bytes[3] = (uint8_t)(val >> 24);
}

/* Read val from little-endian array */
static inline uint32_t to_int32(const uint8_t *bytes)
{
	return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
	       ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}
#endif

// Implicit: temp, i, f, g, k[], w[]
#define MD5_SWAP(a,b,c,d)		\
	const uint32_t _temp = d;	\
	d = c;				\
	c = b;				\
	b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);	\
	a = _temp


void md5_64(const uint8_t *ptr, hash_t *ctx)
{
	uint32_t _a, _b, _c, _d;
	unsigned int i;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t *w = (uint32_t *)ptr;
#ifdef HAVE___BUILTIN_PREFETCH
	__builtin_prefetch(ptr, 0, 3);
//__builtin_prefetch(ptr+32, 0, 3);
#endif
#else /* BIG ENDIAN */
	uint32_t w[16];
	// break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
	for (i = 0; i < 16; ++i)
		w[i] = to_int32(ptr + i * 4);
#endif

	// Initialize hash value for this chunk:
	_a = ctx->md5_h[0]; _b = ctx->md5_h[1]; 
	_c = ctx->md5_h[2]; _d = ctx->md5_h[3];

	for (i = 0; i < 16; ++i) {
		const uint32_t f = (_b & _c) | ((~_b) & _d);
		const uint32_t g = i;
		MD5_SWAP(_a, _b, _c, _d);
	}
	for (; i < 32; ++i) {
		const uint32_t f = (_d & _b) | ((~_d) & _c);
		const uint32_t g = (5 * i + 1) % 16;
		MD5_SWAP(_a, _b, _c, _d);
	}
	for (; i < 48; ++i) {
		const uint32_t f = _b ^ _c ^ _d;
		const uint32_t g = (3 * i + 5) % 16;
		MD5_SWAP(_a, _b, _c, _d);
	} 
	for (; i < 64; ++i) {
		const uint32_t f = _c ^ (_b | (~_d));
		const uint32_t g = (7 * i) % 16;
		MD5_SWAP(_a, _b, _c, _d);
	}

	// Add this chunk's hash to result so far:
	ctx->md5_h[0] += _a; ctx->md5_h[1] += _b; 
	ctx->md5_h[2] += _c; ctx->md5_h[3] += _d;
}

void md5_init(hash_t *ctx)
{
	memset((char*)ctx, 0, sizeof(hash_t));
	ctx->md5_h[0] = 0x67452301;
	ctx->md5_h[1] = 0xefcdab89;
	ctx->md5_h[2] = 0x98badcfe;
	ctx->md5_h[3] = 0x10325476;
}

void md5_calc(const uint8_t *ptr, size_t chunk_ln, size_t final_len, hash_t *ctx)
{
	uint32_t offset;
	for (offset = 0; offset+64 <= chunk_ln; offset += 64)
		md5_64(ptr + offset, ctx);
	if (offset == chunk_ln && final_len == (size_t)-1)
		return;
	const int remain = chunk_ln - offset;
	uint8_t md5_buf[64];
	if (remain)
		memcpy(md5_buf, ptr+offset, remain);
	memset(md5_buf+remain, 0, 64-remain);
	if (final_len == (size_t)-1) {
		md5_64(md5_buf, ctx);
		fprintf(stderr, "md5: WARN: Incomplete block without EOF!\n");
		return;
	}
	/* EOF */
	md5_buf[remain] = 0x80;
	if (remain >= 56) {
		md5_64(md5_buf, ctx);
		memset(md5_buf, 0, 56);
	}
	/* FIXME: Confused? */
	to_bytes(final_len <<  3, md5_buf+56);
	to_bytes(final_len >> 29, md5_buf+60);
	md5_64(md5_buf, ctx);
}

#define BSWAP32(x) ((x<<24) | ((x<<8)&0x00ff0000) | ((x>>8)&0x0000ff00) | (x>>24))

static char _md5_res[33];
char* md5_hexout(char* buf, const hash_t *ctx)
{
	if (!buf)
		buf = _md5_res;
	*buf = 0;
	int i;
	for (i = 0; i < 4; ++i) {
		char str[9];
		/* FIXME !!! */
		sprintf(str, "%08x", BSWAP32(ctx->md5_h[i]));
		strcat(buf, str);
	}
	return buf;
}

unsigned char* md5_beout(unsigned char* buf, const hash_t *ctx)
{
	assert(buf);
	int i;
	for (i = 0; i < 4; ++i) 
		//*((uint32_t*)buf+i) = htonl(BSWAP32(ctx->md5_h[i]));
#if __BYTE_ORDER == __BIG_ENDIAN
		*((uint32_t*)buf+i) = BSWAP32(ctx->md5_h[i]);
#else
		*((uint32_t*)buf+i) = ctx->md5_h[i];
#endif
	return buf;
}

#ifdef MD5_MAIN
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
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
		fprintf(stderr, "md5: Failed to allocate buffer of size %i\n",
			BUFSIZE);
		exit(2);
	}

	int arg;
	for (arg = 1; arg < argc; ++arg) {
		//uint8_t result[16];
		struct stat stbf;
		if (strcmp(argv[arg], "-") && stat(argv[arg], &stbf)) {
			fprintf(stderr, "md5: Can't stat %s: %s\n", argv[arg],
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
			fprintf(stderr, "md5: Failed to open %s for reading: %s\n",
				argv[arg], strerror(errno));
			free(obf);
			exit(3);
		}

#ifdef BENCH
		int i;
		for (i = 0; i < 10000; ++i) {
#endif
		size_t clen = 0;
		md5_init(&ctx);
		while (1) {
			ssize_t rd = read(fd, bf, BUFSIZE);
			if (rd == 0) {
				md5_calc(bf, 0, clen, &ctx);
				break;
			}
			if (rd < 0) {
				fprintf(stderr, "md5: Error reading %s: %s\n",
					argv[arg], strerror(errno));
				free(bf);
				exit(4);
			}
			clen += rd;
			if (rd < BUFSIZE) {
				md5_calc(bf, rd, clen, &ctx);
				break;
			} else
				md5_calc(bf, BUFSIZE, -1, &ctx);
		}

#ifdef BENCH
		lseek(fd, 0, SEEK_SET);
		}
#endif
		if (fd)
			close(fd);

		// display result
		printf("%s *%s\n", md5_hexout(NULL, &ctx), argv[arg]);
	}
	free(obf);

	return 0;
}
#endif
