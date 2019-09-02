/*
** frandom.c
**      Fast pseudo-random generator 
**
**      (c) Copyright 2003-2011 Eli Billauer
**      http://www.billauer.co.il
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
**
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <asm/errno.h>
#include <unistd.h>

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "frandom.h"
#include "random.h"

#if !defined(INT_IS_SLOWER) && defined(__arm__) /* || ... */
# define INT_IS_FASTER
/* # warning Using INT */
#else
/* # warning Using CHAR */
#endif

#ifdef __GNUC__
# define LIKELY(expr)   __builtin_expect((expr) != 0, 1)
# define UNLIKELY(expr) __builtin_expect((expr) != 0, 0)
#else
# define LIKELY(expr)   (expr)
# define UNLIKELY(expr) (expr)
#endif

typedef unsigned char u8;


struct frandom_state
{
	u8 S[256]; /* The state array */
	u8 i, j;        
};

static struct frandom_state *int_random_state;

static inline void swap_byte(u8 *a, u8 *b)
{
	const u8 swapByte = *a; 
	*a = *b;      
	*b = swapByte;
}

static inline u8 swap_byte_add(u8 *a, u8 *b)
{
	const u8 a1 = *a, b1 = *b;
	*b = a1; *a = b1;   
	return a1+b1;
}

static inline u8 swap_byte_add_v(u8 *sip, u8 *sjp, const u8 si)
{
	const u8 sj = *sjp;
	*sjp = si; *sip = sj;   
	return si+sj;
}

/* Unused, b/c it's slower
static inline void swap_byte_notmp(u8 *a, u8 *b)
{
	*a -= *b;
	*b += *a;
	*a  = *b - *a;
}
 */

void init_rand_state(struct frandom_state *state, u8* seedbf)
{
	unsigned int k;
	unsigned char i, j;
	u8 *S;
	S = state->S;
	for (k=0; k<256; ++k)
		*S++ = k;

	j = 0;
	S = state->S;

	for (k=0; k<256; ++k) {
		j = (j + S[k] + seedbf[k]) & 0xff;
		swap_byte(&S[k], &S[j]);
	}

	/* It's considered good practice to discard the first 256 bytes
	   generated. So we do it:
	*/

	i = 0; j = 0;
	for (k=0; k<256; ++k) {
		i = (i + 1);
		j = (j + S[i]);
		swap_byte(&S[i], &S[j]);
	}

	state->i = i; /* Save state */
	state->j = j;
}

void* frandom_init(unsigned char* seedbf)
{
	struct frandom_state *state;

	state = (struct frandom_state *)malloc(sizeof(struct frandom_state));
	if (!state)
		return NULL;

	init_rand_state(state, seedbf);
	if (!int_random_state)
		int_random_state = state;

	return state; /* Success */
}

void* frandom_stdup(const void* fst)
{
	struct frandom_state *newst = (struct frandom_state *)malloc(sizeof(struct frandom_state));
	if (!newst)
		return 0;
	memcpy(newst, fst, sizeof(struct frandom_state));
	return newst;
}

void* frandom_stcopy(void* target, const void* fst)
{
	memcpy(target, fst, sizeof(struct frandom_state));
	return target;
}

static void get_libc_rand_bytes(u8 *buf, size_t len)
{
	int *lbuf = (int*)buf;
	unsigned int i;
	for (i = 0; i < len/sizeof(int); ++i)
		lbuf[i] = rand();
}


void* frandom_init_lrand(int seedval)
{
	u8 seedbuf[256];

	if (!seedval)
		seedval = random_getseedval32();
	srand(seedval); rand();
	get_libc_rand_bytes(seedbuf, 256);
	return frandom_init(seedbuf);
}

int frandom_release(void* rstate)
{
	struct frandom_state *state = (struct frandom_state *)rstate;
	if (!state)
		state = int_random_state;
	if (!state)
		return -ENOMEM;

	free(state);
	if (state == int_random_state)
		int_random_state = 0;
	return 0;
}

ssize_t _frandom_bytes(void *rstate, u8 *buf, size_t count)
{
	struct frandom_state *state = (struct frandom_state *)rstate;
	u8 *S;
#ifdef INT_IS_FASTER
	unsigned int i, j;
#else
	unsigned char i, j;
#endif
	const ssize_t ret = count;

	if (!state)
		state = int_random_state;
	if (!state)
		state = (struct frandom_state *)frandom_init_lrand(0);
  
	i = state->i;
	j = state->j;
	S = state->S;  

	while (count--) {
#ifdef INT_IS_FASTER
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		*buf++ = S[swap_byte_add(S+i, S+j)];
#else
		j += S[++i];
		*buf++ = S[swap_byte_add(S+i, S+j)];
#endif
	}

	state->i = i;     
	state->j = j;

	return ret;
}


ssize_t _frandom_bytes_inv(void *rstate, u8 *buf, size_t count)
{
	struct frandom_state *state = (struct frandom_state *)rstate;
	u8 *S;
#ifdef INT_IS_FASTER
	unsigned int i, j;
#else
	unsigned char i, j;
#endif
	const ssize_t ret = count;

	if (!state)
		state = int_random_state;
	if (!state)
		state = (struct frandom_state *)frandom_init_lrand(0);
  
	i = state->i;
	j = state->j;
	S = state->S;  

	while (count--) {
#ifdef INT_IS_FASTER
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		*buf++ = S[swap_byte_add(S+i, S+j)];
#else
		j += S[++i];
		*buf++ = S[swap_byte_add(S+i, S+j)];
#endif
	}

	state->i = i;     
	state->j = j;

	return ret;
}


ssize_t frandom_bytes(void *rstate, u8 *buf, size_t count)
{
	struct frandom_state *state = (struct frandom_state *)rstate;
#ifdef INT_IS_FASTER
	unsigned int i, j;
#else
	unsigned char i, j;
#endif
	const ssize_t ret = count;

	//if (!state)
	//	state = (struct frandom_state *)frandom_init_lrand(0);
  
	i = state->i;
	j = state->j;
	u8 * const S = state->S;

	count /= 2;
	while (count--) {
#ifdef INT_IS_FASTER
		i = (i + 1) & 0xff;
		const unsigned int i2 = (i + 1) & 0xff;
		const u8 si1 = S[i];
		j = (j + si1) & 0xff;
		u8 si2 = S[i2];
		*buf++ = S[swap_byte_add_v(S+i, S+j, si1)];
		/* Did we just swap S[i] with S[i+1]? */
		if (UNLIKELY(j == i2))
			si2 = si1; //S[i2];
		j = (j + si2) & 0xff;
		i = i2;
		*buf++ = S[swap_byte_add_v(S+i2, S+j, si2)];
#else
		/* Modern speculative CPUs are still not good enough to
		 * recognize that we can speculatively load si2 .. */
		const u8 si1 = S[++i];
		u8 si2 = S[(u8)(i+1)];
		j += si1;
		*buf++ = S[swap_byte_add_v(S+i, S+j, si1)];
		if (UNLIKELY(j == ++i))
			si2 = S[i]; //si1;
		j += si2;
		*buf++ = S[swap_byte_add_v(S+i, S+j, si2)];

#endif
	}
	if (ret%2) {
#ifdef INT_IS_FASTER
		i = (i + 1) & 0xff;
		const u8 si1 = S[i];
		j = (j + si1) & 0xff;
		*buf++ = S[swap_byte_add_v(S+i, S+j, si1)];
#else
		const u8 si1 = S[++i];
		j += si1;
		*buf++ = S[swap_byte_add_v(S+i, S+j, si1)];
#endif
	}

	state->i = i;     
	state->j = j;

	return ret;
}

ssize_t frandom_bytes_inv(void *rstate, u8 *buf, size_t count)
{
	struct frandom_state *state = (struct frandom_state *)rstate;
#ifdef INT_IS_FASTER
	unsigned int i, j;
#else
	unsigned char i, j;
#endif
	const ssize_t ret = count;

	//if (!state)
	//	state = (struct frandom_state *)frandom_init_lrand(0);
  
	i = state->i;
	j = state->j;
	u8 * const S = state->S;

	count /= 2;
	while (count--) {
#ifdef INT_IS_FASTER
		i = (i + 1) & 0xff;
		const unsigned int i2 = (i + 1) & 0xff;
		const u8 si1 = S[i];
		j = (j + si1) & 0xff;
		u8 si2 = S[i2];
		*buf++ = S[swap_byte_add_v(S+i, S+j, si1)] ^ 0xff;
		/* Did we just swap S[i] with S[i+1]? */
		if (UNLIKELY(j == i2))
			si2 = si1; //S[i2];
		j = (j + si2) & 0xff;
		i = i2;
		*buf++ = S[swap_byte_add_v(S+i2, S+j, si2)] ^ 0xff;
#else
		/* Modern speculative CPUs are still not good enough to
		 * recognize that we can speculatively load si2 .. */
		const u8 si1 = S[++i];
		u8 si2 = S[(u8)(i+1)];
		j += si1;
		*buf++ = S[swap_byte_add_v(S+i, S+j, si1)] ^ 0xff;
		if (UNLIKELY(j == ++i))
			si2 = S[i]; //si1;
		j += si2;
		*buf++ = S[swap_byte_add_v(S+i, S+j, si2)] ^ 0xff;

#endif
	}
	if (ret%2) {
#ifdef INT_IS_FASTER
		i = (i + 1) & 0xff;
		const u8 si1 = S[i];
		j = (j + si1) & 0xff;
		*buf++ = S[swap_byte_add_v(S+i, S+j, si1)] ^ 0xff;
#else
		const u8 si1 = S[++i];
		j += si1;
		*buf++ = S[swap_byte_add_v(S+i, S+j, si1)] ^ 0xff;
#endif
	}

	state->i = i;     
	state->j = j;

	return ret;
}


