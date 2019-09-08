/** aesni.c
 * Implementation of AES en/decryption
 * using intel's AES-NI instruction set.
 * From
 * https://software.intel.com/sites/default/files/article/165683/aes-wp-2012-09-22-v01.pdf
 * adapted by
 * Kurt Garloff <kurt@garloff.de>, 7/2014
 */

#include "aes.h"
#include "aesni.h"
#include "secmem.h"
#include <string.h>
#include <wmmintrin.h>
#include "archdep.h"

static int probe_aes_ni()
{
	return !have_aesni;
}

#ifdef DONTMASK
#define MMCLEAR(xmmreg) xmmreg = _mm_setzero_si128()
#else
#define MMCLEAR(xmmreg) asm volatile ("pxor %0, %0 \n" : "=x"(xmmreg): "0"(xmmreg))
#endif

#define SIZE128 (ssize_t)sizeof(__m128i)

#define MMCLEAR3					\
	asm volatile("	pxor %%xmm2, %%xmm2	\n"	\
		"	pxor %%xmm1, %%xmm1	\n"	\
		"	pxor %%xmm0, %%xmm0	\n"	\
		:					\
		:					\
		: "xmm2", "xmm1", "xmm0")

#define MMCLEAR4					\
	asm volatile("	pxor %%xmm3, %%xmm3	\n"	\
		"	pxor %%xmm2, %%xmm2	\n"	\
		"	pxor %%xmm1, %%xmm1	\n"	\
		"	pxor %%xmm0, %%xmm0	\n"	\
		:					\
		:					\
		: "xmm3", "xmm2", "xmm1", "xmm0")

#define MMCLEAR5					\
	asm volatile("	pxor %%xmm4, %%xmm4	\n"	\
		"	pxor %%xmm3, %%xmm3	\n"	\
		"	pxor %%xmm2, %%xmm2	\n"	\
		"	pxor %%xmm1, %%xmm1	\n"	\
		"	pxor %%xmm0, %%xmm0	\n"	\
		:					\
		:					\
		: "xmm4", "xmm3", "xmm2", "xmm1", "xmm0")


static inline __m128i KEY_128_ASSIST(__m128i temp1, __m128i temp2)
{
	register __m128i temp3;
       	temp2 = _mm_shuffle_epi32(temp2 ,0xff);
	temp3 = _mm_slli_si128(temp1, 0x04);
	temp1 = _mm_xor_si128(temp1, temp3);
	temp3 = _mm_slli_si128(temp3, 0x04);
	temp1 = _mm_xor_si128(temp1, temp3);
	temp3 = _mm_slli_si128(temp3, 0x04);
	temp1 = _mm_xor_si128(temp1, temp3);
	temp1 = _mm_xor_si128(temp1, temp2);
	//MMCLEAR(temp3);
	return temp1;
}

void AESNI_128_EKey_Expansion_r(const unsigned char *userkey,
				      unsigned char *ekey,
				      unsigned int rounds)
{
	register __m128i temp1, temp2;
	__m128i *Key_Schedule = (__m128i*)ekey;

	temp1 = _mm_loadu_si128(( __m128i*)userkey);
	Key_Schedule[0] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x01);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[1] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x02);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[2] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x04);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[3] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x08);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[4] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[5] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[6] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[7] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[8] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[9] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[10] = temp1;
	if (rounds > 10) {
		temp2 = _mm_aeskeygenassist_si128(temp1, 0x6c);
		temp1 = KEY_128_ASSIST(temp1, temp2);
		Key_Schedule[11] = temp1;
		temp2 = _mm_aeskeygenassist_si128(temp1, 0xd8);
		temp1 = KEY_128_ASSIST(temp1, temp2);
		Key_Schedule[12] = temp1;
	}
	//MMCLEAR(temp2);
	//MMCLEAR(temp1);
	MMCLEAR3;
}

static inline void KEY_192_ASSIST(__m128i *temp1, __m128i *temp2, __m128i *temp3)
{
	register __m128i temp4;
	*temp2 = _mm_shuffle_epi32(*temp2, 0x55);
	 temp4 = _mm_slli_si128(*temp1, 0x04);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	 temp4 = _mm_slli_si128(temp4, 0x04);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	 temp4 = _mm_slli_si128(temp4, 0x04);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	*temp1 = _mm_xor_si128(*temp1, *temp2);
	*temp2 = _mm_shuffle_epi32(*temp1, 0xff);
	 temp4 = _mm_slli_si128(*temp3, 0x04);
	*temp3 = _mm_xor_si128(*temp3, temp4);
	*temp3 = _mm_xor_si128(*temp3, *temp2);
	//MMCLEAR(temp4);
} 

void AESNI_192_EKey_Expansion_r(const unsigned char *userkey,
				      unsigned char *key,
				      unsigned int rounds)
{
	__m128i temp1, temp2, temp3;
	__m128i *Key_Schedule = ( __m128i*)key;

	temp1 = _mm_loadu_si128(( __m128i*)userkey);
	temp3 = _mm_loadu_si128(( __m128i*)(userkey+16));

	Key_Schedule[0]  = temp1;
       	Key_Schedule[1]  = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
	KEY_192_ASSIST(&temp1, &temp2, &temp3);
	Key_Schedule[1]  = ( __m128i) _mm_shuffle_pd((__m128d)Key_Schedule[1],
				(__m128d)temp1, 0);
	Key_Schedule[2]  = ( __m128i) _mm_shuffle_pd((__m128d)temp1,
				(__m128d)temp3, 1);
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x02); 
	KEY_192_ASSIST(&temp1, &temp2, &temp3);
	Key_Schedule[3]  = temp1;
	Key_Schedule[4]  = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
	KEY_192_ASSIST(&temp1, &temp2, &temp3);
	Key_Schedule[4]  = ( __m128i) _mm_shuffle_pd((__m128d)Key_Schedule[4],
				(__m128d)temp1, 0);
	Key_Schedule[5]  = ( __m128i) _mm_shuffle_pd((__m128d)temp1,
			 	(__m128d)temp3, 1);
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
	KEY_192_ASSIST(&temp1, &temp2, &temp3);
	Key_Schedule[6]  = temp1; 
	Key_Schedule[7]  = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
	KEY_192_ASSIST(&temp1, &temp2, &temp3);
	Key_Schedule[7]  = ( __m128i) _mm_shuffle_pd((__m128d)Key_Schedule[7],
				(__m128d)temp1, 0);
	Key_Schedule[8]  = ( __m128i) _mm_shuffle_pd((__m128d)temp1,
			 	(__m128d)temp3, 1);
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
	KEY_192_ASSIST(&temp1, &temp2, &temp3);
	Key_Schedule[9]  = temp1;
	Key_Schedule[10] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
	KEY_192_ASSIST(&temp1, &temp2, &temp3);
	Key_Schedule[10] = ( __m128i) _mm_shuffle_pd((__m128d)Key_Schedule[10],
				(__m128d)temp1, 0);
	Key_Schedule[11] = ( __m128i) _mm_shuffle_pd((__m128d)temp1,
			 	(__m128d)temp3, 1);
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
	KEY_192_ASSIST(&temp1, &temp2, &temp3);
	Key_Schedule[12] = temp1; 
	if (rounds > 12) {
		Key_Schedule[13] = temp3;
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x1b);
		KEY_192_ASSIST(&temp1, &temp2, &temp3);
		Key_Schedule[13] = ( __m128i) _mm_shuffle_pd((__m128d)Key_Schedule[13],
					(__m128d)temp1, 0);
		Key_Schedule[14] = ( __m128i) _mm_shuffle_pd((__m128d)temp1,
				 	(__m128d)temp3, 1);
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x36);
		KEY_192_ASSIST(&temp1, &temp2, &temp3);
		Key_Schedule[15] = temp1;
	}
	//MMCLEAR(temp3);
	//MMCLEAR(temp2);
	//MMCLEAR(temp1);
	MMCLEAR4;
} 


static inline void KEY_256_ASSIST_1(__m128i *temp1, __m128i *temp2)
{
	register __m128i temp4;
	*temp2 = _mm_shuffle_epi32(*temp2, 0xff);
	 temp4 = _mm_slli_si128(*temp1, 0x04);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	 temp4 = _mm_slli_si128(temp4, 0x04);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	 temp4 = _mm_slli_si128(temp4, 0x04);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	*temp1 = _mm_xor_si128(*temp1, *temp2);
	//MMCLEAR(temp4);
}

static inline void KEY_256_ASSIST_2(__m128i *temp1, __m128i *temp3)
{
	register __m128i temp2, temp4;
	 temp4 = _mm_aeskeygenassist_si128(*temp1, 0x00);
	 temp2 = _mm_shuffle_epi32(temp4, 0xaa);
	 temp4 = _mm_slli_si128(*temp3, 0x04);
	*temp3 = _mm_xor_si128(*temp3, temp4);
	 temp4 = _mm_slli_si128(temp4, 0x04);
	*temp3 = _mm_xor_si128(*temp3, temp4);
	 temp4 = _mm_slli_si128(temp4, 0x04);
	*temp3 = _mm_xor_si128(*temp3, temp4);
	*temp3 = _mm_xor_si128(*temp3, temp2);
	//MMCLEAR(temp4);
	//MMCLEAR(temp2);
}

void AESNI_256_EKey_Expansion_r(const unsigned char *userkey,
				      unsigned char *key,
				      unsigned int rounds)
{
	__m128i temp1, temp2, temp3;
	__m128i *Key_Schedule = (__m128i*)key;

	temp1 = _mm_loadu_si128((__m128i*)userkey);
	temp3 = _mm_loadu_si128((__m128i*)(userkey+16));

	Key_Schedule[0]  = temp1;
	Key_Schedule[1]  = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[2]  = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[3]  = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[4]  = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[5]  = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[6]  = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[7]  = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[8]  = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[9]  = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[10] = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[11] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[12] = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[13] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[14] = temp1;
	if (rounds > 14) {
		KEY_256_ASSIST_2(&temp1, &temp3);
		Key_Schedule[15] = temp3;
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
		KEY_256_ASSIST_1(&temp1, &temp2);
		Key_Schedule[16] = temp1;
		if (rounds > 16) {
			KEY_256_ASSIST_2(&temp1, &temp3);
			Key_Schedule[17] = temp3;
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x1b);
			KEY_256_ASSIST_1(&temp1, &temp2);
			Key_Schedule[18] = temp1;
		}
	}
	MMCLEAR5;
} 

inline void AESNI_EKey_DKey(const unsigned char* ekey,
			   unsigned char* dkey,
			   int rounds)
{
	const __m128i *EKeys = (const __m128i*)ekey;
	__m128i *DKeys = (__m128i*)dkey;
	int r;
	DKeys[rounds] = EKeys[0];
	for (r = 1; r < rounds; ++r)
		DKeys[rounds-r] = _mm_aesimc_si128(EKeys[r]);
	DKeys[0] = EKeys[rounds];
}


void AESNI_128_DKey_Expansion_r(const unsigned char *userkey,
				unsigned char *dkey,
				unsigned int rounds)
{
	AESNI_128_EKey_Expansion_r(userkey, (unsigned char*)crypto->xkeys, rounds);
	AESNI_EKey_DKey((unsigned char*)crypto->xkeys, dkey, rounds);
}

void AESNI_192_DKey_Expansion_r(const unsigned char *userkey,
				unsigned char *dkey,
				unsigned int rounds)
{
	AESNI_192_EKey_Expansion_r(userkey, (unsigned char*)crypto->xkeys, rounds);
	AESNI_EKey_DKey((unsigned char*)crypto->xkeys, dkey, rounds);
}

void AESNI_256_DKey_Expansion_r(const unsigned char *userkey,
				unsigned char *dkey,
				unsigned int rounds)
{
	AESNI_256_EKey_Expansion_r(userkey, (unsigned char*)crypto->xkeys, rounds);
	AESNI_EKey_DKey((unsigned char*)crypto->xkeys, dkey, rounds);
}

#ifdef DEBUG
#include <stdio.h>
void static _debug_print(const __m128i m, const char* msg)
{
	union { 
		unsigned char a[16];
		unsigned int b[4];
	} val;
	_mm_storeu_si128((__m128i*)&val, m);
	int i;
	printf("%s 0x", msg);
	for (i = 15; i >= 0; --i)
		printf("%02x ", val.a[i]);
	printf(" %08x %08x %08x %08x ", val.b[3], val.b[2], val.b[1], val.b[0]);
	for (i = 0; i < 16; ++i)
		printf(" %02x", val.a[i]);
	printf("\n");
}
#endif

typedef __m128i (crypt_blk_fn)(const __m128i in, const unsigned char *rkeys, unsigned int rounds);
typedef void (crypt_4blks_fn)(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
			      const unsigned char *rkeys, unsigned int rounds);
typedef void (crypt_8blks_fn)(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
			      __m128i *i4, __m128i *i5, __m128i *i6, __m128i *i7,
			      const unsigned char *rkeys, unsigned int rounds);

static inline
__m128i Encrypt_Block(const __m128i in, const unsigned char *ekey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)ekey;
	register __m128i tmp = _mm_xor_si128(in, rkeys[0]);
	for (r = 1; r < rounds; ++r)
		tmp = _mm_aesenc_si128(tmp, rkeys[r]);
	return _mm_aesenclast_si128(tmp, rkeys[rounds]);
}

static inline
__m128i Decrypt_Block(const __m128i in, const unsigned char *dkey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)dkey;
	register __m128i tmp = _mm_xor_si128(in, rkeys[0]);
	for (r = 1; r < rounds; ++r)
		tmp = _mm_aesdec_si128(tmp, rkeys[r]);
	return _mm_aesdeclast_si128(tmp, rkeys[rounds]);
}

static inline
void Encrypt_4Blocks(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		     const unsigned char *ekey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)ekey;
	register __m128i rk asm("xmm0") = _mm_loadu_si128(rkeys);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	for (r = 1; r < rounds; ++r) {
		rk = _mm_loadu_si128(rkeys+r);
		*i0 = _mm_aesenc_si128(*i0, rk);
		*i1 = _mm_aesenc_si128(*i1, rk);
		*i2 = _mm_aesenc_si128(*i2, rk);
		*i3 = _mm_aesenc_si128(*i3, rk);
	}
	/* Last round ... */
	rk = _mm_loadu_si128(rkeys+rounds);
	*i0 = _mm_aesenclast_si128(*i0, rk);
	*i1 = _mm_aesenclast_si128(*i1, rk);
	*i2 = _mm_aesenclast_si128(*i2, rk);
	*i3 = _mm_aesenclast_si128(*i3, rk);
	MMCLEAR(rk);
	//asm volatile("pxor %%xmm5, %%xmm5\n" :::"xmm5");
}

static inline
void Decrypt_4Blocks(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		     const unsigned char *dkey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)dkey;
	register __m128i rk asm("xmm0") = _mm_loadu_si128(rkeys);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	for (r = 1; r < rounds; ++r) {
		rk = _mm_loadu_si128(rkeys+r);
		*i0 = _mm_aesdec_si128(*i0, rk);
		*i1 = _mm_aesdec_si128(*i1, rk);
		*i2 = _mm_aesdec_si128(*i2, rk);
		*i3 = _mm_aesdec_si128(*i3, rk);
	}
	/* Last round ... */
	rk = _mm_loadu_si128(rkeys+rounds);
	*i0 = _mm_aesdeclast_si128(*i0, rk);
	*i1 = _mm_aesdeclast_si128(*i1, rk);
	*i2 = _mm_aesdeclast_si128(*i2, rk);
	*i3 = _mm_aesdeclast_si128(*i3, rk);
	MMCLEAR(rk);
	//asm volatile("pxor %%xmm5, %%xmm5\n" :::"xmm5");
}

static inline
void Encrypt_8Blocks(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		     __m128i *i4, __m128i *i5, __m128i *i6, __m128i *i7,
		     const unsigned char *ekey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)ekey;
	register __m128i rk asm("xmm0") = _mm_loadu_si128(rkeys);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	*i4 = _mm_xor_si128(*i4, rk);
	*i5 = _mm_xor_si128(*i5, rk);
	*i6 = _mm_xor_si128(*i6, rk);
	*i7 = _mm_xor_si128(*i7, rk);
	for (r = 1; r < rounds; ++r) {
		rk = _mm_loadu_si128(rkeys+r);
		*i0 = _mm_aesenc_si128(*i0, rk);
		*i1 = _mm_aesenc_si128(*i1, rk);
		*i2 = _mm_aesenc_si128(*i2, rk);
		*i3 = _mm_aesenc_si128(*i3, rk);
		*i4 = _mm_aesenc_si128(*i4, rk);
		*i5 = _mm_aesenc_si128(*i5, rk);
		*i6 = _mm_aesenc_si128(*i6, rk);
		*i7 = _mm_aesenc_si128(*i7, rk);
	}
	/* Last round ... */
	rk = _mm_loadu_si128(rkeys+rounds);
	*i0 = _mm_aesenclast_si128(*i0, rk);
	*i1 = _mm_aesenclast_si128(*i1, rk);
	*i2 = _mm_aesenclast_si128(*i2, rk);
	*i3 = _mm_aesenclast_si128(*i3, rk);
	*i4 = _mm_aesenclast_si128(*i4, rk);
	*i5 = _mm_aesenclast_si128(*i5, rk);
	*i6 = _mm_aesenclast_si128(*i6, rk);
	*i7 = _mm_aesenclast_si128(*i7, rk);
	MMCLEAR(rk);
	//asm volatile("pxor %%xmm0, %%xmm0\n" :::"xmm0");
}


static inline
void Decrypt_8Blocks(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		     __m128i *i4, __m128i *i5, __m128i *i6, __m128i *i7,
		     const unsigned char *dkey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)dkey;
	register __m128i rk asm("xmm0") = _mm_loadu_si128(rkeys);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	*i4 = _mm_xor_si128(*i4, rk);
	*i5 = _mm_xor_si128(*i5, rk);
	*i6 = _mm_xor_si128(*i6, rk);
	*i7 = _mm_xor_si128(*i7, rk);
	for (r = 1; r < rounds; ++r) {
		rk = _mm_loadu_si128(rkeys+r);
		*i0 = _mm_aesdec_si128(*i0, rk);
		*i1 = _mm_aesdec_si128(*i1, rk);
		*i2 = _mm_aesdec_si128(*i2, rk);
		*i3 = _mm_aesdec_si128(*i3, rk);
		*i4 = _mm_aesdec_si128(*i4, rk);
		*i5 = _mm_aesdec_si128(*i5, rk);
		*i6 = _mm_aesdec_si128(*i6, rk);
		*i7 = _mm_aesdec_si128(*i7, rk);
	}
	/* Last round ... */
	rk = _mm_loadu_si128(rkeys+rounds);
	*i0 = _mm_aesdeclast_si128(*i0, rk);
	*i1 = _mm_aesdeclast_si128(*i1, rk);
	*i2 = _mm_aesdeclast_si128(*i2, rk);
	*i3 = _mm_aesdeclast_si128(*i3, rk);
	*i4 = _mm_aesdeclast_si128(*i4, rk);
	*i5 = _mm_aesdeclast_si128(*i5, rk);
	*i6 = _mm_aesdeclast_si128(*i6, rk);
	*i7 = _mm_aesdeclast_si128(*i7, rk);
	MMCLEAR(rk);
	//asm volatile("pxor %%xmm0, %%xmm0\n" :::"xmm0");
}


static inline
__m128i _mkmask(char ln)
{
	ln &= 0x0f;
	return (ln >= 8? 
			_mm_set_epi64x((1ULL<<(8*ln-64))-1, 0xffffffffffffffffULL):
			_mm_set_epi64x(0ULL, (1ULL<<(8*ln))-1)
		);

}
static inline
__m128i _mkpad(char ln)
{
	uchar by = 16 - (ln & 0x0f);
	return _mm_set_epi8(by, by, by, by, by, by, by, by,
			    by, by, by, by, by, by, by, by);
}

void AESNI_ECB_Encrypt_old(const unsigned char* in, unsigned char* out,
			   ssize_t len, const unsigned char* key, unsigned int rounds)
{
	while (len >= SIZE128) {
		register __m128i blk = _mm_loadu_si128((const __m128i*)in);
		blk = Encrypt_Block(blk, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
	if (len) {
		register __m128i blk = _mm_loadu_si128((const __m128i*)in);
		__m128i mask = _mkmask(len);
		__m128i pad = _mkpad(len);
		__m128i imask = _mm_set_epi64x(0xffffffffffffffffULL, 0xffffffffffffffffULL);
		imask = _mm_xor_si128(imask, mask);
		pad = _mm_and_si128(pad, imask);
		blk = _mm_and_si128(blk, mask);
		blk = _mm_or_si128(blk, pad);
		blk = Encrypt_Block(blk, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk);
	}
}

void AESNI_ECB_Decrypt_old(const unsigned char* in, unsigned char* out,
			   ssize_t len, const unsigned char* key, unsigned int rounds)
{
	while (len > 0) {
		register __m128i blk = _mm_loadu_si128((const __m128i*)in);
		blk = Decrypt_Block(blk, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
}


static inline
int  AESNI_ECB_Crypt_Tmpl(crypt_8blks_fn *crypt8, crypt_blk_fn *crypt, int enc,
			  const unsigned char* key, unsigned int rounds,
			  unsigned int pad,
			  const unsigned char* in, unsigned char* out,
			  ssize_t len, ssize_t *olen)
{
	*olen = len;
	while (len >= 8*SIZE128) {
		__m128i blk0 = _mm_loadu_si128((const __m128i*)in);
		__m128i blk1 = _mm_loadu_si128((const __m128i*)(in+SIZE128));
		__m128i blk2 = _mm_loadu_si128((const __m128i*)(in+2*SIZE128));
		__m128i blk3 = _mm_loadu_si128((const __m128i*)(in+3*SIZE128));
		__m128i blk4 = _mm_loadu_si128((const __m128i*)(in+4*SIZE128));
		__m128i blk5 = _mm_loadu_si128((const __m128i*)(in+5*SIZE128));
		__m128i blk6 = _mm_loadu_si128((const __m128i*)(in+6*SIZE128));
		__m128i blk7 = _mm_loadu_si128((const __m128i*)(in+7*SIZE128));
		crypt8(&blk0, &blk1, &blk2, &blk3, &blk4, &blk5, &blk6, &blk7, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk0);
		_mm_storeu_si128((__m128i*)(out+SIZE128), blk1);
		_mm_storeu_si128((__m128i*)(out+2*SIZE128), blk2);
		_mm_storeu_si128((__m128i*)(out+3*SIZE128), blk3);
		_mm_storeu_si128((__m128i*)(out+4*SIZE128), blk4);
		_mm_storeu_si128((__m128i*)(out+5*SIZE128), blk5);
		_mm_storeu_si128((__m128i*)(out+6*SIZE128), blk6);
		_mm_storeu_si128((__m128i*)(out+7*SIZE128), blk7);
		len -= 8*SIZE128;
		in  += 8*SIZE128;
		out += 8*SIZE128;
	}
	while (len > 0 || (enc && len == 0 && pad == PAD_ALWAYS)) {
		register __m128i blk = _mm_loadu_si128((const __m128i*)in);
		if (enc && len < SIZE128) {
			__m128i mask = _mkmask(len);
			blk = _mm_and_si128(blk, mask);
			if (pad) {
				__m128i padv = _mkpad(len);
				__m128i imask = _mm_set_epi64x(0xffffffffffffffffULL, 0xffffffffffffffffULL);
				imask = _mm_xor_si128(imask, mask);
				padv = _mm_and_si128(padv, imask);
				blk = _mm_or_si128(blk, padv);
#ifdef DEBUG
				if (!len) {
					_debug_print(mask, "mask");
					_debug_print(imask, "imask");
					_debug_print(padv, "padv");
				}
#endif
			}
			*olen += 16-(len&15);
		}
		blk = crypt(blk, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
	if (enc)
		return (pad == PAD_ALWAYS || (len&15))? 16-(len&15): 0;
	if (pad) 
		return dec_fix_olen_pad(olen, pad, out);
	else
		return 0;
}

int  AESNI_ECB_Encrypt(const unsigned char* key, unsigned int rounds,
			unsigned char *iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen)
{
	return AESNI_ECB_Crypt_Tmpl(Encrypt_8Blocks, Encrypt_Block, 1,
			     key, rounds, pad, in, out, len, olen);
}

int  AESNI_ECB_Decrypt(const unsigned char* key, unsigned int rounds,
			unsigned char *iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen)
{
	return AESNI_ECB_Crypt_Tmpl(Decrypt_8Blocks, Decrypt_Block, 0,
			     key, rounds, pad, in, out, len, olen);
}

#if 0
void AESNI_ECB_Decrypt(const unsigned char* key, unsigned int rounds,
			unsigned char *iv,
			const unsigned char* in, unsigned char* out,
			ssize_t len) 
{
	while (len >= 4*SIZE128) {
		__m128i blk0 = _mm_loadu_si128((const __m128i*)in);
		__m128i blk1 = _mm_loadu_si128((const __m128i*)(in+SIZE128));
		__m128i blk2 = _mm_loadu_si128((const __m128i*)(in+2*SIZE128));
		__m128i blk3 = _mm_loadu_si128((const __m128i*)(in+3*SIZE128));
		Decrypt_4Blocks(&blk0, &blk1, &blk2, &blk3, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk0);
		_mm_storeu_si128((__m128i*)(out+SIZE128), blk1);
		_mm_storeu_si128((__m128i*)(out+2*SIZE128), blk2);
		_mm_storeu_si128((__m128i*)(out+3*SIZE128), blk3);
		len -= 4*SIZE128;
		in  += 4*SIZE128;
		out += 4*SIZE128;
	}
	while (len > 0) {
		register __m128i blk = _mm_loadu_si128((const __m128i*)in);
		blk = Decrypt_Block(blk, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
}
#endif

static inline
int AESNI_CBC_Encrypt_Tmpl(crypt_blk_fn *encrypt,
			const unsigned char* key, unsigned int rounds,
			unsigned char* iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen) 
{
	register __m128i ivb = _mm_loadu_si128((const __m128i*)iv);
	*olen = len;
	while (len >= SIZE128) {
		register __m128i dat = _mm_loadu_si128((const __m128i*)in);
		ivb = _mm_xor_si128(ivb, dat);
		ivb = encrypt(ivb, key, rounds);
		_mm_storeu_si128((__m128i*)out, ivb);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
	_mm_storeu_si128((__m128i*)iv, ivb);
	if (len || pad == PAD_ALWAYS) {
		register __m128i dat = _mm_loadu_si128((const __m128i*)in);
		__m128i mask = _mkmask(len);
		dat = _mm_and_si128(dat, mask);
		if (pad) {
			__m128i padv = _mkpad(len);
			__m128i imask = _mm_set_epi64x(0xffffffffffffffffULL, 0xffffffffffffffffULL);
			imask = _mm_xor_si128(imask, mask);
			padv = _mm_and_si128(padv, imask);
			dat = _mm_or_si128(dat, padv);
		}
		ivb = _mm_xor_si128(ivb, dat);
		ivb = encrypt(ivb, key, rounds);
		_mm_storeu_si128((__m128i*)out, ivb);
		*olen += 16-(*olen&15);
	}
	//_mm_storeu_si128((__m128i*)iv, ivb);
	return (pad == PAD_ALWAYS || (len&15))? 16-(len&15): 0;
}

int AESNI_CBC_Encrypt(	const unsigned char* key, unsigned int rounds,
			unsigned char* iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen) 
{
	return AESNI_CBC_Encrypt_Tmpl(Encrypt_Block, key, rounds, iv, pad, in, out, len, olen);
}

static inline
int  AESNI_CBC_Decrypt_Tmpl(crypt_4blks_fn *decrypt4, crypt_blk_fn *decrypt,
			const unsigned char* key, unsigned int rounds,
			unsigned char* iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen)
{
	register __m128i ivb = _mm_loadu_si128((const __m128i*)iv);
	*olen = len;
	/* TODO: We could do 4 blocks in parallel for CBC decrypt (NOT: encrypt) */
	while (len >= 4*SIZE128) {
		__m128i dat0 = _mm_loadu_si128((const __m128i*)in);
		__m128i dat1 = _mm_loadu_si128((const __m128i*)in+1);
		__m128i dat2 = _mm_loadu_si128((const __m128i*)in+2);
		__m128i dat3 = _mm_loadu_si128((const __m128i*)in+3);
		__m128i b0 = dat0, b1= dat1, b2 = dat2, b3 = dat3;
		decrypt4(&dat0, &dat1, &dat2, &dat3, key, rounds);
		_mm_storeu_si128((__m128i*)out  , _mm_xor_si128(dat0, ivb));
		_mm_storeu_si128((__m128i*)out+1, _mm_xor_si128(dat1, b0));
		_mm_storeu_si128((__m128i*)out+2, _mm_xor_si128(dat2, b1));
		_mm_storeu_si128((__m128i*)out+3, _mm_xor_si128(dat3, b2));
		ivb = b3;
		len -= 4*SIZE128;
		in  += 4*SIZE128;
		out += 4*SIZE128;
	}
	//_mm_storeu_si128((__m128i*)iv, ivb);
	while (len > 0) {
		__m128i dat = _mm_loadu_si128((const __m128i*)in);
		register __m128i blk = decrypt(dat, key, rounds);
		_mm_storeu_si128((__m128i*)out, _mm_xor_si128(blk, ivb));
		ivb = dat;
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
	_mm_storeu_si128((__m128i*)iv, ivb);
	if (pad)
		return dec_fix_olen_pad(olen, pad, out);
	else
		return 0;
}

int  AESNI_CBC_Decrypt( const unsigned char* key, unsigned int rounds,
			unsigned char* iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen)
{
	return AESNI_CBC_Decrypt_Tmpl(Decrypt_4Blocks, Decrypt_Block,
			key, rounds, iv, pad, in, out, len, olen);
}

#include <emmintrin.h>
#include <smmintrin.h>

#if 0
/* CTR is big-endian */
void AESNI_CTR_Prep_2(const unsigned char* iv, const unsigned char* nonce,
		      unsigned char* ctr, unsigned long long val)
{
	__m128i BSWAP_EPI64, VAL, tmp;
	VAL = _mm_set_epi64x(val, 0);
	BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8); 
	
	tmp = _mm_setzero_si128();
	tmp = _mm_insert_epi64(tmp, *(unsigned long long*)iv, 1);
	tmp = _mm_insert_epi32(tmp, *(unsigned int*)nonce, 1);
	/* Shift left by 32 bits */
	tmp = _mm_srli_si128(tmp, 4);
	tmp = _mm_shuffle_epi8(tmp, BSWAP_EPI64);
	tmp = _mm_add_epi64(tmp, VAL);
	_mm_storeu_si128((__m128i*)ctr, tmp);
#ifdef DEBUG_CBLK_SETUP
	static int c = 0;
	if (!c++) {
		_debug_print(tmp);
		__m128i ONE = _mm_set_epi32(0, 1, 0, 0);
		tmp = _mm_add_epi64(tmp, ONE);
		tmp = _mm_shuffle_epi8(tmp, BSWAP_EPI64);
		_debug_print(tmp);
	}
#endif
}
#endif

/* CTR is big-endian */
void AESNI_CTR_Prep(const unsigned char* iv, unsigned char* ctr, unsigned long long val)
{
	__m128i BSWAP_EPI64, VAL, tmp/*, MSK*/;
	VAL = _mm_set_epi64x(val, 0);
	//MSK = _mm_set_epi32(0xffffffff, 0, 0xffffffff, 0xffffffff);
	BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8); 
	
	tmp = _mm_loadu_si128((__m128i*)iv);
	tmp = _mm_shuffle_epi8(tmp, BSWAP_EPI64);
	//tmp = _mm_and_si128(tmp, MSK);
	tmp = _mm_add_epi64(tmp, VAL);
	_mm_storeu_si128((__m128i*)ctr, tmp);
#ifdef DEBUG_CBLK_SETUP
	static int c = 0;
	if (!c++) {
		_debug_print(tmp);
		__m128i ONE = _mm_set_epi32(0, 1, 0, 0);
		tmp = _mm_add_epi64(tmp, ONE);
		tmp = _mm_shuffle_epi8(tmp, BSWAP_EPI64);
		_debug_print(tmp);
	}
#endif
}

static inline
int AESNI_CTR_Crypt_Tmpl(crypt_8blks_fn *crypt8, crypt_blk_fn *crypt,
			 const unsigned char* key, unsigned int rounds,
		 	 unsigned char* ctr,
		 	 const unsigned char* in, unsigned char* out,
			 ssize_t len)
{
	__m128i ONE = _mm_set_epi32(0, 1, 0, 0);
	__m128i BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8); 
	__m128i cblk = _mm_loadu_si128((__m128i*)ctr);
	while (len >= 8*SIZE128) {
		__m128i tmp0 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp1 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp2 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp3 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp4 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp5 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp6 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp7 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		crypt8(&tmp0, &tmp1, &tmp2, &tmp3, &tmp4, &tmp5, &tmp6, &tmp7, key, rounds);
		tmp0 = _mm_xor_si128(tmp0, _mm_loadu_si128((__m128i*)in));
		tmp1 = _mm_xor_si128(tmp1, _mm_loadu_si128((__m128i*)in+1));
		tmp2 = _mm_xor_si128(tmp2, _mm_loadu_si128((__m128i*)in+2));
		tmp3 = _mm_xor_si128(tmp3, _mm_loadu_si128((__m128i*)in+3));
		_mm_storeu_si128((__m128i*)out  , tmp0);
		_mm_storeu_si128((__m128i*)out+1, tmp1);
		_mm_storeu_si128((__m128i*)out+2, tmp2);
		_mm_storeu_si128((__m128i*)out+3, tmp3);
		tmp4 = _mm_xor_si128(tmp4, _mm_loadu_si128((__m128i*)in+4));
		tmp5 = _mm_xor_si128(tmp5, _mm_loadu_si128((__m128i*)in+5));
		tmp6 = _mm_xor_si128(tmp6, _mm_loadu_si128((__m128i*)in+6));
		tmp7 = _mm_xor_si128(tmp7, _mm_loadu_si128((__m128i*)in+7));
		_mm_storeu_si128((__m128i*)out+4, tmp4);
		_mm_storeu_si128((__m128i*)out+5, tmp5);
		_mm_storeu_si128((__m128i*)out+6, tmp6);
		_mm_storeu_si128((__m128i*)out+7, tmp7);
		len -= 8*SIZE128;
		in  += 8*SIZE128;
		out += 8*SIZE128;
	}
	while (len > 0) {
		register __m128i tmp = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		tmp = crypt(tmp, key, rounds);
		if (len < SIZE128) {
			uchar obuf[16];
			__m128i mask = _mkmask(len);
			mask = _mm_and_si128(mask, _mm_loadu_si128((__m128i*)in));
			tmp = _mm_xor_si128(tmp, mask);
			_mm_storeu_si128((__m128i*)obuf, tmp);
			memcpy(out, obuf, len);
		} else {
			cblk = _mm_add_epi64(cblk, ONE);
			tmp = _mm_xor_si128(tmp, _mm_loadu_si128((__m128i*)in));
			_mm_storeu_si128((__m128i*)out, tmp);
		}
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
	_mm_storeu_si128((__m128i*)ctr, cblk);
	return 0;
}

int AESNI_CTR_Crypt(const unsigned char* key, unsigned int rounds,
		     unsigned char* ctr, unsigned int pad,
		     const unsigned char* in, unsigned char* out,
		     ssize_t len, ssize_t *olen)
{
	*olen = len;
	return AESNI_CTR_Crypt_Tmpl(Encrypt_8Blocks, Encrypt_Block,
				    key, rounds, ctr, in, out, len);
}


#if 0
void AESNI_CTR_Crypt4(const unsigned char* in, unsigned char* out,
		     unsigned char* ctr,
		     ssize_t len, const unsigned char* key, unsigned int rounds)
{
	__m128i ONE = _mm_set_epi32(0, 1, 0, 0);
	__m128i BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8); 
	__m128i cblk = _mm_loadu_si128((__m128i*)ctr);
	while (len >= 4*SIZE128) {
		__m128i tmp0 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp1 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp2 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp3 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		Encrypt_4Blocks(&tmp0, &tmp1, &tmp2, &tmp3, key, rounds);
		tmp0 = _mm_xor_si128(tmp0, _mm_loadu_si128((__m128i*)in));
		tmp1 = _mm_xor_si128(tmp1, _mm_loadu_si128((__m128i*)in+1));
		tmp2 = _mm_xor_si128(tmp2, _mm_loadu_si128((__m128i*)in+2));
		tmp3 = _mm_xor_si128(tmp3, _mm_loadu_si128((__m128i*)in+3));
		_mm_storeu_si128((__m128i*)out  , tmp0);
		_mm_storeu_si128((__m128i*)out+1, tmp1);
		_mm_storeu_si128((__m128i*)out+2, tmp2);
		_mm_storeu_si128((__m128i*)out+3, tmp3);
		len -= 4*SIZE128;
		in  += 4*SIZE128;
		out += 4*SIZE128;
	}
	while (len > 0) {
		register __m128i tmp = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		tmp = Encrypt_Block(tmp, key, rounds);
		if (len < SIZE128) {
			__m128i mask = _mkmask(len);
			mask = _mm_and_si128(mask, _mm_loadu_si128((__m128i*)in));
			tmp = _mm_xor_si128(tmp, mask);
		} else {
			cblk = _mm_add_epi64(cblk, ONE);
			tmp = _mm_xor_si128(tmp, _mm_loadu_si128((__m128i*)in));
		}
		_mm_storeu_si128((__m128i*)out, tmp);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
	_mm_storeu_si128((__m128i*)ctr, cblk);
}

void AESNI_CTR_Crypt_old(const unsigned char* in, unsigned char* out,
		         unsigned char* ctr,
		         ssize_t len, const unsigned char* key, unsigned int rounds)
{
	__m128i ONE = _mm_set_epi32(0, 1, 0, 0);
	__m128i BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8); 
	__m128i cblk = _mm_loadu_si128((__m128i*)ctr);
	/* TODO: We could process 4 blocks at once here as well */
	while (len >= SIZE128) {
		register __m128i tmp = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		tmp = Encrypt_Block(tmp, key, rounds);
		tmp = _mm_xor_si128(tmp, _mm_loadu_si128((__m128i*)in));
		_mm_storeu_si128((__m128i*)out, tmp);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
	if (len) {
		register __m128i tmp = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		//cblk = _mm_add_epi64(cblk, ONE);
		tmp = Encrypt_Block(tmp, key, rounds);
		__m128i mask = _mkmask(len);
		mask = _mm_and_si128(mask, _mm_loadu_si128((__m128i*)in));
		tmp = _mm_xor_si128(tmp, mask);
		_mm_storeu_si128((__m128i*)out, tmp);
	}
	_mm_storeu_si128((__m128i*)ctr, cblk);
}
#endif

#include "sha256.h"
#include <assert.h>
#include <string.h>

#define AESNI_Key_ExpansionX2(MODE, BITS)				\
void AESNI_##BITS##_##MODE##Key_ExpansionX2_r(const uchar *usrkey, uchar* rkeys, unsigned int rounds)	\
{									\
	assert(0 == rounds%2);						\
	AESNI_##BITS##_##MODE##Key_Expansion_r(usrkey, rkeys, rounds/2);\
	/* Second half: Calc sha256 from usrkey and expand */		\
	hash_t hv;							\
	sha256_init(&hv);						\
	sha256_calc(usrkey, BITS/8, BITS/8, &hv);			\
	sha256_beout(crypto->userkey2, &hv);				\
	sha256_init(&hv);						\
	AESNI_##BITS##_##MODE##Key_Expansion_r(crypto->userkey2, rkeys+16+8*rounds, rounds/2);	\
	/*memset(crypto->userkey2, 0, 32);*/				\
	sha256_init(&hv);						\
	asm("":::"memory");						\
}

AESNI_Key_ExpansionX2(E, 128);
AESNI_Key_ExpansionX2(D, 128);
AESNI_Key_ExpansionX2(E, 192);
AESNI_Key_ExpansionX2(D, 192);
AESNI_Key_ExpansionX2(E, 256);
AESNI_Key_ExpansionX2(D, 256);

static inline
__m128i Encrypt_BlockX2(const __m128i in, const unsigned char *ekey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)ekey;
	register __m128i tmp = _mm_xor_si128(in, rkeys[0]);
	for (r = 1; r < rounds/2; ++r)
		tmp = _mm_aesenc_si128(tmp, rkeys[r]);
	tmp = _mm_aesenclast_si128(tmp, rkeys[r]);
	tmp = _mm_xor_si128(tmp, rkeys[++r]);
	for (++r; r < rounds+1; ++r)
		tmp = _mm_aesenc_si128(tmp, rkeys[r]);
	return _mm_aesenclast_si128(tmp, rkeys[r]);
}

static inline
__m128i Decrypt_BlockX2(const __m128i in, const unsigned char *dkey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)dkey;
	register __m128i tmp = _mm_xor_si128(in, rkeys[rounds/2+1]);
	for (r = rounds/2+2; r < rounds+1; ++r)
		tmp = _mm_aesdec_si128(tmp, rkeys[r]);
	tmp = _mm_aesdeclast_si128(tmp, rkeys[r]);
	tmp = _mm_xor_si128(tmp, rkeys[0]);
	for (r = 1; r < rounds/2; ++r)
		tmp = _mm_aesdec_si128(tmp, rkeys[r]);
	return _mm_aesdeclast_si128(tmp, rkeys[r]);
}

static inline
void Encrypt_8BlocksX2(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		       __m128i *i4, __m128i *i5, __m128i *i6, __m128i *i7,
		       const unsigned char *ekey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)ekey;
	register __m128i rk asm("xmm0") = _mm_loadu_si128(rkeys);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	*i4 = _mm_xor_si128(*i4, rk);
	*i5 = _mm_xor_si128(*i5, rk);
	*i6 = _mm_xor_si128(*i6, rk);
	*i7 = _mm_xor_si128(*i7, rk);
	for (r = 1; r < rounds/2; ++r) {
		rk = _mm_loadu_si128(rkeys+r);
		*i0 = _mm_aesenc_si128(*i0, rk);
		*i1 = _mm_aesenc_si128(*i1, rk);
		*i2 = _mm_aesenc_si128(*i2, rk);
		*i3 = _mm_aesenc_si128(*i3, rk);
		*i4 = _mm_aesenc_si128(*i4, rk);
		*i5 = _mm_aesenc_si128(*i5, rk);
		*i6 = _mm_aesenc_si128(*i6, rk);
		*i7 = _mm_aesenc_si128(*i7, rk);
	}
	/* Last round ... */
	rk = _mm_loadu_si128(rkeys+r++);
	*i0 = _mm_aesenclast_si128(*i0, rk);
	*i1 = _mm_aesenclast_si128(*i1, rk);
	*i2 = _mm_aesenclast_si128(*i2, rk);
	*i3 = _mm_aesenclast_si128(*i3, rk);
	*i4 = _mm_aesenclast_si128(*i4, rk);
	*i5 = _mm_aesenclast_si128(*i5, rk);
	*i6 = _mm_aesenclast_si128(*i6, rk);
	*i7 = _mm_aesenclast_si128(*i7, rk);
	/* Second encryption ... */
	rk = _mm_loadu_si128(rkeys+r++);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	*i4 = _mm_xor_si128(*i4, rk);
	*i5 = _mm_xor_si128(*i5, rk);
	*i6 = _mm_xor_si128(*i6, rk);
	*i7 = _mm_xor_si128(*i7, rk);
	for (; r < rounds+1; ++r) {
		rk = _mm_loadu_si128(rkeys+r);
		*i0 = _mm_aesenc_si128(*i0, rk);
		*i1 = _mm_aesenc_si128(*i1, rk);
		*i2 = _mm_aesenc_si128(*i2, rk);
		*i3 = _mm_aesenc_si128(*i3, rk);
		*i4 = _mm_aesenc_si128(*i4, rk);
		*i5 = _mm_aesenc_si128(*i5, rk);
		*i6 = _mm_aesenc_si128(*i6, rk);
		*i7 = _mm_aesenc_si128(*i7, rk);
	}
	/* Last round ... */
	rk = _mm_loadu_si128(rkeys+r++);
	*i0 = _mm_aesenclast_si128(*i0, rk);
	*i1 = _mm_aesenclast_si128(*i1, rk);
	*i2 = _mm_aesenclast_si128(*i2, rk);
	*i3 = _mm_aesenclast_si128(*i3, rk);
	*i4 = _mm_aesenclast_si128(*i4, rk);
	*i5 = _mm_aesenclast_si128(*i5, rk);
	*i6 = _mm_aesenclast_si128(*i6, rk);
	*i7 = _mm_aesenclast_si128(*i7, rk);
	MMCLEAR(rk);
	//asm volatile("pxor %%xmm0, %%xmm0\n" :::"xmm0");
}

static inline
void Decrypt_8BlocksX2(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		       __m128i *i4, __m128i *i5, __m128i *i6, __m128i *i7,
		       const unsigned char *dkey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)dkey;
	register __m128i rk asm("xmm0") = _mm_loadu_si128(rkeys+rounds/2+1);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	*i4 = _mm_xor_si128(*i4, rk);
	*i5 = _mm_xor_si128(*i5, rk);
	*i6 = _mm_xor_si128(*i6, rk);
	*i7 = _mm_xor_si128(*i7, rk);
	for (r = rounds/2+2; r < rounds+1; ++r) {
		rk = _mm_loadu_si128(rkeys+r);
		*i0 = _mm_aesdec_si128(*i0, rk);
		*i1 = _mm_aesdec_si128(*i1, rk);
		*i2 = _mm_aesdec_si128(*i2, rk);
		*i3 = _mm_aesdec_si128(*i3, rk);
		*i4 = _mm_aesdec_si128(*i4, rk);
		*i5 = _mm_aesdec_si128(*i5, rk);
		*i6 = _mm_aesdec_si128(*i6, rk);
		*i7 = _mm_aesdec_si128(*i7, rk);
	}
	/* Last round ... */
	rk = _mm_loadu_si128(rkeys+r);
	*i0 = _mm_aesdeclast_si128(*i0, rk);
	*i1 = _mm_aesdeclast_si128(*i1, rk);
	*i2 = _mm_aesdeclast_si128(*i2, rk);
	*i3 = _mm_aesdeclast_si128(*i3, rk);
	*i4 = _mm_aesdeclast_si128(*i4, rk);
	*i5 = _mm_aesdeclast_si128(*i5, rk);
	*i6 = _mm_aesdeclast_si128(*i6, rk);
	*i7 = _mm_aesdeclast_si128(*i7, rk);
	/* First key */
	rk = _mm_loadu_si128(rkeys);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	*i4 = _mm_xor_si128(*i4, rk);
	*i5 = _mm_xor_si128(*i5, rk);
	*i6 = _mm_xor_si128(*i6, rk);
	*i7 = _mm_xor_si128(*i7, rk);
	for (r = 1; r < rounds/2; ++r) {
		rk = _mm_loadu_si128(rkeys+r);
		*i0 = _mm_aesdec_si128(*i0, rk);
		*i1 = _mm_aesdec_si128(*i1, rk);
		*i2 = _mm_aesdec_si128(*i2, rk);
		*i3 = _mm_aesdec_si128(*i3, rk);
		*i4 = _mm_aesdec_si128(*i4, rk);
		*i5 = _mm_aesdec_si128(*i5, rk);
		*i6 = _mm_aesdec_si128(*i6, rk);
		*i7 = _mm_aesdec_si128(*i7, rk);
	}
	/* Last round ... */
	rk = _mm_loadu_si128(rkeys+r);
	*i0 = _mm_aesdeclast_si128(*i0, rk);
	*i1 = _mm_aesdeclast_si128(*i1, rk);
	*i2 = _mm_aesdeclast_si128(*i2, rk);
	*i3 = _mm_aesdeclast_si128(*i3, rk);
	*i4 = _mm_aesdeclast_si128(*i4, rk);
	*i5 = _mm_aesdeclast_si128(*i5, rk);
	*i6 = _mm_aesdeclast_si128(*i6, rk);
	*i7 = _mm_aesdeclast_si128(*i7, rk);
	MMCLEAR(rk);
	//asm volatile("pxor %%xmm0, %%xmm0\n" :::"xmm0");
}

static inline
void Decrypt_4BlocksX2(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		       const unsigned char *dkey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)dkey;
	register __m128i rk asm("xmm0") = _mm_loadu_si128(rkeys+rounds/2+1);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	for (r = rounds/2+2; r < rounds+1; ++r) {
		rk = _mm_loadu_si128(rkeys+r);
		*i0 = _mm_aesdec_si128(*i0, rk);
		*i1 = _mm_aesdec_si128(*i1, rk);
		*i2 = _mm_aesdec_si128(*i2, rk);
		*i3 = _mm_aesdec_si128(*i3, rk);
	}
	/* Last round ... */
	rk = _mm_loadu_si128(rkeys+r);
	*i0 = _mm_aesdeclast_si128(*i0, rk);
	*i1 = _mm_aesdeclast_si128(*i1, rk);
	*i2 = _mm_aesdeclast_si128(*i2, rk);
	*i3 = _mm_aesdeclast_si128(*i3, rk);
	/* First key */
	rk = _mm_loadu_si128(rkeys);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	for (r = 1; r < rounds/2; ++r) {
		rk = _mm_loadu_si128(rkeys+r);
		*i0 = _mm_aesdec_si128(*i0, rk);
		*i1 = _mm_aesdec_si128(*i1, rk);
		*i2 = _mm_aesdec_si128(*i2, rk);
		*i3 = _mm_aesdec_si128(*i3, rk);
	}
	/* Last round ... */
	rk = _mm_loadu_si128(rkeys+r);
	*i0 = _mm_aesdeclast_si128(*i0, rk);
	*i1 = _mm_aesdeclast_si128(*i1, rk);
	*i2 = _mm_aesdeclast_si128(*i2, rk);
	*i3 = _mm_aesdeclast_si128(*i3, rk);
	MMCLEAR(rk);
	//asm volatile("pxor %%xmm0, %%xmm0\n" :::"xmm0");
}

int  AESNI_ECB_EncryptX2(const uchar* rkeys, unsigned int rounds,
			 uchar *iv, uint pad, const uchar *in, uchar *out, 
			 ssize_t len, ssize_t *olen)
{
	return AESNI_ECB_Crypt_Tmpl(Encrypt_8BlocksX2, Encrypt_BlockX2, 1,
				    rkeys, rounds, pad, in, out, len, olen);
}

int  AESNI_ECB_DecryptX2(const uchar* rkeys, unsigned int rounds,
			 uchar *iv, uint pad, const uchar *in, uchar *out, 
			 ssize_t len, ssize_t *olen)
{
	return AESNI_ECB_Crypt_Tmpl(Decrypt_8BlocksX2, Decrypt_BlockX2, 0,
				    rkeys, rounds, pad, in, out, len, olen);
}

int  AESNI_CBC_EncryptX2(const uchar* rkeys, unsigned int rounds,
			 uchar *iv, uint pad, const uchar *in, uchar *out, 
			 ssize_t len, ssize_t *olen)
{
	return AESNI_CBC_Encrypt_Tmpl(Encrypt_BlockX2, rkeys, rounds, 
				iv, pad, in, out, len, olen);
}

int  AESNI_CBC_DecryptX2(const uchar* rkeys, unsigned int rounds,
			 uchar *iv, uint pad, const uchar *in, uchar *out, 
			 ssize_t len, ssize_t *olen)
{
	return AESNI_CBC_Decrypt_Tmpl(Decrypt_4BlocksX2, Decrypt_BlockX2, rkeys, rounds, 
				iv, pad, in, out, len, olen);
}
int  AESNI_CTR_CryptX2(const uchar* rkeys, unsigned int rounds,
			uchar *iv, uint pad, const uchar *in, uchar *out, 
			ssize_t len, ssize_t *olen)
{
	*olen = len;
	return AESNI_CTR_Crypt_Tmpl(Encrypt_8BlocksX2, Encrypt_BlockX2,
				    rkeys, rounds, iv, in, out, len);
}

stream_dsc_t aesni_stream_ctr = {  1, 1, STP_CTR, 1, AESNI_CTR_Prep };

ciph_desc_t AESNI_Methods[] = {{"AES128-ECB"  , 128, 10, 16, 11*16, &aes_stream_ecb,
					AESNI_128_EKey_Expansion_r, AESNI_128_DKey_Expansion_r,
					AESNI_ECB_Encrypt, AESNI_ECB_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES128-CBC"  , 128, 10, 16, 11*16, &aes_stream_cbc,
					AESNI_128_EKey_Expansion_r, AESNI_128_DKey_Expansion_r,
					AESNI_CBC_Encrypt, AESNI_CBC_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES128-CTR"  , 128, 10, 16, 11*16, &aesni_stream_ctr,
					AESNI_128_EKey_Expansion_r, AESNI_128_EKey_Expansion_r,
					AESNI_CTR_Crypt, AESNI_CTR_Crypt, AES_Gen_Release, probe_aes_ni},
			       {"AES192-ECB"  , 192, 12, 16, 13*16, &aes_stream_ecb,
					AESNI_192_EKey_Expansion_r, AESNI_192_DKey_Expansion_r,
					AESNI_ECB_Encrypt, AESNI_ECB_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES192-CBC"  , 192, 12, 16, 13*16, &aes_stream_cbc,
					AESNI_192_EKey_Expansion_r, AESNI_192_DKey_Expansion_r,
					AESNI_CBC_Encrypt, AESNI_CBC_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES192-CTR"  , 192, 12, 16, 13*16, &aesni_stream_ctr,
					AESNI_192_EKey_Expansion_r, AESNI_192_EKey_Expansion_r,
					AESNI_CTR_Crypt, AESNI_CTR_Crypt, AES_Gen_Release, probe_aes_ni},
			       {"AES256-ECB"  , 256, 14, 16, 15*16, &aes_stream_ecb,
					AESNI_256_EKey_Expansion_r, AESNI_256_DKey_Expansion_r,
					AESNI_ECB_Encrypt, AESNI_ECB_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES256-CBC"  , 256, 14, 16, 15*16, &aes_stream_cbc,
					AESNI_256_EKey_Expansion_r, AESNI_256_DKey_Expansion_r,
					AESNI_CBC_Encrypt, AESNI_CBC_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES256-CTR"  , 256, 14, 16, 15*16, &aesni_stream_ctr,
					AESNI_256_EKey_Expansion_r, AESNI_256_EKey_Expansion_r,
					AESNI_CTR_Crypt, AESNI_CTR_Crypt, AES_Gen_Release, probe_aes_ni},
				/* plus methods */
			       {"AES128+-ECB" , 128, 12, 16, 13*16, &aes_stream_ecb,
					AESNI_128_EKey_Expansion_r, AESNI_128_DKey_Expansion_r,
					AESNI_ECB_Encrypt, AESNI_ECB_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES128+-CBC" , 128, 12, 16, 13*16, &aes_stream_cbc,
					AESNI_128_EKey_Expansion_r, AESNI_128_DKey_Expansion_r,
					AESNI_CBC_Encrypt, AESNI_CBC_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES128+-CTR" , 128, 12, 16, 13*16, &aesni_stream_ctr,
					AESNI_128_EKey_Expansion_r, AESNI_128_EKey_Expansion_r,
					AESNI_CTR_Crypt, AESNI_CTR_Crypt, AES_Gen_Release, probe_aes_ni},
			       {"AES192+-ECB" , 192, 15, 16, 16*16, &aes_stream_ecb,
					AESNI_192_EKey_Expansion_r, AESNI_192_DKey_Expansion_r,
					AESNI_ECB_Encrypt, AESNI_ECB_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES192+-CBC" , 192, 15, 16, 16*16, &aes_stream_cbc,
					AESNI_192_EKey_Expansion_r, AESNI_192_DKey_Expansion_r,
					AESNI_CBC_Encrypt, AESNI_CBC_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES192+-CTR" , 192, 15, 16, 16*16, &aesni_stream_ctr,
					AESNI_192_EKey_Expansion_r, AESNI_192_EKey_Expansion_r,
					AESNI_CTR_Crypt, AESNI_CTR_Crypt, AES_Gen_Release, probe_aes_ni},
			       {"AES256+-ECB" , 256, 18, 16, 19*16, &aes_stream_ecb,
					AESNI_256_EKey_Expansion_r, AESNI_256_DKey_Expansion_r,
					AESNI_ECB_Encrypt, AESNI_ECB_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES256+-CBC" , 256, 18, 16, 19*16, &aes_stream_cbc,
					AESNI_256_EKey_Expansion_r, AESNI_256_DKey_Expansion_r,
					AESNI_CBC_Encrypt, AESNI_CBC_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES256+-CTR" , 256, 18, 16, 19*16, &aesni_stream_ctr,
					AESNI_256_EKey_Expansion_r, AESNI_256_EKey_Expansion_r,
					AESNI_CTR_Crypt, AESNI_CTR_Crypt, AES_Gen_Release, probe_aes_ni},
				/* x2 methods */
			       {"AES128x2-ECB", 128, 20, 16, 22*16, &aes_stream_ecb,
					AESNI_128_EKey_ExpansionX2_r, AESNI_128_DKey_ExpansionX2_r,
					AESNI_ECB_EncryptX2, AESNI_ECB_DecryptX2, AES_Gen_Release, probe_aes_ni},
			       {"AES128x2-CBC", 128, 20, 16, 22*16, &aes_stream_cbc,
					AESNI_128_EKey_ExpansionX2_r, AESNI_128_DKey_ExpansionX2_r,
					AESNI_CBC_EncryptX2, AESNI_CBC_DecryptX2, AES_Gen_Release, probe_aes_ni},
			       {"AES128x2-CTR", 128, 20, 16, 22*16, &aesni_stream_ctr,
					AESNI_128_EKey_ExpansionX2_r, AESNI_128_EKey_ExpansionX2_r,
					AESNI_CTR_CryptX2, AESNI_CTR_CryptX2, AES_Gen_Release, probe_aes_ni},
			       {"AES192x2-ECB", 192, 24, 16, 26*16, &aes_stream_ecb,
					AESNI_192_EKey_ExpansionX2_r, AESNI_192_DKey_ExpansionX2_r,
					AESNI_ECB_EncryptX2, AESNI_ECB_DecryptX2, AES_Gen_Release, probe_aes_ni},
			       {"AES192x2-CBC", 192, 24, 16, 26*16, &aes_stream_cbc,
					AESNI_192_EKey_ExpansionX2_r, AESNI_192_DKey_ExpansionX2_r,
					AESNI_CBC_EncryptX2, AESNI_CBC_DecryptX2, AES_Gen_Release, probe_aes_ni},
			       {"AES192x2-CTR", 192, 24, 16, 26*16, &aesni_stream_ctr,
					AESNI_192_EKey_ExpansionX2_r, AESNI_192_EKey_ExpansionX2_r,
					AESNI_CTR_CryptX2, AESNI_CTR_CryptX2, AES_Gen_Release, probe_aes_ni},
			       {"AES256x2-ECB", 256, 28, 16, 30*16, &aes_stream_ecb,
					AESNI_256_EKey_ExpansionX2_r, AESNI_256_DKey_ExpansionX2_r,
					AESNI_ECB_EncryptX2, AESNI_ECB_DecryptX2, AES_Gen_Release, probe_aes_ni},
			       {"AES256x2-CBC", 256, 28, 16, 30*16, &aes_stream_cbc,
					AESNI_256_EKey_ExpansionX2_r, AESNI_256_DKey_ExpansionX2_r,
					AESNI_CBC_EncryptX2, AESNI_CBC_DecryptX2, AES_Gen_Release, probe_aes_ni},
			       {"AES256x2-CTR", 256, 28, 16, 30*16, &aesni_stream_ctr,
					AESNI_256_EKey_ExpansionX2_r, AESNI_256_EKey_ExpansionX2_r,
					AESNI_CTR_CryptX2, AESNI_CTR_CryptX2, AES_Gen_Release, probe_aes_ni},
			       {NULL, /* ... */}
};


