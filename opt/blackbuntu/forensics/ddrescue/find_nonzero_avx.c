/** find_nonzero_avx.c
  * AVX2 optimized search for non-zero bytes
  * taken straight from SSE2 and adapted to use AVX registers
  * Needs recent (2.23+) binutils to compile ...
  * Has only seen testing in bochs ...
  * (c) Kurt Garloff <kurt@garloff.de>, 2013
  * License: GNU GPL v2 or v3
  */

#define _GNU_SOURCE 1
#include "find_nonzero.h"

#ifdef __AVX2__

#include <immintrin.h>
volatile unsigned _cmp_mask_probe_avx;
void probe_avx2()
{
	__m256i register _probe_ymm = _mm256_setzero_si256();
	__m256i register ymm2 = _mm256_setzero_si256();
	__m256i register ymm3 = _mm256_cmpeq_epi8(_probe_ymm, ymm2);
	_cmp_mask_probe_avx = _mm256_movemask_epi8(ymm3);
}

/** AVX2 version for measuring the initial zero bytes of 32b aligned blk */
size_t find_nonzero_avx2(const unsigned char* blk, const size_t ln)
{
	const __m256i register zero = _mm256_setzero_si256();
	__m256i register ymm;
	unsigned register eax;
	size_t i = 0;
	//asm(".p2align 5");
	for (; i < ln; i+= 32) {
		//ymm = _mm256_load_si256((__m256i*)(blk+i));
		ymm = _mm256_cmpeq_epi8(*(__m256i*)(blk+i), zero);
		eax = ~(_mm256_movemask_epi8(ymm));
		if (eax) 
			return i + myffs(eax)-1;
	}
	return ln;
}
#endif


