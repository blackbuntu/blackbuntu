/** find_nonzero_arm64.c
 *
 * ARMv8 (aarch64) assembler optimized version to find first non-zero byte in a block
 * (c) Kurt Garloff <kurt@garloff.de>, GNU GPL v2 or v3
 */

#include "find_nonzero.h"

#if defined(__aarch64__)
/** ASM optimized version for ARMv8.
 * transform the armv6 ldmia form into ldp
 */

#ifdef  USE_PREFETCH
#define PREFETCH(x) "	prfm pldl1keep,[%0," #x "]	\n"
#else
#define PREFETCH(x) 
#endif
size_t find_nonzero_arm8(const unsigned char *blk, const size_t ln)
{
	/*
	if (!ln || *blk)
		return 0;
	 */
	register unsigned char* res;
	const register unsigned char* end = blk+ln;
	asm volatile(
//	".align 4			\n"
	PREFETCH(0)
	PREFETCH(64)
	PREFETCH(128)
	PREFETCH(192)
	"1:				\n"
	"	ldp x10,x11,[%0],#16	\n"	/* Need #16; #8 is not scaled here. (WHY?) */
	"	cmp x10, #0		\n"
	"	bne 2f			\n"
	"	ldp x12,x13,[%0],#16	\n"	/* ldnp (don't cache) does not support post-indexed */
	"	cmp x11, #0		\n"
	"	bne 3f			\n"
	"	cmp x12, #0		\n"
	"	bne 4f			\n"
	"	cmp x13, #0		\n"
	"	bne 5f			\n"
	PREFETCH(256)
	"	cmp %0, %2		\n"	/* end? */
	"	blt 1b			\n"
	"	mov %0, %2		\n"	
	"	b 10f			\n"	/* exhausted search */
	"2:				\n"
	"	add %0, %0, #8		\n"	/* First u32 is non-zero */
	"	mov x11, x10		\n"
	"3:				\n"
	"	sub %0, %0, #8		\n"
	"	mov x12, x11		\n"
	"4:				\n"
	"	sub %0, %0, #8		\n"
	"	mov x13, x12		\n"
	"5:				\n"
	"	sub %0, %0, #8		\n"
//#ifndef __ARMEB__				/* Little endian bitmasks */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	"	rev x13, x13		\n"
#endif
	"	clz x12, x13		\n"
	"	add %0, %0, x12, lsr#3	\n"
	"10:				\n"
	: "=r"(res)
	: "0"(blk), "r"(end)
	: "x10", "x11", "x12", "x13");
	return res-blk;
}

void probe_arm8crypto()
{
	asm volatile(
	"	movi	v0.16b, #0		\n"
	"	movi	v1.16b, #0		\n"
	"	aese v1.16b, v0.16b		\n"
	:
	:
	: "v0", "v1");
}

#else
#warning no point compiling this on non-ARM64 arch
#endif
