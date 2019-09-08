/** find_nonzero_arm.c
 *
 * ARM assembler optimized version to find first non-zero byte in a block
 * (c) Kurt Garloff <kurt@garloff.de>, GNU GPL v2 or v3
 */

#include "find_nonzero.h"

#if defined(__arm__) && !defined(__a64__)
/** ASM optimized version for ARM.
 * Inspired by Linaro's strlen() implementation; 
 * we don't even need NEON here, ldmia does the 3x speedup on Cortexes */
size_t find_nonzero_arm6(const unsigned char *blk, const size_t ln)
{
	/*
	if (!ln || *blk)
		return 0;
	 */
	register unsigned char* res;
	const register unsigned char* end = blk+ln;
	asm volatile(
	//".align 4			\n"
	"1:				\n"
	"	ldmia %0!,{r2,r3}	\n"
	"	cmp r2, #0		\n"
	"	bne 2f			\n"
	"	ldmia %0!,{r4,r5}	\n"
	"	cmp r3, #0		\n"
	"	bne 3f			\n"
	"	cmp r4, #0		\n"
	"	bne 4f			\n"
	"	cmp r5, #0		\n"
	"	bne 5f			\n"
	"	cmp %0, %2		\n"	/* end? */
	"	blt 1b			\n"
	"	mov %0, %2		\n"	
	"	b 10f			\n"	/* exhausted search */
	"2:				\n"
	"	add %0, #4		\n"	/* First u32 is non-zero */
	"	mov r3, r2		\n"
	"3:				\n"
	"	sub %0, #4		\n"
	"	mov r4, r3		\n"
	"4:				\n"
	"	sub %0, #4		\n"
	"	mov r5, r4		\n"
	"5:				\n"
	"	sub %0, #4		\n"
#ifdef __ARM_FEATURE_CLZ
#if __BYTE_ORDER == __LITTLE_ENDIAN
#if defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_6__)
	"	rev r5, r5		\n"
#else
#warning open code rev for ARMv5
	"	eor r4,r5,r5, ror #16	\n"
	"	bic r4,r4,#0x00FF0000	\n"
	"	mov r5,r5,ror #8	\n"
	"	eor r5,r5,r4, lsr #8	\n"
#endif
#endif
	"	clz r4, r5		\n"
	"	add %0, %0, r4, lsr#3	\n"
#else
//#ifndef __ARMEB__				/* Little endian bitmasks */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	"	tst r5, #0xff		\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst r5, #0xff00		\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst r5, #0xff0000	\n"
#else
	"	tst r5, #0xff000000	\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst r5, #0xff0000	\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst r5, #0xff00		\n"
#endif
	"	bne 10f			\n"
	"	add %0, #1		\n"	
#endif
	"10:				\n"
	: "=r"(res)
	: "0"(blk), "r"(end)
	: "r2", "r3", "r4", "r5");
	return res-blk;
}

void probe_arm8crypto_32()
{
	asm volatile(
	"	.fpu crypto-neon-fp-armv8	\n"
	"	veor	q0, q0, q0		\n"
	"	veor 	q1, q1, q1		\n"
	"	aese.8	q1, q0			\n"
	:
	:
	: "q0", "q1");
}

#else
#warning no point compiling this on non-ARM 32bit arch
#endif
