/** ffs.h
 *
 * bit search functions header
 * ideally, we can juswt refer to libc,
 * if not, there's a open-coded C implementation here
 * and the possibility to use SSE4.2 popcnt insns on x86
 * (c) Kurt Garloff <kurt@garloff.de>, GNU GPL v2 or v3
 */

#ifndef _FFS_H
#define _FFS_H

/* HAVE_FFS */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/* ffs, ffsl */
#define _GNU_SOURCE 1
#include <string.h>
//#ifdef __BIONIC__
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
/* __BYTE_ORDER */
#include <sys/types.h>
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif


#ifdef HAVE_FFS
# define myffs(x) ffs(x)
# if __WORDSIZE == 32
#  define myffsl(x) ffs(x)
# else /* 64bit */
#  ifdef HAVE_FFSL
#   define myffsl(x) ffsl(x)
#  elif defined(__i386__) || defined(__x86_64__)
#   define NEED_FFSL_C 1
#   define myffsl(x) (have_sse42? myffsl_sse42(x): myffsl_c(x))
#  else 
#   define NEED_FFSL_C 1
#   define myffsl(x) myffsl_c(x)
#  endif
# endif
#elif defined(__i386__) || defined(__x86_64__)
# define NEED_FFSL_C 1
# define myffs(x) (have_sse42? myffs_sse42(x): myffs_c(x))
# define myffsl(x) (have_sse42? myffsl_sse42(x): myffsl_c(x))
#else
# define NEED_FFSL_C 1
# define myffs(x) myffsl_c(x)
# define myffsl(x) myffsl_c(x)
#endif

#ifndef __BYTE_ORDER
# error Need to define __BYTE_ORDER
#endif
#ifndef __WORDSIZE
# error Need to define __WORDSIZE
#endif

//#ifndef HAVE_FFS
#ifdef NEED_FFSL_C
/** Find first (lowest) bit set in word val, returns a val b/w 1 and __WORDSIZE, 0 if no bit is set */
static int myffsl_c(unsigned long val)
{
	int res = 1;
	if (!val)
		return 0;
#if __WORDSIZE == 64
	unsigned int vlo = val;
	unsigned int vhi = val >> 32;
	if (!vlo) {
		res += 32;
		vlo = vhi;
	}
#else
	unsigned int vlo = val;
#endif
	unsigned int mask = 0x0000ffff;
	unsigned int shift = 16;
	while (shift > 0) {
		if (!(vlo & mask)) {
			res += shift;
			vlo >>= shift;
		}
		shift >>= 1;
		mask >>= shift;
	}
	return res;
}
#endif

#if __BYTE_ORDER == __BIG_ENDIAN || defined(TEST)
/** Find last (highest) bit set in word val, returns a val b/w __WORDSIZE and 1, 0 if no bit is set */
static int myflsl(unsigned long val)
{
#if defined(HAVE_FFS) && (defined(__aarch64__) || defined(__ARM_ARCH_7A__))
	asm volatile(
	"	rbit %0, %0	\n"
	: "=r"(val)
	: "0"(val)
	);
	val = myffsl(val);
	return val? (__WORDSIZE+1)-val: 0;
#else
	int res = __WORDSIZE;
	if (!val)
		return 0;
#if __WORDSIZE == 64
	unsigned int vlo = val;
	unsigned int vhi = val >> 32;
	if (!vhi) {
		res -= 32;
		vhi = vlo;
	}
#else
	unsigned int vhi = val;
#endif
	unsigned int mask = 0xffff0000;
	unsigned int shift = 16;
	while (shift > 0) {
		if (!(vhi & mask)) {
			res -= shift;
			vhi <<= shift;
		}
		shift >>= 1;
		mask <<= shift;
	}
	return res;
#endif
}
#endif

void probe_sse42();

#endif /* _FFS_H */
