/** fallocate64.h
 * wrapper for syscall
 */

#ifndef _FALLOCATE64_H
#define _FALLOCATE64_H

#include <sys/syscall.h>
#include <sys/types.h>
#ifdef HAVE_ENDIAN_H
# include <endian.h>
#endif

#define __KERNEL__
#include <asm/unistd.h>
#ifdef __NR_fallocate
# ifndef FALLOC_FL_KEEP_SIZE
#  define FALLOC_FL_ADJUST_SIZE 0
#  define FALLOC_FL_KEEP_SIZE 1
# endif
/* Linux has a system call fallocate() since 2.6.23, but glibc
 * only provides the wrapper with glibc-2.10+
 * So add a (weak) fallocate symbol here.
 */
typedef off64_t __off64_t;
//static inline int fallocate64(int fd, int mode, __off64_t start, __off64_t len) __attribute__((weak));
static inline int fallocate64(int fd, int mode, __off64_t start, __off64_t len)
{
# if __WORDSIZE == 64
	/* Two extra 0ULL for strace */
	return syscall(__NR_fallocate, fd, mode,
			start, len /*, 0ULL, 0ULL*/);	
# else
#  if __BYTE_ORDER == __LITTLE_ENDIAN
	return syscall(__NR_fallocate, fd, mode,
			(int)start, (int)(start>>32),
			(int)len, (int)(len>>32));
#  else
	return syscall(__NR_fallocate, fd, mode,
			(int)(start>>32), (int)start,
			(int)(len>>32), (int)len);
#  endif
# endif /* __WORDSIZE */
}
# define HAVE_FALLOCATE64
#endif /* __NR_fallocate */
#undef __KERNEL__

#endif /* _FALLOCATE64_H */


