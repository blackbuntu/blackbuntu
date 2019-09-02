/** splice.h
 * wrapper around syscall
 */

#ifndef _SPLICE_H
#define _SPLICE_H

#include <sys/syscall.h>
#include <sys/types.h>
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif

#define __KERNEL__
#include <asm/unistd.h>
#ifdef __NR_splice
# define HAVE_SPLICE 1
# ifndef SPLICE_F_MOVE	/* from fcntl.h on x86-64 linux */
#  define SPLICE_F_MOVE 1
#  define SPLICE_F_MORE 4
# endif
# if 1
typedef off64_t __off64_t;
static inline ssize_t splice(int fdin, off64_t *off_in, int fdout, 
			      off64_t *off_out, size_t len, unsigned int flags)
{
	return syscall(__NR_splice, fdin, off_in, fdout, off_out, len, flags);
}
# else
_syscall6(long, splice, int, fdin, loff_t*, off_in, int, fdout, loff_t*, off_out, size_t, len, unsigned int, flags);
# endif
#endif /* __NR_splice */
#undef __KERNEL__

#endif
