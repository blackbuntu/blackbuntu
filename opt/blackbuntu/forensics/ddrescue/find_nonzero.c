/** find_nonzero.c
 *
 * Test & Benchmark program for find_nonzero()
 * (c) Kurt Garloff <kurt@garloff.de>, 2013
 * License: GNU GPL v2 or v3
 */

#define _GNU_SOURCE 1
#define IN_FINDZERO

#include "find_nonzero.h"

#include <stdio.h>

char cap_str[64];
char FNZ_OPT[64];

ARCH_DECLS

#include <signal.h>
#include <setjmp.h>
static sig_atomic_t have_feature;
static jmp_buf sigill_jmp;
static void ill_handler(int sig)
{
	/* As we can't return from handler (as it would result in 
	 * reexecuting the illegal instruction again - we jump back
	 * using longjmp) -- we have to restore signal delivery, so the
	 * program context is back to normal. Otherwise a second
	 * probe_procedure would not handle SIGILL. */
	sigset_t sigmask;
	sigemptyset(&sigmask); sigaddset(&sigmask, sig);
	sigprocmask(SIG_UNBLOCK, &sigmask, NULL);
	longjmp(sigill_jmp, 1);
}

char probe_procedure(void (*probefn)(void))
{
	signal(SIGILL, ill_handler);
	if (setjmp(sigill_jmp) == 0) {
		probefn();
		asm volatile("" : : : "memory");
		have_feature = 1;
	} else {
		have_feature = 0;
	}
	signal(SIGILL, SIG_DFL);
	return have_feature;
}

void detect_cpu_cap()
{
	*cap_str = 0;
	ARCH_DETECT;
	sprintf(FNZ_OPT, "find_nonzero_%s", OPT_STR2);
}

#if defined(TEST) && (defined(__i386__) || defined(__x86_64__))
/** Just for testing the speed of the good old x86 string instructions */
size_t find_nonzero_rep(const unsigned char* blk, const size_t ln)
{
	unsigned long register res;
	asm volatile (
	"	xor %%al, %%al	\n"
	"	repz scasb	\n"
	"	je 1f		\n"
#ifdef __i386__
	"	inc %%ecx	\n"
#else
	"	inc %%rcx	\n"
#endif
	"	1:		\n"
		: "=c"(res), "=D"(blk): "0"(ln), "1"(blk): "al");
	return ln - res;
}
#define HAVE_NONZERO_REP
#endif

#ifdef TEST
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>

#define SIZE (64*1024*1024)

#define mem_clobber	asm("": : : "memory")
#define RTESTC(sz,routine,rnm,rep,tsz) 	\
	memset(buf, 0, sz);		\
	if (sz<tsz) buf[sz] = 1;	\
	expect = (tsz<sz? tsz: sz);	\
	gettimeofday(&t1, NULL);	\
	for (i = 0; i < rep; ++i) {	\
		mem_clobber;		\
		ln = routine(buf, tsz);	\
	}				\
	gettimeofday(&t2, NULL);	\
	tdiff = t2.tv_sec-t1.tv_sec + 0.000001*(t2.tv_usec-t1.tv_usec);	\
	printf("%7i x %20s (%8i): %8i (%6.3fs => %5.0fMB/s)\n",	\
		rep, rnm, sz, ln, tdiff, (double)(rep)*(double)(expect+1)/(1024*1024*tdiff));	\
	if (ln != expect)		\
		abort()


#define RTEST2C(sz,routine,rnm,rep,tsz) \
	memset(buf, 0, tsz);		\
	if (sz<tsz) buf[sz]= 1;		\
	expect = (tsz<sz? tsz: sz);	\
	gettimeofday(&t1, NULL);	\
	buf[sz] = 0x4c;			\
	gettimeofday(&t1, NULL);	\
	for (i = 0; i < rep; ++i) {	\
		mem_clobber;		\
		ln = routine(buf, tsz);	\
	}				\
	gettimeofday(&t2, NULL);	\
	tdiff = t2.tv_sec-t1.tv_sec + 0.000001*(t2.tv_usec-t1.tv_usec);	\
	printf("%7i x %20s (%8i): %8i (%6.3fs => %5.0fMB/s)\n",	\
		rep, rnm, sz, ln, tdiff, (double)(rep)*(double)(expect+1)/(1024*1024*tdiff));	\
	if (ln != expect)		\
		abort()

#define TESTC(sz,rtn,rep,tsz) RTESTC(sz,rtn,#rtn,rep,tsz)
#define TEST2C(sz,rtn,rep,tsz) RTEST2C(sz,rtn,#rtn,rep,tsz)

#ifdef HAVE_OPT
#define TEST_SIMD(a,b,c,d) RTESTC(a,b,FNZ_OPT,c*2,d)
#define TEST2_SIMD(a,b,c,d) RTEST2C(a,b,FNZ_OPT,c*2,d)
#else
#define TEST_SIMD(a,b,c,d) do {} while (0)
#define TEST2_SIMD(a,b,c,d) do {} while (0)
#endif

#ifdef __SSE2__
#ifdef __x86_64__
#define TEST_SIMD2(a,b,c,d) TESTC(a,b,c*2,d)
#define TEST2_SIMD2(a,b,c,d) TEST2C(a,b,c*2,d)
#else
#define TEST_SIMD2(a,b,c,d) if (have_sse2) { TESTC(a,b,c*2,d); }
#define TEST2_SIMD2(a,b,c,d) if (have_sse2) { TEST2C(a,b,c*2,d); }
#endif
#else
#define TEST_SIMD2(a,b,c,d) do {} while (0)
#define TEST2_SIMD2(a,b,c,d) do {} while (0)
#endif

#if defined(HAVE_NONZERO_REP)
#define TEST_REP(a,b,c,d) TESTC(a,b,c,d)
#else
#define TEST_REP(a,b,c,d) do {} while (0)
#endif

#define TESTFFS(val) printf("%08x: last %i first %i\n", val, myffsl(val), myflsl(val));
#if __WORDSIZE == 64
#define TESTFFS64(val) printf("%016Lx: last %i first %i\n", val, myffsl(val), myflsl(val));
#else
#define TESTFFS64(val) do {} while (0)
#endif

int main(int argc, char* argv[])
{
	unsigned char* obuf = (unsigned char*)malloc(SIZE+31);
	unsigned char* buf = (obuf+31)-((unsigned long)(obuf+31)%32);
	struct timeval t1, t2;
	int i, expect, ln = 0;
	double tdiff;
	int scale = 16;
	detect_cpu_cap();

	printf("Using extensions: %s\n", OPT_STR);
	TESTFFS(0x00000000);
	TESTFFS(0x00000001);
	TESTFFS(0x80000000);
	TESTFFS(0x05000100);
	TESTFFS(0x00900002);
	TESTFFS(0x00000100);
	TESTFFS(0x80400000);
	TESTFFS64(0x0030000000000100ULL);
	TESTFFS64(0x1000000000000000ULL);
	TESTFFS64(0x0000000000001000ULL);

	if (argc > 1)
		scale = atoi(argv[1]);
	memset(buf, 0xa5, SIZE);

	ln = find_nonzero_c  (buf, SIZE);
	ln = find_nonzero    (buf, SIZE);
	ln = FIND_NONZERO_OPT(buf, SIZE);
	
	TESTC    (0, find_nonzero_c,    1024*512*scale/16, SIZE);
	TEST_SIMD(0, FIND_NONZERO_OPT,  1024*512*scale/16, SIZE);
	TESTC    (0, find_nonzero,      1024*512*scale/16, SIZE);
	TEST_REP (0, find_nonzero_rep,  1024*512*scale/16, SIZE);
	
	TESTC    (8*1024-15, find_nonzero_c,    1024*128*scale/16, SIZE);
	TEST_SIMD(8*1024-15, FIND_NONZERO_OPT,  1024*128*scale/16, SIZE);
	TESTC    (8*1024-15, find_nonzero,      1024*128*scale/16, SIZE);
	TEST_REP (8*1024-15, find_nonzero_rep,  1024*128*scale/16, SIZE);
	buf++;
	TESTC    (8*1024-15, find_nonzero,      1024*128*scale/16, SIZE);
	TEST_REP (8*1024-15, find_nonzero_rep,  1024*128*scale/16, SIZE);
	buf--;
	TESTC     (32*1024-9, find_nonzero_c,     1024*32*scale/16, SIZE);
	TEST_SIMD (32*1024-9, FIND_NONZERO_OPT,   1024*32*scale/16, SIZE);
	TEST_SIMD2(32*1024-9, find_nonzero_sse2o, 1024*32*scale/16, SIZE);
	TESTC     (32*1024-9, find_nonzero,       1024*32*scale/16, SIZE);
	TEST_REP  (32*1024-9, find_nonzero_rep,   1024*32*scale/16, SIZE);
	TESTC    (128*1024-8, find_nonzero_c,    1024*8*scale/16, SIZE);
	TEST_SIMD(128*1024-8, FIND_NONZERO_OPT,  1024*8*scale/16, SIZE);
	TEST_REP (128*1024-8, find_nonzero_rep,  1024*8*scale/16, SIZE);
	TESTC    (1024*1024-7, find_nonzero_c,    1024*scale/16, SIZE);
	TEST_SIMD(1024*1024-7, FIND_NONZERO_OPT,  1024*scale/16, SIZE);
	TEST_REP (1024*1024-7, find_nonzero_rep,  1024*scale/16, SIZE);
	TESTC    (4096*1024-1, find_nonzero_c,    256*scale/16, SIZE);
	TEST_SIMD(4096*1024-1, FIND_NONZERO_OPT,  256*scale/16, SIZE);
	TESTC    (16*1024*1024, find_nonzero_c,    64*scale/16, SIZE);
	TEST_SIMD(16*1024*1024, FIND_NONZERO_OPT,  64*scale/16, SIZE);
	TESTC    (64*1024*1024, find_nonzero_c,    16*scale/16, SIZE);
	TEST_SIMD(64*1024*1024, FIND_NONZERO_OPT,  16*scale/16, SIZE);
	
	TESTC    (64*1024*1024, find_nonzero_c,    1+scale/16, SIZE-16);
	TEST_SIMD(64*1024*1024, FIND_NONZERO_OPT,  1+scale/16, SIZE-16);
	TESTC    (64*1024*1024, find_nonzero,      1+scale/16, SIZE-16);
	TEST_REP (64*1024*1024, find_nonzero_rep,  1+scale/16, SIZE-16);

	TESTC    (64*1024*1024, find_nonzero_c,    1+scale/16, SIZE-5);
	TEST_SIMD(64*1024*1024, FIND_NONZERO_OPT,  1+scale/16, SIZE-5);
	TESTC    (64*1024*1024, find_nonzero,      1+scale/16, SIZE-5);
	TEST_REP (64*1024*1024, find_nonzero_rep,  1+scale/16, SIZE-5);

	TEST2C     (12*1024*1024, find_nonzero_c,     80*scale/16, SIZE);
	TEST2_SIMD (12*1024*1024, FIND_NONZERO_OPT,   80*scale/16, SIZE);
	TEST2_SIMD2(12*1024*1024, find_nonzero_sse2o, 80*scale/16, SIZE);

	free(obuf);
	return 0;
}
#endif
