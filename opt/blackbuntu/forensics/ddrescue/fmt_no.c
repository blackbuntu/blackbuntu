/** Convert long integer to strings with highlighting 
 * (c) Kurt Garloff <kurt@garloff.de>, 2013
 * License: GNU GPL v2 or v3
 */

#define _LARGEFILE_SOURCE
#define _FILE_OFFSET_BITS 64

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "fmt_no.h"
#include <string.h>

#ifdef TEST
#define BOLD "\x1b[0;32m"
//#define BOLD "\x1b[0;1m"
#define NORM "\x1b[0;0m"
#endif

//typedef long long off_t;

static int mypow(int base, int pwr)
{
	int i;
	int pw = 1;
	for (i = 0; i < pwr; ++i)
		pw *= base;
	return pw;
}

static char fmtbufs[8][64];

/** Format integers: pre digits before the ., post digits after.
 * The integer is divided by scale prior to being returned as string.
 * The string has groups of <group> digits that are highlighted with bold
 * and norm strings. If boldinvis is set, the number will be prefixed
 * with bold if the foremost group should be bold ...
 * Limitations: 
 * - We can't return more than 8 strings in parallel, before
 *   we start overwriting buffers. 
 * - The string can't be longer than 64 chars, which should be
 *   enough though to print all possible 64bit ints.
 * - bold and norm need to be either invisible (boldinvis=1)
 *   or a single (visible) character or empty/NULL
 */
char* fmt_int_b(unsigned char pre, unsigned char post, unsigned int scale,
		loff_t no, const char* bold, const int blen,
		const char* norm, const int nlen,
		const char boldinvis, const unsigned char base,
		const unsigned char group)
{
	static int fbno = -1;
	int idx = sizeof(fmtbufs[0])-1;
	char pos;
	loff_t my_no;
	char* fmtbuf = fmtbufs[++fbno%8];
	char isneg = no < 0;
	const unsigned char twogroup = group? 2*group: 127;
	if (!scale)
		scale = 1;
	fmtbuf[idx] = 0;
	no = (isneg? -no: no);
	if (post) {
		/* Avoid 64bit overflow */
		my_no = (no * mypow(base, post) + scale/2) / scale;
		if (my_no < 0)
			my_no = 0;
		while (post--) {
			unsigned char digit = my_no - base*(my_no/base);
			fmtbuf[--idx] = digit >= 10? 'a'-10+digit: '0' + digit;
			my_no /= base;
		}
		fmtbuf[--idx] = '.';
		my_no = no / scale;
	} else
		my_no = (no + scale/2) / scale;
	for (pos = 0; (pos < pre-isneg || !pre) && (my_no || !pos); ++pos) {
		unsigned char digit = my_no - base*(my_no/base);
		if (blen && pos && !(pos % twogroup)) {
			/* insert bold */
			memcpy(fmtbuf+idx-blen, bold, blen);
			idx -= blen;
			if (!boldinvis && pre && --pre <= pos+isneg) {
				pos++; break;
			}
		} else if (nlen && !((pos+group) % twogroup)) {
			/* insert norm */
			memcpy(fmtbuf+idx-nlen, norm, nlen);
			idx -= nlen;
			if (!boldinvis && pre && --pre <= pos+isneg) {
				pos++; break;
			}
		}
		fmtbuf[--idx] = digit >= 10? 'a'-10+digit: '0' + digit;
		my_no /= base;
	}
	/* overflow */
	if (my_no) {
		if (post)
			fmtbuf[sizeof(fmtbufs[0])-2] = '+';
		else if (!isneg)
			++idx;
	}
	/* Do we need a leading bold? */
	if (bold && boldinvis && group && ((pos-1) % twogroup >= group)) {
		memcpy(fmtbuf+idx-blen, bold, blen);
		idx -= blen;
	}
	if (isneg) {
		if (my_no && !post)
			fmtbuf[--idx] = '<';
		else
			fmtbuf[--idx] = '-';
	} else if (my_no && !post)
		fmtbuf[--idx] = '>';
	/* Fill */
	if (pos+isneg < pre) {
		memset(fmtbuf+idx+pos+isneg-pre, ' ', pre-pos-isneg);
		idx -= pre-pos-isneg;
	}
	return fmtbuf+idx;
}

#ifdef TEST
#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv)
{
	int i; loff_t l;
	for (i = 1; i < argc; ++i) {
		l = atoll(argv[i]);
		printf("%16.2f:\n%s\n_%s\n__%s\n___%s\n",
			(double)l/1024.0, 
			fmt_int(13, 1, 1024, l, BOLD, NORM, 1),
			fmt_int(12, 1, 1024, l, BOLD, NORM, 1),
			fmt_int(11, 1, 1024, l, BOLD, NORM, 1),
			fmt_int(10, 1, 1024, l, BOLD, NORM, 1));
		printf("____%s\n_____%s\n______%s\n_______%s\n________%s\n_________%s\n%s\n",
			fmt_int( 9, 2, 1024, l, BOLD, NORM, 1),
			fmt_int( 8, 2, 1024, l, BOLD, NORM, 1),
			fmt_int( 7, 2, 1024, l, BOLD, NORM, 1),
			fmt_int( 6, 2, 1024, l, BOLD, NORM, 1),
			fmt_int( 5, 2, 1024, l, ",", ",", 0),
			fmt_int( 4, 2, 1024, l, ",", ",", 0),
			fmt_int(13, 2, 1024, l, ",", ",", 0));
		printf("____%s\n_____%s\n______%s\n_______%s\n________%s\n_________%s\n%s\n",
			fmt_int( 9, 0, 1024, l, BOLD, NORM, 1),
			fmt_int( 8, 0, 1024, l, BOLD, NORM, 1),
			fmt_int( 7, 0, 1024, l, BOLD, NORM, 1),
			fmt_int( 6, 0, 1024, l, BOLD, NORM, 1),
			fmt_int( 5, 0, 1024, l, ",", ",", 0),
			fmt_int( 4, 0, 1024, l, ",", ",", 0),
			fmt_int(13, 0, 1024, l, ",", ",", 0));
		const int bln = strlen(BOLD), nln = strlen(NORM);
		printf("\n%s\n", fmt_int(0, 1, 1024, l, BOLD, NORM, 1));
		printf("%s\n",   fmt_int_b(0, 1, 1024, l, BOLD, bln, NORM, nln, 1, 10, 0));
		printf("0x%s\n\n", fmt_int_b(0, 1, 1024, l, BOLD, bln, NORM, nln, 1, 16, 4));
		printf("%s\n",   fmt_int_b(0, 0, 1024, l, BOLD, bln, NORM, nln, 1, 10, 3));
		printf("%s\n\n", fmt_int_b(0, 0, 1024, l, BOLD, bln, NORM, nln, 0, 10, 3));
		printf("%s\n",   fmt_int_b(0, 0, 1024, l, "", 0, "", 0, 1, 10, 3));
		printf("%s\n",   fmt_int_b(0, 0, 1024, l, "", 0, "", 0, 0, 10, 3));
		printf("%s\n",   fmt_int_b(0, 0, 1024, l, NULL, 0, NULL, 0, 1, 10, 3));
		printf("%s\n",   fmt_int_b(0, 0, 1024, l, NULL, 0, NULL, 0, 0, 10, 3));
	}
	return 0;
}
#endif



