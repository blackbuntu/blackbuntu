/** Decl for int to str conversion with highlighting */

#ifndef _FMT_NO_H
#define _FMT_NO_H

#include <sys/types.h>
char* fmt_int_b(unsigned char pre, unsigned char post, unsigned int scale,
		loff_t no, const char* bold, const int blen,
		const char* norm, const int nlen,
		const char boldinvis, const unsigned char base,
		const unsigned char group);

#include <string.h>
static inline 
char* fmt_int(unsigned char pre, unsigned char post, unsigned int scale,
	       	loff_t no, const char* bold, const char* norm, const char boldinvis)
{ 
	return fmt_int_b(pre, post, scale, no, bold, (bold? strlen(bold): 0),
			 norm, (norm? strlen(norm): 0), boldinvis, 10, 3);
}

#endif

