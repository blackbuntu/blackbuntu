/* Header file for frandom.c */

#ifndef _FRANDOM_H
#define _FRANDOM_H

#include <sys/types.h>

/* frandom.c */
ssize_t frandom_bytes(void *rstate, unsigned char *buf, size_t count);
ssize_t frandom_bytes_inv(void *rstate, unsigned char *buf, size_t count);
int frandom_release(void* rstate);
void* frandom_init_lrand(int seedval);
void* frandom_init(unsigned char* seedbf);
void* frandom_stdup(const void* rstate);
void* frandom_stcopy(void* tostate, const void* fromstate);
unsigned int frandom_getseedval();

#endif
