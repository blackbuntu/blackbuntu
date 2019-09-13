#ifndef _RANDOM_H
#define _RANDOM_H

unsigned int random_getseedval32();
unsigned int random_bytes(unsigned char* buf, unsigned int ln, unsigned char nourand);

#endif
