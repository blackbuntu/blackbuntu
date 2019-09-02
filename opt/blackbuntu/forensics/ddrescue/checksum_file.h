#ifndef _CHECKSUM_FILE_H
#define _CHECKSUM_FILE_H

//#include "ddr_plugin.h"

//off_t find_chks(FILE* f, const char* nm, char* res);
int get_chks(const char* cnm, const char *nm, char *chks, int wantedln);
int upd_chks(const char* cnm, const char *nm, const char *chks, int mode);

#endif
