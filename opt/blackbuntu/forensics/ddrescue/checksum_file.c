/** checksum_file.c
 *  
 * Routines for CHECKSUMS.hash resp. KEYS.crypt file parsing and updating
 * also contains the xattr pieces that allow to store hashes or ivs
 * or even keys (bad idea!) in xattrs.
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 8/2014
 * License: GPL v2 or v3.
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "checksum_file.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "hash.h"

#ifdef __BIONIC__
#include <libgen.h>
#endif

#ifndef HAVE_FEOF_UNLOCKED
#define feof_unlocked(x) feof(x)
#endif

#ifndef HAVE_GETLINE
ssize_t getline(char **bf, size_t *sz, FILE *f)
{
	if (*sz == 0) {
		*bf = (char*)malloc(1024);
		*sz = 1024;
	}
	char* bret = fgets(*bf, *sz, f);
	if (!bret)
		return -1;
	int ln = strlen(bret);
	//if (bret[ln-1] != '\n') increase_buffersize();
	return ln;
}
#endif

#define MIN(a,b) ((a)<(b)? (a): (b))
#define MAX(a,b) ((a)<(b)? (b): (a))

/* file offset in the chksum file which has the chksum for nm, -1 = not found */
off_t find_chks(FILE* f, const char* nm, char* res, int wantedln)
{
	char *lnbf = NULL;
	size_t lln = 0;
	char* bnm = basename((char*)nm);
	while (!feof_unlocked(f)) {
		char *fnm, *fwh;
		off_t pos = ftello(f);
		ssize_t n = getline(&lnbf, &lln, f);
		if (n <= 0)
			break;
		fwh = strchr(lnbf, ' ');
		if (!fwh)
			continue;
		fnm = fwh;
		++fnm;
		if (*fnm == '*' || *fnm == ' ')
			fnm++;
		int last = strlen(fnm)-1;
		// Remove trailing \n\r
		while (last > 0 && (fnm[last] == '\n' || fnm[last] == '\r'))
			fnm[last--] = 0;
		//printf("\"%s\" <-> \"%s\"/\"%s\"\n", fnm, nm, bnm);
		if (!strcmp(fnm, nm) || !strcmp(fnm, bnm)) {
			if (wantedln && fwh-lnbf != wantedln)
				continue;
			if (res && fwh-lnbf <= 2*(int)sizeof(hash_t)+14) {
				const int ln = MIN(142, fwh-lnbf);
				memcpy(res, lnbf, ln);
				res[ln] = 0;
			} else if (res)
				*res = 0;
			free(lnbf);
			return pos;
		}
	}
	if (lnbf)
		free(lnbf);
	return -ENOENT;
}

FILE* fopen_chks(const char* fnm, const char* mode, int acc)
{
	if (!fnm)
		return NULL;
	if (!strcmp("-", fnm))
		return stdin;
	else {
		if (acc) {
			int fd;
			if (strcmp(mode, "w"))
				abort();
			fd = open(fnm, O_WRONLY|O_CREAT, acc);
			return fdopen(fd, mode);
		} else
			return fopen(fnm, mode);
	}
}

/* get chksum */
int get_chks(const char* cnm, const char* nm, char* chks, int wantedln)
{
	FILE *f = fopen_chks(cnm, "r", 0);
	if (!f)
		return -1;
	off_t err = find_chks(f, nm, chks, wantedln);
	if (f != stdin)
		fclose(f);
	return err < 0? err: 0;
}

/* update chksum */
int upd_chks(const char* cnm, const char *nm, const char *chks, int acc)
{
	FILE *f = fopen_chks(cnm, "r+", 0);
	int err = 0;
	char oldchks[144];
	char* bnm = basename(nm);
	if (!f) {
		errno = 0;
		f = fopen_chks(cnm, "w", acc);
		if (!f)
			return -errno;
		fprintf(f, "%s *%s\n", chks, bnm);
		err = -errno;
	} else {
		off_t pos = find_chks(f, nm, oldchks, strlen(chks));
		if (pos == -ENOENT || strlen(chks) != strlen(oldchks)) {
			fclose(f);
			f = fopen_chks(cnm, "a", 0);
			fprintf(f, "%s *%s\n", chks, bnm);
			err = -errno;
		} else {
			if (strcmp(chks, oldchks)) {
				if (pwrite(fileno(f), chks, strlen(chks), pos) <= 0)
					err = -errno;
				//pwrite(fileno(f), "*", 1, pos+strlen(chks)+1);
			}
		}
	}
	fclose(f);
	return err;
}

