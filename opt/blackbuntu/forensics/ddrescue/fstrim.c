/** fstrim.c
 *
 * issues a FITRIM on the filesystem
 * resulting in free blocks to be reported
 * to the underlying storage device.
 * Relevant for SSDs, MMC and thinly provisioned storage.
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 2014, GNU GPL v2 or v3
 */

#include "fstrim.h"
#include <string.h>


void mydirnm(char* nm)
{
	char* last = nm+strlen(nm)-1;
	while (last > nm && *last != '/')
		--last;
	if (last == nm) {
		*nm++ = '.'; *nm = 0;
	} else 
		*++nm = 0;
}

#ifdef FITRIM

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

loff_t fstrim(const char* onm, char quiet)
{
	char* dirnm = strdup(onm);
	mydirnm(dirnm);
	struct fstrim_range trim;
	int fd = open(dirnm, O_RDONLY);
	if (fd < 0) {
		free(dirnm);
		return -errno;
	}
	trim.start = 0;
	trim.len = (__u64)(-1);
	trim.minlen = 16384;
	if (!quiet) {
		fprintf(stderr, "dd_rescue: FITRIM %s ...\r", dirnm); 
		fflush(stderr);
	}
	int trimerr = ioctl(fd, FITRIM, &trim);
	close(fd);
	free(dirnm);
	return (trimerr? -errno: trim.len);
}
#else
# warning compiling fstrim only makes sense with FITRI support
#endif


