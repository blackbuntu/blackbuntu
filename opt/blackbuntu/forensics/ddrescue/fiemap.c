/* fiemap.c */
/* Implements the routines to locate blocks of a file
 * in the block device the holds the filesystem.
 * It uses Linux' fiemap icotl and does some additional
 * sanity checks.
 */

#define _LARGEFILE_SOURCE 1
#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE 1
#include "fstrim.h"
#include "fiemap.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include <unistd.h>

#include <sys/stat.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>

#include <assert.h>

#include <signal.h>

#ifdef __BIONIC__
# include <libgen.h>
#endif

#ifndef FIFREEZE
# define FIFREEZE	_IOWR('X', 119, int)	/* Freeze */
# define FITHAW		_IOWR('X', 120, int)	/* Thaw */
#endif

char quiet = 0;

int unfreeze_fd = 0;

void unfreeze_handler(int sig)
{
	if (unfreeze_fd)
		ioctl(unfreeze_fd, FITHAW, 0);
	unfreeze_fd = 0;
	signal(sig, SIG_DFL);
	raise(sig);
}

int alloc_and_get_mapping(const int fd, const uint64_t start, const uint64_t len, 
			  struct fiemap_extent **ext, const int needfreeze)
{
	int err;
	struct fiemap fmap;
	sync();
	//struct fiemap_extent *fmap_exts;
	fmap.fm_start = start;
	fmap.fm_length = len;
	fmap.fm_flags = FIEMAP_FLAG_SYNC;
	fmap.fm_extent_count = 0;
	err = ioctl(fd, FS_IOC_FIEMAP, &fmap);
	if (err != 0)
		return -errno;
	if (fmap.fm_mapped_extents)
		++fmap.fm_mapped_extents;
	struct fiemap *fm = (struct fiemap*) malloc(sizeof(struct fiemap) 
			+ sizeof(struct fiemap_extent)*fmap.fm_mapped_extents);
	if (!fm)
		return -errno;
	fm->fm_start = start;
	fm->fm_length = len;
	fm->fm_flags = 0;
	fm->fm_extent_count = fmap.fm_mapped_extents;
	/* TODO: FREEZE */
	err = ioctl(fd, FIFREEZE, 0);
	if (err != 0 && needfreeze) {
		free(fm);
		ext = NULL;
		return -errno;
	}
	if (!err) {
		unfreeze_fd = fd;
		signal(SIGINT, unfreeze_handler);
		signal(SIGQUIT, unfreeze_handler);
		signal(SIGTERM, unfreeze_handler);
		signal(SIGHUP, unfreeze_handler);
		signal(SIGBUS, unfreeze_handler);
		signal(SIGSEGV, unfreeze_handler);
	}
	err = ioctl(fd, FS_IOC_FIEMAP, fm);
	if (err != 0 || fm->fm_mapped_extents == 0) {
		free(fm);
		ext = NULL;
		err = errno;
		ioctl(fd, FITHAW, 0);
		return -err;
	}
	/* Correct last extent length */
	struct fiemap_extent *lastext = fm->fm_extents+(fm->fm_mapped_extents-1);
	if (lastext->fe_flags & FIEMAP_EXTENT_LAST) 
		lastext->fe_length = len-lastext->fe_logical;
	*ext = fm->fm_extents;
	return fm->fm_mapped_extents;
}

void free_mapping(const int fd, struct fiemap_extent *ext)
{
	if (fd > 0)
		ioctl(fd, FITHAW, 0);
	unfreeze_fd = 0;
	/* TODO: Remove signal handlers */
	if (ext)
		free(((char*)ext) - sizeof(struct fiemap));
}

struct fiemap_extent* copy_ext(const struct fiemap_extent *ext, const int nr)
{
	struct fiemap_extent *copy = (struct fiemap_extent*)malloc(nr*sizeof(struct fiemap_extent));
	if (!copy)
		return copy;
	memcpy(copy, ext, nr*sizeof(struct fiemap_extent));
	return copy;
}

static char _devnm_str[64];
char* devname(const dev_t dev)
{
	unsigned maj = (dev & 0xfff00) >> 8;
        unsigned min = (dev & 0xff) | ((dev >> 12) & 0xfff00);
	char partln[128];
	FILE *f = fopen("/proc/partitions", "r");
	if (!f)
		return NULL;
	int found = 0;
	char pnm[32];
	while (fgets(partln, 128, f) != 0) {
		unsigned pmaj, pmin;
	       	unsigned long psz;
		if (!*partln || *partln == '\n' || isalpha(*partln))
			continue;
		sscanf(partln, "%i %i %li %s",
			&pmaj, &pmin, &psz, pnm);
		if (maj == pmaj && min == pmin) {
			++found;
			break;
		}
	}
	fclose(f);
	if (!found)
		return NULL;
	struct stat64 st;
	sprintf(_devnm_str, "/dev/%s", pnm);
	if (!stat64(_devnm_str, &st))
		if (S_ISBLK(st.st_mode) && st.st_rdev == dev)
			return _devnm_str;
	sprintf(_devnm_str, "/dev/block/%s", pnm);
	if (!stat64(_devnm_str, &st))
		if (S_ISBLK(st.st_mode) && st.st_rdev == dev)
			return _devnm_str;
	return NULL;
}

static char _fiemap_str[128];
char* fiemap_str(const uint32_t flags)
{
	_fiemap_str[0] = 0;
	if (flags & FIEMAP_EXTENT_UNKNOWN)
		strcat(_fiemap_str, "UNKNOWN ");
	if (flags & FIEMAP_EXTENT_DELALLOC)
		strcat(_fiemap_str, "(DELALLOC) ");
	if (flags & FIEMAP_EXTENT_ENCODED)
		strcat(_fiemap_str, "ENCODED ");
	if (flags & FIEMAP_EXTENT_DATA_ENCRYPTED)
		strcat(_fiemap_str, "(DATA_ENCRYPTED) ");
	if (flags & FIEMAP_EXTENT_NOT_ALIGNED)
		strcat(_fiemap_str, "NOT_ALIGNED ");
	if (flags & FIEMAP_EXTENT_DATA_INLINE)
		strcat(_fiemap_str, "(DATA_INLINE) ");
	if (flags & FIEMAP_EXTENT_DATA_TAIL)
		strcat(_fiemap_str, "(DATA_TAIL) ");
	if (flags & FIEMAP_EXTENT_UNWRITTEN)
		strcat(_fiemap_str, "UNWRITTEN ");
	if (flags & FIEMAP_EXTENT_MERGED)
		strcat(_fiemap_str, "MERGED ");
	if (flags & FIEMAP_EXTENT_LAST)
		strcat(_fiemap_str, "LAST ");
	return _fiemap_str;
}
// FIXME: Is UNWRITTEN really dangerous?
#define FIEMAP_DANGEROUS (FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_ENCODED | FIEMAP_EXTENT_NOT_ALIGNED | FIEMAP_EXTENT_UNWRITTEN)


#define BLKSZ 16384
int compare_ext(const int fd1, const int fd2, const struct fiemap_extent* ext, uint64_t offset)
{
	/* FIXME: Is comparing one block enough? */
	unsigned char *b1 = (unsigned char*)malloc(BLKSZ);
	if (!b1)
		return -1;
	unsigned char *b2 = (unsigned char*)malloc(BLKSZ);
	if (!b2) {
		free(b1);
		return -1;
	}
	ssize_t toread = ext->fe_length < BLKSZ? ext->fe_length: BLKSZ;
	ssize_t rd1 = pread(fd1, b1, toread, ext->fe_logical);
	/* Not needed anymore since we correct this when getting the mapping */
	/*
	if (rd1 > 0 && rd1 < toread && (ext->fe_flags & FIEMAP_EXTENT_LAST))
		toread = rd1;
	 */
	ssize_t rd2 = pread(fd2, b2, toread, ext->fe_physical+offset);
	int res;
	if (rd1 != toread || rd2 != toread) 
		res = -1;
	else
		res = memcmp(b1, b2, toread);
	free(b2); free(b1);
	return res;
}

#if __WORDSIZE == 64
#define LL "l"
#elif __WORDSIZE == 32
#define LL "ll"
#else
#error __WORDSIZE undefined
#endif


int64_t fstrim_ext(const char* dirname, const struct fiemap_extent* ext, const int nrext)
{
	struct fstrim_range trim;
	int64_t tottrim = 0;
	int i, fd = open(dirname, O_RDONLY);
	if (fd < 0) {
		int err = errno;
		fprintf(stderr, "Can't open dir %s: %s\n",
			dirname, strerror(errno));
		return -err;
	}
	for (i = 0; i < nrext; ++i) {
		int j;
		uint64_t accln = ext[i].fe_length;
		if (ext[i].fe_flags & FIEMAP_DANGEROUS)
			continue;
		/*
		if (compare_ext(fd, fd2, ext+i))
			continue;
		 */
		for (j = i+1; j < nrext; ++j) {
			if (ext[j].fe_flags & FIEMAP_DANGEROUS)
				break;
			if (ext[j].fe_physical != ext[i].fe_physical + accln)
				break;
			/*
			if (compare_ext(fd, fd2, ext+j))
				break;
			 */
			accln += ext[j].fe_length;
		}
		trim.start = ext[i].fe_physical;
		trim.len = accln;
		trim.minlen = 16384;
		int trimerr = ioctl(fd, FITRIM, &trim);
		if (!trimerr)
			tottrim += trim.len;
#ifdef DEBUG
		printf("0x%" LL "x/%" LL "x bytes trimmed\n", trimerr? 0: (uint64_t)trim.len, accln);
#endif
		i = j-1;
	}
	close(fd);
	return tottrim;
}

static char _fulldevnm[32]; 
char* strippart(const char* partname)
{
	strncpy(_fulldevnm, partname, 31);
	char* noptr = _fulldevnm + strlen(_fulldevnm);
	while (isdigit(*--noptr));
	*++noptr = 0;
	return _fulldevnm;
}

#include <linux/hdreg.h>
/* Get partition offset in sectors for block device devnm */
int64_t partoffset(const char* devnm)
{
	struct hd_geometry hdgeo;
	int fd = open/*64*/(devnm, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open %s: %s\n", devnm, strerror(errno));
		return -1;
	}
	int err = ioctl(fd, HDIO_GETGEO, &hdgeo);
	int64_t ret = -1;
	if (err) 
		fprintf(stderr, "HDIO_GETGEO ioctl on %s failed: %s\n", devnm, strerror(errno));
	else
		ret = hdgeo.start;
	close(fd);
#if __WORDSIZE == 64 && !defined(PARTOFFPARANOIA)
	return ret;
#else
	if (ret < 1)
		return ret;
	const char* basedevnm = basename(devnm);
	char sysdevnm[128];
	sprintf(sysdevnm, "/sys/block/%s/%s/start", strippart(basedevnm), basedevnm);
	FILE *f = fopen(sysdevnm, "r");
	int64_t val;
	if (!f)
		return -1;
	err = fscanf(f, "%" LL "i", &val);
	if (err != 1)
		fprintf(stderr, "Ouch, failed parsing start ...%" LL "i\n", val);
	fclose(f);
	if ((val & 0xffffffff) != ret) {
		fprintf(stderr, "Val. inconsistent: %" LL "x <-> %" LL "x\n",
			ret, val);
		return -1;
	}
	if (val != ret)
		fprintf(stderr, "Warn: HDGETGEO does not work well on 32bit system ....");
	return val;
#endif
}

#ifdef TEST_FIEMAP

void usage()
{
	fprintf(stderr, "Usage: fiemap FILENAME [FILENAME [...]]\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	int fno = 1, errs = 0;
	int dotrim = 0;
	if (argc < 2)
		usage();
	if (!strcmp(argv[1], "-t")) {
		++dotrim;
		++fno;
	}
	for (; fno < argc; ++fno) {
		struct fiemap_extent *ext = NULL;
		struct stat64 st;
		int i, err, fd2 = 0;
		int fd = open/*64*/(argv[fno], O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "Can't open %s: %s\n", argv[fno], strerror(errno));
			++errs;
			continue;
		}
		err = fstat64(fd, &st);
		if (err) {
			fprintf(stderr, "Can't stat %s: %s\n", argv[fno], strerror(errno));
			close(fd);
			++errs;
			continue;
		}
		err = alloc_and_get_mapping(fd, 0, st.st_size, &ext, 0);
		if (err <= 0) {
			fprintf(stderr, "Can't get extents for %s: %s\n", argv[fno], strerror(-err));
			close(fd);
			++errs;
			continue;
		}
		char* dnm = devname(st.st_dev);
		if (*dnm) {
			fd2 = open/*64*/(dnm, O_RDONLY);
			if (fd2 < 0)
				fprintf(stderr, "Could not open %s for comparison: %s\n",
					dnm, strerror(errno));
			ioctl(fd2, BLKFLSBUF, 0);
		}
		printf("Extents for %s (ino %" LL "i) on dev %s (0x%08" LL "x bytes): %i\n",
			argv[fno], st.st_ino, devname(st.st_dev), st.st_size, err);
		for (i = 0; i < err; ++i) {
			printf(" %08" LL "x @ %010" LL "x: %012" LL "x %s\n", 
				(uint64_t)ext[i].fe_length,
				(uint64_t)ext[i].fe_logical, 
				(uint64_t)ext[i].fe_physical,
				fiemap_str(ext[i].fe_flags));
			if (fd2 > 0 && compare_ext(fd, fd2, ext+i, 0)) {
				printf(" Comparison failed!!!\n");
				dotrim = 0;
			}
		}
		if ((ext[err-1].fe_flags & FIEMAP_EXTENT_LAST) == 0)
			printf(" (INCOMPLETE)\n");
		int64_t poffs = partoffset(dnm);
		printf("Partition offset for dev %s: 0x%" LL "x sectors\n", dnm, poffs);
		if (poffs > 0 && fd2 > 0) {
			close(fd2);
			fd2 = open/*64*/(strippart(dnm), O_RDONLY);
			if (fd2 < 0)
				break;
			ioctl(fd2, BLKFLSBUF, 0);
			for (i = 0; i < err; ++i) {
				if (fd2 > 0 && compare_ext(fd, fd2, ext+i, poffs << 9)) {
					printf(" Comparison failed!!!\n");
					dotrim = 0;
				}
			}
		}
		struct fiemap_extent* extc = NULL;
		if (dotrim && fd2 > 0)
			extc = copy_ext(ext, err);
		if (fd2 > 0) 
			close(fd2);
		free_mapping(fd, ext);
		close(fd);
		if (extc) {
			int64_t trimmed;
			char* trimnm = strdup(argv[fno]);
			mydirnm(trimnm);
			unlink(argv[fno]);
#ifdef JUST_DO_FSTRIM
			trimmed = fstrim(argv[fno]);
#else
			trimmed = fstrim_ext(trimnm, extc, err);
#endif
			printf("Trimmed 0x%" LL "x bytes on dir %s\n", trimmed, trimnm);
			free(trimnm);
			free(extc);
		}
	}
	return errs;
}
#endif

