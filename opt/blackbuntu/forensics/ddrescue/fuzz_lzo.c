/** \file fuzz_lzo.c
 * \brief
 * This program produces broken LZO files to test robustness
 * of the libddr_lzo decompressor against broken files
 * as this is a potential attack vector for malicious folks.
 *
 * Overwriting random bytes is simple, but we can also be more
 * clever in fuzzing and fix checksums to see whether we can expose
 * vulnerabilities this way.
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 5/2014
 * License: GNU GPLv2 or v3.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <lzo/lzo1x.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netinet/in.h>
//#include <sys/mman.h>
#include "list.h"

void usage()
{
	fprintf(stderr, "Usage: fuzz_lzo [options] input output.lzo\n");
	fprintf(stderr, " fuzz_lzo produces an lzo compressed file from input and writes\n"
			" it to output.lzo\n");
	fprintf(stderr, " fuzz_lzo applies distortions according to the options specified.\n");
	fprintf(stderr, " Many distortions can be done with and without fixing the checksums.\n"
			" The option -! toggles fixing for subsequent distortions, starting with on\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, " -h\t\tThis help\n");
	fprintf(stderr, " -d\t\tENable debug mode\n");
	fprintf(stderr, " -b BLKSZ\tBlocksize while compressing\n");
	fprintf(stderr, " -v/V XXX\tSet version/version to extract to hex XXX\n");
	fprintf(stderr, " -m/l YYY\tSet method/level to YYY\n");
	fprintf(stderr, " -n NAME\tSet name to string NAME\n");
	fprintf(stderr, " -f FLAGS\nSets hdr flags to hex XXX\n");
	fprintf(stderr, " -u BLK=VAL\tSet uncompressed len of block BLK to VAL\n");
	fprintf(stderr, " -c BLK=VAL\tSet   compressed len of block BLK to VAL\n");
	fprintf(stderr, " -x BLK:OFF=VAL\tSet byte at offset OFF in block BLK to VAL\n");
	fprintf(stderr, " -U BLK\tBreaks the uncompressed cksum for block BLK\n");
	fprintf(stderr, " -C BLK\tBreaks the   compressed cksum for block BLK\n");
	exit(1);
}

char debug = 0;

enum disttype { NONE = 0, ULEN, CLEN, BYTE, UCKS, CCKS };

typedef struct {
	unsigned int blkno;
	unsigned int offset;
	unsigned int val;
	enum disttype dist;
	char fixup;
} blk_dist_t;

LISTDECL(blk_dist_t);
LISTTYPE(blk_dist_t) *blk_dists;

/* parses BLK=VAL */
void parse_one(blk_dist_t *dist, const char *arg)
{
	if (sscanf(arg, "%i", &dist->blkno) != 1) {
		fprintf(stderr, "Error parsing %s; expect BLK\n", arg);
		usage();
	}
	dist->offset = 0;
	dist->val = 0xdeadbeef;
}

void parse_two(blk_dist_t *dist, const char *arg)
{
	if (sscanf(arg, "%i=%i", &dist->blkno, &dist->val) != 2) {
		fprintf(stderr, "Error parsing %s; expect BLK=VAL\n", arg);
		usage();
	}
	dist->offset = 0;
}

/* parses BLK:OFF=VAL */
void parse_three(blk_dist_t *dist, const char *arg)
{
	if (sscanf(arg, "%i:%i=%i", &dist->blkno, &dist->offset, &dist->val) != 3) {
		fprintf(stderr, "Error parsing %s; expect BLK:OFF=VAL\n", arg);
		usage();
	}
}

void dist_append(char dst, const char* arg, char fix)
{
	blk_dist_t dist;
	dist.fixup = fix;
	switch (dst) {
		case 'u': dist.dist = ULEN;
			  parse_two(&dist, arg);
			  break;
		case 'c': dist.dist = CLEN;
			  parse_two(&dist, arg);
			  break;
		case 'x': dist.dist = BYTE;
			  parse_three(&dist, arg);
			  break;
		case 'U': dist.dist = UCKS;
			  parse_one(&dist, arg);
			  break;
		case 'C': dist.dist = CCKS;
			  parse_one(&dist, arg);
			  break;
	}
	LISTAPPEND(blk_dists, dist, blk_dist_t);
}

#define F_VERSION 0x1789	/* BCD 1.789 */
#define ADLER32_INIT_VALUE 1
#define CRC32_INIT_VALUE 0

static const unsigned char 
	lzop_hdr[] = { 0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a };

int write8(int fd, unsigned char val, uint32_t *adl)
{
	*adl = lzo_adler32(*adl, (const unsigned char*)&val, 1);
	return write(fd, &val, 1);
}

int write16(int fd, unsigned short val, uint32_t *adl)
{
	unsigned short nval = htons(val);
	*adl = lzo_adler32(*adl, (const unsigned char*)&nval, 2);
	return write(fd, &nval, 2);
}

int write32(int fd, unsigned int val, uint32_t *adl)
{
	unsigned int nval = htonl(val);
	int wr = write(fd, &nval, 4);
	*adl = lzo_adler32(*adl, (const unsigned char*)&nval, 4);
	return wr;
}


int write_header(int ofd, const char* nm, 
		 unsigned short hvers, unsigned short evers, 
		 unsigned char meth, unsigned char levl,
		 unsigned int flags, char hdr_fixup)
{
	if (write(ofd, lzop_hdr, sizeof(lzop_hdr)) != sizeof(lzop_hdr))
		abort();
	uint32_t adl = ADLER32_INIT_VALUE;
	uint32_t dum = ADLER32_INIT_VALUE;
	write16(ofd, hvers, &adl);
	write16(ofd, 0x2060, &adl);
	write16(ofd, evers, &adl);
	write8(ofd, meth, &adl);
	write8(ofd, levl, &adl);
	write32(ofd, flags, &adl);
	write32(ofd, 0640, &adl);
	write32(ofd, 1400000000, &adl);
	write32(ofd, 0, &adl);
	write8(ofd, strlen(nm), &adl);
	if (write(ofd, nm, strlen(nm)) != (int)strlen(nm))
		abort();
	adl = lzo_adler32(adl, (const unsigned char*)nm, strlen(nm));
	write32(ofd, hdr_fixup? adl: 0xdeadbeef, &dum);
	return lseek(ofd, 0, SEEK_CUR);
}

void error(const char* txt)
{
	perror(txt);
	abort();
}
		
blk_dist_t* find_dist(LISTTYPE(blk_dist_t)* dlist, int blkno, enum disttype type, signed char fix)
{
	LISTTYPE(blk_dist_t) *dist;
	LISTFOREACH(dlist, dist) {
		blk_dist_t *dst = &LISTDATA(dist);
		if ((unsigned)blkno == dst->blkno && type == dst->dist && 
			(fix == -1 || fix == dst->fixup))
			return dst;
	}
	return NULL;
}

#define APPLY_DIST(TP, FIX, VAR, APPL) \
	dist = find_dist(dists, blk, TP, FIX);	\
	if (dist) {				\
		fprintf(stderr, "Blk %i: " #VAR "(%x) " #APPL " %x\n",	\
			blk, dist->offset, dist->val);	\
		VAR APPL dist->val;		\
	}




#define CBFLEN blksz+(blksz>>6)+128
int compress(int ifd, int ofd, unsigned int blksz, LISTTYPE(blk_dist_t)*dists)
{	
	int blk = 0;
	ssize_t rd, wr = 0;
	unsigned char *dbuf = (unsigned char*)malloc(blksz);
	unsigned char *cbuf = (unsigned char*)malloc(CBFLEN); 
	unsigned char *wmem = (unsigned char*)malloc(LZO1X_1_MEM_COMPRESS);
	do {
		rd = read(ifd, dbuf, blksz);
		if (!rd)
			break;
		if (rd < 0)
			error("Can't read");
		uint32_t uadl = lzo_adler32(ADLER32_INIT_VALUE, dbuf, rd);
		lzo_uint cln = CBFLEN;
		int err = lzo1x_1_compress(dbuf, rd, cbuf, &cln, wmem);
		if (err)
			abort();
		if (cln >= (unsigned)rd) {
			memcpy(cbuf, dbuf, rd);
			cln = rd;
		}
		blk_dist_t *dist;
		/* Change bytes with fixing cmpr cksum */
		APPLY_DIST(BYTE, 1, cbuf[dist->offset], =);
		uint32_t cadl = lzo_adler32(ADLER32_INIT_VALUE, cbuf, cln);
		/* Change bytes without fixing cksum */
		APPLY_DIST(BYTE, 0, cbuf[dist->offset], =);
		uint32_t ulen = rd;
		uint32_t clen = cln;
		/* Change ulen+clen */
		APPLY_DIST(ULEN, -1, ulen, =);
		APPLY_DIST(CLEN, -1, clen, =);
		/* Change ucksum+ccksum */
		APPLY_DIST(UCKS, -1, uadl, ^=);
		APPLY_DIST(CCKS, -1, cadl, ^=);
		/* Write blk header */
		uint32_t dum = ADLER32_INIT_VALUE;
		write32(ofd, ulen, &dum);
		write32(ofd, clen, &dum);
		write32(ofd, uadl, &dum);
		if (cln != (unsigned)rd)
			write32(ofd, cadl, &dum);
		/* And write block */
		wr += write(ofd, cbuf, cln); 
		++blk;
	} while (rd > 0);
	/* EOF */
	memset(cbuf, 0, 4);
	wr += write(ofd, cbuf, 4);
	free(wmem);
	free(cbuf);
	free(dbuf);
	return wr;
}

void dump_blkdists(LISTTYPE(blk_dist_t) *dlist) 
{
	LISTTYPE(blk_dist_t) *dist;
	LISTFOREACH(dlist, dist) {
		blk_dist_t *dst = &LISTDATA(dist);
		enum disttype dtp = dst->dist;
		if (dtp == BYTE)
			printf("Blk %i: chg byte @ %x to %02x %c\n",
				dst->blkno, 
				dst->offset,
				dst->val,
				dst->fixup? ' ': '!');
		else if (dtp == UCKS || dtp == CCKS)
			printf("Blk %i: chg %s cksum %c\n",
				dst->blkno,
				(dst->dist == UCKS? "uncmpr": "compr"),
				dst->fixup? ' ': '!');
		else if (dtp == ULEN || dtp == CLEN)
			printf("Blk %i: chg %s to %08x %c\n",
				dst->blkno,
				(dst->dist == ULEN? "ulen": "clen"),
				dst->val,
				dst->fixup? ' ': '!');
		else
			abort();
	}
	
}

/* TODO: MULTIPART and sparse ... */
int main(int argc, char* argv[])
{
	char fixup = 1;
	char hdr_fixup = fixup;
	unsigned int blksize = 16*1024;
	unsigned short hversion = F_VERSION;
	unsigned short extrvers = 0x0940;
	char *hname = NULL;
	char meth = 1;
	char levl = 5;
	unsigned int flags = 0x03000003UL;	/* UNIX | ADLER32_C | ADLER32_D */
	int c;
        while ((c = getopt(argc, argv, "hdb:v:V:m:l:n:f:u:c:x:U:C:!")) != -1) {
		switch (c) {
			case 'h':
				usage();
				break;
			case '!':
				fixup = !fixup;
				break;
			case 'd':
				debug = 1;
				break;
			case 'b':
				blksize = atoi(optarg);
				break;
			case 'v':
				hversion = atoi(optarg);
				hdr_fixup = fixup;
				break;
			case 'V':
				extrvers = atoi(optarg);
				hdr_fixup = fixup;
				break;
			case 'n':
				hname = optarg;
				hdr_fixup = fixup;
				break;
			case 'm':
				meth = atoi(optarg);
				hdr_fixup = fixup;
				break;
			case 'l':
				levl = atoi(optarg);
				hdr_fixup = fixup;
				break;
			case 'f':
				flags = atoi(optarg);
				hdr_fixup = fixup;
				break;
			case 'u':
			case 'c':
			case 'x':
			case 'U':
			case 'C':
				dist_append(c, optarg, fixup);
				break;
			case ':':
				fprintf(stderr, "ERROR: option -%c requires an argument!\n",
					optopt);
				usage();
				break;
			case '?':
				fprintf(stderr, "ERROR: unknown option -%c!\n", optopt);
				usage();
				break;
			default:
				fprintf(stderr, "ERROR: getopt() err! '%c' '%c'\n", optopt, c);
				abort();
		}

	}
	if (argc-optind != 2) {
		fprintf(stderr, "ERROR: Need exactly two non option arguments!\n");
		usage();
	}

	char *iname = argv[optind++];
	char *oname = argv[optind++];
	if (!hname)
		hname = iname;

	if (debug) {
		printf("Header: %1x.%3x %1x.%3x %i/%i %s %08x %c\n",
			hversion >> 12, hversion & 0xfff,
			extrvers >> 12, extrvers & 0xfff,
			meth, levl, hname, flags,
			hdr_fixup? ' ': '!');
		dump_blkdists(blk_dists);
	}

	int ifd = open(iname, O_RDONLY);
	if (ifd <= 0) {
		fprintf(stderr, "ERROR: Can't open %s for reading\n", iname);
		exit(2);
	}
	int ofd = open(oname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (ofd <= 0) {
		fprintf(stderr, "ERROR: Can't open %s for iwriting\n", oname);
		exit(3);
	}

	write_header(ofd, hname, hversion, extrvers, meth, levl, flags, hdr_fixup);
	compress(ifd, ofd, blksize, blk_dists);

	close(ofd);
	close(ifd);
	
	if (debug)
		dump_blkdists(blk_dists);

	LISTTREEDEL(blk_dists, blk_dist_t);

	return 0;
}

