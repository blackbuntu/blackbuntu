/* libddr_lzo.c
 *
 * plugin for dd_rescue, doing lzo de/compression during copying ...
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 2014
 * License: GNU GPLv2 or v3
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif

#define _LARGEFILE64_SOURCE 1
#define _FILE_OFFSET_BITS 64

#include "ddr_plugin.h"
#include "ddr_ctrl.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <libgen.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <signal.h>
#include <lzo/lzo1x.h>
#include <lzo/lzo1y.h>
#include <lzo/lzo1f.h>
#include <lzo/lzo1b.h>
#include <lzo/lzo1c.h>
#include <lzo/lzo2a.h>
#include <time.h>
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif

#if __WORDSIZE == 64
#define LL "l"
#elif __WORDSIZE == 32
#define LL "ll"
#else
#error __WORDSIZE unknown
#endif

#ifdef HAVE_BASENAME
//char* basename(char*);
#else
static char* basename(char *nm)
{
	const char* ptr = strrchr(nm, '/');	/* Not on DOS */
	if (ptr)
		return ptr+1;
	else
		return nm;
}
#endif

// TODO: pass at runtime rather than compile time
#ifdef DEBUG
# define LZO_DEBUG(x) x
#else
# define LZO_DEBUG(x) do {} while (0)
#endif

/* Some bits from lzop -- we strive for some level of compatibility */
/* We use version numbers that are not likely to clash with lzop anytime soon;
 * let's see whether this can be coordinated with Markus Oberhumer */ 
#define F_VERSION 0x1789	/* BCD 1.789 */

static const unsigned char 
	lzop_hdr[] = { 0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a };

/* 9 bytes, ugh --- and header_t has not been designed with alignment considerations either */

#define F_ADLER32_D	0x00000001UL
#define F_ADLER32_C	0x00000002UL
#define F_H_EXTRA_FIELD	0x00000040UL
#define F_CRC32_D	0x00000100UL
#define F_CRC32_C	0x00000200UL
#define F_MULTIPART	0x00000400UL
#define F_H_CRC32	0x00001000UL
#define F_OS_UNIX	0x03000000UL

#define NAMELEN 22

typedef struct
{
    uint16_t version;
    uint16_t lib_version;
    uint16_t version_needed_to_extract;
    unsigned char method;
    unsigned char level;
    uint32_t flags;
    //uint32_t filter;
    uint32_t mode;
    uint32_t mtime_low;
    uint32_t mtime_high;
    // Do this for alignment
    unsigned char nmlen;
    char name[NAMELEN];
    
    uint32_t hdr_checksum;	/* crc32 or adler32 */

    /* only if flags & F_H_EXTRA_FIELD */
   
    /* 
    uint32_t extrafield_len;
    uint32_t extra_seglen;
    uint32_t extrafield_checksum;
     */
} __attribute__((packed)) header_t;

typedef struct {
    uint32_t uncmpr_len;   
    uint32_t cmpr_len;   
    uint32_t uncmpr_chksum;
    uint32_t cmpr_chksum;
} blockhdr_t;

#define ADLER32_INIT_VALUE 1
#define CRC32_INIT_VALUE 0

#define MIN(a,b) ((a)<(b)? (a): (b))


/* All algs need zero workmem to decompress, so no need to put in table */
typedef struct {
	const char* name;
	lzo_compress_t compress;
	lzo_decompress_t decompr;
	lzo_optimize_t optimize;
	unsigned int workmem;
	unsigned char meth, lev;
} comp_alg;

/* Method/level table: Only 1/5, 2/1 and 3/9 are defined by lzop,
 * (lzo1x_1,1x_1_15,1x_999).
 * NRVYX if encoded 0xYX (BCD) and zlib is 128 in lzop. 
 * We use lzop's codes here, but use a systematic approach
 * for the algorithms not supported by lzop (as of 1.03).
 */
//																systematically
comp_alg calgos[] = { {"lzo1x_1",    lzo1x_1_compress,    lzo1x_decompress_safe, lzo1x_optimize, LZO1X_1_MEM_COMPRESS,    1, 5},  // 88,1
		      {"lzo1x_1_11", lzo1x_1_11_compress, lzo1x_decompress_safe, lzo1x_optimize, LZO1X_1_11_MEM_COMPRESS, 2, 11}, // 88,11 
		      {"lzo1x_1_12", lzo1x_1_12_compress, lzo1x_decompress_safe, lzo1x_optimize, LZO1X_1_12_MEM_COMPRESS, 2, 12}, // 88,12
		      {"lzo1x_1_15", lzo1x_1_15_compress, lzo1x_decompress_safe, lzo1x_optimize, LZO1X_1_15_MEM_COMPRESS, 2, 1},  // 88,15
      		      {"lzo1x_999",  lzo1x_999_compress,  lzo1x_decompress_safe, lzo1x_optimize, LZO1X_999_MEM_COMPRESS,  3, 9},  // 88,29
		      /* We DON'T use a different method indicator for the variants unlike lzop 
		       * The encoding is the following: lzo1@_â¬ gets method 65+@-'a', 2@_â¬ -> 97+@-'a' 
		       * and level â¬ if â¬<=9, 19 for 99 and 29 for 999 */
		      {"lzo1y_1",    lzo1y_1_compress,    lzo1y_decompress_safe, lzo1y_optimize, LZO1Y_MEM_COMPRESS,     89, 1},
		      {"lzo1y_999",  lzo1y_999_compress,  lzo1y_decompress_safe, lzo1y_optimize, LZO1Y_999_MEM_COMPRESS, 89, 29},
		      {"lzo1f_1",    lzo1f_1_compress,    lzo1f_decompress_safe, NULL,           LZO1F_MEM_COMPRESS,     70, 1},
		      {"lzo1f_999",  lzo1f_999_compress,  lzo1f_decompress_safe, NULL,           LZO1F_999_MEM_COMPRESS, 70, 29},
		      {"lzo1b_1",    lzo1b_1_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     66, 1},
		      {"lzo1b_2",    lzo1b_2_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     66, 2},
		      {"lzo1b_3",    lzo1b_3_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     66, 3},
		      {"lzo1b_4",    lzo1b_4_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     66, 4},
		      {"lzo1b_5",    lzo1b_5_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     66, 5},
		      {"lzo1b_6",    lzo1b_6_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     66, 6},
		      {"lzo1b_7",    lzo1b_7_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     66, 7},
		      {"lzo1b_8",    lzo1b_8_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     66, 8},
		      {"lzo1b_9",    lzo1b_9_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     66, 9},
		      {"lzo1b_99",   lzo1b_99_compress,   lzo1b_decompress_safe, NULL,           LZO1B_99_MEM_COMPRESS,  66, 19},
		      {"lzo1b_999",  lzo1b_999_compress,  lzo1b_decompress_safe, NULL,           LZO1B_999_MEM_COMPRESS, 66, 29},
		      {"lzo1c_1",    lzo1c_1_compress,    lzo1c_decompress_safe, NULL,           LZO1C_MEM_COMPRESS,     67, 1},
		      {"lzo1c_2",    lzo1c_2_compress,    lzo1c_decompress_safe, NULL,           LZO1C_MEM_COMPRESS,     67, 2},
		      {"lzo1c_3",    lzo1c_3_compress,    lzo1c_decompress_safe, NULL,           LZO1C_MEM_COMPRESS,     67, 3},
		      {"lzo1c_4",    lzo1c_4_compress,    lzo1c_decompress_safe, NULL,           LZO1C_MEM_COMPRESS,     67, 4},
		      {"lzo1c_5",    lzo1c_5_compress,    lzo1c_decompress_safe, NULL,           LZO1C_MEM_COMPRESS,     67, 5},
		      {"lzo1c_6",    lzo1c_6_compress,    lzo1c_decompress_safe, NULL,           LZO1C_MEM_COMPRESS,     67, 6},
		      {"lzo1c_7",    lzo1c_7_compress,    lzo1c_decompress_safe, NULL,           LZO1C_MEM_COMPRESS,     67, 7},
		      {"lzo1c_8",    lzo1c_8_compress,    lzo1c_decompress_safe, NULL,           LZO1C_MEM_COMPRESS,     67, 8},
		      {"lzo1c_9",    lzo1c_9_compress,    lzo1c_decompress_safe, NULL,           LZO1C_MEM_COMPRESS,     67, 9},
		      {"lzo1c_99",   lzo1c_99_compress,   lzo1c_decompress_safe, NULL,           LZO1C_99_MEM_COMPRESS,  67, 19},
		      {"lzo1c_999",  lzo1c_999_compress,  lzo1c_decompress_safe, NULL,           LZO1C_999_MEM_COMPRESS, 67, 29},
		      {"lzo2a_999",  lzo2a_999_compress,  lzo2a_decompress_safe, NULL,           LZO2A_999_MEM_COMPRESS, 97, 29},

		    };	      


/* fwd decl */
extern ddr_plugin_t ddr_plug;

enum compmode {AUTO=0, COMPRESS, DECOMPRESS};

typedef struct _lzo_state {
	void *workspace;
	unsigned char *dbuf, *orig_dbuf;
	unsigned char *obuf;
	size_t dbuflen;
       	int hdroff;
	unsigned int slackpre, slackpost;
	uint32_t flags;
	int seq;
	int hdr_seen;
	unsigned int blockno, holeno;
	unsigned char eof_seen, do_bench, do_opt, do_search;
	unsigned char debug, nodiscard;
	enum compmode mode;
	unsigned int last_ulen;
	comp_alg *algo;
	const opt_t *opts;
	loff_t next_ipos;
	/* Statistics */
	unsigned int nr_memmove, nr_realloc, nr_cheapmemmove;
	unsigned int cmp_hdr;
	size_t cmp_ln, unc_ln;
	/* Bench */
	clock_t cpu;
} lzo_state;

#define FPLOG(lvl, fmt, args...) \
	plug_log(ddr_plug.logger, stderr, lvl, fmt, ##args)

static unsigned int pagesize = 4096;

void lzo_hdr(header_t* hdr, loff_t hole, lzo_state *state)
{
	memset(hdr, 0, sizeof(header_t));
	hdr->version = htons(F_VERSION);
	hdr->lib_version = htons(LZO_VERSION);
	if (state->algo->meth <= 3)
		hdr->version_needed_to_extract = htons(0x0940);
	else
		hdr->version_needed_to_extract = htons(F_VERSION);
	hdr->method = state->algo->meth;
	hdr->level = state->algo->lev;
	hdr->flags = htonl(state->flags);
	hdr->nmlen = NAMELEN;
	if (hole) {
		char* bnm = basename((char*)state->opts->iname);
		/* This would abort with -D_FORTIFY_SOURCE=2 
		sprintf(hdr->name+6, ".%04x.%010lx", state->holeno++, hole);
		*/
		sprintf(hdr->name, ":%04x:%010" LL "x", state->holeno++, hole);
		memmove(hdr->name+6, hdr->name, NAMELEN-6);
		memcpy(hdr->name, bnm, MIN(6, strlen(bnm)));
		if (strlen(bnm) < 6)
			memset(hdr->name+strlen(bnm), ' ', 6-strlen(bnm));
		hdr->mode = htonl(0640);
		hdr->mtime_low = htonl(hole & 0xffffffff);
		hdr->mtime_high= htonl(hole >> 32);
	} else {
		char* nm = (char*)state->opts->iname;
		if (strlen(nm) > NAMELEN)
			nm = basename(nm);
		memcpy(hdr->name, nm, MIN(NAMELEN, strlen(nm)));
		struct stat stbf;
		if (nm && 0 == stat(state->opts->iname, &stbf)) {
			hdr->mode = htonl(stbf.st_mode);
			hdr->mtime_low = htonl(stbf.st_mtime & 0xffffffff);
#if __WORDSIZE != 32
			hdr->mtime_high = htonl(stbf.st_mtime >> 32);
#endif
		}
	}
	hdr->hdr_checksum = htonl(state->flags & F_H_CRC32?
			lzo_crc32  (  CRC32_INIT_VALUE, (const lzo_bytep)hdr, offsetof(header_t, hdr_checksum)) :
			lzo_adler32(ADLER32_INIT_VALUE, (const lzo_bytep)hdr, offsetof(header_t, hdr_checksum)));
	state->hdr_seen = sizeof(header_t);
}

int lzo_parse_hdr(unsigned char* bf, loff_t* hole, lzo_state *state)
{
	header_t *hdr = (header_t*)bf;
	if (ntohs(hdr->version_needed_to_extract) > 0x1030 && ntohs(hdr->version_needed_to_extract) != F_VERSION) {
		FPLOG(FATAL, "requires version %01x.%03x to extract\n",
			ntohs(hdr->version_needed_to_extract) >> 12,
			ntohs(hdr->version_needed_to_extract) & 0xfff);
		return -2;
	}
	if (state->algo == NULL || state->algo->meth != hdr->method || state->algo->lev != hdr->level) { 
		comp_alg *ca, *ca2 = NULL;
		state->algo = NULL;
		for (ca = calgos; ca < calgos+sizeof(calgos)/sizeof(comp_alg); ++ca) {
			if (hdr->method == ca->meth) {
				ca2 = ca;
				if (hdr->level == ca->lev) {
					state->algo = ca;
					break;
				}
			}
		}
		if (!ca2) {
			FPLOG(FATAL, "unsupported method %i level %i\n", hdr->method, hdr->level);
			return -3;
		}
		/* lzop -1 special case: 2/1 means lzo1x_1_15 not _1_11 */
		if (state->algo == calgos+1 && ntohs(hdr->version) != F_VERSION)
			state->algo += 2;
		/* If we have not found an exact match, just use the family -- good enough to decode */
		if (!state->algo)
			state->algo = ca2;
	}

	state->flags = ntohl(hdr->flags);
	if ((state->flags & (F_CRC32_C | F_ADLER32_C)) == (F_CRC32_C | F_ADLER32_C)) {
		FPLOG(FATAL, "Can't have both CRC32_C and ADLER32_C\n");
		return -5;
	}
	if ((state->flags & (F_CRC32_D | F_ADLER32_D)) == (F_CRC32_D | F_ADLER32_D)) {
		FPLOG(FATAL, "Can't have both CRC32_D and ADLER32_D\n");
		return -5;
	}

	uint32_t cksum = ntohl(*(uint32_t*)((char*)hdr+offsetof(header_t,name)+hdr->nmlen));
	uint32_t comp = (state->flags & F_H_CRC32 ? lzo_crc32(  CRC32_INIT_VALUE, (const lzo_bytep)hdr, sizeof(header_t)-NAMELEN+hdr->nmlen-4)
						: lzo_adler32(ADLER32_INIT_VALUE, (const lzo_bytep)hdr, sizeof(header_t)-NAMELEN+hdr->nmlen-4));
	if (cksum != comp) {
		FPLOG(FATAL, "header fails checksum %08x != %08x\n",
			cksum, comp);
		return -6;
	}
	int off = sizeof(header_t) + hdr->nmlen-NAMELEN;
	if (state->flags & F_H_EXTRA_FIELD) {
		off += 8 + ntohl(*(uint32_t*)(bf+off));
		if (off > 4000) {
			FPLOG(FATAL, "excessive extra field size %i\n", off);
			return -7;
		}
	}
	state->hdr_seen = off;
	state->cmp_hdr += off;
	/* Look for encoded holes */
	if (hole) {
		char nm[NAMELEN+1];
		memcpy(nm, hdr->name, NAMELEN);
		nm[NAMELEN] = 0;
		*hole = 0;
		char* ptr = strchr(nm, ':');
		if (ptr) {
			int seq;
			int parsed = sscanf(ptr+1, "%x:%" LL "x", &seq, hole);
			if (parsed == 2)
				*hole = (uint64_t)ntohl(hdr->mtime_high) << 32 | ntohl(hdr->mtime_low);
		}
	}
	return off;
}

void block_hdr(blockhdr_t* hdr, uint32_t uncompr, uint32_t compr, uint32_t unc_cks, void *cdata, uint32_t flags)
{
	hdr->uncmpr_len = htonl(uncompr);
	hdr->cmpr_len = htonl(compr);
	hdr->uncmpr_chksum = htonl(unc_cks);
	/* Don't overwrite copied data or compressed data without F_ADLER32_C 
	 * TODO: We should support CRC32 here ... */
	if (cdata != &hdr->cmpr_chksum)
	       	hdr->cmpr_chksum = htonl(flags & F_ADLER32_C?
				lzo_adler32(ADLER32_INIT_VALUE, (const lzo_bytep)cdata, compr):
				lzo_crc32(CRC32_INIT_VALUE, (const lzo_bytep)cdata, compr));
}

/* Returns compressed len */
void parse_block_hdr(blockhdr_t *hdr, unsigned int *unc_cksum, unsigned int *cmp_cksum, lzo_state *state)
{
	if (state->flags & (F_ADLER32_D | F_CRC32_D)) {
		*unc_cksum = ntohl(hdr->uncmpr_chksum);
		if (state->flags & (F_ADLER32_C | F_CRC32_C)) 
			*cmp_cksum = ntohl(hdr->cmpr_chksum);
	} else if (state->flags & (F_ADLER32_C | F_CRC32_C)) 
		*cmp_cksum = ntohl(hdr->uncmpr_chksum);
}

const char *lzo_help = "The lzo plugin for dd_rescue de/compresses data on the fly.\n"
		" Parameters: compress:decompress:benchmark:algo=lzo1?_?:optimize:flags=XXX\n"
		"\tsearch:debug:nodiscard:crc32\n"
		"  Use algo=help for a list of (de)compression algorithms.\n";


int choose_alg(char* anm, lzo_state *state)
{
	comp_alg *ca;
	if (!strcmp(anm, "help")) {
		FPLOG(INFO, "Algorithm (mem, meth, lev)\n");
		for (ca = calgos; ca < calgos+sizeof(calgos)/sizeof(comp_alg); ++ca)
			FPLOG(INFO, "%s (%i, %i, %i)\n",
					ca->name, ca->workmem, ca->meth, ca->lev);
		return 1;
	}
	for (ca = calgos; ca < calgos+sizeof(calgos)/sizeof(comp_alg); ++ca) {
		if (!strcasecmp(ca->name, anm)) {
			state->algo = ca;
			return 0;
		}
	}
	FPLOG(FATAL, "Algorithm %s not found, try algo=help\n", anm);
	return 13;
}


int lzo_plug_init(void **stat, char* param, int seq, const opt_t *opt)
{
	int err = 0;
	lzo_state *state = (lzo_state*)malloc(sizeof(lzo_state));
	if (!state) {
		FPLOG(FATAL, "can't allocate %i bytes\n", sizeof(lzo_state));
		return -1;
	}
	memset(state, 0, sizeof(lzo_state));
	*stat = (void*)state;
	state->mode = AUTO;
	state->seq = seq;
	state->algo = calgos;
	state->opts = opt;
	/* Notes: We want checksums on compressed content; lzop forces us to do both then 
	 * CRC32 has slightly better error protection quality than adler32 -- but crc32
	 * is rather slow (zlib has a highly optimized faster version), so stick with adler32 
	 * for now ..., unfortunately file fmt does not allow crc32c, which has HW acceleration
	 * on various platforms */
	state->flags = F_OS_UNIX | F_ADLER32_C | F_ADLER32_D;	/* 0x03000003 */
	if (opt->sparse || !opt->nosparse)
		state->flags |= F_MULTIPART;			/* 0x03000403 */
	while (param) {
		char* next = strchr(param, ':');
		if (next)
			*next++ = 0;
		if (!strcmp(param, "help"))
			FPLOG(INFO, "%s", lzo_help);
		else if (!memcmp(param, "compr", 5))
			state->mode = COMPRESS;
		else if (!memcmp(param, "decom", 5))
			state->mode = DECOMPRESS;
		else if (!memcmp(param, "bench", 5))
			state->do_bench = 1;
		else if (!strcmp(param, "search"))
			state->do_search = 1;
		else if (!strcmp(param, "debug"))
			state->debug = 1;
		else if (!strcmp(param, "crc32"))
			state->flags = (state->flags | F_H_CRC32 | F_CRC32_C | F_CRC32_D) & ~(F_ADLER32_C | F_ADLER32_D);
		else if (!memcmp(param, "opt", 3))
			state->do_opt = 1;
		else if (!memcmp(param, "nodisc", 6))
			state->nodiscard = 1;
		else if (!memcmp(param, "algo=", 5))
			err += choose_alg(param+5, state);
		else if (!memcmp(param, "alg=", 4))
			err += choose_alg(param+4, state);
		else if (!memcmp(param, "algorithm=", 10))
			err += choose_alg(param+10, state);
		else if (!memcmp(param, "flags=", 6)) {
			state->flags = strtol(param+6, NULL, 0);
			/* TODO Sanity check for flags ... */
			//FPLOG(INFO, "Flags: %08x\n", state->flags);
		} else {
			FPLOG(FATAL, "plugin doesn't understand param %s\n",
				param);
			--err;
		}
		param = next;
	}
	pagesize = opt->pagesize;
	return err;
}

void* slackalloc(size_t ln, lzo_state *state)
{
	unsigned char *ptr = (unsigned char*)malloc(ln+state->slackpre+state->slackpost+pagesize);
	if (!ptr) {
		FPLOG(FATAL, "allocation of %i bytes failed: %s\n",
			ln+state->slackpre+state->slackpost, strerror(errno));
		raise(SIGQUIT);
	}
	state->orig_dbuf = ptr;
	ptr += state->slackpre + pagesize-1;
	ptr -= (unsigned long)ptr%pagesize;
	return ptr;
}

void* slackrealloc(void* base, size_t newln, lzo_state *state)
{
	unsigned char *ptr, *optr;
	++state->nr_realloc;
	/* Note: We could use free and malloc IF we have no data decompressed yet 
	 * (d_off == 0) and no slack space from plugins behind us is needed.
	 * Probably not worth the effort ... */
	ptr = (unsigned char*)malloc(newln+state->slackpre+state->slackpost+pagesize);
	/* Note: We can be somewhat graceful if realloc fails by returning the original
	 * pointer and buffer size and raise(SIGQUIT) -- this would result in 
	 * writing out data that has been processed already.
	 */
	if (!ptr) {
		FPLOG(FATAL, "reallocation of %i bytes failed: %s\n",
			newln+state->slackpre+state->slackpost, strerror(errno));
		raise(SIGQUIT);
		return NULL;
	}
	optr = ptr;
	ptr += state->slackpre + pagesize-1;
	ptr -= (unsigned long)ptr%pagesize;
	memcpy(ptr-state->slackpre, (char*)base-state->slackpre, state->dbuflen+state->slackpre+state->slackpost);
	free(state->orig_dbuf);
	state->orig_dbuf = optr;
	return ptr;
}

void slackfree(void* base, lzo_state *state)
{
	//free(base-state->slackpre);
	free(state->orig_dbuf);
}

int lzo_plug_release(void **stat)
{
	if (!stat | !*stat)
		return -1;
	lzo_state *state = (lzo_state*)*stat;
	if (state->dbuflen)
		slackfree(state->dbuf, state);
	if (state->workspace)
		free(state->workspace);
	free(*stat);
	return 0;
}

/* TO DO: We could as well adjust to real max (2*softbs) */
#define MAXBLOCKSZ 16UL*1024UL*1024UL
int lzo_open(const opt_t *opt, int ilnchg, int olnchg, int ichg, int ochg,
	     unsigned int totslack_pre, unsigned int totslack_post,
	     const fstate_t *fst, void **stat)
{
	lzo_state *state = (lzo_state*)*stat;
	state->opts = opt;
	state->hdroff = 0;
	const unsigned int bsz = opt->softbs;
	if (lzo_init() != LZO_E_OK) {
		FPLOG(FATAL, "failed to initialize lzo library!");
		return -1;
	}
	if (state->mode == AUTO) {
		if (!strcmp(opt->iname+strlen(opt->iname)-2, "zo"))
			state->mode = DECOMPRESS;
		else if (!strcmp(opt->oname+strlen(opt->oname)-2, "zo"))
			state->mode = COMPRESS;
		else {
			FPLOG(FATAL, "can't determine compression/decompression from filenames (and not set)!\n");
			return -1;
		}
	}
	if (state->mode == COMPRESS) {
		if (state->do_search) {
			FPLOG(FATAL, "compress and search can't be combined!\n");
			return -1;
		}
		state->workspace = malloc(state->algo->workmem);
		if (!state->workspace) {
			FPLOG(FATAL, "can't allocate workspace of size %i for compression!\n", state->algo->workmem);
			return -1;
		}
		state->dbuflen = bsz + (bsz>>4) + 72 + sizeof(lzop_hdr) + sizeof(header_t);
	} else {
		state->dbuflen = 4*bsz+16;
	}
	state->slackpost = totslack_post;
	state->slackpre  = totslack_pre ;
	state->dbuf = (unsigned char*)slackalloc(state->dbuflen, state);
	if (state->do_bench) 
		state->cpu = 0;
	if (state->mode == COMPRESS) {
		if (opt->softbs > MAXBLOCKSZ)
			FPLOG(WARN, "Blocks larger than %iMiB not recommended (%iMiB specified)\n",
				MAXBLOCKSZ>>20, opt->softbs>>20);
		else if (opt->softbs > 256*1024)
			FPLOG(WARN, "Blocks larger than 256kiB need recompilation of lzop (%ikiB specified)\n",
				opt->softbs>>10);
	}
	state->next_ipos = opt->init_ipos;
	return 0;
	/* This breaks MD5 in chain before us
	return consumed;
	*/
}

/* Block header size: 8 -- 16 bytes dep. on checksums ... */
int bhdr_size(const lzo_state *state, uint32_t uln, uint32_t cln)
{
	int sz = 8;
	if (state->flags & (F_ADLER32_D | F_CRC32_D))
		sz += 4;
	if (state->flags & (F_ADLER32_C | F_CRC32_C) && uln != cln)
		sz += 4;
	return sz;
}

uint32_t chksum_null(unsigned int ln, lzo_state *state)
{
	unsigned char zero[4096];
	uint32_t val;
	static char buf_init = 0;
	if (!buf_init++)
		memset(zero, 0, 4096);
	if (state->flags&(F_ADLER32_C|F_ADLER32_D)) {
		val = ADLER32_INIT_VALUE;
		while (ln != 0) {
			unsigned int bsz = MIN(4096, ln);
			val = lzo_adler32(val, zero, bsz);
			ln -= bsz;
		}
	} else {
		val = CRC32_INIT_VALUE;
		while (ln != 0) {
			unsigned int bsz = MIN(4096, ln);
			val = lzo_crc32(val, zero, bsz);
			ln -= bsz;
		}
	}
	return val;
}

/* We should just encode a block header with compr_len = 0 and correct checksums ...
 * Problem is that this breaks lzop.
 * Possible approaches:
 * (a) Just swap uncompr and compr lengths -- this would lzop make detect EOF
 * (b) Encode holes by using the MULTIPART feature (and encoding hole size
 * 	in file name or extension header)
 */
int encode_hole_swap(unsigned char* bhdp, int nopre, loff_t hsz, int hlen, lzo_state *state)
{
	blockhdr_t *holehdr = nopre?  (blockhdr_t*)bhdp: (blockhdr_t*)(bhdp-hlen);
	holehdr->uncmpr_len = 0; holehdr->cmpr_len = htonl(hsz);
	holehdr->cmpr_chksum = htonl(chksum_null(hsz, state));
	if (hlen > 12) {
		holehdr->uncmpr_chksum = holehdr->cmpr_chksum;
		holehdr->cmpr_chksum = htonl(state->flags&F_ADLER32_C? ADLER32_INIT_VALUE: CRC32_INIT_VALUE);
	}
	return hlen;
}

int encode_hole(unsigned char* bhdp, int nopre, loff_t hsz, int hlen, lzo_state *state)
{
	if (!(state->flags & F_MULTIPART))
		return encode_hole_swap(bhdp, nopre, hsz, hlen, state);
	hlen = sizeof(lzop_hdr)+sizeof(header_t)+4;
	unsigned char* ptr = bhdp - (nopre? 0: hlen);
	memset(ptr, 0, 4);	/* EOF */
	ptr += 4;
	memcpy(ptr, lzop_hdr, sizeof(lzop_hdr));
	ptr += sizeof(lzop_hdr);
	lzo_hdr((header_t*)ptr, hsz, state);
	return hlen;
}


unsigned char* lzo_compress(fstate_t *fst, unsigned char *bf, 
			    int *towr, int eof, int *recall, lzo_state *state)
{
	//const loff_t ooff = fst->opos;
	lzo_uint dst_len = state->dbuflen-3-sizeof(lzop_hdr)-sizeof(header_t);
	unsigned char *hdrp = state->dbuf+3+sizeof(lzop_hdr);
	unsigned char *bhdp = hdrp+sizeof(header_t);
	unsigned char *wrbf = bhdp;
	unsigned int addwr = 0;
	unsigned int hlen = sizeof(blockhdr_t)-4+((state->flags&(F_ADLER32_C|F_CRC32_C))? 4: 0);
	if (state->hdr_seen == 0) { // was: ooff == state->opts->init_opos) {
		if (state->opts->init_opos > 0 && state->opts->extend) {
			/* TODO: Check for multipart archive and attach a part if yes */
			ssize_t ln = pread(fst->odes, bhdp, 512, 0);
			if (ln < (int)(sizeof(lzop_hdr)+sizeof(header_t)-NAMELEN)) {
				FPLOG(FATAL, "Can't extend lzo file with incomplete header of size %i\n", ln);
				abort();
			}
			if (memcmp(bhdp, lzop_hdr, sizeof(lzop_hdr))) {
				FPLOG(FATAL, "Can only extend lzo files with existing magic\n", ln);
				abort();
			};
			if (lzo_parse_hdr(bhdp+sizeof(lzop_hdr), NULL, state) < 0)
				abort();
			/* TODO (optional): Jump block headers to see whether we are at a valid offset */
			/* Due to different flags, blkhdr size could have changed ... */
			hlen = sizeof(blockhdr_t)-4+((state->flags&(F_ADLER32_C|F_CRC32_C))? 4: 0);
			/* Overwrite EOF */
			if (state->flags & F_MULTIPART) {
				if (!state->opts->quiet)
					FPLOG(INFO, "extending by writing next part (MULTIPART)\n");
				state->hdr_seen = 0;
			} else {
				if (!state->opts->quiet)
					FPLOG(INFO, "extending by overwriting EOF\n");
				fst->opos -= 4;
			}
		}
		if (state->hdr_seen == 0) {
			memcpy(state->dbuf+3, lzop_hdr, sizeof(lzop_hdr));
			lzo_hdr((header_t*)hdrp, 0, state);
			addwr = sizeof(header_t) + sizeof(lzop_hdr);
			wrbf = state->dbuf+3;
			state->cmp_hdr += sizeof(lzop_hdr)+sizeof(header_t);
		}
	}
	if (fst->ipos > state->next_ipos) {
		/* Sparse support */
		const loff_t hsz = fst->ipos - state->next_ipos;
		if (state->debug)
			FPLOG(DEBUG, "hole %i@%i/%i (sz %i/%i+%i)\n",
				state->blockno, state->next_ipos, fst->opos-hsz,
				hsz, 0, hlen);
		int holehdrsz = encode_hole(bhdp, addwr, hsz, hlen, state);
		if (!addwr)
			wrbf -= holehdrsz;
		else 
			bhdp += holehdrsz;
	
		addwr += holehdrsz;
		state->next_ipos = fst->ipos;
		state->blockno++;
		/* Compensate for dd_rescue moving opos forward ... */
		fst->opos -= hsz;
	}
	/* NOTE: We always calc checksum of uncompressed data, as we don't get a
	 * checksum at all otherwise (lzop decompressor does not allow for checksums
	 * exclusively on compressed data). */
	if (*towr) {
		uint32_t unc_cks = state->flags & F_ADLER32_D? 
			lzo_adler32(ADLER32_INIT_VALUE, bf, *towr):
			lzo_crc32(CRC32_INIT_VALUE, bf, *towr);
		unsigned char *cdata = bhdp+hlen;
		int err = state->algo->compress(bf, *towr, cdata, &dst_len, state->workspace);
		assert(err == 0);
		if (dst_len >= (unsigned int)*towr) {
			/* We NEED to do the same optimization as lzop if dst_len >= *towr, if we
			 * want to be compatible, as the * lzop ddecompression code otherwise bails
			 * out, sigh.
			 * So if this is the case, copy original block; decompression recognizes
			 * this by cmp_len == unc_len ....
			 * lzop does not write second checksum IF it's just a mem copy
			 *
			 * TODO: We could return original buffer instead  
			 * and save a copy -- don't bother for now ...
			 * as the added header makes this somewhat complex.
			 */
			hlen = sizeof(blockhdr_t)-4;
			cdata = bhdp+hlen;
			memcpy(cdata, bf, *towr);
			dst_len = *towr;
		} else if (state->do_opt && state->algo->optimize) {
			/* Note that this memcpy could be avoided for performance.
			 * But we don't optimize for optimize ... it's not useful enough */
			memcpy(bf, cdata, dst_len);
			state->algo->optimize(bf, dst_len, cdata, &dst_len, state->workspace);
		}
		if (state->debug)
			FPLOG(DEBUG, "block%i@%i/%i (sz %i/%i+%i)\n",
				state->blockno, fst->ipos, fst->opos+addwr,
				*towr, dst_len, hlen);
		state->cmp_hdr += hlen;
		state->cmp_ln += dst_len; state->unc_ln += *towr;
		block_hdr((blockhdr_t*)bhdp, *towr, dst_len, unc_cks, cdata, state->flags);
		state->blockno++;
		state->next_ipos = fst->ipos + *towr;
		*towr = dst_len + hlen + addwr;
	} else {
		*towr = addwr;
	}
	if (eof) {
		state->cmp_hdr += 4;
		memset(wrbf+*towr, 0, 4);
		*towr += 4;
	}
	return wrbf;
}

int check_blklen_and_next(lzo_state *state, fstate_t *fst,
			  int bfln, int c_off, int bhsz,
			  uint32_t uln, uint32_t cln)
{
	if (uln > MAXBLOCKSZ || cln > MAXBLOCKSZ)
		return 0;
	uint32_t nextulen = (unsigned)bfln >= c_off+state->hdroff+bhsz+cln+4?
				*(uint32_t*)(fst->buf+state->hdroff+c_off+bhsz+cln): 0;
	uint32_t nextclen = (unsigned)bfln >= c_off+state->hdroff+bhsz+cln+8?
				*(uint32_t*)(fst->buf+state->hdroff+c_off+bhsz+cln+4): 0;
	if (nextulen > MAXBLOCKSZ || (nextulen && nextclen > MAXBLOCKSZ))
		return 0;
	return 1;
}

#undef HTONL
#if __BYTE_ORDER == __BIG_ENDIAN
#define HTONL(x) x
#else
#define HTONL(x) (((((x) & 0xFF)) << 24) | \
		  ((((x) & 0xFF00)) << 8) | \
		  ((((x) & 0xFF0000)) >> 8) | \
		  ((((x) & 0xFF000000)) >> 24))
#endif

unsigned char* lzo_search_hdr(fstate_t *fst, unsigned char* bf, int *towr,
			      int eof, int *recall, lzo_state *state)
{
	int off;
	/* Look for a block header ...
	 * (a) We need two 32bit words (big endian) that could be uncompressed
	 *  and compressed length. We limit block sizes to <16M, so we can look
	 *  for two null bytes.
	 *  0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a
	 */
	static const uint32_t lzo1 = HTONL(0x894c5a4f);
	static const uint32_t lzo2 = HTONL(0x000d0a1a);
	static const uint32_t mask = HTONL(~((MAXBLOCKSZ<<1)-1));
	//FPLOG(DEBUG, "Mask %08x LZO %08x %08x\n", mask, lzo1, lzo2);
	uint32_t unc_len = 0xffffffff, cmp_len=0xffffffff;
	for (off = state->hdroff; off < *towr-8; ++off) {
		unc_len = *(uint32_t*)(fst->buf+off);
		cmp_len = *(uint32_t*)(fst->buf+off+4);
		/* Recognize LZOP header -- MULTIPART!!! */
		if (unc_len == lzo1 && cmp_len == lzo2 
				&& fst->buf[off+8] == lzop_hdr[8]) {
			loff_t hole;
			int hlen = lzo_parse_hdr(fst->buf+off+sizeof(lzop_hdr), &hole, state);
			if (!state->opts->quiet)
				FPLOG(INFO, "lzop header at %i (sz %i/hole %li)\n", fst->ipos+off, 
					hlen+sizeof(lzop_hdr), hole);
			fst->opos += hole;
			off += hlen+sizeof(lzop_hdr);
			unc_len = *(uint32_t*)(fst->buf+off);
			cmp_len = *(uint32_t*)(fst->buf+off+4);
			if (state->debug)
				FPLOG(DEBUG, "Next blk: %i/%i\n",
					ntohl(unc_len), ntohl(cmp_len));
		}
		if (unc_len & mask || cmp_len & mask)
			continue;
		/* OK, we found a candidate ... */
		unc_len = ntohl(unc_len);
		cmp_len = ntohl(cmp_len);
		/* OK, we passed the quick test, here's the real one ... */
		if (!check_blklen_and_next(state, fst, *towr, off-state->hdroff,
					   16, unc_len, cmp_len) &&
		    !check_blklen_and_next(state, fst, *towr, off-state->hdroff,
			    		   12, unc_len, cmp_len)) {
			if (state->debug)
				FPLOG(DEBUG, "Blk Cand @ %i failed chain tests ...\n",
						fst->ipos+off);
			continue;
		}
		/* Candidate found but we can't decode it with our buffer sizes ... */
		if (cmp_len > 2*state->opts->softbs) {
			if (state->debug)
				FPLOG(DEBUG, "Blk Cand @ %i with large size %i, increase softblocksize\n",
					fst->ipos+off, cmp_len);
			continue;
		}
		/* Best case: We have a complete block */
		if ((int32_t)(cmp_len+sizeof(blockhdr_t)) <= *towr-off) {
			/* Do checksum tests etc. */
			uint32_t ucks = ntohl(*(uint32_t*)(fst->buf+off+8));
			uint32_t ccks = ntohl(*(uint32_t*)(fst->buf+off+12));
			/* If there is a compr chksum at all, we'll have both */
			uint32_t ca32 = lzo_adler32(ADLER32_INIT_VALUE, fst->buf+off+16, cmp_len);
			if (ca32 == ccks) 
				state->flags = F_OS_UNIX | F_ADLER32_C | F_ADLER32_D | F_MULTIPART;
			else {
				uint32_t cc32 = lzo_crc32(CRC32_INIT_VALUE, fst->buf+off+16, cmp_len);
				if (cc32 == ccks)
					state->flags = F_OS_UNIX | F_CRC32_C | F_CRC32_D | F_MULTIPART;
				else {
					/* No checksum matches: Either we have no valid block or compression
					 * has been done without compressed checksums -- try decompression ... */
					lzo_uint dst_len = state->dbuflen;
					/* No guessing of compression algo implemented yet ... */
					int err = state->algo->decompr(fst->buf+off+12, cmp_len, state->dbuf, &dst_len, NULL);
					if (err != LZO_E_OK || dst_len != unc_len) {
						if (state->debug)
							FPLOG(DEBUG, "Blk Cand @ %i failed decompression\n",
								fst->ipos + off);
						continue;
					}
					/* Check decompr checksum */
					ca32 = lzo_adler32(ADLER32_INIT_VALUE, state->dbuf, dst_len);
					if (ca32 == ucks)
						state->flags = F_OS_UNIX | F_ADLER32_D | F_MULTIPART;
					else {
						cc32 = lzo_crc32(CRC32_INIT_VALUE, state->dbuf, dst_len);
						if (cc32 == ucks) 
							state->flags = F_OS_UNIX | F_CRC32_D | F_MULTIPART;
						else {
							//if (state->debug)
							FPLOG(DEBUG, "Blk Cand @ %i fails decomp chksum test\n",
									fst->ipos+off);
							continue;
						}
					}
				}
			}
			if (!state->opts->quiet)
				FPLOG(INFO, "Found block @ %i (flags %08x)\n",
					fst->ipos+off, state->flags);
			//*towr -= off;
			state->hdroff = off;
			state->do_search = 0;
			state->hdr_seen = 1;
			return fst->buf+off;
		} else {
			/* No complete block, prepare to append ...*/
			const size_t totbufln = state->opts->softbs - ddr_plug.slack_post*((state->opts->softbs+15)/16);
			const size_t left = totbufln - (*towr-off);
			if (left < state->opts->softbs) {
				if (!state->opts->quiet)
					FPLOG(INFO, "Buffer exhausted Blk Cand @ %i\n", fst->ipos+off);
				off += fst->buf-state->obuf;
				fst->buf = state->obuf;
				assert(off >= 0);
				continue;
			}
			if (state->debug)
				FPLOG(DEBUG, "Incomplete block @ %i: (off %i@%p/%p)\n",
					fst->ipos+off, off, fst->buf, state->obuf);
			if (state->obuf != fst->buf+off)
				memmove(state->obuf, fst->buf+off, *towr-off);
			fst->buf = state->obuf + *towr-off;
			state->hdroff = -(*towr-off);
			*towr = 0;
			return fst->buf;
		}
	}
	/* Nothing found */
	/* Special case: block header straddles a blk boundary */
	memcpy(state->obuf-7, fst->buf+*towr-7, 7);
	state->hdroff = -7;
	fst->buf = state->obuf;
	*towr = 0;
	return fst->buf;
}

void recover_decompr_msg(lzo_state *state, fstate_t *fst,
			 int *c_off, int d_off, int bhsz,
       			 uint32_t unc_len, uint32_t cmp_len,
			 const char* msg)
{
	int can_recover = 1;
	if (cmp_len > MAXBLOCKSZ || unc_len > MAXBLOCKSZ)
		can_recover = 0;
	/* We need to have drained data before coming here */
	enum ddrlog_t prio = can_recover? WARN: FATAL;
	FPLOG(prio, "decompr err block %i@%i/%i (size %i+%i/%i):\n",
			state->blockno,
			fst->ipos +*c_off + state->hdroff,
			fst->opos + d_off,
			bhsz, cmp_len, unc_len,
			msg);
	if (msg && *msg)
		FPLOG(prio, "%s\n", msg);
}


int recover_decompr_error(lzo_state *state, fstate_t *fst,
			  int bflen, int *c_off, int d_off, int bhsz,
       			  uint32_t unc_len, uint32_t cmp_len,
			  const char* msg)
{
	/* We need to have drained data before coming here */
	assert(d_off == 0);
	recover_decompr_msg(state, fst, c_off, d_off, bhsz,
			    unc_len, cmp_len, msg);
	fst->nrerr++;
	int recoverable = check_blklen_and_next(state, fst, bflen, *c_off, 
						bhsz, unc_len, cmp_len);
	if (recoverable && !state->nodiscard) {
		state->cmp_hdr += bhsz;
		*c_off += cmp_len+bhsz;
		//Don't d_off += dst_len, as we're skipping; instead:
		fst->opos += unc_len;
		state->cmp_ln += cmp_len;
		state->unc_ln += unc_len;
		state->blockno++;
		return 1;
	}
	return recoverable;
}


#define QUIT { raise(SIGQUIT); ++do_break; break; }
#define BREAK if (!state->nodiscard) ++do_break; break
#define DRAIN(x) { do { ++do_break; *recall=1; 		\
		   LZO_DEBUG(FPLOG(DEBUG, "Drain %i bytes before %s error handling\n", d_off, x));	\
		   eof = 0;				\
       		   break; } while(0); 			\
		   if (do_break) break; }

/* TODO:
 * - Debug: Output block boundaries
 * - On error, see whether we can be graceful (jump ahead and continue),
 *    otherwise output info on where we left off ... (sparseness)
 */
unsigned char* lzo_decompress(fstate_t *fst, unsigned char* bf, int *towr,
			      int eof, int *recall, lzo_state *state)
{
	const loff_t ooff = fst->opos;
	const int inlen = *towr;
	/* Decompression is tricky */
	int c_off = 0;
	int d_off = 0;
	if (!state->hdr_seen) {
		assert(ooff - state->opts->init_opos == 0);
		if (memcmp(bf, lzop_hdr, sizeof(lzop_hdr))) {
			if (state->opts->init_ipos == 0) {
				FPLOG(FATAL, "lzop magic broken\n");
				abort();
			} else {
				ssize_t ln = pread(fst->ides, state->dbuf, 320, 0);
				if (ln < (int)(sizeof(lzop_hdr) + sizeof(header_t)-NAMELEN)) {
					FPLOG(FATAL, "lzop read too short (%i) for header\n", ln);
					abort();
				}
				if (memcmp(state->dbuf, lzop_hdr, sizeof(lzop_hdr))) {
					FPLOG(FATAL, "lzop magic broken\n");
					abort();
				}
				if (lzo_parse_hdr(state->dbuf+sizeof(lzop_hdr), NULL, state) < 0)
					abort();
			}
		} else {	
			state->cmp_hdr = sizeof(lzop_hdr);
			c_off += sizeof(lzop_hdr);
			int err = lzo_parse_hdr(bf+c_off, NULL, state);
			if (err < 0)
				abort();
			c_off += err;
		}
	}
	/* Now do processing: Do we have a full block? */
	const size_t totbufln = state->opts->softbs - ddr_plug.slack_post*((state->opts->softbs+15)/16);
	unsigned char* effbf = NULL;
	size_t have_len = 0;
	uint32_t cmp_len = 0, unc_len = 0;
	int bhsz = sizeof(blockhdr_t);
	if (inlen-state->hdroff <= 0)
		return bf;
	/* Main loop: Process blocks */
	do {
		char do_break = 0;
		char is_err = 0;
		effbf = bf+c_off+state->hdroff;
		lzo_uint dst_len;
		LZO_DEBUG(FPLOG(DEBUG, "dec blk @ %p (offs %i, stoffs %i, bln %zi, tbw %i)\n",
				effbf, effbf-state->obuf, state->hdroff, totbufln, inlen));
		blockhdr_t *hdr = (blockhdr_t*)effbf;
		have_len = inlen-state->hdroff-c_off;
		/* Not even space for unc_len/EOF */
		if (have_len < 4)
			break;
		unc_len = ntohl(hdr->uncmpr_len);
		bhsz = bhdr_size(state, unc_len, cmp_len);
		if (!unc_len && (!(state->flags & F_MULTIPART) || (eof && have_len < 8))) {
			/* EOF */
			state->eof_seen = 1;
			state->cmp_hdr += 4;
			if (have_len != 4)
				FPLOG(WARN, "%i+ bytes after EOF @ %i ignored\n", have_len-4, 
					state->cmp_ln+state->cmp_hdr);
			break;
		}
		if (!unc_len && state->flags & F_MULTIPART && have_len > 32) {
			/* EOF with new LZOP sig */
			LZO_DEBUG(FPLOG(DEBUG, "Next part ...\n"));
			if (memcmp(effbf+4, lzop_hdr, sizeof(lzop_hdr))) {
				FPLOG(FATAL, "EOF with MULTIPART, but no new hdr\n");
				raise(SIGQUIT);
				break;
			}
			loff_t hsz;
			int hln = lzo_parse_hdr(effbf+4+sizeof(lzop_hdr), &hsz, state);
			bhsz = hln+sizeof(lzop_hdr)+4;
			if (!hsz) {
				if (!state->opts->quiet)
					FPLOG(INFO, "MULTIPART, just append ...\n");
				c_off += bhsz;
				state->cmp_hdr += bhsz;
				continue;
			}
			unc_len = hsz;
			cmp_len = 0;
		} else {
			if (have_len < 8)
				break;
			cmp_len = ntohl(hdr->cmpr_len);
			bhsz = bhdr_size(state, unc_len, cmp_len);
		}
#if 1 //def SWAP_HOLE
		/* Alternative hole encoding */
		if (!unc_len && cmp_len) {
			unc_len = cmp_len;
			cmp_len = 0;
		};
#endif
		uint32_t unc_cksum = 0, cmp_cksum = 0;

		if (have_len >= 16)
			 parse_block_hdr(hdr, &unc_cksum, &cmp_cksum, state);

		/* No second checksum .... */
		if (cmp_len == unc_len) 
			cmp_cksum = unc_cksum;
		
		LZO_DEBUG(FPLOG(DEBUG, "dec blk @ %p (hdroff %i, cln %i, uln %i, have %i)\n",
				effbf, c_off+state->hdroff, unc_len, cmp_len, have_len));
		/* Block incomplete? Then we're done for this round ... */
		if (have_len < bhsz+cmp_len)
			break;
		if (state->flags & ( F_ADLER32_C | F_CRC32_C)) {
			uint32_t cksum = state->flags & F_ADLER32_C ?
				lzo_adler32(ADLER32_INIT_VALUE, effbf+bhsz, cmp_len) :
				lzo_crc32  (  CRC32_INIT_VALUE, effbf+bhsz, cmp_len);
			/*
			FPLOG(DEBUG, "Check: %02x %02x %02x ... %02x %02x %02x %02x (%i)\n",
				effbf[bhsz], effbf[bhsz+1], effbf[bhsz+2],
				effbf[bhsz+cmp_len-4],
				effbf[bhsz+cmp_len-3], effbf[bhsz+cmp_len-2],
				effbf[bhsz+cmp_len-1], cmp_len);
			 */
			if (cksum != cmp_cksum && (cmp_len || !(state->flags & F_MULTIPART))) {
				if (d_off) 
					DRAIN("ccksm");
				++is_err;
				if (!recover_decompr_error(state, fst, inlen, &c_off, d_off, 
							   bhsz, unc_len, cmp_len,
							   "compr checksum mismatch"))
					QUIT;
				if (!state->nodiscard)
					break;
			}
		}

		/* Sparse ... */
		if (0 == cmp_len) {
			if (d_off) 
				DRAIN("hole");
			if (state->debug)
				FPLOG(DEBUG, "hole %i@%i/%i (sz %i+%i/%i)\n",
					state->blockno, fst->ipos+c_off+state->hdroff,
					fst->opos+d_off, bhsz, cmp_len, unc_len);
			state->cmp_hdr += bhsz;
			c_off += cmp_len+bhsz;
			//Instead of d_off += unc_len;
			fst->opos += unc_len;
			state->cmp_ln += cmp_len;
			//state->unc_ln += unc_len;
			state->blockno++;
			continue;
		}


		dst_len = state->dbuflen-d_off;
		if (dst_len < unc_len) {
			/* TODO: Check if drain would help us ... */
			/* If memalloc fails, we'll abort in a second, so warn ... */
			if (unc_len > MAXBLOCKSZ)
				FPLOG(WARN, "large uncompressed block sz %i @%i\n",
						unc_len, state->cmp_ln+state->cmp_hdr);
			size_t newlen = unc_len+d_off+255;
			newlen -= newlen%256;
			unsigned char *newbuf = (unsigned char*)slackrealloc(state->dbuf, newlen, state);
			/* if realloc failed, exit loop, write out existing data and exit;
			 * slackrealloc has done raise(SIGQUIT) already ... */
			if (!newbuf)
				break;
			state->dbuf = newbuf;
			state->dbuflen = newlen;
			dst_len = newlen-d_off;
		}
		int err = 0;
		/*
		if (do_break)
			break;
		*/
		/* lzop: cmp_len == unc_len means that we just have a copy of the original */
		if (cmp_len != unc_len) {
			if (cmp_len > unc_len)
				FPLOG(WARN, "compressed %i > uncompressed %i breaks lzop\n",
					cmp_len, unc_len);
			err = state->algo->decompr(effbf+bhsz, cmp_len, (unsigned char*)state->dbuf+d_off, &dst_len, NULL);
			LZO_DEBUG(FPLOG(DEBUG, "decompressed %i@%p -> %i\n",
				cmp_len, effbf+bhsz, dst_len));
			if (dst_len != unc_len) {
				fst->nrerr++;
				FPLOG(WARN, "inconsistent uncompressed size @%i: %i <-> %i\n",
					state->cmp_ln+state->cmp_hdr, unc_len, dst_len);
				/* Rather than risking writing out garbage, write 0 */
				if (dst_len < unc_len)
					memset(state->dbuf+d_off+dst_len, 0, unc_len-dst_len);
				/* We keep track of previous block's ulen to determine whom to trust */
				if (err || unc_len == state->last_ulen)
					dst_len = unc_len;
				
			}
		} else {
			memcpy(state->dbuf+d_off, effbf+bhsz, unc_len);
			dst_len = unc_len;
		}
		do_break = 0;
		if (err != LZO_E_OK && d_off)
			DRAIN("LZO");
		switch (err) {
		case LZO_E_INPUT_OVERRUN:
			/* TODO: Partial block, handle! */
			FPLOG(FATAL, "input overrun @ %i: %i %i %i; try larger block sizes\n", 
					state->cmp_ln+state->cmp_hdr, *towr, state->dbuflen, dst_len);
			if (0 == recover_decompr_error(state, fst, inlen, &c_off, d_off, bhsz, 
							unc_len, cmp_len, "input overrun"))
				QUIT;
			BREAK;
		case LZO_E_EOF_NOT_FOUND:
			/* TODO: Partial block, handle! */
			FPLOG(FATAL, "EOF not found @ %i: %i %i %i; try larger block sizes\n", 
					state->cmp_ln+state->cmp_hdr, *towr, state->dbuflen, dst_len);
			if (0 == recover_decompr_error(state, fst, inlen, &c_off, d_off, bhsz, 
							unc_len, cmp_len, "EOF not found"))
				QUIT;
			BREAK;
		case LZO_E_OUTPUT_OVERRUN:
			FPLOG(FATAL, "output overrun @ %i: %i %i %i; try larger block sizes\n", 
					state->cmp_ln+state->cmp_hdr, *towr, state->dbuflen, dst_len);
			if (0 == recover_decompr_error(state, fst, inlen, &c_off, d_off, bhsz, 
							unc_len, cmp_len, "output overrun"))
				QUIT;
			BREAK;
		case LZO_E_LOOKBEHIND_OVERRUN:
			FPLOG(FATAL, "lookbehind overrun @ %i: %i %i %i; data corrupt?\n", 
					state->cmp_ln+state->cmp_hdr, *towr, state->dbuflen, dst_len);
			if (0 == recover_decompr_error(state, fst, inlen, &c_off, d_off, bhsz, 
							unc_len, cmp_len, "lookbehind overrun"))
				QUIT;
			BREAK;
		case LZO_E_ERROR:
			FPLOG(FATAL, "unspecified error @ %i: %i %i %i; data corrupt?\n", 
					state->cmp_ln+state->cmp_hdr, *towr, state->dbuflen, dst_len);
			if (0 == recover_decompr_error(state, fst, inlen, &c_off, d_off, bhsz,
							unc_len, cmp_len, "unspecified error"))
				QUIT;
			BREAK;
		case LZO_E_INPUT_NOT_CONSUMED:
			/* TODO: Leftover bytes, store */
			FPLOG(WARN, "input not fully consumed @ %i: %i %i %i\n", 
					state->cmp_ln+state->cmp_hdr, *towr, state->dbuflen, dst_len);
			recover_decompr_msg(state, fst, &c_off, d_off, bhsz, unc_len, cmp_len,
					       "input not consumed");
			break;
		}
		if (do_break)
			break;
		else if (err != LZO_E_OK)
			++is_err;
		if (state->flags & ( F_ADLER32_D | F_CRC32_D)) {
			uint32_t cksum;
			/* If we have just copied and tested the compressed checksum before,
			 * no need to adler32/crc32 the same memory again ... */
		       	if (cmp_len == unc_len && state->flags & (F_ADLER32_C | F_CRC32_C))
				cksum = cmp_cksum;
			else
				cksum = state->flags & F_ADLER32_D ?
					lzo_adler32(ADLER32_INIT_VALUE, state->dbuf+d_off, dst_len) :
					lzo_crc32  (  CRC32_INIT_VALUE, state->dbuf+d_off, dst_len);
			if (cksum != unc_cksum) {
				if (d_off)
					DRAIN("dcksm");
				is_err++;
				FPLOG(WARN, "decompr checksum mismatch @ %i\n",
						state->cmp_ln+state->cmp_hdr);
				if (0 == recover_decompr_error(state, fst, inlen, &c_off, d_off, bhsz,
							unc_len, cmp_len, "decompr checksum mismatch"))
					QUIT;
				if (!state->nodiscard)
					break;
			} else if (!err)
				state->last_ulen = dst_len;
		}
		if (state->debug)
			FPLOG(DEBUG, "block%i@%i/%i (sz %i+%i/%i)%c\n",
				state->blockno, fst->ipos+c_off+state->hdroff,
				fst->opos+d_off, bhsz, cmp_len, dst_len,
				is_err? '!': ' ');
		state->cmp_hdr += bhsz;
		c_off += cmp_len+bhsz;
		d_off += dst_len;
		state->cmp_ln += cmp_len; 
		state->unc_ln += dst_len;
		state->blockno++;
	} while (1);
	/* If there's no more input, we should have seen EOF marker */
	if (eof && !state->eof_seen)
		FPLOG(WARN, "End of input @ %i but no EOF marker seen\n", state->cmp_ln+state->cmp_hdr);

	/* OK, so now we know what we have ..., let's do some buffer management and ensure that
	 * (a) We preserve incomplete blocks for further processing
	 * (b) We keep track of block header position
	 * (c) We have enough space for another read block (unless we use *recall)
	 */
	/* Need drain? */
	int spcleft = totbufln-(fst->buf+inlen-state->obuf);
	//if (!*recall && spcleft < state->opts->softbs)
	//       *recall = 1;
	int nextrd = *recall? 0: state->opts->softbs;
	/* Trivial case: No bytes to store */
	if (have_len == 0) {
		state->hdroff = 0;
		fst->buf = state->obuf;
	} else if (have_len <= state->opts->softbs>>4) { 
		/* Only a few bytes (softbs/16) -- use opportunity to wrap around cheaply */
		if (effbf != state->obuf) {
			memmove(state->obuf, effbf, have_len);
			++state->nr_cheapmemmove;
		}
		state->hdroff = -have_len;
		fst->buf = state->obuf+have_len;
	/* Enough space for complete block and enough left for next read? */
	} else if (effbf+bhsz+cmp_len <= state->obuf+totbufln && spcleft >= nextrd) {
		/* We have enough space to just append */
		state->hdroff -= inlen-c_off;
		fst->buf += inlen;
		LZO_DEBUG(FPLOG(DEBUG, "append  @ %p\n", fst->buf));

	/* OK, now for the bad cases:
	 * (a) We can't append, but everything fits if we memmove to start
	 * (b) We can't fit it in
	 */
	/* Simplify to bhsz+cmp_len+state->softbs < totbufln ? */
	} else if (bhsz+cmp_len < totbufln &&
		   have_len+nextrd < totbufln) {
		/* We need to move block to beg of buffer */
		LZO_DEBUG(FPLOG(DEBUG, "move %i bytes to buffer head\n", have_len));
		if (effbf != state->obuf) {
			memmove(state->obuf, effbf, have_len);
			++state->nr_memmove;
		}
		state->hdroff = -have_len;
		fst->buf = state->obuf+have_len;
		//c_off = 0;
	} else {
		/* Our buffer is too small */
		recover_decompr_msg(state, fst, &c_off, d_off, bhsz, unc_len, cmp_len,
				"Read blocks too small");
		FPLOG(FATAL, "Can't assemble block of size %i, increase softblocksize to at least %i\n", 
				cmp_len, cmp_len/2);
		raise(SIGQUIT);
	}

	*towr = d_off;
	return state->dbuf;
}
#undef BREAK
#undef DRAIN


unsigned char* lzo_block(fstate_t *fst, unsigned char* bf, 
			 int *towr, int eof, int *recall, void **stat)
{
	lzo_state *state = (lzo_state*)*stat;
	if (!state->obuf)
		state->obuf = fst->buf;
	unsigned char* ptr = 0;	/* Silence gcc */
	clock_t t1 = 0;
	if (state->do_bench) 
		t1 = clock();
	if (state->mode == COMPRESS) 
		ptr = lzo_compress(  fst, bf, towr, eof, recall, state);
	else {
		if (state->do_search) 
			ptr = lzo_search_hdr(fst, bf, towr, eof, recall, state);
		if (!state->do_search)		
			ptr = lzo_decompress(fst, bf, towr, eof, recall, state);
	}
	if (state->do_bench)
		state->cpu += clock() - t1;
	return ptr;
}

int lzo_close(loff_t ooff, void **stat)
{
	lzo_state *state = (lzo_state*)*stat;
	//loff_t len = ooff-state->first_ooff;
	if (state->do_bench || !state->opts->quiet) {
		if (state->mode == COMPRESS)
			FPLOG(INFO, "%s_compress %.1fkiB (%1.f%%) + %i <- %.1fkiB\n",
				state->algo->name,
				state->cmp_ln/1024.0, 
				100.0*((double)state->cmp_ln/state->unc_ln),
				state->cmp_hdr,
				state->unc_ln/1024.0);
		else {
			FPLOG(INFO, "%s_decompr %.1fkiB (%.1f%%) + %i -> %.1fkiB\n",
				state->algo->name,
				state->cmp_ln/1024.0, 
				100.0*((double)state->cmp_ln/state->unc_ln),
				state->cmp_hdr,
				state->unc_ln/1024.0);
			if (state->do_bench)
				FPLOG(INFO, "%i reallocs (%ikiB), %i(+%i) moves\n",
					state->nr_realloc, state->dbuflen/1024,
					state->nr_memmove, state->nr_cheapmemmove);
		}
		/* Only output if it took us more than 0.05s, otherwise it's completely meaningless */
		if (state->do_bench && state->cpu/(CLOCKS_PER_SEC/20) > 0)
			FPLOG(INFO, "%.2fs CPU time, %.1fMiB/s\n",
				(double)state->cpu/CLOCKS_PER_SEC, 
				state->unc_ln/1024 / (state->cpu/(CLOCKS_PER_SEC/1024.0)));
	}
	return 0;
}


ddr_plugin_t ddr_plug = {
	//.name = "lzo",
	.slack_pre = 8, /* For search */
	.slack_post = -33,
	.needs_align = 1,
	.handles_sparse = 1,
	.makes_unsparse = 1,
	.changes_output = 1,
	.changes_output_len = 1,
	.supports_seek = 0,
	.init_callback  = lzo_plug_init,
	.open_callback  = lzo_open,
	.block_callback = lzo_block,
	.close_callback = lzo_close,
	.release_callback = lzo_plug_release,
};


