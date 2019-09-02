/** libddr_MD5.c
 *
 * plugin for dd_rescue, calculating a hash value during copying ...
 * A PoC for the plugin infrastructure ...
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
#include "hash.h"
#include "md5.h"
#include "sha256.h"
#include "sha512.h"
#include "sha1.h"
#include "pbkdf2.h"
#include "checksum_file.h"

#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <netinet/in.h>	/* For ntohl/htonl */
#include <endian.h>

#ifdef HAVE_ATTR_XATTR_H
#include <attr/xattr.h>
#endif
// TODO: pass at runtime rather than compile time
#define HASH_DEBUG(x) if (state->debug) x

#define FPLOG(lvl, fmt, args...) \
	plug_log(ddr_plug.logger, stderr, lvl, fmt, ##args)

/* fwd decl */
extern ddr_plugin_t ddr_plug;

hashalg_t hashes[] = { MD5_HALG_T, SHA1_HALG_T, SHA256_HALG_T, SHA224_HALG_T, SHA512_HALG_T, SHA384_HALG_T,
			// SHA3 ...
};
	
typedef struct _hash_state {
	hash_t hash, hmach;
	loff_t hash_pos;
	const char *fname;
	const char *append, *prepend;
	hashalg_t *alg;
	uint8_t buf[288];	// enough for SHA-3 with max blksz of 144Bytes
	int seq;
	int outfd;
	unsigned char buflen;
	unsigned char ilnchg, olnchg, ichg, ochg, debug, outf, chkf, chkfalloc;
	const char* chkfnm;
	const opt_t *opts;
	unsigned char* hmacpwd;
#ifndef NO_S3_MP
	/* multipart s3 style checksum */
	loff_t multisz;
	unsigned char *mpbuf;
	int mpbufsz;
	int mpbufseg;
#endif
	int hmacpln;
	char xfallback;
#if 1 //def HAVE_ATTR_XATTR_H
	char chk_xattr, set_xattr, xnmalloc;
	char* xattr_name;
#endif
} hash_state;

const char *hash_help = "The HASH plugin for dd_rescue calculates a cryptographic checksum on the fly.\n"
		" It supports unaligned blocks (arbitrary offsets) and holes(sparse writing).\n"
		" Parameters: output:outfd=FNO:outnm=FILE:check:chknm=FILE:debug:[alg[o[rithm]=]ALG\n"
		"\t:append=STR:prepend=STR:hmacpwd=STR:hmacpwdfd=FNO:hmacpwdnm=FILE\n"
		"\t:pbkdf2=ALG/PWD/SALT/ITER/LEN"
#ifndef NO_S3_MP
		":multipart=size"
#endif
		"\n"
#ifdef HAVE_ATTR_XATTR_H
		"\t:chk_xattr[=xattr_name]:set_xattr[=xattr_name]:fallb[ack][=FILE]\n"
#endif
		" Use algorithm=help to get a list of supported hash algorithms\n";


#ifndef NO_S3_MP
static loff_t readint(const char* const ptr)
{
	char *es; double res;

	res = strtod(ptr, &es);
	switch (*es) {
		case 'b': res *= 512; break;
		case 'k': res *= 1024; break;
		case 'M': res *= 1024*1024; break;
		case 'G': res *= 1024*1024*1024; break;
		case ' ':
		case '\0': break;
		default:
			FPLOG(WARN, "suffix %c ignored!\n", *es);
	}
	return (loff_t)res;
}
#define ALLOC_CHUNK 16384
#endif

hashalg_t *get_hashalg(hash_state *state, const char* nm)
{
	unsigned int i;
	const char help = !strcmp(nm, "help");
	if (help)
		FPLOG(INFO, "Supported algorithms:");
	for (i = 0; i < sizeof(hashes)/sizeof(hashalg_t); ++i) {
		if (help)
			fprintf(stderr, " %s", hashes[i].name);
		else if (!strcasecmp(nm, hashes[i].name))
			return hashes+i;
	}
	if (help)
		fprintf(stderr, "\n");
	return NULL;
}

#define MAX_HMACPWDLN 2048
int do_pbkdf2(hash_state *state, char* param);

int hash_plug_init(void **stat, char* param, int seq, const opt_t *opt)
{
	int err = 0;
	hash_state *state; /* = (hash_state*)malloc(sizeof(hash_state));*/
	if (posix_memalign(stat, 64, sizeof(hash_state))) {
		FPLOG(FATAL, "No enough memory for hash state!\n");
		return -1;
	}
	state = (hash_state*)*stat;
	memset(state, 0, sizeof(hash_state));
	state->seq = seq;
	state->opts = opt;
	state->alg = get_hashalg(state, ddr_plug.name);
	while (param) {
		char* next = strchr(param, ':');
		if (next)
			*next++ = 0;
		if (!strcmp(param, "help"))
			FPLOG(INFO, "%s", hash_help);
		
		else if (!strcmp(param, "debug"))
			state->debug = 1;
		else if (!strcmp(param, "output"))
			state->outfd = 1;
		else if (!memcmp(param, "outfd=", 6))
			state->outfd = atoi(param+6);
		else if (!memcmp(param, "append=", 7))
			state->append = param+7;
		else if (!memcmp(param, "prepend=", 8))
			state->prepend = param+8;
#if 1 //def HAVE_ATTR_XATTR_H
		else if (!memcmp(param, "chk_xattr=", 10)) {
			state->chk_xattr = 1; state->xattr_name = param+10; }
		else if (!strcmp(param, "chk_xattr"))
			state->chk_xattr = 1;
		else if (!memcmp(param, "set_xattr=", 10)) {
			state->set_xattr = 1; state->xattr_name = param+10; }
		else if (!strcmp(param, "set_xattr")) 
			state->set_xattr = 1;
#endif
		else if (!strcmp(param, "fallb")) 
			state->xfallback = 1;
		else if (!strcmp(param, "fallback")) 
			state->xfallback = 1;
		else if (!memcmp(param, "fallback=", 9)) {
			state->xfallback = 1; state->chkfnm = param+9; }
		else if (!memcmp(param, "fallb=", 6)) {
			state->xfallback = 1; state->chkfnm = param+6; }
		else if (!strcmp(param, "outnm"))
			state->outf = 1;
		else if (!memcmp(param, "outnm=", 6)) {
			state->outf = 1; state->chkfnm=param+6; }
		else if (!strcmp(param, "chknm"))
			state->chkf = 1;
		else if (!memcmp(param, "chknm=", 6)) {
			state->chkf = 1; state->chkfnm=param+6; }
		else if (!strcmp(param, "check")) {
			state->chkf = 1; state->chkfnm="-"; }
#ifndef NO_S3_MP
		else if (!memcmp(param, "multipart=", 10)) {
			state->multisz = readint(param+10); }
#endif
		else if (!memcmp(param, "algo=", 5))
			state->alg = get_hashalg(state, param+5);
		else if (!memcmp(param, "alg=", 4))
			state->alg = get_hashalg(state, param+4);
		else if (!memcmp(param, "algorithm=", 10))
			state->alg = get_hashalg(state, param+10);
		else if (!memcmp(param, "hmacpwd=", 8)) {
			state->hmacpwd = (unsigned char*)malloc(MAX_HMACPWDLN);
			strncpy((char*)state->hmacpwd, param+8, MAX_HMACPWDLN);
			state->hmacpln = strlen(param+8);
		}
		else if (!memcmp(param, "hmacpwdfd=", 10)) {
			int hfd = atol(param+10);
			state->hmacpwd = (unsigned char*)malloc(MAX_HMACPWDLN);
			if (hfd == 0 && isatty(hfd)) {
				FPLOG(INPUT, "%s", "Enter HMAC password: ");
				state->hmacpln = hidden_input(hfd, (char*)state->hmacpwd, MAX_HMACPWDLN, 1);
			} else
				state->hmacpln = read(hfd, state->hmacpwd, MAX_HMACPWDLN);
			if (state->hmacpln <= 0) {
				FPLOG(FATAL, "No HMAC password entered!\n");
				--err;
			}
		}
		else if (!memcmp(param, "hmacpwdnm=", 10)) {
			FILE *f = fopen(param+10, "r");
			if (!f) {
				FPLOG(FATAL, "Could not open %s for reading HMAC pwd!\n", param+10);
				--err;
				param = next;
				continue;
			}
			state->hmacpwd = (unsigned char*)malloc(MAX_HMACPWDLN);
			state->hmacpln = fread(state->hmacpwd, 1, MAX_HMACPWDLN, f);
			if (state->hmacpln <= 0) {
				FPLOG(FATAL, "No HMAC pwd contents found in %s!\n", param+10);
				--err;
			}
		}
		else if (!memcmp(param, "pbkdf2=", 7))
			err += do_pbkdf2(state, param+7);
		/* elif .... */
		/* Hmmm, ok, let's support algname without alg= */
		else {
			hashalg_t *hash = get_hashalg(state, param);
			if (hash)
				state->alg = hash;
			else {
				FPLOG(FATAL, "plugin doesn't understand param %s\n",
					param);
				--err;
			}
		}
		param = next;
	}
	if (!state->alg) {
		FPLOG(FATAL, "No hash algorithm specified\n");
		return --err;
	}
#ifdef HAVE_ATTR_XATTR_H
	if ((state->chk_xattr || state->set_xattr) && !state->xattr_name) {
		state->xattr_name = (char*)malloc(32);
		state->xnmalloc = 1;
		if (state->hmacpwd)
			snprintf(state->xattr_name, 32, "user.hmac.%s", state->alg->name);
		else
			snprintf(state->xattr_name, 32, "user.checksum.%s", state->alg->name);
	}
#endif
	if ((!state->chkfnm || !*state->chkfnm) && (state->chkf || state->outf
#ifdef HAVE_ATTR_XATTR_H
				|| state->xfallback
#endif
			     				)) {
		char cfnm[32];
		// if (!strcmp(state->alg->name, "md5")) strcpy(cfnm, "MD5SUMS"); else
		// FIXME: Should we prepend iname or oname path to HMACS/CHECKSUMS ?
		if (state->hmacpwd)
			snprintf(cfnm, 32, "HMACS.%s", state->alg->name);
		else
			snprintf(cfnm, 32, "CHECKSUMS.%s", state->alg->name);
		state->chkfalloc = 1;
		state->chkfnm = strdup(cfnm);
	}
	if ((unsigned)state->hmacpln > state->alg->blksz) {
		hash_t hv;
		state->alg->hash_init(&hv);
		state->alg->hash_calc(state->hmacpwd, state->hmacpln, state->hmacpln, &hv);
		memset(state->hmacpwd+state->alg->hashln, 0, 256-state->alg->hashln);
		state->alg->hash_beout(state->hmacpwd, &hv);
		state->hmacpln = state->alg->hashln;
	}
	if (state->debug)
		FPLOG(DEBUG, "Initialized plugin %s (%s)\n", ddr_plug.name, state->alg->name);
	return err;
}

int hash_plug_release(void **stat)
{
	if (!stat || !(*stat))
		return -1;
	hash_state *state = (hash_state*)*stat;
#ifdef HAVE_ATTR_XATTR_H
	if (state->xnmalloc)
		free((void*)state->xattr_name);
#endif
	if (state->chkfalloc)
		free((void*)state->chkfnm);
	if (state->fname && strcmp(state->fname, state->opts->iname) && strcmp(state->fname, state->opts->oname))
		free((void*)state->fname);
	if (state->hmacpwd) {
		memset(state->hmacpwd, 0, MAX_HMACPWDLN);
		asm("":::"memory");
		free(state->hmacpwd);
	}
	free(*stat);
	return 0;
}

#define MIN(a,b) ((a)<(b)? (a): (b))
#define MAX(a,b) ((a)<(b)? (b): (a))

int hash_open(const opt_t *opt, int ilnchg, int olnchg, int ichg, int ochg,
	     unsigned int totslack_pre, unsigned int totslack_post,
	     const fstate_t *fst, void **stat)
{
	int err = 0;
	hash_state *state = (hash_state*)*stat;
	state->opts = opt;
	state->alg->hash_init(&state->hash);
	const unsigned int blen = state->alg->blksz;
	if (state->hmacpwd) {
		state->alg->hash_init(&state->hmach);
		/* inner buf */
		unsigned char ibuf[blen];
		memset(ibuf, 0x36, blen);
		memxor(ibuf, state->hmacpwd, state->hmacpln);
		state->alg->hash_block(ibuf, &state->hmach);
		memset(ibuf, 0, blen); asm("":::"memory");
	}
	state->hash_pos = 0;

	if (!ochg && state->seq != 0 && strcmp(opt->oname, "/dev/null"))
		state->fname = opt->oname;
	else if (!ichg)
		state->fname = opt->iname;
	else {
		char* nnm = (char*)malloc(strlen(opt->iname)+strlen(opt->oname)+3);
		strcpy(nnm, opt->iname);
		strcat(nnm, "->");
		strcat(nnm, opt->oname);
		state->fname = nnm;
#ifdef HAVE_ATTR_XATTR_H
		if (state->chk_xattr || state->set_xattr) {
			--err;
			FPLOG(WARN, "Can't access xattr in the middle of a plugin chain!");
		}
#endif
	}
	if (state->prepend) {
		int done = 0; int remain = strlen(state->prepend);
		while (remain >= (int)blen) {
			state->alg->hash_block((uint8_t*)(state->prepend)+done, &state->hash);
			if (state->hmacpwd)
				state->alg->hash_block((uint8_t*)(state->prepend)+done, &state->hmach);
			remain -= blen;
			done += blen;
		}
		HASH_DEBUG(FPLOG(DEBUG, "Prepending %i+%i bytes (padded with %i bytes)\n",
				done, remain, blen-remain));
		if (remain) {
			memcpy(state->buf, state->prepend+done, remain);
			memset(state->buf+remain, 0, blen-remain);
			state->alg->hash_block(state->buf, &state->hash);
			if (state->hmacpwd)
				state->alg->hash_block(state->buf, &state->hmach);
		}
	}
	memset(state->buf, 0, sizeof(state->buf));
	state->buflen = 0;
	state->ilnchg = ilnchg;
	state->olnchg = olnchg;
	state->ichg = ichg;
	state->ochg = ochg;
	if (ichg && ochg && (state->opts->sparse || !state->opts->nosparse)) {
		FPLOG(WARN, "Size of potential holes may not be correct due to other plugins;\n");
		FPLOG(WARN, " Hash/HMAC may be miscomputed! Avoid holes (remove -a, use -A).\n");
	}
	return err;
}

#if __WORDSIZE == 64
#define LL "l"
#elif __WORDSIZE == 32
#define LL "ll"
#else
#error __WORDSIZE unknown
#endif

static inline int round_down(int val, const int gran)
{
	return val-val%gran;
}
	
#define round_up(v, g) round_down(v+g-1, g)

void hash_last(hash_state *state, loff_t pos)
{
	//hash_block(0, 0, ooff, stat);
	int left = pos - state->hash_pos;
	assert(state->buflen == left || (state->ilnchg && state->olnchg));
	/*
	fprintf(stderr, "HASH_DEBUG: %s: len=%li, hashpos=%li\n", 
		state->fname, len, state->hash_pos);
	 */
	HASH_DEBUG(FPLOG(DEBUG, "Last block with %i bytes\n", state->buflen));
	if (state->append) {
		memcpy(state->buf+state->buflen, state->append, strlen(state->append));
		state->buflen += strlen(state->append);
		HASH_DEBUG(FPLOG(DEBUG, "Append string with %i bytes for hash\n", strlen(state->append)));
	}
	int preln = state->prepend? round_up(strlen(state->prepend), state->alg->blksz): 0;
	if (preln)
		HASH_DEBUG(FPLOG(DEBUG, "Account for %i extra prepended bytes\n", preln));
	state->alg->hash_calc(state->buf, state->buflen, state->hash_pos+state->buflen+preln, &state->hash);
	if (state->hmacpwd)
		state->alg->hash_calc(state->buf, state->buflen, 
				      state->hash_pos+state->buflen+preln+state->alg->blksz,
				      &state->hmach);
	state->hash_pos += state->buflen;
}

static inline void hash_block_buf(hash_state* state, int clear)
{
	state->alg->hash_block(state->buf, &state->hash);
	if (state->hmacpwd)
		state->alg->hash_block(state->buf, &state->hmach);
	state->hash_pos += state->alg->blksz;
	state->buflen = 0;
	if (clear)
		memset(state->buf, 0, clear);
}

void hash_hole(fstate_t *fst, hash_state *state, loff_t holelen)
{
	const unsigned int blksz = state->alg->blksz;
	if (state->buflen) {
		const unsigned int remain = blksz - state->buflen;
		HASH_DEBUG(FPLOG(DEBUG, "first sparse block (drain %i)\n", state->buflen));
		memset(state->buf+state->buflen, 0, remain);
		if (holelen >= blksz-state->buflen) {
			holelen -= remain;
			hash_block_buf(state, state->buflen);
		} else {
			state->buflen += holelen;
			return;
		}
	}
	assert(state->buflen == 0);
	HASH_DEBUG(FPLOG(DEBUG, "bulk sparse %i\n", holelen-holelen%blksz));
	while (holelen >= blksz) {
		hash_block_buf(state, 0);
		holelen -= blksz;
	}
	assert(holelen >= 0 && holelen < blksz);
	// memset(state->buf, 0, holelen);
	state->buflen = holelen;
	HASH_DEBUG(FPLOG(DEBUG, "sparse left %i (%i+%i)\n", holelen, state->hash_pos, state->buflen));
	return;
}

/* This is rather complex, as we handle both non-aligned first block size
 * as well as sparse files */
unsigned char* hash_blk_cb(fstate_t *fst, unsigned char* bf, 
			   int *towr, int eof, int *recall, void **stat)
{
	/* TODO: Replace usage of state->buf by using slack space
	 * Hmmm, really? Probably buffer management is not sophisticated enough currently ... */
	/* TODO: If both ilnchg and olnchg are set, switch off sanity checks and go into dumb mode */
	hash_state *state = (hash_state*)*stat;
	const loff_t pos = state->olnchg? 
			fst->ipos - state->opts->init_ipos:
			fst->opos - state->opts->init_opos;
	HASH_DEBUG(FPLOG(DEBUG, "block(%i/%i): towr=%i, eof=%i, pos=%" LL "i, hash_pos=%" LL "i, buflen=%i\n",
				state->seq, state->olnchg, *towr, eof, pos, state->hash_pos, state->buflen));
#ifndef NO_S3_MP
	if (state->multisz && ((!(state->hash_pos%state->multisz) && state->hash_pos && *towr) || (!*towr && state->mpbufseg))) {
		/* TODO: Check if we have enough space and enlarge mpbuf if needed */
		const unsigned int hln = state->alg->hashln;
		if ((1+state->mpbufseg)*hln > state->mpbufsz) {
			state->mpbufsz += ALLOC_CHUNK;
			state->mpbuf = realloc(state->mpbuf, state->mpbufsz);
			assert(state->mpbuf);
		}
		/* Copy current hash into mpbuf and incr mpbufseg */
		unsigned long diff = state->hash_pos - (state->hash_pos-1)%state->multisz - 1;
		state->hash_pos -= diff;
		hash_last(state, pos-diff);
		memcpy(state->mpbuf+state->mpbufseg*hln, &state->hash, hln);
		state->mpbufseg++;
		if (state->debug) {
			char res[129];
			FPLOG(DEBUG, "Hash segment %i: %s (pos %" LL "i hash %li)\n", state->mpbufseg, state->alg->hash_hexout(res, &state->hash), pos, state->hash_pos);
		}
		/* Reset hash to zero ... */
		state->alg->hash_init(&state->hash);
		state->hash_pos += diff;
	}
#endif
	// Handle hole (sparse files)
	const loff_t holesz = pos - (state->hash_pos + state->buflen);
	assert(holesz >= 0 || (state->ilnchg && state->olnchg));
	const unsigned int blksz = state->alg->blksz;
	if (holesz && !(state->ilnchg && state->olnchg))
		hash_hole(fst, state, holesz);

	assert(pos == state->hash_pos+state->buflen || (state->ilnchg && state->olnchg));
	int consumed = 0;
	assert(bf);
	/* First block */
	if (state->buflen && *towr) {
		/* Reassemble and process first block */
		consumed = MIN((int)blksz-state->buflen, *towr);
		HASH_DEBUG(FPLOG(DEBUG, "Append %i bytes @ %i to store\n", consumed, pos));
		memcpy(state->buf+state->buflen, bf, consumed);
		if (consumed+state->buflen == (int)blksz) {
			hash_block_buf(state, blksz);
		} else {
			state->buflen += consumed;
			//memset(state->buf+state->buflen, 0, blksz-state->buflen);
		}
	}

	assert(state->hash_pos+state->buflen == pos+consumed || (state->ilnchg && state->olnchg));
	/* Bulk buffer process */
	int to_process = *towr - consumed;
	assert(to_process >= 0);
	to_process -= to_process%blksz;
	if (to_process) {
		HASH_DEBUG(FPLOG(DEBUG, "Consume %i bytes @ %i\n", to_process, pos+consumed));
		assert(state->buflen == 0);
		state->alg->hash_calc(bf+consumed, to_process, -1, &state->hash);
		if (state->hmacpwd)
			state->alg->hash_calc(bf+consumed, to_process, -1, &state->hmach);
		consumed += to_process; state->hash_pos += to_process;
	}
	assert(state->hash_pos+state->buflen == pos+consumed || (state->ilnchg && state->olnchg));
	to_process = *towr - consumed;
	assert(to_process >= 0 && to_process < (int)blksz);
	/* Copy remainder into buffer */
	if (!(state->olnchg && state->ilnchg) && state->hash_pos + state->buflen != pos + consumed)
		FPLOG(FATAL, "Inconsistency: HASH pos %i, buff %i, st pos %" LL "i, cons %i, tbw %i\n",
				state->hash_pos, state->buflen, pos, consumed, *towr);
	if (to_process) {
		HASH_DEBUG(FPLOG(DEBUG, "Store %i bytes @ %" LL "i\n", to_process, pos+consumed));
		assert(state->buflen == 0);
		memcpy(state->buf+state->buflen, bf+consumed, to_process);
		state->buflen = to_process;
	}
	if (eof)
		hash_last(state, pos+*towr);
	return bf;
}


int check_chkf(hash_state *state, const char* res)
{
	const char* name = state->opts->iname;
	char cks[144];
	if (state->ichg && !state->ochg) {
		name = state->opts->oname;
		if (!state->opts->quiet)
			FPLOG(INFO, "Read checksum from %s for output file %s\n", state->chkfnm, name);
	} else if (state->ichg) {
		FPLOG(WARN, "Can't read checksum in the middle of plugin chain (%s)\n", state->fname);
		return -ENOENT;
	}
	int err = get_chks(state->chkfnm, name, cks, strlen(res));
	if (err < 0) {
		FPLOG(WARN, "Can't find checksum in %s for %s\n", state->chkfnm, name);
		return -ENOENT;
	}
	if (strcmp(cks, res)) {
		FPLOG(WARN, "Hash from chksum file %s for %s does not match\n", state->chkfnm, name);
		FPLOG(WARN, "comp %s, read %s\n", res, cks);
		return -EBADF;
	}
	return 0;
}

int write_chkf(hash_state *state, const char *res)
{
	const char* name = state->opts->oname;
	if ((state->ochg || !strcmp(state->opts->oname, "/dev/null")) && !state->ichg) {
		name = state->opts->iname;
		if (!state->opts->quiet)
			FPLOG(INFO, "Write checksum to %s for input file %s\n", state->chkfnm, name);
	} else if (state->ochg) {
		FPLOG(WARN, "Can't write checksum in the middle of plugin chain (%s)\n",
				state->fname);
		return -ENOENT;
	}
	int err = upd_chks(state->chkfnm, name, res, 0644);
	if (err) 
		FPLOG(WARN, "Hash writing to %s for %s failed\n", state->chkfnm, name);
	return err;
}

#ifdef HAVE_ATTR_XATTR_H
int check_xattr(hash_state* state, const char* res)
{
	char xatstr[144];
	strcpy(xatstr, "xattr");
	const char* name = state->opts->iname;
	if (state->ichg && !state->ochg) {
		name = state->opts->oname;
		if (!state->opts->quiet)
			FPLOG(INFO, "Read xattr from output file %s\n", name);
	} else if (state->ichg) {
		FPLOG(WARN, "Can't read xattrs in the middle of plugin chain (%s)\n", state->fname);
		return -ENOENT;
	}
	/* Longest is 128byte hex for SHA512 (8x64byte numbers -> 8x16 digits) */
	char chksum[144];
	ssize_t itln = getxattr(name, state->xattr_name, chksum, 144);
	const int rln = strlen(res);
	if (itln <= 0) {
		if (state->xfallback) {
			int err = get_chks(state->chkfnm, name, chksum, rln);
			snprintf(xatstr, 143, "chksum file %s", state->chkfnm);
			if (err < 0) {
				FPLOG(WARN, "no hash found in xattr nor %s for %s\n", xatstr, name);
				return -ENOENT;
			} else if (strcmp(chksum, res)) {
				FPLOG(WARN, "Hash from %s for %s does not match\n", xatstr, name);
				return -EBADF;
			}
		} else {
			FPLOG(WARN, "Hash could not be read from xattr of %s\n", name);
			return -ENOENT;
		}
	} else if (itln < rln || memcmp(res, chksum, rln)) {
		FPLOG(WARN, "Hash from xattr of %s does not match\n", name);
		return -EBADF;
	}
	if (!state->opts->quiet || state->debug)
		FPLOG(INFO, "Successfully validated hash from %s for %s\n", xatstr, name);
	return 0;
}

int write_xattr(hash_state* state, const char* res)
{
	const char* name = state->opts->oname;
	char xatstr[144];
	snprintf(xatstr, 143, "xattr %s", state->xattr_name);
	if (state->ochg && !state->ichg) {
		name = state->opts->iname;
		if (!state->opts->quiet)
			FPLOG(INFO, "Write xattr to input file %s\n", name);
	} else if (state->ochg) {
		FPLOG(WARN, "Can't write xattr in the middle of plugin chain (%s)\n",
				state->fname);
		return -ENOENT;
	}
	if (setxattr(name, state->xattr_name, res, strlen(res), 0)) {
		if (state->xfallback) {
			int err = upd_chks(state->chkfnm, name, res, 0644);
			snprintf(xatstr, 143, "chksum file %s", state->chkfnm);
			if (err) {
				FPLOG(WARN, "Failed writing to %s for %s: %s\n", 
						xatstr, name, strerror(-err));
				return err;
			}
		} else {
			FPLOG(WARN, "Failed writing hash to xattr of %s\n", name);
			return -errno;
		}
	}
	if (state->debug)
		FPLOG(DEBUG, "Set %s for %s to %s\n",
				xatstr, name, res);
	return 0;
}
#endif

int hash_close(loff_t ooff, void **stat)
{
	int err = 0;
	hash_state *state = (hash_state*)*stat;
	char res[144];
	const unsigned int hlen = state->alg->hashln;
	const unsigned int blen = state->alg->blksz;
	loff_t firstpos = (state->seq == 0? state->opts->init_ipos: state->opts->init_opos);
#ifndef NO_S3_MP
	if (state->multisz && state->mpbufseg) {
		const unsigned int hln = state->alg->hashln;
		state->alg->hash_init(&state->hash);
		state->alg->hash_calc(state->mpbuf, state->mpbufseg*hln, state->mpbufseg*hln, &state->hash);
		state->alg->hash_hexout(res, &state->hash);
		sprintf(res+strlen(res), "-%i", state->mpbufseg);
	} else
#endif
	state->alg->hash_hexout(res, &state->hash);
	if (!state->opts->quiet) 
		FPLOG(INFO, "%s %s (%" LL "i-%" LL "i): %s\n",
			state->alg->name, state->fname, firstpos, firstpos+state->hash_pos, res);
	/* If we calculate an HMAC, use it rather than the hash value for ev.thing else */
	if (state->hmacpwd) {
		assert(hlen < blen-9);
		unsigned char obuf[2*blen];
		memset(obuf, 0x5c, blen);
		memxor(obuf, state->hmacpwd, state->hmacpln);
		state->alg->hash_beout(obuf+blen, &state->hmach);
		state->alg->hash_init(&state->hmach);
		state->alg->hash_calc(obuf, blen+hlen, blen+hlen, &state->hmach);
		memset(obuf, 0, blen); asm("":::"memory");
		state->alg->hash_hexout(res, &state->hmach);
		if (!state->opts->quiet) 
			FPLOG(INFO, "HMAC %s %s (%" LL "i-%" LL "i): %s\n",
				state->alg->name, state->fname, firstpos, firstpos+state->hash_pos, res);
	}
	if (state->outfd) {
		char outbuf[512];
		snprintf(outbuf, 511, "%s *%s\n", res, state->fname);
		if (write(state->outfd, outbuf, strlen(outbuf)) <= 0) {
			FPLOG(WARN, "Could not write %s result to fd %i\n", 
				(state->hmacpwd? "HMAC": "HASH"),
				state->outfd);
			--err;
		}
	}
	if (state->chkf) 
		err += check_chkf(state, res);
	if (state->outf)
		err += write_chkf(state, res);
#ifdef HAVE_ATTR_XATTR_H
	if (state->chk_xattr)
		err += check_xattr(state, res);
	if (state->set_xattr)
		err += write_xattr(state, res);
#endif
	return err;
}

static char _kout_buf[2049];
char* kout(unsigned char* key, int klen)
{
	int i;
	for (i = 0; i < klen; ++i)
		sprintf(_kout_buf+2*i, "%02x", key[i]);
	return _kout_buf;
}

int do_pbkdf2(hash_state *state, char* param)
{
	char *pwd, *salt;
	unsigned int iter; int klen, err = 1;
	unsigned char *key;
	hashalg_t *halg;

	char* next = strchr(param, '/');
	if (next)
		*next++ = 0;
	else
		goto out_err;
	halg = get_hashalg(state, param);
	if (!halg) {
		FPLOG(FATAL, "Unknown hash alg %s!\n", param);
		return 1;
	}		
	
	param = next;
	next = strchr(param, '/');
	if (next)
		*next++ = 0;
	else
		goto out_err;
	pwd = param;
	
	param = next;
	next = strchr(param, '/');
	if (next)
		*next++ = 0;
	else
		goto out_err;
	salt = param;

	param = next;
	next = strchr(param, '/');
	if (next)
		*next++ = 0;
	else
		goto out_err;
	iter = atol(param);

	klen = atol(next)/8;

	key = (unsigned char*)malloc(klen);

	err = pbkdf2(halg, (unsigned char*)pwd, strlen(pwd), 
			 (unsigned char*)salt, strlen(salt),
			 iter, key, klen);
	
	FPLOG(INFO, "PBKDF2(%s, %s, %s, %i, %i) = %s\n",
		halg->name, pwd, salt, iter, klen*8, kout(key, klen));
	free(key);
	return err;
    out_err:
	FPLOG(FATAL, "Syntax: pbkdf2=ALG/PWD/SALT/ITER/KEYLEN\n");		
	return 1;
}


ddr_plugin_t ddr_plug = {
	//.name = "hash",
	.slack_pre = 144,	// not yet used
	.slack_post = 288,	// not yet used
	.needs_align = 0,
	.handles_sparse = 1,
	.makes_unsparse = 0,
	.changes_output = 0,
	.changes_output_len = 0,
	.supports_seek = 0,
	.init_callback  = hash_plug_init,
	.open_callback  = hash_open,
	.block_callback = hash_blk_cb,
	.close_callback = hash_close,
	.release_callback = hash_plug_release,
};


