/** dd_rescue.c
 * 
 * dd_rescue copies your data from one file to another.  Files might as well be
 * block devices, such as hd partitions.  Unlike dd, it does not necessarily
 * abort on errors but continues to copy the disk, possibly leaving holes
 * behind.  Also, it does NOT truncate the output file, so you can copy more
 * and more pieces of your data, as time goes by.  This tool is thus suitable
 * for rescueing data of crashed disk, and that's the reason it has been
 * written by me.
 *
 * Copyright (C) Kurt Garloff <kurt@garloff.de>, 11/1997 -- 02/2013
 *
 * Improvements from LAB Valentin, see
 * http://www.kalysto.org/utilities/dd_rhelp/index.en.html
 * 
 * License: GNU GPL v2 or v3
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the Free
 *  Software Foundation; either version 2 of the License, or (at your option)
 *  version 3.
 *
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 *  more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110-1301,  USA.
 */

/**
 * TODO:
 * - Use termcap to fetch cursor up/down and color codes
 * - Display more infos on errors by collecting info from syslog
 * - Option to send TRIM on zeroed file blocks
 * - Plugins for compression/decompression other than liblzo2
 * - Reed-Solomon/Erasure codes a la par2
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef VERSION
# define VERSION "(unknown)"
#endif
#ifndef __COMPILER__
# define __COMPILER__ "(unknown compiler)"
#endif

#ifndef BUF_SOFTBLOCKSIZE
# define BUF_SOFTBLOCKSIZE 131072
#endif

#ifndef BUF_HARDBLOCKSIZE
# define BUF_HARDBLOCKSIZE pagesize
#endif

#ifndef DIO_SOFTBLOCKSIZE
# define DIO_SOFTBLOCKSIZE 1048576
#endif

#ifndef DIO_HARDBLOCKSIZE
# define DIO_HARDBLOCKSIZE 512
#endif


#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
#define _LARGEFILE_SOURCE
#define _FILE_OFFSET_BITS 64

#ifdef TEST_SYSCALL
#define splice _splice
#define fallocate64 _fallocate64
#define pread64 _pread64
#define pwrite64 _pwrite64
#endif
// hack around buggy splice definition(!)
#if defined(__GLIBC__) && __GLIBC__ == 2 && __GLIBC_MINOR__ < 10
# define SPLICE_IS_BUGGY 1
# define splice _splice
#endif

#include <unistd.h>
#include <fcntl.h>

#ifdef SPLICE_IS_BUGGY
#undef splice
#endif
#ifdef TEST_SYSCALL
#undef splice
#undef fallocate64
#undef pread64
#undef pwrite64
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <utime.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <libgen.h>
#include <assert.h>

#include "random.h"
#include "frandom.h"
#include "list.h"
#include "fmt_no.h"
#include "find_nonzero.h"

#include "fstrim.h"

#include "ddr_plugin.h"
#include "ddr_ctrl.h"

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#endif

#ifdef HAVE_SCHED_H
#include <sched.h>
#endif

#ifdef NO_LIBFALLOCATE
# undef HAVE_LIBFALLOCATE
# undef HAVE_FALLOCATE_H
#endif

#ifdef HAVE_FALLOCATE_H
# include <fallocate.h>
#else
# ifdef HAVE_FALLOCATE64
#  include <linux/falloc.h>
typedef off64_t __off64_t;
# endif
#endif

#if defined(HAVE_DLFCN_H) && !defined(NO_LIBDL)
#include <dlfcn.h>
void* libfalloc = (void*)0;
#define USE_LIBDL 1
#endif

/* splice */
#if defined(__linux__) && (!defined(HAVE_SPLICE) || defined(SPLICE_IS_BUGGY) || defined(TEST_SYSCALL))
#include "splice.h"
#endif
/* fallocate64 */
#if defined(__linux__) && (!defined(HAVE_FALLOCATE64) || defined(TEST_SYSCALL))
# include "fallocate64.h"
#endif

/* xattrs */
#ifdef HAVE_ATTR_XATTR_H
# include <attr/xattr.h>
#else
/* TODO: Could provide the prototypes for the syscalls ourselves ... */
# warning No support for copying extended attributes / ACLs
#endif

/* Handle lack of stat64 */
#ifdef HAVE_STAT64
# define STAT64 stat64
# define FSTAT64 fstat64
#else
# define STAT64 stat
# define FSTAT64 fstat
# warning We lack stat64, may not handle >2GB files correctly
#endif

#ifndef HAVE_LSEEK64
# define lseek64 lseek
# warning We lack lseek64, may not handle >2GB files correctly
#endif

/* This is not critical -- most platforms have an internal 64bit offset with plain open() */
#ifndef HAVE_OPEN64
# define open64 open
#endif

#if !defined(HAVE_PREAD64) || defined(TEST_SYSCALL)
#include "pread64.h"
#endif

#define MIN(a,b) ((a)<(b)? (a): (b))

#if __WORDSIZE == 64
# define LL "l"
#elif __WORDSIZE == 32
# define LL "ll"
#else
# error __WORDSIZE undefined
#endif

#ifdef HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#endif

#if defined(HAVE_REP_NOP) && (defined(__x86_64__) || defined(__i386__))
# define cpu_relax() asm volatile ("rep nop":::"memory");
#else
# define cpu_relax() while (0) {}
#endif


/* fwd decls */
int cleanup(char);

struct emerg_ptrs {
	opt_t *opts;
	fstate_t *fstate;
	progress_t *progress;
	repeat_t *repeat;
	dpopt_t *dpopts;
	dpstate_t *dpstate;
} eptrs;

void set_eptrs(opt_t *op, fstate_t *fst, progress_t *prg,
		repeat_t *rep, dpopt_t *dop, dpstate_t *dst)
{
	eptrs.opts = op;
	eptrs.fstate = fst;
	eptrs.progress = prg;
	eptrs.repeat = rep;
	eptrs.dpopts = dop;
	eptrs.dpstate = dst;
}


/* Globals, shadowing opts/fstate info */
char nocol;
static unsigned int pagesize;

/* Rate limit for status updates */
float printint = 0.1;
char in_report;

FILE *logfd;

struct timeval starttime, lasttime, currenttime;
struct timezone tz;
clock_t startclock;

sig_atomic_t interrupted = 0;
int int_by = 0;

/* multiple output files */
typedef struct _ofile {
	const char* name;
	int fd;
	char cdev;
} ofile_t;
LISTDECL(ofile_t);
LISTTYPE(ofile_t) *ofiles;

typedef char* charp;
LISTDECL(charp);
LISTTYPE(charp) *freenames;

typedef struct _fault_in {
	loff_t off, off2;
	int rep;
} fault_in_t;

LISTDECL(fault_in_t);
LISTTYPE(fault_in_t) *read_faults;
LISTTYPE(fault_in_t) *write_faults;

const char *scrollup = 0;

#ifndef UP
# define UP "\x1b[A"
# define DOWN "\n"
# define RIGHT "\x1b[C"
#endif

const char* up = UP;
const char* fourup = UP UP UP UP;
const char* threeup = UP UP UP;
//const char* down = DOWN;
const char* right = RIGHT;
const char* nineright = RIGHT RIGHT RIGHT RIGHT RIGHT RIGHT RIGHT RIGHT RIGHT;
char *graph;	/* = NULL */

#ifdef NO_COLORS
# define RED ""
# define AMBER ""
# define YELLOW ""
# define GREEN ""
# define BOLD ""
# define INV ""
# define NORM ""
#else
#ifndef RED
# define RED "\x1b[0;31m"
# define AMBER "\x1b[0;33m"
# define YELLOW "\x1b[1;33m"
# define GREEN "\x1b[0;32m"
# define BOLD "\x1b[0;1m"
# define ULINE "\x1b[0;4m"
# define INV "\x1b[0;7m"
# define NORM "\x1b[0;0m"
#endif
#endif


#define DDR_DEBUG "dd_rescue: (debug): "
#define DDR_INFO  "dd_rescue: (info): "
#define DDR_WARN  "dd_rescue: (warning): "
#define DDR_FATAL "dd_rescue: (fatal): "
#define DDR_GOOD  "dd_rescue: (success): "
#define DDR_INPUT "dd_rescue: (input): "
#define DDR_DEBUG_C ULINE DDR_DEBUG NORM
#define DDR_INFO_C  BOLD DDR_INFO NORM
#define DDR_WARN_C  AMBER DDR_WARN NORM
#define DDR_FATAL_C RED DDR_FATAL NORM
#define DDR_GOOD_C  GREEN DDR_GOOD NORM
#define DDR_INPUT_C INV DDR_INPUT NORM

const char* ddrlogpre[] = {"", DDR_DEBUG, DDR_INFO, DDR_WARN, DDR_FATAL, DDR_GOOD, DDR_INPUT };
const char* ddrlogpre_c[] = {"", DDR_DEBUG_C, DDR_INFO_C, DDR_WARN_C, DDR_FATAL_C, DDR_GOOD_C, DDR_INPUT_C };


#ifdef MISS_STRSIGNAL
static char sfstate->buf[16];
static char* strsignal(int sig)
{
	sprintf(sfstate->buf, "sig %i", sig);
	return sfstate->buf;
}
#endif

static inline char* fmt_kiB(loff_t no, char col)
{
	return fmt_int(0, 1, 1024, no, (col? BOLD: ""), (col? NORM: ""), 1);
}

static inline float difftimetv(const struct timeval* const t2,
			const struct timeval* const t1)
{
	return  (float) (t2->tv_sec  - t1->tv_sec ) +
		(float) (t2->tv_usec - t1->tv_usec) * 1e-6;
}


/** Write to file and simultaneously log to logfdile, if existing */
int fplog(FILE* const file, enum ddrlog_t logpre, const char * const fmt, ...)
{
	int ret = 0;
	va_list vl; 
	va_start(vl, fmt);
	if (file) {
		if (logpre) {
			if ((file == stdout || file == stderr) && !nocol)
				fprintf(file, "%s", ddrlogpre_c[logpre]);
			else
				fprintf(file, "%s", ddrlogpre[logpre]);
		}
		ret = vfprintf(file, fmt, vl);
	}
	va_end(vl);
	if (logfd) {
		if (logpre)
			fprintf(logfd, "%s", ddrlogpre[logpre]);
		va_start(vl, fmt);
		ret = vfprintf(logfd, fmt, vl);
		va_end(vl);
	}
	scrollup = 0;
	return ret;
}

/** Write to file and simultaneously log to logfdile, if existing */
int vfplog(FILE* const file, enum ddrlog_t logpre, const char* const prefix, const char * const fmt, va_list va)
{
	int ret = 0;
	va_list v2;
#ifdef va_copy
       	va_copy(v2, va);
#else
	v2 = va;
#endif
	if (file) {
		if (logpre) {
			if ((file == stdout || file == stderr) && !nocol)
				fprintf(file, "%s", ddrlogpre_c[logpre]);
			else
				fprintf(file, "%s", ddrlogpre[logpre]);
			fprintf(file, "%s", prefix);
		}
		ret = vfprintf(file, fmt, va);
	}
	if (logfd) {
		if (logpre) {
			fprintf(logfd, "%s", ddrlogpre[logpre]);
			fprintf(logfd, "%s", prefix);
		}
		ret = vfprintf(logfd, fmt, v2);
	}
	scrollup = 0;
	return ret;
}


/** Plugin infrastructure */
unsigned int plug_max_slack_pre = 0;
int plug_max_neg_slack_pre = 0;
unsigned int plug_max_slack_post = 0;
int plug_max_neg_slack_post = 0;
int plug_first_lenchg = 9999;
int plug_last_lenchg = -1;
int plug_first_chg = 9999;
int plug_last_chg = -1;
unsigned int plug_max_req_align = 0;
char plug_not_sparse = 0;
char plug_unsparse = 0;
char plug_output_chg = 0;
char plugin_help = 0;
char plug_no_seek = 0;
char no_input = 0;
char no_output = 0;

char plugins_loaded = 0;
char plugins_opened = 0;
LISTDECL(ddr_plugin_t);
LISTTYPE(ddr_plugin_t) *ddr_plugins;

void call_plugins_open(opt_t *op, fstate_t *fst)
{
	unsigned int slk_pre = 0, slk_post = 0;
	/* Do iterate over list */
	LISTTYPE(ddr_plugin_t) *plug;
	LISTFOREACH(ddr_plugins, plug) {
		if (LISTDATA(plug).open_callback) {
			int spre  = LISTDATA(plug).slack_pre ;
			int spost = LISTDATA(plug).slack_post;
			slk_pre  += spre  >= 0? spre : -spre *((op->softbs+15)/16);
			slk_post += spost >= 0? spost: -spost*((op->softbs+15)/16);
			/*
			fplog(stderr, INFO, "Pre %i Post %i TPre %i TPost %i\n",
				spre, spost, slk_pre, slk_post);
			 */
			int err = LISTDATA(plug).open_callback(op, (plugins_opened > plug_first_lenchg? 1: 0),
								   (plugins_opened < plug_last_lenchg ? 1: 0),
								   (plugins_opened > plug_first_chg? 1: 0),
								   (plugins_opened < plug_last_chg ? 1: 0),
						plug_max_slack_pre-slk_pre, plug_max_slack_post-slk_post,
						fst, &LISTDATA(plug).state);
			if (err < 0) {
				fplog(stderr, WARN, "Error initializing plugin %s(%i): %s!\n",
					LISTDATA(plug).name, plugins_opened, strerror(-err));
				exit(13);
			} else if (err>0) {
				fst->ipos += err;
				fplog(stderr, WARN, "Plugin %s(%i) skipping %i bytes might break other plugins!\n",
					LISTDATA(plug).name, plugins_opened, err);
			}
		}
		++plugins_opened;
	}
	assert(slk_pre  == plug_max_slack_pre );
	assert(slk_post == plug_max_slack_post);
}

int call_plugins_close(opt_t *op, fstate_t *fst)
{
	int errs = 0;
	int seq = 0;
	if (!plugins_opened)
		return 0;
	LISTTYPE(ddr_plugin_t) *plug;
	LISTFOREACH(ddr_plugins, plug) {
		if (LISTDATA(plug).close_callback) {
			int err = LISTDATA(plug).close_callback(fst->opos, &LISTDATA(plug).state);
			if (err) {
				fplog(stderr, WARN, "Plugin %s(%i) reported error on close: %s!\n",
					LISTDATA(plug).name, seq, strerror(-err));
				++errs;
			}
		}
		++seq;
		--plugins_opened;
	}
	return errs;
}

/** Call the plugin block processing chain ...
 *  Each block callback can analyze the buffer, modify it, change the number of bytes to be written
 *  and request to be called again (without new input). The latter may help with error handling
 *  or draining buffers if they fill up. eof will be cleared on plugins after a recall has been
 *  requested.
 *  We are also passing the fstate struct, allowing a wide range of manipulations (use with care!)
 */
unsigned char* call_plugins_block(unsigned char *bf, int *towr, int eof, int *skip, opt_t *op, fstate_t *fst)
{
	if (!plugins_opened)
		return bf;
	int recall = -1;
	int seq = 0;
	LISTTYPE(ddr_plugin_t) *plug;
	LISTFOREACH(ddr_plugins, plug) {
		ddr_plugin_t *plugp = &LISTDATA(plug);
		if (plugp->block_callback && seq >= *skip) {
			int myrec = 0;
			bf = plugp->block_callback(fst, bf, towr, recall==-1? eof: 0, &myrec, &plugp->state);
			if (myrec && recall==-1)
				recall = seq;
			if (op->sparse && plugp->changes_output) {
				/* TODO: Do sparse detection again */
			}
		}
		++seq;
	}
	*skip = recall;
	return bf;
}

#ifdef USE_LIBDL
typedef void* VOIDP;
LISTDECL(VOIDP);
LISTTYPE(VOIDP) *ddr_plug_handles;

void unload_plugins();

ddr_plugin_t* insert_plugin(void* hdl, const char* nm, char* param, opt_t *op)
{
	LISTAPPEND(ddr_plug_handles, hdl, VOIDP);
	ddr_plugin_t *plug = (ddr_plugin_t*)dlsym(hdl, "ddr_plug");
	if (!plug) {
		fplog(stderr, WARN, "plugin %s loaded, but ddr_plug not found!\n", nm);
		return NULL;
	}
	if (!plug->name)
		plug->name = nm;
	
	/* Call init after dd_rescue-filled fields have been set; this allows the
	 * init_callback to adjust fiels like slack, align_needs, output_chg
	 * depending on parameters and options ... */
	if (param && !plug->init_callback) {
		fplog(stderr, FATAL, "Plugin %s has no init callback to consume passed param %s\n",
			nm, param);
		exit(13);
	}

	plug->logger = (plug_logger_t*)malloc(sizeof(plug_logger_t));
	snprintf(plug->logger->prefix, 24, "%s(%i): ", plug->name, plugins_loaded);
	plug->logger->vfplog = vfplog;

	if (plug->init_callback) {
		int ret = plug->init_callback(&plug->state, param, plugins_loaded, op);
		if (ret) {
			plugins_loaded++;
			LISTAPPEND(ddr_plugins, *plug, ddr_plugin_t);
			unload_plugins();
			exit(-ret);
		}
	}
	if (plug->slack_pre > 0)
		plug_max_slack_pre += plug->slack_pre;
	else if (plug->slack_pre < 0)
		plug_max_neg_slack_pre += plug->slack_pre;
	if (plug->slack_post > 0)
		plug_max_slack_post += plug->slack_post;
	else if (plug->slack_post < 0)
		plug_max_neg_slack_post += plug->slack_post;

	if (plug->needs_align > plug_max_req_align)
		plug_max_req_align = plug->needs_align;
	if (!plug->handles_sparse && !plug_unsparse)
		plug_not_sparse = 1;
	if (plug->makes_unsparse)
		plug_unsparse = 1;
	if (plug->changes_output)
		plug_output_chg = 1;
	if (param && !memcmp(param, "help", 4))
		plugin_help++;

	if (!plug->supports_seek)
		plug_no_seek++;

	if (plug->replaces_input)
		no_input++;
	if (plug->replaces_output)
		no_output++;

	LISTAPPEND(ddr_plugins, *plug, ddr_plugin_t);
	plugins_loaded++;
	return plug;
}

void load_plugins(char* plugs, opt_t *op)
{
	char* next;
	char path[256];
	int plugno = 0;
	int errs = 0;
	while (plugs) {
		next = strchr(plugs, ',');
		if (next)
			*next++ = 0;
		char* param = strchr(plugs, '=');
		if (param)
			*param++ = 0;
		snprintf(path, 255, "libddr_%s.so", plugs);
		//errno = ENOENT;
		void* hdl = dlopen(path, RTLD_NOW);
		/* Allow full name (with absolute path if wanted) */
		if (!hdl) {
			/* Second attempt: Try with name passed */
			hdl = dlopen(plugs, RTLD_NOW);
			/* Extract plugin name */
			if (hdl) {
				char* ptr = strrchr(plugs, '_');
				if (ptr) {
					char* ptr2 = strchr(ptr+1, '.');
					if (ptr2) {
						*ptr2 = 0;
						plugs = ptr+1;
					}
				}
			}
		}
		if (!hdl) {
			fplog(stderr, FATAL, "Could not load plugin %s (%s)\n", 
				plugs, dlerror());
			++errs;
		} else {
			ddr_plugin_t *plug = insert_plugin(hdl, plugs, param, op);
			if (!plug) {
				++errs;
				continue;
			}
			if (plug->changes_output_len)
				plug_last_lenchg = plugno;
			if (plug_first_lenchg == 9999 && plug->changes_output_len)
				plug_first_lenchg = plugno;
			if (plug->changes_output)
				plug_last_chg = plugno;
			if (plug_first_chg == 9999 && plug->changes_output)
				plug_first_chg = plugno;
			++plugno;
		}
		plugs = next;
	}
	if (errs) {
		unload_plugins();
		exit(13);
	}
}

void unload_plugins()
{
	if (!plugins_loaded)
		return;
	LISTTYPE(VOIDP) *plug_hdl;
	LISTTYPE(ddr_plugin_t) *ddrplug;
	/* FIXME: Freeing in reverse order would be better ... */
	LISTFOREACH(ddr_plugins, ddrplug) {
		ddr_plugin_t *plugp = &LISTDATA(ddrplug);
		if (plugp->release_callback)
			plugp->release_callback(&plugp->state);
		free(plugp->logger);
	}
	LISTFOREACH(ddr_plug_handles, plug_hdl) 
		dlclose(LISTDATA(plug_hdl));
	LISTTREEDEL(ddr_plug_handles, VOIDP);
	LISTTREEDEL(ddr_plugins, ddr_plugin_t);
}
#else
static void unload_plugins() {};
#endif

#if defined(HAVE_POSIX_FADVISE) && !defined(HAVE_POSIX_FADVISE64)
#define posix_fadvise64 posix_fadvise
#endif
#ifdef HAVE_POSIX_FADVISE
static inline void fadvise(char after, opt_t *op, fstate_t *fst, progress_t *prg)
{
	if (!op->reverse) {
		if (after) 
			posix_fadvise64(fst->ides, op->init_ipos, prg->xfer, POSIX_FADV_NOREUSE);
		else 
			posix_fadvise64(fst->ides, op->init_ipos, fst->estxfer, POSIX_FADV_SEQUENTIAL);
	}
}
#else
static inline void fadvise(char after, opt_t *op, fstate_t *fst, progress_t *prg)
{}
#endif


static int check_identical(const char* const in, const char* const on)
{
	int err = 0;
	struct STAT64 istat, ostat;
	errno = 0;
	if (strcmp(in, on) == 0) 
		return 1;
	err -= STAT64(in, &istat);
	if (err)
	       	return 0;
	err -= STAT64(on, &ostat);
	errno = 0;
	if (!err &&
	    istat.st_ino == ostat.st_ino &&
	    istat.st_dev == ostat.st_dev)
		return 1;
	return 0;
}

static int openfile(const char* const fname, const int flags)
{
	int fdes;
	if (!strcmp(fname, "-")) {
		if (flags & O_WRONLY || flags & O_RDWR)
			fdes = 1;  /* stdout */
		else 
			fdes = 0;  /* stdin */
	} else
		fdes = open64(fname, flags, 0640);
	if (fdes == -1) {
		fplog(stderr, FATAL, "open \"%s\" failed: %s\n",
			fname, strerror(errno));
		cleanup(1); exit(17);
	}
	return fdes;
}

/** Checks whether file is seekable */
static void check_seekable(const int fd, char *ischr, const char* msg)
{
	errno = 0;
	if (!*ischr && lseek64(fd, (loff_t)0, SEEK_SET) != 0) {
		if (msg) {
			fplog(stderr, WARN, "file %s is not seekable!\n", msg);
			fplog(stderr, WARN, "%s\n", strerror(errno));
		}
		*ischr = 1;
	}
	errno = 0;
}

/** Calc position in graph */
static inline int gpos(loff_t off, loff_t len)
{
	static const int glen = 40; //strlen(graph) - 2;
	return 1+(glen*off/len);
}

/** Prepare graph */
static char *sgraph = ":.........................................:";
static void preparegraph(opt_t *op, fstate_t *fst, loff_t ifin)
{
	if (!fst->estxfer)
		return;
	graph = strdup(sgraph);
	if ((op->reverse && fst->fin_ipos > 0) || (!op->reverse && op->init_ipos > 0))
		graph[gpos(0, fst->estxfer)-1] = '=';
	else
		graph[gpos(0, fst->estxfer)-1] = '>';
	loff_t finpos = fst->fin_ipos? fst->fin_ipos: fst->fin_opos;
	if ((op->reverse && op->init_ipos < ifin) || (!op->reverse && finpos < ifin))
		graph[gpos(fst->estxfer, fst->estxfer)+1] = '=';
	else
		graph[gpos(fst->estxfer, fst->estxfer)+1] = '<';
}

void updgraph(int err, fstate_t *fst, dpopt_t *dop, opt_t *op)
{
	if (!graph)
		return;
	const loff_t base = op->reverse? fst->fin_ipos: op->init_ipos;
	loff_t relpos = fst->ipos - base;
	if (relpos < 0) {
		graph[0] = '!';
		return;
	}
	if (relpos > fst->estxfer) {
		graph[42] = '!';
		return;
	}
	const int off = gpos(relpos, fst->estxfer);
	if (graph[off] == 'x')
		return;
	if (err)
		graph[off] = 'x';
	else {
		if (dop->bsim715_2ndpass)
			graph[off] = '.';
		else
			graph[off] = '-';
	}
}

#if 1
loff_t file_len(int fd, char *ischr, char* isblk, const char* nm, char quiet, char sparse)
{
	struct STAT64 stbuf;
	if (*ischr)
		return 0;
	if (FSTAT64(fd, &stbuf))
		return 0;
	/* Note: S_ISLNK not relevant, we opened fd w/o NOLINK */
	/* Char device or pipe */
	if (S_ISCHR(stbuf.st_mode) || S_ISFIFO(stbuf.st_mode) || S_ISSOCK(stbuf.st_mode)) {
		*ischr = 1;
		return 0;
	}
	/* Block device */
	if (S_ISBLK(stbuf.st_mode)) {
		*isblk = 1;
		/* Do magic to figure size of block dev */
		loff_t l, p = lseek64(fd, 0, SEEK_CUR);
		if (p == -1)
			return 0;
		l = lseek64(fd, 0, SEEK_END) /* + 1 */;
		lseek64(fd, p, SEEK_SET);
		return l;
	}
	/* Regular file */
	loff_t diff;
	if (!stbuf.st_size)
		return 0;
	diff = stbuf.st_size - stbuf.st_blocks*512;
	if (!quiet && diff >= 4096 && (float)diff/stbuf.st_size > 0.05)
	       fplog(stderr, INFO, "%s is sparse (%i%%) %s\n", nm, (int)(100.0*diff/stbuf.st_size), (sparse? "": ", consider -a"));
	return stbuf.st_size;
}
#endif

static inline loff_t min3_nonnull(loff_t i1, loff_t i2, loff_t i3)
{
	loff_t min = i1;
	if (i2 && (i2 < min || !min))
		min = i2;
	if (i3 && (i3 < min || !min))
		min = i3;
	return min;
}

/** Tries to determine size of files */
void input_length(opt_t *op, fstate_t *fst)
{
	char iblk = 0;
	loff_t ilen, olen, ofree = 0;
	ilen = file_len(fst->ides, &fst->i_chr, &iblk, op->iname, op->quiet, op->sparse);
	olen = file_len(fst->odes, &fst->o_chr, &fst->o_blk, op->oname, op->quiet, 1);
	/* If we have a valid len already, things are easy ... */
	if (ilen) {
		if (op->reverse) {
			fst->estxfer = min3_nonnull(op->init_ipos, olen? op->init_opos: 0, op->maxxfer);
			fst->fin_ipos = op->init_ipos? op->init_ipos - fst->estxfer: 0;
			fst->fin_opos = olen && op->init_opos? op->init_opos - fst->estxfer: 0;
		} else {
			fst->estxfer = min3_nonnull(ilen-op->init_ipos, olen&&op->noextend? olen-op->init_opos: 0, op->maxxfer);
			fst->fin_ipos = op->init_ipos + fst->estxfer;
			fst->fin_opos = olen? op->init_opos + fst->estxfer: 0;
		}
		assert(fst->estxfer > 0);
		preparegraph(op, fst, ilen);
		if (!op->quiet)
			fplog(stderr, INFO, "expect to copy %skiB from %s\n",
				fmt_kiB(fst->estxfer, !nocol), op->iname);
		return;
	}
	/* Could not determine transfer len from input file, try output file */
#ifdef HAVE_SYS_STATVFS_H
	/* How much space do we have on output FS? */
	if (!op->noextend && !fst->o_blk && !fst->o_chr) {
		struct statvfs svfs;
		if (!fstatvfs(fst->odes, &svfs)) {
			/* FIXME: Should be CAP_SYS_RESOURCE check? */
			uid_t uid = geteuid();
			ofree = (uid? svfs.f_bavail: svfs.f_bfree) * svfs.f_bsize;
			if (olen) {
				loff_t add = svfs.f_bsize-1 + olen;
				add -= add%svfs.f_bsize;
				if (op->verbose)
					fplog(stderr, INFO, "free space %" LL "i + %" LL "i\n", ofree, add);
				ofree += add - (op->reverse? 0: op->init_opos);
			}
		} else
			fplog(stderr, WARN, "statvfs call failed: %s\n", strerror(errno));
	}
#endif
	if (olen) {
		if (op->reverse) {
			fst->estxfer = min3_nonnull(op->init_opos, op->maxxfer, ofree);
			fst->fin_opos = op->init_opos? op->init_opos - fst->estxfer: 0;
		} else {
			fst->estxfer = min3_nonnull(op->noextend? olen-op->init_opos: 0, op->maxxfer, ofree);
			fst->fin_opos = op->init_opos + fst->estxfer;
		}
	}
	if (!fst->estxfer)
		fst->estxfer = min3_nonnull(op->maxxfer, ofree, 0);
	assert(fst->estxfer >= 0);
	if (fst->estxfer) {
		preparegraph(op, fst, olen);
		if (!op->quiet)
			fplog(stderr, INFO, "expect to copy %skiB from %s\n",
				fmt_kiB(fst->estxfer, !nocol), op->iname);
	}
}

int output_length(opt_t *op, fstate_t *fst)
{
	struct STAT64 stbuf;
	if (fst->o_chr)
		return -1;
	if (FSTAT64(fst->odes, &stbuf))
		return -1;
	if (S_ISLNK(stbuf.st_mode)) {
		// TODO: Use readlink and follow?
		fst->o_lnk = 1;
		return -1;
	}
	if (S_ISCHR(stbuf.st_mode)) {
		fst->o_chr = 1;
		return -1;
	}
	if (S_ISBLK(stbuf.st_mode)) {
		/* Do magic to figure size of block dev */
		loff_t p = lseek64(fst->odes, 0, SEEK_CUR);
		fst->o_blk = 1;
		if (p == -1)
			return -1;
		fst->fin_opos = lseek64(fst->odes, 0, SEEK_END) + 1;
		lseek64(fst->odes, p, SEEK_SET);
	} else {
		loff_t diff;
		fst->fin_opos = stbuf.st_size;
		if (!fst->fin_opos)
			return -1;
		diff = fst->fin_opos - stbuf.st_blocks*512;
		if (diff >= 4096 && (float)diff/fst->fin_opos > 0.05 && !op->quiet)
		       fplog(stderr, INFO, "%s is sparse (%i%%) %s\n", op->oname, (int)(100.0*diff/fst->fin_opos), (op->sparse? "": ", consider -a"));
	}
	if (!fst->fin_opos)
		return -1;
	if (op->extend) {
		if (op->reverse) {
			fplog(stderr, INFO, "Advance output pos by ilen %i for reverse extend ...\n", fst->fin_ipos);
			op->init_opos += fst->fin_ipos;
		}
		return 0;
	}
	if (!op->reverse) {
		loff_t newmax = fst->fin_opos - op->init_opos;
		if (newmax < 0) {
			fplog(stderr, FATAL, "output position is beyond end of file but -M specified!\n");
			cleanup(1); exit(19);
		}			
		if (!op->maxxfer || op->maxxfer > newmax) {
			op->maxxfer = newmax;
			if (!op->quiet)
				fplog(stderr, INFO, "limit max xfer to %skiB\n",
					fmt_kiB(op->maxxfer, !nocol));
		}
	} else if (op->init_opos > fst->fin_opos) {
		fplog(stderr, WARN, "change output position %skiB to endpos %skiB due to -M\n",
			fmt_kiB(op->init_opos, !nocol), fmt_kiB(fst->fin_opos, !nocol));
		op->init_opos = fst->fin_opos;
	}
	return 0;
}


static void sparse_output_warn(opt_t *op, fstate_t *fst)
{
	struct STAT64 stbuf;
	loff_t eff_opos;
	if (fst->o_chr)
		return;
	if (FSTAT64(fst->odes, &stbuf))
		return;
	if (S_ISCHR(stbuf.st_mode)) {
		fst->o_chr = 1;
		return;
	}
	if (S_ISBLK(stbuf.st_mode)) {
		if (op->sparse || !op->nosparse)
			fplog(stderr, WARN, "%s is a block device; -a not recommended; -A recommended\n", op->oname);
		return;
	}
	eff_opos = (op->init_opos == (loff_t)-INT_MAX? op->init_ipos: op->init_opos);
	if (op->sparse && (eff_opos < stbuf.st_size))
		fplog(stderr, WARN, "write into %s (@%sk/%sk): sparse not recommended\n", 
				op->oname, fmt_kiB(eff_opos, !nocol), fmt_kiB(stbuf.st_size, !nocol));
}

#if defined(HAVE_FALLOCATE64) || defined(HAVE_LIBFALLOCATE)

#ifdef USE_LIBDL
static void* load_libfallocate()
{
	if (!libfalloc)
		libfalloc = dlopen("libfallocate.so.0", RTLD_NOW);
	if (!libfalloc)
		return 0;
	else
		return dlsym(libfalloc, "linux_fallocate64");
}
#endif

static void do_fallocate(int fd, const char* onm, opt_t *op, fstate_t *fst)
{
	struct STAT64 stbuf;
	loff_t to_falloc, alloced;
	int rc = 0;
	if (!fst->estxfer)
		return;
	if (FSTAT64(fd, &stbuf))
		return;
	if (!S_ISREG(stbuf.st_mode))
		return;
	alloced = stbuf.st_blocks*512 - op->init_opos;
	to_falloc = fst->estxfer - (alloced < 0 ? 0 : alloced);
	if (to_falloc <= 0)
		return;
#ifdef USE_LIBDL
	typedef int (*_l_f_t) (int fd, int mode, __off64_t start, __off64_t len);
	//int (*_linux_fallocate64)(int fd, int mode, __off64_t start, __off64_t len);
	_l_f_t _linux_fallocate64 = (_l_f_t)load_libfallocate();
	if (_linux_fallocate64)
		rc = _linux_fallocate64(fd, FALLOC_FL_KEEP_SIZE,
				op->init_opos, to_falloc);
#ifdef HAVE_FALLOCATE64
	else
		rc = fallocate64(fd, 1, op->init_opos, to_falloc);
#endif
#elif defined(HAVE_LIBFALLOCATE)
	rc = linux_fallocate64(fd, FALLOC_FL_KEEP_SIZE, 
			      op->init_opos, to_falloc);
#else /* HAVE_FALLOCATE64 */
	rc = fallocate64(fd, 1, op->init_opos, to_falloc);
#endif
	if (rc)
	       fplog(stderr, WARN, "fallocate %s (%sk, %sk) failed: %s\n",
		      onm, fmt_kiB(op->init_opos, !nocol), fmt_kiB(to_falloc, !nocol), strerror(errno));
}
#endif

float floatrate4  = 0.0;
float floatrate32 = 0.0;
void doprint(FILE* const file, const unsigned int bs, const clock_t cl, 
	     const float t1, const float t2, const int sync,
	     opt_t *op, fstate_t *fst, progress_t *prg, dpopt_t *dop)
{
	float avgrate = (float)prg->xfer/t1;
	float currate = (float)(prg->xfer-prg->lxfer)/t2;
	const char *bold = BOLD, *norm = NORM;
	if (!floatrate4) {
		floatrate4  = currate;
		floatrate32 = currate;
	} else {
		floatrate4  = (floatrate4 * 3 + currate)/ 4;
		floatrate32 = (floatrate32*31 + currate)/32;
	}
	if (nocol || (file != stderr && file != stdout)) {
		bold = ""; norm = "";
	}
	fprintf(file, DDR_INFO "ipos:%sk, opos:%sk, xferd:%sk\n",
		fmt_int(10, 1, 1024, fst->ipos, bold, norm, 1),
		fmt_int(10, 1, 1024, fst->opos, bold, norm, 1),
		fmt_int(10, 1, 1024, prg->xfer, bold, norm, 1));
	fprintf(file, "             %s  %s  errs:%7i, errxfer:%sk, succxfer:%sk\n",
		(op->reverse? "-": " "), (bs==op->hardbs? "*": " "), fst->nrerr, 
		fmt_int(10, 1, 1024, prg->fxfer, bold, norm, 1),
		fmt_int(10, 1, 1024, prg->sxfer, bold, norm, 1));
	if (sync || (file != stdin && file != stdout) )
		fprintf(file, "             +curr.rate:%skB/s, avg.rate:%skB/s, avg.load:%s%%\n",
			fmt_int(9, 0, 1024, floatrate4, bold, norm, 1),
			fmt_int(9, 0, 1024, avgrate, bold, norm, 1),
			fmt_int(3, 1, 10, (cl-startclock)/(t1*(CLOCKS_PER_SEC/1000)), bold, norm, 1));
	else
		fprintf(file, "             -curr.rate:%skB/s, avg.rate:%skB/s, avg.load:%s%%\n",
			nineright, 
			fmt_int(9, 0, 1024, avgrate, bold, norm, 1),
			fmt_int(3, 1, 10, (cl-startclock)/(t1*(CLOCKS_PER_SEC/1000)), bold, norm, 1));
	if (fst->estxfer && avgrate > 0) {
		int sec;
		if (in_report)
			sec = 0.5 + t1;
		else
			sec = 0.5 + 2*(fst->estxfer-prg->xfer)/(avgrate+floatrate32);
		int hour = sec / 3600;
		int min = (sec % 3600) / 60;
		sec = sec % 60;
		updgraph(0, fst, dop, op);
		fprintf(file, "             %s %3i%%  %s: %2i:%02i:%02i \n",
			graph? graph: sgraph, (int)(100*prg->xfer/fst->estxfer),
			(in_report? "TOT": "ETA"), hour, min, sec);
		scrollup = fourup;
	} else
		scrollup = threeup;
}

void printstatus(FILE* const file1, FILE* const file2,
		 const int bs, const int sync,
		 opt_t *op, fstate_t *fst, progress_t *prg,
		 dpopt_t *dop)
{
	float t1, t2; 
	clock_t cl;
	static int einvalwarn = 0;

	if (sync) {
		int err = fsync(fst->odes);
		if (err && (errno != EINVAL || !einvalwarn) &&!fst->o_chr) {
			fplog(stderr, WARN, "sync %s (%sskiB): %s!  \n",
			      op->oname, fmt_kiB(fst->ipos, !nocol), strerror(errno));
			++einvalwarn;
		}
		errno = 0;
	}

	gettimeofday(&currenttime, NULL);
	t1 = difftimetv(&currenttime, &starttime);
	t2 = difftimetv(&currenttime, &lasttime);
	cl = clock();

#if 0
	if (t1 == 0.0)
		t1 = 0.0001;
	if (t2 == 0.0)
		t2 = 0.0001;
#endif
	if (op->maxkbs && t1 && t2) {
		static unsigned w1 =0, w2 = 0, w3 = 0;
		static float t1w = 0.0, t2w = 0.0;
		/* Avoid global rate above limit */
		float c1rate = prg->xfer/(1024.0*t1);
		/* Avoid local rate above twice the limit */
		float c2rate = (prg->xfer-prg->lxfer)/(2048.0*t2);
		if (!in_report && (c1rate > op->maxkbs || c2rate > op->maxkbs)) {
			struct timeval wtime;
			memcpy(&wtime, &currenttime, sizeof(wtime));
			int m1sleep = 3*prg->xfer/(2*op->maxkbs) - t1*1536.0;
			int m2sleep = (prg->xfer-prg->lxfer)/(2*op->maxkbs) - t2*1024.0;
			int mssleep;
			if (m2sleep >= m1sleep) {
			       	++w3;
				mssleep = m2sleep;
			} else
				mssleep = m1sleep;
			/* Do not pause longer than 8.2s */
			if (mssleep > 8192)
				mssleep = 8192;
			//fprintf(stderr, "%04ims\r", mssleep); fflush(stderr);
			cpu_relax();
			if (mssleep >= 2) {
				struct timespec ts;
				++w1;
				if (op->verbose && scrollup)
					fprintf(stderr, "%s.\n", up);
				ts.tv_sec = mssleep / 1000;
				ts.tv_nsec = 1000*1000ULL*(mssleep%1000);
				nanosleep(&ts, NULL);
				gettimeofday(&currenttime, NULL);
				t1w += difftimetv(&currenttime, &wtime);
			} else {
				++w2;
				sched_yield();
				gettimeofday(&currenttime, NULL);
				t2w += difftimetv(&currenttime, &wtime);
			}
			t1 = difftimetv(&currenttime, &starttime);
			t2 = difftimetv(&currenttime, &lasttime);
			cl = clock();
		}
		if (in_report && op->verbose)
			fplog(stderr, INFO, "Sleep stats: %i(%.4f), %i(%.6f) - %i\n",
					w1, w1? t1w/w1: 0.0,
					w2, w2? t2w/w2: 0.0, w3);
	}
	/* Idea: Could save last not printed status and print on err */
	if (t2 < printint && !sync && !in_report) {
		if (fst->estxfer)
			updgraph(0, fst, dop, op);
		return;
	}

	if (scrollup) {
		if (file1 == stderr || file1 == stdout)
			fprintf(file1, "%s", scrollup);
		if (file2 == stderr || file2 == stdout)
			fprintf(file2, "%s", scrollup);
	}

	if (file1) 
		doprint(file1, bs, cl, t1, t2, sync, op, fst, prg, dop);
	if (file2)
		doprint(file2, bs, cl, t1, t2, sync, op, fst, prg, dop);
	if (1 || sync) {
		memcpy(&lasttime, &currenttime, sizeof(lasttime));
		prg->lxfer = prg->xfer;
	}
}

static void savebb(loff_t block, opt_t *op)
{
	FILE *bbfile;
	fplog(stderr, WARN, "Bad block reading %s: %s \n", 
			op->iname, fmt_int(0, 0, 1, block, (nocol? "": BOLD), (nocol? "": NORM), 1));
	if (op->bbname == NULL)
		return;
	bbfile = fopen(op->bbname, "a");
	fprintf(bbfile, "%s\n", fmt_int(0, 0, 1, block, "", "", 0));
	fclose(bbfile);
}

void printreport(opt_t *op, fstate_t *fst, progress_t *prg, dpopt_t *dop)
{
	/* report */
	FILE *report = (!op->quiet || fst->nrerr)? stderr: 0;
	in_report = 1;
	if (report) {
		fplog(report, INFO, "Summary for %s -> %s", op->iname, op->oname);
		LISTTYPE(ofile_t) *of;
		LISTFOREACH(ofiles, of)
			fplog(report, NOHDR, "; %s", LISTDATA(of).name);
		if (logfd > 0)
			fprintf(logfd, ":\n");
		fprintf(report, "\n");
		printstatus(report, logfd, 0, 1, op, fst, prg, dop);
		if (op->avoidwrite) 
			fplog(report, INFO, "Avoided %skiB of writes (performed %skiB)\n", 
				fmt_kiB(prg->axfer, !nocol), fmt_kiB(prg->sxfer-prg->axfer, !nocol));
	}
}

void _printreport()
{
	printreport(eptrs.opts, eptrs.fstate, eptrs.progress, eptrs.dpopts);
}

void exit_report(int rc, opt_t *op, fstate_t *fst, progress_t *prg, dpopt_t *dop)
{
	gettimeofday(&currenttime, NULL);
	printreport(op, fst, prg, dop);
	cleanup(0);
	fplog(stderr, FATAL, "Not completed fully successfully! \n");
	if (logfd)
		fclose(logfd);
	exit(rc);
}


int copyperm(int ifd, int ofd)
{
	int err; 
	mode_t fmode;
	struct stat stbuf;
	err = fstat(ifd, &stbuf);
	if (err)
		return err;
	fmode = stbuf.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID | S_ISGID | S_ISVTX);
	err = fchown(ofd, stbuf.st_uid, stbuf.st_gid);
	if (err)
		fmode &= ~(S_ISUID | S_ISGID);
	err += fchmod(ofd, fmode);
	return err;
}


/** Copy xattrs */
int copyxattr(const char* inm, const char* onm)
#ifdef HAVE_ATTR_XATTR_H
{
	char *attrs = NULL;
	ssize_t aln = listxattr(inm, NULL, 0);
	int copied = 0;
	if (aln <= 0)
		return 0;
	attrs = (char*)malloc(aln);
	if (!attrs) {
		fplog(stderr, WARN, "Can't allocate buffer of len %z for attr names\n", aln);
		return -1;
	}
	aln = listxattr(inm, attrs, aln);
	if (aln <= 0) {
		fplog(stderr, WARN, "Could not read attr list: %s\n", strerror(errno));
		free(attrs);
		return -1;
	}
	int offs;
	unsigned char* extrabuf = (unsigned char*)malloc(4096);
	int ebufall = 4096;
	for (offs = 0; offs < aln; offs += 1+strlen(attrs+offs)) {
		ssize_t itln = getxattr(inm, attrs+offs, NULL, 0);
		if (ebufall && itln > ebufall) {
			extrabuf = (unsigned char*)realloc(extrabuf, itln);
			ebufall = itln;
		}
		itln = getxattr(inm, attrs+offs, extrabuf, itln);
		if (itln <= 0) {
			fplog(stderr, WARN, "Could not read attr %s: %s\n", attrs+offs, strerror(errno));
			continue;
		}
		if (setxattr(onm, attrs+offs, extrabuf, itln, 0))
			fplog(stderr, WARN, "Could not write attr %s: %s\n", attrs+offs, strerror(errno));
		if (eptrs.opts->verbose)
			fplog(stderr, INFO, "Copied attr %s (%i bytes)\n", attrs+offs, itln);
		++copied;
	}
	if (ebufall)
		free(extrabuf);
	free(attrs);
	return copied;
}
#else
{
	return 0;
}
#endif

/** File time copy */
int copytimes(const char* inm, const char* onm)
{
	int err;
	struct stat stbuf;
	struct utimbuf utbuf;
	err = stat(inm, &stbuf);
	if (err)
		return err;
	utbuf.actime  = stbuf.st_atime;
	utbuf.modtime = stbuf.st_mtime;
	err = utime(onm, &utbuf);
	return err;
}

static int mayexpandfile(const char* onm, opt_t *op, fstate_t *fst)
{
	struct STAT64 st;
	loff_t maxopos = fst->opos;
	if (op->init_opos > fst->opos)
		maxopos = op->init_opos;
	if (STAT64(onm, &st))
		return -1;
	if (!S_ISREG(st.st_mode))
		return 0;
	if (st.st_size < maxopos || op->trunclast)
		return truncate(onm, maxopos);
	else 
		return 0;
}


void remove_and_trim(const char* onm, opt_t *op)
{
	int err = unlink(onm);
	if (err)
		fplog(stderr, WARN, "remove(%s) failed: %s\n",
			onm, strerror(errno));
#ifdef FITRIM
	loff_t trimmed = fstrim(onm, op->quiet);
	if (trimmed < 0) 
		fplog(stderr, WARN, "fstrim %s failed: %s%s\n", 
			onm, strerror(-trimmed), (-trimmed == EPERM? " (have root?)": ""));
	else
		fplog(stderr, INFO, "Trimmed %skiB \n", 
				fmt_int(0, 0, 1024, trimmed, (nocol? "": BOLD), (nocol? "": NORM), 1));
#endif
}

int sync_close(int fd, const char* nm, char chr, opt_t *op, fstate_t *fst)
{
	int rc, err = 0;
	if (fd != -1) {
		/* Make sure, the output file is expanded to the last (first) position
	 	 * FIXME: 0 byte writes do NOT expand file -- mayexpandfile() will
		 * take care of that. */
		if (!op->avoidwrite) 
			rc = pwrite(fd, fst->buf, 0, fst->opos);
		rc = fsync(fd);
		if (rc && !chr) {
			fplog(stderr, WARN, "fsync %s (%skiB): %s!\n",
			      nm, fmt_kiB(fst->opos, !nocol), strerror(errno));
			++err;
			errno = 0;
		}
		rc = close(fd); 
		if (rc) {
			fplog(stderr, WARN, "close %s (%skiB): %s!\n",
			      nm, fmt_kiB(fst->opos, !nocol), strerror(errno));
			++err;
		}
		rc = chr? 0: mayexpandfile(nm, op, fst);
		if (rc && (op->trunclast || op->sparse))
			fplog(stderr, WARN, "extend/truncate %s (%skiB): %s!\n",
			      nm, fmt_kiB(fst->opos, !nocol), strerror(errno));
	}
	return err;
}			 

#define ZFREE(ptr)	\
	do {		\
	  if (ptr)	\
	    free(ptr);	\
	  ptr = 0;	\
	} while(0)


ssize_t writeblock(int towrite, int *shouldwr, opt_t *op, fstate_t *fst,
		   progress_t *prg, dpopt_t *dop);
static void advancepos(const ssize_t rd, const ssize_t wr, const ssize_t rwr,
		       opt_t *op, fstate_t *fst, progress_t *prg);

int real_cleanup(opt_t *op, fstate_t *fst, progress_t *prg, 
		 dpopt_t *dop, dpstate_t *dst, char closelog)
{
	int rc, errs = 0;
	if (!op->dosplice && !dop->bsim715) {
		/* EOF notifiction */
		int fbytes = writeblock(0, &rc, op, fst, prg, dop);
		if (fbytes >= 0)
			advancepos(0, fbytes, fbytes, op, fst, prg);
		else
			errs++;
		/* And finalize */
		errs += call_plugins_close(op, fst);
	}
	errs += sync_close(fst->odes, op->oname, fst->o_chr, op, fst);
	if (fst->ides != -1) {
		rc = close(fst->ides);
		if (rc) {
			fplog(stderr, WARN, "close %s (%skiB): %s!\n",
			      op->iname, fmt_kiB(fst->ipos, !nocol), strerror(errno));
			++errs;
		}
	}
	LISTTYPE(ofile_t) *of;
	LISTFOREACH(ofiles, of) {
		ofile_t *oft = &(LISTDATA(of));
		rc = sync_close(oft->fd, oft->name, oft->cdev, op, fst);
	}
	ZFREE(fst->origbuf2);
	ZFREE(graph);
	if (op->preserve) {
		copyxattr(op->iname, op->oname);
		copytimes(op->iname, op->oname);
	}
	if (op->rmvtrim)
		remove_and_trim(op->oname, op);
	LISTFOREACH(ofiles, of) {
		if (op->preserve) {
			copyxattr(op->iname, LISTDATA(of).name);
			copytimes(op->iname, LISTDATA(of).name);
		}
		if (op->rmvtrim)
			remove_and_trim(LISTDATA(of).name, op);
	}
	ZFREE(fst->origbuf);
	if (dst->prng_state2) {
		frandom_release(dst->prng_state2);
		dst->prng_state2 = 0;
	}
	if (dst->prng_state) {
		frandom_release(dst->prng_state);
		dst->prng_state = 0;
	}
	LISTTREEDEL(ofiles, ofile_t);
	LISTTYPE(charp) *onl;
	LISTFOREACH(freenames, onl) {
		free(LISTDATA(onl));
		LISTDATA(onl) = 0;
	}
	LISTTREEDEL(freenames, charp);
	LISTTREEDEL(read_faults, fault_in_t);
	LISTTREEDEL(write_faults, fault_in_t);
#if USE_LIBDL
	if (libfalloc)
		dlclose(libfalloc);
	unload_plugins();
#endif
	if (logfd && closelog) {
		fclose(logfd);
		logfd = 0;
	}
	return errs;
}

int cleanup(char closelog)
{
	return real_cleanup(eptrs.opts, eptrs.fstate, eptrs.progress, eptrs.dpopts, eptrs.dpstate, closelog);
}

int l2(unsigned int l)
{
	int r = 0;
	int allset = l&1 ? 1: 0;
	while(l >>= 1) {
		if (!(l&1))
			allset = 0;
		++r;
	}
	//printf("%i\n", r+allset);
	return r+allset;
}

ssize_t fill_rand(void *bf, size_t ln)
{
	const char rand_bits = l2(RAND_MAX);
	const char rand_bytes = rand_bits/8;
	unsigned int i;
	for (i = 0; i < ln; i+= rand_bytes) {
		unsigned int r = rand();
		// Use extra bits ...
		if (rand_bits > 16)
			r ^= r>>16;
		memcpy(bf+i, &r, i+rand_bytes>ln? ln-i: rand_bytes);
	}
	return ln;
}

ssize_t fill_rand_old(void *bf, size_t ln)
{
	unsigned int i;
	int* rbuf = (int*)bf;
	for (i = 0; i < ln/sizeof(int); ++i)
		rbuf[i] = rand();
	return ln;
}

/** is the block zero ? */
static ssize_t blockiszero(const unsigned char* blk, const size_t ln,
			   opt_t *op, repeat_t *rep)
{
	if (op->i_repeat && rep->i_rep_zero)
		return rep->i_rep_zero;
	if (!ln || *blk) 
		rep->i_rep_zero = 0;
	else
		rep->i_rep_zero = find_nonzero(blk, ln);
	return rep->i_rep_zero;
}

#if 0
/* TODO: Use this in call_plugins_block() and in dowrite_sparse() */
#define MAX(a,b) ((a)>(b)?(a):(b))
static ssize_t find_zero_blk(const unsigned char* blk, const size_t ln,
			     int *offs, opt_t *op, repeat_t *rep)
{
	*offs = 0;
	int maxoff = 0;
	ssize_t zlen = blockiszero(blk, ln, op, rep);
	if (zlen == ln)
		return ln;
	ssize_t maxzlen = zlen;
	for (*offs = MAX(pagesize, pagesize*(zlen/pagesize)); *offs < ln; *offs += pagesize) {
		zlen = blockiszero(blk+*offs, ln-*offs, op, rep);
		if (zlen > maxzlen) {
			maxzlen = zlen;
			maxoff = *offs;
			/* opt */
			if (zlen == ln-*offs)
				return zlen;
			if (zlen > pagesize)
				*offs += pagesize*(zlen/pagesize);
		}
	}
	if (maxzlen >= pagesize) {
		*offs = maxoff;
		return maxzlen;
	}
	return 0;
}
#endif

int in_fault_list(LISTTYPE(fault_in_t) *faults, off_t off1, off_t off2)
{
	if (!faults)
		return 0;
	int hit = 0;
	LISTTYPE(fault_in_t) *faultiter;
	LISTFOREACH(faults, faultiter) {
		fault_in_t *fault = &LISTDATA(faultiter);
#if 0
		fplog(stderr, DEBUG, "Match [%li,%li[ against %li-%i/%i: ",
			(long)off1, (long)off2,
			(long)fault->off, (long)fault->off2, fault->rep);
#endif
		if (!fault->rep || off1 >= fault->off2 || off2 <= fault->off)
			continue;
		/* We have a hit! */
		if (fault->rep < 0) {
			if (!++fault->rep)
				fault->rep = 15;
			continue;
		} else {
			--fault->rep;
			if (!hit)
				hit = 1+(fault->off>off1? fault->off-off1: 0);
		}
	}
#if 0
	fplog(stderr, NOHDR, "%i%s\n", hit, (hit?"-1":""));
#endif
	return hit;
}

static inline ssize_t mypread(int fd, void* bf, size_t sz, loff_t off,
			      opt_t *op, fstate_t *fst, repeat_t *rep, 
			      dpopt_t *dop, dpstate_t *dst)
{
	/* TODO: Handle plugin input here ... */
	/* Handle fault injection here */
	int fault = in_fault_list(read_faults, off/op->hardbs,
				  (off+(loff_t)sz+(loff_t)(op->hardbs-1))/op->hardbs);
	if (fault) {
		if (op->verbose)
			fplog(stderr, DEBUG, "Inject read fault @ %li (rd %iblk @ %li*%i)\n",
				(long)((fault-1)*op->hardbs+off), (sz+op->hardbs-1)/op->hardbs,
				off/op->hardbs, op->hardbs);
		if (!op->reverse && fst->fin_ipos && fst->ipos == fst->fin_ipos) {
			/* EOF, we can't proceed any further */
			errno = 0;
			return 0;
		} else {
			errno = EIO;
			return -1;
		}
		// Cloud read and return (fault-1)*op->hardbs bytes ...
	}
	/* Optimization for repeated read from same input */
	if (op->i_repeat) {
		if (rep->i_rep_init)
			return sz;
		else
			rep->i_rep_init = 1;
	}
	/* Random numbers */
	if (dop->prng_libc)
		return fill_rand(bf, sz);
	if (dop->prng_frnd) {
		if (!dop->bsim715_2ndpass)
			return frandom_bytes(dst->prng_state, (unsigned char*) bf, sz);
		else
			return frandom_bytes_inv(dst->prng_state, (unsigned char*) bf, sz);
	}
	/* We won't make progress beyond EOF */
	ssize_t rd;
	/* OK, regular read ... */
	if (fst->i_chr)
		rd = read(fd, bf, sz);
	else
		rd = pread64(fd, bf, sz, off);
	if (rd == -1 && !op->reverse && fst->fin_ipos && fst->ipos == fst->fin_ipos) {
		errno = 0;
		return 0;
	} else
		return rd;
}

static inline ssize_t mypwrite(int fd, void* bf, size_t sz, loff_t off,
			       opt_t *op, fstate_t *fst, progress_t *prg)
{
	/* TODO: Handle plugin output here ... */
	/* Handle fault injection here */
	int fault = in_fault_list(write_faults, off/op->hardbs,
				  (off+(loff_t)sz+(loff_t)(op->hardbs-1))/op->hardbs);
	if (fault) {
		if (op->verbose)
			fplog(stderr, DEBUG, "Inject write fault @ %li (wr %iblk @ %li*%i)\n",
				(long)((fault-1)*op->hardbs+off), (sz+op->hardbs-1)/op->hardbs,
				off/op->hardbs, op->hardbs);
		errno = EIO;
		return -1;
		// Cloud write and return (fault-1)*op->hardbs bytes ...
	}
	/* Continue with real writes */
	if (fst->o_chr) {
		if (!op->avoidnull)
			return write(fd, bf, sz);
		else {
			prg->axfer += sz;
			return sz;
		}
	} else {
		if (op->avoidwrite) {
			ssize_t ln = pread64(fd, fst->buf2, sz, off);
			if (ln < (ssize_t)sz)
				return pwrite64(fd, bf, sz, off);
			if (memcmp(bf, fst->buf2, ln))
				return pwrite64(fd, bf, sz, off);
			else {
				prg->axfer += ln;
				return ln;
			}
		} else
			return pwrite64(fd, bf, sz, off);
	}
}


ssize_t readblock(const int toread,
		  opt_t *op, fstate_t *fst, repeat_t *rep,
		  dpopt_t *dop, dpstate_t *dst)
{
	ssize_t err, rd = 0;
	//errno = 0; /* should not be necessary */
	do {
		rd += (err = mypread(fst->ides, fst->buf+rd, toread-rd, fst->ipos+rd-op->reverse*toread, op, fst, rep, dop, dst));
		if (err == -1) 
			rd++;
	} while ((err == -1 && (errno == EINTR || errno == EAGAIN))
		  || (rd < toread && err > 0 && errno == 0));
	//if (rd < toread) memset (fst->buf+rd, 0, toread-rd);
	return (/*err == -1? err:*/ rd);
}

/* write a block from fst->buf to fst->odes at fst->opos
 * also writes to secondary output files
 * The plugin chain will be called.
 * return number of written bytes OR negative errno */
ssize_t writeblock(int towrite, int* shouldwrite,
		   opt_t *op, fstate_t *fst, progress_t *prg, dpopt_t *dop)
{
	ssize_t err, totwr = 0;
	int lasterr = 0;
	int eof = towrite? 0: 1;
	int adv_ipos = 0, adv_opos = 0;
	int prev_tow;
	int redo = -1;
	unsigned char* wbuf;
	*shouldwrite = 0;
	do {
		char retry = fst->o_chr;
		prev_tow = towrite;
		/* Plugins can indicate that they could only process a part of the
		 * input this time by setting redo != -1.
		 * If so, we advance ipos by what we fed to the plugins, opos by
		 * what we actually received back and wrote.
		 * This will be recorded and UNDONE after we are done and redo is
		 * back to -1.
		 * This is a hack to ensure that plugins have the illusion of the
		 * right position in ipos/opos.
		 */
	       	wbuf = call_plugins_block(fst->buf, &towrite, eof, &redo, op, fst);
		/* Move ipos already ... */
		if (redo != -1) {
			fst->ipos += prev_tow;
			adv_ipos += prev_tow;
		}
		if (!wbuf)
			assert(!towrite);
		/* Nothing to write? Next round (or end if redo == -1) */
		if (!towrite)
			continue;
		*shouldwrite += towrite;
		/* If sparse detection needs to be redone, it's handled in call_plugins_block() */
		ssize_t wr = 0;
		//errno = 0; /* should not be necessary */
		/* Loop for EINTR/EAGAIN and for incomplete writes that make progress */
		do {
			wr += (err = mypwrite(fst->odes, wbuf+wr, towrite-wr,
					      fst->opos+wr-op->reverse*towrite, op, fst, prg));
			if (err == -1)
				wr++;
		} while ((err == -1 && (errno == EINTR || errno == EAGAIN || !retry++))
		      || (err > 0 && errno == 0 && wr < towrite)
		      || (err == 0 && !retry++));
		//fplog(stderr, DEBUG, "wrote %i/%i orig %i\n", wr, towrite, prev_tow);
		if (wr < towrite && err != 0) {
			/* HANDLE write errors here ... */
			lasterr = errno;
			fplog(stderr, (op->abwrerr? FATAL: WARN),
					"write %s (%skiB): %s\n",
		      			op->oname, fmt_kiB(fst->opos, !nocol), strerror(errno));
			if (op->abwrerr) {
				totwr += wr;
				exit_report(21, op, fst, prg, dop);
			}
			fst->nrerr++;
			if (lasterr != ENXIO && lasterr != EROFS && !fst->o_chr && towrite > op->hardbs) {
				/* TODO: Write retry */
				fplog(stderr, INFO, "retrying writes with smaller blocks \n");
				int rc = fsync(fst->odes);
				if (rc && errno != EINVAL && !fst->o_chr)
					fplog(stderr, WARN, "sync %s (%sskiB): %s!  \n",
					      op->oname, fmt_kiB(fst->ipos, !nocol), strerror(errno));
#ifdef HAVE_SCHED_YIELD
				sched_yield();
#endif
				wr = 0;
				loff_t off;
				if (op->reverse) {
					for (off = towrite-towrite%op->hardbs; off >= 0; off -= op->hardbs) {
						do {
							err = mypwrite(fst->odes, wbuf+off, MIN(op->hardbs, towrite-off),
									fst->opos+off-op->reverse*towrite, op, fst, prg);
						} while (err == -1 && (errno == EINTR || errno == EAGAIN));
						if (err >= 0)
							wr += err;
						else
							lasterr = errno;
					}
				} else {
					for (off = 0; off < towrite; off += op->hardbs) {
						do {
							err = mypwrite(fst->odes, wbuf+off, MIN(op->hardbs, towrite-off),
									fst->opos+off-op->reverse*towrite, op, fst, prg);
						} while (err == -1 && (errno == EINTR || errno == EAGAIN));
						if (err >= 0)
							wr += err;
						else
							lasterr = errno;
					}
				}
			}
		}
		totwr += wr;
		/* Handle multiple output files, NO error handling, just reporting */
		char oldochr = fst->o_chr;
		LISTTYPE(ofile_t) *of;
		LISTFOREACH(ofiles, of) {
			ssize_t e2, w2 = 0;
			ofile_t *oft = &(LISTDATA(of));
			fst->o_chr = oft->cdev;
			do {
				w2 += (e2 = mypwrite(oft->fd, wbuf+w2, towrite-w2, fst->opos+w2-op->reverse*towrite, op, fst, prg));
				if (e2 == -1) 
					w2++;
			} while ((e2 == -1 && (errno == EINTR || errno == EAGAIN))
				  || (w2 < towrite && e2 > 0 && errno == 0));
			if (w2 < towrite && e2 != 0) 
				fplog(stderr, WARN, "2ndary write %s (%skiB): %s\n",
				      oft->name, fmt_kiB(fst->opos, !nocol), strerror(errno));
		}
		fst->o_chr = oldochr;
		if (redo != -1) {
			fst->opos += wr;
			adv_opos += wr;
		}
		towrite = 0;
	} while (redo != -1);
	/* Undo opos/ipos changes */
	fst->ipos -= adv_ipos;
	fst->opos -= adv_opos;
	return (lasterr? -lasterr: totwr);
}

/* Returns the SIZE of the next block to be copied, at max the passed bs,
 * but maybe smaller due to maxxfer or file positions
 */
int blockxfer(const loff_t max, const int bs,
	      opt_t *op, fstate_t *fst, progress_t *prg)
{
	int block = bs;
	/* Don't progress->xfer more bytes than our limit */
	if (max && max-prg->xfer < bs)
		block = max-prg->xfer;
	if (op->reverse) {
		/* Can't go beyond the beginning of the file */
		if (block > fst->ipos)
			block = fst->ipos;
		if (block > fst->opos)
			block = fst->opos;
	}
	/* If we write the first block and it's a full block, do alignment ... */
	if (block == bs && !prg->xfer && ((fst->opos % bs && !fst->o_chr) || (fst->ipos % bs && !fst->i_chr))) {
		/* Write alignment is more important except if fstate->o_chr == 1 */
		int off = fst->o_chr? fst->ipos % bs: fst->opos % bs;
		int aligned = op->reverse? off: bs-off;
		if (!plug_max_req_align || !(aligned % plug_max_req_align) || op->reverse)
			block = aligned;
		if (0 && op->verbose)
			fplog(stderr, DEBUG, "blockxfer: %i -> %i/%i (@%zi/%zi)\n",
				bs, block, aligned, fst->ipos, fst->opos);
	}
	return block;
}

void exitfatalerr(const int eno, opt_t *op, fstate_t *fst, progress_t *prg, dpopt_t *dop)
{
	if (eno == ESPIPE || eno == EPERM || eno == ENXIO || eno == ENODEV) {
		fplog(stderr, FATAL, "%s (%skiB): %s! \n", 
		      op->iname, fmt_kiB(fst->ipos, !nocol), strerror(eno));
		fplog(stderr, NOHDR, "dd_rescue: Last error fatal! Exiting ... \n");
		exit_report(20, op, fst, prg, dop);
	}
}

/* Update positions after successful copy,
 * rd, wr => updates for read and write positions
 * 	(should be the same unless some plugin changes the length)
 * rwr    => really written (successful xfer)
 */
static void advancepos(const ssize_t rd, const ssize_t wr, const ssize_t rwr,
		       opt_t *op, fstate_t *fst, progress_t *prg)
{
	prg->sxfer += rwr; prg->xfer += rd;
#if 0
	fplog(stderr, DEBUG, "Adv %i+%i->%i, %i+%i->%i\n",
		(int)fst->ipos, op->reverse? (int)-rd: (int)rd, op->reverse? (int)(fst->ipos-rd): (int)(fst->ipos+rd),
		(int)fst->opos, op->reverse? (int)-wr: (int)wr, op->reverse? (int)(fst->opos-wr): (int)(fst->opos+wr));
#endif
	if (op->reverse) { 
		fst->ipos -= rd; fst->opos -= wr; 
	} else { 
		fst->ipos += rd; fst->opos += wr; 
	}
}

static int is_writeerr_fatal(int err, opt_t *op)
{
	return (err == ENOSPC || err == EROFS
#ifdef EDQUOT
               || err == EDQUOT
#endif
               || (err == EFBIG && !op->reverse));
}

/* Do write, returns 0 for success, 1 for error, -1 for fatal error
 * Advances position IF AND ONLY IF return value is NOT negative */
ssize_t dowrite(const ssize_t rd, opt_t *op, fstate_t *fst, 
		progress_t *prg, dpopt_t *dop)
{
	int err = 0;
	int fatal = 0;
	ssize_t wr = 0;
	int shouldwr = 0;
	err = ((wr = writeblock(rd, &shouldwr, op, fst, prg, dop)) < 0 ? -wr: 0);
	if (err && is_writeerr_fatal(err, op))
		++fatal;
	if (err) {
		fplog(stderr, WARN, "assumption rd(%i) == wr(%i) failed! \n", rd, wr);
		fplog(stderr, (fatal? FATAL: WARN),
			"write %s (%skiB): %s!\n", 
			op->oname, fmt_kiB(fst->opos/*+wr*/, !nocol), strerror(err));
		/* No retry at this high level, move on -- this breaks plugins that
		 * don't handle sparse but what can we do? */
		if (plug_not_sparse)
			fplog(stderr, FATAL, "output file will be broken (plugins don't handle sparse)\n");
		// Advance in case of write errors
		advancepos(rd, shouldwr, 0, op, fst, prg);
		return fatal? -1: 1;
	} else {
		advancepos(rd, shouldwr, wr, op, fst, prg);
		if (wr != shouldwr) {
			fplog(stderr, DEBUG, "Should have written %i, but only %i done\n");
			return 1;
		}
		return 0;
	}
}

/* Write rd-sized block at fstate->buf; if op->sparse is set,
 * check if at least half of the block is empty and if so, move
 * over the sparse pieces ...
 * Note that this assumes that it's OK for all plugins to skip
 * over empty (zeroed) blocks.
 * This is the case for ddr_null (no surprise) and quite some
 * effort has gone into ddr_hash to catch up after a hole.
 * ddr_crypt COULD do it with CTR and skiphole, but this is
 * not implemented.
 */
ssize_t dowrite_sparse(const ssize_t rd, opt_t *op, fstate_t *fst, 
		       progress_t *prg, repeat_t *rep, dpopt_t *dop)
{
	/* Simple case: opts->sparse not set => just write */
	if (!op->sparse)
		return dowrite(rd, op, fst, prg, dop);
	ssize_t zln = blockiszero(fst->buf, rd, op, rep);
	/* Also simple: Whole block is empty, so just move on */
	if (zln >= rd) {
		advancepos(rd, rd, 0, op, fst, prg);
		return 0;
	}
	/* Block is smaller than 2*opts->hardbs and not completely zero, so don't bother optimizing ... */
	if (rd < 2*(ssize_t)op->hardbs)
		return dowrite(rd, op, fst, prg, dop);
	/* Check both halves -- aligned to opts->hardbs boundaries */
	int mid = rd/2;
	mid -= mid%op->hardbs;
	zln -= zln%op->hardbs;
	/* First half is empty */
	if (zln >= mid) {
		unsigned char* oldbuf = fst->buf;
		advancepos(zln, zln, 0, op, fst, prg);
		fst->buf += zln;
		ssize_t wr = dowrite(rd-zln, op, fst, prg, dop);
		fst->buf = oldbuf;
		return wr;
	}
	/* Check second half */
	ssize_t zln2 = blockiszero(fst->buf+mid, rd-mid, op, rep);
	if (zln2 < rd-mid) // Not empty either, just write ..
		return dowrite(rd, op, fst, prg, dop);
	else {
		ssize_t wr = dowrite(mid, op, fst, prg, dop);
		advancepos(rd-mid, rd-mid, 0, op, fst, prg);
		return wr;
	}
}


static int partialwrite(const ssize_t rd, opt_t *op, fstate_t *fst,
			progress_t *prg, repeat_t *rep, dpopt_t *dop)
{
	/* But first: write available data and advance (optimization) */
	if (rd > 0 && !op->reverse) 
		return dowrite_sparse(rd, op, fst, prg, rep, dop);
	/* Nothing TBD */
	return 0;
}

static int updstat = 8;

int copyfile_hardbs(const loff_t max, opt_t *op, fstate_t *fst,
		    progress_t *prg, repeat_t *rep, 
		    dpopt_t *dop, dpstate_t *dst)
{
	ssize_t toread;
	int errs = 0; errno = 0;
#if 0	
	fprintf(stderr, "%s%s%s%s copyfile (fstate->ipos=%.1fk, progress->xfer=%.1fk, max=%.1fk, bs=%i)                         ##\n%s%s%s%s",
		up, up, up, up,
		(double)fstate->ipos/1024, (double)progress->xfer/1024, (double)max/1024, opts->hardbs,
		down, down, down, down);
#endif
	while ((toread = blockxfer(max, op->hardbs, op, fst, prg)) > 0 && !interrupted) { 
		int eno;
		ssize_t rd = readblock(toread, op, fst, rep, dop, dst);
		eno = errno;

		/* EOF */
		if (rd == 0 && !eno) {
			if (!op->quiet)
				fplog(stderr, INFO, "read %s (%skiB): EOF\n", 
				      op->iname, fmt_kiB(fst->ipos, !nocol));
			return errs;
		}
		/* READ ERROR */
		if (rd < toread/* && errno*/) {
			if (eno) {
				++errs;
				/* Read error occurred: Print warning */
				printstatus(stderr, logfd, op->hardbs, 1, op, fst, prg, dop);
			}
			/* Some errnos are fatal */
			exitfatalerr(eno, op, fst, prg, dop);
			/* Non fatal error */
			/* This is the case, where we were not called from copyfile_softbs and thus have to assume harmless EOF */
			if (/*op->softbs <= op->hardbs &&*/ eno == 0) {
				int ret;
				/* But first: write available data and advance (optimization) */
				if ((ret = partialwrite(rd, op, fst, prg, rep, dop)) < 0)
					return ret;
				else
					errs += ret;
				/* partialwrite calls dowrite_retry which updates
				 * statistics and positions. */
				continue;
			}					
			/* Real error on small blocks: Don't retry */
			fst->nrerr++; 
			loff_t pos = (op->reverse? fst->ipos - toread: fst->ipos);
			fplog(stderr, WARN, "read %s (%skiB): %s!\n", 
			      op->iname, fmt_kiB(pos, !nocol), strerror(eno));
		
			errno = 0;
			/* Adjust toread to not extend beyond EOF if src filesize is known */
			if (!op->reverse && fst->fin_ipos && fst->ipos+toread > fst->fin_ipos)
				toread = fst->fin_ipos-fst->ipos;
			/* Note: This should handle maxxfer as well */
			/* TODO: Do we need to special case last block on reverse copy as well? */
			if (op->nosparse || 
			    (rd > 0 && (!op->sparse || blockiszero(fst->buf, rd, op, rep) < rd))) {
				ssize_t wr = 0;
				int shouldwr = 0;
				memset(fst->buf+rd, 0, toread-rd);
				errs += ((wr = writeblock(toread, &shouldwr, op, fst, prg, dop)) < 0? -wr: 0);
				eno = errno;
				if (wr <= 0 && (eno == ENOSPC 
					   || (eno == EFBIG && !op->reverse))) 
					return errs;
				if (shouldwr != wr) {
					fplog(stderr, WARN, "assumption shouldwr(%i) == wr(%i) failed! \n", shouldwr, wr);
					/*
					fplog(stderr, WARN, "%s (%skiB): %s!\n", 
					      op->oname, fmt_kiB(fst->opos, !nocol), strerror(eno));
					fprintf(stderr, "%s%s%s%s", down, down, down, down);
				 	*/
				}
			}
			savebb(pos/op->hardbs, op);
			updgraph(1, fst, dop, op);
			prg->fxfer += toread; prg->xfer += toread;
			if (op->reverse) { 
				fst->ipos -= toread; fst->opos -= toread; 
			} else { 
				fst->ipos += toread; fst->opos += toread; 
			}
			/* exit if too many errs */
			if (op->maxerr && fst->nrerr >= op->maxerr) {
				fplog(stderr, FATAL, "maxerr reached!\n");
				exit_report(32, op, fst, prg, dop);
			}
			/*
			if (!op->reverse && fst->fin_ipos && fst->ipos == fst->fin_ipos)
				return errs;
			 */
		} else {
			int err = dowrite_sparse(rd, op, fst, prg, rep, dop);
			if (err < 0)
				return -err;
			else
				errs += err;
		}

		if (op->syncfreq && !(prg->xfer % (op->syncfreq*op->softbs)))
			printstatus((op->quiet? 0: stderr), 0, op->hardbs, 1, op, fst, prg, dop);
		else if (!op->quiet && !(prg->xfer % (updstat*op->softbs)))
			printstatus(stderr, 0, op->hardbs, 0, op, fst, prg, dop);
		else if (op->quiet && op->maxkbs && !(prg->xfer % (updstat*op->softbs)))
			printstatus(0, 0, op->hardbs, 0, op, fst, prg, dop);
	} /* remain */
	return errs;
}

int copyfile_softbs(const loff_t max, opt_t *op, fstate_t *fst,
		    progress_t *prg, repeat_t *rep, 
		    dpopt_t *dop, dpstate_t *dst)
{
	ssize_t toread;
	int errs = 0, rc; int eno;
	errno = 0;
#if 0	
	fprintf(stderr, "%s%s%s%s copyfile (fstate->ipos=%.1fk, progress->xfer=%.1fk, max=%.1fk, bs=%i)                         ##\n%s%s%s%s",
		up, up, up, up,
		(double)fstate->ipos/1024, (double)progress->xfer/1024, (double)max/1024, opts->softbs,
		down, down, down, down);
#endif
	/* expand file to AT LEAST the right length 
	 * FIXME: 0 byte writes do NOT expand file */
	if (!fst->o_chr && !op->avoidwrite) {
		rc = pwrite(fst->odes, fst->buf, 0, fst->opos);
		if (rc)
			fplog(stderr, WARN, "extending file %s to %skiB failed\n",
			      op->oname, fmt_kiB(fst->opos, !nocol));
	}
	while ((toread = blockxfer(max, op->softbs, op, fst, prg)) > 0 && !interrupted) {
		int err;
		ssize_t rd = readblock(toread, op, fst, rep, dop, dst);
		eno = errno;

		/* EOF */
		if (rd == 0 && !eno) {
			if (!op->quiet)
				fplog(stderr, INFO, "read %s (%skiB): EOF\n", 
				      op->iname, fmt_kiB(fst->ipos, !nocol));
			return errs;
		}
		/* READ ERROR or short read */
		if (rd < toread/* && errno*/) {
			int ret;
			loff_t new_max, old_xfer;
			if (eno) {
				++errs;
				/* Read error occurred: Print warning */
				printstatus(stderr, logfd, op->softbs, 1, op, fst, prg, dop);
			}
			/* Some errnos are fatal */
			exitfatalerr(eno, op, fst, prg, dop);
			/* Non fatal error */
			new_max = prg->xfer + toread;
			/* Error with large blocks: Try small ones ... */
			if (op->verbose & eno) {
				/*
				fprintf(stderr, DDR_INFO "problems at ipos %.1fk: %s \n                 fall back to smaller blocksize \n%s%s%s%s",
				        (double)fstate->ipos/1024, strerror(eno), down, down, down, down);
				 */
				loff_t pos = (op->reverse? fst->ipos - toread: fst->ipos);
				fprintf(stderr, DDR_INFO "problems at ipos %skiB: %s \n               fall back to smaller blocksize \n",
				        fmt_kiB(pos, !nocol), strerror(eno));
				scrollup = 0;
				printstatus(stderr, logfd, op->hardbs, 1, op, fst, prg, dop);
			}
			/* But first: write available data and advance (optimization) */
			if ((ret = partialwrite(rd, op, fst, prg, rep, dop)) < 0)
				return ret;
			else
				errs += ret;
			old_xfer = prg->xfer;
			errs += (err = copyfile_hardbs(new_max, op, fst, prg, rep, dop, dst));
			/* EOF */
			if (!err && old_xfer == prg->xfer)
				return errs;
			/*
			if (opts->reverse && rd) {
				fstate->ipos -= rd; fstate->opos -= rd;
				progress->xfer += rd; progress->sxfer += wr;
			}
			*/	
			/* Stay with small blocks, until we could read two whole 
			   large ones without errors */
			new_max = prg->xfer;
			while (err && (!max || (max-prg->xfer > 0)) && ((!op->reverse) || (fst->ipos > 0 && fst->opos > 0))) {
				new_max += 2*op->softbs; old_xfer = prg->xfer;
				if (max && new_max > max) 
					new_max = max;
				errs += (err = copyfile_hardbs(new_max,  op, fst, prg, rep, dop, dst));
			}
			errno = 0;
			/* EOF ? */      
			if (!err && prg->xfer == old_xfer)
				return errs;
			if (op->verbose) {
				fprintf(stderr, DDR_INFO "ipos %skiB promote to large bs again! \n",
					fmt_kiB(fst->ipos, !nocol));
				scrollup = 0;
			}
		} else {
			err = dowrite_sparse(rd, op, fst, prg, rep, dop);
			if (err < 0)
				return -err;
			else
				errs += err;
		} /* errno */

		if (op->syncfreq && !(prg->xfer % (op->syncfreq*op->softbs)))
			printstatus((op->quiet? 0: stderr), 0, op->softbs, 1, op, fst, prg, dop);
		else if (!op->quiet && !(prg->xfer % (2*updstat*op->softbs)))
			printstatus(stderr, 0, op->softbs, 0, op, fst, prg, dop);
		else if (op->quiet && op->maxkbs && !(prg->xfer % (2*updstat*op->softbs)))
			printstatus(0, 0, op->softbs, 0, op, fst, prg, dop);
	} /* remain */
	return errs;
}

#ifdef HAVE_SPLICE
int copyfile_splice(const loff_t max, opt_t *op, fstate_t *fst,
		    progress_t *prg, repeat_t *rep, 
		    dpopt_t *dop, dpstate_t *dst)

{
	ssize_t toread;
	int fd_pipe[2];
	LISTTYPE(ofile_t) *oft;
	if (pipe(fd_pipe) < 0)
		return copyfile_softbs(max, op, fst, prg, rep, dop, dst);
	while ((toread	= blockxfer(max, op->softbs, op, fst, prg) && !interrupted) > 0) {
		loff_t old_ipos = fst->ipos, old_opos = fst->opos;
		ssize_t rd = splice(fst->ides, &fst->ipos, fd_pipe[1], NULL, toread,
					SPLICE_F_MOVE | SPLICE_F_MORE);
		if (rd < 0) {
			if (!op->quiet)
				fplog(stderr, INFO, "%s (%skiB): fall back to userspace copy\n",
				      op->iname, fmt_kiB(fst->ipos, !nocol));
			close(fd_pipe[0]); close(fd_pipe[1]);
			return copyfile_softbs(max, op, fst, prg, rep, dop, dst);
		}
		if (rd == 0) {
			if (!op->quiet)
				fplog(stderr, INFO, "read %s (%skiB): EOF (splice)\n",
				      op->iname, fmt_kiB(fst->ipos, !nocol));
			break;
		}
		while (rd) {
			ssize_t wr = splice(fd_pipe[0], NULL, fst->odes, &fst->opos, rd,
					SPLICE_F_MOVE | SPLICE_F_MORE);
			if (wr < 0) {
				fplog(stderr, FATAL, "write %s (%skiB): %s (splice)\n",
					op->oname, fmt_kiB(fst->opos, !nocol), strerror(errno));

				close(fd_pipe[0]); close(fd_pipe[1]);
				exit_report(23, op, fst, prg, dop);
			}
			rd -= wr; prg->xfer += wr; prg->sxfer += wr;
		}
		loff_t new_ipos = fst->ipos, new_opos = fst->opos;
		LISTFOREACH(ofiles, oft) {
			fst->ipos = old_ipos; fst->opos = old_opos;
			rd = splice(fst->ides, &fst->ipos, fd_pipe[1], NULL, toread,
					SPLICE_F_MOVE | SPLICE_F_MORE);
			/* Simplify error handling, it worked before ... */
			if (rd <= 0) {
				fplog(stderr, WARN, "Confused: splice() read failed unexpectedly: %s\n",
					strerror(errno));
				/* We should abort here .... */
				fst->ipos = new_ipos; fst->opos = new_opos;
				continue;
			}
			while (rd) {
				ssize_t wr = splice(fd_pipe[0], NULL, LISTDATA(oft).fd, &fst->opos, rd,
						SPLICE_F_MOVE | SPLICE_F_MORE);
				if (wr < 0) {	
					fplog(stderr, WARN, "Confused: splice() write failed unexpectedly: %s\n",
						strerror(errno));
					/* We should abort here .... */
					fst->ipos = new_ipos; fst->opos = new_opos;
					continue;
				}
			rd -= wr;
			}
		}
		if (fst->ipos != new_ipos || fst->opos != new_opos) {
			fplog(stderr, WARN, "Confused: splice progress inconsistent: %zi %zi %zi %zi\n",
				fst->ipos, new_ipos, fst->opos, new_opos);
			fst->ipos = new_ipos; fst->opos = new_opos;
		}	
		advancepos(0, 0, 0, op, fst, prg);
		if (op->syncfreq && !(prg->xfer % (op->syncfreq*op->softbs)))
			printstatus((op->quiet? 0: stderr), 0, op->softbs, 1, op, fst, prg, dop);
		else if (!op->quiet && !(prg->xfer % (2*updstat*op->softbs)))
			printstatus(stderr, 0, op->softbs, 0, op, fst, prg, dop);
		else if (op->quiet && op->maxkbs && !(prg->xfer % (2*updstat*op->softbs)))
			printstatus(0, 0, op->softbs, 0, op, fst, prg, dop);
	}
	close(fd_pipe[0]); close(fd_pipe[1]);
	return 0;
}
#endif

int tripleoverwrite(const loff_t max, opt_t *op, fstate_t *fst,
		    progress_t *prg, repeat_t *rep, 
		    dpopt_t *dop, dpstate_t *dst)

{
	int ret = 0;
	void* prng_state3 = frandom_stdup(dst->prng_state);
	clock_t orig_startclock = startclock;
	struct timeval orig_starttime;
	LISTTYPE(ofile_t) *of;
	memcpy(&orig_starttime, &starttime, sizeof(starttime));
	//fprintf(stderr, "%s%s%s%s" DDR_INFO "Triple overwrite (BSI M7.15): first pass ... (frandom)      \n\n\n\n\n", up, up, up, up);
	fprintf(stderr, DDR_INFO "Triple overwrite (BSI M7.15): first pass ... (frandom)      \n");
	ret += copyfile_softbs(max, op, fst, prg, rep, dop, dst);
	fprintf(stderr, "syncing ... \n%s", up);
	ret += fsync(fst->odes);
	LISTFOREACH(ofiles, of)
		fsync(LISTDATA(of).fd);
	/* TODO: better error handling */
	frandom_release(dst->prng_state);
	dst->prng_state = prng_state3; prng_state3 = 0;
	dop->bsim715_2ndpass = 1;
	if (!dop->bsim715_2) {
		fst->opos = op->init_opos; prg->xfer = 0; fst->ipos = 0;
		startclock = clock(); gettimeofday(&starttime, NULL);
		fprintf(stderr, DDR_INFO "Triple overwrite (BSI M7.15): second pass ... (frandom_inv)\n\n\n\n\n");
		ret += copyfile_softbs(max, op, fst, prg, rep, dop, dst);
		fprintf(stderr, "syncing ... \n%s", up);
		ret += fsync(fst->odes);
		LISTFOREACH(ofiles, of)
			fsync(LISTDATA(of).fd);
		/* TODO: better error handling */
		dop->bsim715_2ndpass = 0;
		if (dop->bsim715_4) {
			frandom_bytes(dst->prng_state, fst->buf, 16);
			fprintf(stderr, DDR_INFO "Triple overwrite (BSI M7.15): third pass ... (frandom) \n\n\n\n\n");
			fst->opos = op->init_opos; prg->xfer = 0; fst->ipos = 0;
			startclock = clock(); gettimeofday(&starttime, NULL);
			ret += copyfile_softbs(max, op, fst, prg, rep, dop, dst);
			fprintf(stderr, "syncing ... \n%s", up);
			ret += fsync(fst->odes);
			LISTFOREACH(ofiles, of)
				fsync(LISTDATA(of).fd);
			dop->bsim715_2ndpass = 1;
			op->iname = "FRND+invFRND+FRND2+ZERO";
		} else
			op->iname = "FRND+invFRND+ZERO";
	} else
		op->iname = "FRND+ZERO";
	fprintf(stderr, DDR_INFO "Triple overwrite (BSI M7.15): last pass ... (zeros) \n\n\n\n\n");
	frandom_release(dst->prng_state); dst->prng_state = 0;
	memset(fst->buf, 0, op->softbs); 
	op->i_repeat = 1; rep->i_rep_init = 1;
	fst->opos = op->init_opos; prg->xfer = 0; fst->ipos = 0;
	startclock = clock(); gettimeofday(&starttime, NULL);
	ret += copyfile_softbs(max, op, fst, prg, rep, dop, dst);
	startclock = orig_startclock;
	memcpy(&starttime, &orig_starttime, sizeof(starttime));
	prg->xfer = prg->sxfer;
	if (ret)
		fplog(stderr, WARN, 
			"There were %i errors! %s may not be safely overwritten!\n", ret, op->oname);
	//fprintf(stderr, "syncing ... \n%s", up);
	return ret;
}

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
			fplog(stderr, WARN, "suffix %c ignored!\n", *es);
	}
	return (loff_t)res;
}

char readbool(const char* arg)
{
	if (isdigit(*arg))
		return !!atoi(arg);
	if (!strcasecmp(arg, "yes")
		|| !strcasecmp(arg, "y")
		|| !strcasecmp(arg, "always")
		|| !strcasecmp(arg, "true"))
		return 1;
	return 0;
}

void init_random(opt_t *op, dpopt_t *dop, dpstate_t *dst)
{
	if (dop->prng_sfile) {
		int ln, fd = -1;
		unsigned char sbf[256];
		if (!strcmp(dop->prng_sfile, "-")) {
			fd = 0;
			if (op->verbose)
				fplog(stderr, INFO, "reading random seed from <stdin> ...\n");
		} else
			fd = open(dop->prng_sfile, O_RDONLY);
		if (fd == -1) {
			fplog(stderr, FATAL, "Could not open \"%s\" for random seed!\n", dop->prng_sfile);
			/* ERROR */
			cleanup(1); exit(28);
		}
		if (dop->prng_libc) {
			unsigned int* sval = (unsigned int*)sbf;
			ln = read(fd, sbf, 4);
			if (ln != 4) {
				fplog(stderr, FATAL, "failed to read 4 bytes from \"%s\"!\n", dop->prng_sfile);
				cleanup(1); exit(29);
			}
			srand(*sval); rand();
		} else {
			ln = read(fd, sbf, 256);
			if (ln != 256) {
				fplog(stderr, FATAL, "failed to read 256 bytes from \"%s\"!\n", dop->prng_sfile);
				cleanup(1); exit(29);
			}
			dst->prng_state = frandom_init(sbf);
		}
	} else {
		if (!dop->prng_seed)
			dop->prng_seed = random_getseedval32();
		if (dop->prng_libc) {
			srand(dop->prng_seed); rand();
		} else
			dst->prng_state = frandom_init_lrand(dop->prng_seed);
	}
}


void printversion()
{
	fprintf(stderr, "\ndd_rescue Version %s, kurt@garloff.de, GNU GPL v2/v3\n", VERSION);
	fprintf(stderr, " (%s)\n", ID);
	fprintf(stderr, " (compiled %s %s by %s)\n", __DATE__, __TIME__, __COMPILER__);
	fprintf(stderr, " (features: ");
#ifdef O_DIRECT
	fprintf(stderr, "O_DIRECT ");
#endif
#ifdef USE_LIBDL
	fprintf(stderr, "dl/libfallocate ");
#elif defined(HAVE_LIBFALLOCATE)
	fprintf(stderr, "libfallocate ");
#endif	
#if defined(HAVE_FALLOCATE64)
	fprintf(stderr, "fallocate ");
#endif
#ifdef HAVE_SPLICE
	fprintf(stderr, "splice ");
#endif
#ifdef FITRIM
	fprintf(stderr, "fitrim ");
#endif
#ifdef HAVE_ATTR_XATTR_H
	fprintf(stderr, "xattr ");
#endif
#if (defined(__x86_64__) || defined(__i386__)) && !defined(NO_RDRND)
	if (have_rdrand)
		fprintf(stderr, "rdrnd ");
#if 0
	if (have_aesni)
		fprintf(stderr, "aes ");
#endif
#endif
#if defined(__aarch64__) || defined(__arm__)
	if (have_arm8crypto)
		fprintf(stderr, "aes ");
#endif
	fprintf(stderr, "%s", OPT_STR);
	fprintf(stderr, ")\n");
	fprintf(stderr, "dd_rescue is free software. It's protected by the terms of GNU GPL v2 or v3\n");
	fprintf(stderr, " (at your option).\n");
}


#ifdef HAVE_GETOPT_LONG
struct option longopts[] = { 	{"help", 0, NULL, 'h'}, {"verbose", 0, NULL, 'v'},
				{"quiet", 0, NULL, 'q'}, {"version", 0, NULL, 'V'},
				{"color", 1, NULL, 'c'}, {"ratecontrol", 1, NULL, 'C'},
				{"ipos", 1, NULL, 's'}, {"opos", 1, NULL, 'S'},
				{"softbs", 1, NULL, 'b'}, {"hardbs", 1, NULL, 'B'},
				{"maxerr", 1, NULL, 'e'}, {"maxxfer", 1, NULL, 'm'},
				{"noextend", 0, NULL, 'M'}, {"extend", 0, NULL, 'x'},
				{"append", 0, NULL, 'x'},
				{"syncfreq", 1, NULL, 'y'}, {"logfile", 1, NULL, 'l'},
				{"bbfile", 1, NULL, 'o'}, {"reverse", 0, NULL, 'r'},
				{"repeat", 0, NULL, 'R'}, {"truncate", 0, NULL, 't'},
				{"trunclast", 0, NULL, 'T'},
				{"odir_in", 0, NULL, 'd'}, {"odir_out", 0, NULL, 'D'},
				{"splice", 0, NULL, 'k'}, {"fallocate", 0, NULL, 'P'},
				{"abort_we", 0, NULL, 'w'}, {"avoidwrite", 0, NULL, 'W'},
				{"sparse", 0, NULL, 'a'}, {"alwayswrite", 0, NULL, 'A'},
				{"interactive", 0, NULL, 'i'}, {"force", 0, NULL, 'f'},
				{"preserve", 0, NULL, 'p'}, {"outfile", 1, NULL, 'Y'},
				{"random", 1, NULL, 'z'}, {"frandom", 1, NULL, 'Z'},
 				{"shred3", 1, NULL, '3'}, {"shred4", 1, NULL, '4'},
 				{"shred2", 1, NULL, '2'},
				{"rmvtrim", 0, NULL, 'u'}, {"plugins", 1, NULL, 'L'},
				{"fault", 1, NULL, 'F'},
				/* GNU ddrescue compat */
				{"block-size", 1, NULL, 'B'}, {"input-position", 1, NULL, 's'},
				{"output-position", 1, NULL, 'S'}, {"max-size", 1, NULL, 'm'},
				/* dd like args */
				{"bs", 1, NULL, 'b'},	/* seek and skip refer to obs/ibs, thus no direct corresp. */
				{"of", 1, NULL, 'Y'},	/* short form of outfile */
				/* END */	
				{NULL, 0, NULL, 0},
};
#endif


void printlonghelp()
{
	printversion();
	fprintf(stderr, "dd_rescue copies data from one file (or device or pipe) to others.\n");
	fprintf(stderr, "USAGE: dd_rescue [options] infile outfile\n");
	fprintf(stderr, "Options: -s ipos    start position in  input file (default=0),\n");
	fprintf(stderr, "         -S opos    start position in output file (def=ipos),\n");
	fprintf(stderr, "         -b softbs  block size for copy operation (def=%i, %i for -d),\n", BUF_SOFTBLOCKSIZE, DIO_SOFTBLOCKSIZE);
	fprintf(stderr, "         -B hardbs  fallback block size in case of errs (def=%i, %i for -d),\n", BUF_HARDBLOCKSIZE, DIO_HARDBLOCKSIZE);
	fprintf(stderr, "         -e maxerr  exit after maxerr errors (def=0=infinite),\n");
	fprintf(stderr, "         -m maxxfer maximum amount of data to be transfered (def=0=inf),\n");
	fprintf(stderr,	"         -M         avoid extending outfile,\n");
	fprintf(stderr,	"         -x         count opos from the end of outfile (eXtend),\n");
	fprintf(stderr, "         -y syncsz  frequency of fsync calls in bytes (def=512*softbs),\n");
	fprintf(stderr, "         -l logfile name of a file to log errors and summary to (def=\"\"),\n");
	fprintf(stderr, "         -o bbfile  name of a file to log bad blocks numbers (def=\"\"),\n");
	fprintf(stderr, "         -r         reverse direction copy (def=forward),\n");
	fprintf(stderr, "         -R         repeatedly write same block (def if infile is /dev/zero),\n");
	fprintf(stderr, "         -t         truncate output file at start (def=no),\n");
	fprintf(stderr, "         -T         truncate output file at last pos (def=no),\n");
	fprintf(stderr, "         -u         undo writes by deleting outfile and issueing fstrim\n");
#ifdef O_DIRECT
	fprintf(stderr, "         -d/D       use O_DIRECT for input/output (def=no),\n");
#endif
#ifdef HAVE_SPLICE
	fprintf(stderr, "         -k         use efficient in-kernel zerocopy splice,\n");
#endif       	
#if defined(HAVE_FALLOCATE64) || defined(HAVE_LIBFALLOCATE)
	fprintf(stderr, "         -P         use fallocate to preallocate target space,\n");
#endif
#ifdef USE_LIBDL
	fprintf(stderr, "         -L plug1[=par1[:par2]][,plug2[,..]]    load plugins,\n");
#endif
	fprintf(stderr, "         -w         abort on Write errors (def=no),\n");
	fprintf(stderr, "         -W         read target block and avoid Writes if identical (def=no),\n");
	fprintf(stderr, "         -a         detect zero-filled blocks and write spArsely (def=no),\n");
	fprintf(stderr, "         -A         Always write blocks, zeroed if err (def=no),\n");
	fprintf(stderr, "         -i         interactive: ask before overwriting data (def=no),\n");
	fprintf(stderr, "         -f         force: skip some sanity checks (def=no),\n");
	fprintf(stderr, "         -p         preserve: preserve ownership, perms, times, attrs (def=no),\n");
	fprintf(stderr, "         -C limit   rateControl: avoid xfer data faster than limit B/s\n");
	fprintf(stderr, "         -Y oname   Secondary output file (multiple possible),\n");
	fprintf(stderr, "         -F off[-off]r/rep[,off[-off]w/rep[,...]]  fault injection (hardbs off) r/w\n");
	fprintf(stderr, "         -q         quiet operation,\n");
	fprintf(stderr, "         -v         verbose operation,\n");
	fprintf(stderr, "         -c 0/1     switch off/on colors (def=auto),\n");
	fprintf(stderr, "         -V         display version and exit,\n");
	fprintf(stderr, "         -h         display this help and exit.\n");
	fprintf(stderr, "Instead of infile, -z/Z SEED or -z/Z SEEDFILE may be specified, taking the PRNG\n");
	fprintf(stderr, " from libc or frandom (RC4 based) as input. SEED = 0 means a time based seed;\n");
	fprintf(stderr, " Using /dev/urandom as SEEDFILE gives good pseudo random numbers.\n");
	fprintf(stderr, "Likewise, -3 SEED/SEEDFILE will overwrite ofile 3 times (r,ir,0, BSI M7.15).\n");
	fprintf(stderr, " With -4 SEED/SEEDFILE you get an additional random pass (r,ir,r2,0).\n");
	fprintf(stderr, " With -2 SEED/SEEDFILE you only get one random pass (r,0).\n\n");
	fprintf(stderr, "Sizes may be given in units b(=512), k(=1024), M(=1024^2) or G(1024^3) bytes\n");
	fprintf(stderr, "This program is useful to rescue data in case of I/O errors, because\n");
	fprintf(stderr, " it does not normally abort or truncate the output.\n");
	fprintf(stderr, "It may also help data protection by securely overwriting data.\n");
	fprintf(stderr, "There are plugins for compression, hashing and encryption.\n");
	fprintf(stderr, "Have a look a the man page for more details and long options.\n");
}

void shortusage()
{
	fplog(stderr, INFO, "USAGE: dd_rescue [options] infile outfile\n"
		"   or: dd_rescue [options] -z/Z/2/3/4 SEED[FILE] outfile\n"
		" Use dd_rescue -h or dd_rescue --help for more information\n"
		"  or consult the man page dd_rescue(1).\n");
}

#define YESNO(flag) (flag? "yes": "no ")

void printinfo(FILE* const file, opt_t *op)
{
	fplog(file, INFO, "about to transfer %s kiBytes from %s to %s\n",
	      (op->maxxfer? fmt_kiB(op->maxxfer, !op->nocol): "unlim"), op->iname, op->oname);
	fplog(file, INFO, "blocksizes: soft %i, hard %i\n", op->softbs, op->hardbs);
	fplog(file, INFO, "starting positions: in %skiB, out %skiB\n",
	      fmt_kiB(op->init_ipos, !nocol), fmt_kiB(op->init_opos, !nocol));
	fplog(file, INFO, "Logfile: %s, Maxerr: %li\n",
	      (op->lname? op->lname: "(none)"), op->maxerr);
	fplog(file, INFO, "Reverse: %s, Trunc: %s, interactive: %s\n",
	      YESNO(op->reverse), (op->dotrunc? "yes": (op->trunclast? "last": "no")), YESNO(op->interact));
	fplog(file, INFO, "abort on Write errs: %s, spArse write: %s\n",
	      YESNO(op->abwrerr), (op->sparse? "yes": (op->nosparse? "never": "if err")));
	fplog(file, INFO, "preserve: %s, splice: %s, avoidWrite: %s\n",
	      YESNO(op->preserve), YESNO(op->dosplice), YESNO(op->avoidwrite));
	fplog(file, INFO, "fallocate: %s, Repeat: %s, O_DIRECT: %s/%s\n",
	      YESNO(op->falloc), YESNO(op->i_repeat), YESNO(op->o_dir_in), YESNO(op->o_dir_out));
	/*
	fplog(file, INFO, "verbose: %s, quiet: %s\n", 
	      YESNO(op->verbose), YESNO(op->quiet));
	*/
}

void breakhandler(int sig)
{
	int_by = sig;
	if (!interrupted++) {
		fplog(stderr, FATAL, "Caught signal %i \"%s\". Flush and exit after current block!\n",
		      sig, strsignal(sig));
	} else {
		fplog(stderr, FATAL, "Caught signal %i \"%s\". Flush and exit immediately!\n",
		      sig, strsignal(sig));
		_printreport();
		cleanup(1);
		signal(sig, SIG_DFL);
		raise(sig);
	}
}

unsigned char* zalloc_aligned_buf(unsigned int bs, unsigned char**obuf)
{
	unsigned char *ptr = 0;
//#if defined (__DragonFly__) || defined(__NetBSD__) || defined(__BIONIC__)
#ifdef HAVE_VALLOC
	ptr = plug_max_slack_pre%pagesize? 0: (unsigned char*)valloc(bs + plug_max_slack_pre + plug_max_slack_post);
#elif defined(HAVE_POSIX_MEMALIGN)
	void *mp;
	if (plug_max_slack_pre%pagesize || posix_memalign(&mp, pagesize, bs + plug_max_slack_pre + plug_max_slack_post))
		ptr = 0;
	else
		ptr = (unsigned char*)mp;
#endif /* NetBSD */
	if (obuf) 
		*obuf = ptr;
	if (!ptr) {
		if (0 == plug_max_slack_pre%pagesize)
			fplog(stderr, WARN, "allocation of aligned buffer failed -- use malloc\n");
		ptr = (unsigned char*)malloc(bs + pagesize + plug_max_slack_pre + plug_max_slack_post);
		if (!ptr) {
			fplog(stderr, FATAL, "allocation of buffer of size %li failed!\n", 
				bs+pagesize+plug_max_slack_pre+plug_max_slack_post);
			cleanup(1); exit(18);
		}
		if (obuf)
			*obuf = ptr;
		ptr += plug_max_slack_pre+pagesize-1;
		ptr -= (unsigned long)ptr % pagesize;
	} else
		ptr += plug_max_slack_pre;
	memset(ptr-plug_max_slack_pre, 0, bs+plug_max_slack_pre+plug_max_slack_post);
	return ptr;
}

/** Heuristic: strings starting with - or a digit are numbers, ev.thing else a filename. A pure "-" is a filename. */
int is_filename(char* arg)
{
	if (!arg)
		return 0;
	if (!strcmp(arg, "-"))
		return 1;
	if (isdigit(arg[0]) || arg[0] == '-')
		return 0;
	return 1;
}

#ifdef __BIONIC__
#define strdupa(str)				\
({						\
	char* _mem = alloca(strlen(str)+1);	\
 	strcpy(_mem, str);			\
 	_mem;					\
 })
#endif

const char* retstrdupcat3(const char* dir, char dirsep, const char* inm)
{
	char* ibase = basename(strdupa(inm));
	const int dlen = strlen(dir) + (dirsep>0? 1: dirsep);
	char* ret = (char*)malloc(dlen + strlen(inm) + 1);
	strcpy(ret, dir);
	if (dirsep > 0) {
		ret[dlen-1] = dirsep;
		ret[dlen] = 0;
	}
	strcpy(ret+dlen, ibase);
	LISTAPPEND(freenames, ret, charp);
	return ret;
}
		

/** Fix output filename if it's a directory */
const char* dirappfile(const char* onm, opt_t *op)
{
	size_t oln = strlen(onm);
	if (!strcmp(onm, ".")) {
		char* ret = strdup(basename(strdupa(op->iname)));
		LISTAPPEND(freenames, ret, charp);
		return ret;
	}
	if (oln > 0) {
		char lastchr = onm[oln-1];
		if (lastchr == '/') 
			return retstrdupcat3(onm, 0, op->iname);
		else if ((lastchr == '.') &&
			  (oln > 1 && onm[oln-2] == '/'))
			return retstrdupcat3(onm, -1, op->iname);
		else if ((lastchr == '.') &&
			   (oln > 2 && onm[oln-2] == '.' && onm[oln-3] == '/'))
			return retstrdupcat3(onm, '/', op->iname);
		else { /* Not clear by name, so test */
			struct stat stbuf;
			int err = stat(onm, &stbuf);
			if (!err && S_ISDIR(stbuf.st_mode))
				return retstrdupcat3(onm, '/', op->iname);
		}
	}
	return onm;
}

char test_nocolor_term()
{
	char* term = getenv("TERM");
	if (!term) 
		return 1;
	if (!strcasecmp(term, "dumb") || !strcasecmp(term, "unknown")
		|| !strcasecmp(term, "net") || !strcasecmp(term, "vanilla"))
		return 1;
	if (!strcasecmp(term+strlen(term)-2, "-m") 
		|| !strcasecmp(term+strlen(term)-5, "-mono"))
		return 1;
	return 0;
}

void populate_faultlists(const char* arg, opt_t *op)
{
	if (!*arg) {
		fplog(stderr, FATAL, "Empty fault list specified\n");
		exit(11);
	}
	while (*arg) {
		const char* ptr = strchr(arg, ',');
		char rw;
		fault_in_t fault;
		fault.off = 0L;
		fault.off2 = 0L;
		int err = sscanf(arg, "%lu%c/%i", (unsigned long*)&fault.off, &rw, &fault.rep);
		if (err != 3) {
			int err = sscanf(arg, "%lu-%lu%c/%i", (unsigned long*)&fault.off, 
					 (unsigned long*)&fault.off2, &rw, &fault.rep);
			if (err != 4) {
				fplog(stderr, FATAL, "Could not parse fault spec %s\n", arg);
				exit(11);
			}
		} else
			fault.off2 = fault.off+1;
		if (fault.rep == 0)
			fault.rep = INT_MAX;
		if (rw == 'r')
			LISTAPPEND(read_faults, fault, fault_in_t);
		else if (rw == 'w')
			LISTAPPEND(write_faults, fault, fault_in_t);
		else {
			fplog(stderr, FATAL, "Need to specify r or w for X in offX/rep in %s\n", arg);
			exit(11);
		}
		if (ptr)
			arg = ptr+1;
		else
			arg = arg+strlen(arg);
		if (op->verbose)
			fplog(stderr, DEBUG, "Inject %c fault (%ix) for range %" LL "u-%" LL "u\n",
				rw, fault.rep, fault.off, fault.off2);
	}
	if (op->verbose)
		fplog(stderr, DEBUG, "Will inject %i/%i faults for read/write\n",
			LISTSIZE(read_faults, fault_in_t), LISTSIZE(write_faults, fault_in_t));
}


char* parse_opts(int argc, char* argv[], opt_t *op, dpopt_t *dop)
{
	int c;
	char* plugins = NULL;
	loff_t syncsz = -1;
	
  	/* defaults */
	memset(op, 0, sizeof(opt_t));
	memset(dop, 0, sizeof(dpopt_t));

	op->init_ipos = (loff_t)-INT_MAX; 
	op->init_opos = (loff_t)-INT_MAX; 

	op->nocol = test_nocolor_term();
	nocol = op->nocol;

#ifdef _SC_PAGESIZE
	op->pagesize = sysconf(_SC_PAGESIZE);
#else
#warning Cant determine pagesize, setting to 4kiB
	op->pagesize = 4096;
#endif
	pagesize = op->pagesize;

      	ofiles = NULL;

	int tmpfd = 0;

#ifdef LACK_GETOPT_LONG
	while ((c = getopt(argc, argv, ":rtTfihqvVwWaAdDkMRpPuc:b:B:m:e:s:S:l:L:o:y:z:Z:2:3:4:xY:F:C:")) != -1)
#else
	while ((c = getopt_long(argc, argv, ":rtTfihqvVwWaAdDkMRpPuc:b:B:m:e:s:S:l:L:o:y:z:Z:2:3:4:xY:F:C:", longopts, NULL)) != -1)
#endif
	{
		switch (c) {
			case 'r': op->reverse = 1; break;
			case 'R': op->i_repeat = 1; break;
			case 't': op->dotrunc = O_TRUNC; break;
			case 'T': op->trunclast = 1; break;
			case 'i': op->interact = 1; op->force = 0; break;
			case 'f': op->interact = 0; op->force = 1; break;
#ifdef O_DIRECT
			case 'd': op->o_dir_in  = O_DIRECT; break;
			case 'D': op->o_dir_out = O_DIRECT; break;
#endif
#ifdef HAVE_SPLICE
			case 'k': op->dosplice = 1; break;
#endif				  
			case 'p': op->preserve = 1; break;
			case 'P': op->falloc = 1; break;
			case 'a': op->sparse = 1; op->nosparse = 0; break;
			case 'A': op->nosparse = 1; op->sparse = 0; break;
			case 'w': op->abwrerr = 1; break;
			case 'W': op->avoidwrite = 1; break;
			case 'h': printlonghelp(); exit(0); break;
			case 'V': printversion(); exit(0); break;
			case 'v': op->quiet = 0; op->verbose = 1; break;
			case 'q': op->verbose = 0; op->quiet = 1; break;
			case 'c': op->nocol = !readbool(optarg); nocol = op->nocol; break;
			case 'C': op->maxkbs = (unsigned int)(readint(optarg)/1024); break;
			case 'b': op->softbs = (int)readint(optarg); break;
			case 'B': op->hardbs = (int)readint(optarg); break;
			case 'm': op->maxxfer = readint(optarg); break;
			case 'M': op->noextend = 1; break;
			case 'e': op->maxerr = (int)readint(optarg); break;
			case 'y': syncsz = readint(optarg); break;
			case 's': op->init_ipos = readint(optarg); break;
			case 'S': op->init_opos = readint(optarg); break;
			case 'l': op->lname = optarg;
				tmpfd = openfile(op->lname, O_WRONLY | O_CREAT | O_APPEND /* O_EXCL */);
				logfd = fdopen(tmpfd, "a");
				break;
			case 'L': plugins = optarg; break;
			case 'o': op->bbname = optarg; break;
			case 'x': op->extend = 1; break;
			case 'u': op->rmvtrim = 1; break;
			case 'F': populate_faultlists(optarg, op); break;
			case 'Y': do { ofile_t of; of.name = optarg; of.fd = -1; of.cdev = 0; LISTAPPEND(ofiles, of, ofile_t); } while (0); break;
			case 'z': dop->prng_libc = 1; if (is_filename(optarg)) dop->prng_sfile = optarg; else dop->prng_seed = readint(optarg); break;
			case 'Z': dop->prng_frnd = 1; if (is_filename(optarg)) dop->prng_sfile = optarg; else dop->prng_seed = readint(optarg); break;
			case '2': dop->prng_frnd = 1; if (is_filename(optarg)) dop->prng_sfile = optarg; else dop->prng_seed = readint(optarg); dop->bsim715 = 1; dop->bsim715_2 = 1; break;
			case '3': dop->prng_frnd = 1; if (is_filename(optarg)) dop->prng_sfile = optarg; else dop->prng_seed = readint(optarg); dop->bsim715 = 1; break;
			case '4': dop->prng_frnd = 1; if (is_filename(optarg)) dop->prng_sfile = optarg; else dop->prng_seed = readint(optarg); dop->bsim715 = 1; dop->bsim715_4 = 1; break;
			case ':': fplog(stderr, FATAL, "option %c requires an argument!\n", optopt); 
				shortusage();
				exit(11); break;
			case '?': fplog(stderr, FATAL, "unknown option %c!\n", optopt, argv[0]);
				shortusage();
				exit(11); break;
			default: fplog(stderr, FATAL, "your getopt() is buggy!\n");
				exit(255);
		}
	}
 
	if (dop->prng_libc)
		op->iname = "PRNG_libc";
	else if (dop->prng_frnd)
		op->iname = "PRNG_frnd";
	else if (optind < argc)
		op->iname = argv[optind++];

	if (optind < argc) 
		op->oname = argv[optind++];
	if (optind < argc) {
		fplog(stderr, FATAL, "spurious options: %s ...\n", argv[optind]);
		shortusage();
		if (logfd)
			fclose(logfd);
		exit(12);
	}
	/* Defaults for blocksizes */
	if (op->softbs == 0) {
		if (op->o_dir_in)
			op->softbs = DIO_SOFTBLOCKSIZE;
		else
			op->softbs = BUF_SOFTBLOCKSIZE;
	}
	if (op->hardbs == 0) {
		if (op->o_dir_in)
			op->hardbs = DIO_HARDBLOCKSIZE;
		else
			op->hardbs = BUF_HARDBLOCKSIZE;
	}

	if (!op->quiet)
		fplog(stderr, INFO, "Using softbs=%skiB, hardbs=%skiB\n", 
			fmt_kiB(op->softbs, !nocol), fmt_kiB(op->hardbs, !nocol));

	/* sanity checks */
#ifdef O_DIRECT
	if ((op->o_dir_in || op->o_dir_out) && op->hardbs < 512) {
		op->hardbs = 512;
		fplog(stderr, WARN, "O_DIRECT requires hardbs of at least %i!\n",
		      op->hardbs);
	}

	if (op->o_dir_in || op->o_dir_out)
		fplog(stderr, WARN, "We don't handle misalignment of last block w/ O_DIRECT!\n");
				
#endif

	if (op->softbs < op->hardbs) {
		fplog(stderr, WARN, "setting hardbs from %i to softbs %i!\n",
		      op->hardbs, op->softbs);
		op->hardbs = op->softbs;
	}

	/* Set sync frequency */
	/*
	if (syncsz == -1)
		op->syncfreq = 512;
	else */ 
	if (syncsz <= 0)
		op->syncfreq = 0;
	else
		op->syncfreq = (syncsz + op->softbs - 1) / op->softbs;

	return plugins;
}

/** Check passed options for sanity,
 *  fill in defaults (positions, names, ...)
 *  open files
 *  copy permissions (opt)
 *  fallocate (opt)
 *  truncate output file (opt)
 */

void sanitize_and_prepare(opt_t *op, dpopt_t *dop, fstate_t *fst, dpstate_t *dst, progress_t *prg)
{
	/* Have those been set by cmdline params? */
	if (op->init_ipos == (loff_t)-INT_MAX)
		op->init_ipos = 0;

	if (op->dosplice && op->avoidwrite) {
		fplog(stderr, WARN, "disable write avoidance (-W) for splice copy\n");
		op->avoidwrite = 0;
	}
	plug_max_slack_pre  += -plug_max_neg_slack_pre *((op->softbs+15)/16);
	plug_max_slack_post += -plug_max_neg_slack_post*((op->softbs+15)/16);
	fst->buf = zalloc_aligned_buf(op->softbs, &fst->origbuf);

	/* Optimization: Don't reread from /dev/zero over and over ... */
	if (!op->dosplice && !strcmp(op->iname, "/dev/zero")) {
		if (!op->i_repeat && op->verbose)
			fplog(stderr, INFO, "turning on repeat (-R) for /dev/zero\n");
		op->i_repeat = 1;
		if (op->reverse && !op->init_ipos && op->maxxfer)
			op->init_ipos = (op->init_opos != (loff_t)-INT_MAX && op->maxxfer > op->init_opos)? op->init_opos: op->maxxfer;
	}

	/* Properly append input basename if output name is dir */
	op->oname = dirappfile(op->oname, op);

	fst->identical = check_identical(op->iname, op->oname);

	if (fst->identical && op->dotrunc && !op->force) {
		fplog(stderr, FATAL, "infile and outfile are identical and trunc turned on!\n");
		cleanup(1); exit(14);
	}

	/* Open input and output files */
	if (dop->prng_libc || dop->prng_frnd) {
		init_random(op, dop, dst);
		fst->i_chr = 1; /* fst->ides = 0; */
		op->dosplice = 0; op->sparse = 0;
	} else {
		fst->ides = openfile(op->iname, O_RDONLY | op->o_dir_in);
		if (fst->ides < 0) {
			fplog(stderr, FATAL, "could not open %s: %s\n", op->iname, strerror(errno));
			cleanup(1); exit(22);
		}
	}
	/* Overwrite? */
	/* Special case '-': stdout */
	if (strcmp(op->oname, "-"))
		fst->odes = open64(op->oname, O_WRONLY | op->o_dir_out, 0640);
	else {
		fst->odes = 1;
		fst->o_chr = 1;
	}

	if (fst->odes > 1) 
		close(fst->odes);

	if (fst->odes > 1 && op->interact) {
		int a;
		do {
			fprintf(stderr, "dd_rescue: (question): %s existing %s [y/n]? ", 
				(op->dotrunc? "Overwrite": "Write into"), op->oname);
			a = toupper(fgetc(stdin)); //fprintf(stderr, "\n");
		} while (a != 'Y' && a != 'N');
		if (a == 'N') {
			fplog(stderr, FATAL, "exit on user request!\n");
			cleanup(1); exit(23);
		}
	}
	if (fst->o_chr && op->avoidwrite) {
		if (!strcmp(op->oname, "/dev/null")) {
			fplog(stderr, INFO, "Avoid writes to /dev/null ...\n");
			op->avoidnull = 1;
		} else {
			fplog(stderr, WARN, "Disabling -Write avoidance b/c ofile is not seekable\n");
			op->avoidwrite = 0;
		}
	}
		
	/* Sanity checks for op->rmvtrim */
	if ((fst->o_chr || fst->o_lnk || fst->o_blk) && op->rmvtrim) {
		fplog(stderr, FATAL, "Can't delete output file when it's not a normal file\n");
		cleanup(1); exit(23);
	}

	if (op->rmvtrim && !(op->i_repeat || dop->prng_libc || dop->prng_frnd || op->force)) {
		int a;
		do {
			fprintf(stderr, "dd_rescue: (question): really remove %s at the end [y/n]? ",
				op->oname);
			a = toupper(fgetc(stdin)); //fprintf(stderr, "\n");
		} while (a != 'Y' && a != 'N');
		if (a == 'N') {
			fplog(stderr, FATAL, "exit on user request!\n");
			op->rmvtrim = 0;
			cleanup(1); exit(23);
		}
	}

	if (fst->odes != 1) {
		int o_wr = (op->avoidwrite || (op->extend && plugins_loaded))? O_RDWR: O_WRONLY;
		if (op->avoidwrite) {
			if (op->dotrunc) {
				fplog(stderr, WARN, "Disable early trunc(-t) as we can't avoid writes otherwise.\n");
				op->dotrunc = 0;
			}
			fst->buf2 = zalloc_aligned_buf(op->softbs, &fst->origbuf2);
		}
		fst->odes = openfile(op->oname, o_wr | O_CREAT | op->o_dir_out /*| O_EXCL*/ | op->dotrunc);
	}

	if (fst->odes < 0) {
		fplog(stderr, FATAL, "%s: %s\n", op->oname, strerror(errno));
		cleanup(1); exit(24);
	}

	if (op->preserve)
		copyperm(fst->ides, fst->odes);
			
	check_seekable(fst->ides, &fst->i_chr, "input");
	check_seekable(fst->odes, &fst->o_chr, "output");
	
	if (!op->extend)
		sparse_output_warn(op, fst);
	if (fst->o_chr) {
		if (!op->nosparse)
			fplog(stderr, WARN, "Not using sparse writes for non-seekable output\n");
		op->nosparse = 1; op->sparse = 0; op->dosplice = 0;
		if (op->avoidwrite) {
			if (!strcmp(op->oname, "/dev/null")) {
				fplog(stderr, INFO, "Avoid writes to /dev/null ...\n");
				op->avoidnull = 1;
			} else {
				fplog(stderr, WARN, "Disabling -Write avoidance b/c ofile is not seekable\n");
				ZFREE(fst->origbuf2);
				op->avoidwrite = 0;
			}
		}
	}

	/* special case: op->reverse with op->init_ipos == 0 means op->init_ipos = EOF */
	if (op->reverse && op->init_ipos == 0) {
		op->init_ipos = lseek64(fst->ides, 0, SEEK_END);
		if (op->init_ipos == -1) {
			fplog(stderr, FATAL, "could not seek to end of file %s!\n", op->iname);
			perror("dd_rescue"); cleanup(1); exit(19);
		}
		if (op->verbose) 
			fprintf(stderr, DDR_INFO "ipos set to the end: %skiB\n", 
			        fmt_kiB(op->init_ipos, !nocol));
		/* if op->init_opos not set, assume same position */
		if (op->init_opos == (loff_t)-INT_MAX) 
			op->init_opos = op->init_ipos;
		/* if explicitly set to zero, assume end of _existing_ file */
		if (op->init_opos == 0) {
			op->init_opos = lseek64(fst->odes, 0, SEEK_END);
			if (op->init_opos == (loff_t)-1) {
				fplog(stderr, FATAL, "could not seek to end of file %s!\n", op->oname);
				perror("dd_rescue"); cleanup(1); exit(19);
			}
			/* if existing empty, assume same position */
			if (op->init_opos == 0)
				op->init_opos = op->init_ipos;
			if (op->init_opos == 0 && op->maxxfer && !fst->o_chr)
				op->init_opos = op->maxxfer;
			if (op->verbose) 
				fprintf(stderr, DDR_INFO "opos set to: %skiB\n",
					fmt_kiB(op->init_opos, !nocol));
    		}
	}

	/* if op->init_opos not set, assume same position */
	if (op->init_opos == (loff_t)-INT_MAX)
		op->init_opos = op->init_ipos;

	if (fst->identical) {
		fplog(stderr, WARN, "infile and outfile are identical!\n");
		if (op->init_opos > op->init_ipos && !op->reverse && !op->force) {
			fplog(stderr, WARN, "turned on reverse, as ipos < opos!\n");
			op->reverse = 1;
    		}
		if (op->init_opos < op->init_ipos && op->reverse && !op->force) {
			fplog(stderr, WARN, "turned off reverse, as opos < ipos!\n");
			op->reverse = 0;
		}
  	}

	if (fst->o_chr && op->init_opos != 0) {
		if (op->force)
			fplog(stderr, WARN, "ignore non-seekable output with opos != 0 due to --force\n");
		else {
			fplog(stderr, FATAL, "outfile not seekable, but opos !=0 requested!\n");
			cleanup(1); exit(19);
		}
	}
	if (fst->i_chr && op->init_ipos != 0) {
		fplog(stderr, FATAL, "infile not seekable, but ipos !=0 requested!\n");
		cleanup(1); exit(19);
	}
		
	if (op->dosplice) {
		if (!op->quiet)
			fplog(stderr, INFO, "splice copy, ignoring -a, -r, -y, -R, -W\n");
		op->reverse = 0;
	}

	if (op->noextend || op->extend) {
		if (output_length(op, fst) == -1) {
			fplog(stderr, FATAL, "asked to (not) extend output file but can't determine size\n");
			cleanup(1); exit(19);
		}
		if (op->extend)
			op->init_opos += fst->fin_opos;
	}
	input_length(op, fst);

	if (op->init_ipos < 0 || op->init_opos < 0) {
		fplog(stderr, FATAL, "negative position requested (%skiB)\n", 
			fmt_kiB(op->init_ipos, !nocol));
		cleanup(1); exit(25);
	}

#if defined(HAVE_FALLOCATE64) || defined(HAVE_LIBFALLOCATE)
	if (op->falloc && !fst->o_chr)
		do_fallocate(fst->odes, op->oname, op, fst);
#endif

	if (op->verbose)
		printinfo(stderr, op);

	if (dop->bsim715 && op->avoidwrite) {
		fplog(stderr, WARN, "won't avoid writes for -3\n");
		op->avoidwrite = 0;
		ZFREE(fst->buf2);
	}
	if (dop->bsim715 && fst->o_chr) {
		fplog(stderr, WARN, "triple overwrite with non-seekable output!\n");
	}
	if (op->reverse && op->trunclast)
		if (ftruncate(fst->odes, op->init_opos))
			fplog(stderr, WARN, "Could not truncate %s to %skiB: %s!\n",
				op->oname, fmt_kiB(op->init_opos, !nocol), strerror(errno));
	if (op->maxkbs) {
		/* Ev 8s, but only ev. second is synced, kB */
		int upd = 4096*op->maxkbs/op->softbs;
		if (!upd) {
			upd = 1;
			fplog(stderr, WARN, "Lower softbs (-b) to achieve low ratecontrol\n");
		}
		if (upd < updstat) {
			if (op->verbose)
				fplog(stderr, INFO, "Need to update stat every %i softbs\n", upd);
			updstat = upd;
		}
	}

}


int main(int argc, char* argv[])
{
	/* Options */
	static opt_t _opts;
	opt_t *opts = &_opts;

	/* Data protection */
	static dpopt_t _dpopts;
	dpopt_t *dpopts = &_dpopts;

	static dpstate_t _dpstate;
	dpstate_t *dpstate = &_dpstate;

	/* State */
	static fstate_t _fstate;
	fstate_t *fstate = &_fstate;

	/* Progress */
	static progress_t _progress;
	progress_t *progress = &_progress;

	/* Repeat zero optimization */
	static repeat_t _repeat;
	repeat_t *repeat = &_repeat;

	/* Initialize */
	memset(dpstate, 0, sizeof(dpstate_t));
	memset(fstate, 0, sizeof(fstate_t));
	memset(progress, 0, sizeof(progress_t));
	memset(repeat, 0, sizeof(repeat_t));
	
	fstate->ides = -1; fstate->odes = -1;

	detect_cpu_cap();

	set_eptrs(opts, fstate, progress, repeat, dpopts, dpstate);

#if 0
	if (sizeof(loff_t) <= 4/* || sizeof(size_t) <= 4*/)
		fplog(stderr, WARN, "Limited range: off_t %i/%i bits, size_t %i bits%\n", 
			8*sizeof(off_t), 8*sizeof(loff_t), 8*sizeof(size_t));
#endif
	char* plugins = parse_opts(argc, argv, opts, dpopts);

#ifdef USE_LIBDL
	if (plugins)
		load_plugins(plugins, opts);
	if (plug_not_sparse && opts->sparse) {
		fplog(stderr, FATAL, "not all plugins handle -a/--sparse!\n");
		unload_plugins();
		exit(13);
	}
	if (plug_not_sparse && !opts->nosparse) {
		fplog(stderr, WARN, "some plugins don't handle sparse, enabled -A/--nosparse!\n");
		opts->nosparse = 1;
	}
	/* TODO: Check for supports_seek of all plugins instead */
	if (plug_no_seek && opts->reverse) {
		fplog(stderr, FATAL, "Plugins currently don't handle reverse\n");
		unload_plugins();
		exit(13);
	}
	if (plugins_loaded && opts->dosplice) {
		fplog(stderr, FATAL, "Plugins can't handle splice\n");
		unload_plugins();
		exit(13);
	}
#else
	if (plugins) {
		fplog(stderr, FATAL, "Can not handle plugins in static build!\n");
		exit(12);
	}
#endif

	if (no_input || no_output) {
		fplog(stderr, FATAL, "plugins that replace in/output not yet supported!\n");
		shortusage();
		unload_plugins();
		exit(12);
	}

	if (!opts->iname || !opts->oname) {
		fplog(stderr, FATAL, "both input and output files have to be specified!\n");
		shortusage();
		unload_plugins();
		exit(12);
	}

	sanitize_and_prepare(opts, dpopts, fstate, dpstate, progress);

	LISTTYPE(ofile_t) *of;
	LISTFOREACH(ofiles, of) {
		int id;
		ofile_t *oft = &(LISTDATA(of));
		oft->name = dirappfile(oft->name, opts);
		id = check_identical(opts->iname, oft->name);
		if (id)
			fplog(stderr, WARN, "Input file and secondary output file %s are identical!\n", oft->name);
		oft->fd = openfile(oft->name, (opts->avoidwrite? O_RDWR: O_WRONLY) | O_CREAT | opts->o_dir_out | opts->dotrunc);
		check_seekable(oft->fd, &(oft->cdev), NULL);
		if (opts->preserve)
			copyperm(fstate->ides, oft->fd);
#if defined(HAVE_FALLOCATE64) || defined(HAVE_LIBFALLOCATE)
		if (opts->falloc && !oft->cdev)
			do_fallocate(oft->fd, oft->name, opts, fstate);
#endif
		if (opts->reverse && opts->trunclast)
			if (ftruncate(oft->fd, opts->init_opos))
				fplog(stderr, WARN, "Could not truncate %s to %skiB: %s!\n",
					oft->name, fmt_kiB(opts->init_opos, !nocol), strerror(errno));
	}

	/* Install signal handler */
	signal(SIGHUP , breakhandler);
	signal(SIGINT , breakhandler);
	signal(SIGTERM, breakhandler);
	/* Used to signal clean abort from plugins */
	signal(SIGQUIT, breakhandler);

	/* Save time and start to work */
	fstate->ipos = opts->init_ipos;
	fstate->opos = opts->init_opos;
	int err = 0;

	startclock = clock();
	gettimeofday(&starttime, NULL);
	memcpy(&lasttime, &starttime, sizeof(lasttime));

	if (!opts->quiet) {
		scrollup = 0;
		printstatus(stderr, 0, opts->softbs, 0, opts, fstate, progress, dpopts);
	}

	if (dpopts->bsim715) {
		err = tripleoverwrite(opts->maxxfer, opts, fstate, progress, repeat, dpopts, dpstate);
	} else {
		fadvise(0, opts, fstate, progress);
#ifdef HAVE_SPLICE
		if (opts->dosplice)
			err = copyfile_splice(opts->maxxfer, opts, fstate, progress, repeat, dpopts, dpstate);
		else 
#endif
		{
			call_plugins_open(opts, fstate);
			if (opts->softbs > opts->hardbs)
				err = copyfile_softbs(opts->maxxfer, opts, fstate, progress, repeat, dpopts, dpstate);
			else
				err = copyfile_hardbs(opts->maxxfer, opts, fstate, progress, repeat, dpopts, dpstate);
		}
	}

	err += fstate->nrerr;
	gettimeofday(&currenttime, NULL);
	printreport(opts, fstate, progress, dpopts);
	fadvise(1, opts, fstate, progress);
	err += cleanup(0);
	if (int_by == SIGQUIT)
		++err;
	if (err && !opts->quiet)
		fplog(stderr, WARN, "There were %i errors! \n", err);
	if (logfd)
		fclose(logfd);
	if (interrupted && int_by != SIGQUIT)
		return 128+int_by;
	else
		return err;
}
