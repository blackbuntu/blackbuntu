/** \file ddr_ctrl.h
 *  \brief
 *  Declares the structures that control the program's
 *  behaviour and tracks it's state
 *
 *  (c) Kurt Garloff <kurt@garloff.de>, 5/2014
 *  License: GNU GPLv2 or v3
 */

#ifndef _DDR_CTRL_H
#define _DDR_CTRL_H

/* Options */
typedef struct _opt_t {
	const char *iname, *oname, *lname, *bbname;
	loff_t init_ipos, init_opos;
	loff_t maxxfer;
	unsigned int softbs, hardbs, syncfreq;
	unsigned int pagesize;
	/* Flags */
	int o_dir_in, o_dir_out;
	int dotrunc;
	int maxerr;
	char trunclast, reverse, abwrerr, sparse, nosparse;
	char verbose, quiet, interact, force, nocol;
	char preserve, falloc, dosplice;
	char noextend, avoidwrite, avoidnull;
	char extend, rmvtrim, i_repeat;
	unsigned int maxkbs; /* from 1kB/s to 4TB/s */
} opt_t;
extern char nocol;

/* Data protection */
typedef struct _dpopt_t {
	char* prng_sfile;
	int  prng_seed;
	char prng_libc, prng_frnd;
	char bsim715, bsim715_4, bsim715_2, bsim715_2ndpass;
} dpopt_t;

typedef struct _dpstate_t {
	void *prng_state, *prng_state2;
} dpstate_t;

/* State */
typedef struct _fstate_t {
	loff_t ipos, opos;
	int ides, odes;
	unsigned char *buf, *buf2, *origbuf, *origbuf2;
	loff_t fin_ipos, fin_opos, estxfer;
	char i_chr, o_chr, o_blk, o_lnk;
	int nrerr;
	char identical;
} fstate_t;

/* Progress */
typedef struct _progress_t {
	loff_t xfer, lxfer, sxfer, fxfer, axfer;
} progress_t;

/* Repeat zero optimization */
typedef struct _repeat_t {
	size_t i_rep_zero;
	char i_rep_init;
} repeat_t;
#endif


