/* Data structures of dd_rescue2 needed for plugins */

#ifndef _DD_RESCUE2_H
#define _DD_RESCUE2_H 1

//#define _GNU_SOURCE
#define _LARGEFILE_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>

typedef struct struct_dd_r_file {
	char* name;
	off_t pos, len;
	int des, is_chr;
	void *handle;
} dd_r_file;

typedef struct struct_dd_r_ctrl_par {
	int hardbs, softbs, syncfreq, maxerr;
	off_t maxxfer;
	int reverse:1, dotrunc:1, abwrerr:1, preserve:1;
	int sparse:1, nosparse:1, falloc:1, dosplice:1;
	int o_dir_in:1, o_dir_out:1, identical: 1;
	int verbose:1, quiet:1, interact:1, force:1;
} dd_r_ctrl_par;

typedef struct struct_dd_r_status {
	off_t xfer, sxfer, errxfer, estxfer;
	int nrerr;
} dd_r_status;

//extern void* dd_r_buf;

/* Semantics: prepare and finish are additive, open, pread and pwrite
 * will be overwritten
 */
typedef int (*dd_r_open_read)(dd_r_file *infile, dd_r_ctrl_par *par);
typedef int (*dd_r_prepare_read)(dd_r_file *infile, dd_r_ctrl_par *par);
typedef int (*dd_r_pread)(void* buf, dd_r_file *infile, dd_r_ctrl_par *par);
typedef int (*dd_r_finish_read)(dd_r_file *infile, dd_r_ctrl_par *par);

typedef int (*dd_r_open_write)(dd_r_file *outfile, dd_r_ctrl_par *par);
typedef int (*dd_r_prepare_write)(dd_r_file *outfile, dd_r_ctrl_par *par);
typedef int (*dd_r_pwrite)(void* buf, dd_r_file *outfile, dd_r_ctrl_par *par);
typedef int (*dd_r_finish_write)(dd_r_file *outfile, dd_r_ctrl_par *par);

int fplog(FILE* const file, const char * const fmt, ...);

struct dd_r_plugin_ops {
	dd_r_open_read d_open_r;
	dd_r_prepare_read d_prep_r;
	dd_r_pread d_pread;
	dd_r_finish_read d_fin_r;

	dd_r_open_write d_open_w;
	dd_r_prepare_write d_prep_w;
	dd_r_pwrite d_pwrite;
	dd_r_finish_write d_fin_w;
};


#endif

