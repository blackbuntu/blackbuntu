/** ddr_plugin.h
 *
 * Data structure to register dd_rescue plugins
 */

#ifndef _DDR_PLUGIN_H
#define _DDR_PLUGIN_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#if 0
typedef struct _opt_t opt_t;
typedef struct _fstate_t fstate_t;
typedef struct _progress_t progress_t;
#else
#include "ddr_ctrl.h"
#endif

/** init callback parameters:
 * opaque handle, parameters from commandline, sequence in filter chain,
 * pointer to options.
 * Return value: 0 = OK, -x = ERROR
 */
typedef int (_init_callback)(void **stat, char* param, int seq, const opt_t *opt);
/** open_callback parameters: pointer to options, four flags telling the
 * 	plugin whether length, and/or contents of the stream are changed
 * 	by other plugins before (i) or after (o) this one,
 * 	required extra buffer memory before and after the main buffer
 * 	and the opaque handle
 * 	Return value: 0 = OK, -x = ERROR, +x = Bytes consumed from input file.
 */
typedef int (_open_callback)(const opt_t *opt, int ilnchange, int olnchange, 
			     int ichange, int ochange,
			     unsigned int totslack_pre, unsigned int totslack_post,
			     const fstate_t *fst, void **stat);
/** block_callback parameters: file state (contains file descriptors, positions,
 * 	...), buffer to be written (can be modified),
 *  	number of bytes to be written (can be null and can be modified), 
 *  	eof flag, recall request(output!), handle.
 *  Will be called with eof=1 exactly once at the end.
 *  Return value: buffer to be really written.
 */
typedef unsigned char* (_block_callback)(fstate_t *fst, unsigned char* bf, 
					 int *towr, int eof, int *recall, 
					 void **stat);
/** close_callback parameters: final output position and handle.
 * Return value: 0 = OK, -x = ERROR
 * close_callback is called before files are fsynced and closed
 */
typedef int (_close_callback)(loff_t ooff, void **stat);

/** release_callback: Called before the plugin is unloaded
 * (New in 1.47! Previously, deallocation was supposed to happen
 * in the close_callback
 */
typedef int (_release_callback)(void **stat);


enum ddrlog_t { NOHDR=0, DEBUG, INFO, WARN, FATAL, GOOD, INPUT };
typedef int (_fplog_upcall)(FILE* const f, enum ddrlog_t logpre, 
			    const char* const prefix, const char* const fmt, 
			    va_list va);

typedef struct _plug_logger {
	_fplog_upcall *vfplog;
	char prefix[24];
} plug_logger_t;


static inline 
int plug_log(plug_logger_t *logger, FILE* const f, enum ddrlog_t logpre,
		const char* const fmt, ...)
{
	va_list vag;
	va_start(vag, fmt);
	int ret = logger->vfplog(f, logpre, logger->prefix, fmt, vag);
	va_end(vag);
	return ret;
}

typedef struct _ddr_plugin {
	/* Will be filled by loader */
	const char* name;
	/* Amount of extra bytes required in buffer, negative => softbs*slackspace/16 */
	int slack_pre;
	int slack_post;
	/* Alignment need */
	unsigned int needs_align;
	/* Handles sparse */
	char handles_sparse:1;
	/* Transforms to unsparse */
	char makes_unsparse:1;
	/* Transforms output */
	char changes_output:1;
	/* Output transformation changes length -- breaks sparse detection on subsequent plugins */
	char changes_output_len:1;
	/* Support random access / reverse */
	char supports_seek:1;
	/* Don't use first non-option arg as input */
	char replaces_input:1;
	/* Don't use second non-option arg as output */
	char replaces_output:1;
	/* Internal individual state of plugin */
	void* state;
	/* Will be called after loading the plugin */
	 _init_callback * init_callback;
	/* Will be called after opening the input and output files */
	 _open_callback * open_callback;
	/* Will be called before a block is written */
	_block_callback *block_callback;
	/* Will be called before fsyncing and closing the output file */
	_close_callback *close_callback;
	/* Will be called before unloading */
	_release_callback *release_callback;
	/* Callback filled by the loader: Logging */
	//_fplog_upcall *fplog;
	plug_logger_t *logger;
	/* Filled by loader: Parameters */
	char* param;
} ddr_plugin_t;
#endif	/* _DDR_PLUGIN_H */
