/* libddr_null.c
 *
 * plugin for dd_rescue, doing nothing (except optionally setting changes_length)
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 2014
 * License: GNU GPLv2 or v3
 */

#include "ddr_plugin.h"
#include "ddr_ctrl.h"
#include <string.h>
#include <stdlib.h>

/* fwd decl */
extern ddr_plugin_t ddr_plug;

typedef struct _null_state {
	int seq;
	char debug;
} null_state;

#define FPLOG(lvl, fmt, args...) \
	plug_log(ddr_plug.logger, stderr, lvl, fmt, ##args)

const char* null_help = "The null plugin does nothing ...\n"
			"Options: debug:[no]lnchange:[no]change. [no]lnchange indicates that the length\n"
		        " may [not] be changed by ddr_null; [no]change indicates that the contents may\n"
			" [not] be changed by ddr_null.	(Both is not true, but influences the behavior\n"
			" of other plugins)\n";

int null_plug_init(void **stat, char* param, int seq, const opt_t *opt)
{
	null_state *state = (null_state*)malloc(sizeof(null_state));
	*stat = (void*)state;
	memset(state, 0, sizeof(null_state));
	state->seq = seq;
	while (param) {
		char* next = strchr(param, ':');
		if (next)
			*next++ = 0;
		if (!strcmp(param, "help"))
			FPLOG(INFO, "%s", null_help);
		else if (!strcmp(param, "lnchange"))
			ddr_plug.changes_output_len = 1;
		else if (!strcmp(param, "lnchg"))
			ddr_plug.changes_output_len = 1;
		/* Do we need this if loaded multiple times? */
		else if (!strcmp(param, "nolnchange"))
			ddr_plug.changes_output_len = 0;
		else if (!strcmp(param, "nolnchg"))
			ddr_plug.changes_output_len = 0;
		else if (!strcmp(param, "change"))
			ddr_plug.changes_output = 1;
		else if (!strcmp(param, "chg"))
			ddr_plug.changes_output = 1;
		/* Do we need this if loaded multiple times? */
		else if (!strcmp(param, "nochange"))
			ddr_plug.changes_output = 0;
		else if (!strcmp(param, "nochg"))
			ddr_plug.changes_output = 0;
		else if (!strcmp(param, "debug"))
			state->debug = 1;
		else {
			FPLOG(FATAL, "plugin doesn't understand param %s\n",
				param);
			return 1;

		}
		param = next;
	}
	/* If the length changes, so does the contents ... */
	if (ddr_plug.changes_output_len && !ddr_plug.changes_output)
		FPLOG(WARN, "Change indication for length without contents change?\n");
	return 0;
}

int null_plug_release(void **stat)
{
	if (!stat || !*stat)
		return -1;
	//null_state *state = (null_state*)*stat;
	free(*stat);
	return 0;
}

int null_open(const opt_t *opt, int ilnchg, int olnchg, int ichg, int ochg,
	      unsigned int totslack_pre, unsigned int totslack_post,
	      const fstate_t *fst, void **stat)
{
	return 0;
}

#if __WORDSIZE == 64
#define LL "l"
#elif __WORDSIZE == 32
#define LL "ll"
#else
#error __WORDSIZE unknown
#endif


unsigned char* null_blk_cb(fstate_t *fst, unsigned char* bf, 
			   int *towr, int eof, int *recall, void **stat)
{
	/* TODO: Could actually add debugging output here if wanted ... */
	null_state *state = (null_state*)*stat;
	if (state->debug) 
		FPLOG(DEBUG, "Block ipos %" LL "i opos %" LL "i with %i bytes %s\n",
			fst->ipos, fst->opos, *towr, (eof? "EOF": ""));
	return bf;
}

int null_close(loff_t ooff, void **stat)
{
	return 0;
}

ddr_plugin_t ddr_plug = {
	.name = "null",
	.needs_align = 0,
	.handles_sparse = 1,
	.init_callback  = null_plug_init,
	.open_callback  = null_open,
	.block_callback = null_blk_cb,
	.close_callback = null_close,
	.release_callback = null_plug_release,
};


