/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdinstruments probes — list every DTrace probe (built-in or USDT)
 * the kernel currently knows about.  --provider restricts to one
 * provider; --pid attaches to a process first so its USDT providers
 * surface; --regex post-filters the full names; --json emits JSONL.
 */

#include <err.h>
#include <getopt.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dtrace.h>

#include "otelexport.h"
#include "bsdinstruments.h"

static void __dead2
probes_usage(void)
{

	fprintf(stderr,
	    "usage: bsdinstruments probes [--provider name] [--regex re]\n"
	    "           [--pid n] [--json]\n");
	exit(2);
}

struct probes_ctx {
	regex_t		*regex;
	int		 json;
	size_t		 count;
};

static int
probe_callback(dtrace_hdl_t *dtp __unused, const dtrace_probedesc_t *pdp,
    void *arg)
{
	struct probes_ctx *ctx = arg;
	struct oe_buf b;
	char full[DTRACE_FULLNAMELEN];

	snprintf(full, sizeof(full), "%s:%s:%s:%s", pdp->dtpd_provider,
	    pdp->dtpd_mod, pdp->dtpd_func, pdp->dtpd_name);
	if (ctx->regex != NULL &&
	    regexec(ctx->regex, full, 0, NULL, 0) != 0)
		return (0);
	if (ctx->json) {
		oe_buf_init(&b);
		oe_buf_appendf(&b, "{\"fullName\":\"");
		oe_buf_appendjson(&b, full);
		oe_buf_appendf(&b, "\",\"function\":\"");
		oe_buf_appendjson(&b, pdp->dtpd_func);
		oe_buf_appendf(&b, "\",\"id\":%u,\"module\":\"",
		    (unsigned)pdp->dtpd_id);
		oe_buf_appendjson(&b, pdp->dtpd_mod);
		oe_buf_appendf(&b, "\",\"name\":\"");
		oe_buf_appendjson(&b, pdp->dtpd_name);
		oe_buf_appendf(&b, "\",\"provider\":\"");
		oe_buf_appendjson(&b, pdp->dtpd_provider);
		oe_buf_appendstr(&b, "\"}");
		printf("%s\n", b.data != NULL ? b.data : "{}");
		oe_buf_free(&b);
	} else
		printf("%s\n", full);
	ctx->count++;
	return (0);
}

int
cmd_probes(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "provider", required_argument, NULL, 'P' },
		{ "regex", required_argument, NULL, 'r' },
		{ "pid", required_argument, NULL, 'p' },
		{ "json", no_argument, NULL, 'j' },
		{ NULL, 0, NULL, 0 }
	};
	struct probes_ctx ctx;
	struct ps_prochandle *proc;
	dtrace_probedesc_t desc, *descp;
	dtrace_hdl_t *dtp;
	regex_t regex;
	const char *provider, *pattern;
	char spec[DTRACE_FULLNAMELEN];
	pid_t pid;
	int ch, error, have_pid, json, ret;

	provider = NULL;
	pattern = NULL;
	have_pid = 0;
	pid = 0;
	json = 0;
	while ((ch = getopt_long(argc, argv, "h", opts, NULL)) != -1) {
		switch (ch) {
		case 'P':
			provider = optarg;
			break;
		case 'r':
			pattern = optarg;
			break;
		case 'p':
			have_pid = 1;
			pid = (pid_t)strtol(optarg, NULL, 10);
			break;
		case 'j':
			json = 1;
			break;
		default:
			probes_usage();
		}
	}
	if (optind != argc)
		probes_usage();

	/* Compile the regex before opening a libdtrace handle. */
	memset(&ctx, 0, sizeof(ctx));
	ctx.json = json;
	if (pattern != NULL) {
		error = regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB);
		if (error != 0) {
			char errbuf[128];

			regerror(error, &regex, errbuf, sizeof(errbuf));
			errx(2, "invalid --regex pattern: %s", errbuf);
		}
		ctx.regex = &regex;
	}

	dtp = dtrace_open(DTRACE_VERSION, 0, &error);
	if (dtp == NULL) {
		fprintf(stderr, "bsdinstruments probes: failed to open "
		    "libdtrace (%s). Are you root?\n",
		    dtrace_errmsg(NULL, error));
		if (ctx.regex != NULL)
			regfree(&regex);
		return (1);
	}

	ret = 0;
	descp = NULL;
	if (provider != NULL) {
		snprintf(spec, sizeof(spec), "%s:::", provider);
		if (dtrace_str2desc(dtp, DTRACE_PROBESPEC_NAME, spec,
		    &desc) != 0) {
			fprintf(stderr, "bsdinstruments probes: invalid "
			    "provider '%s': %s\n", provider,
			    dtrace_errmsg(dtp, dtrace_errno(dtp)));
			ret = 1;
			goto out;
		}
		descp = &desc;
	}

	/*
	 * Grab the process first (if requested) so its USDT providers
	 * are loaded into the handle, and hold it across the listing.
	 */
	proc = NULL;
	if (have_pid) {
		proc = dtrace_proc_grab(dtp, pid, 0);
		if (proc == NULL) {
			fprintf(stderr, "bsdinstruments probes: failed to "
			    "grab pid %d: %s\n", (int)pid,
			    dtrace_errmsg(dtp, dtrace_errno(dtp)));
			ret = 1;
			goto out;
		}
	}

	if (dtrace_probe_iter(dtp, descp, probe_callback, &ctx) != 0) {
		fprintf(stderr, "bsdinstruments probes: probe listing "
		    "failed: %s\n", dtrace_errmsg(dtp, dtrace_errno(dtp)));
		ret = 1;
	}

	if (proc != NULL) {
		dtrace_proc_continue(dtp, proc);
		dtrace_proc_release(dtp, proc);
	}

	if (!json)
		fprintf(stderr, "\n%zu probe%s\n", ctx.count,
		    ctx.count == 1 ? "" : "s");

out:
	dtrace_close(dtp);
	if (ctx.regex != NULL)
		regfree(&regex);
	return (ret);
}
