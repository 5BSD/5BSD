/*-
 * Copyright (c) 2026 Kory Heard
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * bsdtrace trace — attach HWT tracing to a running process.
 *
 * Attaches thread-mode tracing to the given PID and streams
 * records until interrupted (Ctrl-C), duration elapsed, or
 * the target exits.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bsdtrace.h"

#define	DEFAULT_BUFSIZE		"64m"
#define	MAX_POLL_RECORDS	256

/* Global flag set by SIGINT handler. */
static volatile sig_atomic_t trace_interrupted;

/*
 * True when the target has exited but has not been reaped —
 * kill(pid, 0) still succeeds for zombies.
 */
static bool
proc_is_zombie(pid_t pid)
{
	struct kinfo_proc kp;
	size_t len;
	int mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = (int)pid;
	len = sizeof(kp);
	if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0 || len == 0)
		return (true);	/* gone entirely */
	return (kp.ki_stat == SZOMB);
}

static void
sigint_handler(int sig __unused)
{

	trace_interrupted = 1;
}

/*
 * Strict numeric option parsers: reject garbage, trailing junk, and
 * out-of-range values instead of atoi()'s silent zero.
 */
static int
parse_long_opt(const char *s, long minval, long maxval, long *out)
{
	char *end;
	long v;

	errno = 0;
	v = strtol(s, &end, 10);
	if (end == s || *end != '\0' || errno == ERANGE ||
	    v < minval || v > maxval)
		return (-1);
	*out = v;
	return (0);
}

static int
parse_duration_opt(const char *s, double *out)
{
	char *end;
	double v;

	errno = 0;
	v = strtod(s, &end);
	if (end == s || *end != '\0' || errno == ERANGE ||
	    !isfinite(v) || v < 0)
		return (-1);
	*out = v;
	return (0);
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

int
cmd_trace(int argc, char **argv)
{
	struct bsdtrace_record records[MAX_POLL_RECORDS];
	struct trace_state ts;
	struct hwt_ctx ctx;
	struct timespec start, now;
	char pathbuf[1024];
	struct meta_writer *meta;
	char pt_path[64];
	char meta_path[MAXPATHLEN];
	const char *pt_output;
	enum bsdtrace_fmt fmt;
	const char *bufsize_str;
	const char *backend_name;
	const char *execname;
	char *detected_backend;
	double duration;
	size_t bufsize;
	pid_t pid;
	struct ip_filter filter;
	struct range_spec range_specs[2];
	int nrange_specs;
	int tid;
	bool trace_all_threads;
	int requested_tids[MAX_THREADS];
	int nrequested_tids;
	int maxrecords;
	int totalrecords;
	int empty_drains;
	int nrecs;
	int ch, i;
	int psb_freq;
	int mtc_freq_cli;
	int cyc_thresh_cli;
	bool timing;
	bool ptwrite;
	bool os_trace;
	bool dryrun;
	char **filter_funcs;
	int nfilter_funcs;
	struct pt_decode_opts dopts;
	struct pt_capture_env env;
	bool pause_on_mmap;
	bool target_gone;

	fmt = FMT_TEXT;
	bufsize_str = DEFAULT_BUFSIZE;
	backend_name = NULL;
	detected_backend = NULL;
	pt_output = NULL;
	duration = 0;
	maxrecords = 0;
	tid = 0;
	trace_all_threads = false;
	nrequested_tids = 0;
	memset(&filter, 0, sizeof(filter));
	nrange_specs = 0;
	psb_freq = 0;
	mtc_freq_cli = 0;
	cyc_thresh_cli = 0;
	timing = false;
	ptwrite = false;
	os_trace = false;
	dryrun = false;
	filter_funcs = NULL;
	nfilter_funcs = 0;
	pause_on_mmap = false;

	optind = 1;
	while ((ch = getopt(argc, argv, "f:b:s:d:t:m:o:r:T:P:M:Y:F:hnpCWK")) != -1) {
		switch (ch) {
		case 'f':
			if (strcmp(optarg, "json") == 0)
				fmt = FMT_JSON;
			else if (strcmp(optarg, "text") == 0)
				fmt = FMT_TEXT;
			else if (strcmp(optarg, "profile") == 0)
				fmt = FMT_PROFILE;
			else if (strcmp(optarg, "tree") == 0)
				fmt = FMT_TREE;
			else if (strcmp(optarg, "collapsed") == 0)
				fmt = FMT_COLLAPSED;
			else if (strcmp(optarg, "speedscope") == 0)
				fmt = FMT_SPEEDSCOPE;
			else if (strcmp(optarg, "callers") == 0)
				fmt = FMT_CALLERS;
			else {
				fprintf(stderr,
				    "bsdtrace trace: unknown format '%s'\n",
				    optarg);
				return (1);
			}
			break;
		case 'b':
			backend_name = optarg;
			break;
		case 's':
			bufsize_str = optarg;
			break;
		case 'd':
		case 't':
			/* 0 (the default) means trace until Ctrl-C. */
			if (parse_duration_opt(optarg, &duration) != 0) {
				fprintf(stderr,
				    "bsdtrace trace: invalid duration '%s'\n",
				    optarg);
				return (1);
			}
			break;
		case 'm': {
			long v;

			if (parse_long_opt(optarg, 0, INT_MAX, &v) != 0) {
				fprintf(stderr,
				    "bsdtrace trace: invalid record count "
				    "'%s'\n", optarg);
				return (1);
			}
			maxrecords = (int)v;
			break;
		}
		case 'o':
			pt_output = optarg;
			break;
		case 'r':
			if (nrange_specs >= 2) {
				fprintf(stderr,
				    "bsdtrace trace: max 2 IP ranges\n");
				return (1);
			}
			if (parse_range_spec(optarg,
			    &range_specs[nrange_specs]) != 0)
				return (1);
			nrange_specs++;
			break;
		case 'T':
			if (strcmp(optarg, "all") == 0) {
				tid = 0;
				trace_all_threads = true;
			} else if (strchr(optarg, ',') != NULL) {
				char *tstr, *tok, *saveptr;
				long v;

				tstr = strdup(optarg);
				if (tstr == NULL)
					err(1, NULL);
				nrequested_tids = 0;
				tok = strtok_r(tstr, ",", &saveptr);
				while (tok != NULL &&
				    nrequested_tids < MAX_THREADS) {
					if (parse_long_opt(tok, 0, INT_MAX,
					    &v) != 0) {
						fprintf(stderr,
						    "bsdtrace trace: invalid "
						    "thread id '%s'\n", tok);
						free(tstr);
						return (1);
					}
					requested_tids[nrequested_tids++] =
					    (int)v;
					tok = strtok_r(NULL, ",", &saveptr);
				}
				if (tok != NULL)
					fprintf(stderr,
					    "warning: -T lists more than %d "
					    "thread ids; excess ignored\n",
					    MAX_THREADS);
				free(tstr);
				if (nrequested_tids < 1) {
					fprintf(stderr,
					    "bsdtrace trace: -T requires "
					    "at least one thread id\n");
					return (1);
				}
				tid = requested_tids[0];
			} else {
				long v;

				if (parse_long_opt(optarg, 0, INT_MAX,
				    &v) != 0) {
					fprintf(stderr,
					    "bsdtrace trace: invalid thread "
					    "id '%s'\n", optarg);
					return (1);
				}
				tid = (int)v;
			}
			break;
		case 'P': {
			long v;

			if (parse_long_opt(optarg, 0, 15, &v) != 0) {
				fprintf(stderr,
				    "bsdtrace trace: psb-freq must be "
				    "0-15\n");
				return (1);
			}
			psb_freq = (int)v;
			break;
		}
		case 'M': {
			long v;

			if (parse_long_opt(optarg, 1, 15, &v) != 0) {
				fprintf(stderr,
				    "bsdtrace trace: mtc-freq must be "
				    "1-15\n");
				return (1);
			}
			mtc_freq_cli = (int)v;
			break;
		}
		case 'Y': {
			long v;

			if (parse_long_opt(optarg, 1, 15, &v) != 0) {
				fprintf(stderr,
				    "bsdtrace trace: cyc-thresh must be "
				    "1-15\n");
				return (1);
			}
			cyc_thresh_cli = (int)v;
			break;
		}
		case 'C':
			timing = true;
			break;
		case 'W':
			ptwrite = true;
			break;
		case 'K':
			os_trace = true;
			break;
		case 'F': {
			char *fstr, *tok, *saveptr;
			int j;

			/* A repeated -F replaces the earlier list. */
			for (j = 0; j < nfilter_funcs; j++)
				free(filter_funcs[j]);
			free(filter_funcs);
			filter_funcs = NULL;
			fstr = strdup(optarg);
			if (fstr == NULL)
				err(1, NULL);
			nfilter_funcs = 0;
			tok = strtok_r(fstr, ",", &saveptr);
			while (tok != NULL) {
				nfilter_funcs++;
				tok = strtok_r(NULL, ",", &saveptr);
			}
			free(fstr);
			filter_funcs = calloc(nfilter_funcs, sizeof(char *));
			if (filter_funcs == NULL && nfilter_funcs > 0)
				err(1, NULL);
			nfilter_funcs = 0;
			fstr = strdup(optarg);
			if (fstr == NULL)
				err(1, NULL);
			tok = strtok_r(fstr, ",", &saveptr);
			while (tok != NULL) {
				filter_funcs[nfilter_funcs] = strdup(tok);
				if (filter_funcs[nfilter_funcs] == NULL)
					err(1, NULL);
				nfilter_funcs++;
				tok = strtok_r(NULL, ",", &saveptr);
			}
			free(fstr);
			break;
		}
		case 'n':
			dryrun = true;
			break;
		case 'p':
			pause_on_mmap = true;
			break;
		case 'h':
			fprintf(stderr,
			    "usage: bsdtrace trace [options] pid\n"
			    "\n"
			    "Attach to a running process and trace it.\n"
			    "\n"
			    "Options:\n"
			    "  -f format   Output format: text, json, profile, tree, or collapsed\n"
			    "  -d seconds  Trace duration (0 = until Ctrl-C, default)\n"
			    "  -s size     Trace buffer size, e.g. 8m, 64m (default: 64m)\n"
			    "  -o file     Output path for .pt data (default: bsdtrace-<pid>.pt)\n"
			    "  -r range    IP filter: 0xstart:0xend or func_name (stop: prefix for TraceStop)\n"
			    "  -T tid       Thread index (default: 0), list (0,1,3), or 'all'\n"
			    "  -P freq     PSB sync frequency 0-15 (lower = more sync, 0 = default)\n"
			    "  -C          Enable timing packets (MTC + CYC, auto-detect freq)\n"
			    "  -M freq     MTC frequency 1-15 (explicit, overrides -C)\n"
			    "  -Y thresh   CYC threshold 1-15 (explicit, overrides -C)\n"
			    "  -W          Enable PTWRITE trace markers\n"
			    "  -K          Include kernel/OS-mode tracing\n"
			    "  -m count    Stop after N records\n"
			    "  -b backend  HWT backend name (default: auto-detect)\n"
			    "  -p          Pause target on mmap/exec events\n"
			    "  -n          Dry run: validate setup without tracing\n"
			    "  -h          Show this help\n");
			return (0);
		default:
			fprintf(stderr,
			    "usage: bsdtrace trace [options] pid\n"
			    "       (use -h for help)\n");
			return (1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		fprintf(stderr, "bsdtrace trace: PID required\n");
		return (1);
	}

	{
		long v;

		if (parse_long_opt(argv[0], 1, INT_MAX, &v) != 0) {
			fprintf(stderr,
			    "bsdtrace trace: invalid PID '%s'\n", argv[0]);
			return (1);
		}
		pid = (pid_t)v;
	}

	/* Verify target exists. */
	if (kill(pid, 0) != 0) {
		fprintf(stderr,
		    "bsdtrace trace: process %d not found or not accessible\n",
		    (int)pid);
		return (1);
	}

	bufsize = parse_size(bufsize_str);
	if (bufsize == 0) {
		fprintf(stderr,
		    "bsdtrace: invalid -s size '%s' (use e.g. 8m, 64m)\n",
		    bufsize_str);
		return (1);
	}

	/* Resolve backend and check kernel support. */
	backend_name = resolve_backend(backend_name, &detected_backend,
	    dryrun);
	if (backend_name == NULL)
		return (1);
	if (check_hwt_hooks(dryrun) != 0) {
		free(detected_backend);
		return (dryrun ? 0 : 1);
	}

	execname = process_name(pid, pathbuf, sizeof(pathbuf));
	if (execname == NULL)
		execname = "?";

	/* Resolve any symbol-based range specs to addresses. */
	if (nrange_specs > 0) {
		char fullpath[MAXPATHLEN];
		bool unused_aslr;

		if (process_exe_fullpath(pid, fullpath,
		    sizeof(fullpath)) != 0) {
			warnx("cannot determine executable path for pid %d",
			    (int)pid);
			free(detected_backend);
			return (1);
		}
		if (resolve_range_specs(range_specs, nrange_specs,
		    &filter, pid, fullpath, false, &unused_aslr) != 0) {
			free(detected_backend);
			return (1);
		}
	}

	/* Allocate HWT context. */
	if (hwt_ctx_alloc(&ctx, HWT_MODE_THREAD, pid, tid,
	    bufsize, backend_name) != 0) {
		free(detected_backend);
		return (1);
	}

	/* Apply hardware IP range filter if specified. */
	ctx.filter = filter;
	ctx.psb_freq = psb_freq;
	ctx.ptwrite = ptwrite;
	ctx.os_trace = os_trace;
	if (mtc_freq_cli > 0)
		ctx.mtc_freq = mtc_freq_cli;
	if (cyc_thresh_cli > 0)
		ctx.cyc_thresh = cyc_thresh_cli;
	if (timing && ctx.mtc_freq == 0 && ctx.cyc_thresh == 0) {
		hwt_pt_default_timing(&ctx.mtc_freq, &ctx.cyc_thresh);
		if (ctx.mtc_freq == 0 && ctx.cyc_thresh == 0) {
			fprintf(stderr,
			    "bsdtrace trace: -C requested but CPU does "
			    "not support timing packets\n");
			hwt_ctx_close(&ctx);
			free(detected_backend);
			return (1);
		}
	}
	ctx.all_threads = trace_all_threads;
	if (nrequested_tids > 0) {
		memcpy(ctx.requested_tids, requested_tids,
		    nrequested_tids * sizeof(int));
		ctx.nrequested = nrequested_tids;
	}

	/*
	 * CRITICAL: Set the PT backend config BEFORE starting.
	 * See hwt.c comments for why this prevents kernel panics.
	 */
	if (hwt_ctx_set_config(&ctx, pause_on_mmap) != 0) {
		hwt_ctx_close(&ctx);
		free(detected_backend);
		return (1);
	}

	if (dryrun) {
		fprintf(stderr,
		    "dry-run: HWT context allocated OK "
		    "(ident=%d, pid=%d, backend=%s, bufsize=%zu)\n",
		    ctx.ident, (int)pid, backend_name, bufsize);
		hwt_ctx_close(&ctx);
		free(detected_backend);
		return (0);
	}

	/* Install signal handlers for clean shutdown.
	 * SIGPIPE must be ignored so a closed stdout doesn't kill
	 * us before we can stop tracing and resume a paused target. */
	trace_interrupted = 0;
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);

	if (hwt_ctx_start(&ctx) != 0) {
		hwt_ctx_close(&ctx);
		free(detected_backend);
		return (1);
	}

	/* Resolve PT output path now so the .meta sidecar is co-located. */
	if (pt_output == NULL) {
		snprintf(pt_path, sizeof(pt_path),
		    "bsdtrace-%d.pt", (int)pid);
		pt_output = pt_path;
	}
	derive_meta_path(pt_output, meta_path, sizeof(meta_path));
	meta = meta_writer_open(meta_path);
	if (meta == NULL)
		warnx("could not create %s — continuing without metadata",
		    meta_path);
	meta_writer_header(meta, pid, tid);
	meta_writer_timing(meta, (uint8_t)ctx.mtc_freq,
	    (uint8_t)ctx.cyc_thresh);
	trace_state_init(&ts, meta);
	ts.buf_tid = ctx.tid;
	memset(&env, 0, sizeof(env));
	if (hwt_pt_capture_env(&env) != 0)
		warnx("could not read capture CPU environment — "
		    "offline timing decode will be degraded");
	meta_writer_capture_env(meta, &env, &ctx.filter);
	if (trace_state_seed_process_mmaps(&ts, pid) != 0)
		warnx("could not snapshot existing executable mappings "
		    "for pid %d", (int)pid);

	clock_gettime(CLOCK_MONOTONIC, &start);
	totalrecords = 0;
	empty_drains = 0;
	target_gone = false;

	/*
	 * Line-buffer stdout so each JSON/text line is flushed as a
	 * single write().  Without this, the default full buffering
	 * (when piped) lets stderr writes interleave mid-line, producing
	 * malformed JSON when captured via 2>&1.
	 */
	setvbuf(stdout, NULL, _IOLBF, 0);

	if (fmt == FMT_TEXT)
		fprintf(stderr, "Tracing PID %d (%s)...\n",
		    (int)pid, execname);

	while (!trace_interrupted) {
		/* Check duration. */
		if (!target_gone && duration > 0) {
			clock_gettime(CLOCK_MONOTONIC, &now);
			double elapsed = (now.tv_sec - start.tv_sec) +
			    (now.tv_nsec - start.tv_nsec) / 1e9;
			if (elapsed >= duration)
				break;
		}

		/* Check max records. */
		if (!target_gone && maxrecords > 0 && totalrecords >= maxrecords) {
			fprintf(stderr,
			    "max-records: %d reached, stopping trace\n",
			    maxrecords);
			break;
		}

		/*
		 * Once the target exits, keep draining a few times before
		 * closing ctx_fd.  We cannot rely on a post-stop drain
		 * because the PT-safe stop path closes the device.
		 * kill(pid, 0) succeeds for zombies, so also check the
		 * process state — an exited-but-unreaped target must
		 * still end the trace.
		 */
		if (!target_gone &&
		    (kill(pid, 0) != 0 || proc_is_zombie(pid))) {
			target_gone = true;
			if (fmt == FMT_TEXT)
				fprintf(stderr,
				    "Target process %d exited\n", (int)pid);
		}

		/* Drain records. */
		nrecs = 0;
		if (hwt_ctx_poll_records(&ctx, records, MAX_POLL_RECORDS,
		    false, &nrecs) != 0)
			break;

		for (i = 0; i < nrecs; i++) {
			totalrecords++;
			emit_and_process(&records[i], pid, fmt,
			    pause_on_mmap, &ctx, &ts);
		}

		/* See cmd_exec.c: re-wake to close the missed-wakeup race. */
		if (pause_on_mmap)
			(void)hwt_ctx_wakeup(&ctx);

		if (target_gone) {
			if (nrecs == 0) {
				empty_drains++;
				if (empty_drains >= 5)
					break;
			} else {
				empty_drains = 0;
			}
		}

		usleep(nrecs > 0 ? 100 : 5000);
	}

	/*
	 * Restore default signal handling before the (potentially
	 * long) finalize/decode phase, so a second Ctrl-C is not
	 * silently absorbed by the now-purposeless handler.
	 */
	signal(SIGINT, SIG_DFL);

	memset(&dopts, 0, sizeof(dopts));
	dopts.tid = ctx.tid;
	dopts.filter_funcs = (const char **)filter_funcs;
	dopts.nfilter_funcs = nfilter_funcs;
	dopts.env = env;
	totalrecords = trace_finalize(&ctx, &ts, meta, pt_output,
	    pid, fmt, totalrecords, &dopts);

	if (fmt == FMT_TEXT && totalrecords >= 0) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		double elapsed = (now.tv_sec - start.tv_sec) +
		    (now.tv_nsec - start.tv_nsec) / 1e9;
		fprintf(stderr, "\n%d records in %.3fs\n",
		    totalrecords, elapsed);
	}

	/* Restore default signals. */
	signal(SIGINT, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);

	free(detected_backend);
	return (totalrecords < 0 ? 1 : 0);
}
