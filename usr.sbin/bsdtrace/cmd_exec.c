/*-
 * Copyright (c) 2026 Kory Heard
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * bsdtrace exec — run a command under HWT tracing and report events.
 *
 * Forks the child stopped (via raise(SIGSTOP)), attaches HWT
 * thread-mode tracing, resumes the child, and collects records
 * until it exits or duration.
 */

#include <sys/types.h>
#include <sys/procctl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bsdtrace.h"

#define	DEFAULT_DURATION		30.0
#define	DEFAULT_BUFSIZE		"64m"
#define	MAX_POLL_RECORDS	256

/*
 * SIGINT/SIGTERM must still produce a usable trace: the handler sets
 * a flag, the poll loop breaks, and trace_finalize() runs (stop
 * ioctl, drain, snapshot, .meta close).  Without this, Ctrl-C loses
 * the whole trace and leaves stale kernel PT state behind.
 */
static volatile sig_atomic_t exec_interrupted;

static void
exec_sigint_handler(int sig __unused)
{

	exec_interrupted = 1;
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
/* Fork helper                                                         */
/* ------------------------------------------------------------------ */


/*
 * Fork the child, have it raise(SIGSTOP) before exec.
 * Parent waits for the stop, then returns the child PID.
 *
 * Only async-signal-safe / POSIX calls in the child path.
 * No Swift runtime, no ARC, no closures — just C.
 */
static pid_t
fork_stopped(char **args, bool no_aslr)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid == -1) {
		warn("fork");
		return (-1);
	}
	if (pid == 0) {
		/* Child — only async-signal-safe calls. */
		if (no_aslr) {
			int val = PROC_ASLR_FORCE_DISABLE;
			procctl(P_PID, getpid(), PROC_ASLR_CTL, &val);
		}
		raise(SIGSTOP);
		execvp(args[0], args);
		_exit(127);
	}

	/* Parent — wait for child to stop. */
	if (waitpid(pid, &status, WUNTRACED) < 0) {
		warn("waitpid");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		return (-1);
	}
	if (!WIFSTOPPED(status)) {
		warnx("child did not stop as expected");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		return (-1);
	}

	return (pid);
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

int
cmd_exec(int argc, char **argv)
{
	struct bsdtrace_record records[MAX_POLL_RECORDS];
	struct trace_state ts;
	struct hwt_ctx ctx;
	struct timespec start, now;
	struct meta_writer *meta;
	enum bsdtrace_fmt fmt;
	const char *bufsize_str;
	const char *backend_name;
	char *detected_backend;
	double duration;
	size_t bufsize;
	pid_t child;
	char pt_path[64];
	char meta_path[MAXPATHLEN];
	const char *pt_output;
	struct ip_filter filter;
	struct range_spec range_specs[2];
	int nrange_specs;
	int tid;
	bool trace_all_threads;
	int requested_tids[MAX_THREADS];
	int nrequested_tids;
	int maxrecords;
	bool no_aslr;
	int totalrecords;
	int exitcode;
	int empty_drains;
	int nrecs;
	int status;
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
	bool child_done;
	char **cmd_argv;

	fmt = FMT_TEXT;
	bufsize_str = DEFAULT_BUFSIZE;
	backend_name = NULL;
	detected_backend = NULL;
	pt_output = NULL;
	duration = DEFAULT_DURATION;
	maxrecords = 0;
	tid = 0;
	trace_all_threads = false;
	nrequested_tids = 0;
	memset(&filter, 0, sizeof(filter));
	nrange_specs = 0;
	no_aslr = false;
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
	while ((ch = getopt(argc, argv, "f:b:s:d:t:m:o:r:T:P:M:Y:F:AhnpCWK")) != -1) {
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
				    "bsdtrace exec: unknown format '%s'\n",
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
			/* An explicit "-d 0" disables the duration cap. */
			if (parse_duration_opt(optarg, &duration) != 0) {
				fprintf(stderr,
				    "bsdtrace exec: invalid duration '%s'\n",
				    optarg);
				return (1);
			}
			break;
		case 'm': {
			long v;

			if (parse_long_opt(optarg, 0, INT_MAX, &v) != 0) {
				fprintf(stderr,
				    "bsdtrace exec: invalid record count "
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
				    "bsdtrace exec: max 2 IP ranges\n");
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
				/* Comma-separated list: -T 0,1,3 */
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
						    "bsdtrace exec: invalid "
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
					    "bsdtrace exec: -T requires "
					    "at least one thread id\n");
					return (1);
				}
				tid = requested_tids[0];
			} else {
				long v;

				if (parse_long_opt(optarg, 0, INT_MAX,
				    &v) != 0) {
					fprintf(stderr,
					    "bsdtrace exec: invalid thread "
					    "id '%s'\n", optarg);
					return (1);
				}
				tid = (int)v;
			}
			break;
		case 'A':
			no_aslr = true;
			break;
		case 'n':
			dryrun = true;
			break;
		case 'p':
			pause_on_mmap = true;
			break;
		case 'P': {
			long v;

			if (parse_long_opt(optarg, 0, 15, &v) != 0) {
				fprintf(stderr,
				    "bsdtrace exec: psb-freq must be "
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
				    "bsdtrace exec: mtc-freq must be "
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
				    "bsdtrace exec: cyc-thresh must be "
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
		case 'h':
			fprintf(stderr,
			    "usage: bsdtrace exec [options] -- command [args...]\n"
			    "\n"
			    "Run a command under hardware trace and decode the results.\n"
			    "\n"
			    "Options:\n"
			    "  -f format   Output format: text, json, profile, tree, or collapsed\n"
			    "  -d seconds  Maximum trace duration (default: 30)\n"
			    "  -s size     Trace buffer size, e.g. 8m, 64m (default: 64m)\n"
			    "  -o file     Output path for .pt data (default: bsdtrace-<pid>.pt)\n"
			    "  -r range    IP filter: 0xstart:0xend or func_name (stop: prefix for TraceStop)\n"
			    "  -T tid       Thread index (default: 0), list (0,1,3), or 'all'\n"
			    "  -m count    Stop after N records\n"
			    "  -b backend  HWT backend name (default: auto-detect)\n"
			    "  -P freq     PSB sync frequency 0-15 (lower = more sync, 0 = default)\n"
			    "  -C          Enable timing packets (MTC + CYC, auto-detect freq)\n"
			    "  -M freq     MTC frequency 1-15 (explicit, overrides -C)\n"
			    "  -Y thresh   CYC threshold 1-15 (explicit, overrides -C)\n"
			    "  -W          Enable PTWRITE trace markers\n"
			    "  -K          Include kernel/OS-mode tracing\n"
			    "  -A          Disable ASLR for the child process\n"
			    "  -p          Pause target on mmap/exec events\n"
			    "  -n          Dry run: validate setup without tracing\n"
			    "  -h          Show this help\n");
			return (0);
		default:
			fprintf(stderr,
			    "usage: bsdtrace exec [options] -- command [args...]\n"
			    "       (use -h for help)\n");
			return (1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Skip "--" separator if present. */
	if (argc > 0 && strcmp(argv[0], "--") == 0) {
		argc--;
		argv++;
	}

	if (argc < 1) {
		fprintf(stderr,
		    "bsdtrace exec: provide a command after '--'\n");
		return (1);
	}
	cmd_argv = argv;

	/* Resolve symbol-based range specs before forking.
	 * If the command is a bare name (no '/'), resolve via PATH
	 * so symbol lookup can find the ELF binary. */
	if (nrange_specs > 0) {
		bool need_aslr_disable;
		char resolved_cmd[MAXPATHLEN];
		const char *exe_for_symbols;

		exe_for_symbols = cmd_argv[0];
		if (strchr(cmd_argv[0], '/') == NULL) {
			const char *p = getenv("PATH");
			struct stat sb;

			/*
			 * Mirror execvp: an empty PATH component means the
			 * current directory, and a candidate counts only if
			 * it is a regular file we may execute — so the
			 * binary we read symbols from is the one execvp
			 * will actually run.
			 */
			if (p == NULL)
				p = _PATH_DEFPATH;
			resolved_cmd[0] = '\0';
			while (p != NULL) {
				const char *end = strchr(p, ':');
				size_t len = end ? (size_t)(end - p) : strlen(p);

				if (len == 0)
					snprintf(resolved_cmd,
					    sizeof(resolved_cmd),
					    "./%s", cmd_argv[0]);
				else
					snprintf(resolved_cmd,
					    sizeof(resolved_cmd),
					    "%.*s/%s", (int)len, p,
					    cmd_argv[0]);
				if (stat(resolved_cmd, &sb) == 0 &&
				    S_ISREG(sb.st_mode) &&
				    access(resolved_cmd, X_OK) == 0)
					break;
				resolved_cmd[0] = '\0';
				p = end ? end + 1 : NULL;
			}
			if (resolved_cmd[0] != '\0')
				exe_for_symbols = resolved_cmd;
			else
				warnx("could not resolve '%s' via PATH for "
				    "symbol lookup", cmd_argv[0]);
		}

		if (resolve_range_specs(range_specs, nrange_specs,
		    &filter, 0, exe_for_symbols, true,
		    &need_aslr_disable) != 0)
			return (1);
		if (need_aslr_disable && !no_aslr) {
			fprintf(stderr,
			    "note: disabling ASLR for symbol-based "
			    "range filter\n");
			no_aslr = true;
		}
	}

	bufsize = parse_size(bufsize_str);
	if (bufsize == 0) {
		fprintf(stderr,
		    "bsdtrace: invalid -s size '%s' (use e.g. 8m, 64m)\n",
		    bufsize_str);
		return (1);
	}

	/*
	 * In exec mode only thread 0 exists when the HWT context is
	 * allocated — per-thread devices for other indexes appear
	 * later via THREAD_CREATE records.  Normalize any -T request
	 * to primary thread 0 plus a requested-thread list serviced
	 * on demand.
	 */
	if (!trace_all_threads && tid != 0 && nrequested_tids == 0) {
		requested_tids[0] = tid;
		nrequested_tids = 1;
	}
	if (tid != 0) {
		fprintf(stderr,
		    "note: exec mode traces thread 0 as primary; "
		    "thread %d will be captured when it is created\n", tid);
		tid = 0;
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

	/* Fork child stopped. */
	child = fork_stopped(cmd_argv, no_aslr);
	if (child < 0)
		return (1);

	/* Allocate HWT context for the child. */
	if (hwt_ctx_alloc(&ctx, HWT_MODE_THREAD, child, tid,
	    bufsize, backend_name) != 0) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		free(detected_backend);
		return (1);
	}

	/* Apply hardware IP range filter if specified. */
	ctx.filter = filter;
	ctx.psb_freq = psb_freq;
	ctx.ptwrite = ptwrite;
	ctx.os_trace = os_trace;
	ctx.all_threads = trace_all_threads;
	if (nrequested_tids > 0) {
		memcpy(ctx.requested_tids, requested_tids,
		    nrequested_tids * sizeof(int));
		ctx.nrequested = nrequested_tids;
	}
	if (mtc_freq_cli > 0)
		ctx.mtc_freq = mtc_freq_cli;
	if (cyc_thresh_cli > 0)
		ctx.cyc_thresh = cyc_thresh_cli;
	if (timing && ctx.mtc_freq == 0 && ctx.cyc_thresh == 0) {
		hwt_pt_default_timing(&ctx.mtc_freq, &ctx.cyc_thresh);
		if (ctx.mtc_freq == 0 && ctx.cyc_thresh == 0) {
			fprintf(stderr,
			    "bsdtrace exec: -C requested but CPU does "
			    "not support timing packets\n");
			kill(child, SIGKILL);
			waitpid(child, NULL, 0);
			hwt_ctx_close(&ctx);
			free(detected_backend);
			return (1);
		}
	}

	/*
	 * CRITICAL: Set the PT backend config BEFORE starting.
	 *
	 * The PT backend's pt_backend_configure() dereferences
	 * ctx->config on the first hwt_switch_in.  If config is
	 * NULL, the kernel page-faults.
	 */
	if (hwt_ctx_set_config(&ctx, pause_on_mmap) != 0) {
		hwt_ctx_close(&ctx);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		free(detected_backend);
		return (1);
	}

	if (dryrun) {
		fprintf(stderr,
		    "dry-run: HWT context allocated OK "
		    "(ident=%d, backend=%s, bufsize=%zu)\n",
		    ctx.ident, backend_name, bufsize);
		hwt_ctx_close(&ctx);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		free(detected_backend);
		return (0);
	}

	/* Start tracing and resume child. */
	if (hwt_ctx_start(&ctx) != 0) {
		hwt_ctx_close(&ctx);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		free(detected_backend);
		return (1);
	}

	/* Resolve PT output path and open .meta sidecar. */
	if (pt_output == NULL) {
		snprintf(pt_path, sizeof(pt_path),
		    "bsdtrace-%d.pt", (int)child);
		pt_output = pt_path;
	}
	derive_meta_path(pt_output, meta_path, sizeof(meta_path));
	meta = meta_writer_open(meta_path);
	if (meta == NULL)
		warnx("could not create %s — continuing without metadata",
		    meta_path);
	meta_writer_header(meta, child, tid);
	meta_writer_timing(meta, (uint8_t)ctx.mtc_freq,
	    (uint8_t)ctx.cyc_thresh);
	trace_state_init(&ts, meta);
	ts.buf_tid = ctx.tid;
	memset(&env, 0, sizeof(env));
	if (hwt_pt_capture_env(&env) != 0)
		warnx("could not read capture CPU environment — "
		    "offline timing decode will be degraded");
	meta_writer_capture_env(meta, &env, &ctx.filter);

	/* Line-buffer stdout — see cmd_trace.c comment.
	 * Ignore SIGPIPE so a closed stdout doesn't prevent cleanup. */
	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGPIPE, SIG_IGN);
	exec_interrupted = 0;
	signal(SIGINT, exec_sigint_handler);
	signal(SIGTERM, exec_sigint_handler);

	kill(child, SIGCONT);
	clock_gettime(CLOCK_MONOTONIC, &start);

	/* Poll records until child exits or duration. */
	child_done = false;
	exitcode = 0;
	totalrecords = 0;
	empty_drains = 0;

	for (;;) {
		/* Interrupted: stop cleanly so the trace is finalized. */
		if (exec_interrupted) {
			fprintf(stderr, "interrupted, stopping trace\n");
			if (!child_done)
				kill(child, SIGKILL);
			break;
		}

		/* Check duration. */
		clock_gettime(CLOCK_MONOTONIC, &now);
		double elapsed = (now.tv_sec - start.tv_sec) +
		    (now.tv_nsec - start.tv_nsec) / 1e9;
		if (duration > 0 && elapsed >= duration) {
			fprintf(stderr,
			    "duration: %.0fs elapsed, stopping trace\n",
			    duration);
			if (!child_done)
				kill(child, SIGKILL);
			break;
		}

		/* Check max records. */
		if (maxrecords > 0 && totalrecords >= maxrecords) {
			fprintf(stderr,
			    "max-records: %d reached, stopping trace\n",
			    maxrecords);
			if (!child_done)
				kill(child, SIGKILL);
			break;
		}

		/* Check child status (non-blocking). */
		status = 0;
		if (!child_done && waitpid(child, &status, WNOHANG) > 0) {
			child_done = true;
			if (WIFEXITED(status))
				exitcode = WEXITSTATUS(status);
			else if (WIFSIGNALED(status))
				exitcode = 128 + WTERMSIG(status);
		}

		/* Drain records. */
		nrecs = 0;
		if (hwt_ctx_poll_records(&ctx, records, MAX_POLL_RECORDS,
		    false, &nrecs) != 0) {
			if (child_done)
				break;
			/*
			 * Poll error while child is still running.
			 * Kill child, reap, then fall through to cleanup.
			 */
			kill(child, SIGKILL);
			waitpid(child, &status, 0);
			child_done = true;
			exitcode = WIFSIGNALED(status) ?
			    128 + WTERMSIG(status) : 1;
			break;
		}

		for (i = 0; i < nrecs; i++) {
			totalrecords++;
			emit_and_process(&records[i], child, fmt,
			    pause_on_mmap, &ctx, &ts);
		}

		/*
		 * With pause-on-mmap active, re-issue the wakeup every
		 * round: the kernel enqueues the MMAP record and wakes
		 * the owner BEFORE the target thread sleeps, so a
		 * purely record-driven wakeup can be lost.  A wakeup
		 * with no sleeper is harmless.
		 */
		if (pause_on_mmap)
			(void)hwt_ctx_wakeup(&ctx);

		/*
		 * Once the child exits, keep draining a few times before
		 * closing ctx_fd.  We cannot rely on a post-stop drain
		 * because the PT-safe stop path closes the device.
		 */
		if (child_done) {
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
	 * Restore default signal handling BEFORE the blocking reap:
	 * BSD signal() semantics restart the wait, so keeping the
	 * flag-only handlers installed would make an unkillable child
	 * an unkillable tracer too.
	 */
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

	/* Reap child if we killed it above (duration/maxrecords). */
	if (!child_done) {
		status = 0;
		waitpid(child, &status, 0);
		child_done = true;
		if (WIFEXITED(status))
			exitcode = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			exitcode = 128 + WTERMSIG(status);
	}

	memset(&dopts, 0, sizeof(dopts));
	dopts.tid = ctx.tid;
	dopts.filter_funcs = (const char **)filter_funcs;
	dopts.nfilter_funcs = nfilter_funcs;
	dopts.env = env;
	totalrecords = trace_finalize(&ctx, &ts, meta, pt_output,
	    child, fmt, totalrecords, &dopts);

	if (fmt == FMT_TEXT)
		fprintf(stderr, "\n%d records collected, exit code %d\n",
		    totalrecords, exitcode);

	free(detected_backend);
	/*
	 * A failed snapshot/finalize must not masquerade as the
	 * child's (usually 0) exit code.
	 */
	if (totalrecords < 0 && exitcode == 0)
		return (1);
	return (exitcode);
}
