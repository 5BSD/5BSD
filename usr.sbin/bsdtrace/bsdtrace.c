/*-
 * Copyright (c) 2026 Kory Heard
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * bsdtrace — process tracing via FreeBSD Hardware Trace (HWT).
 *
 * Entry point, usage, subcommand dispatch, and shared helpers.
 */

#include <sys/types.h>
#include <sys/sysctl.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bsdtrace.h"

#define	BSDTRACE_VERSION	"0.1.0"

static void
usage(void)
{

	fprintf(stderr,
	    "usage: bsdtrace <command> [options]\n"
	    "\n"
	    "Commands:\n"
	    "  list              Show HWT framework and backend status\n"
	    "  exec [opts] -- cmd  Run a command under hardware trace\n"
	    "  trace [opts] pid  Attach to a running process\n"
	    "  decode [opts] .pt Decode a saved trace offline\n"
	    "\n"
	    "Common options:\n"
	    "  -f format   Output: text, json, profile, tree, or collapsed\n"
	    "  -d seconds  Trace duration (-t also accepted)\n"
	    "  -s size     Buffer size, e.g. 8m, 64m (default: 64m)\n"
	    "  -o file     Output .pt file path\n"
	    "  -r range    IP filter: addr/func (stop: prefix for TraceStop)\n"
	    "  -T tid      Thread: index, list (0,1,3), or 'all'\n"
	    "  -P freq     PSB sync frequency 0-15\n"
	    "  -C          Enable timing packets (MTC + CYC, auto-detect)\n"
	    "  -M freq     MTC frequency 1-15 (explicit)\n"
	    "  -Y thresh   CYC threshold 1-15 (explicit)\n"
	    "  -W          Enable PTWRITE trace markers\n"
	    "  -K          Include kernel/OS-mode tracing\n"
	    "  -h          Per-command help\n"
	    "\n"
	    "Requires root and kernel modules: kldload hwt && kldload pt\n"
	    );
	exit(1);
}

/* ------------------------------------------------------------------ */
/* Shared helpers                                                      */
/* ------------------------------------------------------------------ */

/*
 * Parse a human-readable size string: "4m" → 4194304, "16k" → 16384.
 * Returns bytes, or 0 for malformed input (no digits, non-positive,
 * unknown suffix, trailing junk, or multiplication overflow).
 */
size_t
parse_size(const char *s)
{
	char *end;
	long val;
	size_t mult;

	errno = 0;
	val = strtol(s, &end, 10);
	if (end == s || errno == ERANGE || val <= 0)
		return (0);

	switch (tolower((unsigned char)*end)) {
	case 'g':
		mult = 1024UL * 1024 * 1024;
		end++;
		break;
	case 'm':
		mult = 1024UL * 1024;
		end++;
		break;
	case 'k':
		mult = 1024UL;
		end++;
		break;
	case '\0':
		mult = 1;
		break;
	default:
		return (0);
	}
	if (*end != '\0')
		return (0);
	if ((size_t)val > SIZE_MAX / mult)
		return (0);

	return ((size_t)val * mult);
}

/*
 * Look up the executable name for a PID via sysctl.
 * Returns basename pointer into buf on success, NULL on failure.
 */
const char *
process_name(pid_t pid, char *buf, size_t bufsz)
{
	char *p;

	if (process_exe_fullpath(pid, buf, bufsz) != 0)
		return (NULL);

	p = strrchr(buf, '/');
	if (p != NULL)
		return (p + 1);
	return (buf);
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int
main(int argc, char **argv)
{

	if (argc < 2)
		usage();

	if (strcmp(argv[1], "list") == 0)
		return (cmd_list(argc - 1, argv + 1));
	if (strcmp(argv[1], "exec") == 0)
		return (cmd_exec(argc - 1, argv + 1));
	if (strcmp(argv[1], "trace") == 0)
		return (cmd_trace(argc - 1, argv + 1));
	if (strcmp(argv[1], "decode") == 0)
		return (cmd_decode(argc - 1, argv + 1));

	if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
		printf("bsdtrace %s\n", BSDTRACE_VERSION);
		return (0);
	}

	fprintf(stderr, "bsdtrace: unknown command '%s'\n", argv[1]);
	usage();
	/* NOTREACHED */
	return (1);
}
