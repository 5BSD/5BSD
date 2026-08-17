/*-
 * Copyright (c) 2026 Kory Heard
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * bsdtrace list — show HWT availability and backend capabilities.
 */

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bsdtrace.h"

/* ------------------------------------------------------------------ */
/* Thread listing                                                      */
/* ------------------------------------------------------------------ */

static void
list_threads(pid_t pid)
{
	struct kinfo_proc *kip;
	size_t len;
	int mib[4];
	unsigned int i, nthreads;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID | KERN_PROC_INC_THREAD;
	mib[3] = pid;

	if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) {
		fprintf(stderr,
		    "bsdtrace: cannot query threads for pid %d\n",
		    (int)pid);
		return;
	}

	kip = malloc(len);
	if (kip == NULL)
		return;

	if (sysctl(mib, 4, kip, &len, NULL, 0) != 0) {
		free(kip);
		return;
	}

	nthreads = len / sizeof(*kip);
	if (nthreads == 0) {
		fprintf(stderr,
		    "bsdtrace: no threads found for pid %d\n", (int)pid);
		free(kip);
		return;
	}
	printf("Threads for PID %d (%s):\n", (int)pid,
	    kip[0].ki_comm);
	printf("  %-6s  %-6s  %s\n", "INDEX", "TID", "NAME");
	for (i = 0; i < nthreads; i++) {
		printf("  %-6u  %-6d  %s\n",
		    i,
		    (int)kip[i].ki_tid,
		    kip[i].ki_tdname[0] != '\0' ?
		    kip[i].ki_tdname : "(unnamed)");
	}

	free(kip);
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static int
sysctl_string(const char *name, char *buf, size_t bufsz)
{
	size_t len;

	len = bufsz;
	if (sysctlbyname(name, buf, &len, NULL, 0) != 0)
		return (-1);
	return (0);
}

/* ------------------------------------------------------------------ */
/* Text output                                                         */
/* ------------------------------------------------------------------ */

static void
list_text(int hwt_avail, int hooks, const char *backend,
    const char *cpu_model, const char *machine)
{

	printf("HWT Framework\n");
	printf("────────────────────────────────────────\n");
	printf("  /dev/hwt:       %s\n",
	    hwt_avail ? "available" : "not found (kldload hwt)");
	printf("  Kernel hooks:   %s\n",
	    hooks > 0 ? "enabled" :
	    hooks == 0 ? "missing (boot kernel with HWT_HOOKS)" :
	    "unknown");
	printf("  Backend:        %s\n",
	    backend ? backend : "none loaded");
	printf("  CPU:            %s\n", cpu_model);
	printf("  Architecture:   %s\n", machine);

	if (backend != NULL) {
		printf("\nBackend: %s\n", backend);
		printf("────────────────────────────────────────\n");

		if (strcmp(backend, "pt") == 0) {
			uint32_t mtc, cyc;
			printf("  Type:           Intel Processor Trace\n");
			printf("  Modes:          thread, cpu\n");
			hwt_pt_default_timing(&mtc, &cyc);
			if (mtc > 0 && cyc > 0)
				printf("  Features:       branch tracing, "
				    "timing, cycle-accurate\n");
			else if (mtc > 0)
				printf("  Features:       branch tracing, "
				    "timing\n");
			else
				printf("  Features:       branch tracing\n");
		} else if (strcmp(backend, "coresight") == 0) {
			printf("  Type:           ARM CoreSight ETM\n");
			printf("  Modes:          thread, cpu\n");
			printf("  Features:       branch tracing, "
			    "timestamps\n");
		} else if (strcmp(backend, "spe") == 0) {
			printf("  Type:           ARM Statistical Profiling "
			    "Extension\n");
			printf("  Modes:          thread, cpu\n");
			printf("  Features:       statistical sampling, "
			    "latency, events\n");
		} else {
			printf("  Type:           unknown\n");
		}
	}

	if (!hwt_avail) {
		printf("\nTo enable HWT:\n");
		printf("  sudo kldload hwt\n");
		if (strcmp(machine, "amd64") == 0)
			printf("  sudo kldload pt\n");
		else if (strcmp(machine, "aarch64") == 0)
			printf("  sudo kldload coresight\n");
	} else if (backend == NULL) {
		printf("\nhwt.ko is loaded but no backend driver found.\n");
		if (strcmp(machine, "amd64") == 0) {
			printf("  sudo kldload pt\n");
			printf("  # If pt.ko is missing, build from "
			    "source:\n");
			printf("  # cd /usr/src/sys/modules/pt && "
			    "sudo make && sudo make install\n");
		} else if (strcmp(machine, "aarch64") == 0) {
			printf("  sudo kldload coresight  # or: "
			    "sudo kldload spe\n");
		}
	}

	if (hooks == 0) {
		printf("\nThe running kernel lacks HWT_HOOKS.\n");
		printf("  HWT_IOC_ALLOC can still create a context, but "
		    "exec/mmap records and scheduler-driven tracing are "
		    "not available.\n");
		printf("  Boot a kernel built with:\n");
		printf("    options HWT_HOOKS\n");
	}
}

/* ------------------------------------------------------------------ */
/* JSON output                                                         */
/* ------------------------------------------------------------------ */

static void
list_json(int hwt_avail, int hooks, const char *backend,
    const char *cpu_model, const char *machine)
{

	printf("{\"hwt_available\":%s", hwt_avail ? "true" : "false");
	if (hooks > 0)
		printf(",\"kernel_hooks\":true");
	else if (hooks == 0)
		printf(",\"kernel_hooks\":false");
	else
		printf(",\"kernel_hooks\":null");
	if (backend != NULL)
		printf(",\"backend\":\"%s\"", backend);
	else
		printf(",\"backend\":null");
	printf(",\"cpu_model\":\"%s\"", cpu_model);
	printf(",\"machine\":\"%s\"", machine);
	printf(",\"intel_pt\":%s",
	    (strcmp(machine, "amd64") == 0 && backend != NULL &&
	    strcmp(backend, "pt") == 0) ? "true" : "false");
	puts("}");
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

int
cmd_list(int argc, char **argv)
{
	enum bsdtrace_fmt fmt;
	char cpu_model[256];
	char machine[64];
	char *backend;
	int hwt_avail;
	int hooks;
	int ch;
	pid_t list_pid;

	fmt = FMT_TEXT;
	list_pid = 0;

	while ((ch = getopt(argc, argv, "f:p:h")) != -1) {
		switch (ch) {
		case 'f':
			if (strcmp(optarg, "json") == 0)
				fmt = FMT_JSON;
			else if (strcmp(optarg, "text") == 0)
				fmt = FMT_TEXT;
			else {
				fprintf(stderr,
				    "bsdtrace list: unknown format '%s'\n",
				    optarg);
				return (1);
			}
			break;
		case 'p': {
			char *end;
			long v;

			errno = 0;
			v = strtol(optarg, &end, 10);
			if (end == optarg || *end != '\0' ||
			    errno == ERANGE || v <= 0 || v > INT_MAX) {
				fprintf(stderr,
				    "bsdtrace list: invalid pid '%s'\n",
				    optarg);
				return (1);
			}
			list_pid = (pid_t)v;
			break;
		}
		case 'h':
			fprintf(stderr,
			    "usage: bsdtrace list [options]\n"
			    "\n"
			    "Show HWT framework status and backend capabilities.\n"
			    "\n"
			    "Options:\n"
			    "  -f format   Output: text (default) or json\n"
			    "  -p pid      List threads for a process\n"
			    "  -h          Show this help\n");
			return (0);
		default:
			fprintf(stderr,
			    "usage: bsdtrace list [-f text|json] [-p pid]\n"
			    "       (use -h for help)\n");
			return (1);
		}
	}

	hwt_avail = hwt_available();
	hooks = hwt_hooks_enabled();
	backend = hwt_detect_backend();

	if (sysctl_string("hw.model", cpu_model, sizeof(cpu_model)) != 0)
		strlcpy(cpu_model, "unknown", sizeof(cpu_model));
	if (sysctl_string("hw.machine", machine, sizeof(machine)) != 0)
		strlcpy(machine, "unknown", sizeof(machine));

	if (fmt == FMT_JSON)
		list_json(hwt_avail, hooks, backend, cpu_model, machine);
	else
		list_text(hwt_avail, hooks, backend, cpu_model, machine);

	free(backend);

	if (list_pid > 0)
		list_threads(list_pid);

	return (0);
}
