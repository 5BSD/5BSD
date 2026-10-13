/*-
 * Copyright (c) 2020 Domagoj Stolfa
 * Copyright (c) 2021 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from Arm Limited.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from the Kenneth Hayter Scholarship Fund.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libutil.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "dtraced.h"
#include "dtraced_errmsg.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

#define LOCK_FILE                "/var/run/dtraced.pid"

#define NEXISTS                  0
#define EXISTS_CHANGED           1
#define EXISTS_EQUAL             2

char version_str[128];

/*
 * Awful global variable, but is here because of the signal handler.
 */
static dtraced::state state;
static pthread_t sig_handletd;
static const char *program_name;
static unsigned long threadpool_size = 1;

static void *
handle_signals(void *arg)
{
	sigset_t sigset;
	int err, sig;
	__maybe_unused(arg);

	(void) sigfillset(&sigset);
	err = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
	if (err) {
		ERR("failed to sigmask signal handler thread: %s",
		    strerror(err));
		abort();
	}

	(void) sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);

	err = sigwait(&sigset, &sig);
	if (err) {
		ERR("failed to sigwait: %s", strerror(err));
		abort();
	}

	broadcast_shutdown(state);
	return (NULL);
}

static void
print_help(void)
{
	fprintf(stderr, "Usage: %s [-dhmOqvZ] [-D directory]\n", program_name);

	fprintf(stderr, "\n"
	    "\t-d  run dtraced in debug (foreground) mode.\n"
	    "\t-D  specify the directory to use for dtraced state.\n"
	    "\t-h  display this help page.\n"
	    "\t-m  run dtraced in 'minion' mode.\n"
	    "\t-O  run dtraced in 'overlord' mode.\n"
	    "\t-q  quiet mode.\n"
	    "\t-t  specify threadpool size.\n"
	    "\t-v  print dtraced version.\n"
	    "\t-Z  do not checksum DTrace programs when transmitting them.\n");
}

static char *
version(void)
{
	sprintf(version_str, "%u.%u.%u-%s", DTRACED_MAJOR, DTRACED_MINOR,
	    DTRACED_PATCH, DTRACED_EXTRA_IDENTIFIER);

	return (version_str);
}

static void
print_version(void)
{

	printf("dtraced: version %s", version());
}

static void
setup_sighdlrs(void)
{
	sigset_t sigset;
	int err;

	(void) sigemptyset(&sigset);
	(void) sigaddset(&sigset, SIGINT);
	(void) sigaddset(&sigset, SIGTERM);

	(void) pthread_sigmask(SIG_BLOCK, &sigset, NULL);

	err = pthread_create(&sig_handletd, NULL, handle_signals, NULL);
	if (err) {
		ERR("failed to create sighandler thread: %s", strerror(err));
		abort();
	}
}

int
main(int argc, const char **argv)
{
	char elfpath[MAXPATHLEN] = "/var/ddtrace";
	__cleanup(dtraced::closefd_generic) int efd = -1;
	int retry, nosha = 0;
	char ch;
	char pidstr[256];
	char hypervisor[128];
	int debug_mode = 0;
	size_t len = sizeof(hypervisor);
	size_t optlen;
	__cleanup(dtraced::cleanup_pidfile) struct pidfh *pfh = NULL;
	pid_t otherpid;
	int ctrlmachine = 1; /* default to control machine (-O) */
	char *end;

	program_name = argv[0];

	retry = 0;
	memset(pidstr, 0, sizeof(pidstr));

	if (sysctlbyname("kern.vm_guest", hypervisor, &len, NULL, 0)) {
		ERR("Failed to get kern.vm_guest: %m");
		return (EX_OSERR);
	}

	/* If we're running under bhyve, assume minion mode */
	if (strcmp(hypervisor, "bhyve") == 0)
		ctrlmachine = 0;

	if (ctrlmachine == 0)
		LOG("running in minion mode.");
	else
		LOG("running in overlord mode.");

	while ((ch = getopt(argc, (char *const *)argv, "D:Odhmvt:qZ")) != -1) {
		switch (ch) {
		case 'h':
			print_help();
			return (-1);

		case 'v':
			print_version();
			return (0);

		case 'D':
			optlen = strlen(optarg);
			strcpy(elfpath, optarg);
			strcpy(dtraced::INBOUNDDIR, optarg);
			strcpy(dtraced::INBOUNDDIR + optlen, "/inbound/");
			strcpy(dtraced::OUTBOUNDDIR, optarg);
			strcpy(dtraced::OUTBOUNDDIR + optlen, "/outbound/");
			strcpy(dtraced::BASEDIR, optarg);
			strcpy(dtraced::BASEDIR + optlen, "/base/");
			break;

		/*
		 * Run the daemon in 'overlord' mode. An overlord daemon in this
		 * case also spawns a minion thread which is going to spawn
		 * DTrace instances on the host in order to do the necessary
		 * linking.
		 */
		case 'O':
			if (strcmp(hypervisor, "none") != 0) {
				/*
				 * We are virtualized, so we can't be an
				 * overlord. Virtual machines don't have
				 * minions.
				 */
				WARN(
				    "Specified '-O' (overlord mode) "
				    "on a virtual machine. This is not (really)"
				    " supported... Don't report bugs.");
			}

			ctrlmachine = 1;
			break;

		/*
		 * Run the daemon in 'minion' mode.
		 */
		case 'm':
			if (strcmp(hypervisor, "none") == 0) {
				/*
				 * Warn the user that this makes very little
				 * sense on a non-virtualized machine...
				 *
				 * XXX: We only support bhyve for now.
				 */
				WARN("Specified '-m' (minion mode) on "
				     "a native (bare metal) machine. Did you "
				     "mean to make this machine an "
				     "overlord ('-O')?");
			}
			ctrlmachine = 0;
			break;

		case 'd':
			debug_mode = 1;
			break;

		case 't':
			threadpool_size = strtoul(optarg, &end, 10);
			if (errno != 0) {
				ERR("Invalid argument (-t): "
				    "failed to parse %s as a number",
				    optarg);
				return (EXIT_FAILURE);
			}

			DEBUG("Setting threadpool size to %lu",
			    threadpool_size);
			break;

		case 'Z':
			nosha = 1;
			break;

		case 'q':
			be_quiet();
			break;

		default:
			print_version();
			return (-1);
		}
	}

	pfh = pidfile_open(LOCK_FILE, 0600, &otherpid);
	if (pfh == NULL) {
		if (errno == EEXIST) {
			ERR("dtraced is already running as pid %jd (check %s)",
			    (intmax_t)otherpid, LOCK_FILE);
			return (EX_OSERR);
		}

		ERR("Could not open %s: %m", LOCK_FILE);
		return (EX_OSERR);
	}

	if (ctrlmachine != 0 && ctrlmachine != 1) {
		ERR("You must either specify whether to run the daemon in "
		    "minion ('-m') or overlord ('-O') mode");
		return (EX_OSERR);
	}

	if (!debug_mode && daemon(0, 0) != 0) {
		ERR("Failed to daemonize %m");
		return (EX_OSERR);
	}

	if (pidfile_write(pfh)) {
		ERR("Failed to write PID to %s: %m", LOCK_FILE);
		return (EX_OSERR);
	}

againefd:
	efd = open(elfpath, O_RDONLY | O_DIRECTORY);
	if (efd == -1) {
		if (retry == 0 && errno == ENOENT) {
			if (mkdir(elfpath, 0700) != 0)
				ERR("Failed to mkdir %s: %m",
				    elfpath);
			else {
				retry = 1;
				goto againefd;
			}
		}

		ERR("Failed to open %s: %m", elfpath);
		return (EX_OSERR);
	}

	setup_sighdlrs();

	if (!state.initialize(ctrlmachine, nosha, threadpool_size, argv))
		return (EXIT_FAILURE);

	state.outbounddir->listen();

	if (!state.finalize())
		return (EXIT_FAILURE);

	return (0);
}
