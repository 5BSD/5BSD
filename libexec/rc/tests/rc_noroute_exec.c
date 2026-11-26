/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * rc_noroute_exec: run a command with no SwitchBoard reachable.
 *
 * usage: rc_noroute_exec command [args ...]
 *
 * It clears the process's discovery slot (cap_process(MAC_CAP_PROCESS_CLEAR),
 * the call a program makes to give up its lookup route) and execs the
 * command, which inherits the empty slot: every lookup of system.switchboard
 * from it or its children fails, as it does under /etc/rc.shutdown after a
 * SwitchBoard crash.  A process with no route clears nothing and still
 * succeeds.
 */

#include <sys/types.h>
#include <sys/cap_process.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{

	if (argc < 2) {
		fprintf(stderr, "usage: rc_noroute_exec command [args ...]\n");
		return (2);
	}
	if (cap_process(MAC_CAP_PROCESS_CLEAR, -1, 0, NULL) == -1)
		err(1, "cap_process(MAC_CAP_PROCESS_CLEAR)");
	execvp(argv[1], argv + 1);
	err(127, "%s", argv[1]);
}
