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
 * It leaves the process with no discovery route and execs the command,
 * which inherits that: every lookup of system.switchboard from it or its
 * children fails, as it does under /etc/rc.shutdown after a SwitchBoard
 * crash.
 *
 * The call that gives that state is MAC_CAP_PROCESS_SET_NONE where the
 * kernel has it.  After channel S4a, MAC_CAP_PROCESS_CLEAR restores the
 * system route instead (channel-ipc-promotion.md rev 1.8, 5.6.3), so CLEAR
 * is only the fallback for a kernel without SET_NONE (dev, where CLEAR
 * empties the slot).
 */

#include <sys/types.h>
#include <sys/cap_process.h>

#include <err.h>
#include <errno.h>
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
#ifdef MAC_CAP_PROCESS_SET_NONE
	if (cap_process(MAC_CAP_PROCESS_SET_NONE, -1, 0, NULL) == 0)
		goto run;
	if (errno != EINVAL && errno != EOPNOTSUPP)
		err(1, "cap_process(MAC_CAP_PROCESS_SET_NONE)");
#endif
	if (cap_process(MAC_CAP_PROCESS_CLEAR, -1, 0, NULL) == -1)
		err(1, "cap_process(MAC_CAP_PROCESS_CLEAR)");
#ifdef MAC_CAP_PROCESS_SET_NONE
run:
#endif
	execvp(argv[1], argv + 1);
	err(127, "%s", argv[1]);
}
