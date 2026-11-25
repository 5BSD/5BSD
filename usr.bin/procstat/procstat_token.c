/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * procstat token: the audit token ids of processes (audit_token(3)).
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <libprocstat.h>
#include <stdint.h>
#include <stdio.h>

#include "procstat.h"

/*
 * Display the ids the audit token carries beside the pid: the lifetime id,
 * the exec generation and the image id (0: a kernel process, which has no
 * image).  Every column comes from kinfo_proc.
 */
void
procstat_token(struct procstat *procstat __unused, struct kinfo_proc *kipp)
{

	if ((procstat_opts & PS_OPT_NOHEADER) == 0)
		xo_emit("{T:/%5s %-19s %10s %10s %10s}\n",
		    "PID", "COMM", "UNIQUEID", "EXECGEN", "IMAGEID");

	xo_emit("{k:process_id/%5d/%d} ", kipp->ki_pid);
	xo_emit("{:command/%-19s/%s} ", kipp->ki_comm);
	xo_emit("{:uniqueid/%10ju/%ju} ", (uintmax_t)kipp->ki_uniqueid);
	xo_emit("{:execgen/%10ju/%ju} ", (uintmax_t)kipp->ki_execgen);
	xo_emit("{:imageid/%10ju/%ju}\n", (uintmax_t)kipp->ki_imageid);
}
