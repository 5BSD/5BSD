/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * procstat coalition: capability-plane coalition identity of processes.
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <libprocstat.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "procstat.h"

/*
 * Display the coalition a process belongs to, the coalition responsible for
 * it, and the band that decides how hard the system tries to keep it when
 * memory runs short.  Every column comes straight from kinfo_proc, so this
 * works on live systems and on cores alike (a core reports nothing: the
 * identity lives in the coalition module, not in struct proc).
 */
static const char *
band_name(int band)
{

	switch (band) {
	case 0:
		return ("idle");
	case 1:
		return ("background");
	case 2:
		return ("standard");
	case 3:
		return ("interactive");
	case 4:
		return ("critical");
	default:
		return ("-");
	}
}

void
procstat_coalition(struct procstat *procstat __unused,
    struct kinfo_proc *kipp)
{

	if ((procstat_opts & PS_OPT_NOHEADER) == 0)
		xo_emit("{T:/%5s %-12s %12s %12s %6s %-11s %s}\n",
		    "PID", "COMM", "COALITION", "RESPONSIBLE", "RPID",
		    "BAND", "RELATION");

	xo_emit("{k:process_id/%5d/%d} ", kipp->ki_pid);
	xo_emit("{:command/%-12s/%s} ", kipp->ki_comm);
	xo_emit("{:coalition/%12ju/%ju} ", (uintmax_t)kipp->ki_coalition);
	xo_emit("{:responsible_coalition/%12ju/%ju} ",
	    (uintmax_t)kipp->ki_rcoalition);
	xo_emit("{:responsible_pid/%6d/%d} ", kipp->ki_rpid);
	xo_emit("{:band/%-11s/%s} ", band_name(kipp->ki_coalition_band));
	if (kipp->ki_coalition == 0)
		xo_emit("{:relation/%s}\n", "-");
	else if (kipp->ki_rcoalition == 0)
		xo_emit("{:relation/%s}\n", "unset");
	else if (kipp->ki_rcoalition == kipp->ki_coalition)
		xo_emit("{:relation/%s}\n", "self");
	else
		xo_emit("{:relation/%s}\n", "parent");
}
