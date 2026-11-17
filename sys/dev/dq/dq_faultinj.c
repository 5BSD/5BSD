/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: fault injection for the test suites (options
 * DQ_FAULT_INJECTION).
 *
 * Each knob widens one window a test must hit, by sleeping one second at
 * a point where no lock is held, for the next N times the point is
 * reached.  Everything the option adds is in this file, built only with
 * the option (sys/conf/files); the call sites are under the option.
 *
 * A kernel built with the option is a test kernel and must never be
 * published.  release/scripts/check-test-kernel.sh refuses any kernel or
 * module that carries the marker below or a dq_faultinj_ symbol; both are
 * its row of sys/conf/test-options, with the knobs.  Do not rename either
 * without changing the ledger in the same change.  The older debug.dq
 * fault knobs (dq_queue.c) predate the option and move here later.
 *
 * The option is not available to the dq module: sys/modules/dq/Makefile
 * writes its own opt_dq.h, so a module would silently lose the call sites.
 */

#include "opt_dq.h"

#ifdef KLD_MODULE
#error "options DQ_FAULT_INJECTION is for a kernel with device dq, not for dq.ko"
#endif
#ifndef DQ_FAULT_INJECTION
#error "dq_faultinj.c is built only with options DQ_FAULT_INJECTION"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>

#include <machine/atomic.h>

#include <dev/dq/dq.h>
#include <dev/dq/dq_var.h>

/*
 * The publication check searches kernels and modules for this string (its
 * row of sys/conf/test-options).
 */
static const char dq_faultinj_marker[] __used =
    "@(#)5BSD DQ_FAULT_INJECTION test kernel: not for publication";

SYSCTL_DECL(_debug_dq);

/*
 * The window between a SWAP answer's take and the queue lock, in which
 * the requester can give up and the reply becomes ECANCELED.
 */
static u_int dq_faultinj_swap_take;
SYSCTL_UINT(_debug_dq, OID_AUTO, delay_swap_take, CTLFLAG_RW,
    &dq_faultinj_swap_take, 0,
    "Test kernel only: the next N SWAP replies sleep one second after the "
    "take, before the queue lock");

/*
 * The window between a requester's wake-up with its reply and its apply of
 * the reply's post-operation attributes, in which a later reply to
 * another requester is applied first.
 */
static u_int dq_faultinj_postop_apply;
SYSCTL_UINT(_debug_dq, OID_AUTO, delay_postop_apply, CTLFLAG_RW,
    &dq_faultinj_postop_apply, 0,
    "Test kernel only: the next N post-operation applies sleep one second "
    "first");

static void
dq_faultinj_pause(u_int *counter, const char *wmesg)
{
	u_int n;

	do {
		n = atomic_load_int(counter);
		if (n == 0)
			return;
	} while (!atomic_cmpset_int(counter, n, n - 1));
	pause_sbt(wmesg, SBT_1S, 0, 0);
}

void
dq_faultinj_swap_take_pause(void)
{

	dq_faultinj_pause(&dq_faultinj_swap_take, "dqswtk");
}

void
dq_faultinj_postop_apply_pause(void)
{

	dq_faultinj_pause(&dq_faultinj_postop_apply, "dqpoap");
}
