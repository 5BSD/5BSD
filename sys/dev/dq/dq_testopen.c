/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: test access (options DQ_TEST_OPEN).
 *
 * Everything the option adds to the kernel is in this file, and this file
 * is built only with the option (sys/conf/files), so that a kernel either
 * carries all of it or none of it.  dq_open() calls dq_testopen_bind()
 * under the option; a kernel configured with the option that does not
 * build this file does not link.
 *
 * A kernel built with the option is a test kernel and must never be
 * published.  release/scripts/check-kernel-no-dq-test.sh refuses any
 * kernel or module that carries the marker below or a dq_testopen_ symbol
 * name; both names are part of that contract.  Do not rename either
 * without changing the script and its tests in the same change.
 *
 * The option is not available to the dq module: sys/modules/dq/Makefile
 * writes its own opt_dq.h, so a module would silently lose the call site.
 */

#include "opt_dq.h"

#ifdef KLD_MODULE
#error "options DQ_TEST_OPEN is for a kernel with device dq, not for dq.ko"
#endif
#ifndef DQ_TEST_OPEN
#error "dq_testopen.c is built only with options DQ_TEST_OPEN"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/sysctl.h>

#include <machine/atomic.h>

#include <dev/dq/dq.h>
#include <dev/dq/dq_var.h>

/* The publication check searches kernels and modules for this string. */
static const char dq_testopen_marker[] __used =
    "@(#)5BSD DQ_TEST_OPEN test kernel: not for publication";

SYSCTL_DECL(_debug_dq);

/*
 * debug.dq.unverified_open: loader tunable, fixed for the life of the
 * boot.  Any value other than 1 reads back as 0.
 */
static int dq_testopen_unverified;
SYSCTL_INT(_debug_dq, OID_AUTO, unverified_open,
    CTLFLAG_RDTUN | CTLFLAG_NOFETCH, &dq_testopen_unverified, 0,
    "Test kernel only: the test binding of /dev/dq opens is enabled");

static u_long dq_testopen_count;
SYSCTL_ULONG(_debug_dq, OID_AUTO, test_opens, CTLFLAG_RD,
    &dq_testopen_count, 0,
    "Test kernel only: opens that reached the test binding");

static void
dq_testopen_init(void *arg __unused)
{
	int value;

	value = 0;
	TUNABLE_INT_FETCH("debug.dq.unverified_open", &value);
	dq_testopen_unverified = (value == 1);
	if (dq_testopen_unverified)
		printf("dq: TEST KERNEL: debug.dq.unverified_open=1; "
		    "not for publication\n");
}
SYSINIT(dq_testopen, SI_SUB_TUNABLES, SI_ORDER_ANY, dq_testopen_init, NULL);

/*
 * Called by dq_open() after every check it makes has passed, before the
 * queue is created.  It decides nothing: who may open /dev/dq is exactly
 * what dq_open() enforces without the option.  With the tunable set it
 * counts the open; the binding itself arrives with the legitimacy rules.
 * dq_open() runs without a lock, hence the atomic.
 */
void
dq_testopen_bind(struct thread *td __unused)
{

	if (dq_testopen_unverified == 0)
		return;
	atomic_add_long(&dq_testopen_count, 1);
}
