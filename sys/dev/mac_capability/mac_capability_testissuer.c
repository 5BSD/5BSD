/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Test issuers (options MAC_CAPABILITY_TEST_PERMISSIVE): the tunable, the
 * reporting sysctls and the test-only controls.  The state machine itself
 * is in mac_capability_authority.c, which owns struct authority_issuer.
 *
 * A kernel built with the option is a test kernel and must never be
 * published: it is a live row of the test-kernel option ledger,
 * sys/conf/test-options, whose marker (below) and symbol prefix
 * (mac_capability_test_issuer_) release/scripts/check-test-kernel.sh
 * refuses.  Do not rename either without changing the ledger in the same
 * change.  GENERIC-TEST is the one configuration allowed to carry it.
 *
 * The tunable kern.mac_capability.test_issuer is read once, at boot; only
 * the value 1 turns test issuers on.  It cannot be changed afterwards, by
 * anyone.
 */

#include "opt_mac_capability.h"

#ifdef KLD_MODULE
#error "options MAC_CAPABILITY_TEST_PERMISSIVE is for the kernel, not for a module"
#endif
#ifndef MAC_CAPABILITY_TEST_PERMISSIVE
#error "mac_capability_testissuer.c is built only with options MAC_CAPABILITY_TEST_PERMISSIVE"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/refcount.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>

#include <machine/atomic.h>

#include "mac_capability_internal.h"

/*
 * The publication check searches kernels and modules for this string (its
 * row of sys/conf/test-options).
 */
static const char mac_capability_test_issuer_marker[] __used =
    "@(#)5BSD MAC_CAPABILITY_TEST_PERMISSIVE test kernel: not for publication";

SYSCTL_DECL(_kern_mac_capability);

int mac_capability_test_issuer_enabled;
SYSCTL_INT(_kern_mac_capability, OID_AUTO, test_issuer,
    CTLFLAG_RDTUN | CTLFLAG_NOFETCH, &mac_capability_test_issuer_enabled, 0,
    "Test kernel only: a root process other than PID 1 may create an "
    "authority issuer until PID 1 anchors the boot");

SYSCTL_ULONG(_kern_mac_capability, OID_AUTO, test_issuers, CTLFLAG_RD,
    __DEVOLATILE(u_long *, &mac_capability_test_issuer_created), 0,
    "Test kernel only: test issuers created");

SYSCTL_UINT(_kern_mac_capability, OID_AUTO, test_issuers_live, CTLFLAG_RD,
    __DEVOLATILE(u_int *, &mac_capability_test_issuer_live), 0,
    "Test kernel only: test issuers not yet freed");

static int
mac_capability_test_issuer_state_sysctl(SYSCTL_HANDLER_ARGS)
{
	static const char *const names[] = {
		[MAC_CAPABILITY_TEST_ISSUER_NONE] = "none",
		[MAC_CAPABILITY_TEST_ISSUER_TEST] = "test",
		[MAC_CAPABILITY_TEST_ISSUER_ANCHORED] = "anchored",
	};
	const char *name;
	u_int state;

	state = mac_capability_test_issuer_state();
	name = state < nitems(names) ? names[state] : "unknown";
	return (sysctl_handle_string(oidp, __DECONST(char *, name), 0, req));
}
SYSCTL_PROC(_kern_mac_capability, OID_AUTO, test_issuer_state,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    mac_capability_test_issuer_state_sysctl, "A",
    "Test kernel only: none, test (a test issuer was created) or anchored "
    "(PID 1 attempted its issuer)");

/*
 * Test-only controls.  Neither is a tunable, and neither is writable from a
 * jail.  Both can only restrict: one anchors as PID 1's attempt would, the
 * other makes PID 1's next attempt fail after it has anchored.
 */
static SYSCTL_NODE(_debug, OID_AUTO, mac_capability,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Test kernel only: mac_capability test controls");

static int
mac_capability_test_issuer_anchor_sysctl(SYSCTL_HANDLER_ARGS)
{
	int error, value;

	value = 0;
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (value != 1)
		return (EINVAL);
	mac_capability_test_issuer_anchor();
	return (0);
}
SYSCTL_PROC(_debug_mac_capability, OID_AUTO, test_issuer_anchor,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    mac_capability_test_issuer_anchor_sysctl, "I",
    "Test kernel only: write 1 to anchor the boot as PID 1's attempt does");

volatile u_int mac_capability_test_issuer_fail_init;

static int
mac_capability_test_issuer_fail_init_sysctl(SYSCTL_HANDLER_ARGS)
{
	int error, value;

	value = atomic_load_int(&mac_capability_test_issuer_fail_init);
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	switch (value) {
	case 0:
	case ENOSPC:
	case ENFILE:
	case EMFILE:
		atomic_store_int(&mac_capability_test_issuer_fail_init, value);
		return (0);
	default:
		return (EINVAL);
	}
}
SYSCTL_PROC(_debug_mac_capability, OID_AUTO, test_issuer_fail_init,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    mac_capability_test_issuer_fail_init_sysctl, "I",
    "Test kernel only: the errno (ENOSPC, ENFILE, EMFILE, or 0) PID 1's next "
    "issuer creation fails with, once, after it anchors");

static void
mac_capability_test_issuer_init(void *arg __unused)
{
	int value;

	value = 0;
	TUNABLE_INT_FETCH("kern.mac_capability.test_issuer", &value);
	mac_capability_test_issuer_enabled = (value == 1);
	printf("mac_capability: TEST KERNEL (MAC_CAPABILITY_TEST_PERMISSIVE): "
	    "kern.mac_capability.test_issuer=%d; not for publication\n",
	    mac_capability_test_issuer_enabled);
}
SYSINIT(mac_capability_test_issuer, SI_SUB_TUNABLES, SI_ORDER_ANY,
    mac_capability_test_issuer_init, NULL);
