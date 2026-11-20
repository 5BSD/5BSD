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
#include <sys/capsicum.h>
#include <sys/dqres.h>
#include <sys/errno.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/ktrace.h>
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

/*
 * Base exclusion (cap_process(2) BASE EXCLUSION) is anchored at PID 1: only
 * PID 1's fork chain can become excluded.  A Kyua test cannot run there, so
 * on a test kernel with test issuers on, a root process may mark itself
 * excluded, standing in for PID 1, and then exercise the chain rule with a
 * test issuer's Core token (tests/sys/mac_capability/cap_exclusion_test).
 * Refused when the caller is traced, ktraced, attached to a Capability
 * Broker, jailed or in capability mode, as an exec would refuse them.
 */
static int
mac_capability_test_issuer_exclude_self_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct thread *td = curthread;
	struct proc *p = td->td_proc;
	int error, value;

	PROC_LOCK(p);
	value = P_CAP_EXCLUDED(p) ? 1 : 0;
	PROC_UNLOCK(p);
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (value != 1)
		return (EINVAL);
	if (mac_capability_test_issuer_enabled != 1 || jailed(td->td_ucred) ||
	    IN_CAPABILITY_MODE(td))
		return (EPERM);
	PROC_LOCK(p);
	if ((p->p_flag & P_TRACED) != 0 ||
	    (p->p_traceflag & KTRFAC_MASK) != 0 ||
	    dqres_cred_change_refused(p))
		error = EPERM;
	else
		p->p_flag2 |= P2_CAP_EXCLUDED;
	PROC_UNLOCK(p);
	return (error);
}
SYSCTL_PROC(_debug_mac_capability, OID_AUTO, test_issuer_exclude_self,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    mac_capability_test_issuer_exclude_self_sysctl, "I",
    "Test kernel only: write 1 to mark the calling process excluded from "
    "OES and Capability Brokers, as PID 1 is (needs test issuers on)");

/*
 * OES test fail point: while set to a pid, every event OES records with
 * that process as its subject is filled as if the subject's process lock
 * were contended (oes_pending_init()'s unlocked fallback).  0 turns it off.
 * Lets a test prove that the reader rule (oes(4), "A client's own
 * processes") does not depend on that lock.
 */
volatile u_int mac_capability_test_issuer_oes_trylock_fail;

static int
mac_capability_test_issuer_oes_trylock_fail_sysctl(SYSCTL_HANDLER_ARGS)
{
	int error, value;

	value = atomic_load_int(&mac_capability_test_issuer_oes_trylock_fail);
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (value < 0)
		return (EINVAL);
	atomic_store_int(&mac_capability_test_issuer_oes_trylock_fail, value);
	return (0);
}
SYSCTL_PROC(_debug_mac_capability, OID_AUTO, test_issuer_oes_trylock_fail,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    mac_capability_test_issuer_oes_trylock_fail_sysctl, "I",
    "Test kernel only: a pid whose OES event records are filled as if its "
    "process lock were contended (0: off)");

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
