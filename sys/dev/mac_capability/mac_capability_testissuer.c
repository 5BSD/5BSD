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
		/* Clearing also restores the one-shot, no-skip default. */
		if (value == 0) {
			atomic_store_int(&mac_capability_test_issuer_fail_count,
			    1);
			atomic_store_int(&mac_capability_test_issuer_fail_skip,
			    0);
		}
		return (0);
	default:
		return (EINVAL);
	}
}
SYSCTL_PROC(_debug_mac_capability, OID_AUTO, test_issuer_fail_init,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    mac_capability_test_issuer_fail_init_sysctl, "I",
    "Test kernel only: the errno (ENOSPC, ENFILE, EMFILE, or 0) PID 1's next "
    "issuer creations fail with, test_issuer_fail_init_count times, after it "
    "anchors");

/*
 * How many consecutive PID 1 creates fail_init fails: 1 (the default) is one
 * transient failure, a larger count an outage that outlasts Capsule's wait.
 */
volatile u_int mac_capability_test_issuer_fail_count = 1;

static int
mac_capability_test_issuer_fail_count_sysctl(SYSCTL_HANDLER_ARGS)
{
	int error, value;

	value = atomic_load_int(&mac_capability_test_issuer_fail_count);
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (value < 0)
		return (EINVAL);
	atomic_store_int(&mac_capability_test_issuer_fail_count, value);
	return (0);
}
SYSCTL_PROC(_debug_mac_capability, OID_AUTO, test_issuer_fail_init_count,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    mac_capability_test_issuer_fail_count_sysctl, "I",
    "Test kernel only: how many of PID 1's issuer creations in a row "
    "test_issuer_fail_init fails (default 1; 0: until it is cleared)");

/*
 * How many of PID 1's creates succeed before fail_init applies: 1 fails the
 * issuer Capsule creates in advance for the next start, not the first one.
 */
volatile u_int mac_capability_test_issuer_fail_skip;

static int
mac_capability_test_issuer_fail_skip_sysctl(SYSCTL_HANDLER_ARGS)
{
	int error, value;

	value = atomic_load_int(&mac_capability_test_issuer_fail_skip);
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (value < 0)
		return (EINVAL);
	atomic_store_int(&mac_capability_test_issuer_fail_skip, value);
	return (0);
}
SYSCTL_PROC(_debug_mac_capability, OID_AUTO, test_issuer_fail_init_skip,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    mac_capability_test_issuer_fail_skip_sysctl, "I",
    "Test kernel only: how many of PID 1's issuer creations succeed before "
    "test_issuer_fail_init applies (default 0)");

/*
 * The errno PID 1's issuer create fails with now, or 0: let
 * test_issuer_fail_init_skip creates succeed, then fail
 * test_issuer_fail_init_count in a row (0: until fail_init is cleared), then
 * clear the fault.  Each counter is consumed with a compare-and-set, so
 * concurrent creates (and sysctl writes) each take one step.
 */
int
mac_capability_test_issuer_fail_take(void)
{
	u_int count, error, skip;

	error = atomic_load_int(&mac_capability_test_issuer_fail_init);
	if (error == 0)
		return (0);
	skip = atomic_load_int(&mac_capability_test_issuer_fail_skip);
	while (skip > 0) {
		if (atomic_fcmpset_int(&mac_capability_test_issuer_fail_skip,
		    &skip, skip - 1))
			return (0);
	}
	count = atomic_load_int(&mac_capability_test_issuer_fail_count);
	while (count > 0) {
		if (!atomic_fcmpset_int(&mac_capability_test_issuer_fail_count,
		    &count, count - 1))
			continue;
		/*
		 * The last failure clears the fault and restores the one-shot
		 * default.  The count is restored even when the clear loses to
		 * a concurrent write of fail_init, so a fault armed in that
		 * window is one-shot rather than "until cleared"; a count
		 * written in the same window is overwritten.  Test kernels only.
		 */
		if (count == 1) {
			(void)atomic_cmpset_int(
			    &mac_capability_test_issuer_fail_init, error, 0);
			atomic_store_int(&mac_capability_test_issuer_fail_count,
			    1);
		}
		break;
	}
	return ((int)error);
}

/*
 * Base exclusion (cap_process(2) BASE EXCLUSION) is anchored at PID 1: only
 * PID 1's fork chain can become excluded.  A Kyua test cannot run there, so
 * on a test kernel with test issuers on, a root process may mark itself
 * excluded, standing in for PID 1, and then exercise the chain rule with a
 * test issuer's Core token (tests/sys/mac_capability/cap_exclusion_test).
 * Refused when the caller is traced, ktraced, has no_new_privs, is attached
 * to a Capability Broker, jailed or in capability mode, as an exec would
 * refuse them.
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
	    (p->p_flag2 & P2_NO_NEW_PRIVS) != 0 ||
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

/*
 * Hold point for OES deferred delivery (oes_mac.c oes_defer_task_fn()).
 * Write 1 to arm: the deferred task's next round parks before it takes an
 * event off the queue, so every event queued from then on stays queued.
 * Write 0 to release.  A reader-set join that must wait for the task
 * (oes_client.c oes_client_join()) releases the hold itself, since it
 * would otherwise wait forever: a test proves with it that events queued
 * while a process was a reader are matched against that reader even when
 * the reader's entry is being dropped.  Read: 0 off, 1 armed, 2 parked.
 */
static struct mtx mac_capability_test_issuer_oes_defer_mtx;
MTX_SYSINIT(mac_capability_test_issuer_oes_defer,
    &mac_capability_test_issuer_oes_defer_mtx, "oes defer hold", MTX_DEF);
static int mac_capability_test_issuer_oes_defer_state;

void
mac_capability_test_issuer_oes_defer_park(void)
{

	if (atomic_load_int(&mac_capability_test_issuer_oes_defer_state) == 0)
		return;
	mtx_lock(&mac_capability_test_issuer_oes_defer_mtx);
	while (mac_capability_test_issuer_oes_defer_state != 0) {
		mac_capability_test_issuer_oes_defer_state = 2;
		mtx_sleep(&mac_capability_test_issuer_oes_defer_state,
		    &mac_capability_test_issuer_oes_defer_mtx, 0, "oesdhold", 0);
	}
	mtx_unlock(&mac_capability_test_issuer_oes_defer_mtx);
}

/* Re-arming while a join waits on the task parks it under that join again: arm once per case. */
void
mac_capability_test_issuer_oes_defer_unpark(void)
{

	if (atomic_load_int(&mac_capability_test_issuer_oes_defer_state) == 0)
		return;
	mtx_lock(&mac_capability_test_issuer_oes_defer_mtx);
	mac_capability_test_issuer_oes_defer_state = 0;
	wakeup(&mac_capability_test_issuer_oes_defer_state);
	mtx_unlock(&mac_capability_test_issuer_oes_defer_mtx);
}

static int
mac_capability_test_issuer_oes_defer_hold_sysctl(SYSCTL_HANDLER_ARGS)
{
	int error, value;

	value = atomic_load_int(&mac_capability_test_issuer_oes_defer_state);
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (value == 0) {
		mac_capability_test_issuer_oes_defer_unpark();
		return (0);
	}
	if (value != 1)
		return (EINVAL);
	mtx_lock(&mac_capability_test_issuer_oes_defer_mtx);
	if (mac_capability_test_issuer_oes_defer_state == 0)
		mac_capability_test_issuer_oes_defer_state = 1;
	mtx_unlock(&mac_capability_test_issuer_oes_defer_mtx);
	return (0);
}
SYSCTL_PROC(_debug_mac_capability, OID_AUTO, test_issuer_oes_defer_hold,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    mac_capability_test_issuer_oes_defer_hold_sysctl, "I",
    "Test kernel only: 1 parks OES deferred delivery before its next event, "
    "0 releases it (read: 0 off, 1 armed, 2 parked)");

/*
 * Hold point for an OES client's first use of the decision cache (oes_mac.c
 * oes_gate_client_update()).  Write 1 to arm: the next update that makes a
 * client's cache use count parks after it has taken sc_gate_sx, before it
 * publishes the hooks that drop cached decisions.  Write 2 to wait until
 * such an update has parked.  Write 0 to release it.  A cache adder that
 * waits for the gate (oes_cache.c oes_cache_add()) releases a parked update
 * itself, so a test can tell an adder that waits from one that returns
 * while the hooks are not yet live.  Read: 0 off, 1 armed, 2 parked.
 */
static struct mtx mac_capability_test_issuer_oes_gate_mtx;
MTX_SYSINIT(mac_capability_test_issuer_oes_gate,
    &mac_capability_test_issuer_oes_gate_mtx, "oes gate hold", MTX_DEF);
static int mac_capability_test_issuer_oes_gate_state;

void
mac_capability_test_issuer_oes_gate_park(void)
{

	if (atomic_load_int(&mac_capability_test_issuer_oes_gate_state) == 0)
		return;
	mtx_lock(&mac_capability_test_issuer_oes_gate_mtx);
	if (mac_capability_test_issuer_oes_gate_state == 1) {
		mac_capability_test_issuer_oes_gate_state = 2;
		wakeup(&mac_capability_test_issuer_oes_gate_state);
		while (mac_capability_test_issuer_oes_gate_state == 2)
			mtx_sleep(&mac_capability_test_issuer_oes_gate_state,
			    &mac_capability_test_issuer_oes_gate_mtx, 0,
			    "oesghold", 0);
	}
	mtx_unlock(&mac_capability_test_issuer_oes_gate_mtx);
}

/* Release a parked update; an armed hold nothing has reached stays armed. */
void
mac_capability_test_issuer_oes_gate_release(void)
{

	if (atomic_load_int(&mac_capability_test_issuer_oes_gate_state) != 2)
		return;
	mtx_lock(&mac_capability_test_issuer_oes_gate_mtx);
	if (mac_capability_test_issuer_oes_gate_state == 2) {
		mac_capability_test_issuer_oes_gate_state = 0;
		wakeup(&mac_capability_test_issuer_oes_gate_state);
	}
	mtx_unlock(&mac_capability_test_issuer_oes_gate_mtx);
}

static int
mac_capability_test_issuer_oes_gate_hold_sysctl(SYSCTL_HANDLER_ARGS)
{
	int error, value;

	value = atomic_load_int(&mac_capability_test_issuer_oes_gate_state);
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	error = 0;
	mtx_lock(&mac_capability_test_issuer_oes_gate_mtx);
	switch (value) {
	case 0:
		mac_capability_test_issuer_oes_gate_state = 0;
		wakeup(&mac_capability_test_issuer_oes_gate_state);
		break;
	case 1:
		if (mac_capability_test_issuer_oes_gate_state == 0)
			mac_capability_test_issuer_oes_gate_state = 1;
		break;
	case 2:
		/* Until an update parks, or the hold is released (0). */
		while (error == 0 &&
		    mac_capability_test_issuer_oes_gate_state == 1)
			error = mtx_sleep(
			    &mac_capability_test_issuer_oes_gate_state,
			    &mac_capability_test_issuer_oes_gate_mtx, PCATCH,
			    "oesgwait", 0);
		if (error == 0 && mac_capability_test_issuer_oes_gate_state != 2)
			error = ENOENT;
		break;
	default:
		error = EINVAL;
		break;
	}
	mtx_unlock(&mac_capability_test_issuer_oes_gate_mtx);
	return (error);
}
SYSCTL_PROC(_debug_mac_capability, OID_AUTO, test_issuer_oes_gate_hold,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    mac_capability_test_issuer_oes_gate_hold_sysctl, "I",
    "Test kernel only: 1 parks the next OES cache first-use gate update "
    "before it publishes, 2 waits for it to park, 0 releases it "
    "(read: 0 off, 1 armed, 2 parked)");

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
