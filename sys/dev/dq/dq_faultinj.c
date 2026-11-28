/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: fault injection for the test suites (options
 * DQ_FAULT_INJECTION).
 *
 * Each knob acts the next N times its point is reached: most widen one
 * window a test must hit, by sleeping one second at a point where no lock
 * is held; refuse_postop_reply refuses a reply instead, and
 * debug.dqres.fail_fhold fails one process's next inheritance of its
 * served starts.  Everything the option adds is in this file, built only
 * with the option (sys/conf/files); the call sites are under the option.
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
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/dqres.h>
#include <sys/sysctl.h>
#include <sys/user.h>

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
SYSCTL_DECL(_debug_dqres);

/*
 * A dead served start (DR_CWD_DEAD, DR_ROOT_DEAD) without 2^31 fholds
 * (D200's dead row): the next inheritance of served starts by the process
 * with this pid (fork, rfork, the copy at an attach) fails its fholds of
 * the served cwd and root, as a reference count about to overflow makes
 * fhold fail.  A pid, not a count: no other process's fork meanwhile is
 * touched.  It does not sleep; 0 is off.
 */
static u_int dq_faultinj_fhold_pid;
SYSCTL_UINT(_debug_dqres, OID_AUTO, fail_fhold, CTLFLAG_RW,
    &dq_faultinj_fhold_pid, 0,
    "Test kernel only: the next inheritance of served starts by this pid "
    "fails their fhold (a dead start)");

bool
dq_faultinj_fhold_fail(void)
{
	u_int pid;

	pid = atomic_load_int(&dq_faultinj_fhold_pid);
	if (pid == 0 || pid != (u_int)curproc->p_pid)
		return (false);
	return (atomic_cmpset_int(&dq_faultinj_fhold_pid, pid, 0) != 0);
}

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

/*
 * A post-operation block the kernel refuses (EINVAL, the event left in
 * flight), so a test can see that libdq reports the refusal and keeps
 * offering blocks.
 */
static u_int dq_faultinj_postop_refusals;
SYSCTL_UINT(_debug_dq, OID_AUTO, refuse_postop_reply, CTLFLAG_RW,
    &dq_faultinj_postop_refusals, 0,
    "Test kernel only: the next N replies that carry a post-operation "
    "block are refused with EINVAL");

/*
 * Wakeups a test drops to prove that its waiter has no other way out
 * (DQ_WAKE_* of dq_var.h, a mask): with the bit set, that wakeup is not
 * issued until the bit is cleared.  The dq waits are event-driven (no
 * polling), so a dropped wakeup leaves its waiter asleep.
 */
static u_int dq_faultinj_drop_wakeups;
SYSCTL_UINT(_debug_dq, OID_AUTO, drop_wakeup, CTLFLAG_RW,
    &dq_faultinj_drop_wakeups, 0,
    "Test kernel only: a mask of DQ_WAKE_* wakeups not issued");

/*
 * Each wakeup dropped counts here, per site (the bit's index), so a test
 * knows the moment its waiter's only way out was taken, and an unrelated
 * drop cannot stand in for it.  debug.dq.wakeups_dropped reads the
 * counts; a write of struct dq_faultinj_dropwait to
 * debug.dq.wakeup_drop_wait sleeps (catching signals) until the site's
 * count reaches dw_count: the test waits on the event, not on a timer.
 */
static struct mtx dq_faultinj_drop_mtx;
MTX_SYSINIT(dq_faultinj_drop, &dq_faultinj_drop_mtx, "dq faultinj drop",
    MTX_DEF);
static uint64_t dq_faultinj_dropped[DQ_WAKE_NSITES];

static int
dq_faultinj_dropped_sysctl(SYSCTL_HANDLER_ARGS)
{
	uint64_t counts[DQ_WAKE_NSITES];

	mtx_lock(&dq_faultinj_drop_mtx);
	memcpy(counts, dq_faultinj_dropped, sizeof(counts));
	mtx_unlock(&dq_faultinj_drop_mtx);
	return (SYSCTL_OUT(req, counts, sizeof(counts)));
}
SYSCTL_PROC(_debug_dq, OID_AUTO, wakeups_dropped,
    CTLTYPE_OPAQUE | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    dq_faultinj_dropped_sysctl, "S",
    "Test kernel only: wakeups drop_wakeup has dropped, per DQ_WAKE_* bit");

struct dq_faultinj_dropwait {
	uint32_t	dw_site;	/* a DQ_WAKE_* bit */
	uint32_t	dw_pad;
	uint64_t	dw_count;	/* until the site's count reaches it */
};

static int
dq_faultinj_dropwait_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct dq_faultinj_dropwait dw;
	int error, idx;

	if (req->newptr == NULL)
		return (SYSCTL_OUT(req, NULL, 0));
	error = SYSCTL_IN(req, &dw, sizeof(dw));
	if (error != 0)
		return (error);
	if (dw.dw_site == 0 || !powerof2(dw.dw_site) ||
	    (idx = ffs(dw.dw_site) - 1) >= DQ_WAKE_NSITES)
		return (EINVAL);
	mtx_lock(&dq_faultinj_drop_mtx);
	while (dq_faultinj_dropped[idx] < dw.dw_count) {
		error = msleep(&dq_faultinj_dropped, &dq_faultinj_drop_mtx,
		    PCATCH, "dqdrpw", 0);
		if (error != 0)
			break;
	}
	mtx_unlock(&dq_faultinj_drop_mtx);
	return (error);
}
SYSCTL_PROC(_debug_dq, OID_AUTO, wakeup_drop_wait,
    CTLTYPE_OPAQUE | CTLFLAG_WR | CTLFLAG_MPSAFE, NULL, 0,
    dq_faultinj_dropwait_sysctl, "S",
    "Test kernel only: sleep until a DQ_WAKE_* site has dropped N wakeups");

bool
dq_faultinj_wake(u_int site)
{

	if ((atomic_load_int(&dq_faultinj_drop_wakeups) & site) == 0)
		return (true);
	mtx_lock(&dq_faultinj_drop_mtx);
	dq_faultinj_dropped[ffs(site) - 1]++;
	wakeup(&dq_faultinj_dropped);
	mtx_unlock(&dq_faultinj_drop_mtx);
	return (false);
}

/*
 * debug.dq.thread_sleeps.<pid>: each thread of the process asleep, with
 * its wmesg and the time left before its sleep's timeout (0: none).  A
 * test that drops a wakeup proves with it that the waiter is still in its
 * sleep and that the sleep has no timer that could end it, so a wait
 * re-checking on a timer cannot pass for one that waits on the event.
 */
struct dq_faultinj_sleep {
	int32_t		ds_tid;
	uint32_t	ds_pad;
	uint64_t	ds_left_ms;	/* 0: no timeout */
	char		ds_wmesg[WMESGLEN + 1];
};

static int
dq_faultinj_sleeps_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct dq_faultinj_sleep ds;
	struct thread *td;
	struct proc *p;
	sbintime_t now, timo;
	int *name, error;

	name = (int *)arg1;
	if (arg2 != 1)
		return (EINVAL);
	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);
	p = pfind(name[0]);
	if (p == NULL)
		return (ESRCH);
	/* What kern.proc shows: p_cansee, with the MAC policies' say. */
	error = p_cansee(curthread, p);
	if (error != 0) {
		PROC_UNLOCK(p);
		return (error);
	}
	now = sbinuptime();
	error = 0;
	FOREACH_THREAD_IN_PROC(p, td) {
		memset(&ds, 0, sizeof(ds));
		thread_lock(td);
		if (TD_ON_SLEEPQ(td) && td->td_wmesg != NULL) {
			ds.ds_tid = td->td_tid;
			strlcpy(ds.ds_wmesg, td->td_wmesg,
			    sizeof(ds.ds_wmesg));
			timo = td->td_sleeptimo;
			ds.ds_left_ms = timo == 0 ? 0 : timo > now ?
			    (uint64_t)((timo - now) / SBT_1MS) + 1 : 1;
		}
		thread_unlock(td);
		if (ds.ds_tid == 0)
			continue;
		error = SYSCTL_OUT(req, &ds, sizeof(ds));
		if (error != 0)
			break;
	}
	PROC_UNLOCK(p);
	return (error);
}
static SYSCTL_NODE(_debug_dq, OID_AUTO, thread_sleeps,
    CTLFLAG_RD | CTLFLAG_MPSAFE, dq_faultinj_sleeps_sysctl,
    "Test kernel only: a process's sleeping threads, wmesg and timeout");

static bool
dq_faultinj_take(u_int *counter)
{
	u_int n;

	do {
		n = atomic_load_int(counter);
		if (n == 0)
			return (false);
	} while (!atomic_cmpset_int(counter, n, n - 1));
	return (true);
}

static void
dq_faultinj_pause(u_int *counter, const char *wmesg)
{

	if (dq_faultinj_take(counter))
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

bool
dq_faultinj_postop_refuse(void)
{

	return (dq_faultinj_take(&dq_faultinj_postop_refusals));
}

/*
 * The quota sleeps of waited posts (dq_post_quota_sleep), counted per
 * quota (DQ_QUOTA_OBJECT, DQ_QUOTA_REQUESTER: index quota - 1) as each
 * sleep begins, after ds2_quota_waiters is raised and with the queue lock
 * still held, so a test woken here that reads the statistics finds the
 * waiter counted and asleep.  debug.dq.quota_sleeps reads the counts; a
 * write of struct dq_faultinj_quotawait to debug.dq.quota_sleep_wait
 * sleeps (catching signals) until the quota's count reaches qw_count: the
 * test waits on the sleep itself, not on a sample of wait messages.
 */
#define	DQ_FAULTINJ_NQUOTAS	2
static struct mtx dq_faultinj_quota_mtx;
MTX_SYSINIT(dq_faultinj_quota, &dq_faultinj_quota_mtx, "dq faultinj quota",
    MTX_DEF);
static uint64_t dq_faultinj_quota_slept[DQ_FAULTINJ_NQUOTAS];

static int
dq_faultinj_quota_sleeps_sysctl(SYSCTL_HANDLER_ARGS)
{
	uint64_t counts[DQ_FAULTINJ_NQUOTAS];

	mtx_lock(&dq_faultinj_quota_mtx);
	memcpy(counts, dq_faultinj_quota_slept, sizeof(counts));
	mtx_unlock(&dq_faultinj_quota_mtx);
	return (SYSCTL_OUT(req, counts, sizeof(counts)));
}
SYSCTL_PROC(_debug_dq, OID_AUTO, quota_sleeps,
    CTLTYPE_OPAQUE | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    dq_faultinj_quota_sleeps_sysctl, "S",
    "Test kernel only: quota sleeps of waited posts, object then requester");

struct dq_faultinj_quotawait {
	uint32_t	qw_quota;	/* DQ_QUOTA_OBJECT or _REQUESTER */
	uint32_t	qw_pad;
	uint64_t	qw_count;	/* until the quota's count reaches it */
};

static int
dq_faultinj_quotawait_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct dq_faultinj_quotawait qw;
	int error;

	if (req->newptr == NULL)
		return (SYSCTL_OUT(req, NULL, 0));
	error = SYSCTL_IN(req, &qw, sizeof(qw));
	if (error != 0)
		return (error);
	if (qw.qw_quota != DQ_QUOTA_OBJECT &&
	    qw.qw_quota != DQ_QUOTA_REQUESTER)
		return (EINVAL);
	mtx_lock(&dq_faultinj_quota_mtx);
	while (dq_faultinj_quota_slept[qw.qw_quota - 1] < qw.qw_count) {
		error = msleep(&dq_faultinj_quota_slept,
		    &dq_faultinj_quota_mtx, PCATCH, "dqqslw", 0);
		if (error != 0)
			break;
	}
	mtx_unlock(&dq_faultinj_quota_mtx);
	return (error);
}
SYSCTL_PROC(_debug_dq, OID_AUTO, quota_sleep_wait,
    CTLTYPE_OPAQUE | CTLFLAG_WR | CTLFLAG_MPSAFE, NULL, 0,
    dq_faultinj_quotawait_sysctl, "S",
    "Test kernel only: sleep until a quota has had N quota sleeps");

void
dq_faultinj_quota_sleep(u_int quota)
{

	KASSERT(quota == DQ_QUOTA_OBJECT || quota == DQ_QUOTA_REQUESTER,
	    ("dq_faultinj_quota_sleep: quota %u", quota));
	mtx_lock(&dq_faultinj_quota_mtx);
	dq_faultinj_quota_slept[quota - 1]++;
	wakeup(&dq_faultinj_quota_slept);
	mtx_unlock(&dq_faultinj_quota_mtx);
}
