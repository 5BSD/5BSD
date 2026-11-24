/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * A debugger's transparent PT_ATTACH (debug.ptrace_attach_transparent=1)
 * of a requester asleep in a served wait.  Only a wait that catches
 * signals, DQ_WAIT_CATCH (an object minted DQ_PF_INTR, a queue with
 * DQ_QF_INTR, a LOCK), can be stopped where it sleeps (TDSC_INPLACE in
 * sleepq_catch_signals).  The other modes run under
 * sigdeferstop(SIGDEFERSTOP_SILENT), whose TDF_SBDRY makes the stop check
 * return before the in-place branch, so they are never stopped in place.
 *
 * Stopped in place, the read keeps its event: the controller sees no
 * INTERRUPT and no second READ, and the read returns the answer, whether
 * the answer comes after the detach or while the thread is stopped.  A
 * non-transparent attach stops the thread at the signal instead: the wait
 * ends (ERESTART), the controller gets an INTERRUPT, and the read is
 * restarted after the detach as a second READ.  The program sees the
 * same data either way; what is pinned is what the controller sees.
 */

#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "dqt.h"

#define	TRANSPARENT	"debug.ptrace_attach_transparent"
#define	READ_LEN	16

static unsigned char data[8192];
static char oracle_path[DQT_PATH_MAX];

/* The debuggee's memory the debugger reads (PT_IO). */
static volatile int poke = 0x5bd;

struct pread_res {
	struct dqt_rr	 rr;
	unsigned char	 buf[READ_LEN];
};

static void
child_pread(void *arg, void *result)
{
	struct pread_res *r = result;

	DQT_RR(r->rr, pread(*(int *)arg, r->buf, sizeof(r->buf), 0));
}

static unsigned
read_events(struct dqt_ctl *c)
{
	unsigned n;

	dqt_lock(c);
	n = c->events[DQ_OP_READ];
	dqt_unlock(c);
	return (n);
}

/* The answer to the i-th held event: the first READ_LEN bytes. */
static void
answer(struct dqt_ctl *c, int i)
{

	ATF_REQUIRE_EQ_MSG(0, dq_reply(c->q, dqt_held_id(c, i), 0, data,
	    READ_LEN), "dq_reply: %s", strerror(errno));
}

enum when {
	ANSWER_AFTER_DETACH,
	ANSWER_WHILE_STOPPED,
};

/*
 * A DQ_PF_INTR object with no deadline; the child's read held by the
 * controller; the child traced (PT_ATTACH, stopped) on return.
 */
static void
attach_setup(struct dqt_ctl *c, int *oraclep, int transparent,
    struct dqt_child *ch, int *fdp)
{
	struct dqt_object *o;
	struct dq_policy pol;
	int st;

	dqt_fill(data, sizeof(data), 91);
	*oraclep = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_sysctl_save_set_uint(TRANSPARENT, (u_int)transparent);
	dqt_init(c);
	dq_policy_default(&pol);
	pol.dp_flags = DQ_PF_INTR;
	pol.dp_deadline_ms = 0;
	o = dqt_mint(c, *oraclep, oracle_path, data, sizeof(data), &pol);
	*fdp = o->fd;
	dqt_hold(c, true);
	dqt_spawn(ch, child_pread, fdp);
	ATF_REQUIRE(dqt_wait_held(c, 1, DQT_WAIT_MS));
	ATF_REQUIRE(dqt_wait_wmesg(ch->pid, DQT_WMESG_REPLY, DQT_WAIT_MS));
	ATF_REQUIRE_EQ_MSG(0, ptrace(PT_ATTACH, ch->pid, NULL, 0),
	    "PT_ATTACH: %s", strerror(errno));
	ATF_REQUIRE_EQ(ch->pid, waitpid(ch->pid, &st, 0));
	ATF_REQUIRE_MSG(WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP,
	    "status %#x", st);
}

/* The debugger looks at the stopped thread's memory, then detaches. */
static void
peek_detach(pid_t pid)
{
	struct ptrace_io_desc piod;
	int val;

	val = 0;
	piod.piod_op = PIOD_READ_D;
	piod.piod_offs = __DEVOLATILE(int *, &poke);
	piod.piod_addr = &val;
	piod.piod_len = sizeof(val);
	ATF_REQUIRE_EQ_MSG(0, ptrace(PT_IO, pid, (caddr_t)&piod, 0),
	    "PT_IO: %s", strerror(errno));
	ATF_CHECK_EQ(0x5bd, val);
	ATF_REQUIRE_EQ_MSG(0, ptrace(PT_DETACH, pid, (caddr_t)1, 0),
	    "PT_DETACH: %s", strerror(errno));
}

static void
transparent_case(enum when when)
{
	struct dqt_ctl c;
	struct dqt_child ch;
	struct pread_res r;
	int fd, oracle;

	attach_setup(&c, &oracle, 1, &ch, &fd);
	/*
	 * Stopped where it sleeps: still in the served wait, its event
	 * still the controller's, no INTERRUPT.
	 */
	ATF_CHECK_MSG(dqt_wait_wmesg(ch.pid, DQT_WMESG_REPLY, 0),
	    "the stopped thread left its served wait");
	ATF_CHECK_MSG(!dqt_wait_interrupts(&c, 1, 0), "the transparent "
	    "attach ended the served wait (INTERRUPT to the controller)");
	if (when == ANSWER_WHILE_STOPPED)
		answer(&c, 0);
	peek_detach(ch.pid);
	if (when == ANSWER_AFTER_DETACH)
		answer(&c, 0);
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(READ_LEN, r.rr.rv, "read: %s", strerror(r.rr.err));
	ATF_CHECK(memcmp(r.buf, data, READ_LEN) == 0);
	/* One READ, no INTERRUPT: the operation was never restarted. */
	ATF_CHECK_EQ(1, read_events(&c));
	ATF_CHECK(!dqt_wait_interrupts(&c, 1, 0));
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC_WITH_CLEANUP(transparent_attach_answer_after_detach);
ATF_TC_HEAD(transparent_attach_answer_after_detach, tc)
{
	atf_tc_set_md_var(tc, "descr", "a transparent PT_ATTACH stops a "
	    "requester in its interruptible served read in place: no "
	    "INTERRUPT; after PT_IO and the detach the answer completes the "
	    "read, with no EINTR and no second READ");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(transparent_attach_answer_after_detach, tc)
{

	transparent_case(ANSWER_AFTER_DETACH);
}
ATF_TC_CLEANUP(transparent_attach_answer_after_detach, tc)
{

	(void)dqt_sysctl_restore(TRANSPARENT);
}

ATF_TC_WITH_CLEANUP(transparent_attach_answer_while_stopped);
ATF_TC_HEAD(transparent_attach_answer_while_stopped, tc)
{
	atf_tc_set_md_var(tc, "descr", "the answer to a served read whose "
	    "thread a transparent PT_ATTACH stopped in place arrives while it "
	    "is stopped: after the detach the read returns it, with no EINTR "
	    "and no second READ");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(transparent_attach_answer_while_stopped, tc)
{

	transparent_case(ANSWER_WHILE_STOPPED);
}
ATF_TC_CLEANUP(transparent_attach_answer_while_stopped, tc)
{

	(void)dqt_sysctl_restore(TRANSPARENT);
}

ATF_TC_WITH_CLEANUP(plain_attach_restarts);
ATF_TC_HEAD(plain_attach_restarts, tc)
{
	atf_tc_set_md_var(tc, "descr", "the contrast: a non-transparent "
	    "PT_ATTACH stops the requester at the signal, its interruptible "
	    "served read ends (INTERRUPT) and is restarted after the detach "
	    "as a second READ, which the answer completes");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(plain_attach_restarts, tc)
{
	struct dqt_ctl c;
	struct dqt_child ch;
	struct pread_res r;
	int fd, oracle;

	attach_setup(&c, &oracle, 0, &ch, &fd);
	ATF_REQUIRE(dqt_wait_interrupts(&c, 1, DQT_WAIT_MS));
	peek_detach(ch.pid);
	ATF_REQUIRE(dqt_wait_held(&c, 2, DQT_WAIT_MS));
	answer(&c, 1);
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(READ_LEN, r.rr.rv, "read: %s", strerror(r.rr.err));
	ATF_CHECK(memcmp(r.buf, data, READ_LEN) == 0);
	ATF_CHECK_EQ(2, read_events(&c));
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
}
ATF_TC_CLEANUP(plain_attach_restarts, tc)
{

	(void)dqt_sysctl_restore(TRANSPARENT);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, transparent_attach_answer_after_detach);
	ATF_TP_ADD_TC(tp, transparent_attach_answer_while_stopped);
	ATF_TP_ADD_TC(tp, plain_attach_restarts);
	return (atf_no_error());
}
