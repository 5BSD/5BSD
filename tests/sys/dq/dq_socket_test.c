/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * RESOLVE for sockets (stage 1c-ii, D139, D155): socket(2) and
 * socketpair(2) of an attached process post one event each, after the
 * protocol lookup, the capability-mode test and the jail's address-family
 * test and before any descriptor slot exists, with the protocol as the
 * kernel resolved it and the type without its SOCK_* flags.  Errors keep
 * upstream's precedence: a full descriptor table is EMFILE to socket(2)
 * before any other test, attached or not, and posts nothing.  The controller
 * answers PASS or an errno from the socket list; a dead controller is
 * EACCES (D136).  Kernel socket creation (socreate) is never consulted.
 * Abstract AF_UNIX names, consulted since 1c-i, are posted with
 * DQ_RF_ABSTRACT.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/jail.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/procdesc.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <netinet/in.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <libutil.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

#define	DTRACE		"/usr/sbin/dtrace"

struct sock_res {
	struct dqt_rr	 r[8];
	int		 fdflags, flflags;
	int		 nextfd;
	char		 pairbuf[4];
};

#define	RR(rr, call) do {						\
	errno = 0;							\
	(rr).rv = (long)(call);						\
	(rr).err = (rr).rv == -1 ? errno : 0;				\
} while (0)

/* The index of the n-th (from 0) recorded event of op, or -1. */
static int
nth_event(struct dqt_ctl *c, uint32_t op, int n)
    __requires_unlocked(c->mtx)
{
	int i;

	dqt_lock(c);
	for (i = 0; i < c->nrs; i++)
		if (c->rs[i].op == op && n-- == 0)
			break;
	if (i == c->nrs)
		i = -1;
	dqt_unlock(c);
	return (i);
}

static int
count_events(struct dqt_ctl *c, uint32_t op, int domain, int type)
    __requires_unlocked(c->mtx)
{
	int i, n;

	n = 0;
	dqt_lock(c);
	for (i = 0; i < c->nrs; i++)
		if (c->rs[i].op == op && (domain == -1 ||
		    c->rs[i].domain == domain) && (type == -1 ||
		    c->rs[i].type == type))
			n++;
	dqt_unlock(c);
	return (n);
}

static void
check_socket_event(struct dqt_ctl *c, int i, uint32_t op, int domain,
    int type, int protocol)
    __requires_unlocked(c->mtx)
{

	ATF_REQUIRE_MSG(i != -1, "no event of op %u", op);
	dqt_lock(c);
	ATF_CHECK_EQ(op, c->rs[i].op);
	ATF_CHECK_EQ(domain, c->rs[i].domain);
	ATF_CHECK_EQ_MSG(type, c->rs[i].type, "type %d", c->rs[i].type);
	ATF_CHECK_EQ_MSG(protocol, c->rs[i].protocol, "protocol %d",
	    c->rs[i].protocol);
	ATF_CHECK_EQ(DQ_RCLASS_USER, c->rs[i].cls);
	ATF_CHECK_EQ(DQ_RF_USER, c->rs[i].rflags);
	ATF_CHECK_EQ(DQ_START_NONE, c->rs[i].start_kind);
	ATF_CHECK_EQ(0, c->rs[i].pathlen);
	ATF_CHECK_STREQ("", c->rs[i].path);
	ATF_CHECK_STREQ("", c->rs[i].path2);
	ATF_CHECK_EQ(op == DQ_ROP_SOCKET ? SYS_socket : SYS_socketpair,
	    (int)c->rs[i].syscall);
	ATF_CHECK((c->rs[i].caller_flags & DQ_CALLER_F_ATTACHED) != 0);
	dqt_unlock(c);
}

/*
 * protocol_resolved
 */

static void
child_protocols(void *arg __unused, void *result)
{
	struct sock_res *r = result;
	int s;

	RR(r->r[0], s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC |
	    SOCK_NONBLOCK, 0));
	if (s != -1) {
		r->fdflags = fcntl(s, F_GETFD);
		r->flflags = fcntl(s, F_GETFL);
	}
	RR(r->r[1], socket(AF_INET, SOCK_DGRAM, 0));
	/* Raw IP is a wildcard protosw: the requested protocol is posted. */
	RR(r->r[2], socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
	RR(r->r[3], socket(AF_UNIX, SOCK_SEQPACKET, 0));
	/* Refused by the protocol lookup: nothing is posted. */
	RR(r->r[4], socket(AF_UNIX, SOCK_RAW, 0));
	RR(r->r[5], socket(AF_MAX + 10, SOCK_STREAM, 0));
}

ATF_TC(protocol_resolved);
ATF_TC_HEAD(protocol_resolved, tc)
{
	atf_tc_set_md_var(tc, "descr", "socket(2) posts one SOCKET event with "
	    "the domain, the type without SOCK_CLOEXEC/SOCK_NONBLOCK and the "
	    "protocol the kernel resolved (SOCK_STREAM 0 on AF_INET is "
	    "IPPROTO_TCP; raw IP posts the requested protocol), class USER, "
	    "start NONE and no path; the flags still apply to the descriptor; "
	    "a request the protocol lookup refuses posts nothing");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(protocol_resolved, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct sock_res r;
	struct dq_stats2 st;

	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, child_protocols, NULL);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_MSG(r.r[0].rv >= 0, "socket: %s", strerror(r.r[0].err));
	ATF_CHECK((r.fdflags & FD_CLOEXEC) != 0);
	ATF_CHECK((r.flflags & O_NONBLOCK) != 0);
	ATF_CHECK(r.r[1].rv >= 0);
	ATF_CHECK(r.r[2].rv >= 0);
	ATF_CHECK(r.r[3].rv >= 0);
	ATF_CHECK_EQ(-1, r.r[4].rv);
	ATF_CHECK_EQ(EPROTOTYPE, r.r[4].err);
	ATF_CHECK_EQ(-1, r.r[5].rv);
	ATF_CHECK_EQ(EAFNOSUPPORT, r.r[5].err);

	ATF_CHECK_EQ(4, count_events(&c, DQ_ROP_SOCKET, -1, -1));
	check_socket_event(&c, nth_event(&c, DQ_ROP_SOCKET, 0), DQ_ROP_SOCKET,
	    AF_INET, SOCK_STREAM, IPPROTO_TCP);
	check_socket_event(&c, nth_event(&c, DQ_ROP_SOCKET, 1), DQ_ROP_SOCKET,
	    AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	check_socket_event(&c, nth_event(&c, DQ_ROP_SOCKET, 2), DQ_ROP_SOCKET,
	    AF_INET, SOCK_RAW, IPPROTO_ICMP);
	check_socket_event(&c, nth_event(&c, DQ_ROP_SOCKET, 3), DQ_ROP_SOCKET,
	    AF_UNIX, SOCK_SEQPACKET, 0);
	ATF_CHECK_EQ(0, count_events(&c, DQ_ROP_SOCKET, AF_UNIX, SOCK_RAW));
	dqt_stats2(&c, &st);
	ATF_CHECK_EQ(0, st.ds2_resolve_failclosed);
	ATF_CHECK_EQ(0, st.ds2_resolve_kernel);
	dqt_fini(&c);
}

/*
 * socketpair_one_event
 */

static void
child_pair(void *arg __unused, void *result)
{
	struct sock_res *r = result;
	int sv[2];

	RR(r->r[0], socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv));
	if (r->r[0].rv == 0) {
		r->fdflags = fcntl(sv[1], F_GETFD);
		RR(r->r[1], write(sv[0], "abc", 3));
		RR(r->r[2], read(sv[1], r->pairbuf, 3));
	}
	RR(r->r[3], socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));
	/* Found, consulted, then refused by the protocol (no connect2). */
	RR(r->r[4], socketpair(AF_INET, SOCK_STREAM, 0, sv));
}

ATF_TC(socketpair_one_event);
ATF_TC_HEAD(socketpair_one_event, tc)
{
	atf_tc_set_md_var(tc, "descr", "socketpair(2) posts exactly one "
	    "SOCKETPAIR event (no SOCKET event) for the pair, which then works; "
	    "a pair the protocol cannot connect is posted and fails as "
	    "unattached");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(socketpair_one_event, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct sock_res o, r;

	memset(&o, 0, sizeof(o));
	dqt_run_child(child_pair, NULL, &o, sizeof(o));

	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, child_pair, NULL);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(0, r.r[0].rv);
	ATF_CHECK((r.fdflags & FD_CLOEXEC) != 0);
	ATF_CHECK_EQ(3, r.r[2].rv);
	ATF_CHECK_EQ(0, memcmp(r.pairbuf, "abc", 3));
	ATF_CHECK_EQ(0, r.r[3].rv);
	ATF_CHECK_EQ(o.r[4].rv, r.r[4].rv);
	ATF_CHECK_EQ(o.r[4].err, r.r[4].err);
	ATF_CHECK_EQ(0, count_events(&c, DQ_ROP_SOCKET, -1, -1));
	ATF_CHECK_EQ(3, count_events(&c, DQ_ROP_SOCKETPAIR, -1, -1));
	check_socket_event(&c, nth_event(&c, DQ_ROP_SOCKETPAIR, 0),
	    DQ_ROP_SOCKETPAIR, AF_UNIX, SOCK_STREAM, 0);
	check_socket_event(&c, nth_event(&c, DQ_ROP_SOCKETPAIR, 1),
	    DQ_ROP_SOCKETPAIR, AF_UNIX, SOCK_DGRAM, 0);
	check_socket_event(&c, nth_event(&c, DQ_ROP_SOCKETPAIR, 2),
	    DQ_ROP_SOCKETPAIR, AF_INET, SOCK_STREAM, IPPROTO_TCP);
	dqt_fini(&c);
}

/*
 * capmode_no_event
 */

static void
child_capmode(void *arg __unused, void *result)
{
	struct sock_res *r = result;
	int sv[2];

	if (cap_enter() != 0)
		_exit(5);
	/* Raw IP has no PR_CAPATTACH: ECAPMODE before any consultation. */
	RR(r->r[0], socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
	/* TCP and AF_UNIX may be created in capability mode: consulted. */
	RR(r->r[1], socket(AF_INET, SOCK_STREAM, 0));
	RR(r->r[2], socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
}

ATF_TC(capmode_no_event);
ATF_TC_HEAD(capmode_no_event, tc)
{
	atf_tc_set_md_var(tc, "descr", "in capability mode a protocol without "
	    "PR_CAPATTACH fails with ECAPMODE and posts nothing; protocols "
	    "capability mode allows are consulted");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(capmode_no_event, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct sock_res r;

	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, child_capmode, NULL);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.r[0].rv);
	ATF_CHECK_EQ(ECAPMODE, r.r[0].err);
	ATF_CHECK_EQ(0, count_events(&c, DQ_ROP_SOCKET, AF_INET, SOCK_RAW));
	ATF_CHECK(r.r[1].rv >= 0);
	ATF_CHECK_EQ(1, count_events(&c, DQ_ROP_SOCKET, AF_INET,
	    SOCK_STREAM));
	ATF_CHECK_EQ(0, r.r[2].rv);
	ATF_CHECK_EQ(1, count_events(&c, DQ_ROP_SOCKETPAIR, AF_UNIX, -1));
	dqt_fini(&c);
}

/*
 * mac_denial_no_event
 *
 * The mac_test_hooks policy returns a hook's deny toggle from the hook
 * while the toggle is set.  A toggle acts on every process, so the child
 * keeps it set for one system call at a time, the case is exclusive, and
 * the cleanup clears it.
 */
#define	MAC_HOOKS		"mac_test_hooks"
#define	MAC_HOOKS_LOADED	"mac_test_hooks.loaded"
#define	MAC_CREATE_DENY							\
	"security.mac.test_hooks.deny.socket_check_create"
#define	MAC_CREATE_COUNT						\
	"security.mac.test_hooks.counter.socket_check_create"

static int
mac_create_deny(int error)
{

	return (sysctlbyname(MAC_CREATE_DENY, NULL, NULL, &error,
	    sizeof(error)));
}

static void
child_mac_denied(void *arg __unused, void *result)
{
	struct sock_res *r = result;
	int sv[2];

	if (mac_create_deny(EPERM) != 0)
		_exit(6);
	RR(r->r[0], socket(AF_INET, SOCK_DGRAM, 0));
	if (mac_create_deny(0) != 0 || mac_create_deny(EPERM) != 0)
		_exit(7);
	RR(r->r[1], socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	if (mac_create_deny(0) != 0)
		_exit(8);
	/* The same call once the policy allows it: consulted. */
	RR(r->r[2], socket(AF_INET, SOCK_DGRAM, 0));
}

ATF_TC_WITH_CLEANUP(mac_denial_no_event);
ATF_TC_HEAD(mac_denial_no_event, tc)
{
	atf_tc_set_md_var(tc, "descr", "a MAC denial of socket creation "
	    "(mac_socket_check_create) is socket(2)'s and socketpair(2)'s "
	    "result and posts nothing; the same call is consulted once the "
	    "policy allows it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mac_denial_no_event, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct sock_res r;
	size_t len;
	int after, before, fd, status;

	/*
	 * kern_socket and kern_socketpair call mac_socket_check_create
	 * before socreate_find and the consultation.  Of the policies in
	 * the tree only mac_test_hooks can refuse it: mac_abac allows every
	 * creation (abac_socket.c) and OES only notifies.
	 */
	if (kldfind(MAC_HOOKS) == -1) {
		/* The capability plane refuses a module load this late. */
		if (kldload(MAC_HOOKS) == -1)
			atf_tc_fail("%s is not loaded and cannot be loaded "
			    "now (%s); preload it", MAC_HOOKS, strerror(errno));
		/* Loaded here, so the cleanup unloads it. */
		fd = open(MAC_HOOKS_LOADED, O_CREAT | O_WRONLY, 0600);
		ATF_REQUIRE(fd >= 0);
		(void)close(fd);
	}
	len = sizeof(before);
	if (sysctlbyname(MAC_CREATE_COUNT, &before, &len, NULL, 0) != 0) {
		if (errno == ENOENT)
			atf_tc_fail("this kernel's %s has no "
			    "socket_check_create hook", MAC_HOOKS);
		atf_tc_fail("%s: %s", MAC_CREATE_COUNT, strerror(errno));
	}

	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, child_mac_denied, NULL);
	memset(&r, 0, sizeof(r));
	status = dqt_attach_wait(&ch, &r, sizeof(r));
	ATF_REQUIRE_EQ(0, mac_create_deny(0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "the program: status %#x", status);
	len = sizeof(after);
	ATF_REQUIRE_EQ(0, sysctlbyname(MAC_CREATE_COUNT, &after, &len, NULL,
	    0));
	ATF_CHECK_MSG(after - before >= 3, "the policy's hook ran %d times",
	    after - before);

	ATF_CHECK_EQ(-1, r.r[0].rv);
	ATF_CHECK_EQ(EPERM, r.r[0].err);
	ATF_CHECK_EQ(-1, r.r[1].rv);
	ATF_CHECK_EQ(EPERM, r.r[1].err);
	ATF_CHECK_EQ(0, count_events(&c, DQ_ROP_SOCKETPAIR, -1, -1));
	/* The one event is the allowed call's. */
	ATF_CHECK_MSG(r.r[2].rv >= 0, "socket once allowed: errno %d",
	    r.r[2].err);
	ATF_CHECK_EQ(1, count_events(&c, DQ_ROP_SOCKET, -1, -1));
	ATF_CHECK_EQ(1, count_events(&c, DQ_ROP_SOCKET, AF_INET,
	    SOCK_DGRAM));
	dqt_fini(&c);
}
ATF_TC_CLEANUP(mac_denial_no_event, tc)
{
	int id;

	(void)mac_create_deny(0);
	if (access(MAC_HOOKS_LOADED, F_OK) == 0 &&
	    (id = kldfind(MAC_HOOKS)) != -1)
		(void)kldunload(id);
}

/*
 * errno_answers
 */

static void
child_one_socket(void *arg __unused, void *result)
{
	struct sock_res *r = result;
	int sv[2];

	r->nextfd = dup(0);
	if (r->nextfd != -1)
		(void)close(r->nextfd);
	RR(r->r[0], socket(AF_INET, SOCK_DGRAM, 0));
	RR(r->r[1], socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	/* No descriptor was used by a refusal. */
	RR(r->r[2], dup(0));
}

ATF_TC(errno_answers);
ATF_TC_HEAD(errno_answers, tc)
{
	atf_tc_set_md_var(tc, "descr", "an errno answer from the socket list "
	    "(EACCES, EPERM) is socket(2)'s and socketpair(2)'s result and uses "
	    "no descriptor; an errno outside the socket list (ENOENT, EIO) "
	    "arrives as EIO and counts in ds2_bad_replies");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(errno_answers, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct sock_res r;
	struct dq_stats2 st;

	dqt_init(&c);
	dqt_resolve_errno(&c, DQ_ROP_SOCKET, EACCES);
	dqt_resolve_errno(&c, DQ_ROP_SOCKETPAIR, EPERM);
	dqt_attach_spawn(&c, &ch, child_one_socket, NULL);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.r[0].rv);
	ATF_CHECK_EQ(EACCES, r.r[0].err);
	ATF_CHECK_EQ(-1, r.r[1].rv);
	ATF_CHECK_EQ(EPERM, r.r[1].err);
	ATF_CHECK_EQ(r.nextfd, r.r[2].rv);
	dqt_stats2(&c, &st);
	ATF_CHECK_EQ(0, st.ds2_bad_replies);
	dqt_fini(&c);

	dqt_init(&c);
	dqt_resolve_errno(&c, DQ_ROP_SOCKET, ENOENT);	/* a lookup's errno */
	dqt_resolve_errno(&c, DQ_ROP_SOCKETPAIR, EINTR);	/* not on the list */
	dqt_attach_spawn(&c, &ch, child_one_socket, NULL);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(EIO, r.r[0].err);
	ATF_CHECK_EQ(EIO, r.r[1].err);
	dqt_stats2(&c, &st);
	ATF_CHECK_EQ(2, st.ds2_bad_replies);
	dqt_fini(&c);
}

/*
 * fd_reply_einval and no_fd_slot_while_waiting
 */

struct slot_arg {
	int		 tellfd;	/* the next free descriptor goes here */
};

static void
child_slot(void *arg, void *result)
{
	struct slot_arg *a = arg;
	struct sock_res *r = result;

	r->nextfd = dup(0);
	if (r->nextfd != -1)
		(void)close(r->nextfd);
	(void)write(a->tellfd, &r->nextfd, sizeof(r->nextfd));
	RR(r->r[0], socket(AF_INET, SOCK_STREAM, 0));
}

/* Files of pid: the count and whether descriptor fd is among them. */
static int
files_of(pid_t pid, int fd, bool *hasfd)
{
	struct kinfo_file *kf;
	int i, n;

	kf = kinfo_getfile(pid, &n);
	ATF_REQUIRE_MSG(kf != NULL, "kinfo_getfile: %s", strerror(errno));
	*hasfd = false;
	for (i = 0; i < n; i++)
		if (kf[i].kf_fd == fd)
			*hasfd = true;
	free(kf);
	return (n);
}

ATF_TC(no_fd_slot_while_waiting);
ATF_TC_HEAD(no_fd_slot_while_waiting, tc)
{
	atf_tc_set_md_var(tc, "descr", "while the controller holds a SOCKET "
	    "event the requester's descriptor table is unchanged: the "
	    "descriptor the socket will get is not allocated; an FD-kind reply "
	    "is EINVAL to the controller and the event stays in flight; PASS "
	    "then gives the socket that descriptor");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(no_fd_slot_while_waiting, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct slot_arg a;
	struct sock_res r;
	struct dq_resolve_reply rr;
	uint64_t id;
	bool has;
	int tell[2], next, n1, n2;

	ATF_REQUIRE_EQ(0, pipe(tell));
	a.tellfd = tell[1];
	dqt_init(&c);
	dqt_resolve_hold(&c, NULL, DQ_ROP_SOCKET);
	dqt_attach_spawn(&c, &ch, child_slot, &a);
	(void)close(tell[1]);
	ATF_REQUIRE_EQ((ssize_t)sizeof(next), read(tell[0], &next,
	    sizeof(next)));
	ATF_REQUIRE(next >= 0);
	n1 = files_of(ch.pid, next, &has);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	id = dqt_held_id(&c, 0);
	n2 = files_of(ch.pid, next, &has);
	ATF_CHECK_MSG(!has, "descriptor %d is allocated while the SOCKET "
	    "event waits", next);
	ATF_CHECK_EQ_MSG(n1, n2, "%d files before the wait, %d during", n1,
	    n2);

	/* An FD reply is stage 2: EINVAL, the event stays in flight. */
	memset(&rr, 0, sizeof(rr));
	rr.drr_kind = DQ_RESOLVE_FD;
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(c.q, id, 0, &rr, sizeof(rr)));
	ATF_CHECK_EQ(EINVAL, errno);
	n2 = files_of(ch.pid, next, &has);
	ATF_CHECK(!has);
	dqt_resolve_hold(&c, NULL, 0);
	ATF_CHECK_EQ(0, dq_reply_resolve_pass(c.q, id));
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(next, r.r[0].rv);
	ATF_CHECK_EQ(1, count_events(&c, DQ_ROP_SOCKET, -1, -1));
	(void)close(tell[0]);
	dqt_fini(&c);
}

/*
 * dead_controller_eacces
 */

static void
child_dead(void *arg __unused, void *result)
{
	struct sock_res *r = result;
	struct stat sb;
	int sv[2];

	RR(r->r[0], socket(AF_INET, SOCK_STREAM, 0));	/* held */
	RR(r->r[1], socket(AF_INET, SOCK_STREAM, 0));
	RR(r->r[2], socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	RR(r->r[3], stat("/bin/sh", &sb));		/* a lookup: EIO */
}

/* dtrace counting a probe for one pid; -1 and a reason when it cannot. */
struct dtrace_run {
	pid_t		 pid;
	FILE		*out;
};

static int
dtrace_start(struct dtrace_run *d, const char *prog, char *why, size_t len)
{
	char line[256];
	int pfd[2];

	d->pid = -1;
	d->out = NULL;
	if (access(DTRACE, X_OK) != 0) {
		(void)snprintf(why, len, "no %s", DTRACE);
		return (-1);
	}
	ATF_REQUIRE_EQ(0, pipe(pfd));
	d->pid = fork();
	ATF_REQUIRE(d->pid != -1);
	if (d->pid == 0) {
		(void)dup2(pfd[1], STDOUT_FILENO);
		(void)dup2(pfd[1], STDERR_FILENO);
		(void)close(pfd[0]);
		execl(DTRACE, "dtrace", "-q", "-n", prog, (char *)NULL);
		_exit(127);
	}
	(void)close(pfd[1]);
	d->out = fdopen(pfd[0], "r");
	ATF_REQUIRE(d->out != NULL);
	why[0] = '\0';
	while (fgets(line, sizeof(line), d->out) != NULL) {
		if (strcmp(line, "ready\n") == 0)
			return (0);
		if (why[0] == '\0')
			(void)strlcpy(why, line, len);
	}
	if (why[0] == '\0')
		(void)strlcpy(why, "dtrace exited before tracing", len);
	(void)fclose(d->out);
	d->out = NULL;
	(void)waitpid(d->pid, NULL, 0);
	d->pid = -1;
	return (-1);
}

static long
dtrace_stop(struct dtrace_run *d)
{
	char line[256];
	long count;

	if (d->pid == -1)
		return (-1);
	(void)kill(d->pid, SIGINT);
	count = -1;
	while (fgets(line, sizeof(line), d->out) != NULL)
		if (sscanf(line, "count %ld", &count) == 1)
			break;
	(void)fclose(d->out);
	(void)waitpid(d->pid, NULL, 0);
	return (count);
}

/* kern.dq.stats.NAME: the system-wide counter (never reset). */
static uint64_t
gstat(const char *name)
{
	char oid[64];
	uint64_t v;
	size_t len;

	(void)snprintf(oid, sizeof(oid), "kern.dq.stats.%s", name);
	len = sizeof(v);
	ATF_REQUIRE_MSG(sysctlbyname(oid, &v, &len, NULL, 0) == 0 &&
	    len == sizeof(v), "%s: %s", oid, strerror(errno));
	return (v);
}

/*
 * Hold a SOCKET event, close the queue (optionally with dtrace counting
 * the probe for the requester), and check what the requester got.
 * Returns the probe count, or -1 without dtrace (the reason in why).
 */
static long
dead_controller(uint64_t *delta, bool trace, char *why, size_t whylen)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct dtrace_run d;
	struct sock_res r;
	char prog[256];
	uint64_t before;
	long n;

	dqt_init(&c);
	dqt_resolve_hold(&c, NULL, DQ_ROP_SOCKET);
	before = gstat("resolve_failclosed");
	dqt_attach_spawn(&c, &ch, child_dead, NULL);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	d.pid = -1;
	if (trace) {
		(void)snprintf(prog, sizeof(prog),
		    "BEGIN { printf(\"ready\\n\"); } "
		    "dq:::resolve-failclosed /pid == %d/ { n++; } "
		    "END { printf(\"count %%d\\n\", n); }", (int)ch.pid);
		(void)dtrace_start(&d, prog, why, whylen);
	}
	dqt_close_queue(&c);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.r[0].rv);
	ATF_CHECK_EQ_MSG(EACCES, r.r[0].err, "waiting socket: %s",
	    strerror(r.r[0].err));
	ATF_CHECK_EQ(EACCES, r.r[1].err);
	ATF_CHECK_EQ(EACCES, r.r[2].err);
	ATF_CHECK_EQ(EIO, r.r[3].err);
	*delta = gstat("resolve_failclosed") - before;
	n = dtrace_stop(&d);
	dqt_fini(&c);
	return (n);
}

ATF_TC(dead_controller_eacces);
ATF_TC_HEAD(dead_controller_eacces, tc)
{
	atf_tc_set_md_var(tc, "descr", "when the controller's queue closes, a "
	    "waiting socket(2) and every later socket(2) and socketpair(2) of "
	    "the attached process fail with EACCES (a lookup with EIO), each "
	    "counted as failed closed: kern.dq.stats.resolve_failclosed grows "
	    "by 4 (the queue's own ds2 counter dies with it)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(dead_controller_eacces, tc)
{
	uint64_t delta;
	char why[256];

	(void)dead_controller(&delta, false, why, sizeof(why));
	ATF_CHECK_EQ_MSG(4, delta, "kern.dq.stats.resolve_failclosed grew by "
	    "%ju", (uintmax_t)delta);
}

ATF_TC(dead_controller_probe);
ATF_TC_HEAD(dead_controller_probe, tc)
{
	atf_tc_set_md_var(tc, "descr", "the four fail-closed refusals of "
	    "dead_controller_eacces each fire dq:::resolve-failclosed in the "
	    "requester");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(dead_controller_probe, tc)
{
	uint64_t delta;
	char why[256];
	long n;

	why[0] = '\0';
	if (access(DTRACE, X_OK) != 0)
		atf_tc_fail("no %s", DTRACE);
	n = dead_controller(&delta, true, why, sizeof(why));
	if (n == -1)
		atf_tc_fail("dtrace: %s", why[0] != '\0' ? why :
		    "printed no count");
	ATF_CHECK_EQ_MSG(4, n, "resolve-failclosed fired %ld times", n);
}

/*
 * The counter itself, while the queue is open: a SOCKET wait that misses
 * its deadline is EIO (not a dead controller) and counts as failed closed.
 */
#define	DEFAULT_DEADLINE	"kern.dq.default_deadline_ms"

ATF_TC_WITH_CLEANUP(deadline_counts_failclosed);
ATF_TC_HEAD(deadline_counts_failclosed, tc)
{
	atf_tc_set_md_var(tc, "descr", "an unanswered SOCKET event fails with "
	    "EIO at the deadline (the controller is alive) and counts in "
	    "ds2_resolve_failclosed");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(deadline_counts_failclosed, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct sock_res r;
	struct dq_stats2 st;

	dqt_sysctl_save_set_uint(DEFAULT_DEADLINE, 500);
	dqt_init(&c);
	dqt_resolve_hold(&c, NULL, DQ_ROP_SOCKET);
	dqt_attach_spawn(&c, &ch, child_one_socket, NULL);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(EIO, r.r[0].err);
	ATF_CHECK_EQ(0, r.r[1].rv);	/* socketpair is not held */
	dqt_stats2(&c, &st);
	ATF_CHECK_EQ(1, st.ds2_resolve_failclosed);
	ATF_CHECK(st.ds2_deadline_misses >= 1);
	dqt_fini(&c);
}
ATF_TC_CLEANUP(deadline_counts_failclosed, tc)
{

	(void)dqt_sysctl_restore(DEFAULT_DEADLINE);
}

/*
 * full_table_unattached and full_table_attached: upstream's falloc-first
 * order.  socket(2) takes its descriptor before socreate, so a full table
 * is EMFILE before a bad family, type or protocol and before ECAPMODE;
 * socketpair(2) creates its sockets first, so there a bad type wins.
 */
#define	FULL_LIMIT	64

struct full_arg {
	bool		 capmode;
};

/* Every slot below a NOFILE limit of FULL_LIMIT used; the last one. */
static int
fill_table(void)
{
	struct rlimit rl;
	int p[2], fd, last;

	rl.rlim_cur = rl.rlim_max = FULL_LIMIT;
	if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
		_exit(6);
	if (pipe(p) != 0)
		_exit(7);
	last = p[1];
	while ((fd = dup(p[0])) != -1)
		last = fd;
	if (errno != EMFILE)
		_exit(8);
	return (last);
}

static void
child_full(void *arg, void *result)
{
	struct full_arg *a = arg;
	struct sock_res *r = result;
	int last, sv[2];

	last = fill_table();
	if (a->capmode) {
		if (cap_enter() != 0)
			_exit(5);
		/* Raw IP has no PR_CAPATTACH: ECAPMODE with room. */
		RR(r->r[0], socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
		RR(r->r[1], socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
		return;
	}
	RR(r->r[0], socket(AF_INET, SOCK_STREAM, 0));
	RR(r->r[1], socket(AF_UNIX, SOCK_RAW, 0));	/* EPROTOTYPE */
	RR(r->r[2], socket(AF_MAX + 10, SOCK_STREAM, 0)); /* EAFNOSUPPORT */
	RR(r->r[3], socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	RR(r->r[4], socketpair(AF_UNIX, SOCK_RAW, 0, sv));
	/* One free slot: socket(2) fits, socketpair(2) does not. */
	(void)close(last);
	RR(r->r[5], socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	RR(r->r[6], socket(AF_INET, SOCK_STREAM, 0));
	r->nextfd = last;
}

static void
check_full(const struct sock_res *r, bool capmode, const char *who)
{

	if (capmode) {
		ATF_CHECK_EQ_MSG(EMFILE, r->r[0].err, "%s capmode socket: %s",
		    who, strerror(r->r[0].err));
		ATF_CHECK_EQ_MSG(EMFILE, r->r[1].err, "%s capmode socketpair: "
		    "%s", who, strerror(r->r[1].err));
		return;
	}
	ATF_CHECK_EQ_MSG(EMFILE, r->r[0].err, "%s socket: %s", who,
	    strerror(r->r[0].err));
	ATF_CHECK_EQ_MSG(EMFILE, r->r[1].err, "%s bad type: %s", who,
	    strerror(r->r[1].err));
	ATF_CHECK_EQ_MSG(EMFILE, r->r[2].err, "%s bad family: %s", who,
	    strerror(r->r[2].err));
	ATF_CHECK_EQ_MSG(EMFILE, r->r[3].err, "%s socketpair: %s", who,
	    strerror(r->r[3].err));
	ATF_CHECK_EQ_MSG(EPROTOTYPE, r->r[4].err, "%s socketpair bad type: "
	    "%s", who, strerror(r->r[4].err));
	ATF_CHECK_EQ_MSG(EMFILE, r->r[5].err, "%s socketpair, one slot: %s",
	    who, strerror(r->r[5].err));
	ATF_CHECK_EQ_MSG(r->nextfd, r->r[6].rv, "%s socket, one slot: %ld "
	    "(%s)", who, r->r[6].rv, strerror(r->r[6].err));
}

ATF_TC(full_table_unattached);
ATF_TC_HEAD(full_table_unattached, tc)
{
	atf_tc_set_md_var(tc, "descr", "an unattached process with a full "
	    "descriptor table gets upstream's errors: socket(2) is EMFILE "
	    "before a bad type or family and before ECAPMODE; socketpair(2) "
	    "with a bad type is EPROTOTYPE, and EMFILE without room for both "
	    "descriptors");
}
ATF_TC_BODY(full_table_unattached, tc)
{
	struct full_arg a;
	struct sock_res r;

	a.capmode = false;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_full, &a, &r, sizeof(r));
	check_full(&r, false, "unattached");
	a.capmode = true;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_full, &a, &r, sizeof(r));
	check_full(&r, true, "unattached");
}

ATF_TC(full_table_attached);
ATF_TC_HEAD(full_table_attached, tc)
{
	atf_tc_set_md_var(tc, "descr", "an attached process with a full "
	    "descriptor table gets exactly the unattached errors and posts "
	    "nothing for them: socket(2) is EMFILE before the protocol, "
	    "capability-mode and jail tests and the consultation; socketpair(2) "
	    "is EPROTOTYPE for a bad type and EMFILE without room for both "
	    "descriptors; with one slot free socket(2) is posted and gets it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(full_table_attached, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct full_arg a;
	struct sock_res o, r;
	int i;

	a.capmode = false;
	memset(&o, 0, sizeof(o));
	dqt_run_child(child_full, &a, &o, sizeof(o));
	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, child_full, &a);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	check_full(&r, false, "attached");
	for (i = 0; i < 7; i++) {
		ATF_CHECK_EQ_MSG(o.r[i].err, r.r[i].err, "row %d: unattached "
		    "%s, attached %s", i, strerror(o.r[i].err),
		    strerror(r.r[i].err));
	}
	/* Only the socket that had its slot was posted. */
	ATF_CHECK_EQ(1, count_events(&c, DQ_ROP_SOCKET, -1, -1));
	check_socket_event(&c, nth_event(&c, DQ_ROP_SOCKET, 0), DQ_ROP_SOCKET,
	    AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ATF_CHECK_EQ(0, count_events(&c, DQ_ROP_SOCKETPAIR, -1, -1));
	dqt_fini(&c);

	a.capmode = true;
	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, child_full, &a);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	check_full(&r, true, "attached");
	ATF_CHECK_EQ(0, count_events(&c, DQ_ROP_SOCKET, -1, -1));
	ATF_CHECK_EQ(0, count_events(&c, DQ_ROP_SOCKETPAIR, -1, -1));
	dqt_fini(&c);
}

/*
 * jail_af_before_consult
 */

#define	JAILNAME	"dqt_sock"

struct jail_arg {
	int		 jid;
};

static void
child_jail_inet(void *arg __unused, void *result)
{
	struct sock_res *r = result;

	RR(r->r[0], socket(AF_INET, SOCK_STREAM, 0));
	RR(r->r[1], socket(AF_UNIX, SOCK_STREAM, 0));
}

/* dqt_attach_spawn, with the child entering the jail before ATTACH. */
static void
spawn_jailed(struct dqt_ctl *c, struct dqt_achild *ch, int jid,
    dqt_child_fn fn)
{
	int go[2], res[2], jailed[2];
	char b;

	ATF_REQUIRE_EQ(0, pipe(go));
	ATF_REQUIRE_EQ(0, pipe(res));
	ATF_REQUIRE_EQ(0, pipe(jailed));
	ch->pid = pdfork(&ch->pd, 0);
	ATF_REQUIRE(ch->pid != -1);
	if (ch->pid == 0) {
		char result[4096];

		(void)close(go[1]);
		(void)close(res[0]);
		(void)close(jailed[0]);
		b = jail_attach(jid) == 0 ? 'j' : 'x';
		(void)write(jailed[1], &b, 1);
		if (b != 'j' || read(go[0], &b, 1) != 1)
			_exit(2);
		memset(result, 0, sizeof(result));
		fn(NULL, result);
		(void)write(res[1], result, sizeof(result));
		_exit(0);
	}
	(void)close(go[0]);
	(void)close(res[1]);
	(void)close(jailed[1]);
	ch->pipefd = res[0];
	ATF_REQUIRE_EQ(1, read(jailed[0], &b, 1));
	ATF_REQUIRE_MSG(b == 'j', "jail_attach failed in the child");
	(void)close(jailed[0]);
	if (c != NULL)
		ATF_REQUIRE_MSG(dq_attach(c->q, ch->pd) == 0,
		    "DQ_IOC_ATTACH: %s", strerror(errno));
	b = 'g';
	ATF_REQUIRE_EQ(1, write(go[1], &b, 1));
	(void)close(go[1]);
}

ATF_TC_WITH_CLEANUP(jail_af_before_consult);
ATF_TC_HEAD(jail_af_before_consult, tc)
{
	atf_tc_set_md_var(tc, "descr", "the jail's address-family test runs "
	    "before the consultation, where socreate runs it: in a jail with "
	    "ip4=disable, socket(AF_INET) fails with EPROTONOSUPPORT as "
	    "unattached and posts nothing, whatever the controller would "
	    "answer; socket(AF_UNIX) is posted and gets the controller's "
	    "answer");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_af_before_consult, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct sock_res o, r;
	int jid;

	jid = jail_setv(JAIL_CREATE, "path", "/", "name", JAILNAME,
	    "ip4", "disable", "persist", NULL, NULL);
	if (jid < 0)
		atf_tc_fail("jail_setv: %s", jail_errmsg);

	/* The oracle: the same jail, unattached. */
	spawn_jailed(NULL, &ch, jid, child_jail_inet);
	memset(&o, 0, sizeof(o));
	dqt_attach_collect(&ch, &o, sizeof(o));
	ATF_REQUIRE_EQ_MSG(EPROTONOSUPPORT, o.r[0].err, "unattached jailed "
	    "socket(AF_INET): %s", strerror(o.r[0].err));

	dqt_init(&c);
	spawn_jailed(&c, &ch, jid, child_jail_inet);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.r[0].rv);
	ATF_CHECK_EQ(EPROTONOSUPPORT, r.r[0].err);
	ATF_CHECK(r.r[1].rv >= 0);
	ATF_CHECK_EQ(0, count_events(&c, DQ_ROP_SOCKET, AF_INET, -1));
	ATF_CHECK_EQ(1, count_events(&c, DQ_ROP_SOCKET, AF_UNIX, SOCK_STREAM));
	dqt_fini(&c);

	/* A refusing controller is not asked about the refused family. */
	dqt_init(&c);
	dqt_resolve_errno(&c, DQ_ROP_SOCKET, EACCES);
	spawn_jailed(&c, &ch, jid, child_jail_inet);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(EPROTONOSUPPORT, r.r[0].err);
	ATF_CHECK_EQ(EACCES, r.r[1].err);
	ATF_CHECK_EQ(0, count_events(&c, DQ_ROP_SOCKET, AF_INET, -1));
	ATF_CHECK_EQ(1, count_events(&c, DQ_ROP_SOCKET, AF_UNIX, SOCK_STREAM));
	dqt_fini(&c);
	(void)jail_remove(jid);
}
ATF_TC_CLEANUP(jail_af_before_consult, tc)
{
	int jid;

	jid = jail_getid(JAILNAME);
	if (jid > 0)
		(void)jail_remove(jid);
}

/*
 * kernel_socreate_not_consulted
 */

#define	TUNPORT		"net.inet.tcp.udp_tunneling_port"
#define	TUNPORT_VALUE	9899

static void
child_tunport(void *arg __unused, void *result)
{
	struct sock_res *r = result;
	u_int v;

	v = TUNPORT_VALUE;
	RR(r->r[0], sysctlbyname(TUNPORT, NULL, NULL, &v, sizeof(v)));
	RR(r->r[1], socket(AF_INET, SOCK_DGRAM, 0));
}

ATF_TC_WITH_CLEANUP(kernel_socreate_not_consulted);
ATF_TC_HEAD(kernel_socreate_not_consulted, tc)
{
	atf_tc_set_md_var(tc, "descr", "sockets the kernel creates with "
	    "socreate() in an attached thread are not consulted: setting "
	    TUNPORT " creates the TCP-over-UDP sockets in the writer's thread "
	    "and posts nothing; the process's own socket(2) is posted");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(kernel_socreate_not_consulted, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct sock_res r;
	struct dq_stats2 st;
	u_int v;

	if (!dqt_sysctl_get_uint(TUNPORT, &v))
		atf_tc_fail("no " TUNPORT);
	if (v != 0)
		atf_tc_fail(TUNPORT " is in use (%u)", v);
	/* What the cleanup restores (the child sets it). */
	dqt_sysctl_save(TUNPORT);
	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, child_tunport, NULL);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	if (r.r[0].rv == -1 && r.r[0].err == EADDRINUSE) {
		dqt_fini(&c);
		atf_tc_fail("UDP port %d is in use", TUNPORT_VALUE);
	}
	ATF_CHECK_EQ_MSG(0, r.r[0].rv, TUNPORT ": %s", strerror(r.r[0].err));
	ATF_CHECK(dqt_sysctl_get_uint(TUNPORT, &v) && v == TUNPORT_VALUE);
	ATF_CHECK(r.r[1].rv >= 0);
	/* Only the process's own socket(2). */
	ATF_CHECK_EQ(1, count_events(&c, DQ_ROP_SOCKET, -1, -1));
	ATF_CHECK_EQ(1, count_events(&c, DQ_ROP_SOCKET, AF_INET, SOCK_DGRAM));
	dqt_stats2(&c, &st);
	ATF_CHECK_EQ(0, st.ds2_resolve_unmarked);
	dqt_fini(&c);
}
ATF_TC_CLEANUP(kernel_socreate_not_consulted, tc)
{

	(void)dqt_sysctl_restore(TUNPORT);
}

/*
 * abstract_names
 */

static void
child_abstract(void *arg __unused, void *result)
{
	struct sock_res *r = result;
	struct sockaddr_un sun;
	socklen_t len;
	int s;

	/*
	 * A name whose first byte is NUL.  Natively the protocol takes it as
	 * a path, which is empty (ENOENT before any lookup); only a socket a
	 * Linux64 process created has the abstract namespace
	 * (UNP_LINUX_ABSTRACT), not reachable from this native test.  Either
	 * way the name is consulted first, as ABSTRACT.
	 */
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path, "\0rt-abs", 7);
	len = offsetof(struct sockaddr_un, sun_path) + 7;
	sun.sun_len = len;
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	RR(r->r[0], bind(s, (struct sockaddr *)&sun, len));
	(void)close(s);
	memcpy(sun.sun_path, "\0rt-abc", 7);
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	RR(r->r[1], connect(s, (struct sockaddr *)&sun, len));
	(void)close(s);
}

ATF_TC(abstract_names);
ATF_TC_HEAD(abstract_names, tc)
{
	atf_tc_set_md_var(tc, "descr", "an AF_UNIX name beginning with NUL is "
	    "posted as BIND or CONNECT with DQ_RF_ABSTRACT, start NONE and the "
	    "name's bytes after the NUL, and the calls then return what they "
	    "return unattached");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(abstract_names, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct sock_res o, r;
	struct dq_stats2 st;
	int i;

	memset(&o, 0, sizeof(o));
	dqt_run_child(child_abstract, NULL, &o, sizeof(o));
	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, child_abstract, NULL);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	for (i = 0; i < 2; i++) {
		ATF_CHECK_EQ(o.r[i].rv, r.r[i].rv);
		ATF_CHECK_EQ(o.r[i].err, r.r[i].err);
	}
	i = dqt_find_resolve(&c, "rt-abs", DQ_ROP_BIND, 0);
	ATF_REQUIRE(i != -1);
	dqt_lock(&c);
	ATF_CHECK_STREQ("rt-abs", c.rs[i].path);
	ATF_CHECK_EQ(6, c.rs[i].pathlen);
	ATF_CHECK_EQ(DQ_RF_USER | DQ_RF_ABSTRACT, c.rs[i].rflags);
	ATF_CHECK_EQ(DQ_START_NONE, c.rs[i].start_kind);
	ATF_CHECK_EQ(DQ_RCLASS_USER, c.rs[i].cls);
	dqt_unlock(&c);
	i = dqt_find_resolve(&c, "rt-abc", DQ_ROP_CONNECT, 0);
	ATF_REQUIRE(i != -1);
	dqt_lock(&c);
	ATF_CHECK_EQ(DQ_RF_USER | DQ_RF_ABSTRACT, c.rs[i].rflags);
	ATF_CHECK_EQ(DQ_START_NONE, c.rs[i].start_kind);
	dqt_unlock(&c);
	ATF_CHECK_EQ(1, dqt_count_resolve(&c, "rt-abs", DQ_ROP_BIND));
	ATF_CHECK_EQ(1, dqt_count_resolve(&c, "rt-abc", DQ_ROP_CONNECT));
	/* The native protocol's lookup of the empty path is no ledger gap. */
	dqt_stats2(&c, &st);
	ATF_CHECK_EQ(0, st.ds2_resolve_unmarked);
	dqt_fini(&c);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, protocol_resolved);
	ATF_TP_ADD_TC(tp, socketpair_one_event);
	ATF_TP_ADD_TC(tp, capmode_no_event);
	ATF_TP_ADD_TC(tp, mac_denial_no_event);
	ATF_TP_ADD_TC(tp, errno_answers);
	ATF_TP_ADD_TC(tp, no_fd_slot_while_waiting);
	ATF_TP_ADD_TC(tp, dead_controller_eacces);
	ATF_TP_ADD_TC(tp, dead_controller_probe);
	ATF_TP_ADD_TC(tp, deadline_counts_failclosed);
	ATF_TP_ADD_TC(tp, full_table_unattached);
	ATF_TP_ADD_TC(tp, full_table_attached);
	ATF_TP_ADD_TC(tp, jail_af_before_consult);
	ATF_TP_ADD_TC(tp, kernel_socreate_not_consulted);
	ATF_TP_ADD_TC(tp, abstract_names);
	return (atf_no_error());
}
