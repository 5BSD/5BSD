/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * LA-0: pins of who may DQ_IOC_ATTACH a process today, written before the
 * launch/attach slices (LA-1k, LA-1, LA-2) change it.  Every case records
 * what the kernel does now and names the slice expected to change it; none
 * is a statement of what should happen.
 *
 * The attach permission is p_candebug() of the target (kern_dqres.c,
 * dqres_attach), so the cases below are pins of p_candebug as seen through
 * the queue: plain credentials, the capprotect ptrace shield and its
 * tokens, PD_PROTECTED, and the pre-exec rule.  The da_pad0 refusal
 * (LA-0 (h)) is already pinned by dq_attach_test:attach_refusals and is
 * not repeated.
 *
 * Not written: LA-0 (f1) and (f2), the software-authority rule of
 * cap_authority_debug_check().  They need a launcher that holds valid
 * software authority, and a test run by kyua holds none (CAP_AUTH_INFO
 * reports identity 0, valid 0 in the plane-on guest); nothing a test may
 * do gives it one.  With no authority on the target the rule does not
 * apply, which every case here already exercises.
 *
 * Actors are forked children that open their own queue: the process under
 * test must be neither the queue holder's child by accident nor a holder
 * of the queue (that is EBUSY, a different refusal).
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/procctl.h>
#include <sys/procdesc.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_capprotect_proto.h>
#include <dev/mac_capability/mac_capability_channel_proto.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

#define	NA	(-9999)		/* a step that was not reached */
#define	ERRNO_OF(call)	((call) == -1 ? errno : 0)

/* The attach bit LA-1k plans for capprotect tokens; undefined today. */
#define	LA_ATTACH_BIT	0x10000u

/* A pdfork child that waits on a pipe until told to exit (or exec). */
struct idle {
	pid_t		 pid;
	int		 pd;
	int		 go[2];
};

static void
idle_spawn(struct idle *s, int pdflags, const char *exec_path)
{
	char b;

	ATF_REQUIRE_EQ(0, pipe(s->go));
	s->pid = pdfork(&s->pd, pdflags);
	ATF_REQUIRE_MSG(s->pid != -1, "pdfork: %s", strerror(errno));
	if (s->pid == 0) {
		(void)close(s->go[1]);
		if (exec_path != NULL) {
			execl(exec_path, exec_path, "30", (char *)NULL);
			_exit(3);
		}
		(void)read(s->go[0], &b, 1);
		_exit(0);
	}
}

static void
idle_end(struct idle *s)
{
	int status;

	(void)write(s->go[1], "x", 1);
	(void)pdkill(s->pd, SIGKILL);
	(void)pdwait(s->pd, &status, WEXITED, NULL, NULL);
	(void)close(s->pd);
	(void)close(s->go[0]);
	(void)close(s->go[1]);
}

/*
 * The capability plane, without the ATF-calling helpers: these run in
 * forked children, which must report through their result and not through
 * the test program's result file.
 */
static int
cp_connect(const char *name)
{
	struct mac_capability_connect_args ca;
	int ctl, saved;

	ctl = open("/dev/mac_capability", O_RDWR);
	if (ctl == -1)
		return (-1);
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, name, sizeof(ca.name));
	if (ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) != 0) {
		saved = errno;
		(void)close(ctl);
		errno = saved;
		return (-1);
	}
	(void)close(ctl);
	return (ca.fd);
}

/* One capprotect request on fd; a procdesc and a reply fd are optional. */
static int
cp_request(int fd, uint32_t op, uint32_t flags, int procdesc, int *reply_fd)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int rfds[1];

	memset(&req, 0, sizeof(req));
	req.op = op;
	req.flags = flags;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	if (procdesc != -1) {
		ca.req_fds = &procdesc;
		ca.req_nfds = 1;
	}
	if (reply_fd != NULL) {
		rfds[0] = -1;
		ca.reply_fds = rfds;
		ca.reply_nfds = 1;
	}
	if (ioctl(fd, MAC_CAPABILITY_CALL, &ca) != 0)
		return (-1);
	if (reply_fd != NULL)
		*reply_fd = rfds[0];
	return (0);
}

/* Shield the caller (procdesc == -1) or the process behind procdesc. */
static int
cp_shield(int procdesc, uint32_t flags)
{
	int fd, saved;

	fd = cp_connect("capprotect");
	if (fd == -1)
		return (-1);
	if (cp_request(fd, procdesc == -1 ? CP_OP_SHIELD : CP_OP_PROTECT,
	    flags, procdesc, NULL) != 0) {
		saved = errno;
		(void)close(fd);
		errno = saved;
		return (-1);
	}
	return (fd);
}

static int
chan_create(int pair[2])
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	uint32_t op;
	int fd, peer, saved;

	fd = cp_connect("channel");
	if (fd == -1)
		return (-1);
	op = CHANNEL_OP_CREATE;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &op;
	sa.payload_len = sizeof(op);
	memset(&ra, 0, sizeof(ra));
	ra.fds = &peer;
	ra.nfds = 1;
	if (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) != 0 ||
	    ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) != 0 || ra.nfds != 1) {
		saved = errno;
		(void)close(fd);
		errno = saved != 0 ? saved : EPROTO;
		return (-1);
	}
	pair[0] = fd;
	pair[1] = peer;
	return (0);
}

static int
chan_send_fd(int chan, int fd)
{
	struct mac_capability_sendmsg_args sa;

	memset(&sa, 0, sizeof(sa));
	sa.payload = "fd";
	sa.payload_len = 2;
	sa.fds = &fd;
	sa.nfds = 1;
	return (ioctl(chan, MAC_CAPABILITY_SENDMSG, &sa));
}

/* The message is already queued: no wait. */
static int
chan_recv_fd(int chan, int *fd)
{
	struct mac_capability_recvmsg_args ra;
	char buf[8];

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ra.fds = fd;
	ra.nfds = 1;
	if (ioctl(chan, MAC_CAPABILITY_RECVMSG, &ra) != 0)
		return (-1);
	if (ra.nfds != 1) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

/*
 * The actor: a forked child that opens its own queue and attaches the
 * process behind pd, after the optional steps its flags select.  Every
 * step is an errno (0 on success) or NA.
 */
#define	ACT_SETUID	0x01	/* drop to an unprivileged uid first */
#define	ACT_PTRACE	0x02	/* PT_ATTACH, wait, PT_DETACH the target */
#define	ACT_TOKEN	0x04	/* receive a token on chan and activate it */
#define	ACT_TOKCLOSE	0x08	/* close the token before attaching */
#define	ACT_RESEND	0x10	/* send the received token back, no attach */
#define	ACT_NOATTACH	0x40
#define	ACT_UID		65534

struct act {
	int		 pd;
	pid_t		 pid;
	int		 flags;
	int		 chan;
};

struct act_res {
	int		 open, setuid;
	int		 recv, resend, authorize;
	int		 pt_attach, pt_stopped, pt_detach;
	int		 attach;
	uint64_t	 attached;	/* ds2_attached of the actor's queue */
};

static void
actor(void *arg, void *result)
{
	struct act *a = arg;
	struct act_res *r = result;
	struct dq_stats2 st;
	int q, status, tok;

	r->open = r->setuid = r->recv = r->resend = NA;
	r->authorize = r->pt_attach = r->pt_stopped = r->pt_detach = NA;
	r->attach = NA;
	tok = -1;

	q = dq_open();
	r->open = ERRNO_OF(q);
	if (q == -1)
		return;
	if ((a->flags & ACT_SETUID) != 0) {
		r->setuid = ERRNO_OF(setuid(ACT_UID));
		if (r->setuid != 0)
			return;
	}
	if ((a->flags & (ACT_TOKEN | ACT_RESEND)) != 0) {
		r->recv = ERRNO_OF(chan_recv_fd(a->chan, &tok));
		if (r->recv != 0)
			return;
	}
	if ((a->flags & ACT_RESEND) != 0)
		r->resend = ERRNO_OF(chan_send_fd(a->chan, tok));
	if ((a->flags & ACT_TOKEN) != 0) {
		r->authorize = ERRNO_OF(cp_request(tok, CP_OP_AUTHORIZE, 0,
		    -1, NULL));
		if ((a->flags & ACT_TOKCLOSE) != 0) {
			(void)close(tok);
			tok = -1;
		}
	}
	if ((a->flags & ACT_PTRACE) != 0) {
		r->pt_attach = ERRNO_OF(ptrace(PT_ATTACH, a->pid, NULL, 0));
		if (r->pt_attach == 0) {
			/* The attach stop is certain: an unbounded wait. */
			r->pt_stopped = waitpid(a->pid, &status, 0) ==
			    a->pid && WIFSTOPPED(status) ? 0 : 1;
			r->pt_detach = ERRNO_OF(ptrace(PT_DETACH, a->pid,
			    (caddr_t)1, 0));
		}
	}
	if ((a->flags & (ACT_NOATTACH | ACT_RESEND)) != 0)
		return;
	r->attach = ERRNO_OF(dq_attach(q, a->pd));
	if (dq_get_stats2(q, &st) == 0)
		r->attached = st.ds2_attached;
}

static struct act_res
act_run(int pd, pid_t pid, int flags, int chan)
{
	struct act a = { .pd = pd, .pid = pid, .flags = flags, .chan = chan };
	struct act_res r;

	memset(&r, 0, sizeof(r));
	dqt_run_child(actor, &a, &r, sizeof(r));
	ATF_REQUIRE_EQ_MSG(0, r.open, "the actor's dq_open: %s",
	    strerror(r.open));
	return (r);
}

#define	ROW(what, got, want) do {					\
	int got_ = (int)(got), want_ = (int)(want);			\
	ATF_CHECK_EQ_MSG(want_, got_, "%s: got %d, pinned %d", (what),	\
	    got_, want_);						\
} while (0)

/* (a): the descriptor arrives by SCM_RIGHTS in a process that never forked. */
struct recv_arg {
	int		 sock;
};

static void
actor_scm(void *arg, void *result)
{
	struct recv_arg *ra = arg;
	struct act a;
	struct msghdr mh;
	struct iovec iov;
	union {
		struct cmsghdr	 hdr;
		char		 buf[CMSG_SPACE(sizeof(int))];
	} cm;
	char b;

	memset(&mh, 0, sizeof(mh));
	iov.iov_base = &b;
	iov.iov_len = 1;
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = cm.buf;
	mh.msg_controllen = sizeof(cm.buf);
	if (recvmsg(ra->sock, &mh, 0) != 1 ||
	    cm.hdr.cmsg_level != SOL_SOCKET || cm.hdr.cmsg_type != SCM_RIGHTS) {
		((struct act_res *)result)->open = EPROTO;
		return;
	}
	memset(&a, 0, sizeof(a));
	memcpy(&a.pd, CMSG_DATA(&cm.hdr), sizeof(int));
	actor(&a, result);
}

static int
send_fd(int sock, int fd)
{
	struct msghdr mh;
	struct iovec iov;
	union {
		struct cmsghdr	 hdr;
		char		 buf[CMSG_SPACE(sizeof(int))];
	} cm;
	char b = 'f';

	memset(&mh, 0, sizeof(mh));
	memset(&cm, 0, sizeof(cm));
	iov.iov_base = &b;
	iov.iov_len = 1;
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = cm.buf;
	mh.msg_controllen = sizeof(cm.buf);
	cm.hdr.cmsg_len = CMSG_LEN(sizeof(int));
	cm.hdr.cmsg_level = SOL_SOCKET;
	cm.hdr.cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(&cm.hdr), &fd, sizeof(int));
	return (sendmsg(sock, &mh, 0) == 1 ? 0 : -1);
}

ATF_TC(nonparent_attach);
ATF_TC_HEAD(nonparent_attach, tc)
{
	atf_tc_set_md_var(tc, "descr", "LA-0 (a), (b): a root process that "
	    "is not the target's parent and only received its process "
	    "descriptor (SCM_RIGHTS, or inheritance) attaches a pre-exec "
	    "child; after the child exec'd the same attach is EBUSY.  "
	    "Parenthood is not part of the rule today; LA-1 keeps that and "
	    "LA-2 adds registration beside it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(nonparent_attach, tc)
{
	struct dqt_child ch;
	struct recv_arg ra;
	struct act_res r;
	struct idle s;
	struct kevent kev;
	struct timespec ts = { 10, 0 };
	int kq, sv[2], status;

	/* (a) SCM_RIGHTS: the actor exists before the target does. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	ra.sock = sv[1];
	dqt_spawn(&ch, actor_scm, &ra);
	idle_spawn(&s, 0, NULL);
	ATF_REQUIRE_EQ(0, send_fd(sv[0], s.pd));
	memset(&r, 0, sizeof(r));
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ROW("received by SCM_RIGHTS: dq_open", r.open, 0);
	ROW("received by SCM_RIGHTS: attach", r.attach, 0);
	ROW("received by SCM_RIGHTS: ds2_attached", r.attached, 1);
	idle_end(&s);
	(void)close(sv[0]);
	(void)close(sv[1]);

	/* (a) by inheritance: a sibling of the target. */
	idle_spawn(&s, 0, NULL);
	r = act_run(s.pd, s.pid, 0, -1);
	ROW("inherited: attach", r.attach, 0);
	ROW("inherited: ds2_attached", r.attached, 1);
	idle_end(&s);

	/* (b) the target exec'd. */
	kq = kqueue();
	ATF_REQUIRE(kq != -1);
	idle_spawn(&s, 0, "/bin/sleep");
	EV_SET(&kev, s.pd, EVFILT_PROCDESC, EV_ADD, NOTE_EXEC, 0, NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, &kev, 1, NULL, 0, NULL));
	ATF_REQUIRE_EQ_MSG(1, kevent(kq, NULL, 0, &kev, 1, &ts),
	    "no NOTE_EXEC from the target");
	r = act_run(s.pd, s.pid, 0, -1);
	ROW("after exec: attach", r.attach, EBUSY);
	ROW("after exec: ds2_attached", r.attached, 0);
	idle_end(&s);
	(void)close(kq);
}

ATF_TC(unprivileged_attach);
ATF_TC_HEAD(unprivileged_attach, tc)
{
	atf_tc_set_md_var(tc, "descr", "LA-0 (c): a caller that fails "
	    "p_candebug for a reason that is not a shield (it holds a queue "
	    "opened as root, then became uid 65534; the target is root's) is "
	    "refused EPERM, the errno p_candebug returned.  LA-1 is expected "
	    "to keep the errno");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(unprivileged_attach, tc)
{
	struct act_res r;
	struct idle s;

	idle_spawn(&s, 0, NULL);
	r = act_run(s.pd, s.pid, ACT_SETUID, -1);
	ROW("setuid", r.setuid, 0);
	ROW("attach", r.attach, EPERM);
	ROW("ds2_attached", r.attached, 0);
	/* The same target is still attachable by root: nothing was left. */
	r = act_run(s.pd, s.pid, 0, -1);
	ROW("root afterwards: attach", r.attach, 0);
	idle_end(&s);
}

/* (d): the protector is a third process, neither parent nor the test. */
struct prot_arg {
	int		 pd;
	pid_t		 pid;
	int		 ready[2];	/* protector -> test: shield applied */
	int		 go[2];		/* test -> protector: attach now */
};

struct prot_res {
	int		 shield;
	struct act_res	 act;
};

static void
protector(void *arg, void *result)
{
	struct prot_arg *pa = arg;
	struct prot_res *r = result;
	struct act a;
	char b;
	int fd;

	(void)close(pa->ready[0]);
	(void)close(pa->go[1]);
	fd = cp_shield(pa->pd, CP_SF_PTRACE);
	r->shield = ERRNO_OF(fd);
	b = 'r';
	(void)write(pa->ready[1], &b, 1);
	if (read(pa->go[0], &b, 1) != 1 || fd == -1) {
		r->act.attach = NA;
		return;
	}
	memset(&a, 0, sizeof(a));
	a.pd = pa->pd;
	a.pid = pa->pid;
	actor(&a, &r->act);
}

ATF_TC(shielded_attach);
ATF_TC_HEAD(shielded_attach, tc)
{
	atf_tc_set_md_var(tc, "descr", "LA-0 (d): a pre-exec target that a "
	    "third process shielded with CP_SF_PTRACE (CP_OP_PROTECT) cannot "
	    "be attached by a root process that is not its protector "
	    "(EACCES, the parent included) and can by the protector.  LA-1k "
	    "adds the attach token as a second way in; these rows stay");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(shielded_attach, tc)
{
	struct dqt_ctl c;
	struct dqt_child ch;
	struct prot_arg pa;
	struct prot_res pr;
	struct act_res r;
	struct idle s;
	char b;
	int status;

	dqt_init_manual(&c);
	idle_spawn(&s, 0, NULL);
	pa.pd = s.pd;
	pa.pid = s.pid;
	ATF_REQUIRE_EQ(0, pipe(pa.ready));
	ATF_REQUIRE_EQ(0, pipe(pa.go));
	dqt_spawn(&ch, protector, &pa);
	(void)close(pa.ready[1]);
	(void)close(pa.go[0]);
	ATF_REQUIRE_EQ(1, read(pa.ready[0], &b, 1));

	/* A root sibling, then the parent itself: neither is the protector. */
	r = act_run(s.pd, s.pid, 0, -1);
	ROW("non-protector: attach", r.attach, EACCES);
	ROW("non-protector: ds2_attached", r.attached, 0);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_attach(c.q, s.pd));
	ROW("parent, not the protector: attach", errno, EACCES);

	ATF_REQUIRE_EQ(1, write(pa.go[1], "g", 1));
	memset(&pr, 0, sizeof(pr));
	status = dqt_wait(&ch, &pr, sizeof(pr));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ROW("CP_OP_PROTECT", pr.shield, 0);
	ROW("protector: attach", pr.act.attach, 0);
	ROW("protector: ds2_attached", pr.act.attached, 1);

	idle_end(&s);
	(void)close(pa.ready[0]);
	(void)close(pa.go[1]);
	dqt_fini(&c);
}

ATF_TC(pd_protected_attach);
ATF_TC_HEAD(pd_protected_attach, tc)
{
	atf_tc_set_md_var(tc, "descr", "LA-0 (e): a child forked with "
	    "PD_PROTECTED cannot be attached by anyone, its parent "
	    "included: EPERM.  LA-1 decides whether a launcher may attach "
	    "the protected child it made; until then this is the answer");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pd_protected_attach, tc)
{
	struct dqt_ctl c;
	struct act_res r;
	struct idle s;

	dqt_init_manual(&c);
	idle_spawn(&s, PD_PROTECTED, NULL);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_attach(c.q, s.pd));
	ROW("parent: attach", errno, EPERM);
	r = act_run(s.pd, s.pid, 0, -1);
	ROW("non-parent: attach", r.attach, EPERM);
	ROW("non-parent: ds2_attached", r.attached, 0);
	idle_end(&s);
	dqt_fini(&c);
}

/* (g): a self-shielded parent and its pre-exec fork. */
struct sp_arg {
	int		 sock;		/* to the test */
};

struct sp_res {
	int		 shield;
	pid_t		 self, child;
};

static void
shielded_parent(void *arg, void *result)
{
	struct sp_arg *sa = arg;
	struct sp_res *r = result;
	struct idle s;
	char b;
	int fd;

	fd = cp_shield(-1, CP_SF_PTRACE);
	r->shield = ERRNO_OF(fd);
	r->self = getpid();
	if (pipe(s.go) != 0)
		_exit(4);
	s.pid = pdfork(&s.pd, 0);
	if (s.pid == -1)
		_exit(5);
	if (s.pid == 0) {
		(void)close(s.go[1]);
		(void)read(s.go[0], &b, 1);
		_exit(0);
	}
	r->child = s.pid;
	if (send_fd(sa->sock, s.pd) != 0)
		_exit(6);
	if (write(sa->sock, r, sizeof(*r)) != (ssize_t)sizeof(*r))
		_exit(7);
	/* Stay, shielded, until the test has looked at both processes. */
	(void)read(sa->sock, &b, 1);
	idle_end(&s);
}

static int
recv_fd(int sock)
{
	struct msghdr mh;
	struct iovec iov;
	union {
		struct cmsghdr	 hdr;
		char		 buf[CMSG_SPACE(sizeof(int))];
	} cm;
	char b;
	int fd;

	memset(&mh, 0, sizeof(mh));
	iov.iov_base = &b;
	iov.iov_len = 1;
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = cm.buf;
	mh.msg_controllen = sizeof(cm.buf);
	if (recvmsg(sock, &mh, 0) != 1 || cm.hdr.cmsg_type != SCM_RIGHTS)
		return (-1);
	memcpy(&fd, CMSG_DATA(&cm.hdr), sizeof(int));
	return (fd);
}

ATF_TC(shield_not_inherited);
ATF_TC_HEAD(shield_not_inherited, tc)
{
	atf_tc_set_md_var(tc, "descr", "LA-0 (g), the B6 pin: the pre-exec "
	    "fork of a parent that shielded itself with CP_SF_PTRACE is not "
	    "shielded.  A root process that is no one's protector is refused "
	    "ptrace of the parent (EACCES) and is allowed both ptrace and dq "
	    "attach of the fork.  LA-1k (shield first, then attach by token) "
	    "is what closes this for a parked child; the row for the fork "
	    "flips only where the launcher shields it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(shield_not_inherited, tc)
{
	struct dqt_child ch;
	struct sp_arg sa;
	struct sp_res sr, dummy;
	struct act_res r;
	int pd, status, sv[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	sa.sock = sv[1];
	dqt_spawn(&ch, shielded_parent, &sa);
	pd = recv_fd(sv[0]);
	ATF_REQUIRE_MSG(pd != -1, "no process descriptor from the parent");
	ATF_REQUIRE_EQ((ssize_t)sizeof(sr), read(sv[0], &sr, sizeof(sr)));
	ROW("CP_OP_SHIELD", sr.shield, 0);

	/* The shield is real: the parent cannot be traced. */
	r = act_run(-1, sr.self, ACT_PTRACE | ACT_NOATTACH, -1);
	ROW("shielded parent: PT_ATTACH", r.pt_attach, EACCES);

	/* Its fork is an ordinary process. */
	r = act_run(pd, sr.child, ACT_PTRACE, -1);
	ROW("fork: PT_ATTACH", r.pt_attach, 0);
	ROW("fork: attach stop seen", r.pt_stopped, 0);
	ROW("fork: PT_DETACH", r.pt_detach, 0);
	ROW("fork: dq attach", r.attach, 0);
	ROW("fork: ds2_attached", r.attached, 1);

	ATF_REQUIRE_EQ(1, write(sv[0], "x", 1));
	status = dqt_wait(&ch, &dummy, sizeof(dummy));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	(void)close(pd);
	(void)close(sv[0]);
	(void)close(sv[1]);
}

/* (i): what CP_OP_SHIELD and CP_OP_MINT say to the planned attach bit. */
struct mint_arg {
	uint32_t	 shield_flags;	/* 0 is every flag */
};

struct mint_res {
	int		 shield_bit, shield;
	int		 mint_bit, mint_bit_ptrace, mint_ptrace;
};

static void
mint_child(void *arg, void *result)
{
	struct mint_arg *ma = arg;
	struct mint_res *r = result;
	int fd, tok;

	r->shield = r->mint_bit = r->mint_bit_ptrace = r->mint_ptrace = NA;
	fd = cp_shield(-1, CP_SF_PTRACE | LA_ATTACH_BIT);
	r->shield_bit = ERRNO_OF(fd);
	if (fd != -1)
		return;
	fd = cp_shield(-1, ma->shield_flags);
	r->shield = ERRNO_OF(fd);
	if (fd == -1)
		return;
	tok = -1;
	r->mint_bit = ERRNO_OF(cp_request(fd, CP_OP_MINT, LA_ATTACH_BIT, -1,
	    &tok));
	r->mint_bit_ptrace = ERRNO_OF(cp_request(fd, CP_OP_MINT,
	    CP_SF_PTRACE | LA_ATTACH_BIT, -1, &tok));
	r->mint_ptrace = ERRNO_OF(cp_request(fd, CP_OP_MINT, CP_SF_PTRACE,
	    -1, &tok));
}

ATF_TC(mint_attach_bit);
ATF_TC_HEAD(mint_attach_bit, tc)
{
	atf_tc_set_md_var(tc, "descr", "LA-0 (i): bit 0x10000, which LA-1k "
	    "plans as the attach permission of a capprotect token, is "
	    "unreachable today: CP_OP_SHIELD and CP_OP_MINT refuse it "
	    "EINVAL whether the shield holds CP_SF_PTRACE alone or with "
	    "CP_SF_CORE, alone or beside CP_SF_PTRACE; an ordinary ptrace token "
	    "is still minted.  LA-1k flips the MINT rows");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mint_attach_bit, tc)
{
	static const struct {
		const char	*name;
		uint32_t	 flags;
	} shields[] = {
		{ "CP_SF_PTRACE shield", CP_SF_PTRACE },
		{ "CP_SF_PTRACE | CP_SF_CORE shield", CP_SF_PTRACE | CP_SF_CORE },
	};
	struct mint_arg ma;
	struct mint_res r;
	u_int i;

	ATF_REQUIRE_EQ(0, CP_SF_ALL & LA_ATTACH_BIT);
	for (i = 0; i < nitems(shields); i++) {
		ma.shield_flags = shields[i].flags;
		memset(&r, 0, sizeof(r));
		dqt_run_child(mint_child, &ma, &r, sizeof(r));
		printf("%s:\n", shields[i].name);
		ROW("SHIELD with the bit", r.shield_bit, EINVAL);
		ROW("SHIELD", r.shield, 0);
		ROW("MINT the bit", r.mint_bit, EINVAL);
		ROW("MINT ptrace and the bit", r.mint_bit_ptrace, EINVAL);
		ROW("MINT ptrace", r.mint_ptrace, 0);
	}
}

ATF_TC(token_attach);
ATF_TC_HEAD(token_attach, tc)
{
	atf_tc_set_md_var(tc, "descr", "LA-0 (j): a process that activated "
	    "an ordinary CP_SF_PTRACE token attaches a shielded pre-exec "
	    "target; one that activated a token and closed it is refused "
	    "EACCES, as is one with no token.  The token crosses a channel: "
	    "a freshly minted token is transferable and arrives "
	    "transferable; limited to once it arrives with transfer state "
	    "none (a second send is ENOTCAPABLE); limited to none it cannot "
	    "be sent.  LA-1k narrows the ptrace token (attach needs its own "
	    "bit) and sets the state itself");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(token_attach, tc)
{
	struct act_res r;
	struct idle s;
	int chan[2], shield, tok;

	idle_spawn(&s, 0, NULL);
	shield = cp_shield(s.pd, CP_SF_PTRACE);
	ATF_REQUIRE_MSG(shield != -1, "CP_OP_PROTECT: %s", strerror(errno));
	ATF_REQUIRE_MSG(chan_create(chan) == 0, "channel: %s",
	    strerror(errno));

	/* No token. */
	r = act_run(s.pd, s.pid, 0, -1);
	ROW("no token: attach", r.attach, EACCES);

	/* Transfer state: default, once, none. */
	ATF_REQUIRE_EQ(0, cp_request(shield, CP_OP_MINT, 0, -1, &tok));
	ROW("default token: send", ERRNO_OF(chan_send_fd(chan[0], tok)), 0);
	(void)close(tok);
	r = act_run(s.pd, s.pid, ACT_RESEND, chan[1]);
	ROW("default token: receive", r.recv, 0);
	ROW("default token: send again", r.resend, 0);

	ATF_REQUIRE_EQ(0, cp_request(shield, CP_OP_MINT, 0, -1, &tok));
	ATF_REQUIRE_EQ(0, cap_xfer_limit(tok, CAP_XFER_ONCE));
	ROW("once token: send", ERRNO_OF(chan_send_fd(chan[0], tok)), 0);
	(void)close(tok);
	r = act_run(s.pd, s.pid, ACT_RESEND, chan[1]);
	ROW("once token: receive", r.recv, 0);
	ROW("once token: send again", r.resend, ENOTCAPABLE);

	ATF_REQUIRE_EQ(0, cp_request(shield, CP_OP_MINT, 0, -1, &tok));
	ATF_REQUIRE_EQ(0, cap_xfer_limit(tok, CAP_XFER_NONE));
	ROW("none token: send", ERRNO_OF(chan_send_fd(chan[0], tok)),
	    ENOTCAPABLE);
	(void)close(tok);

	/* A fresh pair: the probes above left tokens queued in the old one. */
	(void)close(chan[0]);
	(void)close(chan[1]);
	ATF_REQUIRE_MSG(chan_create(chan) == 0, "channel: %s",
	    strerror(errno));

	/* Activated, then closed: the grant goes with the token. */
	ATF_REQUIRE_EQ(0, cp_request(shield, CP_OP_MINT, CP_SF_PTRACE, -1,
	    &tok));
	ATF_REQUIRE_EQ(0, cap_xfer_limit(tok, CAP_XFER_ONCE));
	ATF_REQUIRE_EQ(0, chan_send_fd(chan[0], tok));
	(void)close(tok);
	r = act_run(s.pd, s.pid, ACT_TOKEN | ACT_TOKCLOSE, chan[1]);
	ROW("closed token: receive", r.recv, 0);
	ROW("closed token: AUTHORIZE", r.authorize, 0);
	ROW("closed token: attach", r.attach, EACCES);
	ROW("closed token: ds2_attached", r.attached, 0);

	/* Activated and held. */
	ATF_REQUIRE_EQ(0, cp_request(shield, CP_OP_MINT, CP_SF_PTRACE, -1,
	    &tok));
	ATF_REQUIRE_EQ(0, cap_xfer_limit(tok, CAP_XFER_ONCE));
	ATF_REQUIRE_EQ(0, chan_send_fd(chan[0], tok));
	(void)close(tok);
	r = act_run(s.pd, s.pid, ACT_TOKEN, chan[1]);
	ROW("held token: receive", r.recv, 0);
	ROW("held token: AUTHORIZE", r.authorize, 0);
	ROW("held token: attach", r.attach, 0);
	ROW("held token: ds2_attached", r.attached, 1);

	idle_end(&s);
	(void)close(chan[0]);
	(void)close(chan[1]);
	(void)close(shield);
}

struct nnp_res {
	int		 rv, err, nnp;
};

static void
nnp_reader(void *arg, void *result)
{
	struct nnp_res *r = result;
	pid_t pid = *(pid_t *)arg;

	r->nnp = NA;
	r->rv = procctl(P_PID, pid, PROC_NO_NEW_PRIVS_STATUS, &r->nnp);
	r->err = r->rv == -1 ? errno : 0;
}

ATF_TC(nnp_seen_by_others);
ATF_TC_HEAD(nnp_seen_by_others, tc)
{
	atf_tc_set_md_var(tc, "descr", "LA-0 (k): PROC_NO_NEW_PRIVS_STATUS "
	    "of the target, read by a process that is neither its parent "
	    "nor its controller, is disabled before attach and enabled "
	    "after: attach is visible to any process that may see the "
	    "target.  LA-1 keeps the bit; a launcher that reads it to "
	    "confirm the attach relies on this");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(nnp_seen_by_others, tc)
{
	struct dqt_ctl c;
	struct nnp_res r;
	struct idle s;

	dqt_init_manual(&c);
	idle_spawn(&s, 0, NULL);
	memset(&r, 0, sizeof(r));
	dqt_run_child(nnp_reader, &s.pid, &r, sizeof(r));
	ROW("before: procctl", r.err, 0);
	ROW("before: status", r.nnp, PROC_NO_NEW_PRIVS_DISABLE);
	ATF_REQUIRE_EQ_MSG(0, dq_attach(c.q, s.pd), "attach: %s",
	    strerror(errno));
	memset(&r, 0, sizeof(r));
	dqt_run_child(nnp_reader, &s.pid, &r, sizeof(r));
	ROW("after: procctl", r.err, 0);
	ROW("after: status", r.nnp, PROC_NO_NEW_PRIVS_ENABLE);
	idle_end(&s);
	dqt_fini(&c);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, nonparent_attach);
	ATF_TP_ADD_TC(tp, unprivileged_attach);
	ATF_TP_ADD_TC(tp, shielded_attach);
	ATF_TP_ADD_TC(tp, pd_protected_attach);
	ATF_TP_ADD_TC(tp, shield_not_inherited);
	ATF_TP_ADD_TC(tp, mint_attach_bit);
	ATF_TP_ADD_TC(tp, token_attach);
	ATF_TP_ADD_TC(tp, nnp_seen_by_others);
	return (atf_no_error());
}
