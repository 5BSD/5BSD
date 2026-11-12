/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Pins for the supervisor-legitimacy work (slice lg-0).  Every case records
 * what the kernel does today with /dev/dq, a queue descriptor held by a
 * process that did not open it, the dq.observe connect gate and the
 * software-authority constraint words, so that the later slices change
 * these answers on purpose and keep the rest.  Each case says which slice
 * is expected to change it ("changes in") or that it must stay ("preserve").
 *
 * No case skips for want of a device, compiler, linker, Linux ABI module
 * or privilege: each is a failure, because a skipped pin proves nothing
 * about the kernel under test.  The cases that need root do not declare
 * require.user (kyua would skip them for an unprivileged run); they fail.
 * The one permitted skip is by architecture: linux_open_ioctl and
 * ilp32_no_abi are amd64 programs and facts (require.arch).  A run on amd64
 * therefore reports LG_NCASES results, none skipped.
 *
 * Predicted failures.  Each later slice first runs these pins unchanged on
 * its kernel and records that exactly the rows below fail, with the answer
 * given, before it rewrites them; any other failure, in particular of a
 * "preserve" row, is a finding.
 *
 * From lg-3 on the answer depends on the kernel configuration, because
 * most cases begin with root opening /dev/dq:
 *
 * P  the production kernel (GENERIC).  Root has no role, so the open is
 *    EPERM and every case that makes one stops at that open: root_open,
 *    attached_root_open, bearer_*, attach_*, observe_connect_gate,
 *    linux_open_ioctl (root half) and unattached_control fail at their
 *    first open, whatever the table says about their later rows.  Rows
 *    marked T are not observable on P from this program.
 * T  the test kernel (GENERIC-DQTEST, options DQ_TEST_OPEN, with
 *    debug.dq.unverified_open=1; design 9.1).  Root's open binds a test
 *    queue.  The owner rule applies to a test-bound queue, so the
 *    non-owner rows change there; the attach token rule does not (no
 *    token is needed to attach through a test-bound queue), so the root
 *    attach rows stay 0 on T in lg-5b.
 *
 * Rows without a letter do not depend on the configuration.
 *
 * case / check                          slice   answer after the slice
 * root_open: mode 0600                  lg-3    0666
 * root_open: opens                      lg-3    P: EPERM.  T: 0, and each
 *                                               open a queue of its own
 * nonroot_open: three opens             lg-3    EPERM (was EACCES)
 * nonroot_open: access R_OK, W_OK       lg-3    0
 * nonroot_open_behind_mode              -       preserve
 * jailed_open: root EPERM               -       preserve
 * jailed_open: mode check               lg-3    0666
 * jailed_open: non-root open            lg-3    EPERM (was EACCES)
 * capmode_open: openat by root          lg-3    P: EPERM.  T: 0
 * capmode_open: ECAPMODE                -       preserve
 * attached_root_open: open, stats       lg-3    EPERM, then EBADF (open
 *                                               row 4 precedes the test
 *                                               binding); P: stops first
 * bearer_fork: stats .. FIONBIO, read   lg-3    T: EPERM for a non-owner
 * bearer_fork: own open EACCES          lg-3    EPERM
 * bearer_scm_rights: same slots         lg-3    T: EPERM for a non-owner
 * bearer_exec_attach: stats, attach 0   lg-3    T: EPERM for a non-owner
 * bearer_exec_attach: EPERM, knob off   lg-3    T: EPERM, for another
 *                                               reason (re-home, below)
 * attach_outside_prison: jailed stats   lg-3    T: EPERM for a non-owner
 * attach_outside_prison: ESRCH          lg-3    T: EPERM (re-home, below)
 * attach_outside_prison: sibling 0      lg-3    T: EPERM for a non-owner
 * attach_child_jail_target: root 0      -       T: preserve.  On P a role
 *                                               holder needs a token from
 *                                               lg-5b; not seen from here
 * attach_child_jail_target: EBUSY/EPERM lg-3    T: EPERM for both (re-home)
 * attach_errno_order: non-owner rows    lg-3    T: EPERM for all four
 * attach_errno_order: root rows         -       T: preserve (as above for
 *                                               lg-5b on P)
 * observe_connect_gate: root lists      lg-3    P: stops at the open.  T:
 *                                               preserve (PRIV_DRIVER on
 *                                               a test kernel)
 * observe_connect_gate: device EACCES   -       preserve
 * observe_connect_gate: connect EPERM,  lg-3    connect succeeds for any
 *   non-root and jailed root                    credential; the refusal
 *                                               moves to each call, EPERM
 *                                               (design 2.4)
 * constrain_reserved_words: flags bits  lg-1    landed: the supervisor role
 *                                               (0x2) passes (EBADF here);
 *                                               the other 31 stay EINVAL
 * constrain_reserved_words: reserved    lg-11k  assigned bits pass
 * constrain_reserved_words: nexec       -       preserve
 * linux_open_ioctl: root open, read     lg-3    P: EPERM, then EBADF.
 *                                               T: preserve
 * linux_open_ioctl: 'j' ioctl on queue  lg-10k  T: reaches dq_ioctl
 * linux_open_ioctl: 'j' on /dev/null    -       preserve
 * linux_open_ioctl: non-root open       lg-3    EPERM (Linux -1)
 * unattached_control                    -       T: preserve, every slice.
 *                                               P: fails at its open from
 *                                               lg-3; lg-3 must give it a
 *                                               queue from another source
 *                                               (a role holder's), since
 *                                               the property matters most
 *                                               on P
 * ilp32_no_abi                          -       preserve; a failure means
 *                                               the ILP32 pins are due
 *
 * The slices that must record both runs are therefore lg-3 and later: the
 * plane-on suite on P with the stops above, and the same suite on T with
 * the per-check answers.
 *
 * Re-homing in lg-3: attach_errno_order and bearer_exec_attach (knob off),
 * like the ESRCH row of attach_outside_prison, show the errno order of
 * ATTACH through a holder that is not the queue's owner, the only
 * unprivileged holder there is today.  lg-3 refuses that holder outright
 * (EPERM), which hides the order.  The property to preserve is the order
 * seen by an unprivileged owner; lg-3 must move these rows onto one (it
 * exists from lg-3 on, in the PID 1 fixture), not delete them.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/cap_authority.h>
#include <sys/event.h>
#include <sys/filio.h>
#include <sys/jail.h>
#include <sys/linker.h>
#include <sys/procctl.h>
#include <sys/procdesc.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <capability.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dev/dq/dq_observe_proto.h>

#include "dq_test.h"

#define	NOBODY_UID	65534
#define	PROC_DEBUG	"security.bsd.unprivileged_proc_debug"
#define	LG_NRES		12
/* The descriptor number the exec'd programs find an inherited queue at. */
#define	LG_QFD		9
/* The cases below; a complete amd64 run reports this many, none skipped. */
#define	LG_NCASES	17

/*
 * In place of require.user root, which would turn an unprivileged run into
 * skips.
 */
#define	LG_ROOT() ATF_REQUIRE_MSG(geteuid() == 0,			\
	"the legitimacy pins run as root and must not be skipped")

/* The Linux errno values the Linux program reports (negated). */
#define	LINUX_EBADF	9
#define	LINUX_EAGAIN	11
#define	LINUX_EACCES	13
#define	LINUX_EINVAL	22

struct lg_res {
	struct dqt_rr	 r[LG_NRES];
	uint64_t	 id;
};

#define	SET(rr, call) do {						\
	errno = 0;							\
	(rr).rv = (call);						\
	(rr).err = (rr).rv == -1 ? errno : 0;				\
} while (0)

#define	CHECK_OK(rr) ATF_CHECK_MSG((rr).rv != -1,			\
	"%s: failed, errno %d", #rr, (rr).err)
#define	CHECK_ERR(rr, want) ATF_CHECK_MSG((rr).rv == -1 &&		\
	(rr).err == (want), "%s: rv %ld errno %d, want errno %d", #rr,	\
	(rr).rv, (rr).err, (want))

static bool
become_nobody(void)
{
	gid_t gid = NOBODY_UID;

	return (setgroups(1, &gid) == 0 && setgid(NOBODY_UID) == 0 &&
	    setuid(NOBODY_UID) == 0);
}

/* The queue device as a process without libdq's O_CLOFORK opens it. */
static int
raw_open(void)
{
	int q;

	q = open(DQ_DEVICE, O_RDWR);
	ATF_REQUIRE_MSG(q != -1, "open %s: %s", DQ_DEVICE, strerror(errno));
	return (q);
}

static int
make_jail(const char *name)
{
	int jid;

	jid = jail_setv(JAIL_CREATE, "path", "/", "name", name, "persist",
	    NULL, NULL);
	ATF_REQUIRE_MSG(jid != -1, "jail_setv %s: %s", name, jail_errmsg);
	return (jid);
}

/* An idle child behind a process descriptor, as dq_attach_test makes one. */
struct idle {
	pid_t		 pid;
	int		 pd;
	int		 go[2];
};

/*
 * With exec_path the child waits for idle_exec() before it execs, so that
 * the NOTE_EXEC registration cannot lose the race; before that it enters
 * jail jid (unless -1) and, with nobody, gives up root.
 */
static void
idle_spawn_as(struct idle *s, const char *exec_path, int jid, bool nobody)
{
	char b;

	ATF_REQUIRE_EQ(0, pipe(s->go));
	s->pid = pdfork(&s->pd, 0);
	ATF_REQUIRE_MSG(s->pid != -1, "pdfork: %s", strerror(errno));
	if (s->pid == 0) {
		if (jid != -1 && jail_attach(jid) != 0)
			_exit(5);
		if (nobody && !become_nobody())
			_exit(4);
		(void)read(s->go[0], &b, 1);
		if (exec_path != NULL) {
			execl(exec_path, exec_path, "60", (char *)NULL);
			_exit(3);
		}
		_exit(0);
	}
}

static void
idle_spawn(struct idle *s, const char *exec_path)
{

	idle_spawn_as(s, exec_path, -1, false);
}

/* Let a child spawned with an exec_path go, and wait until it has exec'd. */
static void
idle_exec(struct idle *s)
{
	struct kevent kev;
	struct timespec ts = { 30, 0 };
	int kq;

	kq = kqueue();
	ATF_REQUIRE(kq != -1);
	EV_SET(&kev, s->pd, EVFILT_PROCDESC, EV_ADD, NOTE_EXEC | NOTE_EXIT, 0,
	    NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, &kev, 1, NULL, 0, NULL));
	ATF_REQUIRE_EQ(1, write(s->go[1], "x", 1));
	ATF_REQUIRE_EQ(1, kevent(kq, NULL, 0, &kev, 1, &ts));
	ATF_REQUIRE_MSG((kev.fflags & NOTE_EXIT) == 0 &&
	    (kev.fflags & NOTE_EXEC) != 0, "the target did not exec: %#x",
	    kev.fflags);
	(void)close(kq);
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
 * Open
 */

static void
child_open_stats(void *arg __unused, void *result)
{
	struct lg_res *res = result;
	struct dq_stats st;
	int q;

	SET(res->r[0], open(DQ_DEVICE, O_RDWR));
	q = (int)res->r[0].rv;
	SET(res->r[1], dq_get_stats(q, &st));
	res->id = res->r[1].rv == 0 ? st.ds_queue_id : 0;
}

/*
 * Changes in lg-3: root without the supervisor role is EPERM (open row 2),
 * a second open by one process is EBUSY, a fork child's open is EBUSY, and
 * the node becomes 0666.  Until then root opens as often as it likes.
 */
ATF_TC(root_open);
ATF_TC_HEAD(root_open, tc)
{
	atf_tc_set_md_var(tc, "descr", "unjailed root opens /dev/dq (0600 "
	    "root:wheel), twice, and again in a fork child; each open is a "
	    "queue of its own that answers GET_STATS");
}
ATF_TC_BODY(root_open, tc)
{
	struct lg_res res;
	struct dq_stats st, st2;
	struct stat sb;
	int q, q2;

	LG_ROOT();
	ATF_REQUIRE_EQ(0, stat(DQ_DEVICE, &sb));
	ATF_CHECK(S_ISCHR(sb.st_mode));
	ATF_CHECK_EQ_MSG(0600, sb.st_mode & ALLPERMS, "mode %#o",
	    sb.st_mode & ALLPERMS);
	ATF_CHECK_EQ(0, sb.st_uid);
	ATF_CHECK_EQ(0, sb.st_gid);
	ATF_CHECK_EQ(0, access(DQ_DEVICE, R_OK | W_OK));

	q = raw_open();
	ATF_REQUIRE_EQ(0, dq_get_stats(q, &st));
	ATF_CHECK(st.ds_queue_id != 0);
	q2 = raw_open();
	ATF_REQUIRE_EQ(0, dq_get_stats(q2, &st2));
	ATF_CHECK(st2.ds_queue_id != st.ds_queue_id);
	(void)close(q2);

	memset(&res, 0, sizeof(res));
	dqt_run_child(child_open_stats, NULL, &res, sizeof(res));
	CHECK_OK(res.r[0]);
	CHECK_OK(res.r[1]);
	ATF_CHECK(res.id != 0 && res.id != st.ds_queue_id);
	(void)close(q);
}

static void
child_nobody_open(void *arg __unused, void *result)
{
	struct lg_res *res = result;

	if (!become_nobody())
		_exit(4);
	SET(res->r[0], open(DQ_DEVICE, O_RDWR));
	SET(res->r[1], open(DQ_DEVICE, O_RDONLY));
	SET(res->r[2], open(DQ_DEVICE, O_WRONLY));
	SET(res->r[3], access(DQ_DEVICE, F_OK));
	SET(res->r[4], access(DQ_DEVICE, R_OK));
	SET(res->r[5], access(DQ_DEVICE, W_OK));
}

/*
 * Changes in lg-3: the node is 0666 and a non-root caller without the role
 * is refused by dq_open with EPERM; access(2) for reading and writing then
 * succeeds.  Today the node's mode answers first, with EACCES.
 */
ATF_TC(nonroot_open);
ATF_TC_HEAD(nonroot_open, tc)
{
	atf_tc_set_md_var(tc, "descr", "a non-root open of /dev/dq is EACCES "
	    "from the node's mode, for every access mode; access(2) agrees");
}
ATF_TC_BODY(nonroot_open, tc)
{
	struct lg_res res;

	LG_ROOT();
	memset(&res, 0, sizeof(res));
	dqt_run_child(child_nobody_open, NULL, &res, sizeof(res));
	CHECK_ERR(res.r[0], EACCES);
	CHECK_ERR(res.r[1], EACCES);
	CHECK_ERR(res.r[2], EACCES);
	CHECK_OK(res.r[3]);
	CHECK_ERR(res.r[4], EACCES);
	CHECK_ERR(res.r[5], EACCES);
}

/*
 * Preserve: with the node made accessible, the privilege check in dq_open
 * answers a non-root caller EPERM.  This is the errno lg-3 gives such a
 * caller once the node is 0666, so the order "mode, then EPERM" is the
 * part that stays.
 */
ATF_TC_WITH_CLEANUP(nonroot_open_behind_mode);
ATF_TC_HEAD(nonroot_open_behind_mode, tc)
{
	atf_tc_set_md_var(tc, "descr", "with the node chmod'ed 0666 a "
	    "non-root open is EPERM from dq_open's privilege check");
}
ATF_TC_BODY(nonroot_open_behind_mode, tc)
{
	struct lg_res res;

	LG_ROOT();
	ATF_REQUIRE_EQ(0, chmod(DQ_DEVICE, 0666));
	memset(&res, 0, sizeof(res));
	dqt_run_child(child_nobody_open, NULL, &res, sizeof(res));
	ATF_REQUIRE_EQ(0, chmod(DQ_DEVICE, 0600));
	CHECK_ERR(res.r[0], EPERM);
	CHECK_ERR(res.r[1], EPERM);
	CHECK_ERR(res.r[2], EPERM);
	CHECK_OK(res.r[4]);
	CHECK_OK(res.r[5]);
}
ATF_TC_CLEANUP(nonroot_open_behind_mode, tc)
{

	(void)chmod(DQ_DEVICE, 0600);
}

struct jail_arg {
	int		 jid;
	bool		 nobody;
	int		 q;		/* an inherited queue, or -1 */
	int		 pd;		/* a process outside the jail, or -1 */
	int		 dev;		/* /dev/mac_capability, or -1 */
};

static void
child_jailed(void *arg, void *result)
{
	struct jail_arg *a = arg;
	struct lg_res *res = result;
	struct dq_stats st;
	struct stat sb;

	if (jail_attach(a->jid) != 0)
		_exit(5);
	if (a->nobody && !become_nobody())
		_exit(4);
	SET(res->r[0], open(DQ_DEVICE, O_RDWR));
	SET(res->r[1], stat(DQ_DEVICE, &sb));
	res->id = res->r[1].rv == 0 ? sb.st_mode & ALLPERMS : 0;
	if (a->q != -1) {
		SET(res->r[2], dq_get_stats(a->q, &st));
		SET(res->r[3], dq_attach(a->q, a->pd));
	}
	if (a->dev != -1)
		SET(res->r[4], capability_service_connect(a->dev,
		    DQ_OBSERVE_SERVICE));
}

/*
 * Preserve: root in a jail without the role stays EPERM (open row 2; a
 * jailed supervisor opens by its role from lg-11k on).  The non-root answer
 * changes with the node's mode in lg-3 (EACCES to EPERM).
 */
ATF_TC_WITH_CLEANUP(jailed_open);
ATF_TC_HEAD(jailed_open, tc)
{
	atf_tc_set_md_var(tc, "descr", "in a jail that sees the node, root's "
	    "open is EPERM (PRIV_DRIVER is not a jail privilege) and a "
	    "non-root open is EACCES");
}
ATF_TC_BODY(jailed_open, tc)
{
	struct jail_arg a;
	struct lg_res res;

	LG_ROOT();
	a.jid = make_jail("dq_lg_open");
	a.q = a.pd = a.dev = -1;
	a.nobody = false;
	memset(&res, 0, sizeof(res));
	dqt_run_child(child_jailed, &a, &res, sizeof(res));
	CHECK_ERR(res.r[0], EPERM);
	CHECK_OK(res.r[1]);
	ATF_CHECK_EQ(0600, res.id);

	a.nobody = true;
	memset(&res, 0, sizeof(res));
	dqt_run_child(child_jailed, &a, &res, sizeof(res));
	CHECK_ERR(res.r[0], EACCES);
	CHECK_OK(res.r[1]);
	ATF_REQUIRE_EQ(0, jail_remove(a.jid));
}
ATF_TC_CLEANUP(jailed_open, tc)
{

	(void)jail_remove(jail_getid("dq_lg_open"));
}

static void
child_capmode(void *arg __unused, void *result)
{
	struct lg_res *res = result;
	struct dq_stats st;
	int dev, q;

	dev = open("/dev", O_RDONLY | O_DIRECTORY);
	if (dev == -1 || cap_enter() != 0)
		_exit(6);
	SET(res->r[0], open(DQ_DEVICE, O_RDWR));
	SET(res->r[1], openat(dev, "dq", O_RDWR));
	q = (int)res->r[1].rv;
	SET(res->r[2], dq_get_stats(q, &st));
}

/*
 * Not named by the design; recorded so that lg-3's open rows change it on
 * purpose.  A capability-mode process cannot name /dev/dq, but root in
 * capability mode holding a /dev directory descriptor opens a queue: no
 * check in dq_open looks at capability mode.  Expected to change in lg-3
 * with every other root open (EPERM without the role).
 */
ATF_TC(capmode_open);
ATF_TC_HEAD(capmode_open, tc)
{
	atf_tc_set_md_var(tc, "descr", "in capability mode open(2) of the "
	    "path is ECAPMODE; openat(2) below a /dev descriptor opens a "
	    "working queue for root");
}
ATF_TC_BODY(capmode_open, tc)
{
	struct lg_res res;

	LG_ROOT();
	memset(&res, 0, sizeof(res));
	dqt_run_child(child_capmode, NULL, &res, sizeof(res));
	CHECK_ERR(res.r[0], ECAPMODE);
	CHECK_OK(res.r[1]);
	CHECK_OK(res.r[2]);
}

/*
 * Changes in lg-3 (abuse review F-18, open row 4): an attached process's
 * open becomes EPERM.  Today an attached root process opens a queue of its
 * own; the open is itself resolved through its supervisor.
 */
ATF_TC(attached_root_open);
ATF_TC_HEAD(attached_root_open, tc)
{
	atf_tc_set_md_var(tc, "descr", "a root process attached to a queue "
	    "opens /dev/dq and gets a second, working queue");
}
ATF_TC_BODY(attached_root_open, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct dq_stats st;
	struct lg_res res;
	int status;

	LG_ROOT();
	dqt_init(&c);
	dqt_stats(&c, &st);
	memset(&res, 0, sizeof(res));
	dqt_attach_spawn(&c, &ch, child_open_stats, NULL);
	status = dqt_attach_wait(&ch, &res, sizeof(res));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK_OK(res.r[0]);
	CHECK_OK(res.r[1]);
	ATF_CHECK(res.id != 0 && res.id != st.ds_queue_id);
	/* It was attached: its open of the node was posted here. */
	ATF_CHECK(dqt_count_resolve(&c, DQ_DEVICE, 0) >= 1);
	dqt_fini(&c);
}

/*
 * A queue descriptor in the hands of a process that did not open it
 */

struct bearer_arg {
	int		 q;
	int		 sock;		/* -1, or where the queue arrives */
	const struct dq_ident_file *ident;
};

static int
recv_fd(int sock)
{
	union {
		struct cmsghdr	hdr;
		char		buf[CMSG_SPACE(sizeof(int))];
	} ctl;
	struct msghdr msg;
	struct iovec iov;
	char b;
	int fd;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &b;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ctl.buf;
	msg.msg_controllen = sizeof(ctl.buf);
	if (recvmsg(sock, &msg, 0) != 1 ||
	    msg.msg_controllen < CMSG_LEN(sizeof(int)) ||
	    ctl.hdr.cmsg_level != SOL_SOCKET || ctl.hdr.cmsg_type != SCM_RIGHTS)
		return (-1);
	memcpy(&fd, CMSG_DATA(&ctl.hdr), sizeof(fd));
	return (fd);
}

static int
send_fd(int sock, int fd)
{
	union {
		struct cmsghdr	hdr;
		char		buf[CMSG_SPACE(sizeof(int))];
	} ctl;
	struct msghdr msg;
	struct iovec iov;
	char b = 'q';

	memset(&msg, 0, sizeof(msg));
	memset(&ctl, 0, sizeof(ctl));
	iov.iov_base = &b;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ctl.buf;
	msg.msg_controllen = sizeof(ctl.buf);
	ctl.hdr.cmsg_len = CMSG_LEN(sizeof(int));
	ctl.hdr.cmsg_level = SOL_SOCKET;
	ctl.hdr.cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(&ctl.hdr), &fd, sizeof(fd));
	return (sendmsg(sock, &msg, 0) == 1 ? 0 : -1);
}

/* Every kind of queue operation, as nobody, on a queue root opened. */
static void
child_bearer(void *arg, void *result)
{
	struct bearer_arg *a = arg;
	struct lg_res *res = result;
	struct dq_policy pol;
	struct dq_stats st;
	struct dq_stats2 st2;
	char buf[4096];
	uint64_t object;
	int fd, on, q, reason;

	if (!become_nobody())
		_exit(4);
	q = a->q;
	if (a->sock != -1) {
		/* The O_CLOFORK queue did not come by fork. */
		SET(res->r[10], fcntl(q, F_GETFD));
		q = recv_fd(a->sock);
		if (q == -1)
			_exit(7);
	}
	SET(res->r[0], open(DQ_DEVICE, O_RDWR));	/* it is not root */
	SET(res->r[1], dq_get_stats(q, &st));
	res->id = res->r[1].rv == 0 ? st.ds_queue_id : 0;
	SET(res->r[2], dq_get_stats2(q, &st2));
	/* Read first: the objects minted below post records. */
	on = 1;
	SET(res->r[6], ioctl(q, FIONBIO, &on));
	SET(res->r[7], read(q, buf, sizeof(buf)));
	SET(res->r[3], dq_mint_observer(q, 0));
	dq_policy_default(&pol);
	object = 0;
	fd = -1;
	SET(res->r[4], dq_mint_file(q, a->ident, &pol, &object, &fd, &reason));
	SET(res->r[5], dq_revoke(q, object));
}

static void
check_bearer(const struct lg_res *res, uint64_t id)
{

	CHECK_ERR(res->r[0], EACCES);
	CHECK_OK(res->r[1]);
	ATF_CHECK_EQ(id, res->id);
	CHECK_OK(res->r[2]);
	CHECK_OK(res->r[3]);
	CHECK_OK(res->r[4]);
	CHECK_OK(res->r[5]);
	CHECK_OK(res->r[6]);
	CHECK_ERR(res->r[7], EAGAIN);
}

static void
bearer_ident(struct dq_ident_file *ident)
{
	static char path[DQT_PATH_MAX];
	struct statfs sfs;
	struct stat sb;
	int fd;

	fd = dqt_make_oracle("lg_oracle", "pin", 3, path, sizeof(path));
	dqt_ident_of(fd, path, ident, &sb, &sfs);
	(void)close(fd);
}

/*
 * Changes in lg-3 (abuse review F-02; the per-operation gate of 2.3): only
 * the process that opened the queue under its role may operate it, and a
 * fork child using the inherited descriptor is EPERM.  Today the descriptor
 * is a bearer token: the kernel does not make it close-on-fork (only
 * libdq's dq_open() asks for that) and no ioctl or read looks at the
 * caller.
 */
ATF_TC(bearer_fork);
ATF_TC_HEAD(bearer_fork, tc)
{
	atf_tc_set_md_var(tc, "descr", "a fork child that dropped to an "
	    "unprivileged user operates the inherited queue: statistics, "
	    "observer and object mint, revoke, FIONBIO, read");
}
ATF_TC_BODY(bearer_fork, tc)
{
	struct bearer_arg a;
	struct dq_ident_file *ident;
	struct dq_stats st;
	struct lg_res res;

	LG_ROOT();
	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	bearer_ident(ident);
	a.q = raw_open();
	a.sock = -1;
	a.ident = ident;
	ATF_REQUIRE_EQ(0, dq_get_stats(a.q, &st));
	memset(&res, 0, sizeof(res));
	dqt_run_child(child_bearer, &a, &res, sizeof(res));
	check_bearer(&res, st.ds_queue_id);
	(void)close(a.q);
	free(ident);
}

/*
 * Changes in lg-3, as bearer_fork.  The queue descriptor, unlike the
 * descriptors it mints, may be sent over a local socket today.
 */
ATF_TC(bearer_scm_rights);
ATF_TC_HEAD(bearer_scm_rights, tc)
{
	atf_tc_set_md_var(tc, "descr", "the queue descriptor passes over "
	    "SCM_RIGHTS to an unprivileged process, which operates it");
}
ATF_TC_BODY(bearer_scm_rights, tc)
{
	struct bearer_arg a;
	struct dqt_child ch;
	struct dq_ident_file *ident;
	struct dq_stats st;
	struct lg_res res;
	int status, sv[2];

	LG_ROOT();
	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	bearer_ident(ident);
	a.q = dq_open();		/* O_CLOFORK: not inherited */
	ATF_REQUIRE_MSG(a.q != -1, "dq_open: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));
	a.sock = sv[1];
	a.ident = ident;
	ATF_REQUIRE_EQ(0, dq_get_stats(a.q, &st));
	memset(&res, 0, sizeof(res));
	dqt_spawn(&ch, child_bearer, &a);
	ATF_CHECK_EQ_MSG(0, send_fd(sv[0], a.q), "sendmsg: %s",
	    strerror(errno));
	status = dqt_wait(&ch, &res, sizeof(res));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "status %#x", status);
	CHECK_ERR(res.r[10], EBADF);
	check_bearer(&res, st.ds_queue_id);
	(void)close(sv[0]);
	(void)close(sv[1]);
	(void)close(a.q);
	free(ident);
}

/* What dq_legitimacy_helper writes to its standard output. */
struct helper_res {
	int		 stats_rv, stats_errno;
	int		 attach_rv, attach_errno;
};

static void
run_helper(const atf_tc_t *tc, int q, struct helper_res *hr)
{
	char path[PATH_MAX];
	ssize_t n;
	pid_t pid;
	int pfd[2], status;

	snprintf(path, sizeof(path), "%s/dq_legitimacy_helper",
	    atf_tc_get_config_var(tc, "srcdir"));
	ATF_REQUIRE_EQ(0, pipe(pfd));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		if (dup2(q, LG_QFD) != LG_QFD ||
		    dup2(pfd[1], STDOUT_FILENO) != STDOUT_FILENO)
			_exit(126);
		/*
		 * One reference only: the helper's child must not hold the
		 * queue (EBUSY), and it closes just descriptor LG_QFD.
		 */
		if (q != LG_QFD)
			(void)close(q);
		closefrom(LG_QFD + 1);
		if (!become_nobody())
			_exit(4);
		execl(path, path, (char *)NULL);
		_exit(127);
	}
	(void)close(pfd[1]);
	n = read(pfd[0], hr, sizeof(*hr));
	(void)close(pfd[0]);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "%s: status %#x", path, status);
	ATF_REQUIRE_EQ((ssize_t)sizeof(*hr), n);
}

/*
 * Changes in lg-3 (interim attach refusal for a caller that is not the
 * queue's owner) and lg-5b (mandatory attach token).  Today a program run
 * by an unprivileged user that merely inherited a queue across execve(2)
 * attaches its own child to it: ATTACH asks only p_candebug().  With
 * security.bsd.unprivileged_proc_debug off the same call is EPERM, which
 * is the errno order to preserve for a caller that may not debug.  lg-3
 * must re-home that row on an unprivileged owner: a holder that is not
 * the owner is EPERM for another reason from then on (see the head of
 * this file).
 */
ATF_TC_WITH_CLEANUP(bearer_exec_attach);
ATF_TC_HEAD(bearer_exec_attach, tc)
{
	atf_tc_set_md_var(tc, "descr", "an unprivileged program that "
	    "inherited the queue across exec reads its statistics and "
	    "attaches its own child; EPERM with unprivileged_proc_debug off");
}
ATF_TC_BODY(bearer_exec_attach, tc)
{
	struct helper_res hr;
	FILE *f;
	u_int old;
	int q;

	LG_ROOT();
	ATF_REQUIRE(dqt_sysctl_get_uint(PROC_DEBUG, &old));
	f = fopen("proc_debug.save", "w");
	ATF_REQUIRE(f != NULL);
	fprintf(f, "%u\n", old);
	ATF_REQUIRE_EQ(0, fclose(f));

	q = raw_open();
	dqt_sysctl_set_uint(PROC_DEBUG, 1);
	memset(&hr, 0xff, sizeof(hr));
	run_helper(tc, q, &hr);
	ATF_CHECK_EQ_MSG(0, hr.stats_rv, "errno %d", hr.stats_errno);
	ATF_CHECK_EQ_MSG(0, hr.attach_rv, "errno %d", hr.attach_errno);

	dqt_sysctl_set_uint(PROC_DEBUG, 0);
	memset(&hr, 0xff, sizeof(hr));
	run_helper(tc, q, &hr);
	dqt_sysctl_set_uint(PROC_DEBUG, old);
	ATF_CHECK_EQ_MSG(0, hr.stats_rv, "errno %d", hr.stats_errno);
	ATF_CHECK_EQ(-1, hr.attach_rv);
	ATF_CHECK_EQ(EPERM, hr.attach_errno);
	(void)close(q);
}
ATF_TC_CLEANUP(bearer_exec_attach, tc)
{
	FILE *f;
	u_int old;

	f = fopen("proc_debug.save", "r");
	if (f != NULL) {
		if (fscanf(f, "%u", &old) == 1)
			(void)sysctlbyname(PROC_DEBUG, NULL, NULL, &old,
			    sizeof(old));
		(void)fclose(f);
	}
}

/*
 * Attach
 */

static void
child_attach(void *arg, void *result)
{
	struct jail_arg *a = arg;
	struct lg_res *res = result;

	SET(res->r[3], dq_attach(a->q, a->pd));
}

/*
 * Preserve: ATTACH to a process outside the caller's prison subtree is
 * ESRCH (p_candebug's prison_check; 15.3 keeps it for jailed supervisors).
 * That a jailed root process operates an inherited queue it could not open
 * changes in lg-3 with the other bearer cases.
 */
ATF_TC_WITH_CLEANUP(attach_outside_prison);
ATF_TC_HEAD(attach_outside_prison, tc)
{
	atf_tc_set_md_var(tc, "descr", "a root process that is not the "
	    "target's parent attaches it; the same call from inside a jail "
	    "on a process outside it is ESRCH");
}
ATF_TC_BODY(attach_outside_prison, tc)
{
	struct dqt_ctl c;
	struct idle s1, s2;
	struct jail_arg a;
	struct lg_res res;

	LG_ROOT();
	dqt_init_manual(&c);
	idle_spawn(&s1, NULL);
	idle_spawn(&s2, NULL);
	/* After the targets exist: a target holding the queue is EBUSY. */
	a.q = fcntl(c.q, F_DUPFD, 0);
	ATF_REQUIRE(a.q != -1);
	a.dev = -1;
	a.nobody = false;

	/* Control: an unjailed sibling attaches. */
	a.pd = s1.pd;
	memset(&res, 0, sizeof(res));
	dqt_run_child(child_attach, &a, &res, sizeof(res));
	CHECK_OK(res.r[3]);

	a.jid = make_jail("dq_lg_attach");
	a.pd = s2.pd;
	memset(&res, 0, sizeof(res));
	dqt_run_child(child_jailed, &a, &res, sizeof(res));
	CHECK_ERR(res.r[0], EPERM);
	CHECK_OK(res.r[2]);
	CHECK_ERR(res.r[3], ESRCH);
	ATF_REQUIRE_EQ(0, jail_remove(a.jid));

	(void)close(a.q);
	idle_end(&s1);
	idle_end(&s2);
	dqt_fini(&c);
}
ATF_TC_CLEANUP(attach_outside_prison, tc)
{

	(void)jail_remove(jail_getid("dq_lg_attach"));
}

struct targets_arg {
	int		 q;
	int		 plain, jailed;
};

static void
child_attach_targets(void *arg, void *result)
{
	struct targets_arg *a = arg;
	struct lg_res *res = result;

	if (!become_nobody())
		_exit(4);
	SET(res->r[0], dq_attach(a->q, a->plain));
	SET(res->r[1], dq_attach(a->q, a->jailed));
}

/*
 * Preserve: host root attaches a target that has entered a child jail
 * (prison_check passes downward, PRIV_DEBUG_DIFFJAIL).
 *
 * Preserve (design 15.3, review 4 N1): an unprivileged holder of the queue
 * may not attach a process of its own uid that is in a child jail: EPERM
 * from p_candebug (cr_can_tamper_with_subjail: no PRIV_DEBUG_DIFFJAIL,
 * and the jail does not allow unprivileged parent tampering).  The control
 * is the same target outside the jail, which is past the debug check and
 * is refused for its state (EBUSY: it has exec'd, as it must to shed
 * P_SUGID).  With security.bsd.unprivileged_proc_debug at 1, required.
 * The holder here is not the queue's owner; lg-3 re-homes these two rows
 * on an unprivileged owner with the others.
 */
ATF_TC_WITH_CLEANUP(attach_child_jail_target);
ATF_TC_HEAD(attach_child_jail_target, tc)
{
	atf_tc_set_md_var(tc, "descr", "unjailed root attaches a target "
	    "that entered a child jail; an unprivileged holder of the queue "
	    "is EPERM for a same-uid target there, EBUSY for one outside");
}
ATF_TC_BODY(attach_child_jail_target, tc)
{
	struct dqt_ctl c;
	struct idle plain, jailed;
	struct targets_arg a;
	struct lg_res res;
	pid_t pid;
	u_int knob;
	int go[2], jid, pd, ready[2], status;
	char b;

	LG_ROOT();
	ATF_REQUIRE(dqt_sysctl_get_uint(PROC_DEBUG, &knob));
	ATF_REQUIRE_EQ_MSG(1, knob, PROC_DEBUG " is %u", knob);
	dqt_init(&c);
	jid = make_jail("dq_lg_target");
	ATF_REQUIRE_EQ(0, pipe(go));
	ATF_REQUIRE_EQ(0, pipe(ready));
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		b = jail_attach(jid) == 0 ? 'j' : 'f';
		(void)write(ready[1], &b, 1);
		(void)read(go[0], &b, 1);
		_exit(0);
	}
	ATF_REQUIRE_EQ(1, read(ready[0], &b, 1));
	ATF_REQUIRE_EQ('j', b);
	ATF_CHECK_EQ_MSG(0, dq_attach(c.q, pd), "errno %d", errno);
	(void)write(go[1], "x", 1);
	(void)pdkill(pd, SIGKILL);
	(void)pdwait(pd, &status, WEXITED, NULL, NULL);
	(void)close(pd);

	idle_spawn_as(&plain, "/bin/sleep", -1, true);
	idle_exec(&plain);
	idle_spawn_as(&jailed, "/bin/sleep", jid, true);
	idle_exec(&jailed);
	a.plain = plain.pd;
	a.jailed = jailed.pd;
	a.q = fcntl(c.q, F_DUPFD, 0);
	ATF_REQUIRE(a.q != -1);
	memset(&res, 0, sizeof(res));
	dqt_run_child(child_attach_targets, &a, &res, sizeof(res));
	CHECK_ERR(res.r[0], EBUSY);
	CHECK_ERR(res.r[1], EPERM);
	(void)close(a.q);
	idle_end(&plain);
	idle_end(&jailed);

	ATF_REQUIRE_EQ(0, jail_remove(jid));
	dqt_fini(&c);
}
ATF_TC_CLEANUP(attach_child_jail_target, tc)
{

	(void)jail_remove(jail_getid("dq_lg_target"));
}

struct order_arg {
	int		 q;
	int		 notpd;
	int		 exited, execed, idle;
};

static void
child_attach_order(void *arg, void *result)
{
	struct order_arg *a = arg;
	struct lg_res *res = result;

	if (!become_nobody())
		_exit(4);
	SET(res->r[0], dq_attach(a->q, a->notpd));
	SET(res->r[1], dq_attach(a->q, a->exited));
	SET(res->r[2], dq_attach(a->q, a->execed));
	SET(res->r[3], dq_attach(a->q, a->idle));
}

/*
 * Preserve (attach errno order, which unattached and refused callers see):
 * argument errors (EINVAL), then a target that is gone (ESRCH), then the
 * caller's right to debug it (EPERM), then the target's state (EBUSY).  An
 * unprivileged holder of the queue shows the order: for a target that has
 * exec'd it is told EPERM where root is told EBUSY.  lg-3 and lg-5b put
 * their refusals (EPERM) in front for a caller without the role or the
 * token; the order behind them stays.  After lg-3 a holder that is not
 * the owner is told EPERM for all four, so lg-3 must re-home the first
 * four rows on an unprivileged owner (see the head of this file).
 */
ATF_TC(attach_errno_order);
ATF_TC_HEAD(attach_errno_order, tc)
{
	atf_tc_set_md_var(tc, "descr", "ATTACH by an unprivileged holder of "
	    "the queue: EINVAL for a descriptor that is no process, ESRCH "
	    "for an exited one, EPERM before EBUSY for one that exec'd");
}
ATF_TC_BODY(attach_errno_order, tc)
{
	struct dqt_ctl c;
	struct idle exited, execed, idle;
	struct order_arg a;
	struct lg_res res;
	int status;

	LG_ROOT();
	dqt_init_manual(&c);
	idle_spawn(&exited, NULL);
	(void)write(exited.go[1], "x", 1);
	ATF_REQUIRE_EQ(0, pdwait(exited.pd, &status, WEXITED, NULL, NULL));
	idle_spawn(&execed, "/bin/sleep");
	idle_exec(&execed);
	idle_spawn(&idle, NULL);

	a.notpd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(a.notpd != -1);
	a.exited = exited.pd;
	a.execed = execed.pd;
	a.idle = idle.pd;
	a.q = fcntl(c.q, F_DUPFD, 0);
	ATF_REQUIRE(a.q != -1);
	memset(&res, 0, sizeof(res));
	dqt_run_child(child_attach_order, &a, &res, sizeof(res));
	CHECK_ERR(res.r[0], EINVAL);
	CHECK_ERR(res.r[1], ESRCH);
	CHECK_ERR(res.r[2], EPERM);
	CHECK_ERR(res.r[3], EPERM);
	(void)close(a.q);

	/* Root is past the debug check: the target's state answers. */
	errno = 0;
	ATF_CHECK_EQ(-1, dq_attach(c.q, execed.pd));
	ATF_CHECK_EQ(EBUSY, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_attach(c.q, exited.pd));
	ATF_CHECK_EQ(ESRCH, errno);
	ATF_CHECK_EQ_MSG(0, dq_attach(c.q, idle.pd), "errno %d", errno);

	(void)close(a.notpd);
	(void)close(exited.pd);
	(void)close(exited.go[0]);
	(void)close(exited.go[1]);
	idle_end(&execed);
	idle_end(&idle);
	dqt_fini(&c);
}

/*
 * The dq.observe service
 */

struct observe_arg {
	uint64_t	 id;
	int		 dev;
	bool		 nobody;
};

static void
child_observe(void *arg, void *result)
{
	struct observe_arg *a = arg;
	struct lg_res *res = result;
	struct dqo_queue_info qi[64];
	size_t count, i;
	uint64_t first, total;
	int svc;

	if (a->nobody) {
		if (!become_nobody())
			_exit(4);
		SET(res->r[0], open(DQ_MAC_CAPABILITY_DEVICE, O_RDWR));
		SET(res->r[1], capability_service_connect(a->dev,
		    DQ_OBSERVE_SERVICE));
		return;
	}
	SET(res->r[1], dq_observe_connect());
	svc = (int)res->r[1].rv;
	first = 0;
	do {
		SET(res->r[2], dq_observe_list_queues(svc, first, qi,
		    nitems(qi), &count, &total));
		if (res->r[2].rv != 0)
			return;
		for (i = 0; i < count; i++) {
			if (qi[i].qi_id == a->id)
				res->id = a->id;
		}
		first += count;
	} while (count != 0 && first < total && res->id == 0);
}

/*
 * Changes in lg-3 (S3: the observe service checks the supervisor role, and
 * the connect gate changes if Q14 is accepted).  Today the gate is
 * PRIV_DRIVER on the connecting credential and nothing else: any unjailed
 * root process lists every queue, also one it has nothing to do with.
 * A credential without the privilege is EPERM at connect, in a jail too.
 * That also changes in lg-3 (design 2.4): connect admits any credential
 * and each call is refused EPERM instead; only the device open's EACCES
 * is preserved.  The jailed row claims the errno only: whether the dq
 * gate or an earlier refusal of a jailed caller produces it is not
 * established.
 */
ATF_TC_WITH_CLEANUP(observe_connect_gate);
ATF_TC_HEAD(observe_connect_gate, tc)
{
	atf_tc_set_md_var(tc, "descr", "dq.observe: an unrelated root "
	    "process connects and finds another process's queue; a non-root "
	    "and a jailed root credential are EPERM at connect, on a device "
	    "descriptor root opened for them");
}
ATF_TC_BODY(observe_connect_gate, tc)
{
	struct observe_arg a;
	struct jail_arg ja;
	struct dq_stats st;
	struct lg_res res;
	int q;

	LG_ROOT();
	q = dq_open();
	ATF_REQUIRE_MSG(q != -1, "dq_open: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, dq_get_stats(q, &st));
	a.id = st.ds_queue_id;
	a.dev = open(DQ_MAC_CAPABILITY_DEVICE, O_RDWR);
	ATF_REQUIRE_MSG(a.dev != -1, "open %s: %s", DQ_MAC_CAPABILITY_DEVICE,
	    strerror(errno));

	a.nobody = false;
	memset(&res, 0, sizeof(res));
	dqt_run_child(child_observe, &a, &res, sizeof(res));
	CHECK_OK(res.r[1]);
	CHECK_OK(res.r[2]);
	ATF_CHECK_EQ(st.ds_queue_id, res.id);

	a.nobody = true;
	memset(&res, 0, sizeof(res));
	dqt_run_child(child_observe, &a, &res, sizeof(res));
	CHECK_ERR(res.r[0], EACCES);
	CHECK_ERR(res.r[1], EPERM);

	ja.jid = make_jail("dq_lg_observe");
	ja.nobody = false;
	ja.q = ja.pd = -1;
	ja.dev = a.dev;
	memset(&res, 0, sizeof(res));
	dqt_run_child(child_jailed, &ja, &res, sizeof(res));
	CHECK_ERR(res.r[4], EPERM);
	ATF_REQUIRE_EQ(0, jail_remove(ja.jid));

	(void)close(a.dev);
	(void)close(q);
}
ATF_TC_CLEANUP(observe_connect_gate, tc)
{

	(void)jail_remove(jail_getid("dq_lg_observe"));
}

/*
 * Software authority: the constraint words the role will use
 */

static int
constrain(const struct cap_authority_constraint *c)
{

	return (syscall(SYS_cap_process, CAP_AUTH_CONSTRAIN, -1, 0, c));
}

/*
 * Changed in lg-1: flags carries the role bits.  CAP_AUTH_ROLE_DQ_SUPERVISOR
 * is accepted, so that request now gets as far as the bad issuer
 * descriptor, like the control; this says nothing about who may set it,
 * which needs an issuer (the PID 1 fixture checks that).  Every other bit
 * of flags, the retired 0x1 among them, is still EINVAL.
 * Changes in lg-11k (the reserved word carries the jail).  Every bit of
 * the reserved word is refused with EINVAL.  The check comes before the
 * issuer descriptor is looked at, so any process can ask: the control with
 * both words zero gets as far as the bad issuer descriptor (EBADF).
 * Preserve: nexec of 0 or more than CAP_AUTH_EXEC_MAX is EINVAL.
 */
ATF_TC(constrain_reserved_words);
ATF_TC_HEAD(constrain_reserved_words, tc)
{
	atf_tc_set_md_var(tc, "descr", "CAP_AUTH_CONSTRAIN refuses every "
	    "bit of flags and of the reserved word with EINVAL before it "
	    "looks at the issuer");
}
ATF_TC_BODY(constrain_reserved_words, tc)
{
	struct cap_authority_constraint c;
	int bit, expect;

	memset(&c, 0, sizeof(c));
	c.token_fd = -1;
	c.nexec = 1;
	c.executable_fds[0] = -1;
	errno = 0;
	ATF_REQUIRE_EQ(-1, constrain(&c));
	ATF_REQUIRE_EQ_MSG(EBADF, errno, "control: errno %d", errno);

	for (bit = 0; bit < 32; bit++) {
		c.flags = 1U << bit;
		errno = 0;
		ATF_CHECK_EQ(-1, constrain(&c));
		expect = c.flags == CAP_AUTH_ROLE_DQ_SUPERVISOR ? EBADF : EINVAL;
		ATF_CHECK_EQ_MSG(expect, errno, "flags bit %d: errno %d", bit,
		    errno);
		c.flags = 0;
		c.reserved = 1U << bit;
		errno = 0;
		ATF_CHECK_EQ(-1, constrain(&c));
		ATF_CHECK_EQ_MSG(EINVAL, errno, "reserved bit %d: errno %d",
		    bit, errno);
		c.reserved = 0;
	}

	c.nexec = 0;
	errno = 0;
	ATF_CHECK_EQ(-1, constrain(&c));
	ATF_CHECK_EQ(EINVAL, errno);
	c.nexec = CAP_AUTH_EXEC_MAX + 1;
	errno = 0;
	ATF_CHECK_EQ(-1, constrain(&c));
	ATF_CHECK_EQ(EINVAL, errno);
}

/*
 * Other ABIs
 */

#define	LINUX_CC	"clang --target=%s -fuse-ld=lld -nostdlib -static "	\
	"-fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror "	\
	"-o %s %s/%s"

static void
build_foreign(const atf_tc_t *tc, const char *target, const char *out,
    const char *src)
{
	char cmd[PATH_MAX + 512];

	snprintf(cmd, sizeof(cmd), LINUX_CC, target, out,
	    atf_tc_get_config_var(tc, "srcdir"), src);
	/* Not a skip: without the compiler the pin is not taken. */
	ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s", cmd);
}

#define	LX_NRES		11

/* Run dq_legitimacy_linux with q as descriptor LG_QFD; collect its answers. */
static void
run_linux(int q, bool nobody, long *lr)
{
	char *const argv[] = { __DECONST(char *, "dq_legitimacy_linux"), NULL };
	char *const envp[] = { NULL };
	ssize_t n;
	pid_t pid;
	int image, pfd[2], status;

	image = open("dq_legitimacy_linux", O_RDONLY);
	ATF_REQUIRE(image != -1);
	ATF_REQUIRE_EQ(0, pipe(pfd));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		if (dup2(q, LG_QFD) != LG_QFD ||
		    dup2(pfd[1], STDOUT_FILENO) != STDOUT_FILENO)
			_exit(126);
		if (nobody && !become_nobody())
			_exit(4);
		fexecve(image, argv, envp);
		_exit(127);
	}
	(void)close(pfd[1]);
	(void)close(image);
	n = read(pfd[0], lr, LX_NRES * sizeof(*lr));
	(void)close(pfd[0]);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	/* 127: the Linux ABI is not loaded.  Not a skip either. */
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "dq_legitimacy_linux: status %#x", status);
	ATF_REQUIRE_EQ((ssize_t)(LX_NRES * sizeof(*lr)), n);
}

/*
 * Changes in lg-3 (a Linux root process without the role is EPERM at open,
 * as a native one) and lg-10k (the dq commands are translated for a Linux
 * supervisor).  Preserve: a group 'j' request on a descriptor that is not
 * a queue keeps today's answer (EINVAL from the Linux ioctl fallback), and
 * read and FIONBIO need no translation.  Today an LP64 Linux process opens
 * and reads a queue but no dq command reaches it: the Linux ioctl entry
 * has no handler for the group.
 */
ATF_TC(linux_open_ioctl);
ATF_TC_HEAD(linux_open_ioctl, tc)
{
	atf_tc_set_md_var(tc, "descr", "an LP64 Linux process: root opens "
	    "and reads a queue, a non-root open is EACCES, an inherited "
	    "queue is read by either, and every group 'j' ioctl is EINVAL "
	    "on a queue as on /dev/null");
	/* The program is amd64 Linux: the one permitted kind of skip. */
	atf_tc_set_md_var(tc, "require.arch", "amd64");
}
ATF_TC_BODY(linux_open_ioctl, tc)
{
	long lr[LX_NRES];
	int i, q;

	LG_ROOT();
	build_foreign(tc, "x86_64-linux-gnu", "dq_legitimacy_linux",
	    "dq_legitimacy_linux.c");
	ATF_REQUIRE_EQ(0, chmod("dq_legitimacy_linux", 0755));

	q = raw_open();
	memset(lr, 0x55, sizeof(lr));
	run_linux(q, false, lr);
	ATF_CHECK_MSG(lr[0] >= 0, "open: %ld", lr[0]);
	for (i = 1; i <= 3; i++)
		ATF_CHECK_EQ_MSG(-LINUX_EINVAL, lr[i], "ioctl %d: %ld", i,
		    lr[i]);
	ATF_CHECK_EQ_MSG(0, lr[4], "FIONBIO: %ld", lr[4]);
	ATF_CHECK_EQ_MSG(-LINUX_EAGAIN, lr[5], "read: %ld", lr[5]);
	ATF_CHECK_EQ_MSG(-LINUX_EINVAL, lr[6], "inherited ioctl: %ld", lr[6]);
	ATF_CHECK_EQ_MSG(0, lr[7], "inherited FIONBIO: %ld", lr[7]);
	ATF_CHECK_EQ_MSG(-LINUX_EAGAIN, lr[8], "inherited read: %ld", lr[8]);
	ATF_CHECK_MSG(lr[9] >= 0, "open /dev/null: %ld", lr[9]);
	ATF_CHECK_EQ_MSG(-LINUX_EINVAL, lr[10], "/dev/null ioctl: %ld",
	    lr[10]);
	(void)close(q);

	/* A fresh queue: the first run left its descriptor non-blocking. */
	q = raw_open();
	memset(lr, 0x55, sizeof(lr));
	run_linux(q, true, lr);
	ATF_CHECK_EQ_MSG(-LINUX_EACCES, lr[0], "open: %ld", lr[0]);
	for (i = 1; i <= 5; i++)
		ATF_CHECK_EQ_MSG(-LINUX_EBADF, lr[i], "call %d: %ld", i,
		    lr[i]);
	ATF_CHECK_EQ_MSG(-LINUX_EINVAL, lr[6], "inherited ioctl: %ld", lr[6]);
	ATF_CHECK_EQ_MSG(0, lr[7], "inherited FIONBIO: %ld", lr[7]);
	ATF_CHECK_EQ_MSG(-LINUX_EAGAIN, lr[8], "inherited read: %ld", lr[8]);
	ATF_CHECK_EQ_MSG(-LINUX_EINVAL, lr[10], "/dev/null ioctl: %ld",
	    lr[10]);
	(void)close(q);
}

/*
 * Unattached control
 */

static void
child_control(void *arg, void *result)
{
	struct lg_res *res = result;
	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
	pid_t pid;
	int go[2], status, tracing;
	char b;

	/* No queue of its own, and none inherited. */
	(void)close(*(int *)arg);

	if (pipe(go) != 0)
		_exit(6);
	pid = fork();
	if (pid == -1)
		_exit(7);
	if (pid == 0) {
		(void)close(go[1]);
		(void)read(go[0], &b, 1);
		_exit(0);
	}
	SET(res->r[0], ptrace(PT_ATTACH, pid, NULL, 0));
	status = 0;
	SET(res->r[1], waitpid(pid, &status, WUNTRACED) == pid &&
	    WIFSTOPPED(status) ? 0 : -1);
	SET(res->r[2], ptrace(PT_DETACH, pid, (caddr_t)1, 0));
	(void)close(go[1]);
	status = -1;
	SET(res->r[3], waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 0 ? 0 : -1);

	tracing = -2;
	SET(res->r[4], procctl(P_PID, getpid(), PROC_TRACE_STATUS, &tracing));
	res->id = (uint64_t)(int64_t)tracing;

	/* A child that aborts leaves a core. */
	pid = fork();
	if (pid == -1)
		_exit(7);
	if (pid == 0) {
		(void)setrlimit(RLIMIT_CORE, &rl);
		(void)signal(SIGABRT, SIG_DFL);
		abort();
	}
	status = 0;
	SET(res->r[5], waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) &&
	    WTERMSIG(status) == SIGABRT ? 0 : -1);
	res->r[6].rv = WCOREDUMP(status) ? 1 : 0;
	res->r[6].err = 0;
}

/*
 * Preserve, in every slice: a process that holds no queue and is attached
 * to none sees what it sees today while another process runs a queue.  The
 * later slices refuse to debug a supervisor, to trace one and to dump its
 * core (lg-3), and none of that may reach an unrelated process: it debugs
 * its own child, is itself traceable, and its aborting child dumps core.
 * The answers are compared as one transcript, byte for byte.
 */
ATF_TC(unattached_control);
ATF_TC_HEAD(unattached_control, tc)
{
	atf_tc_set_md_var(tc, "descr", "beside a live queue, a process "
	    "without one debugs its child, is traceable and has a child "
	    "dump core: one transcript, compared byte for byte");
}
ATF_TC_BODY(unattached_control, tc)
{
	static const char expected[] =
	    "attach=0/0 stop=0/0 detach=0/0 exit=0/0 trace_status=0/0:0 "
	    "abort=0/0 core=1";
	struct lg_res res;
	char transcript[256];
	int q;

	LG_ROOT();
	q = raw_open();
	memset(&res, 0xff, sizeof(res));
	dqt_run_child(child_control, &q, &res, sizeof(res));
	snprintf(transcript, sizeof(transcript),
	    "attach=%ld/%d stop=%ld/%d detach=%ld/%d exit=%ld/%d "
	    "trace_status=%ld/%d:%jd abort=%ld/%d core=%ld",
	    res.r[0].rv, res.r[0].err, res.r[1].rv, res.r[1].err,
	    res.r[2].rv, res.r[2].err, res.r[3].rv, res.r[3].err,
	    res.r[4].rv, res.r[4].err, (intmax_t)(int64_t)res.id,
	    res.r[5].rv, res.r[5].err, res.r[6].rv);
	ATF_CHECK_STREQ(expected, transcript);
	(void)close(q);
}

static int
exec_errno(const char *image)
{
	char *const argv[] = { __DECONST(char *, image), NULL };
	char *const envp[] = { NULL };
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		execve(image, argv, envp);
		_exit(errno == ENOEXEC ? 100 : 101);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	return (WEXITSTATUS(status));
}

/*
 * The design's ILP32 rows (a 32-bit caller's open is EOPNOTSUPP, EACCES
 * for a non-root one until lg-3) cannot be reached on this kernel: amd64
 * GENERIC has neither COMPAT_FREEBSD32 nor a 32-bit Linux ABI, so no ILP32
 * process exists to make the call.  This pins that fact, directly (the
 * kernel does not announce the compat_freebsd32 feature and the 32-bit
 * Linux ABI module is not loaded, where the 64-bit one is) and by its
 * effect (neither image runs).  If any of this changes, the ILP32 check in
 * dq_open has become reachable and its pins must be written before lg-3
 * moves it.
 */
ATF_TC(ilp32_no_abi);
ATF_TC_HEAD(ilp32_no_abi, tc)
{
	atf_tc_set_md_var(tc, "descr", "a 32-bit FreeBSD and a 32-bit Linux "
	    "image are ENOEXEC: no ILP32 process can reach dq_open");
	atf_tc_set_md_var(tc, "require.arch", "amd64");
}
ATF_TC_BODY(ilp32_no_abi, tc)
{
	size_t len;
	int feature;

	len = sizeof(feature);
	errno = 0;
	ATF_CHECK_EQ(-1, sysctlbyname("kern.features.compat_freebsd32",
	    &feature, &len, NULL, 0));
	ATF_CHECK_EQ(ENOENT, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, kldfind("linux.ko"));
	ATF_CHECK_EQ(ENOENT, errno);
	/* The control: kldfind does find the 64-bit ABI. */
	ATF_CHECK_MSG(kldfind("linux64.ko") != -1, "linux64.ko: %s",
	    strerror(errno));

	build_foreign(tc, "i386-unknown-freebsd", "ilp32_freebsd",
	    "dq_legitimacy_ilp32.c");
	build_foreign(tc, "i386-linux-gnu", "ilp32_linux",
	    "dq_legitimacy_ilp32.c");
	ATF_CHECK_EQ(100, exec_errno("./ilp32_freebsd"));
	ATF_CHECK_EQ(100, exec_errno("./ilp32_linux"));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, root_open);
	ATF_TP_ADD_TC(tp, nonroot_open);
	ATF_TP_ADD_TC(tp, nonroot_open_behind_mode);
	ATF_TP_ADD_TC(tp, jailed_open);
	ATF_TP_ADD_TC(tp, capmode_open);
	ATF_TP_ADD_TC(tp, attached_root_open);
	ATF_TP_ADD_TC(tp, bearer_fork);
	ATF_TP_ADD_TC(tp, bearer_scm_rights);
	ATF_TP_ADD_TC(tp, bearer_exec_attach);
	ATF_TP_ADD_TC(tp, attach_outside_prison);
	ATF_TP_ADD_TC(tp, attach_child_jail_target);
	ATF_TP_ADD_TC(tp, attach_errno_order);
	ATF_TP_ADD_TC(tp, observe_connect_gate);
	ATF_TP_ADD_TC(tp, constrain_reserved_words);
	ATF_TP_ADD_TC(tp, linux_open_ioctl);
	ATF_TP_ADD_TC(tp, unattached_control);
	ATF_TP_ADD_TC(tp, ilp32_no_abi);
	return (atf_no_error());
}
