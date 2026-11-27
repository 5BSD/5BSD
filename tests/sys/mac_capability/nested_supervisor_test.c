/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * NS0: kernel pins of what a parent can do with its children's service
 * lookup route on dev, written before the nested-supervisor slices
 * (nested-supervisors.md rev 1.3, section 9) change it.  Each case pins
 * real behaviour of today's kernel and passes on dev:
 *
 *   NR1 parent_route_receives_child_lookups  an unprivileged process
 *	installs a channel it made with the ungated
 *	mac_capability_channel_create() syscall as its child's route; the
 *	child's MAC_CAP_PROCESS_GET descriptor and the child's own lookups
 *	reach the parent's far end, and the parent can answer them.  Steps
 *	2-4 (and NR2's lookup half in subset_test) speak dev's
 *	REGISTER_LOOKUP handshake on the shared route, which channel S4b
 *	rewrites; they are rewritten with it.
 *   NR4 coalition_needs_device  the coalition service is gated only by
 *	reaching /dev/mac_capability: an unprivileged open is EACCES, root
 *	is refused too while Capsule's claim is enforced, and a held device
 *	descriptor mints a coalition whatever the caller's credentials.
 *   NR6 clear_gives_no_route_on_dev  MAC_CAP_PROCESS_CLEAR leaves no route
 *	at all, not the system route, even under the plane.  Channel S4a
 *	inverts this case in its own tests ("reset to the default").
 *   NR8 route_survives_setid_exec  a route a parent installed survives a
 *	set-uid exec: same generation, and GET reaches the parent's far end.
 *
 * Every wait is on an event: a child's exit (waitpid, a pipe's end of
 * file) or a message on a channel (MAC_CAPABILITY_RECV_F_WAIT).  A
 * supervising process drops its own references to the far end's peer
 * before it waits, so a child that dies early ends the wait with
 * ECONNRESET instead of leaving it asleep.
 */

#include <sys/param.h>
#include <sys/cap_authority.h>
#include <sys/cap_process.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <kenv.h>
#include <libservice.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <switchboard_svc_proto.h>

#include "nested_supervisor.h"

#define	NA	(-9999)		/* a step that was not reached */
#define	ERRNO_OF(rv)	((rv) == -1 ? errno : 0)

#define	ROW(what, got, want) do {					\
	int got_ = (int)(got), want_ = (int)(want);			\
	ATF_CHECK_EQ_MSG(want_, got_, "%s: got %d (%s), pinned %d (%s)",	\
	    (what), got_, got_ > 0 ? strerror(got_) : "-", want_,	\
	    want_ > 0 ? strerror(want_) : "-");				\
} while (0)

/*
 * Run fn in a child and copy its result back over a pipe.  The parent's
 * read ends at the child's write or its exit, whichever comes first.
 */
static void
run_child(void (*fn)(const void *, void *), const void *arg, void *result,
    size_t size)
{
	ssize_t n;
	size_t got;
	pid_t pid;
	int p[2], status;

	ATF_REQUIRE(pipe2(p, O_CLOEXEC) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		(void)close(p[0]);
		fn(arg, result);
		_exit(write(p[1], result, size) == (ssize_t)size ? 0 : 70);
	}
	(void)close(p[1]);
	for (got = 0; got < size; got += (size_t)n) {
		n = read(p[0], (char *)result + got, size - got);
		if (n <= 0)
			break;
	}
	(void)close(p[0]);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child status %#x", status);
	ATF_REQUIRE_EQ_MSG(size, got, "child reported %zu of %zu bytes", got,
	    size);
}

static void
helper_path(const atf_tc_t *tc, const char *name, char *buf, size_t len)
{

	snprintf(buf, len, "%s/%s", atf_tc_get_config_var(tc, "srcdir"),
	    name);
	ATF_REQUIRE_MSG(access(buf, X_OK) == 0, "%s: %s", buf,
	    strerror(errno));
}

/* The account the unprivileged rows run as. */
static void
unprivileged_ids(uid_t *uid, gid_t *gid)
{
	struct passwd *pw;

	pw = getpwnam("nobody");
	ATF_REQUIRE_MSG(pw != NULL, "no nobody account");
	*uid = pw->pw_uid;
	*gid = pw->pw_gid;
}

/* In a child: become uid/gid with no supplementary groups; errno or 0. */
static int
drop_to(uid_t uid, gid_t gid)
{

	if (setgroups(1, &gid) == -1 || setgid(gid) == -1 ||
	    setuid(uid) == -1)
		return (errno);
	return (0);
}

/* PID 1 is Capsule: the capability plane is on. */
static bool
plane_is_on(void)
{
	struct kinfo_proc kp;
	size_t len;
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 1 };

	len = sizeof(kp);
	ATF_REQUIRE_MSG(sysctl(mib, nitems(mib), &kp, &len, NULL, 0) == 0,
	    "kern.proc.pid.1: %s", strerror(errno));
	return (strcmp(kp.ki_comm, "capsule") == 0);
}

/* Receive one message on `fd`, waiting for it with no limit. */
static int
recv_wait(int fd, void *buf, size_t len, int *fds, uint32_t nfds,
    struct mac_capability_recvmsg_v2_args *out)
{
	struct mac_capability_recvmsg_v2_args ra;

	memset(&ra, 0, sizeof(ra));
	ra.message.payload = buf;
	ra.message.payload_len = len;
	ra.message.fds = fds;
	ra.message.nfds = nfds;
	ra.message.flags = MAC_CAPABILITY_RECV_F_WAIT;
	ra.message._reserved[0] = MAC_CAPABILITY_RECV_WAIT_FOREVER;
	if (ioctl(fd, MAC_CAPABILITY_RECVMSG_V2, &ra) == -1)
		return (errno);
	/* A peer that closed is reported as an empty message. */
	if (ra.message.payload_len == 0 && ra.message.nfds == 0)
		return (ECONNRESET);
	if (out != NULL)
		*out = ra;
	return (0);
}

static int
send_msg(int fd, const void *buf, size_t len, const int *fds, uint32_t nfds,
    uint64_t token)
{
	struct mac_capability_sendmsg_args sa;

	memset(&sa, 0, sizeof(sa));
	sa.payload = buf;
	sa.payload_len = len;
	sa.fds = fds;
	sa.nfds = nfds;
	sa.reply_token = token;
	return (ERRNO_OF(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa)));
}

/*
 * NR1.  The supervising process runs unprivileged in a child of the test:
 * it makes the pair, installs one end as its own route, forks the helper
 * (which inherits the route through exec), then drops every reference it
 * holds to that end so the helper's route is the only one.
 */
struct nr1_res {
	int		drop, create, set;
	uid_t		uid;
	pid_t		child;
	int		tag_recv, tag_nfds;
	pid_t		tag_pid;
	char		tag[32];
	int		reg_recv, reg_nfds, reg_token;
	uint32_t	reg_op;
	int		ack_send;
	int		lookup_recv;
	uint32_t	lookup_op;
	char		lookup_name[SWITCHBOARD_NAME_MAX + 1];
	int		reply_send;
	int		session_recv;
	char		session[32];
	int		child_status;
};

struct nr1_arg {
	char		helper[PATH_MAX];
	uid_t		uid;
	gid_t		gid;
};

static void
nr1_supervisor(const void *argp, void *resp)
{
	const struct nr1_arg *arg = argp;
	struct nr1_res *r = resp;
	struct mac_capability_recvmsg_v2_args ra;
	struct svc_register_lookup_req reg;
	struct svc_register_lookup_ack ack;
	struct svc_lookup_req lookup;
	struct svc_reply reply;
	int pair[2], session[2], fds[1], private_end, pd;

	memset(r, 0, sizeof(*r));
	r->create = r->set = r->tag_recv = r->reg_recv = r->ack_send = NA;
	r->lookup_recv = r->reply_send = r->session_recv = NA;
	r->child_status = -1;
	r->drop = drop_to(arg->uid, arg->gid);
	r->uid = getuid();
	if (r->drop != 0)
		return;
	r->create = ERRNO_OF(mac_capability_channel_create(pair));
	if (r->create != 0)
		return;
	(void)fcntl(pair[0], F_SETFD, FD_CLOEXEC);
	(void)fcntl(pair[1], F_SETFD, FD_CLOEXEC);
	r->set = ERRNO_OF(cap_process(MAC_CAP_PROCESS_SET, pair[0], getuid(),
	    NULL));
	if (r->set != 0)
		return;
	r->child = fork();
	if (r->child == 0) {
		execl(arg->helper, arg->helper, NSH_MODE_LOOKUP,
		    NSH_NR1_NAME, NSH_NR1_TAG, (char *)NULL);
		_exit(NSH_EXIT_EXEC);
	}
	if (r->child == -1)
		return;
	/* The helper's route is now the only holder of pair[0]. */
	(void)cap_process(MAC_CAP_PROCESS_CLEAR, -1, 0, NULL);
	(void)close(pair[0]);

	/* 1. What the helper sent on its MAC_CAP_PROCESS_GET descriptor. */
	r->tag_recv = recv_wait(pair[1], r->tag, sizeof(r->tag) - 1, NULL, 0,
	    &ra);
	if (r->tag_recv == 0) {
		r->tag_nfds = (int)ra.message.nfds;
		r->tag_pid = ra.process.pid;
	}
	/* 2. Its libservice lookup: the private-channel registration. */
	fds[0] = -1;
	memset(&reg, 0, sizeof(reg));
	r->reg_recv = recv_wait(pair[1], &reg, sizeof(reg), fds, 1, &ra);
	if (r->reg_recv != 0)
		goto out;
	r->reg_op = reg.op;
	r->reg_nfds = (int)ra.message.nfds;
	r->reg_token = ra.message.reply_token != 0;
	private_end = fds[0];
	memset(&ack, 0, sizeof(ack));
	ack.op = SVC_OP_REGISTER_LOOKUP;
	ack.status = 0;
	ack.magic = SVC_REGISTER_LOOKUP_MAGIC;
	r->ack_send = send_msg(private_end, &ack, sizeof(ack), NULL, 0, 0);
	/* 3. The lookup itself, answered with a session of our own. */
	pd = -1;
	memset(&lookup, 0, sizeof(lookup));
	r->lookup_recv = recv_wait(private_end, &lookup, sizeof(lookup), &pd,
	    1, &ra);
	if (r->lookup_recv != 0)
		goto out;
	if (pd >= 0)
		(void)close(pd);
	r->lookup_op = lookup.op;
	strlcpy(r->lookup_name, lookup.name, sizeof(r->lookup_name));
	if (mac_capability_channel_create(session) == -1) {
		r->reply_send = errno;
		goto out;
	}
	memset(&reply, 0, sizeof(reply));
	reply.status = 0;
	r->reply_send = send_msg(private_end, &reply, sizeof(reply),
	    &session[0], 1, ra.message.reply_token);
	(void)close(session[0]);
	/* 4. The helper uses the session it was given. */
	if (r->reply_send == 0)
		r->session_recv = recv_wait(session[1], r->session,
		    sizeof(r->session) - 1, NULL, 0, NULL);
out:
	(void)waitpid(r->child, &r->child_status, 0);
}

ATF_TC(parent_route_receives_child_lookups);
ATF_TC_HEAD(parent_route_receives_child_lookups, tc)
{
	atf_tc_set_md_var(tc, "descr", "NR1: an unprivileged process makes "
	    "a channel with the ungated mac_capability_channel_create() "
	    "syscall, installs one end as its child's route (SET, fork, "
	    "exec) and receives on the other end what the child sends on "
	    "its MAC_CAP_PROCESS_GET descriptor and the child's libservice "
	    "lookup (REGISTER_LOOKUP, then LOOKUP on the private channel), "
	    "and its answer gives the child a working session");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(parent_route_receives_child_lookups, tc)
{
	struct nr1_arg arg;
	struct nr1_res r;

	helper_path(tc, "nested_supervisor_helper", arg.helper,
	    sizeof(arg.helper));
	unprivileged_ids(&arg.uid, &arg.gid);
	run_child(nr1_supervisor, &arg, &r, sizeof(r));

	printf("uid %u child %d tag \"%s\" from pid %d; register op %u "
	    "nfds %d; lookup op %u \"%s\"; session \"%s\"; status %#x\n",
	    r.uid, (int)r.child, r.tag, (int)r.tag_pid, r.reg_op,
	    r.reg_nfds, r.lookup_op, r.lookup_name, r.session,
	    r.child_status);
	ROW("drop to nobody", r.drop, 0);
	ATF_CHECK_MSG(r.uid != 0, "the supervisor runs as uid %u", r.uid);
	ROW("mac_capability_channel_create", r.create, 0);
	ROW("MAC_CAP_PROCESS_SET", r.set, 0);
	ATF_REQUIRE_MSG(r.child > 0, "fork failed");
	ROW("receive the GET descriptor's message", r.tag_recv, 0);
	ATF_CHECK_STREQ_MSG(NSH_NR1_TAG, r.tag, "far end received \"%s\"",
	    r.tag);
	ATF_CHECK_EQ_MSG(r.child, r.tag_pid, "the message came from pid %d, "
	    "the child is %d", (int)r.tag_pid, (int)r.child);
	ROW("tag carries no descriptor", r.tag_nfds, 0);
	ROW("receive the child's REGISTER_LOOKUP", r.reg_recv, 0);
	ROW("REGISTER_LOOKUP op", r.reg_op, SVC_OP_REGISTER_LOOKUP);
	ROW("REGISTER_LOOKUP carries the private end", r.reg_nfds, 1);
	ROW("REGISTER_LOOKUP is a request", r.reg_token, 1);
	ROW("ACK on the private end", r.ack_send, 0);
	ROW("receive the child's LOOKUP", r.lookup_recv, 0);
	ROW("LOOKUP op", r.lookup_op, SVC_OP_LOOKUP);
	ATF_CHECK_STREQ(NSH_NR1_NAME, r.lookup_name);
	ROW("reply with a session", r.reply_send, 0);
	ROW("receive on the session", r.session_recv, 0);
	ATF_CHECK_STREQ(NSH_NR1_SESSION, r.session);
	ATF_CHECK_MSG(WIFEXITED(r.child_status) &&
	    WEXITSTATUS(r.child_status) == 0, "helper status %#x (%s)",
	    r.child_status, nsh_exit_name(WIFEXITED(r.child_status) ?
	    WEXITSTATUS(r.child_status) : -1));
}

/*
 * NR4.  Open the device as root and as nobody; with the device held,
 * connect to the coalition service as root and as nobody.
 */
struct nr4_res {
	int	root_open, root_connect;
	int	unpriv_drop, unpriv_open;
	int	held_drop, held_connect;
};

static int
connect_service(int dev, const char *name)
{
	struct mac_capability_connect_args ca;

	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, name, sizeof(ca.name));
	if (ioctl(dev, MAC_CAPABILITY_CONNECT, &ca) == -1)
		return (errno);
	(void)close(ca.fd);
	return (0);
}

struct nr4_arg {
	uid_t	uid;
	gid_t	gid;
};

static void
nr4_rows(const void *argp, void *resp)
{
	const struct nr4_arg *ids = argp;
	struct nr4_res *r = resp;
	pid_t pid;
	int dev, p[2], status, v[2];

	r->root_connect = r->held_drop = r->held_connect = NA;
	dev = open(NSH_DEVICE, O_RDWR | O_CLOEXEC);
	r->root_open = ERRNO_OF(dev);
	if (dev >= 0)
		r->root_connect = connect_service(dev, "coalition");

	/* A process that is nobody from the start. */
	if (pipe(p) == -1)
		return;
	pid = fork();
	if (pid == 0) {
		int fd;

		v[0] = drop_to(ids->uid, ids->gid);
		fd = open(NSH_DEVICE, O_RDWR | O_CLOEXEC);
		v[1] = v[0] != 0 ? NA : ERRNO_OF(fd);
		_exit(write(p[1], v, sizeof(v)) == sizeof(v) ? 0 : 70);
	}
	(void)close(p[1]);
	if (pid > 0 && read(p[0], v, sizeof(v)) == sizeof(v)) {
		r->unpriv_drop = v[0];
		r->unpriv_open = v[1];
	}
	(void)close(p[0]);
	if (pid > 0)
		(void)waitpid(pid, &status, 0);

	/* A process that holds root's device descriptor, then is nobody. */
	if (dev < 0 || pipe(p) == -1)
		return;
	pid = fork();
	if (pid == 0) {
		v[0] = drop_to(ids->uid, ids->gid);
		v[1] = v[0] != 0 ? NA : connect_service(dev, "coalition");
		_exit(write(p[1], v, sizeof(v)) == sizeof(v) ? 0 : 70);
	}
	(void)close(p[1]);
	if (pid > 0 && read(p[0], v, sizeof(v)) == sizeof(v)) {
		r->held_drop = v[0];
		r->held_connect = v[1];
	}
	(void)close(p[0]);
	if (pid > 0)
		(void)waitpid(pid, &status, 0);
	(void)close(dev);
}

ATF_TC(coalition_needs_device);
ATF_TC_HEAD(coalition_needs_device, tc)
{
	atf_tc_set_md_var(tc, "descr", "NR4: the coalition service is "
	    "reached only through /dev/mac_capability.  An unprivileged "
	    "open is EACCES on every tier; root is refused too (EACCES) "
	    "when the isolation policy enforces Capsule's claim on the "
	    "device (plane on, kern.mac_capability_isolation.enforce=1) and "
	    "opens it elsewhere; a held device descriptor connects to "
	    "\"coalition\" for root and for nobody alike, because "
	    "coalition_connect() reads no credentials");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(coalition_needs_device, tc)
{
	struct nr4_arg ids;
	struct nr4_res r;
	size_t len;
	int enforce, want_root;
	bool claimed, plane;

	len = sizeof(enforce);
	ATF_REQUIRE_MSG(sysctlbyname("kern.mac_capability_isolation.enforce",
	    &enforce, &len, NULL, 0) == 0,
	    "kern.mac_capability_isolation.enforce: %s", strerror(errno));
	plane = plane_is_on();
	/* Capsule claims the device at plane start; nothing else does. */
	claimed = plane && enforce != 0;
	want_root = claimed ? EACCES : 0;
	unprivileged_ids(&ids.uid, &ids.gid);
	memset(&r, 0, sizeof(r));
	run_child(nr4_rows, &ids, &r, sizeof(r));

	printf("tier: plane %s, enforce %d: root open %d connect %d; nobody "
	    "open %d; held descriptor as nobody connect %d\n",
	    plane ? "on" : "off", enforce, r.root_open, r.root_connect,
	    r.unpriv_open, r.held_connect);
	ROW("drop to nobody", r.unpriv_drop, 0);
	ROW("unprivileged open(/dev/mac_capability)", r.unpriv_open, EACCES);
	ROW("root open(/dev/mac_capability)", r.root_open, want_root);
	if (claimed) {
		ROW("root connect (not reached)", r.root_connect, NA);
		return;
	}
	ROW("root MAC_CAPABILITY_CONNECT coalition", r.root_connect, 0);
	ROW("drop to nobody with the device held", r.held_drop, 0);
	ROW("nobody MAC_CAPABILITY_CONNECT coalition on a held device",
	    r.held_connect, 0);
}

/*
 * NR6.  Install a route of the process's own, clear it, and look at what
 * is left: nothing, for the process, its fork child and an exec'd program.
 */
struct nr6_res {
	int		info0_err, present0;
	int		create, set, info1_err, present1;
	uint64_t	generation1;
	int		clear, info2_err, present2;
	uint64_t	generation2;
	int		get, open_notify;
	int		fork_info_err, fork_present, fork_get;
	int		exec_status;
};

static void
nr6_rows(const void *argp, void *resp)
{
	const char *helper = argp;
	struct mac_cap_process_info info;
	struct nr6_res *r = resp;
	pid_t pid;
	int fd, p[2], pair[2], v[3];

	memset(r, 0, sizeof(*r));
	r->exec_status = -1;
	r->fork_info_err = r->fork_present = r->fork_get = NA;
	memset(&info, 0, sizeof(info));
	r->info0_err = ERRNO_OF(cap_process(MAC_CAP_PROCESS_INFO, -1, 0,
	    &info));
	r->present0 = (int)info.present;
	r->create = ERRNO_OF(mac_capability_channel_create(pair));
	if (r->create != 0)
		return;
	r->set = ERRNO_OF(cap_process(MAC_CAP_PROCESS_SET, pair[0], getuid(),
	    NULL));
	memset(&info, 0, sizeof(info));
	r->info1_err = ERRNO_OF(cap_process(MAC_CAP_PROCESS_INFO, -1, 0,
	    &info));
	r->present1 = (int)info.present;
	r->generation1 = info.generation;
	(void)close(pair[0]);
	(void)close(pair[1]);

	r->clear = ERRNO_OF(cap_process(MAC_CAP_PROCESS_CLEAR, -1, 0, NULL));
	memset(&info, 0, sizeof(info));
	r->info2_err = ERRNO_OF(cap_process(MAC_CAP_PROCESS_INFO, -1, 0,
	    &info));
	r->present2 = (int)info.present;
	r->generation2 = info.generation;
	fd = cap_process(MAC_CAP_PROCESS_GET, -1, 0, NULL);
	r->get = ERRNO_OF(fd);
	if (fd >= 0)
		(void)close(fd);
	fd = -1;
	r->open_notify = ERRNO_OF(service_open("system.Notify", &fd));
	if (fd >= 0)
		(void)close(fd);

	if (pipe(p) == -1)
		return;
	pid = fork();
	if (pid == 0) {
		memset(&info, 0, sizeof(info));
		v[0] = ERRNO_OF(cap_process(MAC_CAP_PROCESS_INFO, -1, 0,
		    &info));
		v[1] = (int)info.present;
		v[2] = ERRNO_OF(cap_process(MAC_CAP_PROCESS_GET, -1, 0, NULL));
		_exit(write(p[1], v, sizeof(v)) == sizeof(v) ? 0 : 70);
	}
	(void)close(p[1]);
	if (pid > 0 && read(p[0], v, sizeof(v)) == sizeof(v)) {
		r->fork_info_err = v[0];
		r->fork_present = v[1];
		r->fork_get = v[2];
	}
	(void)close(p[0]);
	if (pid > 0)
		(void)waitpid(pid, NULL, 0);

	pid = fork();
	if (pid == 0) {
		execl(helper, helper, NSH_MODE_NOROUTE, (char *)NULL);
		_exit(NSH_EXIT_EXEC);
	}
	if (pid > 0)
		(void)waitpid(pid, &r->exec_status, 0);
}

ATF_TC(clear_gives_no_route_on_dev);
ATF_TC_HEAD(clear_gives_no_route_on_dev, tc)
{
	atf_tc_set_md_var(tc, "descr", "NR6: on dev MAC_CAP_PROCESS_CLEAR "
	    "means \"no route\": INFO reports no route (generation advanced), "
	    "GET is ENOENT and service_open ENOENT, for the process, its "
	    "fork child and a program it execs; under the plane the system "
	    "route it inherited is not put back.  Channel S4a turns CLEAR "
	    "into \"reset to the default\" and inverts this case in its "
	    "own tests");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(clear_gives_no_route_on_dev, tc)
{
	char helper[PATH_MAX];
	struct nr6_res r;
	bool plane;

	helper_path(tc, "nested_supervisor_helper", helper, sizeof(helper));
	plane = plane_is_on();
	run_child(nr6_rows, helper, &r, sizeof(r));

	printf("plane %s: route at start %d; own route %d gen %ju; after "
	    "CLEAR %d gen %ju GET %d service_open %d; fork child %d GET %d; "
	    "exec status %#x\n", plane ? "on" : "off", r.present0,
	    r.present1, (uintmax_t)r.generation1, r.present2,
	    (uintmax_t)r.generation2, r.get, r.open_notify, r.fork_present,
	    r.fork_get, r.exec_status);
	ROW("INFO at start", r.info0_err, 0);
	/* Under the plane the test inherited SwitchBoard's system route. */
	if (plane)
		ROW("system route inherited under the plane", r.present0, 1);
	ROW("mac_capability_channel_create", r.create, 0);
	ROW("SET", r.set, 0);
	ROW("INFO after SET", r.info1_err, 0);
	ROW("route present after SET", r.present1, 1);
	ROW("CLEAR", r.clear, 0);
	ROW("INFO after CLEAR", r.info2_err, 0);
	ROW("route present after CLEAR", r.present2, 0);
	ATF_CHECK_EQ_MSG(r.generation1 + 1, r.generation2,
	    "CLEAR moved the generation from %ju to %ju",
	    (uintmax_t)r.generation1, (uintmax_t)r.generation2);
	ROW("GET after CLEAR", r.get, ENOENT);
	ROW("service_open(system.Notify) after CLEAR", r.open_notify,
	    ENOENT);
	ROW("fork child INFO", r.fork_info_err, 0);
	ROW("fork child route present", r.fork_present, 0);
	ROW("fork child GET", r.fork_get, ENOENT);
	ATF_CHECK_MSG(WIFEXITED(r.exec_status) &&
	    WEXITSTATUS(r.exec_status) == 0, "exec'd program: status %#x "
	    "(%s)", r.exec_status, nsh_exit_name(WIFEXITED(r.exec_status) ?
	    WEXITSTATUS(r.exec_status) : -1));
}

/*
 * NR8.  As NR1, but the child execs a set-uid root program from an
 * unprivileged supervisor, so the exec changes its effective uid and
 * marks it P_SUGID.  The program reports over the route it kept.
 */
struct nr8_res {
	int		drop, create, set, info_err;
	uid_t		uid;
	uint64_t	generation;
	pid_t		child;
	int		report_recv, report_nfds;
	pid_t		report_pid;
	struct nsh_setid_report report;
	int		child_status;
};

static void
nr8_supervisor(const void *argp, void *resp)
{
	const struct nr1_arg *arg = argp;
	struct mac_capability_recvmsg_v2_args ra;
	struct mac_cap_process_info info;
	struct nr8_res *r = resp;
	int pair[2];

	memset(r, 0, sizeof(*r));
	r->create = r->set = r->info_err = r->report_recv = NA;
	r->child_status = -1;
	r->drop = drop_to(arg->uid, arg->gid);
	r->uid = getuid();
	if (r->drop != 0)
		return;
	r->create = ERRNO_OF(mac_capability_channel_create(pair));
	if (r->create != 0)
		return;
	(void)fcntl(pair[0], F_SETFD, FD_CLOEXEC);
	(void)fcntl(pair[1], F_SETFD, FD_CLOEXEC);
	r->set = ERRNO_OF(cap_process(MAC_CAP_PROCESS_SET, pair[0], getuid(),
	    NULL));
	memset(&info, 0, sizeof(info));
	r->info_err = ERRNO_OF(cap_process(MAC_CAP_PROCESS_INFO, -1, 0,
	    &info));
	r->generation = info.generation;
	if (r->set != 0 || r->info_err != 0)
		return;
	r->child = fork();
	if (r->child == 0) {
		execl(arg->helper, arg->helper, (char *)NULL);
		_exit(NSH_EXIT_EXEC);
	}
	if (r->child == -1)
		return;
	(void)cap_process(MAC_CAP_PROCESS_CLEAR, -1, 0, NULL);
	(void)close(pair[0]);
	r->report_recv = recv_wait(pair[1], &r->report, sizeof(r->report),
	    NULL, 0, &ra);
	if (r->report_recv == 0) {
		r->report_nfds = (int)ra.message.nfds;
		r->report_pid = ra.process.pid;
		if (ra.message.payload_len != sizeof(r->report))
			r->report_recv = EMSGSIZE;
	}
	(void)waitpid(r->child, &r->child_status, 0);
}

ATF_TC(route_survives_setid_exec);
ATF_TC_HEAD(route_survives_setid_exec, tc)
{
	atf_tc_set_md_var(tc, "descr", "NR8: an unprivileged parent installs "
	    "a route of its own; its child execs a set-uid root program "
	    "(effective uid 0, issetugid 1).  The program still has the "
	    "route: MAC_CAP_PROCESS_INFO shows the parent's generation and "
	    "its GET descriptor reaches the parent's far end (owner "
	    "question 4 keeps this)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(route_survives_setid_exec, tc)
{
	struct nr1_arg arg;
	struct nr8_res r;
	struct stat sb;

	helper_path(tc, "nested_supervisor_setid", arg.helper,
	    sizeof(arg.helper));
	ATF_REQUIRE(stat(arg.helper, &sb) == 0);
	ATF_REQUIRE_MSG(sb.st_uid == 0 && (sb.st_mode & S_ISUID) != 0,
	    "%s is not set-uid root (mode %o, uid %u)", arg.helper,
	    (unsigned)sb.st_mode, (unsigned)sb.st_uid);
	unprivileged_ids(&arg.uid, &arg.gid);
	run_child(nr8_supervisor, &arg, &r, sizeof(r));

	printf("supervisor uid %u gen %ju; program pid %d: issetugid %d "
	    "ruid %u euid %u present %u gen %ju GET %d; status %#x\n",
	    r.uid, (uintmax_t)r.generation, (int)r.report_pid,
	    r.report.issetugid, r.report.ruid, r.report.euid,
	    r.report.present, (uintmax_t)r.report.generation,
	    r.report.get_err, r.child_status);
	ROW("drop to nobody", r.drop, 0);
	ROW("mac_capability_channel_create", r.create, 0);
	ROW("SET", r.set, 0);
	ROW("INFO", r.info_err, 0);
	ROW("receive the set-id program's report on the far end",
	    r.report_recv, 0);
	ATF_REQUIRE_MSG(r.report_recv == 0, "no report: status %#x (%s)",
	    r.child_status, nsh_exit_name(WIFEXITED(r.child_status) ?
	    WEXITSTATUS(r.child_status) : -1));
	ATF_CHECK_EQ_MSG(r.child, r.report_pid, "report from pid %d, the "
	    "child is %d", (int)r.report_pid, (int)r.child);
	/* The exec really was set-id. */
	ROW("issetugid() in the program", r.report.issetugid, 1);
	ROW("effective uid", r.report.euid, 0);
	ROW("real uid", r.report.ruid, r.uid);
	ROW("program INFO", r.report.info_err, 0);
	ROW("route present after the set-id exec", r.report.present, 1);
	ATF_CHECK_EQ_MSG(r.generation, r.report.generation,
	    "generation %ju after the exec, the parent installed %ju",
	    (uintmax_t)r.report.generation, (uintmax_t)r.generation);
	ROW("program GET", r.report.get_err, 0);
	ROW("report carries no descriptor", r.report_nfds, 0);
	ATF_CHECK_MSG(WIFEXITED(r.child_status) &&
	    WEXITSTATUS(r.child_status) == 0, "program status %#x",
	    r.child_status);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, parent_route_receives_child_lookups);
	ATF_TP_ADD_TC(tp, coalition_needs_device);
	ATF_TP_ADD_TC(tp, clear_gives_no_route_on_dev);
	ATF_TP_ADD_TC(tp, route_survives_setid_exec);
	return (atf_no_error());
}
