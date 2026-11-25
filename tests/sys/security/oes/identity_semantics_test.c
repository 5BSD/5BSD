/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * T0a pins (kernel-identity-and-coalitions.md, section 2.4) of the two OES
 * identities, through what a client observes, so the cases pass on dev
 * (ept_genid from the start time, ep_exec_id from the credential nonce) and
 * after T1 (the process's uniqueid and image id):
 *
 *  - the execution id is shared by a fork child and changes at exec, while
 *    the process token tells the child from its parent;
 *  - a reader of a client is one process in one execution: its fork child
 *    is not a reader, its next execution is not either;
 *  - a process mute names one process: a reused pid is not muted, and a
 *    token whose generation is not the live process's is refused (ESRCH),
 *    so a computed generation buys nothing.
 *
 * Every count waits for a fence: an open of a marker file by a process that
 * no case mutes and that reads no client.  Events reach a client in order,
 * so once the fence's arrives every earlier one has.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

#define	PID_MAX_SAVED	"pid_max.saved"
/* The lowest kern.pid_max the kernel accepts (sysctl_kern_pid_max()). */
#define	LOW_PID_MAX	300

struct paths {
	char	probe[PATH_MAX];
	char	marker[PATH_MAX];
	struct stat probe_sb;
};

static void
paths_init(struct paths *p)
{

	ATF_REQUIRE(getcwd(p->probe, sizeof(p->probe)) != NULL);
	strlcpy(p->marker, p->probe, sizeof(p->marker));
	strlcat(p->probe, "/probe", sizeof(p->probe));
	strlcat(p->marker, "/marker", sizeof(p->marker));
	ATF_REQUIRE(close(open(p->probe, O_WRONLY | O_CREAT, 0644)) == 0);
	ATF_REQUIRE(close(open(p->marker, O_WRONLY | O_CREAT, 0644)) == 0);
	ATF_REQUIRE(stat(p->probe, &p->probe_sb) == 0);
}

static void
open_close(const char *path)
{
	int fd;

	fd = open(path, O_RDONLY);
	if (fd >= 0)
		close(fd);
}

/* A global NOTIFY_OPEN client. */
static int
open_client(void)
{
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_OPEN };
	int fd;

	fd = test_open_oes();
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/oes: %s", strerror(errno));
	ATF_REQUIRE(test_set_mode(fd, OES_MODE_NOTIFY) == 0);
	ATF_REQUIRE(test_subscribe(fd, events, nitems(events),
	    OES_SUB_REPLACE) == 0);
	return (fd);
}

/* A child that opens path once released; its pid and gate. */
static pid_t
fence_child(const char *path, int *gate)
{
	int p[2];
	pid_t pid;
	char c;

	ATF_REQUIRE(pipe(p) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(p[1]);
		if (read(p[0], &c, 1) != 1)
			_exit(1);
		open_close(path);
		_exit(0);
	}
	close(p[0]);
	*gate = p[1];
	return (pid);
}

static pid_t
start_fence(const struct paths *p)
{
	pid_t fence;
	int gate, status;

	fence = fence_child(p->marker, &gate);
	ATF_REQUIRE(write(gate, "g", 1) == 1);
	close(gate);
	ATF_REQUIRE(waitpid(fence, &status, 0) == fence);
	return (fence);
}

static bool
is_probe_open(const oes_message_t *msg, const struct paths *p)
{

	return (msg->em_event == OES_EVENT_NOTIFY_OPEN &&
	    msg->em_event_data.open.file.ef_ino ==
	    (uint64_t)p->probe_sb.st_ino &&
	    msg->em_event_data.open.file.ef_dev ==
	    (uint64_t)p->probe_sb.st_dev);
}

/*
 * Collect, until fence's NOTIFY_OPEN, up to max probe opens by pid into
 * out (process records, in order); return how many arrived.
 */
static int
probe_opens_until_fence(int fd, const struct paths *p, pid_t pid,
    pid_t fence, oes_process_t *out, int max)
{
	test_msg_buf buf;
	oes_message_t *msg = &buf.msg;
	int n = 0;

	for (;;) {
		ATF_REQUIRE_MSG(test_wait_event(fd, msg, OES_TEST_DEADLINE_MS) ==
		    0, "no fence event within %d ms", OES_TEST_DEADLINE_MS);
		if (msg->em_event != OES_EVENT_NOTIFY_OPEN)
			continue;
		if (msg->em_process.ep_pid == fence)
			return (n);
		if (msg->em_process.ep_pid != pid || !is_probe_open(msg, p))
			continue;
		if (n < max)
			out[n] = msg->em_process;
		n++;
	}
}

/* The first probe open by pid (no fence: it must come). */
static void
first_probe_open(int fd, const struct paths *p, pid_t pid, oes_process_t *out)
{
	test_msg_buf buf;
	oes_message_t *msg = &buf.msg;

	for (;;) {
		ATF_REQUIRE_MSG(test_wait_event(fd, msg, OES_TEST_DEADLINE_MS) ==
		    0, "no open of the probe by %d within %d ms", (int)pid,
		    OES_TEST_DEADLINE_MS);
		if (msg->em_process.ep_pid == pid && is_probe_open(msg, p)) {
			*out = msg->em_process;
			return;
		}
	}
}

static void
send_fd(int sock, int fd)
{
	char cbuf[CMSG_SPACE(sizeof(int))], c = 'f';
	struct iovec iov = { .iov_base = &c, .iov_len = 1 };
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1,
	    .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
	struct cmsghdr *cm;

	memset(cbuf, 0, sizeof(cbuf));
	cm = CMSG_FIRSTHDR(&m);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &fd, sizeof(int));
	ATF_REQUIRE(sendmsg(sock, &m, 0) == 1);
}

static int
recv_fd(int sock)
{
	char cbuf[CMSG_SPACE(sizeof(int))], c;
	struct iovec iov = { .iov_base = &c, .iov_len = 1 };
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1,
	    .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
	struct cmsghdr *cm;
	int fd;

	if (recvmsg(sock, &m, 0) != 1)
		return (-1);
	cm = CMSG_FIRSTHDR(&m);
	if (cm == NULL || cm->cmsg_type != SCM_RIGHTS)
		return (-1);
	memcpy(&fd, CMSG_DATA(cm), sizeof(int));
	return (fd);
}

/* Exec cat(1) on probe with its output discarded; 100+ on failure. */
static int
exec_cat(const char *probe)
{
	char *const argv[] = { __DECONST(char *, "cat"),
	    __DECONST(char *, probe), NULL };
	int devnull;

	devnull = open("/dev/null", O_WRONLY);
	if (devnull < 0 || dup2(devnull, STDOUT_FILENO) < 0)
		return (110);
	execv("/bin/cat", argv);
	return (111);
}

/* ---------------------------------------------------------------- */

/*
 * X opens the probe, forks Y which opens it, then execs cat(1) on it; X
 * reports Y's pid on sock first.
 */
static int
exec_id_subject(int sock, int go, const char *probe)
{
	pid_t y;
	int status;
	char c;

	if (read(go, &c, 1) != 1)
		return (101);
	open_close(probe);
	y = fork();
	if (y < 0)
		return (102);
	if (y == 0) {
		open_close(probe);
		_exit(0);
	}
	if (waitpid(y, &status, 0) != y)
		return (103);
	if (write(sock, &y, sizeof(y)) != sizeof(y))
		return (104);
	return (exec_cat(probe));
}

ATF_TC(oes_exec_id_fork_shared);
ATF_TC_HEAD(oes_exec_id_fork_shared, tc)
{
	atf_tc_set_md_var(tc, "descr", "A fork child's events carry its "
	    "parent's execution id (non-zero) and another process token; the "
	    "parent's next execution carries a new execution id and the same "
	    "process token");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(oes_exec_id_fork_shared, tc)
{
	struct paths p;
	oes_process_t x[2], y[1];
	pid_t xpid, ypid, fence;
	int fd, go[2], sv[2], status;

	paths_init(&p);
	fd = open_client();
	ATF_REQUIRE(pipe(go) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	xpid = fork();
	ATF_REQUIRE(xpid >= 0);
	if (xpid == 0) {
		close(go[1]);
		close(sv[0]);
		_exit(exec_id_subject(sv[1], go[0], p.probe));
	}
	close(go[0]);
	close(sv[1]);
	ATF_REQUIRE(write(go[1], "g", 1) == 1);
	ATF_REQUIRE(read(sv[0], &ypid, sizeof(ypid)) == sizeof(ypid));
	ATF_REQUIRE(waitpid(xpid, &status, 0) == xpid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "subject status %#x", status);
	fence = start_fence(&p);

	/* One pass: X and Y interleave in the stream. */
	{
		test_msg_buf buf;
		oes_message_t *msg = &buf.msg;
		int nx = 0, ny = 0;

		for (;;) {
			ATF_REQUIRE_MSG(test_wait_event(fd, msg,
			    OES_TEST_DEADLINE_MS) == 0,
			    "no fence event within %d ms",
			    OES_TEST_DEADLINE_MS);
			if (msg->em_event != OES_EVENT_NOTIFY_OPEN)
				continue;
			if (msg->em_process.ep_pid == fence)
				break;
			if (!is_probe_open(msg, &p))
				continue;
			if (msg->em_process.ep_pid == xpid && nx < 2)
				x[nx++] = msg->em_process;
			else if (msg->em_process.ep_pid == ypid && ny < 1)
				y[ny++] = msg->em_process;
		}
		ATF_REQUIRE_EQ_MSG(2, nx, "%d probe opens by the parent", nx);
		ATF_REQUIRE_EQ_MSG(1, ny, "%d probe opens by the child", ny);
	}
	ATF_CHECK(x[0].ep_exec_id != 0);
	/* Fork: same execution, another process. */
	ATF_CHECK_EQ(x[0].ep_exec_id, y[0].ep_exec_id);
	ATF_CHECK(x[0].ep_token.ept_genid != y[0].ep_token.ept_genid);
	ATF_CHECK_EQ((uint64_t)ypid, y[0].ep_token.ept_id);
	/* Exec: same process, another execution. */
	ATF_CHECK(x[1].ep_exec_id != 0);
	ATF_CHECK(x[1].ep_exec_id != x[0].ep_exec_id);
	ATF_CHECK_EQ(x[0].ep_token.ept_genid, x[1].ep_token.ept_genid);
	close(sv[0]);
	close(go[1]);
	close(fd);
}

/*
 * R receives the client and joins it, opens the probe (hidden: R is a
 * reader), forks K which opens it (K reads nothing), reports K's pid, then
 * execs cat(1) on the probe (the new execution reads nothing either).
 */
static int
reader_subject(int sock, const char *probe)
{
	pid_t k;
	int client, status;

	client = recv_fd(sock);
	if (client < 0)
		return (101);
	if (ioctl(client, OES_IOC_JOIN) != 0)
		return (102);
	open_close(probe);
	k = fork();
	if (k < 0)
		return (103);
	if (k == 0) {
		open_close(probe);
		_exit(0);
	}
	if (waitpid(k, &status, 0) != k)
		return (104);
	if (write(sock, &k, sizeof(k)) != sizeof(k))
		return (105);
	return (exec_cat(probe));
}

ATF_TC(oes_reader_set_exec);
ATF_TC_HEAD(oes_reader_set_exec, tc)
{
	atf_tc_set_md_var(tc, "descr", "A reader of a client is one process "
	    "in one execution: its own opens are hidden from the client, its "
	    "fork child's (same execution) and its next execution's are "
	    "delivered");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(oes_reader_set_exec, tc)
{
	struct paths p;
	test_msg_buf buf;
	oes_message_t *msg = &buf.msg;
	pid_t rpid, kpid, fence;
	int fd, sv[2], status, nr, nk, ncat;

	paths_init(&p);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	rpid = fork();
	ATF_REQUIRE(rpid >= 0);
	if (rpid == 0) {
		close(sv[0]);
		_exit(reader_subject(sv[1], p.probe));
	}
	close(sv[1]);
	fd = open_client();
	send_fd(sv[0], fd);
	ATF_REQUIRE(read(sv[0], &kpid, sizeof(kpid)) == sizeof(kpid));
	ATF_REQUIRE(waitpid(rpid, &status, 0) == rpid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "reader status %#x", status);
	fence = start_fence(&p);

	nr = nk = ncat = 0;
	for (;;) {
		ATF_REQUIRE_MSG(test_wait_event(fd, msg, OES_TEST_DEADLINE_MS) ==
		    0, "no fence event within %d ms", OES_TEST_DEADLINE_MS);
		if (msg->em_event != OES_EVENT_NOTIFY_OPEN)
			continue;
		if (msg->em_process.ep_pid == fence)
			break;
		if (!is_probe_open(msg, &p))
			continue;
		if (msg->em_process.ep_pid == rpid) {
			nr++;
			if (strcmp(oes_msg_string(msg,
			    msg->em_process.ep_path_off), "/bin/cat") == 0)
				ncat++;
		} else if (msg->em_process.ep_pid == kpid)
			nk++;
	}
	ATF_CHECK_EQ_MSG(1, nk, "%d opens by the reader's fork child", nk);
	/* Only the open of the reader's next execution arrives. */
	ATF_CHECK_EQ_MSG(1, nr, "%d opens by the reader", nr);
	ATF_CHECK_EQ_MSG(nr, ncat, "%d of the reader's opens came from an "
	    "image other than /bin/cat", nr - ncat);
	close(sv[0]);
	close(fd);
}

/* ---------------------------------------------------------------- */

static int
read_int_sysctl(const char *name)
{
	size_t len;
	int v;

	len = sizeof(v);
	ATF_REQUIRE_MSG(sysctlbyname(name, &v, &len, NULL, 0) == 0, "%s: %s",
	    name, strerror(errno));
	return (v);
}

static void
write_int_sysctl(const char *name, int v)
{

	ATF_REQUIRE_MSG(sysctlbyname(name, NULL, NULL, &v, sizeof(v)) == 0,
	    "%s=%d: %s", name, v, strerror(errno));
}

static int
mute_token(int fd, pid_t pid, uint64_t genid)
{
	struct oes_mute_args args;

	memset(&args, 0, sizeof(args));
	args.emu_token.ept_id = (uint64_t)pid;
	args.emu_token.ept_genid = genid;
	return (ioctl(fd, OES_IOC_MUTE_PROCESS, &args) == 0 ? 0 : errno);
}

/* A process that opens probe once per byte on go until go closes. */
static pid_t
opener(const char *probe, int *go)
{
	int p[2];
	pid_t pid;
	char c;

	ATF_REQUIRE(pipe(p) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(p[1]);
		while (read(p[0], &c, 1) == 1)
			open_close(probe);
		_exit(0);
	}
	close(p[0]);
	*go = p[1];
	return (pid);
}

ATF_TC_WITH_CLEANUP(oes_mute_pid_reuse);
ATF_TC_HEAD(oes_mute_pid_reuse, tc)
{
	atf_tc_set_md_var(tc, "descr", "A process mute names one process: "
	    "its opens are muted, a computed generation is refused (ESRCH), "
	    "and a later process that reuses its pid is not muted");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(oes_mute_pid_reuse, tc)
{
	struct paths p;
	oes_process_t xp, yp[1];
	pid_t x, y, fence;
	FILE *f;
	int fd, go, old, status, tries, n;

	paths_init(&p);
	/* A random pid allocator would make reuse a matter of luck. */
	ATF_REQUIRE_EQ_MSG(0, read_int_sysctl("kern.randompid"),
	    "kern.randompid is set: pid reuse cannot be driven");
	old = read_int_sysctl("kern.pid_max");
	f = fopen(PID_MAX_SAVED, "w");
	ATF_REQUIRE(f != NULL && fprintf(f, "%d\n", old) > 0 &&
	    fclose(f) == 0);
	write_int_sysctl("kern.pid_max", LOW_PID_MAX);

	fd = open_client();
	x = opener(p.probe, &go);
	ATF_REQUIRE(write(go, "o", 1) == 1);
	first_probe_open(fd, &p, x, &xp);
	ATF_REQUIRE_EQ((uint64_t)x, xp.ep_token.ept_id);
	ATF_REQUIRE(xp.ep_token.ept_genid != 0);

	/* The generation next to the live one names no process. */
	ATF_CHECK_EQ(ESRCH, mute_token(fd, x, xp.ep_token.ept_genid + 1));
	ATF_CHECK_EQ(ESRCH, mute_token(fd, x, xp.ep_token.ept_genid - 1));
	ATF_REQUIRE_EQ(0, mute_token(fd, x, xp.ep_token.ept_genid));

	/* Muted: X's next open does not arrive before the fence. */
	ATF_REQUIRE(write(go, "o", 1) == 1);
	close(go);
	/* X is a zombie until reaped below, so the fence cannot take its pid. */
	fence = start_fence(&p);
	n = probe_opens_until_fence(fd, &p, x, fence, yp, nitems(yp));
	ATF_CHECK_EQ_MSG(0, n, "%d opens by the muted process", n);
	ATF_REQUIRE_EQ(x, waitpid(x, &status, 0));

	/*
	 * Fork until a process gets X's pid.  Each fork moves the allocator
	 * on; a pid nobody holds comes round again within one pass over the
	 * pid space, so two passes without it mean something else holds it.
	 */
	y = -1;
	for (tries = 0; tries < 2 * LOW_PID_MAX; tries++) {
		y = opener(p.probe, &go);
		if (y == x)
			break;
		close(go);
		ATF_REQUIRE_EQ(y, waitpid(y, &status, 0));
	}
	ATF_REQUIRE_EQ_MSG(x, y, "pid %d was not reused in %d forks", (int)x,
	    tries);
	ATF_REQUIRE(write(go, "o", 1) == 1);
	close(go);
	fence = start_fence(&p);
	n = probe_opens_until_fence(fd, &p, y, fence, yp, nitems(yp));
	ATF_REQUIRE_EQ(y, waitpid(y, &status, 0));
	ATF_CHECK_EQ_MSG(1, n, "%d opens by the process that reused the "
	    "muted pid", n);
	if (n == 1)
		ATF_CHECK(yp[0].ep_token.ept_genid != xp.ep_token.ept_genid);

	write_int_sysctl("kern.pid_max", old);
	close(fd);
}
ATF_TC_CLEANUP(oes_mute_pid_reuse, tc)
{
	FILE *f;
	int old;

	f = fopen(PID_MAX_SAVED, "r");
	if (f == NULL)
		return;
	if (fscanf(f, "%d", &old) == 1)
		(void)sysctlbyname("kern.pid_max", NULL, NULL, &old,
		    sizeof(old));
	fclose(f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, oes_exec_id_fork_shared);
	ATF_TP_ADD_TC(tp, oes_reader_set_exec);
	ATF_TP_ADD_TC(tp, oes_mute_pid_reuse);

	return (atf_no_error());
}
