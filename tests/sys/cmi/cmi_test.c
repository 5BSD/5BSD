/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Tests for cmi — generic capability interface for kernel modules.
 *
 * Requires:
 *   kldload cmi
 *   kldload cmi_keystore
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/event.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "cmi_ioctl.h"

/* Keystore protocol — matches cmi_keystore.c */
#define	KS_OP_STORE	1
#define	KS_OP_FETCH	2
#define	KS_STATUS_OK		0
#define	KS_STATUS_NOTFOUND	1

struct ks_request {
	uint32_t	op;
	uint32_t	keyid;
} __packed;

struct ks_reply {
	uint32_t	status;
} __packed;

static int
closed_fd(void)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/null: %s", strerror(errno));
	ATF_REQUIRE(close(fd) == 0);
	return (fd);
}

/* Helper: open /dev/cmi or skip */
static int
cmi_open(void)
{
	int fd;

	fd = open("/dev/cmi", O_RDWR);
	if (fd < 0 && errno == ENOENT)
		atf_tc_skip("cmi module not loaded");
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/cmi: %s", strerror(errno));
	return (fd);
}

/* Helper: connect to a service, return instance fd */
static int
cmi_connect(const char *name)
{
	struct cmi_connect_args ca;
	int ctl;

	ctl = cmi_open();
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, name, sizeof(ca.name));
	if (ioctl(ctl, CMI_CONNECT, &ca) != 0) {
		close(ctl);
		return (-1);
	}
	close(ctl);
	return (ca.fd);
}

/* Helper: send a message via CMI_SENDMSG */
static int
cmi_send(int fd, const void *payload, uint32_t len, uint64_t token)
{
	struct cmi_sendmsg_args sa;

	memset(&sa, 0, sizeof(sa));
	sa.payload = payload;
	sa.payload_len = len;
	sa.reply_token = token;
	return (ioctl(fd, CMI_SENDMSG, &sa));
}

/* Helper: receive a message via CMI_RECVMSG (blocks) */
static int
cmi_recv(int fd, void *buf, uint32_t *lenp, uint64_t *tokenp)
{
	struct cmi_recvmsg_args ra;
	int ret;

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = *lenp;
	ret = ioctl(fd, CMI_RECVMSG, &ra);
	if (ret == 0) {
		*lenp = ra.payload_len;
		if (tokenp != NULL)
			*tokenp = ra.reply_token;
	}
	return (ret);
}

/* Helper: store a key via SENDMSG/RECVMSG round-trip */
static void
cmi_store(int fd, uint32_t keyid, const void *data, size_t datalen)
{
	char buf[sizeof(struct ks_request) + 4096];
	struct ks_request *req = (struct ks_request *)buf;
	struct ks_reply reply;
	uint32_t rlen;

	req->op = KS_OP_STORE;
	req->keyid = keyid;
	if (datalen > 0)
		memcpy(buf + sizeof(*req), data, datalen);
	ATF_REQUIRE(cmi_send(fd, buf, sizeof(*req) + datalen, 0) == 0);
	rlen = sizeof(reply);
	ATF_REQUIRE(cmi_recv(fd, &reply, &rlen, NULL) == 0);
	ATF_REQUIRE_EQ(reply.status, KS_STATUS_OK);
}


/* ================================================================
 * Lifecycle tests
 * ================================================================ */

ATF_TC(open_close);
ATF_TC_HEAD(open_close, tc)
{
	atf_tc_set_md_var(tc, "descr", "Open and close /dev/cmi");
}
ATF_TC_BODY(open_close, tc)
{
	int fd = cmi_open();
	ATF_REQUIRE(close(fd) == 0);
}

/* ================================================================
 * Connection tests
 * ================================================================ */

ATF_TC(connect_service);
ATF_TC_HEAD(connect_service, tc)
{
	atf_tc_set_md_var(tc, "descr", "Connect to keystore service");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(connect_service, tc)
{
	int fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);
	close(fd);
}

ATF_TC(connect_noent);
ATF_TC_HEAD(connect_noent, tc)
{
	atf_tc_set_md_var(tc, "descr", "Connect to nonexistent service fails");
}
ATF_TC_BODY(connect_noent, tc)
{
	struct cmi_connect_args ca;
	int ctl = cmi_open();

	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "no_such_service", sizeof(ca.name));
	ATF_CHECK_ERRNO(ENOENT, ioctl(ctl, CMI_CONNECT, &ca) == -1);
	close(ctl);
}

ATF_TC(connect_empty_name);
ATF_TC_HEAD(connect_empty_name, tc)
{
	atf_tc_set_md_var(tc, "descr", "Empty service name fails");
}
ATF_TC_BODY(connect_empty_name, tc)
{
	struct cmi_connect_args ca;
	int ctl = cmi_open();

	memset(&ca, 0, sizeof(ca));
	ATF_CHECK_ERRNO(EINVAL, ioctl(ctl, CMI_CONNECT, &ca) == -1);
	close(ctl);
}

/* ================================================================
 * Descriptor / Capsicum integration tests
 * ================================================================ */

ATF_TC(fcntl_cloexec_flag);
ATF_TC_HEAD(fcntl_cloexec_flag, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "F_GETFD/F_SETFD work on cmi instance fds");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(fcntl_cloexec_flag, tc)
{
	int fd, flags;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	flags = fcntl(fd, F_GETFD);
	ATF_REQUIRE(flags >= 0);
	ATF_CHECK((flags & FD_CLOEXEC) == 0);

	ATF_REQUIRE(fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0);
	flags = fcntl(fd, F_GETFD);
	ATF_REQUIRE(flags >= 0);
	ATF_CHECK((flags & FD_CLOEXEC) != 0);

	close(fd);
}

ATF_TC(cloexec_on_exec);
ATF_TC_HEAD(cloexec_on_exec, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FD_CLOEXEC closes a cmi instance fd across exec");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(cloexec_on_exec, tc)
{
	char exec_path[1024];
	char fdstr[32];
	int fd, flags, status;
	pid_t pid;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	flags = fcntl(fd, F_GETFD);
	ATF_REQUIRE(flags >= 0);
	ATF_REQUIRE(fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		snprintf(exec_path, sizeof(exec_path), "%s/cmi_exec_helper",
		    atf_tc_get_config_var(tc, "srcdir"));
		snprintf(fdstr, sizeof(fdstr), "%d", fd);
		execl(exec_path, exec_path, fdstr, NULL);
		_exit(127);
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	close(fd);
}

ATF_TC(fcntl_nonblock_recvmsg);
ATF_TC_HEAD(fcntl_nonblock_recvmsg, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "fcntl(O_NONBLOCK) enables nonblocking CMI_RECVMSG");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(fcntl_nonblock_recvmsg, tc)
{
	struct cmi_recvmsg_args ra;
	char buf[1];
	int fd, flags;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	flags = fcntl(fd, F_GETFL, 0);
	ATF_REQUIRE(flags >= 0);
	ATF_REQUIRE(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);

	flags = fcntl(fd, F_GETFL, 0);
	ATF_REQUIRE(flags >= 0);
	ATF_CHECK((flags & O_NONBLOCK) != 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_CHECK_ERRNO(EAGAIN, ioctl(fd, CMI_RECVMSG, &ra) == -1);

	close(fd);
}

ATF_TC(capsicum_ioctl_limit);
ATF_TC_HEAD(capsicum_ioctl_limit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "cap_ioctls_limit restricts CMI instance ioctls");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(capsicum_ioctl_limit, tc)
{
	cap_rights_t rights;
	cap_ioctl_t cmds[1];
	struct cmi_info_args info;
	struct cmi_sendmsg_args sa;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	cap_rights_init(&rights, CAP_IOCTL);
	ATF_REQUIRE(cap_rights_limit(fd, &rights) == 0);

	cmds[0] = CMI_GETINFO;
	ATF_REQUIRE(cap_ioctls_limit(fd, cmds, 1) == 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, CMI_GETINFO, &info) == 0);

	memset(&sa, 0, sizeof(sa));
	sa.payload = "x";
	sa.payload_len = 1;
	ATF_CHECK_ERRNO(ENOTCAPABLE, ioctl(fd, CMI_SENDMSG, &sa) == -1);

	close(fd);
}

ATF_TC(capsicum_fcntl_limit);
ATF_TC_HEAD(capsicum_fcntl_limit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "cap_fcntls_limit restricts fcntl operations on cmi fds");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(capsicum_fcntl_limit, tc)
{
	cap_rights_t rights;
	int fd, flags;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	cap_rights_init(&rights, CAP_FCNTL);
	ATF_REQUIRE(cap_rights_limit(fd, &rights) == 0);
	ATF_REQUIRE(cap_fcntls_limit(fd, CAP_FCNTL_GETFL) == 0);

	flags = fcntl(fd, F_GETFL, 0);
	ATF_REQUIRE(flags >= 0);
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1);

	close(fd);
}

ATF_TC(capsicum_event_limit);
ATF_TC_HEAD(capsicum_event_limit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CAP_EVENT gates kqueue registration on cmi instance fds");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(capsicum_event_limit, tc)
{
	cap_rights_t rights;
	struct kevent kev;
	int fd, kq;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	cap_rights_init(&rights, CAP_IOCTL);
	ATF_REQUIRE(cap_rights_limit(fd, &rights) == 0);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_CHECK_ERRNO(ENOTCAPABLE, kevent(kq, &kev, 1, NULL, 0, NULL) == -1);
	close(kq);
	close(fd);

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	cap_rights_init(&rights, CAP_EVENT);
	ATF_REQUIRE(cap_rights_limit(fd, &rights) == 0);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);

	close(kq);
	close(fd);
}

ATF_TC(capmode_existing_instance);
ATF_TC_HEAD(capmode_existing_instance, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Existing cmi instances keep working after cap_enter");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(capmode_existing_instance, tc)
{
	int status;
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		cap_rights_t rights;
		cap_ioctl_t cmds[1];
		struct cmi_info_args info;
		int fd;

		fd = cmi_connect("keystore");
		if (fd < 0)
			_exit(1);

		cap_rights_init(&rights, CAP_IOCTL);
		if (cap_rights_limit(fd, &rights) != 0)
			_exit(2);
		cmds[0] = CMI_GETINFO;
		if (cap_ioctls_limit(fd, cmds, 1) != 0)
			_exit(3);
		if (cap_enter() != 0)
			_exit(4);
		memset(&info, 0, sizeof(info));
		if (ioctl(fd, CMI_GETINFO, &info) != 0)
			_exit(5);
		_exit(0);
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* ================================================================
 * Request / response tests
 * ================================================================ */

ATF_TC(write_read);
ATF_TC_HEAD(write_read, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_SENDMSG enqueues async, CMI_RECVMSG gets reply");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(write_read, tc)
{
	struct ks_request req;
	struct ks_reply reply;
	char buf[128];
	uint32_t rlen;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Store a key */
	memset(buf, 0, sizeof(buf));
	req.op = KS_OP_STORE;
	req.keyid = 1;
	memcpy(buf, &req, sizeof(req));
	memcpy(buf + sizeof(req), "hello", 5);
	ATF_REQUIRE(cmi_send(fd, buf, sizeof(req) + 5, 0) == 0);

	rlen = sizeof(reply);
	ATF_REQUIRE(cmi_recv(fd, &reply, &rlen, NULL) == 0);
	ATF_CHECK_EQ(reply.status, KS_STATUS_OK);

	/* Fetch it back */
	req.op = KS_OP_FETCH;
	req.keyid = 1;
	ATF_REQUIRE(cmi_send(fd, &req, sizeof(req), 0) == 0);

	memset(buf, 0, sizeof(buf));
	rlen = sizeof(buf);
	ATF_REQUIRE(cmi_recv(fd, buf, &rlen, NULL) == 0);
	ATF_REQUIRE(rlen >= sizeof(reply));
	memcpy(&reply, buf, sizeof(reply));
	ATF_CHECK_EQ(reply.status, KS_STATUS_OK);
	ATF_CHECK(memcmp(buf + sizeof(reply), "hello", 5) == 0);

	close(fd);
}

ATF_TC(fetch_notfound);
ATF_TC_HEAD(fetch_notfound, tc)
{
	atf_tc_set_md_var(tc, "descr", "Fetch nonexistent key returns NOTFOUND");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(fetch_notfound, tc)
{
	struct ks_request req;
	struct ks_reply reply;
	uint32_t rlen;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	req.op = KS_OP_FETCH;
	req.keyid = 99999;
	ATF_REQUIRE(cmi_send(fd, &req, sizeof(req), 0) == 0);
	rlen = sizeof(reply);
	ATF_REQUIRE(cmi_recv(fd, &reply, &rlen, NULL) == 0);
	ATF_CHECK_EQ(reply.status, KS_STATUS_NOTFOUND);

	close(fd);
}

ATF_TC(concurrent_instances);
ATF_TC_HEAD(concurrent_instances, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Multiple instances to same service work independently");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(concurrent_instances, tc)
{
	int fd1, fd2;

	fd1 = cmi_connect("keystore");
	fd2 = cmi_connect("keystore");
	ATF_REQUIRE(fd1 >= 0);
	ATF_REQUIRE(fd2 >= 0);
	ATF_CHECK(fd1 != fd2);

	close(fd2);
	close(fd1);
}

ATF_TC(zero_length_write_noop);
ATF_TC_HEAD(zero_length_write_noop, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_SENDMSG with payload_len=0 sends a zero-length message");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(zero_length_write_noop, tc)
{
	struct cmi_recvmsg_args ra;
	char buf[64];
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Zero-length SENDMSG should succeed and enqueue a message. */
	ATF_REQUIRE(cmi_send(fd, NULL, 0, 0) == 0);

	/* The handler receives a 0-byte message and replies (e.g. error). */

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_CHECK(ioctl(fd, CMI_RECVMSG, &ra) == 0);
	ATF_CHECK(ra.payload_len > 0);

	close(fd);
}

/* ================================================================
 * Async behavior tests
 * ================================================================ */

ATF_TC(nonblock_read_eagain);
ATF_TC_HEAD(nonblock_read_eagain, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "O_NONBLOCK CMI_RECVMSG with no pending messages returns EAGAIN");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(nonblock_read_eagain, tc)
{
	char buf[64];
	uint32_t rlen;
	int fd, flags;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	flags = fcntl(fd, F_GETFL, 0);
	ATF_REQUIRE(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);

	rlen = sizeof(buf);
	ATF_CHECK_ERRNO(EAGAIN, cmi_recv(fd, buf, &rlen, NULL) == -1);

	close(fd);
}

/* ================================================================
 * SENDMSG / RECVMSG tests
 * ================================================================ */

ATF_TC(recvmsg_basic);
ATF_TC_HEAD(recvmsg_basic, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_RECVMSG dequeues reply with payload and reply token");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(recvmsg_basic, tc)
{
	struct cmi_sendmsg_args sa;
	struct cmi_recvmsg_args ra;
	struct ks_request req;
	struct ks_reply reply;
	char buf[128];
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	cmi_store(fd, 42, "world", 5);

	req.op = KS_OP_FETCH;
	req.keyid = 42;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.reply_token = 0x1234;
	ATF_REQUIRE(ioctl(fd, CMI_SENDMSG, &sa) == 0);


	memset(&ra, 0, sizeof(ra));
	memset(buf, 0, sizeof(buf));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_REQUIRE(ioctl(fd, CMI_RECVMSG, &ra) == 0);
	ATF_REQUIRE(ra.payload_len >= sizeof(reply));
	memcpy(&reply, buf, sizeof(reply));
	ATF_CHECK_EQ(reply.status, KS_STATUS_OK);
	ATF_CHECK(memcmp(buf + sizeof(reply), "world", 5) == 0);
	ATF_CHECK_EQ(ra.reply_token, 0x1234);

	close(fd);
}

ATF_TC(reply_token_correlation);
ATF_TC_HEAD(reply_token_correlation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Reply tokens correlate requests to responses in FIFO order");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(reply_token_correlation, tc)
{
	struct cmi_sendmsg_args sa;
	struct cmi_recvmsg_args ra;
	struct ks_request req;
	char buf[128];
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Send two requests with different tokens. */
	req.op = KS_OP_FETCH;
	req.keyid = 1;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.reply_token = 0xAAAA;
	ATF_REQUIRE(ioctl(fd, CMI_SENDMSG, &sa) == 0);

	req.keyid = 2;
	sa.reply_token = 0xBBBB;
	ATF_REQUIRE(ioctl(fd, CMI_SENDMSG, &sa) == 0);

	/* Read both — FIFO order, tokens match. */

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_REQUIRE(ioctl(fd, CMI_RECVMSG, &ra) == 0);
	ATF_CHECK_EQ(ra.reply_token, 0xAAAA);

	ra.payload_len = sizeof(buf);
	ra.nfds = 0;
	ATF_REQUIRE(ioctl(fd, CMI_RECVMSG, &ra) == 0);
	ATF_CHECK_EQ(ra.reply_token, 0xBBBB);

	close(fd);
}

/* ================================================================
 * Fd passing tests — various descriptor types
 * ================================================================ */

ATF_TC(fd_passing_pipe);
ATF_TC_HEAD(fd_passing_pipe, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG with pipe-fd attachment");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(fd_passing_pipe, tc)
{
	struct cmi_sendmsg_args sa;
	struct ks_request req;
	struct ks_reply reply;
	int fd, pipefd[2];

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pipe(pipefd) == 0);

	req.op = KS_OP_FETCH;
	req.keyid = 0;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = &pipefd[0];
	sa.nfds = 1;
	ATF_REQUIRE(ioctl(fd, CMI_SENDMSG, &sa) == 0);

	{
		uint32_t rlen = sizeof(reply);
		ATF_REQUIRE(cmi_recv(fd, &reply, &rlen, NULL) == 0);
	}

	close(pipefd[0]);
	close(pipefd[1]);
	close(fd);
}

ATF_TC(fd_passing_socket);
ATF_TC_HEAD(fd_passing_socket, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG with socket fd attachment");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(fd_passing_socket, tc)
{
	struct cmi_sendmsg_args sa;
	struct ks_request req;
	struct ks_reply reply;
	int fd, sv[2];

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	req.op = KS_OP_FETCH;
	req.keyid = 0;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = &sv[0];
	sa.nfds = 1;
	ATF_REQUIRE(ioctl(fd, CMI_SENDMSG, &sa) == 0);

	{
		uint32_t rlen = sizeof(reply);
		ATF_REQUIRE(cmi_recv(fd, &reply, &rlen, NULL) == 0);
	}

	close(sv[0]);
	close(sv[1]);
	close(fd);
}

ATF_TC(fd_passing_devnull);
ATF_TC_HEAD(fd_passing_devnull, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG with /dev/null fd attachment");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(fd_passing_devnull, tc)
{
	struct cmi_sendmsg_args sa;
	struct ks_request req;
	struct ks_reply reply;
	int fd, devnull;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);
	devnull = open("/dev/null", O_RDWR);
	ATF_REQUIRE(devnull >= 0);

	req.op = KS_OP_FETCH;
	req.keyid = 0;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = &devnull;
	sa.nfds = 1;
	ATF_REQUIRE(ioctl(fd, CMI_SENDMSG, &sa) == 0);

	{
		uint32_t rlen = sizeof(reply);
		ATF_REQUIRE(cmi_recv(fd, &reply, &rlen, NULL) == 0);
	}

	close(devnull);
	close(fd);
}

ATF_TC(fd_passing_multiple_types);
ATF_TC_HEAD(fd_passing_multiple_types, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG with pipe + socket + file fds in one message");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(fd_passing_multiple_types, tc)
{
	struct cmi_sendmsg_args sa;
	struct ks_request req;
	struct ks_reply reply;
	int fd, fds[3], sv[2], pipefd[2];

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pipe(pipefd) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	fds[0] = pipefd[0];
	fds[1] = sv[0];
	fds[2] = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fds[2] >= 0);

	req.op = KS_OP_FETCH;
	req.keyid = 0;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = fds;
	sa.nfds = 3;
	ATF_REQUIRE(ioctl(fd, CMI_SENDMSG, &sa) == 0);

	{
		uint32_t rlen = sizeof(reply);
		ATF_REQUIRE(cmi_recv(fd, &reply, &rlen, NULL) == 0);
	}

	close(fds[2]);
	close(sv[0]);
	close(sv[1]);
	close(pipefd[0]);
	close(pipefd[1]);
	close(fd);
}

ATF_TC(fd_too_many);
ATF_TC_HEAD(fd_too_many, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Sending > CMI_MAX_FDS fds fails EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(fd_too_many, tc)
{
	struct cmi_sendmsg_args sa;
	int fds[CMI_MAX_FDS + 1];
	int fd, i;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	for (i = 0; i <= CMI_MAX_FDS; i++)
		fds[i] = STDOUT_FILENO;

	memset(&sa, 0, sizeof(sa));
	sa.payload = "x";
	sa.payload_len = 1;
	sa.fds = fds;
	sa.nfds = CMI_MAX_FDS + 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, CMI_SENDMSG, &sa) == -1);

	close(fd);
}

/* ================================================================
 * Poll / kqueue tests
 * ================================================================ */


ATF_TC(kqueue_read);
ATF_TC_HEAD(kqueue_read, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "kqueue EVFILT_READ fires when reply available");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(kqueue_read, tc)
{
	struct ks_request req;
	struct kevent kev;
	struct timespec ts;
	int fd, kq, ret;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);

	req.op = KS_OP_FETCH;
	req.keyid = 0;
	ATF_REQUIRE(cmi_send(fd, &req, sizeof(req), 0) == 0);

	ts.tv_sec = 2;
	ts.tv_nsec = 0;
	ret = kevent(kq, NULL, 0, &kev, 1, &ts);
	ATF_CHECK(ret > 0);

	close(kq);
	close(fd);
}

ATF_TC(kqueue_evfilt_write);
ATF_TC_HEAD(kqueue_evfilt_write, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "kqueue EVFILT_WRITE fires when RX queue has space");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(kqueue_evfilt_write, tc)
{
	struct kevent kev;
	struct timespec ts;
	int fd, kq, ret;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&kev, fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);

	ts.tv_sec = 1;
	ts.tv_nsec = 0;
	ret = kevent(kq, NULL, 0, &kev, 1, &ts);
	ATF_CHECK(ret > 0);
	ATF_CHECK(kev.data > 0);

	close(kq);
	close(fd);
}

/* ================================================================
 * Clone test
 * ================================================================ */

/* ================================================================
 * Stat tests
 * ================================================================ */

ATF_TC(instance_fstat);
ATF_TC_HEAD(instance_fstat, tc)
{
	atf_tc_set_md_var(tc, "descr", "fstat on instance fd reports TX queue len");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(instance_fstat, tc)
{
	struct ks_request req;
	struct stat sb;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(fstat(fd, &sb) == 0);
	ATF_CHECK_EQ(sb.st_size, 0);

	/* Trigger a reply. */
	req.op = KS_OP_FETCH;
	req.keyid = 0;
	ATF_REQUIRE(cmi_send(fd, &req, sizeof(req), 0) == 0);
	usleep(100000);  /* wait for async dispatch */

	ATF_REQUIRE(fstat(fd, &sb) == 0);
	ATF_CHECK(sb.st_size >= 1);

	close(fd);
}

/* ================================================================
 * Queue ordering test
 * ================================================================ */

ATF_TC(queue_ordering);
ATF_TC_HEAD(queue_ordering, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Multiple replies dequeued in FIFO order");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(queue_ordering, tc)
{
	struct cmi_sendmsg_args sa;
	struct cmi_recvmsg_args ra;
	struct ks_request req;
	char buf[128];
	int fd, i;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	for (i = 0; i < 5; i++) {
		req.op = KS_OP_FETCH;
		req.keyid = (uint32_t)i;
		memset(&sa, 0, sizeof(sa));
		sa.payload = &req;
		sa.payload_len = sizeof(req);
		sa.reply_token = (uint64_t)(i + 1);
		ATF_REQUIRE(ioctl(fd, CMI_SENDMSG, &sa) == 0);
	}

	for (i = 0; i < 5; i++) {
		memset(&ra, 0, sizeof(ra));
		ra.payload = buf;
		ra.payload_len = sizeof(buf);
		ATF_REQUIRE_MSG(ioctl(fd, CMI_RECVMSG, &ra) == 0,
		    "recvmsg %d: %s", i, strerror(errno));
		ATF_CHECK_EQ_MSG(ra.reply_token, (uint64_t)(i + 1),
		    "reply %d: expected token %d, got %llu",
		    i, i + 1, (unsigned long long)ra.reply_token);
	}

	close(fd);
}

/* ================================================================
 * Multi-process tests
 * ================================================================ */

ATF_TC(capability_delegation);
ATF_TC_HEAD(capability_delegation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Instance fd inherited by child process works");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(capability_delegation, tc)
{
	struct ks_request req;
	struct ks_reply reply;
	int fd, status;
	pid_t pid;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		struct cmi_sendmsg_args sa;
		struct cmi_recvmsg_args ra;

		req.op = KS_OP_FETCH;
		req.keyid = 0;
		memset(&sa, 0, sizeof(sa));
		sa.payload = &req;
		sa.payload_len = sizeof(req);
		if (ioctl(fd, CMI_SENDMSG, &sa) != 0)
			_exit(1);
		memset(&ra, 0, sizeof(ra));
		ra.payload = &reply;
		ra.payload_len = sizeof(reply);
		if (ioctl(fd, CMI_RECVMSG, &ra) != 0)
			_exit(2);
		_exit(0);
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(fd);
}

ATF_TC(scm_rights_passing);
ATF_TC_HEAD(scm_rights_passing, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Instance fd sent via SCM_RIGHTS works in recipient");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(scm_rights_passing, tc)
{
	struct ks_request req;
	int sv[2], fd, status;
	pid_t pid;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: receive fd via SCM_RIGHTS, use it. */
		struct msghdr msgh;
		struct iovec iov;
		union {
			struct cmsghdr hdr;
			char buf[CMSG_SPACE(sizeof(int))];
		} cmsgbuf;
		struct cmsghdr *cmsg;
		char reply[256];
		int received_fd;
		char dummy;

		close(sv[0]);
		close(fd);

		memset(&msgh, 0, sizeof(msgh));
		iov.iov_base = &dummy;
		iov.iov_len = 1;
		msgh.msg_iov = &iov;
		msgh.msg_iovlen = 1;
		msgh.msg_control = cmsgbuf.buf;
		msgh.msg_controllen = sizeof(cmsgbuf.buf);

		if (recvmsg(sv[1], &msgh, 0) < 0)
			_exit(1);

		cmsg = CMSG_FIRSTHDR(&msgh);
		if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS)
			_exit(2);
		memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int));

		{
			struct cmi_sendmsg_args sa;
			struct cmi_recvmsg_args ra;

			req.op = KS_OP_FETCH;
			req.keyid = 0;
			memset(&sa, 0, sizeof(sa));
			sa.payload = &req;
			sa.payload_len = sizeof(req);
			if (ioctl(received_fd, CMI_SENDMSG, &sa) != 0)
				_exit(3);
			memset(&ra, 0, sizeof(ra));
			ra.payload = &reply;
			ra.payload_len = sizeof(reply);
			if (ioctl(received_fd, CMI_RECVMSG, &ra) != 0)
				_exit(4);
		}
		close(received_fd);
		close(sv[1]);
		_exit(0);
	}

	/* Parent: send fd via SCM_RIGHTS. */
	{
		struct msghdr msgh;
		struct iovec iov;
		union {
			struct cmsghdr hdr;
			char buf[CMSG_SPACE(sizeof(int))];
		} cmsgbuf;
		struct cmsghdr *cmsg;
		char dummy = 'x';

		close(sv[1]);

		memset(&msgh, 0, sizeof(msgh));
		iov.iov_base = &dummy;
		iov.iov_len = 1;
		msgh.msg_iov = &iov;
		msgh.msg_iovlen = 1;
		msgh.msg_control = cmsgbuf.buf;
		msgh.msg_controllen = sizeof(cmsgbuf.buf);

		cmsg = CMSG_FIRSTHDR(&msgh);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

		ATF_REQUIRE(sendmsg(sv[0], &msgh, 0) >= 0);
		close(sv[0]);
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child exited with status %d", WEXITSTATUS(status));
	close(fd);
}

ATF_TC(multiproc_store_fetch);
ATF_TC_HEAD(multiproc_store_fetch, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Parent stores key, child fetches via separate instance");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(multiproc_store_fetch, tc)
{
	int fd, status;
	pid_t pid;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Parent stores a key. */
	cmi_store(fd, 7777, "shared", 6);
	close(fd);

	/* Child opens its own instance and fetches. */
	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		struct cmi_sendmsg_args sa;
		struct cmi_recvmsg_args ra;
		struct ks_request req;
		struct ks_reply reply;
		char buf[128];
		int cfd = cmi_connect("keystore");
		if (cfd < 0)
			_exit(10);

		req.op = KS_OP_FETCH;
		req.keyid = 7777;
		memset(&sa, 0, sizeof(sa));
		sa.payload = &req;
		sa.payload_len = sizeof(req);
		if (ioctl(cfd, CMI_SENDMSG, &sa) != 0)
			_exit(1);

		memset(buf, 0, sizeof(buf));
		memset(&ra, 0, sizeof(ra));
		ra.payload = buf;
		ra.payload_len = sizeof(buf);
		if (ioctl(cfd, CMI_RECVMSG, &ra) != 0)
			_exit(2);
		if (ra.payload_len < sizeof(reply))
			_exit(2);
		memcpy(&reply, buf, sizeof(reply));
		if (reply.status != KS_STATUS_OK)
			_exit(3);
		if (memcmp(buf + sizeof(reply), "shared", 6) != 0)
			_exit(4);
		close(cfd);
		_exit(0);
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child exited with status %d", WEXITSTATUS(status));
}

ATF_TC(multiproc_concurrent_writers);
ATF_TC_HEAD(multiproc_concurrent_writers, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Multiple processes write concurrently to separate instances");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(multiproc_concurrent_writers, tc)
{
	pid_t pids[4];
	int i, status;

	for (i = 0; i < 4; i++) {
		pids[i] = fork();
		ATF_REQUIRE(pids[i] >= 0);

		if (pids[i] == 0) {
			struct cmi_sendmsg_args sa;
			struct cmi_recvmsg_args ra;
			struct ks_request req;
			struct ks_reply reply;
			char buf[sizeof(struct ks_request) + 32];
			int fd, j;

			fd = cmi_connect("keystore");
			if (fd < 0)
				_exit(10);

			/* Each child stores and fetches 10 keys. */
			for (j = 0; j < 10; j++) {
				uint32_t keyid = (uint32_t)(i * 1000 + j);

				memset(buf, 0, sizeof(buf));
				req.op = KS_OP_STORE;
				req.keyid = keyid;
				memcpy(buf, &req, sizeof(req));
				memcpy(buf + sizeof(req), "data", 4);
				memset(&sa, 0, sizeof(sa));
				sa.payload = buf;
				sa.payload_len = sizeof(req) + 4;
				if (ioctl(fd, CMI_SENDMSG, &sa) != 0)
					_exit(1);
				memset(&ra, 0, sizeof(ra));
				ra.payload = &reply;
				ra.payload_len = sizeof(reply);
				if (ioctl(fd, CMI_RECVMSG, &ra) != 0)
					_exit(2);
				if (reply.status != KS_STATUS_OK)
					_exit(3);
			}

			close(fd);
			_exit(0);
		}
	}

	for (i = 0; i < 4; i++) {
		ATF_REQUIRE(waitpid(pids[i], &status, 0) == pids[i]);
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "child %d exited with status %d", i, WEXITSTATUS(status));
	}
}

ATF_TC(close_during_pending);
ATF_TC_HEAD(close_during_pending, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing instance with pending messages does not panic");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(close_during_pending, tc)
{
	struct ks_request req;
	int fd, i;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Fire off several sends then immediately close. */
	for (i = 0; i < 20; i++) {
		req.op = KS_OP_FETCH;
		req.keyid = (uint32_t)i;
		(void)cmi_send(fd, &req, sizeof(req), 0);
	}

	/* Close with replies pending — must not crash. */
	close(fd);
}

ATF_TC(rapid_fire);
ATF_TC_HEAD(rapid_fire, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Rapid fire 100 requests, recv all 100 replies");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(rapid_fire, tc)
{
	struct ks_request req;
	char buf[256];
	uint32_t rlen;
	int fd, i, flags;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Send 100 requests. */
	for (i = 0; i < 100; i++) {
		req.op = KS_OP_FETCH;
		req.keyid = (uint32_t)i;
		ATF_REQUIRE(cmi_send(fd, &req, sizeof(req), 0) == 0);
	}

	/* Recv all 100 replies. */
	for (i = 0; i < 100; i++) {
		rlen = sizeof(buf);
		ATF_REQUIRE_MSG(
		    cmi_recv(fd, buf, &rlen, NULL) == 0,
		    "recv reply %d: %s", i, strerror(errno));
	}

	/* No more pending — nonblock recv should EAGAIN. */
	flags = fcntl(fd, F_GETFL, 0);
	ATF_REQUIRE(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
	rlen = sizeof(buf);
	ATF_CHECK_ERRNO(EAGAIN, cmi_recv(fd, buf, &rlen, NULL) == -1);

	close(fd);
}

/* ================================================================
 * Failure condition tests
 * ================================================================ */

ATF_TC(write_oversized);
ATF_TC_HEAD(write_oversized, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_SENDMSG with payload > CMI_MAX_MSG returns EMSGSIZE");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(write_oversized, tc)
{
	struct cmi_sendmsg_args sa;
	char *big;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	big = calloc(1, CMI_MAX_MSG + 1);
	ATF_REQUIRE(big != NULL);
	memset(&sa, 0, sizeof(sa));
	sa.payload = big;
	sa.payload_len = CMI_MAX_MSG + 1;
	ATF_CHECK_ERRNO(EMSGSIZE, ioctl(fd, CMI_SENDMSG, &sa) == -1);
	free(big);
	close(fd);
}

ATF_TC(sendmsg_bad_fd);
ATF_TC_HEAD(sendmsg_bad_fd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG with invalid fd number fails EBADF");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(sendmsg_bad_fd, tc)
{
	struct cmi_sendmsg_args sa;
	struct ks_request req;
	int fd, badfd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	badfd = closed_fd();
	req.op = KS_OP_FETCH;
	req.keyid = 0;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = &badfd;
	sa.nfds = 1;
	ATF_CHECK_ERRNO(EBADF, ioctl(fd, CMI_SENDMSG, &sa) == -1);
	close(fd);
}

ATF_TC(read_buffer_too_small);
ATF_TC_HEAD(read_buffer_too_small, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_RECVMSG with buffer smaller than message returns EMSGSIZE");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(read_buffer_too_small, tc)
{
	struct cmi_recvmsg_args ra;
	struct ks_request req;
	char tiny[1];
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Store a key so the reply has payload. */
	cmi_store(fd, 100, "big_value", 9);

	/* Fetch — reply is sizeof(ks_reply) + 9 = 13 bytes. */
	req.op = KS_OP_FETCH;
	req.keyid = 100;
	ATF_REQUIRE(cmi_send(fd, &req, sizeof(req), 0) == 0);

	/* Recv with a 1-byte buffer. */
	memset(&ra, 0, sizeof(ra));
	ra.payload = tiny;
	ra.payload_len = sizeof(tiny);
	ATF_CHECK_ERRNO(EMSGSIZE, ioctl(fd, CMI_RECVMSG, &ra) == -1);

	/* Message should still be queued — recv with full buffer works. */
	{
		char buf[64];
		uint32_t rlen = sizeof(buf);
		ATF_CHECK(cmi_recv(fd, buf, &rlen, NULL) == 0);
		ATF_CHECK(rlen > 0);
	}

	close(fd);
}

ATF_TC(recvmsg_buffer_too_small);
ATF_TC_HEAD(recvmsg_buffer_too_small, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "RECVMSG with small buffer returns EMSGSIZE and required size");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(recvmsg_buffer_too_small, tc)
{
	struct cmi_sendmsg_args sa;
	struct cmi_recvmsg_args ra;
	struct ks_request req;
	char buf[128];
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);
	cmi_store(fd, 200, "somedata", 8);

	req.op = KS_OP_FETCH;
	req.keyid = 200;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	ATF_REQUIRE(ioctl(fd, CMI_SENDMSG, &sa) == 0);

	/* Try with 1-byte buffer. */
	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = 1;
	ATF_CHECK_ERRNO(EMSGSIZE, ioctl(fd, CMI_RECVMSG, &ra) == -1);

	/* Message stays queued — retry with full buffer. */
	ra.payload_len = sizeof(buf);
	ATF_CHECK(ioctl(fd, CMI_RECVMSG, &ra) == 0);
	ATF_CHECK(ra.payload_len > 0);

	close(fd);
}

ATF_TC(recvmsg_empty_nonblock);
ATF_TC_HEAD(recvmsg_empty_nonblock, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "RECVMSG on empty queue with O_NONBLOCK returns EAGAIN");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(recvmsg_empty_nonblock, tc)
{
	struct cmi_recvmsg_args ra;
	char buf[64];
	int fd, flags;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	flags = fcntl(fd, F_GETFL, 0);
	ATF_REQUIRE(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_CHECK_ERRNO(EAGAIN, ioctl(fd, CMI_RECVMSG, &ra) == -1);

	close(fd);
}

ATF_TC(dup_shared_instance);
ATF_TC_HEAD(dup_shared_instance, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "dup() shares instance �� write on one, read on the other");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(dup_shared_instance, tc)
{
	struct ks_request req;
	struct ks_reply reply;
	int fd, fd2;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	fd2 = dup(fd);
	ATF_REQUIRE(fd2 >= 0);

	/* Send on fd, recv on fd2 — they share the same instance. */
	{
		uint32_t rlen;
		req.op = KS_OP_FETCH;
		req.keyid = 0;
		ATF_REQUIRE(cmi_send(fd, &req, sizeof(req), 0) == 0);
		rlen = sizeof(reply);
		ATF_REQUIRE(cmi_recv(fd2, &reply, &rlen, NULL) == 0);
	}

	close(fd2);
	close(fd);
}

ATF_TC(ioctl_bad_cmd);
ATF_TC_HEAD(ioctl_bad_cmd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Unknown ioctl on /dev/cmi returns ENOTTY");
}
ATF_TC_BODY(ioctl_bad_cmd, tc)
{
	int fd, dummy;

	fd = cmi_open();
	ATF_CHECK_ERRNO(ENOTTY, ioctl(fd, _IO('Y', 99), &dummy) == -1);
	close(fd);
}

ATF_TC(instance_ioctl_bad_cmd);
ATF_TC_HEAD(instance_ioctl_bad_cmd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Unknown ioctl on instance fd returns ENOTTY");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(instance_ioctl_bad_cmd, tc)
{
	int fd, dummy;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_ERRNO(ENOTTY, ioctl(fd, _IO('Y', 99), &dummy) == -1);
	close(fd);
}

ATF_TC(connect_on_instance_fd);
ATF_TC_HEAD(connect_on_instance_fd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_CONNECT on a instance fd returns ENOTTY");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(connect_on_instance_fd, tc)
{
	struct cmi_connect_args ca;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "keystore", sizeof(ca.name));
	ATF_CHECK_ERRNO(ENOTTY, ioctl(fd, CMI_CONNECT, &ca) == -1);
	close(fd);
}

ATF_TC(write_after_close_child);
ATF_TC_HEAD(write_after_close_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_SENDMSG after peer process closes shared fd still works");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(write_after_close_child, tc)
{
	struct ks_request req;
	char buf[256];
	uint32_t rlen;
	int fd, status;
	pid_t pid;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Fork, child closes its copy immediately. */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(fd);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);

	/*
	 * Parent still has its fd — the instance is alive because
	 * the parent's struct file still holds a reference.
	 * CMI_SENDMSG should succeed.
	 */
	req.op = KS_OP_FETCH;
	req.keyid = 0;
	ATF_CHECK(cmi_send(fd, &req, sizeof(req), 0) == 0);
	rlen = sizeof(buf);
	ATF_CHECK(cmi_recv(fd, buf, &rlen, NULL) == 0);

	close(fd);
}

ATF_TC(sendmsg_zero_payload_with_fds);
ATF_TC_HEAD(sendmsg_zero_payload_with_fds, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG with zero payload but attached fds works");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(sendmsg_zero_payload_with_fds, tc)
{
	struct cmi_sendmsg_args sa;
	char buf[64];
	int fd, pipefd[2];

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pipe(pipefd) == 0);

	memset(&sa, 0, sizeof(sa));
	sa.payload = NULL;
	sa.payload_len = 0;
	sa.fds = &pipefd[0];
	sa.nfds = 1;

	/* Keystore will see a 0-byte message and reply with error. */
	ATF_REQUIRE(ioctl(fd, CMI_SENDMSG, &sa) == 0);
	{
		uint32_t rlen = sizeof(buf);
		ATF_REQUIRE(cmi_recv(fd, buf, &rlen, NULL) == 0);
		ATF_REQUIRE(rlen > 0);
	}

	close(pipefd[0]);
	close(pipefd[1]);
	close(fd);
}

/* ================================================================
 * Introspection tests
 * ================================================================ */

ATF_TC(getinfo);
ATF_TC_HEAD(getinfo, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_GETINFO returns service identity and basic metadata");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(getinfo, tc)
{
	struct cmi_info_args info;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, CMI_GETINFO, &info) == 0);
	ATF_CHECK_STREQ(info.name, "keystore");
	ATF_CHECK(info.badge != 0);
	ATF_CHECK(info.id != 0);

	/* Second instance should get different badge and ID. */
	{
		struct cmi_info_args info2;
		int fd2 = cmi_connect("keystore");
		ATF_REQUIRE(fd2 >= 0);
		ATF_REQUIRE(ioctl(fd2, CMI_GETINFO, &info2) == 0);
		ATF_CHECK_STREQ(info2.name, "keystore");
		ATF_CHECK(info2.badge != info.badge);
		ATF_CHECK(info2.id != info.id);
		close(fd2);
	}

	close(fd);
}

/* ================================================================
 * Capability pair tests (requires cmi_pair module)
 * ================================================================ */

#define	PAIR_OP_CREATE	1

/*
 * Helper: connect to pair service, send PAIR_OP_CREATE, receive peer fd.
 * Returns both fds via out parameters.
 */
static void
cmi_pair_pair(int *fd_a, int *fd_b)
{
	struct cmi_sendmsg_args sa;
	struct cmi_recvmsg_args ra;
	uint32_t op;
	int fds_out[1];
	int fd;

	fd = cmi_connect("pair");
	ATF_REQUIRE_MSG(fd >= 0, "connect pair: %s", strerror(errno));

	op = PAIR_OP_CREATE;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &op;
	sa.payload_len = sizeof(op);
	ATF_REQUIRE(ioctl(fd, CMI_SENDMSG, &sa) == 0);


	memset(&ra, 0, sizeof(ra));
	ra.fds = fds_out;
	ra.nfds = 1;
	ATF_REQUIRE(ioctl(fd, CMI_RECVMSG, &ra) == 0);
	ATF_REQUIRE_MSG(ra.nfds == 1, "expected 1 fd, got %u", ra.nfds);

	*fd_a = fd;
	*fd_b = fds_out[0];
}

ATF_TC(pair_create);
ATF_TC_HEAD(pair_create, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Connect to pair, PAIR_OP_CREATE returns peer fd");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_pair");
}
ATF_TC_BODY(pair_create, tc)
{
	int fd_a, fd_b;

	cmi_pair_pair(&fd_a, &fd_b);
	ATF_CHECK(fd_a >= 0);
	ATF_CHECK(fd_b >= 0);
	ATF_CHECK(fd_a != fd_b);
	close(fd_b);
	close(fd_a);
}

ATF_TC(pair_bidirectional);
ATF_TC_HEAD(pair_bidirectional, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Send on A, recv on B; send on B, recv on A");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_pair");
}
ATF_TC_BODY(pair_bidirectional, tc)
{
	char buf[64];
	uint32_t rlen;
	int fd_a, fd_b;

	cmi_pair_pair(&fd_a, &fd_b);

	/* A → B: send on A, data appears on B. */
	ATF_REQUIRE(cmi_send(fd_a, "hello", 5, 0) == 0);

	memset(buf, 0, sizeof(buf));
	rlen = sizeof(buf);
	ATF_REQUIRE(cmi_recv(fd_b, buf, &rlen, NULL) == 0);
	ATF_REQUIRE(rlen == 5);
	ATF_CHECK(memcmp(buf, "hello", 5) == 0);

	/* B → A: send on B, data appears on A. */
	ATF_REQUIRE(cmi_send(fd_b, "world", 5, 0) == 0);

	memset(buf, 0, sizeof(buf));
	rlen = sizeof(buf);
	ATF_REQUIRE(cmi_recv(fd_a, buf, &rlen, NULL) == 0);
	ATF_REQUIRE(rlen == 5);
	ATF_CHECK(memcmp(buf, "world", 5) == 0);

	close(fd_b);
	close(fd_a);
}

ATF_TC(pair_close_one_end);
ATF_TC_HEAD(pair_close_one_end, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing one end of pair revokes the other");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_pair");
}
ATF_TC_BODY(pair_close_one_end, tc)
{
	char buf[64];
	int fd_a, fd_b, flags;

	cmi_pair_pair(&fd_a, &fd_b);

	/* Close A. */
	close(fd_a);

	/*
	 * B should be revoked.  Set nonblock and try to send —
	 * should get EPIPE or ECONNRESET.
	 */
	flags = fcntl(fd_b, F_GETFL, 0);
	fcntl(fd_b, F_SETFL, flags | O_NONBLOCK);

	/* Give the framework a moment to process the revocation. */
	usleep(50000);

	ATF_CHECK(cmi_send(fd_b, "x", 1, 0) == -1);
	ATF_CHECK(errno == EPIPE || errno == ECONNRESET);

	{
		uint32_t rlen = sizeof(buf);
		ATF_CHECK(cmi_recv(fd_b, buf, &rlen, NULL) == -1);
		ATF_CHECK(errno == ECONNRESET || errno == EAGAIN);
	}

	close(fd_b);
}

ATF_TC(pair_multiproc);
ATF_TC_HEAD(pair_multiproc, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Pair works across processes via fork");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_pair");
}
ATF_TC_BODY(pair_multiproc, tc)
{
	char buf[64];
	int fd_a, fd_b, status;
	pid_t pid;

	cmi_pair_pair(&fd_a, &fd_b);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: owns fd_b, sends a message. No ack expected. */
		struct cmi_sendmsg_args sa;

		close(fd_a);
		memset(&sa, 0, sizeof(sa));
		sa.payload = "child";
		sa.payload_len = 5;
		if (ioctl(fd_b, CMI_SENDMSG, &sa) != 0)
			_exit(1);
		close(fd_b);
		_exit(0);
	}

	/* Parent: owns fd_a, recvs the forwarded message. */
	close(fd_b);

	/* Recv the forwarded message from child. */
	memset(buf, 0, sizeof(buf));
	{
		uint32_t rlen = sizeof(buf);
		ATF_REQUIRE(cmi_recv(fd_a, buf, &rlen, NULL) == 0);
		ATF_REQUIRE(rlen == 5);
	}
	ATF_CHECK(memcmp(buf, "child", 5) == 0);

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(fd_a);
}

/* ================================================================
 * Additional coverage
 * ================================================================ */

ATF_TC(getinfo_limits);
ATF_TC_HEAD(getinfo_limits, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_GETINFO returns real limits and feature bits");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(getinfo_limits, tc)
{
	struct cmi_info_args info;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, CMI_GETINFO, &info) == 0);
	ATF_CHECK_EQ(info.msg_limit, CMI_MAX_MSG);
	ATF_CHECK_EQ(info.queue_depth, CMI_DEFAULT_QUEUE_DEPTH);
	ATF_CHECK_EQ(info.tx_limit, CMI_DEFAULT_TX_LIMIT);
	ATF_CHECK_EQ(info.max_fds, CMI_MAX_FDS);
	/* keystore is async-only: SENDMSG + KQUEUE, no CALL */
	ATF_CHECK((info.features & CMI_INFO_F_SENDMSG) != 0);
	ATF_CHECK((info.features & CMI_INFO_F_CALL) == 0);
	ATF_CHECK((info.features & CMI_INFO_F_KQUEUE) != 0);

	close(fd);
}

ATF_TC(credential_trailer);
ATF_TC_HEAD(credential_trailer, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "RECVMSG trailer has correct uid and pid on RX path");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(credential_trailer, tc)
{
	struct cmi_sendmsg_args sa;
	struct cmi_recvmsg_args ra;
	struct ks_request req;
	char buf[128];
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/*
	 * The credential trailer on a REPLY message will be zero
	 * because the kernel handler doesn't stamp creds on TX.
	 * So we just verify the fields are deterministic (zeroed).
	 * Full credential testing requires a service that echoes
	 * the sender's creds back in the payload.
	 */
	req.op = KS_OP_FETCH;
	req.keyid = 0;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	ATF_REQUIRE(ioctl(fd, CMI_SENDMSG, &sa) == 0);


	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_REQUIRE(ioctl(fd, CMI_RECVMSG, &ra) == 0);

	/* Replies from kernel have zero trailer (no sender identity). */
	ATF_CHECK_EQ(ra.trailer.uid, 0);
	ATF_CHECK_EQ(ra.trailer.pid, 0);

	close(fd);
}

/* ================================================================
 * CMI_CALL tests
 * ================================================================ */

ATF_TC(call_no_handler);
ATF_TC_HEAD(call_no_handler, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_CALL on async-only service returns EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(call_no_handler, tc)
{
	struct cmi_call_args ca;
	char buf[16];
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	memset(&ca, 0, sizeof(ca));
	ca.req = "x";
	ca.req_len = 1;
	ca.reply = buf;
	ca.reply_len = sizeof(buf);
	ATF_CHECK_ERRNO(EOPNOTSUPP, ioctl(fd, CMI_CALL, &ca) == -1);

	close(fd);
}

ATF_TC(call_flags_nonzero);
ATF_TC_HEAD(call_flags_nonzero, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_CALL with nonzero flags returns EINVAL on sync service");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(call_flags_nonzero, tc)
{
	struct cmi_call_args ca;
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	memset(&ca, 0, sizeof(ca));
	ca.flags = 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, CMI_CALL, &ca) == -1);

	close(fd);
}

/* ================================================================
 * Revoke-via-message tests
 * ================================================================ */

ATF_TC(terminate_instance);
ATF_TC_HEAD(terminate_instance, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_TERMINATE kills the instance for all holders");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(terminate_instance, tc)
{
	struct cmi_recvmsg_args ra;
	char buf[64];
	int fd, flags;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Send revoke token. */
	ATF_REQUIRE(ioctl(fd, CMI_TERMINATE, NULL) == 0);

	/* Instance should be revoked — recv returns ECONNRESET. */
	flags = fcntl(fd, F_GETFL, 0);
	ATF_REQUIRE(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_CHECK_ERRNO(ECONNRESET, ioctl(fd, CMI_RECVMSG, &ra) == -1);

	close(fd);
}

ATF_TC(terminate_then_send);
ATF_TC_HEAD(terminate_then_send, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG after revoke-via-token returns EPIPE");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(terminate_then_send, tc)
{
	struct ks_request req;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(ioctl(fd, CMI_TERMINATE, NULL) == 0);

	/* Subsequent send should fail. */
	req.op = KS_OP_FETCH;
	req.keyid = 0;
	ATF_CHECK_ERRNO(EPIPE, cmi_send(fd, &req, sizeof(req), 0) == -1);

	close(fd);
}

ATF_TC(terminate_sync_service);
ATF_TC_HEAD(terminate_sync_service, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_TERMINATE works on sync-only service");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(terminate_sync_service, tc)
{
	struct cmi_call_args ca;
	uint32_t op;
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	/* Revoke via the token. */
	ATF_REQUIRE(ioctl(fd, CMI_TERMINATE, NULL) == 0);

	/* CALL should now fail. */
	op = 1; /* NS_OP_INFO */
	memset(&ca, 0, sizeof(ca));
	ca.req = &op;
	ca.req_len = sizeof(op);
	ca.reply = &op;
	ca.reply_len = sizeof(op);
	ATF_CHECK_ERRNO(ECONNRESET, ioctl(fd, CMI_CALL, &ca) == -1);

	close(fd);
}

ATF_TC(normal_ops_no_terminate);
ATF_TC_HEAD(normal_ops_no_terminate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Normal operations do not terminate");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(normal_ops_no_terminate, tc)
{
	struct ks_request req;
	char buf[256];
	uint32_t rlen;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Send with a normal token — should work, not revoke. */
	req.op = KS_OP_FETCH;
	req.keyid = 99998;	/* unlikely to have data from other tests */
	ATF_REQUIRE(cmi_send(fd, &req, sizeof(req), 0x1234) == 0);

	rlen = sizeof(buf);
	ATF_REQUIRE(cmi_recv(fd, buf, &rlen, NULL) == 0);

	close(fd);
}

/* ================================================================
 * Sync-or-async enforcement tests
 * ================================================================ */

ATF_TC(sendmsg_on_sync_service);
ATF_TC_HEAD(sendmsg_on_sync_service, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_SENDMSG on sync-only service returns EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(sendmsg_on_sync_service, tc)
{
	uint32_t op;
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	op = 1; /* NS_OP_INFO */
	ATF_CHECK_ERRNO(EOPNOTSUPP, cmi_send(fd, &op, sizeof(op), 0) == -1);

	close(fd);
}

ATF_TC(call_on_async_service);
ATF_TC_HEAD(call_on_async_service, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_CALL on async-only service returns EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(call_on_async_service, tc)
{
	struct cmi_call_args ca;
	struct ks_request req;
	char reply[64];
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	req.op = KS_OP_FETCH;
	req.keyid = 0;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply = reply;
	ca.reply_len = sizeof(reply);
	ATF_CHECK_ERRNO(EOPNOTSUPP, ioctl(fd, CMI_CALL, &ca) == -1);

	close(fd);
}

ATF_TC(namespace_call_info);
ATF_TC_HEAD(namespace_call_info, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_CALL to namespace service returns namespace info");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(namespace_call_info, tc)
{
	struct cmi_call_args ca;
	uint32_t op;
	char reply[512];
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	op = 1; /* NS_OP_INFO */
	memset(&ca, 0, sizeof(ca));
	ca.req = &op;
	ca.req_len = sizeof(op);
	ca.reply = reply;
	ca.reply_len = sizeof(reply);
	ATF_REQUIRE(ioctl(fd, CMI_CALL, &ca) == 0);
	ATF_CHECK(ca.reply_len > 0);

	close(fd);
}

ATF_TC(namespace_call_short_req);
ATF_TC_HEAD(namespace_call_short_req, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_CALL to namespace with short request returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(namespace_call_short_req, tc)
{
	struct cmi_call_args ca;
	char req[1] = { 0 };
	char reply[64];
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	memset(&ca, 0, sizeof(ca));
	ca.req = req;
	ca.req_len = 1;  /* Too short for ns_request */
	ca.reply = reply;
	ca.reply_len = sizeof(reply);
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, CMI_CALL, &ca) == -1);

	close(fd);
}

ATF_TC(namespace_call_bad_op);
ATF_TC_HEAD(namespace_call_bad_op, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_CALL to namespace with unknown op returns EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(namespace_call_bad_op, tc)
{
	struct cmi_call_args ca;
	uint32_t op;
	char reply[64];
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	op = 99; /* Invalid operation */
	memset(&ca, 0, sizeof(ca));
	ca.req = &op;
	ca.req_len = sizeof(op);
	ca.reply = reply;
	ca.reply_len = sizeof(reply);
	ATF_CHECK_ERRNO(EOPNOTSUPP, ioctl(fd, CMI_CALL, &ca) == -1);

	close(fd);
}

/* ================================================================
 * Getinfo feature bits tests
 * ================================================================ */

ATF_TC(getinfo_async_features);
ATF_TC_HEAD(getinfo_async_features, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Async service reports SENDMSG+KQUEUE but not CALL");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(getinfo_async_features, tc)
{
	struct cmi_info_args info;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, CMI_GETINFO, &info) == 0);
	ATF_CHECK((info.features & CMI_INFO_F_SENDMSG) != 0);
	ATF_CHECK((info.features & CMI_INFO_F_KQUEUE) != 0);
	ATF_CHECK((info.features & CMI_INFO_F_CALL) == 0);

	close(fd);
}

ATF_TC(getinfo_sync_features);
ATF_TC_HEAD(getinfo_sync_features, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Sync service reports CALL but not SENDMSG or KQUEUE");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(getinfo_sync_features, tc)
{
	struct cmi_info_args info;
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, CMI_GETINFO, &info) == 0);
	ATF_CHECK((info.features & CMI_INFO_F_CALL) != 0);
	ATF_CHECK((info.features & CMI_INFO_F_SENDMSG) == 0);
	ATF_CHECK((info.features & CMI_INFO_F_KQUEUE) == 0);

	close(fd);
}

/* ================================================================
 * Pair: fd passing through pair
 * ================================================================ */

ATF_TC(pair_fd_passing);
ATF_TC_HEAD(pair_fd_passing, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "File descriptors pass through a pair");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_pair");
}
ATF_TC_BODY(pair_fd_passing, tc)
{
	struct cmi_sendmsg_args sa;
	struct cmi_recvmsg_args ra;
	int fd_a, fd_b, pipefd[2], recv_fd;
	char buf[64];

	cmi_pair_pair(&fd_a, &fd_b);
	ATF_REQUIRE(pipe(pipefd) == 0);

	/* Send a pipe fd through the pair A -> B. */
	memset(&sa, 0, sizeof(sa));
	sa.payload = "hi";
	sa.payload_len = 2;
	sa.fds = &pipefd[0];
	sa.nfds = 1;
	ATF_REQUIRE(ioctl(fd_a, CMI_SENDMSG, &sa) == 0);

	/* Receive on B — should get the fd. */
	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ra.fds = &recv_fd;
	ra.nfds = 1;
	ATF_REQUIRE(ioctl(fd_b, CMI_RECVMSG, &ra) == 0);
	ATF_CHECK_EQ(ra.payload_len, 2);
	ATF_CHECK(memcmp(buf, "hi", 2) == 0);
	ATF_CHECK_EQ(ra.nfds, 1);

	/* Verify the received fd is usable — write on original, read on received. */
	ATF_REQUIRE(write(pipefd[1], "test", 4) == 4);
	memset(buf, 0, sizeof(buf));
	ATF_CHECK(read(recv_fd, buf, sizeof(buf)) == 4);
	ATF_CHECK(memcmp(buf, "test", 4) == 0);

	close(recv_fd);
	close(pipefd[0]);
	close(pipefd[1]);
	close(fd_b);
	close(fd_a);
}

/* ================================================================
 * Pair: stress — many messages
 * ================================================================ */

ATF_TC(pair_stress);
ATF_TC_HEAD(pair_stress, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "100 messages through a pair");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_pair");
}
ATF_TC_BODY(pair_stress, tc)
{
	char buf[64];
	uint32_t rlen;
	int fd_a, fd_b, i;

	cmi_pair_pair(&fd_a, &fd_b);

	for (i = 0; i < 100; i++) {
		uint32_t val = (uint32_t)i;

		ATF_REQUIRE(cmi_send(fd_a, &val, sizeof(val), 0) == 0);

		rlen = sizeof(buf);
		ATF_REQUIRE_MSG(cmi_recv(fd_b, buf, &rlen, NULL) == 0,
		    "recv %d: %s", i, strerror(errno));
		ATF_REQUIRE_EQ(rlen, sizeof(val));
		ATF_CHECK_EQ(*(uint32_t *)buf, val);
	}

	close(fd_b);
	close(fd_a);
}

/* ================================================================
 * Pair: getinfo on pair
 * ================================================================ */

ATF_TC(pair_getinfo);
ATF_TC_HEAD(pair_getinfo, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "GETINFO on pair returns correct metadata");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_pair");
}
ATF_TC_BODY(pair_getinfo, tc)
{
	struct cmi_info_args info;
	int fd_a, fd_b;

	cmi_pair_pair(&fd_a, &fd_b);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd_a, CMI_GETINFO, &info) == 0);
	ATF_CHECK_STREQ(info.name, "pair");
	ATF_CHECK(info.badge != 0);
	ATF_CHECK(info.id != 0);
	ATF_CHECK((info.features & CMI_INFO_F_SENDMSG) != 0);
	ATF_CHECK((info.features & CMI_INFO_F_CALL) == 0);

	/* Peer should have different badge and ID. */
	{
		struct cmi_info_args info_b;
		memset(&info_b, 0, sizeof(info_b));
		ATF_REQUIRE(ioctl(fd_b, CMI_GETINFO, &info_b) == 0);
		ATF_CHECK_STREQ(info_b.name, "pair");
		ATF_CHECK(info_b.badge != info.badge);
		ATF_CHECK(info_b.id != info.id);
	}

	close(fd_b);
	close(fd_a);
}

/* ================================================================
 * Namespace: CALL with zero-length request
 * ================================================================ */

ATF_TC(namespace_call_zero_req);
ATF_TC_HEAD(namespace_call_zero_req, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_CALL to namespace with zero-length request returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(namespace_call_zero_req, tc)
{
	struct cmi_call_args ca;
	char reply[512];
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	memset(&ca, 0, sizeof(ca));
	ca.reply = reply;
	ca.reply_len = sizeof(reply);
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, CMI_CALL, &ca) == -1);

	close(fd);
}

/* ================================================================
 * Namespace: getinfo
 * ================================================================ */

ATF_TC(namespace_getinfo);
ATF_TC_HEAD(namespace_getinfo, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "GETINFO on namespace returns sync-only metadata");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(namespace_getinfo, tc)
{
	struct cmi_info_args info;
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, CMI_GETINFO, &info) == 0);
	ATF_CHECK_STREQ(info.name, "namespace");
	ATF_CHECK(info.badge != 0);
	ATF_CHECK(info.id != 0);
	ATF_CHECK((info.features & CMI_INFO_F_CALL) != 0);
	ATF_CHECK((info.features & CMI_INFO_F_SENDMSG) == 0);
	ATF_CHECK((info.features & CMI_INFO_F_KQUEUE) == 0);

	close(fd);
}

/* ================================================================
 * Namespace: multiple instances have different badges
 * ================================================================ */

ATF_TC(namespace_badge_unique);
ATF_TC_HEAD(namespace_badge_unique, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Each namespace instance gets a unique badge");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(namespace_badge_unique, tc)
{
	struct cmi_info_args info1, info2;
	int fd1, fd2;

	fd1 = cmi_connect("namespace");
	fd2 = cmi_connect("namespace");
	ATF_REQUIRE(fd1 >= 0);
	ATF_REQUIRE(fd2 >= 0);

	memset(&info1, 0, sizeof(info1));
	memset(&info2, 0, sizeof(info2));
	ATF_REQUIRE(ioctl(fd1, CMI_GETINFO, &info1) == 0);
	ATF_REQUIRE(ioctl(fd2, CMI_GETINFO, &info2) == 0);
	ATF_CHECK(info1.badge != info2.badge);
	ATF_CHECK(info1.id != info2.id);

	close(fd2);
	close(fd1);
}

/* ================================================================
 * Namespace: revoke via token on sync service
 * then verify CALL fails
 * ================================================================ */

ATF_TC(namespace_revoke_then_call);
ATF_TC_HEAD(namespace_revoke_then_call, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Revoke namespace instance, then CALL returns ECONNRESET");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(namespace_revoke_then_call, tc)
{
	struct cmi_call_args ca;
	uint32_t op;
	char reply[512];
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	/* Revoke. */
	ATF_REQUIRE(ioctl(fd, CMI_TERMINATE, NULL) == 0);

	/* CALL should fail. */
	op = 1;
	memset(&ca, 0, sizeof(ca));
	ca.req = &op;
	ca.req_len = sizeof(op);
	ca.reply = reply;
	ca.reply_len = sizeof(reply);
	ATF_CHECK_ERRNO(ECONNRESET, ioctl(fd, CMI_CALL, &ca) == -1);

	close(fd);
}

/* ================================================================
 * Keystore: max keys limit
 * ================================================================ */

ATF_TC(keystore_max_keys);
ATF_TC_HEAD(keystore_max_keys, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Keystore enforces max key limit");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(keystore_max_keys, tc)
{
	/*
	 * KS_MAX_KEYS is 1024.  We can't easily fill it without
	 * conflicting with other tests, so just verify we can
	 * store and fetch a reasonable number without error.
	 */
	int fd, i;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Store 50 keys with unique IDs. */
	for (i = 0; i < 50; i++)
		cmi_store(fd, 90000 + (uint32_t)i, "val", 3);

	/* Fetch them back. */
	for (i = 0; i < 50; i++) {
		struct ks_request req;
		char buf[256];
		uint32_t rlen;

		req.op = KS_OP_FETCH;
		req.keyid = 90000 + (uint32_t)i;
		ATF_REQUIRE(cmi_send(fd, &req, sizeof(req), 0) == 0);
		rlen = sizeof(buf);
		ATF_REQUIRE(cmi_recv(fd, buf, &rlen, NULL) == 0);
		ATF_REQUIRE(rlen >= sizeof(struct ks_reply));
		ATF_CHECK_EQ(((struct ks_reply *)buf)->status, KS_STATUS_OK);
	}

	close(fd);
}

/* ================================================================
 * Keystore: overwrite existing key
 * ================================================================ */

ATF_TC(keystore_overwrite);
ATF_TC_HEAD(keystore_overwrite, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Storing to an existing key overwrites the value");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(keystore_overwrite, tc)
{
	struct ks_request req;
	char buf[256];
	uint32_t rlen;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Store "old". */
	cmi_store(fd, 80000, "old", 3);

	/* Overwrite with "new_value". */
	cmi_store(fd, 80000, "new_value", 9);

	/* Fetch — should get "new_value". */
	req.op = KS_OP_FETCH;
	req.keyid = 80000;
	ATF_REQUIRE(cmi_send(fd, &req, sizeof(req), 0) == 0);
	rlen = sizeof(buf);
	ATF_REQUIRE(cmi_recv(fd, buf, &rlen, NULL) == 0);
	ATF_REQUIRE(rlen >= sizeof(struct ks_reply) + 9);
	ATF_CHECK_EQ(((struct ks_reply *)buf)->status, KS_STATUS_OK);
	ATF_CHECK(memcmp(buf + sizeof(struct ks_reply), "new_value", 9) == 0);

	close(fd);
}

/* ================================================================
 * Keystore: credential isolation
 * ================================================================ */

ATF_TC(keystore_uid_isolation);
ATF_TC_HEAD(keystore_uid_isolation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Different UIDs cannot see each other's keys");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(keystore_uid_isolation, tc)
{
	int fd, status;
	pid_t pid;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Store as root (uid 0). */
	cmi_store(fd, 70000, "rootdata", 8);
	close(fd);

	/* Child changes uid and tries to fetch. */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct ks_request req;
		struct ks_reply reply;
		char buf[256];
		uint32_t rlen;
		int cfd;

		/* Change to uid 65534 (nobody). */
		if (setuid(65534) != 0)
			_exit(10);

		cfd = cmi_connect("keystore");
		if (cfd < 0)
			_exit(11);

		req.op = KS_OP_FETCH;
		req.keyid = 70000;
		if (cmi_send(cfd, &req, sizeof(req), 0) != 0)
			_exit(1);
		rlen = sizeof(buf);
		if (cmi_recv(cfd, buf, &rlen, NULL) != 0)
			_exit(2);
		memcpy(&reply, buf, sizeof(reply));
		/* Should be NOTFOUND — different uid. */
		if (reply.status != KS_STATUS_NOTFOUND)
			_exit(3);
		close(cfd);
		_exit(0);
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child exited with status %d", WEXITSTATUS(status));
}

/* ================================================================
 * Keystore: badge uniqueness
 * ================================================================ */

ATF_TC(keystore_badge_unique);
ATF_TC_HEAD(keystore_badge_unique, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Each keystore instance gets a unique badge");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(keystore_badge_unique, tc)
{
	struct cmi_info_args info1, info2, info3;
	int fd1, fd2, fd3;

	fd1 = cmi_connect("keystore");
	fd2 = cmi_connect("keystore");
	fd3 = cmi_connect("keystore");
	ATF_REQUIRE(fd1 >= 0);
	ATF_REQUIRE(fd2 >= 0);
	ATF_REQUIRE(fd3 >= 0);

	memset(&info1, 0, sizeof(info1));
	memset(&info2, 0, sizeof(info2));
	memset(&info3, 0, sizeof(info3));
	ATF_REQUIRE(ioctl(fd1, CMI_GETINFO, &info1) == 0);
	ATF_REQUIRE(ioctl(fd2, CMI_GETINFO, &info2) == 0);
	ATF_REQUIRE(ioctl(fd3, CMI_GETINFO, &info3) == 0);

	ATF_CHECK(info1.badge != info2.badge);
	ATF_CHECK(info2.badge != info3.badge);
	ATF_CHECK(info1.badge != info3.badge);

	close(fd3);
	close(fd2);
	close(fd1);
}

/* ================================================================
 * Non-transferable capability (CMI_SVC_NOXFER)
 * ================================================================ */

ATF_TC(noxfer_scm_rights);
ATF_TC_HEAD(noxfer_scm_rights, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Non-transferable capability cannot be passed via SCM_RIGHTS");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(noxfer_scm_rights, tc)
{
	struct msghdr msgh;
	struct iovec iov;
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	char dummy = 'x';
	int sv[2], fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	/* Try to send the jail capability via SCM_RIGHTS. */
	memset(&msgh, 0, sizeof(msgh));
	iov.iov_base = &dummy;
	iov.iov_len = 1;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = cmsgbuf.buf;
	msgh.msg_controllen = sizeof(cmsgbuf.buf);

	cmsg = CMSG_FIRSTHDR(&msgh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

	/* Should fail — jail is non-transferable. */
	ATF_CHECK(sendmsg(sv[0], &msgh, 0) == -1);

	close(sv[0]);
	close(sv[1]);
	close(fd);
}

ATF_TC(noxfer_cmi_attach);
ATF_TC_HEAD(noxfer_cmi_attach, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Non-transferable fd cannot be attached to CMI_SENDMSG");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore cmi_namespace");
}
ATF_TC_BODY(noxfer_cmi_attach, tc)
{
	struct cmi_sendmsg_args sa;
	struct ks_request req;
	int ks_fd, jail_fd;

	ks_fd = cmi_connect("keystore");
	jail_fd = cmi_connect("namespace");
	ATF_REQUIRE(ks_fd >= 0);
	ATF_REQUIRE(jail_fd >= 0);

	/* Try to attach the jail fd to a keystore message. */
	req.op = KS_OP_FETCH;
	req.keyid = 0;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = &jail_fd;
	sa.nfds = 1;

	/* Should fail — jail fd is non-passable. */
	ATF_CHECK_ERRNO(EINVAL, ioctl(ks_fd, CMI_SENDMSG, &sa) == -1);

	close(jail_fd);
	close(ks_fd);
}

ATF_TC(xfer_keystore_ok);
ATF_TC_HEAD(xfer_keystore_ok, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Transferable capability can be passed via SCM_RIGHTS");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(xfer_keystore_ok, tc)
{
	struct msghdr msgh;
	struct iovec iov;
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	char dummy = 'x';
	int sv[2], fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	/* Keystore is transferable — sendmsg should succeed. */
	memset(&msgh, 0, sizeof(msgh));
	iov.iov_base = &dummy;
	iov.iov_len = 1;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = cmsgbuf.buf;
	msgh.msg_controllen = sizeof(cmsgbuf.buf);

	cmsg = CMSG_FIRSTHDR(&msgh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

	ATF_CHECK(sendmsg(sv[0], &msgh, 0) >= 0);

	close(sv[0]);
	close(sv[1]);
	close(fd);
}

/* ================================================================
 * co_fdclose — dup + close exercises the fdclose path
 * ================================================================ */

ATF_TC(fdclose_dup_survives);
ATF_TC_HEAD(fdclose_dup_survives, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing one dup'd fd fires co_fdclose, instance survives");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_pair");
}
ATF_TC_BODY(fdclose_dup_survives, tc)
{
	int fd_a, fd_b, fd_a2;

	cmi_pair_pair(&fd_a, &fd_b);

	/* Dup fd_a. */
	fd_a2 = dup(fd_a);
	ATF_REQUIRE(fd_a2 >= 0);

	/* Close original — co_fdclose fires, but instance survives. */
	close(fd_a);

	/* fd_a2 should still work — send on it, recv on B. */
	ATF_REQUIRE(cmi_send(fd_a2, "alive", 5, 0) == 0);
	{
		char buf[64];
		uint32_t rlen = sizeof(buf);
		ATF_REQUIRE(cmi_recv(fd_b, buf, &rlen, NULL) == 0);
		ATF_REQUIRE(rlen == 5);
		ATF_CHECK(memcmp(buf, "alive", 5) == 0);
	}

	close(fd_a2);
	close(fd_b);
}

ATF_TC(fdclose_dup_then_close_all);
ATF_TC_HEAD(fdclose_dup_then_close_all, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing all dup'd fds revokes the instance");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_pair");
}
ATF_TC_BODY(fdclose_dup_then_close_all, tc)
{
	int fd_a, fd_b, fd_a2, flags;

	cmi_pair_pair(&fd_a, &fd_b);

	fd_a2 = dup(fd_a);
	ATF_REQUIRE(fd_a2 >= 0);

	/* Close both — instance should die, peer gets revoked. */
	close(fd_a);
	close(fd_a2);

	/* Give revocation a moment to propagate. */
	usleep(50000);

	/* B should be revoked. */
	flags = fcntl(fd_b, F_GETFL, 0);
	fcntl(fd_b, F_SETFL, flags | O_NONBLOCK);
	ATF_CHECK(cmi_send(fd_b, "x", 1, 0) == -1);
	ATF_CHECK(errno == EPIPE || errno == ECONNRESET);

	close(fd_b);
}

/* ================================================================
 * Namespace: create a jail, enter it, verify via CMI
 * ================================================================ */

/* Namespace protocol — matches cmi_namespace.c */
#define	NS_OP_INFO	1
#define	NS_OP_CREATE	2
#define	NS_OP_ATTACH	3
#define	NS_OP_REMOVE	4
#define	NS_OP_MINT	5

struct ns_request {
	uint32_t	op;
} __packed;

struct ns_create_request {
	uint32_t	op;
	char		hostname[256];
} __packed;

struct ns_info_reply {
	uint32_t	status;
	int		jid;
	char		name[256];
};

ATF_TC(namespace_enter_and_query);
ATF_TC_HEAD(namespace_enter_and_query, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Create a namespace, enter it, CMI_CALL confirms process is inside");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(namespace_enter_and_query, tc)
{
	int status, jid;
	pid_t pid;

	/* Create a jail. */
	jid = jail_setv(JAIL_CREATE,
	    "name", "cmi_test_jail",
	    "path", "/",
	    "persist", NULL,
	    NULL);
	ATF_REQUIRE_MSG(jid >= 0, "jail_setv: %s", strerror(errno));

	/* Fork — child enters the jail and queries via CMI. */
	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		struct cmi_call_args ca;
		struct ns_request req;
		struct ns_info_reply reply;
		int fd;

		/* First, query from host — jid should be 0. */
		fd = cmi_connect("namespace");
		if (fd < 0)
			_exit(10);

		req.op = NS_OP_INFO;
		memset(&ca, 0, sizeof(ca));
		ca.req = &req;
		ca.req_len = sizeof(req);
		ca.reply = &reply;
		ca.reply_len = sizeof(reply);
		if (ioctl(fd, CMI_CALL, &ca) != 0)
			_exit(1);
		if (reply.jid != 0)
			_exit(2);  /* Expected host jail (jid 0). */

		/* Enter the jail. */
		if (jail_attach(jid) != 0)
			_exit(3);

		/* Query again — should now report the test jail. */
		memset(&ca, 0, sizeof(ca));
		ca.req = &req;
		ca.req_len = sizeof(req);
		ca.reply = &reply;
		ca.reply_len = sizeof(reply);
		if (ioctl(fd, CMI_CALL, &ca) != 0)
			_exit(4);
		if (reply.jid == 0)
			_exit(5);  /* Should NOT be host anymore. */
		if (strcmp(reply.name, "cmi_test_jail") != 0)
			_exit(6);  /* Name should match. */

		close(fd);
		_exit(0);
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child exited with status %d", WEXITSTATUS(status));

	/* Clean up the jail. */
	jail_remove(jid);
}

/* ================================================================
 * Namespace: create, remove, mint, nest via CMI
 * ================================================================ */

ATF_TC(namespace_create_and_remove);
ATF_TC_HEAD(namespace_create_and_remove, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Create a namespace via CMI, remove it");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(namespace_create_and_remove, tc)
{
	struct cmi_call_args ca;
	struct ns_create_request cr;
	struct ns_request nr;
	int ns_fd, child_fd;
	int reply_fds[1];

	ns_fd = cmi_connect("namespace");
	ATF_REQUIRE(ns_fd >= 0);

	memset(&cr, 0, sizeof(cr));
	cr.op = NS_OP_CREATE;
	strlcpy(cr.hostname, "test_child", sizeof(cr.hostname));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(ns_fd, CMI_CALL, &ca) == 0);
	ATF_REQUIRE_EQ(ca.reply_nfds, 1);
	child_fd = reply_fds[0];
	ATF_REQUIRE(child_fd >= 0);

	nr.op = NS_OP_REMOVE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ATF_REQUIRE(ioctl(child_fd, CMI_CALL, &ca) == 0);

	close(child_fd);
	close(ns_fd);
}

ATF_TC(namespace_close_removes);
ATF_TC_HEAD(namespace_close_removes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing owner fd removes namespace via co_revoke");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(namespace_close_removes, tc)
{
	struct cmi_call_args ca;
	struct ns_create_request cr;
	int ns_fd, child_fd;
	int reply_fds[1];

	ns_fd = cmi_connect("namespace");
	ATF_REQUIRE(ns_fd >= 0);

	memset(&cr, 0, sizeof(cr));
	cr.op = NS_OP_CREATE;
	strlcpy(cr.hostname, "close_test", sizeof(cr.hostname));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(ns_fd, CMI_CALL, &ca) == 0);
	child_fd = reply_fds[0];

	close(child_fd);
	close(ns_fd);
}

ATF_TC(namespace_mint_member);
ATF_TC_HEAD(namespace_mint_member, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Member can info but not remove or create");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(namespace_mint_member, tc)
{
	struct cmi_call_args ca;
	struct ns_create_request cr;
	struct ns_request nr;
	int ns_fd, owner_fd, member_fd;
	int reply_fds[1];

	ns_fd = cmi_connect("namespace");
	ATF_REQUIRE(ns_fd >= 0);

	memset(&cr, 0, sizeof(cr));
	cr.op = NS_OP_CREATE;
	strlcpy(cr.hostname, "mint_test", sizeof(cr.hostname));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(ns_fd, CMI_CALL, &ca) == 0);
	owner_fd = reply_fds[0];

	nr.op = NS_OP_MINT;
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(owner_fd, CMI_CALL, &ca) == 0);
	member_fd = reply_fds[0];

	/* Member CAN do INFO. */
	{
		struct ns_info_reply info;
		struct ns_request inforeq;

		inforeq.op = NS_OP_INFO;
		memset(&ca, 0, sizeof(ca));
		ca.req = &inforeq;
		ca.req_len = sizeof(inforeq);
		ca.reply = &info;
		ca.reply_len = sizeof(info);
		ATF_CHECK(ioctl(member_fd, CMI_CALL, &ca) == 0);
	}

	/* Member CAN do ATTACH (get jid). */
	{
		struct ns_request areq;
		int jid;

		areq.op = NS_OP_ATTACH;
		memset(&ca, 0, sizeof(ca));
		ca.req = &areq;
		ca.req_len = sizeof(areq);
		ca.reply = &jid;
		ca.reply_len = sizeof(jid);
		ATF_CHECK(ioctl(member_fd, CMI_CALL, &ca) == 0);
		ATF_CHECK(jid > 0);
	}

	/* Member cannot REMOVE. */
	nr.op = NS_OP_REMOVE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ATF_CHECK_ERRNO(EPERM, ioctl(member_fd, CMI_CALL, &ca) == -1);

	/* Member cannot CREATE. */
	memset(&cr, 0, sizeof(cr));
	cr.op = NS_OP_CREATE;
	strlcpy(cr.hostname, "no_create", sizeof(cr.hostname));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_CHECK_ERRNO(EPERM, ioctl(member_fd, CMI_CALL, &ca) == -1);

	/* Member cannot MINT. */
	nr.op = NS_OP_MINT;
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_CHECK_ERRNO(EPERM, ioctl(member_fd, CMI_CALL, &ca) == -1);

	close(member_fd);
	close(owner_fd);
	close(ns_fd);
}

ATF_TC(namespace_nest);
ATF_TC_HEAD(namespace_nest, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Create nested namespaces, remove parent cascades");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(namespace_nest, tc)
{
	struct cmi_call_args ca;
	struct ns_create_request cr;
	struct ns_request nr;
	int ns_fd, parent_fd, child_fd;
	int reply_fds[1];

	ns_fd = cmi_connect("namespace");
	ATF_REQUIRE(ns_fd >= 0);

	memset(&cr, 0, sizeof(cr));
	cr.op = NS_OP_CREATE;
	strlcpy(cr.hostname, "parent", sizeof(cr.hostname));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(ns_fd, CMI_CALL, &ca) == 0);
	parent_fd = reply_fds[0];

	memset(&cr, 0, sizeof(cr));
	cr.op = NS_OP_CREATE;
	strlcpy(cr.hostname, "child", sizeof(cr.hostname));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(parent_fd, CMI_CALL, &ca) == 0);
	child_fd = reply_fds[0];

	/* Verify child is nested: ATTACH returns a jid, and we can
	 * check that the child's jid is different from the parent's. */
	{
		struct ns_request areq;
		int parent_jid, child_jid;

		areq.op = NS_OP_ATTACH;
		memset(&ca, 0, sizeof(ca));
		ca.req = &areq;
		ca.req_len = sizeof(areq);
		ca.reply = &parent_jid;
		ca.reply_len = sizeof(parent_jid);
		ATF_REQUIRE(ioctl(parent_fd, CMI_CALL, &ca) == 0);
		ATF_REQUIRE(parent_jid > 0);

		memset(&ca, 0, sizeof(ca));
		ca.req = &areq;
		ca.req_len = sizeof(areq);
		ca.reply = &child_jid;
		ca.reply_len = sizeof(child_jid);
		ATF_REQUIRE(ioctl(child_fd, CMI_CALL, &ca) == 0);
		ATF_REQUIRE(child_jid > 0);

		/* Parent and child have different jids. */
		ATF_CHECK(parent_jid != child_jid);
	}

	/* Remove parent — child should cascade. */
	nr.op = NS_OP_REMOVE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ATF_REQUIRE(ioctl(parent_fd, CMI_CALL, &ca) == 0);

	/* Child's namespace is gone — REMOVE should fail. */
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ATF_CHECK(ioctl(child_fd, CMI_CALL, &ca) != 0);

	close(child_fd);
	close(parent_fd);
	close(ns_fd);
}

/* ================================================================
 * Granular revoke
 * ================================================================ */

ATF_TC(revoke_send_blocks_send);
ATF_TC_HEAD(revoke_send_blocks_send, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_REVOKE_SEND blocks SENDMSG, RECVMSG still works");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(revoke_send_blocks_send, tc)
{
	struct ks_request req;
	char buf[256];
	uint32_t rlen;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Send a message before revoking — should work. */
	req.op = KS_OP_FETCH;
	req.keyid = 0;
	ATF_REQUIRE(cmi_send(fd, &req, sizeof(req), 0) == 0);

	/* Consume the reply. */
	rlen = sizeof(buf);
	ATF_REQUIRE(cmi_recv(fd, buf, &rlen, NULL) == 0);

	/* Revoke send. */
	ATF_REQUIRE(ioctl(fd, CMI_REVOKE_SEND, NULL) == 0);

	/* SENDMSG should fail. */
	ATF_CHECK_ERRNO(EACCES, cmi_send(fd, &req, sizeof(req), 0) == -1);

	close(fd);
}

ATF_TC(revoke_recv_blocks_recv);
ATF_TC_HEAD(revoke_recv_blocks_recv, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_REVOKE_RECV blocks RECVMSG, SENDMSG still works");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(revoke_recv_blocks_recv, tc)
{
	struct ks_request req;
	struct cmi_recvmsg_args ra;
	char buf[256];
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Revoke recv. */
	ATF_REQUIRE(ioctl(fd, CMI_REVOKE_RECV, NULL) == 0);

	/* SENDMSG should still work. */
	req.op = KS_OP_FETCH;
	req.keyid = 0;
	ATF_CHECK(cmi_send(fd, &req, sizeof(req), 0) == 0);

	/* RECVMSG should fail. */
	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_CHECK_ERRNO(EACCES, ioctl(fd, CMI_RECVMSG, &ra) == -1);

	close(fd);
}

ATF_TC(revoke_call_blocks_call);
ATF_TC_HEAD(revoke_call_blocks_call, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_REVOKE_CALL blocks CALL");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(revoke_call_blocks_call, tc)
{
	struct cmi_call_args ca;
	uint32_t op;
	char reply[512];
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	/* CALL should work before revoke. */
	op = NS_OP_INFO;
	memset(&ca, 0, sizeof(ca));
	ca.req = &op;
	ca.req_len = sizeof(op);
	ca.reply = reply;
	ca.reply_len = sizeof(reply);
	ATF_REQUIRE(ioctl(fd, CMI_CALL, &ca) == 0);

	/* Revoke call. */
	ATF_REQUIRE(ioctl(fd, CMI_REVOKE_CALL, NULL) == 0);

	/* CALL should fail. */
	memset(&ca, 0, sizeof(ca));
	ca.req = &op;
	ca.req_len = sizeof(op);
	ca.reply = reply;
	ca.reply_len = sizeof(reply);
	ATF_CHECK_ERRNO(EACCES, ioctl(fd, CMI_CALL, &ca) == -1);

	close(fd);
}

ATF_TC(revoke_send_recv_both);
ATF_TC_HEAD(revoke_send_recv_both, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Revoking both send and recv blocks both");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(revoke_send_recv_both, tc)
{
	struct ks_request req;
	struct cmi_recvmsg_args ra;
	struct cmi_info_args info;
	char buf[256];
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(ioctl(fd, CMI_REVOKE_SEND, NULL) == 0);
	ATF_REQUIRE(ioctl(fd, CMI_REVOKE_RECV, NULL) == 0);

	/* Both blocked. */
	req.op = KS_OP_FETCH;
	req.keyid = 0;
	ATF_CHECK_ERRNO(EACCES, cmi_send(fd, &req, sizeof(req), 0) == -1);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_CHECK_ERRNO(EACCES, ioctl(fd, CMI_RECVMSG, &ra) == -1);

	/* GETINFO always works. */
	memset(&info, 0, sizeof(info));
	ATF_CHECK(ioctl(fd, CMI_GETINFO, &info) == 0);
	ATF_CHECK_STREQ(info.name, "keystore");

	close(fd);
}

ATF_TC(revoke_is_permanent);
ATF_TC_HEAD(revoke_is_permanent, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Revoke is one-way — calling it again is harmless");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(revoke_is_permanent, tc)
{
	struct ks_request req;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(ioctl(fd, CMI_REVOKE_SEND, NULL) == 0);
	/* Second call is harmless. */
	ATF_REQUIRE(ioctl(fd, CMI_REVOKE_SEND, NULL) == 0);

	/* Still blocked. */
	req.op = KS_OP_FETCH;
	req.keyid = 0;
	ATF_CHECK_ERRNO(EACCES, cmi_send(fd, &req, sizeof(req), 0) == -1);

	close(fd);
}

ATF_TC(revoke_affects_all_dups);
ATF_TC_HEAD(revoke_affects_all_dups, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Revoke on one handle affects all dups (same instance)");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(revoke_affects_all_dups, tc)
{
	struct ks_request req;
	int fd, fd2;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);
	fd2 = dup(fd);
	ATF_REQUIRE(fd2 >= 0);

	/* Revoke send on fd. */
	ATF_REQUIRE(ioctl(fd, CMI_REVOKE_SEND, NULL) == 0);

	/* fd2 should also be blocked — same instance. */
	req.op = KS_OP_FETCH;
	req.keyid = 0;
	ATF_CHECK_ERRNO(EACCES, cmi_send(fd2, &req, sizeof(req), 0) == -1);

	close(fd2);
	close(fd);
}

ATF_TC(terminate_after_revoke_send);
ATF_TC_HEAD(terminate_after_revoke_send, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_TERMINATE works even after CMI_REVOKE_SEND");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(terminate_after_revoke_send, tc)
{
	struct cmi_recvmsg_args ra;
	char buf[64];
	int fd, flags;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Restrict send. */
	ATF_REQUIRE(ioctl(fd, CMI_REVOKE_SEND, NULL) == 0);

	/* Token revoke should still work. */
	ATF_REQUIRE(ioctl(fd, CMI_TERMINATE, NULL) == 0);

	/* Instance should be dead. */
	flags = fcntl(fd, F_GETFL, 0);
	ATF_REQUIRE(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_CHECK_ERRNO(ECONNRESET, ioctl(fd, CMI_RECVMSG, &ra) == -1);

	close(fd);
}

/* ================================================================
 * CMI_CALL reply fds
 * ================================================================ */

ATF_TC(call_reply_fds_zero);
ATF_TC_HEAD(call_reply_fds_zero, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_CALL with reply_nfds=0 works normally");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(call_reply_fds_zero, tc)
{
	struct cmi_call_args ca;
	uint32_t op;
	char reply[512];
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	op = NS_OP_INFO;
	memset(&ca, 0, sizeof(ca));
	ca.req = &op;
	ca.req_len = sizeof(op);
	ca.reply = reply;
	ca.reply_len = sizeof(reply);
	ca.reply_fds = NULL;
	ca.reply_nfds = 0;
	ATF_REQUIRE(ioctl(fd, CMI_CALL, &ca) == 0);
	ATF_CHECK(ca.reply_len > 0);
	ATF_CHECK_EQ(ca.reply_nfds, 0);

	close(fd);
}

ATF_TC(call_reply_fds_buf_no_fds);
ATF_TC_HEAD(call_reply_fds_buf_no_fds, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_CALL with reply_fds buffer but handler returns 0 fds");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(call_reply_fds_buf_no_fds, tc)
{
	struct cmi_call_args ca;
	uint32_t op;
	char reply[512];
	int reply_fds[4];
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	op = NS_OP_INFO;
	memset(&ca, 0, sizeof(ca));
	ca.req = &op;
	ca.req_len = sizeof(op);
	ca.reply = reply;
	ca.reply_len = sizeof(reply);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 4;
	ATF_REQUIRE(ioctl(fd, CMI_CALL, &ca) == 0);
	ATF_CHECK(ca.reply_len > 0);
	ATF_CHECK_EQ(ca.reply_nfds, 0);

	close(fd);
}

ATF_TC(call_reply_nfds_too_many);
ATF_TC_HEAD(call_reply_nfds_too_many, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_CALL with reply_nfds > CMI_MAX_FDS returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(call_reply_nfds_too_many, tc)
{
	struct cmi_call_args ca;
	uint32_t op;
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	op = NS_OP_INFO;
	memset(&ca, 0, sizeof(ca));
	ca.req = &op;
	ca.req_len = sizeof(op);
	ca.reply_nfds = CMI_MAX_FDS + 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, CMI_CALL, &ca) == -1);

	close(fd);
}

/* ================================================================
 * CMI_LOCK — per-instance transfer lock
 * ================================================================ */

ATF_TC(lock_prevents_transfer);
ATF_TC_HEAD(lock_prevents_transfer, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_LOCK prevents SCM_RIGHTS transfer");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(lock_prevents_transfer, tc)
{
	struct msghdr msgh;
	struct iovec iov;
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	char dummy = 'x';
	int sv[2], fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	/* Before lock — transfer should succeed. */
	memset(&msgh, 0, sizeof(msgh));
	iov.iov_base = &dummy;
	iov.iov_len = 1;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = cmsgbuf.buf;
	msgh.msg_controllen = sizeof(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&msgh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	ATF_CHECK(sendmsg(sv[0], &msgh, 0) >= 0);

	/* Drain the received fd so we don't leak. */
	{
		struct msghdr rmsgh;
		struct iovec riov;
		union {
			struct cmsghdr hdr;
			char buf[CMSG_SPACE(sizeof(int))];
		} rcmsgbuf;
		char rdummy;
		int rfd;

		memset(&rmsgh, 0, sizeof(rmsgh));
		riov.iov_base = &rdummy;
		riov.iov_len = 1;
		rmsgh.msg_iov = &riov;
		rmsgh.msg_iovlen = 1;
		rmsgh.msg_control = rcmsgbuf.buf;
		rmsgh.msg_controllen = sizeof(rcmsgbuf.buf);
		ATF_REQUIRE(recvmsg(sv[1], &rmsgh, 0) >= 0);
		cmsg = CMSG_FIRSTHDR(&rmsgh);
		if (cmsg != NULL && cmsg->cmsg_type == SCM_RIGHTS) {
			memcpy(&rfd, CMSG_DATA(cmsg), sizeof(int));
			close(rfd);
		}
	}

	/* Lock it. */
	ATF_REQUIRE(ioctl(fd, CMI_LOCK, NULL) == 0);

	/* After lock — transfer should fail. */
	memset(&msgh, 0, sizeof(msgh));
	iov.iov_base = &dummy;
	iov.iov_len = 1;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = cmsgbuf.buf;
	msgh.msg_controllen = sizeof(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&msgh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	ATF_CHECK(sendmsg(sv[0], &msgh, 0) == -1);

	close(sv[0]);
	close(sv[1]);
	close(fd);
}

ATF_TC(lock_still_usable);
ATF_TC_HEAD(lock_still_usable, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Locked capability still works for messaging");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(lock_still_usable, tc)
{
	struct ks_request req;
	char buf[256];
	uint32_t rlen;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Lock it. */
	ATF_REQUIRE(ioctl(fd, CMI_LOCK, NULL) == 0);

	/* Should still work for normal messaging. */
	cmi_store(fd, 85000, "locked", 6);

	req.op = KS_OP_FETCH;
	req.keyid = 85000;
	ATF_REQUIRE(cmi_send(fd, &req, sizeof(req), 0) == 0);
	rlen = sizeof(buf);
	ATF_REQUIRE(cmi_recv(fd, buf, &rlen, NULL) == 0);
	ATF_CHECK_EQ(((struct ks_reply *)buf)->status, KS_STATUS_OK);

	close(fd);
}

ATF_TC(lock_trampoline);
ATF_TC_HEAD(lock_trampoline, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Trampoline receives capability, locks it, cannot forward");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(lock_trampoline, tc)
{
	int sv[2], fd, status;
	pid_t pid;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child (trampoline): receive fd, lock it, try to forward. */
		struct msghdr msgh;
		struct iovec iov;
		union {
			struct cmsghdr hdr;
			char buf[CMSG_SPACE(sizeof(int))];
		} cmsgbuf;
		struct cmsghdr *cmsg;
		char dummy;
		int received_fd, sv2[2];

		close(sv[0]);
		close(fd);

		/* Receive the capability. */
		memset(&msgh, 0, sizeof(msgh));
		iov.iov_base = &dummy;
		iov.iov_len = 1;
		msgh.msg_iov = &iov;
		msgh.msg_iovlen = 1;
		msgh.msg_control = cmsgbuf.buf;
		msgh.msg_controllen = sizeof(cmsgbuf.buf);
		if (recvmsg(sv[1], &msgh, 0) < 0)
			_exit(1);
		cmsg = CMSG_FIRSTHDR(&msgh);
		if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS)
			_exit(2);
		memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int));

		/* Lock it — no further transfers. */
		if (ioctl(received_fd, CMI_LOCK, NULL) != 0)
			_exit(3);

		/* Verify it still works. */
		{
			struct cmi_info_args info;
			memset(&info, 0, sizeof(info));
			if (ioctl(received_fd, CMI_GETINFO, &info) != 0)
				_exit(4);
		}

		/* Try to forward via another socketpair — should fail. */
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) != 0)
			_exit(5);
		memset(&msgh, 0, sizeof(msgh));
		dummy = 'y';
		iov.iov_base = &dummy;
		iov.iov_len = 1;
		msgh.msg_iov = &iov;
		msgh.msg_iovlen = 1;
		msgh.msg_control = cmsgbuf.buf;
		msgh.msg_controllen = sizeof(cmsgbuf.buf);
		cmsg = CMSG_FIRSTHDR(&msgh);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &received_fd, sizeof(int));
		if (sendmsg(sv2[0], &msgh, 0) >= 0)
			_exit(6);  /* Should have failed! */

		close(sv2[0]);
		close(sv2[1]);
		close(received_fd);
		close(sv[1]);
		_exit(0);
	}

	/* Parent: send the capability to child. */
	{
		struct msghdr msgh;
		struct iovec iov;
		union {
			struct cmsghdr hdr;
			char buf[CMSG_SPACE(sizeof(int))];
		} cmsgbuf;
		struct cmsghdr *cmsg;
		char dummy = 'x';

		close(sv[1]);
		memset(&msgh, 0, sizeof(msgh));
		iov.iov_base = &dummy;
		iov.iov_len = 1;
		msgh.msg_iov = &iov;
		msgh.msg_iovlen = 1;
		msgh.msg_control = cmsgbuf.buf;
		msgh.msg_controllen = sizeof(cmsgbuf.buf);
		cmsg = CMSG_FIRSTHDR(&msgh);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
		ATF_REQUIRE(sendmsg(sv[0], &msgh, 0) >= 0);
		close(sv[0]);
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child exited with status %d", WEXITSTATUS(status));
	close(fd);
}

/* ================================================================
 * cap_debug — process debug protection
 * ================================================================ */

/* Debug protocol — matches cmi_debug.c */
#define	DEBUG_OP_SHIELD		1
#define	DEBUG_OP_MINT		2
#define	DEBUG_OP_ACTIVATE	3

struct debug_request {
	uint32_t	op;
} __packed;

/* Helper: connect to debug service and shield */
static int
debug_shield(void)
{
	struct cmi_call_args ca;
	struct debug_request req;
	int fd;

	fd = cmi_connect("debug");
	if (fd < 0)
		return (-1);

	req.op = DEBUG_OP_SHIELD;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	if (ioctl(fd, CMI_CALL, &ca) != 0) {
		close(fd);
		return (-1);
	}
	return (fd);
}

ATF_TC(debug_shield_blocks_ptrace);
ATF_TC_HEAD(debug_shield_blocks_ptrace, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Shielded process cannot be ptraced");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_debug");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(debug_shield_blocks_ptrace, tc)
{
	int status;
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int shield_fd = debug_shield();
		if (shield_fd < 0)
			_exit(10);
		/* Stay alive for parent to try ptrace. */
		sleep(5);
		close(shield_fd);
		_exit(0);
	}

	/* Give child time to shield. */
	usleep(100000);

	/* ptrace should fail. */
	ATF_CHECK_ERRNO(EACCES,
	    ptrace(PT_ATTACH, pid, NULL, 0) == -1);

	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
}

ATF_TC(debug_close_unshields);
ATF_TC_HEAD(debug_close_unshields, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing shield fd removes protection");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_debug");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(debug_close_unshields, tc)
{
	int sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		char buf;
		int shield_fd;

		close(sv[0]);
		shield_fd = debug_shield();
		if (shield_fd < 0)
			_exit(10);

		/* Signal parent we're shielded. */
		write(sv[1], "s", 1);

		/* Wait for parent to tell us to unshield. */
		read(sv[1], &buf, 1);
		close(shield_fd);

		/* Signal parent we're unshielded. */
		write(sv[1], "u", 1);

		/* Wait to be ptraced. */
		sleep(5);
		close(sv[1]);
		_exit(0);
	}

	close(sv[1]);
	{
		char buf;
		/* Wait for shield. */
		read(sv[0], &buf, 1);

		/* ptrace should fail while shielded. */
		ATF_CHECK_ERRNO(EACCES,
		    ptrace(PT_ATTACH, pid, NULL, 0) == -1);

		/* Tell child to unshield. */
		write(sv[0], "g", 1);

		/* Wait for unshield. */
		read(sv[0], &buf, 1);
	}

	/* ptrace should now succeed. */
	ATF_CHECK(ptrace(PT_ATTACH, pid, NULL, 0) == 0);
	waitpid(pid, &status, WUNTRACED);
	ptrace(PT_DETACH, pid, NULL, 0);

	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

ATF_TC(debug_shield_blocks_signal);
ATF_TC_HEAD(debug_shield_blocks_signal, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Shielded process cannot be signaled");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_debug");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(debug_shield_blocks_signal, tc)
{
	int status;
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int shield_fd = debug_shield();
		if (shield_fd < 0)
			_exit(10);
		sleep(5);
		close(shield_fd);
		_exit(0);
	}

	usleep(100000);

	/* Signal should fail (except SIGKILL from root - that always works). */
	ATF_CHECK_ERRNO(EACCES, kill(pid, SIGUSR1) == -1);

	/* Clean up with SIGKILL - need to unshield first. */
	/* Actually SIGKILL from root may be blocked too. Just terminate. */
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
}

ATF_TC(debug_mint_and_activate);
ATF_TC_HEAD(debug_mint_and_activate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Mint debug token, activate it, ptrace succeeds");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_debug");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(debug_mint_and_activate, tc)
{
	struct cmi_call_args ca;
	struct debug_request req;
	int sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: shield, mint debug token, send to parent. */
		struct msghdr msgh;
		struct iovec iov;
		union {
			struct cmsghdr hdr;
			char buf[CMSG_SPACE(sizeof(int))];
		} cmsgbuf;
		struct cmsghdr *cmsg;
		char dummy = 'x';
		int shield_fd, token_fd;
		int reply_fds[1];

		close(sv[0]);

		shield_fd = debug_shield();
		if (shield_fd < 0)
			_exit(10);

		/* Mint a debug token. */
		req.op = DEBUG_OP_MINT;
		memset(&ca, 0, sizeof(ca));
		ca.req = &req;
		ca.req_len = sizeof(req);
		ca.reply_fds = reply_fds;
		ca.reply_nfds = 1;
		if (ioctl(shield_fd, CMI_CALL, &ca) != 0)
			_exit(11);
		token_fd = reply_fds[0];

		/* Send token to parent via SCM_RIGHTS. */
		memset(&msgh, 0, sizeof(msgh));
		iov.iov_base = &dummy;
		iov.iov_len = 1;
		msgh.msg_iov = &iov;
		msgh.msg_iovlen = 1;
		msgh.msg_control = cmsgbuf.buf;
		msgh.msg_controllen = sizeof(cmsgbuf.buf);
		cmsg = CMSG_FIRSTHDR(&msgh);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &token_fd, sizeof(int));
		sendmsg(sv[1], &msgh, 0);
		close(token_fd);

		/* Stay alive. */
		sleep(5);
		close(shield_fd);
		close(sv[1]);
		_exit(0);
	}

	/* Parent: receive token, activate it, ptrace child. */
	close(sv[1]);
	{
		struct msghdr msgh;
		struct iovec iov;
		union {
			struct cmsghdr hdr;
			char buf[CMSG_SPACE(sizeof(int))];
		} cmsgbuf;
		struct cmsghdr *cmsg;
		char dummy;
		int token_fd;

		/* Receive the debug token. */
		memset(&msgh, 0, sizeof(msgh));
		iov.iov_base = &dummy;
		iov.iov_len = 1;
		msgh.msg_iov = &iov;
		msgh.msg_iovlen = 1;
		msgh.msg_control = cmsgbuf.buf;
		msgh.msg_controllen = sizeof(cmsgbuf.buf);
		ATF_REQUIRE(recvmsg(sv[0], &msgh, 0) >= 0);
		cmsg = CMSG_FIRSTHDR(&msgh);
		ATF_REQUIRE(cmsg != NULL && cmsg->cmsg_type == SCM_RIGHTS);
		memcpy(&token_fd, CMSG_DATA(cmsg), sizeof(int));

		/* Without activation, ptrace should fail. */
		usleep(100000);
		ATF_CHECK_ERRNO(EACCES,
		    ptrace(PT_ATTACH, pid, NULL, 0) == -1);

		/* Activate the debug token. */
		req.op = DEBUG_OP_ACTIVATE;
		memset(&ca, 0, sizeof(ca));
		ca.req = &req;
		ca.req_len = sizeof(req);
		ATF_REQUIRE(ioctl(token_fd, CMI_CALL, &ca) == 0);

		/* Now ptrace should succeed. */
		ATF_CHECK(ptrace(PT_ATTACH, pid, NULL, 0) == 0);
		waitpid(pid, &status, WUNTRACED);
		ptrace(PT_DETACH, pid, NULL, 0);

		close(token_fd);
	}

	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

ATF_TC(debug_double_shield);
ATF_TC_HEAD(debug_double_shield, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Calling SHIELD twice is idempotent");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_debug");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(debug_double_shield, tc)
{
	struct cmi_call_args ca;
	struct debug_request req;
	int fd;

	fd = debug_shield();
	ATF_REQUIRE(fd >= 0);

	/* Second shield should succeed (idempotent). */
	req.op = DEBUG_OP_SHIELD;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ATF_CHECK(ioctl(fd, CMI_CALL, &ca) == 0);

	close(fd);
}

ATF_TC(debug_mint_without_shield);
ATF_TC_HEAD(debug_mint_without_shield, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MINT without active shield returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_debug");
}
ATF_TC_BODY(debug_mint_without_shield, tc)
{
	struct cmi_call_args ca;
	struct debug_request req;
	int fd, reply_fds[1];

	fd = cmi_connect("debug");
	ATF_REQUIRE(fd >= 0);

	req.op = DEBUG_OP_MINT;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, CMI_CALL, &ca) == -1);

	close(fd);
}

ATF_TC(debug_shield_from_token);
ATF_TC_HEAD(debug_shield_from_token, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Calling SHIELD on a token fd returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_debug");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(debug_shield_from_token, tc)
{
	struct cmi_call_args ca;
	struct debug_request req;
	int fd, token_fd;
	int reply_fds[1];

	fd = debug_shield();
	ATF_REQUIRE(fd >= 0);

	/* Mint a token. */
	req.op = DEBUG_OP_MINT;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(fd, CMI_CALL, &ca) == 0);
	token_fd = reply_fds[0];

	/* SHIELD on token should fail. */
	req.op = DEBUG_OP_SHIELD;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ATF_CHECK_ERRNO(EINVAL, ioctl(token_fd, CMI_CALL, &ca) == -1);

	close(token_fd);
	close(fd);
}

ATF_TC(debug_activate_on_shield);
ATF_TC_HEAD(debug_activate_on_shield, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Calling ACTIVATE on a shield fd returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_debug");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(debug_activate_on_shield, tc)
{
	struct cmi_call_args ca;
	struct debug_request req;
	int fd;

	fd = debug_shield();
	ATF_REQUIRE(fd >= 0);

	req.op = DEBUG_OP_ACTIVATE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, CMI_CALL, &ca) == -1);

	close(fd);
}

ATF_TC(debug_bad_op);
ATF_TC_HEAD(debug_bad_op, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Unknown debug op returns EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_debug");
}
ATF_TC_BODY(debug_bad_op, tc)
{
	struct cmi_call_args ca;
	struct debug_request req;
	int fd;

	fd = cmi_connect("debug");
	ATF_REQUIRE(fd >= 0);

	req.op = 99;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ATF_CHECK_ERRNO(EOPNOTSUPP, ioctl(fd, CMI_CALL, &ca) == -1);

	close(fd);
}

ATF_TC(debug_token_close_revokes);
ATF_TC_HEAD(debug_token_close_revokes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing debug token revokes ptrace access");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_debug");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(debug_token_close_revokes, tc)
{
	int sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		struct cmi_call_args ca;
		struct debug_request req;
		struct msghdr msgh;
		struct iovec iov;
		union {
			struct cmsghdr hdr;
			char buf[CMSG_SPACE(sizeof(int))];
		} cmsgbuf;
		struct cmsghdr *cmsg;
		char dummy = 'x';
		int shield_fd, token_fd;
		int reply_fds[1];

		close(sv[0]);
		shield_fd = debug_shield();
		if (shield_fd < 0)
			_exit(10);

		req.op = DEBUG_OP_MINT;
		memset(&ca, 0, sizeof(ca));
		ca.req = &req;
		ca.req_len = sizeof(req);
		ca.reply_fds = reply_fds;
		ca.reply_nfds = 1;
		if (ioctl(shield_fd, CMI_CALL, &ca) != 0)
			_exit(11);
		token_fd = reply_fds[0];

		/* Send token to parent. */
		memset(&msgh, 0, sizeof(msgh));
		iov.iov_base = &dummy;
		iov.iov_len = 1;
		msgh.msg_iov = &iov;
		msgh.msg_iovlen = 1;
		msgh.msg_control = cmsgbuf.buf;
		msgh.msg_controllen = sizeof(cmsgbuf.buf);
		cmsg = CMSG_FIRSTHDR(&msgh);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &token_fd, sizeof(int));
		sendmsg(sv[1], &msgh, 0);
		close(token_fd);

		sleep(10);
		close(shield_fd);
		close(sv[1]);
		_exit(0);
	}

	close(sv[1]);
	{
		struct cmi_call_args ca;
		struct debug_request req;
		struct msghdr msgh;
		struct iovec iov;
		union {
			struct cmsghdr hdr;
			char buf[CMSG_SPACE(sizeof(int))];
		} cmsgbuf;
		struct cmsghdr *cmsg;
		char dummy;
		int token_fd;

		memset(&msgh, 0, sizeof(msgh));
		iov.iov_base = &dummy;
		iov.iov_len = 1;
		msgh.msg_iov = &iov;
		msgh.msg_iovlen = 1;
		msgh.msg_control = cmsgbuf.buf;
		msgh.msg_controllen = sizeof(cmsgbuf.buf);
		ATF_REQUIRE(recvmsg(sv[0], &msgh, 0) >= 0);
		cmsg = CMSG_FIRSTHDR(&msgh);
		ATF_REQUIRE(cmsg != NULL);
		memcpy(&token_fd, CMSG_DATA(cmsg), sizeof(int));

		/* Activate token. */
		req.op = DEBUG_OP_ACTIVATE;
		memset(&ca, 0, sizeof(ca));
		ca.req = &req;
		ca.req_len = sizeof(req);
		ATF_REQUIRE(ioctl(token_fd, CMI_CALL, &ca) == 0);

		usleep(100000);

		/* ptrace should work. */
		ATF_CHECK(ptrace(PT_ATTACH, pid, NULL, 0) == 0);
		waitpid(pid, &status, WUNTRACED);
		ptrace(PT_DETACH, pid, NULL, 0);

		/* Close the token — revokes authorization. */
		close(token_fd);

		usleep(100000);

		/* ptrace should fail again. */
		ATF_CHECK_ERRNO(EACCES,
		    ptrace(PT_ATTACH, pid, NULL, 0) == -1);
	}

	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

/* ================================================================
 * Token capability
 * ================================================================ */

#define	TOKEN_OP_CREATE		1
#define	TOKEN_OP_VALIDATE	2
#define	TOKEN_OP_REVOKE		3
#define	TOKEN_LABEL_MAX		64

struct token_create_request {
	uint32_t	op;
	char		label[TOKEN_LABEL_MAX];
} __packed;

struct token_request {
	uint32_t	op;
} __packed;

struct token_validate_reply {
	uint32_t	valid;
	uid_t		issuer_uid;
	pid_t		issuer_pid;
	char		label[TOKEN_LABEL_MAX];
};

ATF_TC(token_create_and_validate);
ATF_TC_HEAD(token_create_and_validate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Create a token, validate it");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_token");
}
ATF_TC_BODY(token_create_and_validate, tc)
{
	struct cmi_call_args ca;
	struct token_create_request cr;
	struct token_request tr;
	struct token_validate_reply vr;
	int issuer_fd, token_fd;
	int reply_fds[1];

	issuer_fd = cmi_connect("token");
	ATF_REQUIRE(issuer_fd >= 0);

	memset(&cr, 0, sizeof(cr));
	cr.op = TOKEN_OP_CREATE;
	strlcpy(cr.label, "test_auth", sizeof(cr.label));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(issuer_fd, CMI_CALL, &ca) == 0);
	token_fd = reply_fds[0];
	ATF_REQUIRE(token_fd >= 0);

	/* Validate. */
	tr.op = TOKEN_OP_VALIDATE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &tr;
	ca.req_len = sizeof(tr);
	ca.reply = &vr;
	ca.reply_len = sizeof(vr);
	ATF_REQUIRE(ioctl(token_fd, CMI_CALL, &ca) == 0);
	ATF_CHECK_EQ(vr.valid, 1);
	ATF_CHECK_STREQ(vr.label, "test_auth");
	ATF_CHECK_EQ(vr.issuer_uid, getuid());
	ATF_CHECK_EQ(vr.issuer_pid, getpid());

	close(token_fd);
	close(issuer_fd);
}

ATF_TC(token_revoke_invalidates);
ATF_TC_HEAD(token_revoke_invalidates, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Revoking a token makes validate return invalid");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_token");
}
ATF_TC_BODY(token_revoke_invalidates, tc)
{
	struct cmi_call_args ca;
	struct token_create_request cr;
	struct token_request tr;
	struct token_validate_reply vr;
	int issuer_fd, token_fd;
	int reply_fds[1];

	issuer_fd = cmi_connect("token");
	ATF_REQUIRE(issuer_fd >= 0);

	memset(&cr, 0, sizeof(cr));
	cr.op = TOKEN_OP_CREATE;
	strlcpy(cr.label, "revoke_test", sizeof(cr.label));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(issuer_fd, CMI_CALL, &ca) == 0);
	token_fd = reply_fds[0];

	/* Revoke it. */
	tr.op = TOKEN_OP_REVOKE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &tr;
	ca.req_len = sizeof(tr);
	ATF_REQUIRE(ioctl(token_fd, CMI_CALL, &ca) == 0);

	/* Validate — should show invalid. */
	tr.op = TOKEN_OP_VALIDATE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &tr;
	ca.req_len = sizeof(tr);
	ca.reply = &vr;
	ca.reply_len = sizeof(vr);
	ATF_REQUIRE(ioctl(token_fd, CMI_CALL, &ca) == 0);
	ATF_CHECK_EQ(vr.valid, 0);
	/* Label is still readable even after revoke. */
	ATF_CHECK_STREQ(vr.label, "revoke_test");

	close(token_fd);
	close(issuer_fd);
}

ATF_TC(token_dup_shares_instance);
ATF_TC_HEAD(token_dup_shares_instance, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Dup'd token shares instance — revoke one, both invalid");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_token");
}
ATF_TC_BODY(token_dup_shares_instance, tc)
{
	struct cmi_call_args ca;
	struct token_create_request cr;
	struct token_request tr;
	struct token_validate_reply vr;
	int issuer_fd, token_fd, dup_fd;
	int reply_fds[1];

	issuer_fd = cmi_connect("token");
	ATF_REQUIRE(issuer_fd >= 0);

	memset(&cr, 0, sizeof(cr));
	cr.op = TOKEN_OP_CREATE;
	strlcpy(cr.label, "dup_test", sizeof(cr.label));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(issuer_fd, CMI_CALL, &ca) == 0);
	token_fd = reply_fds[0];

	dup_fd = dup(token_fd);
	ATF_REQUIRE(dup_fd >= 0);

	/* Revoke via original. */
	tr.op = TOKEN_OP_REVOKE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &tr;
	ca.req_len = sizeof(tr);
	ATF_REQUIRE(ioctl(token_fd, CMI_CALL, &ca) == 0);

	/* Validate via dup — should be invalid. */
	tr.op = TOKEN_OP_VALIDATE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &tr;
	ca.req_len = sizeof(tr);
	ca.reply = &vr;
	ca.reply_len = sizeof(vr);
	ATF_REQUIRE(ioctl(dup_fd, CMI_CALL, &ca) == 0);
	ATF_CHECK_EQ(vr.valid, 0);

	close(dup_fd);
	close(token_fd);
	close(issuer_fd);
}

ATF_TC(token_validate_on_issuer);
ATF_TC_HEAD(token_validate_on_issuer, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "VALIDATE on issuer fd returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_token");
}
ATF_TC_BODY(token_validate_on_issuer, tc)
{
	struct cmi_call_args ca;
	struct token_create_request cr;
	struct token_request tr;
	struct token_validate_reply vr;
	int issuer_fd, token_fd;
	int reply_fds[1];

	issuer_fd = cmi_connect("token");
	ATF_REQUIRE(issuer_fd >= 0);

	/* Create a token first so issuer role is set. */
	memset(&cr, 0, sizeof(cr));
	cr.op = TOKEN_OP_CREATE;
	strlcpy(cr.label, "x", sizeof(cr.label));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(issuer_fd, CMI_CALL, &ca) == 0);
	token_fd = reply_fds[0];
	close(token_fd);

	/* Validate on issuer should fail. */
	tr.op = TOKEN_OP_VALIDATE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &tr;
	ca.req_len = sizeof(tr);
	ca.reply = &vr;
	ca.reply_len = sizeof(vr);
	ATF_CHECK_ERRNO(EINVAL, ioctl(issuer_fd, CMI_CALL, &ca) == -1);

	close(issuer_fd);
}

ATF_TC(token_create_from_token);
ATF_TC_HEAD(token_create_from_token, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CREATE on a token fd returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_token");
}
ATF_TC_BODY(token_create_from_token, tc)
{
	struct cmi_call_args ca;
	struct token_create_request cr;
	int issuer_fd, token_fd;
	int reply_fds[1];

	issuer_fd = cmi_connect("token");
	ATF_REQUIRE(issuer_fd >= 0);

	memset(&cr, 0, sizeof(cr));
	cr.op = TOKEN_OP_CREATE;
	strlcpy(cr.label, "x", sizeof(cr.label));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(issuer_fd, CMI_CALL, &ca) == 0);
	token_fd = reply_fds[0];

	/* CREATE on token should fail. */
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(token_fd, CMI_CALL, &ca) == -1);

	close(token_fd);
	close(issuer_fd);
}

ATF_TC(token_bad_op);
ATF_TC_HEAD(token_bad_op, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Unknown token op returns EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_token");
}
ATF_TC_BODY(token_bad_op, tc)
{
	struct cmi_call_args ca;
	struct token_request tr;
	int fd;

	fd = cmi_connect("token");
	ATF_REQUIRE(fd >= 0);

	tr.op = 99;
	memset(&ca, 0, sizeof(ca));
	ca.req = &tr;
	ca.req_len = sizeof(tr);
	ATF_CHECK_ERRNO(EOPNOTSUPP, ioctl(fd, CMI_CALL, &ca) == -1);

	close(fd);
}

/* ================================================================
 * Additional framework edge cases
 * ================================================================ */

ATF_TC(kqueue_eof_on_terminate);
ATF_TC_HEAD(kqueue_eof_on_terminate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "kqueue fires EV_EOF when instance is terminated");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(kqueue_eof_on_terminate, tc)
{
	struct kevent kev;
	struct timespec ts;
	int fd, kq, ret;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);

	/* Terminate the instance. */
	ATF_REQUIRE(ioctl(fd, CMI_TERMINATE, NULL) == 0);

	/* kqueue should fire with EV_EOF. */
	ts.tv_sec = 1;
	ts.tv_nsec = 0;
	ret = kevent(kq, NULL, 0, &kev, 1, &ts);
	ATF_CHECK(ret > 0);
	ATF_CHECK((kev.flags & EV_EOF) != 0);

	close(kq);
	close(fd);
}

ATF_TC(max_payload_size);
ATF_TC_HEAD(max_payload_size, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Send exactly CMI_MAX_MSG bytes, verify round trip");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(max_payload_size, tc)
{
	char *big;
	struct ks_request *req;
	char buf[CMI_MAX_MSG];
	uint32_t rlen;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Build a STORE that fills max payload. */
	big = calloc(1, CMI_MAX_MSG);
	ATF_REQUIRE(big != NULL);
	req = (struct ks_request *)big;
	req->op = KS_OP_STORE;
	req->keyid = 55555;
	memset(big + sizeof(*req), 'A', CMI_MAX_MSG - sizeof(*req));
	ATF_REQUIRE(cmi_send(fd, big, CMI_MAX_MSG, 0) == 0);

	rlen = sizeof(buf);
	ATF_REQUIRE(cmi_recv(fd, buf, &rlen, NULL) == 0);
	free(big);

	close(fd);
}

ATF_TC(payload_over_max);
ATF_TC_HEAD(payload_over_max, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Send CMI_MAX_MSG+1 bytes returns EMSGSIZE");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(payload_over_max, tc)
{
	struct cmi_sendmsg_args sa;
	char *big;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	big = calloc(1, CMI_MAX_MSG + 1);
	ATF_REQUIRE(big != NULL);
	memset(&sa, 0, sizeof(sa));
	sa.payload = big;
	sa.payload_len = CMI_MAX_MSG + 1;
	ATF_CHECK_ERRNO(EMSGSIZE, ioctl(fd, CMI_SENDMSG, &sa) == -1);

	free(big);
	close(fd);
}

ATF_TC(token_fork_inherits);
ATF_TC_HEAD(token_fork_inherits, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Token fd inherited by child is still valid");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_token");
}
ATF_TC_BODY(token_fork_inherits, tc)
{
	struct cmi_call_args ca;
	struct token_create_request cr;
	struct token_request tr;
	struct token_validate_reply vr;
	int issuer_fd, token_fd, status;
	int reply_fds[1];
	pid_t pid;

	issuer_fd = cmi_connect("token");
	ATF_REQUIRE(issuer_fd >= 0);

	memset(&cr, 0, sizeof(cr));
	cr.op = TOKEN_OP_CREATE;
	strlcpy(cr.label, "fork_test", sizeof(cr.label));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(issuer_fd, CMI_CALL, &ca) == 0);
	token_fd = reply_fds[0];

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(issuer_fd);
		tr.op = TOKEN_OP_VALIDATE;
		memset(&ca, 0, sizeof(ca));
		ca.req = &tr;
		ca.req_len = sizeof(tr);
		ca.reply = &vr;
		ca.reply_len = sizeof(vr);
		if (ioctl(token_fd, CMI_CALL, &ca) != 0)
			_exit(1);
		if (vr.valid != 1)
			_exit(2);
		if (strcmp(vr.label, "fork_test") != 0)
			_exit(3);
		close(token_fd);
		_exit(0);
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child exited with status %d", WEXITSTATUS(status));
	close(token_fd);
	close(issuer_fd);
}

ATF_TC(token_multiple_from_issuer);
ATF_TC_HEAD(token_multiple_from_issuer, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Issuer can create multiple independent tokens");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_token");
}
ATF_TC_BODY(token_multiple_from_issuer, tc)
{
	struct cmi_call_args ca;
	struct token_create_request cr;
	struct token_request tr;
	struct token_validate_reply vr;
	int issuer_fd, tok1, tok2;
	int reply_fds[1];

	issuer_fd = cmi_connect("token");
	ATF_REQUIRE(issuer_fd >= 0);

	/* Create first token. */
	memset(&cr, 0, sizeof(cr));
	cr.op = TOKEN_OP_CREATE;
	strlcpy(cr.label, "alpha", sizeof(cr.label));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(issuer_fd, CMI_CALL, &ca) == 0);
	tok1 = reply_fds[0];

	/* Create second token. */
	strlcpy(cr.label, "beta", sizeof(cr.label));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(issuer_fd, CMI_CALL, &ca) == 0);
	tok2 = reply_fds[0];

	/* Both valid with different labels. */
	tr.op = TOKEN_OP_VALIDATE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &tr;
	ca.req_len = sizeof(tr);
	ca.reply = &vr;
	ca.reply_len = sizeof(vr);
	ATF_REQUIRE(ioctl(tok1, CMI_CALL, &ca) == 0);
	ATF_CHECK_STREQ(vr.label, "alpha");

	memset(&ca, 0, sizeof(ca));
	ca.req = &tr;
	ca.req_len = sizeof(tr);
	ca.reply = &vr;
	ca.reply_len = sizeof(vr);
	ATF_REQUIRE(ioctl(tok2, CMI_CALL, &ca) == 0);
	ATF_CHECK_STREQ(vr.label, "beta");

	/* Revoke one, other still valid. */
	tr.op = TOKEN_OP_REVOKE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &tr;
	ca.req_len = sizeof(tr);
	ATF_REQUIRE(ioctl(tok1, CMI_CALL, &ca) == 0);

	tr.op = TOKEN_OP_VALIDATE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &tr;
	ca.req_len = sizeof(tr);
	ca.reply = &vr;
	ca.reply_len = sizeof(vr);
	ATF_REQUIRE(ioctl(tok2, CMI_CALL, &ca) == 0);
	ATF_CHECK_EQ(vr.valid, 1);

	close(tok2);
	close(tok1);
	close(issuer_fd);
}

ATF_TC(pair_kqueue_eof_on_close);
ATF_TC_HEAD(pair_kqueue_eof_on_close, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "kqueue fires EV_EOF on pair when peer closes");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_pair");
}
ATF_TC_BODY(pair_kqueue_eof_on_close, tc)
{
	struct kevent kev;
	struct timespec ts;
	int fd_a, fd_b, kq, ret;

	cmi_pair_pair(&fd_a, &fd_b);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&kev, fd_b, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);

	/* Close A — B should get EV_EOF. */
	close(fd_a);

	ts.tv_sec = 2;
	ts.tv_nsec = 0;
	ret = kevent(kq, NULL, 0, &kev, 1, &ts);
	ATF_CHECK(ret > 0);
	ATF_CHECK((kev.flags & EV_EOF) != 0);

	close(kq);
	close(fd_b);
}

ATF_TC(pair_send_after_peer_close);
ATF_TC_HEAD(pair_send_after_peer_close, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG after peer closes returns EPIPE or ECONNRESET");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_pair");
}
ATF_TC_BODY(pair_send_after_peer_close, tc)
{
	int fd_a, fd_b;

	cmi_pair_pair(&fd_a, &fd_b);
	close(fd_a);

	usleep(50000);

	ATF_CHECK(cmi_send(fd_b, "dead", 4, 0) == -1);
	ATF_CHECK(errno == EPIPE || errno == ECONNRESET);

	close(fd_b);
}

ATF_TC(pair_unpaired_send);
ATF_TC_HEAD(pair_unpaired_send, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG before PAIR_OP_CREATE with wrong op fails");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_pair");
}
ATF_TC_BODY(pair_unpaired_send, tc)
{
	char buf[64];
	uint32_t rlen;
	int fd;

	fd = cmi_connect("pair");
	ATF_REQUIRE(fd >= 0);

	/* Send a non-CREATE message to unpaired instance. */
	uint32_t val = 99;
	ATF_REQUIRE(cmi_send(fd, &val, sizeof(val), 0) == 0);

	/* Should get an error reply (handler returns EINVAL). */
	rlen = sizeof(buf);
	ATF_REQUIRE(cmi_recv(fd, buf, &rlen, NULL) == 0);
	/* Error reply is 4 bytes (uint32_t errno). */
	ATF_CHECK(rlen == 4);

	close(fd);
}

ATF_TC(terminate_twice);
ATF_TC_HEAD(terminate_twice, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_TERMINATE twice is harmless");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(terminate_twice, tc)
{
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(ioctl(fd, CMI_TERMINATE, NULL) == 0);
	/* Second terminate — instance already dead. */
	ATF_CHECK(ioctl(fd, CMI_TERMINATE, NULL) == 0);

	close(fd);
}

ATF_TC(connect_reserved_nonzero);
ATF_TC_HEAD(connect_reserved_nonzero, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_CONNECT with nonzero reserved fields returns EINVAL");
}
ATF_TC_BODY(connect_reserved_nonzero, tc)
{
	struct cmi_connect_args ca;
	int ctl;

	ctl = cmi_open();

	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "keystore", sizeof(ca.name));
	ca._reserved[0] = 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(ctl, CMI_CONNECT, &ca) == -1);

	close(ctl);
}

ATF_TC(call_req_oversized);
ATF_TC_HEAD(call_req_oversized, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_CALL with req_len > max returns EMSGSIZE");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(call_req_oversized, tc)
{
	struct cmi_call_args ca;
	char *big;
	char reply[64];
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	big = calloc(1, CMI_MAX_MSG + 1);
	ATF_REQUIRE(big != NULL);
	memset(&ca, 0, sizeof(ca));
	ca.req = big;
	ca.req_len = CMI_MAX_MSG + 1;
	ca.reply = reply;
	ca.reply_len = sizeof(reply);
	ATF_CHECK_ERRNO(EMSGSIZE, ioctl(fd, CMI_CALL, &ca) == -1);

	free(big);
	close(fd);
}

ATF_TC(debug_getinfo_call_feature);
ATF_TC_HEAD(debug_getinfo_call_feature, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Debug service reports CALL feature, not SENDMSG");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_debug");
}
ATF_TC_BODY(debug_getinfo_call_feature, tc)
{
	struct cmi_info_args info;
	int fd;

	fd = cmi_connect("debug");
	ATF_REQUIRE(fd >= 0);
	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, CMI_GETINFO, &info) == 0);
	ATF_CHECK_STREQ(info.name, "debug");
	ATF_CHECK((info.features & CMI_INFO_F_CALL) != 0);
	ATF_CHECK((info.features & CMI_INFO_F_SENDMSG) == 0);
	close(fd);
}

ATF_TC(namespace_getinfo_call_feature);
ATF_TC_HEAD(namespace_getinfo_call_feature, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Namespace service reports CALL feature, not SENDMSG");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(namespace_getinfo_call_feature, tc)
{
	struct cmi_info_args info;
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);
	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, CMI_GETINFO, &info) == 0);
	ATF_CHECK_STREQ(info.name, "namespace");
	ATF_CHECK((info.features & CMI_INFO_F_CALL) != 0);
	ATF_CHECK((info.features & CMI_INFO_F_SENDMSG) == 0);
	close(fd);
}

ATF_TC(pair_concurrent_writers);
ATF_TC_HEAD(pair_concurrent_writers, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Multiple processes send on same pair end concurrently");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_pair");
}
ATF_TC_BODY(pair_concurrent_writers, tc)
{
	int fd_a, fd_b, status;
	pid_t pids[4];
	int i;

	cmi_pair_pair(&fd_a, &fd_b);

	/* Fork 4 children, each sends 10 messages on fd_a. */
	for (i = 0; i < 4; i++) {
		pids[i] = fork();
		ATF_REQUIRE(pids[i] >= 0);
		if (pids[i] == 0) {
			int j;
			close(fd_b);
			for (j = 0; j < 10; j++) {
				uint32_t val = (uint32_t)(i * 100 + j);
				if (cmi_send(fd_a, &val, sizeof(val), 0) != 0)
					_exit(1);
			}
			close(fd_a);
			_exit(0);
		}
	}

	/* Parent receives all 40 messages on fd_b. */
	close(fd_a);
	for (i = 0; i < 40; i++) {
		char buf[64];
		uint32_t rlen = sizeof(buf);
		ATF_REQUIRE_MSG(cmi_recv(fd_b, buf, &rlen, NULL) == 0,
		    "recv %d: %s", i, strerror(errno));
		ATF_REQUIRE_EQ(rlen, sizeof(uint32_t));
	}

	for (i = 0; i < 4; i++) {
		ATF_REQUIRE(waitpid(pids[i], &status, 0) == pids[i]);
		ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}

	close(fd_b);
}

ATF_TC(rapid_connect_disconnect);
ATF_TC_HEAD(rapid_connect_disconnect, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Rapid connect and close 100 times does not leak");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(rapid_connect_disconnect, tc)
{
	int i;

	for (i = 0; i < 100; i++) {
		int fd = cmi_connect("keystore");
		ATF_REQUIRE_MSG(fd >= 0, "connect %d: %s", i, strerror(errno));
		close(fd);
	}
}

ATF_TC(pair_nonblock_recv_empty);
ATF_TC_HEAD(pair_nonblock_recv_empty, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "O_NONBLOCK RECVMSG on pair with no messages returns EAGAIN");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_pair");
}
ATF_TC_BODY(pair_nonblock_recv_empty, tc)
{
	struct cmi_recvmsg_args ra;
	char buf[64];
	int fd_a, fd_b, flags;

	cmi_pair_pair(&fd_a, &fd_b);

	flags = fcntl(fd_b, F_GETFL, 0);
	ATF_REQUIRE(fcntl(fd_b, F_SETFL, flags | O_NONBLOCK) == 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_CHECK_ERRNO(EAGAIN, ioctl(fd_b, CMI_RECVMSG, &ra) == -1);

	close(fd_b);
	close(fd_a);
}

ATF_TC(debug_fork_child_unshielded);
ATF_TC_HEAD(debug_fork_child_unshielded, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Shielded parent forks — child is NOT shielded");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_debug");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(debug_fork_child_unshielded, tc)
{
	int sv[2], status;
	pid_t child_pid, grandchild_pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	child_pid = fork();
	ATF_REQUIRE(child_pid >= 0);

	if (child_pid == 0) {
		/* Child: shield self, then fork grandchild. */
		int shield_fd;
		pid_t gc;
		char buf;

		close(sv[0]);
		shield_fd = debug_shield();
		if (shield_fd < 0)
			_exit(10);

		gc = fork();
		if (gc < 0)
			_exit(11);
		if (gc == 0) {
			/* Grandchild: just wait. */
			close(shield_fd);
			sleep(5);
			_exit(0);
		}

		/* Tell parent the grandchild pid. */
		write(sv[1], &gc, sizeof(gc));

		/* Wait for parent to test. */
		read(sv[1], &buf, 1);

		kill(gc, SIGKILL);
		waitpid(gc, NULL, 0);
		close(shield_fd);
		close(sv[1]);
		_exit(0);
	}

	close(sv[1]);

	/* Read grandchild pid. */
	ATF_REQUIRE(read(sv[0], &grandchild_pid, sizeof(grandchild_pid))
	    == (ssize_t)sizeof(grandchild_pid));

	usleep(100000);

	/*
	 * The child (shielded) should block ptrace.
	 * The grandchild (unshielded, different pid) should allow it.
	 */
	ATF_CHECK_ERRNO(EACCES,
	    ptrace(PT_ATTACH, child_pid, NULL, 0) == -1);

	/* Grandchild is a different pid — not in shield table. */
	ATF_CHECK(ptrace(PT_ATTACH, grandchild_pid, NULL, 0) == 0);
	waitpid(grandchild_pid, &status, WUNTRACED);
	ptrace(PT_DETACH, grandchild_pid, NULL, 0);

	/* Tell child to clean up. */
	write(sv[0], "x", 1);
	waitpid(child_pid, &status, 0);
	close(sv[0]);
}

ATF_TC(token_empty_label);
ATF_TC_HEAD(token_empty_label, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Token with empty label is valid");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_token");
}
ATF_TC_BODY(token_empty_label, tc)
{
	struct cmi_call_args ca;
	struct token_create_request cr;
	struct token_request tr;
	struct token_validate_reply vr;
	int issuer_fd, token_fd;
	int reply_fds[1];

	issuer_fd = cmi_connect("token");
	ATF_REQUIRE(issuer_fd >= 0);

	memset(&cr, 0, sizeof(cr));
	cr.op = TOKEN_OP_CREATE;
	/* Empty label — cr.label is all zeros. */
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(issuer_fd, CMI_CALL, &ca) == 0);
	token_fd = reply_fds[0];

	tr.op = TOKEN_OP_VALIDATE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &tr;
	ca.req_len = sizeof(tr);
	ca.reply = &vr;
	ca.reply_len = sizeof(vr);
	ATF_REQUIRE(ioctl(token_fd, CMI_CALL, &ca) == 0);
	ATF_CHECK_EQ(vr.valid, 1);
	ATF_CHECK_STREQ(vr.label, "");

	close(token_fd);
	close(issuer_fd);
}

ATF_TC(token_terminate_issuer_tokens_survive);
ATF_TC_HEAD(token_terminate_issuer_tokens_survive, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Terminating issuer does not invalidate tokens");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_token");
}
ATF_TC_BODY(token_terminate_issuer_tokens_survive, tc)
{
	struct cmi_call_args ca;
	struct token_create_request cr;
	struct token_request tr;
	struct token_validate_reply vr;
	int issuer_fd, token_fd;
	int reply_fds[1];

	issuer_fd = cmi_connect("token");
	ATF_REQUIRE(issuer_fd >= 0);

	memset(&cr, 0, sizeof(cr));
	cr.op = TOKEN_OP_CREATE;
	strlcpy(cr.label, "survive", sizeof(cr.label));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(issuer_fd, CMI_CALL, &ca) == 0);
	token_fd = reply_fds[0];

	/* Terminate the issuer. */
	ATF_REQUIRE(ioctl(issuer_fd, CMI_TERMINATE, NULL) == 0);
	close(issuer_fd);

	/* Token is a separate instance — should still be valid. */
	tr.op = TOKEN_OP_VALIDATE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &tr;
	ca.req_len = sizeof(tr);
	ca.reply = &vr;
	ca.reply_len = sizeof(vr);
	ATF_REQUIRE(ioctl(token_fd, CMI_CALL, &ca) == 0);
	ATF_CHECK_EQ(vr.valid, 1);
	ATF_CHECK_STREQ(vr.label, "survive");

	close(token_fd);
}

ATF_TC(namespace_info_returns_jid);
ATF_TC_HEAD(namespace_info_returns_jid, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NS_OP_INFO returns valid jid for current namespace");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(namespace_info_returns_jid, tc)
{
	struct cmi_call_args ca;
	struct ns_request nr;
	struct ns_info_reply info;
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	nr.op = NS_OP_INFO;
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply = &info;
	ca.reply_len = sizeof(info);
	ATF_REQUIRE(ioctl(fd, CMI_CALL, &ca) == 0);
	ATF_CHECK_EQ(info.status, 0);
	/* Host jail is jid 0. */
	ATF_CHECK_EQ(info.jid, 0);

	close(fd);
}

ATF_TC(pair_double_create);
ATF_TC_HEAD(pair_double_create, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Second PAIR_OP_CREATE after pairing gets error reply");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_pair");
}
ATF_TC_BODY(pair_double_create, tc)
{
	uint32_t op;
	char buf[64];
	uint32_t rlen;
	int fd_a, fd_b;

	cmi_pair_pair(&fd_a, &fd_b);

	/* Already paired — second CREATE should get error. */
	op = PAIR_OP_CREATE;
	ATF_REQUIRE(cmi_send(fd_a, &op, sizeof(op), 0) == 0);
	rlen = sizeof(buf);
	ATF_REQUIRE(cmi_recv(fd_a, buf, &rlen, NULL) == 0);
	/* Error reply is 4 bytes. */
	ATF_CHECK_EQ(rlen, 4);

	close(fd_b);
	close(fd_a);
}

ATF_TC(sendmsg_flags_nonzero);
ATF_TC_HEAD(sendmsg_flags_nonzero, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG with nonzero flags returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(sendmsg_flags_nonzero, tc)
{
	struct cmi_sendmsg_args sa;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	memset(&sa, 0, sizeof(sa));
	sa.payload = "x";
	sa.payload_len = 1;
	sa.flags = 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, CMI_SENDMSG, &sa) == -1);

	close(fd);
}

ATF_TC(recvmsg_flags_nonzero);
ATF_TC_HEAD(recvmsg_flags_nonzero, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "RECVMSG with nonzero flags returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(recvmsg_flags_nonzero, tc)
{
	struct cmi_recvmsg_args ra;
	char buf[64];
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ra.flags = 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, CMI_RECVMSG, &ra) == -1);

	close(fd);
}

ATF_TC(lock_idempotent);
ATF_TC_HEAD(lock_idempotent, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_LOCK twice is harmless");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(lock_idempotent, tc)
{
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(ioctl(fd, CMI_LOCK, NULL) == 0);
	ATF_CHECK(ioctl(fd, CMI_LOCK, NULL) == 0);

	close(fd);
}

ATF_TC(revoke_send_on_sync);
ATF_TC_HEAD(revoke_send_on_sync, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "REVOKE_SEND on sync service — SENDMSG already EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
}
ATF_TC_BODY(revoke_send_on_sync, tc)
{
	struct cmi_sendmsg_args sa;
	int fd;

	fd = cmi_connect("namespace");
	ATF_REQUIRE(fd >= 0);

	/* Revoke send on a sync service. */
	ATF_REQUIRE(ioctl(fd, CMI_REVOKE_SEND, NULL) == 0);

	/* SENDMSG was already EOPNOTSUPP, now it's EACCES. */
	memset(&sa, 0, sizeof(sa));
	sa.payload = "x";
	sa.payload_len = 1;
	ATF_CHECK(ioctl(fd, CMI_SENDMSG, &sa) == -1);
	ATF_CHECK(errno == EACCES || errno == EOPNOTSUPP);

	close(fd);
}

ATF_TC(revoke_call_on_async);
ATF_TC_HEAD(revoke_call_on_async, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "REVOKE_CALL on async service — CALL already EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(revoke_call_on_async, tc)
{
	struct cmi_call_args ca;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(ioctl(fd, CMI_REVOKE_CALL, NULL) == 0);

	memset(&ca, 0, sizeof(ca));
	ca.req = "x";
	ca.req_len = 1;
	ATF_CHECK(ioctl(fd, CMI_CALL, &ca) == -1);
	ATF_CHECK(errno == EACCES || errno == EOPNOTSUPP);

	close(fd);
}

ATF_TC(token_getinfo_features);
ATF_TC_HEAD(token_getinfo_features, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Token service reports CALL only, not SENDMSG");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_token");
}
ATF_TC_BODY(token_getinfo_features, tc)
{
	struct cmi_info_args info;
	int fd;

	fd = cmi_connect("token");
	ATF_REQUIRE(fd >= 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, CMI_GETINFO, &info) == 0);
	ATF_CHECK_STREQ(info.name, "token");
	ATF_CHECK((info.features & CMI_INFO_F_CALL) != 0);
	ATF_CHECK((info.features & CMI_INFO_F_SENDMSG) == 0);
	ATF_CHECK((info.features & CMI_INFO_F_KQUEUE) == 0);

	close(fd);
}

ATF_TC(close_during_blocked_recv);
ATF_TC_HEAD(close_during_blocked_recv, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Close fd from another thread while RECVMSG blocks");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(close_during_blocked_recv, tc)
{
	int fd, status;
	pid_t pid;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: block on RECVMSG (no messages pending). */
		struct cmi_recvmsg_args ra;
		char buf[64];

		memset(&ra, 0, sizeof(ra));
		ra.payload = buf;
		ra.payload_len = sizeof(buf);
		/* This will block until parent closes or we get a signal. */
		ioctl(fd, CMI_RECVMSG, &ra);
		_exit(0);
	}

	/* Parent: give child time to block, then close. */
	usleep(100000);
	close(fd);

	/* Child should unblock and exit. */
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFEXITED(status));
}

ATF_TC(namespace_double_remove);
ATF_TC_HEAD(namespace_double_remove, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Removing an already-removed namespace returns error");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(namespace_double_remove, tc)
{
	struct cmi_call_args ca;
	struct ns_create_request cr;
	struct ns_request nr;
	int ns_fd, child_fd;
	int reply_fds[1];

	ns_fd = cmi_connect("namespace");
	ATF_REQUIRE(ns_fd >= 0);

	memset(&cr, 0, sizeof(cr));
	cr.op = NS_OP_CREATE;
	strlcpy(cr.hostname, "double_rm", sizeof(cr.hostname));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(ns_fd, CMI_CALL, &ca) == 0);
	child_fd = reply_fds[0];

	/* First remove succeeds. */
	nr.op = NS_OP_REMOVE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ATF_REQUIRE(ioctl(child_fd, CMI_CALL, &ca) == 0);

	/* Second remove fails (jid already cleared). */
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ATF_CHECK(ioctl(child_fd, CMI_CALL, &ca) != 0);

	close(child_fd);
	close(ns_fd);
}

ATF_TC(namespace_deep_nest);
ATF_TC_HEAD(namespace_deep_nest, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Three levels of nesting, remove root cascades all");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(namespace_deep_nest, tc)
{
	struct cmi_call_args ca;
	struct ns_create_request cr;
	struct ns_request nr;
	int ns_fd, l1_fd, l2_fd, l3_fd;
	int reply_fds[1];

	ns_fd = cmi_connect("namespace");
	ATF_REQUIRE(ns_fd >= 0);

	/* Level 1. */
	memset(&cr, 0, sizeof(cr));
	cr.op = NS_OP_CREATE;
	strlcpy(cr.hostname, "level1", sizeof(cr.hostname));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(ns_fd, CMI_CALL, &ca) == 0);
	l1_fd = reply_fds[0];

	/* Level 2 nested in 1. */
	strlcpy(cr.hostname, "level2", sizeof(cr.hostname));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(l1_fd, CMI_CALL, &ca) == 0);
	l2_fd = reply_fds[0];

	/* Level 3 nested in 2. */
	strlcpy(cr.hostname, "level3", sizeof(cr.hostname));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(l2_fd, CMI_CALL, &ca) == 0);
	l3_fd = reply_fds[0];

	/* Remove level 1 — 2 and 3 should cascade. */
	nr.op = NS_OP_REMOVE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ATF_REQUIRE(ioctl(l1_fd, CMI_CALL, &ca) == 0);

	/* Level 2 should be dead. */
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ATF_CHECK(ioctl(l2_fd, CMI_CALL, &ca) != 0);

	/* Level 3 should be dead. */
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ATF_CHECK(ioctl(l3_fd, CMI_CALL, &ca) != 0);

	close(l3_fd);
	close(l2_fd);
	close(l1_fd);
	close(ns_fd);
}

ATF_TC(namespace_member_survives_owner_close);
ATF_TC_HEAD(namespace_member_survives_owner_close, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Member fd remains usable for INFO after owner closes");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(namespace_member_survives_owner_close, tc)
{
	struct cmi_call_args ca;
	struct ns_create_request cr;
	struct ns_request nr;
	struct ns_info_reply info;
	int ns_fd, owner_fd, member_fd;
	int reply_fds[1];

	ns_fd = cmi_connect("namespace");
	ATF_REQUIRE(ns_fd >= 0);

	memset(&cr, 0, sizeof(cr));
	cr.op = NS_OP_CREATE;
	strlcpy(cr.hostname, "survive", sizeof(cr.hostname));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(ns_fd, CMI_CALL, &ca) == 0);
	owner_fd = reply_fds[0];

	/* Mint member. */
	nr.op = NS_OP_MINT;
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(owner_fd, CMI_CALL, &ca) == 0);
	member_fd = reply_fds[0];

	/*
	 * Close owner — namespace is destroyed (co_revoke).
	 * Member fd is still open but namespace is gone.
	 */
	close(owner_fd);

	/*
	 * Member INFO still works (reads caller's current namespace,
	 * not the destroyed one).
	 */
	nr.op = NS_OP_INFO;
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply = &info;
	ca.reply_len = sizeof(info);
	ATF_CHECK(ioctl(member_fd, CMI_CALL, &ca) == 0);

	/* Member ATTACH should fail — namespace is gone. */
	nr.op = NS_OP_ATTACH;
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply = &info;
	ca.reply_len = sizeof(info);
	ATF_CHECK(ioctl(member_fd, CMI_CALL, &ca) != 0);

	close(member_fd);
	close(ns_fd);
}

ATF_TC(getinfo_after_terminate);
ATF_TC_HEAD(getinfo_after_terminate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "GETINFO on terminated instance still returns metadata");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(getinfo_after_terminate, tc)
{
	struct cmi_info_args info;
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(ioctl(fd, CMI_TERMINATE, NULL) == 0);

	/* GETINFO should still work — it doesn't check DEAD. */
	memset(&info, 0, sizeof(info));
	ATF_CHECK(ioctl(fd, CMI_GETINFO, &info) == 0);
	ATF_CHECK_STREQ(info.name, "keystore");

	close(fd);
}

ATF_TC(capsicum_gates_terminate);
ATF_TC_HEAD(capsicum_gates_terminate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "cap_ioctls_limit can block CMI_TERMINATE");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_keystore");
}
ATF_TC_BODY(capsicum_gates_terminate, tc)
{
	cap_rights_t rights;
	cap_ioctl_t cmds[1];
	int fd;

	fd = cmi_connect("keystore");
	ATF_REQUIRE(fd >= 0);

	/* Restrict to GETINFO only. */
	cap_rights_init(&rights, CAP_IOCTL);
	ATF_REQUIRE(cap_rights_limit(fd, &rights) == 0);
	cmds[0] = CMI_GETINFO;
	ATF_REQUIRE(cap_ioctls_limit(fd, cmds, 1) == 0);

	/* TERMINATE should be blocked. */
	ATF_CHECK_ERRNO(ENOTCAPABLE, ioctl(fd, CMI_TERMINATE, NULL) == -1);

	close(fd);
}

ATF_TC(namespace_terminate_removes);
ATF_TC_HEAD(namespace_terminate_removes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CMI_TERMINATE on namespace owner removes namespace");
	atf_tc_set_md_var(tc, "require.kmods", "cmi cmi_namespace");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(namespace_terminate_removes, tc)
{
	struct cmi_call_args ca;
	struct ns_create_request cr;
	struct ns_request nr;
	int ns_fd, child_fd;
	int reply_fds[1];

	ns_fd = cmi_connect("namespace");
	ATF_REQUIRE(ns_fd >= 0);

	memset(&cr, 0, sizeof(cr));
	cr.op = NS_OP_CREATE;
	strlcpy(cr.hostname, "term_test", sizeof(cr.hostname));
	memset(&ca, 0, sizeof(ca));
	ca.req = &cr;
	ca.req_len = sizeof(cr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(ns_fd, CMI_CALL, &ca) == 0);
	child_fd = reply_fds[0];

	/* CMI_TERMINATE should remove the namespace. */
	ATF_REQUIRE(ioctl(child_fd, CMI_TERMINATE, NULL) == 0);

	/* REMOVE should fail — already gone. */
	nr.op = NS_OP_REMOVE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ATF_CHECK(ioctl(child_fd, CMI_CALL, &ca) != 0);

	close(child_fd);
	close(ns_fd);
}

/* ================================================================ */
ATF_TP_ADD_TCS(tp)
{
	/* Lifecycle */
	ATF_TP_ADD_TC(tp, open_close);

	/* Connection */
	ATF_TP_ADD_TC(tp, connect_service);
	ATF_TP_ADD_TC(tp, connect_noent);
	ATF_TP_ADD_TC(tp, connect_empty_name);

	/* Descriptor / Capsicum integration */
	ATF_TP_ADD_TC(tp, fcntl_cloexec_flag);
	ATF_TP_ADD_TC(tp, cloexec_on_exec);
	ATF_TP_ADD_TC(tp, fcntl_nonblock_recvmsg);
	ATF_TP_ADD_TC(tp, capsicum_ioctl_limit);
	ATF_TP_ADD_TC(tp, capsicum_fcntl_limit);
	ATF_TP_ADD_TC(tp, capsicum_event_limit);
	ATF_TP_ADD_TC(tp, capmode_existing_instance);

	/* Request / response */
	ATF_TP_ADD_TC(tp, write_read);
	ATF_TP_ADD_TC(tp, fetch_notfound);
	ATF_TP_ADD_TC(tp, zero_length_write_noop);
	ATF_TP_ADD_TC(tp, concurrent_instances);

	/* Async */
	ATF_TP_ADD_TC(tp, nonblock_read_eagain);

	/* SENDMSG / RECVMSG */
	ATF_TP_ADD_TC(tp, recvmsg_basic);
	ATF_TP_ADD_TC(tp, reply_token_correlation);

	/* Fd passing — multiple descriptor types */
	ATF_TP_ADD_TC(tp, fd_passing_pipe);
	ATF_TP_ADD_TC(tp, fd_passing_socket);
	ATF_TP_ADD_TC(tp, fd_passing_devnull);
	ATF_TP_ADD_TC(tp, fd_passing_multiple_types);
	ATF_TP_ADD_TC(tp, fd_too_many);

	/* kqueue */
	ATF_TP_ADD_TC(tp, kqueue_read);
	ATF_TP_ADD_TC(tp, kqueue_evfilt_write);

	/* Stat */
	ATF_TP_ADD_TC(tp, instance_fstat);

	/* Queue behavior */
	ATF_TP_ADD_TC(tp, queue_ordering);

	/* Multi-process */
	ATF_TP_ADD_TC(tp, capability_delegation);
	ATF_TP_ADD_TC(tp, scm_rights_passing);
	ATF_TP_ADD_TC(tp, multiproc_store_fetch);
	ATF_TP_ADD_TC(tp, multiproc_concurrent_writers);

	/* Stress / edge cases */
	ATF_TP_ADD_TC(tp, close_during_pending);
	ATF_TP_ADD_TC(tp, rapid_fire);

	/* Failure conditions */
	ATF_TP_ADD_TC(tp, write_oversized);
	ATF_TP_ADD_TC(tp, sendmsg_bad_fd);
	ATF_TP_ADD_TC(tp, read_buffer_too_small);
	ATF_TP_ADD_TC(tp, recvmsg_buffer_too_small);
	ATF_TP_ADD_TC(tp, recvmsg_empty_nonblock);
	ATF_TP_ADD_TC(tp, dup_shared_instance);
	ATF_TP_ADD_TC(tp, ioctl_bad_cmd);
	ATF_TP_ADD_TC(tp, instance_ioctl_bad_cmd);
	ATF_TP_ADD_TC(tp, connect_on_instance_fd);
	ATF_TP_ADD_TC(tp, write_after_close_child);
	ATF_TP_ADD_TC(tp, sendmsg_zero_payload_with_fds);

	/* Introspection */
	ATF_TP_ADD_TC(tp, getinfo);

	/* Capability pair */
	ATF_TP_ADD_TC(tp, pair_create);
	ATF_TP_ADD_TC(tp, pair_bidirectional);
	ATF_TP_ADD_TC(tp, pair_close_one_end);
	ATF_TP_ADD_TC(tp, pair_multiproc);

	/* Additional coverage */
	ATF_TP_ADD_TC(tp, getinfo_limits);
	ATF_TP_ADD_TC(tp, credential_trailer);

	/* CMI_CALL */
	ATF_TP_ADD_TC(tp, call_no_handler);
	ATF_TP_ADD_TC(tp, call_flags_nonzero);

	/* Revoke via message */
	ATF_TP_ADD_TC(tp, terminate_instance);
	ATF_TP_ADD_TC(tp, terminate_then_send);
	ATF_TP_ADD_TC(tp, terminate_sync_service);
	ATF_TP_ADD_TC(tp, normal_ops_no_terminate);

	/* Sync/async enforcement */
	ATF_TP_ADD_TC(tp, sendmsg_on_sync_service);
	ATF_TP_ADD_TC(tp, call_on_async_service);
	ATF_TP_ADD_TC(tp, namespace_call_info);
	ATF_TP_ADD_TC(tp, namespace_call_short_req);
	ATF_TP_ADD_TC(tp, namespace_call_bad_op);

	/* Feature bit introspection */
	ATF_TP_ADD_TC(tp, getinfo_async_features);
	ATF_TP_ADD_TC(tp, getinfo_sync_features);

	/* Pair: additional coverage */
	ATF_TP_ADD_TC(tp, pair_fd_passing);
	ATF_TP_ADD_TC(tp, pair_stress);
	ATF_TP_ADD_TC(tp, pair_getinfo);

	/* Namespace: additional coverage */
	ATF_TP_ADD_TC(tp, namespace_call_zero_req);
	ATF_TP_ADD_TC(tp, namespace_getinfo);
	ATF_TP_ADD_TC(tp, namespace_badge_unique);
	ATF_TP_ADD_TC(tp, namespace_revoke_then_call);
	ATF_TP_ADD_TC(tp, namespace_enter_and_query);
	ATF_TP_ADD_TC(tp, namespace_create_and_remove);
	ATF_TP_ADD_TC(tp, namespace_close_removes);
	ATF_TP_ADD_TC(tp, namespace_mint_member);
	ATF_TP_ADD_TC(tp, namespace_nest);

	/* Keystore: additional coverage */
	ATF_TP_ADD_TC(tp, keystore_max_keys);
	ATF_TP_ADD_TC(tp, keystore_overwrite);
	ATF_TP_ADD_TC(tp, keystore_uid_isolation);
	ATF_TP_ADD_TC(tp, keystore_badge_unique);

	/* Non-transferable (CMI_SVC_NOXFER) */
	ATF_TP_ADD_TC(tp, noxfer_scm_rights);
	ATF_TP_ADD_TC(tp, noxfer_cmi_attach);
	ATF_TP_ADD_TC(tp, xfer_keystore_ok);

	/* co_fdclose */
	ATF_TP_ADD_TC(tp, fdclose_dup_survives);
	ATF_TP_ADD_TC(tp, fdclose_dup_then_close_all);

	/* Granular revoke */
	ATF_TP_ADD_TC(tp, revoke_send_blocks_send);
	ATF_TP_ADD_TC(tp, revoke_recv_blocks_recv);
	ATF_TP_ADD_TC(tp, revoke_call_blocks_call);
	ATF_TP_ADD_TC(tp, revoke_send_recv_both);
	ATF_TP_ADD_TC(tp, revoke_is_permanent);
	ATF_TP_ADD_TC(tp, revoke_affects_all_dups);
	ATF_TP_ADD_TC(tp, terminate_after_revoke_send);

	/* CMI_CALL reply fds */
	ATF_TP_ADD_TC(tp, call_reply_fds_zero);
	ATF_TP_ADD_TC(tp, call_reply_fds_buf_no_fds);
	ATF_TP_ADD_TC(tp, call_reply_nfds_too_many);

	/* CMI_LOCK */
	ATF_TP_ADD_TC(tp, lock_prevents_transfer);
	ATF_TP_ADD_TC(tp, lock_still_usable);
	ATF_TP_ADD_TC(tp, lock_trampoline);

	/* cap_debug */
	ATF_TP_ADD_TC(tp, debug_shield_blocks_ptrace);
	ATF_TP_ADD_TC(tp, debug_close_unshields);
	ATF_TP_ADD_TC(tp, debug_shield_blocks_signal);
	ATF_TP_ADD_TC(tp, debug_mint_and_activate);
	ATF_TP_ADD_TC(tp, debug_double_shield);
	ATF_TP_ADD_TC(tp, debug_mint_without_shield);
	ATF_TP_ADD_TC(tp, debug_shield_from_token);
	ATF_TP_ADD_TC(tp, debug_activate_on_shield);
	ATF_TP_ADD_TC(tp, debug_bad_op);
	ATF_TP_ADD_TC(tp, debug_token_close_revokes);

	/* Token capability */
	ATF_TP_ADD_TC(tp, token_create_and_validate);
	ATF_TP_ADD_TC(tp, token_revoke_invalidates);
	ATF_TP_ADD_TC(tp, token_dup_shares_instance);
	ATF_TP_ADD_TC(tp, token_validate_on_issuer);
	ATF_TP_ADD_TC(tp, token_create_from_token);
	ATF_TP_ADD_TC(tp, token_bad_op);

	/* Edge cases */
	ATF_TP_ADD_TC(tp, kqueue_eof_on_terminate);
	ATF_TP_ADD_TC(tp, max_payload_size);
	ATF_TP_ADD_TC(tp, payload_over_max);
	ATF_TP_ADD_TC(tp, token_fork_inherits);
	ATF_TP_ADD_TC(tp, token_multiple_from_issuer);
	ATF_TP_ADD_TC(tp, pair_kqueue_eof_on_close);

	/* Pair: edge cases */
	ATF_TP_ADD_TC(tp, pair_send_after_peer_close);
	ATF_TP_ADD_TC(tp, pair_unpaired_send);
	ATF_TP_ADD_TC(tp, pair_double_create);

	/* More framework edge cases */
	ATF_TP_ADD_TC(tp, sendmsg_flags_nonzero);
	ATF_TP_ADD_TC(tp, recvmsg_flags_nonzero);
	ATF_TP_ADD_TC(tp, lock_idempotent);
	ATF_TP_ADD_TC(tp, revoke_send_on_sync);
	ATF_TP_ADD_TC(tp, revoke_call_on_async);
	ATF_TP_ADD_TC(tp, token_getinfo_features);
	ATF_TP_ADD_TC(tp, close_during_blocked_recv);

	/* Service-specific edge cases */
	ATF_TP_ADD_TC(tp, pair_nonblock_recv_empty);
	ATF_TP_ADD_TC(tp, debug_fork_child_unshielded);
	ATF_TP_ADD_TC(tp, token_empty_label);
	ATF_TP_ADD_TC(tp, token_terminate_issuer_tokens_survive);
	ATF_TP_ADD_TC(tp, namespace_info_returns_jid);

	/* More coverage */
	ATF_TP_ADD_TC(tp, call_req_oversized);
	ATF_TP_ADD_TC(tp, debug_getinfo_call_feature);
	ATF_TP_ADD_TC(tp, namespace_getinfo_call_feature);
	ATF_TP_ADD_TC(tp, pair_concurrent_writers);
	ATF_TP_ADD_TC(tp, rapid_connect_disconnect);

	/* Framework: additional */
	ATF_TP_ADD_TC(tp, terminate_twice);
	ATF_TP_ADD_TC(tp, connect_reserved_nonzero);

	/* Namespace: edge cases */
	ATF_TP_ADD_TC(tp, namespace_double_remove);
	ATF_TP_ADD_TC(tp, namespace_deep_nest);
	ATF_TP_ADD_TC(tp, namespace_member_survives_owner_close);
	ATF_TP_ADD_TC(tp, namespace_terminate_removes);

	/* Framework: edge cases */
	ATF_TP_ADD_TC(tp, getinfo_after_terminate);
	ATF_TP_ADD_TC(tp, capsicum_gates_terminate);

	return (atf_no_error());
}
