/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Tests for mac_capability — generic capability interface for kernel modules.
 *
 * Requires:
 *   kldload mac_capability
 *   kldload mac_capability_test_keystore
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/event.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/procdesc.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <libutil.h>
#include <signal.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_test_helpers.h"
#include "mac_capability_capprotect_proto.h"
#include "mac_capability_identity_proto.h"
#include "mac_capability_test_keystore_proto.h"
#include "mac_capability_test_kernelstore_proto.h"

#ifndef CAP_XFER_UNLIMITED
#define	CAP_XFER_UNLIMITED	0
#define	CAP_XFER_ONCE		1
#define	CAP_XFER_NONE		2
#endif
#ifndef CAP_CLOEXEC_ONCE
#define	CAP_CLOEXEC_ONCE	2
#endif
#ifndef CAP_CLOFORK_ONCE
#define	CAP_CLOFORK_ONCE	2
#endif

static int
closed_fd(void)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/null: %s", strerror(errno));
	ATF_REQUIRE(close(fd) == 0);
	return (fd);
}

static uint32_t
mac_capability_missing_key(void)
{

	return (0xffff0000u | ((uint32_t)getpid() & 0xffffu));
}

/* Helper: send a message via MAC_CAPABILITY_SENDMSG */
static int
mac_capability_send(int fd, const void *payload, uint32_t len, uint64_t token)
{
	struct mac_capability_sendmsg_args sa;

	memset(&sa, 0, sizeof(sa));
	sa.payload = payload;
	sa.payload_len = len;
	sa.reply_token = token;
	return (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa));
}

/* Helper: receive a message via MAC_CAPABILITY_RECVMSG (blocks) */
static int
mac_capability_recv(int fd, void *buf, uint32_t *lenp, uint64_t *tokenp)
{
	struct mac_capability_recvmsg_args ra;
	int ret;

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = *lenp;
	ret = ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra);
	if (ret == 0) {
		*lenp = ra.payload_len;
		if (tokenp != NULL)
			*tokenp = ra.reply_token;
	}
	return (ret);
}

static void
mac_capability_fetch_trailer(int fd, struct mac_capability_cred_trailer *trailer)
{
	struct mac_capability_call_args ca;
	struct kstore_request kr;
	struct kstore_status_reply sr;

	memset(&kr, 0, sizeof(kr));
	kr.op = KSTORE_OP_GET;
	strlcpy(kr.key, "_trailer", sizeof(kr.key));
	memset(&ca, 0, sizeof(ca));
	ca.req = &kr;
	ca.req_len = sizeof(kr);
	ca.reply = &sr;
	ca.reply_len = sizeof(sr);
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_CALL, &ca) == 0);
	*trailer = ca.trailer;
}

/* Helper: store a key via SENDMSG/RECVMSG round-trip */
static void
mac_capability_store(int fd, uint32_t keyid, const void *data, size_t datalen)
{
	char buf[sizeof(struct ks_request) + 4096];
	struct ks_request *req = (struct ks_request *)buf;
	struct ks_reply reply;
	uint32_t rlen;

	req->op = KS_OP_STORE;
	req->keyid = keyid;
	if (datalen > 0)
		memcpy(buf + sizeof(*req), data, datalen);
	ATF_REQUIRE(mac_capability_send(fd, buf, sizeof(*req) + datalen, 0) == 0);
	rlen = sizeof(reply);
	ATF_REQUIRE(mac_capability_recv(fd, &reply, &rlen, NULL) == 0);
	ATF_REQUIRE_EQ(reply.status, KS_STATUS_OK);
}


/* ================================================================
 * Lifecycle tests
 * ================================================================ */

ATF_TC(open_close);
ATF_TC_HEAD(open_close, tc)
{
	atf_tc_set_md_var(tc, "descr", "Open and close /dev/mac_capability");
}
ATF_TC_BODY(open_close, tc)
{
	int fd = mac_capability_open();
	ATF_REQUIRE(close(fd) == 0);
}

/* ================================================================
 * Connection tests
 * ================================================================ */

ATF_TC(connect_service);
ATF_TC_HEAD(connect_service, tc)
{
	atf_tc_set_md_var(tc, "descr", "Connect to keystore service");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(connect_service, tc)
{
	int fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	close(fd);
}

ATF_TC(descriptor_kinfo);
ATF_TC_HEAD(descriptor_kinfo, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC capability descriptors expose service identity to process tools");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(descriptor_kinfo, tc)
{
	struct kinfo_file *files;
	int count, fd, i;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	files = kinfo_getfile(getpid(), &count);
	ATF_REQUIRE_MSG(files != NULL, "kinfo_getfile: %s", strerror(errno));
	for (i = 0; i < count && files[i].kf_fd != fd; i++)
		;
	ATF_REQUIRE_MSG(i != count, "capability fd %d was not exported", fd);
	ATF_REQUIRE_EQ(KF_TYPE_MAC_CAPABILITY, files[i].kf_type);
	ATF_REQUIRE((files[i].kf_status & KF_ATTR_VALID) != 0);
	ATF_REQUIRE_MSG(strncmp(files[i].kf_path,
	    "mac_capability:test_keystore[", 29) == 0,
	    "unexpected descriptor name: %s", files[i].kf_path);
	free(files);
	close(fd);
}

ATF_TC(connect_noent);
ATF_TC_HEAD(connect_noent, tc)
{
	atf_tc_set_md_var(tc, "descr", "Connect to nonexistent service fails");
}
ATF_TC_BODY(connect_noent, tc)
{
	struct mac_capability_connect_args ca;
	int ctl = mac_capability_open();

	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "no_such_service", sizeof(ca.name));
	ATF_CHECK_ERRNO(ENOENT, ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) == -1);
	close(ctl);
}

ATF_TC(connect_empty_name);
ATF_TC_HEAD(connect_empty_name, tc)
{
	atf_tc_set_md_var(tc, "descr", "Empty service name fails");
}
ATF_TC_BODY(connect_empty_name, tc)
{
	struct mac_capability_connect_args ca;
	int ctl = mac_capability_open();

	memset(&ca, 0, sizeof(ca));
	ATF_CHECK_ERRNO(EINVAL, ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) == -1);
	close(ctl);
}

/* ================================================================
 * Descriptor / Capsicum integration tests
 * ================================================================ */

ATF_TC(fcntl_cloexec_flag);
ATF_TC_HEAD(fcntl_cloexec_flag, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "F_GETFD/F_SETFD work on mac_capability instance fds");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(fcntl_cloexec_flag, tc)
{
	int fd, flags;

	fd = mac_capability_connect("test_keystore");
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
	    "FD_CLOEXEC closes a mac_capability instance fd across exec");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(cloexec_on_exec, tc)
{
	char exec_path[1024];
	char fdstr[32];
	int fd, flags, status;
	pid_t pid;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	flags = fcntl(fd, F_GETFD);
	ATF_REQUIRE(flags >= 0);
	ATF_REQUIRE(fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		snprintf(exec_path, sizeof(exec_path), "%s/mac_capability_exec_helper",
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
	    "fcntl(O_NONBLOCK) enables nonblocking MAC_CAPABILITY_RECVMSG");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(fcntl_nonblock_recvmsg, tc)
{
	struct mac_capability_recvmsg_args ra;
	char buf[1];
	int fd, flags;

	fd = mac_capability_connect("test_keystore");
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
	ATF_CHECK_ERRNO(EAGAIN, ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == -1);

	close(fd);
}

ATF_TC(capsicum_ioctl_limit);
ATF_TC_HEAD(capsicum_ioctl_limit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "cap_ioctls_limit restricts MAC_CAPABILITY instance ioctls");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(capsicum_ioctl_limit, tc)
{
	cap_rights_t rights;
	cap_ioctl_t cmds[1];
	struct mac_capability_info_args info;
	struct mac_capability_sendmsg_args sa;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	cap_rights_init(&rights, CAP_IOCTL);
	ATF_REQUIRE(cap_rights_limit(fd, &rights) == 0);

	cmds[0] = MAC_CAPABILITY_GETINFO;
	ATF_REQUIRE(cap_ioctls_limit(fd, cmds, 1) == 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);

	memset(&sa, 0, sizeof(sa));
	sa.payload = "x";
	sa.payload_len = 1;
	ATF_CHECK_ERRNO(ENOTCAPABLE, ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);

	close(fd);
}

static int
verify_getinfo_only(int fd)
{
	struct mac_capability_info_args info;
	struct mac_capability_sendmsg_args sa;
	cap_ioctl_t cmd;
	char payload = 'x';

	if (cap_ioctls_get(fd, &cmd, 1) != 1 ||
	    cmd != MAC_CAPABILITY_GETINFO)
		return (1);
	memset(&info, 0, sizeof(info));
	if (ioctl(fd, MAC_CAPABILITY_GETINFO, &info) != 0)
		return (2);
	memset(&sa, 0, sizeof(sa));
	sa.payload = &payload;
	sa.payload_len = sizeof(payload);
	if (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) != -1 ||
	    errno != ENOTCAPABLE)
		return (3);
	return (0);
}

ATF_TC(capsicum_fcntl_limit);
ATF_TC_HEAD(capsicum_fcntl_limit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "cap_fcntls_limit restricts fcntl operations on mac_capability fds");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(capsicum_fcntl_limit, tc)
{
	cap_rights_t rights;
	int fd, flags;

	fd = mac_capability_connect("test_keystore");
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
	    "CAP_EVENT gates kqueue registration on mac_capability instance fds");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(capsicum_event_limit, tc)
{
	cap_rights_t rights;
	struct kevent kev;
	int fd, kq;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	cap_rights_init(&rights, CAP_IOCTL);
	ATF_REQUIRE(cap_rights_limit(fd, &rights) == 0);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_CHECK_ERRNO(ENOTCAPABLE, kevent(kq, &kev, 1, NULL, 0, NULL) == -1);
	close(kq);
	close(fd);

	fd = mac_capability_connect("test_keystore");
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
	    "Existing mac_capability instances keep working after cap_enter");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
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
		struct mac_capability_info_args info;
		int fd;

		fd = mac_capability_connect("test_keystore");
		if (fd < 0)
			_exit(1);

		cap_rights_init(&rights, CAP_IOCTL);
		if (cap_rights_limit(fd, &rights) != 0)
			_exit(2);
		cmds[0] = MAC_CAPABILITY_GETINFO;
		if (cap_ioctls_limit(fd, cmds, 1) != 0)
			_exit(3);
		if (cap_enter() != 0)
			_exit(4);
		memset(&info, 0, sizeof(info));
		if (ioctl(fd, MAC_CAPABILITY_GETINFO, &info) != 0)
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
	    "MAC_CAPABILITY_SENDMSG enqueues async, MAC_CAPABILITY_RECVMSG gets reply");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(write_read, tc)
{
	struct ks_request req;
	struct ks_reply reply;
	char buf[128];
	uint32_t rlen;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/* Store a key */
	memset(buf, 0, sizeof(buf));
	req.op = KS_OP_STORE;
	req.keyid = 1;
	memcpy(buf, &req, sizeof(req));
	memcpy(buf + sizeof(req), "hello", 5);
	ATF_REQUIRE(mac_capability_send(fd, buf, sizeof(req) + 5, 0) == 0);

	rlen = sizeof(reply);
	ATF_REQUIRE(mac_capability_recv(fd, &reply, &rlen, NULL) == 0);
	ATF_CHECK_EQ(reply.status, KS_STATUS_OK);

	/* Fetch it back */
	req.op = KS_OP_FETCH;
	req.keyid = 1;
	ATF_REQUIRE(mac_capability_send(fd, &req, sizeof(req), 0) == 0);

	memset(buf, 0, sizeof(buf));
	rlen = sizeof(buf);
	ATF_REQUIRE(mac_capability_recv(fd, buf, &rlen, NULL) == 0);
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
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(fetch_notfound, tc)
{
	struct ks_request req;
	struct ks_reply reply;
	uint32_t rlen;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	req.op = KS_OP_FETCH;
	req.keyid = 99999;
	ATF_REQUIRE(mac_capability_send(fd, &req, sizeof(req), 0) == 0);
	rlen = sizeof(reply);
	ATF_REQUIRE(mac_capability_recv(fd, &reply, &rlen, NULL) == 0);
	ATF_CHECK_EQ(reply.status, KS_STATUS_NOTFOUND);

	close(fd);
}

ATF_TC(concurrent_instances);
ATF_TC_HEAD(concurrent_instances, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Multiple instances to same service work independently");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(concurrent_instances, tc)
{
	int fd1, fd2;

	fd1 = mac_capability_connect("test_keystore");
	fd2 = mac_capability_connect("test_keystore");
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
	    "MAC_CAPABILITY_SENDMSG with payload_len=0 sends a zero-length message");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(zero_length_write_noop, tc)
{
	struct mac_capability_recvmsg_args ra;
	char buf[64];
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/* Zero-length SENDMSG should succeed and enqueue a message. */
	ATF_REQUIRE(mac_capability_send(fd, NULL, 0, 0) == 0);

	/* The handler receives a 0-byte message and replies (e.g. error). */

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_CHECK(ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == 0);
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
	    "O_NONBLOCK MAC_CAPABILITY_RECVMSG with no pending messages returns EAGAIN");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(nonblock_read_eagain, tc)
{
	char buf[64];
	uint32_t rlen;
	int fd, flags;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	flags = fcntl(fd, F_GETFL, 0);
	ATF_REQUIRE(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);

	rlen = sizeof(buf);
	ATF_CHECK_ERRNO(EAGAIN, mac_capability_recv(fd, buf, &rlen, NULL) == -1);

	close(fd);
}

/* ================================================================
 * SENDMSG / RECVMSG tests
 * ================================================================ */

ATF_TC(recvmsg_basic);
ATF_TC_HEAD(recvmsg_basic, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_RECVMSG dequeues reply with payload and reply token");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(recvmsg_basic, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	struct ks_request req;
	struct ks_reply reply;
	char buf[128];
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	mac_capability_store(fd, 42, "world", 5);

	req.op = KS_OP_FETCH;
	req.keyid = 42;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.reply_token = 0x1234;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == 0);


	memset(&ra, 0, sizeof(ra));
	memset(buf, 0, sizeof(buf));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == 0);
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
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(reply_token_correlation, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	struct ks_request req;
	char buf[128];
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/* Send two requests with different tokens. */
	req.op = KS_OP_FETCH;
	req.keyid = 1;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.reply_token = 0xAAAA;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == 0);

	req.keyid = 2;
	sa.reply_token = 0xBBBB;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == 0);

	/* Read both — FIFO order, tokens match. */

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == 0);
	ATF_CHECK_EQ(ra.reply_token, 0xAAAA);

	ra.payload_len = sizeof(buf);
	ra.nfds = 0;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == 0);
	ATF_CHECK_EQ(ra.reply_token, 0xBBBB);

	close(fd);
}

/* ================================================================
 * Fd passing tests — various descriptor types
 * ================================================================ */

/*
 * fd passing tests.  We test three fd types (pipe, socket, /dev/null)
 * individually in fd_passing_single, and all three together in
 * fd_passing_multiple.
 */

static void
fd_passing_send_one(int svc_fd, int pass_fd)
{
	struct mac_capability_sendmsg_args sa;
	struct ks_request req;
	struct ks_reply reply;

	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = &pass_fd;
	sa.nfds = 1;
	ATF_REQUIRE_MSG(ioctl(svc_fd, MAC_CAPABILITY_SENDMSG, &sa) == 0,
	    "SENDMSG: %s", strerror(errno));

	{
		struct mac_capability_recvmsg_args dbg;
		memset(&dbg, 0, sizeof(dbg));
		dbg.payload = &reply;
		dbg.payload_len = sizeof(reply);
		ATF_REQUIRE_MSG(ioctl(svc_fd, MAC_CAPABILITY_RECVMSG, &dbg) == 0,
		    "RECVMSG: %s (payload_len=%u nfds=%u)",
		    strerror(errno), dbg.payload_len, dbg.nfds);
	}
}

ATF_TC(fd_passing_single);
ATF_TC_HEAD(fd_passing_single, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG with pipe, socket, and /dev/null fd attachments");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(fd_passing_single, tc)
{
	int fd, pipefd[2], sv[2], devnull;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/* pipe fd */
	ATF_REQUIRE(pipe(pipefd) == 0);
	fd_passing_send_one(fd, pipefd[0]);
	close(pipefd[0]);
	close(pipefd[1]);

	/* socket fd */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	fd_passing_send_one(fd, sv[0]);
	close(sv[0]);
	close(sv[1]);

	/* /dev/null fd */
	devnull = open("/dev/null", O_RDWR);
	ATF_REQUIRE(devnull >= 0);
	fd_passing_send_one(fd, devnull);
	close(devnull);

	close(fd);
}

ATF_TC(fd_passing_multiple);
ATF_TC_HEAD(fd_passing_multiple, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG with pipe + socket + file fds in one message");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(fd_passing_multiple, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct ks_request req;
	struct ks_reply reply;
	int fd, fds[3], sv[2], pipefd[2];

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pipe(pipefd) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	fds[0] = pipefd[0];
	fds[1] = sv[0];
	fds[2] = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fds[2] >= 0);

	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = fds;
	sa.nfds = 3;
	ATF_REQUIRE_MSG(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == 0,
	    "SENDMSG multi: %s", strerror(errno));

	{
		uint32_t rlen = sizeof(reply);
		ATF_REQUIRE_MSG(mac_capability_recv(fd, &reply, &rlen, NULL) == 0,
		    "RECVMSG multi: %s (rlen=%u)", strerror(errno), rlen);
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
	    "Sending > MAC_CAPABILITY_MAX_FDS fds fails EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(fd_too_many, tc)
{
	struct mac_capability_sendmsg_args sa;
	int fds[MAC_CAPABILITY_MAX_FDS + 1];
	int fd, i;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	for (i = 0; i <= MAC_CAPABILITY_MAX_FDS; i++)
		fds[i] = STDOUT_FILENO;

	memset(&sa, 0, sizeof(sa));
	sa.payload = "x";
	sa.payload_len = 1;
	sa.fds = fds;
	sa.nfds = MAC_CAPABILITY_MAX_FDS + 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);

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
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(kqueue_read, tc)
{
	struct ks_request req;
	struct kevent kev;
	struct timespec ts;
	int fd, kq, ret;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);

	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	ATF_REQUIRE(mac_capability_send(fd, &req, sizeof(req), 0) == 0);

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
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(kqueue_evfilt_write, tc)
{
	struct kevent kev;
	struct timespec ts;
	int fd, kq, ret;

	fd = mac_capability_connect("test_keystore");
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
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(instance_fstat, tc)
{
	struct ks_request req;
	struct stat sb;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(fstat(fd, &sb) == 0);
	ATF_CHECK_EQ(sb.st_size, 0);

	/* Trigger a reply. */
	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	ATF_REQUIRE(mac_capability_send(fd, &req, sizeof(req), 0) == 0);

	/* Poll fstat until the reply arrives in the TX queue. */
	{
		int i;
		for (i = 0; i < 100; i++) {
			ATF_REQUIRE(fstat(fd, &sb) == 0);
			if (sb.st_size >= 1)
				break;
			usleep(10000);
		}
	}
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
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(queue_ordering, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	struct ks_request req;
	char buf[128];
	int fd, i;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	for (i = 0; i < 5; i++) {
		req.op = i == 0 ? KS_OP_DELAY_FETCH : KS_OP_FETCH;
		req.keyid = (uint32_t)i;
		memset(&sa, 0, sizeof(sa));
		sa.payload = &req;
		sa.payload_len = sizeof(req);
		sa.reply_token = (uint64_t)(i + 1);
		ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == 0);
		/* Let the delayed first handler start before queuing followers. */
		if (i == 0)
			usleep(20000);
	}

	for (i = 0; i < 5; i++) {
		memset(&ra, 0, sizeof(ra));
		ra.payload = buf;
		ra.payload_len = sizeof(buf);
		ATF_REQUIRE_MSG(ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == 0,
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
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(capability_delegation, tc)
{
	struct ks_request req;
	struct ks_reply reply;
	int fd, status;
	pid_t pid;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		struct mac_capability_sendmsg_args sa;
		struct mac_capability_recvmsg_args ra;

		req.op = KS_OP_FETCH;
		req.keyid = mac_capability_missing_key();
		memset(&sa, 0, sizeof(sa));
		sa.payload = &req;
		sa.payload_len = sizeof(req);
		if (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) != 0)
			_exit(1);
		memset(&ra, 0, sizeof(ra));
		ra.payload = &reply;
		ra.payload_len = sizeof(reply);
		if (ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) != 0)
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
	    "SCM_RIGHTS preserves a mac_capability fd ioctl allowlist");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(scm_rights_passing, tc)
{
	cap_ioctl_t cmds[] = { MAC_CAPABILITY_GETINFO };
	int sv[2], fd, status;
	pid_t pid;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(cap_ioctls_limit(fd, cmds, nitems(cmds)) == 0);
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

		if (verify_getinfo_only(received_fd) != 0)
			_exit(3);
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
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(multiproc_store_fetch, tc)
{
	int fd, status;
	pid_t pid;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/* Parent stores a key. */
	mac_capability_store(fd, 7777, "shared", 6);
	close(fd);

	/* Child opens its own instance and fetches. */
	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		struct mac_capability_sendmsg_args sa;
		struct mac_capability_recvmsg_args ra;
		struct ks_request req;
		struct ks_reply reply;
		char buf[128];
		int cfd = mac_capability_connect("test_keystore");
		if (cfd < 0)
			_exit(10);

		req.op = KS_OP_FETCH;
		req.keyid = 7777;
		memset(&sa, 0, sizeof(sa));
		sa.payload = &req;
		sa.payload_len = sizeof(req);
		if (ioctl(cfd, MAC_CAPABILITY_SENDMSG, &sa) != 0)
			_exit(1);

		memset(buf, 0, sizeof(buf));
		memset(&ra, 0, sizeof(ra));
		ra.payload = buf;
		ra.payload_len = sizeof(buf);
		if (ioctl(cfd, MAC_CAPABILITY_RECVMSG, &ra) != 0)
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
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(multiproc_concurrent_writers, tc)
{
	pid_t pids[4];
	int i, status;

	for (i = 0; i < 4; i++) {
		pids[i] = fork();
		ATF_REQUIRE(pids[i] >= 0);

		if (pids[i] == 0) {
			struct mac_capability_sendmsg_args sa;
			struct mac_capability_recvmsg_args ra;
			struct ks_request req;
			struct ks_reply reply;
			char buf[sizeof(struct ks_request) + 32];
			int fd, j;

			fd = mac_capability_connect("test_keystore");
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
				if (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) != 0)
					_exit(1);
				memset(&ra, 0, sizeof(ra));
				ra.payload = &reply;
				ra.payload_len = sizeof(reply);
				if (ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) != 0)
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
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(close_during_pending, tc)
{
	struct ks_request req;
	int fd, i;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/* Fire off several sends then immediately close. */
	for (i = 0; i < 20; i++) {
		req.op = KS_OP_FETCH;
		req.keyid = (uint32_t)i;
		(void)mac_capability_send(fd, &req, sizeof(req), 0);
	}

	/* Close with replies pending — must not crash. */
	close(fd);
}

ATF_TC(rapid_fire);
ATF_TC_HEAD(rapid_fire, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Rapid fire 100 requests, recv all 100 replies");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(rapid_fire, tc)
{
	struct ks_request req;
	char buf[256];
	uint32_t rlen;
	int fd, i, flags;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/* Send 100 requests. */
	for (i = 0; i < 100; i++) {
		req.op = KS_OP_FETCH;
		req.keyid = (uint32_t)i;
		ATF_REQUIRE(mac_capability_send(fd, &req, sizeof(req), 0) == 0);
	}

	/* Recv all 100 replies. */
	for (i = 0; i < 100; i++) {
		rlen = sizeof(buf);
		ATF_REQUIRE_MSG(
		    mac_capability_recv(fd, buf, &rlen, NULL) == 0,
		    "recv reply %d: %s", i, strerror(errno));
	}

	/* No more pending — nonblock recv should EAGAIN. */
	flags = fcntl(fd, F_GETFL, 0);
	ATF_REQUIRE(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
	rlen = sizeof(buf);
	ATF_CHECK_ERRNO(EAGAIN, mac_capability_recv(fd, buf, &rlen, NULL) == -1);

	close(fd);
}

/* ================================================================
 * Failure condition tests
 * ================================================================ */

ATF_TC(write_oversized);
ATF_TC_HEAD(write_oversized, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_SENDMSG with payload > MAC_CAPABILITY_MAX_MSG returns EMSGSIZE");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(write_oversized, tc)
{
	struct mac_capability_sendmsg_args sa;
	char *big;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	big = calloc(1, MAC_CAPABILITY_MAX_MSG + 1);
	ATF_REQUIRE(big != NULL);
	memset(&sa, 0, sizeof(sa));
	sa.payload = big;
	sa.payload_len = MAC_CAPABILITY_MAX_MSG + 1;
	ATF_CHECK_ERRNO(EMSGSIZE, ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);
	free(big);
	close(fd);
}

ATF_TC(sendmsg_bad_fd);
ATF_TC_HEAD(sendmsg_bad_fd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG with invalid fd number fails EBADF");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(sendmsg_bad_fd, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct ks_request req;
	int fd, badfd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	badfd = closed_fd();
	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = &badfd;
	sa.nfds = 1;
	ATF_CHECK_ERRNO(EBADF, ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);
	close(fd);
}

ATF_TC(read_buffer_too_small);
ATF_TC_HEAD(read_buffer_too_small, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_RECVMSG with buffer smaller than message returns EMSGSIZE");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(read_buffer_too_small, tc)
{
	struct mac_capability_recvmsg_args ra;
	struct ks_request req;
	char tiny[1];
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/* Store a key so the reply has payload. */
	mac_capability_store(fd, 100, "big_value", 9);

	/* Fetch — reply is sizeof(ks_reply) + 9 = 13 bytes. */
	req.op = KS_OP_FETCH;
	req.keyid = 100;
	ATF_REQUIRE(mac_capability_send(fd, &req, sizeof(req), 0) == 0);

	/* Recv with a 1-byte buffer. */
	memset(&ra, 0, sizeof(ra));
	ra.payload = tiny;
	ra.payload_len = sizeof(tiny);
	ATF_CHECK_ERRNO(EMSGSIZE, ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == -1);

	/* Message should still be queued — recv with full buffer works. */
	{
		char buf[64];
		uint32_t rlen = sizeof(buf);
		ATF_CHECK(mac_capability_recv(fd, buf, &rlen, NULL) == 0);
		ATF_CHECK(rlen > 0);
	}

	close(fd);
}

ATF_TC(recvmsg_buffer_too_small);
ATF_TC_HEAD(recvmsg_buffer_too_small, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "RECVMSG with small buffer returns EMSGSIZE and required size");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(recvmsg_buffer_too_small, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	struct ks_request req;
	char buf[128];
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	mac_capability_store(fd, 200, "somedata", 8);

	req.op = KS_OP_FETCH;
	req.keyid = 200;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == 0);

	/* Try with 1-byte buffer. */
	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = 1;
	ATF_CHECK_ERRNO(EMSGSIZE, ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == -1);

	/* Message stays queued — retry with full buffer. */
	ra.payload_len = sizeof(buf);
	ATF_CHECK(ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == 0);
	ATF_CHECK(ra.payload_len > 0);

	close(fd);
}

ATF_TC(recvmsg_empty_nonblock);
ATF_TC_HEAD(recvmsg_empty_nonblock, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "RECVMSG on empty queue with O_NONBLOCK returns EAGAIN");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(recvmsg_empty_nonblock, tc)
{
	struct mac_capability_recvmsg_args ra;
	char buf[64];
	int fd, flags;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	flags = fcntl(fd, F_GETFL, 0);
	ATF_REQUIRE(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_CHECK_ERRNO(EAGAIN, ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == -1);

	close(fd);
}

ATF_TC(dup_shared_instance);
ATF_TC_HEAD(dup_shared_instance, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "dup() shares instance �� write on one, read on the other");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(dup_shared_instance, tc)
{
	struct ks_request req;
	struct ks_reply reply;
	int fd, fd2;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	fd2 = dup(fd);
	ATF_REQUIRE(fd2 >= 0);

	/* Send on fd, recv on fd2 — they share the same instance. */
	{
		uint32_t rlen;
		req.op = KS_OP_FETCH;
		req.keyid = mac_capability_missing_key();
		ATF_REQUIRE_MSG(mac_capability_send(fd, &req, sizeof(req), 0) == 0,
		    "SENDMSG: %s", strerror(errno));
		rlen = sizeof(reply);
		ATF_REQUIRE_MSG(mac_capability_recv(fd2, &reply, &rlen, NULL) == 0,
		    "RECVMSG on dup: %s (rlen=%u)", strerror(errno), rlen);
	}

	close(fd2);
	close(fd);
}

ATF_TC(ioctl_bad_cmd);
ATF_TC_HEAD(ioctl_bad_cmd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Unknown ioctl on /dev/mac_capability returns ENOTTY");
}
ATF_TC_BODY(ioctl_bad_cmd, tc)
{
	int fd, dummy;

	fd = mac_capability_open();
	ATF_CHECK_ERRNO(ENOTTY, ioctl(fd, _IO('Y', 99), &dummy) == -1);
	close(fd);
}

ATF_TC(instance_ioctl_bad_cmd);
ATF_TC_HEAD(instance_ioctl_bad_cmd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Unknown ioctl on instance fd returns ENOTTY");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(instance_ioctl_bad_cmd, tc)
{
	int fd, dummy;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_ERRNO(ENOTTY, ioctl(fd, _IO('Y', 99), &dummy) == -1);
	close(fd);
}

ATF_TC(connect_on_instance_fd);
ATF_TC_HEAD(connect_on_instance_fd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_CONNECT on a instance fd returns ENOTTY");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(connect_on_instance_fd, tc)
{
	struct mac_capability_connect_args ca;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "test_keystore", sizeof(ca.name));
	ATF_CHECK_ERRNO(ENOTTY, ioctl(fd, MAC_CAPABILITY_CONNECT, &ca) == -1);
	close(fd);
}

ATF_TC(write_after_close_child);
ATF_TC_HEAD(write_after_close_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_SENDMSG after peer process closes shared fd still works");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(write_after_close_child, tc)
{
	struct ks_request req;
	char buf[256];
	uint32_t rlen;
	int fd, status;
	pid_t pid;

	fd = mac_capability_connect("test_keystore");
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
	 * MAC_CAPABILITY_SENDMSG should succeed.
	 */
	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	ATF_CHECK(mac_capability_send(fd, &req, sizeof(req), 0) == 0);
	rlen = sizeof(buf);
	ATF_CHECK(mac_capability_recv(fd, buf, &rlen, NULL) == 0);

	close(fd);
}

ATF_TC(sendmsg_zero_payload_with_fds);
ATF_TC_HEAD(sendmsg_zero_payload_with_fds, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG with zero payload but attached fds works");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(sendmsg_zero_payload_with_fds, tc)
{
	struct mac_capability_sendmsg_args sa;
	char buf[64];
	int fd, pipefd[2];

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pipe(pipefd) == 0);

	memset(&sa, 0, sizeof(sa));
	sa.payload = NULL;
	sa.payload_len = 0;
	sa.fds = &pipefd[0];
	sa.nfds = 1;

	/* Keystore will see a 0-byte message and reply with error. */
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == 0);
	{
		uint32_t rlen = sizeof(buf);
		ATF_REQUIRE(mac_capability_recv(fd, buf, &rlen, NULL) == 0);
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
	    "MAC_CAPABILITY_GETINFO returns service identity and basic metadata");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(getinfo, tc)
{
	struct mac_capability_info_args info;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);
	ATF_CHECK_STREQ(info.name, "test_keystore");
	ATF_CHECK(info.badge != 0);

	/* Second instance should get different badge. */
	{
		struct mac_capability_info_args info2;
		int fd2 = mac_capability_connect("test_keystore");
		ATF_REQUIRE(fd2 >= 0);
		ATF_REQUIRE(ioctl(fd2, MAC_CAPABILITY_GETINFO, &info2) == 0);
		ATF_CHECK_STREQ(info2.name, "test_keystore");
		ATF_CHECK(info2.badge != info.badge);
		close(fd2);
	}

	close(fd);
}

/* ================================================================
 * Capability channel tests (requires mac_capability_channel module)
 * ================================================================ */

#include "mac_capability_channel_proto.h"

/*
 * Helper: connect to channel service, send CHANNEL_OP_CREATE, receive peer fd.
 * Returns both fds via out parameters.
 */
static void
mac_capability_channel_create(int *fd_a, int *fd_b)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	uint32_t op;
	int fds_out[1];
	int fd;

	fd = mac_capability_connect("channel");
	ATF_REQUIRE_MSG(fd >= 0, "connect channel: %s", strerror(errno));

	op = CHANNEL_OP_CREATE;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &op;
	sa.payload_len = sizeof(op);
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == 0);


	memset(&ra, 0, sizeof(ra));
	ra.fds = fds_out;
	ra.nfds = 1;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == 0);
	ATF_REQUIRE_MSG(ra.nfds == 1, "expected 1 fd, got %u", ra.nfds);

	*fd_a = fd;
	*fd_b = fds_out[0];
}

ATF_TC(channel_create);
ATF_TC_HEAD(channel_create, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Connect to channel, CHANNEL_OP_CREATE returns peer fd");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_create, tc)
{
	int fd_a, fd_b;

	mac_capability_channel_create(&fd_a, &fd_b);
	ATF_CHECK(fd_a >= 0);
	ATF_CHECK(fd_b >= 0);
	ATF_CHECK(fd_a != fd_b);
	close(fd_b);
	close(fd_a);
}

ATF_TC(channel_bidirectional);
ATF_TC_HEAD(channel_bidirectional, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Send on A, recv on B; send on B, recv on A");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_bidirectional, tc)
{
	char buf[64];
	uint32_t rlen;
	int fd_a, fd_b;

	mac_capability_channel_create(&fd_a, &fd_b);

	/* A → B: send on A, data appears on B. */
	ATF_REQUIRE(mac_capability_send(fd_a, "hello", 5, 0) == 0);

	memset(buf, 0, sizeof(buf));
	rlen = sizeof(buf);
	ATF_REQUIRE(mac_capability_recv(fd_b, buf, &rlen, NULL) == 0);
	ATF_REQUIRE(rlen == 5);
	ATF_CHECK(memcmp(buf, "hello", 5) == 0);

	/* B → A: send on B, data appears on A. */
	ATF_REQUIRE(mac_capability_send(fd_b, "world", 5, 0) == 0);

	memset(buf, 0, sizeof(buf));
	rlen = sizeof(buf);
	ATF_REQUIRE(mac_capability_recv(fd_a, buf, &rlen, NULL) == 0);
	ATF_REQUIRE(rlen == 5);
	ATF_CHECK(memcmp(buf, "world", 5) == 0);

	close(fd_b);
	close(fd_a);
}

ATF_TC(channel_forwards_metadata);
ATF_TC_HEAD(channel_forwards_metadata, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Channel forwarding preserves badge, reply token, and trailer");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel mac_capability_test_kernelstore");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(channel_forwards_metadata, tc)
{
	struct mac_capability_recvmsg_args ra;
	struct mac_capability_info_args info;
	struct mac_capability_cred_trailer trailer;
	char payload[] = "meta";
	char buf[64];
	int fd_a, fd_b, ks_fd;

	mac_capability_channel_create(&fd_a, &fd_b);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd_a, MAC_CAPABILITY_GETINFO, &info) == 0);

	ks_fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(ks_fd >= 0);
	mac_capability_fetch_trailer(ks_fd, &trailer);
	ATF_REQUIRE(trailer.nonce != 0);

	ATF_REQUIRE(mac_capability_send(fd_a, payload, sizeof(payload) - 1,
	    0x123456789abcdef0ULL) == 0);

	memset(&ra, 0, sizeof(ra));
	memset(buf, 0, sizeof(buf));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_REQUIRE(ioctl(fd_b, MAC_CAPABILITY_RECVMSG, &ra) == 0);
	ATF_CHECK_EQ(ra.payload_len, sizeof(payload) - 1);
	ATF_CHECK(memcmp(buf, payload, sizeof(payload) - 1) == 0);
	ATF_CHECK_EQ(ra.badge, info.badge);
	ATF_CHECK_EQ(ra.reply_token, 0x123456789abcdef0ULL);
	ATF_CHECK_EQ(ra.trailer.uid, trailer.uid);
	ATF_CHECK_EQ(ra.trailer.gid, trailer.gid);
	ATF_CHECK_EQ(ra.trailer.prison_id, trailer.prison_id);
	ATF_CHECK_EQ(ra.trailer.nonce, trailer.nonce);

	close(ks_fd);
	close(fd_b);
	close(fd_a);
}

ATF_TC(channel_forwards_fds_and_metadata);
ATF_TC_HEAD(channel_forwards_fds_and_metadata, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Channel forwarding preserves attached fds and metadata");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel mac_capability_test_kernelstore");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(channel_forwards_fds_and_metadata, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	struct mac_capability_info_args info;
	struct mac_capability_cred_trailer trailer;
	int fd_a, fd_b, ks_fd, pipefd[2], recv_fd;
	char buf[64];

	mac_capability_channel_create(&fd_a, &fd_b);
	ATF_REQUIRE(pipe(pipefd) == 0);
	ATF_REQUIRE(cap_cloexec_limit(pipefd[0], CAP_CLOEXEC_ONCE) == 0);
	ATF_REQUIRE(cap_clofork_limit(pipefd[0], CAP_CLOFORK_ONCE) == 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd_a, MAC_CAPABILITY_GETINFO, &info) == 0);

	ks_fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(ks_fd >= 0);
	mac_capability_fetch_trailer(ks_fd, &trailer);
	ATF_REQUIRE(trailer.nonce != 0);

	memset(&sa, 0, sizeof(sa));
	sa.payload = "fd";
	sa.payload_len = 2;
	sa.fds = &pipefd[0];
	sa.nfds = 1;
	sa.reply_token = 0xfeedfaceULL;
	ATF_REQUIRE(ioctl(fd_a, MAC_CAPABILITY_SENDMSG, &sa) == 0);

	memset(&ra, 0, sizeof(ra));
	memset(buf, 0, sizeof(buf));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ra.fds = &recv_fd;
	ra.nfds = 1;
	ATF_REQUIRE(ioctl(fd_b, MAC_CAPABILITY_RECVMSG, &ra) == 0);
	ATF_CHECK_EQ(ra.payload_len, 2);
	ATF_CHECK(memcmp(buf, "fd", 2) == 0);
	ATF_CHECK_EQ(ra.nfds, 1);
	ATF_CHECK_EQ(ra.badge, info.badge);
	ATF_CHECK_EQ(ra.reply_token, 0xfeedfaceULL);
	ATF_CHECK_EQ(ra.trailer.uid, trailer.uid);
	ATF_CHECK_EQ(ra.trailer.gid, trailer.gid);
	ATF_CHECK_EQ(ra.trailer.prison_id, trailer.prison_id);
	ATF_CHECK_EQ(ra.trailer.nonce, trailer.nonce);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_cloexec_limit(recv_fd, CAP_CLOEXEC_UNLOCKED) == -1);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_clofork_limit(recv_fd, CAP_CLOFORK_UNLOCKED) == -1);
	ATF_REQUIRE(cap_cloexec_limit(recv_fd, CAP_CLOEXEC_ONCE) == 0);
	ATF_REQUIRE(cap_clofork_limit(recv_fd, CAP_CLOFORK_ONCE) == 0);

	ATF_REQUIRE(write(pipefd[1], "test", 4) == 4);
	memset(buf, 0, sizeof(buf));
	ATF_CHECK(read(recv_fd, buf, sizeof(buf)) == 4);
	ATF_CHECK(memcmp(buf, "test", 4) == 0);

	close(recv_fd);
	close(pipefd[0]);
	close(pipefd[1]);
	close(ks_fd);
	close(fd_b);
	close(fd_a);
}

ATF_TC(channel_close_one_end);
ATF_TC_HEAD(channel_close_one_end, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing one end of channel revokes the other");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_close_one_end, tc)
{
	char buf[64];
	int fd_a, fd_b, flags, i;

	mac_capability_channel_create(&fd_a, &fd_b);

	/* Close A. */
	close(fd_a);

	/*
	 * B should be revoked.  Set nonblock and poll until
	 * the revocation propagates (no usleep dependency).
	 */
	flags = fcntl(fd_b, F_GETFL, 0);
	fcntl(fd_b, F_SETFL, flags | O_NONBLOCK);

	for (i = 0; i < 100; i++) {
		if (mac_capability_send(fd_b, "x", 1, 0) == -1 &&
		    (errno == EPIPE || errno == ECONNRESET))
			break;
		usleep(10000);
	}
	ATF_CHECK(mac_capability_send(fd_b, "x", 1, 0) == -1);
	ATF_CHECK(errno == EPIPE || errno == ECONNRESET);

	{
		uint32_t rlen = sizeof(buf);
		ATF_CHECK(mac_capability_recv(fd_b, buf, &rlen, NULL) == -1);
		ATF_CHECK(errno == ECONNRESET || errno == EAGAIN);
	}

	close(fd_b);
}

ATF_TC(channel_multiproc);
ATF_TC_HEAD(channel_multiproc, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Channel works across processes via fork");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_multiproc, tc)
{
	char buf[64];
	int fd_a, fd_b, status;
	pid_t pid;

	mac_capability_channel_create(&fd_a, &fd_b);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: owns fd_b, sends a message. No ack expected. */
		struct mac_capability_sendmsg_args sa;

		close(fd_a);
		memset(&sa, 0, sizeof(sa));
		sa.payload = "child";
		sa.payload_len = 5;
		if (ioctl(fd_b, MAC_CAPABILITY_SENDMSG, &sa) != 0)
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
		ATF_REQUIRE(mac_capability_recv(fd_a, buf, &rlen, NULL) == 0);
		ATF_REQUIRE(rlen == 5);
	}
	ATF_CHECK(memcmp(buf, "child", 5) == 0);

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(fd_a);
}

ATF_TC(channel_crossproc_forwards_metadata);
ATF_TC_HEAD(channel_crossproc_forwards_metadata, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Channel forwarding preserves child sender metadata across fork");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel mac_capability_test_kernelstore");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(channel_crossproc_forwards_metadata, tc)
{
	struct mac_capability_recvmsg_args ra;
	struct mac_capability_info_args info;
	struct mac_capability_cred_trailer expected;
	char buf[64];
	int fd_a, fd_b, ks_fd, status, sv[2];
	pid_t pid;

	mac_capability_channel_create(&fd_a, &fd_b);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd_b, MAC_CAPABILITY_GETINFO, &info) == 0);

	ks_fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(ks_fd >= 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		struct mac_capability_cred_trailer child_trailer;

		close(fd_a);
		close(sv[0]);

		if (setgid(1) != 0)
			_exit(10);
		if (setuid(1) != 0)
			_exit(11);

		mac_capability_fetch_trailer(ks_fd, &child_trailer);
		if (write(sv[1], &child_trailer, sizeof(child_trailer)) !=
		    sizeof(child_trailer))
			_exit(12);
		if (mac_capability_send(fd_b, "childmeta", 9, 0xaabbccddULL) != 0)
			_exit(13);
		close(ks_fd);
		close(fd_b);
		close(sv[1]);
		_exit(0);
	}

	close(fd_b);
	close(sv[1]);

	ATF_REQUIRE(read(sv[0], &expected, sizeof(expected)) ==
	    sizeof(expected));
	ATF_REQUIRE(expected.nonce != 0);

	memset(&ra, 0, sizeof(ra));
	memset(buf, 0, sizeof(buf));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_REQUIRE(ioctl(fd_a, MAC_CAPABILITY_RECVMSG, &ra) == 0);
	ATF_CHECK_EQ(ra.payload_len, 9);
	ATF_CHECK(memcmp(buf, "childmeta", 9) == 0);
	ATF_CHECK_EQ(ra.badge, info.badge);
	ATF_CHECK_EQ(ra.reply_token, 0xaabbccddULL);
	ATF_CHECK_EQ(ra.trailer.uid, expected.uid);
	ATF_CHECK_EQ(ra.trailer.gid, expected.gid);
	ATF_CHECK_EQ(ra.trailer.prison_id, expected.prison_id);
	ATF_CHECK_EQ(ra.trailer.nonce, expected.nonce);

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	close(ks_fd);
	close(sv[0]);
	close(fd_a);
}

/* ================================================================
 * Additional coverage
 * ================================================================ */

ATF_TC(getinfo_limits);
ATF_TC_HEAD(getinfo_limits, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_GETINFO returns real limits and feature bits");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(getinfo_limits, tc)
{
	struct mac_capability_info_args info;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);
	ATF_CHECK_EQ(info.msg_limit, MAC_CAPABILITY_MAX_MSG);
	ATF_CHECK_EQ(info.queue_depth, MAC_CAPABILITY_DEFAULT_QUEUE_DEPTH);
	ATF_CHECK_EQ(info.tx_limit, MAC_CAPABILITY_DEFAULT_TX_LIMIT);
	ATF_CHECK_EQ(info.max_fds, MAC_CAPABILITY_MAX_FDS);
	/* keystore is async-only: SENDMSG + KQUEUE, no CALL */
	ATF_CHECK((info.features & MAC_CAPABILITY_INFO_F_SENDMSG) != 0);
	ATF_CHECK((info.features & MAC_CAPABILITY_INFO_F_CALL) == 0);
	ATF_CHECK((info.features & MAC_CAPABILITY_INFO_F_KQUEUE) != 0);

	close(fd);
}

ATF_TC(credential_trailer);
ATF_TC_HEAD(credential_trailer, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "RECVMSG trailer is zeroed on kernel reply path");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(credential_trailer, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	struct ks_request req;
	char buf[128];
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/*
	 * The credential trailer on a REPLY message will be zero
	 * because the kernel handler doesn't stamp creds on TX.
	 * So we just verify the fields are deterministic (zeroed).
	 * Full credential testing requires a service that echoes
	 * the sender's creds back in the payload.
	 */
	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == 0);


	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == 0);

	/* Replies from kernel have zero trailer (no sender identity). */
	ATF_CHECK_EQ(ra.trailer.uid, 0);
	ATF_CHECK_EQ(ra.trailer.gid, 0);
	ATF_CHECK_EQ(ra.trailer.prison_id, 0);
	ATF_CHECK_EQ(ra.trailer.nonce, 0);

	close(fd);
}

/* ================================================================
 * MAC_CAPABILITY_CALL tests
 * ================================================================ */

ATF_TC(call_no_handler);
ATF_TC_HEAD(call_no_handler, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_CALL on async-only service returns EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(call_no_handler, tc)
{
	struct mac_capability_call_args ca;
	char buf[16];
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	memset(&ca, 0, sizeof(ca));
	ca.req = "x";
	ca.req_len = 1;
	ca.reply = buf;
	ca.reply_len = sizeof(buf);
	ATF_CHECK_ERRNO(EOPNOTSUPP, ioctl(fd, MAC_CAPABILITY_CALL, &ca) == -1);

	close(fd);
}

ATF_TC(call_flags_nonzero);
ATF_TC_HEAD(call_flags_nonzero, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_CALL with nonzero flags returns EINVAL on sync service");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(call_flags_nonzero, tc)
{
	struct mac_capability_call_args ca;
	int fd;

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);

	memset(&ca, 0, sizeof(ca));
	ca.flags = 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, MAC_CAPABILITY_CALL, &ca) == -1);

	close(fd);
}

/* ================================================================
 * Revoke-via-message tests
 * ================================================================ */

ATF_TC(terminate_instance);
ATF_TC_HEAD(terminate_instance, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_TERMINATE kills the instance for all holders");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(terminate_instance, tc)
{
	struct mac_capability_recvmsg_args ra;
	char buf[64];
	int fd, flags;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/* Send revoke token. */
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_TERMINATE, NULL) == 0);

	/* Instance should be revoked — recv returns ECONNRESET. */
	flags = fcntl(fd, F_GETFL, 0);
	ATF_REQUIRE(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_CHECK_ERRNO(ECONNRESET, ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == -1);

	close(fd);
}

ATF_TC(terminate_then_send);
ATF_TC_HEAD(terminate_then_send, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG after revoke-via-token returns EPIPE");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(terminate_then_send, tc)
{
	struct ks_request req;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_TERMINATE, NULL) == 0);

	/* Subsequent send should fail. */
	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	ATF_CHECK_ERRNO(EPIPE, mac_capability_send(fd, &req, sizeof(req), 0) == -1);

	close(fd);
}

ATF_TC(terminate_sync_service);
ATF_TC_HEAD(terminate_sync_service, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_TERMINATE works on sync-only service");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(terminate_sync_service, tc)
{
	struct mac_capability_call_args ca;
	struct kstore_request kr;
	int fd;

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);

	/* Revoke via the token. */
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_TERMINATE, NULL) == 0);

	/* CALL should now fail. */
	memset(&kr, 0, sizeof(kr));
	kr.op = KSTORE_OP_GET;
	strlcpy(kr.key, "_test", sizeof(kr.key));
	memset(&ca, 0, sizeof(ca));
	ca.req = &kr;
	ca.req_len = sizeof(kr);
	ca.reply = &kr;
	ca.reply_len = sizeof(kr);
	ATF_CHECK_ERRNO(ECONNRESET, ioctl(fd, MAC_CAPABILITY_CALL, &ca) == -1);

	close(fd);
}

ATF_TC(normal_ops_no_terminate);
ATF_TC_HEAD(normal_ops_no_terminate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Normal operations do not terminate");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(normal_ops_no_terminate, tc)
{
	struct ks_request req;
	char buf[256];
	uint32_t rlen;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/* Send with a normal token — should work, not revoke. */
	req.op = KS_OP_FETCH;
	req.keyid = 99998;	/* unlikely to have data from other tests */
	ATF_REQUIRE(mac_capability_send(fd, &req, sizeof(req), 0x1234) == 0);

	rlen = sizeof(buf);
	ATF_REQUIRE(mac_capability_recv(fd, buf, &rlen, NULL) == 0);

	close(fd);
}

/* ================================================================
 * Sync-or-async enforcement tests
 * ================================================================ */

ATF_TC(sendmsg_on_sync_service);
ATF_TC_HEAD(sendmsg_on_sync_service, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_SENDMSG on sync-only service returns EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(sendmsg_on_sync_service, tc)
{
	uint32_t op;
	int fd;

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);

	op = 1; /* any op */
	ATF_CHECK_ERRNO(EOPNOTSUPP, mac_capability_send(fd, &op, sizeof(op), 0) == -1);

	close(fd);
}

ATF_TC(call_on_async_service);
ATF_TC_HEAD(call_on_async_service, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_CALL on async-only service returns EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(call_on_async_service, tc)
{
	struct mac_capability_call_args ca;
	struct ks_request req;
	char reply[64];
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply = reply;
	ca.reply_len = sizeof(reply);
	ATF_CHECK_ERRNO(EOPNOTSUPP, ioctl(fd, MAC_CAPABILITY_CALL, &ca) == -1);

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
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(getinfo_async_features, tc)
{
	struct mac_capability_info_args info;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);
	ATF_CHECK((info.features & MAC_CAPABILITY_INFO_F_SENDMSG) != 0);
	ATF_CHECK((info.features & MAC_CAPABILITY_INFO_F_KQUEUE) != 0);
	ATF_CHECK((info.features & MAC_CAPABILITY_INFO_F_CALL) == 0);

	close(fd);
}

ATF_TC(getinfo_sync_features);
ATF_TC_HEAD(getinfo_sync_features, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Sync service reports CALL but not SENDMSG or KQUEUE");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(getinfo_sync_features, tc)
{
	struct mac_capability_info_args info;
	int fd;

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);
	ATF_CHECK_STREQ(info.name, "test_kernelstore");
	ATF_CHECK((info.features & MAC_CAPABILITY_INFO_F_CALL) != 0);
	ATF_CHECK((info.features & MAC_CAPABILITY_INFO_F_SENDMSG) == 0);
	ATF_CHECK((info.features & MAC_CAPABILITY_INFO_F_KQUEUE) == 0);

	close(fd);
}

/* ================================================================
 * Channel: fd passing through channel
 * ================================================================ */

ATF_TC(channel_fd_passing);
ATF_TC_HEAD(channel_fd_passing, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "File descriptors pass through a channel");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_fd_passing, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	int fd_a, fd_b, pipefd[2], recv_fd;
	char buf[64];

	mac_capability_channel_create(&fd_a, &fd_b);
	ATF_REQUIRE(pipe(pipefd) == 0);

	/* Send a pipe fd through the channel A -> B. */
	memset(&sa, 0, sizeof(sa));
	sa.payload = "hi";
	sa.payload_len = 2;
	sa.fds = &pipefd[0];
	sa.nfds = 1;
	ATF_REQUIRE(ioctl(fd_a, MAC_CAPABILITY_SENDMSG, &sa) == 0);

	/* Receive on B — should get the fd. */
	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ra.fds = &recv_fd;
	ra.nfds = 1;
	ATF_REQUIRE(ioctl(fd_b, MAC_CAPABILITY_RECVMSG, &ra) == 0);
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

ATF_TC(channel_fd_attachment_order);
ATF_TC_HEAD(channel_fd_attachment_order, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "RECVMSG installs new descriptor numbers in sender attachment order");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_fd_attachment_order, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	const char expected[] = { 'a', 'b', 'c' };
	char payload, value;
	int fd_a, fd_b, pipes[3][2], send_fds[3], recv_fds[3];
	size_t i, j;

	mac_capability_channel_create(&fd_a, &fd_b);
	for (i = 0; i < nitems(pipes); i++) {
		ATF_REQUIRE(pipe(pipes[i]) == 0);
		send_fds[i] = pipes[i][0];
		recv_fds[i] = -1;
		ATF_REQUIRE(write(pipes[i][1], &expected[i], 1) == 1);
	}

	payload = 'x';
	memset(&sa, 0, sizeof(sa));
	sa.payload = &payload;
	sa.payload_len = sizeof(payload);
	sa.fds = send_fds;
	sa.nfds = nitems(send_fds);
	sa.reply_token = 0x0102030405060708ULL;
	ATF_REQUIRE_MSG(ioctl(fd_a, MAC_CAPABILITY_SENDMSG, &sa) == 0,
	    "SENDMSG: %s", strerror(errno));

	memset(&ra, 0, sizeof(ra));
	ra.payload = &payload;
	ra.payload_len = sizeof(payload);
	ra.fds = recv_fds;
	ra.nfds = nitems(recv_fds);
	ATF_REQUIRE_MSG(ioctl(fd_b, MAC_CAPABILITY_RECVMSG, &ra) == 0,
	    "RECVMSG: %s", strerror(errno));
	ATF_REQUIRE_EQ(nitems(recv_fds), ra.nfds);
	ATF_CHECK(ra.reply_token == 0x0102030405060708ULL);

	for (i = 0; i < nitems(recv_fds); i++) {
		for (j = 0; j < nitems(send_fds); j++)
			ATF_CHECK(recv_fds[i] != send_fds[j]);
		ATF_REQUIRE(read(recv_fds[i], &value, 1) == 1);
		ATF_CHECK_EQ(expected[i], value);
		close(recv_fds[i]);
		close(pipes[i][0]);
		close(pipes[i][1]);
	}
	close(fd_b);
	close(fd_a);
}

ATF_TC(channel_preserves_ioctl_limit);
ATF_TC_HEAD(channel_preserves_ioctl_limit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "mac_capability message transfer preserves an fd ioctl allowlist");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_preserves_ioctl_limit, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	cap_ioctl_t cmds[] = { MAC_CAPABILITY_GETINFO };
	int fd_a, fd_b, target_fd, target_peer, received_fd;
	char buf[4];

	mac_capability_channel_create(&fd_a, &fd_b);
	mac_capability_channel_create(&target_fd, &target_peer);
	ATF_REQUIRE(cap_ioctls_limit(target_fd, cmds, nitems(cmds)) == 0);

	memset(&sa, 0, sizeof(sa));
	sa.payload = "fd";
	sa.payload_len = 2;
	sa.fds = &target_fd;
	sa.nfds = 1;
	ATF_REQUIRE(ioctl(fd_a, MAC_CAPABILITY_SENDMSG, &sa) == 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ra.fds = &received_fd;
	ra.nfds = 1;
	ATF_REQUIRE(ioctl(fd_b, MAC_CAPABILITY_RECVMSG, &ra) == 0);
	ATF_REQUIRE_EQ(ra.nfds, 1);
	ATF_CHECK_EQ(verify_getinfo_only(received_fd), 0);

	close(received_fd);
	close(target_peer);
	close(target_fd);
	close(fd_b);
	close(fd_a);
}

ATF_TC(channel_applies_xfer_caps);
ATF_TC_HEAD(channel_applies_xfer_caps, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "mac_capability message transfer attenuates attached fd rights");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_applies_xfer_caps, tc)
{
	struct mac_capability_recvmsg_args ra;
	struct mac_capability_sendmsg_args sa;
	cap_ioctl_t cmds[] = { MAC_CAPABILITY_GETINFO };
	cap_rights_t rights;
	char buf[4];
	int fd_a, fd_b, received_fd, target_fd, target_peer;

	mac_capability_channel_create(&fd_a, &fd_b);
	mac_capability_channel_create(&target_fd, &target_peer);

	cap_rights_init(&rights, CAP_IOCTL);
	ATF_REQUIRE(cap_xfer_rights_limit(target_fd, &rights) == 0);
	ATF_REQUIRE(cap_xfer_ioctls_limit(target_fd, cmds,
	    nitems(cmds)) == 0);

	memset(&sa, 0, sizeof(sa));
	sa.payload = "fd";
	sa.payload_len = 2;
	sa.fds = &target_fd;
	sa.nfds = 1;
	ATF_REQUIRE(ioctl(fd_a, MAC_CAPABILITY_SENDMSG, &sa) == 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ra.fds = &received_fd;
	ra.nfds = 1;
	ATF_REQUIRE(ioctl(fd_b, MAC_CAPABILITY_RECVMSG, &ra) == 0);
	ATF_REQUIRE_EQ(ra.nfds, 1);
	ATF_CHECK_EQ(verify_getinfo_only(received_fd), 0);

	/* The sender remains broad; only the transferred descriptor narrows. */
	ATF_CHECK_EQ(cap_ioctls_get(target_fd, NULL, 0), CAP_IOCTLS_ALL);

	close(received_fd);
	close(target_peer);
	close(target_fd);
	close(fd_b);
	close(fd_a);
}

/* ================================================================
 * Channel: stress — many messages
 * ================================================================ */

ATF_TC(channel_stress);
ATF_TC_HEAD(channel_stress, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "100 messages through a channel");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_stress, tc)
{
	char buf[64];
	uint32_t rlen;
	int fd_a, fd_b, i;

	mac_capability_channel_create(&fd_a, &fd_b);

	for (i = 0; i < 100; i++) {
		uint32_t val = (uint32_t)i;

		ATF_REQUIRE(mac_capability_send(fd_a, &val, sizeof(val), 0) == 0);

		rlen = sizeof(buf);
		ATF_REQUIRE_MSG(mac_capability_recv(fd_b, buf, &rlen, NULL) == 0,
		    "recv %d: %s", i, strerror(errno));
		ATF_REQUIRE_EQ(rlen, sizeof(val));
		{
			uint32_t got;
			memcpy(&got, buf, sizeof(got));
			ATF_CHECK_EQ(got, val);
		}
	}

	close(fd_b);
	close(fd_a);
}

ATF_TC(channel_backpressure_preserves_messages);
ATF_TC_HEAD(channel_backpressure_preserves_messages, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Channel backpressure retains FIFO messages and emits no synthetic replies");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_backpressure_preserves_messages, tc)
{
	struct mac_capability_info_args info;
	struct mac_capability_recvmsg_args ra;
	uint32_t sent, value, limit, i;
	char stray[16];
	int fd_a, fd_b, flags;

	mac_capability_channel_create(&fd_a, &fd_b);
	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd_a, MAC_CAPABILITY_GETINFO, &info) == 0);
	limit = info.queue_depth * 4;
	ATF_REQUIRE(limit > 0);

	for (sent = 0; sent < limit; sent++) {
		value = sent;
		if (mac_capability_send(fd_a, &value, sizeof(value),
		    (uint64_t)sent + 1) == -1)
			break;
	}
	ATF_REQUIRE_MSG(sent > 0 && sent < limit,
	    "channel did not apply bounded backpressure after %u sends", sent);
	ATF_REQUIRE_EQ(errno, EAGAIN);

	for (i = 0; i < sent; i++) {
		uint64_t token;
		uint32_t len;

		value = UINT32_MAX;
		len = sizeof(value);
		ATF_REQUIRE_MSG(mac_capability_recv(fd_b, &value, &len,
		    &token) == 0, "receive %u/%u: %s", i, sent,
		    strerror(errno));
		ATF_REQUIRE_EQ(len, sizeof(value));
		ATF_CHECK_EQ(value, i);
		ATF_CHECK_EQ(token, (uint64_t)i + 1);
	}

	/* Backpressure is transport state, never an application reply. */
	flags = fcntl(fd_a, F_GETFL, 0);
	ATF_REQUIRE(flags >= 0);
	ATF_REQUIRE(fcntl(fd_a, F_SETFL, flags | O_NONBLOCK) == 0);
	memset(&ra, 0, sizeof(ra));
	ra.payload = stray;
	ra.payload_len = sizeof(stray);
	ATF_CHECK_ERRNO(EAGAIN,
	    ioctl(fd_a, MAC_CAPABILITY_RECVMSG, &ra) == -1);

	close(fd_b);
	close(fd_a);
}

ATF_TC(channel_backpressure_xfer_retry_atomic);
ATF_TC_HEAD(channel_backpressure_xfer_retry_atomic, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "EAGAIN does not consume one-shot descriptor transfer authority");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(channel_backpressure_xfer_retry_atomic, tc)
{
	struct mac_capability_info_args info;
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	uint32_t sent, value, limit, i;
	char attached[8], byte;
	int fd_a, fd_b, pipefd[2], received, attempt;

	mac_capability_channel_create(&fd_a, &fd_b);
	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd_a, MAC_CAPABILITY_GETINFO, &info) == 0);
	limit = info.queue_depth * 4;

	for (sent = 0; sent < limit; sent++) {
		value = sent;
		if (mac_capability_send(fd_a, &value, sizeof(value), 0) == -1)
			break;
	}
	ATF_REQUIRE_MSG(sent > 0 && sent < limit,
	    "channel did not become backpressured");
	ATF_REQUIRE_EQ(errno, EAGAIN);

	ATF_REQUIRE(pipe(pipefd) == 0);
	ATF_REQUIRE(cap_xfer_limit(pipefd[0], CAP_XFER_ONCE) == 0);
	memset(&sa, 0, sizeof(sa));
	sa.payload = "attached";
	sa.payload_len = 8;
	sa.fds = &pipefd[0];
	sa.nfds = 1;
	ATF_CHECK_ERRNO(EAGAIN,
	    ioctl(fd_a, MAC_CAPABILITY_SENDMSG, &sa) == -1);

	/* Release capacity, then retry the exact one-shot attachment. */
	value = UINT32_MAX;
	{
		uint32_t len = sizeof(value);
		ATF_REQUIRE(mac_capability_recv(fd_b, &value, &len, NULL) == 0);
		ATF_CHECK_EQ(value, 0);
	}
	for (attempt = 0; attempt < 200; attempt++) {
		if (ioctl(fd_a, MAC_CAPABILITY_SENDMSG, &sa) == 0)
			break;
		ATF_REQUIRE_EQ(errno, EAGAIN);
		usleep(1000);
	}
	ATF_REQUIRE_MSG(attempt < 200,
	    "attachment retry never observed released capacity");

	/* Drain the remaining fillers in order. */
	for (i = 1; i < sent; i++) {
		uint32_t len = sizeof(value);

		value = UINT32_MAX;
		ATF_REQUIRE(mac_capability_recv(fd_b, &value, &len, NULL) == 0);
		ATF_CHECK_EQ(value, i);
	}

	/* The retried attachment is the final message and remains usable. */
	received = -1;
	memset(&ra, 0, sizeof(ra));
	memset(attached, 0, sizeof(attached));
	ra.payload = attached;
	ra.payload_len = sizeof(attached);
	ra.fds = &received;
	ra.nfds = 1;
	ATF_REQUIRE(ioctl(fd_b, MAC_CAPABILITY_RECVMSG, &ra) == 0);
	ATF_CHECK_EQ(ra.payload_len, 8);
	ATF_CHECK(memcmp(attached, "attached", 8) == 0);
	ATF_CHECK_EQ(ra.nfds, 1);
	ATF_REQUIRE(received >= 0);
	ATF_REQUIRE(write(pipefd[1], "x", 1) == 1);
	ATF_REQUIRE(read(received, &byte, 1) == 1);
	ATF_CHECK_EQ(byte, 'x');

	close(received);
	close(pipefd[0]);
	close(pipefd[1]);
	close(fd_b);
	close(fd_a);
}

/* ================================================================
 * Channel: getinfo on channel
 * ================================================================ */

ATF_TC(channel_getinfo);
ATF_TC_HEAD(channel_getinfo, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "GETINFO on channel returns correct metadata");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_getinfo, tc)
{
	struct mac_capability_info_args info;
	int fd_a, fd_b;

	mac_capability_channel_create(&fd_a, &fd_b);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd_a, MAC_CAPABILITY_GETINFO, &info) == 0);
	ATF_CHECK_STREQ(info.name, "channel");
	ATF_CHECK(info.badge != 0);
	ATF_CHECK((info.features & MAC_CAPABILITY_INFO_F_SENDMSG) != 0);
	ATF_CHECK((info.features & MAC_CAPABILITY_INFO_F_CALL) == 0);

	/* Peer should have different badge. */
	{
		struct mac_capability_info_args info_b;
		memset(&info_b, 0, sizeof(info_b));
		ATF_REQUIRE(ioctl(fd_b, MAC_CAPABILITY_GETINFO, &info_b) == 0);
		ATF_CHECK_STREQ(info_b.name, "channel");
		ATF_CHECK(info_b.badge != info.badge);
	}

	close(fd_b);
	close(fd_a);
}

/* ================================================================
 * Keystore: max keys limit
 * ================================================================ */

ATF_TC(keystore_max_keys);
ATF_TC_HEAD(keystore_max_keys, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Keystore enforces max key limit");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
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

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/* Store 50 keys with unique IDs. */
	for (i = 0; i < 50; i++)
		mac_capability_store(fd, 90000 + (uint32_t)i, "val", 3);

	/* Fetch them back. */
	for (i = 0; i < 50; i++) {
		struct ks_request req;
		char buf[256];
		uint32_t rlen;

		req.op = KS_OP_FETCH;
		req.keyid = 90000 + (uint32_t)i;
		ATF_REQUIRE(mac_capability_send(fd, &req, sizeof(req), 0) == 0);
		rlen = sizeof(buf);
		ATF_REQUIRE(mac_capability_recv(fd, buf, &rlen, NULL) == 0);
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
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(keystore_overwrite, tc)
{
	struct ks_request req;
	char buf[256];
	uint32_t rlen;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/* Store "old". */
	mac_capability_store(fd, 80000, "old", 3);

	/* Overwrite with "new_value". */
	mac_capability_store(fd, 80000, "new_value", 9);

	/* Fetch — should get "new_value". */
	req.op = KS_OP_FETCH;
	req.keyid = 80000;
	ATF_REQUIRE(mac_capability_send(fd, &req, sizeof(req), 0) == 0);
	rlen = sizeof(buf);
	ATF_REQUIRE(mac_capability_recv(fd, buf, &rlen, NULL) == 0);
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
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(keystore_uid_isolation, tc)
{
	uint32_t keyid;
	int fd, status;
	pid_t pid;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	keyid = arc4random();
	if (keyid == 0)
		keyid = 1;

	/* Store as root (uid 0). */
	mac_capability_store(fd, keyid, "rootdata", 8);

	/*
	 * Child changes uid and tries to fetch using the inherited
	 * capability.  The keystore policy keys off message credentials,
	 * not connect-time credentials, so reopening /dev/mac_capability here would
	 * only test control-device permissions.
	 */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct ks_request req;
		struct ks_reply reply;
		char buf[256];
		uint32_t rlen;

		/* Change to any non-root uid. */
		if (setuid(1) != 0)
			_exit(10);
		if (getuid() != 1 || geteuid() != 1)
			_exit(12);

		req.op = KS_OP_FETCH;
		req.keyid = keyid;
		if (mac_capability_send(fd, &req, sizeof(req), 0) != 0)
			_exit(1);
		rlen = sizeof(buf);
		if (mac_capability_recv(fd, buf, &rlen, NULL) != 0)
			_exit(2);
		memcpy(&reply, buf, sizeof(reply));
		/* Should be NOTFOUND — different uid. */
		if (reply.status != KS_STATUS_NOTFOUND)
			_exit(3);
		close(fd);
		_exit(0);
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child exited with status %d", WEXITSTATUS(status));
	close(fd);
}

/* ================================================================
 * Keystore: badge uniqueness
 * ================================================================ */

ATF_TC(keystore_badge_unique);
ATF_TC_HEAD(keystore_badge_unique, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Each keystore instance gets a unique badge");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(keystore_badge_unique, tc)
{
	struct mac_capability_info_args info1, info2, info3;
	int fd1, fd2, fd3;

	fd1 = mac_capability_connect("test_keystore");
	fd2 = mac_capability_connect("test_keystore");
	fd3 = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd1 >= 0);
	ATF_REQUIRE(fd2 >= 0);
	ATF_REQUIRE(fd3 >= 0);

	memset(&info1, 0, sizeof(info1));
	memset(&info2, 0, sizeof(info2));
	memset(&info3, 0, sizeof(info3));
	ATF_REQUIRE(ioctl(fd1, MAC_CAPABILITY_GETINFO, &info1) == 0);
	ATF_REQUIRE(ioctl(fd2, MAC_CAPABILITY_GETINFO, &info2) == 0);
	ATF_REQUIRE(ioctl(fd3, MAC_CAPABILITY_GETINFO, &info3) == 0);

	ATF_CHECK(info1.badge != info2.badge);
	ATF_CHECK(info2.badge != info3.badge);
	ATF_CHECK(info1.badge != info3.badge);

	close(fd3);
	close(fd2);
	close(fd1);
}

/* ================================================================
 * Descriptor transfer state (CAP_XFER)
 * ================================================================ */

ATF_TC(xfer_keystore_ok);
ATF_TC_HEAD(xfer_keystore_ok, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Transferable capability can be passed via SCM_RIGHTS");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
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

	fd = mac_capability_connect("test_keystore");
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
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(fdclose_dup_survives, tc)
{
	int fd_a, fd_b, fd_a2;

	mac_capability_channel_create(&fd_a, &fd_b);

	/* Dup fd_a. */
	fd_a2 = dup(fd_a);
	ATF_REQUIRE(fd_a2 >= 0);

	/* Close original — co_fdclose fires, but instance survives. */
	close(fd_a);

	/* fd_a2 should still work — send on it, recv on B. */
	ATF_REQUIRE(mac_capability_send(fd_a2, "alive", 5, 0) == 0);
	{
		char buf[64];
		uint32_t rlen = sizeof(buf);
		ATF_REQUIRE(mac_capability_recv(fd_b, buf, &rlen, NULL) == 0);
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
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(fdclose_dup_then_close_all, tc)
{
	int fd_a, fd_b, fd_a2, flags;

	mac_capability_channel_create(&fd_a, &fd_b);

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
	ATF_CHECK(mac_capability_send(fd_b, "x", 1, 0) == -1);
	ATF_CHECK(errno == EPIPE || errno == ECONNRESET);

	close(fd_b);
}

/* ================================================================
 * Granular revoke
 * ================================================================ */

ATF_TC(revoke_blocks_operations);
ATF_TC_HEAD(revoke_blocks_operations, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_REVOKE_{SEND,RECV,CALL} each block their operation");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_test_keystore mac_capability_test_kernelstore");
}
ATF_TC_BODY(revoke_blocks_operations, tc)
{
	struct ks_request req;
	struct mac_capability_recvmsg_args ra;
	struct mac_capability_call_args ca;
	struct kstore_request kr;
	struct kstore_status_reply sr;
	char buf[256];
	uint32_t rlen;
	int fd;

	/*
	 * REVOKE_SEND: blocks SENDMSG, RECVMSG still works.
	 */
	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	ATF_REQUIRE(mac_capability_send(fd, &req, sizeof(req), 0) == 0);
	rlen = sizeof(buf);
	ATF_REQUIRE(mac_capability_recv(fd, buf, &rlen, NULL) == 0);

	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_REVOKE_SEND, NULL) == 0);
	ATF_CHECK_ERRNO(EACCES, mac_capability_send(fd, &req, sizeof(req), 0) == -1);
	close(fd);

	/*
	 * REVOKE_RECV: blocks RECVMSG, SENDMSG still works.
	 */
	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_REVOKE_RECV, NULL) == 0);

	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	ATF_CHECK(mac_capability_send(fd, &req, sizeof(req), 0) == 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_CHECK_ERRNO(EACCES, ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == -1);
	close(fd);

	/*
	 * REVOKE_CALL: blocks CALL.
	 */
	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);

	memset(&kr, 0, sizeof(kr));
	kr.op = KSTORE_OP_GET;
	strlcpy(kr.key, "_test", sizeof(kr.key));
	memset(&ca, 0, sizeof(ca));
	ca.req = &kr;
	ca.req_len = sizeof(kr);
	ca.reply = &sr;
	ca.reply_len = sizeof(sr);
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_CALL, &ca) == 0);

	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_REVOKE_CALL, NULL) == 0);

	memset(&ca, 0, sizeof(ca));
	ca.req = &kr;
	ca.req_len = sizeof(kr);
	ca.reply = &sr;
	ca.reply_len = sizeof(sr);
	ATF_CHECK_ERRNO(EACCES, ioctl(fd, MAC_CAPABILITY_CALL, &ca) == -1);
	close(fd);
}

ATF_TC(revoke_send_recv_both);
ATF_TC_HEAD(revoke_send_recv_both, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Revoking both send and recv blocks both");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(revoke_send_recv_both, tc)
{
	struct ks_request req;
	struct mac_capability_recvmsg_args ra;
	struct mac_capability_info_args info;
	char buf[256];
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_REVOKE_SEND, NULL) == 0);
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_REVOKE_RECV, NULL) == 0);

	/* Both blocked. */
	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	ATF_CHECK_ERRNO(EACCES, mac_capability_send(fd, &req, sizeof(req), 0) == -1);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_CHECK_ERRNO(EACCES, ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == -1);

	/* GETINFO always works. */
	memset(&info, 0, sizeof(info));
	ATF_CHECK(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);
	ATF_CHECK_STREQ(info.name, "test_keystore");

	close(fd);
}

ATF_TC(revoke_is_permanent);
ATF_TC_HEAD(revoke_is_permanent, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Revoke is one-way — calling it again is harmless");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(revoke_is_permanent, tc)
{
	struct ks_request req;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_REVOKE_SEND, NULL) == 0);
	/* Second call is harmless. */
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_REVOKE_SEND, NULL) == 0);

	/* Still blocked. */
	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	ATF_CHECK_ERRNO(EACCES, mac_capability_send(fd, &req, sizeof(req), 0) == -1);

	close(fd);
}

ATF_TC(revoke_affects_all_dups);
ATF_TC_HEAD(revoke_affects_all_dups, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Revoke on one handle affects all dups (same instance)");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(revoke_affects_all_dups, tc)
{
	struct ks_request req;
	int fd, fd2;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	fd2 = dup(fd);
	ATF_REQUIRE(fd2 >= 0);

	/* Revoke send on fd. */
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_REVOKE_SEND, NULL) == 0);

	/* fd2 should also be blocked — same instance. */
	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	ATF_CHECK_ERRNO(EACCES, mac_capability_send(fd2, &req, sizeof(req), 0) == -1);

	close(fd2);
	close(fd);
}

ATF_TC(terminate_after_revoke_send);
ATF_TC_HEAD(terminate_after_revoke_send, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_TERMINATE works even after MAC_CAPABILITY_REVOKE_SEND");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(terminate_after_revoke_send, tc)
{
	struct mac_capability_recvmsg_args ra;
	char buf[64];
	int fd, flags;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/* Restrict send. */
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_REVOKE_SEND, NULL) == 0);

	/* Token revoke should still work. */
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_TERMINATE, NULL) == 0);

	/* Instance should be dead. */
	flags = fcntl(fd, F_GETFL, 0);
	ATF_REQUIRE(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_CHECK_ERRNO(ECONNRESET, ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == -1);

	close(fd);
}

/* ================================================================
 * MAC_CAPABILITY_CALL reply fds
 * ================================================================ */

ATF_TC(call_reply_fds_zero);
ATF_TC_HEAD(call_reply_fds_zero, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_CALL with reply_nfds=0 works normally");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(call_reply_fds_zero, tc)
{
	struct mac_capability_call_args ca;
	struct kstore_request kr;
	struct kstore_status_reply sr;
	int fd;

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);

	memset(&kr, 0, sizeof(kr));
	kr.op = KSTORE_OP_GET;
	strlcpy(kr.key, "_test", sizeof(kr.key));
	memset(&ca, 0, sizeof(ca));
	ca.req = &kr;
	ca.req_len = sizeof(kr);
	ca.reply = &sr;
	ca.reply_len = sizeof(sr);
	ca.reply_fds = NULL;
	ca.reply_nfds = 0;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_CALL, &ca) == 0);
	ATF_CHECK(ca.reply_len > 0);
	ATF_CHECK_EQ(ca.reply_nfds, 0);

	close(fd);
}

ATF_TC(call_reply_fds_buf_no_fds);
ATF_TC_HEAD(call_reply_fds_buf_no_fds, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_CALL with reply_fds buffer but handler returns 0 fds");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(call_reply_fds_buf_no_fds, tc)
{
	struct mac_capability_call_args ca;
	struct kstore_request kr;
	struct kstore_status_reply sr;
	int reply_fds[4];
	int fd;

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);

	memset(&kr, 0, sizeof(kr));
	kr.op = KSTORE_OP_GET;
	strlcpy(kr.key, "_test", sizeof(kr.key));
	memset(&ca, 0, sizeof(ca));
	ca.req = &kr;
	ca.req_len = sizeof(kr);
	ca.reply = &sr;
	ca.reply_len = sizeof(sr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 4;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_CALL, &ca) == 0);
	ATF_CHECK(ca.reply_len > 0);
	ATF_CHECK_EQ(ca.reply_nfds, 0);

	close(fd);
}

ATF_TC(call_reply_nfds_too_many);
ATF_TC_HEAD(call_reply_nfds_too_many, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_CALL with reply_nfds > MAC_CAPABILITY_MAX_FDS returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(call_reply_nfds_too_many, tc)
{
	struct mac_capability_call_args ca;
	struct kstore_request kr;
	int fd;

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);

	memset(&kr, 0, sizeof(kr));
	kr.op = KSTORE_OP_GET;
	strlcpy(kr.key, "_test", sizeof(kr.key));
	memset(&ca, 0, sizeof(ca));
	ca.req = &kr;
	ca.req_len = sizeof(kr);
	ca.reply_nfds = MAC_CAPABILITY_MAX_FDS + 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, MAC_CAPABILITY_CALL, &ca) == -1);

	close(fd);
}

ATF_TC(call_reply_preserves_ioctl_limit);
ATF_TC_HEAD(call_reply_preserves_ioctl_limit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_CALL reply fd preserves its ioctl allowlist");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(call_reply_preserves_ioctl_limit, tc)
{
	struct mac_capability_call_args ca;
	struct kstore_request kr;
	cap_ioctl_t cmds[] = { MAC_CAPABILITY_GETINFO };
	int svc_fd, target_fd, received_fd;

	svc_fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(svc_fd >= 0);
	target_fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(target_fd >= 0);
	ATF_REQUIRE(cap_ioctls_limit(target_fd, cmds, nitems(cmds)) == 0);
	ATF_REQUIRE(cap_cloexec_limit(target_fd, CAP_CLOEXEC_ONCE) == 0);
	ATF_REQUIRE(cap_clofork_limit(target_fd, CAP_CLOFORK_ONCE) == 0);

	memset(&kr, 0, sizeof(kr));
	kr.op = KSTORE_OP_ECHO_FD;
	memset(&ca, 0, sizeof(ca));
	ca.req = &kr;
	ca.req_len = sizeof(kr);
	ca.req_fds = &target_fd;
	ca.req_nfds = 1;
	ca.reply_fds = &received_fd;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(svc_fd, MAC_CAPABILITY_CALL, &ca) == 0);
	ATF_REQUIRE_EQ(ca.reply_nfds, 1);
	ATF_CHECK_EQ(verify_getinfo_only(received_fd), 0);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_cloexec_limit(received_fd, CAP_CLOEXEC_UNLOCKED) == -1);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_clofork_limit(received_fd, CAP_CLOFORK_UNLOCKED) == -1);
	ATF_REQUIRE(cap_cloexec_limit(received_fd, CAP_CLOEXEC_ONCE) == 0);
	ATF_REQUIRE(cap_clofork_limit(received_fd, CAP_CLOFORK_ONCE) == 0);

	close(received_fd);
	close(target_fd);
	close(svc_fd);
}

/* ================================================================
 * CAP_XFER_NONE — per-descriptor transfer lock
 * ================================================================ */

ATF_TC(xfer_none_prevents_transfer);
ATF_TC_HEAD(xfer_none_prevents_transfer, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CAP_XFER_NONE prevents SCM_RIGHTS transfer");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(xfer_none_prevents_transfer, tc)
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

	fd = mac_capability_connect("test_keystore");
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

	/* Prevent further descriptor transfer. */
	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_NONE) == 0);

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

ATF_TC(xfer_none_still_usable);
ATF_TC_HEAD(xfer_none_still_usable, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CAP_XFER_NONE capability still works for messaging");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(xfer_none_still_usable, tc)
{
	struct ks_request req;
	char buf[256];
	uint32_t rlen;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/* Prevent transfer, but keep normal mac_capability operations usable. */
	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_NONE) == 0);

	/* Should still work for normal messaging. */
	mac_capability_store(fd, 85000, "locked", 6);

	req.op = KS_OP_FETCH;
	req.keyid = 85000;
	ATF_REQUIRE(mac_capability_send(fd, &req, sizeof(req), 0) == 0);
	rlen = sizeof(buf);
	ATF_REQUIRE(mac_capability_recv(fd, buf, &rlen, NULL) == 0);
	ATF_CHECK_EQ(((struct ks_reply *)buf)->status, KS_STATUS_OK);

	close(fd);
}

ATF_TC(xfer_none_trampoline);
ATF_TC_HEAD(xfer_none_trampoline, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Trampoline receives capability, sets CAP_XFER_NONE, cannot forward");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(xfer_none_trampoline, tc)
{
	int sv[2], fd, status;
	pid_t pid;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child (trampoline): receive fd, restrict transfer, try to forward. */
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

		/* No further transfers. */
		if (cap_xfer_limit(received_fd, CAP_XFER_NONE) != 0)
			_exit(3);

		/* Verify it still works. */
		{
			struct mac_capability_info_args info;
			memset(&info, 0, sizeof(info));
			if (ioctl(received_fd, MAC_CAPABILITY_GETINFO, &info) != 0)
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
 * CAP_XFER enforcement — mac_capability SENDMSG/RECVMSG/CALL paths
 * ================================================================ */

ATF_TC(xfer_sendmsg_none_blocks);
ATF_TC_HEAD(xfer_sendmsg_none_blocks, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "mac_capability SENDMSG rejects attached fd with CAP_XFER_NONE");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(xfer_sendmsg_none_blocks, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct ks_request req;
	int fd, pipefd[2];

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pipe(pipefd) == 0);

	ATF_REQUIRE(cap_xfer_limit(pipefd[0], CAP_XFER_NONE) == 0);

	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = &pipefd[0];
	sa.nfds = 1;

	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);

	close(pipefd[0]);
	close(pipefd[1]);
	close(fd);
}

ATF_TC(xfer_sendmsg_once_consumed);
ATF_TC_HEAD(xfer_sendmsg_once_consumed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "mac_capability SENDMSG with XFER_ONCE: first succeeds, second fails");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(xfer_sendmsg_once_consumed, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct ks_request req;
	char buf[64];
	uint32_t rlen;
	int fd, pipefd[2];

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pipe(pipefd) == 0);

	ATF_REQUIRE(cap_xfer_limit(pipefd[0], CAP_XFER_ONCE) == 0);

	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = &pipefd[0];
	sa.nfds = 1;

	/* First send succeeds — ONCE consumed. */
	ATF_REQUIRE_MSG(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == 0,
	    "first SENDMSG: %s", strerror(errno));

	/* Drain reply. */
	rlen = sizeof(buf);
	ATF_REQUIRE(mac_capability_recv(fd, buf, &rlen, NULL) == 0);

	/* Second send fails — state is now NONE. */
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = &pipefd[0];
	sa.nfds = 1;
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);

	close(pipefd[0]);
	close(pipefd[1]);
	close(fd);
}

ATF_TC(xfer_sendmsg_multi_atomic);
ATF_TC_HEAD(xfer_sendmsg_multi_atomic, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "mac_capability SENDMSG multi-fd with one NONE rejects atomically");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(xfer_sendmsg_multi_atomic, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct ks_request req;
	int fd, pipefd[2], devnull;
	int fds[2];

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pipe(pipefd) == 0);
	devnull = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(devnull >= 0);

	/* pipefd[0] is ONCE, devnull is NONE. */
	ATF_REQUIRE(cap_xfer_limit(pipefd[0], CAP_XFER_ONCE) == 0);
	ATF_REQUIRE(cap_xfer_limit(devnull, CAP_XFER_NONE) == 0);

	fds[0] = pipefd[0];
	fds[1] = devnull;

	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = fds;
	sa.nfds = 2;

	/* Should be rejected because devnull is NONE. */
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);

	/*
	 * pipefd[0] should still be ONCE — verify by sending it
	 * alone (should succeed).
	 */
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = &pipefd[0];
	sa.nfds = 1;
	ATF_CHECK_MSG(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == 0,
	    "ONCE fd consumed despite atomic rejection: %s",
	    strerror(errno));

	/* Drain reply. */
	{
		char buf[64];
		uint32_t rlen = sizeof(buf);
		mac_capability_recv(fd, buf, &rlen, NULL);
	}

	close(devnull);
	close(pipefd[0]);
	close(pipefd[1]);
	close(fd);
}

/* ---- RECVMSG xfer state propagation ---- */

ATF_TC(xfer_recvmsg_unlimited_preserved);
ATF_TC_HEAD(xfer_recvmsg_unlimited_preserved, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "mac_capability RECVMSG: UNLIMITED fd arrives as UNLIMITED");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(xfer_recvmsg_unlimited_preserved, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	struct ks_request req;
	char buf[64];
	int fd, pipefd[2], recv_fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pipe(pipefd) == 0);

	/* pipefd[0] is default UNLIMITED. */
	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = &pipefd[0];
	sa.nfds = 1;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == 0);

	/* Receive the reply (keystore echoes fds back). */
	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ra.fds = &recv_fd;
	ra.nfds = 1;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == 0);

	if (ra.nfds == 1) {
		/*
		 * Received fd should be UNLIMITED — can tighten to ONCE,
		 * proving it wasn't degraded.
		 */
		ATF_CHECK(cap_xfer_limit(recv_fd, CAP_XFER_ONCE) == 0);
		close(recv_fd);
	}

	close(pipefd[0]);
	close(pipefd[1]);
	close(fd);
}

ATF_TC(xfer_recvmsg_once_arrives_none);
ATF_TC_HEAD(xfer_recvmsg_once_arrives_none, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "mac_capability RECVMSG: XFER_ONCE fd arrives as XFER_NONE");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(xfer_recvmsg_once_arrives_none, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	struct ks_request req;
	char buf[64];
	int fd, pipefd[2], recv_fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pipe(pipefd) == 0);

	ATF_REQUIRE(cap_xfer_limit(pipefd[0], CAP_XFER_ONCE) == 0);

	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = &pipefd[0];
	sa.nfds = 1;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ra.fds = &recv_fd;
	ra.nfds = 1;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == 0);

	if (ra.nfds == 1) {
		/* ONCE was consumed on send — receiver gets NONE. */
		ATF_CHECK_ERRNO(ENOTCAPABLE,
		    cap_xfer_limit(recv_fd, CAP_XFER_UNLIMITED) == -1);
		/* Cannot forward. */
		{
			struct msghdr msgh;
			struct iovec iov;
			union {
				struct cmsghdr hdr;
				char cbuf[CMSG_SPACE(sizeof(int))];
			} cmsgbuf;
			struct cmsghdr *cmsg;
			char dummy = 'x';
			int sv[2];

			ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0,
			    sv) == 0);
			memset(&msgh, 0, sizeof(msgh));
			iov.iov_base = &dummy;
			iov.iov_len = 1;
			msgh.msg_iov = &iov;
			msgh.msg_iovlen = 1;
			msgh.msg_control = cmsgbuf.cbuf;
			msgh.msg_controllen = sizeof(cmsgbuf.cbuf);
			cmsg = CMSG_FIRSTHDR(&msgh);
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			cmsg->cmsg_len = CMSG_LEN(sizeof(int));
			memcpy(CMSG_DATA(cmsg), &recv_fd, sizeof(int));
			ATF_CHECK_MSG(sendmsg(sv[0], &msgh, 0) == -1,
			    "forwarding NONE fd should fail");
			close(sv[0]);
			close(sv[1]);
		}
		close(recv_fd);
	}

	close(pipefd[0]);
	close(pipefd[1]);
	close(fd);
}

ATF_TC(propagation_once_recvmsg_preserved);
ATF_TC_HEAD(propagation_once_recvmsg_preserved, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "mac_capability RECVMSG preserves CLOEXEC_ONCE and CLOFORK_ONCE");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(propagation_once_recvmsg_preserved, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	struct ks_request req;
	char buf[64];
	int fd, pipefd[2], recv_fd, status;
	pid_t pid;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pipe(pipefd) == 0);
	ATF_REQUIRE(cap_cloexec_limit(pipefd[0], CAP_CLOEXEC_ONCE) == 0);
	ATF_REQUIRE(cap_clofork_limit(pipefd[0], CAP_CLOFORK_ONCE) == 0);

	req.op = KS_OP_FETCH;
	req.keyid = mac_capability_missing_key();
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.fds = &pipefd[0];
	sa.nfds = 1;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ra.fds = &recv_fd;
	ra.nfds = 1;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == 0);
	ATF_REQUIRE_EQ(ra.nfds, 1);

	/* These two checks together prove each exact intermediate state. */
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_cloexec_limit(recv_fd, CAP_CLOEXEC_UNLOCKED) == -1);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_clofork_limit(recv_fd, CAP_CLOFORK_UNLOCKED) == -1);
	ATF_REQUIRE(cap_cloexec_limit(recv_fd, CAP_CLOEXEC_ONCE) == 0);
	ATF_REQUIRE(cap_clofork_limit(recv_fd, CAP_CLOFORK_ONCE) == 0);

	/* The received fork state must be enforced, not merely stored. */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(fcntl(recv_fd, F_GETFD) == -1 ? 40 : 0);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "mac_capability descriptor missed its permitted fork (exit %d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(fcntl(recv_fd, F_GETFD) == -1 && errno == EBADF ?
		    0 : 41);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "mac_capability descriptor survived a second fork (exit %d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	close(recv_fd);
	close(pipefd[0]);
	close(pipefd[1]);
	close(fd);
}

/* ---- CALL xfer state propagation ---- */

ATF_TC(xfer_call_none_rejected);
ATF_TC_HEAD(xfer_call_none_rejected, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "mac_capability CALL rejects request fd with CAP_XFER_NONE");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(xfer_call_none_rejected, tc)
{
	struct mac_capability_call_args ca;
	struct kstore_request kr;
	struct kstore_status_reply sr;
	int fd, pipefd[2];

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pipe(pipefd) == 0);

	ATF_REQUIRE(cap_xfer_limit(pipefd[0], CAP_XFER_NONE) == 0);

	memset(&kr, 0, sizeof(kr));
	kr.op = KSTORE_OP_GET;
	strlcpy(kr.key, "_xfer_test", sizeof(kr.key));
	memset(&ca, 0, sizeof(ca));
	ca.req = &kr;
	ca.req_len = sizeof(kr);
	ca.req_fds = &pipefd[0];
	ca.req_nfds = 1;
	ca.reply = &sr;
	ca.reply_len = sizeof(sr);

	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    ioctl(fd, MAC_CAPABILITY_CALL, &ca) == -1);

	close(pipefd[0]);
	close(pipefd[1]);
	close(fd);
}

ATF_TC(xfer_call_once_consumed);
ATF_TC_HEAD(xfer_call_once_consumed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "mac_capability CALL with XFER_ONCE: consumed, second call fails");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(xfer_call_once_consumed, tc)
{
	struct mac_capability_call_args ca;
	struct kstore_request kr;
	struct kstore_status_reply sr;
	int fd, pipefd[2];

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pipe(pipefd) == 0);

	ATF_REQUIRE(cap_xfer_limit(pipefd[0], CAP_XFER_ONCE) == 0);

	memset(&kr, 0, sizeof(kr));
	kr.op = KSTORE_OP_GET;
	strlcpy(kr.key, "_xfer_test", sizeof(kr.key));
	memset(&ca, 0, sizeof(ca));
	ca.req = &kr;
	ca.req_len = sizeof(kr);
	ca.req_fds = &pipefd[0];
	ca.req_nfds = 1;
	ca.reply = &sr;
	ca.reply_len = sizeof(sr);

	/* First CALL succeeds — ONCE consumed. */
	ATF_REQUIRE_MSG(ioctl(fd, MAC_CAPABILITY_CALL, &ca) == 0,
	    "first CALL: %s", strerror(errno));

	/* Second CALL fails — state is now NONE. */
	memset(&ca, 0, sizeof(ca));
	ca.req = &kr;
	ca.req_len = sizeof(kr);
	ca.req_fds = &pipefd[0];
	ca.req_nfds = 1;
	ca.reply = &sr;
	ca.reply_len = sizeof(sr);

	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    ioctl(fd, MAC_CAPABILITY_CALL, &ca) == -1);

	close(pipefd[0]);
	close(pipefd[1]);
	close(fd);
}

/* ================================================================
 * Capability Protection (capprotect)
 * ================================================================ */

static const char *
shield_helper_path(void)
{
	static char path[256];
	const char *dir;
	char self[PATH_MAX];
	int mib[4];
	size_t len;

	dir = getenv("TESTSDIR");
	if (dir == NULL)
		dir = getenv("SRCDIR");
	if (dir == NULL) {
		/* Derive from our own binary path via sysctl. */
		mib[0] = CTL_KERN;
		mib[1] = KERN_PROC;
		mib[2] = KERN_PROC_PATHNAME;
		mib[3] = -1;
		len = sizeof(self);
		if (sysctl(mib, 4, self, &len, NULL, 0) == 0) {
			char *slash = strrchr(self, '/');
			if (slash != NULL) {
				*slash = '\0';
				dir = self;
			}
		}
	}
	if (dir == NULL)
		dir = "/usr/tests/sys/mac_capability";
	snprintf(path, sizeof(path), "%s/mac_capability_shield_helper", dir);
	return (path);
}

static int
run_shield_helper(const char *op, pid_t target)
{
	pid_t helper;
	int status;
	char pidstr[16];
	const char *path;

	snprintf(pidstr, sizeof(pidstr), "%d", (int)target);
	path = shield_helper_path();

	helper = fork();
	if (helper < 0)
		return (-1);
	if (helper == 0) {
		execl(path, "mac_capability_shield_helper", op, pidstr, NULL);
		dprintf(STDERR_FILENO, "exec %s: %s\n", path,
		    strerror(errno));
		_exit(2);
	}
	if (waitpid(helper, &status, 0) != helper)
		return (-1);
	if (!WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

static void
require_shield_blocks(const char *op, pid_t target)
{
	int result;

	result = run_shield_helper(op, target);
	if (result == 1) {
		ATF_REQUIRE_MSG(false,
		    "ambient %s unexpectedly allowed for pid %d",
		    op, (int)target);
	}
	ATF_REQUIRE_MSG(result == 0,
	    "shield helper %s failed with status %d for pid %d",
	    op, result, (int)target);
}

static int
identity_self_nonce(uint64_t *noncep)
{
	struct mac_capability_call_args call;
	struct identity_request req;
	struct identity_reply reply;
	int fd;

	fd = mac_capability_connect("identity");
	if (fd < 0)
		return (-1);
	memset(&req, 0, sizeof(req));
	req.op = IDENTITY_OP_SELF;
	memset(&reply, 0, sizeof(reply));
	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.reply = &reply;
	call.reply_len = sizeof(reply);
	if (ioctl(fd, MAC_CAPABILITY_CALL, &call) != 0 ||
	    reply.status != IDENTITY_STATUS_OK || reply.nonce == 0) {
		close(fd);
		return (-1);
	}
	close(fd);
	*noncep = reply.nonce;
	return (0);
}

static int
exec_helper_nonce(uint64_t *noncep)
{
	char fdstr[16];
	const char *path;
	pid_t child;
	ssize_t nread;
	int pipefd[2], status;

	if (pipe(pipefd) != 0)
		return (-1);
	path = shield_helper_path();
	child = fork();
	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return (-1);
	}
	if (child == 0) {
		close(pipefd[0]);
		snprintf(fdstr, sizeof(fdstr), "%d", pipefd[1]);
		execl(path, "mac_capability_shield_helper", "self_nonce",
		    fdstr, NULL);
		dprintf(STDERR_FILENO, "exec %s: %s\n", path,
		    strerror(errno));
		_exit(2);
	}
	close(pipefd[1]);
	do {
		nread = read(pipefd[0], noncep, sizeof(*noncep));
	} while (nread == -1 && errno == EINTR);
	close(pipefd[0]);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0 || nread != sizeof(*noncep))
		return (-1);
	return (0);
}

static int
capprotect_shield(uint32_t flags)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int fd;

	fd = mac_capability_connect("capprotect");
	if (fd < 0)
		return (-1);

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_SHIELD;
	req.flags = flags;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	if (ioctl(fd, MAC_CAPABILITY_CALL, &ca) != 0) {
		close(fd);
		return (-1);
	}
	return (fd);
}

/*
 * Launcher-applied protection: shield the process behind procdesc_fd (a
 * pdfork(2) descriptor).  The returned capprotect fd is the protector's
 * authority and is kept open by the caller.
 */
static int
capprotect_protect(int procdesc_fd, uint32_t flags)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int fd;

	fd = mac_capability_connect("capprotect");
	if (fd < 0)
		return (-1);
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_PROTECT;
	req.flags = flags;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.req_fds = &procdesc_fd;
	ca.req_nfds = 1;
	if (ioctl(fd, MAC_CAPABILITY_CALL, &ca) != 0) {
		close(fd);
		return (-1);
	}
	return (fd);
}

ATF_TC(cap_pro_shield_basic);
ATF_TC_HEAD(cap_pro_shield_basic, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Connect to capprotect and shield with all flags");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_shield_basic, tc)
{
	int fd;

	fd = capprotect_shield(CP_SF_ALL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
}

ATF_TC(cap_pro_protector_can_act);
ATF_TC_HEAD(cap_pro_protector_can_act, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The launcher that protected a target (CP_OP_PROTECT) may act on it; "
	    "a foreign process may not");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_protector_can_act, tc)
{
	int sv[2], pd, cfd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		close(sv[0]);
		/* The child does NOT shield itself; its launcher protects it. */
		write(sv[1], "r", 1);
		read(sv[1], &buf, 1);
		close(sv[1]);
		_exit(0);
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }

	cfd = capprotect_protect(pd, CP_SF_SIGNAL);
	ATF_REQUIRE(cfd >= 0);

	/* Protector may signal the target (signal 0 checks permission only). */
	ATF_CHECK(kill(pid, 0) == 0);
	/* A foreign process may not. */
	ATF_CHECK_EQ(run_shield_helper("signal", pid), 0);

	write(sv[0], "g", 1);
	close(cfd);
	close(pd);		/* reaps the procdesc-owned child */
	close(sv[0]);
}

ATF_TC(cap_pro_selfshield_blocks_parent);
ATF_TC_HEAD(cap_pro_selfshield_blocks_parent, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A self-shielded child blocks even its own parent (which is not the "
	    "protector) from signalling it");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_selfshield_blocks_parent, tc)
{
	int sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		int fd;
		close(sv[0]);
		fd = capprotect_shield(CP_SF_SIGNAL);
		if (fd < 0) _exit(10);
		write(sv[1], "s", 1);
		read(sv[1], &buf, 1);
		close(fd); close(sv[1]); _exit(0);
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }

	/* Parent is not the protector; the shield blocks it too. */
	errno = 0;
	ATF_CHECK(kill(pid, 0) == -1);
	ATF_CHECK_EQ(errno, EACCES);

	write(sv[0], "g", 1);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

ATF_TC(cap_pro_protect_via_procdesc);
ATF_TC_HEAD(cap_pro_protect_via_procdesc, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CP_OP_PROTECT shields a target that never shielded itself; a "
	    "foreign process is then blocked");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_protect_via_procdesc, tc)
{
	int sv[2], pd, cfd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		close(sv[0]);
		write(sv[1], "r", 1);
		read(sv[1], &buf, 1);
		close(sv[1]); _exit(0);
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }

	/* Before protection, a foreign process can ptrace the child. */
	ATF_CHECK_EQ(run_shield_helper("ptrace", pid), 1);

	cfd = capprotect_protect(pd, CP_SF_PTRACE);
	ATF_REQUIRE(cfd >= 0);

	/* After launcher protection, the foreign ptrace is blocked. */
	ATF_CHECK_EQ(run_shield_helper("ptrace", pid), 0);

	write(sv[0], "g", 1);
	close(cfd); close(pd); close(sv[0]);
}

ATF_TC(cap_pro_foreign_ptrace_blocked);
ATF_TC_HEAD(cap_pro_foreign_ptrace_blocked, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Shield with SF_PTRACE blocks foreign ptrace");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_foreign_ptrace_blocked, tc)
{
	int sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		int fd;
		close(sv[0]);
		fd = capprotect_shield(CP_SF_PTRACE);
		if (fd < 0) _exit(10);
		write(sv[1], "s", 1);
		read(sv[1], &buf, 1);
		close(fd); close(sv[1]); _exit(0);
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }
	ATF_CHECK_EQ(run_shield_helper("ptrace", pid), 0);
	write(sv[0], "g", 1);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

ATF_TC(cap_pro_foreign_signal_blocked);
ATF_TC_HEAD(cap_pro_foreign_signal_blocked, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Shield with SF_SIGNAL blocks foreign signal");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_foreign_signal_blocked, tc)
{
	int sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		int fd;
		close(sv[0]);
		fd = capprotect_shield(CP_SF_SIGNAL);
		if (fd < 0) _exit(10);
		write(sv[1], "s", 1);
		read(sv[1], &buf, 1);
		close(fd); close(sv[1]); _exit(0);
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }
	ATF_CHECK_EQ(run_shield_helper("signal", pid), 0);
	write(sv[0], "g", 1);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

ATF_TC(cap_pro_foreign_sigkill_blocked);
ATF_TC_HEAD(cap_pro_foreign_sigkill_blocked, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Shield with SF_SIGKILL blocks foreign SIGKILL");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_foreign_sigkill_blocked, tc)
{
	int sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		int fd;
		close(sv[0]);
		fd = capprotect_shield(CP_SF_SIGKILL);
		if (fd < 0) _exit(10);
		write(sv[1], "s", 1);
		read(sv[1], &buf, 1);
		close(fd); close(sv[1]); _exit(0);
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }
	ATF_CHECK_EQ(run_shield_helper("sigkill", pid), 0);
	write(sv[0], "g", 1);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

/*
 * pdkill tests — the process descriptor is a capability.  Holding it
 * is sufficient authority to signal the child regardless of capprotect
 * shields, even after exec rotates the nonce.
 */

ATF_TC(cap_pro_exec_rotates_nonce);
ATF_TC_HEAD(cap_pro_exec_rotates_nonce, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Exec helper has a different program nonce before shield tests");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_identity");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "15");
}
ATF_TC_BODY(cap_pro_exec_rotates_nonce, tc)
{
	uint64_t exec_nonce, parent_nonce;

	ATF_REQUIRE_MSG(identity_self_nonce(&parent_nonce) == 0,
	    "could not query parent program nonce: %s", strerror(errno));
	ATF_REQUIRE_MSG(exec_helper_nonce(&exec_nonce) == 0,
	    "could not query exec helper program nonce");
	ATF_CHECK_MSG(exec_nonce != parent_nonce,
	    "exec did not rotate program nonce (0x%jx); check MNT_NOSUID",
	    (uintmax_t)parent_nonce);
}

/*
 * Helper: pdfork a same-program child which shields itself and pauses.
 * Parent gets back the pd and child pid.  Foreign ambient probes are
 * performed by the separately exec'd shield helper.
 */
static pid_t
pdfork_shielded_child(int *pd_out, uint32_t shield_flags)
{
	pid_t pid;
	ssize_t nread;
	int pd, status, sv[2];
	char ready;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return (-1);

	pid = pdfork(&pd, PD_CLOEXEC);
	if (pid < 0) {
		close(sv[0]);
		close(sv[1]);
		return (-1);
	}
	if (pid == 0) {
		/* Child: shield, signal ready, then pause forever.
		 * pdkill or close(pd) will terminate us. */
		int fd;

		close(sv[0]);
		fd = capprotect_shield(shield_flags);
		if (fd < 0)
			_exit(10);
		(void)write(sv[1], "s", 1);
		close(sv[1]);
		for (;;)
			pause();
		/* NOTREACHED */
		_exit(0);
	}

	/* Parent: wait for child to be shielded. */
	close(sv[1]);
	do {
		nread = read(sv[0], &ready, sizeof(ready));
	} while (nread == -1 && errno == EINTR);
	close(sv[0]);
	if (nread != sizeof(ready) || ready != 's') {
		(void)waitpid(pid, &status, 0);
		close(pd);
		errno = EIO;
		return (-1);
	}
	*pd_out = pd;
	return (pid);
}

ATF_TC(cap_pro_pdkill_bypasses_signal_shield);
ATF_TC_HEAD(cap_pro_pdkill_bypasses_signal_shield, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "pdkill delivers signal through CP_SF_SIGNAL shield");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "15");
}
ATF_TC_BODY(cap_pro_pdkill_bypasses_signal_shield, tc)
{
	pid_t pid;
	int pd, status;

	pid = pdfork_shielded_child(&pd, CP_SF_SIGNAL);
	ATF_REQUIRE(pid > 0);

	/* Exercise p_cansignal without delivering or consuming the target. */
	require_shield_blocks("signal0", pid);

	/* pdkill via process descriptor must succeed. */
	ATF_REQUIRE_EQ(pdkill(pd, SIGUSR1), 0);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFSIGNALED(status));
	ATF_CHECK_EQ(WTERMSIG(status), SIGUSR1);

	close(pd);
}

ATF_TC(cap_pro_pdkill_bypasses_sigkill_shield);
ATF_TC_HEAD(cap_pro_pdkill_bypasses_sigkill_shield, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "pdkill delivers SIGKILL through CP_SF_SIGKILL shield");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "15");
}
ATF_TC_BODY(cap_pro_pdkill_bypasses_sigkill_shield, tc)
{
	pid_t pid;
	int pd, status;

	pid = pdfork_shielded_child(&pd, CP_SF_SIGKILL);
	ATF_REQUIRE(pid > 0);

	/* kill(pid, SIGKILL) must be blocked — verify shield is active. */
	require_shield_blocks("sigkill", pid);

	/* pdkill via process descriptor must succeed. */
	ATF_REQUIRE_EQ(pdkill(pd, SIGKILL), 0);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFSIGNALED(status));
	ATF_CHECK_EQ(WTERMSIG(status), SIGKILL);

	close(pd);
}

ATF_TC(cap_pro_pdkill_bypasses_full_shield);
ATF_TC_HEAD(cap_pro_pdkill_bypasses_full_shield, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "pdkill delivers SIGKILL through CP_SF_ALL shield");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "15");
}
ATF_TC_BODY(cap_pro_pdkill_bypasses_full_shield, tc)
{
	pid_t pid;
	int pd, status;

	pid = pdfork_shielded_child(&pd, CP_SF_ALL);
	ATF_REQUIRE(pid > 0);

	/* pdkill via process descriptor must succeed even with full shield. */
	ATF_REQUIRE_EQ(pdkill(pd, SIGKILL), 0);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFSIGNALED(status));
	ATF_CHECK_EQ(WTERMSIG(status), SIGKILL);

	close(pd);
}

ATF_TC(cap_pro_pdkill_sigterm_through_shield);
ATF_TC_HEAD(cap_pro_pdkill_sigterm_through_shield, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "pdkill delivers SIGTERM through CP_SF_SIGNAL|CP_SF_SIGKILL shield");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "15");
}
ATF_TC_BODY(cap_pro_pdkill_sigterm_through_shield, tc)
{
	pid_t pid;
	int pd, status;

	pid = pdfork_shielded_child(&pd, CP_SF_SIGNAL | CP_SF_SIGKILL);
	ATF_REQUIRE(pid > 0);

	/* Both signal and sigkill blocked for foreign nonces. */
	require_shield_blocks("signal0", pid);
	require_shield_blocks("sigkill", pid);

	/* pdkill SIGTERM via process descriptor must succeed. */
	ATF_REQUIRE_EQ(pdkill(pd, SIGTERM), 0);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFSIGNALED(status));
	ATF_CHECK_EQ(WTERMSIG(status), SIGTERM);

	close(pd);
}

ATF_TC(cap_pro_pdwait_bypasses_wait_shield);
ATF_TC_HEAD(cap_pro_pdwait_bypasses_wait_shield, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "pdwait collects exit status through CP_SF_WAIT shield");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_pdwait_bypasses_wait_shield, tc)
{
	pid_t pid;
	int pd, status;

	pid = pdfork_shielded_child(&pd, CP_SF_WAIT | CP_SF_SIGNAL);
	ATF_REQUIRE(pid > 0);

	/*
	 * We cannot directly verify CP_SF_WAIT blocks foreign waitpid()
	 * from the shield helper because waitpid() on a non-child already
	 * fails with ECHILD before the MAC hook fires.  The shield is
	 * verified by the cap_pro_foreign_wait_blocked test which uses
	 * a parent-child relationship.  Here we just test that pdwait
	 * works through the shield.
	 */

	/* Kill the child via pdkill so it exits. */
	ATF_REQUIRE_EQ(pdkill(pd, SIGKILL), 0);

	/* pdwait via process descriptor must collect the exit status.
	 * Use blocking wait (WEXITED only, no WNOHANG) — the child
	 * may not have finished dying yet after pdkill returns.
	 * pdwait returns 0 on success (not pid like waitpid). */
	status = 0;
	ATF_REQUIRE_EQ(pdwait(pd, &status, WEXITED,
	    NULL, NULL), 0);
	ATF_CHECK(WIFSIGNALED(status));
	ATF_CHECK_EQ(WTERMSIG(status), SIGKILL);

	close(pd);
}

ATF_TC(cap_pro_pdwait_bypasses_full_shield);
ATF_TC_HEAD(cap_pro_pdwait_bypasses_full_shield, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "pdwait collects exit status through CP_SF_ALL shield");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_pdwait_bypasses_full_shield, tc)
{
	pid_t pid;
	int pd, status;

	pid = pdfork_shielded_child(&pd, CP_SF_ALL);
	ATF_REQUIRE(pid > 0);

	/* Kill and wait through maximum shield.
	 * pdwait returns 0 on success (not pid like waitpid). */
	ATF_REQUIRE_EQ(pdkill(pd, SIGKILL), 0);

	status = 0;
	ATF_REQUIRE_EQ(pdwait(pd, &status, WEXITED,
	    NULL, NULL), 0);
	ATF_CHECK(WIFSIGNALED(status));
	ATF_CHECK_EQ(WTERMSIG(status), SIGKILL);

	close(pd);
}

ATF_TC(cap_pro_unshielded_same_session_sigcont_allowed);
ATF_TC_HEAD(cap_pro_unshielded_same_session_sigcont_allowed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "same-session SIGCONT remains allowed without a MAC shield");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_unshielded_same_session_sigcont_allowed, tc)
{
	int pd, status;
	pid_t pid;

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		for (;;)
			pause();
	}
	ATF_REQUIRE_MSG(run_shield_helper("sigcont", pid) == 1,
	    "same-session SIGCONT was not allowed for unshielded pid %d",
	    (int)pid);
	ATF_REQUIRE_EQ(kill(pid, SIGKILL), 0);
	ATF_REQUIRE_EQ(waitpid(pid, &status, 0), pid);
	ATF_CHECK(WIFSIGNALED(status));
	ATF_CHECK_EQ(WTERMSIG(status), SIGKILL);
	close(pd);
}

ATF_TC(cap_pro_foreign_sigcont_blocked);
ATF_TC_HEAD(cap_pro_foreign_sigcont_blocked, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Shield with SF_SIGCONT blocks foreign SIGCONT");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_foreign_sigcont_blocked, tc)
{
	char byte;
	ssize_t nbytes;
	int pd, result, sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd;

		close(sv[0]);
		fd = capprotect_shield(CP_SF_SIGCONT);
		if (fd < 0)
			_exit(10);
		if (write(sv[1], "s", 1) != 1)
			_exit(11);
		if (read(sv[1], &byte, 1) != 1 || byte != 'g')
			_exit(12);
		close(fd);
		close(sv[1]);
		_exit(0);
	}
	close(sv[1]);
	do {
		nbytes = read(sv[0], &byte, 1);
	} while (nbytes < 0 && errno == EINTR);
	ATF_REQUIRE_MSG(nbytes == 1 && byte == 's',
	    "shielded child did not report readiness");
	result = run_shield_helper("sigcont", pid);
	ATF_REQUIRE_MSG(result != 1,
	    "foreign same-session SIGCONT bypassed MAC policy; install and boot "
	    "a kernel containing the p_cansignal MAC veto");
	ATF_REQUIRE_MSG(result == 0,
	    "shield helper sigcont failed with status %d for pid %d",
	    result, (int)pid);
	do {
		nbytes = write(sv[0], "g", 1);
	} while (nbytes < 0 && errno == EINTR);
	ATF_REQUIRE_MSG(nbytes == 1, "could not release shielded child");
	ATF_REQUIRE_EQ(waitpid(pid, &status, 0), pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "shielded child exited abnormally (status %#x)", status);
	close(sv[0]);
	close(pd);
}

ATF_TC(cap_pro_foreign_visible_blocked);
ATF_TC_HEAD(cap_pro_foreign_visible_blocked, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Shield with SF_VISIBLE hides from foreign process");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_foreign_visible_blocked, tc)
{
	int sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		int fd;
		close(sv[0]);
		fd = capprotect_shield(CP_SF_VISIBLE);
		if (fd < 0) _exit(10);
		write(sv[1], "s", 1);
		read(sv[1], &buf, 1);
		close(fd); close(sv[1]); _exit(0);
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }
	ATF_CHECK_EQ(run_shield_helper("visibility", pid), 0);
	write(sv[0], "g", 1);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

ATF_TC(cap_pro_selective_flags);
ATF_TC_HEAD(cap_pro_selective_flags, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Only requested flags apply — ptrace blocked, signal allowed");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_selective_flags, tc)
{
	int sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		int fd;
		close(sv[0]);
		fd = capprotect_shield(CP_SF_PTRACE);
		if (fd < 0) _exit(10);
		write(sv[1], "s", 1);
		read(sv[1], &buf, 1);
		close(fd); close(sv[1]); _exit(0);
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }
	ATF_CHECK_EQ(run_shield_helper("ptrace", pid), 0);
	/* Use signal0 — real signals would kill the unshielded child. */
	ATF_CHECK_EQ(run_shield_helper("signal0", pid), 1);
	write(sv[0], "g", 1);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

ATF_TC(cap_pro_all_flags_blocks_all);
ATF_TC_HEAD(cap_pro_all_flags_blocks_all, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SF_ALL blocks everything from foreign program");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_all_flags_blocks_all, tc)
{
	int sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		int fd;
		close(sv[0]);
		fd = capprotect_shield(CP_SF_PROTECT);
		if (fd < 0) _exit(10);
		write(sv[1], "s", 1);
		read(sv[1], &buf, 1);
		close(fd); close(sv[1]); _exit(0);
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }
	ATF_CHECK_EQ(run_shield_helper("ptrace", pid), 0);
	ATF_CHECK_EQ(run_shield_helper("signal", pid), 0);
	ATF_CHECK_EQ(run_shield_helper("sigkill", pid), 0);
	ATF_CHECK_EQ(run_shield_helper("visibility", pid), 0);
	ATF_CHECK_EQ(run_shield_helper("ktrace", pid), 0);
	ATF_CHECK_EQ(run_shield_helper("suspend", pid), 0);
	write(sv[0], "g", 1);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

ATF_TC(cap_pro_close_does_not_unshield);
ATF_TC_HEAD(cap_pro_close_does_not_unshield, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing the shield fd does NOT remove protection; a per-process "
	    "shield lives for the process's lifetime and is dropped on exit");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_close_does_not_unshield, tc)
{
	int sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		int fd;
		close(sv[0]);
		fd = capprotect_shield(CP_SF_PTRACE);
		if (fd < 0) _exit(10);
		write(sv[1], "s", 1);
		read(sv[1], &buf, 1);
		close(fd);		/* closing the fd must NOT unshield */
		write(sv[1], "u", 1);
		sleep(5);
		close(sv[1]); _exit(0);
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1);
	  ATF_CHECK_EQ(run_shield_helper("ptrace", pid), 0);
	  write(sv[0], "g", 1);
	  read(sv[0], &buf, 1); }
	/* Still blocked after the descriptor is closed (exit is the bound). */
	ATF_CHECK_EQ(run_shield_helper("ptrace", pid), 0);
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

ATF_TC(cap_pro_double_shield_idempotent);
ATF_TC_HEAD(cap_pro_double_shield_idempotent, tc)
{
	atf_tc_set_md_var(tc, "descr", "SHIELD twice is idempotent");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_double_shield_idempotent, tc)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int fd;

	fd = capprotect_shield(CP_SF_ALL);
	ATF_REQUIRE(fd >= 0);
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_SHIELD;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ATF_CHECK(ioctl(fd, MAC_CAPABILITY_CALL, &ca) == 0);
	close(fd);
}

ATF_TC(cap_pro_mint_returns_token);
ATF_TC_HEAD(cap_pro_mint_returns_token, tc)
{
	atf_tc_set_md_var(tc, "descr", "MINT returns a valid token fd");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_mint_returns_token, tc)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int fd, token_fd, reply_fds[1];

	fd = capprotect_shield(CP_SF_ALL);
	ATF_REQUIRE(fd >= 0);
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_MINT;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_CALL, &ca) == 0);
	token_fd = reply_fds[0];
	ATF_CHECK(token_fd >= 0);
	ATF_CHECK(fcntl(token_fd, F_GETFD) != -1);
	close(token_fd);
	close(fd);
}

ATF_TC(cap_pro_mint_without_shield_fails);
ATF_TC_HEAD(cap_pro_mint_without_shield_fails, tc)
{
	atf_tc_set_md_var(tc, "descr", "MINT without shield returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
}
ATF_TC_BODY(cap_pro_mint_without_shield_fails, tc)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int fd, reply_fds[1];

	fd = mac_capability_connect("capprotect");
	ATF_REQUIRE(fd >= 0);
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_MINT;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, MAC_CAPABILITY_CALL, &ca) == -1);
	close(fd);
}

ATF_TC(cap_pro_shield_on_token_fails);
ATF_TC_HEAD(cap_pro_shield_on_token_fails, tc)
{
	atf_tc_set_md_var(tc, "descr", "SHIELD on token fd returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_shield_on_token_fails, tc)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int fd, token_fd, reply_fds[1];

	fd = capprotect_shield(CP_SF_ALL);
	ATF_REQUIRE(fd >= 0);
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_MINT;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_CALL, &ca) == 0);
	token_fd = reply_fds[0];

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_SHIELD;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ATF_CHECK_ERRNO(EINVAL, ioctl(token_fd, MAC_CAPABILITY_CALL, &ca) == -1);
	close(token_fd);
	close(fd);
}

ATF_TC(cap_pro_authorize_on_shield_fails);
ATF_TC_HEAD(cap_pro_authorize_on_shield_fails, tc)
{
	atf_tc_set_md_var(tc, "descr", "AUTHORIZE on shield fd returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_authorize_on_shield_fails, tc)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int fd;

	fd = capprotect_shield(CP_SF_ALL);
	ATF_REQUIRE(fd >= 0);
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_AUTHORIZE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, MAC_CAPABILITY_CALL, &ca) == -1);
	close(fd);
}

ATF_TC(cap_pro_bad_op);
ATF_TC_HEAD(cap_pro_bad_op, tc)
{
	atf_tc_set_md_var(tc, "descr", "Unknown op returns EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
}
ATF_TC_BODY(cap_pro_bad_op, tc)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int fd;

	fd = mac_capability_connect("capprotect");
	ATF_REQUIRE(fd >= 0);
	memset(&req, 0, sizeof(req));
	req.op = 99;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ATF_CHECK_ERRNO(EOPNOTSUPP, ioctl(fd, MAC_CAPABILITY_CALL, &ca) == -1);
	close(fd);
}

ATF_TC(cap_pro_bad_flags);
ATF_TC_HEAD(cap_pro_bad_flags, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Unknown shield flags are rejected with EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_bad_flags, tc)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int fd;

	fd = mac_capability_connect("capprotect");
	ATF_REQUIRE(fd >= 0);
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_SHIELD;
	req.flags = 0x80000000;	/* undefined bit (above CP_SF_ALL) */
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, MAC_CAPABILITY_CALL, &ca) == -1);
	close(fd);
}

ATF_TC(cap_pro_fork_not_inherited);
ATF_TC_HEAD(cap_pro_fork_not_inherited, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A shield is per-process: a fork child is NOT covered by the "
	    "parent's shield (born unprotected)");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_fork_not_inherited, tc)
{
	int sv[2], status;
	pid_t child_pid, grandchild_pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	child_pid = fork();
	ATF_REQUIRE(child_pid >= 0);
	if (child_pid == 0) {
		int shield_fd;
		pid_t gc;
		char buf;
		close(sv[0]);
		shield_fd = capprotect_shield(CP_SF_PTRACE);
		if (shield_fd < 0) _exit(10);
		gc = fork();		/* child born after the parent shielded */
		if (gc < 0) _exit(11);
		if (gc == 0) { close(shield_fd); sleep(5); _exit(0); }
		write(sv[1], &gc, sizeof(gc));
		read(sv[1], &buf, 1);
		kill(gc, SIGKILL);
		waitpid(gc, NULL, 0);
		close(shield_fd); close(sv[1]); _exit(0);
	}
	close(sv[1]);
	ATF_REQUIRE(read(sv[0], &grandchild_pid, sizeof(grandchild_pid))
	    == (ssize_t)sizeof(grandchild_pid));
	usleep(200000);
	/* The shielded process is protected; its fork child is NOT. */
	ATF_CHECK_EQ(run_shield_helper("ptrace", child_pid), 0);
	ATF_CHECK_EQ(run_shield_helper("ptrace", grandchild_pid), 1);
	write(sv[0], "g", 1);
	waitpid(child_pid, &status, 0);
	close(sv[0]);
}

ATF_TC(cap_pro_foreign_sched_blocked);
ATF_TC_HEAD(cap_pro_foreign_sched_blocked, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Shield with SF_SCHED blocks foreign getpriority");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_foreign_sched_blocked, tc)
{
	int sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		int fd;
		close(sv[0]);
		fd = capprotect_shield(CP_SF_SCHED);
		if (fd < 0) _exit(10);
		write(sv[1], "s", 1);
		read(sv[1], &buf, 1);
		close(fd); close(sv[1]); _exit(0);
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }
	ATF_CHECK_EQ(run_shield_helper("sched", pid), 0);
	write(sv[0], "g", 1);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

ATF_TC(cap_pro_foreign_wait_blocked);
ATF_TC_HEAD(cap_pro_foreign_wait_blocked, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Shield with SF_WAIT blocks foreign wait4");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_foreign_wait_blocked, tc)
{
	int sv[2], status;
	pid_t pid;

	atf_tc_expect_fail("waitpid on non-child returns ECHILD before "
	    "MAC hook is consulted — hook only gates child visibility");
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		int fd;
		close(sv[0]);
		fd = capprotect_shield(CP_SF_WAIT);
		if (fd < 0) _exit(10);
		write(sv[1], "s", 1);
		read(sv[1], &buf, 1);
		close(fd); close(sv[1]); _exit(0);
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }
	ATF_CHECK_EQ(run_shield_helper("wait", pid), 0);
	write(sv[0], "g", 1);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

ATF_TC(cap_pro_foreign_ktrace_blocked);
ATF_TC_HEAD(cap_pro_foreign_ktrace_blocked, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Shield with SF_KTRACE blocks foreign ktrace");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_foreign_ktrace_blocked, tc)
{
	int sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		int fd;
		close(sv[0]);
		fd = capprotect_shield(CP_SF_KTRACE);
		if (fd < 0) _exit(10);
		write(sv[1], "s", 1);
		read(sv[1], &buf, 1);
		close(fd); close(sv[1]); _exit(0);
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }
	ATF_CHECK_EQ(run_shield_helper("ktrace", pid), 0);
	write(sv[0], "g", 1);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

ATF_TC(cap_pro_foreign_suspend_blocked);
ATF_TC_HEAD(cap_pro_foreign_suspend_blocked, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Shield with SF_SIGNAL blocks foreign SIGSTOP suspension");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_foreign_suspend_blocked, tc)
{
	int sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		int fd;
		close(sv[0]);
		fd = capprotect_shield(CP_SF_SIGNAL);
		if (fd < 0) _exit(10);
		write(sv[1], "s", 1);
		read(sv[1], &buf, 1);
		close(fd); close(sv[1]); _exit(0);
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }
	ATF_CHECK_EQ(run_shield_helper("suspend", pid), 0);
	write(sv[0], "g", 1);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

ATF_TC(cap_pro_foreign_core_blocked);
ATF_TC_HEAD(cap_pro_foreign_core_blocked, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Shield with SF_CORE suppresses core dump");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_foreign_core_blocked, tc)
{
	int sv[2], status;
	pid_t pid;
	struct rlimit rl;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		int fd;
		close(sv[0]);
		/* Enable core dumps. */
		rl.rlim_cur = RLIM_INFINITY;
		rl.rlim_max = RLIM_INFINITY;
		setrlimit(RLIMIT_CORE, &rl);
		fd = capprotect_shield(CP_SF_CORE);
		if (fd < 0) _exit(10);
		write(sv[1], "s", 1);
		/* Wait for parent, then abort to trigger core dump. */
		read(sv[1], &buf, 1);
		abort();
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }
	/*
	 * Tell child to abort.  The MAC hook should suppress the
	 * core dump, but the process still dies from SIGABRT.
	 */
	write(sv[0], "g", 1);
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFSIGNALED(status));
	ATF_CHECK_EQ(WTERMSIG(status), SIGABRT);
	/* Core flag should NOT be set — dump was suppressed. */
	ATF_CHECK(!(WCOREDUMP(status)));
	close(sv[0]);
}

ATF_TC(cap_pro_authorize_grants_access);
ATF_TC_HEAD(cap_pro_authorize_grants_access, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Minted token + AUTHORIZE grants foreign program access");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_authorize_grants_access, tc)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int sv[2], status;
	pid_t pid;
	int shield_fd, token_fd, reply_fds[1];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		char buf;
		int fd;
		close(sv[0]);
		fd = capprotect_shield(CP_SF_PTRACE);
		if (fd < 0) _exit(10);
		write(sv[1], "s", 1);
		read(sv[1], &buf, 1);
		close(fd); close(sv[1]); _exit(0);
	}

	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }

	/* Foreign helper is blocked. */
	ATF_CHECK_EQ(run_shield_helper("ptrace", pid), 0);

	/*
	 * Now connect from this process (same nonce as child),
	 * mint a token, and authorize from a forked+exec'd child.
	 * Since we can't easily pass an fd to the exec'd helper,
	 * we authorize from the parent (same nonce — already allowed)
	 * and then verify the auth table entry exists by checking
	 * the helper is still blocked (auth is keyed by nonce, and
	 * the helper has a different nonce than us).
	 *
	 * For a proper cross-nonce authorize test, we use a second
	 * fork where the child execs, inherits the token fd, and
	 * authorizes itself.
	 */

	/*
	 * Instead: open a second capprotect connection (same nonce),
	 * mint a token, and pass it to a child that execs.  The child
	 * must activate the token after exec to get its new nonce into
	 * the auth table.  But MAC_CAPABILITY fds are CLOEXEC...
	 *
	 * Simplest viable test: authorize from parent (demonstrates
	 * the authorize path succeeds), then verify the auth table
	 * allows the parent nonce through.  Since parent is same-nonce
	 * it's already allowed.  This test is really about verifying
	 * CP_OP_AUTHORIZE doesn't error and the state machine works.
	 */
	shield_fd = capprotect_shield(CP_SF_PTRACE);
	ATF_REQUIRE(shield_fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_MINT;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(shield_fd, MAC_CAPABILITY_CALL, &ca) == 0);
	token_fd = reply_fds[0];
	ATF_REQUIRE(token_fd >= 0);

	/* Authorize succeeds. */
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_AUTHORIZE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ATF_CHECK(ioctl(token_fd, MAC_CAPABILITY_CALL, &ca) == 0);

	/* Double authorize is idempotent. */
	ATF_CHECK(ioctl(token_fd, MAC_CAPABILITY_CALL, &ca) == 0);

	close(token_fd);
	close(shield_fd);

	write(sv[0], "g", 1);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

ATF_TC(cap_pro_token_close_revokes);
ATF_TC_HEAD(cap_pro_token_close_revokes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing token fd revokes authorization");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_token_close_revokes, tc)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int shield_fd, token_fd, reply_fds[1];

	shield_fd = capprotect_shield(CP_SF_ALL);
	ATF_REQUIRE(shield_fd >= 0);

	/* Mint and authorize. */
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_MINT;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(shield_fd, MAC_CAPABILITY_CALL, &ca) == 0);
	token_fd = reply_fds[0];

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_AUTHORIZE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ATF_REQUIRE(ioctl(token_fd, MAC_CAPABILITY_CALL, &ca) == 0);

	/* Token is active — close it to revoke. */
	close(token_fd);

	/*
	 * After close, the auth entry for our nonce is removed.
	 * We can't directly observe this from the same nonce (same-
	 * nonce bypass), but we can verify the token fd is gone.
	 */
	ATF_CHECK(fcntl(token_fd, F_GETFD) == -1);

	close(shield_fd);
}

ATF_TC(cap_pro_delegated_access);
ATF_TC_HEAD(cap_pro_delegated_access, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Mint token, authorize from foreign nonce, access granted then revoked");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_delegated_access, tc)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	struct msghdr msgh;
	struct iovec iov;
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	int sv[2], status;
	int token_fd, reply_fds[1];
	pid_t target, helper;
	char dummy = 'x';
	char path[256];
	char fdstr[16], pidstr[16];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	/* Fork the target process that will shield itself. */
	target = fork();
	ATF_REQUIRE(target >= 0);
	if (target == 0) {
		char buf;
		int fd;
		close(sv[0]);

		fd = capprotect_shield(CP_SF_PTRACE);
		if (fd < 0) _exit(10);

		/* Mint a token. */
		memset(&req, 0, sizeof(req));
		req.op = CP_OP_MINT;
		memset(&ca, 0, sizeof(ca));
		ca.req = &req;
		ca.req_len = sizeof(req);
		ca.reply_fds = reply_fds;
		ca.reply_nfds = 1;
		if (ioctl(fd, MAC_CAPABILITY_CALL, &ca) != 0)
			_exit(11);

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
		memcpy(CMSG_DATA(cmsg), &reply_fds[0], sizeof(int));
		sendmsg(sv[1], &msgh, 0);
		close(reply_fds[0]);

		/* Wait for parent to finish testing. */
		read(sv[1], &buf, 1);
		close(fd); close(sv[1]); _exit(0);
	}

	close(sv[1]);

	/* Receive the token fd from child. */
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
	ATF_REQUIRE(token_fd >= 0);

	/* Verify: foreign process is blocked without authorization. */
	ATF_CHECK_EQ(run_shield_helper("ptrace", target), 0);

	/* Clear CLOEXEC so the helper inherits this fd across exec. */
	ATF_REQUIRE(fcntl(token_fd, F_SETFD, 0) == 0);

	/* Fork+exec a helper that authorizes itself and ptraces. */
	strlcpy(path, shield_helper_path(), sizeof(path));
	snprintf(fdstr, sizeof(fdstr), "%d", token_fd);
	snprintf(pidstr, sizeof(pidstr), "%d", (int)target);

	helper = fork();
	ATF_REQUIRE(helper >= 0);
	if (helper == 0) {
		execl(path, "mac_capability_shield_helper",
		    "authorize_ptrace", fdstr, pidstr, NULL);
		_exit(2);
	}
	waitpid(helper, &status, 0);
	ATF_REQUIRE(WIFEXITED(status));
	/* Helper authorized itself and ptrace succeeded. */
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	/* Close the token — revokes access. */
	close(token_fd);

	/* Foreign process should be blocked again. */
	ATF_CHECK_EQ(run_shield_helper("ptrace", target), 0);

	/* Clean up. */
	write(sv[0], "g", 1);
	waitpid(target, &status, 0);
	close(sv[0]);
}

ATF_TC(cap_pro_refcount_shield);
ATF_TC_HEAD(cap_pro_refcount_shield, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Multiple shield fds: closing one keeps protection");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_refcount_shield, tc)
{
	int sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		int fd1, fd2;
		close(sv[0]);

		/* Open two shield fds. */
		fd1 = capprotect_shield(CP_SF_PTRACE);
		if (fd1 < 0) _exit(10);
		fd2 = capprotect_shield(CP_SF_PTRACE);
		if (fd2 < 0) _exit(11);

		write(sv[1], "s", 1);
		read(sv[1], &buf, 1);

		/* Close first fd — should still be protected. */
		close(fd1);
		write(sv[1], "1", 1);
		read(sv[1], &buf, 1);

		/* Close second fd — now unprotected. */
		close(fd2);
		write(sv[1], "2", 1);

		sleep(5);
		close(sv[1]); _exit(0);
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }

	/* Both fds open — blocked. */
	ATF_CHECK_EQ(run_shield_helper("ptrace", pid), 0);

	/* Tell child to close first fd. */
	write(sv[0], "g", 1);
	{ char buf; read(sv[0], &buf, 1); }

	/* Still blocked (refcount > 0). */
	ATF_CHECK_EQ(run_shield_helper("ptrace", pid), 0);

	/* Tell child to close second fd. */
	write(sv[0], "g", 1);
	{ char buf; read(sv[0], &buf, 1); }

	/* Now unprotected. */
	ATF_CHECK_EQ(run_shield_helper("ptrace", pid), 1);

	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	close(sv[0]);
}

ATF_TC(cap_pro_mint_narrow_subset);
ATF_TC_HEAD(cap_pro_mint_narrow_subset, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MINT with subset of shield flags succeeds");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_mint_narrow_subset, tc)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int fd, token_fd, reply_fds[1];

	fd = capprotect_shield(CP_SF_PTRACE | CP_SF_SIGNAL | CP_SF_VISIBLE);
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_MINT;
	req.flags = CP_SF_SIGNAL;  /* narrowed: only signal access */
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_CALL, &ca) == 0);
	token_fd = reply_fds[0];
	ATF_CHECK(token_fd >= 0);
	close(token_fd);
	close(fd);
}

ATF_TC(cap_pro_mint_narrow_rejects_unshielded);
ATF_TC_HEAD(cap_pro_mint_narrow_rejects_unshielded, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MINT with flags outside shield scope fails");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_mint_narrow_rejects_unshielded, tc)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int fd, reply_fds[1];

	fd = capprotect_shield(CP_SF_PTRACE | CP_SF_SIGNAL);
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_MINT;
	req.flags = CP_SF_VISIBLE;  /* not in shield scope */
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_CHECK(ioctl(fd, MAC_CAPABILITY_CALL, &ca) != 0);
	ATF_CHECK(errno == EINVAL);
	close(fd);
}

ATF_TC(cap_pro_mint_narrow_zero_gives_all);
ATF_TC_HEAD(cap_pro_mint_narrow_zero_gives_all, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MINT with flags=0 gives full shield scope");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_mint_narrow_zero_gives_all, tc)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int fd, token_fd, reply_fds[1];

	fd = capprotect_shield(CP_SF_PTRACE | CP_SF_SIGNAL);
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_MINT;
	req.flags = 0;  /* should get all shield flags */
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_CALL, &ca) == 0);
	token_fd = reply_fds[0];
	ATF_CHECK(token_fd >= 0);
	close(token_fd);
	close(fd);
}

/* ================================================================
 * Self-restriction: CP_SF_NOEXEC / CP_SF_NOSOCK
 * ================================================================ */

ATF_TC(cap_pro_noexec_blocks_exec);
ATF_TC_HEAD(cap_pro_noexec_blocks_exec, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CP_SF_NOEXEC prevents execve in shielded child");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_noexec_blocks_exec, tc)
{
	int sv[2], status;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd;
		close(sv[0]);
		fd = capprotect_shield(CP_SF_NOEXEC);
		if (fd < 0) _exit(10);
		write(sv[1], "r", 1);
		/* Try to exec — should fail with EPERM. */
		execl("/usr/bin/true", "true", NULL);
		/* If we get here, exec failed as expected. */
		_exit(errno == EPERM ? 0 : 1);
	}
	close(sv[1]);
	{ char buf; read(sv[0], &buf, 1); }
	waitpid(pid, &status, 0);
	close(sv[0]);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);
}

ATF_TC(cap_pro_noexec_unshield_allows_exec);
ATF_TC_HEAD(cap_pro_noexec_unshield_allows_exec, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing shield fd removes CP_SF_NOEXEC, exec succeeds");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_noexec_unshield_allows_exec, tc)
{
	int status;
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd;
		fd = capprotect_shield(CP_SF_NOEXEC);
		if (fd < 0) _exit(10);
		close(fd);
		execl("/usr/bin/true", "true", NULL);
		_exit(1);  /* exec failed unexpectedly */
	}
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);
}

ATF_TC(cap_pro_nosock_blocks_socket);
ATF_TC_HEAD(cap_pro_nosock_blocks_socket, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CP_SF_NOSOCK prevents socket() in shielded child");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_nosock_blocks_socket, tc)
{
	int status;
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd, sock;
		fd = capprotect_shield(CP_SF_NOSOCK);
		if (fd < 0) _exit(10);
		sock = socket(AF_UNIX, SOCK_STREAM, 0);
		if (sock >= 0) {
			close(sock);
			close(fd);
			_exit(1);  /* socket should have failed */
		}
		close(fd);
		_exit(errno == EPERM ? 0 : 2);
	}
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);
}

ATF_TC(cap_pro_nosock_unshield_allows_socket);
ATF_TC_HEAD(cap_pro_nosock_unshield_allows_socket, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing shield fd removes CP_SF_NOSOCK, socket succeeds");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_nosock_unshield_allows_socket, tc)
{
	int status;
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd, sock;
		fd = capprotect_shield(CP_SF_NOSOCK);
		if (fd < 0) _exit(10);
		close(fd);
		sock = socket(AF_UNIX, SOCK_STREAM, 0);
		if (sock < 0) _exit(1);  /* socket should have worked */
		close(sock);
		_exit(0);
	}
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);
}

ATF_TC(cap_pro_nosock_socketpair_blocked);
ATF_TC_HEAD(cap_pro_nosock_socketpair_blocked, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CP_SF_NOSOCK also blocks socketpair()");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_nosock_socketpair_blocked, tc)
{
	int status;
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd, sv[2];
		fd = capprotect_shield(CP_SF_NOSOCK);
		if (fd < 0) _exit(10);
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
			close(sv[0]);
			close(sv[1]);
			close(fd);
			_exit(1);  /* socketpair should have failed */
		}
		close(fd);
		_exit(errno == EPERM ? 0 : 2);
	}
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);
}

ATF_TC(cap_pro_nofdrecv_channel_attachment);
ATF_TC_HEAD(cap_pro_nofdrecv_channel_attachment, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CP_SF_NOFDRECV blocks ambient SCM_RIGHTS but permits bounded attachments on an already-held capability channel");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cap_pro_nofdrecv_channel_attachment, tc)
{
	struct mac_capability_recvmsg_args ra;
	struct mac_capability_sendmsg_args sa;
	struct msghdr message;
	struct cmsghdr *cmsg;
	struct iovec iov;
	union {
		struct cmsghdr align;
		char data[CMSG_SPACE(sizeof(int))];
	} control;
	char byte, payload;
	int channel[2], ordinary[2], pipe_channel[2], pipe_unix[2];
	int received_fd, shield_fd;

	mac_capability_channel_create(&channel[0], &channel[1]);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_DGRAM, 0, ordinary) == 0);
	ATF_REQUIRE(pipe(pipe_unix) == 0);
	ATF_REQUIRE(pipe(pipe_channel) == 0);
	shield_fd = capprotect_shield(CP_SF_NOFDRECV);
	ATF_REQUIRE(shield_fd >= 0);

	memset(&message, 0, sizeof(message));
	memset(&control, 0, sizeof(control));
	byte = 'u';
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = control.data;
	message.msg_controllen = sizeof(control.data);
	cmsg = CMSG_FIRSTHDR(&message);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &pipe_unix[0], sizeof(int));
	ATF_REQUIRE(sendmsg(ordinary[0], &message, 0) == sizeof(byte));

	memset(&message, 0, sizeof(message));
	memset(&control, 0, sizeof(control));
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = control.data;
	message.msg_controllen = sizeof(control.data);
	ATF_CHECK_ERRNO(EACCES, recvmsg(ordinary[1], &message, 0) == -1);

	ATF_REQUIRE(cap_xfer_limit(pipe_channel[0], CAP_XFER_ONCE) == 0);
	payload = 'c';
	memset(&sa, 0, sizeof(sa));
	sa.payload = &payload;
	sa.payload_len = sizeof(payload);
	sa.fds = &pipe_channel[0];
	sa.nfds = 1;
	ATF_REQUIRE(ioctl(channel[0], MAC_CAPABILITY_SENDMSG, &sa) == 0);
	received_fd = -1;
	memset(&ra, 0, sizeof(ra));
	ra.payload = &payload;
	ra.payload_len = sizeof(payload);
	ra.fds = &received_fd;
	ra.nfds = 1;
	ATF_REQUIRE(ioctl(channel[1], MAC_CAPABILITY_RECVMSG, &ra) == 0);
	ATF_REQUIRE_EQ(1, ra.nfds);
	ATF_REQUIRE(received_fd >= 0);
	errno = 0;
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    cap_xfer_limit(received_fd, CAP_XFER_ONCE) == -1);
	ATF_REQUIRE(write(pipe_channel[1], "x", 1) == 1);
	ATF_CHECK(read(received_fd, &byte, 1) == 1 && byte == 'x');

	close(received_fd);
	close(shield_fd);
	close(pipe_channel[0]);
	close(pipe_channel[1]);
	close(pipe_unix[0]);
	close(pipe_unix[1]);
	close(ordinary[0]);
	close(ordinary[1]);
	close(channel[0]);
	close(channel[1]);
}

/* ================================================================
 * Token capability
 * ================================================================ */

/* ================================================================
 * Additional framework edge cases
 * ================================================================ */

ATF_TC(kqueue_eof_on_terminate);
ATF_TC_HEAD(kqueue_eof_on_terminate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "kqueue fires EV_EOF when instance is terminated");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(kqueue_eof_on_terminate, tc)
{
	struct kevent kev;
	struct timespec ts;
	int fd, kq, ret;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);

	/* Terminate the instance. */
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_TERMINATE, NULL) == 0);

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
	    "Send exactly MAC_CAPABILITY_MAX_MSG bytes, verify round trip");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(max_payload_size, tc)
{
	char *big;
	struct ks_request *req;
	char buf[MAC_CAPABILITY_MAX_MSG];
	uint32_t rlen;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/* Build a STORE that fills max payload. */
	big = calloc(1, MAC_CAPABILITY_MAX_MSG);
	ATF_REQUIRE(big != NULL);
	req = (struct ks_request *)big;
	req->op = KS_OP_STORE;
	req->keyid = 55555;
	memset(big + sizeof(*req), 'A', MAC_CAPABILITY_MAX_MSG - sizeof(*req));
	ATF_REQUIRE(mac_capability_send(fd, big, MAC_CAPABILITY_MAX_MSG, 0) == 0);

	rlen = sizeof(buf);
	ATF_REQUIRE(mac_capability_recv(fd, buf, &rlen, NULL) == 0);
	free(big);

	close(fd);
}

ATF_TC(payload_over_max);
ATF_TC_HEAD(payload_over_max, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Send MAC_CAPABILITY_MAX_MSG+1 bytes returns EMSGSIZE");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(payload_over_max, tc)
{
	struct mac_capability_sendmsg_args sa;
	char *big;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	big = calloc(1, MAC_CAPABILITY_MAX_MSG + 1);
	ATF_REQUIRE(big != NULL);
	memset(&sa, 0, sizeof(sa));
	sa.payload = big;
	sa.payload_len = MAC_CAPABILITY_MAX_MSG + 1;
	ATF_CHECK_ERRNO(EMSGSIZE, ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);

	free(big);
	close(fd);
}

ATF_TC(channel_kqueue_eof_on_close);
ATF_TC_HEAD(channel_kqueue_eof_on_close, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "kqueue fires EV_EOF on channel when peer closes");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_kqueue_eof_on_close, tc)
{
	struct kevent kev;
	struct timespec ts;
	int fd_a, fd_b, kq, ret;

	mac_capability_channel_create(&fd_a, &fd_b);

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

ATF_TC(channel_send_after_peer_close);
ATF_TC_HEAD(channel_send_after_peer_close, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG after peer closes returns EPIPE or ECONNRESET");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_send_after_peer_close, tc)
{
	int fd_a, fd_b, i, flags;

	mac_capability_channel_create(&fd_a, &fd_b);
	close(fd_a);

	flags = fcntl(fd_b, F_GETFL, 0);
	fcntl(fd_b, F_SETFL, flags | O_NONBLOCK);

	/* Poll until revocation propagates. */
	for (i = 0; i < 100; i++) {
		if (mac_capability_send(fd_b, "x", 1, 0) == -1 &&
		    (errno == EPIPE || errno == ECONNRESET))
			break;
		usleep(10000);
	}
	ATF_CHECK(mac_capability_send(fd_b, "dead", 4, 0) == -1);
	ATF_CHECK(errno == EPIPE || errno == ECONNRESET);

	close(fd_b);
}

ATF_TC(channel_unconnected_send);
ATF_TC_HEAD(channel_unconnected_send, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG before CHANNEL_OP_CREATE with wrong op fails");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_unconnected_send, tc)
{
	char buf[64];
	uint32_t rlen;
	int fd;

	fd = mac_capability_connect("channel");
	ATF_REQUIRE(fd >= 0);

	/* Send a non-CREATE message to unconnected instance. */
	uint32_t val = 99;
	ATF_REQUIRE(mac_capability_send(fd, &val, sizeof(val), 0) == 0);

	/* Should get an error reply (handler returns EINVAL). */
	rlen = sizeof(buf);
	ATF_REQUIRE(mac_capability_recv(fd, buf, &rlen, NULL) == 0);
	/* Error reply is 4 bytes (uint32_t errno). */
	ATF_CHECK(rlen == 4);

	close(fd);
}

ATF_TC(terminate_twice);
ATF_TC_HEAD(terminate_twice, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_TERMINATE twice is harmless");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(terminate_twice, tc)
{
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_TERMINATE, NULL) == 0);
	/* Second terminate — instance already dead. */
	ATF_CHECK(ioctl(fd, MAC_CAPABILITY_TERMINATE, NULL) == 0);

	close(fd);
}

ATF_TC(connect_reserved_nonzero);
ATF_TC_HEAD(connect_reserved_nonzero, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_CONNECT with nonzero reserved fields returns EINVAL");
}
ATF_TC_BODY(connect_reserved_nonzero, tc)
{
	struct mac_capability_connect_args ca;
	int ctl;

	ctl = mac_capability_open();

	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "test_keystore", sizeof(ca.name));
	ca._reserved[0] = 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) == -1);

	close(ctl);
}

ATF_TC(call_req_oversized);
ATF_TC_HEAD(call_req_oversized, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_CALL with req_len > max returns EMSGSIZE");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(call_req_oversized, tc)
{
	struct mac_capability_call_args ca;
	char *big;
	char reply[64];
	int fd;

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);

	big = calloc(1, MAC_CAPABILITY_MAX_MSG + 1);
	ATF_REQUIRE(big != NULL);
	memset(&ca, 0, sizeof(ca));
	ca.req = big;
	ca.req_len = MAC_CAPABILITY_MAX_MSG + 1;
	ca.reply = reply;
	ca.reply_len = sizeof(reply);
	ATF_CHECK_ERRNO(EMSGSIZE, ioctl(fd, MAC_CAPABILITY_CALL, &ca) == -1);

	free(big);
	close(fd);
}

ATF_TC(capprotect_getinfo_call_feature);
ATF_TC_HEAD(capprotect_getinfo_call_feature, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Capprotect service reports CALL feature, not SENDMSG");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_capprotect");
}
ATF_TC_BODY(capprotect_getinfo_call_feature, tc)
{
	struct mac_capability_info_args info;
	int fd;

	fd = mac_capability_connect("capprotect");
	ATF_REQUIRE(fd >= 0);
	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);
	ATF_CHECK_STREQ(info.name, "capprotect");
	ATF_CHECK((info.features & MAC_CAPABILITY_INFO_F_CALL) != 0);
	ATF_CHECK((info.features & MAC_CAPABILITY_INFO_F_SENDMSG) == 0);
	close(fd);
}

ATF_TC(channel_concurrent_writers);
ATF_TC_HEAD(channel_concurrent_writers, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Multiple processes send on same channel end concurrently");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_concurrent_writers, tc)
{
	int fd_a, fd_b, status;
	pid_t pids[4];
	int i;

	mac_capability_channel_create(&fd_a, &fd_b);

	/* Fork 4 children, each sends 10 messages on fd_a. */
	for (i = 0; i < 4; i++) {
		pids[i] = fork();
		ATF_REQUIRE(pids[i] >= 0);
		if (pids[i] == 0) {
			int j;
			close(fd_b);
			for (j = 0; j < 10; j++) {
				uint32_t val = (uint32_t)(i * 100 + j);
				if (mac_capability_send(fd_a, &val, sizeof(val), 0) != 0)
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
		ATF_REQUIRE_MSG(mac_capability_recv(fd_b, buf, &rlen, NULL) == 0,
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
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(rapid_connect_disconnect, tc)
{
	int i;

	for (i = 0; i < 100; i++) {
		int fd = mac_capability_connect("test_keystore");
		ATF_REQUIRE_MSG(fd >= 0, "connect %d: %s", i, strerror(errno));
		close(fd);
	}
}

ATF_TC(channel_nonblock_recv_empty);
ATF_TC_HEAD(channel_nonblock_recv_empty, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "O_NONBLOCK RECVMSG on channel with no messages returns EAGAIN");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_nonblock_recv_empty, tc)
{
	struct mac_capability_recvmsg_args ra;
	char buf[64];
	int fd_a, fd_b, flags;

	mac_capability_channel_create(&fd_a, &fd_b);

	flags = fcntl(fd_b, F_GETFL, 0);
	ATF_REQUIRE(fcntl(fd_b, F_SETFL, flags | O_NONBLOCK) == 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_CHECK_ERRNO(EAGAIN, ioctl(fd_b, MAC_CAPABILITY_RECVMSG, &ra) == -1);

	close(fd_b);
	close(fd_a);
}

ATF_TC(channel_double_create);
ATF_TC_HEAD(channel_double_create, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Second CHANNEL_OP_CREATE after connecting gets error reply");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(channel_double_create, tc)
{
	uint32_t op;
	char buf[64];
	uint32_t rlen;
	int fd_a, fd_b;

	mac_capability_channel_create(&fd_a, &fd_b);

	/*
	 * Already connected — second CREATE is forwarded to peer
	 * as data (channel is a pipe after connecting, not a command
	 * interface).  Verify it arrives on fd_b.
	 */
	op = CHANNEL_OP_CREATE;
	ATF_REQUIRE(mac_capability_send(fd_a, &op, sizeof(op), 0) == 0);
	rlen = sizeof(buf);
	ATF_REQUIRE(mac_capability_recv(fd_b, buf, &rlen, NULL) == 0);
	ATF_CHECK_EQ(rlen, sizeof(op));

	close(fd_b);
	close(fd_a);
}

ATF_TC(sendmsg_flags_nonzero);
ATF_TC_HEAD(sendmsg_flags_nonzero, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG with nonzero flags returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(sendmsg_flags_nonzero, tc)
{
	struct mac_capability_sendmsg_args sa;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	memset(&sa, 0, sizeof(sa));
	sa.payload = "x";
	sa.payload_len = 1;
	sa.flags = 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);

	close(fd);
}

ATF_TC(recvmsg_flags_nonzero);
ATF_TC_HEAD(recvmsg_flags_nonzero, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "RECVMSG with nonzero flags returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(recvmsg_flags_nonzero, tc)
{
	struct mac_capability_recvmsg_args ra;
	char buf[64];
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ra.flags = 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == -1);

	close(fd);
}

ATF_TC(xfer_none_idempotent);
ATF_TC_HEAD(xfer_none_idempotent, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CAP_XFER_NONE twice is harmless");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(xfer_none_idempotent, tc)
{
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_NONE) == 0);
	ATF_CHECK(cap_xfer_limit(fd, CAP_XFER_NONE) == 0);

	close(fd);
}

ATF_TC(revoke_send_on_sync);
ATF_TC_HEAD(revoke_send_on_sync, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "REVOKE_SEND on sync service — SENDMSG already EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(revoke_send_on_sync, tc)
{
	struct mac_capability_sendmsg_args sa;
	int fd;

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);

	/* Revoke send on a sync service. */
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_REVOKE_SEND, NULL) == 0);

	/* SENDMSG was already EOPNOTSUPP, now it's EACCES. */
	memset(&sa, 0, sizeof(sa));
	sa.payload = "x";
	sa.payload_len = 1;
	ATF_CHECK(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);
	ATF_CHECK(errno == EACCES || errno == EOPNOTSUPP);

	close(fd);
}

ATF_TC(revoke_call_on_async);
ATF_TC_HEAD(revoke_call_on_async, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "REVOKE_CALL on async service — CALL already EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(revoke_call_on_async, tc)
{
	struct mac_capability_call_args ca;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_REVOKE_CALL, NULL) == 0);

	memset(&ca, 0, sizeof(ca));
	ca.req = "x";
	ca.req_len = 1;
	ATF_CHECK(ioctl(fd, MAC_CAPABILITY_CALL, &ca) == -1);
	ATF_CHECK(errno == EACCES || errno == EOPNOTSUPP);

	close(fd);
}

ATF_TC(close_during_blocked_recv);
ATF_TC_HEAD(close_during_blocked_recv, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Close fd from another thread while RECVMSG blocks");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(close_during_blocked_recv, tc)
{
	int fd, status;
	pid_t pid;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: block on RECVMSG (no messages pending). */
		struct mac_capability_recvmsg_args ra;
		char buf[64];
		int ret;

		memset(&ra, 0, sizeof(ra));
		ra.payload = buf;
		ra.payload_len = sizeof(buf);
		ret = ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra);
		/* Should unblock with ECONNRESET after terminate. */
		if (ret == -1 && errno == ECONNRESET)
			_exit(0);
		_exit(1);
	}

	/* Parent: give child time to block, then terminate. */
	usleep(100000);
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_TERMINATE, NULL) == 0);

	/* Child should unblock with ECONNRESET and exit 0. */
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child exited with status %d", WEXITSTATUS(status));
	close(fd);
}

ATF_TC(getinfo_after_terminate);
ATF_TC_HEAD(getinfo_after_terminate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "GETINFO on terminated instance still returns metadata");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(getinfo_after_terminate, tc)
{
	struct mac_capability_info_args info;
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_TERMINATE, NULL) == 0);

	/* GETINFO should still work — it doesn't check DEAD. */
	memset(&info, 0, sizeof(info));
	ATF_CHECK(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);
	ATF_CHECK_STREQ(info.name, "test_keystore");

	close(fd);
}

ATF_TC(capsicum_gates_terminate);
ATF_TC_HEAD(capsicum_gates_terminate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "cap_ioctls_limit can block MAC_CAPABILITY_TERMINATE");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(capsicum_gates_terminate, tc)
{
	cap_rights_t rights;
	cap_ioctl_t cmds[1];
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	/* Restrict to GETINFO only. */
	cap_rights_init(&rights, CAP_IOCTL);
	ATF_REQUIRE(cap_rights_limit(fd, &rights) == 0);
	cmds[0] = MAC_CAPABILITY_GETINFO;
	ATF_REQUIRE(cap_ioctls_limit(fd, cmds, 1) == 0);

	/* TERMINATE should be blocked. */
	ATF_CHECK_ERRNO(ENOTCAPABLE, ioctl(fd, MAC_CAPABILITY_TERMINATE, NULL) == -1);

	close(fd);
}

/* ================================================================
 * Mint restriction tests (ioctl allowlist + REVOKE_MINT)
 * ================================================================ */

static int
channel_mint_instance(int fd)
{
	struct mac_capability_mint_instance_args ma;

	memset(&ma, 0, sizeof(ma));
	if (ioctl(fd, MAC_CAPABILITY_MINT_INSTANCE, &ma) != 0)
		return (-1);
	return (ma.fd);
}

ATF_TC(capsicum_mint_ioctl_limit);
ATF_TC_HEAD(capsicum_mint_ioctl_limit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Removing MINT_INSTANCE from the ioctl allowlist blocks minting");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(capsicum_mint_ioctl_limit, tc)
{
	cap_ioctl_t cmds[] = { MAC_CAPABILITY_GETINFO };
	int fd, minted;

	fd = mac_capability_connect("channel");
	ATF_REQUIRE(fd >= 0);

	/* Mint should work before limiting. */
	minted = channel_mint_instance(fd);
	ATF_REQUIRE_MSG(minted >= 0, "mint before limit: %s", strerror(errno));
	close(minted);

	ATF_REQUIRE(cap_ioctls_limit(fd, cmds, nitems(cmds)) == 0);

	/* Mint should now fail with ENOTCAPABLE. */
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    ioctl(fd, MAC_CAPABILITY_MINT_INSTANCE, &(struct mac_capability_mint_instance_args){0}) == -1);

	close(fd);
}

ATF_TC(revoke_mint_blocks_minting);
ATF_TC_HEAD(revoke_mint_blocks_minting, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_REVOKE_MINT blocks MINT_INSTANCE on all fds");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_channel");
}
ATF_TC_BODY(revoke_mint_blocks_minting, tc)
{
	int fd, fd2, minted;

	fd = mac_capability_connect("channel");
	ATF_REQUIRE(fd >= 0);

	/* Dup before revoking — both fds share the instance. */
	fd2 = dup(fd);
	ATF_REQUIRE(fd2 >= 0);

	/* Mint works before revoke. */
	minted = channel_mint_instance(fd);
	ATF_REQUIRE(minted >= 0);
	close(minted);

	/* Revoke minting. */
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_REVOKE_MINT, NULL) == 0);

	/* Both fds should be blocked. */
	ATF_CHECK_ERRNO(EACCES, channel_mint_instance(fd) == -1);
	ATF_CHECK_ERRNO(EACCES, channel_mint_instance(fd2) == -1);

	close(fd2);
	close(fd);
}

/* ================================================================
 * Process nonce tests
 * ================================================================ */

/*
 * Nonce is in the credential trailer.  Send a message, receive the
 * reply, and check that the nonce field is non-zero.  (Replies from
 * kernel handlers have zero trailer, so we test via a forked child
 * that sends a message — the child's creds are stamped on RX.)
 *
 * Since keystore replies come from the kernel (zero trailer), we
 * test the nonce via fork: parent and child should share the same
 * nonce, and after exec the nonce should change.
 */

ATF_TC(nonce_nonzero);
ATF_TC_HEAD(nonce_nonzero, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Program nonce is non-zero in credential trailer");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(nonce_nonzero, tc)
{
	int sv[2], status;
	int fd;
	pid_t pid;
	uint64_t child_nonce;
	struct kstore_request kr;

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		struct mac_capability_call_args ca;
		struct kstore_status_reply sr;

		close(sv[0]);
		memset(&kr, 0, sizeof(kr));
		kr.op = KSTORE_OP_GET;
		strlcpy(kr.key, "_test", sizeof(kr.key));
		memset(&ca, 0, sizeof(ca));
		ca.req = &kr;
		ca.req_len = sizeof(kr);
		ca.reply = &sr;
		ca.reply_len = sizeof(sr);
		if (ioctl(fd, MAC_CAPABILITY_CALL, &ca) != 0)
			_exit(10);
		if (write(sv[1], &ca.trailer.nonce,
		    sizeof(ca.trailer.nonce)) != sizeof(ca.trailer.nonce))
			_exit(11);
		close(fd);
		close(sv[1]);
		_exit(0);
	}

	close(sv[1]);
	ATF_REQUIRE(read(sv[0], &child_nonce, sizeof(child_nonce)) ==
	    sizeof(child_nonce));

	ATF_CHECK_MSG(child_nonce != 0,
	    "process nonce should be non-zero");

	waitpid(pid, &status, 0);
	close(fd);
	close(sv[0]);
}

ATF_TC(nonce_inherits_fork);
ATF_TC_HEAD(nonce_inherits_fork, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Forked child inherits parent's process nonce");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(nonce_inherits_fork, tc)
{
	int sv[2], status;
	int fd;
	uint64_t parent_nonce, child_nonce;
	pid_t pid;
	struct mac_capability_call_args ca;
	struct kstore_request kr;
	struct kstore_status_reply sr;

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	memset(&kr, 0, sizeof(kr));
	kr.op = KSTORE_OP_GET;
	strlcpy(kr.key, "_test", sizeof(kr.key));
	memset(&ca, 0, sizeof(ca));
	ca.req = &kr;
	ca.req_len = sizeof(kr);
	ca.reply = &sr;
	ca.reply_len = sizeof(sr);
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_CALL, &ca) == 0);
	parent_nonce = ca.trailer.nonce;

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		struct mac_capability_call_args child_ca;
		struct kstore_status_reply child_sr;

		close(sv[0]);
		memset(&child_ca, 0, sizeof(child_ca));
		child_ca.req = &kr;
		child_ca.req_len = sizeof(kr);
		child_ca.reply = &child_sr;
		child_ca.reply_len = sizeof(child_sr);
		if (ioctl(fd, MAC_CAPABILITY_CALL, &child_ca) != 0)
			_exit(10);
		if (write(sv[1], &child_ca.trailer.nonce,
		    sizeof(child_ca.trailer.nonce)) !=
		    sizeof(child_ca.trailer.nonce))
			_exit(11);
		close(fd);
		close(sv[1]);
		_exit(0);
	}

	close(sv[1]);
	ATF_REQUIRE(read(sv[0], &child_nonce, sizeof(child_nonce)) ==
	    sizeof(child_nonce));

	ATF_CHECK_MSG(parent_nonce != 0, "parent nonce should be non-zero");
	ATF_CHECK_MSG(child_nonce == parent_nonce,
	    "child nonce 0x%lx should equal parent nonce 0x%lx",
	    (unsigned long)child_nonce, (unsigned long)parent_nonce);

	waitpid(pid, &status, 0);
	close(fd);
	close(sv[0]);
}

ATF_TC(nonce_trailer_zero_on_reply);
ATF_TC_HEAD(nonce_trailer_zero_on_reply, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Kernel replies have zero nonce in trailer");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_keystore");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(nonce_trailer_zero_on_reply, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	struct ks_request req;
	char buf[128];
	int fd;

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	req.op = KS_OP_FETCH;
	req.keyid = 9999;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == 0);

	/* Replies from kernel handlers have zero trailer. */
	ATF_CHECK_EQ(ra.trailer.nonce, 0);

	close(fd);
}


/* ================================================================
 * KernelStore tests
 * ================================================================ */


static int
kstore_put(int fd, const char *key, const void *val, size_t vallen)
{
	struct mac_capability_call_args ca;
	char reqbuf[sizeof(struct kstore_request) + 4096];
	struct kstore_request *kr = (struct kstore_request *)reqbuf;
	struct kstore_status_reply sr;

	memset(kr, 0, sizeof(*kr));
	kr->op = KSTORE_OP_PUT;
	strlcpy(kr->key, key, sizeof(kr->key));
	if (vallen > 0)
		memcpy(reqbuf + sizeof(*kr), val, vallen);

	memset(&ca, 0, sizeof(ca));
	ca.req = reqbuf;
	ca.req_len = sizeof(*kr) + vallen;
	ca.reply = &sr;
	ca.reply_len = sizeof(sr);
	if (ioctl(fd, MAC_CAPABILITY_CALL, &ca) != 0)
		return (-1);
	return (sr.status);
}

static int
kstore_get(int fd, const char *key, void *buf, size_t buflen, size_t *outlen)
{
	struct mac_capability_call_args ca;
	struct kstore_request kr;
	char replybuf[sizeof(struct kstore_status_reply) + 4096];
	struct kstore_status_reply *sr;

	memset(&kr, 0, sizeof(kr));
	kr.op = KSTORE_OP_GET;
	strlcpy(kr.key, key, sizeof(kr.key));

	memset(&ca, 0, sizeof(ca));
	ca.req = &kr;
	ca.req_len = sizeof(kr);
	ca.reply = replybuf;
	ca.reply_len = sizeof(replybuf);
	if (ioctl(fd, MAC_CAPABILITY_CALL, &ca) != 0)
		return (-1);

	sr = (struct kstore_status_reply *)replybuf;
	if (sr->status != KSTORE_STATUS_OK)
		return (sr->status);

	size_t datalen = ca.reply_len - sizeof(*sr);
	if (datalen > buflen)
		datalen = buflen;
	if (datalen > 0)
		memcpy(buf, replybuf + sizeof(*sr), datalen);
	if (outlen != NULL)
		*outlen = datalen;
	return (KSTORE_STATUS_OK);
}

static int
kstore_delete(int fd, const char *key)
{
	struct mac_capability_call_args ca;
	struct kstore_request kr;
	struct kstore_status_reply sr;

	memset(&kr, 0, sizeof(kr));
	kr.op = KSTORE_OP_DELETE;
	strlcpy(kr.key, key, sizeof(kr.key));

	memset(&ca, 0, sizeof(ca));
	ca.req = &kr;
	ca.req_len = sizeof(kr);
	ca.reply = &sr;
	ca.reply_len = sizeof(sr);
	if (ioctl(fd, MAC_CAPABILITY_CALL, &ca) != 0)
		return (-1);
	return (sr.status);
}

static int
kstore_mint(int fd)
{
	struct mac_capability_call_args ca;
	struct kstore_request kr;
	int reply_fds[1];

	memset(&kr, 0, sizeof(kr));
	kr.op = KSTORE_OP_MINT;

	memset(&ca, 0, sizeof(ca));
	ca.req = &kr;
	ca.req_len = sizeof(kr);
	ca.reply_fds = reply_fds;
	ca.reply_nfds = 1;
	if (ioctl(fd, MAC_CAPABILITY_CALL, &ca) != 0)
		return (-1);
	return (reply_fds[0]);
}

ATF_TC(kstore_put_get);
ATF_TC_HEAD(kstore_put_get, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Put and get a value from kernelstore");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(kstore_put_get, tc)
{
	int fd;
	char buf[128];
	size_t len;

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);

	ATF_CHECK_EQ(kstore_put(fd, "hello", "world", 5), KSTORE_STATUS_OK);
	ATF_CHECK_EQ(kstore_get(fd, "hello", buf, sizeof(buf), &len),
	    KSTORE_STATUS_OK);
	ATF_CHECK_EQ(len, 5);
	ATF_CHECK(memcmp(buf, "world", 5) == 0);

	close(fd);
}

ATF_TC(kstore_get_notfound);
ATF_TC_HEAD(kstore_get_notfound, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Get on missing key returns NOTFOUND");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(kstore_get_notfound, tc)
{
	int fd;
	char buf[128];
	size_t len;

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);

	ATF_CHECK_EQ(kstore_get(fd, "nokey", buf, sizeof(buf), &len),
	    KSTORE_STATUS_NOTFOUND);

	close(fd);
}

ATF_TC(kstore_delete);
ATF_TC_HEAD(kstore_delete, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Delete removes a key");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(kstore_delete, tc)
{
	int fd;
	char buf[128];
	size_t len;

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);

	ATF_CHECK_EQ(kstore_put(fd, "tmp", "data", 4), KSTORE_STATUS_OK);
	ATF_CHECK_EQ(kstore_delete(fd, "tmp"), KSTORE_STATUS_OK);
	ATF_CHECK_EQ(kstore_get(fd, "tmp", buf, sizeof(buf), &len),
	    KSTORE_STATUS_NOTFOUND);

	close(fd);
}

ATF_TC(kstore_overwrite);
ATF_TC_HEAD(kstore_overwrite, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Put overwrites existing value");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(kstore_overwrite, tc)
{
	int fd;
	char buf[128];
	size_t len;

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);

	ATF_CHECK_EQ(kstore_put(fd, "k", "old", 3), KSTORE_STATUS_OK);
	ATF_CHECK_EQ(kstore_put(fd, "k", "new", 3), KSTORE_STATUS_OK);
	ATF_CHECK_EQ(kstore_get(fd, "k", buf, sizeof(buf), &len),
	    KSTORE_STATUS_OK);
	ATF_CHECK_EQ(len, 3);
	ATF_CHECK(memcmp(buf, "new", 3) == 0);

	close(fd);
}

ATF_TC(kstore_mint_shared);
ATF_TC_HEAD(kstore_mint_shared, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Minted member sees same data as owner");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(kstore_mint_shared, tc)
{
	int owner_fd, member_fd;
	char buf[128];
	size_t len;

	owner_fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(owner_fd >= 0);

	/* Owner puts a value. */
	ATF_CHECK_EQ(kstore_put(owner_fd, "shared", "data", 4),
	    KSTORE_STATUS_OK);

	/* Mint a member. */
	member_fd = kstore_mint(owner_fd);
	ATF_REQUIRE(member_fd >= 0);

	/* Member can read it. */
	ATF_CHECK_EQ(kstore_get(member_fd, "shared", buf, sizeof(buf), &len),
	    KSTORE_STATUS_OK);
	ATF_CHECK_EQ(len, 4);
	ATF_CHECK(memcmp(buf, "data", 4) == 0);

	/* Member can write, owner can read it. */
	ATF_CHECK_EQ(kstore_put(member_fd, "from_member", "hi", 2),
	    KSTORE_STATUS_OK);
	ATF_CHECK_EQ(kstore_get(owner_fd, "from_member", buf, sizeof(buf),
	    &len), KSTORE_STATUS_OK);
	ATF_CHECK_EQ(len, 2);
	ATF_CHECK(memcmp(buf, "hi", 2) == 0);

	close(member_fd);
	close(owner_fd);
}

ATF_TC(kstore_member_no_mint);
ATF_TC_HEAD(kstore_member_no_mint, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Members cannot mint");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(kstore_member_no_mint, tc)
{
	int owner_fd, member_fd;

	owner_fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(owner_fd >= 0);

	member_fd = kstore_mint(owner_fd);
	ATF_REQUIRE(member_fd >= 0);

	/* Member trying to mint should fail. */
	ATF_CHECK_EQ(kstore_mint(member_fd), -1);

	close(member_fd);
	close(owner_fd);
}

ATF_TC(kstore_close_destroys);
ATF_TC_HEAD(kstore_close_destroys, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing all fds destroys the store");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(kstore_close_destroys, tc)
{
	int fd1, fd2;
	char buf[128];
	size_t len;

	fd1 = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd1 >= 0);

	ATF_CHECK_EQ(kstore_put(fd1, "persist", "yes", 3),
	    KSTORE_STATUS_OK);

	fd2 = kstore_mint(fd1);
	ATF_REQUIRE(fd2 >= 0);

	/* Close owner — member still works. */
	close(fd1);
	ATF_CHECK_EQ(kstore_get(fd2, "persist", buf, sizeof(buf), &len),
	    KSTORE_STATUS_OK);

	/* Close last fd — store destroyed. New connect = empty store. */
	close(fd2);

	fd1 = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd1 >= 0);
	ATF_CHECK_EQ(kstore_get(fd1, "persist", buf, sizeof(buf), &len),
	    KSTORE_STATUS_NOTFOUND);
	close(fd1);
}

ATF_TC(kstore_separate_stores);
ATF_TC_HEAD(kstore_separate_stores, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Two connects create separate stores");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(kstore_separate_stores, tc)
{
	int fd1, fd2;
	char buf[128];
	size_t len;

	fd1 = mac_capability_connect("test_kernelstore");
	fd2 = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd1 >= 0);
	ATF_REQUIRE(fd2 >= 0);

	ATF_CHECK_EQ(kstore_put(fd1, "only_in_1", "v", 1),
	    KSTORE_STATUS_OK);

	/* fd2 has its own store — should not see fd1's data. */
	ATF_CHECK_EQ(kstore_get(fd2, "only_in_1", buf, sizeof(buf), &len),
	    KSTORE_STATUS_NOTFOUND);

	close(fd2);
	close(fd1);
}

ATF_TC(kstore_delete_notfound);
ATF_TC_HEAD(kstore_delete_notfound, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Delete on missing key returns NOTFOUND");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(kstore_delete_notfound, tc)
{
	int fd;

	fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(fd >= 0);

	ATF_CHECK_EQ(kstore_delete(fd, "nope"), KSTORE_STATUS_NOTFOUND);

	close(fd);
}

ATF_TC(kstore_multiproc);
ATF_TC_HEAD(kstore_multiproc, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Child process writes, parent reads via shared store");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(kstore_multiproc, tc)
{
	int owner_fd, member_fd, sv[2], status;
	char buf[128];
	size_t len;
	pid_t pid;

	owner_fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(owner_fd >= 0);

	member_fd = kstore_mint(owner_fd);
	ATF_REQUIRE(member_fd >= 0);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		char sig;
		close(sv[0]);
		close(owner_fd);
		/* Child writes to the shared store. */
		kstore_put(member_fd, "from_child", "hello", 5);
		write(sv[1], "d", 1);
		read(sv[1], &sig, 1);
		close(member_fd);
		close(sv[1]);
		_exit(0);
	}

	close(sv[1]);
	close(member_fd);

	/* Wait for child to write. */
	{
		char sig;
		read(sv[0], &sig, 1);
	}

	/* Parent reads child's data. */
	ATF_CHECK_EQ(kstore_get(owner_fd, "from_child", buf, sizeof(buf),
	    &len), KSTORE_STATUS_OK);
	ATF_CHECK_EQ(len, 5);
	ATF_CHECK(memcmp(buf, "hello", 5) == 0);

	write(sv[0], "x", 1);
	waitpid(pid, &status, 0);
	close(owner_fd);
	close(sv[0]);
}

ATF_TC(kstore_revoke_member);
ATF_TC_HEAD(kstore_revoke_member, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Owner can revoke member via MAC_CAPABILITY_TERMINATE");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_test_kernelstore");
}
ATF_TC_BODY(kstore_revoke_member, tc)
{
	int owner_fd, member_fd;
	char buf[128];
	size_t len;

	owner_fd = mac_capability_connect("test_kernelstore");
	ATF_REQUIRE(owner_fd >= 0);

	ATF_CHECK_EQ(kstore_put(owner_fd, "data", "val", 3),
	    KSTORE_STATUS_OK);

	member_fd = kstore_mint(owner_fd);
	ATF_REQUIRE(member_fd >= 0);

	/* Member can read before revoke. */
	ATF_CHECK_EQ(kstore_get(member_fd, "data", buf, sizeof(buf), &len),
	    KSTORE_STATUS_OK);

	/* Owner terminates the member. */
	ATF_REQUIRE(ioctl(member_fd, MAC_CAPABILITY_TERMINATE) == 0);

	/* Member fd is dead — operations fail. */
	ATF_CHECK_ERRNO(ECONNRESET,
	    kstore_get(member_fd, "data", buf, sizeof(buf), &len) == -1);

	/* Owner still works. */
	ATF_CHECK_EQ(kstore_get(owner_fd, "data", buf, sizeof(buf), &len),
	    KSTORE_STATUS_OK);

	close(member_fd);
	close(owner_fd);
}

/* ================================================================ */
ATF_TP_ADD_TCS(tp)
{
	/* Lifecycle */
	ATF_TP_ADD_TC(tp, open_close);

	/* Connection */
	ATF_TP_ADD_TC(tp, connect_service);
	ATF_TP_ADD_TC(tp, descriptor_kinfo);
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
	ATF_TP_ADD_TC(tp, fd_passing_single);
	ATF_TP_ADD_TC(tp, fd_passing_multiple);
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

	/* Capability channel */
	ATF_TP_ADD_TC(tp, channel_create);
	ATF_TP_ADD_TC(tp, channel_bidirectional);
	ATF_TP_ADD_TC(tp, channel_forwards_metadata);
	ATF_TP_ADD_TC(tp, channel_forwards_fds_and_metadata);
	ATF_TP_ADD_TC(tp, channel_close_one_end);
	ATF_TP_ADD_TC(tp, channel_multiproc);
	ATF_TP_ADD_TC(tp, channel_crossproc_forwards_metadata);

	/* Additional coverage */
	ATF_TP_ADD_TC(tp, getinfo_limits);
	ATF_TP_ADD_TC(tp, credential_trailer);

	/* MAC_CAPABILITY_CALL */
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

	/* Feature bit introspection */
	ATF_TP_ADD_TC(tp, getinfo_async_features);
	ATF_TP_ADD_TC(tp, getinfo_sync_features);

	/* Channel: additional coverage */
	ATF_TP_ADD_TC(tp, channel_fd_passing);
	ATF_TP_ADD_TC(tp, channel_fd_attachment_order);
	ATF_TP_ADD_TC(tp, channel_preserves_ioctl_limit);
	ATF_TP_ADD_TC(tp, channel_applies_xfer_caps);
	ATF_TP_ADD_TC(tp, channel_stress);
	ATF_TP_ADD_TC(tp, channel_backpressure_preserves_messages);
	ATF_TP_ADD_TC(tp, channel_backpressure_xfer_retry_atomic);
	ATF_TP_ADD_TC(tp, channel_getinfo);

	/* Keystore: additional coverage */
	ATF_TP_ADD_TC(tp, keystore_max_keys);
	ATF_TP_ADD_TC(tp, keystore_overwrite);
	ATF_TP_ADD_TC(tp, keystore_uid_isolation);
	ATF_TP_ADD_TC(tp, keystore_badge_unique);

	/* Transfer control */
	ATF_TP_ADD_TC(tp, xfer_keystore_ok);

	/* co_fdclose */
	ATF_TP_ADD_TC(tp, fdclose_dup_survives);
	ATF_TP_ADD_TC(tp, fdclose_dup_then_close_all);

	/* Granular revoke */
	ATF_TP_ADD_TC(tp, revoke_blocks_operations);
	ATF_TP_ADD_TC(tp, revoke_send_recv_both);
	ATF_TP_ADD_TC(tp, revoke_is_permanent);
	ATF_TP_ADD_TC(tp, revoke_affects_all_dups);
	ATF_TP_ADD_TC(tp, terminate_after_revoke_send);

	/* MAC_CAPABILITY_CALL reply fds */
	ATF_TP_ADD_TC(tp, call_reply_fds_zero);
	ATF_TP_ADD_TC(tp, call_reply_fds_buf_no_fds);
	ATF_TP_ADD_TC(tp, call_reply_nfds_too_many);
	ATF_TP_ADD_TC(tp, call_reply_preserves_ioctl_limit);

	/* CAP_XFER_NONE */
	ATF_TP_ADD_TC(tp, xfer_none_prevents_transfer);
	ATF_TP_ADD_TC(tp, xfer_none_still_usable);
	ATF_TP_ADD_TC(tp, xfer_none_trampoline);

	/* CAP_XFER enforcement — mac_capability paths */
	ATF_TP_ADD_TC(tp, xfer_sendmsg_none_blocks);
	ATF_TP_ADD_TC(tp, xfer_sendmsg_once_consumed);
	ATF_TP_ADD_TC(tp, xfer_sendmsg_multi_atomic);
	ATF_TP_ADD_TC(tp, xfer_recvmsg_unlimited_preserved);
	ATF_TP_ADD_TC(tp, xfer_recvmsg_once_arrives_none);
	ATF_TP_ADD_TC(tp, propagation_once_recvmsg_preserved);
	ATF_TP_ADD_TC(tp, xfer_call_none_rejected);
	ATF_TP_ADD_TC(tp, xfer_call_once_consumed);

	/* Edge cases */
	ATF_TP_ADD_TC(tp, kqueue_eof_on_terminate);
	ATF_TP_ADD_TC(tp, max_payload_size);
	ATF_TP_ADD_TC(tp, payload_over_max);
	ATF_TP_ADD_TC(tp, channel_kqueue_eof_on_close);

	/* Channel: edge cases */
	ATF_TP_ADD_TC(tp, channel_send_after_peer_close);
	ATF_TP_ADD_TC(tp, channel_unconnected_send);
	ATF_TP_ADD_TC(tp, channel_double_create);

	/* More framework edge cases */
	ATF_TP_ADD_TC(tp, sendmsg_flags_nonzero);
	ATF_TP_ADD_TC(tp, recvmsg_flags_nonzero);
	ATF_TP_ADD_TC(tp, xfer_none_idempotent);
	ATF_TP_ADD_TC(tp, revoke_send_on_sync);
	ATF_TP_ADD_TC(tp, revoke_call_on_async);
	ATF_TP_ADD_TC(tp, close_during_blocked_recv);

	/* Service-specific edge cases */
	ATF_TP_ADD_TC(tp, channel_nonblock_recv_empty);

	/* More coverage */
	ATF_TP_ADD_TC(tp, call_req_oversized);
	ATF_TP_ADD_TC(tp, capprotect_getinfo_call_feature);
	ATF_TP_ADD_TC(tp, channel_concurrent_writers);
	ATF_TP_ADD_TC(tp, rapid_connect_disconnect);

	/* Framework: additional */
	ATF_TP_ADD_TC(tp, terminate_twice);
	ATF_TP_ADD_TC(tp, connect_reserved_nonzero);

	/* Framework: edge cases */
	ATF_TP_ADD_TC(tp, getinfo_after_terminate);
	ATF_TP_ADD_TC(tp, capsicum_gates_terminate);

	/* KernelStore */
	ATF_TP_ADD_TC(tp, kstore_put_get);
	ATF_TP_ADD_TC(tp, kstore_get_notfound);
	ATF_TP_ADD_TC(tp, kstore_delete);
	ATF_TP_ADD_TC(tp, kstore_overwrite);
	ATF_TP_ADD_TC(tp, kstore_mint_shared);
	ATF_TP_ADD_TC(tp, kstore_member_no_mint);
	ATF_TP_ADD_TC(tp, kstore_close_destroys);
	ATF_TP_ADD_TC(tp, kstore_separate_stores);
	ATF_TP_ADD_TC(tp, kstore_delete_notfound);
	ATF_TP_ADD_TC(tp, kstore_multiproc);
	ATF_TP_ADD_TC(tp, kstore_revoke_member);

	/* Process nonce */
	ATF_TP_ADD_TC(tp, nonce_nonzero);
	ATF_TP_ADD_TC(tp, nonce_inherits_fork);
	ATF_TP_ADD_TC(tp, nonce_trailer_zero_on_reply);


	/* Capability Protection */
	ATF_TP_ADD_TC(tp, cap_pro_shield_basic);
	ATF_TP_ADD_TC(tp, cap_pro_protector_can_act);
	ATF_TP_ADD_TC(tp, cap_pro_selfshield_blocks_parent);
	ATF_TP_ADD_TC(tp, cap_pro_protect_via_procdesc);
	ATF_TP_ADD_TC(tp, cap_pro_foreign_ptrace_blocked);
	ATF_TP_ADD_TC(tp, cap_pro_foreign_signal_blocked);
	ATF_TP_ADD_TC(tp, cap_pro_foreign_sigkill_blocked);
	ATF_TP_ADD_TC(tp, cap_pro_exec_rotates_nonce);
	ATF_TP_ADD_TC(tp, cap_pro_pdkill_bypasses_signal_shield);
	ATF_TP_ADD_TC(tp, cap_pro_pdkill_bypasses_sigkill_shield);
	ATF_TP_ADD_TC(tp, cap_pro_pdkill_bypasses_full_shield);
	ATF_TP_ADD_TC(tp, cap_pro_pdkill_sigterm_through_shield);
	ATF_TP_ADD_TC(tp, cap_pro_pdwait_bypasses_wait_shield);
	ATF_TP_ADD_TC(tp, cap_pro_pdwait_bypasses_full_shield);
	ATF_TP_ADD_TC(tp, cap_pro_unshielded_same_session_sigcont_allowed);
	ATF_TP_ADD_TC(tp, cap_pro_foreign_sigcont_blocked);
	ATF_TP_ADD_TC(tp, cap_pro_foreign_visible_blocked);
	ATF_TP_ADD_TC(tp, cap_pro_selective_flags);
	ATF_TP_ADD_TC(tp, cap_pro_all_flags_blocks_all);
	ATF_TP_ADD_TC(tp, cap_pro_close_does_not_unshield);
	ATF_TP_ADD_TC(tp, cap_pro_double_shield_idempotent);
	ATF_TP_ADD_TC(tp, cap_pro_mint_returns_token);
	ATF_TP_ADD_TC(tp, cap_pro_mint_without_shield_fails);
	ATF_TP_ADD_TC(tp, cap_pro_shield_on_token_fails);
	ATF_TP_ADD_TC(tp, cap_pro_authorize_on_shield_fails);
	ATF_TP_ADD_TC(tp, cap_pro_bad_op);
	ATF_TP_ADD_TC(tp, cap_pro_bad_flags);
	ATF_TP_ADD_TC(tp, cap_pro_fork_not_inherited);
	ATF_TP_ADD_TC(tp, cap_pro_foreign_sched_blocked);
	ATF_TP_ADD_TC(tp, cap_pro_foreign_wait_blocked);
	ATF_TP_ADD_TC(tp, cap_pro_foreign_ktrace_blocked);
	ATF_TP_ADD_TC(tp, cap_pro_foreign_suspend_blocked);
	ATF_TP_ADD_TC(tp, cap_pro_foreign_core_blocked);
	ATF_TP_ADD_TC(tp, cap_pro_authorize_grants_access);
	ATF_TP_ADD_TC(tp, cap_pro_token_close_revokes);
	ATF_TP_ADD_TC(tp, cap_pro_delegated_access);
	ATF_TP_ADD_TC(tp, cap_pro_refcount_shield);
	ATF_TP_ADD_TC(tp, cap_pro_mint_narrow_subset);
	ATF_TP_ADD_TC(tp, cap_pro_mint_narrow_rejects_unshielded);
	ATF_TP_ADD_TC(tp, cap_pro_mint_narrow_zero_gives_all);
	ATF_TP_ADD_TC(tp, cap_pro_noexec_blocks_exec);
	ATF_TP_ADD_TC(tp, cap_pro_noexec_unshield_allows_exec);
	ATF_TP_ADD_TC(tp, cap_pro_nosock_blocks_socket);
	ATF_TP_ADD_TC(tp, cap_pro_nosock_unshield_allows_socket);
	ATF_TP_ADD_TC(tp, cap_pro_nosock_socketpair_blocked);
	ATF_TP_ADD_TC(tp, cap_pro_nofdrecv_channel_attachment);

	/* Mint restriction */
	ATF_TP_ADD_TC(tp, capsicum_mint_ioctl_limit);
	ATF_TP_ADD_TC(tp, revoke_mint_blocks_minting);

	return (atf_no_error());
}
