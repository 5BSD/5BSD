/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Host-independent adversarial protocol tests for libtzfsd.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>
#include <trustedzfs.h>
#include "tzfsd.h"

enum scenario {
	SC_SHORT,
	SC_PING_FD,
	SC_REQUEST_NOFD,
	SC_REQUEST_BADNAME,
	SC_REQUEST_TWOFDS,
	SC_REQUEST_VALID,
};

static void
send_packet(int fd, const void *buf, size_t len, const int *fds, size_t nfds)
{
	union {
		struct cmsghdr align;
		char buf[CMSG_SPACE(sizeof(int) * 2)];
	} control;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cm;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = __DECONST(void *, buf);
	iov.iov_len = len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (nfds != 0) {
		memset(&control, 0, sizeof(control));
		msg.msg_control = control.buf;
		msg.msg_controllen = CMSG_SPACE(sizeof(int) * nfds);
		cm = CMSG_FIRSTHDR(&msg);
		cm->cmsg_level = SOL_SOCKET;
		cm->cmsg_type = SCM_RIGHTS;
		cm->cmsg_len = CMSG_LEN(sizeof(int) * nfds);
		memcpy(CMSG_DATA(cm), fds, sizeof(int) * nfds);
	}
	ATF_REQUIRE_EQ((ssize_t)len, sendmsg(fd, &msg, 0));
}

static void
client(enum scenario sc, int fd)
{
	struct tzfsd_req req;
	struct tzfsd_grant grant;
	int rc, expected;

	if (sc == SC_SHORT || sc == SC_PING_FD) {
		rc = tzfsd_ping(fd);
		expected = EPROTO;
	} else {
		memset(&req, 0, sizeof(req));
		strlcpy(req.dataset, "claim", sizeof(req.dataset));
		req.rights = ZH_PROPS_READ;
		req.lifetime = TZFSD_LEASE;
		rc = tzfsd_request(fd, &req, &grant);
		if (sc == SC_REQUEST_VALID) {
			if (rc != 0 || grant.handle_fd < 0 ||
			    (fcntl(grant.handle_fd, F_GETFD) & FD_CLOEXEC) == 0 ||
			    strcmp(grant.dataset, "pool/claim") != 0)
				_exit(20);
			close(grant.handle_fd);
			_exit(0);
		}
		expected = EPROTO;
	}
	_exit(rc == -1 && errno == expected ? 0 : 21);
}

static void
run_scenario(enum scenario sc)
{
	struct tzfsd_request request;
	struct tzfsd_reply reply;
	pid_t pid;
	int sv[2], pass[2], status;
	ssize_t n;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(sv[0]);
		client(sc, sv[1]);
	}
	close(sv[1]);
	n = recv(sv[0], &request, sizeof(request), 0);
	ATF_REQUIRE_EQ((ssize_t)sizeof(request), n);
	pass[0] = open("/dev/null", O_RDONLY);
	pass[1] = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(pass[0] >= 0 && pass[1] >= 0);
	memset(&reply, 0, sizeof(reply));
	switch (sc) {
	case SC_SHORT:
		send_packet(sv[0], &reply, sizeof(reply) - 1, NULL, 0);
		break;
	case SC_PING_FD:
		send_packet(sv[0], &reply, sizeof(reply), pass, 1);
		break;
	case SC_REQUEST_NOFD:
		strlcpy(reply.dataset, "pool/claim", sizeof(reply.dataset));
		send_packet(sv[0], &reply, sizeof(reply), NULL, 0);
		break;
	case SC_REQUEST_BADNAME:
		memset(reply.dataset, 'x', sizeof(reply.dataset));
		send_packet(sv[0], &reply, sizeof(reply), pass, 1);
		break;
	case SC_REQUEST_TWOFDS:
		strlcpy(reply.dataset, "pool/claim", sizeof(reply.dataset));
		send_packet(sv[0], &reply, sizeof(reply), pass, 2);
		break;
	case SC_REQUEST_VALID:
		strlcpy(reply.dataset, "pool/claim", sizeof(reply.dataset));
		send_packet(sv[0], &reply, sizeof(reply), pass, 1);
		break;
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "client status %#x", status);
	close(pass[0]); close(pass[1]); close(sv[0]);
}

#define	PROTO_TC(name, scenario, description) \
	ATF_TC(name); \
	ATF_TC_HEAD(name, tc) { atf_tc_set_md_var(tc, "descr", description); } \
	ATF_TC_BODY(name, tc) { run_scenario(scenario); }

PROTO_TC(short_reply, SC_SHORT, "short replies are protocol errors")
PROTO_TC(unexpected_fd, SC_PING_FD, "unexpected descriptors are rejected")
PROTO_TC(missing_fd, SC_REQUEST_NOFD, "successful grants require one descriptor")
PROTO_TC(unterminated_dataset, SC_REQUEST_BADNAME, "grant names must terminate")
PROTO_TC(multiple_fds, SC_REQUEST_TWOFDS, "grants reject descriptor smuggling")
PROTO_TC(valid_cloexec_fd, SC_REQUEST_VALID, "received descriptors are CLOEXEC")

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, short_reply);
	ATF_TP_ADD_TC(tp, unexpected_fd);
	ATF_TP_ADD_TC(tp, missing_fd);
	ATF_TP_ADD_TC(tp, unterminated_dataset);
	ATF_TP_ADD_TC(tp, multiple_fds);
	ATF_TP_ADD_TC(tp, valid_cloexec_fd);
	return (atf_no_error());
}
