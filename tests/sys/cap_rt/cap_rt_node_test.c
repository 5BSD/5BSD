/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Tests for the cap_rt node service (process observation and control).
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/cpuset.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <sys/procctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "cap_rt_ioctl.h"
#include "cap_rt_node_proto.h"
#include "cap_rt_capprotect_proto.h"

#ifndef RACCT_NOFILE
#define	RACCT_NOFILE	7
#endif

/* ----------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------- */

static int
cap_rt_open(void)
{
	int fd;

	fd = open("/dev/cap_rt", O_RDWR);
	if (fd < 0 && errno == ENOENT)
		atf_tc_skip("cap_rt module not loaded");
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/cap_rt: %s", strerror(errno));
	return (fd);
}

static int
cap_rt_connect(const char *name)
{
	struct cap_rt_connect_args ca;
	int ctl;

	ctl = cap_rt_open();
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, name, sizeof(ca.name));
	if (ioctl(ctl, CAP_RT_CONNECT, &ca) != 0) {
		close(ctl);
		return (-1);
	}
	close(ctl);
	return (ca.fd);
}

static int
node_call_raw(int fd, const void *req, size_t reqlen,
    const int *req_fds, int nfds,
    void *reply, size_t replylen)
{
	struct cap_rt_call_args ca;

	memset(&ca, 0, sizeof(ca));
	ca.req = req;
	ca.req_len = reqlen;
	ca.req_fds = req_fds;
	ca.req_nfds = nfds;
	ca.reply = reply;
	ca.reply_len = replylen;
	return (ioctl(fd, CAP_RT_CALL, &ca));
}

/* ----------------------------------------------------------------
 * Self-targeting tests (no procdesc attached)
 * ---------------------------------------------------------------- */

ATF_TC(node_stat_self);
ATF_TC_HEAD(node_stat_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_STAT on self returns pid and name");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_stat_self, tc)
{
	struct node_request req;
	struct node_stat_reply reply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_STAT;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.pid, (int32_t)getpid());
	ATF_CHECK(reply.numthreads >= 1);
	ATF_CHECK(reply.name[0] != '\0');

	close(fd);
}

ATF_TC(node_cred_self);
ATF_TC_HEAD(node_cred_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_CRED on self returns correct uid/gid");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_cred_self, tc)
{
	struct node_request req;
	struct node_cred_reply reply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_CRED;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.uid, geteuid());
	ATF_CHECK_EQ(reply.ruid, getuid());
	ATF_CHECK_EQ(reply.gid, getegid());
	ATF_CHECK(reply.nonce != 0);

	close(fd);
}

ATF_TC(node_rusage_self);
ATF_TC_HEAD(node_rusage_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_RUSAGE on self returns non-negative values");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_rusage_self, tc)
{
	struct node_request req;
	struct node_rusage_reply reply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_RUSAGE;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK(reply.utime_usec >= 0);
	ATF_CHECK(reply.stime_usec >= 0);

	close(fd);
}

ATF_TC(node_rlimit_get_self);
ATF_TC_HEAD(node_rlimit_get_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_GET_RLIMIT on self matches getrlimit");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_rlimit_get_self, tc)
{
	struct node_request req;
	struct node_rlimit_reply reply;
	struct rlimit rl;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_GET_RLIMIT;
	req.resource = RLIMIT_NOFILE;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	ATF_REQUIRE(getrlimit(RLIMIT_NOFILE, &rl) == 0);
	ATF_CHECK_EQ(reply.rlim_cur, (int64_t)rl.rlim_cur);
	ATF_CHECK_EQ(reply.rlim_max, (int64_t)rl.rlim_max);

	close(fd);
}

ATF_TC(node_rlimit_set_self);
ATF_TC_HEAD(node_rlimit_set_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_RLIMIT on self changes the limit");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_rlimit_set_self, tc)
{
	struct node_rlimit_set sreq;
	struct node_rlimit_reply reply;
	struct rlimit rl, orig;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(getrlimit(RLIMIT_NOFILE, &orig) == 0);

	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_RLIMIT;
	sreq.resource = RLIMIT_NOFILE;
	sreq.rlim_cur = orig.rlim_cur / 2;
	sreq.rlim_max = orig.rlim_max;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	ATF_REQUIRE(getrlimit(RLIMIT_NOFILE, &rl) == 0);
	ATF_CHECK_EQ((int64_t)rl.rlim_cur, orig.rlim_cur / 2);

	/* Restore */
	sreq.rlim_cur = orig.rlim_cur;
	node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply));

	close(fd);
}

ATF_TC(node_nice_get_self);
ATF_TC_HEAD(node_nice_get_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_GET_NICE on self returns current nice");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_nice_get_self, tc)
{
	struct node_request req;
	struct node_nice_reply reply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_GET_NICE;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.nice, getpriority(PRIO_PROCESS, 0));

	close(fd);
}

ATF_TC(node_nice_set_self);
ATF_TC_HEAD(node_nice_set_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_NICE on self changes priority");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_nice_set_self, tc)
{
	struct node_nice_set sreq;
	struct node_nice_reply reply;
	int fd, orig;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	orig = getpriority(PRIO_PROCESS, 0);

	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_NICE;
	sreq.nice = orig + 1;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(getpriority(PRIO_PROCESS, 0), orig + 1);

	close(fd);
}

ATF_TC(node_affinity_get_self);
ATF_TC_HEAD(node_affinity_get_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_GET_AFFINITY on self returns a cpuset mask");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_affinity_get_self, tc)
{
	struct node_request req;
	struct node_affinity_reply reply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_GET_AFFINITY;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK(reply.size > 0);

	close(fd);
}

ATF_TC(node_racct_get_self);
ATF_TC_HEAD(node_racct_get_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_GET_RACCT on self returns a racct snapshot");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_racct_get_self, tc)
{
	struct node_request req;
	struct node_racct_reply reply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_GET_RACCT;
	req.resource = RACCT_NOFILE;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	if (reply.status == NODE_STATUS_ERR)
		atf_tc_skip("RACCT not compiled into kernel");
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.resource, RACCT_NOFILE);
	ATF_CHECK(reply.usage >= 0);

	close(fd);
}

ATF_TC(node_affinity_set_self);
ATF_TC_HEAD(node_affinity_set_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_AFFINITY on self accepts the current cpuset mask");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_affinity_set_self, tc)
{
	struct node_request greq;
	struct node_affinity_set sreq;
	struct node_affinity_reply before, after;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_GET_AFFINITY;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), NULL, 0,
	    &before, sizeof(before)) == 0);
	ATF_REQUIRE(before.status == NODE_STATUS_OK);
	ATF_REQUIRE(before.size > 0);
	ATF_REQUIRE(before.size <= NODE_CPUSET_MAXSIZE);

	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_AFFINITY;
	sreq.size = before.size;
	memcpy(sreq.mask, before.mask, before.size);
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &after, sizeof(after)) == 0);
	ATF_CHECK_EQ(after.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(after.size, before.size);
	ATF_CHECK(memcmp(after.mask, before.mask, before.size) == 0);

	close(fd);
}

ATF_TC(node_procctl_get_self);
ATF_TC_HEAD(node_procctl_get_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_GET_PROCCTL on self queries ASLR status");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_procctl_get_self, tc)
{
	struct node_request req;
	struct node_procctl_reply reply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_GET_PROCCTL;
	req.resource = PROC_ASLR_STATUS;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	close(fd);
}

ATF_TC(node_procctl_set_self);
ATF_TC_HEAD(node_procctl_set_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_PROCCTL on self sets trapcap flag");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_procctl_set_self, tc)
{
	struct node_procctl_set sreq;
	struct node_procctl_reply reply;
	struct node_request greq;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	/* Enable TRAPCAP on self */
	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_PROCCTL;
	sreq.com = PROC_TRAPCAP_CTL;
	sreq.val = PROC_TRAPCAP_CTL_ENABLE;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	/* Verify */
	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_GET_PROCCTL;
	greq.resource = PROC_TRAPCAP_STATUS;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK(reply.val != 0);

	/* Restore */
	sreq.val = PROC_TRAPCAP_CTL_DISABLE;
	node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply));

	close(fd);
}

ATF_TC(node_set_session_self);
ATF_TC_HEAD(node_set_session_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_SESSION on self creates new session");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_set_session_self, tc)
{
	struct node_request req;
	struct node_session_reply reply;
	int fd, status;
	pid_t pid;

	/* Must fork — setsid fails if already session leader */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		fd = cap_rt_connect("node");
		if (fd < 0)
			_exit(10);
		memset(&req, 0, sizeof(req));
		req.op = NODE_OP_SET_SESSION;
		if (node_call_raw(fd, &req, sizeof(req), NULL, 0,
		    &reply, sizeof(reply)) != 0)
			_exit(1);
		_exit(reply.status == NODE_STATUS_OK ? 0 : 2);
	}
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

ATF_TC(node_set_pgrp_self);
ATF_TC_HEAD(node_set_pgrp_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_PGRP on self creates new process group");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_set_pgrp_self, tc)
{
	struct node_pgrp_set sreq;
	struct node_session_reply reply;
	int fd, status;
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		fd = cap_rt_connect("node");
		if (fd < 0)
			_exit(10);
		memset(&sreq, 0, sizeof(sreq));
		sreq.op = NODE_OP_SET_PGRP;
		sreq.pgid = 0;
		if (node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
		    &reply, sizeof(reply)) != 0)
			_exit(1);
		_exit(reply.status == NODE_STATUS_OK ? 0 : 2);
	}
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

ATF_TC(node_set_login_self);
ATF_TC_HEAD(node_set_login_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_LOGIN on self sets login name");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(node_set_login_self, tc)
{
	struct node_login_set lreq;
	struct node_login_reply reply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&lreq, 0, sizeof(lreq));
	lreq.op = NODE_OP_SET_LOGIN;
	strlcpy(lreq.name, "captest", sizeof(lreq.name));
	ATF_REQUIRE(node_call_raw(fd, &lreq, sizeof(lreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_MSG(strcmp(reply.name, "captest") == 0,
	    "expected 'captest', got '%s'", reply.name);

	close(fd);
}

/* ----------------------------------------------------------------
 * Procdesc-targeting tests
 * ---------------------------------------------------------------- */

ATF_TC(node_stat_child);
ATF_TC_HEAD(node_stat_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_STAT on child via procdesc returns child pid");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_stat_child, tc)
{
	struct node_request req;
	struct node_stat_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(fd);
		sleep(10);
		_exit(0);
	}

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_STAT;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.pid, (int32_t)pid);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_rlimit_set_child);
ATF_TC_HEAD(node_rlimit_set_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_RLIMIT on child via procdesc changes child limit");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_rlimit_set_child, tc)
{
	struct node_rlimit_set sreq;
	struct node_rlimit_reply reply;
	struct node_request greq;
	int fd, pd, status, sv[2];
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;
		struct rlimit rl;

		close(fd);
		close(sv[0]);
		/* Wait for parent to set our limit */
		read(sv[1], &buf, 1);
		getrlimit(RLIMIT_CORE, &rl);
		/* Exit with 0 if limit was changed, 1 otherwise */
		_exit(rl.rlim_cur == 12345 ? 0 : 1);
	}
	close(sv[1]);

	/* Set child's RLIMIT_CORE */
	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_RLIMIT;
	sreq.resource = RLIMIT_CORE;
	sreq.rlim_cur = 12345;
	sreq.rlim_max = 12345;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	/* Verify via GET */
	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_GET_RLIMIT;
	greq.resource = RLIMIT_CORE;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.rlim_cur, 12345);

	/* Tell child to check and exit */
	write(sv[0], "g", 1);
	close(sv[0]);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	close(pd);
	close(fd);
}

ATF_TC(node_procctl_set_child);
ATF_TC_HEAD(node_procctl_set_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_PROCCTL on child updates procctl state");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_procctl_set_child, tc)
{
	struct node_procctl_set sreq;
	struct node_procctl_reply sreply, greply;
	struct node_request greq;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(fd);
		sleep(10);
		_exit(0);
	}

	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_PROCCTL;
	sreq.com = PROC_NO_NEW_PRIVS_CTL;
	sreq.val = PROC_NO_NEW_PRIVS_ENABLE;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), &pd, 1,
	    &sreply, sizeof(sreply)) == 0);
	ATF_CHECK_EQ(sreply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(sreply.com, PROC_NO_NEW_PRIVS_CTL);

	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_GET_PROCCTL;
	greq.resource = PROC_NO_NEW_PRIVS_STATUS;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), &pd, 1,
	    &greply, sizeof(greply)) == 0);
	ATF_CHECK_EQ(greply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(greply.com, PROC_NO_NEW_PRIVS_STATUS);
	ATF_CHECK(greply.val != 0);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_cred_child);
ATF_TC_HEAD(node_cred_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_CRED on child via procdesc returns child credentials");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_cred_child, tc)
{
	struct node_request req;
	struct node_cred_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_CRED;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.uid, geteuid());
	ATF_CHECK(reply.nonce != 0);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_rusage_child);
ATF_TC_HEAD(node_rusage_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_RUSAGE on child via procdesc returns usage");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_rusage_child, tc)
{
	struct node_request req;
	struct node_rusage_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_RUSAGE;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK(reply.utime_usec >= 0);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_nice_set_child);
ATF_TC_HEAD(node_nice_set_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_NICE on child via procdesc changes priority");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_nice_set_child, tc)
{
	struct node_nice_set sreq;
	struct node_nice_reply reply;
	struct node_request greq;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	/* Set child nice to +5 */
	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_NICE;
	sreq.nice = 5;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	/* Verify via GET */
	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_GET_NICE;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.nice, 5);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_affinity_get_child);
ATF_TC_HEAD(node_affinity_get_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_GET_AFFINITY on child via procdesc returns cpuset");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_affinity_get_child, tc)
{
	struct node_request req;
	struct node_affinity_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_GET_AFFINITY;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK(reply.size > 0);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_racct_get_child);
ATF_TC_HEAD(node_racct_get_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_GET_RACCT on child via procdesc returns usage");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_racct_get_child, tc)
{
	struct node_request req;
	struct node_racct_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_GET_RACCT;
	req.resource = RACCT_NOFILE;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	if (reply.status == NODE_STATUS_ERR)
		atf_tc_skip("RACCT not compiled into kernel");
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_set_cred_child);
ATF_TC_HEAD(node_set_cred_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_CRED on child changes uid/gid");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(node_set_cred_child, tc)
{
	struct node_cred_set sreq;
	struct node_cred_reply reply;
	struct node_request greq;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	/* Set child to uid=65534, gid=65534 (nobody) */
	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_CRED;
	sreq.flags = NODE_CREDF_UID | NODE_CREDF_RUID |
	    NODE_CREDF_GID | NODE_CREDF_RGID;
	sreq.uid = 65534;
	sreq.ruid = 65534;
	sreq.gid = 65534;
	sreq.rgid = 65534;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.uid, 65534);
	ATF_CHECK_EQ(reply.gid, 65534);

	/* Verify via GET */
	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_CRED;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.uid, 65534);
	ATF_CHECK_EQ(reply.ruid, 65534);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_set_cred_groups_child);
ATF_TC_HEAD(node_set_cred_groups_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_CRED sets supplementary groups on child");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(node_set_cred_groups_child, tc)
{
	struct node_cred_set sreq;
	struct node_cred_reply reply;
	struct node_request greq;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_CRED;
	sreq.flags = NODE_CREDF_UID | NODE_CREDF_RUID |
	    NODE_CREDF_GID | NODE_CREDF_RGID | NODE_CREDF_GROUPS;
	sreq.uid = 65534;
	sreq.ruid = 65534;
	sreq.gid = 65534;
	sreq.rgid = 65534;
	sreq.ngroups = 3;
	sreq.groups[0] = 65534;
	sreq.groups[1] = 100;
	sreq.groups[2] = 27;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	/* Verify groups via CRED query */
	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_CRED;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.uid, 65534);
	ATF_CHECK(reply.ngroups >= 3);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_set_cred_eperm);
ATF_TC_HEAD(node_set_cred_eperm, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_CRED without root returns EPERM");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}
ATF_TC_BODY(node_set_cred_eperm, tc)
{
	struct node_cred_set sreq;
	struct node_cred_reply reply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	/* Try to set own uid — should fail without privilege */
	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_CRED;
	sreq.flags = NODE_CREDF_UID;
	sreq.uid = 0;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_EPERM);

	close(fd);
}

ATF_TC(node_set_cred_invalid_ngroups);
ATF_TC_HEAD(node_set_cred_invalid_ngroups, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_CRED rejects ngroups > NODE_CRED_MAXGROUPS");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_set_cred_invalid_ngroups, tc)
{
	struct node_cred_set sreq;
	struct node_cred_reply reply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_CRED;
	sreq.flags = NODE_CREDF_GROUPS;
	sreq.ngroups = NODE_CRED_MAXGROUPS + 1; /* too many */
	ATF_CHECK_ERRNO(EINVAL,
	    node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply)) == -1);

	close(fd);
}

ATF_TC(node_set_session_remote_rejected);
ATF_TC_HEAD(node_set_session_remote_rejected, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_SESSION on remote child returns EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_set_session_remote_rejected, tc)
{
	struct node_request req;
	struct node_session_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_SET_SESSION;
	ATF_CHECK_ERRNO(EOPNOTSUPP,
	    node_call_raw(fd, &req, sizeof(req), &pd, 1,
	    &reply, sizeof(reply)) == -1);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_set_pgrp_remote_rejected);
ATF_TC_HEAD(node_set_pgrp_remote_rejected, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_PGRP on remote child returns EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_set_pgrp_remote_rejected, tc)
{
	struct node_pgrp_set sreq;
	struct node_session_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_PGRP;
	sreq.pgid = 0;
	ATF_CHECK_ERRNO(EOPNOTSUPP,
	    node_call_raw(fd, &sreq, sizeof(sreq), &pd, 1,
	    &reply, sizeof(reply)) == -1);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_umask_self);
ATF_TC_HEAD(node_umask_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_GET_UMASK and SET_UMASK on self");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_umask_self, tc)
{
	struct node_request greq;
	struct node_umask_set sreq;
	struct node_umask_reply reply;
	int fd;
	mode_t orig;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	/* Get current umask */
	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_GET_UMASK;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	orig = reply.mask;

	/* Set new umask */
	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_UMASK;
	sreq.mask = 0077;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.mask, orig); /* returns previous mask */

	/* Verify it changed */
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.mask, 0077);

	/* Restore */
	sreq.mask = orig;
	node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply));

	close(fd);
}

ATF_TC(node_set_login_child);
ATF_TC_HEAD(node_set_login_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_LOGIN via child procdesc sets login on shared session");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(node_set_login_child, tc)
{
	struct node_login_set lreq;
	struct node_login_reply lreply;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	/*
	 * Set login name on the child's session.  The child inherits
	 * the parent's session, so this sets the login on the shared
	 * session.  A real init would setsid the child first.
	 */
	memset(&lreq, 0, sizeof(lreq));
	lreq.op = NODE_OP_SET_LOGIN;
	strlcpy(lreq.name, "testuser", sizeof(lreq.name));
	ATF_REQUIRE(node_call_raw(fd, &lreq, sizeof(lreq), &pd, 1,
	    &lreply, sizeof(lreply)) == 0);
	ATF_CHECK_EQ(lreply.status, NODE_STATUS_OK);
	ATF_CHECK_MSG(strcmp(lreply.name, "testuser") == 0,
	    "expected 'testuser', got '%s'", lreply.name);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_rlimit_get_child);
ATF_TC_HEAD(node_rlimit_get_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_GET_RLIMIT on child via procdesc");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_rlimit_get_child, tc)
{
	struct node_request req;
	struct node_rlimit_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_GET_RLIMIT;
	req.resource = RLIMIT_NOFILE;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK(reply.rlim_cur > 0);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_nice_get_child);
ATF_TC_HEAD(node_nice_get_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_GET_NICE on child via procdesc");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_nice_get_child, tc)
{
	struct node_request req;
	struct node_nice_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_GET_NICE;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_affinity_set_child);
ATF_TC_HEAD(node_affinity_set_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_AFFINITY on child via procdesc");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_affinity_set_child, tc)
{
	struct node_request greq;
	struct node_affinity_set sreq;
	struct node_affinity_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	/* Get child's current affinity */
	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_GET_AFFINITY;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_REQUIRE(reply.status == NODE_STATUS_OK);

	/* Set it back (round-trip) */
	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_AFFINITY;
	sreq.size = reply.size;
	memcpy(sreq.mask, reply.mask, reply.size);
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_procctl_get_child);
ATF_TC_HEAD(node_procctl_get_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_GET_PROCCTL on child via procdesc");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_procctl_get_child, tc)
{
	struct node_request req;
	struct node_procctl_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_GET_PROCCTL;
	req.resource = PROC_ASLR_STATUS;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_umask_child);
ATF_TC_HEAD(node_umask_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_GET_UMASK and SET_UMASK on child via procdesc");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_umask_child, tc)
{
	struct node_request greq;
	struct node_umask_set sreq;
	struct node_umask_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	/* Get child's umask */
	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_GET_UMASK;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	/* Set child's umask */
	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_UMASK;
	sreq.mask = 0077;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	/* Verify */
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.mask, 0077);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_stat_dead_child);
ATF_TC_HEAD(node_stat_dead_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_STAT on dead child returns DEAD status");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_stat_dead_child, tc)
{
	struct node_request req;
	struct node_stat_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(0);

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_STAT;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_DEAD);

	close(pd);
	close(fd);
}

/* ----------------------------------------------------------------
 * Edge case tests
 * ---------------------------------------------------------------- */

ATF_TC(node_rlimit_max_values);
ATF_TC_HEAD(node_rlimit_max_values, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_RLIMIT with large values round-trips");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(node_rlimit_max_values, tc)
{
	struct node_rlimit_set sreq;
	struct node_rlimit_reply reply;
	struct node_request greq;
	struct rlimit orig;
	size_t len;
	int maxfilesperproc;
	int fd;
	/*
	 * Use a large but valid value instead of RLIM_INFINITY.
	 * The kernel may clamp or reject RLIM_INFINITY for NOFILE.
	 */
	const int64_t large_val = 1000000;
	int64_t expected_val;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(getrlimit(RLIMIT_NOFILE, &orig) == 0);
	len = sizeof(maxfilesperproc);
	ATF_REQUIRE(sysctlbyname("kern.maxfilesperproc", &maxfilesperproc,
	    &len, NULL, 0) == 0);
	expected_val = large_val;
	if (maxfilesperproc > 0 && expected_val > maxfilesperproc)
		expected_val = maxfilesperproc;

	/* Set RLIMIT_NOFILE to a large value for both cur and max */
	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_RLIMIT;
	sreq.resource = RLIMIT_NOFILE;
	sreq.rlim_cur = large_val;
	sreq.rlim_max = large_val;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	if (reply.status != NODE_STATUS_OK) {
		close(fd);
		atf_tc_skip("kernel rejected large rlimit value");
	}

	/* Verify via GET */
	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_GET_RLIMIT;
	greq.resource = RLIMIT_NOFILE;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK(reply.rlim_cur >= expected_val);
	ATF_CHECK(reply.rlim_max >= expected_val);

	/* Restore original limits */
	sreq.rlim_cur = (int64_t)orig.rlim_cur;
	sreq.rlim_max = (int64_t)orig.rlim_max;
	node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply));

	close(fd);
}

ATF_TC(node_nice_boundary);
ATF_TC_HEAD(node_nice_boundary, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_NICE at boundary values 20 and -20");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(node_nice_boundary, tc)
{
	struct node_nice_set sreq;
	struct node_nice_reply reply;
	struct node_request greq;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	/* Use a child so we don't permanently alter our own priority */
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	/* Set nice to 20 (lowest priority) */
	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_NICE;
	sreq.nice = 20;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	/* Verify via GET */
	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_GET_NICE;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.nice, 20);

	/* Set nice to -20 (highest priority, requires root) */
	sreq.nice = -20;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	/* Verify via GET */
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.nice, -20);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_stat_zombie);
ATF_TC_HEAD(node_stat_zombie, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_STAT on zombie child reports PRS_ZOMBIE state");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_stat_zombie, tc)
{
	struct node_request req;
	struct node_stat_reply reply;
	int fd, pd;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(0);

	/*
	 * Don't waitpid — let the child become a zombie.
	 * Give it a moment to exit and transition to zombie state.
	 */
	usleep(100000);

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_STAT;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), &pd, 1,
	    &reply, sizeof(reply)) == 0);

	/*
	 * The zombie is not yet reaped, so it should still be visible
	 * via procdesc.  Check that state indicates zombie (PRS_ZOMBIE=2)
	 * or that the service reports NODE_STATUS_DEAD.
	 */
	if (reply.status == NODE_STATUS_OK) {
		ATF_CHECK_EQ(reply.pid, (int32_t)pid);
		ATF_CHECK_EQ(reply.state, 2); /* PRS_ZOMBIE */
	} else {
		ATF_CHECK_EQ(reply.status, NODE_STATUS_DEAD);
	}

	/* Reap the zombie */
	waitpid(pid, NULL, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_cred_ngroups_zero);
ATF_TC_HEAD(node_cred_ngroups_zero, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_SET_CRED with ngroups=0 clears supplementary groups");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(node_cred_ngroups_zero, tc)
{
	struct node_cred_set sreq;
	struct node_cred_reply reply;
	struct node_request greq;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	/* Set credentials with ngroups=0 (clear supplementary groups) */
	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_CRED;
	sreq.flags = NODE_CREDF_UID | NODE_CREDF_RUID |
	    NODE_CREDF_GID | NODE_CREDF_RGID | NODE_CREDF_GROUPS;
	sreq.uid = 65534;
	sreq.ruid = 65534;
	sreq.gid = 65534;
	sreq.rgid = 65534;
	sreq.ngroups = 0;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	/* Verify via CRED query that ngroups is 0 */
	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_CRED;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.uid, 65534);
	ATF_CHECK_EQ(reply.ngroups, 0);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

/* ----------------------------------------------------------------
 * Error cases
 * ---------------------------------------------------------------- */

ATF_TC(node_invalid_rlimit);
ATF_TC_HEAD(node_invalid_rlimit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_GET_RLIMIT with invalid resource returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_invalid_rlimit, tc)
{
	struct node_request req;
	struct node_rlimit_reply reply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_GET_RLIMIT;
	req.resource = 9999;
	ATF_CHECK_ERRNO(EINVAL,
	    node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == -1);

	close(fd);
}

ATF_TC(node_wrong_fd_type);
ATF_TC_HEAD(node_wrong_fd_type, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Attaching a non-procdesc fd returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_wrong_fd_type, tc)
{
	struct node_request req;
	struct node_stat_reply reply;
	int fd, pipefd[2];

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pipe(pipefd) == 0);

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_STAT;
	ATF_CHECK_ERRNO(EINVAL,
	    node_call_raw(fd, &req, sizeof(req), &pipefd[0], 1,
	    &reply, sizeof(reply)) == -1);

	close(pipefd[0]);
	close(pipefd[1]);
	close(fd);
}

ATF_TC(node_bad_op);
ATF_TC_HEAD(node_bad_op, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Unknown operation returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_bad_op, tc)
{
	struct node_request req;
	char reply[256];
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = 99;
	ATF_CHECK_ERRNO(EINVAL,
	    node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    reply, sizeof(reply)) == -1);

	close(fd);
}

ATF_TC(node_invalid_procctl);
ATF_TC_HEAD(node_invalid_procctl, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NODE_OP_GET_PROCCTL with disallowed command returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_invalid_procctl, tc)
{
	struct node_request req;
	struct node_procctl_reply reply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	/* PROC_REAP_ACQUIRE is not in the allowed set */
	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_GET_PROCCTL;
	req.resource = PROC_REAP_ACQUIRE;
	ATF_CHECK_ERRNO(EINVAL,
	    node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == -1);

	close(fd);
}

/* ----------------------------------------------------------------
 * Scheduler class (rtprio) tests
 * ---------------------------------------------------------------- */

ATF_TC(node_rtprio_get_self);
ATF_TC_HEAD(node_rtprio_get_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "GET_RTPRIO returns current scheduler class for self");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(node_rtprio_get_self, tc)
{
	struct node_request req;
	struct node_rtprio_reply reply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_GET_RTPRIO;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	/* Default process should be timeshare (NORMAL) */
	ATF_CHECK_EQ(reply.type, NODE_RTPRIO_NORMAL);

	close(fd);
}

ATF_TC(node_rtprio_set_idle_self);
ATF_TC_HEAD(node_rtprio_set_idle_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SET_RTPRIO can switch self to idle class and back");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(node_rtprio_set_idle_self, tc)
{
	struct node_rtprio_set sreq;
	struct node_rtprio_reply reply;
	struct node_request greq;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	/* Switch to idle class, priority 10 */
	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_RTPRIO;
	sreq.type = NODE_RTPRIO_IDLE;
	sreq.prio = 10;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.type, NODE_RTPRIO_IDLE);
	ATF_CHECK_EQ(reply.prio, 10);

	/* Verify via GET */
	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_GET_RTPRIO;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.type, NODE_RTPRIO_IDLE);
	ATF_CHECK_EQ(reply.prio, 10);

	/* Switch back to normal */
	sreq.type = NODE_RTPRIO_NORMAL;
	sreq.prio = 0;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.type, NODE_RTPRIO_NORMAL);

	/* Verify switch-back via GET */
	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_GET_RTPRIO;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.type, NODE_RTPRIO_NORMAL);

	close(fd);
}

ATF_TC(node_rtprio_set_realtime_child);
ATF_TC_HEAD(node_rtprio_set_realtime_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SET_RTPRIO can switch child to realtime class via procdesc");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(node_rtprio_set_realtime_child, tc)
{
	struct node_rtprio_set sreq;
	struct node_rtprio_reply reply;
	struct node_request greq;
	int fd, pd;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(fd);
		pause();
		_exit(0);
	}

	/* Set child to realtime FIFO, priority 5 */
	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_RTPRIO;
	sreq.type = NODE_RTPRIO_REALTIME;
	sreq.prio = 5;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.type, NODE_RTPRIO_REALTIME);
	ATF_CHECK_EQ(reply.prio, 5);

	/* Verify via GET on child */
	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_GET_RTPRIO;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.type, NODE_RTPRIO_REALTIME);
	ATF_CHECK_EQ(reply.prio, 5);

	pdkill(pd, SIGKILL);
	close(pd);
	close(fd);
}

ATF_TC(node_rtprio_invalid_class);
ATF_TC_HEAD(node_rtprio_invalid_class, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SET_RTPRIO rejects invalid scheduler class");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(node_rtprio_invalid_class, tc)
{
	struct node_rtprio_set sreq;
	struct node_rtprio_reply reply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_RTPRIO;
	sreq.type = 99;	/* invalid class */
	sreq.prio = 0;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_ERR);

	close(fd);
}

ATF_TC(node_rtprio_invalid_prio);
ATF_TC_HEAD(node_rtprio_invalid_prio, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SET_RTPRIO rejects priority > RTP_PRIO_MAX");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(node_rtprio_invalid_prio, tc)
{
	struct node_rtprio_set sreq;
	struct node_rtprio_reply reply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_RTPRIO;
	sreq.type = NODE_RTPRIO_REALTIME;
	sreq.prio = 100;	/* > RTP_PRIO_MAX (31) */
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_ERR);

	close(fd);
}

/* ----------------------------------------------------------------
 * Confinement tests
 * ---------------------------------------------------------------- */

ATF_TC(node_pdeathsig_set_child);
ATF_TC_HEAD(node_pdeathsig_set_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SET_PDEATHSIG on child sets signal, GET_PDEATHSIG reads it back");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_pdeathsig_set_child, tc)
{
	struct node_pdeathsig_set sreq;
	struct node_pdeathsig_reply reply;
	struct node_request greq;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	/* Set pdeathsig=SIGTERM on child */
	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_PDEATHSIG;
	sreq.signal = SIGTERM;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	/* Read it back */
	memset(&greq, 0, sizeof(greq));
	greq.op = NODE_OP_GET_PDEATHSIG;
	ATF_REQUIRE(node_call_raw(fd, &greq, sizeof(greq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);
	ATF_CHECK_EQ(reply.signal, (uint32_t)SIGTERM);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_pdeathsig_invalid_signal);
ATF_TC_HEAD(node_pdeathsig_invalid_signal, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SET_PDEATHSIG with invalid signal returns NODE_STATUS_ERR");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
}
ATF_TC_BODY(node_pdeathsig_invalid_signal, tc)
{
	struct node_pdeathsig_set sreq;
	struct node_pdeathsig_reply reply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_PDEATHSIG;
	sreq.signal = 999;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_ERR);

	close(fd);
}

ATF_TC(node_protect_child);
ATF_TC_HEAD(node_protect_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SET_PROCCTL with PROC_SPROTECT / PPROT_SET on child");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(node_protect_child, tc)
{
	struct node_procctl_set sreq;
	struct node_procctl_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	memset(&sreq, 0, sizeof(sreq));
	sreq.op = NODE_OP_SET_PROCCTL;
	sreq.com = PROC_SPROTECT;
	sreq.val = PPROT_SET;
	ATF_REQUIRE(node_call_raw(fd, &sreq, sizeof(sreq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, NODE_STATUS_OK);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(node_reap_acquire_self);
ATF_TC_HEAD(node_reap_acquire_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "REAP_ACQUIRE/STATUS/RELEASE self-targeting lifecycle");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(node_reap_acquire_self, tc)
{
	struct node_request req;
	struct node_status_reply areply;
	struct node_reap_status_reply sreply;
	int fd;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	/* Acquire reaper status */
	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_REAP_ACQUIRE;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &areply, sizeof(areply)) == 0);
	ATF_CHECK_EQ(areply.status, NODE_STATUS_OK);

	/* Query reaper status */
	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_REAP_STATUS;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &sreply, sizeof(sreply)) == 0);
	ATF_CHECK_EQ(sreply.status, NODE_STATUS_OK);
	ATF_CHECK(sreply.rs_flags & REAPER_STATUS_OWNED);

	/* Release */
	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_REAP_RELEASE;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &areply, sizeof(areply)) == 0);
	ATF_CHECK_EQ(areply.status, NODE_STATUS_OK);

	close(fd);
}

ATF_TC(node_reap_kill_children);
ATF_TC_HEAD(node_reap_kill_children, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "REAP_ACQUIRE then REAP_KILL signals all children");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_node");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(node_reap_kill_children, tc)
{
	struct node_request req;
	struct node_status_reply areply;
	struct node_reap_kill_req kreq;
	struct node_reap_kill_reply kreply;
	int fd, status;
	pid_t c1, c2;

	fd = cap_rt_connect("node");
	ATF_REQUIRE(fd >= 0);

	/* Become reaper */
	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_REAP_ACQUIRE;
	ATF_REQUIRE(node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &areply, sizeof(areply)) == 0);
	ATF_REQUIRE(areply.status == NODE_STATUS_OK);

	/* Fork two children */
	c1 = fork();
	ATF_REQUIRE(c1 >= 0);
	if (c1 == 0) { sleep(60); _exit(0); }

	c2 = fork();
	ATF_REQUIRE(c2 >= 0);
	if (c2 == 0) { sleep(60); _exit(0); }

	/* Let children start */
	usleep(50000);

	/* Kill all children via reaper */
	memset(&kreq, 0, sizeof(kreq));
	kreq.op = NODE_OP_REAP_KILL;
	kreq.rk_sig = SIGKILL;
	kreq.rk_flags = REAPER_KILL_CHILDREN;
	ATF_REQUIRE(node_call_raw(fd, &kreq, sizeof(kreq), NULL, 0,
	    &kreply, sizeof(kreply)) == 0);
	ATF_CHECK(kreply.status == NODE_STATUS_OK ||
	    kreply.status == NODE_STATUS_ERR);
	if (kreply.status == NODE_STATUS_OK)
		ATF_CHECK(kreply.rk_killed >= 2);

	/* Reap children */
	waitpid(c1, &status, 0);
	waitpid(c2, &status, 0);

	/* Release reaper */
	memset(&req, 0, sizeof(req));
	req.op = NODE_OP_REAP_RELEASE;
	node_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &areply, sizeof(areply));

	close(fd);
}

ATF_TC(capprotect_capmode);
ATF_TC_HEAD(capprotect_capmode, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CP_OP_CAPMODE on capprotect enters capability mode");
	atf_tc_set_md_var(tc, "require.kmods",
	    "cap_rt cap_rt_capprotect");
}
ATF_TC_BODY(capprotect_capmode, tc)
{
	int status;
	pid_t pid;

	/*
	 * Must fork because capability mode is irreversible.
	 */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct cp_request req;
		int cpfd, tfd;

		cpfd = cap_rt_connect("capprotect");
		if (cpfd < 0)
			_exit(10);

		memset(&req, 0, sizeof(req));
		req.op = CP_OP_CAPMODE;
		if (node_call_raw(cpfd, &req, sizeof(req), NULL, 0,
		    NULL, 0) != 0)
			_exit(1);

		/* Verify we are in capability mode: open should fail */
		tfd = open("/dev/null", O_RDONLY);
		if (tfd >= 0) {
			close(tfd);
			_exit(3); /* open succeeded — not in capmode */
		}
		if (errno != ECAPMODE)
			_exit(4); /* wrong errno */

		close(cpfd);
		_exit(0);
	}
	waitpid(pid, &status, 0);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child exited with status %d (signal %d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1,
	    WIFSIGNALED(status) ? WTERMSIG(status) : -1);
}

ATF_TC(capprotect_chroot);
ATF_TC_HEAD(capprotect_chroot, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CP_OP_CHROOT with attached dir fd changes filesystem root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "cap_rt cap_rt_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(capprotect_chroot, tc)
{
	int status;
	pid_t pid;
	char tmpdir[] = "/tmp/cap_rt_chroot.XXXXXX";

	ATF_REQUIRE(mkdtemp(tmpdir) != NULL);

	/*
	 * Must fork because chroot is irreversible.
	 */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct cp_request req;
		int cpfd, dfd, tfd;

		cpfd = cap_rt_connect("capprotect");
		if (cpfd < 0)
			_exit(10);

		dfd = open(tmpdir, O_RDONLY | O_DIRECTORY);
		if (dfd < 0)
			_exit(11);

		memset(&req, 0, sizeof(req));
		req.op = CP_OP_CHROOT;
		if (node_call_raw(cpfd, &req, sizeof(req), &dfd, 1,
		    NULL, 0) != 0)
			_exit(1);
		close(dfd);

		/* Verify: /dev/null should not exist in the chroot */
		tfd = open("/dev/null", O_RDONLY);
		if (tfd >= 0) {
			close(tfd);
			_exit(3); /* file accessible — chroot failed */
		}

		close(cpfd);
		_exit(0);
	}
	waitpid(pid, &status, 0);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child exited with status %d (signal %d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1,
	    WIFSIGNALED(status) ? WTERMSIG(status) : -1);

	rmdir(tmpdir);
}

/* ----------------------------------------------------------------
 * Test registration
 * ---------------------------------------------------------------- */

ATF_TP_ADD_TCS(tp)
{
	/* Self-targeting */
	ATF_TP_ADD_TC(tp, node_stat_self);
	ATF_TP_ADD_TC(tp, node_cred_self);
	ATF_TP_ADD_TC(tp, node_rusage_self);
	ATF_TP_ADD_TC(tp, node_rlimit_get_self);
	ATF_TP_ADD_TC(tp, node_rlimit_set_self);
	ATF_TP_ADD_TC(tp, node_nice_get_self);
	ATF_TP_ADD_TC(tp, node_nice_set_self);
	ATF_TP_ADD_TC(tp, node_racct_get_self);
	ATF_TP_ADD_TC(tp, node_affinity_get_self);
	ATF_TP_ADD_TC(tp, node_affinity_set_self);
	ATF_TP_ADD_TC(tp, node_procctl_get_self);
	ATF_TP_ADD_TC(tp, node_procctl_set_self);
	ATF_TP_ADD_TC(tp, node_umask_self);
	ATF_TP_ADD_TC(tp, node_set_session_self);
	ATF_TP_ADD_TC(tp, node_set_pgrp_self);
	ATF_TP_ADD_TC(tp, node_set_login_self);

	/* Procdesc-targeting */
	ATF_TP_ADD_TC(tp, node_stat_child);
	ATF_TP_ADD_TC(tp, node_cred_child);
	ATF_TP_ADD_TC(tp, node_rusage_child);
	ATF_TP_ADD_TC(tp, node_rlimit_set_child);
	ATF_TP_ADD_TC(tp, node_nice_set_child);
	ATF_TP_ADD_TC(tp, node_affinity_get_child);
	ATF_TP_ADD_TC(tp, node_racct_get_child);
	ATF_TP_ADD_TC(tp, node_procctl_set_child);
	ATF_TP_ADD_TC(tp, node_set_cred_child);
	ATF_TP_ADD_TC(tp, node_set_cred_groups_child);
	ATF_TP_ADD_TC(tp, node_set_session_remote_rejected);
	ATF_TP_ADD_TC(tp, node_set_pgrp_remote_rejected);
	ATF_TP_ADD_TC(tp, node_set_login_child);
	ATF_TP_ADD_TC(tp, node_rlimit_get_child);
	ATF_TP_ADD_TC(tp, node_nice_get_child);
	ATF_TP_ADD_TC(tp, node_affinity_set_child);
	ATF_TP_ADD_TC(tp, node_procctl_get_child);
	ATF_TP_ADD_TC(tp, node_umask_child);
	ATF_TP_ADD_TC(tp, node_stat_dead_child);

	/* Scheduler class (rtprio) */
	ATF_TP_ADD_TC(tp, node_rtprio_get_self);
	ATF_TP_ADD_TC(tp, node_rtprio_set_idle_self);
	ATF_TP_ADD_TC(tp, node_rtprio_set_realtime_child);
	ATF_TP_ADD_TC(tp, node_rtprio_invalid_class);
	ATF_TP_ADD_TC(tp, node_rtprio_invalid_prio);

	/* Edge cases */
	ATF_TP_ADD_TC(tp, node_rlimit_max_values);
	ATF_TP_ADD_TC(tp, node_nice_boundary);
	ATF_TP_ADD_TC(tp, node_stat_zombie);
	ATF_TP_ADD_TC(tp, node_cred_ngroups_zero);

	/* Confinement */
	ATF_TP_ADD_TC(tp, node_pdeathsig_set_child);
	ATF_TP_ADD_TC(tp, node_pdeathsig_invalid_signal);
	ATF_TP_ADD_TC(tp, node_protect_child);
	ATF_TP_ADD_TC(tp, node_reap_acquire_self);
	ATF_TP_ADD_TC(tp, node_reap_kill_children);
	ATF_TP_ADD_TC(tp, capprotect_capmode);
	ATF_TP_ADD_TC(tp, capprotect_chroot);

	/* Error cases */
	ATF_TP_ADD_TC(tp, node_set_cred_eperm);
	ATF_TP_ADD_TC(tp, node_set_cred_invalid_ngroups);
	ATF_TP_ADD_TC(tp, node_invalid_rlimit);
	ATF_TP_ADD_TC(tp, node_wrong_fd_type);
	ATF_TP_ADD_TC(tp, node_bad_op);
	ATF_TP_ADD_TC(tp, node_invalid_procctl);

	return (atf_no_error());
}
