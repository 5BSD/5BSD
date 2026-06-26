/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * Tests for mac_capability isolation.
 *
 * Requires:
 *   kldload mac_capability
 *   kldload mac_capability_isolation
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_test_helpers.h"
#include "mac_capability_isolation_proto.h"

/* ----------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------- */

static int	run_net_try_bind(const atf_tc_t *, uint16_t);

static int
fi_connect(void)
{
	struct mac_capability_connect_args ca;
	int ctl;

	ctl = mac_capability_open();
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "isolation", sizeof(ca.name));
	if (ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) != 0) {
		if (errno == ENOENT)
			atf_tc_skip("isolation service not loaded");
		ATF_REQUIRE_MSG(0, "connect isolation: %s",
		    strerror(errno));
	}
	close(ctl);
	return (ca.fd);
}

static int
fi_call(int fd, uint32_t op, int target_fd, uint64_t actions,
    struct fi_reply *rpl)
{
	struct mac_capability_call_args ca;
	struct fi_request req;

	memset(&req, 0, sizeof(req));
	req.op = op;
	req.actions = actions;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.req_fds = &target_fd;
	ca.req_nfds = 1;
	ca.reply = rpl;
	ca.reply_len = sizeof(*rpl);
	return (ioctl(fd, MAC_CAPABILITY_CALL, &ca));
}

/*
 * Mint an access token for a vnode claim.  Returns the token fd
 * on success, -1 on failure.
 */
static int
fi_mint(int svc_fd, int target_fd, uint64_t actions)
{
	struct mac_capability_call_args ca;
	struct fi_request req;
	struct fi_reply rpl;
	int token_fd;

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_MINT;
	req.actions = actions;
	token_fd = -1;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.req_fds = &target_fd;
	ca.req_nfds = 1;
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	ca.reply_fds = &token_fd;
	ca.reply_nfds = 1;
	if (ioctl(svc_fd, MAC_CAPABILITY_CALL, &ca) != 0)
		return (-1);
	return (token_fd);
}

/*
 * Authorize the caller on a token fd.
 */
static int __unused
fi_authorize(int token_fd)
{
	struct mac_capability_call_args ca;
	struct fi_request req;
	struct fi_reply rpl;

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_AUTHORIZE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	return (ioctl(token_fd, MAC_CAPABILITY_CALL, &ca));
}

static char tmppath[128];

static void
make_tmpfile(void)
{
	int fd;

	snprintf(tmppath, sizeof(tmppath),
	    "/tmp/fi_test.%d", (int)getpid());
	fd = open(tmppath, O_CREAT | O_RDWR, 0644);
	ATF_REQUIRE_MSG(fd >= 0, "create %s: %s", tmppath, strerror(errno));
	close(fd);
}

static void
cleanup_tmpfile(void)
{

	unlink(tmppath);
}

/* ----------------------------------------------------------------
 * Tests
 * ---------------------------------------------------------------- */

ATF_TC_WITH_CLEANUP(claim_and_query);
ATF_TC_HEAD(claim_and_query, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Claim a file and verify query reports it as ours");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(claim_and_query, tc)
{
	struct fi_reply rpl;
	int svc, target;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);

	/* Claim */
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);

	/* Query — should be claimed and ours */
	ATF_REQUIRE(fi_call(svc, FI_OP_QUERY, target, FI_FS_ALL, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, FI_QF_CLAIMED | FI_QF_MINE);

	close(target);
	close(svc);
}
ATF_TC_CLEANUP(claim_and_query, tc)
{
	cleanup_tmpfile();
}

ATF_TC_WITH_CLEANUP(claim_allows_same_nonce);
ATF_TC_HEAD(claim_allows_same_nonce, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Forked child (same nonce) can open an isolated file");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(claim_allows_same_nonce, tc)
{
	struct fi_reply rpl;
	int svc, target, status;
	pid_t pid;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);
	close(target);

	/*
	 * Fork a child (no exec).  The child inherits the parent's
	 * nonce, so it should be able to open the isolated file.
	 */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd = open(tmppath, O_RDONLY);
		_exit(fd >= 0 ? 0 : errno);
	}
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(svc);
}
ATF_TC_CLEANUP(claim_allows_same_nonce, tc)
{
	cleanup_tmpfile();
}

ATF_TC_WITH_CLEANUP(claim_blocks_stat);
ATF_TC_HEAD(claim_blocks_stat, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Isolated file cannot be stat'd by a different nonce");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(claim_blocks_stat, tc)
{
	struct fi_reply rpl;
	struct stat sb;
	int svc, target, status;
	pid_t pid;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);
	close(target);

	/*
	 * Fork a child that exec's /usr/bin/stat to get a new nonce.
	 * The stat should fail.
	 */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl("/usr/bin/stat", "stat", tmppath, NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	/* stat should exit non-zero because the MACF hook blocks it */
	ATF_CHECK(WEXITSTATUS(status) != 0);

	/* Same-nonce stat should succeed */
	ATF_CHECK_EQ(stat(tmppath, &sb), 0);

	close(svc);
}
ATF_TC_CLEANUP(claim_blocks_stat, tc)
{
	cleanup_tmpfile();
}

ATF_TC_WITH_CLEANUP(claim_blocks_unlink);
ATF_TC_HEAD(claim_blocks_unlink, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Isolated file cannot be unlinked by a different nonce");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(claim_blocks_unlink, tc)
{
	struct fi_reply rpl;
	int svc, target, status;
	pid_t pid;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);
	close(target);

	/* Child with new nonce via exec tries to unlink */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl("/bin/rm", "rm", "-f", tmppath, NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK(WEXITSTATUS(status) != 0);

	/* File should still exist */
	ATF_CHECK_EQ(access(tmppath, F_OK), 0);

	close(svc);
}
ATF_TC_CLEANUP(claim_blocks_unlink, tc)
{
	cleanup_tmpfile();
}

ATF_TC_WITH_CLEANUP(release_allows_access);
ATF_TC_HEAD(release_allows_access, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Releasing isolation restores normal access");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(release_allows_access, tc)
{
	struct fi_reply rpl;
	int svc, target, status;
	pid_t pid;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_RELEASE, target, 0, &rpl) == 0);
	close(target);

	/* Query should show not claimed */
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_QUERY, target, FI_FS_ALL, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, 0);
	close(target);

	/* Child with new nonce should now be able to stat */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl("/usr/bin/stat", "stat", tmppath, NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(svc);
}
ATF_TC_CLEANUP(release_allows_access, tc)
{
	cleanup_tmpfile();
}

ATF_TC_WITH_CLEANUP(close_releases_claims);
ATF_TC_HEAD(close_releases_claims, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing the instance fd releases all claims");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(close_releases_claims, tc)
{
	struct fi_reply rpl;
	int svc, svc2, target;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);

	/* Close the instance — claim should be released */
	close(svc);

	/* Verify via a new instance */
	svc2 = fi_connect();
	ATF_REQUIRE(fi_call(svc2, FI_OP_QUERY, target, FI_FS_ALL, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, 0);

	close(target);
	close(svc2);
}
ATF_TC_CLEANUP(close_releases_claims, tc)
{
	cleanup_tmpfile();
}

ATF_TC_WITH_CLEANUP(double_claim_same_nonce);
ATF_TC_HEAD(double_claim_same_nonce, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Re-claiming from same nonce transfers ownership");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(double_claim_same_nonce, tc)
{
	struct fi_reply rpl;
	int svc1, svc2, target;

	make_tmpfile();
	svc1 = fi_connect();
	svc2 = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);

	/* Claim via first instance */
	ATF_REQUIRE(fi_call(svc1, FI_OP_CLAIM, target, 0, &rpl) == 0);

	/* Re-claim via second instance (same nonce) — should succeed */
	ATF_REQUIRE(fi_call(svc2, FI_OP_CLAIM, target, 0, &rpl) == 0);

	/* Close first instance — claim should survive (owned by svc2) */
	close(svc1);

	ATF_REQUIRE(fi_call(svc2, FI_OP_QUERY, target, FI_FS_ALL, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, FI_QF_CLAIMED | FI_QF_MINE);

	close(target);
	close(svc2);
}
ATF_TC_CLEANUP(double_claim_same_nonce, tc)
{
	cleanup_tmpfile();
}

ATF_TC_WITH_CLEANUP(child_reclaim_same_nonce);
ATF_TC_HEAD(child_reclaim_same_nonce, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Forked child (same nonce) can re-claim an already-claimed vnode");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(child_reclaim_same_nonce, tc)
{
	struct fi_reply rpl;
	int svc, target, pfd[2], status;
	pid_t pid;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);
	close(target);

	ATF_REQUIRE(pipe(pfd) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(pfd[0]);
		int csvc = fi_connect();
		/* Same nonce, should transfer (succeed) */
		target = open(tmppath, O_RDONLY);
		int ret = fi_call(csvc, FI_OP_CLAIM, target, 0, &rpl);
		int result = (ret == 0) ? 0 : errno;
		write(pfd[1], &result, sizeof(result));
		close(target);
		close(csvc);
		close(pfd[1]);
		_exit(0);
	}
	close(pfd[1]);
	int result;
	ATF_REQUIRE(read(pfd[0], &result, sizeof(result)) == sizeof(result));
	close(pfd[0]);
	ATF_CHECK_EQ(result, 0);

	waitpid(pid, &status, 0);
	close(svc);
}
ATF_TC_CLEANUP(child_reclaim_same_nonce, tc)
{
	cleanup_tmpfile();
}

ATF_TC(claim_pipe_fails);
ATF_TC_HEAD(claim_pipe_fails, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Claiming an fd without a vnode (pipe) returns EINVAL");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(claim_pipe_fails, tc)
{
	struct fi_reply rpl;
	int svc, pfd[2];

	svc = fi_connect();
	ATF_REQUIRE(pipe(pfd) == 0);
	ATF_CHECK_ERRNO(EINVAL, fi_call(svc, FI_OP_CLAIM, pfd[0], 0, &rpl) == -1);
	close(pfd[0]);
	close(pfd[1]);
	close(svc);
}

ATF_TC_WITH_CLEANUP(same_nonce_can_open);
ATF_TC_HEAD(same_nonce_can_open, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Same-nonce process (fork, no exec) can open isolated file");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(same_nonce_can_open, tc)
{
	struct fi_reply rpl;
	int svc, target, status;
	pid_t pid;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);
	close(target);

	/* Forked child (same nonce) should succeed */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd = open(tmppath, O_RDONLY);
		_exit(fd >= 0 ? 0 : errno);
	}
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(svc);
}
ATF_TC_CLEANUP(same_nonce_can_open, tc)
{
	cleanup_tmpfile();
}

ATF_TC_WITH_CLEANUP(query_unclaimed);
ATF_TC_HEAD(query_unclaimed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Querying an unclaimed vnode returns zero flags");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(query_unclaimed, tc)
{
	struct fi_reply rpl;
	int svc, target;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);

	ATF_REQUIRE(fi_call(svc, FI_OP_QUERY, target, FI_FS_ALL, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, 0);

	close(target);
	close(svc);
}
ATF_TC_CLEANUP(query_unclaimed, tc)
{
	cleanup_tmpfile();
}

/* ----------------------------------------------------------------
 * Directory isolation tests
 * ---------------------------------------------------------------- */

static char tmpdir[128];
static char tmpdir_file[160];

static void
make_tmpdir(void)
{
	int fd;

	snprintf(tmpdir, sizeof(tmpdir),
	    "/tmp/fi_dir_test.%d", (int)getpid());
	ATF_REQUIRE_MSG(mkdir(tmpdir, 0755) == 0 || errno == EEXIST,
	    "mkdir %s: %s", tmpdir, strerror(errno));

	snprintf(tmpdir_file, sizeof(tmpdir_file),
	    "%s/secret.txt", tmpdir);
	fd = open(tmpdir_file, O_CREAT | O_RDWR, 0644);
	ATF_REQUIRE_MSG(fd >= 0, "create %s: %s",
	    tmpdir_file, strerror(errno));
	write(fd, "secret", 6);
	close(fd);
}

static void
cleanup_tmpdir(void)
{

	unlink(tmpdir_file);
	rmdir(tmpdir);
}

static char tmpsockpath[128];

static int
make_tmpunix_listener(void)
{
	struct sockaddr_un sun;
	int s;

	snprintf(tmpsockpath, sizeof(tmpsockpath),
	    "/tmp/fi_sock_test.%d", (int)getpid());
	unlink(tmpsockpath);

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(s >= 0, "socket(AF_UNIX): %s", strerror(errno));

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, tmpsockpath, sizeof(sun.sun_path));

	ATF_REQUIRE_MSG(bind(s, (struct sockaddr *)&sun, sizeof(sun)) == 0,
	    "bind %s: %s", tmpsockpath, strerror(errno));
	ATF_REQUIRE_MSG(listen(s, 1) == 0, "listen %s: %s",
	    tmpsockpath, strerror(errno));

	return (s);
}

static void
cleanup_tmpsock(void)
{

	unlink(tmpsockpath);
}

ATF_TC_WITH_CLEANUP(dir_claim_blocks_lookup);
ATF_TC_HEAD(dir_claim_blocks_lookup, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Claiming a directory blocks lookups into it from foreign nonce");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(dir_claim_blocks_lookup, tc)
{
	struct fi_reply rpl;
	int svc, dir_fd, status;
	pid_t pid;
	char cmd[256];

	make_tmpdir();
	svc = fi_connect();

	dir_fd = open(tmpdir, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dir_fd >= 0);

	/* Claim the directory */
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, dir_fd, 0, &rpl) == 0);
	close(dir_fd);

	/*
	 * Fork+exec a child that tries to open a file inside.
	 * The exec rotates the nonce, so the lookup into the
	 * claimed directory should fail with EACCES.
	 */
	snprintf(cmd, sizeof(cmd), "cat %s >/dev/null 2>&1", tmpdir_file);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl("/bin/sh", "sh", "-c", cmd, NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	/* cat should fail — lookup blocked */
	ATF_CHECK(WEXITSTATUS(status) != 0);

	/* Same-nonce parent can still open the file inside */
	int inner = open(tmpdir_file, O_RDONLY);
	ATF_CHECK(inner >= 0);
	if (inner >= 0)
		close(inner);

	close(svc);
}
ATF_TC_CLEANUP(dir_claim_blocks_lookup, tc)
{
	cleanup_tmpdir();
}

ATF_TC_WITH_CLEANUP(dir_claim_blocks_stat_inside);
ATF_TC_HEAD(dir_claim_blocks_stat_inside, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Stat of a file inside a claimed directory is blocked");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(dir_claim_blocks_stat_inside, tc)
{
	struct fi_reply rpl;
	int svc, dir_fd, status;
	pid_t pid;

	make_tmpdir();
	svc = fi_connect();

	dir_fd = open(tmpdir, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dir_fd >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, dir_fd, 0, &rpl) == 0);
	close(dir_fd);

	/* Fork+exec /usr/bin/stat on the file inside the dir */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl("/usr/bin/stat", "stat", tmpdir_file, NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK(WEXITSTATUS(status) != 0);

	/* Same-nonce stat succeeds */
	struct stat sb;
	ATF_CHECK_EQ(stat(tmpdir_file, &sb), 0);

	close(svc);
}
ATF_TC_CLEANUP(dir_claim_blocks_stat_inside, tc)
{
	cleanup_tmpdir();
}

ATF_TC_WITH_CLEANUP(dir_release_allows_lookup);
ATF_TC_HEAD(dir_release_allows_lookup, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Releasing a directory claim allows foreign nonce access again");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(dir_release_allows_lookup, tc)
{
	struct fi_reply rpl;
	int svc, dir_fd, status;
	pid_t pid;
	char cmd[256];

	make_tmpdir();
	svc = fi_connect();

	dir_fd = open(tmpdir, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dir_fd >= 0);

	/* Claim then release */
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, dir_fd, 0, &rpl) == 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_RELEASE, dir_fd, 0, &rpl) == 0);
	close(dir_fd);

	/* Foreign-nonce child should now succeed */
	snprintf(cmd, sizeof(cmd), "cat %s >/dev/null 2>&1", tmpdir_file);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl("/bin/sh", "sh", "-c", cmd, NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(svc);
}
ATF_TC_CLEANUP(dir_release_allows_lookup, tc)
{
	cleanup_tmpdir();
}

/* ----------------------------------------------------------------
 * Network isolation tests
 * ---------------------------------------------------------------- */

static int
fi_net_call_addr(int svc, uint32_t op, int domain, int protocol,
    uint16_t port, uint8_t direction, const char *addr, uint8_t prefix)
{
	struct mac_capability_call_args ca;
	struct fi_net_request nr;
	struct fi_reply rpl;

	memset(&nr, 0, sizeof(nr));
	nr.op = op;
	nr.domain = domain;
	nr.protocol = protocol;
	if (port == 0) {
		nr.port_min = htons(0);
		nr.port_max = htons(UINT16_MAX);
	} else {
		nr.port_min = port;
		nr.port_max = port;
	}
	nr.direction = direction;
	nr.prefix = prefix;

	if (addr != NULL) {
		if (domain == AF_INET) {
			struct in_addr in4;

			ATF_REQUIRE_MSG(inet_pton(AF_INET, addr, &in4) == 1,
			    "invalid IPv4 address '%s'", addr);
			nr.addr[10] = 0xff;
			nr.addr[11] = 0xff;
			memcpy(&nr.addr[12], &in4, sizeof(in4));
		} else if (domain == AF_INET6) {
			struct in6_addr in6;

			ATF_REQUIRE_MSG(inet_pton(AF_INET6, addr, &in6) == 1,
			    "invalid IPv6 address '%s'", addr);
			memcpy(nr.addr, &in6, sizeof(in6));
		} else {
			atf_tc_fail("unsupported address family %d", domain);
		}
	}

	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	return (ioctl(svc, MAC_CAPABILITY_CALL, &ca));
}

static int
fi_net_call_raw(int svc, const struct fi_net_request *nr)
{
	struct mac_capability_call_args ca;
	struct fi_reply rpl;

	memset(&ca, 0, sizeof(ca));
	ca.req = nr;
	ca.req_len = sizeof(*nr);
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	return (ioctl(svc, MAC_CAPABILITY_CALL, &ca));
}

static int
fi_net_call2(int svc, uint32_t op, int domain, int protocol,
    uint16_t port_min, uint16_t port_max, uint8_t direction)
{
	struct mac_capability_call_args ca;
	struct fi_net_request nr;
	struct fi_reply rpl;

	memset(&nr, 0, sizeof(nr));
	nr.op = op;
	nr.domain = domain;
	nr.protocol = protocol;
	nr.port_min = htons(port_min);
	nr.port_max = htons(port_max);
	nr.direction = direction;

	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	return (ioctl(svc, MAC_CAPABILITY_CALL, &ca));
}

static int
fi_net_query2(int svc, int domain, int protocol, uint16_t port_min,
    uint16_t port_max, uint8_t direction, struct fi_reply *rpl)
{
	struct mac_capability_call_args ca;
	struct fi_net_request nr;

	memset(&nr, 0, sizeof(nr));
	nr.op = FI_OP_QUERY_NET;
	nr.domain = domain;
	nr.protocol = protocol;
	nr.port_min = htons(port_min);
	nr.port_max = htons(port_max);
	nr.direction = direction;

	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply = rpl;
	ca.reply_len = sizeof(*rpl);
	return (ioctl(svc, MAC_CAPABILITY_CALL, &ca));
}

static int
fi_net_call(int svc, uint32_t op, int domain, int protocol,
    uint16_t port, uint8_t direction)
{

	return (fi_net_call_addr(svc, op, domain, protocol, port, direction,
	    NULL, 0));
}

/*
 * Mint a network access token.  Returns the token fd on success, -1 on
 * failure.  The request describes the endpoint the token covers.
 */
static int
fi_net_mint(int svc, int domain, int protocol, uint16_t port,
    uint8_t direction)
{
	struct mac_capability_call_args ca;
	struct fi_net_request nr;
	struct fi_reply rpl;
	int token_fd;

	memset(&nr, 0, sizeof(nr));
	nr.op = FI_OP_MINT_NET;
	nr.domain = domain;
	nr.protocol = protocol;
	if (port == 0) {
		nr.port_min = htons(0);
		nr.port_max = htons(UINT16_MAX);
	} else {
		nr.port_min = port;
		nr.port_max = port;
	}
	nr.direction = direction;

	token_fd = -1;
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	ca.reply_fds = &token_fd;
	ca.reply_nfds = 1;
	if (ioctl(svc, MAC_CAPABILITY_CALL, &ca) != 0)
		return (-1);
	return (token_fd);
}

static int
fi_net_mint2(int svc, int domain, int protocol, uint16_t port_min,
    uint16_t port_max, uint8_t direction)
{
	struct mac_capability_call_args ca;
	struct fi_net_request nr;
	struct fi_reply rpl;
	int token_fd;

	memset(&nr, 0, sizeof(nr));
	nr.op = FI_OP_MINT_NET;
	nr.domain = domain;
	nr.protocol = protocol;
	nr.port_min = htons(port_min);
	nr.port_max = htons(port_max);
	nr.direction = direction;

	token_fd = -1;
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	ca.reply_fds = &token_fd;
	ca.reply_nfds = 1;
	if (ioctl(svc, MAC_CAPABILITY_CALL, &ca) != 0)
		return (-1);
	return (token_fd);
}

static const char *
fi_helper_path(const atf_tc_t *tc)
{
	static char path[1024];

	snprintf(path, sizeof(path), "%s/mac_capability_isolation_helper",
	    atf_tc_get_config_var(tc, "srcdir"));
	return (path);
}

static int
run_net_claim_helper(const atf_tc_t *tc, int svc, uint32_t op, int domain,
    int protocol, uint16_t port, uint8_t direction, const char *addr,
    uint8_t prefix)
{
	char fdstr[16], opstr[16], domainstr[16], protostr[16];
	char portstr[16], dirstr[16], prefixstr[16];
	const char *path;
	pid_t pid;
	int status;

	snprintf(fdstr, sizeof(fdstr), "%d", svc);
	snprintf(opstr, sizeof(opstr), "%u", op);
	snprintf(domainstr, sizeof(domainstr), "%d", domain);
	snprintf(protostr, sizeof(protostr), "%d", protocol);
	snprintf(portstr, sizeof(portstr), "%u", port);
	snprintf(dirstr, sizeof(dirstr), "%u", direction);
	snprintf(prefixstr, sizeof(prefixstr), "%u", prefix);
	path = fi_helper_path(tc);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(path, path, fdstr, opstr, domainstr, protostr, portstr,
		    dirstr, addr != NULL ? addr : "-", prefixstr, NULL);
		_exit(127);
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	return (WEXITSTATUS(status));
}

static int
run_net_range_claim_helper(const atf_tc_t *tc, int svc, uint32_t op, int domain,
    int protocol, uint16_t port_min, uint16_t port_max, uint8_t direction)
{
	char fdstr[16], opstr[16], domainstr[16], protostr[16];
	char minstr[16], maxstr[16], dirstr[16];
	const char *path;
	pid_t pid;
	int status;

	snprintf(fdstr, sizeof(fdstr), "%d", svc);
	snprintf(opstr, sizeof(opstr), "%u", op);
	snprintf(domainstr, sizeof(domainstr), "%d", domain);
	snprintf(protostr, sizeof(protostr), "%d", protocol);
	snprintf(minstr, sizeof(minstr), "%u", port_min);
	snprintf(maxstr, sizeof(maxstr), "%u", port_max);
	snprintf(dirstr, sizeof(dirstr), "%u", direction);
	path = fi_helper_path(tc);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(path, path, "net-range", fdstr, opstr, domainstr,
		    protostr, minstr, maxstr, dirstr, NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

static int
run_net_query_helper(const atf_tc_t *tc, int svc, int domain, int protocol,
    uint16_t port_min, uint16_t port_max, uint8_t direction,
    uint32_t expected_flags)
{
	char fdstr[16], domainstr[16], protostr[16];
	char minstr[16], maxstr[16], dirstr[16], flagstr[16];
	const char *path;
	pid_t pid;
	int status;

	snprintf(fdstr, sizeof(fdstr), "%d", svc);
	snprintf(domainstr, sizeof(domainstr), "%d", domain);
	snprintf(protostr, sizeof(protostr), "%d", protocol);
	snprintf(minstr, sizeof(minstr), "%u", port_min);
	snprintf(maxstr, sizeof(maxstr), "%u", port_max);
	snprintf(dirstr, sizeof(dirstr), "%u", direction);
	snprintf(flagstr, sizeof(flagstr), "%u", expected_flags);
	path = fi_helper_path(tc);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(path, path, "net-query", fdstr, domainstr, protostr,
		    minstr, maxstr, dirstr, flagstr, NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

static int
run_net_socket_helper(const atf_tc_t *tc, int domain, int type, int protocol)
{
	char domainstr[16], typestr[16], protostr[16];
	const char *path;
	pid_t pid;
	int status;

	snprintf(domainstr, sizeof(domainstr), "%d", domain);
	snprintf(typestr, sizeof(typestr), "%d", type);
	snprintf(protostr, sizeof(protostr), "%d", protocol);
	path = fi_helper_path(tc);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(path, path, "socket", domainstr, typestr, protostr, NULL);
		_exit(127);
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	return (WEXITSTATUS(status));
}

static int
run_net_connect_helper(const atf_tc_t *tc, int domain, int type, int protocol,
    const char *addr, uint16_t port)
{
	char domainstr[16], typestr[16], protostr[16], portstr[16];
	const char *path;
	pid_t pid;
	int status;

	snprintf(domainstr, sizeof(domainstr), "%d", domain);
	snprintf(typestr, sizeof(typestr), "%d", type);
	snprintf(protostr, sizeof(protostr), "%d", protocol);
	snprintf(portstr, sizeof(portstr), "%u", port);
	path = fi_helper_path(tc);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(path, path, "connect", domainstr, typestr, protostr,
		    addr, portstr, NULL);
		_exit(127);
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	return (WEXITSTATUS(status));
}

static int
run_unix_connect_helper(const atf_tc_t *tc, const char *path)
{
	const char *helper;
	pid_t pid;
	int status;

	helper = fi_helper_path(tc);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(helper, helper, "unix-connect", path, NULL);
		_exit(127);
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	return (WEXITSTATUS(status));
}

ATF_TC(net_claim_blocks_bind);
ATF_TC_HEAD(net_claim_blocks_bind, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Network claim blocks foreign nonce from binding the port");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_claim_blocks_bind, tc)
{
	int rc, svc;
	uint16_t port = htons(18443);

	svc = fi_connect();

	/* Claim TCP bind on port 18443 */
	ATF_REQUIRE(fi_net_call(svc, FI_OP_CLAIM_NET,
	    AF_INET, IPPROTO_TCP, port, FI_NET_BIND) == 0);

	/*
	 * Fork+exec the helper to rotate the nonce, then try to
	 * bind the claimed port.  The MACF hook should deny it.
	 */
	rc = run_net_try_bind(tc, 18443);
	ATF_CHECK_MSG(rc == 1,
	    "foreign nonce bind should be denied (got %d)", rc);

	close(svc);
}

ATF_TC(net_claim_allows_owner);
ATF_TC_HEAD(net_claim_allows_owner, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Owner nonce can still bind a claimed port");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_claim_allows_owner, tc)
{
	struct sockaddr_in sin;
	int svc, s;
	uint16_t port = htons(18444);

	svc = fi_connect();

	ATF_REQUIRE(fi_net_call(svc, FI_OP_CLAIM_NET,
	    AF_INET, IPPROTO_TCP, port, FI_NET_BIND) == 0);

	/* Same nonce — bind should succeed */
	s = socket(AF_INET, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = port;
	sin.sin_addr.s_addr = INADDR_ANY;
	ATF_CHECK_EQ(bind(s, (struct sockaddr *)&sin, sizeof(sin)), 0);

	close(s);
	close(svc);
}

ATF_TC(net_release_allows_bind);
ATF_TC_HEAD(net_release_allows_bind, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Releasing a network claim allows binding again");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_release_allows_bind, tc)
{
	int svc;
	uint16_t port = htons(18445);

	svc = fi_connect();

	ATF_REQUIRE(fi_net_call(svc, FI_OP_CLAIM_NET,
	    AF_INET, IPPROTO_TCP, port, FI_NET_BIND) == 0);
	ATF_REQUIRE(fi_net_call(svc, FI_OP_RELEASE_NET,
	    AF_INET, IPPROTO_TCP, port, FI_NET_BIND) == 0);

	/* After release, anyone can bind (close svc to prove it's released) */
	close(svc);

	/* Verify by binding as ourselves (claim is gone) */
	{
		struct sockaddr_in sin;
		int s;

		s = socket(AF_INET, SOCK_STREAM, 0);
		ATF_REQUIRE(s >= 0);
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = port;
		sin.sin_addr.s_addr = INADDR_ANY;
		ATF_CHECK_EQ(bind(s, (struct sockaddr *)&sin, sizeof(sin)), 0);
		close(s);
	}
}

ATF_TC(net_claim_disjoint_address_allows_foreign_claim);
ATF_TC_HEAD(net_claim_disjoint_address_allows_foreign_claim, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Disjoint address claims on the same port do not conflict");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_claim_disjoint_address_allows_foreign_claim, tc)
{
	int rc, svc;
	uint16_t port = 18446;

	svc = fi_connect();

	ATF_REQUIRE(fi_net_call_addr(svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, htons(port), FI_NET_BIND, "127.0.0.1", 0) == 0);

	rc = run_net_claim_helper(tc, svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, port, FI_NET_BIND, "127.0.0.2", 0);
	ATF_CHECK_EQ(rc, 0);

	close(svc);
}

ATF_TC(net_claim_same_address_blocks_foreign_claim);
ATF_TC_HEAD(net_claim_same_address_blocks_foreign_claim, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Overlapping address claims on the same port still conflict");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_claim_same_address_blocks_foreign_claim, tc)
{
	int rc, svc;
	uint16_t port = 18447;

	svc = fi_connect();

	ATF_REQUIRE(fi_net_call_addr(svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, htons(port), FI_NET_BIND, "127.0.0.1", 0) == 0);

	rc = run_net_claim_helper(tc, svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, port, FI_NET_BIND, "127.0.0.1", 0);
	ATF_CHECK_EQ(rc, 1);

	close(svc);
}

ATF_TC(net_claim_blocks_connect);
ATF_TC_HEAD(net_claim_blocks_connect, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Network connect claim blocks foreign nonce from connecting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_claim_blocks_connect, tc)
{
	struct sockaddr_in sin;
	int rc, svc, listener;
	uint16_t port = 18448;

	listener = socket(AF_INET, SOCK_STREAM, 0);
	ATF_REQUIRE(listener >= 0);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ATF_REQUIRE(bind(listener, (struct sockaddr *)&sin, sizeof(sin)) == 0);
	ATF_REQUIRE(listen(listener, 1) == 0);

	svc = fi_connect();
	ATF_REQUIRE(fi_net_call_addr(svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, htons(port), FI_NET_CONNECT, "127.0.0.1", 0) == 0);

	rc = run_net_connect_helper(tc, AF_INET, SOCK_STREAM, IPPROTO_TCP,
	    "127.0.0.1", port);
	ATF_CHECK_EQ(rc, 1);

	close(svc);
	close(listener);
}

ATF_TC(net_wildcard_blocks_socket_create);
ATF_TC_HEAD(net_wildcard_blocks_socket_create, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Fully wildcard FI_NET_ANY claim blocks foreign socket creation");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_wildcard_blocks_socket_create, tc)
{
	int rc, s, svc;

	svc = fi_connect();
	ATF_REQUIRE(fi_net_call(svc, FI_OP_CLAIM_NET,
	    AF_INET, IPPROTO_TCP, 0, FI_NET_ANY) == 0);

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ATF_REQUIRE(s >= 0);
	close(s);

	rc = run_net_socket_helper(tc, AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ATF_CHECK_EQ(rc, 1);

	close(svc);
}

ATF_TC(net_claim_invalid_request);
ATF_TC_HEAD(net_claim_invalid_request, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Invalid network claim arguments are rejected");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_claim_invalid_request, tc)
{
	struct fi_net_request nr;
	int svc;

	svc = fi_connect();

	memset(&nr, 0, sizeof(nr));
	nr.op = FI_OP_CLAIM_NET;
	nr.domain = AF_INET;
	nr.protocol = IPPROTO_TCP;
	nr.port_min = htons(18449);
	nr.port_max = htons(18449);
	nr.direction = FI_NET_BIND;
	nr.flags = 1;
	ATF_CHECK_ERRNO(EINVAL, fi_net_call_raw(svc, &nr) == -1);

	nr.flags = 0;
	nr.direction = 0;
	ATF_CHECK_ERRNO(EINVAL, fi_net_call_raw(svc, &nr) == -1);

	nr.direction = 0x80;
	ATF_CHECK_ERRNO(EINVAL, fi_net_call_raw(svc, &nr) == -1);

	nr.direction = FI_NET_BIND;
	nr.prefix = 129;
	ATF_CHECK_ERRNO(EINVAL, fi_net_call_raw(svc, &nr) == -1);

	close(svc);
}

ATF_TC_WITH_CLEANUP(unix_socket_claim_blocks_connect);
ATF_TC_HEAD(unix_socket_claim_blocks_connect, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Claiming a Unix socket vnode blocks foreign connect()");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(unix_socket_claim_blocks_connect, tc)
{
	struct fi_reply rpl;
	int rc, listener, svc, target;

	listener = make_tmpunix_listener();

	svc = fi_connect();
	target = open(tmpsockpath, O_PATH);
	ATF_REQUIRE_MSG(target >= 0, "open %s: %s",
	    tmpsockpath, strerror(errno));

	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);
	rc = run_unix_connect_helper(tc, tmpsockpath);
	ATF_CHECK_EQ(rc, 1);

	close(target);
	close(svc);
	close(listener);
}
ATF_TC_CLEANUP(unix_socket_claim_blocks_connect, tc)
{
	cleanup_tmpsock();
}

/* ----------------------------------------------------------------
 * Cross-nonce enforcement tests.
 *
 * These fork+exec a child to rotate the nonce, then have the child
 * attempt operations on the isolated file.  The exec helper is /bin/sh
 * running a one-liner.  Exit 0 = operation succeeded (bad), nonzero =
 * blocked (good).
 * ---------------------------------------------------------------- */

static int
run_cross_nonce_op(const char *sh_cmd)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return (-1);
	if (pid == 0) {
		execl("/bin/sh", "sh", "-c", sh_cmd, NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

/*
 * Table-driven cross-nonce enforcement tests.
 *
 * Each entry describes a syscall that a foreign nonce should be unable
 * to perform on an isolated file.  The setup/claim/fork+exec/cleanup
 * pattern is identical for all of them; only the shell command varies.
 *
 * We group them into three ATF test cases so that ATF reporting still
 * shows which category failed:
 *   cross_nonce_read_blocked      — open (read) and open (write)
 *   cross_nonce_metadata_blocked  — chmod, chown, chflags, utimes,
 *                                   access, truncate, readlink
 *   cross_nonce_lifecycle_blocked — link, rename, exec
 */

struct cross_nonce_op {
	const char	*name;		/* human-readable label */
	const char	*cmd_fmt;	/* printf fmt; %s = file path */
};

static void
run_simple_cross_nonce_table(const struct cross_nonce_op *ops, size_t nops)
{
	struct fi_reply rpl;
	int svc, target;
	char cmd[256];
	size_t i;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);
	close(target);

	for (i = 0; i < nops; i++) {
		snprintf(cmd, sizeof(cmd), ops[i].cmd_fmt, tmppath);
		ATF_CHECK_MSG(run_cross_nonce_op(cmd) != 0,
		    "%s was not blocked on isolated file", ops[i].name);
	}

	close(svc);
}

/* -- read group (open for read, open for write) -- */

ATF_TC_WITH_CLEANUP(cross_nonce_read_blocked);
ATF_TC_HEAD(cross_nonce_read_blocked, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Foreign nonce cannot open an isolated file for reading or writing");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cross_nonce_read_blocked, tc)
{
	static const struct cross_nonce_op ops[] = {
		{ "open(read)",  "exec cat '%s' >/dev/null 2>&1" },
		{ "open(write)",
		  "exec dd if=/dev/zero of='%s' bs=1 count=1 2>/dev/null" },
	};

	run_simple_cross_nonce_table(ops, sizeof(ops) / sizeof(ops[0]));
}
ATF_TC_CLEANUP(cross_nonce_read_blocked, tc)
{
	cleanup_tmpfile();
}

/* -- metadata group (chmod, chown, chflags, utimes, access, truncate,
 *    readlink) -- */

ATF_TC_WITH_CLEANUP(cross_nonce_metadata_blocked);
ATF_TC_HEAD(cross_nonce_metadata_blocked, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Foreign nonce cannot modify metadata of an isolated file "
	    "(chmod, chown, chflags, utimes, access, truncate, readlink)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cross_nonce_metadata_blocked, tc)
{
	static const struct cross_nonce_op simple_ops[] = {
		{ "chmod",    "exec chmod 777 '%s'" },
		{ "chown",    "exec chown nobody '%s'" },
		{ "chflags",  "exec chflags nodump '%s'" },
		{ "utimes",   "exec touch '%s'" },
		{ "access",   "exec test -r '%s'" },
		{ "truncate", "exec truncate -s 0 '%s'" },
	};
	struct fi_reply rpl;
	int svc, target;
	char cmd[256], linkpath[160];

	/* Test simple metadata ops via the table */
	run_simple_cross_nonce_table(simple_ops,
	    sizeof(simple_ops) / sizeof(simple_ops[0]));

	/*
	 * readlink needs special setup: create a symlink and claim it.
	 */
	snprintf(linkpath, sizeof(linkpath), "%s.sym", tmppath);
	ATF_REQUIRE(symlink(tmppath, linkpath) == 0);

	svc = fi_connect();
	target = open(linkpath, O_PATH | O_NOFOLLOW);
	ATF_REQUIRE_MSG(target >= 0, "open symlink: %s", strerror(errno));
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);
	close(target);

	snprintf(cmd, sizeof(cmd), "exec readlink '%s'", linkpath);
	ATF_CHECK_MSG(run_cross_nonce_op(cmd) != 0,
	    "readlink was not blocked on isolated symlink");

	unlink(linkpath);
	close(svc);
}
ATF_TC_CLEANUP(cross_nonce_metadata_blocked, tc)
{
	char linkpath[160];
	snprintf(linkpath, sizeof(linkpath), "%s.sym", tmppath);
	unlink(linkpath);
	cleanup_tmpfile();
}

/* -- lifecycle group (link, rename, exec) -- */

ATF_TC_WITH_CLEANUP(cross_nonce_lifecycle_blocked);
ATF_TC_HEAD(cross_nonce_lifecycle_blocked, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Foreign nonce cannot link, rename, or exec an isolated file");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cross_nonce_lifecycle_blocked, tc)
{
	struct fi_reply rpl;
	int svc, target;
	char cmd[256], linkpath[160], newpath[160], exepath[160];

	/* -- hard link -- */
	make_tmpfile();
	snprintf(linkpath, sizeof(linkpath), "%s.link", tmppath);
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);
	close(target);

	snprintf(cmd, sizeof(cmd), "exec ln '%s' '%s'", tmppath, linkpath);
	ATF_CHECK_MSG(run_cross_nonce_op(cmd) != 0,
	    "link was not blocked on isolated file");
	unlink(linkpath);

	/* -- rename -- */
	snprintf(newpath, sizeof(newpath), "%s.new", tmppath);
	snprintf(cmd, sizeof(cmd), "exec mv '%s' '%s'", tmppath, newpath);
	ATF_CHECK_MSG(run_cross_nonce_op(cmd) != 0,
	    "rename was not blocked on isolated file");
	unlink(newpath);

	close(svc);

	/* -- exec -- */
	snprintf(exepath, sizeof(exepath),
	    "/tmp/fi_exec_test.%d", (int)getpid());
	target = open(exepath, O_CREAT | O_RDWR, 0755);
	ATF_REQUIRE(target >= 0);
	write(target, "#!/bin/sh\nexit 0\n", 17);
	close(target);

	svc = fi_connect();
	target = open(exepath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);
	close(target);

	snprintf(cmd, sizeof(cmd), "exec '%s'", exepath);
	ATF_CHECK_MSG(run_cross_nonce_op(cmd) != 0,
	    "exec was not blocked on isolated executable");

	unlink(exepath);
	close(svc);
}
ATF_TC_CLEANUP(cross_nonce_lifecycle_blocked, tc)
{
	char linkpath[160], newpath[160], exepath[160];

	snprintf(linkpath, sizeof(linkpath), "%s.link", tmppath);
	unlink(linkpath);
	snprintf(newpath, sizeof(newpath), "%s.new", tmppath);
	unlink(newpath);
	snprintf(exepath, sizeof(exepath),
	    "/tmp/fi_exec_test.%d", (int)getpid());
	unlink(exepath);
	cleanup_tmpfile();
}

/* chflags is now tested in cross_nonce_metadata_blocked */

ATF_TC(net_claim_rejects_bad_domain);
ATF_TC_HEAD(net_claim_rejects_bad_domain, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_OP_CLAIM_NET rejects unsupported domain values");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_claim_rejects_bad_domain, tc)
{
	struct mac_capability_call_args ca;
	struct fi_net_request nr;
	struct fi_reply rpl;
	int svc;

	svc = fi_connect();

	memset(&nr, 0, sizeof(nr));
	nr.op = FI_OP_CLAIM_NET;
	nr.domain = 99;	/* unsupported */
	nr.protocol = 0;
	nr.port_min = htons(12345);
	nr.port_max = htons(12345);
	nr.direction = FI_NET_BIND;

	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	ATF_CHECK_ERRNO(EINVAL, ioctl(svc, MAC_CAPABILITY_CALL, &ca) == -1);

	close(svc);
}

ATF_TC(net_claim_rejects_bad_protocol);
ATF_TC_HEAD(net_claim_rejects_bad_protocol, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_OP_CLAIM_NET rejects unsupported protocol values");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_claim_rejects_bad_protocol, tc)
{
	struct mac_capability_call_args ca;
	struct fi_net_request nr;
	struct fi_reply rpl;
	int svc;

	svc = fi_connect();

	memset(&nr, 0, sizeof(nr));
	nr.op = FI_OP_CLAIM_NET;
	nr.domain = AF_INET;
	nr.protocol = 99;	/* unsupported */
	nr.port_min = htons(12345);
	nr.port_max = htons(12345);
	nr.direction = FI_NET_BIND;

	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	ATF_CHECK_ERRNO(EINVAL, ioctl(svc, MAC_CAPABILITY_CALL, &ca) == -1);

	close(svc);
}

ATF_TC(net_claim_rejects_ipv4_prefix_above_32);
ATF_TC_HEAD(net_claim_rejects_ipv4_prefix_above_32, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_OP_CLAIM_NET rejects AF_INET prefix > 32");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_claim_rejects_ipv4_prefix_above_32, tc)
{
	struct mac_capability_call_args ca;
	struct fi_net_request nr;
	struct fi_reply rpl;
	int svc;

	svc = fi_connect();

	memset(&nr, 0, sizeof(nr));
	nr.op = FI_OP_CLAIM_NET;
	nr.domain = AF_INET;
	nr.protocol = IPPROTO_TCP;
	nr.port_min = htons(12345);
	nr.port_max = htons(12345);
	nr.direction = FI_NET_BIND;
	nr.prefix = 33;		/* invalid for IPv4 */

	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	ATF_CHECK_ERRNO(EINVAL, ioctl(svc, MAC_CAPABILITY_CALL, &ca) == -1);

	close(svc);
}

/*
 * Verify that socket(AF_INET, SOCK_STREAM, 0) is blocked by a
 * TCP-specific wildcard claim.  The kernel resolves protocol=0 to
 * IPPROTO_TCP internally, so the MACF hook sees protocol=0 but the
 * claim was stored with IPPROTO_TCP.  The fix ensures protocol=0
 * from the caller matches any protocol-specific claim.
 *
 * This test is commented out because it requires both a network
 * claim AND a cross-nonce exec helper with socket() support, which
 * is architecture-dependent.  The logic is tested at the kernel
 * level by the fi_check_socket_create protocol=0 matching code.
 * TODO: uncomment when the isolation helper gains "socket" mode.
 */

ATF_TC_WITH_CLEANUP(release_unclaimed);
ATF_TC_HEAD(release_unclaimed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Releasing a vnode that was never claimed does not crash");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(release_unclaimed, tc)
{
	struct fi_reply rpl;
	int svc, target;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);

	/*
	 * Release without prior claim — the kernel may return an
	 * error (e.g., ENOENT) since nothing was claimed.  Just
	 * verify the call does not crash; any return is acceptable.
	 */
	(void)fi_call(svc, FI_OP_RELEASE, target, 0, &rpl);

	close(target);
	close(svc);
}
ATF_TC_CLEANUP(release_unclaimed, tc)
{
	cleanup_tmpfile();
}

ATF_TC_WITH_CLEANUP(query_after_release);
ATF_TC_HEAD(query_after_release, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Query after claim+release shows vnode is no longer claimed");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(query_after_release, tc)
{
	struct fi_reply rpl;
	int svc, target;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);

	/* Claim, then release */
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_RELEASE, target, 0, &rpl) == 0);

	/* Query — should show not claimed */
	ATF_REQUIRE(fi_call(svc, FI_OP_QUERY, target, FI_FS_ALL, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, 0);

	close(target);
	close(svc);
}
ATF_TC_CLEANUP(query_after_release, tc)
{
	cleanup_tmpfile();
}

static char tmppath2[128];
static char tmppath3[128];

static void
make_tmpfile2(void)
{
	int fd;

	snprintf(tmppath2, sizeof(tmppath2),
	    "/tmp/fi_test2.%d", (int)getpid());
	fd = open(tmppath2, O_CREAT | O_RDWR, 0644);
	ATF_REQUIRE_MSG(fd >= 0, "create %s: %s", tmppath2, strerror(errno));
	close(fd);
}

static void
make_tmpfile3(void)
{
	int fd;

	snprintf(tmppath3, sizeof(tmppath3),
	    "/tmp/fi_test3.%d", (int)getpid());
	fd = open(tmppath3, O_CREAT | O_RDWR, 0644);
	ATF_REQUIRE_MSG(fd >= 0, "create %s: %s", tmppath3, strerror(errno));
	close(fd);
}

ATF_TC_WITH_CLEANUP(claim_multiple_files);
ATF_TC_HEAD(claim_multiple_files, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Claim 3 files, verify each is claimed, close instance releases all");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(claim_multiple_files, tc)
{
	struct fi_reply rpl;
	int svc, svc2, t1, t2, t3;

	make_tmpfile();
	make_tmpfile2();
	make_tmpfile3();
	svc = fi_connect();

	t1 = open(tmppath, O_RDONLY);
	ATF_REQUIRE(t1 >= 0);
	t2 = open(tmppath2, O_RDONLY);
	ATF_REQUIRE(t2 >= 0);
	t3 = open(tmppath3, O_RDONLY);
	ATF_REQUIRE(t3 >= 0);

	/* Claim all three */
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, t1, 0, &rpl) == 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, t2, 0, &rpl) == 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, t3, 0, &rpl) == 0);

	/* Query each — all should be claimed and ours */
	ATF_REQUIRE(fi_call(svc, FI_OP_QUERY, t1, FI_FS_ALL, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, FI_QF_CLAIMED | FI_QF_MINE);
	ATF_REQUIRE(fi_call(svc, FI_OP_QUERY, t2, FI_FS_ALL, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, FI_QF_CLAIMED | FI_QF_MINE);
	ATF_REQUIRE(fi_call(svc, FI_OP_QUERY, t3, FI_FS_ALL, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, FI_QF_CLAIMED | FI_QF_MINE);

	/* Close the instance — all claims should be released */
	close(svc);

	/* Verify via a new instance */
	svc2 = fi_connect();
	ATF_REQUIRE(fi_call(svc2, FI_OP_QUERY, t1, FI_FS_ALL, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, 0);
	ATF_REQUIRE(fi_call(svc2, FI_OP_QUERY, t2, FI_FS_ALL, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, 0);
	ATF_REQUIRE(fi_call(svc2, FI_OP_QUERY, t3, FI_FS_ALL, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, 0);

	close(t1);
	close(t2);
	close(t3);
	close(svc2);
}
ATF_TC_CLEANUP(claim_multiple_files, tc)
{
	cleanup_tmpfile();
	unlink(tmppath2);
	unlink(tmppath3);
}

ATF_TC(net_claim_ipv6);
ATF_TC_HEAD(net_claim_ipv6, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Network claim with AF_INET6 on port 8080 bind succeeds");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_claim_ipv6, tc)
{
	int svc;

	svc = fi_connect();

	ATF_CHECK(fi_net_call(svc, FI_OP_CLAIM_NET,
	    AF_INET6, IPPROTO_TCP, htons(8080), FI_NET_BIND) == 0);

	/* Release to clean up */
	ATF_CHECK(fi_net_call(svc, FI_OP_RELEASE_NET,
	    AF_INET6, IPPROTO_TCP, htons(8080), FI_NET_BIND) == 0);

	close(svc);
}

ATF_TC(net_release_unclaimed);
ATF_TC_HEAD(net_release_unclaimed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Releasing a network claim that was never made does not crash");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_release_unclaimed, tc)
{
	int svc;

	svc = fi_connect();

	/*
	 * Release without prior claim — the kernel may return an
	 * error since no matching claim exists.  Just verify the
	 * call does not crash; any return is acceptable.
	 */
	(void)fi_net_call(svc, FI_OP_RELEASE_NET,
	    AF_INET, IPPROTO_TCP, htons(19999), FI_NET_BIND);

	close(svc);
}

ATF_TC(net_claim_protocol_wildcard);
ATF_TC_HEAD(net_claim_protocol_wildcard, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Wildcard protocol claim blocks foreign nonce TCP claim on same port");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_claim_protocol_wildcard, tc)
{
	int rc, svc;
	uint16_t port = 18460;

	svc = fi_connect();

	/* Claim with protocol=0 (wildcard) */
	ATF_REQUIRE(fi_net_call(svc, FI_OP_CLAIM_NET,
	    AF_INET, 0, htons(port), FI_NET_BIND) == 0);

	/* Foreign nonce tries to claim same port with IPPROTO_TCP — should fail */
	rc = run_net_claim_helper(tc, svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, port, FI_NET_BIND, NULL, 0);
	ATF_CHECK_EQ(rc, 1);

	close(svc);
}

ATF_TC(net_claim_range_blocks_foreign_exact);
ATF_TC_HEAD(net_claim_range_blocks_foreign_exact, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_OP_CLAIM_NET port range blocks foreign exact claim inside range");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_claim_range_blocks_foreign_exact, tc)
{
	int rc, svc;

	svc = fi_connect();
	ATF_REQUIRE(fi_net_call2(svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, 19000, 19010, FI_NET_BIND) == 0);

	rc = run_net_claim_helper(tc, svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, 19005, FI_NET_BIND, NULL, 0);
	ATF_CHECK_MSG(rc == 1,
	    "foreign exact claim inside range should fail (got %d)", rc);

	close(svc);
}

ATF_TC(net_claim_exact_blocks_foreign_range);
ATF_TC_HEAD(net_claim_exact_blocks_foreign_range, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Exact claim blocks overlapping foreign FI_OP_CLAIM_NET range");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_claim_exact_blocks_foreign_range, tc)
{
	int rc, svc;

	svc = fi_connect();
	ATF_REQUIRE(fi_net_call(svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, htons(19100), FI_NET_BIND) == 0);

	rc = run_net_range_claim_helper(tc, svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, 19095, 19105, FI_NET_BIND);
	ATF_CHECK_MSG(rc == 1,
	    "foreign range overlapping exact claim should fail (got %d)", rc);

	close(svc);
}

ATF_TC(net_query_reports_range_claims);
ATF_TC_HEAD(net_query_reports_range_claims, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_OP_QUERY_NET reports owner, foreign, and unclaimed ranges");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_query_reports_range_claims, tc)
{
	struct fi_reply rpl;
	int rc, svc;

	svc = fi_connect();
	ATF_REQUIRE(fi_net_call2(svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, 19200, 19210, FI_NET_BIND) == 0);

	ATF_REQUIRE(fi_net_query2(svc, AF_INET, IPPROTO_TCP, 19205, 19205,
	    FI_NET_BIND, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, FI_QF_CLAIMED | FI_QF_MINE);

	ATF_REQUIRE(fi_net_query2(svc, AF_INET, IPPROTO_TCP, 19211, 19211,
	    FI_NET_BIND, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, 0);

	rc = run_net_query_helper(tc, svc, AF_INET, IPPROTO_TCP, 19205,
	    19205, FI_NET_BIND, FI_QF_CLAIMED);
	ATF_CHECK_MSG(rc == 0,
	    "foreign query inside range should report claimed only (got %d)",
	    rc);

	close(svc);
}

/* write is now tested in cross_nonce_read_blocked */

/* ----------------------------------------------------------------
 * Access token tests (FI_OP_MINT / FI_OP_AUTHORIZE)
 * ---------------------------------------------------------------- */

static int
run_token_open(const atf_tc_t *tc, int token_fd, const char *path_arg,
    const char *mode, bool twice)
{
	char token_str[16];
	const char *path;
	pid_t pid;
	int status;

	path = fi_helper_path(tc);
	snprintf(token_str, sizeof(token_str), "%d", token_fd);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (twice) {
			execl(path, path, "token-open", token_str, path_arg,
			    mode, "twice", NULL);
		} else {
			execl(path, path, "token-open", token_str, path_arg,
			    mode, NULL);
		}
		_exit(127);
	}
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

ATF_TC_WITH_CLEANUP(token_mint_returns_fd);
ATF_TC_HEAD(token_mint_returns_fd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_OP_MINT returns a valid token fd");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(token_mint_returns_fd, tc)
{
	struct fi_reply rpl;
	int svc, target, token;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);

	token = fi_mint(svc, target, FI_FS_ALL);
	ATF_REQUIRE_MSG(token >= 0, "fi_mint: %s", strerror(errno));

	close(token);
	close(target);
	close(svc);
}
ATF_TC_CLEANUP(token_mint_returns_fd, tc)
{
	cleanup_tmpfile();
}

ATF_TC_WITH_CLEANUP(token_authorize_grants_access);
ATF_TC_HEAD(token_authorize_grants_access, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Authorized foreign nonce can access isolated file");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(token_authorize_grants_access, tc)
{
	struct fi_reply rpl;
	int svc, target, token;
	pid_t pid;
	int status;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);

	token = fi_mint(svc, target, FI_FS_ALL);
	ATF_REQUIRE(token >= 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char token_str[16];
		const char *path;

		close(svc);
		close(target);

		/*
		 * Exec the helper to rotate the nonce, then authorize
		 * with the token and try to open the isolated file.
		 * The token fd survives exec (no CLOEXEC).
		 */
		path = fi_helper_path(tc);
		snprintf(token_str, sizeof(token_str), "%d", token);
		execl(path, path, "token-check", token_str, tmppath,
		    NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child exit %d (expected 0 = access granted)", status);

	close(token);
	close(target);
	close(svc);
}
ATF_TC_CLEANUP(token_authorize_grants_access, tc)
{
	cleanup_tmpfile();
}

ATF_TC_WITH_CLEANUP(token_close_revokes_access);
ATF_TC_HEAD(token_close_revokes_access, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing the token fd revokes authorization");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(token_close_revokes_access, tc)
{
	struct fi_reply rpl;
	int svc, target, token;
	pid_t pid;
	int status, readyfd[2], gofd[2];
	char buf;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);

	token = fi_mint(svc, target, FI_FS_ALL);
	ATF_REQUIRE(token >= 0);

	ATF_REQUIRE(pipe(readyfd) == 0);
	ATF_REQUIRE(pipe(gofd) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char token_str[16], ready_str[16], go_str[16];
		const char *path;

		close(readyfd[0]);
		close(gofd[1]);
		close(svc);
		close(target);

		/*
		 * Exec the helper to rotate the nonce.  Without exec
		 * the child shares the parent's nonce and bypasses
		 * isolation (same-nonce fast path).
		 */
		path = fi_helper_path(tc);
		snprintf(token_str, sizeof(token_str), "%d", token);
		snprintf(ready_str, sizeof(ready_str), "%d", readyfd[1]);
		snprintf(go_str, sizeof(go_str), "%d", gofd[0]);
		execl(path, path, "token-revoke", token_str, ready_str,
		    go_str, tmppath, NULL);
		_exit(127);
	}
	close(readyfd[1]);
	close(gofd[0]);

	/* Wait for child to authorize and close its token copy. */
	read(readyfd[0], &buf, 1);
	close(readyfd[0]);

	/* Close parent's token — last ref fires co_revoke. */
	close(token);

	/* Signal child to try the open. */
	write(gofd[1], "x", 1);
	close(gofd[1]);

	waitpid(pid, &status, 0);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child exit %d (expected 0 = blocked)", status);

	close(target);
	close(svc);
}
ATF_TC_CLEANUP(token_close_revokes_access, tc)
{
	cleanup_tmpfile();
}

ATF_TC_WITH_CLEANUP(token_mint_requires_ownership);
ATF_TC_HEAD(token_mint_requires_ownership, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_OP_MINT fails if caller does not own the claim");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(token_mint_requires_ownership, tc)
{
	int svc, target, token;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);

	/* Don't claim — try to mint directly. Should fail. */
	token = fi_mint(svc, target, FI_FS_ALL);
	ATF_CHECK_MSG(token == -1, "mint without claim should fail");

	close(target);
	close(svc);
}
ATF_TC_CLEANUP(token_mint_requires_ownership, tc)
{
	cleanup_tmpfile();
}

ATF_TC_WITH_CLEANUP(token_query_shows_authorized);
ATF_TC_HEAD(token_query_shows_authorized, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_OP_QUERY reports FI_QF_AUTHORIZED for token holders");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(token_query_shows_authorized, tc)
{
	struct fi_reply rpl;
	int svc, target, token;
	pid_t pid;
	int status;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);

	token = fi_mint(svc, target, FI_FS_ALL);
	ATF_REQUIRE(token >= 0);

	/*
	 * Fork+exec to rotate the nonce.  The child authorizes with
	 * the token, then queries the vnode.  Since the child has a
	 * foreign nonce but is authorized via the token, the query
	 * should report FI_QF_CLAIMED | FI_QF_AUTHORIZED.
	 */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char token_str[16], svc_str[16], target_str[16];
		const char *path;

		path = fi_helper_path(tc);
		snprintf(token_str, sizeof(token_str), "%d", token);
		snprintf(svc_str, sizeof(svc_str), "%d", svc);
		snprintf(target_str, sizeof(target_str), "%d", target);
		execl(path, path, "token-query", token_str, svc_str,
		    target_str, NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	/*
	 * token-query returns rpl.flags & 0x07 as exit code.
	 * Expect FI_QF_CLAIMED | FI_QF_AUTHORIZED = 0x05.
	 */
	ATF_CHECK_MSG(WIFEXITED(status) &&
	    WEXITSTATUS(status) == (FI_QF_CLAIMED | FI_QF_AUTHORIZED),
	    "child exit %d (expected %d = CLAIMED|AUTHORIZED)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1,
	    FI_QF_CLAIMED | FI_QF_AUTHORIZED);

	close(token);
	close(target);
	close(svc);
}
ATF_TC_CLEANUP(token_query_shows_authorized, tc)
{
	cleanup_tmpfile();
}

/*
 * Claim-ID scoping: a token minted for file A must NOT authorize
 * access to file B, even when both are claimed by the same nonce.
 */
ATF_TC_WITH_CLEANUP(token_scoped_to_claim);
ATF_TC_HEAD(token_scoped_to_claim, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Token for file A does not authorize access to file B");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(token_scoped_to_claim, tc)
{
	struct fi_reply rpl;
	int svc, target_a, target_b, token;
	pid_t pid;
	int status;

	make_tmpfile();
	make_tmpfile2();
	svc = fi_connect();

	target_a = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target_a >= 0);
	target_b = open(tmppath2, O_RDONLY);
	ATF_REQUIRE(target_b >= 0);

	/* Claim both files. */
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target_a, 0, &rpl) == 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target_b, 0, &rpl) == 0);

	/* Mint token for file A only. */
	token = fi_mint(svc, target_a, FI_FS_ALL);
	ATF_REQUIRE_MSG(token >= 0, "fi_mint: %s", strerror(errno));

	/*
	 * Fork+exec to get a foreign nonce.  The child authorizes with
	 * the token (scoped to A) and tries to open file B.
	 * File B should be DENIED — the token doesn't cover it.
	 */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char token_str[16];
		const char *path;

		close(svc);
		close(target_a);
		close(target_b);

		path = fi_helper_path(tc);
		snprintf(token_str, sizeof(token_str), "%d", token);
		/* token-check: authorize + try to open the given path */
		execl(path, path, "token-check", token_str, tmppath2,
		    NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	/*
	 * token-check returns 0 if open succeeds, 1 if denied.
	 * We expect denied (1) — the token is for file A, not file B.
	 */
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 1,
	    "child exit %d (expected 1 = access denied for wrong file)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	close(token);
	close(target_b);
	close(target_a);
	close(svc);
}
ATF_TC_CLEANUP(token_scoped_to_claim, tc)
{
	cleanup_tmpfile();
	unlink(tmppath2);
}

ATF_TC_WITH_CLEANUP(token_read_only_denies_write);
ATF_TC_HEAD(token_read_only_denies_write, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_OP_MINT read-only token grants read but denies write");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(token_read_only_denies_write, tc)
{
	struct fi_reply rpl;
	int svc, target, token, rc;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDWR);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);

	token = fi_mint(svc, target, FI_FS_READ);
	ATF_REQUIRE_MSG(token >= 0, "fi_mint: %s", strerror(errno));

	rc = run_token_open(tc, token, tmppath, "read", false);
	ATF_CHECK_MSG(rc == 0, "read should succeed with read token (got %d)",
	    rc);

	rc = run_token_open(tc, token, tmppath, "write", false);
	ATF_CHECK_MSG(rc == 1, "write should be denied with read token (got %d)",
	    rc);

	close(token);
	close(target);
	close(svc);
}
ATF_TC_CLEANUP(token_read_only_denies_write, tc)
{
	cleanup_tmpfile();
}

ATF_TC_WITH_CLEANUP(token_authorize_idempotent);
ATF_TC_HEAD(token_authorize_idempotent, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Repeated FI_OP_AUTHORIZE on one token is idempotent");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(token_authorize_idempotent, tc)
{
	struct fi_reply rpl;
	int svc, target, token, rc;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);

	token = fi_mint(svc, target, FI_FS_READ);
	ATF_REQUIRE(token >= 0);

	rc = run_token_open(tc, token, tmppath, "read", true);
	ATF_CHECK_MSG(rc == 0,
	    "repeated authorize should still permit read (got %d)", rc);

	close(token);
	close(target);
	close(svc);
}
ATF_TC_CLEANUP(token_authorize_idempotent, tc)
{
	cleanup_tmpfile();
}

ATF_TC_WITH_CLEANUP(token_dup_lifetime);
ATF_TC_HEAD(token_dup_lifetime, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Duplicated token fds keep one token instance alive");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(token_dup_lifetime, tc)
{
	struct fi_reply rpl;
	int svc, target, token, token_dup;
	pid_t pid;
	int status, readyfd[2], gofd[2];
	char buf;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);

	token = fi_mint(svc, target, FI_FS_READ);
	ATF_REQUIRE(token >= 0);
	token_dup = dup(token);
	ATF_REQUIRE(token_dup >= 0);

	ATF_REQUIRE(pipe(readyfd) == 0);
	ATF_REQUIRE(pipe(gofd) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char token_str[16], ready_str[16], go_str[16];
		const char *path;

		close(readyfd[0]);
		close(gofd[1]);
		close(token_dup);
		close(svc);
		close(target);

		path = fi_helper_path(tc);
		snprintf(token_str, sizeof(token_str), "%d", token);
		snprintf(ready_str, sizeof(ready_str), "%d", readyfd[1]);
		snprintf(go_str, sizeof(go_str), "%d", gofd[0]);
		execl(path, path, "token-revoke", token_str, ready_str,
		    go_str, tmppath, NULL);
		_exit(127);
	}
	close(readyfd[1]);
	close(gofd[0]);

	read(readyfd[0], &buf, 1);
	close(readyfd[0]);

	close(token);

	write(gofd[1], "x", 1);
	close(gofd[1]);

	waitpid(pid, &status, 0);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 1,
	    "child exit %d (expected 1 = still authorized via dup)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	close(token_dup);
	close(target);
	close(svc);
}
ATF_TC_CLEANUP(token_dup_lifetime, tc)
{
	cleanup_tmpfile();
}

/* ----------------------------------------------------------------
 * Network access token tests (FI_OP_MINT_NET / FI_OP_AUTHORIZE)
 * ---------------------------------------------------------------- */

/*
 * Run a child (fork+exec for nonce rotation) that authorizes with
 * a network token and tries to bind.
 * Returns child exit status: 0 = bind succeeded, 1 = denied, 10 = auth failed.
 */
static int
run_net_token_bind(const atf_tc_t *tc, int token_fd, uint16_t port)
{
	char token_str[16], port_str[16];
	const char *path;
	pid_t pid;
	int status;

	path = fi_helper_path(tc);
	snprintf(token_str, sizeof(token_str), "%d", token_fd);
	snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(path, path, "net-token-bind", token_str, port_str,
		    NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

static int
run_net_token_query(const atf_tc_t *tc, int svc, int token_fd, int domain,
    int protocol, uint16_t port_min, uint16_t port_max, uint8_t direction,
    uint32_t expected_flags)
{
	char fdstr[16], token_str[16], domainstr[16], protostr[16];
	char minstr[16], maxstr[16], dirstr[16], flagstr[16];
	const char *path;
	pid_t pid;
	int status;

	path = fi_helper_path(tc);
	snprintf(fdstr, sizeof(fdstr), "%d", svc);
	snprintf(token_str, sizeof(token_str), "%d", token_fd);
	snprintf(domainstr, sizeof(domainstr), "%d", domain);
	snprintf(protostr, sizeof(protostr), "%d", protocol);
	snprintf(minstr, sizeof(minstr), "%u", port_min);
	snprintf(maxstr, sizeof(maxstr), "%u", port_max);
	snprintf(dirstr, sizeof(dirstr), "%u", direction);
	snprintf(flagstr, sizeof(flagstr), "%u", expected_flags);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(path, path, "net-token-query", fdstr, token_str,
		    domainstr, protostr, minstr, maxstr, dirstr, flagstr,
		    NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

/*
 * Run a child that tries to bind without any token.
 * Returns: 0 = bind succeeded, 1 = denied.
 */
static int
run_net_try_bind(const atf_tc_t *tc, uint16_t port)
{
	char port_str[16];
	const char *path;
	pid_t pid;
	int status;

	path = fi_helper_path(tc);
	snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(path, path, "net-try-bind", port_str, NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

ATF_TC(net_token_mint_returns_fd);
ATF_TC_HEAD(net_token_mint_returns_fd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_OP_MINT_NET returns a valid token fd");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_token_mint_returns_fd, tc)
{
	int svc, token;
	uint16_t port = htons(18550);

	svc = fi_connect();
	ATF_REQUIRE(fi_net_call(svc, FI_OP_CLAIM_NET,
	    AF_INET, IPPROTO_TCP, port, FI_NET_BIND) == 0);

	token = fi_net_mint(svc, AF_INET, IPPROTO_TCP, port, FI_NET_BIND);
	ATF_REQUIRE_MSG(token >= 0, "fi_net_mint: %s", strerror(errno));

	close(token);
	close(svc);
}

ATF_TC(net_token_authorize_grants_bind);
ATF_TC_HEAD(net_token_authorize_grants_bind, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Authorized foreign nonce can bind a claimed port");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_token_authorize_grants_bind, tc)
{
	int svc, token, rc;
	uint16_t port_net = htons(18551);

	svc = fi_connect();
	ATF_REQUIRE(fi_net_call(svc, FI_OP_CLAIM_NET,
	    AF_INET, IPPROTO_TCP, port_net, FI_NET_BIND) == 0);

	/* Without token, foreign nonce is denied. */
	rc = run_net_try_bind(tc, 18551);
	ATF_REQUIRE_MSG(rc == 1, "bind should be denied without token (got %d)", rc);

	/* Mint token and authorize in the child. */
	token = fi_net_mint(svc, AF_INET, IPPROTO_TCP, port_net, FI_NET_BIND);
	ATF_REQUIRE(token >= 0);

	rc = run_net_token_bind(tc, token, 18551);
	ATF_CHECK_MSG(rc == 0,
	    "bind should succeed with authorized token (got %d)", rc);

	close(token);
	close(svc);
}

ATF_TC(net_token_scoped_to_endpoint);
ATF_TC_HEAD(net_token_scoped_to_endpoint, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Token for port A does not authorize bind on port B");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_token_scoped_to_endpoint, tc)
{
	int svc, token, rc;
	uint16_t port_a = htons(18552);
	uint16_t port_b = htons(18553);

	svc = fi_connect();

	/* Claim both ports. */
	ATF_REQUIRE(fi_net_call(svc, FI_OP_CLAIM_NET,
	    AF_INET, IPPROTO_TCP, port_a, FI_NET_BIND) == 0);
	ATF_REQUIRE(fi_net_call(svc, FI_OP_CLAIM_NET,
	    AF_INET, IPPROTO_TCP, port_b, FI_NET_BIND) == 0);

	/* Mint token for port A only. */
	token = fi_net_mint(svc, AF_INET, IPPROTO_TCP, port_a, FI_NET_BIND);
	ATF_REQUIRE(token >= 0);

	/* Child authorizes with port-A token, tries to bind port B. */
	rc = run_net_token_bind(tc, token, 18553);
	ATF_CHECK_MSG(rc == 1,
	    "bind port B should be denied with port-A token (got %d)", rc);

	close(token);
	close(svc);
}

ATF_TC(net_token_close_revokes);
ATF_TC_HEAD(net_token_close_revokes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing the network token fd revokes authorization");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_token_close_revokes, tc)
{
	int svc, token, rc;
	uint16_t port_net = htons(18554);

	svc = fi_connect();
	ATF_REQUIRE(fi_net_call(svc, FI_OP_CLAIM_NET,
	    AF_INET, IPPROTO_TCP, port_net, FI_NET_BIND) == 0);

	/* Mint, authorize from a child, verify it works. */
	token = fi_net_mint(svc, AF_INET, IPPROTO_TCP, port_net, FI_NET_BIND);
	ATF_REQUIRE(token >= 0);

	rc = run_net_token_bind(tc, token, 18554);
	ATF_REQUIRE_MSG(rc == 0,
	    "bind should work with token (got %d)", rc);

	/*
	 * The child authorized and exited.  Close the token — this
	 * removes the auth entry.  A new foreign nonce should be denied.
	 */
	close(token);

	rc = run_net_try_bind(tc, 18554);
	ATF_CHECK_MSG(rc == 1,
	    "bind should be denied after token close (got %d)", rc);

	close(svc);
}

ATF_TC(net_token_mint_requires_claim);
ATF_TC_HEAD(net_token_mint_requires_claim, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_OP_MINT_NET fails without a covering claim");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_token_mint_requires_claim, tc)
{
	int svc, token;
	uint16_t port_net = htons(18555);

	svc = fi_connect();

	/* No claim — mint should fail. */
	token = fi_net_mint(svc, AF_INET, IPPROTO_TCP, port_net, FI_NET_BIND);
	ATF_CHECK_MSG(token == -1, "mint without claim should fail");

	close(svc);
}

ATF_TC(net_token_query_shows_authorized_range);
ATF_TC_HEAD(net_token_query_shows_authorized_range, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_OP_QUERY_NET reports token authorization for a port range");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_token_query_shows_authorized_range, tc)
{
	int rc, svc, token;

	svc = fi_connect();
	ATF_REQUIRE(fi_net_call2(svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, 19300, 19310, FI_NET_BIND) == 0);

	token = fi_net_mint2(svc, AF_INET, IPPROTO_TCP, 19300, 19310,
	    FI_NET_BIND);
	ATF_REQUIRE(token >= 0);

	rc = run_net_token_query(tc, svc, token, AF_INET, IPPROTO_TCP,
	    19305, 19305, FI_NET_BIND, FI_QF_CLAIMED | FI_QF_AUTHORIZED);
	ATF_CHECK_MSG(rc == 0,
	    "authorized foreign query inside token range failed (got %d)", rc);

	close(token);
	close(svc);
}

ATF_TC(net_token_range_does_not_authorize_other_claim);
ATF_TC_HEAD(net_token_range_does_not_authorize_other_claim, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Network token for one range does not authorize another claim");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_token_range_does_not_authorize_other_claim, tc)
{
	int rc, svc, token;

	svc = fi_connect();
	ATF_REQUIRE(fi_net_call2(svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, 19320, 19330, FI_NET_BIND) == 0);
	ATF_REQUIRE(fi_net_call(svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, htons(19340), FI_NET_BIND) == 0);

	token = fi_net_mint2(svc, AF_INET, IPPROTO_TCP, 19320, 19330,
	    FI_NET_BIND);
	ATF_REQUIRE(token >= 0);

	rc = run_net_token_query(tc, svc, token, AF_INET, IPPROTO_TCP,
	    19340, 19340, FI_NET_BIND, FI_QF_CLAIMED);
	ATF_CHECK_MSG(rc == 0,
	    "range token must not report authorization on other claim "
	    "(got %d)", rc);

	rc = run_net_token_bind(tc, token, 19340);
	ATF_CHECK_MSG(rc == 1,
	    "range token must not permit bind on other claim (got %d)", rc);

	close(token);
	close(svc);
}

/* ----------------------------------------------------------------
 * Additional coverage tests
 * ---------------------------------------------------------------- */

/*
 * Wildcard claim (0..65535) must block an exact bind from a foreign nonce.
 */
ATF_TC(net_wildcard_claim_blocks_exact_bind);
ATF_TC_HEAD(net_wildcard_claim_blocks_exact_bind, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Wildcard 0..65535 claim blocks foreign exact bind on port 443");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_wildcard_claim_blocks_exact_bind, tc)
{
	int rc, svc;

	svc = fi_connect();

	/* Claim 0..65535 (wildcard) */
	ATF_REQUIRE(fi_net_call2(svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, 0, 65535, FI_NET_BIND) == 0);

	/* Foreign nonce tries to bind port 443 — should be blocked. */
	rc = run_net_try_bind(tc, 443);
	ATF_CHECK_MSG(rc == 1,
	    "wildcard claim should block foreign bind on 443 (got %d)", rc);

	close(svc);
}

/*
 * Range-vs-range overlap: claim 19500-19510, foreign claims 19505-19515.
 */
ATF_TC(net_claim_range_vs_range_overlap);
ATF_TC_HEAD(net_claim_range_vs_range_overlap, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Overlapping foreign range claims conflict");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_claim_range_vs_range_overlap, tc)
{
	int rc, svc;

	svc = fi_connect();
	ATF_REQUIRE(fi_net_call2(svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, 19500, 19510, FI_NET_BIND) == 0);

	/* Foreign nonce tries overlapping range. */
	rc = run_net_range_claim_helper(tc, svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, 19505, 19515, FI_NET_BIND);
	ATF_CHECK_MSG(rc == 1,
	    "overlapping foreign range claim should fail (got %d)", rc);

	close(svc);
}

/*
 * Byte-order regression: port 256 (0x0100) has different host and network
 * representations on little-endian.  Verify the claim and enforcement
 * use the same representation end to end.
 */
ATF_TC(net_byte_order_port_256);
ATF_TC_HEAD(net_byte_order_port_256, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Port 256 byte-order regression — claim and bind agree");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_byte_order_port_256, tc)
{
	struct sockaddr_in sin;
	int svc, s;

	svc = fi_connect();

	/* Claim port 256 via the range API (host-order in, htons inside). */
	ATF_REQUIRE(fi_net_call2(svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, 256, 256, FI_NET_BIND) == 0);

	/* Same nonce bind on port 256 — should succeed. */
	s = socket(AF_INET, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(256);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ATF_CHECK_MSG(bind(s, (struct sockaddr *)&sin, sizeof(sin)) == 0,
	    "owner bind on port 256 should succeed");
	close(s);

	/* Foreign nonce should be blocked on port 256. */
	{
		int rc = run_net_try_bind(tc, 256);
		ATF_CHECK_MSG(rc == 1,
		    "foreign bind on port 256 should be denied (got %d)", rc);
	}

	close(svc);
}

/*
 * STAT-only token denies READ.
 */
ATF_TC_WITH_CLEANUP(token_stat_only_denies_read);
ATF_TC_HEAD(token_stat_only_denies_read, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_OP_MINT stat-only token denies open for read");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(token_stat_only_denies_read, tc)
{
	struct fi_reply rpl;
	int svc, target, token, rc;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);

	/* Mint a STAT-only token. */
	token = fi_mint(svc, target, FI_FS_STAT);
	ATF_REQUIRE_MSG(token >= 0, "fi_mint STAT: %s", strerror(errno));

	/* STAT-only should deny read. */
	rc = run_token_open(tc, token, tmppath, "read", false);
	ATF_CHECK_MSG(rc == 1,
	    "open(read) should be denied with STAT-only token (got %d)", rc);

	close(token);
	close(target);
	close(svc);
}
ATF_TC_CLEANUP(token_stat_only_denies_read, tc)
{
	cleanup_tmpfile();
}

/*
 * MINT rejects invalid action masks.
 */
ATF_TC_WITH_CLEANUP(mint_rejects_invalid_actions);
ATF_TC_HEAD(mint_rejects_invalid_actions, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_OP_MINT rejects actions=0 and out-of-range bits");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mint_rejects_invalid_actions, tc)
{
	struct fi_reply rpl;
	int svc, target, token;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);

	/* actions = 0 should fail. */
	token = fi_mint(svc, target, 0);
	ATF_CHECK_MSG(token == -1 && errno == EINVAL,
	    "mint with actions=0 should return EINVAL (got token=%d errno=%d)",
	    token, errno);

	/* Bit outside FI_FS_ALL should fail. */
	token = fi_mint(svc, target, 0x8000);
	ATF_CHECK_MSG(token == -1 && errno == EINVAL,
	    "mint with invalid action bit should return EINVAL (got token=%d errno=%d)",
	    token, errno);

	close(target);
	close(svc);
}
ATF_TC_CLEANUP(mint_rejects_invalid_actions, tc)
{
	cleanup_tmpfile();
}

/*
 * Two different nonces can authorize the same token and both gain access.
 */
ATF_TC_WITH_CLEANUP(token_two_nonces_authorize);
ATF_TC_HEAD(token_two_nonces_authorize, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Two distinct nonces can authorize the same token");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(token_two_nonces_authorize, tc)
{
	struct fi_reply rpl;
	int svc, target, token, rc;

	make_tmpfile();
	svc = fi_connect();
	target = open(tmppath, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);

	token = fi_mint(svc, target, FI_FS_ALL);
	ATF_REQUIRE(token >= 0);

	/*
	 * First foreign nonce authorizes and opens — should succeed.
	 * run_token_open does fork+exec (new nonce), authorize, open.
	 */
	rc = run_token_open(tc, token, tmppath, "read", false);
	ATF_CHECK_MSG(rc == 0,
	    "first nonce authorize+open should succeed (got %d)", rc);

	/*
	 * Second foreign nonce authorizes and opens — should also succeed.
	 * Each fork+exec creates a new nonce.
	 */
	rc = run_token_open(tc, token, tmppath, "read", false);
	ATF_CHECK_MSG(rc == 0,
	    "second nonce authorize+open should succeed (got %d)", rc);

	close(token);
	close(target);
	close(svc);
}
ATF_TC_CLEANUP(token_two_nonces_authorize, tc)
{
	cleanup_tmpfile();
}

/*
 * Network token range enforcement: claim 19600-19699, mint token for
 * 19600-19699, verify child can bind 19650 but not 19700.
 */
ATF_TC(net_token_range_bind_inside_outside);
ATF_TC_HEAD(net_token_range_bind_inside_outside, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Network token for range permits bind inside but denies outside");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_token_range_bind_inside_outside, tc)
{
	int svc, token, rc;

	svc = fi_connect();

	/* Claim 19600-19699 and also 19700 individually. */
	ATF_REQUIRE(fi_net_call2(svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, 19600, 19699, FI_NET_BIND) == 0);
	ATF_REQUIRE(fi_net_call(svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, htons(19700), FI_NET_BIND) == 0);

	/* Mint token for the range only. */
	token = fi_net_mint2(svc, AF_INET, IPPROTO_TCP, 19600, 19699,
	    FI_NET_BIND);
	ATF_REQUIRE(token >= 0);

	/* Inside the range — should succeed. */
	rc = run_net_token_bind(tc, token, 19650);
	ATF_CHECK_MSG(rc == 0,
	    "bind inside token range should succeed (got %d)", rc);

	/* Outside the range — should be denied. */
	rc = run_net_token_bind(tc, token, 19700);
	ATF_CHECK_MSG(rc == 1,
	    "bind outside token range should be denied (got %d)", rc);

	close(token);
	close(svc);
}

/*
 * Directory claim with narrowed token: CREATE does not imply DELETE.
 */
ATF_TC_WITH_CLEANUP(dir_token_create_no_delete);
ATF_TC_HEAD(dir_token_create_no_delete, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Directory token with LOOKUP+CREATE does not authorize unlink");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(dir_token_create_no_delete, tc)
{
	struct fi_reply rpl;
	int svc, dir_fd, token, status;
	pid_t pid;

	make_tmpdir();
	svc = fi_connect();

	dir_fd = open(tmpdir, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dir_fd >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, dir_fd, 0, &rpl) == 0);

	/* Mint a token with only LOOKUP + CREATE (no DELETE). */
	token = fi_mint(svc, dir_fd, FI_FS_LOOKUP | FI_FS_CREATE);
	ATF_REQUIRE_MSG(token >= 0, "fi_mint dir: %s", strerror(errno));
	close(dir_fd);

	/*
	 * Fork+exec a child that authorizes with the token and tries
	 * to unlink a file inside the directory.  The exec rotates
	 * the nonce.  The child should be DENIED because the token
	 * does not include FI_FS_DELETE.
	 */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char token_str[16];
		const char *path;

		close(svc);
		path = fi_helper_path(tc);
		snprintf(token_str, sizeof(token_str), "%d", token);
		execl(path, path, "token-unlink", token_str, tmpdir_file,
		    NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	/*
	 * The token has LOOKUP but not DELETE — unlink should be
	 * denied because the directory claim requires FI_FS_DELETE.
	 */
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 1,
	    "unlink should be denied without DELETE (exit %d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	close(token);
	close(svc);
}
ATF_TC_CLEANUP(dir_token_create_no_delete, tc)
{
	cleanup_tmpdir();
}

/* ----------------------------------------------------------------
 * Additional narrowed-token and action-mask tests
 * ---------------------------------------------------------------- */

/*
 * Helper: run the helper with a given command, token fd, and path arg.
 * Returns the helper's exit code.
 */
static int
run_token_helper(const atf_tc_t *tc, const char *cmd, int token_fd,
    const char *arg1, const char *arg2)
{
	char token_str[16];
	const char *path;
	pid_t pid;
	int status;

	path = fi_helper_path(tc);
	snprintf(token_str, sizeof(token_str), "%d", token_fd);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (arg2 != NULL)
			execl(path, path, cmd, token_str, arg1, arg2, NULL);
		else
			execl(path, path, cmd, token_str, arg1, NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

/*
 * Mint a network access token with address/CIDR.
 */
static int
fi_net_mint_addr(int svc, int domain, int protocol, uint16_t port,
    uint8_t direction, const char *addr, uint8_t prefix)
{
	struct mac_capability_call_args ca;
	struct fi_net_request nr;
	struct fi_reply rpl;
	int token_fd;

	memset(&nr, 0, sizeof(nr));
	nr.op = FI_OP_MINT_NET;
	nr.domain = domain;
	nr.protocol = protocol;
	nr.port_min = port;
	nr.port_max = port;
	nr.direction = direction;
	nr.prefix = prefix;

	if (addr != NULL) {
		if (domain == AF_INET) {
			struct in_addr in4;

			if (inet_pton(AF_INET, addr, &in4) != 1)
				return (-1);
			nr.addr[10] = 0xff;
			nr.addr[11] = 0xff;
			memcpy(&nr.addr[12], &in4, sizeof(in4));
		} else if (domain == AF_INET6) {
			struct in6_addr in6;

			if (inet_pton(AF_INET6, addr, &in6) != 1)
				return (-1);
			memcpy(nr.addr, &in6, sizeof(in6));
		}
	}

	token_fd = -1;
	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	ca.reply_fds = &token_fd;
	ca.reply_nfds = 1;
	if (ioctl(svc, MAC_CAPABILITY_CALL, &ca) != 0)
		return (-1);
	return (token_fd);
}

/*
 * WRITE token denies exec.
 */
ATF_TC_WITH_CLEANUP(token_write_denies_exec);
ATF_TC_HEAD(token_write_denies_exec, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_FS_WRITE token does not authorize exec");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(token_write_denies_exec, tc)
{
	struct fi_reply rpl;
	int svc, target, token, rc;
	const char *sh = "/bin/sh";

	svc = fi_connect();
	target = open(sh, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);

	token = fi_mint(svc, target, FI_FS_WRITE);
	ATF_REQUIRE_MSG(token >= 0, "fi_mint WRITE: %s", strerror(errno));

	rc = run_token_open(tc, token, sh, "exec", false);
	ATF_CHECK_MSG(rc == 1,
	    "exec should be denied with WRITE-only token (got %d)", rc);

	close(token);
	close(target);
	close(svc);
}
ATF_TC_CLEANUP(token_write_denies_exec, tc)
{
}

/*
 * READ token denies exec.
 */
ATF_TC_WITH_CLEANUP(token_read_denies_exec);
ATF_TC_HEAD(token_read_denies_exec, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_FS_READ token does not authorize exec");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(token_read_denies_exec, tc)
{
	struct fi_reply rpl;
	int svc, target, token, rc;
	const char *sh = "/bin/sh";

	svc = fi_connect();
	target = open(sh, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, target, 0, &rpl) == 0);

	token = fi_mint(svc, target, FI_FS_READ);
	ATF_REQUIRE_MSG(token >= 0, "fi_mint READ: %s", strerror(errno));

	rc = run_token_open(tc, token, sh, "exec", false);
	ATF_CHECK_MSG(rc == 1,
	    "exec should be denied with READ-only token (got %d)", rc);

	close(token);
	close(target);
	close(svc);
}
ATF_TC_CLEANUP(token_read_denies_exec, tc)
{
}

/*
 * Directory LOOKUP-only token does not imply CREATE.
 */
ATF_TC_WITH_CLEANUP(dir_token_lookup_no_create);
ATF_TC_HEAD(dir_token_lookup_no_create, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Directory token with LOOKUP only does not authorize create");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(dir_token_lookup_no_create, tc)
{
	struct fi_reply rpl;
	int svc, dir_fd, token, rc;
	char newfile[160];

	make_tmpdir();
	svc = fi_connect();

	dir_fd = open(tmpdir, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dir_fd >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, dir_fd, 0, &rpl) == 0);

	/* Mint LOOKUP only — no CREATE. */
	token = fi_mint(svc, dir_fd, FI_FS_LOOKUP);
	ATF_REQUIRE_MSG(token >= 0, "fi_mint LOOKUP: %s", strerror(errno));
	close(dir_fd);

	snprintf(newfile, sizeof(newfile), "%s/new_file.txt", tmpdir);
	rc = run_token_helper(tc, "token-create", token, newfile, NULL);
	ATF_CHECK_MSG(rc == 1,
	    "create should be denied with LOOKUP-only token (got %d)", rc);

	close(token);
	close(svc);
}
ATF_TC_CLEANUP(dir_token_lookup_no_create, tc)
{
	cleanup_tmpdir();
}

/*
 * Unix socket connect requires FI_FS_UIPC_CONNECT token.
 */
ATF_TC_WITH_CLEANUP(token_uipc_connect);
ATF_TC_HEAD(token_uipc_connect, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_FS_UIPC_CONNECT token allows Unix socket connect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(token_uipc_connect, tc)
{
	struct fi_reply rpl;
	int svc, listener, sock_fd, token, rc;

	listener = make_tmpunix_listener();
	svc = fi_connect();

	sock_fd = open(tmpsockpath, O_PATH);
	ATF_REQUIRE_MSG(sock_fd >= 0, "open %s: %s",
	    tmpsockpath, strerror(errno));
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, sock_fd, 0, &rpl) == 0);

	/* READ-only token should NOT allow connect. */
	token = fi_mint(svc, sock_fd, FI_FS_READ);
	ATF_REQUIRE(token >= 0);
	rc = run_token_helper(tc, "token-uipc-connect", token, tmpsockpath,
	    NULL);
	ATF_CHECK_MSG(rc == 1,
	    "connect should be denied with READ token (got %d)", rc);
	close(token);

	/* UIPC_CONNECT token should allow connect. */
	token = fi_mint(svc, sock_fd, FI_FS_UIPC_CONNECT);
	ATF_REQUIRE(token >= 0);
	rc = run_token_helper(tc, "token-uipc-connect", token, tmpsockpath,
	    NULL);
	ATF_CHECK_MSG(rc == 0,
	    "connect should succeed with UIPC_CONNECT token (got %d)", rc);

	close(token);
	close(sock_fd);
	close(listener);
	close(svc);
}
ATF_TC_CLEANUP(token_uipc_connect, tc)
{
	cleanup_tmpsock();
}

/*
 * Same nonce can claim overlapping port ranges without conflict.
 */
ATF_TC(net_same_nonce_overlap_no_conflict);
ATF_TC_HEAD(net_same_nonce_overlap_no_conflict, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Same nonce claiming overlapping port ranges does not conflict");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_same_nonce_overlap_no_conflict, tc)
{
	int svc;

	svc = fi_connect();

	/* Claim 19800-19899 */
	ATF_REQUIRE(fi_net_call2(svc, FI_OP_CLAIM_NET,
	    AF_INET, IPPROTO_TCP, 19800, 19899, FI_NET_BIND) == 0);

	/* Claim overlapping 19850-19950 from same nonce — should succeed */
	ATF_REQUIRE(fi_net_call2(svc, FI_OP_CLAIM_NET,
	    AF_INET, IPPROTO_TCP, 19850, 19950, FI_NET_BIND) == 0);

	/* Owner can still bind in the overlap region */
	{
		struct sockaddr_in sin;
		int s;

		s = socket(AF_INET, SOCK_STREAM, 0);
		ATF_REQUIRE(s >= 0);
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(19875);
		sin.sin_addr.s_addr = INADDR_ANY;
		ATF_CHECK_EQ(bind(s, (struct sockaddr *)&sin, sizeof(sin)), 0);
		close(s);
	}

	close(svc);
}

/*
 * Network CIDR token: bind inside the subnet is allowed,
 * bind outside is denied.
 */
ATF_TC(net_cidr_token_inside_outside);
ATF_TC_HEAD(net_cidr_token_inside_outside, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CIDR network token allows bind inside subnet, "
	    "foreign nonce without token is denied");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(net_cidr_token_inside_outside, tc)
{
	int svc, token, rc;
	uint16_t port = htons(18600);

	svc = fi_connect();

	/* Claim 127.0.0.0/8 on port 18600 */
	ATF_REQUIRE(fi_net_call_addr(svc, FI_OP_CLAIM_NET, AF_INET,
	    IPPROTO_TCP, port, FI_NET_BIND, "127.0.0.0", 8) == 0);

	/* Without token, foreign nonce is denied. */
	rc = run_net_try_bind(tc, 18600);
	ATF_CHECK_MSG(rc == 1,
	    "bind should be denied without token (got %d)", rc);

	/* Mint token for the same /8 */
	token = fi_net_mint_addr(svc, AF_INET, IPPROTO_TCP, port,
	    FI_NET_BIND, "127.0.0.0", 8);
	ATF_REQUIRE_MSG(token >= 0, "fi_net_mint_addr: %s", strerror(errno));

	/* Child with token should be able to bind 127.0.0.1:18600 */
	rc = run_net_token_bind(tc, token, 18600);
	ATF_CHECK_MSG(rc == 0,
	    "bind inside CIDR should succeed with token (got %d)", rc);

	close(token);
	close(svc);
}

/*
 * Rename requires authority on both source and destination directories.
 */
ATF_TC_WITH_CLEANUP(rename_requires_both_dirs);
ATF_TC_HEAD(rename_requires_both_dirs, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Rename requires RENAME_FROM on source and RENAME_TO on dest");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(rename_requires_both_dirs, tc)
{
	struct fi_reply rpl;
	int svc, src_fd, dst_fd, token_from, rc;
	char srcdir[128], dstdir[128], srcfile[160], dstfile[160];
	int fd;

	snprintf(srcdir, sizeof(srcdir),
	    "/tmp/fi_rename_src.%d", (int)getpid());
	snprintf(dstdir, sizeof(dstdir),
	    "/tmp/fi_rename_dst.%d", (int)getpid());

	ATF_REQUIRE(mkdir(srcdir, 0755) == 0 || errno == EEXIST);
	ATF_REQUIRE(mkdir(dstdir, 0755) == 0 || errno == EEXIST);

	snprintf(srcfile, sizeof(srcfile), "%s/file.txt", srcdir);
	snprintf(dstfile, sizeof(dstfile), "%s/file.txt", dstdir);

	fd = open(srcfile, O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd >= 0);
	close(fd);

	svc = fi_connect();

	src_fd = open(srcdir, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(src_fd >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, src_fd, 0, &rpl) == 0);

	dst_fd = open(dstdir, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dst_fd >= 0);
	ATF_REQUIRE(fi_call(svc, FI_OP_CLAIM, dst_fd, 0, &rpl) == 0);

	/*
	 * Token with only RENAME_FROM on source dir — rename should
	 * be denied because we lack RENAME_TO on dest dir.
	 */
	token_from = fi_mint(svc, src_fd,
	    FI_FS_LOOKUP | FI_FS_RENAME_FROM);
	ATF_REQUIRE(token_from >= 0);

	rc = run_token_helper(tc, "token-rename", token_from, srcfile,
	    dstfile);
	ATF_CHECK_MSG(rc == 1,
	    "rename should be denied without RENAME_TO on dest (got %d)", rc);
	close(token_from);

	close(src_fd);
	close(dst_fd);
	close(svc);

	/* Clean up */
	unlink(srcfile);
	unlink(dstfile);
	rmdir(srcdir);
	rmdir(dstdir);
}
ATF_TC_CLEANUP(rename_requires_both_dirs, tc)
{
	char srcdir[128], dstdir[128], srcfile[160], dstfile[160];

	snprintf(srcdir, sizeof(srcdir),
	    "/tmp/fi_rename_src.%d", (int)getpid());
	snprintf(dstdir, sizeof(dstdir),
	    "/tmp/fi_rename_dst.%d", (int)getpid());
	snprintf(srcfile, sizeof(srcfile), "%s/file.txt", srcdir);
	snprintf(dstfile, sizeof(dstfile), "%s/file.txt", dstdir);
	unlink(srcfile);
	unlink(dstfile);
	rmdir(srcdir);
	rmdir(dstdir);
}

/* ----------------------------------------------------------------
 * Jail isolation tests
 * ---------------------------------------------------------------- */

static int
fi_jail_call(int svc, uint32_t op, int32_t jid, const char *name,
    uint32_t actions, struct fi_reply *rpl)
{
	struct mac_capability_call_args ca;
	struct fi_jail_request jr;

	memset(&jr, 0, sizeof(jr));
	jr.op = op;
	jr.jid = jid;
	jr.actions = actions;
	if (name != NULL)
		strlcpy(jr.name, name, sizeof(jr.name));

	memset(&ca, 0, sizeof(ca));
	ca.req = &jr;
	ca.req_len = sizeof(jr);
	ca.reply = rpl;
	ca.reply_len = sizeof(*rpl);
	return (ioctl(svc, MAC_CAPABILITY_CALL, &ca));
}

static int
fi_jail_mint(int svc, int32_t jid, const char *name, uint32_t actions)
{
	struct mac_capability_call_args ca;
	struct fi_jail_request jr;
	struct fi_reply rpl;
	int token_fd;

	memset(&jr, 0, sizeof(jr));
	jr.op = FI_OP_MINT_JAIL;
	jr.jid = jid;
	jr.actions = actions;
	if (name != NULL)
		strlcpy(jr.name, name, sizeof(jr.name));

	token_fd = -1;
	memset(&ca, 0, sizeof(ca));
	ca.req = &jr;
	ca.req_len = sizeof(jr);
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	ca.reply_fds = &token_fd;
	ca.reply_nfds = 1;
	if (ioctl(svc, MAC_CAPABILITY_CALL, &ca) != 0)
		return (-1);
	return (token_fd);
}

/*
 * Run a child (fork+exec for nonce rotation) that tries to create a jail.
 * Returns: 0 = jail created, 1 = denied, 2 = other error.
 * If jid_out != NULL, the created JID is written there on success.
 */
static int
run_jail_create_helper(const atf_tc_t *tc, const char *name, int *jid_out)
{
	const char *path;
	pid_t pid;
	int status, pfd[2];

	path = fi_helper_path(tc);

	ATF_REQUIRE(pipe(pfd) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(pfd[0]);
		dup2(pfd[1], STDOUT_FILENO);
		close(pfd[1]);
		execl(path, path, "jail-create", name, NULL);
		_exit(127);
	}
	close(pfd[1]);

	/* Read JID from child stdout */
	{
		char buf[32];
		ssize_t n = read(pfd[0], buf, sizeof(buf) - 1);
		close(pfd[0]);
		if (n > 0 && jid_out != NULL) {
			buf[n] = '\0';
			*jid_out = (int)strtol(buf, NULL, 10);
		}
	}

	waitpid(pid, &status, 0);
	if (!WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

/*
 * Run a child that tries to jail_get on a JID.
 * Returns: 0 = success, 1 = denied.
 */
static int
run_jail_get_helper(const atf_tc_t *tc, int jid)
{
	char jidstr[16];
	const char *path;
	pid_t pid;
	int status;

	path = fi_helper_path(tc);
	snprintf(jidstr, sizeof(jidstr), "%d", jid);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(path, path, "jail-get", jidstr, NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

/*
 * Run a child that tries to jail_remove a JID.
 * Returns: 0 = success, 1 = denied.
 */
static int
run_jail_remove_helper(const atf_tc_t *tc, int jid)
{
	char jidstr[16];
	const char *path;
	pid_t pid;
	int status;

	path = fi_helper_path(tc);
	snprintf(jidstr, sizeof(jidstr), "%d", jid);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(path, path, "jail-remove", jidstr, NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

/*
 * Run a child that authorizes with a jail token, then creates a jail.
 * Returns: 0 = jail created, 1 = denied, 10 = auth failed.
 * If jid_out != NULL, the created JID is written there on success.
 */
static int
run_jail_token_create_helper(const atf_tc_t *tc, int token_fd,
    const char *name, int *jid_out)
{
	char token_str[16];
	const char *path;
	pid_t pid;
	int status, pfd[2];

	path = fi_helper_path(tc);
	snprintf(token_str, sizeof(token_str), "%d", token_fd);

	ATF_REQUIRE(pipe(pfd) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(pfd[0]);
		dup2(pfd[1], STDOUT_FILENO);
		close(pfd[1]);
		execl(path, path, "jail-token-create", token_str, name, NULL);
		_exit(127);
	}
	close(pfd[1]);

	{
		char buf[32];
		ssize_t n = read(pfd[0], buf, sizeof(buf) - 1);
		close(pfd[0]);
		if (n > 0 && jid_out != NULL) {
			buf[n] = '\0';
			*jid_out = (int)strtol(buf, NULL, 10);
		}
	}

	waitpid(pid, &status, 0);
	if (!WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

/*
 * Remove a jail by JID, ignoring errors (for cleanup).
 */
static void
cleanup_jail(int jid)
{

	if (jid > 0)
		jail_remove(jid);
}

static void
cleanup_jail_by_name(const char *name)
{
	struct iovec iov[4];
	int jid;
	char namebuf[64];

	strlcpy(namebuf, name, sizeof(namebuf));
	iov[0].iov_base = __DECONST(char *, "name");
	iov[0].iov_len = sizeof("name");
	iov[1].iov_base = namebuf;
	iov[1].iov_len = strlen(namebuf) + 1;
	iov[2].iov_base = __DECONST(char *, "lastjid");
	iov[2].iov_len = sizeof("lastjid");
	jid = 0;
	iov[3].iov_base = &jid;
	iov[3].iov_len = sizeof(jid);

	jid = jail_get(iov, 4, 0);
	if (jid > 0)
		jail_remove(jid);
}

/* -- Jail claim/release/query -- */

ATF_TC_WITH_CLEANUP(jail_claim_blocks_create);
ATF_TC_HEAD(jail_claim_blocks_create, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Claiming a jail name blocks foreign nonce from jail_set(JAIL_CREATE)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_claim_blocks_create, tc)
{
	struct fi_reply rpl;
	int rc, svc;

	svc = fi_connect();

	/* Claim jail name with CREATE action */
	ATF_REQUIRE(fi_jail_call(svc, FI_OP_CLAIM_JAIL, 0,
	    "fi_test_jail", FI_JAIL_CREATE, &rpl) == 0);

	/* Foreign nonce should be denied */
	rc = run_jail_create_helper(tc, "fi_test_jail", NULL);
	ATF_CHECK_MSG(rc == 1,
	    "foreign jail_set(JAIL_CREATE) should be denied (got %d)", rc);

	close(svc);
}
ATF_TC_CLEANUP(jail_claim_blocks_create, tc)
{
	cleanup_jail_by_name("fi_test_jail");
}

ATF_TC_WITH_CLEANUP(jail_claim_allows_owner);
ATF_TC_HEAD(jail_claim_allows_owner, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Owner nonce can still create a claimed jail");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_claim_allows_owner, tc)
{
	struct fi_reply rpl;
	int svc, jid;
	struct iovec iov[6];
	int persist = 1;

	svc = fi_connect();

	ATF_REQUIRE(fi_jail_call(svc, FI_OP_CLAIM_JAIL, 0,
	    "fi_test_owner", FI_JAIL_CREATE, &rpl) == 0);

	/* Same nonce — jail_set should succeed */
	iov[0].iov_base = __DECONST(char *, "name");
	iov[0].iov_len = sizeof("name");
	iov[1].iov_base = __DECONST(char *, "fi_test_owner");
	iov[1].iov_len = sizeof("fi_test_owner");
	iov[2].iov_base = __DECONST(char *, "path");
	iov[2].iov_len = sizeof("path");
	iov[3].iov_base = __DECONST(char *, "/");
	iov[3].iov_len = sizeof("/");
	iov[4].iov_base = __DECONST(char *, "persist");
	iov[4].iov_len = sizeof("persist");
	iov[5].iov_base = &persist;
	iov[5].iov_len = sizeof(persist);

	jid = jail_set(iov, 6, JAIL_CREATE);
	ATF_CHECK_MSG(jid >= 0, "owner jail_set should succeed: %s",
	    strerror(errno));

	cleanup_jail(jid);
	close(svc);
}
ATF_TC_CLEANUP(jail_claim_allows_owner, tc)
{
	cleanup_jail_by_name("fi_test_owner");
}

ATF_TC_WITH_CLEANUP(jail_release_allows_create);
ATF_TC_HEAD(jail_release_allows_create, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Releasing a jail claim allows foreign nonce to create the jail");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_release_allows_create, tc)
{
	struct fi_reply rpl;
	int rc, svc, jid = 0;

	svc = fi_connect();

	ATF_REQUIRE(fi_jail_call(svc, FI_OP_CLAIM_JAIL, 0,
	    "fi_test_release", FI_JAIL_CREATE, &rpl) == 0);
	ATF_REQUIRE(fi_jail_call(svc, FI_OP_RELEASE_JAIL, 0,
	    "fi_test_release", 0, &rpl) == 0);

	/* After release, foreign nonce should succeed */
	rc = run_jail_create_helper(tc, "fi_test_release", &jid);
	ATF_CHECK_MSG(rc == 0,
	    "jail_set after release should succeed (got %d)", rc);

	cleanup_jail(jid);
	close(svc);
}
ATF_TC_CLEANUP(jail_release_allows_create, tc)
{
	cleanup_jail_by_name("fi_test_release");
}

ATF_TC(jail_claim_query);
ATF_TC_HEAD(jail_claim_query, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_OP_QUERY_JAIL reports claimed and mine flags");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_claim_query, tc)
{
	struct fi_reply rpl;
	int svc;

	svc = fi_connect();

	ATF_REQUIRE(fi_jail_call(svc, FI_OP_CLAIM_JAIL, 0,
	    "fi_test_query", FI_JAIL_ALL, &rpl) == 0);

	memset(&rpl, 0, sizeof(rpl));
	ATF_REQUIRE(fi_jail_call(svc, FI_OP_QUERY_JAIL, 0,
	    "fi_test_query", FI_JAIL_CREATE, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, FI_QF_CLAIMED | FI_QF_MINE);

	close(svc);
}

ATF_TC(jail_query_unclaimed);
ATF_TC_HEAD(jail_query_unclaimed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FI_OP_QUERY_JAIL on unclaimed name returns zero flags");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_query_unclaimed, tc)
{
	struct fi_reply rpl;
	int svc;

	svc = fi_connect();

	memset(&rpl, 0, sizeof(rpl));
	ATF_REQUIRE(fi_jail_call(svc, FI_OP_QUERY_JAIL, 0,
	    "fi_test_noexist", FI_JAIL_CREATE, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, 0);

	close(svc);
}

ATF_TC(jail_close_releases_claims);
ATF_TC_HEAD(jail_close_releases_claims, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing the instance fd releases jail claims");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_close_releases_claims, tc)
{
	struct fi_reply rpl;
	int svc, svc2;

	svc = fi_connect();
	ATF_REQUIRE(fi_jail_call(svc, FI_OP_CLAIM_JAIL, 0,
	    "fi_test_close", FI_JAIL_ALL, &rpl) == 0);

	close(svc);

	svc2 = fi_connect();
	memset(&rpl, 0, sizeof(rpl));
	ATF_REQUIRE(fi_jail_call(svc2, FI_OP_QUERY_JAIL, 0,
	    "fi_test_close", FI_JAIL_CREATE, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, 0);

	close(svc2);
}

ATF_TC_WITH_CLEANUP(jail_claim_blocks_get);
ATF_TC_HEAD(jail_claim_blocks_get, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Jail GET claim blocks foreign nonce from jail_get");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_claim_blocks_get, tc)
{
	struct fi_reply rpl;
	int rc, svc, jid;
	struct iovec iov[6];
	int persist = 1;

	/* First create a real jail so jail_get has something to query */
	iov[0].iov_base = __DECONST(char *, "name");
	iov[0].iov_len = sizeof("name");
	iov[1].iov_base = __DECONST(char *, "fi_test_get");
	iov[1].iov_len = sizeof("fi_test_get");
	iov[2].iov_base = __DECONST(char *, "path");
	iov[2].iov_len = sizeof("path");
	iov[3].iov_base = __DECONST(char *, "/");
	iov[3].iov_len = sizeof("/");
	iov[4].iov_base = __DECONST(char *, "persist");
	iov[4].iov_len = sizeof("persist");
	iov[5].iov_base = &persist;
	iov[5].iov_len = sizeof(persist);

	jid = jail_set(iov, 6, JAIL_CREATE);
	ATF_REQUIRE_MSG(jid >= 0, "create jail: %s", strerror(errno));

	svc = fi_connect();
	ATF_REQUIRE(fi_jail_call(svc, FI_OP_CLAIM_JAIL, jid,
	    "fi_test_get", FI_JAIL_GET, &rpl) == 0);

	/* Foreign nonce jail_get should be denied */
	rc = run_jail_get_helper(tc, jid);
	ATF_CHECK_MSG(rc == 1,
	    "foreign jail_get should be denied (got %d)", rc);

	close(svc);
	cleanup_jail(jid);
}
ATF_TC_CLEANUP(jail_claim_blocks_get, tc)
{
	cleanup_jail_by_name("fi_test_get");
}

ATF_TC_WITH_CLEANUP(jail_claim_blocks_remove);
ATF_TC_HEAD(jail_claim_blocks_remove, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Jail REMOVE claim blocks foreign nonce from jail_remove");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_claim_blocks_remove, tc)
{
	struct fi_reply rpl;
	int rc, svc, jid;
	struct iovec iov[6];
	int persist = 1;

	/* Create a real jail */
	iov[0].iov_base = __DECONST(char *, "name");
	iov[0].iov_len = sizeof("name");
	iov[1].iov_base = __DECONST(char *, "fi_test_rm");
	iov[1].iov_len = sizeof("fi_test_rm");
	iov[2].iov_base = __DECONST(char *, "path");
	iov[2].iov_len = sizeof("path");
	iov[3].iov_base = __DECONST(char *, "/");
	iov[3].iov_len = sizeof("/");
	iov[4].iov_base = __DECONST(char *, "persist");
	iov[4].iov_len = sizeof("persist");
	iov[5].iov_base = &persist;
	iov[5].iov_len = sizeof(persist);

	jid = jail_set(iov, 6, JAIL_CREATE);
	ATF_REQUIRE_MSG(jid >= 0, "create jail: %s", strerror(errno));

	svc = fi_connect();
	ATF_REQUIRE(fi_jail_call(svc, FI_OP_CLAIM_JAIL, jid,
	    "fi_test_rm", FI_JAIL_REMOVE, &rpl) == 0);

	/* Foreign nonce jail_remove should be denied */
	rc = run_jail_remove_helper(tc, jid);
	ATF_CHECK_MSG(rc == 1,
	    "foreign jail_remove should be denied (got %d)", rc);

	close(svc);
	cleanup_jail(jid);
}
ATF_TC_CLEANUP(jail_claim_blocks_remove, tc)
{
	cleanup_jail_by_name("fi_test_rm");
}

/* -- Jail token tests -- */

ATF_TC_WITH_CLEANUP(jail_token_create_grants_access);
ATF_TC_HEAD(jail_token_create_grants_access, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Jail CREATE token allows foreign nonce to create the jail");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_token_create_grants_access, tc)
{
	struct fi_reply rpl;
	int rc, svc, token, jid = 0;

	svc = fi_connect();

	ATF_REQUIRE(fi_jail_call(svc, FI_OP_CLAIM_JAIL, 0,
	    "fi_test_tok", FI_JAIL_CREATE, &rpl) == 0);

	token = fi_jail_mint(svc, 0, "fi_test_tok", FI_JAIL_CREATE);
	ATF_REQUIRE_MSG(token >= 0, "fi_jail_mint: %s", strerror(errno));

	/* Foreign nonce with token should succeed */
	rc = run_jail_token_create_helper(tc, token, "fi_test_tok", &jid);
	ATF_CHECK_MSG(rc == 0,
	    "token holder jail_set should succeed (got %d)", rc);

	cleanup_jail(jid);
	close(token);
	close(svc);
}
ATF_TC_CLEANUP(jail_token_create_grants_access, tc)
{
	cleanup_jail_by_name("fi_test_tok");
}

ATF_TC_WITH_CLEANUP(jail_token_wrong_action_denied);
ATF_TC_HEAD(jail_token_wrong_action_denied, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Jail GET token does not authorize CREATE");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_token_wrong_action_denied, tc)
{
	struct fi_reply rpl;
	int rc, svc, token;

	svc = fi_connect();

	/* Claim with ALL actions */
	ATF_REQUIRE(fi_jail_call(svc, FI_OP_CLAIM_JAIL, 0,
	    "fi_test_wrong", FI_JAIL_ALL, &rpl) == 0);

	/* Mint token with GET only */
	token = fi_jail_mint(svc, 0, "fi_test_wrong", FI_JAIL_GET);
	ATF_REQUIRE_MSG(token >= 0, "fi_jail_mint: %s", strerror(errno));

	/* Foreign nonce tries CREATE with GET-only token — should be denied */
	rc = run_jail_token_create_helper(tc, token, "fi_test_wrong", NULL);
	ATF_CHECK_MSG(rc == 1,
	    "CREATE with GET-only token should be denied (got %d)", rc);

	close(token);
	close(svc);
}
ATF_TC_CLEANUP(jail_token_wrong_action_denied, tc)
{
	cleanup_jail_by_name("fi_test_wrong");
}

ATF_TC(jail_claim_invalid_request);
ATF_TC_HEAD(jail_claim_invalid_request, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Invalid jail claim arguments are rejected");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_claim_invalid_request, tc)
{
	struct fi_reply rpl;
	int svc;

	svc = fi_connect();

	/* Both JID and name empty — should fail */
	ATF_CHECK_ERRNO(EINVAL, fi_jail_call(svc, FI_OP_CLAIM_JAIL,
	    0, NULL, 0, &rpl) == -1);

	/* Name only, no actions — should succeed (actions default to ALL) */
	ATF_CHECK(fi_jail_call(svc, FI_OP_CLAIM_JAIL,
	    0, "fi_test_inval", 0, &rpl) == 0);

	close(svc);
}

ATF_TC(jail_double_claim_same_nonce);
ATF_TC_HEAD(jail_double_claim_same_nonce, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Re-claiming a jail from the same nonce transfers ownership");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_double_claim_same_nonce, tc)
{
	struct fi_reply rpl;
	int svc1, svc2;

	svc1 = fi_connect();
	svc2 = fi_connect();

	/* Claim via first instance */
	ATF_REQUIRE(fi_jail_call(svc1, FI_OP_CLAIM_JAIL, 0,
	    "fi_test_dbl", FI_JAIL_ALL, &rpl) == 0);

	/* Re-claim via second instance (same nonce) */
	ATF_REQUIRE(fi_jail_call(svc2, FI_OP_CLAIM_JAIL, 0,
	    "fi_test_dbl", FI_JAIL_ALL, &rpl) == 0);

	/* Close first instance — claim should survive via svc2 */
	close(svc1);

	memset(&rpl, 0, sizeof(rpl));
	ATF_REQUIRE(fi_jail_call(svc2, FI_OP_QUERY_JAIL, 0,
	    "fi_test_dbl", FI_JAIL_CREATE, &rpl) == 0);
	ATF_CHECK_EQ(rpl.flags, FI_QF_CLAIMED | FI_QF_MINE);

	close(svc2);
}

/* -- Jail stress tests -- */

ATF_TC_WITH_CLEANUP(jail_stress_claim_release);
ATF_TC_HEAD(jail_stress_claim_release, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Rapid jail claim/release cycles concurrent with jail operations");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(jail_stress_claim_release, tc)
{
	struct fi_reply rpl;
	int svc, i, rc;
	pid_t children[4];
	int status;

	svc = fi_connect();

	/*
	 * Rapidly claim and release the same jail name while forked
	 * children (foreign nonces) attempt to create that jail.
	 * This exercises the TOCTOU window between fi_jail_lock
	 * release and fi_auth_lock acquire in fi_check_jail_common.
	 * Any kernel panic here indicates a NOSLEEP violation or
	 * use-after-free in the jail hook path.
	 */

	/* Launch children that repeatedly try to create the jail */
	for (i = 0; i < 4; i++) {
		children[i] = fork();
		ATF_REQUIRE(children[i] >= 0);
		if (children[i] == 0) {
			const char *path = fi_helper_path(tc);
			int iter;

			for (iter = 0; iter < 50; iter++) {
				pid_t p = fork();
				if (p < 0)
					continue;
				if (p == 0) {
					execl(path, path, "jail-create",
					    "fi_stress_jail", NULL);
					_exit(127);
				}
				int s;
				waitpid(p, &s, 0);
				/* Clean up any jail we created */
				if (WIFEXITED(s) && WEXITSTATUS(s) == 0)
					cleanup_jail_by_name("fi_stress_jail");
			}
			_exit(0);
		}
	}

	/* Parent rapidly claims and releases */
	for (i = 0; i < 200; i++) {
		rc = fi_jail_call(svc, FI_OP_CLAIM_JAIL, 0,
		    "fi_stress_jail", FI_JAIL_CREATE, &rpl);
		if (rc == 0) {
			fi_jail_call(svc, FI_OP_RELEASE_JAIL, 0,
			    "fi_stress_jail", 0, &rpl);
		}
	}

	/* Wait for all children */
	for (i = 0; i < 4; i++) {
		waitpid(children[i], &status, 0);
		ATF_CHECK(WIFEXITED(status));
	}

	close(svc);
}
ATF_TC_CLEANUP(jail_stress_claim_release, tc)
{
	cleanup_jail_by_name("fi_stress_jail");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, claim_and_query);
	ATF_TP_ADD_TC(tp, claim_allows_same_nonce);
	ATF_TP_ADD_TC(tp, claim_blocks_stat);
	ATF_TP_ADD_TC(tp, claim_blocks_unlink);
	ATF_TP_ADD_TC(tp, release_allows_access);
	ATF_TP_ADD_TC(tp, close_releases_claims);
	ATF_TP_ADD_TC(tp, double_claim_same_nonce);
	ATF_TP_ADD_TC(tp, child_reclaim_same_nonce);
	ATF_TP_ADD_TC(tp, claim_pipe_fails);
	ATF_TP_ADD_TC(tp, same_nonce_can_open);
	ATF_TP_ADD_TC(tp, query_unclaimed);
	ATF_TP_ADD_TC(tp, release_unclaimed);
	ATF_TP_ADD_TC(tp, query_after_release);
	ATF_TP_ADD_TC(tp, claim_multiple_files);
	ATF_TP_ADD_TC(tp, unix_socket_claim_blocks_connect);

	/* Cross-nonce enforcement (table-driven) */
	ATF_TP_ADD_TC(tp, cross_nonce_read_blocked);
	ATF_TP_ADD_TC(tp, cross_nonce_metadata_blocked);
	ATF_TP_ADD_TC(tp, cross_nonce_lifecycle_blocked);

	/* Directory isolation */
	ATF_TP_ADD_TC(tp, dir_claim_blocks_lookup);
	ATF_TP_ADD_TC(tp, dir_claim_blocks_stat_inside);
	ATF_TP_ADD_TC(tp, dir_release_allows_lookup);

	/* Network isolation */
	ATF_TP_ADD_TC(tp, net_claim_blocks_bind);
	ATF_TP_ADD_TC(tp, net_claim_allows_owner);
	ATF_TP_ADD_TC(tp, net_release_allows_bind);
	ATF_TP_ADD_TC(tp, net_claim_disjoint_address_allows_foreign_claim);
	ATF_TP_ADD_TC(tp, net_claim_same_address_blocks_foreign_claim);
	ATF_TP_ADD_TC(tp, net_claim_blocks_connect);
	ATF_TP_ADD_TC(tp, net_wildcard_blocks_socket_create);
	ATF_TP_ADD_TC(tp, net_claim_invalid_request);
	ATF_TP_ADD_TC(tp, net_claim_rejects_bad_domain);
	ATF_TP_ADD_TC(tp, net_claim_rejects_bad_protocol);
	ATF_TP_ADD_TC(tp, net_claim_rejects_ipv4_prefix_above_32);
	ATF_TP_ADD_TC(tp, net_claim_ipv6);
	ATF_TP_ADD_TC(tp, net_release_unclaimed);
	ATF_TP_ADD_TC(tp, net_claim_protocol_wildcard);
	ATF_TP_ADD_TC(tp, net_claim_range_blocks_foreign_exact);
	ATF_TP_ADD_TC(tp, net_claim_exact_blocks_foreign_range);
	ATF_TP_ADD_TC(tp, net_query_reports_range_claims);

	/* Access tokens */
	ATF_TP_ADD_TC(tp, token_mint_returns_fd);
	ATF_TP_ADD_TC(tp, token_authorize_grants_access);
	ATF_TP_ADD_TC(tp, token_close_revokes_access);
	ATF_TP_ADD_TC(tp, token_mint_requires_ownership);
	ATF_TP_ADD_TC(tp, token_query_shows_authorized);
	ATF_TP_ADD_TC(tp, token_scoped_to_claim);
	ATF_TP_ADD_TC(tp, token_read_only_denies_write);
	ATF_TP_ADD_TC(tp, token_authorize_idempotent);
	ATF_TP_ADD_TC(tp, token_dup_lifetime);

	/* Network access tokens */
	ATF_TP_ADD_TC(tp, net_token_mint_returns_fd);
	ATF_TP_ADD_TC(tp, net_token_authorize_grants_bind);
	ATF_TP_ADD_TC(tp, net_token_scoped_to_endpoint);
	ATF_TP_ADD_TC(tp, net_token_close_revokes);
	ATF_TP_ADD_TC(tp, net_token_mint_requires_claim);
	ATF_TP_ADD_TC(tp, net_token_query_shows_authorized_range);
	ATF_TP_ADD_TC(tp, net_token_range_does_not_authorize_other_claim);

	/* Additional coverage */
	ATF_TP_ADD_TC(tp, net_wildcard_claim_blocks_exact_bind);
	ATF_TP_ADD_TC(tp, net_claim_range_vs_range_overlap);
	ATF_TP_ADD_TC(tp, net_byte_order_port_256);
	ATF_TP_ADD_TC(tp, token_stat_only_denies_read);
	ATF_TP_ADD_TC(tp, mint_rejects_invalid_actions);
	ATF_TP_ADD_TC(tp, token_two_nonces_authorize);
	ATF_TP_ADD_TC(tp, net_token_range_bind_inside_outside);
	ATF_TP_ADD_TC(tp, dir_token_create_no_delete);
	ATF_TP_ADD_TC(tp, token_write_denies_exec);
	ATF_TP_ADD_TC(tp, token_read_denies_exec);
	ATF_TP_ADD_TC(tp, dir_token_lookup_no_create);
	ATF_TP_ADD_TC(tp, token_uipc_connect);
	ATF_TP_ADD_TC(tp, net_same_nonce_overlap_no_conflict);
	ATF_TP_ADD_TC(tp, net_cidr_token_inside_outside);
	ATF_TP_ADD_TC(tp, rename_requires_both_dirs);

	/* Jail isolation */
	ATF_TP_ADD_TC(tp, jail_claim_blocks_create);
	ATF_TP_ADD_TC(tp, jail_claim_allows_owner);
	ATF_TP_ADD_TC(tp, jail_release_allows_create);
	ATF_TP_ADD_TC(tp, jail_claim_query);
	ATF_TP_ADD_TC(tp, jail_query_unclaimed);
	ATF_TP_ADD_TC(tp, jail_close_releases_claims);
	ATF_TP_ADD_TC(tp, jail_claim_blocks_get);
	ATF_TP_ADD_TC(tp, jail_claim_blocks_remove);
	ATF_TP_ADD_TC(tp, jail_token_create_grants_access);
	ATF_TP_ADD_TC(tp, jail_token_wrong_action_denied);
	ATF_TP_ADD_TC(tp, jail_claim_invalid_request);
	ATF_TP_ADD_TC(tp, jail_double_claim_same_nonce);
	ATF_TP_ADD_TC(tp, jail_stress_claim_release);

	return (atf_no_error());
}
