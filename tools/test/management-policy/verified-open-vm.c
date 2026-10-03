/* SPDX-License-Identifier: BSD-2-Clause */
/* Destructive veriexec test: ONLY the disposable management-policy VM. */
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mac.h>
#include <sys/wait.h>
#include <dev/veriexec/veriexec_ioctl.h>
#include <sha256.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "bsdfilesystem.h"

static void
check(int ok, const char *what)
{
	if (!ok) {
		fprintf(stderr, "POLICY_VM_FAIL: %s: %s\n", what, strerror(errno));
		exit(1);
	}
}

static void
seed(const char *path)
{
	int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
	check(fd >= 0, "create fixture");
	check(write(fd, "policy\n", 7) == 7, "write fixture");
	check(close(fd) == 0, "close fixture");
}

static void
enroll(int dev, const char *path, int flags, bool mismatch)
{
	struct verified_exec_params p = {0};
	char hash[SHA256_DIGEST_STRING_LENGTH];
	unsigned i, byte;

	check(SHA256_File(path, hash) != NULL, "hash fixture");
	strlcpy(p.file, path, sizeof(p.file));
	strlcpy(p.fp_type, "SHA256", sizeof(p.fp_type));
	p.flags = flags;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		check(sscanf(hash + 2 * i, "%2x", &byte) == 1, "decode digest");
		p.fingerprint[i] = byte;
	}
	if (mismatch)
		p.fingerprint[0] ^= 0xff;
	check(ioctl(dev, VERIEXEC_LOAD, &p) == 0, "enroll fixture");
}

static void
expect_identity(pid_t pid, bool trusted)
{
	struct mac_veriexec_syscall_params params = {0};
	struct mac_veriexec_syscall_params_args args = {0};

	args.u.pid = pid;
	args.params = &params;
	check(mac_syscall(MAC_VERIEXEC_NAME, MAC_VERIEXEC_GET_PARAMS_PID_SYSCALL,
	    &args) == 0, "query executable identity");
	check(((params.flags & VERIEXEC_TRUSTED) != 0) == trusted,
	    "executable identity follows fork, exec, and credential copies");
}

static void
copy_executable(const char *source, const char *dest)
{
	char buf[16384];
	ssize_t n;
	int in, out;

	in = open(source, O_RDONLY);
	out = open(dest, O_CREAT | O_EXCL | O_WRONLY, 0500);
	check(in >= 0 && out >= 0, "copy executable fixture");
	while ((n = read(in, buf, sizeof(buf))) > 0)
		check(write(out, buf, n) == n, "write executable fixture");
	check(n == 0, "read executable fixture");
	check(close(in) == 0 && close(out) == 0, "close executable fixture");
}

int
main(int argc, char **argv)
{
	struct bsdfilesystem_state st = {0};
	struct bsdfilesystem_open_request rq = {0};
	struct verified_exec_params extra = {0};
	struct bsdfilesystem_config cfg;
	char host[256], buf[8] = {0};
	const char *path = "/root/verified-policy-fixture";
	const char *child_path = "/root/untrusted-executable-fixture";
	pid_t child;
	int status;
	const char *bad = "/root/mismatched-policy-fixture";
	const char *replacement = "/root/unverified-policy-fixture";
	int dev, fd, state;

	check(argc == 2 && (strcmp(argv[1], "--disposable-vm-only") == 0 ||
	    strcmp(argv[1], "--identity-child") == 0),
	    "explicit disposable VM invocation required");
	check(gethostname(host, sizeof(host)) == 0 &&
	    strcmp(host, "auth-policy-vm") == 0 && getuid() == 0 &&
	    access("/root/policy-zfs-test", F_OK) == 0 &&
	    access("/dev/vtbd1", F_OK) == 0, "disposable VM guard");
	dev = open("/dev/veriexec", O_RDWR);
	check(dev >= 0, "open veriexec");
	if (strcmp(argv[1], "--identity-child") == 0) {
		expect_identity(0, false);
		expect_identity(getppid(), true);
		check(issetugid() == 0, "identity refresh is not a set-id exec");
		check(ioctl(dev, VERIEXEC_LOCK) == -1 && errno == EPERM,
		    "untrusted exec loses parent integrity-control authority");
		close(dev);
		check(setuid(2001) == 0, "change ordinary UNIX uid");
		expect_identity(0, false);
		puts("VERIFIED_EXEC_IDENTITY_PASS");
		return (0);
	}
	check(ioctl(dev, VERIEXEC_GETSTATE, &state) == 0 && state == 0,
	    "test requires inactive veriexec");
	copy_executable(argv[0], child_path);
	seed(path);
	seed(replacement);
	seed(bad);
	enroll(dev, argv[0], VERIEXEC_TRUSTED, false);
	enroll(dev, child_path, 0, false);
	expect_identity(0, true);
	enroll(dev, path, VERIEXEC_FILE, false);
	enroll(dev, bad, VERIEXEC_FILE, true);
	st.root_fd = open("/", O_RDONLY | O_DIRECTORY);
	check(st.root_fd >= 0, "root directory");
	st.cfg.nopen_policy = 1;
	strlcpy(st.cfg.open_policy[0].label, "auth", sizeof(st.cfg.open_policy[0].label));
	strlcpy(st.cfg.open_policy[0].path, path, sizeof(st.cfg.open_policy[0].path));
	st.cfg.open_policy[0].rights = BSDFILESYSTEM_OPEN_READ;
	st.cfg.open_policy[0].verify = true;
	rq.op = BSDFILESYSTEM_OP_OPEN;
	rq.rights = BSDFILESYSTEM_OPEN_READ;
	strlcpy(rq.path, path, sizeof(rq.path));
	check(ioctl(dev, VERIEXEC_ENFORCE) == 0, "enable enforcement");
	check(ioctl(dev, VERIEXEC_LOCK) == 0, "lock fingerprint store");
	check(ioctl(dev, VERIEXEC_GETSTATE, &state) == 0 &&
	    (state & (VERIEXEC_STATE_ENFORCE | VERIEXEC_STATE_LOCKED)) ==
	    (VERIEXEC_STATE_ENFORCE | VERIEXEC_STATE_LOCKED), "enforced and locked state");
	child = fork();
	check(child >= 0, "fork identity fixture");
	if (child == 0) {
		expect_identity(0, true);
		execl(child_path, child_path, "--identity-child", (char *)NULL);
		check(0, "exec identity fixture");
	}
	check(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 0, "fork/exec identity regression");
	fd = bsdfilesystem_test_grant_open(&st, "auth", &rq);
	check(fd >= 0, "verified broker read");
	check(read(fd, buf, 7) == 7 && strcmp(buf, "policy\n") == 0,
	    "verified contents");
	close(fd);
	check(open(path, O_WRONLY) == -1 && errno == EPERM,
	    "root cannot write enrolled policy");
	check(ioctl(dev, VERIEXEC_LOAD, &extra) == -1 && errno == EPERM,
	    "locked store rejects root enrollment");
	strlcpy(st.cfg.open_policy[0].path, bad, sizeof(st.cfg.open_policy[0].path));
	strlcpy(rq.path, bad, sizeof(rq.path));
	check(bsdfilesystem_test_grant_open(&st, "auth", &rq) == -1 &&
	    errno == EAUTH, "broker rejects mismatched fingerprint");
	strlcpy(st.cfg.open_policy[0].path, path, sizeof(st.cfg.open_policy[0].path));
	strlcpy(rq.path, path, sizeof(rq.path));
	/* Atomic replacement is always protected.  The default unlink policy
	 * still permits removing the old name before publishing another inode.
	 * The broker must reject that replacement even when its bytes match. */
	check(rename(replacement, path) == -1 && errno == EAUTH,
	    "root cannot atomically overwrite enrolled policy");
	check(unlink(path) == 0, "remove fixture under default unlink policy");
	check(rename(replacement, path) == 0, "publish replacement inode");
	check(bsdfilesystem_test_grant_open(&st, "auth", &rq) == -1 &&
	    errno == EAUTH, "broker rejects unsigned replacement");
	bsdfilesystem_config_defaults(&cfg);
	check(bsdfilesystem_config_load(&cfg, path) == -1 && errno == EAUTH,
	    "broker config loader rejects unsigned replacement");
	/* A normal read is still legal; verified reads are the added boundary. */
	fd = open(path, O_RDONLY);
	check(fd >= 0, "ordinary UNIX read");
	close(fd);
	close(st.root_fd);
	close(dev);
	puts("VERIFIED_POLICY_ENFORCEMENT_PASS");
	puts("POLICY_GUEST_COMPLETE");
	fflush(stdout);
	/* Avoid launching any more unregistered programs under global enforcement. */
	for (;;)
		pause();
}
