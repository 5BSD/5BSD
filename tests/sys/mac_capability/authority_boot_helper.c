/* SPDX-License-Identifier: BSD-2-Clause */
/* VM-only PID 1 fixture. No production issuer bypass is used by these tests. */
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/types.h>
#include <sys/cap_authority.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/reboot.h>
#include <sys/ptrace.h>
#include <sys/procdesc.h>
#include <sys/procctl.h>
#include <capability.h>
#include <dev/mac_capability/mac_capability_coalition_proto.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_isolation_proto.h>
#include <channel.h>
#include <dev/mac_capability/mac_capability_system_proto.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned checks;
static void
failure(int line, const char *expr)
{
	printf("AUTHORITY_FAIL line=%d check=%s errno=%d\n", line, expr, errno);
	fflush(stdout);
	if (getpid() == 1) {
		sync();
		reboot(RB_POWEROFF);
		for (;;) pause();
	}
	_exit(1);
}
#define CHECK(x) do { checks++; if (!(x)) failure(__LINE__, #x); } while (0)
static int
op(int cmd, int fd, void *data)
{
	return (syscall(SYS_cap_process, cmd, fd, 0, data));
}
static int
issue(int issuer, unsigned kind, uid_t uid)
{
	struct cap_authority_spec spec = { CAP_AUTH_VERSION, kind, uid, 0 };
	int fd = op(CAP_AUTH_ISSUE, issuer, &spec);
	CHECK(fd >= 0);
	return (fd);
}
static struct cap_authority_info
info(void)
{
	struct cap_authority_info result;
	CHECK(op(CAP_AUTH_INFO, -1, &result) == 0);
	return (result);
}
static struct cap_authority_info
token_info(int token)
{
	struct cap_authority_info result;
	CHECK(op(CAP_AUTH_TOKEN_INFO, token, &result) == 0);
	return (result);
}
static void
wait_ok(pid_t pid)
{
	int status;
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
static int
send_one(int fd, const void *payload, size_t size)
{
	struct mac_capability_sendmsg_args args = { 0 };
	args.payload = payload;
	args.payload_len = size;
	return (ioctl(fd, MAC_CAPABILITY_SENDMSG, &args));
}
static void
bind_to(int issuer, int token, int fd)
{
	struct cap_authority_bind args = { token, fd, 0, 0 };
	CHECK(op(CAP_AUTH_BIND, issuer, &args) == 0);
	CHECK(op(CAP_AUTH_BIND, issuer, &args) == -1 && errno == EALREADY);
}
static void
revoke_grant(int issuer, int token)
{
	struct cap_authority_revoke args = { token, 0 };
	CHECK(op(CAP_AUTH_REVOKE, issuer, &args) == 0);
}
static int
coal_call(int fd, uint32_t command, int passed)
{
	struct coalition_req_hdr request = { .op = command };
	struct coalition_reply reply;
	size_t length = sizeof(reply), nfds = 0;

	CHECK(capability_kernel_call(fd, &request, sizeof(request),
	    passed >= 0 ? &passed : NULL, passed >= 0 ? 1 : 0,
	    &reply, &length, NULL, &nfds) == 0);
	CHECK(length == sizeof(reply) && nfds == 0);
	return (reply.status);
}
static unsigned
coal_members(int fd)
{
	struct coalition_req_hdr request = { .op = COALITION_OP_STAT };
	struct coalition_stat_reply reply;
	size_t length = sizeof(reply), nfds = 0;

	CHECK(capability_kernel_call(fd, &request, sizeof(request), NULL, 0,
	    &reply, &length, NULL, &nfds) == 0);
	CHECK(length == sizeof(reply) && nfds == 0 && reply.status == 0);
	return (reply.process_count);
}
static void
coalition_rehome_test(void)
{
	pid_t driver, child;
	int dev, a, b, dead, pd, gate[2], ready[2];
	char byte = 'R';

	driver = fork(); CHECK(driver >= 0);
	if (driver != 0) { wait_ok(driver); return; }
	dev = open("/dev/mac_capability", O_RDWR); CHECK(dev >= 0);
	a = capability_service_connect(dev, "coalition"); CHECK(a >= 0);
	b = capability_service_connect(dev, "coalition"); CHECK(b >= 0);
	dead = capability_service_connect(dev, "coalition"); CHECK(dead >= 0);
	close(dev);
	CHECK(coal_call(a, COALITION_OP_JOIN, -1) == 0);
	CHECK(coal_members(a) == 1);
	CHECK(coal_call(b, COALITION_OP_JOIN_REHOME, -1) == 0);
	CHECK(coal_members(a) == 0 && coal_members(b) == 1);
	CHECK(coal_call(b, COALITION_OP_JOIN_REHOME, -1) == 0);
	/* Reject attached descriptors without changing membership. */
	CHECK(coal_call(a, COALITION_OP_JOIN_REHOME, dead) == EINVAL);
	CHECK(coal_members(a) == 0 && coal_members(b) == 1);
	/* Opposite-direction moves share both locks; exercise their ordering. */
	{
		pid_t movers[16];

		for (unsigned i = 0; i < nitems(movers); i++) {
			movers[i] = fork(); CHECK(movers[i] >= 0);
			if (movers[i] == 0) {
				for (unsigned round = 0; round < 100; round++) {
					CHECK(coal_call(a, COALITION_OP_JOIN_REHOME, -1) == 0);
					CHECK(coal_call(b, COALITION_OP_JOIN_REHOME, -1) == 0);
				}
				_exit(0);
			}
		}
		for (unsigned i = 0; i < nitems(movers); i++)
			wait_ok(movers[i]);
		CHECK(coal_members(a) == 0 && coal_members(b) == 1);
	}
	CHECK(coal_call(dead, COALITION_OP_TERMINATE, -1) == 0);
	CHECK(coal_call(dead, COALITION_OP_JOIN_REHOME, -1) == ESHUTDOWN);
	CHECK(coal_members(b) == 1 && coal_members(dead) == 0);
	CHECK(pipe(gate) == 0 && pipe(ready) == 0);
	child = pdfork(&pd, PD_CLOEXEC); CHECK(child >= 0);
	if (child == 0) {
		close(gate[1]); close(ready[0]);
		CHECK(read(gate[0], &byte, 1) == 1);
		CHECK(coal_call(b, COALITION_OP_JOIN_REHOME, -1) == EBUSY);
		CHECK(write(ready[1], &byte, 1) == 1);
		CHECK(read(gate[0], &byte, 1) == 1);
		_exit(0);
	}
	close(gate[0]); close(ready[1]);
	CHECK(coal_call(a, COALITION_OP_ENLIST, pd) == 0);
	CHECK(write(gate[1], &byte, 1) == 1);
	CHECK(read(ready[0], &byte, 1) == 1);
	CHECK(coal_members(a) == 1 && coal_members(b) == 1);
	CHECK(write(gate[1], &byte, 1) == 1);
	wait_ok(child);
	close(pd); close(gate[1]); close(ready[0]);
	close(a); close(b); close(dead);
	_exit(0);
}

/* Run below PID 1 so PT_TRACE_ME exercises normal parent ownership. */
static void
debug_boundary_test(int issuer)
{
	pid_t driver, child;
	int token, own, ready[2], gate[2], status, round;
	char byte = 'R';

	driver = fork(); CHECK(driver >= 0);
	if (driver != 0) {
		wait_ok(driver);
		return;
	}
	for (round = 0; round < 4; round++) {
		CHECK(op(CAP_AUTH_CLEAR, -1, NULL) == 0);
		token = issue(issuer, CAP_AUTH_MANAGED, round == 3 ? 2101 : 0);
		if (round == 1)
			CHECK(op(CAP_AUTH_INSTALL, token, NULL) == 0);
		if (round == 2) {
			own = issue(issuer, CAP_AUTH_MANAGED, 0);
			CHECK(op(CAP_AUTH_INSTALL, own, NULL) == 0);
			close(own);
		}
		CHECK(pipe(ready) == 0 && pipe(gate) == 0);
		child = fork(); CHECK(child >= 0);
		if (child == 0) {
			close(ready[0]); close(gate[1]);
			if (round != 1)
				CHECK(op(CAP_AUTH_INSTALL, token, NULL) == 0);
			CHECK(write(ready[1], &byte, 1) == 1);
			CHECK(read(gate[0], &byte, 1) == 1);
			_exit(0);
		}
		close(ready[1]); close(gate[0]);
		CHECK(read(ready[0], &byte, 1) == 1);
		if (round == 1) {
			CHECK(ptrace(PT_ATTACH, child, NULL, 0) == 0);
			CHECK(waitpid(child, &status, WUNTRACED) == child);
			CHECK(WIFSTOPPED(status));
			CHECK(ptrace(PT_DETACH, child, (caddr_t)1, 0) == 0);
		} else
			CHECK(ptrace(PT_ATTACH, child, NULL, 0) == -1 && errno == EPERM);
		CHECK(write(gate[1], &byte, 1) == 1);
		wait_ok(child);
		close(ready[0]); close(gate[1]); close(token);
	}
	CHECK(op(CAP_AUTH_CLEAR, -1, NULL) == 0);
	token = issue(issuer, CAP_AUTH_MANAGED, 0);
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		CHECK(op(CAP_AUTH_INSTALL, token, NULL) == 0);
		CHECK(ptrace(PT_TRACE_ME, 0, NULL, 0) == -1 && errno == EPERM);
		_exit(0);
	}
	wait_ok(child); close(token);
	token = issue(issuer, CAP_AUTH_MANAGED, 0);
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		CHECK(ptrace(PT_TRACE_ME, 0, NULL, 0) == 0);
		CHECK(op(CAP_AUTH_INSTALL, token, NULL) == -1 && errno == EPERM);
		CHECK(token_info(token).consumed == 0);
		_exit(0);
	}
	wait_ok(child);
	CHECK(token_info(token).consumed == 0);
	CHECK(op(CAP_AUTH_INSTALL, token, NULL) == 0);
	close(token);
	_exit(0);
}

/* Release all contenders together: a genuine token still has only one use. */
static void
concurrent_install_test(int issuer)
{
	enum { CONTENDERS = 16 };
	pid_t children[CONTENDERS];
	char release[CONTENDERS], byte;
	int gate[2], token, status, winners = 0;
	unsigned i;

	token = issue(issuer, CAP_AUTH_MANAGED, 0);
	CHECK(pipe(gate) == 0);
	for (i = 0; i < CONTENDERS; i++) {
		children[i] = fork();
		CHECK(children[i] >= 0);
		if (children[i] == 0) {
			close(gate[1]);
			CHECK(read(gate[0], &byte, 1) == 1);
			close(gate[0]);
			if (op(CAP_AUTH_INSTALL, token, NULL) == 0) {
				CHECK(info().valid);
				_exit(0);
			}
			CHECK(errno == EALREADY);
			_exit(2);
		}
	}
	close(gate[0]);
	memset(release, 'R', sizeof(release));
	CHECK(write(gate[1], release, sizeof(release)) == sizeof(release));
	close(gate[1]);
	for (i = 0; i < CONTENDERS; i++) {
		CHECK(waitpid(children[i], &status, 0) == children[i]);
		CHECK(WIFEXITED(status));
		CHECK(WEXITSTATUS(status) == 0 || WEXITSTATUS(status) == 2);
		winners += WEXITSTATUS(status) == 0;
	}
	CHECK(winners == 1);
	CHECK(token_info(token).consumed == 1);
	CHECK(op(CAP_AUTH_INSTALL, token, NULL) == -1 && errno == EALREADY);
	close(token);
}

static void
provider_exec_tests(int issuer)
{
	struct cap_authority_constraint constraint = {
	    .nexec = 1 };
	int token, image, other, pair[2];
	pid_t child;
	char identity[32], endpoint[32];

	image = open("/sbin/authority-test", O_RDONLY);
	CHECK(image >= 0);
	constraint.executable_fds[0] = image;
	token = issue(issuer, CAP_AUTH_MANAGED, 0);
	constraint.token_fd = token;
	other = op(CAP_AUTH_ISSUER_CREATE, -1, NULL); CHECK(other >= 0);
	CHECK(op(CAP_AUTH_CONSTRAIN, other, &constraint) == -1 && errno == EPERM);
	close(other);
	constraint.nexec = 2; constraint.executable_fds[1] = -1;
	CHECK(op(CAP_AUTH_CONSTRAIN, issuer, &constraint) == -1 && errno == EBADF);
	constraint.nexec = 1;
	constraint.flags = 1; /* Retired fixed-UID flag must not be accepted. */
	CHECK(op(CAP_AUTH_CONSTRAIN, issuer, &constraint) == -1 && errno == EINVAL);
	constraint.flags = 0;
	CHECK(op(CAP_AUTH_CONSTRAIN, issuer, &constraint) == 0);
	CHECK(op(CAP_AUTH_CONSTRAIN, issuer, &constraint) == -1 && errno == EALREADY);
	CHECK(mac_capability_channel_create(pair) == 0);
	bind_to(issuer, token, pair[0]);
	CHECK(fcntl(pair[0], F_SETFD, 0) == 0);
	snprintf(identity, sizeof(identity), "%ju", (uintmax_t)token_info(token).identity);
	snprintf(endpoint, sizeof(endpoint), "%d", pair[0]);
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		CHECK(op(CAP_AUTH_INSTALL, token, NULL) == 0);
		CHECK(!info().valid); /* No issuer/launcher authority before approved exec. */
		execl("/sbin/authority-test", "authority-test", "--provider", identity,
		    endpoint, (char *)NULL);
		CHECK(0);
	}
	wait_ok(child);
	CHECK(op(CAP_AUTH_CONSTRAIN, issuer, &constraint) == -1 && errno == EALREADY);
	close(pair[0]); close(pair[1]); close(image); close(token);
}
static void
provider_child(char **argv)
{
	struct cap_authority_info before = info();
	int fd = atoi(argv[3]);
	pid_t child;
	char byte = 'x';

	CHECK(before.valid && before.identity == strtoull(argv[2], NULL, 10));
	CHECK(issetugid() != 0);
	CHECK(getuid() == 0 && geteuid() == 0);
	CHECK(send_one(fd, &byte, 1) == 0);
	CHECK(seteuid(2101) == 0 && info().valid);
	CHECK(send_one(fd, &byte, 1) == 0);
	CHECK(seteuid(0) == 0 && info().valid);
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		CHECK(setuid(2101) == 0 && info().valid);
		execl("/sbin/authority-test", "authority-test", "--valid-provider",
		    argv[2], argv[3], (char *)NULL);
		CHECK(0);
	}
	wait_ok(child);
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		execl("/sbin/authority-other", "authority-other", "--invalid-provider",
		    argv[2], argv[3], (char *)NULL);
		CHECK(0);
	}
	wait_ok(child);
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		int enable = PROC_NO_NEW_PRIVS_ENABLE;
		CHECK(procctl(P_PID, 0, PROC_NO_NEW_PRIVS_CTL, &enable) == 0);
		execl("/sbin/authority-test", "authority-test", "--invalid-provider",
		    argv[2], argv[3], (char *)NULL);
		CHECK(0);
	}
	wait_ok(child);
	CHECK(info().valid && info().identity == before.identity);
	CHECK(send_one(fd, &byte, 1) == 0);
}

static void
application_loader_test(int issuer)
{
	struct cap_authority_constraint constraint = { .nexec = 1 };
	struct cap_authority_application app;
	int token, image, status;
	pid_t child;

	/* Establish that the DSO really executes in an ordinary dynamic image. */
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		CHECK(setenv("LD_PRELOAD", "/lib/authority-inject.so", 1) == 0);
		execl("/sbin/authority-loader", "authority-loader", (char *)NULL);
		CHECK(0);
	}
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 91);
	image = open("/sbin/authority-loader", O_RDONLY); CHECK(image >= 0);
	token = issue(issuer, CAP_AUTH_MANAGED, 0);
	constraint.token_fd = token;
	constraint.executable_fds[0] = image;
	CHECK(op(CAP_AUTH_CONSTRAIN, issuer, &constraint) == 0);
	/* Not currently executing: the catalogue must still pin image contents. */
	CHECK(open("/sbin/authority-loader", O_WRONLY) == -1 && errno == ETXTBSY);
	app = (struct cap_authority_application){ token, 0 };
	CHECK(op(CAP_AUTH_REGISTER_APP, issuer, &app) == 0);
	for (unsigned i = 0; i < 2; i++) {
		child = fork(); CHECK(child >= 0);
		if (child == 0) {
			CHECK(op(CAP_AUTH_CLEAR, -1, NULL) == 0);
			CHECK(setuid(i == 0 ? 0 : 2101) == 0);
			CHECK(setenv("LD_PRELOAD", "/lib/authority-inject.so", 1) == 0);
			execl("/sbin/authority-loader", "authority-loader", (char *)NULL);
			CHECK(0);
		}
		wait_ok(child);
	}
	revoke_grant(issuer, token);
	close(token); close(image);
}

static void
sandboxed_loader_test(int issuer)
{
	struct cap_authority_constraint constraint = { .nexec = 1 };
	struct cap_authority_libdirs dirs = { .count = 1 };
	int image, directory, token;
	pid_t child;

	image = open("/sbin/authority-loader", O_RDONLY); CHECK(image >= 0);
	directory = open("/lib", O_RDONLY | O_DIRECTORY); CHECK(directory >= 0);
	token = issue(issuer, CAP_AUTH_MANAGED, 0);
	constraint.token_fd = token;
	constraint.executable_fds[0] = image;
	dirs.token_fd = token;
	dirs.directory_fds[0] = directory;
	CHECK(op(CAP_AUTH_CONSTRAIN, issuer, &constraint) == 0);
	CHECK(op(CAP_AUTH_SET_LIBDIRS, issuer, &dirs) == 0);
	close(directory);
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		char arg[] = "authority-loader";
		char preload[] = "LD_PRELOAD=/lib/authority-inject.so";
		char fds[] = "LD_LIBRARY_PATH_FDS=0";
		char path[] = "LD_LIBRARY_PATH=/tmp";
		char *args[] = { arg, NULL };
		char *env[] = { preload, fds, path, NULL };
		CHECK(op(CAP_AUTH_CLEAR, -1, NULL) == 0);
		CHECK(op(CAP_AUTH_INSTALL, token, NULL) == 0);
		CHECK(cap_enter() == 0);
		fexecve(image, args, env);
		CHECK(0);
	}
	wait_ok(child);
	revoke_grant(issuer, token);
	close(token); close(image);
}

static void
library_directory_child(void)
{
	cap_rights_t rights;
	int result;

	result = op(CAP_AUTH_GET_LIBDIR, 0, NULL); CHECK(result >= 0);
	CHECK((fcntl(result, F_GETFD) & FD_CLOEXEC) != 0);
	CHECK(cap_rights_get(result, &rights) == 0);
	CHECK(cap_rights_is_set(&rights, CAP_LOOKUP, CAP_READ, CAP_FSTAT));
	CHECK(!cap_rights_is_set(&rights, CAP_CREATE));
	close(result);
	CHECK(op(CAP_AUTH_GET_LIBDIR, 1, NULL) == -1 && errno == ENOENT);
	CHECK(op(CAP_AUTH_GET_LIBDIR, CAP_AUTH_LIBDIR_MAX, NULL) == -1 &&
	    errno == EINVAL);
	CHECK(op(CAP_AUTH_GET_LIBDIR, 0, &rights) == -1 && errno == EINVAL);
	CHECK(op(CAP_AUTH_CLEAR, -1, NULL) == 0);
	CHECK(op(CAP_AUTH_GET_LIBDIR, 0, NULL) == -1 && errno == ENOENT);
}

static void
library_directory_tests(int issuer)
{
	struct cap_authority_constraint constraint = { .nexec = 1 };
	struct cap_authority_libdirs dirs = { .count = 1 };
	cap_rights_t rights;
	int image, directory, token, other;
	pid_t child;

	image = open("/sbin/authority-test", O_RDONLY); CHECK(image >= 0);
	directory = open("/lib", O_RDONLY | O_DIRECTORY); CHECK(directory >= 0);
	CHECK(cap_rights_limit(directory, cap_rights_init(&rights,
	    CAP_LOOKUP, CAP_READ, CAP_FSTAT)) == 0);
	token = issue(issuer, CAP_AUTH_MANAGED, 0);
	constraint.token_fd = token;
	constraint.executable_fds[0] = image;
	dirs.token_fd = token;
	dirs.directory_fds[0] = directory;
	CHECK(op(CAP_AUTH_SET_LIBDIRS, issuer, &dirs) == -1 && errno == EINVAL);
	CHECK(op(CAP_AUTH_CONSTRAIN, issuer, &constraint) == 0);
	other = op(CAP_AUTH_ISSUER_CREATE, -1, NULL); CHECK(other >= 0);
	CHECK(op(CAP_AUTH_SET_LIBDIRS, other, &dirs) == -1 && errno == EPERM);
	close(other);
	dirs.directory_fds[0] = image;
	CHECK(op(CAP_AUTH_SET_LIBDIRS, issuer, &dirs) == -1 && errno == EINVAL);
	dirs.directory_fds[0] = directory;
	CHECK(op(CAP_AUTH_SET_LIBDIRS, issuer, &dirs) == 0);
	CHECK(op(CAP_AUTH_SET_LIBDIRS, issuer, &dirs) == -1 && errno == EINVAL);
	close(directory); /* The kernel reference must survive descriptor reuse. */
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		CHECK(op(CAP_AUTH_CLEAR, -1, NULL) == 0);
		CHECK(op(CAP_AUTH_GET_LIBDIR, 0, NULL) == -1 && errno == ENOENT);
		CHECK(op(CAP_AUTH_INSTALL, token, NULL) == 0);
		CHECK(cap_enter() == 0);
		char arg[] = "authority-test", mode[] = "--library-dirs";
		char *args[] = { arg, mode, NULL }, *env[] = { NULL };
		CHECK(op(CAP_AUTH_GET_LIBDIR, 0, NULL) == -1 && errno == ENOENT);
		fexecve(image, args, env);
		CHECK(0);
		_exit(0);
	}
	wait_ok(child);
	CHECK(op(CAP_AUTH_SET_LIBDIRS, issuer, &dirs) == -1 && errno == EALREADY);
	revoke_grant(issuer, token);
	close(token); close(image);
}

/* Ordinary exec: no PAM, user grant, token installation, or launcher helper. */
static void
application_exec_tests(int issuer)
{
	struct cap_authority_constraint constraint = { .nexec = 1 };
	struct cap_authority_application app;
	int token, image, duplicate, other, pair[2], ready[2], resume[2];
	pid_t child;
	char identity[32], endpoint[32], uid[32], readyfd[32], resumefd[32], byte;

	image = open("/sbin/authority-test", O_RDONLY); CHECK(image >= 0);
	constraint.executable_fds[0] = image;
	token = issue(issuer, CAP_AUTH_MANAGED, 0);
	app = (struct cap_authority_application){ token, 0 };
	CHECK(op(CAP_AUTH_REGISTER_APP, issuer, &app) == -1 && errno == EINVAL);
	CHECK(!token_info(token).consumed);
	constraint.token_fd = token;
	CHECK(op(CAP_AUTH_CONSTRAIN, issuer, &constraint) == 0);
	other = op(CAP_AUTH_ISSUER_CREATE, -1, NULL); CHECK(other >= 0);
	CHECK(op(CAP_AUTH_REGISTER_APP, other, &app) == -1 && errno == EPERM);
	close(other);
	CHECK(op(CAP_AUTH_REGISTER_APP, issuer, &app) == 0);
	CHECK(op(CAP_AUTH_REGISTER_APP, issuer, &app) == -1 && errno == EALREADY);
	CHECK(op(CAP_AUTH_INSTALL, token, NULL) == -1 && errno == EALREADY);
	duplicate = issue(issuer, CAP_AUTH_MANAGED, 0);
	constraint.token_fd = duplicate;
	CHECK(op(CAP_AUTH_CONSTRAIN, issuer, &constraint) == 0);
	app.token_fd = duplicate;
	CHECK(op(CAP_AUTH_REGISTER_APP, issuer, &app) == -1 && errno == EEXIST);
	CHECK(!token_info(duplicate).consumed);
	close(duplicate);
	CHECK(mac_capability_channel_create(pair) == 0);
	bind_to(issuer, token, pair[0]);
	CHECK(fcntl(pair[0], F_SETFD, 0) == 0);
	snprintf(identity, sizeof(identity), "%ju", (uintmax_t)token_info(token).identity);
	snprintf(endpoint, sizeof(endpoint), "%d", pair[0]);
	for (unsigned i = 0; i < 4; i++) {
		child = fork(); CHECK(child >= 0);
		if (child == 0) {
			CHECK(op(CAP_AUTH_CLEAR, -1, NULL) == 0);
			CHECK(setuid(i == 0 ? 0 : 2101) == 0);
			CHECK(!info().valid);
			if (i == 2) {
				int enable = PROC_NO_NEW_PRIVS_ENABLE;
				CHECK(procctl(P_PID, 0, PROC_NO_NEW_PRIVS_CTL, &enable) == 0);
			}
			snprintf(uid, sizeof(uid), "%u", (unsigned)getuid());
			execl(i == 3 ? "/sbin/authority-other" : "/sbin/authority-test",
			    "authority-test", "--application", identity, endpoint, uid,
			    i >= 2 ? "denied" : "allowed", (char *)NULL);
			CHECK(0);
		}
		wait_ok(child);
	}
	/* Revoke while an attributed client holds a cached endpoint. */
	CHECK(pipe(ready) == 0 && pipe(resume) == 0);
	snprintf(readyfd, sizeof(readyfd), "%d", ready[1]);
	snprintf(resumefd, sizeof(resumefd), "%d", resume[0]);
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		CHECK(op(CAP_AUTH_CLEAR, -1, NULL) == 0);
		execl("/sbin/authority-test", "authority-test", "--application",
		    identity, endpoint, "0", "wait", readyfd, resumefd, (char *)NULL);
		CHECK(0);
	}
	close(ready[1]); close(resume[0]);
	CHECK(read(ready[0], &byte, 1) == 1);
	revoke_grant(issuer, token);
	CHECK(write(resume[1], "r", 1) == 1);
	wait_ok(child);
	close(ready[0]); close(resume[1]);
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		CHECK(op(CAP_AUTH_CLEAR, -1, NULL) == 0);
		execl("/sbin/authority-test", "authority-test", "--application",
		    identity, endpoint, "0", "denied", (char *)NULL);
		CHECK(0);
	}
	wait_ok(child);
	close(pair[0]); close(pair[1]); close(token);
	/* Catalogue ownership outlives its token FD, but never its issuer FD. */
	other = op(CAP_AUTH_ISSUER_CREATE, -1, NULL); CHECK(other >= 0);
	token = issue(other, CAP_AUTH_MANAGED, 0);
	constraint.token_fd = token;
	CHECK(op(CAP_AUTH_CONSTRAIN, other, &constraint) == 0);
	app.token_fd = token;
	CHECK(op(CAP_AUTH_REGISTER_APP, other, &app) == 0);
	close(token); close(other);
	token = issue(issuer, CAP_AUTH_MANAGED, 0);
	constraint.token_fd = token;
	CHECK(op(CAP_AUTH_CONSTRAIN, issuer, &constraint) == 0);
	app.token_fd = token;
	CHECK(op(CAP_AUTH_REGISTER_APP, issuer, &app) == 0);
	revoke_grant(issuer, token);
	close(token); close(image);
}

static void
application_child(char **argv)
{
	char byte = 'a';
	int fd = atoi(argv[3]);
	pid_t child;

	CHECK(getuid() == strtoul(argv[4], NULL, 10));
	CHECK(geteuid() == getuid());
	if (strcmp(argv[5], "denied") == 0) {
		CHECK(!info().valid);
		CHECK(send_one(fd, &byte, 1) == -1 && errno == EPERM);
		return;
	}
	CHECK(info().valid && info().kind == CAP_AUTH_MANAGED);
	CHECK(info().identity == strtoull(argv[2], NULL, 10));
	CHECK(issetugid() != 0);
	CHECK(send_one(fd, &byte, 1) == 0);
	if (strcmp(argv[5], "wait") == 0) {
		CHECK(write(atoi(argv[6]), "r", 1) == 1);
		CHECK(read(atoi(argv[7]), &byte, 1) == 1);
		CHECK(!info().valid);
		CHECK(send_one(fd, &byte, 1) == -1 && errno == EPERM);
		return;
	}
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		CHECK(info().valid);
		CHECK(send_one(fd, &byte, 1) == 0);
		execl("/sbin/authority-other", "authority-other", "--application",
		    argv[2], argv[3], argv[4], "denied", (char *)NULL);
		CHECK(0);
	}
	wait_ok(child);
}

static void
pass(const char *name)
{
	printf("PASS authority-%s\n", name);
}
/* A prison transition must invalidate context and already-bound handles. */
static void
prison_transition_tests(int issuer)
{
	struct cap_authority_info before, after;
	char path[] = "/";
	char name[] = "authority-prison-test";
	struct jail prison = {
		.version = JAIL_API_VERSION,
		.path = path,
		.hostname = name,
		.jailname = name
	};
	int token, spare, pair[2];
	pid_t child;
	char byte = 'p';

	token = issue(issuer, CAP_AUTH_MANAGED, 0);
	spare = issue(issuer, CAP_AUTH_MANAGED, 0);
	CHECK(mac_capability_channel_create(pair) == 0);
	bind_to(issuer, token, pair[0]);
	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		CHECK(op(CAP_AUTH_INSTALL, token, NULL) == 0);
		before = info();
		CHECK(before.valid);
		CHECK(send_one(pair[0], &byte, 1) == 0);
		CHECK(jail(&prison) > 0);
		after = info();
		CHECK(!after.valid);
		CHECK(after.identity == before.identity);
		CHECK(after.generation > before.generation);
		CHECK(send_one(pair[0], &byte, 1) == -1 && errno == EPERM);
		CHECK(op(CAP_AUTH_INSTALL, spare, NULL) == -1 && errno == EPERM);
		CHECK(seteuid(65534) == 0);
		CHECK(seteuid(0) == 0);
		CHECK(!info().valid);
		CHECK(send_one(pair[0], &byte, 1) == -1 && errno == EPERM);
		_exit(0);
	}
	wait_ok(child);
	CHECK(!info().valid);
	close(pair[0]);
	close(pair[1]);
	close(token);
	close(spare);
}

static void
run_tests(void)
{
	int issuer, other, token, copy, pair[2], pipefd[2], ready[2], status;
	pid_t child;
	struct cap_authority_info before, after;
	cap_rights_t rights;
	char byte = 'x';

	CHECK(getpid() == 1);
	CHECK(!info().valid);
	issuer = op(CAP_AUTH_ISSUER_CREATE, -1, NULL);
	CHECK(issuer >= 0);
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		CHECK(getuid() == 0);
		CHECK(op(CAP_AUTH_ISSUER_CREATE, -1, NULL) == -1 && errno == EPERM);
		_exit(0);
	}
	wait_ok(child);
	pass("root-is-not-an-issuer");

	prison_transition_tests(issuer);
	pass("prison-transition-invalidates-authority");

	token = issue(issuer, CAP_AUTH_MANAGED, 0);
	before = token_info(token);
	CHECK(!before.consumed && !before.revoked && before.references == 1);
	copy = dup(token); CHECK(copy >= 0);
	CHECK(op(CAP_AUTH_INSTALL, token, NULL) == 0);
	after = info();
	CHECK(after.valid && after.kind == CAP_AUTH_MANAGED && after.uid == 0);
	CHECK(after.issuer == before.issuer && after.identity == before.identity);
	CHECK(op(CAP_AUTH_INSTALL, copy, NULL) == -1 && errno == EALREADY);
	CHECK(op(CAP_AUTH_INSTALL, issuer, NULL) == -1 && errno == EINVAL);
	close(copy);
	CHECK(token_info(token).references == 2);
	pass("one-use-object-not-wire-identity");

	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		char id[32];
		CHECK(info().identity == before.identity && info().valid);
		snprintf(id, sizeof(id), "%ju", (uintmax_t)before.identity);
		closefrom(3);
		execl("/sbin/authority-test", "authority-test", "--exec", id, NULL);
		failure(__LINE__, "exec");
	}
	wait_ok(child);
	pass("fork-exec-closefrom");

	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		CHECK(seteuid(2101) == 0);
		CHECK(info().valid && info().identity == before.identity);
		CHECK(seteuid(0) == 0);
		CHECK(setreuid(2101, 0) == 0);
		CHECK(info().valid && info().identity == before.identity);
		CHECK(setreuid(0, 0) == 0);
		CHECK(info().valid && info().identity == before.identity);
		_exit(0);
	}
	wait_ok(child);
	pass("unix-uid-changes-preserve-software-identity");

	CHECK(mac_capability_channel_create(pair) == 0);
	bind_to(issuer, token, pair[0]);
	CHECK(send_one(pair[0], &before, sizeof(before)) == 0);
	struct mac_capability_recvmsg_v3_args recv = { 0 };
	struct cap_authority_info payload;
	recv.message.payload = &payload;
	recv.message.payload_len = sizeof(payload);
	for (status = 0; status < 1000; status++) {
		if (ioctl(pair[1], MAC_CAPABILITY_RECVMSG_V3, &recv) == 0)
			break;
		CHECK(errno == EAGAIN); usleep(1000);
	}
	CHECK(status < 1000);
	CHECK(recv.authority.valid && recv.authority.issuer == before.issuer);
	CHECK(recv.authority.identity == before.identity);
	CHECK(recv.authority.generation == info().generation);
	CHECK(recv.process.pid == 1);
	pass("kernel-stamped-sender");

	/* Copyin failures must release the message's retained authority. */
	before = token_info(token);
	for (status = 0; status < 128; status++)
		CHECK(send_one(pair[0], (void *)1, 8) == -1 && errno == EFAULT);
	CHECK(token_info(token).references == before.references);
	pass("bad-payload-no-reference-leak");

	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		CHECK(op(CAP_AUTH_CLEAR, -1, NULL) == 0);
		CHECK(send_one(pair[0], &byte, 1) == -1 && errno == EPERM);
		CHECK(setuid(0) == 0 && !info().valid);
		CHECK(send_one(pair[0], &byte, 1) == -1 && errno == EPERM);
		_exit(0);
	}
	wait_ok(child);
	revoke_grant(issuer, token);
	CHECK(!info().valid);
	CHECK(send_one(pair[0], &byte, 1) == -1 && errno == EPERM);
	CHECK(token_info(token).revoked);
	close(pair[0]); close(pair[1]);
	CHECK(op(CAP_AUTH_CLEAR, -1, NULL) == 0);
	CHECK(token_info(token).references == 1);
	close(token);
	pass("cached-handle-and-explicit-revocation");

	struct cap_authority_spec retired = {
	    CAP_AUTH_VERSION, CAP_AUTH_RETIRED_USER, 2101, 0 };
	CHECK(op(CAP_AUTH_ISSUE, issuer, &retired) == -1 && errno == EINVAL);
	pass("retired-user-authority-rejected");

	token = issue(issuer, CAP_AUTH_MANAGED, 0);
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		CHECK(op(CAP_AUTH_INSTALL, token, NULL) == 0);
		before = info(); CHECK(before.valid);
		CHECK(setuid(2101) == 0);
		CHECK(info().valid && info().identity == before.identity);
		CHECK(info().kind == CAP_AUTH_MANAGED);
		_exit(0);
	}
	wait_ok(child); close(token);
	pass("managed-manifest-survives-uid-drop");
	coalition_rehome_test();
	pass("coalition-session-rehome-atomicity-and-pinned-membership");
	debug_boundary_test(issuer);
	pass("debugger-isolation-and-traced-install-rejection");
	concurrent_install_test(issuer);
	pass("concurrent-token-install-single-winner");
	provider_exec_tests(issuer);
	pass("software-exec-constraints-and-uid-independence");
	library_directory_tests(issuer);
	pass("issuer-library-directories-and-rights-preservation");
	application_exec_tests(issuer);
	pass("ordinary-exec-software-authority-and-uid-independence");
	sandboxed_loader_test(issuer);
	pass("sandboxed-secure-loader-with-hostile-environment");
	application_loader_test(issuer);
	pass("application-loader-injection-denial-and-pinned-contents");

	for (status = 0; status < 4; status++) {
		token = issue(issuer, CAP_AUTH_MANAGED, 0);
		if (status == 0) CHECK(cap_rights_limit(token,
		    cap_rights_init(&rights, CAP_FSTAT)) == 0);
		if (status == 1) CHECK(syscall(SYS_cap_clofork_limit, token,
		    CAP_CLOFORK_LOCKED) == 0);
		if (status == 2) CHECK(syscall(SYS_cap_cloexec_limit, token,
		    CAP_CLOEXEC_LOCKED) == 0);
		if (status == 3) CHECK(syscall(SYS_cap_clofork_limit, token,
		    CAP_CLOFORK_ONCE) == 0);
		CHECK(op(CAP_AUTH_INSTALL, token, NULL) == -1 && errno == ENOTCAPABLE);
		CHECK(!token_info(token).consumed);
		close(token);
	}
	pass("attenuated-tokens-cannot-be-laundered");

	other = op(CAP_AUTH_ISSUER_CREATE, -1, NULL); CHECK(other >= 0);
	token = issue(issuer, CAP_AUTH_MANAGED, 0);
	struct cap_authority_revoke bad = { token, 0 };
	CHECK(op(CAP_AUTH_REVOKE, other, &bad) == -1 && errno == EPERM);
	close(other); close(token);
	pass("issuers-cannot-revoke-each-other");

	/* The recipient keeps a context, but never a copy of the issuer key. */
	token = issue(issuer, CAP_AUTH_MANAGED, 0);
	CHECK(pipe(pipefd) == 0);
	CHECK(pipe(ready) == 0);
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		close(pipefd[1]); close(ready[0]); close(issuer);
		CHECK(op(CAP_AUTH_INSTALL, token, NULL) == 0);
		CHECK(info().valid);
		CHECK(write(ready[1], &byte, 1) == 1);
		close(ready[1]);
		CHECK(read(pipefd[0], &byte, 1) == 1);
		CHECK(!info().valid);
		_exit(0);
	}
	close(pipefd[0]); close(ready[1]);
	CHECK(read(ready[0], &byte, 1) == 1);
	close(ready[0]);
	close(issuer);
	CHECK(write(pipefd[1], &byte, 1) == 1);
	close(pipefd[1]); wait_ok(child); close(token);
	pass("issuer-death-revokes-context");
}
static void
isolation_mapping_race(int service, int file, size_t length)
{
	struct fi_request request;
	struct fi_reply reply;
	struct mac_capability_call_args call = { 0 };
	int command[2], result[2], mapped, claimed, error;
	unsigned claim_wins = 0, mapping_wins = 0;
	char byte = 'x';
	pid_t child;

	call.req = &request; call.req_len = sizeof(request);
	call.req_fds = &file; call.req_nfds = 1;
	call.reply = &reply; call.reply_len = sizeof(reply);
	for (unsigned round = 0; round < 64; round++) {
		CHECK(pipe(command) == 0 && pipe(result) == 0);
		child = fork(); CHECK(child >= 0);
		if (child == 0) {
			void *mapping;
			close(command[1]); close(result[0]);
			CHECK(read(command[0], &byte, 1) == 1);
			mapping = mmap(NULL, length,
			    PROT_READ | ((round & 1) ? PROT_WRITE : 0),
			    MAP_SHARED, file, 0);
			mapped = mapping != MAP_FAILED;
			CHECK(mapped || errno == EACCES);
			CHECK(write(result[1], &mapped, sizeof(mapped)) == sizeof(mapped));
			/* Keep a successful mapping alive until the claim result is checked. */
			CHECK(read(command[0], &byte, 1) == 1);
			if (mapped)
				CHECK(munmap(mapping, length) == 0);
			_exit(0);
		}
		close(command[0]); close(result[1]);
		/* First two rounds force each winner; remaining rounds race freely. */
		if (round != 0)
			CHECK(write(command[1], &byte, 1) == 1);
		if (round == 1)
			CHECK(read(result[0], &mapped, sizeof(mapped)) == sizeof(mapped));
		request = (struct fi_request){ .op = FI_OP_CLAIM };
		claimed = ioctl(service, MAC_CAPABILITY_CALL, &call);
		error = errno;
		if (round == 0)
			CHECK(write(command[1], &byte, 1) == 1);
		if (round != 1)
			CHECK(read(result[0], &mapped, sizeof(mapped)) == sizeof(mapped));
		if (claimed == 0) {
			CHECK(!mapped);
			claim_wins++;
			request.op = FI_OP_RELEASE;
			CHECK(ioctl(service, MAC_CAPABILITY_CALL, &call) == 0);
		} else {
			CHECK(error == EBUSY && mapped);
			mapping_wins++;
		}
		CHECK(write(command[1], &byte, 1) == 1);
		close(command[1]); close(result[0]);
		wait_ok(child);
	}
	CHECK(claim_wins > 0 && mapping_wins > 0);
	pass("isolation-claim-mmap-race");
}

static void
isolation_write_test(void)
{
	struct mac_capability_connect_args connect = { 0 };
	struct mac_capability_call_args call = { 0 };
	struct fi_request request = { .op = FI_OP_CLAIM };
	struct fi_reply reply;
	char mount_values[8][32] = {
		"fstype", "ufs", "fspath", "/", "from", "/dev/vtbd0p2", "noro", ""
	};
	struct iovec mount_options[8];
	char descriptor[32], expected[8];
	int ctl, file, phase, readonly;
	void *mapping;
	size_t page_size = (size_t)getpagesize();
	pid_t child;

	/* The disposable PID 1 fixture owns this UFS image; no host mount occurs. */
	for (unsigned i = 0; i < 8; i++) {
		mount_options[i].iov_base = mount_values[i];
		mount_options[i].iov_len = strlen(mount_values[i]) + 1;
	}
	CHECK(nmount(mount_options, 8, MNT_UPDATE) == 0);
	ctl = open("/dev/mac_capability", O_RDWR);
	CHECK(ctl >= 0);
	strlcpy(connect.name, "isolation", sizeof(connect.name));
	CHECK(ioctl(ctl, MAC_CAPABILITY_CONNECT, &connect) == 0);
	close(ctl);
	file = open("/isolation-write-test", O_RDWR | O_CREAT, 0600);
	CHECK(file >= 0);
	call.req = &request; call.req_len = sizeof(request);
	call.req_fds = &file; call.req_nfds = 1;
	call.reply = &reply; call.reply_len = sizeof(reply);
	CHECK(ftruncate(file, (off_t)page_size) == 0);
	/* Even a currently read-only shared mapping may have writable maxprot. */
	mapping = mmap(NULL, page_size, PROT_READ, MAP_SHARED, file, 0);
	CHECK(mapping != MAP_FAILED);
	CHECK(ioctl(connect.fd, MAC_CAPABILITY_CALL, &call) == -1 && errno == EBUSY);
	CHECK(munmap(mapping, page_size) == 0);
	CHECK(ioctl(connect.fd, MAC_CAPABILITY_CALL, &call) == 0);
	CHECK(pwrite(file, "o", 1, 0) == 1);
	CHECK(mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0) ==
	    MAP_FAILED && errno == EACCES);
	CHECK(mmap(NULL, page_size, PROT_READ, MAP_SHARED, file, 0) ==
	    MAP_FAILED && errno == EACCES);
	mapping = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, file, 0);
	CHECK(mapping != MAP_FAILED);
	*(char *)mapping = 'c';
	CHECK(munmap(mapping, page_size) == 0);
	readonly = open("/isolation-write-test", O_RDONLY);
	CHECK(readonly >= 0);
	mapping = mmap(NULL, page_size, PROT_READ, MAP_SHARED, readonly, 0);
	CHECK(mapping != MAP_FAILED);
	CHECK(*(char *)mapping == 'o');
	CHECK(mprotect(mapping, page_size, PROT_READ | PROT_WRITE) == -1 &&
	    errno == EACCES);
	CHECK(munmap(mapping, page_size) == 0);
	close(readonly);
	snprintf(descriptor, sizeof(descriptor), "%d", file);
	for (phase = 1; phase >= 0; phase--) {
		if (phase == 0) {
			request.op = FI_OP_RELEASE;
			CHECK(ioctl(connect.fd, MAC_CAPABILITY_CALL, &call) == 0);
		}
		snprintf(expected, sizeof(expected), "%d", phase);
		child = fork(); CHECK(child >= 0);
		if (child == 0) {
			execl("/sbin/authority-test", "authority-test", "--isolation-write",
			    descriptor, expected, NULL);
			_exit(127);
		}
		wait_ok(child);
	}
	isolation_mapping_race(connect.fd, file, page_size);
	close(file); close(connect.fd);
	CHECK(unlink("/isolation-write-test") == 0);
	pass("isolation-inherited-write");
}

static void
system_partial_release_test(void)
{
	struct mac_capability_connect_args connect = { 0 };
	struct sys_request request = { .op = SYS_OP_CLAIM,
	    .gates = SYS_GATE_KLDLOAD | SYS_GATE_KLDUNLOAD };
	struct mac_capability_call_args call = {
	    .req = &request, .req_len = sizeof(request) };
	int ctl, token;

	ctl = open("/dev/mac_capability", O_RDWR);
	CHECK(ctl >= 0);
	strlcpy(connect.name, "system", sizeof(connect.name));
	CHECK(ioctl(ctl, MAC_CAPABILITY_CONNECT, &connect) == 0);
	close(ctl);
	CHECK(ioctl(connect.fd, MAC_CAPABILITY_CALL, &call) == 0);
	/* Releasing SYSCTL while another gate remains must discard the old OIDs.
	 * Synthetic MIBs exercise scope storage without changing real sysctls. */
	struct {
		struct sys_request request;
		uint32_t count;
		struct sys_sysctl_oid oids[SYS_SYSCTL_MAXOIDS];
	} scoped = { .request = { .op = SYS_OP_CLAIM,
	    .gates = SYS_GATE_SYSCTL }, .count = SYS_SYSCTL_MAXOIDS };
	struct mac_capability_call_args scope_call = {
	    .req = &scoped, .req_len = sizeof(scoped) };
	for (unsigned round = 0; round < 2; round++) {
		for (unsigned i = 0; i < SYS_SYSCTL_MAXOIDS; i++) {
			scoped.oids[i].depth = 2;
			scoped.oids[i].mib[0] = 100000;
			scoped.oids[i].mib[1] = round * SYS_SYSCTL_MAXOIDS + i;
		}
		CHECK(ioctl(connect.fd, MAC_CAPABILITY_CALL, &scope_call) == 0);
		request.op = SYS_OP_RELEASE;
		request.gates = SYS_GATE_SYSCTL;
		CHECK(ioctl(connect.fd, MAC_CAPABILITY_CALL, &call) == 0);
	}
	request.op = SYS_OP_RELEASE;
	request.gates = SYS_GATE_KLDLOAD | SYS_GATE_REBOOT;
	CHECK(ioctl(connect.fd, MAC_CAPABILITY_CALL, &call) == -1 && errno == EINVAL);
	request.gates = SYS_GATE_KLDLOAD;
	CHECK(ioctl(connect.fd, MAC_CAPABILITY_CALL, &call) == 0);
	request.op = SYS_OP_MINT;
	request.gates = SYS_GATE_KLDUNLOAD;
	call.reply_fds = &token;
	call.reply_nfds = 1;
	CHECK(ioctl(connect.fd, MAC_CAPABILITY_CALL, &call) == 0);
	close(token);
	request.gates = SYS_GATE_KLDLOAD;
	call.reply_nfds = 1;
	CHECK(ioctl(connect.fd, MAC_CAPABILITY_CALL, &call) == -1 && errno == EINVAL);
	request.op = SYS_OP_CLAIM;
	call.reply_fds = NULL;
	call.reply_nfds = 0;
	CHECK(ioctl(connect.fd, MAC_CAPABILITY_CALL, &call) == 0);
	request.op = SYS_OP_RELEASE;
	request.gates = SYS_GATE_KLDUNLOAD;
	CHECK(ioctl(connect.fd, MAC_CAPABILITY_CALL, &call) == 0);
	request.gates = 0; /* Legacy release-all still works. */
	CHECK(ioctl(connect.fd, MAC_CAPABILITY_CALL, &call) == 0);
	close(connect.fd);
	pass("system-partial-release-preserves-other-gates");
}

static int
mixed_connect_system(void)
{
	struct mac_capability_connect_args a = {0};
	int fd = open("/dev/mac_capability", O_RDWR);
	CHECK(fd >= 0);
	strlcpy(a.name, "system", sizeof(a.name));
	CHECK(ioctl(fd, MAC_CAPABILITY_CONNECT, &a) == 0);
	close(fd);
	return a.fd;
}
static void
mixed_request(int fd, uint32_t op)
{
	struct sys_request r = {.op = op, .gates = SYS_GATE_SYSCTL};
	struct mac_capability_call_args c = {.req = &r, .req_len = sizeof(r)};
	CHECK(ioctl(fd, MAC_CAPABILITY_CALL, &c) == 0);
}
static void
mixed_scoped_claim(int fd, const char *name)
{
	struct {
		struct sys_request r;
		uint32_t count;
		struct sys_sysctl_oid oid;
	} r = {.r = {.op = SYS_OP_CLAIM, .gates = SYS_GATE_SYSCTL}, .count = 1};
	size_t depth = CTL_MAXNAME;
	CHECK(sysctlnametomib(name, r.oid.mib, &depth) == 0);
	r.oid.depth = depth;
	struct mac_capability_call_args c = {.req = &r, .req_len = sizeof(r)};
	CHECK(ioctl(fd, MAC_CAPABILITY_CALL, &c) == 0);
}
static void
mixed_drop(int fd, int closing)
{
	if (!closing)
		mixed_request(fd, SYS_OP_RELEASE);
	close(fd);
}
static void
mixed_probe(const char *phase, const char *name, int denied, int a, int b)
{
	int status;
	pid_t p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		if (a >= 0)
			close(a);
		if (b >= 0)
			close(b);
		execl("/sbin/authority-other", "authority-test",
		      "--mixed-sysctl", phase, denied ? "deny" : "allow", name,
		      NULL);
		_exit(127);
	}
	CHECK(waitpid(p, &status, 0) == p);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void
mixed_sysctl_child(char **argv)
{
	char value[256];
	size_t len = sizeof(value);
	CHECK(sysctlbyname(argv[4], value, &len, NULL, 0) == 0);
	errno = 0;
	int rc = sysctlbyname(argv[4], NULL, NULL, value, strlen(value));
	int error = errno;
	if (strcmp(argv[3], "deny") == 0)
		CHECK(rc == -1 && error == EPERM);
	else
		CHECK(rc == 0);
}

static void
system_mixed_sysctl_test(void)
{
	const char *host = "kern.hostname", *domain = "kern.domainname";
	mixed_probe("baseline", host, 0, -1, -1);
	for (int order = 0; order < 2; order++)
		for (int remove_scope = 0; remove_scope < 2; remove_scope++)
			for (int closing = 0; closing < 2; closing++) {
				printf("MIXED_CASE order=%d remove_scope=%d "
				       "close=%d\n",
				       order, remove_scope, closing);
				fflush(stdout);
				int coarse = mixed_connect_system(),
				    scoped = mixed_connect_system();
				if (order == 0)
					mixed_request(coarse, SYS_OP_CLAIM);
				else
					mixed_scoped_claim(scoped, domain);
				mixed_probe("first-claim", host, order == 0,
					    coarse, scoped);
				if (order == 0)
					mixed_scoped_claim(scoped, domain);
				else
					mixed_request(coarse, SYS_OP_CLAIM);
				mixed_request(coarse, SYS_OP_CLAIM);
				mixed_scoped_claim(
				    scoped, domain); /* idempotent reclaims */
				mixed_probe("both-host", host, 1, coarse,
					    scoped);
				mixed_probe("both-domain", domain, 1, coarse,
					    scoped);
				if (remove_scope) {
					mixed_drop(scoped, closing);
					scoped = -1;
				} else {
					mixed_drop(coarse, closing);
					coarse = -1;
				}
				mixed_probe("one-left-host", host, remove_scope,
					    coarse, scoped);
				mixed_probe("one-left-domain", domain, 1,
					    coarse, scoped);
				mixed_drop(remove_scope ? coarse : scoped,
					   closing);
				mixed_probe("released-host", host, 0, -1, -1);
				mixed_probe("released-domain", domain, 0, -1,
					    -1);
			}
	/* Narrowing this connection does not leave an extra coarse reference.
	 */
	int one = mixed_connect_system();
	mixed_request(one, SYS_OP_CLAIM);
	mixed_scoped_claim(one, domain);
	mixed_probe("same-connection-host", host, 0, one, -1);
	mixed_probe("same-connection-domain", domain, 1, one, -1);
	mixed_request(
	    one, SYS_OP_CLAIM); /* no-payload re-claim remains idempotent */
	mixed_probe("same-connection-reclaim", host, 0, one, -1);
	mixed_drop(one, 0);
	/* Last scoped release must discard its OIDs even while coarse remains.
	 */
	int coarse = mixed_connect_system(), scoped = mixed_connect_system();
	mixed_request(coarse, SYS_OP_CLAIM);
	mixed_scoped_claim(scoped, domain);
	mixed_request(scoped, SYS_OP_RELEASE);
	mixed_scoped_claim(scoped, host);
	mixed_drop(coarse, 0);
	coarse = -1;
	mixed_probe("new-scope-host", host, 1, scoped, -1);
	mixed_probe("old-scope-cleared", domain, 0, scoped, -1);
	mixed_drop(scoped, 0);
	mixed_probe("final-host", host, 0, -1, -1);
	mixed_probe("final-domain", domain, 0, -1, -1);
	pass("system-mixed-sysctl-claims");
}

int
main(int argc, char **argv)
{
	if (argc == 5 && strcmp(argv[1], "--mixed-sysctl") == 0) {
		mixed_sysctl_child(argv);
		return (0);
	}
	if (argc == 2 && strcmp(argv[1], "--library-dirs") == 0) {
		library_directory_child();
		return (0);
	}
	if ((argc == 6 || argc == 8) && strcmp(argv[1], "--application") == 0) {
		application_child(argv);
		return (0);
	}
	if (argc == 4 && strcmp(argv[1], "--isolation-write") == 0) {
		ssize_t result = pwrite(atoi(argv[2]), "x", 1, 0);
		if (atoi(argv[3]) != 0)
			CHECK(result == -1 && (errno == EPERM || errno == EACCES));
		else
			CHECK(result == 1);
		return (0);
	}
	if (argc == 3 && strcmp(argv[1], "--exec") == 0) {
		CHECK(info().valid && info().identity == strtoull(argv[2], NULL, 10));
		return (0);
	}
	if (argc == 4 && strcmp(argv[1], "--provider") == 0) {
		provider_child(argv);
		return (0);
	}
	if (argc == 4 && strcmp(argv[1], "--valid-provider") == 0) {
		char byte = 'x';
		CHECK(info().valid);
		CHECK(info().identity == strtoull(argv[2], NULL, 10));
		CHECK(send_one(atoi(argv[3]), &byte, 1) == 0);
		return (0);
	}
	if (argc == 4 && strcmp(argv[1], "--invalid-provider") == 0) {
		char byte = 'x';
		CHECK(!info().valid);
		CHECK(info().identity == strtoull(argv[2], NULL, 10));
		CHECK(send_one(atoi(argv[3]), &byte, 1) == -1 && errno == EPERM);
		return (0);
	}
	int console = open("/dev/console", O_RDWR);
	if (console >= 0) {
		dup2(console, 0); dup2(console, 1); dup2(console, 2);
		if (console > 2) close(console);
	}
	setvbuf(stdout, NULL, _IONBF, 0);
	isolation_write_test();
	system_partial_release_test();
	system_mixed_sysctl_test();
	run_tests();
	printf("AUTHORITY_KERNEL_VM_PASS checks=%u\n", checks);
	sync();
	reboot(RB_POWEROFF);
	for (;;) pause();
}
