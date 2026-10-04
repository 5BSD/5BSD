/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/cap_process.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <channel.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x)                                                        \
	do {                                                            \
		if (!(x))                                               \
			errx(1, "line %d: %s (errno %d)", __LINE__, #x, \
			    errno);                                     \
	} while (0)
static int
call(int op, int fd, uid_t uid, void *p)
{
	return cap_process(op, fd, uid, p);
}
static void
info(struct mac_cap_process_info *i)
{
	CHECK(call(MAC_CAP_PROCESS_INFO, -1, 0, i) == 0);
}
static void
waitok(pid_t p)
{
	int st;
	CHECK(waitpid(p, &st, 0) == p);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
}
static void
pair(int f[2])
{
	CHECK(mac_capability_channel_create(f) == 0);
}
static void
set(int fd, uid_t uid)
{
	CHECK(call(MAC_CAP_PROCESS_SET, fd, uid, NULL) == 0);
}
static int
get(void)
{
	return call(MAC_CAP_PROCESS_GET, -1, 0, NULL);
}
static void
clear(void)
{
	CHECK(call(MAC_CAP_PROCESS_CLEAR, -1, 0, NULL) == 0);
}
static void
pass(const char *s)
{
	printf("PASS %s\n", s);
	fflush(stdout);
}
int
main(int argc, char **argv)
{
	struct mac_cap_process_info a, b, c;
	struct mac_capability_info_args fi;
	int f[2], g[2], fd, token;
	pid_t pid;
	if (argc == 2 && strcmp(argv[1], "exec") == 0) {
		CHECK(getenv("SERVICE_LOOKUP_FD") == NULL);
		fd = get();
		CHECK(fd >= 0);
		CHECK(fcntl(fd, F_GETFD) & FD_CLOEXEC);
		close(fd);
		return 0;
	}
	unsetenv("SERVICE_LOOKUP_FD");
	clear();
	CHECK(get() < 0 && errno == ENOENT);
	pair(f);
	set(f[0], getuid());
	info(&a);
	close(f[0]);
	fd = get();
	CHECK(fd >= 0);
	CHECK(fcntl(fd, F_GETFD) & FD_CLOEXEC);
	close(fd);
	pass("held-reference-and-cloexec");
	pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		info(&b);
		CHECK(a.identity != b.identity);
		closefrom(3);
		clearenv();
		execl(argv[0], argv[0], "exec", NULL);
		_exit(99);
	}
	waitok(pid);
	pass("fork-exec-clearenv-closefrom");
	pid = vfork();
	CHECK(pid >= 0);
	if (pid == 0) {
		execl(argv[0], argv[0], "exec", NULL);
		_exit(99);
	}
	waitok(pid);
	pass("vfork-exec");
	info(&a);
	CHECK(
	    execl("/no-such-process-context-executable", "missing", NULL) < 0);
	info(&b);
	CHECK(a.identity == b.identity && a.generation == b.generation);
	pass("failed-exec-unchanged");
	pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		clear();
		CHECK(get() < 0 && errno == ENOENT);
		_exit(0);
	}
	waitok(pid);
	fd = get();
	CHECK(fd >= 0);
	close(fd);
	pass("child-clear-isolated");
	pair(g);
	set(g[0], getuid());
	info(&b);
	CHECK(b.generation != a.generation);
	close(g[0]);
	close(g[1]);
	pass("replacement-generation");
	fd = open("/dev/null", O_RDONLY);
	CHECK(fd >= 0);
	CHECK(call(MAC_CAP_PROCESS_SET, fd, getuid(), NULL) < 0 &&
	    errno == EINVAL);
	close(fd);
	pass("wrong-object-rejected");
	for (int which = 0; which < 4; which++) {
		pair(g);
		if (which < 2)
			CHECK(cap_clofork_limit(g[0],
				  which == 0 ? CAP_CLOFORK_LOCKED :
					       CAP_CLOFORK_ONCE) == 0);
		else
			CHECK(cap_cloexec_limit(g[0],
				  which == 2 ? CAP_CLOEXEC_LOCKED :
					       CAP_CLOEXEC_ONCE) == 0);
		CHECK(call(MAC_CAP_PROCESS_SET, g[0], getuid(), NULL) < 0 &&
		    errno == ENOTCAPABLE);
		close(g[0]);
		close(g[1]);
	}
	pass("locked-and-once-propagation-rejected");
	pair(g);
	cap_ioctl_t allowed = MAC_CAPABILITY_GETINFO;
	CHECK(cap_ioctls_limit(g[0], &allowed, 1) == 0);
	set(g[0], getuid());
	fd = get();
	CHECK(fd >= 0);
	CHECK(ioctl(fd, MAC_CAPABILITY_GETINFO, &fi) == 0);
	struct mac_capability_sendmsg_args msg = { 0 };
	CHECK(ioctl(fd, MAC_CAPABILITY_SENDMSG, &msg) < 0 &&
	    errno == ENOTCAPABLE);
	close(fd);
	close(g[0]);
	close(g[1]);
	pass("ioctl-rights-preserved");
	pair(g);
	set(g[0], getuid());
	pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		CHECK(setuid(2001) == 0);
		CHECK(get() < 0 && errno == EPERM);
		_exit(0);
	}
	waitok(pid);
	pass("unprovisioned-uid-transition-denied");
	pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		set(g[0], 2001);
		CHECK(setuid(2001) == 0);
		fd = get();
		CHECK(fd >= 0);
		close(fd);
		_exit(0);
	}
	waitok(pid);
	pass("explicit-target-principal");
	pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		CHECK(cap_enter() == 0);
		fd = get();
		CHECK(fd >= 0);
		close(fd);
		_exit(0);
	}
	waitok(pid);
	pass("capability-mode-discovery");
	token = call(MAC_CAP_PROCESS_ORIGIN_EXPORT, -1, 0, NULL);
	CHECK(token >= 0);
	info(&a);
	pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		CHECK(call(MAC_CAP_PROCESS_ORIGIN_SET, token, 0, NULL) == 0);
		info(&b);
		CHECK(b.identity != a.identity &&
		    b.responsible_identity == a.identity &&
		    b.responsible_pid == a.pid);
		pid_t child = fork();
		CHECK(child >= 0);
		if (child == 0) {
			info(&c);
			CHECK(c.identity != b.identity &&
			    c.responsible_identity == a.identity);
			_exit(0);
		}
		waitok(child);
		_exit(0);
	}
	waitok(pid);
	close(token);
	pass("separate-responsible-process-and-inheritance");
	CHECK(call(MAC_CAP_PROCESS_ORIGIN_SET, g[0], 0, NULL) < 0 &&
	    errno == EINVAL);
	pass("forged-origin-rejected");
	info(&a);
	CHECK(a.responsible_identity == 0);
	pass("child-attribution-does-not-change-parent");
	for (int i = 0; i < 128; i++) {
		pid = fork();
		CHECK(pid >= 0);
		if (pid == 0) {
			fd = get();
			CHECK(fd >= 0);
			close(fd);
			_exit(0);
		}
		waitok(pid);
	}
	pass("fork-exit-reference-churn");
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (int i = 0; i < 10000; i++) {
		fd = get();
		CHECK(fd >= 0);
		close(fd);
	}
	clock_gettime(CLOCK_MONOTONIC, &end);
	printf("BENCH get-close 10000 operations %.6f seconds\n",
	    end.tv_sec - start.tv_sec + (end.tv_nsec - start.tv_nsec) / 1e9);
	clear();
	close(g[0]);
	close(g[1]);
	close(f[1]);
	for (int i = 0; i < 128; i++) {
		pair(g);
		set(g[0], getuid());
		close(g[0]);
		close(g[1]);
		clear();
	}
	pass("replace-clear-reference-churn");
	puts("PROCESS_CONTEXT_KERNEL_PASS");
	return 0;
}
