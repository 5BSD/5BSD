/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/cap_process.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/procdesc.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <channel.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x)                                                              \
	do {                                                                  \
		if (!(x))                                                     \
			errx(1, "line %d: %s errno=%d", __LINE__, #x, errno); \
	} while (0)
static int
op(int x, int fd, uid_t uid, void *p)
{
	return syscall(SYS_cap_process, x, fd, uid, p);
}
static void
waitok(pid_t p)
{
	int s;
	CHECK(waitpid(p, &s, 0) == p);
	CHECK(WIFEXITED(s) && WEXITSTATUS(s) == 0);
}
static void
getok(void)
{
	int fd = op(MAC_CAP_PROCESS_GET, -1, 0, NULL);
	CHECK(fd >= 0);
	close(fd);
}
static void *
churn(void *arg)
{
	int *f = arg;
	for (int n = 0; n < 1000; n++) {
		CHECK(op(MAC_CAP_PROCESS_SET, f[n % 2], getuid(), NULL) == 0);
		getok();
	}
	return NULL;
}
int
main(int argc, char **argv)
{
	int a[2], b[2], fd, pd, s;
	pid_t p;
	struct mac_cap_process_info before, after;
	if (argc > 2 && !strcmp(argv[1], "cleanexec")) {
		closefrom(3);
		clearenv();
		execv(argv[2], argv + 2);
		err(1, "exec");
	}
	CHECK(mac_capability_channel_create(a) == 0);
	CHECK(mac_capability_channel_create(b) == 0);
	CHECK(op(MAC_CAP_PROCESS_SET, a[0], getuid(), NULL) == 0);
	CHECK(op(MAC_CAP_PROCESS_INFO, -1, 0, &before) == 0);
	p = fork();
	CHECK(p >= 0);
	if (!p) {
		CHECK(op(MAC_CAP_PROCESS_SET, b[0], getuid(), NULL) == 0);
		p = fork();
		CHECK(p >= 0);
		if (!p) {
			struct mac_capability_info_args x, y;
			fd = op(MAC_CAP_PROCESS_GET, -1, 0, NULL);
			CHECK(fd >= 0);
			CHECK(ioctl(fd, MAC_CAPABILITY_GETINFO, &x) == 0);
			CHECK(ioctl(b[0], MAC_CAPABILITY_GETINFO, &y) == 0);
			CHECK(x.badge == y.badge);
			_exit(0);
		}
		waitok(p);
		_exit(0);
	}
	waitok(p);
	CHECK(op(MAC_CAP_PROCESS_INFO, -1, 0, &after) == 0);
	CHECK(before.generation == after.generation);
	puts("PASS child-subtree-bootstrap-isolation");
	p = rfork(RFPROC | RFFDG);
	CHECK(p >= 0);
	if (!p) {
		closefrom(3);
		getok();
		_exit(0);
	}
	waitok(p);
	puts("PASS rfork-descriptor-cleanup");
	p = pdfork(&pd, 0);
	CHECK(p >= 0);
	if (!p) {
		getok();
		_exit(0);
	}
	CHECK(pdwait(pd, &s, WEXITED, NULL, NULL) == 0);
	CHECK(WIFEXITED(s) && WEXITSTATUS(s) == 0);
	close(pd);
	puts("PASS pdfork-inheritance");
	p = fork();
	CHECK(p >= 0);
	if (!p) {
		struct rlimit lim = { 64, 64 };
		CHECK(setrlimit(RLIMIT_NOFILE, &lim) == 0);
		while ((fd = open("/dev/null", O_RDONLY)) >= 0) {
		}
		CHECK(errno == EMFILE);
		CHECK(op(MAC_CAP_PROCESS_GET, -1, 0, NULL) < 0 &&
		    errno == EMFILE);
		closefrom(3);
		getok();
		_exit(0);
	}
	waitok(p);
	puts("PASS descriptor-exhaustion-recovery");
	p = fork();
	CHECK(p >= 0);
	if (!p) {
		CHECK(seteuid(2001) == 0);
		getok();
		CHECK(seteuid(0) == 0);
		getok();
		_exit(0);
	}
	waitok(p);
	puts("PASS temporary-euid-preserves-discovery-route");
	p = fork();
	CHECK(p >= 0);
	if (!p) {
		int token = op(MAC_CAP_PROCESS_ORIGIN_EXPORT, -1, 0, NULL);
		CHECK(token >= 0);
		char jailpath[] = "/", jailname[] = "context-jail";
		struct jail j = { .version = JAIL_API_VERSION,
			.path = jailpath,
			.hostname = jailname,
			.jailname = jailname };
		CHECK(jail(&j) >= 0);
		CHECK(
		    op(MAC_CAP_PROCESS_GET, -1, 0, NULL) < 0 && errno == EPERM);
		CHECK(op(MAC_CAP_PROCESS_ORIGIN_SET, token, 0, NULL) < 0 &&
		    errno == EPERM);
		_exit(0);
	}
	waitok(p);
	puts("PASS jail-context-and-origin-isolation");
	pthread_t threads[8];
	int channels[2] = { a[0], b[0] };
	for (int i = 0; i < 8; i++)
		CHECK(pthread_create(&threads[i], NULL, churn, channels) == 0);
	for (int i = 0; i < 8; i++)
		CHECK(pthread_join(threads[i], NULL) == 0);
	puts("PASS concurrent-context-replacement");
	CHECK(op(MAC_CAP_PROCESS_CLEAR, -1, 0, NULL) == 0);
	close(a[0]);
	close(a[1]);
	close(b[0]);
	close(b[1]);
	puts("PROCESS_CONTEXT_EDGE_PASS");
	return 0;
}
