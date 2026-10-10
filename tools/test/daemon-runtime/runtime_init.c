/* SPDX-License-Identifier: BSD-2-Clause */
/* Disposable VM PID 1 only. Never invoke as the host's init. */
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>

/* Local TCP/UDP fixtures need lo0; QEMU still has no network adapter. */
static int
configure_loopback(void)
{
	struct ifaliasreq address;
	struct ifreq flags;
	struct sockaddr_in *sin;
	int fd, error = 0;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		return (-1);
	memset(&address, 0, sizeof(address));
	strlcpy(address.ifra_name, "lo0", sizeof(address.ifra_name));
	sin = (struct sockaddr_in *)&address.ifra_addr;
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin = (struct sockaddr_in *)&address.ifra_mask;
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(0xff000000U);
	if (ioctl(fd, SIOCAIFADDR, &address) == -1) {
		error = errno;
		goto out;
	}
	memset(&flags, 0, sizeof(flags));
	strlcpy(flags.ifr_name, "lo0", sizeof(flags.ifr_name));
	if (ioctl(fd, SIOCGIFFLAGS, &flags) == -1) {
		error = errno;
		goto out;
	}
	flags.ifr_flags |= IFF_UP;
	if (ioctl(fd, SIOCSIFFLAGS, &flags) == -1)
		error = errno;
out:
	close(fd);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

static int
run_case(const char *program, const char *name)
{
	char path[256], result[256], line[1024] = { 0 };
	struct timespec start, now, pause_time = { .tv_nsec = 100000000 };
	pid_t child;
	int status = 0;
	FILE *f;
	snprintf(path, sizeof(path), "/tmp/%s_%s", strrchr(program, '/') + 1, name);
	if (mkdir(path, 0700) == -1) {
		perror(path);
		return (-1);
	}
	snprintf(result, sizeof(result), "%s/result", path);
	child = fork();
	if (child == -1)
		return (-1);
	if (child == 0) {
		if (chdir(path) == -1)
			_exit(126);
		execl(program, program, "-s", "/tests", "-r",
		    result, name, NULL);
		_exit(127);
	}
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		pid_t p = waitpid(child, &status, WNOHANG);
		if (p == child)
			break;
		if (p == -1 && errno != EINTR)
			return (-1);
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - start.tv_sec >= 40) {
			kill(child, SIGKILL);
			waitpid(child, &status, 0);
			printf("RUNTIME_CASE_FAIL %s timeout\n", name);
			return (-1);
		}
		nanosleep(&pause_time, NULL);
	}
	f = fopen(result, "r");
	if (f == NULL) {
		perror(result);
		return (-1);
	}
	bool passed = fgets(line, sizeof(line), f) != NULL &&
	    strcmp(line, "passed\n") == 0;
	fclose(f);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || !passed) {
		printf("RUNTIME_CASE_FAIL %s status=%d result=%s\n", name,
		    status, line);
		return (-1);
	}
	printf("RUNTIME_CASE_PASS %s:%s\n", program, name);
	return (0);
}
int
main(void)
{
	char fstype[] = "fstype", devfs[] = "devfs", fspath[] = "fspath",
	     dev[] = "/dev";
	struct iovec iov[] = { { .iov_base = fstype, .iov_len = 7 },
		{ .iov_base = devfs, .iov_len = 6 },
		{ .iov_base = fspath, .iov_len = 7 },
		{ .iov_base = dev, .iov_len = 5 } };
	const char *cases[] = { "service_budget_wire",
		"service_session_payload_and_attachment_lifecycle",
		"service_session_close_cancels_event" };
	int fd, failed = 0;
	if (getpid() != 1)
		return (64);
	(void)nmount(iov, 4, 0);
	fd = open("/dev/console", O_RDWR);
	if (fd >= 0) {
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		if (fd > 2)
			close(fd);
	}
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	setenv("HOME", "/root", 1);
	setenv("TMPDIR", "/tmp", 1);
	puts("RUNTIME_VM_START");
	if (configure_loopback() == -1) {
		perror("configure lo0");
		failed = 1;
	}
	char tmpfs[] = "tmpfs", tmp[] = "/tmp";
	struct iovec tmpiov[] = { { .iov_base = fstype,
				      .iov_len = sizeof(fstype) },
		{ .iov_base = tmpfs, .iov_len = sizeof(tmpfs) },
		{ .iov_base = fspath, .iov_len = sizeof(fspath) },
		{ .iov_base = tmp, .iov_len = sizeof(tmp) } };
	if (nmount(tmpiov, 4, 0) == -1) {
		perror("mount /tmp");
		failed = 1;
	}
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		if (run_case("/tests/libservice_api_test", cases[i]) == -1)
			failed = 1;
	if (run_case("/tests/namespace_test", "delivery_hardening_failure") == -1)
		failed = 1;
	FILE *extra = fopen("/tests/extra-cases", "r");
	if (extra != NULL) {
		char program[128], test_case[128];
		int fields;
		while ((fields = fscanf(extra, "%127s %127s", program, test_case)) == 2)
			if (run_case(program, test_case) == -1)
				failed = 1;
		if (fields != EOF || ferror(extra))
			failed = 1;
		fclose(extra);
	}
	puts(failed ? "RUNTIME_VM_FAIL" : "RUNTIME_VM_PASS");
	/* Let the serial transmitter finish before kernel shutdown messages. */
	if (tcdrain(STDOUT_FILENO) == -1) {
		perror("console drain");
		puts("RUNTIME_VM_FAIL");
	}
	sync();
	reboot(RB_POWEROFF);
	for (;;)
		pause();
}
