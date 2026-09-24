/* SPDX-License-Identifier: BSD-2-Clause */
/* Native security boundaries around linprocfs. Disposable BSD guests only. */
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/jail.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
denied(pid_t pid, int fd, int held)
{
	char path[128], buf[256];
	int copy;

	snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
	if (readlink(path, buf, sizeof(buf)) >= 0)
		return (10);
	copy = open(path, O_RDONLY);
	if (copy >= 0) {
		close(copy);
		return (11);
	}
	snprintf(path, sizeof(path), "/proc/%d/fdinfo/%d", pid, fd);
	copy = open(path, O_RDONLY);
	if (copy >= 0) {
		close(copy);
		return (12);
	}
	if (held >= 0 && pread(held, buf, sizeof(buf), 0) > 0)
		return (13);
	return (0);
}

int
main(int argc, char **argv)
{
	char path[128], buf[256], name[64], error[256] = { 0 };
	struct iovec iov[8];
	cap_rights_t rights;
	pid_t parent = getpid(), child;
	int fd, held, copy, status;

	if (argc == 4 && strcmp(argv[1], "dropped") == 0)
		return (denied(atoi(argv[2]), atoi(argv[3]), -1));
	fd = open("/dev/null", O_RDONLY);
	if (fd < 0)
		return (1);
	snprintf(path, sizeof(path), "/proc/%d/fdinfo/%d", parent, fd);
	held = open(path, O_RDONLY);
	if (held < 0 || pread(held, buf, sizeof(buf), 0) <= 0)
		return (2);
	child = fork();
	if (child < 0)
		return (3);
	if (child == 0) {
		snprintf(name, sizeof(name), "proc-security-%d", getpid());
		iov[0] = (struct iovec){ "name", sizeof("name") };
		iov[1] = (struct iovec){ name, strlen(name) + 1 };
		iov[2] = (struct iovec){ "path", sizeof("path") };
		iov[3] = (struct iovec){ "/", sizeof("/") };
		iov[4] = (struct iovec){ "host.hostname", sizeof("host.hostname") };
		iov[5] = (struct iovec){ name, strlen(name) + 1 };
		iov[6] = (struct iovec){ "errmsg", sizeof("errmsg") };
		iov[7] = (struct iovec){ error, sizeof(error) };
		if (jail_set(iov, 8, JAIL_CREATE | JAIL_ATTACH) < 0)
			_exit(4);
		_exit(denied(parent, fd, held));
	}
	if (waitpid(child, &status, 0) != child || status != 0)
		return (5);
	puts("PROC_NATIVE_JAIL_PASS");
	child = fork();
	if (child < 0)
		return (6);
	if (child == 0) {
		if (setgid(65534) || setuid(65534))
			_exit(7);
		int rc = denied(parent, fd, held);
		if (rc)
			_exit(rc);
		snprintf(path, sizeof(path), "%d", parent);
		snprintf(name, sizeof(name), "%d", fd);
		execl("/tmp/proc_native", "proc_native", "dropped", path, name,
		    (char *)NULL);
		_exit(8);
	}
	if (waitpid(child, &status, 0) != child || status != 0)
		return (9);
	puts("PROC_NATIVE_CREDENTIAL_PASS");
	snprintf(path, sizeof(path), "/proc/%d/fd/%d", parent, fd);
	cap_rights_init(&rights, CAP_READ, CAP_FSTAT);
	if (cap_rights_limit(fd, &rights))
		return (14);
	copy = open(path, O_RDONLY);
	if (copy >= 0 || errno != ENOTCAPABLE)
		return (15);
	if (readlink(path, buf, sizeof(buf)) <= 0)
		return (16);
	puts("PROC_NATIVE_CAPRIGHTS_PASS");
	close(held);
	close(fd);
	fd = open("/proc/mounts", O_RDONLY);
	if (fd < 0 || (pread(fd, buf, 1, INT64_MAX - 1) != -1 || errno != EINVAL))
		return (17);
	if (pread(fd, buf, 1, INT64_MAX) != -1 || errno != EINVAL)
		return (18);
	close(fd);
	puts("PROC_NATIVE_OFFSET_PASS");
	return (0);
}
