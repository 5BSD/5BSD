/* SPDX-License-Identifier: BSD-2-Clause */
/* Starnix procfs_test.cc uptime and boot-id test ideas, rewritten.
 * Reference revision 8a938a3224e768f6254ee12d240b6492361ebccf. */
#include "linux_test.h"
static int
parse_uptime(const char *b, long n, long *value)
{
	long i = 0, v = 0;
	if (n <= 0 || n >= 128)
		return (1);
	while (i < n && b[i] >= '0' && b[i] <= '9') {
		if (v > 1000000000)
			return (2);
		v = v * 10 + b[i++] - '0';
	}
	if (i == 0 || i + 3 >= n || b[i] != '.' ||
	    b[i + 1] < '0' || b[i + 1] > '9' ||
	    b[i + 2] < '0' || b[i + 2] > '9' || b[i + 3] != ' ')
		return (3);
	*value = v * 100 + (b[i + 1] - '0') * 10 + b[i + 2] - '0';
	/* Validate the second decimal field as well, without requiring monotonic idle time. */
	i += 4;
	long start = i;
	while (i < n && b[i] >= '0' && b[i] <= '9')
		i++;
	if (i == start || i + 4 != n || b[i] != '.' ||
	    b[i + 1] < '0' || b[i + 1] > '9' ||
	    b[i + 2] < '0' || b[i + 2] > '9' || b[i + 3] != '\n')
		return (4);
	return (0);
}
static int
read_uptime(long fd, long *value)
{
	char b[128];
	long n = sys3(SYS_read, fd, b, sizeof(b));
	return (parse_uptime(b, n, value));
}
/* UptimeByChar: a partial read must retain its original generated record. */
static int
uptime_snapshot(int mode)
{
	char b[128];
	long fd = -1, other = -1, before, middle, snapshot, n = 1, r;
	struct { long sec, nsec; } delay = { 1, 0 }, remain;
	int rc = 1;

	other = sys3(SYS_open, "/proc/uptime", O_RDONLY, 0);
	if (other < 0 || read_uptime(other, &before) != 0)
		goto out;
	(void)sys1(SYS_close, other);
	other = -1;
	fd = sys3(SYS_open, "/proc/uptime", O_RDONLY, 0);
	if (fd < 0 || sys3(SYS_read, fd, b, 1) != 1) {
		rc = 2;
		goto out;
	}
	other = sys3(SYS_open, "/proc/uptime", O_RDONLY, 0);
	if (other < 0 || read_uptime(other, &middle) != 0) {
		rc = 3;
		goto out;
	}
	/* Failed seeks and offset queries must not discard an active record. */
	if (sys3(SYS_lseek, fd, -1, 0) != -EINVAL ||
	    sys3(SYS_lseek, fd, 0, 1) != 1) { rc = 8; goto out; }
	if (mode == 1) {
		long alias = sys1(SYS_dup, fd);
		if (alias < 0) { rc = 9; goto out; }
		(void)sys1(SYS_close, fd);
		fd = alias;
	} else if (mode == 2) {
		long child = sys0(SYS_fork);
		if (child < 0) { rc = 10; goto out; }
		if (child > 0) {
			int status = -1;
			(void)sys1(SYS_close, fd);
			(void)sys1(SYS_close, other);
			fd = other = -1;
			do { r = sys4(SYS_wait4, child, &status, 0, 0); }
			while (r == -EINTR);
			return (r == child && status == 0 ? 0 : 11);
		}
	}
	do {
		r = sys2(SYS_nanosleep, &delay, &remain);
		if (r == -EINTR)
			delay = remain;
	} while (r == -EINTR);
	if (r != 0) { rc = 4; goto out; }
	while (n < (long)sizeof(b)) {
		r = sys3(SYS_read, fd, b + n, 1);
		if (r == 0)
			break;
		if (r != 1) { rc = 5; goto out; }
		n++;
	}
	if (parse_uptime(b, n, &snapshot) != 0) { rc = 6; goto out; }
	if (snapshot < before || snapshot > middle) {
		msgnum("uptime before ", before);
		msgnum("uptime second descriptor ", middle);
		msgnum("uptime partial record ", snapshot);
		rc = 7;
		goto out;
	}
	rc = 0;
out:
	if (fd >= 0) (void)sys1(SYS_close, fd);
	if (other >= 0) (void)sys1(SYS_close, other);
	return (rc);
}
static int uptime_by_char(void) { return (uptime_snapshot(0)); }
static int uptime_dup(void) { return (uptime_snapshot(1)); }
static int uptime_fork(void) { return (uptime_snapshot(2)); }
static int
uptime(int reopen)
{
	long fd = -1, before, after;
	struct { long sec, nsec; } delay = { 1, 0 }, remain;
	int rc = 0;
	fd = sys3(SYS_open, "/proc/uptime", O_RDONLY, 0);
	if (fd < 0)
		return (1);
	if (read_uptime(fd, &before) != 0) { rc = 2; goto out; }
	long result;
	do {
		result = sys2(SYS_nanosleep, &delay, &remain);
		if (result == -EINTR)
			delay = remain;
	} while (result == -EINTR);
	if (result != 0) { rc = 3; goto out; }
	if (reopen) {
		(void)sys1(SYS_close, fd);
		fd = sys3(SYS_open, "/proc/uptime", O_RDONLY, 0);
		if (fd < 0) { rc = 4; goto out; }
	} else if (sys3(SYS_lseek, fd, 0, 0) != 0) { rc = 5; goto out; }
	if (read_uptime(fd, &after) != 0 || after <= before)
		rc = 6;
out:
	if (fd >= 0)
		(void)sys1(SYS_close, fd);
	return (rc);
}
static int uptime_seek(void) { return (uptime(0)); }
static int uptime_reopen(void) { return (uptime(1)); }
static int
boot_id(void)
{
	char first[64], next[64];
	for (unsigned pass = 0; pass < 2; pass++) {
		char *b = pass == 0 ? first : next;
		long fd = sys3(SYS_open, "/proc/sys/kernel/random/boot_id", O_RDONLY, 0);
		if (fd < 0)
			return (1);
		long n = sys3(SYS_read, fd, b, 64);
		(void)sys1(SYS_close, fd);
		if (n != 37 || b[36] != '\n')
			return (2);
		for (unsigned i = 0; i < 36; i++) {
			if (i == 8 || i == 13 || i == 18 || i == 23) {
				if (b[i] != '-') return (3);
			} else if (!((b[i] >= '0' && b[i] <= '9') ||
			    (b[i] >= 'a' && b[i] <= 'f')))
				return (4);
			if (pass && b[i] != first[i]) return (5);
		}
	}
	return (0);
}
static int
test(int argc, char **argv, char **envp)
{
	static const struct subtest cases[] = {
		{ "uptime_by_char", uptime_by_char },
		{ "uptime_dup", uptime_dup },
		{ "uptime_fork", uptime_fork },
		{ "uptime_seek", uptime_seek },
		{ "uptime_reopen", uptime_reopen },
		{ "boot_id", boot_id },
	};
	(void)envp;
	return (run_subtests(argc, argv, cases, sizeof(cases) / sizeof(cases[0])));
}
