/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The image launch_authority_pins_test pins its grants to, and the other
 * image it executes under them (the test copies this program twice).
 * Statically linked: the exec of a pinned image is a set-id exec whose
 * loader would take the grant's library directories, and most of the
 * test's grants have none.
 *
 *   bound REPORTFD ANNOUNCEFD GATEFD CHANFD NEXT
 *	With ANNOUNCEFD >= 0: send one byte on it (the kernel stamps this
 *	process's authority and identity on it), then block on GATEFD until
 *	the test has acted on what it observed.  Write a report: this
 *	process's CAP_AUTH_INFO, issetugid(2), PROC_PDEATHSIG_STATUS, and
 *	on CHANFD the GETINFO answer here, from a fork child, from a fork
 *	child that cleared its grant, and one send; and the open of /dev/dq.
 *	Then, with the parent death signal set to SIGUSR1, execute NEXT (a
 *	path; "-" for none) as "bound REPORTFD ANNOUNCEFD GATEFD CHANFD -",
 *	so the next image announces, waits and reports the same way.  An
 *	exec that returns is reported (exec_errno) and exits 3.
 *   install REPORTFD TOKENFD
 *	CAP_AUTH_INSTALL the token (a descriptor that survived exec or a
 *	transfer), then report.
 *   libdir REPORTFD
 *	Write a struct la_libdir_report: what CAP_AUTH_GET_LIBDIR answers
 *	here, and what the descriptor it returns refers to.
 *
 * Exit 0 after the last report; LA_HELPER_BROKEN when the helper itself
 * fails.
 */

#include <sys/param.h>
#include <sys/cap_authority.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/procctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "launch_authority.h"

static int
op(int cmd, int fd, void *data)
{

	return (syscall(SYS_cap_process, cmd, fd, 0, data));
}

static void
write_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	ssize_t n;

	while (len > 0) {
		n = write(fd, p, len);
		if (n <= 0)
			_exit(LA_HELPER_BROKEN);
		p += n;
		len -= (size_t)n;
	}
}

/* GETINFO goes through the endpoint's binding check before anything else. */
static int
probe(int fd)
{
	struct mac_capability_info_args info;

	memset(&info, 0, sizeof(info));
	return (ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == -1 ? errno : 0);
}

/* probe(fd) in a fork child, after CAP_AUTH_CLEAR there when clear. */
static int
child_probe(int fd, bool clear)
{
	pid_t pid;
	int p[2], status, v;

	if (pipe(p) == -1)
		return (LA_HELPER_BROKEN);
	pid = fork();
	if (pid == -1)
		return (LA_HELPER_BROKEN);
	if (pid == 0) {
		if (clear && op(CAP_AUTH_CLEAR, -1, NULL) == -1)
			_exit(LA_HELPER_BROKEN);
		v = probe(fd);
		write_all(p[1], &v, sizeof(v));
		_exit(0);
	}
	(void)close(p[1]);
	if (read(p[0], &v, sizeof(v)) != (ssize_t)sizeof(v))
		v = LA_HELPER_BROKEN;
	(void)close(p[0]);
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		v = LA_HELPER_BROKEN;
	return (v);
}

static int
dq_open(void)
{
	int fd;

	fd = open("/dev/dq", O_RDWR | O_CLOEXEC);
	if (fd == -1)
		return (errno);
	(void)close(fd);
	return (0);
}

static int
send_byte(int fd)
{
	struct mac_capability_sendmsg_args sa;
	char byte = 'a';

	memset(&sa, 0, sizeof(sa));
	sa.payload = &byte;
	sa.payload_len = 1;
	return (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1 ? errno : 0);
}

static void
fill(struct la_report *r, int chan)
{
	int sig;

	memset(r, 0, sizeof(*r));
	if (op(CAP_AUTH_INFO, -1, &r->info) == -1)
		_exit(LA_HELPER_BROKEN);
	r->pid = getpid();
	r->issetugid = issetugid();
	if (procctl(P_PID, 0, PROC_PDEATHSIG_STATUS, &sig) == -1)
		_exit(LA_HELPER_BROKEN);
	r->pdeathsig = sig;
	r->probe = chan >= 0 ? probe(chan) : LA_NA;
	r->child_probe = chan >= 0 ? child_probe(chan, false) : LA_NA;
	r->cleared_probe = chan >= 0 ? child_probe(chan, true) : LA_NA;
	r->send = chan >= 0 ? send_byte(chan) : LA_NA;
	r->dq_open = dq_open();
	r->install = LA_NA;
	r->exec_errno = 0;
}

static int
cmd_bound(char **argv)
{
	struct la_report r;
	char byte;
	int announce, chan, gate, report, sig;

	report = atoi(argv[2]);
	announce = atoi(argv[3]);
	gate = atoi(argv[4]);
	chan = atoi(argv[5]);
	if (announce >= 0) {
		if (send_byte(announce) != 0)
			return (LA_HELPER_BROKEN);
		if (read(gate, &byte, 1) != 1)
			return (LA_HELPER_BROKEN);
	}
	fill(&r, chan);
	write_all(report, &r, sizeof(r));
	if (strcmp(argv[6], "-") == 0)
		return (0);
	/* Set before the exec, so the next image reports whether it kept it. */
	sig = SIGUSR1;
	if (procctl(P_PID, 0, PROC_PDEATHSIG_CTL, &sig) == -1)
		return (LA_HELPER_BROKEN);
	execl(argv[6], "launch_authority_helper", "bound", argv[2], argv[3],
	    argv[4], argv[5], "-", (char *)NULL);
	fill(&r, -1);
	r.exec_errno = errno;
	write_all(report, &r, sizeof(r));
	return (3);
}

static int
cmd_install(char **argv)
{
	struct la_report r;
	int report, token, error;

	report = atoi(argv[2]);
	token = atoi(argv[3]);
	error = op(CAP_AUTH_INSTALL, token, NULL) == -1 ? errno : 0;
	fill(&r, -1);
	r.install = error;
	write_all(report, &r, sizeof(r));
	return (0);
}

static int
cmd_libdir(char **argv)
{
	struct la_libdir_report r;
	struct stat st;
	int fd, flags, report;

	report = atoi(argv[2]);
	memset(&r, 0, sizeof(r));
	if (op(CAP_AUTH_INFO, -1, &r.info) == -1)
		return (LA_HELPER_BROKEN);
	fd = op(CAP_AUTH_GET_LIBDIR, 0, NULL);
	r.get0 = fd == -1 ? errno : 0;
	if (fd >= 0) {
		flags = fcntl(fd, F_GETFD);
		r.cloexec = flags == -1 ? -1 : (flags & FD_CLOEXEC) != 0;
		if (fstat(fd, &st) == 0) {
			r.is_dir = S_ISDIR(st.st_mode);
			r.dev = st.st_dev;
			r.ino = st.st_ino;
		} else
			r.is_dir = -1;
		if (cap_rights_get(fd, &r.rights) == -1)
			return (LA_HELPER_BROKEN);
		(void)close(fd);
	}
	fd = op(CAP_AUTH_GET_LIBDIR, 1, NULL);
	r.get1 = fd == -1 ? errno : 0;
	if (fd >= 0)
		(void)close(fd);
	fd = op(CAP_AUTH_GET_LIBDIR, CAP_AUTH_LIBDIR_MAX, NULL);
	r.get3 = fd == -1 ? errno : 0;
	if (fd >= 0)
		(void)close(fd);
	fd = op(CAP_AUTH_GET_LIBDIR, 0, &st);
	r.get_data = fd == -1 ? errno : 0;
	if (fd >= 0)
		(void)close(fd);
	write_all(report, &r, sizeof(r));
	return (0);
}

int
main(int argc, char **argv)
{

	if (argc == 7 && strcmp(argv[1], "bound") == 0)
		return (cmd_bound(argv));
	if (argc == 4 && strcmp(argv[1], "install") == 0)
		return (cmd_install(argv));
	if (argc == 3 && strcmp(argv[1], "libdir") == 0)
		return (cmd_libdir(argv));
	return (LA_HELPER_BROKEN);
}
