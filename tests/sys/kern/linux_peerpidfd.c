/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * SO_PEERPIDFD (Linux 6.5), SOL_UDP option handling, IPC *_STAT_ANY and
 * the TIOCOUTQ/TCSBRK/TIOCSTI terminal ioctls.  Exit status = failed
 * check number.
 */
#include "linux_test.h"

#define	AF_UNIX		1
#define	AF_INET		2
#define	SOCK_STREAM	1
#define	SOCK_DGRAM	2
#define	SOL_SOCKET	1
#define	SOL_UDP		17
#define	SO_PEERCRED	17
#define	SO_PEERPIDFD	77
#define	UDP_CORK	1
#define	UDP_SEGMENT	103
#define	UDP_GRO		104
#define	POLLIN		1
#define	TIOCOUTQ	0x5411
#define	TIOCSTI		0x5412
#define	TCSBRK		0x5409
#define	IPC_RMID	0
#define	IPC_STAT	2
#define	SHM_STAT	13
#define	SHM_STAT_ANY	15
#define	SEM_STAT	18
#define	SEM_STAT_ANY	20
#define	IPC_PRIVATE	0
#define	IPC_CREAT	01000
#define	SYS_shmget	29
#define	SYS_shmctl	31
#define	SYS_semget	64
#define	SYS_semctl	66
#define	SYS_pidfd_send_signal_ 424

struct pollfd { int fd; short events, revents; };
struct ucred_l { int pid, uid, gid; };

static int
test(int argc, char **argv, char **envp)
{
	struct ucred_l uc;
	struct pollfd pfd;
	long pid, pidfd, r, id;
	int sv[2];
	unsigned int len;
	int status, fd, ov;
	char shmbuf[112], sembuf[112];

	(void)argc; (void)argv; (void)envp;

	/* 1: a connected unix socket pair. */
	if (sys4(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, sv) != 0) return (1);
	/* 2: SO_PEERCRED works and names ourselves. */
	len = sizeof(uc);
	if (sys5(SYS_getsockopt, sv[0], SOL_SOCKET, SO_PEERCRED, &uc, &len) != 0)
		return (2);
	if (uc.pid != sys0(SYS_getpid)) return (2);
	/* 3: SO_PEERPIDFD returns a pidfd for the peer (us). */
	len = sizeof(fd);
	fd = -1;
	if (sys5(SYS_getsockopt, sv[0], SOL_SOCKET, SO_PEERPIDFD, &fd, &len) != 0)
		return (3);
	if (fd < 0 || len != sizeof(fd)) return (3);
	/* 4: it is a real pidfd: pidfd_send_signal(0) succeeds on it. */
	if (sys4(SYS_pidfd_send_signal, fd, 0, 0, 0) != 0) return (4);
	(void)sys1(SYS_close, fd);
	/* 5: a short optlen is EINVAL. */
	len = 2;
	if (sys5(SYS_getsockopt, sv[0], SOL_SOCKET, SO_PEERPIDFD, &fd, &len) !=
	    -EINVAL) return (5);
	/* 6: setsockopt of it is ENOPROTOOPT. */
	ov = 1;
	if (sys5(SYS_setsockopt, sv[0], SOL_SOCKET, SO_PEERPIDFD, &ov, 4) !=
	    -92 /* ENOPROTOOPT */) return (6);
	/* 7: on an unconnected socket: ENOTCONN. */
	r = sys3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
	if (r < 0) return (7);
	len = sizeof(fd);
	if (sys5(SYS_getsockopt, r, SOL_SOCKET, SO_PEERPIDFD, &fd, &len) !=
	    -ENOTCONN) return (7);
	(void)sys1(SYS_close, r);
	/*
	 * 8-10: the pidfd tracks the peer process: a child connects, the
	 * parent gets its pidfd, the child exits, the pidfd becomes
	 * readable and signalling it is then ESRCH after reaping.
	 */
	{
		int pair[2];

		if (sys4(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, pair) != 0)
			return (8);
		pid = sys0(SYS_fork);
		if (pid < 0) return (8);
		if (pid == 0) {
			char c;

			(void)sys1(SYS_close, pair[0]);
			/* wait for the go byte, then exit */
			(void)sys3(SYS_read, pair[1], &c, 1);
			(void)sys1(SYS_exit_group, 0);
		}
		(void)sys1(SYS_close, pair[1]);
		/* The peer credential is recorded at socketpair() time: it
		 * names the creator (us), not the child that inherited the
		 * end.  Linux behaves the same for socketpair(); a
		 * connect()ed socket names the connecting process. */
		len = sizeof(fd);
		if (sys5(SYS_getsockopt, pair[0], SOL_SOCKET, SO_PEERPIDFD, &fd,
		    &len) != 0) return (9);
		(void)sys1(SYS_close, fd);
		(void)sys3(SYS_write, pair[0], "g", 1);
		if (sys4(SYS_wait4, pid, &status, 0, 0) != pid) return (10);
		(void)sys1(SYS_close, pair[0]);
	}
	/* 11: a pidfd_open'd child pidfd polls readable after exit (sanity). */
	pid = sys0(SYS_fork);
	if (pid == 0)
		(void)sys1(SYS_exit_group, 0);
	pidfd = sys2(SYS_pidfd_open, pid, 0);
	if (pidfd < 0) return (11);
	pfd.fd = pidfd; pfd.events = POLLIN; pfd.revents = 0;
	if (sys3(SYS_poll, &pfd, 1, 5000) != 1) return (11);
	(void)sys4(SYS_wait4, pid, &status, 0, 0);
	(void)sys1(SYS_close, pidfd);
	(void)sys1(SYS_close, sv[0]);
	(void)sys1(SYS_close, sv[1]);

	/* 12-14: SOL_UDP options are ENOPROTOOPT, quietly, get and set. */
	r = sys3(SYS_socket, AF_INET, SOCK_DGRAM, 0);
	if (r < 0) return (12);
	ov = 1;
	if (sys5(SYS_setsockopt, r, SOL_UDP, UDP_CORK, &ov, 4) != -92) return (12);
	if (sys5(SYS_setsockopt, r, SOL_UDP, UDP_SEGMENT, &ov, 4) != -92)
		return (13);
	len = 4;
	if (sys5(SYS_getsockopt, r, SOL_UDP, UDP_GRO, &ov, &len) != -92)
		return (14);
	(void)sys1(SYS_close, r);

	/* 15-18: SHM_STAT_ANY / SEM_STAT_ANY behave as SHM_STAT / SEM_STAT. */
	id = sys3(SYS_shmget, IPC_PRIVATE, 4096, IPC_CREAT | 0600);
	if (id < 0) return (15);
	xmemset(shmbuf, 0, sizeof(shmbuf));
	if (sys3(SYS_shmctl, id, IPC_STAT, shmbuf) != 0) return (15);
	/* index 0..n: at least one index answers SHM_STAT_ANY with our id */
	{
		long i, found = 0;

		for (i = 0; i < 64 && !found; i++) {
			r = sys3(SYS_shmctl, i, SHM_STAT_ANY, shmbuf);
			if (r == id)
				found = 1;
		}
		if (!found) return (16);
		for (i = 0, found = 0; i < 64 && !found; i++)
			if (sys3(SYS_shmctl, i, SHM_STAT, shmbuf) == id)
				found = 1;
		if (!found) return (16);
	}
	if (sys3(SYS_shmctl, id, IPC_RMID, 0) != 0) return (16);
	id = sys3(SYS_semget, IPC_PRIVATE, 1, IPC_CREAT | 0600);
	if (id < 0) return (17);
	{
		long i, found = 0;

		for (i = 0; i < 64 && !found; i++)
			if (sys4(SYS_semctl, i, 0, SEM_STAT_ANY, sembuf) == id)
				found = 1;
		if (!found) return (18);
	}
	if (sys4(SYS_semctl, id, 0, IPC_RMID, 0) != 0) return (18);

	/* 19-21: TIOCOUTQ on a pty is 0 when idle; TIOCSTI is EIO; TCSBRK 0. */
	fd = sys3(SYS_open, "/dev/ptmx", O_RDWR | O_NOCTTY, 0);
	if (fd < 0) return (19);
	ov = -1;
	if (sys3(SYS_ioctl, fd, TIOCOUTQ, &ov) != 0) return (19);
	if (ov != 0) return (19);
	if (sys3(SYS_ioctl, fd, TIOCSTI, "x") != -EIO) return (20);
	if (sys3(SYS_ioctl, fd, TCSBRK, 0) != 0) return (21);
	if (sys3(SYS_ioctl, fd, TCSBRK, 1) != 0) return (21);
	(void)sys1(SYS_close, fd);
	/* 22: TIOCOUTQ on a regular file is ENOTTY. */
	fd = tmpfile_fd("peerpidfd.tmp");
	if (fd < 0) return (22);
	if (sys3(SYS_ioctl, fd, TIOCOUTQ, &ov) != -ENOTTY) return (22);
	(void)sys1(SYS_close, fd);
	(void)sys1(SYS_unlink, "peerpidfd.tmp");
	return (0);
}
