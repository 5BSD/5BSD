/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * splice(2)/vmsplice(2): file->pipe->file copy with checksums, socket
 * sinks, offsets and offset updates, SPLICE_F_NONBLOCK on empty/full
 * pipes, EOF, validation (no pipe, same pipe, pipe+offset, bad flags,
 * unreadable/unwritable ends), a non-blocking socket sink that fills up
 * (no data may be lost from the pipe), and vmsplice both ways.  Exit
 * status = failed check number.
 */
#include "linux_test.h"

#define	SPLICE_F_MOVE		1
#define	SPLICE_F_NONBLOCK	2
#define	SPLICE_F_MORE		4
#define	SPLICE_F_GIFT		8
#define	SYS_vmsplice		278
#define	SYS_tee			276
#define	AF_UNIX			1
#define	SOCK_STREAM		1
#define	SOL_SOCKET		1
#define	SO_SNDBUF		7
#define	SO_RCVBUF		8
#define	F_SETFL			4
#define	FSZ			(1024 * 1024L)

static unsigned char data[FSZ];
static unsigned char back[FSZ];

static long
splice(long fin, long *oin, long fout, long *oout, long len, long flags)
{

	return (sys6(SYS_splice, fin, oin, fout, oout, len, flags));
}

static unsigned long
csum(const unsigned char *p, long n)
{
	unsigned long h = 1469598103934665603UL;
	long i;

	for (i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211UL; }
	return (h);
}

static int
test(int argc, char **argv, char **envp)
{
	struct iovec iov[2];
	long fd, fd2, r, i, off, off2, moved, total, n;
	int p[2], p2[2], sv[2], v;

	(void)argc; (void)argv; (void)envp;
	ignore_signal(SIGPIPE);

	/* data: pseudo-random */
	{
		unsigned long x = 88172645463325252UL;
		for (i = 0; i < FSZ; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; data[i] = x; }
	}
	fd = tmpfile_fd("splice_in.tmp");
	if (fd < 0) return (1);
	for (i = 0; i < FSZ;) {
		r = sys3(SYS_write, fd, data + i, FSZ - i);
		if (r <= 0) return (1);
		i += r;
	}
	if (sys2(SYS_pipe2, p, 0) != 0) return (1);

	msg("splice: 2-4 validation\n");
	/* 2-4: validation. */
	if (splice(fd, 0, fd, 0, 10, 0) != -EINVAL) return (2);		/* no pipe */
	if (splice(p[0], 0, p[1], 0, 10, 0) != -EINVAL) return (2);	/* same pipe */
	off = 0;
	if (splice(p[0], &off, fd, 0, 10, 0) != -ESPIPE) return (3);	/* pipe offset */
	if (splice(fd, 0, p[1], &off, 10, 0) != -ESPIPE) return (3);
	if (splice(fd, 0, p[1], 0, 10, 0x10) != -EINVAL) return (3);	/* bad flag */
	if (splice(p[1], 0, fd, 0, 10, 0) != -EBADF) return (4);	/* write end as source */
	if (splice(fd, 0, p[0], 0, 10, 0) != -EBADF) return (4);	/* read end as sink */
	if (splice(9999, 0, p[1], 0, 10, 0) != -EBADF) return (4);
	off = -1;
	if (splice(fd, &off, p[1], 0, 10, 0) != -EINVAL) return (4);
	if (splice(fd, 0, p[1], 0, 0, 0) != 0) return (4);		/* len 0 */
	msg("splice: validation done\n");

	msg("splice: 5-8: file \n");
	/* 5-8: file -> pipe -> file, 1 MiB, with explicit offsets. */
	fd2 = tmpfile_fd("splice_out.tmp");
	if (fd2 < 0) return (5);
	off = 0; off2 = 0; total = 0;
	while (total < FSZ) {
		r = splice(fd, &off, p[1], 0, 65536, SPLICE_F_MORE);
		if (r <= 0) { msgnum("splice in ", r); return (5); }
		moved = r;
		if (off != total + moved) return (6);
		n = 0;
		while (n < moved) {
			r = splice(p[0], 0, fd2, &off2, moved - n, SPLICE_F_MOVE);
			if (r <= 0) { msgnum("splice out ", r); return (7); }
			n += r;
		}
		total += moved;
		if (off2 != total) return (6);
	}
	/* at EOF, splice returns 0 */
	if (splice(fd, &off, p[1], 0, 65536, 0) != 0) return (7);
	/* the file offsets used explicitly must not have moved fd's own */
	if (sys3(SYS_lseek, fd, 0, 1) != FSZ) return (8);	/* we wrote it fully */
	if (sys3(SYS_lseek, fd2, 0, 1) != 0) return (8);
	for (i = 0; i < FSZ;) {
		r = sys4(SYS_pread64, fd2, back + i, FSZ - i, i);
		if (r <= 0) return (8);
		i += r;
	}
	if (csum(back, FSZ) != csum(data, FSZ)) return (8);

	/* 9-10: implicit offsets: use and advance the file position. */
	(void)sys3(SYS_lseek, fd, 100, 0);
	r = splice(fd, 0, p[1], 0, 1000, 0);
	if (r != 1000) return (9);
	if (sys3(SYS_lseek, fd, 0, 1) != 1100) return (9);
	xmemset(back, 0, 1000);
	if (splice(p[0], 0, fd2, 0, 1000, 0) != 1000) return (10);
	if (sys3(SYS_lseek, fd2, 0, 1) != 1000) return (10);
	if (sys4(SYS_pread64, fd2, back, 1000, 0) != 1000) return (10);
	if (xmemcmp(back, data + 100, 1000) != 0) return (10);

	msg("splice: 11-13: NON\n");
	/* 11-13: NONBLOCK on an empty pipe source is EAGAIN; on a full sink. */
	if (splice(p[0], 0, fd2, 0, 10, SPLICE_F_NONBLOCK) != -EAGAIN) return (11);
	/* fill the pipe (its capacity is a power of two >= 4 KiB) */
	for (n = 0;;) {
		r = splice(fd, 0, p[1], 0, 65536, SPLICE_F_NONBLOCK);
		if (r == -EAGAIN) break;
		if (r <= 0) { msgnum("fill ", r); return (12); }
		n += r;
		if (n > 64 * 1024 * 1024) return (12);
	}
	if (n == 0) return (12);
	/* drain and compare byte-exact with the file region just spliced */
	{
		long start;

		start = sys3(SYS_lseek, fd, 0, 1) - n;
		for (i = 0; i < n;) {
			r = sys3(SYS_read, p[0], back + i, n - i);
			if (r <= 0) return (13);
			i += r;
		}
		if (xmemcmp(back, data + start, n) != 0) return (13);
	}

	msg("splice: 14-16: pip\n");
	/* 14-16: file -> pipe -> non-blocking unix socket, all three stages
	 * pumped in lockstep and drained into rback; both socket ends are
	 * non-blocking so no stage can block forever, and every byte must
	 * arrive exactly once and in order (no loss when the socket fills). */
	if (sys4(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, sv) != 0) return (14);
	v = 8192;
	(void)sys5(SYS_setsockopt, sv[0], SOL_SOCKET, SO_SNDBUF, &v, 4);
	(void)sys5(SYS_setsockopt, sv[1], SOL_SOCKET, SO_RCVBUF, &v, 4);
	if (sys3(SYS_fcntl, sv[0], F_SETFL, O_NONBLOCK) != 0) return (14);
	if (sys3(SYS_fcntl, sv[1], F_SETFL, O_NONBLOCK) != 0) return (14);
	/* drain any bytes left in the pipe from earlier checks */
	(void)sys3(SYS_fcntl, p[0], F_SETFL, O_NONBLOCK);
	while (sys3(SYS_read, p[0], back, 65536) > 0)
		;
	(void)sys3(SYS_fcntl, p[0], F_SETFL, 0);
	(void)sys3(SYS_lseek, fd, 0, 0);
	total = 128 * 1024;
	{
		long stocked = 0;

		moved = 0; n = 0;
		while (n < total) {
			int progress = 0;

			if (stocked < total) {
				long c = total - stocked;

				r = splice(fd, 0, p[1], 0, c < 16384 ? c : 16384,
				    SPLICE_F_NONBLOCK);
				if (r > 0) { stocked += r; progress = 1; }
				else if (r < 0 && r != -EAGAIN) { msgnum("file->pipe ", r); return (14); }
			}
			r = splice(p[0], 0, sv[0], 0, 65536, SPLICE_F_NONBLOCK);
			if (r > 0) { moved += r; progress = 1; }
			else if (r < 0 && r != -EAGAIN) { msgnum("pipe->socket ", r); return (15); }
			r = sys3(SYS_read, sv[1], back, (total - n) < 65536 ? (total - n) : 65536);
			if (r > 0) {
				if (xmemcmp(back, data + n, r) != 0) { msgnum("mismatch at ", n); return (16); }
				n += r; progress = 1;
			} else if (r < 0 && r != -EAGAIN) { msgnum("socket read ", r); return (16); }
			if (!progress) { msgnum("stuck at ", n); return (16); }
		}
		if (moved != total || stocked != total) { msgnum("moved ", moved); return (16); }
	}
	(void)sys1(SYS_close, sv[0]);
	(void)sys1(SYS_close, sv[1]);

	msg("splice: 17-19: vms\n");
	/* 17-19: vmsplice: user memory into the pipe, and out of it. */
	if (sys2(SYS_pipe2, p2, 0) != 0) return (17);
	iov[0].iov_base = data; iov[0].iov_len = 3000;
	iov[1].iov_base = data + 3000; iov[1].iov_len = 1000;
	r = sys4(SYS_vmsplice, p2[1], iov, 2, SPLICE_F_GIFT);
	if (r != 4000) { msgnum("vmsplice in ", r); return (17); }
	xmemset(back, 0, 4000);
	iov[0].iov_base = back; iov[0].iov_len = 4000;
	if (sys4(SYS_vmsplice, p2[0], iov, 1, 0) != 4000) return (18);
	if (xmemcmp(back, data, 4000) != 0) return (18);
	if (sys4(SYS_vmsplice, fd, iov, 1, 0) != -EBADF) return (19);
	if (sys4(SYS_vmsplice, p2[1], iov, 1, 0x100) != -EINVAL) return (19);
	if (sys4(SYS_vmsplice, p2[1], iov, 1025, 0) != -EINVAL) return (19);
	if (sys4(SYS_vmsplice, p2[1], 0, 1, 0) != -EFAULT) return (19);
	/* 20: tee stays unimplemented: ENOSYS (documented). */
	if (sys4(SYS_tee, p[0], p2[1], 10, 0) != -ENOSYS) return (20);

	(void)sys1(SYS_close, p[0]); (void)sys1(SYS_close, p[1]);
	(void)sys1(SYS_close, p2[0]); (void)sys1(SYS_close, p2[1]);
	(void)sys1(SYS_close, fd); (void)sys1(SYS_close, fd2);
	(void)sys1(SYS_unlink, "splice_in.tmp"); (void)sys1(SYS_unlink, "splice_out.tmp");
	return (0);
}
