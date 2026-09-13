/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * tee(2): duplicate pipe data to another pipe without consuming the source.
 * Verifies the source is unchanged after tee, the sink gets an exact copy,
 * short/zero/EOF/non-blocking behaviour, validation (non-pipe ends, the two
 * ends of one pipe, bad flags), ring-buffer wrap, and integration with
 * splice (tee then splice the copy out).  Exit status = failed check number.
 */
#include "linux_test.h"

#define	SYS_tee			276
#define	SYS_splice		275
#define	SPLICE_F_NONBLOCK	2

static long
tee(long in, long out, long len, long flags)
{

	return (sys4(SYS_tee, in, out, len, flags));
}

static int stress_sink, stress_stop;
static volatile long drain_total;
static struct thread drain_th;
static int
drainer(void *arg __attribute__((unused)))
{
	char b[1024];
	long n;

	for (;;) {
		n = sys3(SYS_read, stress_sink, (long)b, sizeof(b));
		if (n > 0) { __atomic_add_fetch(&drain_total, n, __ATOMIC_ACQ_REL); continue; }
		if (n == 0) break;			/* EOF: writer closed */
		if (n == -EAGAIN) { (void)sys0(SYS_sched_yield); continue; }
		break;
	}
	return (0);
}

static int
test(int argc __attribute__((unused)), char **argv __attribute__((unused)),
    char **envp __attribute__((unused)))
{
	int a[2], b[2], c[2];
	char buf[8192], back[8192];
	long r, i;

	if (sys2(SYS_pipe2, (long)a, 0) != 0) return (1);
	if (sys2(SYS_pipe2, (long)b, 0) != 0) return (1);

	msg("tee: 1-3\n");
	/* 1-3: basic tee leaves the source intact and copies to the sink. */
	if (sys3(SYS_write, a[1], (long)"hello world", 11) != 11) return (1);
	r = tee(a[0], b[1], 11, 0);
	if (r != 11) { msgnum("tee ", r); return (2); }
	/* the sink now has the copy */
	if (sys3(SYS_read, b[0], (long)back, 11) != 11) return (2);
	if (xmemcmp(back, "hello world", 11) != 0) return (2);
	/* the source STILL has the original (not consumed) */
	if (sys3(SYS_read, a[0], (long)back, 11) != 11) return (3);
	if (xmemcmp(back, "hello world", 11) != 0) return (3);

	msg("tee: 4\n");
	/* 4: tee more than available returns only what is there. */
	if (sys3(SYS_write, a[1], (long)"abc", 3) != 3) return (4);
	r = tee(a[0], b[1], 1000, 0);
	if (r != 3) { msgnum("tee short ", r); return (4); }
	(void)sys3(SYS_read, a[0], (long)back, 3);
	(void)sys3(SYS_read, b[0], (long)back, 3);

	msg("tee: 5\n");
	/* 5: zero length is a no-op. */
	if (sys3(SYS_write, a[1], (long)"z", 1) != 1) return (5);
	if (tee(a[0], b[1], 0, 0) != 0) return (5);
	(void)sys3(SYS_read, a[0], (long)back, 1);

	msg("tee: 6\n");
	/* 6: SPLICE_F_NONBLOCK on an empty source is EAGAIN. */
	if (tee(a[0], b[1], 10, SPLICE_F_NONBLOCK) != -EAGAIN) return (6);

	msg("tee: 7\n");
	/* 7: bad flags. */
	if (tee(a[0], b[1], 10, 0x40) != -EINVAL) return (7);

	msg("tee: 8\n");
	/* 8: a non-pipe end is EINVAL (use a regular fd). */
	{
		long fd = tmpfile_fd("tee_reg");

		if (fd < 0) return (8);
		if (tee(fd, b[1], 10, 0) != -EINVAL) return (8);
		if (tee(a[0], fd, 10, 0) != -EINVAL) return (8);
		(void)sys1(SYS_close, fd);
	}

	msg("tee: 9\n");
	/* 9: the two ends of the SAME pipe are EINVAL. */
	if (tee(a[0], a[1], 10, 0) != -EINVAL) return (9);

	msg("tee: 10-11\n");
	/* 10-11: ring-buffer wrap.  Advance the read pointer with small
	 * (buffered) writes, then write a chunk that wraps the ring end and
	 * tee it out byte-exact.  Every write stays below PIPE_MINDIRECT
	 * (8192) so none takes the blocking direct-write path on a pipe with
	 * no concurrent reader. */
	for (i = 0; i < (long)sizeof(buf); i++) buf[i] = (char)(i * 5 + 1);
	for (i = 0; i < 3; i++) {		/* push out to ~12000 */
		if (sys3(SYS_write, a[1], (long)buf, 4000) != 4000) return (10);
		if (sys3(SYS_read, a[0], (long)back, 4000) != 4000) return (10);
	}
	if (sys3(SYS_write, a[1], (long)buf, 6000) != 6000) return (10);	/* wraps */
	r = tee(a[0], b[1], 6000, 0);
	if (r <= 0) { msgnum("tee wrap ", r); return (10); }
	{
		long got = 0;

		while (got < r) {
			long n = sys3(SYS_read, b[0], (long)(back + got), r - got);
			if (n <= 0) break;
			got += n;
		}
		if (got != r || xmemcmp(back, buf, r) != 0) return (11);
	}
	/* drain the source's (unconsumed) copy */
	{ long left = 6000; while (left > 0) { long n = sys3(SYS_read, a[0], (long)back, left); if (n <= 0) break; left -= n; } }

	msg("tee: 12\n");
	/* 12: EOF - writer closed and source drained -> tee returns 0. */
	(void)sys1(SYS_close, a[1]);
	if (tee(a[0], b[1], 10, 0) != 0) return (12);

	msg("tee: 13\n");
	/* 13: integration - tee into a sink, then splice the sink out to a
	 * file, while the teed source is separately readable. */
	if (sys2(SYS_pipe2, (long)c, 0) != 0) return (13);
	if (sys3(SYS_write, c[1], (long)"spliceme!!", 10) != 10) return (13);
	if (tee(c[0], b[1], 10, 0) != 10) return (13);
	{
		long fd = tmpfile_fd("tee_splice");

		if (fd < 0) return (13);
		r = sys6(SYS_splice, b[0], 0, fd, 0, 10, 0);
		if (r != 10) { msgnum("splice teed ", r); return (13); }
		(void)sys3(SYS_lseek, fd, 0, 0);
		if (sys3(SYS_read, fd, (long)back, 10) != 10 ||
		    xmemcmp(back, "spliceme!!", 10) != 0) return (13);
		/* the source pipe c still holds its copy */
		if (sys3(SYS_read, c[0], (long)back, 10) != 10 ||
		    xmemcmp(back, "spliceme!!", 10) != 0) return (13);
		(void)sys1(SYS_close, fd);
	}

	/* 14: threaded stress - a helper thread drains the sink pipe while the
	 * main thread tees a known stream through it many times; the teed
	 * source stream must remain byte-exact and fully re-readable (never
	 * consumed by tee). */
	{
		static int tp[2], tq[2];
		long total = 0, k;

		if (sys2(SYS_pipe2, (long)tp, 0) != 0) return (14);
		if (sys2(SYS_pipe2, (long)tq, 0) != 0) return (14);
		stress_sink = tq[0];
		stress_stop = 0;
		if (thread_create(&drain_th, drainer, 0) != 0) return (14);
		for (k = 0; k < 200; k++) {
			char blk[512];
			long i2, got = 0;

			for (i2 = 0; i2 < (long)sizeof(blk); i2++) blk[i2] = (char)(k + i2);
			if (sys3(SYS_write, tp[1], (long)blk, sizeof(blk)) != (long)sizeof(blk)) { stress_stop = 1; return (14); }
			/* duplicate into the drained sink without consuming tp */
			while (got < (long)sizeof(blk)) {
				long n = tee(tp[0], tq[1], sizeof(blk) - got, 0);
				if (n <= 0) { stress_stop = 1; return (14); }
				got += n;
				total += n;
			}
			/* the source still holds this block - consume+verify it */
			got = 0;
			while (got < (long)sizeof(blk)) {
				long n = sys3(SYS_read, tp[0], (long)(back + got), sizeof(blk) - got);
				if (n <= 0) { stress_stop = 1; return (14); }
				got += n;
			}
			for (i2 = 0; i2 < (long)sizeof(blk); i2++)
				if ((unsigned char)back[i2] != (unsigned char)(k + i2)) { stress_stop = 1; return (14); }
		}
		stress_stop = 1;
		(void)sys1(SYS_close, tq[1]);		/* EOF to the drainer */
		if (thread_join(&drain_th) != 0) return (14);
		if (drain_total != total) { msgnum("drained ", drain_total); msgnum("teed ", total); return (14); }
	}

	return (0);
}
