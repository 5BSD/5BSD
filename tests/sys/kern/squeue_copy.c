/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * A real-workload smoke test and worked example for libsqueue: copy a file
 * through a squeue ring.  It fills the ring with a batch of positioned READs
 * from the source, submits them, then issues the matching WRITEs to the
 * destination, using the <squeue.h> API throughout, and finally verifies the
 * destination matches the source byte for byte.  Exit status = failing check
 * number, 0 = ok.
 */
#include <squeue.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define	CHUNK	4096
#define	NCHUNK	32		/* 128 KiB total */
#define	BATCH	8		/* reads/writes in flight per round */

static char src[CHUNK * NCHUNK];
static char dst[CHUNK * NCHUNK];
static char buf[BATCH][CHUNK];

int
main(void)
{
	struct squeue q;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int sfd, dfd, i, base, got;

	for (i = 0; i < (int)sizeof(src); i++)
		src[i] = (char)(i * 7 + 3);

	(void)unlink("/tmp/squeue_copy_src.tmp");
	(void)unlink("/tmp/squeue_copy_dst.tmp");
	sfd = open("/tmp/squeue_copy_src.tmp", O_RDWR | O_CREAT | O_EXCL, 0600);
	dfd = open("/tmp/squeue_copy_dst.tmp", O_RDWR | O_CREAT | O_EXCL, 0600);
	if (sfd < 0 || dfd < 0)
		return (1);
	if (pwrite(sfd, src, sizeof(src), 0) != (ssize_t)sizeof(src))
		return (2);

	if (squeue_init(&q, 64) < 0)
		return (3);

	for (base = 0; base < NCHUNK; base += BATCH) {
		int n = (NCHUNK - base) < BATCH ? (NCHUNK - base) : BATCH;

		/* Batch: read n chunks from the source. */
		for (i = 0; i < n; i++) {
			sqe = squeue_get_sqe(&q);
			if (sqe == NULL)
				return (4);
			squeue_prep_read(sqe, sfd, buf[i], CHUNK,
			    (uint64_t)(base + i) * CHUNK);
			squeue_sqe_set_data(sqe, (uint64_t)i);
		}
		if (squeue_submit_and_wait(&q, n) < 0)
			return (5);
		for (got = 0; got < n; got++) {
			if (squeue_wait_cqe(&q, &cqe) < 0 || cqe->res != CHUNK)
				return (6);
			squeue_cqe_seen(&q, cqe);
		}
		/* Batch: write the n chunks to the destination. */
		for (i = 0; i < n; i++) {
			sqe = squeue_get_sqe(&q);
			if (sqe == NULL)
				return (7);
			squeue_prep_write(sqe, dfd, buf[i], CHUNK,
			    (uint64_t)(base + i) * CHUNK);
			squeue_sqe_set_data(sqe, (uint64_t)i);
		}
		if (squeue_submit_and_wait(&q, n) < 0)
			return (8);
		for (got = 0; got < n; got++) {
			if (squeue_wait_cqe(&q, &cqe) < 0 || cqe->res != CHUNK)
				return (9);
			squeue_cqe_seen(&q, cqe);
		}
	}

	squeue_exit(&q);

	/* Verify the destination is a byte-exact copy. */
	if (pread(dfd, dst, sizeof(dst), 0) != (ssize_t)sizeof(dst))
		return (10);
	if (memcmp(src, dst, sizeof(src)) != 0)
		return (11);

	(void)close(sfd);
	(void)close(dfd);
	(void)unlink("/tmp/squeue_copy_src.tmp");
	(void)unlink("/tmp/squeue_copy_dst.tmp");
	return (0);
}
