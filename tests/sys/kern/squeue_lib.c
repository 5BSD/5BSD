/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * libsqueue exerciser: drive a ring entirely through the <squeue.h> ergonomic
 * API (init, get_sqe, prep_*, submit_and_wait, wait_cqe, cqe_seen, exit) to
 * prove the userland library works against the real kernel engine.  Exit
 * status = failing check number, 0 = ok.
 */
#include <squeue.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int
main(void)
{
	struct squeue q;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	char rbuf[16];
	int fd;

	/* 1: init */
	if (squeue_init(&q, 8) < 0)
		return (1);

	/* 2: a NOP round-trips through the library */
	sqe = squeue_get_sqe(&q);
	if (sqe == NULL)
		return (2);
	squeue_prep_nop(sqe);
	squeue_sqe_set_data(sqe, 0x1);
	if (squeue_submit_and_wait(&q, 1) < 0)
		return (3);
	if (squeue_wait_cqe(&q, &cqe) < 0)
		return (4);
	if (cqe->user_data != 0x1 || cqe->res != 0)
		return (5);
	squeue_cqe_seen(&q, cqe);

	/* 3: WRITE then READ on a temp file via the library */
	(void)unlink("/tmp/squeue_lib.tmp");
	fd = open("/tmp/squeue_lib.tmp", O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0)
		return (6);
	sqe = squeue_get_sqe(&q);
	if (sqe == NULL)
		return (7);
	squeue_prep_write(sqe, fd, "hello!!", 7, 0);
	squeue_sqe_set_data(sqe, 0x2);
	if (squeue_submit_and_wait(&q, 1) < 0)
		return (8);
	if (squeue_wait_cqe(&q, &cqe) < 0 || cqe->user_data != 0x2 ||
	    cqe->res != 7)
		return (9);
	squeue_cqe_seen(&q, cqe);

	memset(rbuf, 0, sizeof(rbuf));
	sqe = squeue_get_sqe(&q);
	if (sqe == NULL)
		return (10);
	squeue_prep_read(sqe, fd, rbuf, 7, 0);
	squeue_sqe_set_data(sqe, 0x3);
	if (squeue_submit_and_wait(&q, 1) < 0)
		return (11);
	if (squeue_wait_cqe(&q, &cqe) < 0 || cqe->user_data != 0x3 ||
	    cqe->res != 7 || memcmp(rbuf, "hello!!", 7) != 0)
		return (12);
	squeue_cqe_seen(&q, cqe);

	/* 4: batch two NOPs and reap both */
	sqe = squeue_get_sqe(&q);
	squeue_prep_nop(sqe);
	squeue_sqe_set_data(sqe, 0x10);
	sqe = squeue_get_sqe(&q);
	squeue_prep_nop(sqe);
	squeue_sqe_set_data(sqe, 0x11);
	if (squeue_submit_and_wait(&q, 2) != 2)
		return (13);
	{
		int got = 0;

		while (got < 2) {
			if (squeue_wait_cqe(&q, &cqe) < 0)
				return (14);
			if (cqe->res != 0)
				return (15);
			squeue_cqe_seen(&q, cqe);
			got++;
		}
	}

	(void)close(fd);
	(void)unlink("/tmp/squeue_lib.tmp");
	squeue_exit(&q);
	return (0);
}
