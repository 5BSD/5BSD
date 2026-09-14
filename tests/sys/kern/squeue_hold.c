/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Helper for the squeue procstat/fstat test: create a squeue ring, announce
 * readiness on stdout, and hold the descriptor open so the tools can inspect
 * it, then exit on its own after a short timeout.
 */
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/io_uring.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int
main(void)
{
	struct io_uring_params p;
	long fd;

	memset(&p, 0, sizeof(p));
	fd = syscall(SYS_squeue_setup, 8, &p);
	if (fd < 0) {
		fprintf(stderr, "squeue_setup failed\n");
		return (1);
	}
	printf("READY %ld\n", fd);
	fflush(stdout);
	sleep(10);
	return (0);
}
