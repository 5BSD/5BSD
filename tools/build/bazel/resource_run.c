/* SPDX-License-Identifier: BSD-2-Clause */
/* Measure a command from a small native parent, excluding controller RSS. */
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct timespec start, finish;
	struct rusage usage;
	FILE *report;
	pid_t child;
	int fd, status, code;
	double wall;

	if (argc < 4 || strcmp(argv[2], "--") != 0)
		errx(1, "usage: resource_run report.json -- command arguments...");
	fd = open(argv[1], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd == -1)
		err(1, "%s", argv[1]);
	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		err(1, "clock_gettime");
	child = fork();
	if (child == -1)
		err(1, "fork");
	if (child == 0) {
		execv(argv[3], argv + 3);
		err(127, "%s", argv[3]);
	}
	while (wait4(child, &status, 0, &usage) == -1)
		if (errno != EINTR)
			err(1, "wait4");
	if (clock_gettime(CLOCK_MONOTONIC, &finish) != 0)
		err(1, "clock_gettime");
	wall = finish.tv_sec - start.tv_sec +
	    (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
	code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
	if ((report = fdopen(fd, "w")) == NULL)
		err(1, "fdopen");
	fprintf(report, "{\"exit_status\":%d,\"wait_status\":%d,"
	    "\"wall_seconds\":%.9f,\"user_seconds\":%.6f,\"system_seconds\":%.6f,"
	    "\"maxrss_kib\":%ld,\"block_inputs\":%ld,\"block_outputs\":%ld,"
	    "\"major_faults\":%ld}\n", code, status, wall,
	    usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1000000.0,
	    usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1000000.0,
	    usage.ru_maxrss, usage.ru_inblock, usage.ru_oublock, usage.ru_majflt);
	if (fclose(report) != 0)
		err(1, "%s", argv[1]);
	return (code);
}
