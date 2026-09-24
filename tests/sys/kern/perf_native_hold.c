/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	uint64_t value;
	char *end;
	long fd;
	int marker;

	if (argc != 4)
		errx(2, "usage: perf_native_hold fd ready release");
	fd = strtol(argv[1], &end, 10);
	if (*end != '\0' || fd < 0 || fd > 0x7fffffff)
		errx(2, "invalid fd");
	marker = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (marker < 0)
		err(2, "open ready");
	if (write(marker, "ready\n", 6) != 6 || close(marker) != 0)
		err(2, "write ready");
	while (access(argv[3], F_OK) != 0)
		usleep(1000);
	if (read((int)fd, &value, sizeof(value)) != sizeof(value))
		err(3, "read perf fd");
	return (0);
}
