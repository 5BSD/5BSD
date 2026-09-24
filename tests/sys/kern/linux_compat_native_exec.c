/* SPDX-License-Identifier: BSD-2-Clause */
/* Native privilege-drop fixture; execute only inside a disposable test VM. */
#include <sys/types.h>
#include <err.h>
#include <grp.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	if (argc < 3)
		errx(2, "usage: native-exec uid program [args ...]");
	char *end;
	unsigned long id = strtoul(argv[1], &end, 10);
	if (*end != '\0' || id > 65534)
		errx(2, "invalid uid");
	if (setgroups(0, NULL) != 0 || setgid(id) != 0 || setuid(id) != 0)
		err(2, "drop privileges");
	execv(argv[2], &argv[2]);
	err(2, "execv");
}
