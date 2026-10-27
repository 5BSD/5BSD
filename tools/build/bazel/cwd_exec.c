/* SPDX-License-Identifier: BSD-2-Clause */
/* Execute a declared build tool in a declared output directory. */
#include <sys/param.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
    char executable[MAXPATHLEN];

    if (argc < 3)
        errx(1, "usage: cwd_exec directory executable [arguments ...]");
    if (realpath(argv[2], executable) == NULL)
        err(1, "%s", argv[2]);
    if (chdir(argv[1]) != 0)
        err(1, "%s", argv[1]);
    execv(executable, argv + 2);
    err(1, "%s", executable);
}
