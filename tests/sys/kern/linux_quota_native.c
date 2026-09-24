/* SPDX-License-Identifier: BSD-2-Clause */
/* Disposable guest: verify native/Linux quota updates address the same state. */
#include <sys/types.h>
#include <ufs/ufs/quota.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char **argv)
{
	struct dqblk dq = { 0 };
	unsigned long limit;

	if (argc != 4)
		errx(1, "usage: quota_native get|set path limit-in-512-byte-blocks");
	limit = strtoul(argv[3], NULL, 10);
	if (strcmp(argv[1], "permissions") == 0) {
		if (setgroups(0, NULL) != 0 || setgid(60001) != 0 ||
		    setuid(60001) != 0)
			err(1, "drop privilege");
		if (quotactl(argv[2], QCMD(Q_GETQUOTA, USRQUOTA), 60001,
		    (void *)&dq) != 0)
			err(1, "own quota query");
		errno = 0;
		if (quotactl(argv[2], QCMD(Q_GETQUOTA, USRQUOTA), 60002,
		    (void *)&dq) != -1 || errno != EPERM)
			errx(1, "foreign query permission");
		errno = 0;
		if (quotactl(argv[2], QCMD(Q_SETQUOTA, USRQUOTA), 60001,
		    (void *)&dq) != -1 || errno != EPERM)
			errx(1, "setquota permission");
		return (0);
	}
	if (strcmp(argv[1], "set") == 0) {
		dq.dqb_bhardlimit = limit;
		if (quotactl(argv[2], QCMD(Q_SETQUOTA, USRQUOTA), 60001,
		    (void *)&dq) != 0)
			err(1, "native setquota");
	} else {
		if (quotactl(argv[2], QCMD(Q_GETQUOTA, USRQUOTA), 60001,
		    (void *)&dq) != 0)
			err(1, "native getquota");
		if (dq.dqb_bhardlimit != limit)
			errx(1, "native quota value mismatch");
	}
	return (0);
}
