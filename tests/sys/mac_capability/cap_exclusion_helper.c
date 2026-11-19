/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The image cap_exclusion_test executes.  Statically linked, so an exec
 * that selects a software authority (set-id for rtld) needs no library
 * directories.
 *
 *   cap_exclusion_helper report
 *	print "flag2=<hex> valid=<0|1>": this process's p_flag2 (ki_flag2)
 *	and whether it holds a valid software authority (CAP_AUTH_INFO).
 *   cap_exclusion_helper exec PATH [ARGS...]
 *	report, then execv(PATH, ARGS); on failure print "exec=<errno>".
 *   cap_exclusion_helper jail
 *	enter a new jail (path "/"), then report.
 */

#include <sys/param.h>
#include <sys/cap_authority.h>
#include <sys/jail.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
report(void)
{
	struct kinfo_proc kp;
	struct cap_authority_info info;
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
	size_t len = sizeof(kp);
	unsigned valid = 0;

	mib[3] = getpid();
	if (sysctl(mib, nitems(mib), &kp, &len, NULL, 0) != 0) {
		printf("report=%d\n", errno);
		return;
	}
	memset(&info, 0, sizeof(info));
	if (syscall(SYS_cap_process, CAP_AUTH_INFO, -1, 0, &info) == 0)
		valid = info.valid;
	printf("flag2=%#x valid=%u\n", (unsigned)kp.ki_flag2, valid);
	fflush(stdout);
}

int
main(int argc, char *argv[])
{
	struct jail j = {
		.version = JAIL_API_VERSION,
		.path = __DECONST(char *, "/"),
		.hostname = __DECONST(char *, "cap-exclusion"),
	};

	if (argc >= 2 && strcmp(argv[1], "report") == 0) {
		report();
		return (0);
	}
	if (argc >= 3 && strcmp(argv[1], "exec") == 0) {
		report();
		execv(argv[2], &argv[2]);
		printf("exec=%d\n", errno);
		return (1);
	}
	if (argc >= 2 && strcmp(argv[1], "jail") == 0) {
		if (jail(&j) < 0) {
			printf("jail=%d\n", errno);
			return (1);
		}
		report();
		return (0);
	}
	fprintf(stderr, "usage: cap_exclusion_helper report|exec PATH ...|jail\n");
	return (64);
}
