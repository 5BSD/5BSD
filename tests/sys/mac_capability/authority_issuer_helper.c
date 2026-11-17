/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * A helper for the test-issuer cases and the reroot scenario:
 *
 *   authority_issuer_helper info    prints the caller's software authority
 *                                   (CAP_AUTH_INFO), so a test can exec a
 *                                   registered copy and see what exec chose;
 *   authority_issuer_helper create  creates an issuer and exits, printing
 *                                   "created" or "refused errno=N".
 */

#include <sys/param.h>
#include <sys/cap_authority.h>
#include <sys/syscall.h>

#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct cap_authority_info info;
	int fd;

	if (argc == 2 && strcmp(argv[1], "info") == 0) {
		if (syscall(SYS_cap_process, CAP_AUTH_INFO, -1, 0, &info) != 0)
			err(2, "CAP_AUTH_INFO");
		printf("valid=%u issuer=%ju revoked=%u\n", info.valid,
		    (uintmax_t)info.issuer, info.revoked);
		return (0);
	}
	if (argc == 2 && strcmp(argv[1], "create") == 0) {
		fd = syscall(SYS_cap_process, CAP_AUTH_ISSUER_CREATE, -1, 0,
		    NULL);
		if (fd < 0) {
			printf("refused errno=%d\n", errno);
			return (1);
		}
		printf("created\n");
		return (0);
	}
	fprintf(stderr, "usage: authority_issuer_helper info | create\n");
	return (2);
}
