/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * stressprobe: hammer the storage path a fresh boot exercises -- claim many
 * cache stores (each a dataset: create, refquota, anonymous mount), grow a
 * file in each across the record-size boundary (that changes the object's
 * indirect-block depth while it is dirty), close, destroy them all, repeat.
 */
#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libservice.h>

#define	NCLAIMS	24

int
main(void)
{
	struct service_context *ctx = NULL;
	static char buf[65536];
	unsigned round = 0;
	int i, k, outfd = -1;

	openlog("stressprobe", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (cap_enter() == -1)
		syslog(LOG_ERR, "stressprobe: cap_enter: %m");
	while (service_acquire(&ctx) == -1)
		sleep(1);
	for (i = 0; i < 60 && service_storage_open(ctx, "state", &outfd) == -1; i++)
		sleep(1);
	memset(buf, 0x5a, sizeof(buf));
	for (;;) {
		int fds[NCLAIMS], nok = 0, nclaimerr = 0, claimerrno = 0,
		    ndestroyerr = 0, destroyerrno = 0, rfd;
		char line[128];

		for (i = 0; i < NCLAIMS; i++) {
			char nm[16];
			int fd;

			(void)snprintf(nm, sizeof(nm), "s%u_%d", round % 3, i);
			if (service_storage_open_cache(ctx, nm, &fds[i]) == -1) {
				fds[i] = -1;
				nclaimerr++;
				claimerrno = errno;
				continue;
			}
			nok++;
			fd = openat(fds[i], "blob", O_CREAT | O_WRONLY | O_TRUNC, 0600);
			if (fd >= 0) {
				/* 64K..1.5M: crosses 128K records and adds levels */
				for (k = 0; k < 1 + (int)(i % 24); k++)
					(void)write(fd, buf, sizeof(buf));
				(void)fsync(fd);
				(void)close(fd);
			}
		}
		for (i = 0; i < NCLAIMS; i++) {
			char nm[16];

			if (fds[i] >= 0)
				(void)close(fds[i]);
			(void)snprintf(nm, sizeof(nm), "s%u_%d", round % 3, i);
			if (service_storage_destroy_cache(ctx, nm) == -1) {
				ndestroyerr++;
				destroyerrno = errno;
			}
		}
		(void)snprintf(line, sizeof(line), "round %u claims_ok %d "
		    "claim_err %d (errno %d) destroy_err %d (errno %d)\n", round,
		    nok, nclaimerr, claimerrno, ndestroyerr, destroyerrno);
		if (outfd >= 0) {
			rfd = openat(outfd, "result", O_CREAT | O_WRONLY | O_APPEND, 0644);
			if (rfd >= 0) {
				(void)write(rfd, line, strlen(line));
				(void)close(rfd);
			}
		}
		round++;
	}
	return (0);
}
