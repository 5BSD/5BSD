/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * boottimeprobe: a boot unit that records, into its storage container, the
 * kernel uptime (CLOCK_UPTIME, monotonic from boot) at the instant the native
 * BSDFilesystem provider first serves it a storage claim.  That value is the
 * boot-relative "time until the capability plane is usable", independent of the
 * guest's (unreliable, per-boot-jumping) wall clock.  The driver reads it back.
 */
#include <sys/capsicum.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libservice.h>

int
main(void)
{
	struct service_context *ctx = NULL;
	struct timespec ts;
	int dirfd = -1, fd, tries;
	char line[32];
	int n;

	if (cap_enter() == -1)
		/* still proceed; the claim rides inherited descriptors */
		(void)0;
	for (tries = 0; service_acquire(&ctx) == -1 && tries < 6000; tries++)
		usleep(100000);
	for (tries = 0; service_storage_open(ctx, "state", &dirfd) == -1 &&
	    tries < 6000; tries++)
		usleep(100000);
	/* Served (or gave up): stamp the uptime now. */
	if (clock_gettime(CLOCK_UPTIME, &ts) == -1)
		ts.tv_sec = -1;
	if (dirfd != -1) {
		fd = openat(dirfd, "servetime", O_CREAT | O_WRONLY | O_TRUNC, 0600);
		if (fd >= 0) {
			n = snprintf(line, sizeof(line), "%lld\n",
			    (long long)ts.tv_sec);
			if (n > 0)
				(void)write(fd, line, (size_t)n);
			(void)close(fd);
		}
	}
	for (;;)
		(void)pause();
	return (0);
}
