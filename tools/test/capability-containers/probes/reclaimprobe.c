/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * reclaimprobe: a throwaway capability unit for the container-model lifecycle
 * test.  It enters capability mode (switchboard's readiness boundary), claims
 * persistent storage from system.Filesystem -- which materialises its per-bundle
 * container Data/<bundle>/<unit>/persistent -- writes a marker, then idles.
 * Removing its bundle must make bsdfilesystem's reconcile reap that container.
 */
#include <sys/capsicum.h>

#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>

#include <libservice.h>

int
main(void)
{
	struct service_context *ctx = NULL;
	int dirfd = -1, cachefd = -1, fd;

	openlog("reclaimprobe", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	/*
	 * Enter capability mode first: switchboard observes capmode entry as the
	 * readiness boundary (a boot unit that never enters it is killed on the
	 * readiness timeout).  The storage claim below rides inherited descriptors
	 * (the bootstrap envfd + the brokered channel) and openat under the
	 * delivered claim dir, so it needs no path opens and works in capmode.
	 */
	if (cap_enter() == -1)
		syslog(LOG_ERR, "reclaimprobe: cap_enter: %m");
	if (service_acquire(&ctx) == -1)
		syslog(LOG_ERR, "reclaimprobe: service_acquire: %m");
	else if (service_storage_open(ctx, "state", &dirfd) == -1)
		syslog(LOG_ERR, "reclaimprobe: service_storage_open: %m");
	else {
		/* One line per launch: a reinstalled bundle that inherited its
		 * container shows more than one; a fresh container shows one. */
		fd = openat(dirfd, "marker", O_CREAT | O_WRONLY | O_APPEND, 0600);
		if (fd >= 0) {
			(void)write(fd, "launch\n", 7);
			(void)close(fd);
			syslog(LOG_NOTICE,
			    "reclaimprobe: claimed persistent storage");
		} else
			syslog(LOG_ERR, "reclaimprobe: openat marker: %m");
		/* And a cache sub-container, reaped with the unit. */
		if (service_storage_open_cache(ctx, "scratch", &cachefd) == -1)
			syslog(LOG_ERR, "reclaimprobe: open_cache: %m");
		else {
			fd = openat(cachefd, "scratch.bin", O_CREAT | O_WRONLY, 0600);
			if (fd >= 0)
				(void)close(fd);
			/*
			 * The persistent store must still be mounted AFTER the
			 * cache claim (one anchor per claim, not per connection):
			 * write a second file through the first claim's dirfd.
			 */
			fd = openat(dirfd, "after-cache", O_CREAT | O_WRONLY, 0600);
			if (fd >= 0) {
				(void)close(fd);
				syslog(LOG_NOTICE,
				    "reclaimprobe: persistent still mounted after cache claim");
			} else
				syslog(LOG_ERR,
				    "reclaimprobe: persistent LOST after cache claim: %m");
		}
	}
	for (;;)
		(void)pause();
	return (0);
}
