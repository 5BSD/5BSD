/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * jailprobe: a throwaway unit for the jail-reclaim e2e.  It enters a
 * PERSISTENT jail through warden (system.Namespace) -- the kind that by design
 * outlives the process -- and idles.  Uninstalling its bundle must make
 * warden's reconcile remove that jail (named "wj_" + hash of the unit's
 * resource owner), while a live bundle's jail survives.
 */
#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libservice.h>

int
main(int argc, char **argv)
{
	struct service_context *ctx = NULL;
	const char *path = argc > 1 ? argv[1] : "/";
	int outfd = -1, fd, i;

	openlog("jailprobe", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (service_acquire(&ctx) == -1) {
		syslog(LOG_ERR, "jailprobe: service_acquire: %m");
		for (;;)
			(void)pause();
	}
	/* Results in the unit's own persistent store (capmode units cannot syslog). */
	for (i = 0; i < 60; i++) {
		if (service_storage_open(ctx, "state", &outfd) == 0)
			break;
		sleep(1);
	}
	for (i = 0; i < 60; i++) {
		if (service_enter_namespace(ctx, path, "jailprobe", NULL, 0) == 0)
			break;
		syslog(LOG_WARNING, "jailprobe: enter_namespace (try %d): %m", i);
		sleep(1);
	}
	if (outfd >= 0) {
		fd = openat(outfd, "result", O_CREAT | O_WRONLY | O_APPEND, 0644);
		if (fd >= 0) {
			(void)write(fd, i < 60 ? "JAILED\n" : "JAIL_FAILED\n",
			    i < 60 ? 7 : 12);
			(void)close(fd);
		}
	}
	for (;;)
		(void)pause();
	return (0);
}
