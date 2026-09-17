/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * groupprobe: a throwaway unit for the group-container e2e.  It claims its
 * bundle-shared container (Data/<bundle>/shared/persistent/state) and the
 * cross-bundle group container Data/Shared/<GROUPPROBE_GROUP>/persistent/<claim>
 * (claim name from argv[1], default "state"), writes a marker in each, and
 * idles.  A bundle that does not declare the group must get EPERM.
 */
#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libservice.h>
#include <logcmp.h>

#ifndef GROUPPROBE_GROUP
#define	GROUPPROBE_GROUP	"test.shared"
#endif

static void
mark(int dirfd, const char *what)
{
	int fd;

	if (dirfd < 0)
		return;
	fd = openat(dirfd, "marker", O_CREAT | O_WRONLY, 0600);
	if (fd >= 0) {
		(void)write(fd, what, strlen(what));
		(void)close(fd);
	}
}

int
main(int argc, char **argv)
{
	struct service_context *ctx = NULL;
	const char *claim = argc > 1 ? argv[1] : "state";
	int sfd = -1, gfd = -1;

	if (cap_enter() == -1)
		return (1);
	if (service_acquire(&ctx) == -1) {
		logcmp_log(LOG_ERR, "groupprobe: service_acquire: %m");
	} else {
		if (service_storage_open_shared(ctx, "state", &sfd) == -1)
			logcmp_log(LOG_ERR, "groupprobe: open_shared: %m");
		else
			mark(sfd, "shared\n");
		if (service_storage_open_group(ctx, GROUPPROBE_GROUP, claim,
		    &gfd) == -1)
			logcmp_log(LOG_ERR, "groupprobe: open_group(%s,%s): %m",
			    GROUPPROBE_GROUP, claim);
		else
			mark(gfd, "group\n");
	}
	for (;;)
		(void)pause();
	return (0);
}
