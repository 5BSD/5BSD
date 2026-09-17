/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * envprobe: a throwaway unit for the shared-environment e2e.  Two units of one
 * bundle run it: "writer" claims the bundle-shared store "env" read-write and
 * writes env/settings; "reader" claims the read-only view through
 * service_storage_open_env(), waits for the file, logs its content, proves
 * every mutation is refused (ENOTCAPABLE), and keeps re-reading every 3s so
 * the mount can be shown to survive the writer's exit.
 */
#include <sys/capsicum.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libservice.h>

static int outfd = -1;

static void
report(const char *line)
{
	int fd;

	syslog(LOG_NOTICE, "envprobe: %s", line);
	if (outfd < 0)
		return;
	fd = openat(outfd, "result", O_CREAT | O_WRONLY | O_APPEND, 0644);
	if (fd >= 0) {
		(void)write(fd, line, strlen(line));
		(void)write(fd, "\n", 1);
		(void)close(fd);
	}
}

static void
prove_ro(int dirfd)
{
	int bad = 0;

	if (openat(dirfd, "settings", O_WRONLY) != -1 || errno != ENOTCAPABLE)
		bad |= 1;
	if (openat(dirfd, "new", O_CREAT | O_WRONLY, 0644) != -1 ||
	    errno != ENOTCAPABLE)
		bad |= 2;
	if (unlinkat(dirfd, "settings", 0) != -1 || errno != ENOTCAPABLE)
		bad |= 4;
	if (mkdirat(dirfd, "d", 0755) != -1 || errno != ENOTCAPABLE)
		bad |= 8;
	if (renameat(dirfd, "settings", dirfd, "x") != -1 || errno != ENOTCAPABLE)
		bad |= 16;
	if (fchmodat(dirfd, "settings", 0600, 0) != -1 || errno != ENOTCAPABLE)
		bad |= 32;
	if (bad == 0)
		report("RO_ENFORCED");
	else {
		char m[32];

		(void)snprintf(m, sizeof(m), "RO_VIOLATED mask=%d", bad);
		report(m);
	}
}

int
main(int argc, char **argv)
{
	struct service_context *ctx = NULL;
	const char *mode = argc > 1 ? argv[1] : "reader";
	char buf[128];
	int dirfd = -1, fd, i;
	ssize_t n;

	openlog("envprobe", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (cap_enter() == -1)
		syslog(LOG_ERR, "envprobe: cap_enter: %m");
	if (service_acquire(&ctx) == -1) {
		syslog(LOG_ERR, "envprobe: service_acquire: %m");
		for (;;)
			(void)pause();
	}
	if (strcmp(mode, "writer") == 0) {
		if (service_storage_open_shared(ctx, "env", &dirfd) == -1) {
			syslog(LOG_ERR, "envprobe: writer open_shared: %m");
		} else {
			fd = openat(dirfd, "settings", O_CREAT | O_WRONLY | O_TRUNC,
			    0644);
			if (fd >= 0) {
				(void)write(fd, "COLOR=blue\n", 11);
				(void)close(fd);
				syslog(LOG_NOTICE, "envprobe: WRITER_WROTE");
			} else
				syslog(LOG_ERR, "envprobe: writer openat: %m");
		}
		for (;;)
			(void)pause();
	}
	/*
	 * reader: results go to the reader's OWN persistent store.  A boot unit
	 * may start before the storage provider is ready; claims fail soft, so
	 * retry the first one for a while rather than run without a store.
	 */
	for (i = 0; i < 60; i++) {
		if (service_storage_open(ctx, "state", &outfd) == 0)
			break;
		syslog(LOG_WARNING, "envprobe: reader open state (try %d): %m", i);
		sleep(1);
	}
	if (service_storage_open_env(ctx, &dirfd) == -1) {
		report("ENV_CLAIM_FAILED");
		for (;;)
			(void)pause();
	}
	report("ENV_CLAIMED");
	for (i = 0; i < 60; i++) {
		fd = openat(dirfd, "settings", O_RDONLY);
		if (fd >= 0)
			break;
		sleep(1);
	}
	if (fd < 0) {
		report("SETTINGS_NEVER_APPEARED");
	} else {
		char line[160];

		n = read(fd, buf, sizeof(buf) - 1);
		(void)close(fd);
		if (n > 0) {
			buf[n] = '\0';
			if (buf[n - 1] == '\n')
				buf[n - 1] = '\0';
			(void)snprintf(line, sizeof(line), "ENV_READ=%s", buf);
			report(line);
		}
		prove_ro(dirfd);
	}
	for (i = 0;; i++) {
		sleep(3);
		fd = openat(dirfd, "settings", O_RDONLY);
		if (fd >= 0) {
			n = read(fd, buf, sizeof(buf) - 1);
			(void)close(fd);
			if (n > 0) {
				char line[160];

				buf[n] = '\0';
				if (buf[n - 1] == '\n')
					buf[n - 1] = '\0';
				(void)snprintf(line, sizeof(line), "ENV_TICK=%s", buf);
				report(line);
			}
		} else
			report("ENV_TICK_FAIL");
	}
	return (0);
}
