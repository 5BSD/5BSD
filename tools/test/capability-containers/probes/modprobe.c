/*
 * modprobe: a throwaway unit that asks system.SystemExtension to ensure each
 * module named on its command line is loaded, records the outcome of each in
 * its own persistent store ("ENSURED <name>" / "ENSURE_FAILED <name> <errno>"),
 * then idles.  The container proofs use it to give sysextd modules to
 * attribute to a bundle and reclaim once the bundle is gone.
 */
#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libservice.h>

static void
report(int outfd, const char *line)
{
	int fd;

	if (outfd < 0)
		return;
	fd = openat(outfd, "result", O_CREAT | O_WRONLY | O_APPEND, 0644);
	if (fd < 0)
		return;
	(void)write(fd, line, strlen(line));
	(void)close(fd);
}

int
main(int argc, char **argv)
{
	struct service_context *ctx = NULL;
	char line[160];
	int outfd = -1, i, a;

	openlog("modprobe", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (service_acquire(&ctx) == -1) {
		syslog(LOG_ERR, "modprobe: service_acquire: %m");
		for (;;)
			(void)pause();
	}
	/* Results in the unit's own persistent store (capmode units cannot syslog). */
	for (i = 0; i < 60; i++) {
		if (service_storage_open(ctx, "state", &outfd) == 0)
			break;
		sleep(1);
	}
	for (a = 1; a < argc; a++) {
		/* The provider may still be coming up: fail soft, retry. */
		for (i = 0; i < 60; i++) {
			if (service_ensure_extension(ctx, argv[a]) == 0)
				break;
			if (errno == EPERM || errno == ENOENT || errno == EINVAL)
				break;	/* refused: never going to succeed */
			sleep(1);
		}
		if (i < 60 && errno == 0)
			(void)snprintf(line, sizeof(line), "ENSURED %s\n", argv[a]);
		else
			(void)snprintf(line, sizeof(line), "ENSURE_FAILED %s %d\n",
			    argv[a], errno);
		report(outfd, line);
	}
	report(outfd, "DONE\n");
	for (;;)
		(void)pause();
	return (0);
}
