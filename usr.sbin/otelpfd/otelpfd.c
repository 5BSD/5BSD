/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * otelpfd - export pf(4) statistics as OpenTelemetry metrics.
 *
 * Every interval the daemon reads struct pf_status with DIOCGETSTATUS
 * and sends it through libotelexport, configured by otel.conf(5).
 * /dev/pf is opened read-only as root, its rights are limited to that
 * one ioctl, and the process then switches to an unprivileged user.
 * Capability mode is not entered: the exporter must connect(2) to the
 * collector, and reconnect after failures.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <capsicum_helpers.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "otelexport.h"
#include "oe_sysconf.h"
#include "pfstat.h"

#define	OTELPFD_VERSION	"1.0"

static volatile sig_atomic_t done;

static void
on_signal(int sig __unused)
{

	done = 1;
}

static void __dead2
usage(void)
{

	fprintf(stderr, "usage: otelpfd [-c count] [-e endpoint] "
	    "[-f file] [-i interval] [-u user]\n");
	exit(2);
}

/*
 * Read the next status: from /dev/pf, or the next record of a replay
 * file.  Returns 1 on success, 0 at the end of a replay file.
 */
static int
read_status(int fd, int replay, struct pf_status *st)
{
	ssize_t r;

	if (!replay) {
		if (ioctl(fd, DIOCGETSTATUS, st) == -1)
			err(1, "DIOCGETSTATUS");
		return (1);
	}
	r = read(fd, st, sizeof(*st));
	if (r == 0)
		return (0);
	if (r == -1)
		err(1, "read");
	if ((size_t)r != sizeof(*st))
		errx(1, "truncated status record (%zd of %zu bytes)", r,
		    sizeof(*st));
	return (1);
}

int
main(int argc, char **argv)
{
	struct oe_service svc;
	struct sigaction sa;
	struct pf_status st;
	struct timespec ts, next;
	cap_rights_t rights;
	const unsigned long cmds[] = { DIOCGETSTATUS };
	const char *endpoint, *file, *user;
	char errbuf[512], *end;
	long count, n;
	double interval;
	int ch, fd;

	endpoint = file = user = NULL;
	interval = 15;
	count = 0;
	while ((ch = getopt(argc, argv, "c:e:f:i:u:")) != -1) {
		switch (ch) {
		case 'c':
			count = strtol(optarg, &end, 10);
			if (*end != '\0' || count < 1)
				errx(2, "-c must be a positive integer");
			break;
		case 'e':
			endpoint = optarg;
			break;
		case 'f':
			file = optarg;
			break;
		case 'i':
			interval = strtod(optarg, &end);
			if (*end != '\0' || !(interval >= 0.1 &&
			    interval <= 3600))
				errx(2, "-i must be 0.1 to 3600 seconds");
			break;
		case 'u':
			user = optarg;
			break;
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();

	/* Privileged setup: the device, then the configuration. */
	if (file != NULL)
		fd = open(file, O_RDONLY | O_CLOEXEC);
	else
		fd = open("/dev/pf", O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		err(1, "%s", file != NULL ? file : "/dev/pf");
	if (file == NULL) {
		cap_rights_init(&rights, CAP_IOCTL);
		if (caph_rights_limit(fd, &rights) != 0 ||
		    caph_ioctls_limit(fd, cmds, nitems(cmds)) != 0)
			err(1, "cannot limit /dev/pf");
	}
	if (oe_service_open(&svc, "otelpfd", OTELPFD_VERSION, PFSTAT_PROFILE,
	    endpoint, interval, errbuf, sizeof(errbuf)) != 0) {
		oe_service_close(&svc);
		errx(1, "%s", errbuf);
	}
	if (user != NULL && oe_drop_privileges(user, errbuf,
	    sizeof(errbuf)) != 0) {
		oe_service_close(&svc);
		errx(1, "%s", errbuf);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	clock_gettime(CLOCK_MONOTONIC, &next);
	for (n = 0; !done && (count == 0 || n < count); n++) {
		if (!read_status(fd, file != NULL, &st))
			break;
		clock_gettime(CLOCK_REALTIME, &ts);
		if (pfstat_emit(svc.exporter, &st, &ts) < 0)
			warnx("cannot queue the pf metrics");
		if (count != 0 && n + 1 == count)
			break;
		next.tv_sec += (time_t)interval;
		next.tv_nsec += (long)((interval - (double)(time_t)interval) *
		    1e9);
		if (next.tv_nsec >= 1000000000L) {
			next.tv_sec++;
			next.tv_nsec -= 1000000000L;
		}
		while (!done && clock_nanosleep(CLOCK_MONOTONIC,
		    TIMER_ABSTIME, &next, NULL) == EINTR)
			;
	}
	close(fd);
	oe_service_close(&svc);
	return (0);
}
