/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * otelauditd - export audit records as OpenTelemetry log records.
 *
 * Records come from an auditpipe(4) clone (live, with its own queue and
 * optional local preselection) or from a BSM trail file.  The pipe is
 * opened and configured as root, its rights are limited to reading and
 * the drop counter ioctl, and the process then switches to an
 * unprivileged user.  Capability mode is not entered because the
 * exporter must connect(2) to the collector.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>

#include <security/audit/audit_ioctl.h>

#include <bsm/libbsm.h>

#include <capsicum_helpers.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "otelexport.h"
#include "oe_sysconf.h"
#include "auditrec.h"

#define	OTELAUDITD_VERSION	"1.0"
#define	PIPE_RECORD_MAX		(64 * 1024)

static volatile sig_atomic_t done;

static void
on_signal(int sig __unused)
{

	done = 1;
}

static void __dead2
usage(void)
{

	fprintf(stderr, "usage: otelauditd [-c count] [-e endpoint] "
	    "[-f trail | -F flags] [-u user]\n");
	exit(2);
}

/* Open and configure the audit pipe as root. */
static int
open_pipe(const char *flags)
{
	au_mask_t mask;
	u_int qlimit;
	int fd, mode;
	cap_rights_t rights;
	const unsigned long cmds[] = { AUDITPIPE_GET_DROPS };

	fd = open("/dev/auditpipe", O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		err(1, "/dev/auditpipe");
	if (ioctl(fd, AUDITPIPE_GET_QLIMIT_MAX, &qlimit) == 0)
		(void)ioctl(fd, AUDITPIPE_SET_QLIMIT, &qlimit);
	if (flags != NULL) {
		if (getauditflagsbin(__DECONST(char *, flags), &mask) != 0)
			errx(2, "invalid audit flags: %s", flags);
		mode = AUDITPIPE_PRESELECT_MODE_LOCAL;
		if (ioctl(fd, AUDITPIPE_SET_PRESELECT_FLAGS, &mask) == -1 ||
		    ioctl(fd, AUDITPIPE_SET_PRESELECT_NAFLAGS, &mask) == -1 ||
		    ioctl(fd, AUDITPIPE_SET_PRESELECT_MODE, &mode) == -1)
			err(1, "cannot set the audit pipe preselection");
	}
	cap_rights_init(&rights, CAP_READ, CAP_IOCTL, CAP_EVENT);
	if (caph_rights_limit(fd, &rights) != 0 ||
	    caph_ioctls_limit(fd, cmds, nitems(cmds)) != 0)
		err(1, "cannot limit /dev/auditpipe");
	return (fd);
}

int
main(int argc, char **argv)
{
	struct oe_service svc;
	struct auditrec_events events;
	struct sigaction sa;
	struct oe_event ev;
	const char *endpoint, *file, *flags, *user;
	char errbuf[512], body[AUDITREC_BODY_MAX], probe[64], *end;
	u_char *rec, *pipebuf;
	u_int64_t drops, lastdrops;
	long count, n;
	FILE *trail;
	off_t pos;
	ssize_t r;
	int ch, fd, len;

	endpoint = file = flags = user = NULL;
	count = 0;
	while ((ch = getopt(argc, argv, "c:e:f:F:u:")) != -1) {
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
		case 'F':
			flags = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		default:
			usage();
		}
	}
	if (optind != argc || (file != NULL && flags != NULL))
		usage();

	/* Privileged setup: the source, the event table, the exporter. */
	trail = NULL;
	fd = -1;
	if (file != NULL) {
		trail = fopen(file, "re");
		if (trail == NULL)
			err(1, "%s", file);
	} else
		fd = open_pipe(flags);
	if (auditrec_events_load(&events) != 0)
		errx(1, "cannot load the audit event table");
	if (oe_service_open(&svc, "otelauditd", OTELAUDITD_VERSION,
	    AUDITREC_PROFILE, endpoint, 1.0, errbuf, sizeof(errbuf)) != 0) {
		oe_service_close(&svc);
		errx(1, "%s", errbuf);
	}
	if (user != NULL && oe_drop_privileges(user, errbuf,
	    sizeof(errbuf)) != 0) {
		oe_service_close(&svc);
		errx(1, "%s", errbuf);
	}

	/* No SA_RESTART: a signal interrupts the blocking read. */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	pipebuf = trail == NULL ? malloc(PIPE_RECORD_MAX) : NULL;
	if (trail == NULL && pipebuf == NULL)
		err(1, "malloc");
	lastdrops = 0;
	for (n = 0; !done && (count == 0 || n < count);) {
		if (trail != NULL) {
			pos = ftello(trail);
			len = au_read_rec(trail, &rec);
			if (len == -1) {
				/* EOF inside a record means a cut trail. */
				if (ferror(trail))
					warnx("%s: read error", file);
				else if (ftello(trail) != pos)
					warnx("%s: truncated record at the "
					    "end", file);
				break;
			}
		} else {
			r = read(fd, pipebuf, PIPE_RECORD_MAX);
			if (r == -1 && errno == EINTR)
				continue;
			if (r <= 0) {
				warn("/dev/auditpipe");
				break;
			}
			rec = pipebuf;
			len = (int)r;
			if (ioctl(fd, AUDITPIPE_GET_DROPS, &drops) == 0 &&
			    drops > lastdrops) {
				oe_report_drops(svc.exporter,
				    drops - lastdrops);
				lastdrops = drops;
			}
		}
		switch (auditrec_convert(&events, rec, len, &ev, body,
		    sizeof(body), probe, sizeof(probe))) {
		case 1:
			if (oe_event(svc.exporter, &ev) != 0)
				warnx("cannot queue an audit record");
			n++;
			break;
		case 0:
			break;
		default:
			warnx("skipping a malformed audit record");
			break;
		}
		if (trail != NULL)
			free(rec);
	}
	if (trail != NULL)
		fclose(trail);
	else
		close(fd);
	free(pipebuf);
	auditrec_events_free(&events);
	oe_service_close(&svc);
	return (0);
}
