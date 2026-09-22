/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * BSDTimectl -- operator CLI for the system.Time capability (BSDTime).
 *
 *   BSDTimectl get                 print CLOCK_REALTIME (seconds.nanoseconds)
 *   BSDTimectl set <epoch[.nsec]>  step the clock (needs set authority)
 *   BSDTimectl adjust <sec[.usec]> slew the clock by a signed delta
 */
#include <sys/time.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <timecmp.h>

static void
usage(void)
{

	fprintf(stderr,
	    "usage: BSDTimectl get\n"
	    "       BSDTimectl set <epoch[.nsec]>\n"
	    "       BSDTimectl adjust <[-]sec[.usec]>\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	struct timecmp_client *client;
	int rc;

	if (argc < 2)
		usage();
	if (timecmp_client_open(&client) == -1)
		err(1, "open system.Time");
	rc = 1;
	if (strcmp(argv[1], "get") == 0) {
		struct timespec ts;

		if (timecmp_get(client, &ts) == -1)
			err(1, "get");
		printf("%jd.%09ld\n", (intmax_t)ts.tv_sec, (long)ts.tv_nsec);
		rc = 0;
	} else if (strcmp(argv[1], "set") == 0 && argc == 3) {
		struct timespec ts = { 0, 0 };
		char *dot;

		errno = 0;
		ts.tv_sec = (time_t)strtoll(argv[2], &dot, 10);
		if (errno != 0 || dot == argv[2] ||
		    (*dot != '\0' && *dot != '.'))
			errx(1, "set: invalid time \"%s\"", argv[2]);
		if (*dot == '.') {
			char *nend;

			errno = 0;
			ts.tv_nsec = (long)strtol(dot + 1, &nend, 10);
			if (errno != 0 || nend == dot + 1 || *nend != '\0' ||
			    ts.tv_nsec < 0 || ts.tv_nsec > 999999999)
				errx(1, "set: invalid nanoseconds in \"%s\"",
				    argv[2]);
		}
		if (timecmp_set(client, &ts) == -1)
			err(1, "set");
		rc = 0;
	} else if (strcmp(argv[1], "adjust") == 0 && argc == 3) {
		struct timeval delta = { 0, 0 }, old;
		char *dot;
		int neg;

		neg = argv[2][0] == '-';
		errno = 0;
		delta.tv_sec = (time_t)strtoll(argv[2], &dot, 10);
		if (errno != 0 || dot == argv[2] ||
		    (*dot != '\0' && *dot != '.'))
			errx(1, "adjust: invalid delta \"%s\"", argv[2]);
		if (*dot == '.') {
			char *uend;
			long usec;

			errno = 0;
			usec = strtol(dot + 1, &uend, 10);
			if (errno != 0 || uend == dot + 1 || *uend != '\0' ||
			    usec < 0 || usec > 999999)
				errx(1, "adjust: invalid microseconds in \"%s\"",
				    argv[2]);
			delta.tv_usec = (suseconds_t)(neg ? -usec : usec);
		}
		if (timecmp_adjust(client, &delta, &old) == -1)
			err(1, "adjust");
		printf("previous correction: %jd.%06ld\n",
		    (intmax_t)old.tv_sec, (long)old.tv_usec);
		rc = 0;
	} else
		usage();
	timecmp_client_close(client);
	return (rc);
}
