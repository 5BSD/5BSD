/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * BSDPowerctl -- operator CLI for the system.Power capability (BSDPower).
 *
 *   BSDPowerctl states          print the supported ACPI sleep states
 *   BSDPowerctl suspend <N>     enter sleep state SN (needs suspend authority)
 */
#include <err.h>
#include <errno.h>
#include <powercmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t stop;
static void
stopped(int sig)
{
	(void)sig;
	stop = 1;
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: BSDPowerctl states\n"
	    "       BSDPowerctl suspend <1-5>\n"
	    "       BSDPowerctl inhibitors\n"
	    "       BSDPowerctl inhibit <seconds>\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	struct powercmp_client *client;
	int rc;

	if (argc < 2)
		usage();
	if (powercmp_client_open(&client) == -1)
		err(1, "open system.Power");
	rc = 1;
	if (strcmp(argv[1], "states") == 0) {
		uint32_t supported;
		unsigned s;
		int first = 1;

		if (powercmp_states(client, &supported) == -1)
			err(1, "states");
		for (s = 1; s <= 5; s++)
			if (supported & ((uint32_t)1 << s)) {
				printf("%sS%u", first ? "" : " ", s);
				first = 0;
			}
		printf("%s\n", first ? "(none)" : "");
		rc = 0;
	} else if (strcmp(argv[1], "inhibitors") == 0 && argc == 2) {
		uint32_t count;
		if (powercmp_inhibitors(client, &count) == -1)
			err(1, "inhibitors");
		printf("%u\n", count);
		rc = 0;
	} else if (strcmp(argv[1], "inhibit") == 0 && argc == 3) {
		char *end;
		errno = 0;
		unsigned long seconds = strtoul(argv[2], &end, 10);
		if (errno != 0 || *end != '\0' || end == argv[2] ||
		    seconds == 0 || seconds > 86400)
			errx(1, "inhibit: duration must be 1-86400 seconds");
		signal(SIGINT, stopped);
		signal(SIGTERM, stopped);
		if (powercmp_inhibit(client) == -1)
			err(1, "inhibit");
		while (seconds-- != 0 && !stop) {
			sleep(1);
			uint32_t count;
			/* An existing session must still be alive; never reopen
			 * a lost lease. */
			if (powercmp_inhibitors(client, &count) == -1)
				err(1, "lease lost");
		}
		if (powercmp_uninhibit(client) == -1)
			err(1, "uninhibit");
		rc = 0;
	} else if (strcmp(argv[1], "suspend") == 0 && argc == 3) {
		char *end;
		unsigned long v;
		uint32_t state;

		errno = 0;
		v = strtoul(argv[2], &end, 10);
		if (errno != 0 || end == argv[2] || *end != '\0' ||
		    v < 1 || v > 5)
			errx(1, "suspend: sleep state must be 1-5, not \"%s\"",
			    argv[2]);
		state = (uint32_t)v;
		if (powercmp_suspend(client, state) == -1)
			err(1, "suspend");
		rc = 0;
	} else
		usage();
	powercmp_client_close(client);
	return (rc);
}
