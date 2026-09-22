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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <powercmp.h>

static void
usage(void)
{

	fprintf(stderr,
	    "usage: BSDPowerctl states\n"
	    "       BSDPowerctl suspend <1-5>\n");
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
