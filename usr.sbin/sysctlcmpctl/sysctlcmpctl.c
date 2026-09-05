/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * sysctlcmpctl: command-line client for the system.Sysctl capability.
 *   sysctlcmpctl get <name>
 *   sysctlcmpctl set <name> <string-value>
 */

#include <sys/types.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <sysctlcmp.h>

static void
usage(void)
{

	fprintf(stderr, "usage: sysctlcmpctl get <name>\n"
	    "       sysctlcmpctl set <name> <value>\n"
	    "       sysctlcmpctl fmt <name>\n"
	    "       sysctlcmpctl descr <name>\n"
	    "       sysctlcmpctl list [start-name]\n");
	exit(EX_USAGE);
}

/* Print a sysctl value: as text if printable, else as decimal for 4/8 bytes,
 * otherwise as hex. */
static void
print_value(const unsigned char *buf, size_t len)
{
	bool printable;
	size_t i;

	if (len == 0) {
		printf("\n");
		return;
	}
	printable = true;
	for (i = 0; i + 1 < len; i++) {
		if (!isprint(buf[i]) && buf[i] != '\t') {
			printable = false;
			break;
		}
	}
	if (printable && buf[len - 1] == '\0') {
		printf("%s\n", buf);
		return;
	}
	if (len == sizeof(uint32_t)) {
		uint32_t v;
		memcpy(&v, buf, sizeof(v));
		printf("%u\n", v);
		return;
	}
	if (len == sizeof(uint64_t)) {
		uint64_t v;
		memcpy(&v, buf, sizeof(v));
		printf("%ju\n", (uintmax_t)v);
		return;
	}
	for (i = 0; i < len; i++)
		printf("%02x", buf[i]);
	printf("\n");
}

int
main(int argc, char **argv)
{
	struct sysctlcmp_client *client;
	unsigned char buf[8192];
	size_t len;

	if (argc < 2)
		usage();
	if (sysctlcmp_client_open(&client) == -1)
		err(EX_UNAVAILABLE, "open system.Sysctl");

	if (strcmp(argv[1], "get") == 0 && argc >= 3) {
		len = sizeof(buf);
		if (sysctlcmp_get(client, argv[2], buf, &len) == -1)
			err(EX_UNAVAILABLE, "get %s", argv[2]);
		print_value(buf, len);
	} else if (strcmp(argv[1], "set") == 0 && argc >= 4) {
		if (sysctlcmp_set(client, argv[2], argv[3],
		    strlen(argv[3]) + 1) == -1)
			err(EX_UNAVAILABLE, "set %s", argv[2]);
	} else if (strcmp(argv[1], "fmt") == 0 && argc >= 3) {
		unsigned int kind;
		char fmt[64];

		len = sizeof(fmt);
		if (sysctlcmp_oidfmt(client, argv[2], &kind, fmt, &len) == -1)
			err(EX_UNAVAILABLE, "fmt %s", argv[2]);
		printf("kind=0x%x fmt=%s\n", kind, fmt);
	} else if (strcmp(argv[1], "descr") == 0 && argc >= 3) {
		len = sizeof(buf);
		if (sysctlcmp_describe(client, argv[2], (char *)buf, &len) == -1)
			err(EX_UNAVAILABLE, "descr %s", argv[2]);
		printf("%s\n", buf);
	} else if (strcmp(argv[1], "list") == 0) {
		char name[256];

		name[0] = '\0';			/* start from the root */
		for (;;) {
			len = sizeof(name);
			if (sysctlcmp_next(client, name, name, &len) == -1) {
				if (errno == ENOENT)
					break;
				err(EX_UNAVAILABLE, "list");
			}
			printf("%s\n", name);
		}
	} else {
		usage();
	}
	sysctlcmp_client_close(client);
	return (0);
}
