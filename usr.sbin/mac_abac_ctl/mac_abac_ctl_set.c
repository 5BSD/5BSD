/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * mac_abac_ctl - Set command handlers
 *
 * Handles: set enable|disable|swap|move|clear|list
 *
 * IPFW-style rule sets for grouping and bulk enable/disable.
 */

#include <sys/types.h>
#include <sys/mac.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <security/mac_abac/mac_abac.h>
#include "mac_abac_ctl.h"

/*
 * Parse set range specification.
 * Accepts: "N", "N-M", "all"
 * Returns 0 on success, -1 on error.
 */
static int
parse_set_range(const char *s, uint16_t *start, uint16_t *end)
{
	char *dash, *endptr;
	unsigned long val;

	if (strcmp(s, "all") == 0) {
		*start = 0;
		*end = ABAC_MAX_SETS - 1;
		return (0);
	}

	dash = strchr(s, '-');
	if (dash != NULL) {
		/* Range: N-M */
		*dash = '\0';  /* Temporarily split */

		errno = 0;
		val = strtoul(s, &endptr, 10);
		if (errno != 0 || *endptr != '\0' || s[0] == '\0' ||
		    val >= ABAC_MAX_SETS) {
			*dash = '-';  /* Restore */
			return (-1);
		}
		*start = (uint16_t)val;

		errno = 0;
		val = strtoul(dash + 1, &endptr, 10);
		if (errno != 0 || *endptr != '\0' || dash[1] == '\0' ||
		    val >= ABAC_MAX_SETS) {
			*dash = '-';  /* Restore */
			return (-1);
		}
		*end = (uint16_t)val;

		*dash = '-';  /* Restore */

		if (*start > *end)
			return (-1);
	} else {
		/* Single set: N */
		errno = 0;
		val = strtoul(s, &endptr, 10);
		if (errno != 0 || *endptr != '\0' || s[0] == '\0' ||
		    val >= ABAC_MAX_SETS)
			return (-1);

		*start = *end = (uint16_t)val;
	}

	return (0);
}

/*
 * Parse a single set number.
 * Returns 0 on success, -1 on error.
 */
static int
parse_set_num(const char *s, uint16_t *set)
{
	char *endptr;
	unsigned long val;

	errno = 0;
	val = strtoul(s, &endptr, 10);
	if (errno != 0 || *endptr != '\0' || s[0] == '\0' ||
	    val >= ABAC_MAX_SETS)
		return (-1);

	*set = (uint16_t)val;
	return (0);
}

static void
set_usage(void)
{
	fprintf(stderr,
	    "usage: mac_abac_ctl set <command> [arguments]\n"
	    "\n"
	    "Commands:\n"
	    "  enable <N> | <start>-<end> | all\n"
	    "      Enable rule set(s). Rules in disabled sets are not evaluated.\n"
	    "\n"
	    "  disable <N> | <start>-<end> | all\n"
	    "      Disable rule set(s).\n"
	    "\n"
	    "  swap <A> <B>\n"
	    "      Atomically swap two sets. Useful for hot-reloading policies.\n"
	    "\n"
	    "  move <from> <to>\n"
	    "      Move all rules from one set to another.\n"
	    "\n"
	    "  clear <N>\n"
	    "      Remove all rules in the specified set.\n"
	    "\n"
	    "  list [<start>-<end>]\n"
	    "      Show set status and rule counts. Default: 0-31.\n"
	    "\n"
	    "Examples:\n"
	    "  mac_abac_ctl set disable 1\n"
	    "  mac_abac_ctl set enable 1-10\n"
	    "  mac_abac_ctl set swap 0 1000\n"
	    "  mac_abac_ctl set list 0-100\n"
	);
	exit(EX_USAGE);
}

/*
 * set enable|disable|swap|move|clear|list
 */
int
cmd_set(int argc, char *argv[])
{
	struct abac_set_range range;
	uint16_t sets[2];

	if (argc < 1)
		set_usage();

	if (strcmp(argv[0], "enable") == 0) {
		if (argc < 2)
			errx(EX_USAGE, "set enable requires a set number or range");

		if (parse_set_range(argv[1], &range.vsr_start, &range.vsr_end) < 0)
			errx(EX_USAGE, "invalid set range: %s", argv[1]);

		if (abac_syscall(ABAC_SYS_SET_ENABLE, &range) < 0)
			err(EX_OSERR, "SET_ENABLE");

		if (range.vsr_start == range.vsr_end)
			printf("set %u enabled\n", range.vsr_start);
		else
			printf("sets %u-%u enabled\n", range.vsr_start, range.vsr_end);

	} else if (strcmp(argv[0], "disable") == 0) {
		if (argc < 2)
			errx(EX_USAGE, "set disable requires a set number or range");

		if (parse_set_range(argv[1], &range.vsr_start, &range.vsr_end) < 0)
			errx(EX_USAGE, "invalid set range: %s", argv[1]);

		if (abac_syscall(ABAC_SYS_SET_DISABLE, &range) < 0)
			err(EX_OSERR, "SET_DISABLE");

		if (range.vsr_start == range.vsr_end)
			printf("set %u disabled\n", range.vsr_start);
		else
			printf("sets %u-%u disabled\n", range.vsr_start, range.vsr_end);

	} else if (strcmp(argv[0], "swap") == 0) {
		if (argc < 3)
			errx(EX_USAGE, "set swap requires two set numbers");

		if (parse_set_num(argv[1], &sets[0]) < 0)
			errx(EX_USAGE, "invalid set number: %s", argv[1]);
		if (parse_set_num(argv[2], &sets[1]) < 0)
			errx(EX_USAGE, "invalid set number: %s", argv[2]);

		if (abac_syscall(ABAC_SYS_SET_SWAP, sets) < 0)
			err(EX_OSERR, "SET_SWAP");

		printf("swapped sets %u and %u\n", sets[0], sets[1]);

	} else if (strcmp(argv[0], "move") == 0) {
		if (argc < 3)
			errx(EX_USAGE, "set move requires two set numbers");

		if (parse_set_num(argv[1], &sets[0]) < 0)
			errx(EX_USAGE, "invalid set number: %s", argv[1]);
		if (parse_set_num(argv[2], &sets[1]) < 0)
			errx(EX_USAGE, "invalid set number: %s", argv[2]);

		if (abac_syscall(ABAC_SYS_SET_MOVE, sets) < 0)
			err(EX_OSERR, "SET_MOVE");

		printf("moved rules from set %u to set %u\n", sets[0], sets[1]);

	} else if (strcmp(argv[0], "clear") == 0) {
		uint16_t set;

		if (argc < 2)
			errx(EX_USAGE, "set clear requires a set number");

		if (parse_set_num(argv[1], &set) < 0)
			errx(EX_USAGE, "invalid set number: %s", argv[1]);

		if (abac_syscall(ABAC_SYS_SET_CLEAR, &set) < 0)
			err(EX_OSERR, "SET_CLEAR");

		printf("cleared set %u\n", set);

	} else if (strcmp(argv[0], "list") == 0) {
		struct abac_set_list_arg list_arg;
		uint16_t start, end, count;
		uint16_t i;
		int any_output = 0;

		/* Default: show sets 0-31 */
		start = 0;
		end = 31;

		if (argc >= 2) {
			if (parse_set_range(argv[1], &start, &end) < 0)
				errx(EX_USAGE, "invalid set range: %s", argv[1]);
		}

		/* Query in chunks of 256 (max per syscall) */
		printf("Set     Enabled  Rules\n");
		printf("-----   -------  -----\n");

		while (start <= end) {
			count = (end - start + 1);
			if (count > 256)
				count = 256;

			memset(&list_arg, 0, sizeof(list_arg));
			list_arg.vsl_start = start;
			list_arg.vsl_count = count;

			if (abac_syscall(ABAC_SYS_SET_LIST, &list_arg) < 0)
				err(EX_OSERR, "SET_LIST");

			for (i = 0; i < count; i++) {
				int enabled;
				uint32_t rules;
				uint16_t set_num = start + i;

				/* Check enabled bit */
				enabled = (list_arg.vsl_enabled[i / 8] >> (i % 8)) & 1;
				rules = list_arg.vsl_rule_counts[i];

				/* Only show sets with rules or explicitly disabled */
				if (rules > 0 || !enabled) {
					printf("%-5u   %-7s  %u\n",
					    set_num,
					    enabled ? "yes" : "no",
					    rules);
					any_output = 1;
				}
			}

			if (start + count > end || start + count < start)
				break;
			start += count;
		}

		if (!any_output)
			printf("(no sets with rules in range)\n");

	} else {
		errx(EX_USAGE, "unknown set command: %s", argv[0]);
	}

	return (0);
}
