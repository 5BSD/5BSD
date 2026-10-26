/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * mkpfstatus - write deterministic struct pf_status records (the
 * DIOCGETSTATUS payload) for otelpfd -f replay tests.
 *
 * Record i (from 0) has states = 100 + i, every counter c[k] = 1000 * i
 * + k + 1, running = 1, and the remaining gauges small fixed values.
 * "-t" writes a final truncated record.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pfstat.h"

int
main(int argc, char **argv)
{
	struct pf_status st;
	FILE *f;
	uint64_t *c;
	size_t k, ncounters;
	int i, n, truncate;

	truncate = argc > 1 && strcmp(argv[1], "-t") == 0;
	if (truncate) {
		argc--;
		argv++;
	}
	if (argc != 3)
		errx(2, "usage: mkpfstatus [-t] file count");
	n = atoi(argv[2]);
	f = fopen(argv[1], "w");
	if (f == NULL)
		err(1, "%s", argv[1]);
	for (i = 0; i < n; i++) {
		memset(&st, 0, sizeof(st));
		/* The counter arrays are consecutive uint64_t members. */
		c = &st.counters[0];
		ncounters = (size_t)((uint64_t *)&st.stateid - c);
		for (k = 0; k < ncounters; k++)
			c[k] = 1000ULL * (uint64_t)i + k + 1;
		st.running = 1;
		st.states = 100 + (uint32_t)i;
		st.states_halfopen = 3;
		st.src_nodes = 4;
		st.fragments = 5;
		st.syncookies_active = 0;
		strlcpy(st.ifname, "lo0", sizeof(st.ifname));
		if (fwrite(&st, sizeof(st), 1, f) != 1)
			err(1, "write");
	}
	if (truncate && fwrite(&st, sizeof(st) / 2, 1, f) != 1)
		err(1, "write");
	if (fclose(f) != 0)
		err(1, "%s", argv[1]);
	return (0);
}
