/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libdtotel internals shared by dtotel.c and dtotel_agg.c.
 */

#ifndef _DTOTEL_IMPL_H_
#define	_DTOTEL_IMPL_H_

#include <time.h>

#include "dtotel.h"

#define	DTOTEL_MAX_AGG_KEYS	16

/* Aggregation key names parsed from the D source. */
struct dtotel_keynames {
	char		*aggname;
	char		*names[DTOTEL_MAX_AGG_KEYS];
	int		 n;
	struct dtotel_keynames *next;
};

struct dtotel_frames {
	struct oe_frame	*frames;
	size_t		 n, cap;
};

/* Identity of one probe firing: its records share all three. */
struct dtotel_firing {
	int		 valid;
	processorid_t	 cpu;
	uint64_t	 hrtime;
	dtrace_epid_t	 epid;
};

struct dtotel {
	dtrace_hdl_t	*dtp;
	struct oe_exporter *exporter;
	char		*profile;
	struct dtotel_keynames *keynames;
	struct timespec	 start;		/* accumulation window start */
	int		 error;

	/* Probe clock: wall = hrtime + offset once anchored. */
	int		 anchored;
	int64_t		 clock_offset;

	/* Secret salt for span and trace ids derived from D keys. */
	uint8_t		 salt[16];
	int		 warned_span;

	/* The event being accumulated. */
	char		*body;
	char		*probe;
	struct timespec	 body_ts;
	struct timespec	 body_observed;
	struct dtotel_firing body_firing;
	struct dtotel_frames kstack;
	struct dtotel_frames ustack;
	int		 in_ustack;
};

struct dtotel_keynames *dtotel_parse_keynames(const char *);
void	 dtotel_free_keynames(struct dtotel_keynames *);

#endif /* !_DTOTEL_IMPL_H_ */
