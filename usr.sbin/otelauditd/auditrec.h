/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Conversion of BSM audit records into OpenTelemetry log records.
 */

#ifndef _AUDITREC_H_
#define	_AUDITREC_H_

#include <sys/types.h>

#include <bsm/libbsm.h>

#include <stddef.h>

#include "otelexport.h"

#define	AUDITREC_PROFILE	"audit"
#define	AUDITREC_BODY_MAX	4096

/* Event number -> name/description, loaded once from audit_event(5). */
struct auditrec_event {
	au_event_t	 number;
	char		*name;
	char		*desc;
};

struct auditrec_events {
	struct auditrec_event	*ev;
	size_t			 n;
};

/* Load the event table through getauevent(3).  Returns 0 or -1. */
int	auditrec_events_load(struct auditrec_events *);
void	auditrec_events_free(struct auditrec_events *);
const struct auditrec_event *auditrec_event_find(
	    const struct auditrec_events *, au_event_t);

/*
 * Convert one BSM record.  Fills ev (strings point into body, probe and
 * the event table) and returns 1; returns 0 for records that are not
 * audit events (trail file tokens), -1 for malformed records.
 */
int	auditrec_convert(const struct auditrec_events *, u_char *rec,
	    int len, struct oe_event *ev, char *body, size_t bodylen,
	    char *probe, size_t probelen);

#endif /* !_AUDITREC_H_ */
