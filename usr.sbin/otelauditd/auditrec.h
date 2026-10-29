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
#define	AUDITREC_SCOPE		"otelauditd"
#define	AUDITREC_BODY_MAX	4096
#define	AUDITREC_MAXKV		4

/* Event number -> name/description, loaded once from audit_event(5). */
struct auditrec_event {
	au_event_t	 number;
	au_class_t	 class;
	char		*name;
	char		*desc;
};

struct auditrec_events {
	struct auditrec_event	*ev;
	size_t			 n;
	/*
	 * Classes whose failures are errors rather than warnings: login
	 * and logout (lo) and authentication and authorization (aa), as
	 * audit_class(5) names them.
	 */
	au_class_t		 error_classes;
};

/* Storage for the log record attributes of one converted record. */
struct auditrec_attrs {
	struct oe_kv	 kv[AUDITREC_MAXKV];
	char		 auid[16];
	char		 path[1024];
};

/* Load the event table through getauevent(3).  Returns 0 or -1. */
int	auditrec_events_load(struct auditrec_events *);
void	auditrec_events_free(struct auditrec_events *);
const struct auditrec_event *auditrec_event_find(
	    const struct auditrec_events *, au_event_t);

/*
 * The byte length of the BSM record at the start of buf (from its header
 * token), or -1 when buf does not start with a complete record.  One
 * auditpipe(4) read returns as many whole records as fit.
 */
int	auditrec_record_len(u_char *buf, int len);

/*
 * Convert one BSM record.  Fills ev (strings point into body, probe, at
 * and the event table) and returns 1; returns 0 for records that are not
 * audit events (trail file tokens), -1 for malformed records.
 *
 * The severity is INFO for a success or a record without a return token,
 * WARN for a failure, and ERROR for a failure of an event in one of the
 * error classes.  The subject becomes process.pid, process.user.id
 * (euid), process.real_user.id, process.group.id (egid) and
 * process.real_group.id, the audit user user.id; the outcome is
 * otelauditd.result (success, failure) and otelauditd.return (the
 * return value, or the error number of a failure); the first path token
 * is file.path.
 */
int	auditrec_convert(const struct auditrec_events *, u_char *rec,
	    int len, struct oe_event *ev, char *body, size_t bodylen,
	    char *probe, size_t probelen, struct auditrec_attrs *at);

#endif /* !_AUDITREC_H_ */
