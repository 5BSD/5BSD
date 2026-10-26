/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Independent OTLP protobuf-JSON validator used as the test oracle
 * for libotelexport and bsdinstruments.  It shares no code with the
 * library: its own strict RFC 8259 parser, and schema rules written
 * from the OTLP .proto definitions and the proto3 JSON mapping
 * (lowerCamelCase names, 64-bit integers as decimal strings, ids as
 * lowercase hex, unknown fields rejected).
 */

#ifndef _OTLP_VALIDATE_H_
#define	_OTLP_VALIDATE_H_

#include <stddef.h>

enum jv_type { JV_NULL, JV_BOOL, JV_NUM, JV_STR, JV_ARR, JV_OBJ };

struct jv {
	enum jv_type	 type;
	int		 b;
	char		*s;		/* string, or number text */
	size_t		 slen;		/* string length (may embed NUL) */
	struct jv	**items;	/* array items / object values */
	char		**keys;		/* object keys */
	size_t		 n;
};

/* Parse one JSON text; NULL with a message in err on failure. */
struct jv *jv_parse(const char *text, size_t len, char *err, size_t errlen);
void	 jv_free(struct jv *);
const struct jv *jv_get(const struct jv *obj, const char *key);

/* Counts of what a validated request held. */
struct otlp_counts {
	size_t		 requests;
	size_t		 logs, metrics, datapoints, spans;
};

/*
 * Validate one Export{Logs,Metrics,Trace}ServiceRequest.  Returns 0,
 * or -1 with the first violation (and its JSON path) in err.
 */
int	 otlp_validate_request(const struct jv *, struct otlp_counts *,
	    char *err, size_t errlen);

/*
 * Structural comparison of an actual document against a golden one.
 * A golden string "<any>" matches any string, number or boolean;
 * "<int>" any decimal-string integer; "<hex32>" / "<hex16>" any
 * non-zero lowercase hex id of that length.  Object key order is
 * irrelevant; array order is significant.
 */
int	 jv_match(const struct jv *golden, const struct jv *actual,
	    char *err, size_t errlen);

#endif /* !_OTLP_VALIDATE_H_ */
