/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Internal OTLP protobuf-JSON encoder shared by the OTLP/HTTP
 * exporter (oe_otlp.c) and the OTLP JSON Lines file exporter
 * (oe_otlpfile.c), so both emit byte-identical requests.
 */

#ifndef _OE_OTLPENC_H_
#define	_OE_OTLPENC_H_

enum oe_signal {
	OE_SIGNAL_LOGS,
	OE_SIGNAL_METRICS,
	OE_SIGNAL_TRACES
};

struct oe_otlpenc {
	char		*scope;		/* instrumentation scope name */
	char		*version;
	char		*resource_json;	/* prebuilt attribute list */
};

int	 oe_enc_init(struct oe_otlpenc *, const struct oe_resource *);
void	 oe_enc_fini(struct oe_otlpenc *);

/* One record fragment; malloc'd, NULL on allocation failure. */
char	*oe_enc_log_record(const struct oe_otlpenc *, const struct oe_event *);
char	*oe_enc_metric(const struct oe_otlpenc *, const struct oe_snapshot *);

/*
 * Wrap fragments in one Export*ServiceRequest.  "drops" (logs only)
 * is spliced into the first record as "<scope>.drops".  The result
 * is malloc'd and NUL-terminated; *lenp excludes the NUL.
 */
char	*oe_enc_request(const struct oe_otlpenc *, enum oe_signal,
	    char **frags, size_t nfrags, uint64_t drops, size_t *lenp);

/* URL path ("v1/logs", ...) for a signal. */
const char *oe_enc_path(enum oe_signal);

/*
 * Classify one OTLP JSON request by its top-level key; -1 when the
 * line is not a request this library writes.
 */
int	 oe_enc_classify(const char *line);

/* Growable fragment array helpers. */
int	 oe_frags_append(char ***, size_t *, size_t *, char *);
void	 oe_frags_free(char **, size_t);

#endif /* !_OE_OTLPENC_H_ */
