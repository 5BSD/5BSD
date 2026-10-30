/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * An OpenTelemetry export session for a DTrace consumer; see
 * dtotel_session.c.
 */

#ifndef _DTOTEL_SESSION_H_
#define	_DTOTEL_SESSION_H_

#include "dtotel.h"

enum dtotel_format {
	DTOTEL_OFF = 0,
	DTOTEL_OTLP,		/* OTLP/HTTP to a collector */
	DTOTEL_OTLPJSON,	/* OTLP JSON Lines */
	DTOTEL_JSON		/* JSON Lines */
};

struct dtotel_options {
	enum dtotel_format format;
	const char	*endpoint;	/* otlp: collector base URL */
	const char	*protocol;	/* otlp: grpc, http/protobuf, http/json */
	const char	*spool;		/* otlp: spool file */
	uint64_t	 spool_max;
	uint64_t	 rotate_size;	/* file formats with an output file */
	time_t		 rotate_interval;
	unsigned	 rotate_keep;
	int		 profiles;	/* -x otelprofiles (experimental) */
};

/*
 * Parse one "-x name=value" option.  Returns 1 when it was an
 * OpenTelemetry option (otel, otelendpoint, otelprotocol, otelspool,
 * otelspoolmax, otelrotatesize, otelrotatetime, otelrotatekeep,
 * otelprofiles), 0 when the name
 * does not start with "otel", and -1 with a message in err.
 */
int	 dtotel_option(struct dtotel_options *, const char *name,
	    const char *value, char *err, size_t errlen);
/* Check the options together; "output" is the -o file or NULL. */
int	 dtotel_options_check(const struct dtotel_options *,
	    const char *output, char *err, size_t errlen);

struct dtotel_session_config {
	const struct dtotel_options *options;
	dtrace_hdl_t	*dtp;
	const char	*output;	/* file formats: path or NULL (stdout) */
	const char	*service_name;	/* default service.name */
	const char	*service_version;
	const char	*scope_name;	/* instrumentation scope */
	const char	*profile;	/* script name for records */
	const char	*source;	/* D source for aggregation key names */
	int		 hypertrace;	/* one resource per guest */
};

struct dtotel_session;

struct dtotel_session *dtotel_session_open(const struct dtotel_session_config *,
	    char *err, size_t errlen);
struct dtotel	*dtotel_session_bridge(struct dtotel_session *);
/* Compile and enable the probe clock program on the handle. */
int	 dtotel_session_clock(struct dtotel_session *, dtrace_hdl_t *,
	    char *err, size_t errlen);
/*
 * Called from the consumer loop: once a second, file output writes
 * out partial OTLP JSON batches and syncs (OTLP/HTTP batches on its
 * own sender thread).
 */
int	 dtotel_session_tick(struct dtotel_session *);
/* Hand everything accepted so far to the exporter (a drain point). */
int	 dtotel_session_flush(struct dtotel_session *);
/*
 * Shut down: with "finish", emit the pending record and the final
 * aggregation snapshot first.  -1 if anything failed to export.
 */
int	 dtotel_session_close(struct dtotel_session *, int finish);

#endif /* !_DTOTEL_SESSION_H_ */
