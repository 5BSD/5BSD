/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libotelexport — shared exporter layer for the ObservableBSD tools
 * (bsdinstruments, hwtlm).  An exporter consumes probe events and
 * aggregation snapshots from a tool's run loop and ships them to a
 * destination: stdout (text, JSONL, collapsed stacks) or an
 * OTLP/HTTP+JSON collector.
 *
 * C port of the ObservableBSD Swift OTelExport library.
 */

#ifndef _OTELEXPORT_H_
#define	_OTELEXPORT_H_

#include <sys/types.h>

#include <stdint.h>
#include <stdio.h>
#include <time.h>

/*
 * One frame from a stack trace.  "module" and "symbol" may be NULL;
 * has_offset says whether "offset" is meaningful.
 */
struct oe_frame {
	uint64_t	 addr;
	char		*module;	/* malloc'd or NULL */
	char		*symbol;	/* malloc'd or NULL */
	uint64_t	 offset;
	int		 has_offset;
};

/*
 * One probe firing or event, normalized before it reaches any
 * exporter.  Strings are borrowed for the duration of the emit call;
 * exporters must copy anything they keep.
 */
struct oe_event {
	struct timespec	 ts;		/* wall clock (CLOCK_REALTIME) */
	const char	*profile;	/* profile / tool name */
	const char	*probe;		/* probe name or "" */
	pid_t		 pid;		/* 0 for system-level events */
	const char	*execname;	/* "" if unknown */
	const char	*body;		/* rendered text body, NULL/"" if none */
	const struct oe_frame *stack;	/* kernel stack or NULL */
	size_t		 nstack;
	const struct oe_frame *ustack;	/* user stack or NULL */
	size_t		 nustack;
};

/* Which aggregating function a snapshot came from. */
enum oe_agg_kind {
	OE_AGG_COUNT,
	OE_AGG_SUM,
	OE_AGG_MIN,
	OE_AGG_MAX,
	OE_AGG_AVG,
	OE_AGG_STDDEV,
	OE_AGG_QUANTIZE,
	OE_AGG_LQUANTIZE,
	OE_AGG_LLQUANTIZE
};

struct oe_bucket {
	int64_t		 upper;		/* inclusive upper bound */
	int64_t		 count;
};

struct oe_attr {
	const char	*name;
	const char	*value;
};

/*
 * One data point of one aggregation snapshot.  Either a scalar or a
 * histogram (buckets != NULL).  "attrs" carries the tuple key
 * dimensions as named key-value pairs.
 */
struct oe_datapoint {
	const struct oe_attr *attrs;
	size_t		 nattrs;
	int		 is_histogram;
	int64_t		 scalar;
	const struct oe_bucket *buckets;
	size_t		 nbuckets;
};

struct oe_snapshot {
	struct timespec	 ts;
	const char	*profile;
	const char	*name;		/* aggregation name, "" if anonymous */
	enum oe_agg_kind kind;
	const struct oe_datapoint *points;
	size_t		 npoints;
};

/* OTel resource attributes attached to every record. */
struct oe_resource {
	const char	*service_name;
	const char	*service_instance_id;	/* NULL to omit */
	const char	*host_name;
	const char	*host_arch;
	const char	*os_name;
	const char	*os_version;
	const char	*service_version;
	const struct oe_attr *custom;
	size_t		 ncustom;
};

/*
 * Exporter object.  Concrete exporters embed this as their first
 * member.  All methods return 0 on success, -1 on failure with an
 * error message on stderr.  oe_exporter_free() releases the object
 * (call after shutdown).
 */
struct oe_exporter;

struct oe_exporter_ops {
	int	(*start)(struct oe_exporter *);
	int	(*event)(struct oe_exporter *, const struct oe_event *);
	int	(*snapshot)(struct oe_exporter *, const struct oe_snapshot *);
	int	(*flush)(struct oe_exporter *);
	int	(*shutdown)(struct oe_exporter *);
	void	(*free)(struct oe_exporter *);
};

struct oe_exporter {
	const struct oe_exporter_ops *ops;
};

#define	oe_start(e)		((e)->ops->start(e))
#define	oe_event(e, ev)		((e)->ops->event((e), (ev)))
#define	oe_snapshot(e, sn)	((e)->ops->snapshot((e), (sn)))
#define	oe_flush(e)		((e)->ops->flush(e))
#define	oe_shutdown(e)		((e)->ops->shutdown(e))
#define	oe_exporter_free(e)	((e)->ops->free(e))

/*
 * Constructors.  Output FILE pointers are borrowed, not closed.
 */
struct oe_exporter *oe_text_new(FILE *out);
struct oe_exporter *oe_jsonl_new(FILE *out, const char *profile);
struct oe_exporter *oe_collapsed_new(FILE *out);

/* Configuration for the OTLP/HTTP+JSON exporter. */
struct oe_otlp_config {
	const char	*endpoint;	/* base URL, e.g. http://host:4318 */
	const char	*profile;	/* profile name for scope */
	const struct oe_resource *resource;
	int		 batch_size;	/* 0 = default (200) */
	double		 flush_interval; /* seconds; 0 = default (0.5) */
	int		 max_retries;	/* <0 = default (2) */
	double		 timeout;	/* seconds; 0 = default (10) */
	const struct oe_attr *headers;	/* extra HTTP headers */
	size_t		 nheaders;
	const char	*compression;	/* "none" disables gzip; else gzip */
};

struct oe_exporter *oe_otlp_new(const struct oe_otlp_config *);

/*
 * Report kernel-side record drops so the next OTLP batch carries a
 * "<scope>.drops" attribute.  No-op for non-OTLP exporters.
 */
void	oe_report_drops(struct oe_exporter *, uint64_t);

/*
 * OTel-standard environment variables (OTEL_SERVICE_NAME,
 * OTEL_RESOURCE_ATTRIBUTES, OTEL_EXPORTER_OTLP_ENDPOINT,
 * OTEL_EXPORTER_OTLP_HEADERS, OTEL_EXPORTER_OTLP_COMPRESSION,
 * OTEL_EXPORTER_OTLP_TIMEOUT).
 */
struct oe_env {
	const char	*service_name;	/* NULL if unset */
	const char	*endpoint;
	const char	*compression;
	int		 timeout_ms;	/* -1 if unset */
	struct oe_attr	*resource_attrs; /* malloc'd array */
	size_t		 nresource_attrs;
	struct oe_attr	*headers;
	size_t		 nheaders;
};

void	oe_env_load(struct oe_env *);
void	oe_env_free(struct oe_env *);

/*
 * Fill in host.name / host.arch / os.version from the running
 * system.  Buffers are caller-provided.
 */
void	oe_host_name(char *buf, size_t len);
void	oe_host_arch(char *buf, size_t len);
void	oe_os_version(char *buf, size_t len);

/*
 * Growable string buffer used by exporters to build output.
 */
struct oe_buf {
	char		*data;
	size_t		 len;
	size_t		 cap;
	int		 error;
};

void	oe_buf_init(struct oe_buf *);
void	oe_buf_free(struct oe_buf *);
int	oe_buf_append(struct oe_buf *, const char *, size_t);
int	oe_buf_appendstr(struct oe_buf *, const char *);
int	oe_buf_appendf(struct oe_buf *, const char *, ...) __printflike(2, 3);
/* Append s with RFC 8259 JSON string escaping (no surrounding quotes). */
int	oe_buf_appendjson(struct oe_buf *, const char *);

/* Format a frame as module`symbol+0xoff / symbol / 0xaddr. */
void	oe_frame_format(const struct oe_frame *, char *buf, size_t len);

/* ISO 8601 with milliseconds and local UTC offset. */
void	oe_iso8601(const struct timespec *, char *buf, size_t len);

#endif /* !_OTELEXPORT_H_ */
