/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libotelexport — shared exporter layer for the ObservableBSD tools
 * (bsdinstruments, hwstat).  An exporter consumes probe events and
 * aggregation snapshots from a tool's run loop and ships them to a
 * destination: a stream or rotating file (text, JSONL, collapsed
 * stacks, OTLP JSON Lines) or an OTLP/HTTP+JSON collector.
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
 * Who produced a record, exported with OpenTelemetry semantic
 * convention names (process.*, thread.id, cpu.logical_number, and the
 * jail as container.*).  "flags" says which members are known; pid
 * and executable name live in the event/span itself.
 */
#define	OE_CTX_PPID	0x0001	/* process.parent_pid */
#define	OE_CTX_TID	0x0002	/* thread.id */
#define	OE_CTX_UID	0x0004	/* process.user.id (effective) */
#define	OE_CTX_RUID	0x0008	/* process.real_user.id */
#define	OE_CTX_GID	0x0010	/* process.group.id (effective) */
#define	OE_CTX_RGID	0x0020	/* process.real_group.id */
#define	OE_CTX_CPU	0x0040	/* cpu.logical_number */
#define	OE_CTX_JAIL	0x0080	/* container.* when jid != 0 */
#define	OE_CTX_PID	0x0100	/* pid is known even if 0 */

struct oe_context {
	unsigned	 flags;
	pid_t		 ppid;
	int64_t		 tid;
	uid_t		 uid, ruid;
	gid_t		 gid, rgid;
	int		 cpu;
	int		 jid;
	const char	*jail_name;	/* container.name; NULL to omit */
};

/*
 * Log severity, numbered as SeverityNumber in the OpenTelemetry log
 * data model (each range's first value; TRACE2..4 and so on are the
 * values in between).  OE_SEV_UNSPECIFIED exports as INFO.
 */
enum oe_severity {
	OE_SEV_UNSPECIFIED = 0,
	OE_SEV_TRACE = 1,
	OE_SEV_DEBUG = 5,
	OE_SEV_INFO = 9,
	OE_SEV_WARN = 13,
	OE_SEV_ERROR = 17,
	OE_SEV_FATAL = 21
};

/*
 * The short name of a severity number's range (severityText): "TRACE",
 * "DEBUG", "INFO", "WARN", "ERROR" or "FATAL", with the range offset
 * appended as in the data model ("WARN2"); unspecified or out of range
 * values are INFO.
 */
const char *oe_severity_text(int severity, char *buf, size_t len);

struct oe_kv;

/*
 * One probe firing or event, normalized before it reaches any
 * exporter.  Strings are borrowed for the duration of the emit call;
 * exporters must copy anything they keep.
 */
struct oe_event {
	struct timespec	 ts;		/* probe wall clock (CLOCK_REALTIME) */
	const char	*profile;	/* profile / tool name */
	const char	*probe;		/* probe name or "" */
	pid_t		 pid;		/* 0 for system-level events */
	const char	*execname;	/* "" if unknown */
	const char	*body;		/* rendered text body, NULL/"" if none */
	const struct oe_frame *stack;	/* kernel stack or NULL */
	size_t		 nstack;
	const struct oe_frame *ustack;	/* user stack or NULL */
	size_t		 nustack;
	/*
	 * When the consumer read the event (observedTimeUnixNano).
	 * Zero means "now" at encoding time.
	 */
	struct timespec	 observed;
	struct oe_context ctx;
	/* OE_SEV_UNSPECIFIED exports as INFO. */
	enum oe_severity severity;
	/* Additional log record attributes (OTLP and JSONL exporters). */
	const struct oe_kv *attrs;
	size_t		 nattrs;
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
	/*
	 * Start of the accumulation window (startTimeUnixNano of
	 * cumulative sums and histograms); zero omits it.
	 */
	struct timespec	 start;
};

/* A typed attribute (OTLP AnyValue scalar). */
enum oe_value_type {
	OE_VAL_STRING,
	OE_VAL_INT,
	OE_VAL_DOUBLE,
	OE_VAL_BOOL
};

struct oe_kv {
	const char	*key;
	enum oe_value_type type;
	const char	*s;		/* OE_VAL_STRING */
	int64_t		 i;		/* OE_VAL_INT, OE_VAL_BOOL */
	double		 d;		/* OE_VAL_DOUBLE */
};

/* Span kind and status, numbered as in the OTLP trace protocol. */
enum oe_span_kind {
	OE_SPAN_INTERNAL = 1,
	OE_SPAN_SERVER = 2,
	OE_SPAN_CLIENT = 3,
	OE_SPAN_PRODUCER = 4,
	OE_SPAN_CONSUMER = 5
};

enum oe_status_code {
	OE_STATUS_UNSET = 0,
	OE_STATUS_OK = 1,
	OE_STATUS_ERROR = 2
};

#define	OE_TRACE_ID_LEN	16
#define	OE_SPAN_ID_LEN	8

/*
 * One finished span.  An all-zero parent_span_id marks a root span.
 * Strings are borrowed for the duration of the call.
 */
struct oe_span {
	const char	*name;
	const char	*profile;
	const char	*probe;		/* probe that ended it, or "" */
	struct timespec	 start;		/* wall clock */
	struct timespec	 end;
	uint8_t		 trace_id[OE_TRACE_ID_LEN];
	uint8_t		 span_id[OE_SPAN_ID_LEN];
	uint8_t		 parent_span_id[OE_SPAN_ID_LEN];
	enum oe_span_kind kind;
	enum oe_status_code status;
	const char	*status_message; /* NULL to omit */
	pid_t		 pid;		/* 0 if unknown */
	const char	*execname;	/* "" if unknown */
	const struct oe_kv *attrs;
	size_t		 nattrs;
	struct oe_context ctx;
};

/*
 * OTel resource attributes attached to every record.  "custom" (for
 * example OTEL_RESOURCE_ATTRIBUTES) replaces a built-in attribute of
 * the same key, except service.name: the tool resolves that one.
 */
struct oe_resource {
	const char	*service_name;
	const char	*service_instance_id;	/* NULL to omit */
	const char	*host_name;
	const char	*host_arch;
	const char	*os_name;		/* os.type, e.g. "freebsd" */
	const char	*os_version;
	const char	*service_version;
	const struct oe_attr *custom;
	size_t		 ncustom;
	/* NULL members below are omitted. */
	const char	*host_id;		/* host.id */
	const char	*os_full_name;		/* os.name, e.g. "FreeBSD" */
	const char	*os_description;	/* os.description */
};

/*
 * The running host as OTel resource values: host.name, host.id
 * (kern.hostuuid), host.arch (the semantic-convention spelling of the
 * machine), os.type, os.name, os.version, os.description (sysname,
 * release and kernel ident), and a fresh random service.instance.id
 * (UUID v4).  Empty strings mean "unknown".
 */
struct oe_host_info {
	char		 host_name[256];
	char		 host_id[64];
	char		 host_arch[32];
	char		 os_type[16];
	char		 os_name[32];
	char		 os_version[64];
	char		 os_description[192];
	char		 instance_id[40];
};

void	oe_host_detect(struct oe_host_info *);
/* hw.machine_arch in the host.arch spelling of the conventions. */
void	oe_host_arch_semconv(const char *machine_arch, char *buf,
	    size_t len);
/* Fill the host and OS members of a resource from the detection. */
void	oe_resource_host(struct oe_resource *, const struct oe_host_info *);

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
	int	(*span)(struct oe_exporter *, const struct oe_span *);
};

struct oe_exporter {
	const struct oe_exporter_ops *ops;
};

#define	oe_start(e)		((e)->ops->start(e))
#define	oe_event(e, ev)		((e)->ops->event((e), (ev)))
#define	oe_snapshot(e, sn)	((e)->ops->snapshot((e), (sn)))
/* Exporters without span support accept and ignore spans. */
#define	oe_span(e, sp)		((e)->ops->span != NULL ?		\
				    (e)->ops->span((e), (sp)) : 0)
#define	oe_flush(e)		((e)->ops->flush(e))
#define	oe_shutdown(e)		((e)->ops->shutdown(e))
#define	oe_exporter_free(e)	((e)->ops->free(e))

/*
 * Output sink: a borrowed stream or an owned file with optional size
 * and age rotation (path.1 newest .. path.N oldest) and durable
 * (fsync) flushes.  Records are never split across a rotation.
 * Functions return 0 or -1 with a message on stderr; the first write
 * error is sticky.
 */
struct oe_sink;

struct oe_sink_config {
	const char	*path;		/* NULL or "-": borrowed stream */
	FILE		*fp;		/* borrowed stream; NULL = stdout */
	uint64_t	 rotate_size;	/* bytes; 0 disables */
	time_t		 rotate_interval; /* seconds; 0 disables */
	unsigned	 rotate_keep;	/* rotated files kept; 0 = 7 */
	int		 durable;	/* fsync on flush/rotate/close */
};

struct oe_sink	*oe_sink_open(const struct oe_sink_config *);
int	 oe_sink_write(struct oe_sink *, const void *, size_t);
int	 oe_sink_poll(struct oe_sink *);
int	 oe_sink_flush(struct oe_sink *);
FILE	*oe_sink_stream(struct oe_sink *);
const char *oe_sink_path(const struct oe_sink *);
int	 oe_sink_close(struct oe_sink *);

/*
 * Constructors.  Output FILE pointers and sinks are borrowed, not
 * closed.
 */
struct oe_exporter *oe_text_new(FILE *out);
struct oe_exporter *oe_jsonl_new(FILE *out, const char *profile);
struct oe_exporter *oe_collapsed_new(FILE *out);
struct oe_exporter *oe_text_sink_new(struct oe_sink *);
struct oe_exporter *oe_jsonl_sink_new(struct oe_sink *, const char *profile);
struct oe_exporter *oe_collapsed_sink_new(struct oe_sink *);
/*
 * JSONL whose every line also names its resource in a "resource"
 * object (for example a HyperTrace guest); the attributes are copied.
 */
struct oe_exporter *oe_jsonl_resource_new(struct oe_sink *,
	    const char *profile, const struct oe_attr *resource, size_t n);

/*
 * OTLP JSON Lines file exporter: one ExportLogsServiceRequest,
 * ExportMetricsServiceRequest or ExportTraceServiceRequest JSON
 * object per line, as written by the OpenTelemetry Collector's file
 * exporter and read by its otlpjsonfile receiver.
 */
struct oe_otlpjson_config {
	struct oe_sink	*sink;		/* borrowed */
	const char	*profile;
	const struct oe_resource *resource;
	int		 batch_size;	/* records per line; 0 = 200 */
	/*
	 * Instrumentation scope: the tool, e.g. "bsdinstruments".  It
	 * also prefixes tool-specific attribute and metric names.  NULL
	 * falls back to the resource's service name.
	 */
	const char	*scope_name;
};

struct oe_exporter *oe_otlpjson_new(const struct oe_otlpjson_config *);

/*
 * Configuration for the OTLP exporter: OTLP/HTTP with JSON or protobuf
 * bodies, or OTLP/gRPC.
 */
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
	/*
	 * Optional spool: batches that still fail after the retries
	 * are appended here as OTLP JSON Lines and resent, oldest
	 * first, once the collector accepts a request again.
	 */
	const char	*spool_path;	/* NULL disables spooling */
	uint64_t	 spool_max;	/* bytes; 0 = 64 MiB */
	const char	*scope_name;	/* as in struct oe_otlpjson_config */
	/*
	 * A spool that cannot be opened, or that another exporter holds,
	 * is reported and left unused instead of failing creation (the
	 * system spool of otel.conf(5); see oe_config_load()).
	 */
	int		 spool_optional;
	/*
	 * "http/json", "http/protobuf" or "grpc"
	 * (OTEL_EXPORTER_OTLP_PROTOCOL).  NULL is http/json for callers
	 * that build the configuration themselves; oe_otlp_config_env()
	 * sets the resolved protocol, http/protobuf by default.
	 */
	const char	*protocol;
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
 * OTEL_EXPORTER_OTLP_TIMEOUT, OTEL_EXPORTER_OTLP_PROTOCOL).
 */
struct oe_sysconf;

struct oe_env {
	const char	*service_name;	/* NULL if unset */
	const char	*endpoint;
	const char	*compression;
	int		 timeout_ms;	/* -1 if unset */
	struct oe_attr	*resource_attrs; /* malloc'd array */
	size_t		 nresource_attrs;
	struct oe_attr	*headers;
	size_t		 nheaders;
	/* Set by oe_config_load(); oe_env_load() leaves them empty. */
	const char	*spool_path;	/* NULL: no spool */
	uint64_t	 spool_max;	/* 0: the exporter's default */
	int		 spool_optional; /* system spool: never fatal */
	struct oe_sysconf *sysconf;	/* owned otel.conf(5) layer */
	char		*spool_buf;	/* owned system spool path */
	/*
	 * grpc, http/protobuf or http/json; NULL if unset.  Always set by
	 * oe_config_load() (default http/protobuf).
	 */
	const char	*protocol;
};

/*
 * Load the variables above.  Malformed values (a non-numeric or
 * negative timeout, a key=value pair without '=' or with an empty
 * key) are reported on stderr and ignored, never half-applied.
 */
void	oe_env_load(struct oe_env *);
void	oe_env_free(struct oe_env *);

/*
 * The exporter settings every tool resolves the same way, across all
 * configuration layers, highest first: command line > OTEL_*
 * environment > otel.conf(5) (when "system" is set and its enable
 * key is true) > built-in default.  On success env->endpoint is always
 * set; env->spool_path is the command line spool, else the system
 * spool <spool.directory>/<scope>.spool when that directory is
 * writable, else NULL; env->spool_max is the command line bound, else
 * spool.max_bytes for the system spool.  Credentials from the
 * otel.conf headers file are added only when the resolved endpoint is
 * the system endpoint.  Returns 0, or -1 with err filled in (an
 * invalid otel.conf, allocation failure); env is then empty.  Release
 * env with oe_env_free().
 */
struct oe_config_request {
	const char	*scope;		/* tool name; names the spool file */
	const char	*endpoint;	/* command line, or NULL */
	const char	*spool;		/* command line, or NULL */
	uint64_t	 spool_max;	/* command line, or 0 */
	int		 system;	/* read otel.conf(5) */
	const char	*protocol;	/* command line, or NULL */
};

#define	OE_DEFAULT_ENDPOINT	"http://localhost:4318"
/* The default for OTLP/gRPC, whose collectors listen on 4317. */
#define	OE_DEFAULT_GRPC_ENDPOINT "http://localhost:4317"
#define	OE_DEFAULT_PROTOCOL	"http/protobuf"

int	oe_config_load(struct oe_env *, const struct oe_config_request *,
	    char *err, size_t errlen);

/*
 * A resource for the tool: the detected host (oe_host_detect()),
 * service.name from OTEL_SERVICE_NAME, else a service.name among the
 * resource attributes, else "service"; the remaining resource
 * attributes (OTEL_RESOURCE_ATTRIBUTES, then otel.conf) as custom
 * attributes.  Pointers refer into env, host and the arguments.
 */
void	oe_resource_init(struct oe_resource *, const struct oe_env *,
	    const struct oe_host_info *, const char *service,
	    const char *version);

/*
 * Fill the endpoint, protocol, timeout, headers, compression and spool
 * members of an OTLP configuration from resolved settings; other members
 * are left alone.
 */
void	oe_otlp_config_env(struct oe_otlp_config *, const struct oe_env *);

/*
 * Fill in host.name / host.arch / os.version from the running
 * system.  Buffers are caller-provided.
 */
void	oe_host_name(char *buf, size_t len);
void	oe_host_arch(char *buf, size_t len);
void	oe_os_version(char *buf, size_t len);

/*
 * Trace and span ids.  oe_id_random() fills a fresh random id;
 * oe_id_derive() derives a stable one from a secret salt, a
 * namespace and a key tuple (SHA-256, truncated), so records that
 * name the same key get the same id without coordination.  Both
 * never return an all-zero (invalid) id.  oe_id_hex() writes
 * 2*len lowercase hex digits plus a NUL.
 */
void	oe_id_random(uint8_t *id, size_t len);
void	oe_id_derive(const uint8_t salt[16], const char *ns,
	    const int64_t *key, size_t nkey, uint8_t *id, size_t len);
void	oe_id_hex(const uint8_t *id, size_t len, char *buf);
int	oe_id_is_zero(const uint8_t *id, size_t len);

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
/*
 * Append s with RFC 8259 JSON string escaping (no surrounding quotes):
 * well-formed UTF-8 passes through, control characters, quote and
 * backslash are escaped, and malformed bytes become U+FFFD.
 */
int	oe_buf_appendjson(struct oe_buf *, const char *);

/* Format a frame as module`symbol+0xoff / symbol / 0xaddr. */
void	oe_frame_format(const struct oe_frame *, char *buf, size_t len);

/* ISO 8601 with milliseconds and local UTC offset. */
void	oe_iso8601(const struct timespec *, char *buf, size_t len);

#endif /* !_OTELEXPORT_H_ */
