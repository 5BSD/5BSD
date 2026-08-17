/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * OTLP/HTTP+JSON exporter.  Batches events as OpenTelemetry
 * LogRecords and POSTs them to /v1/logs; aggregation snapshots map
 * to OTLP metrics POSTed to /v1/metrics.
 *
 * Batching is count-based (default 200 records) plus a time-based
 * flush (default 500 ms).  A dedicated sender thread performs the
 * HTTP POSTs so network latency never blocks the caller's consumer
 * loop.  Failed posts retry with exponential backoff and jitter per
 * the OTLP spec; 429/503 Retry-After is honored.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <zlib.h>

#include "otelexport.h"
#include "oe_http.h"

#define	OTLP_DEFAULT_BATCH	200
#define	OTLP_DEFAULT_FLUSH	0.5
#define	OTLP_DEFAULT_RETRIES	2
#define	OTLP_DEFAULT_TIMEOUT	10.0

struct post_job {
	struct post_job	*next;
	const char	*path;		/* static string */
	char		*body;
	size_t		 len;
};

struct oe_otlp {
	struct oe_exporter e;

	struct oe_url	 url;
	char		*scope;
	char		*profile;
	char		*version;
	char		*resource_json;	/* prebuilt attribute list */
	char		 user_agent[64];
	int		 batch_size;
	double		 flush_interval;
	int		 max_retries;
	int		 timeout_ms;
	int		 use_gzip;
	struct oe_attr	*headers;
	size_t		 nheaders;

	pthread_mutex_t	 lock;
	pthread_cond_t	 cv;
	char		**logrecs;	/* per-record JSON fragments */
	size_t		 nlogrecs, caplogrecs;
	char		**metrics;	/* per-snapshot metric fragments */
	size_t		 nmetrics, capmetrics;
	uint64_t	 pending_drops;
	struct post_job	*jobs_head, *jobs_tail;
	int		 stop;
	int		 started;
	pthread_t	 sender;
};

static const struct oe_exporter_ops otlp_ops;

static uint64_t
ts_unix_nano(const struct timespec *ts)
{

	if (ts->tv_sec < 0)
		return (0);
	return ((uint64_t)ts->tv_sec * 1000000000ULL + (uint64_t)ts->tv_nsec);
}

static void
append_kv_string(struct oe_buf *b, const char *key, const char *value,
    int *first)
{

	if (!*first)
		oe_buf_appendstr(b, ",");
	*first = 0;
	oe_buf_appendstr(b, "{\"key\":\"");
	oe_buf_appendjson(b, key);
	oe_buf_appendstr(b, "\",\"value\":{\"stringValue\":\"");
	oe_buf_appendjson(b, value != NULL ? value : "");
	oe_buf_appendstr(b, "\"}}");
}

static char *
build_resource_json(const struct oe_resource *r)
{
	struct oe_buf b;
	size_t i;
	int first = 1;

	oe_buf_init(&b);
	append_kv_string(&b, "service.name", r->service_name, &first);
	append_kv_string(&b, "service.version", r->service_version, &first);
	append_kv_string(&b, "host.name", r->host_name, &first);
	append_kv_string(&b, "host.arch", r->host_arch, &first);
	append_kv_string(&b, "os.type", r->os_name, &first);
	append_kv_string(&b, "os.version", r->os_version, &first);
	append_kv_string(&b, "telemetry.sdk.name", "observablebsd", &first);
	append_kv_string(&b, "telemetry.sdk.language", "c", &first);
	append_kv_string(&b, "telemetry.sdk.version", r->service_version,
	    &first);
	if (r->service_instance_id != NULL)
		append_kv_string(&b, "service.instance.id",
		    r->service_instance_id, &first);
	for (i = 0; i < r->ncustom; i++)
		append_kv_string(&b, r->custom[i].name, r->custom[i].value,
		    &first);
	if (b.error) {
		oe_buf_free(&b);
		return (NULL);
	}
	return (b.data);
}

/* ---------------------------------------------------------------- */
/* Envelope construction						*/

static char *
build_log_envelope(struct oe_otlp *o, char **recs, size_t nrecs,
    uint64_t drops, size_t *lenp)
{
	struct oe_buf b;
	size_t i, reclen;

	oe_buf_init(&b);
	oe_buf_appendstr(&b,
	    "{\"resourceLogs\":[{\"resource\":{\"attributes\":[");
	oe_buf_appendstr(&b, o->resource_json);
	oe_buf_appendstr(&b, "]},\"scopeLogs\":[{\"scope\":{\"name\":\"");
	oe_buf_appendjson(&b, o->scope);
	oe_buf_appendstr(&b, "\",\"version\":\"");
	oe_buf_appendjson(&b, o->version);
	oe_buf_appendstr(&b, "\"},\"logRecords\":[");
	for (i = 0; i < nrecs; i++) {
		if (i > 0)
			oe_buf_appendstr(&b, ",");
		if (i == 0 && drops > 0) {
			/*
			 * Splice a drop-counter attribute into the first
			 * record.  Every record fragment ends with "]}"
			 * closing its attribute array.
			 */
			reclen = strlen(recs[i]);
			oe_buf_append(&b, recs[i], reclen - 2);
			oe_buf_appendstr(&b, ",{\"key\":\"");
			oe_buf_appendjson(&b, o->scope);
			oe_buf_appendf(&b,
			    ".drops\",\"value\":{\"intValue\":\"%ju\"}}]}",
			    (uintmax_t)drops);
		} else
			oe_buf_appendstr(&b, recs[i]);
	}
	oe_buf_appendstr(&b, "]}]}]}");
	if (b.error) {
		oe_buf_free(&b);
		return (NULL);
	}
	*lenp = b.len;
	return (b.data);
}

static char *
build_metrics_envelope(struct oe_otlp *o, char **frags, size_t nfrags,
    size_t *lenp)
{
	struct oe_buf b;
	size_t i;

	oe_buf_init(&b);
	oe_buf_appendstr(&b,
	    "{\"resourceMetrics\":[{\"resource\":{\"attributes\":[");
	oe_buf_appendstr(&b, o->resource_json);
	oe_buf_appendstr(&b, "]},\"scopeMetrics\":[{\"scope\":{\"name\":\"");
	oe_buf_appendjson(&b, o->scope);
	oe_buf_appendstr(&b, "\",\"version\":\"");
	oe_buf_appendjson(&b, o->version);
	oe_buf_appendstr(&b, "\"},\"metrics\":[");
	for (i = 0; i < nfrags; i++) {
		if (i > 0)
			oe_buf_appendstr(&b, ",");
		oe_buf_appendstr(&b, frags[i]);
	}
	oe_buf_appendstr(&b, "]}]}]}");
	if (b.error) {
		oe_buf_free(&b);
		return (NULL);
	}
	*lenp = b.len;
	return (b.data);
}

static void
build_dimension_attrs(struct oe_buf *b, const struct oe_datapoint *dp)
{
	size_t i;
	int first = 1;

	for (i = 0; i < dp->nattrs; i++)
		append_kv_string(b, dp->attrs[i].name, dp->attrs[i].value,
		    &first);
}

static int
bucket_cmp(const void *a, const void *b)
{
	const struct oe_bucket *ba = a, *bb = b;

	if (ba->upper < bb->upper)
		return (-1);
	return (ba->upper > bb->upper);
}

/*
 * Build one snapshot's metric JSON fragment.  count/sum become a
 * monotonic Sum, min/max/avg/stddev a Gauge, quantize variants a
 * Histogram (sum omitted — power-of-2 bucket bounds can't recover
 * the true sum of observations).
 */
static char *
build_metric_fragment(struct oe_otlp *o, const struct oe_snapshot *sn)
{
	struct oe_buf b;
	struct oe_bucket *sorted;
	const struct oe_datapoint *dp;
	uint64_t tnano;
	int64_t total;
	size_t i, j;
	int firstdp;

	oe_buf_init(&b);
	tnano = ts_unix_nano(&sn->ts);

	oe_buf_appendstr(&b, "{\"name\":\"");
	oe_buf_appendjson(&b, o->scope);
	oe_buf_appendstr(&b, ".");
	oe_buf_appendjson(&b, sn->profile);
	oe_buf_appendstr(&b, ".");
	if (sn->name != NULL && sn->name[0] != '\0')
		oe_buf_appendjson(&b, sn->name);
	else {
		static const char *kindnames[] = {
			"count", "sum", "min", "max", "avg", "stddev",
			"quantize", "lquantize", "llquantize"
		};
		oe_buf_appendstr(&b, kindnames[sn->kind]);
	}
	oe_buf_appendstr(&b, "\",");

	switch (sn->kind) {
	case OE_AGG_COUNT:
	case OE_AGG_SUM:
	case OE_AGG_MIN:
	case OE_AGG_MAX:
	case OE_AGG_AVG:
	case OE_AGG_STDDEV:
		oe_buf_appendstr(&b, sn->kind == OE_AGG_COUNT ||
		    sn->kind == OE_AGG_SUM ?
		    "\"sum\":{\"dataPoints\":[" :
		    "\"gauge\":{\"dataPoints\":[");
		firstdp = 1;
		for (i = 0; i < sn->npoints; i++) {
			dp = &sn->points[i];
			if (dp->is_histogram)
				continue;
			if (!firstdp)
				oe_buf_appendstr(&b, ",");
			firstdp = 0;
			oe_buf_appendf(&b,
			    "{\"timeUnixNano\":\"%ju\",\"asInt\":\"%jd\","
			    "\"attributes\":[", (uintmax_t)tnano,
			    (intmax_t)dp->scalar);
			build_dimension_attrs(&b, dp);
			oe_buf_appendstr(&b, "]}");
		}
		if (sn->kind == OE_AGG_COUNT || sn->kind == OE_AGG_SUM)
			oe_buf_appendstr(&b, "],\"aggregationTemporality\":2,"
			    "\"isMonotonic\":true}}");
		else
			oe_buf_appendstr(&b, "]}}");
		break;

	case OE_AGG_QUANTIZE:
	case OE_AGG_LQUANTIZE:
	case OE_AGG_LLQUANTIZE:
		oe_buf_appendstr(&b, "\"histogram\":{\"dataPoints\":[");
		firstdp = 1;
		for (i = 0; i < sn->npoints; i++) {
			dp = &sn->points[i];
			/*
			 * A histogram with zero buckets would emit
			 * bucketCounts=[] with explicitBounds=[],
			 * violating len(counts) == len(bounds)+1.
			 */
			if (!dp->is_histogram || dp->nbuckets == 0)
				continue;
			sorted = malloc(dp->nbuckets * sizeof(*sorted));
			if (sorted == NULL) {
				b.error = 1;
				break;
			}
			memcpy(sorted, dp->buckets,
			    dp->nbuckets * sizeof(*sorted));
			qsort(sorted, dp->nbuckets, sizeof(*sorted),
			    bucket_cmp);
			total = 0;
			for (j = 0; j < dp->nbuckets; j++)
				total += sorted[j].count;
			if (!firstdp)
				oe_buf_appendstr(&b, ",");
			firstdp = 0;
			oe_buf_appendf(&b,
			    "{\"timeUnixNano\":\"%ju\",\"count\":\"%jd\","
			    "\"explicitBounds\":[", (uintmax_t)tnano,
			    (intmax_t)total);
			for (j = 0; j + 1 < dp->nbuckets; j++)
				oe_buf_appendf(&b, "%s%jd", j > 0 ? "," : "",
				    (intmax_t)sorted[j].upper);
			oe_buf_appendstr(&b, "],\"bucketCounts\":[");
			for (j = 0; j < dp->nbuckets; j++)
				oe_buf_appendf(&b, "%s\"%jd\"",
				    j > 0 ? "," : "",
				    (intmax_t)sorted[j].count);
			oe_buf_appendstr(&b, "],\"attributes\":[");
			build_dimension_attrs(&b, dp);
			oe_buf_appendstr(&b, "]}");
			free(sorted);
		}
		oe_buf_appendstr(&b, "],\"aggregationTemporality\":2}}");
		break;
	}

	if (b.error) {
		oe_buf_free(&b);
		return (NULL);
	}
	return (b.data);
}

/* ---------------------------------------------------------------- */
/* Posting								*/

static void *
gzip_body(const char *data, size_t len, size_t *outlenp)
{
	z_stream zs;
	unsigned char *out;
	uLong bound;

	if (len == 0)
		return (NULL);
	memset(&zs, 0, sizeof(zs));
	if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
	    15 + 16 /* gzip wrapper */, 8, Z_DEFAULT_STRATEGY) != Z_OK)
		return (NULL);
	/*
	 * deflateBound() accounts for the gzip wrapper configured
	 * above; compressBound() budgets only the smaller zlib one
	 * and can undershoot for tiny incompressible bodies.
	 */
	bound = deflateBound(&zs, len);
	out = malloc(bound);
	if (out == NULL) {
		deflateEnd(&zs);
		return (NULL);
	}
	zs.next_in = __DECONST(unsigned char *, data);
	zs.avail_in = len;
	zs.next_out = out;
	zs.avail_out = bound;
	if (deflate(&zs, Z_FINISH) != Z_STREAM_END) {
		deflateEnd(&zs);
		free(out);
		return (NULL);
	}
	*outlenp = zs.total_out;
	deflateEnd(&zs);
	return (out);
}

static int
status_retryable(int status)
{

	return (status == 429 || status == 502 || status == 503 ||
	    status == 504);
}

/*
 * Best-effort partial_success check on a 2xx response, per the OTLP
 * spec: if the collector rejected some records it reports a count in
 * the response body.  We warn but do not retry.
 */
static void
check_partial_success(const char *body, const char *path)
{
	const char *p;
	long rejected;

	if (body == NULL || strstr(body, "partialSuccess") == NULL)
		return;
	rejected = 0;
	if ((p = strstr(body, "\"rejectedLogRecords\":")) != NULL)
		p += 21;
	else if ((p = strstr(body, "\"rejectedDataPoints\":")) != NULL)
		p += 21;
	if (p != NULL) {
		/* Skip whitespace and an optional quote (proto3 JSON
		 * emits int64 as a quoted string). */
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '"')
			p++;
		rejected = strtol(p, NULL, 10);
	}
	if (rejected > 0)
		fprintf(stderr, "otlp: /%s partial success: %ld records "
		    "rejected\n", path, rejected);
}

static void
sleep_seconds(double secs)
{
	struct timespec ts;

	if (secs <= 0)
		return;
	ts.tv_sec = (time_t)secs;
	ts.tv_nsec = (long)((secs - (double)ts.tv_sec) * 1e9);
	nanosleep(&ts, NULL);
}

static void
post_with_retry(struct oe_otlp *o, const char *path, const char *body,
    size_t len)
{
	struct oe_http_response resp;
	void *gz;
	const void *payload;
	size_t paylen;
	double backoff_ms, retry_after;
	int attempt, gzipped, retryable;

	gz = NULL;
	gzipped = 0;
	payload = body;
	paylen = len;
	if (o->use_gzip) {
		gz = gzip_body(body, len, &paylen);
		if (gz != NULL) {
			payload = gz;
			gzipped = 1;
		} else
			paylen = len;
	}

	retry_after = -1.0;
	for (attempt = 0; attempt <= o->max_retries; attempt++) {
		if (attempt > 0) {
			/* Exponential backoff with jitter (OTLP spec);
			 * clamp the exponent so a large configured
			 * retry count cannot overflow the shift. */
			backoff_ms = 100.0 *
			    (double)(1U << (attempt > 20 ? 20 : attempt - 1));
			backoff_ms += (double)arc4random_uniform(
			    (uint32_t)(backoff_ms * 0.5) + 1);
			sleep_seconds(backoff_ms / 1000.0);
			if (retry_after > 0)
				sleep_seconds(retry_after);
		}

		if (oe_http_post(&o->url, path, o->headers, o->nheaders,
		    o->user_agent, payload, paylen, gzipped, o->timeout_ms,
		    &resp) != 0) {
			retryable = 1;
			retry_after = -1.0;
			if (attempt == o->max_retries)
				fprintf(stderr, "otlp: POST /%s failed: %s "
				    "(after %d attempts)\n", path,
				    resp.errmsg, o->max_retries + 1);
			continue;
		}

		if (resp.status >= 200 && resp.status < 300) {
			check_partial_success(resp.body, path);
			break;
		}

		retryable = status_retryable(resp.status);
		retry_after = resp.retry_after;
		if (!retryable) {
			fprintf(stderr, "otlp: POST /%s returned %d "
			    "(non-retryable)\n", path, resp.status);
			break;
		}
		if (attempt == o->max_retries)
			fprintf(stderr, "otlp: POST /%s returned %d (after "
			    "%d attempts)\n", path, resp.status,
			    o->max_retries + 1);
	}
	free(gz);
}

/* ---------------------------------------------------------------- */
/* Batching and the sender thread				 	*/

static int
append_fragment(char ***arr, size_t *n, size_t *cap, char *frag)
{
	char **p;

	if (*n == *cap) {
		size_t newcap = *cap == 0 ? 64 : *cap * 2;

		p = realloc(*arr, newcap * sizeof(*p));
		if (p == NULL)
			return (-1);
		*arr = p;
		*cap = newcap;
	}
	(*arr)[(*n)++] = frag;
	return (0);
}

static void
free_fragments(char **arr, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		free(arr[i]);
	free(arr);
}

/* Called with the lock held; takes both batches out of the object. */
static void
take_batches(struct oe_otlp *o, char ***logs, size_t *nlogs,
    char ***mets, size_t *nmets, uint64_t *drops)
{

	*logs = o->logrecs;
	*nlogs = o->nlogrecs;
	*mets = o->metrics;
	*nmets = o->nmetrics;
	*drops = o->pending_drops;
	o->logrecs = NULL;
	o->nlogrecs = o->caplogrecs = 0;
	o->metrics = NULL;
	o->nmetrics = o->capmetrics = 0;
	o->pending_drops = 0;
}

/* Post taken batches.  Called without the lock. */
static void
post_batches(struct oe_otlp *o, char **logs, size_t nlogs, char **mets,
    size_t nmets, uint64_t drops)
{
	char *body;
	size_t len;

	if (nlogs > 0) {
		body = build_log_envelope(o, logs, nlogs, drops, &len);
		if (body != NULL) {
			post_with_retry(o, "v1/logs", body, len);
			free(body);
		}
	} else if (drops > 0) {
		/*
		 * No log records this cycle (aggregation-only
		 * profiles): re-credit the drops so they ride the
		 * next batch instead of being silently destroyed.
		 */
		pthread_mutex_lock(&o->lock);
		o->pending_drops += drops;
		pthread_mutex_unlock(&o->lock);
	}
	if (nmets > 0) {
		body = build_metrics_envelope(o, mets, nmets, &len);
		if (body != NULL) {
			post_with_retry(o, "v1/metrics", body, len);
			free(body);
		}
	}
	free_fragments(logs, nlogs);
	free_fragments(mets, nmets);
}

static void
enqueue_job(struct oe_otlp *o, const char *path, char *body, size_t len)
{
	struct post_job *job;

	job = malloc(sizeof(*job));
	if (job == NULL) {
		free(body);
		return;
	}
	job->next = NULL;
	job->path = path;
	job->body = body;
	job->len = len;
	if (o->jobs_tail != NULL)
		o->jobs_tail->next = job;
	else
		o->jobs_head = job;
	o->jobs_tail = job;
	pthread_cond_signal(&o->cv);
}

static void *
sender_main(void *arg)
{
	struct oe_otlp *o = arg;
	struct post_job *job;
	struct timespec deadline;
	char **logs, **mets;
	size_t nlogs, nmets;
	uint64_t drops;
	int timedout;

	pthread_mutex_lock(&o->lock);
	for (;;) {
		timedout = 0;
		while (o->jobs_head == NULL && !o->stop && !timedout) {
			if (o->flush_interval > 0) {
				clock_gettime(CLOCK_REALTIME, &deadline);
				deadline.tv_sec +=
				    (time_t)o->flush_interval;
				deadline.tv_nsec += (long)((o->flush_interval -
				    (double)(time_t)o->flush_interval) * 1e9);
				if (deadline.tv_nsec >= 1000000000L) {
					deadline.tv_sec++;
					deadline.tv_nsec -= 1000000000L;
				}
				if (pthread_cond_timedwait(&o->cv, &o->lock,
				    &deadline) != 0)
					timedout = 1;
			} else
				pthread_cond_wait(&o->cv, &o->lock);
		}

		if (timedout) {
			/* Time-based flush of whatever accumulated. */
			take_batches(o, &logs, &nlogs, &mets, &nmets, &drops);
			if (nlogs > 0 || nmets > 0) {
				pthread_mutex_unlock(&o->lock);
				post_batches(o, logs, nlogs, mets, nmets,
				    drops);
				pthread_mutex_lock(&o->lock);
			} else {
				free_fragments(logs, nlogs);
				free_fragments(mets, nmets);
				/*
				 * Nothing to post this tick: re-credit
				 * any drops so they ride a later batch
				 * instead of being destroyed (the lock
				 * is held here).
				 */
				o->pending_drops += drops;
			}
			continue;
		}

		job = o->jobs_head;
		if (job != NULL) {
			o->jobs_head = job->next;
			if (o->jobs_head == NULL)
				o->jobs_tail = NULL;
			pthread_mutex_unlock(&o->lock);
			post_with_retry(o, job->path, job->body, job->len);
			free(job->body);
			free(job);
			pthread_mutex_lock(&o->lock);
			continue;
		}

		if (o->stop)
			break;
	}
	pthread_mutex_unlock(&o->lock);
	return (NULL);
}

/* ---------------------------------------------------------------- */
/* Exporter methods						 	*/

static int
otlp_start(struct oe_exporter *e)
{
	struct oe_otlp *o = (struct oe_otlp *)e;

	if (o->started)
		return (0);
	if (pthread_create(&o->sender, NULL, sender_main, o) != 0) {
		fprintf(stderr, "otlp: failed to start sender thread\n");
		return (-1);
	}
	o->started = 1;
	return (0);
}

static char *
build_log_record(struct oe_otlp *o, const struct oe_event *ev)
{
	struct oe_buf b;
	uint64_t tnano;

	tnano = ts_unix_nano(&ev->ts);
	oe_buf_init(&b);
	oe_buf_appendf(&b, "{\"timeUnixNano\":\"%ju\","
	    "\"observedTimeUnixNano\":\"%ju\",\"severityNumber\":9,"
	    "\"body\":{\"stringValue\":\"", (uintmax_t)tnano,
	    (uintmax_t)tnano);
	oe_buf_appendjson(&b, ev->body);
	oe_buf_appendstr(&b, "\"},\"attributes\":[{\"key\":\"");
	oe_buf_appendjson(&b, o->scope);
	oe_buf_appendstr(&b, ".profile\",\"value\":{\"stringValue\":\"");
	oe_buf_appendjson(&b, ev->profile);
	oe_buf_appendstr(&b, "\"}},{\"key\":\"");
	oe_buf_appendjson(&b, o->scope);
	oe_buf_appendstr(&b, ".probe\",\"value\":{\"stringValue\":\"");
	oe_buf_appendjson(&b, ev->probe != NULL ? ev->probe : "");
	oe_buf_appendf(&b, "\"}},{\"key\":\"process.pid\",\"value\":"
	    "{\"intValue\":\"%d\"}},{\"key\":\"process.executable.name\","
	    "\"value\":{\"stringValue\":\"", (int)ev->pid);
	oe_buf_appendjson(&b, ev->execname != NULL ? ev->execname : "");
	oe_buf_appendstr(&b, "\"}}]}");
	if (b.error) {
		oe_buf_free(&b);
		return (NULL);
	}
	return (b.data);
}

static int
otlp_event(struct oe_exporter *e, const struct oe_event *ev)
{
	struct oe_otlp *o = (struct oe_otlp *)e;
	char *rec, *body, **logs;
	size_t nlogs, len;
	uint64_t drops;

	if (ev->body == NULL || ev->body[0] == '\0')
		return (0);
	rec = build_log_record(o, ev);
	if (rec == NULL)
		return (-1);

	pthread_mutex_lock(&o->lock);
	if (append_fragment(&o->logrecs, &o->nlogrecs, &o->caplogrecs,
	    rec) != 0) {
		pthread_mutex_unlock(&o->lock);
		free(rec);
		return (-1);
	}
	if (o->nlogrecs < (size_t)o->batch_size) {
		pthread_mutex_unlock(&o->lock);
		return (0);
	}
	/* Batch full: build the envelope and hand it to the sender. */
	logs = o->logrecs;
	nlogs = o->nlogrecs;
	drops = o->pending_drops;
	o->logrecs = NULL;
	o->nlogrecs = o->caplogrecs = 0;
	o->pending_drops = 0;
	body = build_log_envelope(o, logs, nlogs, drops, &len);
	if (body != NULL)
		enqueue_job(o, "v1/logs", body, len);
	pthread_mutex_unlock(&o->lock);
	free_fragments(logs, nlogs);
	return (0);
}

static int
otlp_snapshot(struct oe_exporter *e, const struct oe_snapshot *sn)
{
	struct oe_otlp *o = (struct oe_otlp *)e;
	char *frag;
	int ret;

	if (sn->npoints == 0)
		return (0);
	frag = build_metric_fragment(o, sn);
	if (frag == NULL)
		return (-1);
	pthread_mutex_lock(&o->lock);
	ret = append_fragment(&o->metrics, &o->nmetrics, &o->capmetrics,
	    frag);
	pthread_mutex_unlock(&o->lock);
	if (ret != 0)
		free(frag);
	return (ret);
}

static int
otlp_flush(struct oe_exporter *e)
{
	struct oe_otlp *o = (struct oe_otlp *)e;
	char **logs, **mets;
	size_t nlogs, nmets;
	uint64_t drops;

	pthread_mutex_lock(&o->lock);
	take_batches(o, &logs, &nlogs, &mets, &nmets, &drops);
	pthread_mutex_unlock(&o->lock);
	post_batches(o, logs, nlogs, mets, nmets, drops);
	return (0);
}

static int
otlp_shutdown(struct oe_exporter *e)
{
	struct oe_otlp *o = (struct oe_otlp *)e;

	if (o->started) {
		pthread_mutex_lock(&o->lock);
		o->stop = 1;
		pthread_cond_signal(&o->cv);
		pthread_mutex_unlock(&o->lock);
		pthread_join(o->sender, NULL);
		o->started = 0;
	}
	/* Drain whatever is still batched, synchronously. */
	return (otlp_flush(e));
}

static void
otlp_free(struct oe_exporter *e)
{
	struct oe_otlp *o = (struct oe_otlp *)e;
	struct post_job *job, *next;
	size_t i;

	for (job = o->jobs_head; job != NULL; job = next) {
		next = job->next;
		free(job->body);
		free(job);
	}
	free_fragments(o->logrecs, o->nlogrecs);
	free_fragments(o->metrics, o->nmetrics);
	for (i = 0; i < o->nheaders; i++) {
		free(__DECONST(char *, o->headers[i].name));
		free(__DECONST(char *, o->headers[i].value));
	}
	free(o->headers);
	free(o->scope);
	free(o->profile);
	free(o->version);
	free(o->resource_json);
	pthread_mutex_destroy(&o->lock);
	pthread_cond_destroy(&o->cv);
	free(o);
}

static const struct oe_exporter_ops otlp_ops = {
	.start = otlp_start,
	.event = otlp_event,
	.snapshot = otlp_snapshot,
	.flush = otlp_flush,
	.shutdown = otlp_shutdown,
	.free = otlp_free,
};

void
oe_report_drops(struct oe_exporter *e, uint64_t count)
{
	struct oe_otlp *o;

	if (e == NULL || e->ops != &otlp_ops)
		return;
	o = (struct oe_otlp *)e;
	pthread_mutex_lock(&o->lock);
	o->pending_drops += count;
	pthread_mutex_unlock(&o->lock);
}

struct oe_exporter *
oe_otlp_new(const struct oe_otlp_config *cfg)
{
	struct oe_otlp *o;
	const struct oe_resource *r = cfg->resource;
	size_t i;

	o = calloc(1, sizeof(*o));
	if (o == NULL)
		return (NULL);
	o->e.ops = &otlp_ops;
	pthread_mutex_init(&o->lock, NULL);
	pthread_cond_init(&o->cv, NULL);
	if (oe_url_parse(cfg->endpoint, &o->url) != 0) {
		fprintf(stderr, "otlp: invalid endpoint URL '%s'\n",
		    cfg->endpoint);
		otlp_free(&o->e);
		return (NULL);
	}
	o->scope = strdup(r->service_name);
	o->profile = strdup(cfg->profile != NULL ? cfg->profile : "");
	o->version = strdup(r->service_version);
	o->resource_json = build_resource_json(r);
	if (o->scope == NULL || o->profile == NULL || o->version == NULL ||
	    o->resource_json == NULL)
		goto fail;
	snprintf(o->user_agent, sizeof(o->user_agent),
	    "OTel-OTLP-Exporter-C/%s", r->service_version);
	o->batch_size = cfg->batch_size > 0 ? cfg->batch_size :
	    OTLP_DEFAULT_BATCH;
	o->flush_interval = cfg->flush_interval > 0 ? cfg->flush_interval :
	    OTLP_DEFAULT_FLUSH;
	o->max_retries = cfg->max_retries >= 0 ? cfg->max_retries :
	    OTLP_DEFAULT_RETRIES;
	o->timeout_ms = (int)((cfg->timeout > 0 ? cfg->timeout :
	    OTLP_DEFAULT_TIMEOUT) * 1000.0);
	/* Default to gzip; honor "none" to disable. */
	o->use_gzip = cfg->compression == NULL ||
	    strcasecmp(cfg->compression, "none") != 0;
	if (cfg->nheaders > 0) {
		o->headers = calloc(cfg->nheaders, sizeof(*o->headers));
		if (o->headers == NULL)
			goto fail;
		for (i = 0; i < cfg->nheaders; i++) {
			o->headers[i].name = strdup(cfg->headers[i].name);
			o->headers[i].value = strdup(cfg->headers[i].value);
			if (o->headers[i].name == NULL ||
			    o->headers[i].value == NULL)
				goto fail;
			o->nheaders = i + 1;
		}
	}
	return (&o->e);

fail:
	fprintf(stderr, "otlp: out of memory\n");
	otlp_free(&o->e);
	return (NULL);
}
