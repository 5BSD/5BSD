/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * OTLP/HTTP+JSON exporter.  Batches events as OpenTelemetry
 * LogRecords and POSTs them to /v1/logs; aggregation snapshots map
 * to OTLP metrics POSTed to /v1/metrics and spans to /v1/traces.  Request bodies come from
 * the shared encoder (oe_otlpenc.c), so they are identical to the
 * lines the OTLP JSON file exporter writes.
 *
 * Batching is count-based (default 200 records) plus a time-based
 * flush (default 500 ms).  A dedicated sender thread performs the
 * HTTP POSTs so network latency never blocks the caller's consumer
 * loop.  Failed posts retry with exponential backoff and jitter per
 * the OTLP spec; 429/503 Retry-After is honored.
 *
 * With a spool configured, a request that still fails after the
 * retries is appended to the spool file as one OTLP JSON line
 * (fsynced) instead of being lost.  After the next accepted request,
 * and periodically while idle, the spool is replayed oldest first;
 * whatever the collector still refuses stays spooled.  The spool is
 * bounded: a request that would push it past the limit is dropped
 * and counted, so an outage cannot fill the disk.  Requests the
 * collector rejects as malformed (non-retryable 4xx) are never
 * spooled, since resending cannot succeed.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <zlib.h>

#include "otelexport.h"
#include "oe_http.h"
#include "oe_otlpenc.h"
#include "oe_otlppb.h"

#define	OTLP_DEFAULT_BATCH	200
#define	OTLP_DEFAULT_FLUSH	0.5
#define	OTLP_DEFAULT_RETRIES	2
#define	OTLP_DEFAULT_TIMEOUT	10.0
#define	OTLP_DEFAULT_SPOOL	(64ULL * 1024 * 1024)
#define	OTLP_SPOOL_RETRY	5	/* idle replay cadence, seconds */
#define	OTLP_NSIGNALS		3

enum post_result {
	POST_OK,		/* 2xx */
	POST_REJECTED,		/* non-retryable status: drop */
	POST_FAILED		/* transport error or retries exhausted */
};
_Static_assert(POST_OK == OE_OTLPPB_OK && POST_REJECTED ==
    OE_OTLPPB_REJECTED && POST_FAILED == OE_OTLPPB_FAILED,
    "oe_otlppb_post() results are post_result values");

struct post_job {
	struct post_job	*next;
	enum oe_signal	 sig;
	char		*body;
	size_t		 len;
};

struct oe_otlp {
	struct oe_exporter e;

	struct oe_url	 url;
	struct oe_otlpenc enc;
	char		 user_agent[64];
	int		 batch_size;
	double		 flush_interval;
	int		 max_retries;
	int		 timeout_ms;
	int		 use_gzip;
	struct oe_attr	*headers;
	size_t		 nheaders;
	/* http/protobuf and grpc (oe_otlppb.h); NULL for http/json. */
	struct oe_otlppb *pb;

	pthread_mutex_t	 lock;
	pthread_cond_t	 cv;
	char		**frags[OTLP_NSIGNALS];	/* per-record fragments */
	size_t		 nfrags[OTLP_NSIGNALS], capfrags[OTLP_NSIGNALS];
	struct post_job	*jobs_head, *jobs_tail;
	int		 stop;
	int		 started;
	pthread_t	 sender;

	/* Spool; spool_lock serializes every spool file operation. */
	pthread_mutex_t	 spool_lock;
	char		*spool_path;
	int		 spool_lockfd;	/* <spool>.lock, held exclusively */
	uint64_t	 spool_max;
	uint64_t	 spool_size;
	uint64_t	 spool_dropped;
	time_t		 spool_last_try;
};

static const struct oe_exporter_ops otlp_ops;

/* ---------------------------------------------------------------- */
/* Posting								*/

static void *
gzip_body(const char *data, size_t len, size_t *outlenp)
{
	z_stream zs;
	unsigned char *out;
	uLong bound;

	/* Requests are never empty. */
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
	static const char *const keys[] = {
		"\"rejectedLogRecords\":", "\"rejectedDataPoints\":",
		"\"rejectedSpans\":"
	};
	const char *p;
	long rejected;
	size_t i;

	if (strstr(body, "partialSuccess") == NULL)
		return;
	rejected = 0;
	for (i = 0, p = NULL; i < nitems(keys) && p == NULL; i++)
		if ((p = strstr(body, keys[i])) != NULL)
			p += strlen(keys[i]);
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

static enum post_result
post_with_retry(struct oe_otlp *o, enum oe_signal sig, const char *body,
    size_t len)
{
	struct oe_http_response resp;
	enum post_result result;
	const char *path;
	void *gz;
	const void *payload;
	size_t paylen;
	double backoff_ms, retry_after;
	int attempt, gzipped;

	/* The protobuf transports send and retry on their own. */
	if (o->pb != NULL)
		return ((enum post_result)oe_otlppb_post(o->pb, sig, body,
		    len));
	path = oe_enc_path(sig);
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

	result = POST_FAILED;
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
			sleep_seconds(retry_after);
		}

		if (oe_http_post(&o->url, path, o->headers, o->nheaders,
		    o->user_agent, payload, paylen, gzipped, o->timeout_ms,
		    &resp) != 0) {
			retry_after = -1.0;
			if (attempt == o->max_retries)
				fprintf(stderr, "otlp: POST /%s failed: %s "
				    "(after %d attempts)\n", path,
				    resp.errmsg, o->max_retries + 1);
			continue;
		}

		if (resp.status >= 200 && resp.status < 300) {
			check_partial_success(resp.body, path);
			result = POST_OK;
			break;
		}

		retry_after = resp.retry_after;
		if (!status_retryable(resp.status)) {
			fprintf(stderr, "otlp: POST /%s returned %d "
			    "(non-retryable)\n", path, resp.status);
			result = POST_REJECTED;
			break;
		}
		if (attempt == o->max_retries)
			fprintf(stderr, "otlp: POST /%s returned %d (after "
			    "%d attempts)\n", path, resp.status,
			    o->max_retries + 1);
	}
	free(gz);
	return (result);
}

/* ---------------------------------------------------------------- */
/* Spool								*/

/* Append one request line.  Called with spool_lock held. */
static void
spool_append(struct oe_otlp *o, enum oe_signal sig, const char *body,
    size_t len)
{
	char *line;
	ssize_t n;
	int fd;

	if (o->spool_size + len + 1 > o->spool_max) {
		if (o->spool_dropped++ == 0)
			fprintf(stderr, "otlp: spool %s is full (%ju bytes); "
			    "dropping batches until it drains\n",
			    o->spool_path, (uintmax_t)o->spool_max);
		return;
	}
	fd = open(o->spool_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
	    0600);
	if (fd < 0) {
		fprintf(stderr, "otlp: spool %s: open failed: %s; /%s batch "
		    "lost\n", o->spool_path, strerror(errno),
		    oe_enc_path(sig));
		return;
	}
	/*
	 * One write per line, so several exporters appending to spools
	 * cannot interleave within a line; a short write is cut off
	 * again below, and replay ignores a final line without its
	 * newline in any case.
	 */
	line = malloc(len + 1);
	if (line == NULL) {
		close(fd);
		fprintf(stderr, "otlp: spool %s: out of memory; /%s batch "
		    "lost\n", o->spool_path, oe_enc_path(sig));
		return;
	}
	memcpy(line, body, len);
	line[len] = '\n';
	n = write(fd, line, len + 1);
	free(line);
	if (n != (ssize_t)(len + 1) || fsync(fd) != 0) {
		fprintf(stderr, "otlp: spool %s: write failed: %s; /%s "
		    "batch lost\n", o->spool_path, strerror(errno),
		    oe_enc_path(sig));
		(void)ftruncate(fd, (off_t)o->spool_size);
		close(fd);
		return;
	}
	close(fd);
	o->spool_size += len + 1;
	fprintf(stderr, "otlp: spooled /%s batch to %s (%ju bytes "
	    "pending)\n", oe_enc_path(sig), o->spool_path,
	    (uintmax_t)o->spool_size);
}

static char *
read_whole(const char *path, size_t *lenp)
{
	struct stat st;
	char *data;
	ssize_t n;
	size_t off;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (NULL);
	if (fstat(fd, &st) != 0 || (data = malloc((size_t)st.st_size +
	    1)) == NULL) {
		close(fd);
		return (NULL);
	}
	for (off = 0; off < (size_t)st.st_size; off += (size_t)n) {
		n = read(fd, data + off, (size_t)st.st_size - off);
		if (n <= 0)
			break;
	}
	close(fd);
	data[off] = '\0';
	*lenp = off;
	return (data);
}

/*
 * Keep only data[from..len) in the spool: write it to a temporary
 * sibling, fsync, and rename over the spool so a crash leaves
 * either the old or the new spool, never a mix.
 */
static int
spool_keep_tail(struct oe_otlp *o, const char *data, size_t from,
    size_t len)
{
	char tmp[PATH_MAX];
	int fd;

	if (from == len) {
		if (truncate(o->spool_path, 0) != 0)
			return (-1);
		o->spool_size = 0;
		return (0);
	}
	snprintf(tmp, sizeof(tmp), "%s.tmp", o->spool_path);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return (-1);
	if (write(fd, data + from, len - from) != (ssize_t)(len - from) ||
	    fsync(fd) != 0) {
		close(fd);
		unlink(tmp);
		return (-1);
	}
	close(fd);
	if (rename(tmp, o->spool_path) != 0) {
		unlink(tmp);
		return (-1);
	}
	o->spool_size = len - from;
	return (0);
}

/* Resend spooled requests, oldest first.  Takes spool_lock. */
static void
spool_replay(struct oe_otlp *o)
{
	char *data, *line, *nl;
	size_t len, done, sent;
	int sig;

	pthread_mutex_lock(&o->spool_lock);
	o->spool_last_try = time(NULL);
	/* Callers replay only a non-empty spool. */
	if ((data = read_whole(o->spool_path, &len)) == NULL) {
		pthread_mutex_unlock(&o->spool_lock);
		return;
	}
	done = 0;
	sent = 0;
	for (line = data; (nl = strchr(line, '\n')) != NULL; line = nl + 1) {
		/* Terminate the line only while it is examined. */
		*nl = '\0';
		sig = oe_enc_classify(line);
		if (sig < 0)
			fprintf(stderr, "otlp: spool %s: skipping a line that "
			    "is not an OTLP request\n", o->spool_path);
		else if (post_with_retry(o, (enum oe_signal)sig, line,
		    (size_t)(nl - line)) == POST_FAILED) {
			*nl = '\n';
			break;
		} else
			sent++;
		*nl = '\n';
		done = (size_t)(nl + 1 - data);
	}
	/* A trailing line without '\n' was an interrupted append. */
	if (nl == NULL)
		done = len;
	if (done > 0) {
		if (spool_keep_tail(o, data, done, len) != 0)
			fprintf(stderr, "otlp: spool %s: rewrite failed: %s; "
			    "replayed batches may be sent again\n",
			    o->spool_path, strerror(errno));
		else if (sent > 0)
			fprintf(stderr, "otlp: resent %zu spooled batch%s "
			    "from %s\n", sent, sent == 1 ? "" : "es",
			    o->spool_path);
		if (o->spool_size == 0 && o->spool_dropped > 0) {
			fprintf(stderr, "otlp: spool drained; %ju batch%s "
			    "dropped while it was full\n",
			    (uintmax_t)o->spool_dropped,
			    o->spool_dropped == 1 ? " was" : "es were");
			o->spool_dropped = 0;
		}
	}
	free(data);
	pthread_mutex_unlock(&o->spool_lock);
}

/* POST one request, spooling it on failure and replaying on success. */
static void
deliver(struct oe_otlp *o, enum oe_signal sig, const char *body, size_t len)
{

	switch (post_with_retry(o, sig, body, len)) {
	case POST_OK:
		if (o->spool_path != NULL && o->spool_size > 0)
			spool_replay(o);
		break;
	case POST_FAILED:
		if (o->spool_path != NULL) {
			pthread_mutex_lock(&o->spool_lock);
			spool_append(o, sig, body, len);
			pthread_mutex_unlock(&o->spool_lock);
		}
		break;
	case POST_REJECTED:
		break;
	}
}

/* ---------------------------------------------------------------- */
/* Batching and the sender thread				 	*/

/* Called with the lock held; takes every batch out of the object. */
static void
take_batches(struct oe_otlp *o, char **frags[], size_t nfrags[])
{
	int i;

	for (i = 0; i < OTLP_NSIGNALS; i++) {
		frags[i] = o->frags[i];
		nfrags[i] = o->nfrags[i];
		o->frags[i] = NULL;
		o->nfrags[i] = o->capfrags[i] = 0;
	}
}

/* Post taken batches.  Called without the lock. */
static void
post_batches(struct oe_otlp *o, char **frags[], size_t nfrags[])
{
	char *body;
	size_t len;
	int i;

	for (i = 0; i < OTLP_NSIGNALS; i++) {
		if (nfrags[i] > 0) {
			body = oe_enc_request(&o->enc, (enum oe_signal)i,
			    frags[i], nfrags[i], &len);
			if (body != NULL) {
				deliver(o, (enum oe_signal)i, body, len);
				free(body);
			}
		}
		oe_frags_free(frags[i], nfrags[i]);
	}
}

static void
enqueue_job(struct oe_otlp *o, enum oe_signal sig, char *body, size_t len)
{
	struct post_job *job;

	job = malloc(sizeof(*job));
	if (job == NULL) {
		free(body);
		return;
	}
	job->next = NULL;
	job->sig = sig;
	job->body = body;
	job->len = len;
	if (o->jobs_tail != NULL)
		o->jobs_tail->next = job;
	else
		o->jobs_head = job;
	o->jobs_tail = job;
	pthread_cond_signal(&o->cv);
}

static int
batches_empty(const size_t nfrags[])
{
	int i;

	for (i = 0; i < OTLP_NSIGNALS; i++)
		if (nfrags[i] > 0)
			return (0);
	return (1);
}

static void *
sender_main(void *arg)
{
	struct oe_otlp *o = arg;
	struct post_job *job;
	struct timespec deadline;
	char **frags[OTLP_NSIGNALS];
	size_t nfrags[OTLP_NSIGNALS];
	int i, timedout;

	pthread_mutex_lock(&o->lock);
	for (;;) {
		timedout = 0;
		while (o->jobs_head == NULL && !o->stop && !timedout) {
			clock_gettime(CLOCK_REALTIME, &deadline);
			deadline.tv_sec += (time_t)o->flush_interval;
			deadline.tv_nsec += (long)((o->flush_interval -
			    (double)(time_t)o->flush_interval) * 1e9);
			if (deadline.tv_nsec >= 1000000000L) {
				deadline.tv_sec++;
				deadline.tv_nsec -= 1000000000L;
			}
			if (pthread_cond_timedwait(&o->cv, &o->lock,
			    &deadline) != 0)
				timedout = 1;
		}

		if (timedout) {
			/* Time-based flush of whatever accumulated. */
			take_batches(o, frags, nfrags);
			pthread_mutex_unlock(&o->lock);
			if (!batches_empty(nfrags))
				post_batches(o, frags, nfrags);
			else {
				for (i = 0; i < OTLP_NSIGNALS; i++)
					oe_frags_free(frags[i], nfrags[i]);
				/* Idle: probe the collector for replay. */
				if (o->spool_path != NULL &&
				    o->spool_size > 0 && time(NULL) -
				    o->spool_last_try >= OTLP_SPOOL_RETRY)
					spool_replay(o);
			}
			pthread_mutex_lock(&o->lock);
			continue;
		}

		job = o->jobs_head;
		if (job != NULL) {
			o->jobs_head = job->next;
			if (o->jobs_head == NULL)
				o->jobs_tail = NULL;
			pthread_mutex_unlock(&o->lock);
			deliver(o, job->sig, job->body, job->len);
			free(job->body);
			free(job);
			pthread_mutex_lock(&o->lock);
			continue;
		}

		/* Only o->stop ends the wait without a job or timeout. */
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

	sigset_t all, saved;
	int error;

	if (o->started)
		return (0);
	/*
	 * The sender thread never takes signals: a tool that waits for
	 * them in a thread of its own (dtrace(1)) relies on every other
	 * thread blocking them, or SIGINT would kill the process.
	 */
	sigfillset(&all);
	pthread_sigmask(SIG_SETMASK, &all, &saved);
	error = pthread_create(&o->sender, NULL, sender_main, o);
	pthread_sigmask(SIG_SETMASK, &saved, NULL);
	if (error != 0) {
		fprintf(stderr, "otlp: failed to start sender thread\n");
		return (-1);
	}
	o->started = 1;
	return (0);
}

/*
 * Queue one record fragment.  With "batched", a full batch becomes a
 * request handed to the sender thread; otherwise the fragment waits
 * for the next time-based or explicit flush.
 */
static int
otlp_queue(struct oe_otlp *o, enum oe_signal sig, char *rec, int batched)
{
	char **frags;
	char *body;
	size_t nfrags, len;

	if (rec == NULL)
		return (-1);
	pthread_mutex_lock(&o->lock);
	if (oe_frags_append(&o->frags[sig], &o->nfrags[sig],
	    &o->capfrags[sig], rec) != 0) {
		pthread_mutex_unlock(&o->lock);
		free(rec);
		return (-1);
	}
	if (!batched || o->nfrags[sig] < (size_t)o->batch_size) {
		pthread_mutex_unlock(&o->lock);
		return (0);
	}
	/* Batch full: build the request and hand it to the sender. */
	frags = o->frags[sig];
	nfrags = o->nfrags[sig];
	o->frags[sig] = NULL;
	o->nfrags[sig] = o->capfrags[sig] = 0;
	body = oe_enc_request(&o->enc, sig, frags, nfrags, &len);
	if (body != NULL)
		enqueue_job(o, sig, body, len);
	pthread_mutex_unlock(&o->lock);
	oe_frags_free(frags, nfrags);
	return (0);
}

static int
otlp_event(struct oe_exporter *e, const struct oe_event *ev)
{
	struct oe_otlp *o = (struct oe_otlp *)e;

	if (ev->body == NULL || ev->body[0] == '\0')
		return (0);
	return (otlp_queue(o, OE_SIGNAL_LOGS, oe_enc_log_record(&o->enc, ev),
	    1));
}

static int
otlp_snapshot(struct oe_exporter *e, const struct oe_snapshot *sn)
{
	struct oe_otlp *o = (struct oe_otlp *)e;

	if (sn->npoints == 0)
		return (0);
	return (otlp_queue(o, OE_SIGNAL_METRICS, oe_enc_metric(&o->enc, sn),
	    0));
}

static int
otlp_span(struct oe_exporter *e, const struct oe_span *sp)
{
	struct oe_otlp *o = (struct oe_otlp *)e;

	return (otlp_queue(o, OE_SIGNAL_TRACES, oe_enc_span(&o->enc, sp), 1));
}

static int
otlp_flush(struct oe_exporter *e)
{
	struct oe_otlp *o = (struct oe_otlp *)e;
	char **frags[OTLP_NSIGNALS];
	size_t nfrags[OTLP_NSIGNALS];

	pthread_mutex_lock(&o->lock);
	take_batches(o, frags, nfrags);
	pthread_mutex_unlock(&o->lock);
	post_batches(o, frags, nfrags);
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
	for (i = 0; i < OTLP_NSIGNALS; i++)
		oe_frags_free(o->frags[i], o->nfrags[i]);
	for (i = 0; i < o->nheaders; i++) {
		free(__DECONST(char *, o->headers[i].name));
		free(__DECONST(char *, o->headers[i].value));
	}
	oe_otlppb_free(o->pb);
	free(o->headers);
	free(o->spool_path);
	if (o->spool_lockfd >= 0)
		close(o->spool_lockfd);
	oe_enc_fini(&o->enc);
	pthread_mutex_destroy(&o->lock);
	pthread_mutex_destroy(&o->spool_lock);
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
	.span = otlp_span,
};

static int
spool_open(struct oe_otlp *o, const struct oe_otlp_config *cfg)
{
	struct stat st;
	char lock[PATH_MAX];
	int fd, lfd;

	o->spool_max = cfg->spool_max > 0 ? cfg->spool_max :
	    OTLP_DEFAULT_SPOOL;
	/* Room for the ".lock" and ".tmp" siblings. */
	if (strlen(cfg->spool_path) + 6 > PATH_MAX) {
		fprintf(stderr, "otlp: spool %s: path too long\n",
		    cfg->spool_path);
		return (-1);
	}
	/*
	 * One exporter per spool: replay rewrites the file, so two
	 * processes sharing it would lose each other's batches.  The
	 * lock lives on a sibling because replay renames over the spool.
	 */
	snprintf(lock, sizeof(lock), "%s.lock", cfg->spool_path);
	lfd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC | O_EXLOCK | O_NONBLOCK,
	    0600);
	if (lfd < 0) {
		if (errno == EWOULDBLOCK)
			fprintf(stderr, "otlp: spool %s is in use by another "
			    "exporter\n", cfg->spool_path);
		else
			fprintf(stderr, "otlp: spool %s: open failed: %s\n",
			    lock, strerror(errno));
		return (-1);
	}
	/*
	 * Create (or adopt) the spool now so a bad path fails before
	 * tracing starts rather than during the first outage.  A spool
	 * left by an earlier run is replayed like any other backlog.
	 */
	fd = open(cfg->spool_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
	    0600);
	if (fd < 0) {
		fprintf(stderr, "otlp: spool %s: open failed: %s\n",
		    cfg->spool_path, strerror(errno));
		close(lfd);
		return (-1);
	}
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		fprintf(stderr, "otlp: spool %s: not a regular file\n",
		    cfg->spool_path);
		close(fd);
		close(lfd);
		return (-1);
	}
	close(fd);
	o->spool_path = strdup(cfg->spool_path);
	if (o->spool_path == NULL) {
		close(lfd);
		return (-1);
	}
	o->spool_size = (uint64_t)st.st_size;
	o->spool_lockfd = lfd;
	return (0);
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
	o->spool_lockfd = -1;
	pthread_mutex_init(&o->lock, NULL);
	pthread_mutex_init(&o->spool_lock, NULL);
	pthread_cond_init(&o->cv, NULL);
	if (oe_url_parse(cfg->endpoint, &o->url) != 0) {
		fprintf(stderr, "otlp: invalid endpoint URL '%s'\n",
		    cfg->endpoint);
		otlp_free(&o->e);
		return (NULL);
	}
	if (oe_enc_init(&o->enc, r, cfg->scope_name) != 0)
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
			o->nheaders = i + 1;
			if (o->headers[i].name == NULL ||
			    o->headers[i].value == NULL)
				goto fail;
		}
	}
	if (oe_otlppb_open(cfg->protocol, &o->url, o->headers, o->nheaders,
	    o->user_agent, o->timeout_ms, o->max_retries, o->use_gzip,
	    &o->pb) != 0) {
		otlp_free(&o->e);
		return (NULL);
	}
	if (cfg->spool_path != NULL && spool_open(o, cfg) != 0) {
		if (!cfg->spool_optional) {
			otlp_free(&o->e);
			return (NULL);
		}
		fprintf(stderr, "otlp: continuing without a spool\n");
	}
	return (&o->e);

fail:
	fprintf(stderr, "otlp: out of memory\n");
	otlp_free(&o->e);
	return (NULL);
}
