/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libdtotel session and buffered-output handling; see dtotel.h.
 *
 * libdtrace calls the buffered handler synchronously from
 * dtrace_work() for every printf/printa/stack output chunk instead of
 * writing to a FILE.  Aggregation fragments are skipped here (they
 * are exported as typed metrics by dtotel_aggregate()).  Chunks are
 * grouped by probe firing (CPU, high resolution timestamp, enabled
 * probe id): every text line starts a log record, and the stack
 * frames that follow it from the same firing attach to it.
 *
 * Structured records.  A chunk whose text starts with
 * DTOTEL_RECORD_PREFIX ("\037otel.") is a structured record, never a
 * log line.  Its fields are "\037"-separated key=value pairs:
 *
 *	\037otel.clock\037wall=<walltimestamp>\037ts=<timestamp>
 *		probe clock anchor (see dtotel_clock_program())
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <dtrace.h>

#include "dtotel_impl.h"

#define	USTACK_MARKER	"__BSDINSTRUMENTS_USTACK__"
#define	FIELD_SEP	'\037'

static const char clock_program[] =
    "dtrace:::BEGIN\n"
    "{\n"
    "\tprintf(\"\\037otel.clock\\037wall=%d\\037ts=%u\\n\",\n"
    "\t    walltimestamp, timestamp);\n"
    "}\n"
    "\n"
    "profile:::tick-1s\n"
    "{\n"
    "\tprintf(\"\\037otel.clock\\037wall=%d\\037ts=%u\\n\",\n"
    "\t    walltimestamp, timestamp);\n"
    "}\n";

const char *
dtotel_clock_program(void)
{

	return (clock_program);
}

/* ---------------------------------------------------------------- */
/* Session								*/

struct dtotel *
dtotel_open(const struct dtotel_config *cfg)
{
	struct dtotel *d;

	d = calloc(1, sizeof(*d));
	if (d == NULL)
		return (NULL);
	d->dtp = cfg->dtp;
	d->exporter = cfg->exporter;
	d->profile = strdup(cfg->profile != NULL ? cfg->profile : "");
	if (d->profile == NULL) {
		free(d);
		return (NULL);
	}
	/*
	 * Aggregation key names come from the source so data points
	 * get semantic attribute names instead of key.N.
	 */
	if (cfg->source != NULL)
		d->keynames = dtotel_parse_keynames(cfg->source);
	clock_gettime(CLOCK_REALTIME, &d->start);
	return (d);
}

static void
frames_free(struct dtotel_frames *fa)
{
	size_t i;

	for (i = 0; i < fa->n; i++) {
		free(fa->frames[i].module);
		free(fa->frames[i].symbol);
	}
	free(fa->frames);
	fa->frames = NULL;
	fa->n = fa->cap = 0;
}

void
dtotel_close(struct dtotel *d)
{

	if (d == NULL)
		return;
	free(d->body);
	free(d->probe);
	frames_free(&d->kstack);
	frames_free(&d->ustack);
	dtotel_free_keynames(d->keynames);
	free(d->profile);
	free(d);
}

int
dtotel_handle(struct dtotel *d)
{

	if (dtrace_handle_buffered(d->dtp, dtotel_buffered, d) != 0) {
		fprintf(stderr, "dtotel: failed to install buffered handler: "
		    "%s\n", dtrace_errmsg(d->dtp, dtrace_errno(d->dtp)));
		return (-1);
	}
	return (0);
}

void
dtotel_started(struct dtotel *d)
{

	clock_gettime(CLOCK_REALTIME, &d->start);
}

void
dtotel_drops(struct dtotel *d, uint64_t n)
{

	oe_report_drops(d->exporter, n);
}

int
dtotel_error(const struct dtotel *d)
{

	return (d->error);
}

/* ---------------------------------------------------------------- */
/* Stack frames							 	*/

/*
 * Parse one DTrace stack frame line:
 *   module`symbol+0xoffset
 *   symbol+0xoffset
 *   0xdeadbeef
 */
static void
parse_stack_frame(const char *line, struct oe_frame *f)
{
	const char *bt, *plus;

	memset(f, 0, sizeof(*f));
	bt = strchr(line, '`');
	if (bt != NULL) {
		f->module = strndup(line, (size_t)(bt - line));
		plus = strrchr(bt + 1, '+');
		if (plus != NULL && strncmp(plus + 1, "0x", 2) == 0) {
			f->symbol = strndup(bt + 1,
			    (size_t)(plus - (bt + 1)));
			f->offset = strtoull(plus + 3, NULL, 16);
			f->has_offset = 1;
		} else
			f->symbol = strdup(bt + 1);
		return;
	}
	if (strncmp(line, "0x", 2) == 0) {
		f->addr = strtoull(line + 2, NULL, 16);
		return;
	}
	f->symbol = strdup(line);
}

static void
frames_push(struct dtotel_frames *fa, const char *line)
{
	struct oe_frame *np;
	size_t newcap;

	if (fa->n == fa->cap) {
		newcap = fa->cap == 0 ? 16 : fa->cap * 2;
		np = realloc(fa->frames, newcap * sizeof(*np));
		if (np == NULL)
			return;
		fa->frames = np;
		fa->cap = newcap;
	}
	parse_stack_frame(line, &fa->frames[fa->n]);
	fa->n++;
}

/* ---------------------------------------------------------------- */
/* Events								*/

/*
 * Best-effort execname/pid extraction from the printf body.  Most
 * profiles format as "execname[pid/...]: ...".
 */
static void
parse_body_metadata(const char *body, char *execname, size_t execlen,
    pid_t *pid)
{
	const char *bracket, *p;

	execname[0] = '\0';
	*pid = 0;
	bracket = strchr(body, '[');
	if (bracket == NULL)
		return;
	if ((size_t)(bracket - body) < execlen) {
		memcpy(execname, body, (size_t)(bracket - body));
		execname[bracket - body] = '\0';
	}
	for (p = bracket + 1; isdigit((unsigned char)*p); p++)
		*pid = *pid * 10 + (*p - '0');
}

void
dtotel_flush(struct dtotel *d)
{
	struct oe_event ev;
	char execname[MAXCOMLEN + 1];
	pid_t pid;

	if (d->body == NULL)
		return;
	parse_body_metadata(d->body, execname, sizeof(execname), &pid);
	memset(&ev, 0, sizeof(ev));
	ev.ts = d->body_ts;
	ev.observed = d->body_observed;
	ev.profile = d->profile;
	ev.probe = d->probe != NULL ? d->probe : "";
	ev.pid = pid;
	ev.execname = execname;
	ev.body = d->body;
	ev.stack = d->kstack.frames;
	ev.nstack = d->kstack.n;
	ev.ustack = d->ustack.frames;
	ev.nustack = d->ustack.n;
	if (oe_event(d->exporter, &ev) != 0)
		d->error = 1;
	free(d->body);
	d->body = NULL;
	free(d->probe);
	d->probe = NULL;
	frames_free(&d->kstack);
	frames_free(&d->ustack);
	d->in_ustack = 0;
}

static void
firing_of(const dtrace_bufdata_t *bd, struct dtotel_firing *f)
{
	const dtrace_probedata_t *pd = bd->dtbda_probe;

	memset(f, 0, sizeof(*f));
	if (pd == NULL)
		return;
	f->valid = 1;
	f->cpu = pd->dtpda_cpu;
	f->hrtime = pd->dtpda_timestamp;
	f->epid = pd->dtpda_edesc != NULL ? pd->dtpda_edesc->dtepd_epid : 0;
}

static int
same_firing(const struct dtotel_firing *a, const struct dtotel_firing *b)
{

	return (a->valid && b->valid && a->cpu == b->cpu &&
	    a->hrtime == b->hrtime && a->epid == b->epid);
}

/*
 * The probe's wall time: its high resolution timestamp moved onto the
 * wall clock by the latest anchor, or the consumer's clock when no
 * anchor (or no probe data) is available yet.
 */
static void
probe_walltime(const struct dtotel *d, const struct dtotel_firing *f,
    const struct timespec *observed, struct timespec *ts)
{
	int64_t ns;

	if (!d->anchored || !f->valid) {
		*ts = *observed;
		return;
	}
	ns = (int64_t)f->hrtime + d->clock_offset;
	ts->tv_sec = (time_t)(ns / 1000000000);
	ts->tv_nsec = (long)(ns % 1000000000);
}

static char *
probe_name(const dtrace_bufdata_t *bd)
{
	const dtrace_probedesc_t *pd;
	char buf[DTRACE_FULLNAMELEN];

	if (bd->dtbda_probe == NULL || bd->dtbda_probe->dtpda_pdesc == NULL)
		return (NULL);
	pd = bd->dtbda_probe->dtpda_pdesc;
	snprintf(buf, sizeof(buf), "%s:%s:%s:%s", pd->dtpd_provider,
	    pd->dtpd_mod, pd->dtpd_func, pd->dtpd_name);
	return (strdup(buf));
}

/* Flush the pending event and start a new one for this firing. */
static void
start_event(struct dtotel *d, const dtrace_bufdata_t *bd,
    const struct dtotel_firing *firing, const struct timespec *observed,
    const char *text, size_t len)
{

	dtotel_flush(d);
	d->body = strndup(text, len);
	d->probe = probe_name(bd);
	d->body_firing = *firing;
	d->body_observed = *observed;
	probe_walltime(d, firing, observed, &d->body_ts);
}

/* ---------------------------------------------------------------- */
/* Structured records						 	*/

/*
 * Find "key=" among the separator-delimited fields of a record and
 * return a pointer to its value (ending at the next separator or
 * NUL), or NULL.
 */
static const char *
rec_field(const char *rec, const char *key, size_t *lenp)
{
	const char *p, *end;
	size_t klen = strlen(key);

	for (p = strchr(rec, FIELD_SEP); p != NULL;
	    p = strchr(p + 1, FIELD_SEP)) {
		if (strncmp(p + 1, key, klen) != 0 || p[1 + klen] != '=')
			continue;
		p += klen + 2;
		end = strchr(p, FIELD_SEP);
		*lenp = end != NULL ? (size_t)(end - p) : strlen(p);
		return (p);
	}
	return (NULL);
}

static int
rec_int(const char *rec, const char *key, int64_t *v)
{
	const char *p;
	char buf[32], *end;
	size_t len;

	p = rec_field(rec, key, &len);
	if (p == NULL || len == 0 || len >= sizeof(buf))
		return (-1);
	memcpy(buf, p, len);
	buf[len] = '\0';
	errno = 0;
	*v = strtoll(buf, &end, 10);
	return (*end == '\0' && errno == 0 ? 0 : -1);
}

static void
handle_clock(struct dtotel *d, const char *rec)
{
	int64_t wall, ts;

	if (rec_int(rec, "wall", &wall) != 0 || rec_int(rec, "ts", &ts) != 0) {
		fprintf(stderr, "dtotel: malformed clock record ignored\n");
		return;
	}
	d->clock_offset = wall - ts;
	d->anchored = 1;
}

static void
handle_record(struct dtotel *d, const char *rec)
{
	const char *kind = rec + strlen(DTOTEL_RECORD_PREFIX);

	if (strncmp(kind, "clock\037", 6) == 0)
		handle_clock(d, rec);
	else
		fprintf(stderr, "dtotel: unknown structured record \"%.*s\" "
		    "ignored\n", (int)strcspn(kind, "\037\n"), kind);
}

/* ---------------------------------------------------------------- */
/* Buffered handler							*/

int
dtotel_buffered(const dtrace_bufdata_t *bufdata, void *arg)
{
	struct dtotel *d = arg;
	struct dtotel_firing firing;
	struct timespec observed;
	const char *chunk, *line, *nl, *trimmed;
	char *linebuf, *rec;
	size_t linelen, tlen;
	int is_stack_frame;

	if (bufdata->dtbda_flags & (DTRACE_BUFDATA_AGGKEY |
	    DTRACE_BUFDATA_AGGVAL | DTRACE_BUFDATA_AGGFORMAT |
	    DTRACE_BUFDATA_AGGLAST))
		return (DTRACE_HANDLE_OK);

	chunk = bufdata->dtbda_buffered;
	if (chunk == NULL)
		return (DTRACE_HANDLE_OK);
	firing_of(bufdata, &firing);
	clock_gettime(CLOCK_REALTIME, &observed);

	if (strncmp(chunk, DTOTEL_RECORD_PREFIX,
	    sizeof(DTOTEL_RECORD_PREFIX) - 1) == 0) {
		/* One record per chunk; strip the trailing newline. */
		rec = strndup(chunk, strcspn(chunk, "\n"));
		if (rec != NULL) {
			handle_record(d, rec);
			free(rec);
		}
		return (d->error ? DTRACE_HANDLE_ABORT : DTRACE_HANDLE_OK);
	}

	for (line = chunk; *line != '\0'; line = nl + 1) {
		nl = strchr(line, '\n');
		linelen = nl != NULL ? (size_t)(nl - line) : strlen(line);
		linebuf = strndup(line, linelen);
		if (linebuf == NULL)
			break;

		/* Trim for emptiness/marker checks. */
		trimmed = linebuf;
		while (isspace((unsigned char)*trimmed))
			trimmed++;
		tlen = strlen(trimmed);
		while (tlen > 0 && isspace((unsigned char)trimmed[tlen - 1]))
			tlen--;

		if (tlen == 0) {
			free(linebuf);
			if (nl == NULL)
				break;
			continue;
		}

		is_stack_frame = isspace((unsigned char)linebuf[0]) &&
		    (memchr(trimmed, '`', tlen) != NULL ||
		    strncmp(trimmed, "0x", 2) == 0);

		if (is_stack_frame) {
			char frameline[512];

			/*
			 * Frames belong to the line printed by the same
			 * firing.  A firing that printed no line of its
			 * own becomes a stack-only event (empty body):
			 * the collapsed exporter folds it, the others
			 * skip it.
			 */
			if (d->body == NULL || (firing.valid &&
			    d->body_firing.valid &&
			    !same_firing(&firing, &d->body_firing)))
				start_event(d, bufdata, &firing, &observed,
				    "", 0);
			if (tlen >= sizeof(frameline))
				tlen = sizeof(frameline) - 1;
			memcpy(frameline, trimmed, tlen);
			frameline[tlen] = '\0';
			frames_push(d->in_ustack ? &d->ustack : &d->kstack,
			    frameline);
		} else if (tlen == strlen(USTACK_MARKER) &&
		    strncmp(trimmed, USTACK_MARKER, tlen) == 0) {
			/* Marker between stack() and ustack() output. */
			d->in_ustack = 1;
		} else {
			/* New event: flush pending, start accumulating. */
			start_event(d, bufdata, &firing, &observed, trimmed,
			    tlen);
		}
		free(linebuf);
		if (nl == NULL)
			break;
	}

	return (d->error ? DTRACE_HANDLE_ABORT : DTRACE_HANDLE_OK);
}
