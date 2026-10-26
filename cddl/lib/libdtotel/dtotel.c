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
 * frames that follow it from the same firing attach to it.  Output
 * that continues a line the same firing left open (successive
 * trace() records, a printf without a newline) joins that line.
 *
 * Structured records.  A chunk whose text starts with
 * DTOTEL_RECORD_PREFIX ("\037otel.") is a structured record, never a
 * log line.  Its fields are "\037"-separated key=value pairs:
 *
 *	\037otel.clock\037wall=<walltimestamp>\037ts=<timestamp>
 *		probe clock anchor (see dtotel_clock_program())
 *
 *	\037otel.ctx\037pid=..\037ppid=..\037tid=..\037uid=..\037ruid=..
 *	    \037gid=..\037rgid=..\037jid=..\037execname=<s>
 *		who fired the probe; attached to the log record printed
 *		by the same firing (before or after it), and exported
 *		under semantic-convention names (process.*, thread.id,
 *		cpu.logical_number, container.* for a jail).
 *
 *	\037otel.span\037name=<s>\037start=<ts>\037end=<ts>[...]
 *		one finished span.  Required: name, start and end (D
 *		"timestamp" values; start 0 means the span never
 *		started and the record is dropped).  Optional:
 *		thread, span, parent, trace (integer keys, see below),
 *		error (non-zero sets status ERROR), kind (internal,
 *		server, client, producer, consumer), pid, execname,
 *		the context fields above, and attributes
 *		a.i.<key>=<integer>, a.s.<key>=<string>.
 *
 *	\037otel.resource\037<key>=<value>[...]
 *		resource attributes of a HyperTrace guest (for example
 *		host.name), printed by one of its probes; they join
 *		the guest's resource.  Ignored for host probes, whose
 *		resource the consumer fixes.
 *
 * Span identity.  Ids are derived from integer keys the D program
 * already has, hashed with a per-session secret salt
 * (oe_id_derive()), so a child can name its parent without shared
 * state: span id = H(thread, span), where "span" defaults to the
 * start timestamp and "thread" to 0 (bsdinstruments passes tid);
 * parent span id = H(thread, parent); trace id = H(thread, trace),
 * where "trace" defaults to "parent" for a child and to "span" for a
 * root.  A two-level parent/child pair thus needs only parent=<the
 * parent's start>; deeper trees pass trace= explicitly.
 */

#include <sys/param.h>

#include <ctype.h>
#include <errno.h>
#include <jail.h>
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
    "profile:::tick-1sec\n"
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
	d->guest_exporter = cfg->guest_exporter;
	d->guest_arg = cfg->guest_arg;
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
	arc4random_buf(d->salt, sizeof(d->salt));
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
	int i;

	if (d == NULL)
		return;
	free(d->body);
	free(d->probe);
	free(d->body_exec);
	free(d->ctx_exec);
	frames_free(&d->kstack);
	frames_free(&d->ustack);
	dtotel_free_keynames(d->keynames);
	for (i = 0; i < d->njails; i++)
		free(d->jails[i].name);
	(void)dtotel_shutdown(d);
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
	memset(&ev, 0, sizeof(ev));
	if (d->body_exec != NULL) {
		/* A context record says exactly who fired. */
		ev.pid = d->body_pid;
		ev.execname = d->body_exec;
		ev.ctx = d->body_ctx;
	} else {
		parse_body_metadata(d->body, execname, sizeof(execname),
		    &pid);
		ev.pid = pid;
		ev.execname = execname;
		ev.ctx.flags = d->body_ctx.flags & OE_CTX_CPU;
		ev.ctx.cpu = d->body_ctx.cpu;
	}
	ev.ts = d->body_ts;
	ev.observed = d->body_observed;
	ev.profile = d->profile;
	ev.probe = d->probe != NULL ? d->probe : "";
	ev.body = d->body;
	ev.stack = d->kstack.frames;
	ev.nstack = d->kstack.n;
	ev.ustack = d->ustack.frames;
	ev.nustack = d->ustack.n;
	if (oe_event(dtotel_exporter_for(d, d->body_vmid, NULL), &ev) != 0)
		d->error = 1;
	free(d->body);
	d->body = NULL;
	free(d->probe);
	d->probe = NULL;
	free(d->body_exec);
	d->body_exec = NULL;
	memset(&d->body_ctx, 0, sizeof(d->body_ctx));
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

/* The VMID of the probe behind a record: 0 for the host. */
static uint16_t
record_vmid(const dtrace_bufdata_t *bd, const char **target)
{
	const dtrace_probedata_t *pd = bd->dtbda_probe;

	*target = NULL;
	if (pd == NULL)
		return (0);
	if (pd->dtpda_pdesc != NULL && pd->dtpda_pdesc->dtpd_target[0] != '\0')
		*target = pd->dtpda_pdesc->dtpd_target;
	if (pd->dtpda_edesc != NULL && pd->dtpda_edesc->dtepd_vmid != 0)
		return (pd->dtpda_edesc->dtepd_vmid);
	return (pd->dtpda_pdesc != NULL ? pd->dtpda_pdesc->dtpd_vmid : 0);
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

static void start_event(struct dtotel *, const dtrace_bufdata_t *,
    const struct dtotel_firing *, const struct timespec *, const char *,
    size_t);

static void
append_body(struct dtotel *d, const char *text, size_t len)
{
	char *nb;
	size_t blen = strlen(d->body);

	nb = realloc(d->body, blen + len + 2);
	if (nb == NULL)
		return;
	nb[blen] = ' ';
	memcpy(nb + blen + 1, text, len);
	nb[blen + 1 + len] = '\0';
	d->body = nb;
}

void
dtotel_firing_end(struct dtotel *d, const dtrace_probedata_t *pd, int quiet)
{
	struct dtotel_firing firing;
	dtrace_bufdata_t bd;
	struct timespec observed;
	char *name;

	memset(&bd, 0, sizeof(bd));
	bd.dtbda_probe = __DECONST(dtrace_probedata_t *, pd);
	firing_of(&bd, &firing);
	if (quiet || same_firing(&firing, &d->out_firing))
		return;
	/* A firing that printed nothing: name its probe. */
	clock_gettime(CLOCK_REALTIME, &observed);
	name = probe_name(&bd);
	if (name == NULL)
		return;
	start_event(d, &bd, &firing, &observed, name, strlen(name));
	free(name);
	d->out_firing = firing;
	d->line_open = 0;
}

/* Flush the pending event and start a new one for this firing. */
static void
start_event(struct dtotel *d, const dtrace_bufdata_t *bd,
    const struct dtotel_firing *firing, const struct timespec *observed,
    const char *text, size_t len)
{

	const char *target;

	dtotel_flush(d);
	d->body = strndup(text, len);
	d->probe = probe_name(bd);
	d->body_vmid = record_vmid(bd, &target);
	if (d->body_vmid != 0)
		(void)dtotel_exporter_for(d, d->body_vmid, target);
	d->body_firing = *firing;
	d->body_observed = *observed;
	probe_walltime(d, firing, observed, &d->body_ts);
	if (firing->valid) {
		d->body_ctx.flags = OE_CTX_CPU;
		d->body_ctx.cpu = firing->cpu;
	}
	/* Adopt a context record this firing printed first. */
	if (d->ctx_exec != NULL && same_firing(firing, &d->ctx_firing)) {
		d->body_ctx = d->ctx;
		d->body_pid = d->ctx_pid;
		d->body_exec = d->ctx_exec;
		d->ctx_exec = NULL;
	}
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

static int
parse_int(const char *s, int64_t *v)
{
	char *end;

	if (*s == '\0')
		return (-1);
	errno = 0;
	*v = strtoll(s, &end, 10);
	return (*end == '\0' && errno == 0 ? 0 : -1);
}

const char *
dtotel_jail_name(struct dtotel *d, int jid)
{
	struct dtotel_jail *j;
	int i;

	for (i = 0; i < d->njails; i++)
		if (d->jails[i].jid == jid)
			return (d->jails[i].name);
	/* Full cache: look up without remembering. */
	if (d->njails == DTOTEL_JAIL_CACHE) {
		free(d->jails[0].name);
		memmove(&d->jails[0], &d->jails[1],
		    (DTOTEL_JAIL_CACHE - 1) * sizeof(d->jails[0]));
		d->njails--;
	}
	j = &d->jails[d->njails++];
	j->jid = jid;
	j->name = jail_getname(jid);
	return (j->name);
}

/*
 * Parse the context fields of a record into ctx/pid/execname.  The
 * process fields count only when all of them are present (they come
 * from one printf); returns 1 then, 0 if absent, -1 if malformed.
 */
static int
parse_context(struct dtotel *d, char *field, const char *key,
    const char *val, struct oe_context *ctx, int64_t *seen)
{
	static const struct {
		const char *key;
		unsigned flag;
	} fields[] = {
		{ "ppid", OE_CTX_PPID }, { "tid", OE_CTX_TID },
		{ "uid", OE_CTX_UID }, { "ruid", OE_CTX_RUID },
		{ "gid", OE_CTX_GID }, { "rgid", OE_CTX_RGID },
		{ "jid", OE_CTX_JAIL },
	};
	int64_t v;
	size_t i;
	char *end;

	(void)field;
	for (i = 0; i < nitems(fields); i++)
		if (strcmp(key, fields[i].key) == 0)
			break;
	if (i == nitems(fields))
		return (0);
	errno = 0;
	v = strtoll(val, &end, 10);
	if (*val == '\0' || *end != '\0' || errno != 0)
		return (-1);
	switch (fields[i].flag) {
	case OE_CTX_PPID:
		ctx->ppid = (pid_t)v;
		break;
	case OE_CTX_TID:
		ctx->tid = v;
		break;
	case OE_CTX_UID:
		ctx->uid = (uid_t)v;
		break;
	case OE_CTX_RUID:
		ctx->ruid = (uid_t)v;
		break;
	case OE_CTX_GID:
		ctx->gid = (gid_t)v;
		break;
	case OE_CTX_RGID:
		ctx->rgid = (gid_t)v;
		break;
	case OE_CTX_JAIL:
		ctx->jid = (int)v;
		if (v != 0)
			ctx->jail_name = dtotel_jail_name(d, (int)v);
		break;
	}
	ctx->flags |= fields[i].flag;
	*seen |= (int64_t)fields[i].flag;
	return (1);
}

/*
 * The context fields a ctx record must carry, and the process part of
 * them a span carries when it belongs to the probe's own process.
 */
#define	CTX_ALL	(OE_CTX_PPID | OE_CTX_TID | OE_CTX_UID | OE_CTX_RUID | \
	OE_CTX_GID | OE_CTX_RGID | OE_CTX_JAIL)
#define	PROC_CTX	(CTX_ALL & ~OE_CTX_TID)

static void
handle_ctx(struct dtotel *d, char *rec, const struct dtotel_firing *firing)
{
	struct oe_context ctx;
	char *field, *next, *eq, *exec;
	int64_t seen, pid, v;
	int have_pid;

	memset(&ctx, 0, sizeof(ctx));
	exec = NULL;
	seen = 0;
	pid = 0;
	have_pid = 0;
	for (field = strchr(rec + strlen(DTOTEL_RECORD_PREFIX), FIELD_SEP);
	    field != NULL; field = next) {
		*field++ = '\0';
		next = strchr(field, FIELD_SEP);
		if (next != NULL)
			*next = '\0';
		eq = strchr(field, '=');
		if (eq == NULL)
			goto bad;
		*eq++ = '\0';
		if (strcmp(field, "execname") == 0)
			exec = eq;
		else if (strcmp(field, "pid") == 0) {
			if (parse_int(eq, &v) != 0)
				goto bad;
			pid = v;
			have_pid = 1;
		} else if (parse_context(d, field, field, eq, &ctx, &seen) < 0)
			goto bad;
	}
	if (exec == NULL || !have_pid || (seen & CTX_ALL) != CTX_ALL)
		goto bad;
	ctx.flags |= OE_CTX_PID;
	if (firing->valid) {
		ctx.flags |= OE_CTX_CPU;
		ctx.cpu = firing->cpu;
	}
	if (d->body != NULL && same_firing(firing, &d->body_firing)) {
		/* The line this firing printed is still pending. */
		free(d->body_exec);
		d->body_exec = strdup(exec);
		d->body_pid = (pid_t)pid;
		d->body_ctx = ctx;
		return;
	}
	/* Keep it for the line this firing has yet to print. */
	free(d->ctx_exec);
	d->ctx_exec = strdup(exec);
	d->ctx_pid = (pid_t)pid;
	d->ctx = ctx;
	d->ctx_firing = *firing;
	return;
bad:
	fprintf(stderr, "dtotel: malformed context record ignored\n");
}

#define	SPAN_MAX_ATTRS	16

static enum oe_span_kind
span_kind(const char *s)
{

	if (strcmp(s, "server") == 0)
		return (OE_SPAN_SERVER);
	if (strcmp(s, "client") == 0)
		return (OE_SPAN_CLIENT);
	if (strcmp(s, "producer") == 0)
		return (OE_SPAN_PRODUCER);
	if (strcmp(s, "consumer") == 0)
		return (OE_SPAN_CONSUMER);
	return (OE_SPAN_INTERNAL);
}

static void
ns_to_ts(int64_t ns, struct timespec *ts)
{

	ts->tv_sec = (time_t)(ns / 1000000000);
	ts->tv_nsec = (long)(ns % 1000000000);
}

/*
 * One span record.  "rec" is a private copy: fields are split in
 * place at the separators.
 */
static void
handle_span(struct dtotel *d, char *rec, const dtrace_bufdata_t *bd,
    const struct timespec *observed)
{
	struct oe_kv attrs[SPAN_MAX_ATTRS];
	struct oe_span sp;
	const char *name, *kind, *execname;
	char *field, *next, *eq, msg[48], *probe;
	struct oe_context ctx;
	int64_t start, end, thread, spankey, parent, trace, err, pid, v,
	    key[2], seen;
	int have_start, have_end, have_span, have_parent, have_trace, rc,
	    have_pid, have_thread;
	size_t nattrs;

	name = kind = execname = NULL;
	start = end = thread = spankey = parent = trace = err = pid = 0;
	have_start = have_end = have_span = have_parent = have_trace = 0;
	have_pid = have_thread = 0;
	nattrs = 0;
	seen = 0;
	memset(&ctx, 0, sizeof(ctx));
	/* Fields follow the "\037otel.span" kind tag. */
	for (field = strchr(rec + strlen(DTOTEL_RECORD_PREFIX), FIELD_SEP);
	    field != NULL; field = next) {
		*field++ = '\0';
		next = strchr(field, FIELD_SEP);
		if (next != NULL)
			*next = '\0';
		eq = strchr(field, '=');
		if (eq == NULL)
			goto bad;
		*eq++ = '\0';
		if (strcmp(field, "name") == 0)
			name = eq;
		else if (strcmp(field, "kind") == 0)
			kind = eq;
		else if (strcmp(field, "execname") == 0)
			execname = eq;
		else if (strncmp(field, "a.s.", 4) == 0 && field[4] != '\0') {
			if (nattrs < SPAN_MAX_ATTRS) {
				attrs[nattrs].key = field + 4;
				attrs[nattrs].type = OE_VAL_STRING;
				attrs[nattrs++].s = eq;
			}
		} else if ((rc = parse_context(d, field, field, eq, &ctx,
		    &seen)) != 0) {
			if (rc < 0)
				goto bad;
		} else if (parse_int(eq, &v) != 0)
			goto bad;
		else if (strcmp(field, "start") == 0) {
			start = v;
			have_start = 1;
		} else if (strcmp(field, "end") == 0) {
			end = v;
			have_end = 1;
		} else if (strcmp(field, "thread") == 0) {
			thread = v;
			have_thread = 1;
		}
		else if (strcmp(field, "span") == 0) {
			spankey = v;
			have_span = 1;
		} else if (strcmp(field, "parent") == 0) {
			parent = v;
			have_parent = 1;
		} else if (strcmp(field, "trace") == 0) {
			trace = v;
			have_trace = 1;
		} else if (strcmp(field, "error") == 0)
			err = v;
		else if (strcmp(field, "pid") == 0) {
			pid = v;
			have_pid = 1;
		}
		else if (strncmp(field, "a.i.", 4) == 0 && field[4] != '\0' &&
		    nattrs < SPAN_MAX_ATTRS) {
			attrs[nattrs].key = field + 4;
			attrs[nattrs].type = OE_VAL_INT;
			attrs[nattrs++].i = v;
		}
		/*
		 * Unknown integer fields (newer producers) and attributes
		 * beyond SPAN_MAX_ATTRS are ignored.
		 */
	}
	if (name == NULL || name[0] == '\0' || !have_start || !have_end ||
	    end < start)
		goto bad;
	if (start <= 0) {
		/* The D side never saw the start of this span. */
		return;
	}

	memset(&sp, 0, sizeof(sp));
	sp.name = name;
	sp.profile = d->profile;
	probe = probe_name(bd);
	sp.probe = probe != NULL ? probe : "";
	if (d->anchored) {
		ns_to_ts(start + d->clock_offset, &sp.start);
		ns_to_ts(end + d->clock_offset, &sp.end);
	} else {
		/* Unanchored: end when read, true duration kept. */
		sp.end = *observed;
		ns_to_ts((int64_t)observed->tv_sec * 1000000000 +
		    observed->tv_nsec - (end - start), &sp.start);
	}
	if (!have_span)
		spankey = start;
	key[0] = thread;
	key[1] = spankey;
	oe_id_derive(d->salt, "span", key, 2, sp.span_id, OE_SPAN_ID_LEN);
	if (have_parent) {
		key[1] = parent;
		oe_id_derive(d->salt, "span", key, 2, sp.parent_span_id,
		    OE_SPAN_ID_LEN);
	}
	key[1] = have_trace ? trace : have_parent ? parent : spankey;
	oe_id_derive(d->salt, "trace", key, 2, sp.trace_id,
	    OE_TRACE_ID_LEN);
	sp.kind = kind != NULL ? span_kind(kind) : OE_SPAN_INTERNAL;
	if (err != 0) {
		sp.status = OE_STATUS_ERROR;
		snprintf(msg, sizeof(msg), "error %jd", (intmax_t)err);
		sp.status_message = msg;
	}
	sp.pid = (pid_t)pid;
	sp.execname = execname != NULL ? execname : "";
	sp.attrs = attrs;
	sp.nattrs = nattrs;
	/*
	 * The thread key is the thread the span belongs to.  The other
	 * context fields describe the probe's own process and come only
	 * when the span did not name another one, as does its CPU.
	 */
	sp.ctx = ctx;
	sp.ctx.flags = 0;
	if ((seen & PROC_CTX) == PROC_CTX) {
		sp.ctx.flags = PROC_CTX;
		if (bd->dtbda_probe != NULL) {
			sp.ctx.flags |= OE_CTX_CPU;
			sp.ctx.cpu = bd->dtbda_probe->dtpda_cpu;
		}
	}
	if (have_pid)
		sp.ctx.flags |= OE_CTX_PID;
	if (have_thread) {
		sp.ctx.flags |= OE_CTX_TID;
		sp.ctx.tid = thread;
	}
	{
		const char *target;
		uint16_t vmid = record_vmid(bd, &target);

		if (oe_span(dtotel_exporter_for(d, vmid, target), &sp) != 0)
			d->error = 1;
	}
	free(probe);
	return;
bad:
	if (!d->warned_span++)
		fprintf(stderr, "dtotel: malformed span record ignored (needs "
		    "name, start <= end, integer keys)\n");
}

/* ---------------------------------------------------------------- */
/* HyperTrace guests							*/

static struct dtotel_guest_state *
guest_find(struct dtotel *d, uint16_t vmid)
{
	struct dtotel_guest_state *g;

	for (g = d->guests; g != NULL; g = g->next)
		if (g->vmid == vmid)
			return (g);
	return (NULL);
}

static struct dtotel_guest_state *
guest_add(struct dtotel *d, uint16_t vmid, uint64_t epoch, const char *name)
{
	struct dtotel_guest_state *g;

	g = calloc(1, sizeof(*g));
	if (g == NULL)
		return (NULL);
	g->vmid = vmid;
	g->epoch = epoch;
	g->name = strdup(name != NULL ? name : "");
	if (g->name == NULL) {
		free(g);
		return (NULL);
	}
	g->next = d->guests;
	d->guests = g;
	return (g);
}

/* Flush and release a guest's exporter; the next record recreates it. */
static int
guest_retire(struct dtotel *d, struct dtotel_guest_state *g)
{
	int ret = 0;

	if (g->exporter == NULL)
		return (0);
	/* The pending line may belong to this guest. */
	if (d->body != NULL && d->body_vmid == g->vmid)
		dtotel_flush(d);
	if (oe_shutdown(g->exporter) != 0)
		ret = -1;
	oe_exporter_free(g->exporter);
	g->exporter = NULL;
	return (ret);
}

static void
guest_free(struct dtotel_guest_state *g)
{
	size_t i;

	for (i = 0; i < g->nattrs; i++) {
		free(__DECONST(char *, g->attrs[i].name));
		free(__DECONST(char *, g->attrs[i].value));
	}
	free(g->name);
	free(g);
}

int
dtotel_guest(struct dtotel *d, uint16_t vmid, uint64_t epoch,
    const char *name)
{
	struct dtotel_guest_state *g;
	char *copy;
	int ret = 0;

	if (vmid == 0)
		return (0);
	g = guest_find(d, vmid);
	if (g == NULL)
		return (guest_add(d, vmid, epoch, name) != NULL ? 0 : -1);
	if (g->epoch == epoch && name != NULL && strcmp(g->name, name) == 0)
		return (0);
	/* A new lifetime (or name) of the VMID: a new resource. */
	ret = guest_retire(d, g);
	g->epoch = epoch;
	if (name != NULL) {
		if ((copy = strdup(name)) == NULL)
			return (-1);	/* keeps the old name */
		free(g->name);
		g->name = copy;
	}
	return (ret);
}

struct oe_exporter *
dtotel_exporter_for(struct dtotel *d, uint16_t vmid, const char *target)
{
	struct dtotel_guest_state *g;
	struct dtotel_guest view;

	if (vmid == 0 || d->guest_exporter == NULL)
		return (d->exporter);
	g = guest_find(d, vmid);
	/* An unregistered guest is known by its probes' target name. */
	if (g == NULL && (g = guest_add(d, vmid, 0, target)) == NULL)
		return (d->exporter);
	if (g->exporter == NULL) {
		view.vmid = g->vmid;
		view.epoch = g->epoch;
		view.name = g->name;
		view.attrs = g->attrs;
		view.nattrs = g->nattrs;
		g->exporter = d->guest_exporter(d->guest_arg, &view);
		if (g->exporter == NULL) {
			if (!d->warned_guest++)
				fprintf(stderr, "dtotel: cannot export VM %u "
				    "separately; its records go to the host's "
				    "resource\n", (unsigned)vmid);
			return (d->exporter);
		}
		if (oe_start(g->exporter) != 0)
			d->error = 1;
	}
	return (g->exporter);
}

int
dtotel_shutdown(struct dtotel *d)
{
	struct dtotel_guest_state *g, *next;
	int ret = 0;

	dtotel_flush(d);
	for (g = d->guests; g != NULL; g = next) {
		next = g->next;
		if (guest_retire(d, g) != 0)
			ret = -1;
		guest_free(g);
	}
	d->guests = NULL;
	return (ret);
}

/* Resource attributes from a guest probe. */
static void
handle_resource(struct dtotel *d, char *rec, const dtrace_bufdata_t *bd)
{
	struct dtotel_guest_state *g;
	const char *target;
	char *field, *next, *eq, *value;
	uint16_t vmid;
	size_t i;
	int changed = 0;

	vmid = record_vmid(bd, &target);
	if (vmid == 0 || d->guest_exporter == NULL)
		return;
	g = guest_find(d, vmid);
	if (g == NULL && (g = guest_add(d, vmid, 0, target)) == NULL)
		return;
	for (field = strchr(rec + strlen(DTOTEL_RECORD_PREFIX), FIELD_SEP);
	    field != NULL; field = next) {
		*field++ = '\0';
		next = strchr(field, FIELD_SEP);
		if (next != NULL)
			*next = '\0';
		eq = strchr(field, '=');
		if (eq == NULL || eq == field)
			continue;
		*eq++ = '\0';
		for (i = 0; i < g->nattrs; i++)
			if (strcmp(g->attrs[i].name, field) == 0)
				break;
		if (i == g->nattrs && g->nattrs == DTOTEL_GUEST_ATTRS)
			continue;
		if (i < g->nattrs && strcmp(g->attrs[i].value, eq) == 0)
			continue;
		if ((value = strdup(eq)) == NULL)
			continue;
		if (i < g->nattrs)
			free(__DECONST(char *, g->attrs[i].value));
		else if ((g->attrs[i].name = strdup(field)) == NULL) {
			free(value);
			continue;
		} else
			g->nattrs++;
		g->attrs[i].value = value;
		changed = 1;
	}
	if (changed && guest_retire(d, g) != 0)
		d->error = 1;
}

static void
handle_record(struct dtotel *d, char *rec, const dtrace_bufdata_t *bd,
    const struct dtotel_firing *firing, const struct timespec *observed)
{
	const char *kind = rec + strlen(DTOTEL_RECORD_PREFIX);

	if (strncmp(kind, "clock\037", 6) == 0)
		handle_clock(d, rec);
	else if (strncmp(kind, "span\037", 5) == 0)
		handle_span(d, rec, bd, observed);
	else if (strncmp(kind, "ctx\037", 4) == 0)
		handle_ctx(d, rec, firing);
	else if (strncmp(kind, "resource\037", 9) == 0)
		handle_resource(d, rec, bd);
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
	d->out_firing = firing;

	if (strncmp(chunk, DTOTEL_RECORD_PREFIX,
	    sizeof(DTOTEL_RECORD_PREFIX) - 1) == 0) {
		/*
		 * One record per chunk.  Strip only the final newline:
		 * string fields may themselves contain newlines.
		 */
		linelen = strlen(chunk);
		if (chunk[linelen - 1] == '\n')
			linelen--;
		rec = strndup(chunk, linelen);
		if (rec != NULL) {
			handle_record(d, rec, bufdata, &firing, &observed);
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
		} else if (line == chunk && d->line_open && d->body != NULL &&
		    same_firing(&firing, &d->body_firing)) {
			/* The firing continues the line it left open. */
			append_body(d, trimmed, tlen);
		} else {
			/* New event: flush pending, start accumulating. */
			start_event(d, bufdata, &firing, &observed, trimmed,
			    tlen);
		}
		free(linebuf);
		if (nl == NULL)
			break;
	}

	d->line_open = chunk[0] != '\0' && chunk[strlen(chunk) - 1] != '\n';
	return (d->error ? DTRACE_HANDLE_ABORT : DTRACE_HANDLE_OK);
}
