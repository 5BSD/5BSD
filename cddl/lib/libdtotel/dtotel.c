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
 *	\037otel.trace\037traceparent=<W3C traceparent>
 *		the trace context of the log record printed by the same
 *		firing (before or after it): its trace and span id become
 *		the record's traceId and spanId, so DTrace output joins
 *		the application's trace (copyinstr() of a USDT argument
 *		that carries the application's traceparent).  It also
 *		gives an exemplar record of the same firing its trace, and
 *		a stack-only firing's profile sample its link.
 *
 *	\037otel.exemplar\037agg=<name>\037value=<integer>[\037key=<k>...]
 *		an exemplar of the aggregation series @<name>[<k>, ...]
 *		(the keys in order, printed as %d/%s print them), exported
 *		on that series' data point with the next snapshot: the
 *		firing's wall time, the value, the trace of an inline
 *		traceparent= or of the firing's trace record, and the
 *		filtered attributes a.i.<key>=<integer>, a.s.<key>=<string>.
 *		DTrace aggregations keep no per-sample context, so the D
 *		program prints this record in the firing that updates the
 *		aggregation; see dtotel_agg.c for the bounds.
 *
 * Span records also take traceparent= (the span joins that trace: its
 * trace id, and without parent= the remote span as its parent),
 * tracestate=, event=<timestamp>:<name> (a span event at a D
 * "timestamp" value) and link=<traceparent> (a link to another span),
 * each of the last two up to eight times.
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

static void body_kv_free(struct dtotel *);

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
	d->profiles = cfg->profiles;
	d->prof_interval = DTOTEL_PROF_INTERVAL;
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
	dtotel_prof_free(d);
	dtotel_exemplars_free(d);
	dtotel_series_free(d);
	body_kv_free(d);
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
dtotel_drops(struct dtotel *d, int kind, uint64_t n)
{

	if (n == 0)
		return;
	if ((unsigned)kind >= DTOTEL_NDROPKINDS)
		kind = 0;	/* not expected: count as principal */
	d->drops[kind] += n;
	d->counters_dirty = d->counters_seen = 1;
}

static const char *const drop_kind_names[DTOTEL_NDROPKINDS] = {
	"principal", "aggregation", "dynamic", "dynamic_rinse",
	"dynamic_dirty", "speculation", "speculation_busy",
	"speculation_unavailable", "stack_string_overflow",
	"error_in_error_probe"
};

static const char *const fault_names[DTOTEL_NFAULTS] = {
	"unknown", "badaddr", "badalign", "illop", "divzero", "noscratch",
	"kpriv", "upriv", "tupoflow", "badstack", "library", "other"
};

static int
fault_index(int fault)
{

	if (fault >= DTRACEFLT_UNKNOWN && fault <= DTRACEFLT_BADSTACK)
		return (fault);
	return (fault >= DTRACEFLT_LIBRARY ? 10 : 11);
}

/* One counter snapshot: a point per kind that was ever counted. */
static void
report_counter(struct dtotel *d, const char *name, const char *unit,
    const char *desc, const char *attr, const char *const *kinds,
    const uint64_t *totals, size_t nkinds, const struct timespec *now)
{
	struct oe_datapoint dps[DTOTEL_NFAULTS];
	struct oe_attr attrs[DTOTEL_NFAULTS];
	struct oe_snapshot sn;
	size_t i, n;

	n = 0;
	for (i = 0; i < nkinds; i++) {
		if (totals[i] == 0)
			continue;
		attrs[n].name = attr;
		attrs[n].value = kinds[i];
		memset(&dps[n], 0, sizeof(dps[n]));
		dps[n].attrs = &attrs[n];
		dps[n].nattrs = 1;
		dps[n].scalar = (int64_t)totals[i];
		n++;
	}
	if (n == 0)
		return;
	memset(&sn, 0, sizeof(sn));
	sn.ts = *now;
	sn.start = d->start;
	sn.profile = d->profile;
	sn.name = name;
	sn.kind = OE_AGG_COUNT;
	sn.points = dps;
	sn.npoints = n;
	sn.scope_metric = 1;
	sn.unit = unit;
	sn.description = desc;
	if (oe_snapshot(d->exporter, &sn) != 0)
		d->error = 1;
}

void
dtotel_report(struct dtotel *d, int force)
{
	struct timespec now;

	/* Firing profiles go out on their own interval. */
	if (d->profiles)
		dtotel_prof_tick(d);
	if (!d->counters_seen || (!force && !d->counters_dirty))
		return;
	clock_gettime(CLOCK_REALTIME, &now);
	/*
	 * Drops are not attributed to HyperTrace guests: the kernel counts
	 * them per buffer, not per VM, so they belong to the host.
	 */
	report_counter(d, "drops", "{record}", "Records DTrace dropped, by "
	    "kind", "dtrace.drop.kind", drop_kind_names, d->drops,
	    DTOTEL_NDROPKINDS, &now);
	report_counter(d, "errors", "{error}", "DTrace runtime errors, by "
	    "fault", "dtrace.fault", fault_names, d->faults, DTOTEL_NFAULTS,
	    &now);
	d->counters_dirty = 0;
}

void
dtotel_error_record(struct dtotel *d, const dtrace_errdata_t *e)
{
	struct oe_event ev;
	struct oe_kv kv[6];
	char probe[DTRACE_FULLNAMELEN];
	int fi;
	size_t n;

	dtotel_flush(d);
	fi = fault_index(e->dteda_fault);
	d->faults[fi]++;
	d->counters_dirty = d->counters_seen = 1;
	memset(&ev, 0, sizeof(ev));
	clock_gettime(CLOCK_REALTIME, &ev.ts);
	ev.observed = ev.ts;
	ev.profile = d->profile;
	probe[0] = '\0';
	if (e->dteda_pdesc != NULL)
		snprintf(probe, sizeof(probe), "%s:%s:%s:%s",
		    e->dteda_pdesc->dtpd_provider, e->dteda_pdesc->dtpd_mod,
		    e->dteda_pdesc->dtpd_func, e->dteda_pdesc->dtpd_name);
	ev.probe = probe;
	ev.execname = "";
	ev.body = e->dteda_msg != NULL ? e->dteda_msg : "DTrace error";
	ev.severity = OE_SEV_ERROR;
	ev.event_name = "dtrace.error";
	ev.ctx.flags = OE_CTX_CPU;
	ev.ctx.cpu = e->dteda_cpu;
	n = 0;
	kv[n].key = "dtrace.fault";
	kv[n].type = OE_VAL_STRING;
	kv[n++].s = fault_names[fi];
	kv[n].key = "dtrace.fault.code";
	kv[n].type = OE_VAL_INT;
	kv[n++].i = e->dteda_fault;
	/* Faults with an address: bad address/alignment, privilege. */
	if (e->dteda_fault == DTRACEFLT_BADADDR ||
	    e->dteda_fault == DTRACEFLT_BADALIGN ||
	    e->dteda_fault == DTRACEFLT_KPRIV ||
	    e->dteda_fault == DTRACEFLT_UPRIV) {
		kv[n].key = "dtrace.fault.address";
		kv[n].type = OE_VAL_INT;
		kv[n++].i = (int64_t)e->dteda_addr;
	}
	/* The action number within the clause; 0 is the predicate. */
	kv[n].key = "dtrace.action.index";
	kv[n].type = OE_VAL_INT;
	kv[n++].i = e->dteda_action;
	kv[n].key = "dtrace.difo.offset";
	kv[n].type = OE_VAL_INT;
	kv[n++].i = e->dteda_offset;
	if (e->dteda_edesc != NULL) {
		kv[n].key = "dtrace.epid";
		kv[n].type = OE_VAL_INT;
		kv[n++].i = e->dteda_edesc->dtepd_epid;
	}
	ev.attrs = kv;
	ev.nattrs = n;
	if (oe_event(dtotel_exporter_for(d, e->dteda_edesc != NULL ?
	    e->dteda_edesc->dtepd_vmid : 0, NULL), &ev) != 0)
		d->error = 1;
}

void
dtotel_exit(struct dtotel *d, int status)
{
	struct oe_event ev;
	struct oe_kv kv;
	char body[32];

	dtotel_flush(d);
	memset(&ev, 0, sizeof(ev));
	clock_gettime(CLOCK_REALTIME, &ev.ts);
	ev.observed = ev.ts;
	ev.profile = d->profile;
	ev.probe = "";
	ev.execname = "";
	snprintf(body, sizeof(body), "exit(%d)", status);
	ev.body = body;
	ev.event_name = "dtrace.exit";
	kv.key = "dtrace.exit.status";
	kv.type = OE_VAL_INT;
	kv.i = status;
	ev.attrs = &kv;
	ev.nattrs = 1;
	if (oe_event(d->exporter, &ev) != 0)
		d->error = 1;
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
void
dtotel_parse_frame(const char *line, struct oe_frame *f)
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
	dtotel_parse_frame(line, &fa->frames[fa->n]);
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

/* Release the pending record's typed attributes. */
static void
body_kv_free(struct dtotel *d)
{
	size_t i;

	for (i = 0; i < 2 * DTOTEL_BODY_KV; i++) {
		free(d->body_kvstr[i]);
		d->body_kvstr[i] = NULL;
	}
	d->body_nkv = 0;
}

/* Add an owned key=value string attribute to the pending record. */
static void
body_kv_add(struct dtotel *d, char *key, char *value)
{
	size_t n = d->body_nkv;

	if (key == NULL || value == NULL || n >= DTOTEL_BODY_KV) {
		free(key);
		free(value);
		return;
	}
	d->body_kvstr[2 * n] = key;
	d->body_kvstr[2 * n + 1] = value;
	d->body_kv[n].key = key;
	d->body_kv[n].type = OE_VAL_STRING;
	d->body_kv[n].s = value;
	d->body_nkv = n + 1;
}

void
dtotel_flush(struct dtotel *d)
{
	struct oe_kv kv[DTOTEL_BODY_KV + 1];
	struct oe_event ev;
	char execname[MAXCOMLEN + 1];
	pid_t pid;
	size_t nkv;

	if (d->body == NULL)
		return;
	/* A stack-only firing is a profile sample too. */
	if (d->profiles && d->body[0] == '\0' && d->kstack.n + d->ustack.n > 0)
		dtotel_prof_firing(d);
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
	/* The action that printed the line, then typed print() members. */
	nkv = 0;
	if (d->body_action != NULL) {
		kv[nkv].key = "dtrace.action";
		kv[nkv].type = OE_VAL_STRING;
		kv[nkv++].s = d->body_action;
	}
	memcpy(&kv[nkv], d->body_kv, d->body_nkv * sizeof(kv[0]));
	nkv += d->body_nkv;
	ev.attrs = kv;
	ev.nattrs = nkv;
	memcpy(ev.trace_id, d->body_trace, OE_TRACE_ID_LEN);
	memcpy(ev.span_id, d->body_span, OE_SPAN_ID_LEN);
	ev.trace_flags = d->body_tflags;
	if (oe_event(dtotel_exporter_for(d, d->body_vmid, NULL), &ev) != 0)
		d->error = 1;
	body_kv_free(d);
	d->body_action = NULL;
	memset(d->body_trace, 0, OE_TRACE_ID_LEN);
	memset(d->body_span, 0, OE_SPAN_ID_LEN);
	d->body_tflags = 0;
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

/* The D action behind a record, as dtrace.action names it. */
static const char *
action_name(const dtrace_bufdata_t *bd)
{
	const dtrace_recdesc_t *rec = bd->dtbda_recdesc;

	if (rec == NULL)
		return (NULL);
	switch (rec->dtrd_action) {
	case DTRACEACT_PRINTF:		return ("printf");
	case DTRACEACT_DIFEXPR:
		/* print() carries its type; trace() does not. */
		return (rec->dtrd_format != 0 ? "print" : "trace");
	case DTRACEACT_TRACEMEM:
	case DTRACEACT_TRACEMEM_DYNSIZE: return ("tracemem");
	case DTRACEACT_PRINTM:		return ("printm");
	case DTRACEACT_SYSTEM:		return ("system");
	case DTRACEACT_FREOPEN:		return ("freopen");
	case DTRACEACT_STACK:		return ("stack");
	case DTRACEACT_USTACK:		return ("ustack");
	case DTRACEACT_JSTACK:		return ("jstack");
	case DTRACEACT_SYM:		return ("sym");
	case DTRACEACT_MOD:		return ("mod");
	case DTRACEACT_USYM:		return ("usym");
	case DTRACEACT_UMOD:		return ("umod");
	case DTRACEACT_UADDR:		return ("uaddr");
	default:			return (NULL);
	}
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
	d->body_action = action_name(bd);
	probe_walltime(d, firing, observed, &d->body_ts);
	/* Adopt a trace record this firing printed first. */
	if (same_firing(firing, &d->tp_firing)) {
		memcpy(d->body_trace, d->tp_trace, OE_TRACE_ID_LEN);
		memcpy(d->body_span, d->tp_span, OE_SPAN_ID_LEN);
		d->body_tflags = d->tp_flags;
		d->tp_firing.valid = 0;
	}
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

/*
 * A trace record: the W3C trace context of the line the same firing
 * prints (before or after this record).
 */
static void
handle_trace(struct dtotel *d, const char *rec,
    const struct dtotel_firing *firing)
{
	uint8_t tid[OE_TRACE_ID_LEN], sid[OE_SPAN_ID_LEN], flags;
	const char *tp;
	size_t len;

	tp = rec_field(rec, "traceparent", &len);
	if (tp == NULL || oe_traceparent_parse(tp, len, tid, sid,
	    &flags) != 0) {
		fprintf(stderr, "dtotel: malformed trace record ignored\n");
		return;
	}
	/* An exemplar this firing recorded first takes its trace. */
	dtotel_exemplar_trace(d, firing, tid, sid);
	if (d->body != NULL && same_firing(firing, &d->body_firing)) {
		memcpy(d->body_trace, tid, sizeof(tid));
		memcpy(d->body_span, sid, sizeof(sid));
		d->body_tflags = flags;
		return;
	}
	memcpy(d->tp_trace, tid, sizeof(tid));
	memcpy(d->tp_span, sid, sizeof(sid));
	d->tp_flags = flags;
	d->tp_firing = *firing;
}

#define	SPAN_MAX_ATTRS	16
#define	SPAN_MAX_EVENTS	8
#define	SPAN_MAX_LINKS	8

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
	struct oe_span_event events[SPAN_MAX_EVENTS];
	struct oe_span_link links[SPAN_MAX_LINKS];
	int64_t evts[SPAN_MAX_EVENTS];
	struct oe_span sp;
	const char *name, *kind, *execname, *tp, *tstate;
	char *field, *next, *eq, msg[48], *probe, *colon;
	struct oe_context ctx;
	uint8_t tptrace[OE_TRACE_ID_LEN], tpspan[OE_SPAN_ID_LEN], tpflags;
	int64_t start, end, thread, spankey, parent, trace, err, pid, v,
	    key[2], seen;
	int have_start, have_end, have_span, have_parent, have_trace, rc,
	    have_pid, have_thread;
	size_t nattrs, nevents, nlinks, i;

	tp = tstate = NULL;
	nevents = nlinks = 0;
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
		else if (strcmp(field, "traceparent") == 0)
			tp = eq;
		else if (strcmp(field, "tracestate") == 0)
			tstate = eq;
		else if (strcmp(field, "event") == 0) {
			/* <D timestamp>:<name> */
			colon = strchr(eq, ':');
			if (colon == NULL || colon[1] == '\0')
				goto bad;
			*colon = '\0';
			if (parse_int(eq, &v) != 0)
				goto bad;
			if (nevents < SPAN_MAX_EVENTS) {
				memset(&events[nevents], 0,
				    sizeof(events[0]));
				events[nevents].name = colon + 1;
				evts[nevents++] = v;
			}
		} else if (strcmp(field, "link") == 0) {
			if (nlinks < SPAN_MAX_LINKS) {
				memset(&links[nlinks], 0, sizeof(links[0]));
				if (oe_traceparent_parse(eq, strlen(eq),
				    links[nlinks].trace_id,
				    links[nlinks].span_id, &tpflags) != 0)
					goto bad;
				links[nlinks++].flags = tpflags;
			}
		} else if (strcmp(field, "kind") == 0)
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
	/* Event times move onto the wall clock as the span's do. */
	for (i = 0; i < nevents; i++) {
		if (d->anchored)
			ns_to_ts(evts[i] + d->clock_offset, &events[i].ts);
		else
			ns_to_ts((int64_t)sp.end.tv_sec * 1000000000 +
			    sp.end.tv_nsec - (end - evts[i]), &events[i].ts);
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
	/*
	 * A W3C traceparent (from the application, e.g. a USDT argument)
	 * puts the span into the application's trace; without a local
	 * parent= the application's span is its (remote) parent.
	 */
	if (tp != NULL) {
		if (oe_traceparent_parse(tp, strlen(tp), tptrace, tpspan,
		    &tpflags) != 0)
			goto bad;
		memcpy(sp.trace_id, tptrace, OE_TRACE_ID_LEN);
		sp.flags = tpflags;
		if (!have_parent) {
			memcpy(sp.parent_span_id, tpspan, OE_SPAN_ID_LEN);
			sp.flags |= OE_SPAN_FLAGS_HAS_IS_REMOTE |
			    OE_SPAN_FLAGS_IS_REMOTE;
		} else
			sp.flags |= OE_SPAN_FLAGS_HAS_IS_REMOTE;
	}
	sp.trace_state = tstate;
	sp.events = events;
	sp.nevents = nevents;
	sp.links = links;
	sp.nlinks = nlinks;
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

/*
 * A HyperTrace guest session event on the host's resource: a named log
 * record ("hypertrace.vm.registered", ".restarted" for a new lifetime of
 * the VMID, ".renamed") with the VM's identity as attributes.
 */
static void
guest_event(struct dtotel *d, const char *event, const char *what,
    const struct dtotel_guest_state *g)
{
	struct oe_event ev;
	struct oe_kv kv[3];
	char body[256];

	dtotel_flush(d);
	memset(&ev, 0, sizeof(ev));
	clock_gettime(CLOCK_REALTIME, &ev.ts);
	ev.observed = ev.ts;
	ev.profile = d->profile;
	ev.probe = "";
	ev.execname = "";
	snprintf(body, sizeof(body), "HyperTrace VM %s (id %u, epoch %ju) %s",
	    g->name, (unsigned)g->vmid, (uintmax_t)g->epoch, what);
	ev.body = body;
	ev.event_name = event;
	kv[0].key = "hypertrace.vm.name";
	kv[0].type = OE_VAL_STRING;
	kv[0].s = g->name;
	kv[1].key = "hypertrace.vm.id";
	kv[1].type = OE_VAL_INT;
	kv[1].i = g->vmid;
	kv[2].key = "hypertrace.vm.epoch";
	kv[2].type = OE_VAL_INT;
	kv[2].i = (int64_t)g->epoch;
	ev.attrs = kv;
	ev.nattrs = 3;
	if (oe_event(d->exporter, &ev) != 0)
		d->error = 1;
}

int
dtotel_guest(struct dtotel *d, uint16_t vmid, uint64_t epoch,
    const char *name)
{
	struct dtotel_guest_state *g;
	char *copy;
	int ret = 0, restarted;

	if (vmid == 0)
		return (0);
	g = guest_find(d, vmid);
	if (g == NULL) {
		if ((g = guest_add(d, vmid, epoch, name)) == NULL)
			return (-1);
		guest_event(d, "hypertrace.vm.registered", "registered", g);
		return (0);
	}
	/* Same lifetime, and the same (or no news of the) name. */
	if (g->epoch == epoch && (name == NULL || strcmp(g->name, name) == 0))
		return (0);
	/* A new lifetime (or name) of the VMID: a new resource. */
	restarted = g->epoch != epoch;
	ret = guest_retire(d, g);
	g->epoch = epoch;
	if (name != NULL) {
		if ((copy = strdup(name)) == NULL)
			return (-1);	/* keeps the old name */
		free(g->name);
		g->name = copy;
	}
	guest_event(d, restarted ? "hypertrace.vm.restarted" :
	    "hypertrace.vm.renamed", restarted ? "restarted" : "renamed", g);
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
dtotel_flush_guests(struct dtotel *d)
{
	struct dtotel_guest_state *g;
	int ret = 0;

	for (g = d->guests; g != NULL; g = g->next)
		if (g->exporter != NULL && oe_flush(g->exporter) != 0)
			ret = -1;
	return (ret);
}

int
dtotel_shutdown(struct dtotel *d)
{
	struct dtotel_guest_state *g, *next;
	int ret = 0;

	dtotel_flush(d);
	/* Profiles still accumulated, while the guest exporters exist. */
	if (d->profiles)
		dtotel_prof_emit(d, 0);
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
	else if (strncmp(kind, "trace\037", 6) == 0)
		handle_trace(d, rec, firing);
	else if (strncmp(kind, "exemplar\037", 9) == 0)
		dtotel_exemplar_record(d, rec, bd, firing, observed);
	else
		fprintf(stderr, "dtotel: unknown structured record \"%.*s\" "
		    "ignored\n", (int)strcspn(kind, "\037\n"), kind);
}

/* ---------------------------------------------------------------- */
/* Typed print()							*/

#define	PRINT_MAX_DEPTH	8

static char *
xstrndup_trim(const char *p, size_t n)
{

	while (n > 0 && isspace((unsigned char)*p)) {
		p++;
		n--;
	}
	while (n > 0 && isspace((unsigned char)p[n - 1]))
		n--;
	return (strndup(p, n));
}

/*
 * Structured attributes from libdtrace's rendering of a typed value
 * (dtrace_print()): the first line names the type ("struct timespec {"
 * or "int 0x5"), member lines read "<type> <name> = <value>" (a nested
 * aggregate opens with "= {" and closes with "}").  Members become
 * dtrace.print.<name>[.<name>...] string attributes, the type
 * dtrace.print.type and a scalar's value dtrace.print.value.  Best
 * effort: values stay libdtrace's text, arrays one string, and at most
 * DTOTEL_BODY_KV attributes are kept.
 */
static void
parse_print(struct dtotel *d, const char *text)
{
	const char *line, *nl, *eq, *nm;
	char *path[PRINT_MAX_DEPTH], *key, *value;
	size_t len, depth, lost, i;
	struct oe_buf kb;

	depth = lost = 0;
	nl = strchr(text, '\n');
	len = nl != NULL ? (size_t)(nl - text) : strlen(text);
	while (len > 0 && isspace((unsigned char)text[len - 1]))
		len--;
	if (len > 0 && text[len - 1] == '{')
		body_kv_add(d, strdup("dtrace.print.type"),
		    xstrndup_trim(text, len - 1));
	else {
		for (i = len; i > 0 && text[i - 1] != ' '; i--)
			;
		if (i > 0) {
			body_kv_add(d, strdup("dtrace.print.type"),
			    xstrndup_trim(text, i - 1));
			body_kv_add(d, strdup("dtrace.print.value"),
			    xstrndup_trim(text + i, len - i));
		}
		return;
	}
	for (line = nl; line != NULL; line = nl) {
		line++;
		nl = strchr(line, '\n');
		len = nl != NULL ? (size_t)(nl - line) : strlen(line);
		while (len > 0 && isspace((unsigned char)*line)) {
			line++;
			len--;
		}
		if (len == 0)
			continue;
		if (*line == '}') {
			/* Levels too deep (or without memory) were not kept. */
			if (lost > 0)
				lost--;
			else if (depth > 0)
				free(path[--depth]);
			continue;
		}
		eq = memmem(line, len, " = ", 3);
		if (eq == NULL)
			continue;
		/* The member name: the word before " = " (or " :bits"). */
		nm = memmem(line, (size_t)(eq - line), " :", 2);
		if (nm == NULL)
			nm = eq;
		for (i = (size_t)(nm - line); i > 0 && line[i - 1] != ' ' &&
		    line[i - 1] != '*'; i--)
			;
		oe_buf_init(&kb);
		oe_buf_appendstr(&kb, "dtrace.print");
		for (size_t k = 0; k < depth; k++)
			oe_buf_appendf(&kb, ".%s", path[k]);
		oe_buf_appendf(&kb, ".%.*s", (int)((size_t)(nm - line) - i),
		    line + i);
		value = xstrndup_trim(eq + 3, len - (size_t)(eq + 3 - line));
		if (value != NULL && strcmp(value, "{") == 0) {
			free(value);
			if (lost == 0 && depth < PRINT_MAX_DEPTH &&
			    (path[depth] = strndup(line + i,
			    (size_t)(nm - line) - i)) != NULL)
				depth++;
			else
				lost++;
			oe_buf_free(&kb);
			continue;
		}
		key = kb.error ? NULL : strdup(kb.data);
		oe_buf_free(&kb);
		body_kv_add(d, key, value);
	}
	while (depth > 0)
		free(path[--depth]);
}

/* A typed print() record: one log record however many lines it has. */
static void
handle_print(struct dtotel *d, const dtrace_bufdata_t *bd,
    const struct dtotel_firing *firing, const struct timespec *observed,
    const char *chunk)
{
	size_t len;

	len = strlen(chunk);
	while (len > 0 && chunk[len - 1] == '\n')
		len--;
	start_event(d, bd, firing, observed, chunk, len);
	if (d->body != NULL)
		parse_print(d, d->body);
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
	int is_stack_frame, ustack_rec;

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
	ustack_rec = bufdata->dtbda_recdesc != NULL &&
	    (bufdata->dtbda_recdesc->dtrd_action == DTRACEACT_USTACK ||
	    bufdata->dtbda_recdesc->dtrd_action == DTRACEACT_JSTACK);

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

	if (bufdata->dtbda_recdesc != NULL &&
	    bufdata->dtbda_recdesc->dtrd_action == DTRACEACT_DIFEXPR &&
	    bufdata->dtbda_recdesc->dtrd_format != 0 &&
	    strchr(chunk, '\n') != NULL) {
		handle_print(d, bufdata, &firing, &observed, chunk);
		d->line_open = 0;
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
			/*
			 * User frames: after bsdinstruments' marker, or
			 * the output of a ustack()/jstack() record.
			 */
			frames_push(d->in_ustack || ustack_rec ? &d->ustack :
			    &d->kstack, frameline);
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

/* ---------------------------------------------------------------- */
/* Helpers shared with dtotel_agg.c and dtotel_prof.c			*/

int
dtotel_same_firing(const struct dtotel_firing *a,
    const struct dtotel_firing *b)
{

	return (same_firing(a, b));
}

uint16_t
dtotel_record_vmid(const dtrace_bufdata_t *bd, const char **target)
{

	return (record_vmid(bd, target));
}

void
dtotel_probe_walltime(const struct dtotel *d, const struct dtotel_firing *f,
    const struct timespec *observed, struct timespec *ts)
{

	probe_walltime(d, f, observed, ts);
}
