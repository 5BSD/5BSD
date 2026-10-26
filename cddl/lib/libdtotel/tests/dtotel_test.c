/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for libdtotel, the libdtrace-to-libotelexport bridge.
 * libdtrace is replaced by dtrace_stub.c; buffered-output chunks and
 * aggregation records are built by hand the way libdtrace delivers
 * them, and a capturing exporter records what the bridge emits.
 */

#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <atf-c.h>
#include <dtrace.h>
#include <sys/hypertrace.h>

#include "dtotel.h"
#include "dtotel_session.h"
#include "otlp_validate.h"
#include "otel_testutil.h"
#include "dtrace_stub.h"

/* ---------------------------------------------------------------- */
/* Capturing exporter						 	*/

#define	CAP_MAX	64

struct cap_event {
	struct oe_context ctx;
	char		*jail;
	struct timespec	 ts, observed;
	char		*body, *probe, *execname;
	pid_t		 pid;
	size_t		 nstack, nustack;
	char		*frame0, *uframe0;
};

struct cap_point {
	char		*attrs;		/* "name=value;..." */
	int		 is_histogram;
	int64_t		 scalar;
	char		*buckets;	/* "upper:count;..." */
};

struct cap_span {
	struct oe_context ctx;
	char		*name, *probe, *execname, *msg;
	char		 trace[33], span[17], parent[17];
	struct timespec	 start, end;
	enum oe_span_kind kind;
	enum oe_status_code status;
	pid_t		 pid;
	char		*attrs;		/* "key=value;..." */
};

struct cap_snap {
	char		*name;
	enum oe_agg_kind kind;
	struct timespec	 start;
	size_t		 npoints;
	struct cap_point points[8];
};

struct capture {
	struct oe_exporter e;
	struct cap_event events[CAP_MAX];
	int		 nevents;
	struct cap_snap	 snaps[CAP_MAX];
	int		 nsnaps;
	struct cap_span	 spans[CAP_MAX];
	int		 nspans;
	uint64_t	 drops;
	int		 fail;
};

static char *
fmt_frame(const struct oe_frame *f)
{
	char buf[256];

	oe_frame_format(f, buf, sizeof(buf));
	return (strdup(buf));
}

static int
cap_start(struct oe_exporter *e __unused)
{

	return (0);
}

static int
cap_event(struct oe_exporter *e, const struct oe_event *ev)
{
	struct capture *c = (struct capture *)e;
	struct cap_event *ce;

	if (c->fail)
		return (-1);
	ATF_REQUIRE(c->nevents < CAP_MAX);
	ce = &c->events[c->nevents++];
	ce->ctx = ev->ctx;
	ce->jail = ev->ctx.jail_name != NULL ? strdup(ev->ctx.jail_name) :
	    NULL;
	ce->ts = ev->ts;
	ce->observed = ev->observed;
	ce->body = strdup(ev->body);
	ce->probe = strdup(ev->probe);
	ce->execname = strdup(ev->execname);
	ce->pid = ev->pid;
	ce->nstack = ev->nstack;
	ce->nustack = ev->nustack;
	ce->frame0 = ev->nstack > 0 ? fmt_frame(&ev->stack[0]) : NULL;
	ce->uframe0 = ev->nustack > 0 ? fmt_frame(&ev->ustack[0]) : NULL;
	return (0);
}

static int
cap_snapshot(struct oe_exporter *e, const struct oe_snapshot *sn)
{
	struct capture *c = (struct capture *)e;
	struct cap_snap *cs;
	struct oe_buf b;
	size_t i, j;

	if (c->fail)
		return (-1);
	ATF_REQUIRE(c->nsnaps < CAP_MAX);
	cs = &c->snaps[c->nsnaps++];
	cs->name = strdup(sn->name);
	cs->kind = sn->kind;
	cs->start = sn->start;
	cs->npoints = sn->npoints;
	for (i = 0; i < sn->npoints && i < nitems(cs->points); i++) {
		oe_buf_init(&b);
		for (j = 0; j < sn->points[i].nattrs; j++)
			oe_buf_appendf(&b, "%s=%s;", sn->points[i].attrs[j].name,
			    sn->points[i].attrs[j].value);
		cs->points[i].attrs = strdup(b.data != NULL ? b.data : "");
		oe_buf_free(&b);
		cs->points[i].is_histogram = sn->points[i].is_histogram;
		cs->points[i].scalar = sn->points[i].scalar;
		oe_buf_init(&b);
		for (j = 0; j < sn->points[i].nbuckets; j++)
			oe_buf_appendf(&b, "%jd:%jd;",
			    (intmax_t)sn->points[i].buckets[j].upper,
			    (intmax_t)sn->points[i].buckets[j].count);
		cs->points[i].buckets = strdup(b.data != NULL ? b.data : "");
		oe_buf_free(&b);
	}
	return (0);
}

static int
cap_span(struct oe_exporter *e, const struct oe_span *sp)
{
	struct capture *c = (struct capture *)e;
	struct cap_span *cs;
	struct oe_buf b;
	size_t i;

	if (c->fail)
		return (-1);
	ATF_REQUIRE(c->nspans < CAP_MAX);
	cs = &c->spans[c->nspans++];
	cs->ctx = sp->ctx;
	cs->name = strdup(sp->name);
	cs->probe = strdup(sp->probe);
	cs->execname = strdup(sp->execname);
	cs->msg = sp->status_message != NULL ? strdup(sp->status_message) :
	    NULL;
	oe_id_hex(sp->trace_id, OE_TRACE_ID_LEN, cs->trace);
	oe_id_hex(sp->span_id, OE_SPAN_ID_LEN, cs->span);
	if (oe_id_is_zero(sp->parent_span_id, OE_SPAN_ID_LEN))
		cs->parent[0] = '\0';
	else
		oe_id_hex(sp->parent_span_id, OE_SPAN_ID_LEN, cs->parent);
	cs->start = sp->start;
	cs->end = sp->end;
	cs->kind = sp->kind;
	cs->status = sp->status;
	cs->pid = sp->pid;
	oe_buf_init(&b);
	for (i = 0; i < sp->nattrs; i++) {
		if (sp->attrs[i].type == OE_VAL_INT)
			oe_buf_appendf(&b, "%s=%jd;", sp->attrs[i].key,
			    (intmax_t)sp->attrs[i].i);
		else
			oe_buf_appendf(&b, "%s=%s;", sp->attrs[i].key,
			    sp->attrs[i].s);
	}
	cs->attrs = strdup(b.data != NULL ? b.data : "");
	oe_buf_free(&b);
	return (0);
}

static int
cap_flush(struct oe_exporter *e __unused)
{

	return (0);
}

static void
cap_free(struct oe_exporter *e __unused)
{
}

static const struct oe_exporter_ops cap_ops = {
	.start = cap_start,
	.event = cap_event,
	.snapshot = cap_snapshot,
	.flush = cap_flush,
	.shutdown = cap_flush,
	.free = cap_free,
	.span = cap_span,
};

static struct capture cap;

/* ---------------------------------------------------------------- */
/* Per-guest exporters							*/

#define	GUEST_MAX	16

struct guest_cap {
	struct oe_exporter e;
	char		 ident[256];	/* vmid/epoch/name[/k=v...] */
	int		 events, spans, snaps, started, shutdown;
	char		 lastbody[64];
	int		 freed;
};

static struct guest_cap *guests[GUEST_MAX];
static int nguests, guest_fail;

static int
g_start(struct oe_exporter *e)
{

	((struct guest_cap *)e)->started++;
	return (0);
}

static int
g_event(struct oe_exporter *e, const struct oe_event *ev)
{
	struct guest_cap *g = (struct guest_cap *)e;

	g->events++;
	strlcpy(g->lastbody, ev->body, sizeof(g->lastbody));
	return (0);
}

static int
g_snapshot(struct oe_exporter *e, const struct oe_snapshot *sn __unused)
{

	((struct guest_cap *)e)->snaps++;
	return (0);
}

static int
g_span(struct oe_exporter *e, const struct oe_span *sp __unused)
{

	((struct guest_cap *)e)->spans++;
	return (0);
}

static int
g_flush(struct oe_exporter *e __unused)
{

	return (0);
}

static int
g_shutdown(struct oe_exporter *e)
{

	((struct guest_cap *)e)->shutdown++;
	return (guest_fail == 2 ? -1 : 0);
}

static void
g_free(struct oe_exporter *e)
{

	/* Kept for inspection; marked so tests see the release. */
	((struct guest_cap *)e)->freed = 1;
}

static const struct oe_exporter_ops guest_ops = {
	.start = g_start, .event = g_event, .snapshot = g_snapshot,
	.flush = g_flush, .shutdown = g_shutdown, .free = g_free,
	.span = g_span,
};

static struct oe_exporter *
make_guest(void *arg, const struct dtotel_guest *gi)
{
	struct guest_cap *g;
	size_t i, n;

	ATF_REQUIRE(arg == &guests);
	if (guest_fail == 1)
		return (NULL);
	ATF_REQUIRE(nguests < GUEST_MAX);
	g = calloc(1, sizeof(*g));
	if (g == NULL)		/* an injected allocation failure */
		return (NULL);
	g->e.ops = &guest_ops;
	n = (size_t)snprintf(g->ident, sizeof(g->ident), "%u/%ju/%s",
	    gi->vmid, (uintmax_t)gi->epoch, gi->name);
	for (i = 0; i < gi->nattrs; i++)
		n += (size_t)snprintf(g->ident + n, sizeof(g->ident) - n,
		    "/%s=%s", gi->attrs[i].name, gi->attrs[i].value);
	guests[nguests++] = g;
	return (&g->e);
}

static struct dtotel *
open_bridge(const char *source)
{
	struct dtotel_config cfg;
	struct dtotel *d;

	memset(&cap, 0, sizeof(cap));
	cap.e.ops = &cap_ops;
	memset(&stub, 0, sizeof(stub));
	memset(&cfg, 0, sizeof(cfg));
	cfg.dtp = (dtrace_hdl_t *)&stub;
	cfg.exporter = &cap.e;
	cfg.profile = "prof";
	cfg.source = source;
	d = dtotel_open(&cfg);
	ATF_REQUIRE(d != NULL);
	ATF_REQUIRE_EQ(0, dtotel_handle(d));
	ATF_REQUIRE(stub.bufhandler == dtotel_buffered);
	return (d);
}

/* ---------------------------------------------------------------- */
/* Buffered output						 	*/

static dtrace_probedesc_t test_pdesc = {
	.dtpd_provider = "syscall",
	.dtpd_mod = "freebsd",
	.dtpd_func = "open",
	.dtpd_name = "entry",
};

/* Deliver one chunk as if from a firing (cpu, hrtime, epid). */
static int
deliver(struct dtotel *d, const char *text, int cpu, uint64_t hrtime,
    dtrace_epid_t epid, uint32_t flags)
{
	dtrace_bufdata_t bd;
	dtrace_probedata_t pd;
	dtrace_eprobedesc_t ed;

	(void)d;	/* the handler argument registered with the stub */
	memset(&bd, 0, sizeof(bd));
	memset(&pd, 0, sizeof(pd));
	memset(&ed, 0, sizeof(ed));
	ed.dtepd_epid = epid;
	pd.dtpda_cpu = cpu;
	pd.dtpda_timestamp = hrtime;
	pd.dtpda_edesc = epid != 0 ? &ed : NULL;
	pd.dtpda_pdesc = &test_pdesc;
	bd.dtbda_buffered = text;
	bd.dtbda_probe = cpu >= 0 ? &pd : NULL;
	bd.dtbda_flags = flags;
	return (stub.bufhandler(&bd, stub.bufarg));
}

ATF_TC_WITHOUT_HEAD(clock_program_shape);
ATF_TC_BODY(clock_program_shape, tc)
{
	const char *p = dtotel_clock_program();

	/* Both anchors print the record prefix with both clocks. */
	ATF_REQUIRE(strstr(p, "dtrace:::BEGIN") != NULL);
	ATF_REQUIRE(strstr(p, "profile:::tick-1sec") != NULL);
	ATF_REQUIRE(strstr(p, "\"\\037otel.clock\\037wall=%d\\037ts=%u\\n\"")
	    != NULL);
	ATF_REQUIRE(strstr(p, "walltimestamp, timestamp") != NULL);
}

/*
 * Before an anchor, records carry the consumer's clock; after it,
 * hrtime + (wall - ts).  The observed time is always the consumer's.
 */
ATF_TC_WITHOUT_HEAD(probe_time_anchor);
ATF_TC_BODY(probe_time_anchor, tc)
{
	struct dtotel *d;
	struct timespec before;

	d = open_bridge(NULL);
	clock_gettime(CLOCK_REALTIME, &before);
	ATF_REQUIRE_EQ(DTRACE_HANDLE_OK, deliver(d, "early[1]: x\n", 0, 500,
	    7, 0));
	ATF_REQUIRE_EQ(DTRACE_HANDLE_OK, deliver(d,
	    "\037otel.clock\037wall=1700000000000000000\037ts=1000\n", 0, 1000,
	    3, 0));
	ATF_REQUIRE_EQ(DTRACE_HANDLE_OK, deliver(d, "late[2]: y\n", 1, 4000,
	    7, 0));
	dtotel_flush(d);
	ATF_REQUIRE_EQ(2, cap.nevents);
	ATF_REQUIRE(cap.events[0].ts.tv_sec >= before.tv_sec);
	ATF_REQUIRE_EQ(cap.events[0].ts.tv_sec, cap.events[0].observed.tv_sec);
	ATF_REQUIRE_EQ(1700000000, cap.events[1].ts.tv_sec);
	ATF_REQUIRE_EQ(3000, cap.events[1].ts.tv_nsec);
	ATF_REQUIRE(cap.events[1].observed.tv_sec >= before.tv_sec);
	ATF_REQUIRE_STREQ("late[2]: y", cap.events[1].body);
	ATF_REQUIRE_STREQ("late", cap.events[1].execname);
	ATF_REQUIRE_EQ(2, cap.events[1].pid);
	ATF_REQUIRE_STREQ("syscall:freebsd:open:entry", cap.events[1].probe);
	/* A record without probe data uses the consumer clock. */
	ATF_REQUIRE_EQ(DTRACE_HANDLE_OK, deliver(d, "noprobe\n", -1, 0, 0,
	    0));
	dtotel_flush(d);
	ATF_REQUIRE_EQ(3, cap.nevents);
	ATF_REQUIRE_STREQ("", cap.events[2].probe);
	ATF_REQUIRE_STREQ("", cap.events[2].execname);
	ATF_REQUIRE(cap.events[2].ts.tv_sec != 1700000000);
	dtotel_close(d);
}

ATF_TC_WITHOUT_HEAD(malformed_records);
ATF_TC_BODY(malformed_records, tc)
{
	struct dtotel *d;

	d = open_bridge(NULL);
	/* Missing or non-numeric fields: ignored, not anchored. */
	deliver(d, "\037otel.clock\037wall=12\n", 0, 1, 1, 0);
	deliver(d, "\037otel.clock\037wall=x\037ts=1\n", 0, 1, 1, 0);
	deliver(d, "\037otel.clock\037wall=\037ts=1\n", 0, 1, 1, 0);
	deliver(d, "\037otel.clock\037wall=123456789012345678901234567890"
	    "\037ts=1\n", 0, 1, 1, 0);
	deliver(d, "\037otel.clock\037wall=1234567890123456789012345678901234"
	    "\037ts=1\n", 0, 1, 1, 0);
	deliver(d, "\037otel.clock\037walls=1\037ts=1\n", 0, 1, 1, 0);
	deliver(d, "\037otel.bogus\037a=b\n", 0, 1, 1, 0);
	deliver(d, "line\n", 0, 50, 1, 0);
	dtotel_flush(d);
	ATF_REQUIRE_EQ(1, cap.nevents);
	ATF_REQUIRE(cap.events[0].ts.tv_sec > 1700000000);
	dtotel_close(d);
}

/*
 * Every text line starts a record; frames attach to the line of the
 * same firing; frames from a firing that printed nothing form a
 * stack-only record (empty body); the ustack marker switches lists.
 */
ATF_TC_WITHOUT_HEAD(lines_and_stacks);
ATF_TC_BODY(lines_and_stacks, tc)
{
	struct dtotel *d;

	d = open_bridge(NULL);
	deliver(d, "first[10]: a\nsecond[11]: b\n\n   \n", 0, 100, 1, 0);
	deliver(d, "              kernel`vn_open+0x42\n"
	    "              0xffffffff80001234\n", 0, 100, 1, 0);
	deliver(d, "__BSDINSTRUMENTS_USTACK__\n", 0, 100, 1, 0);
	deliver(d, "              libc.so.7`open+0x8\n", 0, 100, 1, 0);
	/* Different firing: stack-only record. */
	deliver(d, "              kernel`sched_switch+0x1\n", 1, 200, 2, 0);
	/* Unknown firing identity attaches to whatever is pending. */
	deliver(d, "              kernel`mi_switch+0x2\n", -1, 0, 0, 0);
	/* Chunk without a trailing newline. */
	deliver(d, "tail[12]: c", 0, 300, 1, 0);
	/* Aggregation output is never a log record. */
	deliver(d, "agg line\n", 0, 300, 1, DTRACE_BUFDATA_AGGKEY);
	deliver(d, "agg val\n", 0, 300, 1, DTRACE_BUFDATA_AGGLAST);
	{
		dtrace_bufdata_t bd;

		memset(&bd, 0, sizeof(bd));
		ATF_REQUIRE_EQ(DTRACE_HANDLE_OK, stub.bufhandler(&bd,
		    stub.bufarg));
	}
	dtotel_flush(d);
	dtotel_flush(d);		/* nothing pending: no-op */
	ATF_REQUIRE_EQ(4, cap.nevents);
	ATF_REQUIRE_STREQ("first[10]: a", cap.events[0].body);
	ATF_REQUIRE_EQ(0, cap.events[0].nstack);
	ATF_REQUIRE_STREQ("second[11]: b", cap.events[1].body);
	ATF_REQUIRE_EQ(2, cap.events[1].nstack);
	ATF_REQUIRE_STREQ("kernel`vn_open+0x42", cap.events[1].frame0);
	ATF_REQUIRE_EQ(1, cap.events[1].nustack);
	ATF_REQUIRE_STREQ("libc.so.7`open+0x8", cap.events[1].uframe0);
	ATF_REQUIRE_STREQ("", cap.events[2].body);
	ATF_REQUIRE_EQ(2, cap.events[2].nstack);
	ATF_REQUIRE_STREQ("kernel`sched_switch+0x1", cap.events[2].frame0);
	ATF_REQUIRE_STREQ("tail[12]: c", cap.events[3].body);
	dtotel_close(d);
}

ATF_TC_WITHOUT_HEAD(frame_forms);
ATF_TC_BODY(frame_forms, tc)
{
	struct dtotel *d;
	char longframe[700];

	d = open_bridge(NULL);
	deliver(d, "ev\n", 0, 1, 1, 0);
	deliver(d, "  kernel`sym_without_offset\n", 0, 1, 1, 0);
	deliver(d, "  kernel`sym+notanoffset\n", 0, 1, 1, 0);
	memset(longframe, 'a', sizeof(longframe));
	memcpy(longframe, "  k`", 4);
	longframe[sizeof(longframe) - 2] = '\n';
	longframe[sizeof(longframe) - 1] = '\0';
	deliver(d, longframe, 0, 1, 1, 0);
	dtotel_flush(d);
	ATF_REQUIRE_EQ(1, cap.nevents);
	ATF_REQUIRE_EQ(3, cap.events[0].nstack);
	ATF_REQUIRE_STREQ("kernel`sym_without_offset", cap.events[0].frame0);
	dtotel_close(d);
}

ATF_TC_WITHOUT_HEAD(exporter_failure_aborts);
ATF_TC_BODY(exporter_failure_aborts, tc)
{
	struct dtotel *d;

	d = open_bridge(NULL);
	cap.fail = 1;
	ATF_REQUIRE_EQ(DTRACE_HANDLE_OK, deliver(d, "a\n", 0, 1, 1, 0));
	ATF_REQUIRE_EQ(DTRACE_HANDLE_ABORT, deliver(d, "b\n", 0, 2, 1, 0));
	ATF_REQUIRE(dtotel_error(d));
	ATF_REQUIRE_EQ(DTRACE_HANDLE_ABORT, deliver(d,
	    "\037otel.clock\037wall=1\037ts=1\n", 0, 3, 1, 0));
	dtotel_close(d);
	dtotel_close(NULL);
}

ATF_TC_WITHOUT_HEAD(open_and_handle_errors);
ATF_TC_BODY(open_and_handle_errors, tc)
{
	struct dtotel_config cfg;
	struct dtotel *d;

	memset(&cfg, 0, sizeof(cfg));
	memset(&cap, 0, sizeof(cap));
	cap.e.ops = &cap_ops;
	cfg.exporter = &cap.e;
	d = dtotel_open(&cfg);		/* NULL profile and source */
	ATF_REQUIRE(d != NULL);
	stub.fail_handle_buffered = 1;
	ATF_REQUIRE_EQ(-1, dtotel_handle(d));
	stub.fail_handle_buffered = 0;
	dtotel_started(d);
	dtotel_drops(d, 5);		/* forwarded; no-op for capture */
	dtotel_close(d);
}

/* ---------------------------------------------------------------- */
/* Aggregations							 	*/

/*
 * Build one aggregation record set: record 0 is the variable id,
 * then the keys, then the value, laid out in "data".
 */
struct fake_agg {
	dtrace_aggdata_t ad;
	dtrace_aggdesc_t *desc;
	char		 data[1024];
	size_t		 off;
};

static struct fake_agg *
fake_new(const char *name, int nkeys)
{
	struct fake_agg *f;

	f = calloc(1, sizeof(*f));
	f->desc = calloc(1, sizeof(dtrace_aggdesc_t) +
	    (size_t)(nkeys + 2) * sizeof(dtrace_recdesc_t));
	f->desc->dtagd_name = __DECONST(char *, name);
	f->desc->dtagd_nrecs = 1;
	f->desc->dtagd_rec[0].dtrd_action = DTRACEACT_DIFEXPR;
	f->desc->dtagd_rec[0].dtrd_size = sizeof(uint64_t);
	f->off = sizeof(uint64_t);
	f->ad.dtada_desc = f->desc;
	f->ad.dtada_data = f->data;
	f->ad.dtada_normal = 1;
	return (f);
}

static void
fake_rec(struct fake_agg *f, dtrace_actkind_t act, uint64_t arg,
    const void *bytes, size_t len)
{
	dtrace_recdesc_t *r;

	r = &f->desc->dtagd_rec[f->desc->dtagd_nrecs++];
	r->dtrd_action = act;
	r->dtrd_size = (uint32_t)len;
	r->dtrd_offset = (uint32_t)f->off;
	r->dtrd_arg = arg;
	memcpy(f->data + f->off, bytes, len);
	f->off += roundup(len, sizeof(uint64_t));
}

static void
fake_free(struct fake_agg *f)
{

	free(f->desc);
	free(f);
}

static void
run_aggs(struct dtotel *d, struct fake_agg **fa, size_t n)
{
	const dtrace_aggdata_t *ads[16];
	size_t i;

	for (i = 0; i < n; i++)
		ads[i] = &fa[i]->ad;
	stub.aggs = ads;
	stub.naggs = n;
	ATF_REQUIRE_EQ(0, dtotel_aggregate(d));
	stub.aggs = NULL;
	stub.naggs = 0;
}

ATF_TC_WITHOUT_HEAD(agg_scalars);
ATF_TC_BODY(agg_scalars, tc)
{
	struct dtotel *d;
	struct fake_agg *fa[8];
	int64_t v[4];
	uint64_t pid = 42;
	char exec[16] = "nginx";
	size_t i;

	d = open_bridge("x { @calls[execname, pid, probefunc] = count(); "
	    "@lat[tid, probename, probemod, probeprov, \"lit\", "
	    "arg0 + (1, 2), cpu] = avg(x); @[1] = sum(1); }");
	fa[0] = fake_new("calls", 3);
	fake_rec(fa[0], DTRACEACT_DIFEXPR, 0, exec, sizeof(exec));
	fake_rec(fa[0], DTRACEACT_DIFEXPR, 0, &pid, sizeof(pid));
	fake_rec(fa[0], DTRACEACT_DIFEXPR, 0, "read\0\0\0", 8 + 1);
	v[0] = 10;
	fake_rec(fa[0], DTRACEAGG_COUNT, 0, v, sizeof(int64_t));
	/* Same aggregation, second tuple. */
	fa[1] = fake_new("calls", 3);
	fake_rec(fa[1], DTRACEACT_DIFEXPR, 0, "sshd", 5);
	fake_rec(fa[1], DTRACEACT_DIFEXPR, 0, &pid, sizeof(pid));
	fake_rec(fa[1], DTRACEACT_DIFEXPR, 0, "write", 6);
	v[0] = 4;
	fake_rec(fa[1], DTRACEAGG_COUNT, 0, v, sizeof(int64_t));
	/* avg: count, sum; normalize(2). */
	fa[2] = fake_new("lat", 0);
	v[0] = 4;
	v[1] = 80;
	fake_rec(fa[2], DTRACEAGG_AVG, 0, v, 2 * sizeof(int64_t));
	fa[2]->ad.dtada_normal = 2;
	/* anonymous sum, min, max */
	fa[3] = fake_new("_", 0);
	v[0] = 99;
	fake_rec(fa[3], DTRACEAGG_SUM, 0, v, sizeof(int64_t));
	fa[4] = fake_new(NULL, 0);
	fake_rec(fa[4], DTRACEAGG_MIN, 0, v, sizeof(int64_t));
	fa[5] = fake_new("mx", 0);
	fake_rec(fa[5], DTRACEAGG_MAX, 0, v, sizeof(int64_t));
	/* stddev: count 4, sum 20, sumsq 120: sqrt((480-400)/16) -> 2 */
	fa[6] = fake_new("sd", 0);
	v[0] = 4;
	v[1] = 20;
	v[2] = 120;
	v[3] = 0;
	fake_rec(fa[6], DTRACEAGG_STDDEV, 0, v, 4 * sizeof(int64_t));
	/* Unknown aggregating action and an empty descriptor: skipped. */
	fa[7] = fake_new("odd", 0);
	fake_rec(fa[7], DTRACEACT_PRINTF, 0, v, sizeof(int64_t));
	run_aggs(d, fa, 8);
	ATF_REQUIRE_EQ(6, cap.nsnaps);
	for (i = 0; i < (size_t)cap.nsnaps; i++) {
		struct cap_snap *s = &cap.snaps[i];

		ATF_REQUIRE(s->start.tv_sec > 0);
		if (strcmp(s->name, "calls") == 0) {
			ATF_REQUIRE_EQ(OE_AGG_COUNT, s->kind);
			ATF_REQUIRE_EQ(2, s->npoints);
			ATF_REQUIRE_STREQ("process.executable.name=nginx;"
			    "process.pid=42;syscall=read;", s->points[0].attrs);
			ATF_REQUIRE_EQ(10, s->points[0].scalar);
			ATF_REQUIRE_EQ(4, s->points[1].scalar);
		} else if (strcmp(s->name, "lat") == 0) {
			ATF_REQUIRE_EQ(OE_AGG_AVG, s->kind);
			ATF_REQUIRE_EQ(10, s->points[0].scalar);
		} else if (strcmp(s->name, "sd") == 0)
			ATF_REQUIRE_EQ(2, s->points[0].scalar);
		else if (s->kind == OE_AGG_SUM)
			ATF_REQUIRE_STREQ("", s->name);
	}
	for (i = 0; i < 8; i++)
		fake_free(fa[i]);
	dtotel_close(d);
}

ATF_TC_WITHOUT_HEAD(agg_key_names);
ATF_TC_BODY(agg_key_names, tc)
{
	struct dtotel *d;
	struct fake_agg *fa;
	uint32_t k32 = 7;
	int64_t v = 1;

	d = open_bridge("@lat[tid, probename, probemod, probeprov, \"lit\", "
	    "f(a, b), cpu, x] = count(); @lat[ignored] = count(); "
	    "@unterminated[a, b");
	fa = fake_new("lat", 8);
	fake_rec(fa, DTRACEACT_DIFEXPR, 0, &k32, sizeof(k32));
	fake_rec(fa, DTRACEACT_DIFEXPR, 0, "entry", 6);
	fake_rec(fa, DTRACEACT_DIFEXPR, 0, "kernel", 7);
	fake_rec(fa, DTRACEACT_DIFEXPR, 0, "fbt\0", 5);
	fake_rec(fa, DTRACEACT_DIFEXPR, 0, "lit\0", 5);
	fake_rec(fa, DTRACEACT_DIFEXPR, 0, &k32, sizeof(k32));
	fake_rec(fa, DTRACEACT_DIFEXPR, 0, &k32, sizeof(k32));
	fake_rec(fa, DTRACEACT_DIFEXPR, 0, &k32, sizeof(k32));
	fake_rec(fa, DTRACEAGG_COUNT, 0, &v, sizeof(v));
	run_aggs(d, &fa, 1);
	ATF_REQUIRE_EQ(1, cap.nsnaps);
	ATF_REQUIRE_STREQ("thread.id=7;probe=entry;module=kernel;provider=fbt;"
	    "label=lit;key.5=7;cpu.logical_number=7;key.7=7;",
	    cap.snaps[0].points[0].attrs);
	fake_free(fa);
	dtotel_close(d);
}

ATF_TC_WITHOUT_HEAD(agg_key_actions);
ATF_TC_BODY(agg_key_actions, tc)
{
	struct dtotel *d;
	struct fake_agg *fa;
	uint64_t frames[4], ustk[4], usym[2], sym;
	uint8_t k8 = 200;
	uint16_t k16 = 60000;
	int64_t k64 = -5, v = 1;
	char odd[3] = { 1, 2, 3 };

	d = open_bridge(NULL);
	fa = fake_new("k", 12);
	/* Host kernel stack: symbolized; unresolvable stays hex. */
	frames[0] = 0x1142;
	frames[1] = 0x9000;
	frames[2] = 0;
	frames[3] = 0;
	fake_rec(fa, DTRACEACT_STACK, 4, frames, sizeof(frames));
	/* Guest-tagged stack keeps guest attribution. */
	fake_rec(fa, DTRACEACT_STACK, HYPERTRACE_STACK_ENCODE(3, 4), frames,
	    sizeof(frames));
	/* A stack whose frame size is not 8 bytes is hex-dumped. */
	fake_rec(fa, DTRACEACT_STACK, 3, odd, sizeof(odd));
	/* ustack: pid then frames, nframes limit honored. */
	ustk[0] = 77;
	ustk[1] = 0x4000;
	ustk[2] = 0x5000;
	ustk[3] = 0;
	fake_rec(fa, DTRACEACT_USTACK, 1, ustk, sizeof(ustk));
	fake_rec(fa, DTRACEACT_JSTACK, 0, odd, 3);	/* too short */
	sym = 0x1300;
	fake_rec(fa, DTRACEACT_SYM, 0, &sym, sizeof(sym));
	fake_rec(fa, DTRACEACT_MOD, 0, &sym, sizeof(sym));
	sym = 0x9999;
	fake_rec(fa, DTRACEACT_SYM, 0, &sym, sizeof(sym));
	usym[0] = 77;
	usym[1] = 0x4abc;
	fake_rec(fa, DTRACEACT_USYM, 0, usym, sizeof(usym));
	fake_rec(fa, DTRACEACT_DIFEXPR, 0, &k8, sizeof(k8));
	fake_rec(fa, DTRACEACT_DIFEXPR, 0, &k16, sizeof(k16));
	fake_rec(fa, DTRACEACT_DIFEXPR, 0, &k64, sizeof(k64));
	fake_rec(fa, DTRACEAGG_COUNT, 0, &v, sizeof(v));
	run_aggs(d, &fa, 1);
	ATF_REQUIRE_EQ(1, cap.nsnaps);
	ATF_REQUIRE_STREQ("key.0=kernel`fn1+0x42;0x9000;"
	    "key.1=guest[3]`0x1142;guest[3]`0x9000;"
	    "key.2=010203;"
	    "key.3=pid77;0x4000;"
	    "key.4=010203;"
	    "key.5=kernel`fn3;"
	    "key.6=kernel;"
	    "key.7=0x9999;"
	    "key.8=0x4abc;"
	    "key.9=200;key.10=60000;key.11=-5;",
	    cap.snaps[0].points[0].attrs);
	fake_free(fa);
	dtotel_close(d);
}

#define	LQ_ARG(base, step, levels)					\
	(((uint64_t)(step) << DTRACE_LQUANTIZE_STEPSHIFT) |		\
	((uint64_t)(levels) << DTRACE_LQUANTIZE_LEVELSHIFT) |		\
	(uint32_t)(base))
#define	LLQ_ARG(factor, low, high, nsteps)				\
	(((uint64_t)(factor) << DTRACE_LLQUANTIZE_FACTORSHIFT) |	\
	((uint64_t)(low) << DTRACE_LLQUANTIZE_LOWSHIFT) |		\
	((uint64_t)(high) << DTRACE_LLQUANTIZE_HIGHSHIFT) | (nsteps))

ATF_TC_WITHOUT_HEAD(agg_histograms);
ATF_TC_BODY(agg_histograms, tc)
{
	struct dtotel *d;
	struct fake_agg *fa[3];
	int64_t q[DTRACE_QUANTIZE_NBUCKETS], lq[8], llq[16];

	d = open_bridge(NULL);
	/* quantize: one negative, the zero bucket, 1, 2-3, top. */
	memset(q, 0, sizeof(q));
	q[DTRACE_QUANTIZE_ZEROBUCKET - 1] = 1;
	q[DTRACE_QUANTIZE_ZEROBUCKET] = 2;
	q[DTRACE_QUANTIZE_ZEROBUCKET + 1] = 3;
	q[DTRACE_QUANTIZE_ZEROBUCKET + 2] = 4;
	q[DTRACE_QUANTIZE_NBUCKETS - 1] = 5;
	fa[0] = fake_new("q", 0);
	fake_rec(fa[0], DTRACEAGG_QUANTIZE, 0, q, sizeof(q));
	/* lquantize(x, 0, 30, 10): under, [0,10), [10,20), [20,30), over */
	memset(lq, 0, sizeof(lq));
	lq[0] = (int64_t)LQ_ARG(0, 10, 3);
	lq[1] = 1;
	lq[2] = 2;
	lq[4] = 3;
	lq[5] = 4;
	fa[1] = fake_new("lq", 0);
	fake_rec(fa[1], DTRACEAGG_LQUANTIZE, 0, lq, 6 * sizeof(int64_t));
	/*
	 * llquantize(x, 2, 0, 2, 2), walked as dt_print_llquantize()
	 * does: underflow (< 1), [1,2), [2,4), [4,8), overflow.
	 */
	memset(llq, 0, sizeof(llq));
	llq[0] = (int64_t)LLQ_ARG(2, 0, 2, 2);
	llq[1] = 1;
	llq[2] = 2;
	llq[3] = 3;
	llq[4] = 4;
	llq[5] = 5;
	fa[2] = fake_new("llq", 0);
	fake_rec(fa[2], DTRACEAGG_LLQUANTIZE, 0, llq, 6 * sizeof(int64_t));
	run_aggs(d, fa, 3);
	ATF_REQUIRE_EQ(3, cap.nsnaps);
	ATF_REQUIRE_STREQ("-1:1;0:2;1:3;3:4;9223372036854775807:5;",
	    cap.snaps[2].points[0].buckets);
	ATF_REQUIRE_STREQ("-1:1;9:2;29:3;9223372036854775807:4;",
	    cap.snaps[1].points[0].buckets);
	ATF_REQUIRE_EQ(1, cap.snaps[0].points[0].is_histogram);
	ATF_REQUIRE_STREQ("0:1;1:2;3:3;7:4;9223372036854775807:5;",
	    cap.snaps[0].points[0].buckets);
	fake_free(fa[0]);
	fake_free(fa[1]);
	fake_free(fa[2]);
	dtotel_close(d);
}

ATF_TC_WITHOUT_HEAD(agg_errors);
ATF_TC_BODY(agg_errors, tc)
{
	struct dtotel *d;
	struct fake_agg *fa[5];
	int64_t v[4] = { 0, 0, 0, 0 };

	d = open_bridge(NULL);
	stub.fail_snap = 1;
	ATF_REQUIRE_EQ(-1, dtotel_aggregate(d));
	stub.fail_snap = 0;
	stub.fail_walk = 1;
	ATF_REQUIRE_EQ(-1, dtotel_aggregate(d));
	stub.fail_walk = 0;
	/* Short value records and zero counts degrade to zero. */
	fa[0] = fake_new("a", 0);
	fake_rec(fa[0], DTRACEAGG_COUNT, 0, v, 4);
	fa[1] = fake_new("b", 0);
	fake_rec(fa[1], DTRACEAGG_AVG, 0, v, 8);
	fa[2] = fake_new("c", 0);
	fake_rec(fa[2], DTRACEAGG_AVG, 0, v, 16);
	fa[3] = fake_new("d", 0);
	fake_rec(fa[3], DTRACEAGG_STDDEV, 0, v, 32);
	fa[4] = fake_new("e", 0);
	fake_rec(fa[4], DTRACEAGG_STDDEV, 0, v, 8);
	run_aggs(d, fa, 5);
	ATF_REQUIRE_EQ(5, cap.nsnaps);
	ATF_REQUIRE_EQ(0, cap.snaps[0].points[0].scalar);
	/* An exporter failure is reported through dtotel_error(). */
	cap.fail = 1;
	run_aggs(d, fa, 1);
	ATF_REQUIRE(dtotel_error(d));
	for (int i = 0; i < 5; i++)
		fake_free(fa[i]);
	dtotel_close(d);
}

/* ---------------------------------------------------------------- */
/* Spans								*/

#define	ANCHOR	"\037otel.clock\037wall=1700000000000000000\037ts=1000\n"

/*
 * Span records become spans with probe wall times, ids derived from
 * the keys (a child names its parent by the parent's start), status
 * from error=, kind, pid/execname and typed attributes.
 */
ATF_TC_WITHOUT_HEAD(span_records);
ATF_TC_BODY(span_records, tc)
{
	struct dtotel *d;

	d = open_bridge(NULL);
	deliver(d, ANCHOR, 0, 1000, 1, 0);
	/* Child first: it ends first. */
	deliver(d, "\037otel.span\037name=block io\037start=3000\037end=3500"
	    "\037thread=77\037parent=2000\037pid=5\037execname=sh"
	    "\037error=5\037a.i.disk.io.bytes=4096"
	    "\037a.s.disk.io.direction=read\n", 1, 3500, 9, 0);
	deliver(d, "\037otel.span\037name=read\037start=2000\037end=9000"
	    "\037thread=77\037kind=server\037pid=5\037execname=sh\n", 0,
	    9000, 8, 0);
	/* Same key in another thread: an unrelated span. */
	deliver(d, "\037otel.span\037name=read\037start=2000\037end=2500"
	    "\037thread=78\037kind=client\n", 0, 2500, 8, 0);
	ATF_REQUIRE_EQ(3, cap.nspans);
	ATF_REQUIRE_EQ(0, cap.nevents);
	ATF_REQUIRE_STREQ("block io", cap.spans[0].name);
	ATF_REQUIRE_EQ(1700000000, cap.spans[0].start.tv_sec);
	ATF_REQUIRE_EQ(2000, cap.spans[0].start.tv_nsec);
	ATF_REQUIRE_EQ(2500, cap.spans[0].end.tv_nsec);
	ATF_REQUIRE_EQ(OE_STATUS_ERROR, cap.spans[0].status);
	ATF_REQUIRE_STREQ("error 5", cap.spans[0].msg);
	ATF_REQUIRE_EQ(OE_SPAN_INTERNAL, cap.spans[0].kind);
	ATF_REQUIRE_EQ(5, cap.spans[0].pid);
	ATF_REQUIRE_STREQ("sh", cap.spans[0].execname);
	ATF_REQUIRE_STREQ("syscall:freebsd:open:entry", cap.spans[0].probe);
	ATF_REQUIRE_STREQ("disk.io.bytes=4096;disk.io.direction=read;",
	    cap.spans[0].attrs);
	/* Parent link and shared trace. */
	ATF_REQUIRE_STREQ(cap.spans[1].span, cap.spans[0].parent);
	ATF_REQUIRE_STREQ(cap.spans[1].trace, cap.spans[0].trace);
	ATF_REQUIRE_STREQ("", cap.spans[1].parent);
	ATF_REQUIRE_EQ(OE_SPAN_SERVER, cap.spans[1].kind);
	ATF_REQUIRE_EQ(OE_STATUS_UNSET, cap.spans[1].status);
	ATF_REQUIRE(cap.spans[1].msg == NULL);
	ATF_REQUIRE(strcmp(cap.spans[2].span, cap.spans[1].span) != 0);
	ATF_REQUIRE(strcmp(cap.spans[2].trace, cap.spans[1].trace) != 0);
	ATF_REQUIRE_EQ(OE_SPAN_CLIENT, cap.spans[2].kind);
	ATF_REQUIRE_EQ(0, cap.spans[2].pid);
	ATF_REQUIRE_STREQ("", cap.spans[2].execname);
	dtotel_close(d);
}

/* Explicit span= and trace= keys, the other kinds, deep nesting. */
ATF_TC_WITHOUT_HEAD(span_explicit_keys);
ATF_TC_BODY(span_explicit_keys, tc)
{
	struct dtotel *d;

	d = open_bridge(NULL);
	deliver(d, ANCHOR, 0, 1000, 1, 0);
	deliver(d, "\037otel.span\037name=leaf\037start=10\037end=20"
	    "\037span=3\037parent=2\037trace=1\037kind=producer\n", 0, 20,
	    1, 0);
	deliver(d, "\037otel.span\037name=mid\037start=5\037end=30"
	    "\037span=2\037parent=1\037trace=1\037kind=consumer\n", 0, 30,
	    1, 0);
	deliver(d, "\037otel.span\037name=root\037start=1\037end=40"
	    "\037span=1\037trace=1\037kind=bogus\n", 0, 40, 1, 0);
	ATF_REQUIRE_EQ(3, cap.nspans);
	ATF_REQUIRE_STREQ(cap.spans[1].span, cap.spans[0].parent);
	ATF_REQUIRE_STREQ(cap.spans[2].span, cap.spans[1].parent);
	ATF_REQUIRE_STREQ(cap.spans[0].trace, cap.spans[2].trace);
	ATF_REQUIRE_STREQ(cap.spans[1].trace, cap.spans[2].trace);
	ATF_REQUIRE_EQ(OE_SPAN_PRODUCER, cap.spans[0].kind);
	ATF_REQUIRE_EQ(OE_SPAN_CONSUMER, cap.spans[1].kind);
	ATF_REQUIRE_EQ(OE_SPAN_INTERNAL, cap.spans[2].kind);
	dtotel_close(d);
}

/* Each session salts its ids differently. */
ATF_TC_WITHOUT_HEAD(span_ids_salted);
ATF_TC_BODY(span_ids_salted, tc)
{
	struct dtotel *d;
	char first[17];

	d = open_bridge(NULL);
	deliver(d, "\037otel.span\037name=a\037start=1\037end=2\n", 0, 2,
	    1, 0);
	ATF_REQUIRE_EQ(1, cap.nspans);
	strlcpy(first, cap.spans[0].span, sizeof(first));
	dtotel_close(d);
	d = open_bridge(NULL);
	deliver(d, "\037otel.span\037name=a\037start=1\037end=2\n", 0, 2,
	    1, 0);
	ATF_REQUIRE_EQ(1, cap.nspans);
	ATF_REQUIRE(strcmp(first, cap.spans[0].span) != 0);
	dtotel_close(d);
}

/*
 * Before an anchor a span ends when it was read but keeps its true
 * duration; newlines inside string fields survive; attributes past
 * the limit and unknown integer fields are ignored.
 */
ATF_TC_WITHOUT_HEAD(span_unanchored_and_limits);
ATF_TC_BODY(span_unanchored_and_limits, tc)
{
	struct dtotel *d;
	struct oe_buf b;
	int64_t dur;
	int i;

	d = open_bridge(NULL);
	deliver(d, "\037otel.span\037name=two\nlines\037start=1000"
	    "\037end=1700\037future=9\n", 0, 1700, 1, 0);
	ATF_REQUIRE_EQ(1, cap.nspans);
	ATF_REQUIRE_STREQ("two\nlines", cap.spans[0].name);
	dur = ((int64_t)cap.spans[0].end.tv_sec - cap.spans[0].start.tv_sec) *
	    1000000000 + cap.spans[0].end.tv_nsec - cap.spans[0].start.tv_nsec;
	ATF_REQUIRE_EQ(700, dur);
	ATF_REQUIRE(cap.spans[0].end.tv_sec > 1700000000);
	oe_buf_init(&b);
	oe_buf_appendstr(&b, "\037otel.span\037name=many\037start=1\037end=1");
	for (i = 0; i < 20; i++)
		oe_buf_appendf(&b, "\037a.%s.k%d=%d", i % 2 ? "i" : "s", i, i);
	oe_buf_appendstr(&b, "\n");
	deliver(d, b.data, 0, 1, 1, 0);
	oe_buf_free(&b);
	ATF_REQUIRE_EQ(2, cap.nspans);
	ATF_REQUIRE_STREQ("k0=0;k1=1;k2=2;k3=3;k4=4;k5=5;k6=6;k7=7;k8=8;k9=9;"
	    "k10=10;k11=11;k12=12;k13=13;k14=14;k15=15;", cap.spans[1].attrs);
	dtotel_close(d);
}

ATF_TC_WITHOUT_HEAD(span_malformed);
ATF_TC_BODY(span_malformed, tc)
{
	static const char *const bad[] = {
		"\037otel.span\037start=1\037end=2\n",		/* no name */
		"\037otel.span\037name=\037start=1\037end=2\n",
		"\037otel.span\037name=x\037end=2\n",		/* no start */
		"\037otel.span\037name=x\037start=1\n",		/* no end */
		"\037otel.span\037name=x\037start=5\037end=2\n",	/* negative */
		"\037otel.span\037name=x\037start=a\037end=2\n",
		"\037otel.span\037name=x\037start=1\037end=2\037junk\n",
		"\037otel.span\037name=x\037start=1\037end=2\037pid=\n",
	};
	struct dtotel *d;
	size_t i;

	d = open_bridge(NULL);
	for (i = 0; i < nitems(bad); i++)
		ATF_REQUIRE_EQ(DTRACE_HANDLE_OK, deliver(d, bad[i], 0, 1, 1,
		    0));
	/* start 0: the D side never saw the span start; dropped quietly. */
	deliver(d, "\037otel.span\037name=x\037start=0\037end=2\n", 0, 2,
	    1, 0);
	ATF_REQUIRE_EQ(0, cap.nspans);
	/* The record path never produces log events. */
	ATF_REQUIRE_EQ(0, cap.nevents);
	/* An exporter failure on a span aborts the consumer. */
	cap.fail = 1;
	ATF_REQUIRE_EQ(DTRACE_HANDLE_ABORT, deliver(d,
	    "\037otel.span\037name=x\037start=1\037end=2\n", -1, 0, 0, 0));
	dtotel_close(d);
}

/* ---------------------------------------------------------------- */
/* Context								*/

#define	CTX(pid, jid, exec)						\
	"\037otel.ctx\037pid=" #pid "\037ppid=1\037tid=100\037uid=80"		\
	"\037ruid=1001\037gid=80\037rgid=1001\037jid=" #jid			\
	"\037execname=" exec "\n"

#define	ALLCTX	(OE_CTX_PPID | OE_CTX_TID | OE_CTX_UID | OE_CTX_RUID |	\
	OE_CTX_GID | OE_CTX_RGID | OE_CTX_JAIL | OE_CTX_PID | OE_CTX_CPU)

/*
 * A context record attaches to the line printed by the same firing,
 * whether it comes after the line (the stack marker sits at the end
 * of a clause) or before it, and wins over the body heuristic.
 */
ATF_TC_WITHOUT_HEAD(context_records);
ATF_TC_BODY(context_records, tc)
{
	struct dtotel *d;

	d = open_bridge(NULL);
	deliver(d, "wrong[9]: after\n", 2, 10, 1, 0);
	deliver(d, CTX(42, 5, "nginx"), 2, 10, 1, 0);
	deliver(d, CTX(43, 0, "sshd"), 3, 20, 1, 0);
	deliver(d, "before\n", 3, 20, 1, 0);
	/* A context from another firing does not attach. */
	deliver(d, CTX(44, 0, "cron"), 1, 30, 1, 0);
	deliver(d, "plain[7]: no ctx\n", 1, 31, 1, 0);
	dtotel_flush(d);
	ATF_REQUIRE_EQ(3, cap.nevents);
	ATF_REQUIRE_EQ(42, cap.events[0].pid);
	ATF_REQUIRE_STREQ("nginx", cap.events[0].execname);
	ATF_REQUIRE_EQ(ALLCTX, cap.events[0].ctx.flags);
	ATF_REQUIRE_EQ(2, cap.events[0].ctx.cpu);
	ATF_REQUIRE_EQ(1, cap.events[0].ctx.ppid);
	ATF_REQUIRE_EQ(100, cap.events[0].ctx.tid);
	ATF_REQUIRE_EQ(80, cap.events[0].ctx.uid);
	ATF_REQUIRE_EQ(1001, cap.events[0].ctx.ruid);
	ATF_REQUIRE_EQ(80, cap.events[0].ctx.gid);
	ATF_REQUIRE_EQ(1001, cap.events[0].ctx.rgid);
	ATF_REQUIRE_EQ(5, cap.events[0].ctx.jid);
	ATF_REQUIRE_STREQ("jail5", cap.events[0].jail);
	ATF_REQUIRE_EQ(43, cap.events[1].pid);
	ATF_REQUIRE_STREQ("sshd", cap.events[1].execname);
	ATF_REQUIRE_EQ(0, cap.events[1].ctx.jid);
	ATF_REQUIRE(cap.events[1].jail == NULL);
	/* No context: body heuristic plus the firing's CPU only. */
	ATF_REQUIRE_EQ(7, cap.events[2].pid);
	ATF_REQUIRE_STREQ("plain", cap.events[2].execname);
	ATF_REQUIRE_EQ(OE_CTX_CPU, cap.events[2].ctx.flags);
	ATF_REQUIRE_EQ(1, cap.events[2].ctx.cpu);
	/* A context with no probe data: no CPU. */
	deliver(d, "x\n", -1, 0, 0, 0);
	deliver(d, CTX(45, 0, "x"), -1, 0, 0, 0);
	dtotel_flush(d);
	ATF_REQUIRE_EQ(4, cap.nevents);
	ATF_REQUIRE_EQ(0, cap.events[3].ctx.flags & OE_CTX_CPU);
	dtotel_close(d);
}

ATF_TC_WITHOUT_HEAD(context_malformed);
ATF_TC_BODY(context_malformed, tc)
{
	static const char *const bad[] = {
		"\037otel.ctx\037pid=1\n",			/* incomplete */
		"\037otel.ctx\037pid=1\037ppid=1\037tid=1\037uid=1\037ruid=1"
		    "\037gid=1\037rgid=1\037jid=0\n",		/* no execname */
		"\037otel.ctx\037ppid=1\037tid=1\037uid=1\037ruid=1\037gid=1"
		    "\037rgid=1\037jid=0\037execname=x\n",	/* no pid */
		"\037otel.ctx\037pid=x\n",
		"\037otel.ctx\037pid=1\037uid=y\n",
		"\037otel.ctx\037pid=1\037junk\n",
	};
	struct dtotel *d;
	size_t i;

	d = open_bridge(NULL);
	deliver(d, "line[3]: a\n", 0, 5, 1, 0);
	for (i = 0; i < nitems(bad); i++)
		deliver(d, bad[i], 0, 5, 1, 0);
	dtotel_flush(d);
	ATF_REQUIRE_EQ(1, cap.nevents);
	ATF_REQUIRE_EQ(3, cap.events[0].pid);
	ATF_REQUIRE_EQ(OE_CTX_CPU, cap.events[0].ctx.flags);
	dtotel_close(d);
}

/* Jail names are looked up once per jail and the cache is bounded. */
ATF_TC_WITHOUT_HEAD(context_jail_cache);
ATF_TC_BODY(context_jail_cache, tc)
{
	struct dtotel *d;
	char rec[256];
	int i;

	d = open_bridge(NULL);
	for (i = 0; i < 3; i++)
		deliver(d, CTX(1, 7, "a"), 0, (uint64_t)i, 1, 0);
	ATF_REQUIRE_EQ(1, stub.jail_lookups);
	/* More jails than the cache holds, then the first again. */
	for (i = 1; i <= 40; i++) {
		snprintf(rec, sizeof(rec), "\037otel.ctx\037pid=1\037ppid=1"
		    "\037tid=1\037uid=1\037ruid=1\037gid=1\037rgid=1\037jid=%d"
		    "\037execname=a\n", i == 40 ? 200 : i + 10);
		deliver(d, rec, 0, 100 + (uint64_t)i, 1, 0);
	}
	ATF_REQUIRE_EQ(41, stub.jail_lookups);
	deliver(d, CTX(1, 7, "a"), 0, 999, 1, 0);
	ATF_REQUIRE_EQ(42, stub.jail_lookups);
	dtotel_close(d);
}

/*
 * A span in the probe's own process carries the process context and
 * CPU; one attributed elsewhere carries only its thread.
 */
ATF_TC_WITHOUT_HEAD(span_context);
ATF_TC_BODY(span_context, tc)
{
	struct dtotel *d;

	d = open_bridge(NULL);
	deliver(d, "\037otel.span\037name=own\037start=1\037end=2\037thread=100"
	    "\037pid=42\037execname=nginx\037ppid=1\037uid=80\037ruid=1001"
	    "\037gid=80\037rgid=1001\037jid=5\n", 6, 2, 1, 0);
	deliver(d, "\037otel.span\037name=other\037start=1\037end=2"
	    "\037thread=55\037pid=7\037execname=sh\n", 6, 2, 1, 0);
	deliver(d, "\037otel.span\037name=bare\037start=1\037end=2\n", -1, 2,
	    0, 0);
	deliver(d, "\037otel.span\037name=noprobe\037start=1\037end=2"
	    "\037thread=1\037pid=1\037execname=a\037ppid=1\037uid=1"
	    "\037ruid=1\037gid=1\037rgid=1\037jid=0\n", -1, 2, 0, 0);
	ATF_REQUIRE_EQ(4, cap.nspans);
	ATF_REQUIRE_EQ(ALLCTX, cap.spans[0].ctx.flags);
	ATF_REQUIRE_EQ(6, cap.spans[0].ctx.cpu);
	ATF_REQUIRE_EQ(100, cap.spans[0].ctx.tid);
	ATF_REQUIRE_EQ(5, cap.spans[0].ctx.jid);
	ATF_REQUIRE_EQ(OE_CTX_TID | OE_CTX_PID, cap.spans[1].ctx.flags);
	ATF_REQUIRE_EQ(55, cap.spans[1].ctx.tid);
	ATF_REQUIRE_EQ(0, cap.spans[2].ctx.flags);
	ATF_REQUIRE_EQ(ALLCTX & ~OE_CTX_CPU, cap.spans[3].ctx.flags);
	/* A bad context field makes the span malformed. */
	deliver(d, "\037otel.span\037name=x\037start=1\037end=2\037uid=q\n",
	    0, 2, 1, 0);
	ATF_REQUIRE_EQ(4, cap.nspans);
	dtotel_close(d);
}

/* ---------------------------------------------------------------- */
/* HyperTrace guests							*/

/* Deliver a chunk from a guest probe (vmid in the edesc or pdesc). */
static int
deliver_vm(struct dtotel *d, const char *text, uint64_t hrtime,
    uint16_t edesc_vmid, uint16_t pdesc_vmid, const char *target)
{
	dtrace_bufdata_t bd;
	dtrace_probedata_t pd;
	dtrace_eprobedesc_t ed;
	dtrace_probedesc_t pdesc;

	(void)d;
	memset(&bd, 0, sizeof(bd));
	memset(&pd, 0, sizeof(pd));
	memset(&ed, 0, sizeof(ed));
	pdesc = test_pdesc;
	pdesc.dtpd_vmid = pdesc_vmid;
	strlcpy(pdesc.dtpd_target, target, sizeof(pdesc.dtpd_target));
	ed.dtepd_epid = 3;
	ed.dtepd_vmid = edesc_vmid;
	pd.dtpda_timestamp = hrtime;
	pd.dtpda_edesc = &ed;
	pd.dtpda_pdesc = &pdesc;
	bd.dtbda_buffered = text;
	bd.dtbda_probe = &pd;
	return (stub.bufhandler(&bd, stub.bufarg));
}

static struct dtotel *
open_guest_bridge(void)
{
	struct dtotel_config cfg;
	struct dtotel *d;

	memset(&cap, 0, sizeof(cap));
	cap.e.ops = &cap_ops;
	memset(&stub, 0, sizeof(stub));
	nguests = 0;
	guest_fail = 0;
	memset(&cfg, 0, sizeof(cfg));
	cfg.dtp = (dtrace_hdl_t *)&stub;
	cfg.exporter = &cap.e;
	cfg.profile = "prof";
	cfg.guest_exporter = make_guest;
	cfg.guest_arg = &guests;
	d = dtotel_open(&cfg);
	ATF_REQUIRE(d != NULL);
	ATF_REQUIRE_EQ(0, dtotel_handle(d));
	return (d);
}

/*
 * Each guest's records go to its own exporter (its own resource),
 * identified by the registered name and epoch; the host's stay on
 * the host exporter.
 */
ATF_TC_WITHOUT_HEAD(guest_routing);
ATF_TC_BODY(guest_routing, tc)
{
	struct dtotel *d;

	d = open_guest_bridge();
	ATF_REQUIRE_EQ(0, dtotel_guest(d, 3, 9, "vm1"));
	ATF_REQUIRE_EQ(0, dtotel_guest(d, 0, 1, "host"));	/* ignored */
	ATF_REQUIRE_EQ(0, dtotel_guest(d, 3, 9, "vm1"));	/* no change */
	deliver(d, "host line\n", 0, 10, 1, 0);
	deliver_vm(d, "guest line\n", 11, 3, 0, "vm1");
	/* The VMID can come from the probe description too. */
	deliver_vm(d, "\037otel.span\037name=g\037start=1\037end=2\n", 12, 0,
	    3, "vm1");
	/* An unregistered guest is named after its probes' target. */
	deliver_vm(d, "other guest\n", 13, 7, 0, "vm7");
	dtotel_flush(d);
	ATF_REQUIRE_EQ(1, cap.nevents);
	ATF_REQUIRE_STREQ("host line", cap.events[0].body);
	ATF_REQUIRE_EQ(2, nguests);
	ATF_REQUIRE_STREQ("3/9/vm1", guests[0]->ident);
	ATF_REQUIRE_EQ(1, guests[0]->started);
	ATF_REQUIRE_EQ(1, guests[0]->events);
	ATF_REQUIRE_EQ(1, guests[0]->spans);
	ATF_REQUIRE_STREQ("guest line", guests[0]->lastbody);
	ATF_REQUIRE_STREQ("7/0/vm7", guests[1]->ident);
	ATF_REQUIRE_EQ(1, guests[1]->events);
	/* A new epoch is a new resource; the old one is shut down. */
	ATF_REQUIRE_EQ(0, dtotel_guest(d, 3, 10, "vm1"));
	ATF_REQUIRE(guests[0]->freed && guests[0]->shutdown == 1);
	deliver_vm(d, "after restart\n", 20, 3, 0, "vm1");
	dtotel_flush(d);
	ATF_REQUIRE_EQ(3, nguests);
	ATF_REQUIRE_STREQ("3/10/vm1", guests[2]->ident);
	/* A rename is too; NULL keeps the name. */
	ATF_REQUIRE_EQ(0, dtotel_guest(d, 3, 11, NULL));
	deliver_vm(d, "x\n", 21, 3, 0, "vm1");
	ATF_REQUIRE_EQ(0, dtotel_guest(d, 3, 11, "renamed"));
	deliver_vm(d, "y\n", 22, 3, 0, "renamed");
	dtotel_flush(d);
	ATF_REQUIRE_STREQ("3/11/vm1", guests[3]->ident);
	ATF_REQUIRE_STREQ("x", guests[3]->lastbody);
	ATF_REQUIRE_STREQ("3/11/renamed", guests[4]->ident);
	ATF_REQUIRE_EQ(0, dtotel_shutdown(d));
	ATF_REQUIRE(guests[1]->freed && guests[4]->freed);
	dtotel_close(d);
}

/* Guests supply resource attributes with otel.resource records. */
ATF_TC_WITHOUT_HEAD(guest_resource_records);
ATF_TC_BODY(guest_resource_records, tc)
{
	struct dtotel *d;
	char rec[512];
	int i, n;

	d = open_guest_bridge();
	deliver_vm(d, "\037otel.resource\037host.name=web1\037os.type=freebsd"
	    "\037bad\037=x\n", 1, 4, 0, "vm4");
	deliver_vm(d, "first\n", 2, 4, 0, "vm4");
	dtotel_flush(d);
	ATF_REQUIRE_EQ(1, nguests);
	ATF_REQUIRE_STREQ("4/0/vm4/host.name=web1/os.type=freebsd",
	    guests[0]->ident);
	/* An unchanged value keeps the exporter... */
	deliver_vm(d, "\037otel.resource\037host.name=web1\n", 3, 4, 0, "vm4");
	ATF_REQUIRE(!guests[0]->freed);
	/* ...a pending guest line is flushed before a change... */
	deliver_vm(d, "pending\n", 4, 4, 0, "vm4");
	deliver_vm(d, "\037otel.resource\037host.name=web2\n", 5, 4, 0, "vm4");
	ATF_REQUIRE(guests[0]->freed);
	ATF_REQUIRE_STREQ("pending", guests[0]->lastbody);
	deliver_vm(d, "second\n", 6, 4, 0, "vm4");
	dtotel_flush(d);
	ATF_REQUIRE_STREQ("4/0/vm4/host.name=web2/os.type=freebsd",
	    guests[1]->ident);
	/* The attribute table is bounded. */
	n = snprintf(rec, sizeof(rec), "\037otel.resource");
	for (i = 0; i < 12; i++)
		n += snprintf(rec + n, sizeof(rec) - (size_t)n, "\037k%d=%d", i, i);
	snprintf(rec + n, sizeof(rec) - (size_t)n, "\n");
	deliver_vm(d, rec, 7, 4, 0, "vm4");
	deliver_vm(d, "third\n", 8, 4, 0, "vm4");
	dtotel_flush(d);
	ATF_REQUIRE(strstr(guests[2]->ident, "/k5=5") != NULL);
	ATF_REQUIRE(strstr(guests[2]->ident, "/k6=6") == NULL);
	/* A resource record for an unknown guest registers it. */
	deliver_vm(d, "\037otel.resource\037host.name=n\n", 9, 8, 0, "vm8");
	/* Host probes cannot change the host resource. */
	deliver(d, "\037otel.resource\037host.name=evil\n", 0, 9, 1, 0);
	deliver_vm(d, "z\n", 10, 8, 0, "vm8");
	dtotel_flush(d);
	ATF_REQUIRE_STREQ("8/0/vm8/host.name=n", guests[3]->ident);
	dtotel_close(d);
}

/*
 * Without a callback guests share the host exporter; a failing
 * callback falls back to it with a warning; a failing shutdown is
 * reported.
 */
ATF_TC_WITHOUT_HEAD(guest_fallbacks);
ATF_TC_BODY(guest_fallbacks, tc)
{
	struct dtotel *d;

	d = open_bridge(NULL);
	ATF_REQUIRE_EQ(0, dtotel_guest(d, 2, 1, "vm2"));
	deliver_vm(d, "guest\n", 1, 2, 0, "vm2");
	deliver_vm(d, "\037otel.resource\037host.name=x\n", 1, 2, 0, "vm2");
	dtotel_flush(d);
	ATF_REQUIRE_EQ(1, cap.nevents);
	dtotel_close(d);

	d = open_guest_bridge();
	guest_fail = 1;
	deliver_vm(d, "guest\n", 1, 2, 0, "vm2");
	deliver_vm(d, "guest again\n", 2, 2, 0, "vm2");
	dtotel_flush(d);
	ATF_REQUIRE_EQ(2, cap.nevents);
	guest_fail = 2;
	deliver_vm(d, "z\n", 3, 5, 0, "vm5");
	ATF_REQUIRE_EQ(-1, dtotel_shutdown(d));
	/* Retiring on an epoch change reports the failure too. */
	deliver_vm(d, "z\n", 4, 6, 0, "vm6");
	ATF_REQUIRE_EQ(-1, dtotel_guest(d, 6, 2, "vm6"));
	/* A failing resource-driven retire marks the session. */
	deliver_vm(d, "z\n", 5, 6, 0, "vm6");
	deliver_vm(d, "\037otel.resource\037a=b\n", 6, 6, 0, "vm6");
	ATF_REQUIRE(dtotel_error(d));
	guest_fail = 0;
	dtotel_close(d);
}

/* Guest aggregation data is a separate snapshot on the guest. */
ATF_TC_WITHOUT_HEAD(guest_aggregations);
ATF_TC_BODY(guest_aggregations, tc)
{
	struct dtotel *d;
	struct fake_agg *fa[2];
	dtrace_eprobedesc_t ed;
	int64_t v = 5;

	d = open_guest_bridge();
	ATF_REQUIRE_EQ(0, dtotel_guest(d, 3, 1, "vm1"));
	fa[0] = fake_new("c", 0);
	fake_rec(fa[0], DTRACEAGG_COUNT, 0, &v, sizeof(v));
	fa[1] = fake_new("c", 0);
	fake_rec(fa[1], DTRACEAGG_COUNT, 0, &v, sizeof(v));
	memset(&ed, 0, sizeof(ed));
	ed.dtepd_vmid = 3;
	fa[1]->ad.dtada_edesc = &ed;
	run_aggs(d, fa, 2);
	ATF_REQUIRE_EQ(1, cap.nsnaps);
	ATF_REQUIRE_EQ(1, nguests);
	ATF_REQUIRE_EQ(1, guests[0]->snaps);
	fake_free(fa[0]);
	fake_free(fa[1]);
	dtotel_close(d);
}

/*
 * dtrace(1) output: successive trace() records of one firing join a
 * single line, a firing that printed nothing yields its probe name
 * (unless quiet), and a new firing never joins an open line.
 */
ATF_TC_WITHOUT_HEAD(dtrace_records);
ATF_TC_BODY(dtrace_records, tc)
{
	struct dtotel *d;
	dtrace_probedata_t pd;
	dtrace_eprobedesc_t ed;

	d = open_bridge(NULL);
	deliver(d, "               7", 0, 10, 1, 0);
	deliver(d, "  hello", 0, 10, 1, 0);
	deliver(d, "               9", 0, 20, 1, 0);	/* new firing */
	memset(&pd, 0, sizeof(pd));
	memset(&ed, 0, sizeof(ed));
	ed.dtepd_epid = 1;
	pd.dtpda_cpu = 0;
	pd.dtpda_timestamp = 20;
	pd.dtpda_edesc = &ed;
	pd.dtpda_pdesc = &test_pdesc;
	dtotel_firing_end(d, &pd, 0);		/* had output: nothing */
	pd.dtpda_timestamp = 30;
	dtotel_firing_end(d, &pd, 1);		/* quiet: nothing */
	dtotel_firing_end(d, &pd, 0);		/* default output */
	pd.dtpda_pdesc = NULL;
	pd.dtpda_timestamp = 40;
	dtotel_firing_end(d, &pd, 0);		/* no probe: nothing */
	dtotel_flush(d);
	ATF_REQUIRE_EQ(3, cap.nevents);
	ATF_REQUIRE_STREQ("7 hello", cap.events[0].body);
	ATF_REQUIRE_STREQ("9", cap.events[1].body);
	ATF_REQUIRE_STREQ("syscall:freebsd:open:entry", cap.events[2].body);
	dtotel_close(d);
}

/* ---------------------------------------------------------------- */
/* Sessions (dtrace(1)'s -x otel)					*/

ATF_TC_WITHOUT_HEAD(session_options);
ATF_TC_BODY(session_options, tc)
{
	static const struct {
		const char *name, *value;
		int ret;
	} opts[] = {
		{ "bufsize", "4m", 0 }, { "otel", NULL, -1 },
		{ "otel", "xml", -1 }, { "otel", "otlp", 1 },
		{ "otel", "otlp-json", 1 }, { "otel", "json", 1 },
		{ "otelendpoint", NULL, -1 }, { "otelendpoint", "", -1 },
		{ "otelendpoint", "http://h:1", 1 }, { "otelspool", "s", 1 },
		{ "otelspoolmax", "2k", 1 }, { "otelspoolmax", "x", -1 },
		{ "otelspoolmax", "0", -1 }, { "otelspoolmax", "9q", -1 },
		{ "otelspoolmax", "1kk", -1 },
		{ "otelspoolmax", "99999999999999999g", -1 },
		{ "otelspoolmax", "999999999999999999999", -1 },
		{ "otelrotatesize", "1m", 1 }, { "otelrotatesize", "-1", -1 },
		{ "otelrotatetime", "2h", 1 }, { "otelrotatetime", "1y", -1 },
		{ "otelrotatekeep", "3", 1 }, { "otelrotatekeep", "1000", -1 },
		{ "otelrotatekeep", "3k", -1 }, { "otelbogus", "1", -1 },
	};
	struct dtotel_options o;
	char err[256];
	size_t i;

	memset(&o, 0, sizeof(o));
	for (i = 0; i < nitems(opts); i++)
		ATF_REQUIRE_EQ_MSG(opts[i].ret, dtotel_option(&o, opts[i].name,
		    opts[i].value, err, sizeof(err)), "%s=%s", opts[i].name,
		    opts[i].value != NULL ? opts[i].value : "(null)");
	ATF_REQUIRE_EQ(DTOTEL_JSON, o.format);
	ATF_REQUIRE_EQ(2048, o.spool_max);
	ATF_REQUIRE_EQ(1024 * 1024, o.rotate_size);
	ATF_REQUIRE_EQ(7200, o.rotate_interval);
	ATF_REQUIRE_EQ(3, o.rotate_keep);
}

ATF_TC_WITHOUT_HEAD(session_options_check);
ATF_TC_BODY(session_options_check, tc)
{
	struct dtotel_options o;
	char err[256];

	memset(&o, 0, sizeof(o));
	ATF_REQUIRE_EQ(0, dtotel_options_check(&o, NULL, err, sizeof(err)));
	o.rotate_keep = 1;
	ATF_REQUIRE_EQ(-1, dtotel_options_check(&o, NULL, err, sizeof(err)));
	ATF_REQUIRE(strstr(err, "need -x otel") != NULL);
	memset(&o, 0, sizeof(o));
	o.format = DTOTEL_OTLP;
	ATF_REQUIRE_EQ(0, dtotel_options_check(&o, NULL, err, sizeof(err)));
	ATF_REQUIRE_EQ(-1, dtotel_options_check(&o, "f", err, sizeof(err)));
	o.rotate_interval = 1;
	ATF_REQUIRE_EQ(-1, dtotel_options_check(&o, NULL, err, sizeof(err)));
	o.rotate_interval = 0;
	o.spool_max = 1;
	ATF_REQUIRE_EQ(-1, dtotel_options_check(&o, NULL, err, sizeof(err)));
	o.spool = "s";
	ATF_REQUIRE_EQ(0, dtotel_options_check(&o, NULL, err, sizeof(err)));
	o.format = DTOTEL_JSON;
	ATF_REQUIRE_EQ(-1, dtotel_options_check(&o, NULL, err, sizeof(err)));
	memset(&o, 0, sizeof(o));
	o.format = DTOTEL_OTLPJSON;
	o.rotate_size = 1;
	ATF_REQUIRE_EQ(-1, dtotel_options_check(&o, NULL, err, sizeof(err)));
	ATF_REQUIRE_EQ(0, dtotel_options_check(&o, "f", err, sizeof(err)));
}

static struct dtotel_session *
session_on(enum dtotel_format fmt, const char *output, int hypertrace,
    const char *spool)
{
	static struct dtotel_options o;
	struct dtotel_session_config cfg;
	struct dtotel_session *s;
	char err[256];

	memset(&stub, 0, sizeof(stub));
	memset(&o, 0, sizeof(o));
	o.format = fmt;
	o.endpoint = "http://127.0.0.1:9";
	o.spool = spool;
	memset(&cfg, 0, sizeof(cfg));
	cfg.options = &o;
	cfg.dtp = (dtrace_hdl_t *)&stub;
	cfg.output = output;
	cfg.service_name = "dtrace";
	cfg.service_version = "Sun D 1.13";
	cfg.scope_name = "dtrace";
	cfg.profile = "script";
	cfg.source = "@c[execname] = count();";
	cfg.hypertrace = hypertrace;
	s = dtotel_session_open(&cfg, err, sizeof(err));
	ATF_REQUIRE_MSG(s != NULL, "%s", err);
	ATF_REQUIRE(stub.bufhandler == dtotel_buffered);
	return (s);
}

static char *
read_file(const char *path)
{
	FILE *fp;
	char *buf;
	long n;

	fp = fopen(path, "r");
	ATF_REQUIRE(fp != NULL);
	fseek(fp, 0, SEEK_END);
	n = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	buf = calloc(1, (size_t)n + 1);
	ATF_REQUIRE_EQ((size_t)n, fread(buf, 1, (size_t)n, fp));
	fclose(fp);
	return (buf);
}

static void
validate_lines(const char *text, struct otlp_counts *c)
{
	char *copy, *line, *last, err[512];
	struct jv *v;

	memset(c, 0, sizeof(*c));
	copy = strdup(text);
	for (line = strtok_r(copy, "\n", &last); line != NULL;
	    line = strtok_r(NULL, "\n", &last)) {
		v = jv_parse(line, strlen(line), err, sizeof(err));
		ATF_REQUIRE_MSG(v != NULL, "%s", err);
		ATF_REQUIRE_MSG(otlp_validate_request(v, c, err,
		    sizeof(err)) == 0, "%s", err);
		jv_free(v);
	}
	free(copy);
}

/*
 * A HyperTrace session writes the host's and each guest's records as
 * separate resources; the guest's describes the VM (name, id, epoch,
 * the hypervisor), not the host machine, and its own attributes win.
 */
ATF_TC_WITHOUT_HEAD(session_guest_resources);
ATF_TC_BODY(session_guest_resources, tc)
{
	struct dtotel_session *s;
	struct otlp_counts c;
	struct fake_agg *fa;
	int64_t v = 2;
	char *text, *guestline;

	setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment.name=lab",
	    1);
	s = session_on(DTOTEL_OTLPJSON, "out.jsonl", 1, NULL);
	unsetenv("OTEL_RESOURCE_ATTRIBUTES");
	ATF_REQUIRE_EQ(0, dtotel_guest(dtotel_session_bridge(s), 3, 9, "vm3"));
	deliver(NULL, "host line\n", 0, 10, 1, 0);
	deliver_vm(NULL, "\037otel.resource\037os.type=freebsd\n", 11, 3, 0,
	    "vm3");
	deliver_vm(NULL, "guest line\n", 12, 3, 0, "vm3");
	fa = fake_new("c", 0);
	fake_rec(fa, DTRACEAGG_COUNT, 0, &v, sizeof(v));
	{
		const dtrace_aggdata_t *ads[1] = { &fa->ad };

		stub.aggs = ads;
		stub.naggs = 1;
		ATF_REQUIRE_EQ(0, dtotel_session_tick(s));	/* < 1 s */
		ATF_REQUIRE_EQ(0, dtotel_session_flush(s));
		ATF_REQUIRE_EQ(0, dtotel_session_close(s, 1));
		stub.naggs = 0;
	}
	fake_free(fa);
	text = read_file("out.jsonl");
	validate_lines(text, &c);
	ATF_REQUIRE_EQ(2, c.logs);
	ATF_REQUIRE_EQ(1, c.metrics);
	guestline = strstr(text, "hypertrace.vm.name");
	ATF_REQUIRE(guestline != NULL);
	ATF_REQUIRE(strstr(text, "{\"key\":\"hypertrace.vm.id\",\"value\":"
	    "{\"stringValue\":\"3\"}},{\"key\":\"hypertrace.vm.epoch\","
	    "\"value\":{\"stringValue\":\"9\"}}") != NULL);
	ATF_REQUIRE(strstr(text, "{\"key\":\"host.name\",\"value\":"
	    "{\"stringValue\":\"vm3\"}}") != NULL);
	ATF_REQUIRE(strstr(text, "\"deployment.environment.name\"") != NULL);
	ATF_REQUIRE(strstr(text, "\"scope\":{\"name\":\"dtrace\"") != NULL);
	free(text);
}

ATF_TC_WITHOUT_HEAD(session_formats);
ATF_TC_BODY(session_formats, tc)
{
	struct dtotel_session *s;
	char err[256], *text;

	/* JSON to a file: guest lines name their resource. */
	s = session_on(DTOTEL_JSON, "out.json", 1, NULL);
	deliver_vm(NULL, "guest\n", 1, 4, 0, "vm4");
	deliver(NULL, "host\n", 0, 2, 1, 0);
	ATF_REQUIRE_EQ(0, dtotel_session_close(s, 1));
	text = read_file("out.json");
	ATF_REQUIRE(strstr(text, "\"resource\":{\"hypertrace.vm.name\":"
	    "\"vm4\",\"hypertrace.vm.id\":\"4\"") != NULL);
	free(text);
	/* OTLP/HTTP to a refusing port, spooling per guest. */
	s = session_on(DTOTEL_OTLP, NULL, 1, "spool.jsonl");
	deliver_vm(NULL, "guest\n", 1, 5, 0, "vm5");
	ATF_REQUIRE_EQ(0, dtotel_session_close(s, 1));
	text = read_file("spool.jsonl.vm5");
	ATF_REQUIRE(strstr(text, "\"hypertrace.vm.name\"") != NULL);
	free(text);
	/* Not HyperTrace: guest records stay on the host resource. */
	s = session_on(DTOTEL_OTLPJSON, NULL, 0, NULL);
	ATF_REQUIRE_EQ(0, dtotel_session_clock(s, (dtrace_hdl_t *)&stub, err,
	    sizeof(err)));
	ATF_REQUIRE_EQ(1, stub.compiled);
	stub.fail_exec = 1;
	ATF_REQUIRE_EQ(-1, dtotel_session_clock(s, (dtrace_hdl_t *)&stub, err,
	    sizeof(err)));
	ATF_REQUIRE(strstr(err, "cannot enable") != NULL);
	stub.fail_exec = 0;
	stub.fail_compile = 1;
	ATF_REQUIRE_EQ(-1, dtotel_session_clock(s, (dtrace_hdl_t *)&stub, err,
	    sizeof(err)));
	ATF_REQUIRE(strstr(err, "cannot compile") != NULL);
	stub.fail_compile = 0;
	/* A failing final snapshot fails the close. */
	stub.fail_snap = 1;
	ATF_REQUIRE_EQ(-1, dtotel_session_close(s, 1));
	ATF_REQUIRE_EQ(0, dtotel_session_close(NULL, 1));
}

ATF_TC(session_tick);
ATF_TC_HEAD(session_tick, tc)
{

	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(session_tick, tc)
{
	struct dtotel_session *s;
	struct stat st;

	s = session_on(DTOTEL_OTLPJSON, "t.jsonl", 0, NULL);
	deliver(NULL, "line\n", 0, 2, 1, 0);
	deliver(NULL, "next\n", 0, 3, 1, 0);	/* flushes "line" */
	/* The first tick writes both: the pending record is complete. */
	ATF_REQUIRE_EQ(0, dtotel_session_tick(s));
	ATF_REQUIRE(stat("t.jsonl", &st) == 0 && st.st_size > 0);
	ATF_REQUIRE(atf_utils_grep_file("\"next\"", "t.jsonl"));
	/* A record the bridge cannot hand on fails the next tick. */
	deliver(NULL, "more\n", 0, 4, 1, 0);
	usleep(1100000);
	failalloc_arm(1);
	ATF_REQUIRE_EQ(-1, dtotel_session_tick(s));
	failalloc_arm(0);
	ATF_REQUIRE_EQ(-1, dtotel_session_close(s, 0));
	/* OTLP/HTTP hands on the record; its batches stay with the sender. */
	s = session_on(DTOTEL_OTLP, NULL, 0, NULL);
	deliver(NULL, "line\n", 0, 2, 1, 0);
	ATF_REQUIRE_EQ(0, dtotel_session_tick(s));
	ATF_REQUIRE_EQ(0, dtotel_session_close(s, 0));
}

ATF_TC_WITHOUT_HEAD(session_open_errors);
ATF_TC_BODY(session_open_errors, tc)
{
	struct dtotel_options o;
	struct dtotel_session_config cfg;
	char err[256];

	memset(&stub, 0, sizeof(stub));
	memset(&o, 0, sizeof(o));
	memset(&cfg, 0, sizeof(cfg));
	cfg.options = &o;
	cfg.dtp = (dtrace_hdl_t *)&stub;
	cfg.service_name = "dtrace";
	cfg.service_version = "1";
	cfg.scope_name = "dtrace";
	o.format = DTOTEL_OTLPJSON;
	cfg.output = "nodir/x";
	ATF_REQUIRE(dtotel_session_open(&cfg, err, sizeof(err)) == NULL);
	ATF_REQUIRE(strstr(err, "cannot open the OpenTelemetry output") !=
	    NULL);
	cfg.output = NULL;
	o.format = DTOTEL_OTLP;
	o.endpoint = "gopher://x";
	ATF_REQUIRE(dtotel_session_open(&cfg, err, sizeof(err)) == NULL);
	ATF_REQUIRE(strstr(err, "cannot create") != NULL);
	o.endpoint = NULL;
	stub.fail_handle_buffered = 1;
	ATF_REQUIRE(dtotel_session_open(&cfg, err, sizeof(err)) == NULL);
	ATF_REQUIRE(strstr(err, "cannot start") != NULL);
	stub.fail_handle_buffered = 0;
	/* OTEL_SERVICE_NAME and service.name in the attributes. */
	setenv("OTEL_RESOURCE_ATTRIBUTES", "service.name=a", 1);
	setenv("OTEL_SERVICE_NAME", "b", 1);
	{
		struct dtotel_session *s;

		o.format = DTOTEL_JSON;
		s = dtotel_session_open(&cfg, err, sizeof(err));
		ATF_REQUIRE(s != NULL);
		ATF_REQUIRE_EQ(0, dtotel_session_close(s, 0));
	}
	unsetenv("OTEL_SERVICE_NAME");
	unsetenv("OTEL_RESOURCE_ATTRIBUTES");
}


/* ---------------------------------------------------------------- */
/* Edges								*/

ATF_TC_WITHOUT_HEAD(buffered_edges);
ATF_TC_BODY(buffered_edges, tc)
{
	struct dtotel *d;
	char longexec[64];

	d = open_bridge(NULL);
	/* An empty chunk; a record without its newline. */
	deliver(d, "", 0, 1, 1, 0);
	deliver(d, "\037otel.clock\037wall=1700000000000000000\037ts=0", 0, 1, 1,
	    0);
	/* Trailing blanks, an empty last segment without a newline. */
	deliver(d, "body[3]: x   \n   ", 0, 2, 0, 0);
	/* A bare symbol frame, a frame with no line pending. */
	deliver(d, "  just_a_symbol`\n", 0, 2, 0, 0);
	deliver(d, "  plain_symbol_0xnot\n", 0, 2, 0, 0);
	/* A marker-length line that is not the marker. */
	deliver(d, "__BSDINSTRUMENTS_USTACK_X\n", 0, 2, 0, 0);
	/* An open line, then the next chunk from another firing. */
	deliver(d, "open line", 0, 3, 1, 0);
	deliver(d, "other firing\n", 1, 3, 1, 0);
	/* A long execname prefix is not taken as the process. */
	memset(longexec, 'e', sizeof(longexec) - 2);
	longexec[sizeof(longexec) - 2] = '[';
	longexec[sizeof(longexec) - 1] = '\0';
	deliver(d, longexec, 2, 4, 1, 0);
	dtotel_flush(d);
	ATF_REQUIRE(cap.nevents >= 5);
	ATF_REQUIRE_STREQ("body[3]: x", cap.events[0].body);
	ATF_REQUIRE_EQ(1700000000, cap.events[0].ts.tv_sec);
	ATF_REQUIRE_STREQ("", cap.events[cap.nevents - 1].execname);
	dtotel_close(d);
	/* A deep stack and many lines grow their arrays. */
	d = open_bridge(NULL);
	{
		char stk[2048];
		size_t n = 0;

		n += (size_t)snprintf(stk, sizeof(stk), "deep\n");
		for (int k = 0; k < 40; k++)
			n += (size_t)snprintf(stk + n, sizeof(stk) - n,
			    "  kernel`f%d+0x1\n", k);
		deliver(d, stk, 0, 9, 1, 0);
	}
	dtotel_flush(d);
	ATF_REQUIRE_EQ(40, (int)cap.events[0].nstack);
	dtotel_close(d);
	/* Frames with no pending line and no probe data. */
	d = open_bridge(NULL);
	deliver(d, "  kernel`f+0x1\n", -1, 0, 0, 0);
	dtotel_flush(d);
	ATF_REQUIRE_EQ(1, cap.nevents);
	ATF_REQUIRE_STREQ("", cap.events[0].body);
	dtotel_close(d);
}

ATF_TC_WITHOUT_HEAD(record_edges);
ATF_TC_BODY(record_edges, tc)
{
	static const char *const bad[] = {
		"\037otel.ctx\037pid=1\037ppid=\037tid=1\n",
		"\037otel.ctx\037pid=1\037ppid=1x\n",
		"\037otel.span\037name=x\037start=1\037end=2\037a.s.=v\n",
		"\037otel.span\037name=x\037start=1\037end=2\037a.i.=1\n",
	};
	struct dtotel *d;
	size_t i;

	d = open_bridge(NULL);
	for (i = 0; i < nitems(bad); i++)
		deliver(d, bad[i], 0, 1, 1, 0);
	/* "a.i.=1" is an unknown integer field: ignored, span kept. */
	ATF_REQUIRE_EQ(1, cap.nspans);
	dtotel_close(d);
	/* A guest's records with a pdesc vmid but no edesc. */
	d = open_guest_bridge();
	{
		dtrace_bufdata_t bd;
		dtrace_probedata_t pd;
		dtrace_probedesc_t pdesc;

		memset(&bd, 0, sizeof(bd));
		memset(&pd, 0, sizeof(pd));
		pdesc = test_pdesc;
		pdesc.dtpd_vmid = 6;
		pd.dtpda_pdesc = &pdesc;
		bd.dtbda_probe = &pd;
		bd.dtbda_buffered = "guest\n";
		stub.bufhandler(&bd, stub.bufarg);
		/* No probe description at all: the host. */
		pd.dtpda_pdesc = NULL;
		pd.dtpda_timestamp = 9;
		bd.dtbda_buffered = "host\n";
		stub.bufhandler(&bd, stub.bufarg);
	}
	dtotel_flush(d);
	ATF_REQUIRE_EQ(1, nguests);
	ATF_REQUIRE_STREQ("6/0/", guests[0]->ident);
	ATF_REQUIRE_EQ(1, cap.nevents);
	dtotel_close(d);
}

ATF_TC_WITHOUT_HEAD(keyname_edges);
ATF_TC_BODY(keyname_edges, tc)
{
	struct dtotel *d;
	struct fake_agg *fa;
	char src[1200];
	int64_t v = 1;
	uint32_t k = 1;
	int i, n;

	/*
	 * No key list, an over-long name, nested brackets with blanks,
	 * an over-long expression, more keys than tracked.
	 */
	n = snprintf(src, sizeof(src), "@plain = count(); @%0130d[x] = count(); "
	    "@n[ f(a[1]) , \"lit\"  ] = count(); @long[", 0);
	for (i = 0; i < 300; i++)
		src[n++] = 'y';
	n += snprintf(src + n, sizeof(src) - (size_t)n, "] = count(); @many[");
	for (i = 0; i < 18; i++)
		n += snprintf(src + n, sizeof(src) - (size_t)n, "%sk%d",
		    i > 0 ? "," : "", i);
	snprintf(src + n, sizeof(src) - (size_t)n, "] = count();");
	d = open_bridge(src);
	fa = fake_new("n", 2);
	fake_rec(fa, DTRACEACT_DIFEXPR, 0, &k, sizeof(k));
	fake_rec(fa, DTRACEACT_DIFEXPR, 0, "\0\0", 3);	/* empty string */
	fake_rec(fa, DTRACEAGG_COUNT, 0, &v, sizeof(v));
	fa->ad.dtada_normal = 0;			/* treated as 1 */
	run_aggs(d, &fa, 1);
	ATF_REQUIRE_EQ(1, cap.nsnaps);
	ATF_REQUIRE_STREQ("key.0=1;label=;", cap.snaps[0].points[0].attrs);
	fake_free(fa);
	dtotel_close(d);
}

ATF_TC_WITHOUT_HEAD(key_action_edges);
ATF_TC_BODY(key_action_edges, tc)
{
	struct dtotel *d;
	struct fake_agg *fa;
	uint64_t f[2] = { 0x1100, 0 }, u[3] = { 5, 0, 0 }, one = 1;
	int64_t v = 1;

	d = open_bridge(NULL);
	fa = fake_new("k", 6);
	/* nframes 0 in the argument: 8-byte frames assumed. */
	fake_rec(fa, DTRACEACT_STACK, 0, f, sizeof(f));
	/* ustack: no frame limit, a zero frame ends it. */
	fake_rec(fa, DTRACEACT_USTACK, 0, u, sizeof(u));
	fake_rec(fa, DTRACEACT_SYM, 0, &one, 4);		/* too short */
	fake_rec(fa, DTRACEACT_UMOD, 0, u, sizeof(u));
	fake_rec(fa, DTRACEACT_USYM, 0, &one, 4);		/* too short */
	fake_rec(fa, DTRACEACT_DIFEXPR, 0, &one, 8);
	fake_rec(fa, DTRACEAGG_COUNT, 0, &v, sizeof(v));
	run_aggs(d, &fa, 1);
	ATF_REQUIRE_EQ(1, cap.nsnaps);
	ATF_REQUIRE_STREQ("key.0=kernel`fn1+0x0;key.1=pid5;key.2=01000000;"
	    "key.3=0x0;key.4=01000000;key.5=1;", cap.snaps[0].points[0].attrs);
	fake_free(fa);
	dtotel_close(d);
}

ATF_TC_WITHOUT_HEAD(histogram_edges);
ATF_TC_BODY(histogram_edges, tc)
{
	struct dtotel *d;
	struct fake_agg *fa[8];
	int64_t q[DTRACE_QUANTIZE_NBUCKETS + 2], lq[2], llq[24], v[4];
	int i;

	d = open_bridge(NULL);
	/* quantize data longer than the bucket count. */
	memset(q, 0, sizeof(q));
	q[DTRACE_QUANTIZE_ZEROBUCKET] = 1;
	fa[0] = fake_new("q", 0);
	fake_rec(fa[0], DTRACEAGG_QUANTIZE, 0, q, sizeof(q));
	/* lquantize data without its argument word. */
	fa[1] = fake_new("lq", 0);
	fake_rec(fa[1], DTRACEAGG_LQUANTIZE, 0, lq, 4);
	/* llquantize: too short; invalid arguments. */
	fa[2] = fake_new("l1", 0);
	fake_rec(fa[2], DTRACEAGG_LLQUANTIZE, 0, llq, 4);
	memset(llq, 0, sizeof(llq));
	llq[0] = (int64_t)LLQ_ARG(1, 0, 2, 2);		/* factor < 2 */
	fa[3] = fake_new("l2", 0);
	fake_rec(fa[3], DTRACEAGG_LLQUANTIZE, 0, llq, 3 * 8);
	/*
	 * llquantize(x, 10, 1, 2, 20): starts at 10; within an order the
	 * steps are smaller than the order (several bins per order).
	 */
	memset(llq, 0, sizeof(llq));
	llq[0] = (int64_t)LLQ_ARG(10, 1, 2, 20);
	for (i = 2; i < 24; i++)
		llq[i] = i;
	fa[4] = fake_new("l3", 0);
	fake_rec(fa[4], DTRACEAGG_LLQUANTIZE, 0, llq, sizeof(llq));
	/* The other invalid llquantize arguments. */
	{
		static const uint64_t badargs[] = {
			LLQ_ARG(10, 2, 2, 20),		/* low >= high */
			LLQ_ARG(10, 1, 2, 0),		/* no steps */
			LLQ_ARG(10, 1, 2, 5),		/* factor > steps */
		};
		struct fake_agg *b;

		for (i = 0; i < (int)nitems(badargs); i++) {
			memset(llq, 0, sizeof(llq));
			llq[0] = (int64_t)badargs[i];
			b = fake_new("lb", 0);
			fake_rec(b, DTRACEAGG_LLQUANTIZE, 0, llq, 3 * 8);
			run_aggs(d, &b, 1);
			fake_free(b);
		}
		memset(&cap.snaps, 0, sizeof(cap.snaps));
		cap.nsnaps = 0;
	}
	/* stddev whose sum of squares does not exceed the sum squared. */
	v[0] = 1;
	v[1] = 4;
	v[2] = 16;
	v[3] = 0;
	fa[5] = fake_new("sd", 0);
	fake_rec(fa[5], DTRACEAGG_STDDEV, 0, v, sizeof(v));
	/* An aggregation description without records. */
	fa[6] = fake_new("empty", 0);
	fa[6]->desc->dtagd_nrecs = 0;
	run_aggs(d, fa, 7);
	ATF_REQUIRE_EQ(6, cap.nsnaps);
	for (i = 0; i < 7; i++)
		fake_free(fa[i]);
	dtotel_close(d);
}

ATF_TC_WITHOUT_HEAD(bridge_alloc_failure);
ATF_TC_BODY(bridge_alloc_failure, tc)
{
	struct dtotel *d;
	struct fake_agg *fa;
	int64_t v = 1;
	uint32_t k = 3;
	int i;

	for (i = 1; i <= 60; i++) {
		struct dtotel_config cfg;

		memset(&cap, 0, sizeof(cap));
		cap.e.ops = &cap_ops;
		memset(&stub, 0, sizeof(stub));
		memset(&cfg, 0, sizeof(cfg));
		cfg.exporter = &cap.e;
		cfg.source = "@c[pid] = count();";
		cfg.guest_exporter = make_guest;
		cfg.guest_arg = &guests;
		nguests = 0;
		guest_fail = 0;
		fa = fake_new("c", 1);
		fake_rec(fa, DTRACEACT_DIFEXPR, 0, &k, sizeof(k));
		fake_rec(fa, DTRACEAGG_COUNT, 0, &v, sizeof(v));
		failalloc_arm(i);
		d = dtotel_open(&cfg);
		if (d == NULL) {
			failalloc_arm(0);
			fake_free(fa);
			continue;
		}
		(void)dtotel_handle(d);
		deliver(d, "line\n", 0, 1, 1, 0);
		deliver(d, "  kernel`a+0x1\n  kernel`b+0x2\n", 0, 1, 1, 0);
		deliver(d, "more", 0, 1, 1, 0);
		deliver(d, " text\n", 0, 1, 1, 0);
		(void)dtotel_guest(d, 4, 1, "vm4");
		(void)dtotel_guest(d, 4, 2, "vm4b");
		deliver_vm(d, "\037otel.resource\037host.name=h\n", 2, 4, 0, "vm4");
		deliver_vm(d, "g\n", 3, 9, 0, "vm9");
		deliver_vm(d, "\037otel.resource\037a=b\n", 4, 10, 0, "vm10");
		{
			const dtrace_aggdata_t *ads[1] = { &fa->ad };

			stub.aggs = ads;
			stub.naggs = 1;
			(void)dtotel_aggregate(d);
			stub.naggs = 0;
		}
		failalloc_arm(0);
		fake_free(fa);
		dtotel_close(d);
	}
}

ATF_TC_WITHOUT_HEAD(session_edges);
ATF_TC_BODY(session_edges, tc)
{
	struct dtotel_options o;
	struct dtotel_session_config cfg;
	struct dtotel_session *s;
	struct rlimit rl;
	char err[256];
	int i;

	/* Each stray option alone, without -x otel. */
	{
		struct dtotel_options cases[6];

		memset(cases, 0, sizeof(cases));
		cases[0].endpoint = "e";
		cases[1].spool = "s";
		cases[2].spool_max = 1;
		cases[3].rotate_size = 1;
		cases[4].rotate_interval = 1;
		cases[5].rotate_keep = 1;
		for (i = 0; i < 6; i++)
			ATF_REQUIRE_EQ(-1, dtotel_options_check(&cases[i], NULL,
			    err, sizeof(err)));
	}
	memset(&o, 0, sizeof(o));
	o.format = DTOTEL_OTLP;
	o.rotate_size = 1;
	ATF_REQUIRE_EQ(-1, dtotel_options_check(&o, NULL, err, sizeof(err)));
	o.rotate_size = 0;
	o.rotate_keep = 1;
	ATF_REQUIRE_EQ(-1, dtotel_options_check(&o, NULL, err, sizeof(err)));
	memset(&o, 0, sizeof(o));
	o.format = DTOTEL_JSON;
	o.spool = "s";
	ATF_REQUIRE_EQ(-1, dtotel_options_check(&o, NULL, err, sizeof(err)));
	o.spool = NULL;
	o.spool_max = 1;
	ATF_REQUIRE_EQ(-1, dtotel_options_check(&o, NULL, err, sizeof(err)));
	o.spool_max = 0;
	o.rotate_interval = 1;
	ATF_REQUIRE_EQ(-1, dtotel_options_check(&o, NULL, err, sizeof(err)));
	o.rotate_interval = 0;
	o.rotate_keep = 1;
	ATF_REQUIRE_EQ(-1, dtotel_options_check(&o, NULL, err, sizeof(err)));
	o.rotate_keep = 0;
	o.endpoint = "http://x";
	ATF_REQUIRE_EQ(-1, dtotel_options_check(&o, "f", err, sizeof(err)));
	/* The environment's endpoint and timeout reach the exporter. */
	setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9", 1);
	setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "100", 1);
	memset(&o, 0, sizeof(o));
	o.format = DTOTEL_OTLP;
	memset(&cfg, 0, sizeof(cfg));
	cfg.options = &o;
	cfg.dtp = (dtrace_hdl_t *)&stub;
	cfg.service_name = "dtrace";
	cfg.service_version = "1";
	cfg.scope_name = "dtrace";
	memset(&stub, 0, sizeof(stub));
	s = dtotel_session_open(&cfg, err, sizeof(err));
	ATF_REQUIRE(s != NULL);
	ATF_REQUIRE_EQ(0, dtotel_session_close(s, 0));
	unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT");
	unsetenv("OTEL_EXPORTER_OTLP_TIMEOUT");
	/* Twice within a second: one write. */
	s = session_on(DTOTEL_OTLPJSON, "tt.jsonl", 0, NULL);
	ATF_REQUIRE_EQ(0, dtotel_session_tick(s));
	ATF_REQUIRE_EQ(0, dtotel_session_tick(s));
	/* A sink that cannot be written fails the close. */
	signal(SIGXFSZ, SIG_IGN);
	rl.rlim_cur = 0;
	rl.rlim_max = RLIM_INFINITY;
	deliver(NULL, "x\n", 0, 1, 1, 0);
	ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_FSIZE, &rl));
	ATF_REQUIRE_EQ(-1, dtotel_session_close(s, 1));
	rl.rlim_cur = RLIM_INFINITY;
	setrlimit(RLIMIT_FSIZE, &rl);
	/* Allocation failures while opening a session. */
	for (i = 1; i <= 60; i++) {
		memset(&stub, 0, sizeof(stub));
		failalloc_arm(i);
		s = dtotel_session_open(&cfg, err, sizeof(err));
		failalloc_arm(0);
		if (s != NULL)
			(void)dtotel_session_close(s, 0);
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, clock_program_shape);
	ATF_TP_ADD_TC(tp, probe_time_anchor);
	ATF_TP_ADD_TC(tp, malformed_records);
	ATF_TP_ADD_TC(tp, lines_and_stacks);
	ATF_TP_ADD_TC(tp, frame_forms);
	ATF_TP_ADD_TC(tp, exporter_failure_aborts);
	ATF_TP_ADD_TC(tp, open_and_handle_errors);
	ATF_TP_ADD_TC(tp, agg_scalars);
	ATF_TP_ADD_TC(tp, agg_key_names);
	ATF_TP_ADD_TC(tp, agg_key_actions);
	ATF_TP_ADD_TC(tp, agg_histograms);
	ATF_TP_ADD_TC(tp, agg_errors);
	ATF_TP_ADD_TC(tp, span_records);
	ATF_TP_ADD_TC(tp, span_explicit_keys);
	ATF_TP_ADD_TC(tp, span_ids_salted);
	ATF_TP_ADD_TC(tp, span_unanchored_and_limits);
	ATF_TP_ADD_TC(tp, span_malformed);
	ATF_TP_ADD_TC(tp, context_records);
	ATF_TP_ADD_TC(tp, context_malformed);
	ATF_TP_ADD_TC(tp, context_jail_cache);
	ATF_TP_ADD_TC(tp, span_context);
	ATF_TP_ADD_TC(tp, guest_routing);
	ATF_TP_ADD_TC(tp, guest_resource_records);
	ATF_TP_ADD_TC(tp, guest_fallbacks);
	ATF_TP_ADD_TC(tp, guest_aggregations);
	ATF_TP_ADD_TC(tp, dtrace_records);
	ATF_TP_ADD_TC(tp, session_options);
	ATF_TP_ADD_TC(tp, session_options_check);
	ATF_TP_ADD_TC(tp, session_guest_resources);
	ATF_TP_ADD_TC(tp, session_formats);
	ATF_TP_ADD_TC(tp, session_tick);
	ATF_TP_ADD_TC(tp, session_open_errors);
	ATF_TP_ADD_TC(tp, buffered_edges);
	ATF_TP_ADD_TC(tp, record_edges);
	ATF_TP_ADD_TC(tp, keyname_edges);
	ATF_TP_ADD_TC(tp, key_action_edges);
	ATF_TP_ADD_TC(tp, histogram_edges);
	ATF_TP_ADD_TC(tp, bridge_alloc_failure);
	ATF_TP_ADD_TC(tp, session_edges);
	return (atf_no_error());
}
