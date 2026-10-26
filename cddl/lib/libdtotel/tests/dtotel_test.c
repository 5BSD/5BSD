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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <atf-c.h>
#include <dtrace.h>
#include <sys/hypertrace.h>

#include "dtotel.h"
#include "dtrace_stub.h"

/* ---------------------------------------------------------------- */
/* Capturing exporter						 	*/

#define	CAP_MAX	64

struct cap_event {
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
};

static struct capture cap;

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
	ATF_REQUIRE(strstr(p, "profile:::tick-1s") != NULL);
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
			ATF_REQUIRE_STREQ("execname=nginx;pid=42;syscall=read;",
			    s->points[0].attrs);
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
	ATF_REQUIRE_STREQ("tid=7;probe=entry;module=kernel;provider=fbt;"
	    "label=lit;key.5=7;cpu=7;key.7=7;", cap.snaps[0].points[0].attrs);
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
	return (atf_no_error());
}
