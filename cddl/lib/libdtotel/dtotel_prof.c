/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Profiles (experimental OTLP profiles signal; dtotel_config.profiles).
 *
 * Two sources:
 *
 *  - Stack-only probe firings: a firing that prints only stack() and
 *    ustack() output (the usual profile-997 { stack(); ustack(); }) is
 *    one timestamped sample of its probe's profile.  Firings are grouped
 *    by probe and HyperTrace guest; samples with the same stack and
 *    context merge.  profile-N and tick-N probes give the profile its
 *    period (CPU nanoseconds between samples, from N with its unit, Hz
 *    when none).  These profiles are emitted every DTOTEL_PROF_INTERVAL
 *    seconds (from dtotel_report()), at each aggregation snapshot and at
 *    shutdown, each covering the time since the previous one.
 *
 *  - Stack-keyed count() and sum() aggregations (@[stack()] = count(),
 *    @[execname, ustack()] = sum(arg0)): at each snapshot every series'
 *    growth since the previous snapshot is a sample of the aggregation's
 *    profile (a series that shrank was reset and counts in full); the
 *    other keys become sample attributes.  They are not exported as
 *    metrics as well.
 *
 * Frames are symbolized as libdtrace provides: kernel frames by
 * dtrace_lookup_by_addr(), user frames of aggregation keys by
 * dtrace_uaddr2str() while the process can still be examined (an exited
 * process leaves addresses), printed stacks as libdtrace formatted them.
 * A HyperTrace guest's frames are guest addresses under the mapping
 * "guest[<vmid>]", and its samples go to the guest's exporter, so they
 * carry the guest's resource.
 *
 * Bounds: at most DTOTEL_PROF_MAX_SAMPLES distinct samples and
 * DTOTEL_PROF_MAX_TIMES observations per interval; firings beyond them
 * are dropped and reported once per interval.
 */

#include <sys/param.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <dtrace.h>
#include <sys/hypertrace.h>

#include "dtotel_impl.h"

#define	DTOTEL_PROF_MAX_SAMPLES	65536
#define	DTOTEL_PROF_MAX_TIMES	(1024 * 1024)
#define	PROF_HASH		1024
#define	PROF_MAX_ATTRS		DTOTEL_MAX_AGG_KEYS

/* One distinct sample: its stack, context and observations. */
struct prof_sample {
	char		*key;
	struct oe_frame	*frames;	/* kernel frames, then user frames */
	size_t		 nk, nu;
	pid_t		 pid;
	char		*execname;
	struct oe_context ctx;
	char		*jail_name;	/* ctx.jail_name, owned */
	struct oe_kv	 kv[PROF_MAX_ATTRS];
	char		*kvstr[2 * PROF_MAX_ATTRS];	/* owned */
	size_t		 nkv;
	uint8_t		 trace[OE_TRACE_ID_LEN];
	uint8_t		 span[OE_SPAN_ID_LEN];
	int64_t		 value;		/* aggregation samples */
	struct timespec	*ts;		/* firing samples */
	size_t		 nts, capts;
	struct prof_sample *hnext;	/* hash chain */
	struct prof_sample *gnext;	/* group list */
};

/* The samples of one profile: a probe's firings or an aggregation. */
struct prof_group {
	uint16_t	 vmid;
	int		 is_agg;
	char		*name;		/* probe or aggregation name */
	int		 is_sum;	/* a sum() rather than a count() */
	int64_t		 period;	/* 0: none */
	struct prof_sample *samples, **tail;
	size_t		 nsamples;
	struct prof_group *next;
};

/* The previous value of an aggregation series, for its growth. */
struct prof_prev {
	char		*key;
	int64_t		 value;
	struct prof_prev *next;
};

struct dtotel_prof {
	struct prof_group *groups;	/* firing groups */
	struct prof_group *aggs;	/* aggregation groups, one snapshot */
	struct prof_sample *hash[PROF_HASH];
	size_t		 nsamples, ntimes;
	uint64_t	 dropped;
	struct timespec	 start;		/* of the firing interval */
	struct timespec	 last;		/* CLOCK_MONOTONIC of the last emit */
	struct timespec	 agg_start;	/* previous snapshot */
	struct prof_prev *prev[PROF_HASH];
	struct prof_prev *cur[PROF_HASH];	/* this snapshot's values */
};

/*
 * reallocarray() through realloc() (the tests wrap realloc); the counts
 * are bounded far below an overflow.
 */
static void *
prof_realloc(void *p, size_t n, size_t size)
{

	return (realloc(p, n * size));
}

static unsigned
hash_str(const char *s)
{
	unsigned h = 5381;

	while (*s != '\0')
		h = h * 33 + (unsigned char)*s++;
	return (h % PROF_HASH);
}

static struct dtotel_prof *
prof_get(struct dtotel *d)
{
	struct dtotel_prof *p;

	if (d->prof != NULL)
		return (d->prof);
	if ((p = calloc(1, sizeof(*p))) == NULL)
		return (NULL);
	p->start = d->start;
	p->agg_start = d->start;
	clock_gettime(CLOCK_MONOTONIC, &p->last);
	d->prof = p;
	return (p);
}

static void
sample_free(struct prof_sample *s)
{
	size_t i;

	for (i = 0; i < s->nk + s->nu; i++) {
		free(s->frames[i].module);
		free(s->frames[i].symbol);
	}
	for (i = 0; i < 2 * PROF_MAX_ATTRS; i++)
		free(s->kvstr[i]);
	free(s->frames);
	free(s->execname);
	free(s->jail_name);
	free(s->ts);
	free(s->key);
	free(s);
}

static void
groups_free(struct prof_group *g)
{
	struct prof_group *gn;
	struct prof_sample *s, *sn;

	for (; g != NULL; g = gn) {
		gn = g->next;
		for (s = g->samples; s != NULL; s = sn) {
			sn = s->gnext;
			sample_free(s);
		}
		free(g->name);
		free(g);
	}
}

static void
prev_free(struct prof_prev **tab)
{
	struct prof_prev *p, *n;
	size_t i;

	for (i = 0; i < PROF_HASH; i++) {
		for (p = tab[i]; p != NULL; p = n) {
			n = p->next;
			free(p->key);
			free(p);
		}
		tab[i] = NULL;
	}
}

void
dtotel_prof_free(struct dtotel *d)
{
	struct dtotel_prof *p = d->prof;

	if (p == NULL)
		return;
	groups_free(p->groups);
	groups_free(p->aggs);
	prev_free(p->prev);
	prev_free(p->cur);
	free(p);
	d->prof = NULL;
}

/*
 * The sampling period of a profile-N or tick-N probe, in nanoseconds
 * (N with its unit, or N Hz); 0 for other probes.
 */
static int64_t
probe_period(const char *probe)
{
	static const struct {
		const char *unit;
		int64_t ns;
	} units[] = {
		{ "ns", 1 }, { "nsec", 1 }, { "us", 1000 }, { "usec", 1000 },
		{ "ms", 1000000 }, { "msec", 1000000 },
		{ "s", 1000000000LL }, { "sec", 1000000000LL },
		{ "m", 60000000000LL }, { "min", 60000000000LL },
		{ "h", 3600000000000LL }, { "hour", 3600000000000LL },
		{ "d", 86400000000000LL }, { "day", 86400000000000LL },
	};
	const char *name, *p;
	char *end;
	long long n;
	size_t i;

	if (strncmp(probe, "profile:", 8) != 0)
		return (0);
	name = strrchr(probe, ':') + 1;
	if (strncmp(name, "profile-", 8) == 0)
		p = name + 8;
	else if (strncmp(name, "tick-", 5) == 0)
		p = name + 5;
	else
		return (0);
	if (!isdigit((unsigned char)*p))
		return (0);
	errno = 0;
	n = strtoll(p, &end, 10);
	if (errno != 0 || n <= 0)
		return (0);
	if (*end == '\0' || strcmp(end, "hz") == 0)
		return (1000000000LL / n > 0 ? 1000000000LL / n : 1);
	for (i = 0; i < nitems(units); i++)
		if (strcmp(end, units[i].unit) == 0)
			return (n <= INT64_MAX / units[i].ns ? n * units[i].ns :
			    0);
	return (0);
}

static struct prof_group *
group_for(struct prof_group **list, uint16_t vmid, int is_agg,
    const char *name)
{
	struct prof_group *g;

	for (g = *list; g != NULL; g = g->next)
		if (g->vmid == vmid && strcmp(g->name, name) == 0)
			return (g);
	if ((g = calloc(1, sizeof(*g))) == NULL)
		return (NULL);
	if ((g->name = strdup(name)) == NULL) {
		free(g);
		return (NULL);
	}
	g->vmid = vmid;
	g->is_agg = is_agg;
	g->period = is_agg ? 0 : probe_period(name);
	g->tail = &g->samples;
	g->next = *list;
	*list = g;
	return (g);
}

/* Function-level frame identity: module`symbol, or the address. */
static void
key_frame(struct oe_buf *b, const struct oe_frame *f)
{

	if (f->symbol != NULL)
		oe_buf_appendf(b, "\037%s`%s", f->module != NULL ? f->module :
		    "", f->symbol);
	else
		oe_buf_appendf(b, "\0370x%jx", (uintmax_t)f->addr);
}

static int
copy_frames(struct prof_sample *s, const struct oe_frame *k, size_t nk,
    const struct oe_frame *u, size_t nu)
{
	const struct oe_frame *f;
	size_t i;

	if (nk + nu == 0)
		return (0);
	if ((s->frames = calloc(nk + nu, sizeof(*s->frames))) == NULL)
		return (-1);
	for (i = 0; i < nk + nu; i++) {
		f = i < nk ? &k[i] : &u[i - nk];
		s->frames[i].addr = f->addr;
		s->frames[i].offset = f->offset;
		s->frames[i].has_offset = f->has_offset;
		if ((f->module != NULL &&
		    (s->frames[i].module = strdup(f->module)) == NULL) ||
		    (f->symbol != NULL &&
		    (s->frames[i].symbol = strdup(f->symbol)) == NULL)) {
			s->nk = i + 1;	/* free what was copied */
			return (-1);
		}
	}
	s->nk = nk;
	s->nu = nu;
	return (0);
}

/* Look a sample up by key in the interval's table, or NULL. */
static struct prof_sample *
sample_find(struct dtotel_prof *p, const char *key, unsigned h)
{
	struct prof_sample *s;

	for (s = p->hash[h]; s != NULL; s = s->hnext)
		if (strcmp(s->key, key) == 0)
			return (s);
	return (NULL);
}

static int
push_ts(struct prof_sample *s, const struct timespec *ts)
{
	struct timespec *n;
	size_t nc;

	if (s->nts == s->capts) {
		nc = s->capts == 0 ? 8 : s->capts * 2;
		if ((n = prof_realloc(s->ts, nc, sizeof(*n))) == NULL)
			return (-1);
		s->ts = n;
		s->capts = nc;
	}
	s->ts[s->nts++] = *ts;
	return (0);
}

static void
prof_drop(struct dtotel_prof *p)
{

	if (p->dropped++ == 0)
		fprintf(stderr, "dtotel: profile bounds reached (%d samples, "
		    "%d observations per interval); dropping samples until "
		    "the next profile\n", DTOTEL_PROF_MAX_SAMPLES,
		    DTOTEL_PROF_MAX_TIMES);
}

void
dtotel_prof_firing(struct dtotel *d)
{
	struct dtotel_prof *p;
	struct prof_group *g;
	struct prof_sample *s;
	struct oe_buf kb;
	const char *probe, *exec;
	size_t i;
	unsigned h;

	if ((p = prof_get(d)) == NULL)
		return;
	probe = d->probe != NULL ? d->probe : "";
	exec = d->body_exec != NULL ? d->body_exec : "";
	oe_buf_init(&kb);
	oe_buf_appendf(&kb, "f\037%u\037%s\037%d\037%s\037%u\037%jd\037%d"
	    "\037%d", (unsigned)d->body_vmid, probe,
	    d->body_exec != NULL ? (int)d->body_pid : 0, exec,
	    d->body_ctx.flags, (intmax_t)d->body_ctx.tid, d->body_ctx.cpu,
	    d->body_ctx.jid);
	for (i = 0; i < OE_TRACE_ID_LEN; i++)
		oe_buf_appendf(&kb, "%02x", d->body_trace[i]);
	for (i = 0; i < OE_SPAN_ID_LEN; i++)
		oe_buf_appendf(&kb, "%02x", d->body_span[i]);
	for (i = 0; i < d->kstack.n; i++)
		key_frame(&kb, &d->kstack.frames[i]);
	oe_buf_appendstr(&kb, "\037|");
	for (i = 0; i < d->ustack.n; i++)
		key_frame(&kb, &d->ustack.frames[i]);
	if (kb.error) {
		oe_buf_free(&kb);
		return;
	}
	h = hash_str(kb.data);
	if (p->ntimes >= DTOTEL_PROF_MAX_TIMES) {
		oe_buf_free(&kb);
		prof_drop(p);
		return;
	}
	if ((s = sample_find(p, kb.data, h)) != NULL) {
		oe_buf_free(&kb);
		if (push_ts(s, &d->body_ts) == 0)
			p->ntimes++;
		return;
	}
	if (p->nsamples >= DTOTEL_PROF_MAX_SAMPLES) {
		oe_buf_free(&kb);
		prof_drop(p);
		return;
	}
	if ((g = group_for(&p->groups, d->body_vmid, 0, probe)) == NULL ||
	    (s = calloc(1, sizeof(*s))) == NULL) {
		oe_buf_free(&kb);
		return;
	}
	s->key = kb.data;
	/* The pid is known from a context record only. */
	s->pid = d->body_exec != NULL ? d->body_pid : 0;
	s->ctx = d->body_ctx;
	s->ctx.jail_name = NULL;
	memcpy(s->trace, d->body_trace, OE_TRACE_ID_LEN);
	memcpy(s->span, d->body_span, OE_SPAN_ID_LEN);
	if (copy_frames(s, d->kstack.frames, d->kstack.n, d->ustack.frames,
	    d->ustack.n) != 0 || (d->body_exec != NULL &&
	    (s->execname = strdup(d->body_exec)) == NULL) ||
	    (d->body_ctx.jail_name != NULL && (s->jail_name =
	    strdup(d->body_ctx.jail_name)) == NULL) ||
	    push_ts(s, &d->body_ts) != 0) {
		sample_free(s);
		return;
	}
	s->ctx.jail_name = s->jail_name;
	s->hnext = p->hash[h];
	p->hash[h] = s;
	*g->tail = s;
	g->tail = &s->gnext;
	g->nsamples++;
	p->nsamples++;
	p->ntimes++;
}

/* ---------------------------------------------------------------- */
/* Stack-keyed aggregations						*/

/* A frame from a symbolized "module`symbol+0xoff" string. */
static void
frame_from_string(struct oe_frame *f, const char *s, uint64_t pc)
{

	dtotel_parse_frame(s, f);
	f->addr = pc;
}

/* The kernel (or guest) frames of a stack() key record. */
static int
agg_kframes(struct dtotel *d, const dtrace_recdesc_t *rec, caddr_t addr,
    struct dtotel_frames *fa)
{
	dtrace_syminfo_t si;
	GElf_Sym sym;
	uint64_t pc, nframes;
	uint16_t vmid;
	size_t i;
	char buf[512];

	nframes = HYPERTRACE_STACK_NFRAMES(rec->dtrd_arg);
	if (nframes != 0 && rec->dtrd_size / nframes != sizeof(uint64_t))
		return (-1);
	vmid = HYPERTRACE_STACK_GUEST(rec->dtrd_arg) ?
	    HYPERTRACE_STACK_VMID(rec->dtrd_arg) : 0;
	for (i = 0; i < rec->dtrd_size / sizeof(uint64_t); i++) {
		memcpy(&pc, addr + i * sizeof(pc), sizeof(pc));
		if (pc == 0)
			break;
		if (vmid != 0)
			snprintf(buf, sizeof(buf), "guest[%u]`0x%jx",
			    (unsigned)vmid, (uintmax_t)pc);
		else if (dtrace_lookup_by_addr(d->dtp, pc, &sym, &si) == 0)
			snprintf(buf, sizeof(buf), "%s`%s+0x%jx",
			    si.dts_object, si.dts_name,
			    (uintmax_t)(pc - sym.st_value));
		else
			snprintf(buf, sizeof(buf), "0x%jx", (uintmax_t)pc);
		if (fa->n == fa->cap) {
			struct oe_frame *np;
			size_t nc = fa->cap == 0 ? 16 : fa->cap * 2;

			if ((np = prof_realloc(fa->frames, nc,
			    sizeof(*np))) == NULL)
				return (-1);
			fa->frames = np;
			fa->cap = nc;
		}
		frame_from_string(&fa->frames[fa->n++], buf, pc);
	}
	return (0);
}

/* The user frames of a ustack() key record, and its pid. */
static int
agg_uframes(struct dtotel *d, const dtrace_recdesc_t *rec, caddr_t addr,
    struct dtotel_frames *fa, pid_t *pidp)
{
	uint64_t pid, pc;
	size_t i, nframes;
	char buf[512];

	if (rec->dtrd_size < sizeof(uint64_t))
		return (-1);
	memcpy(&pid, addr, sizeof(pid));
	*pidp = (pid_t)pid;
	nframes = rec->dtrd_size / sizeof(uint64_t) - 1;
	if (DTRACE_USTACK_NFRAMES(rec->dtrd_arg) > 0 &&
	    DTRACE_USTACK_NFRAMES(rec->dtrd_arg) < nframes)
		nframes = DTRACE_USTACK_NFRAMES(rec->dtrd_arg);
	for (i = 0; i < nframes; i++) {
		memcpy(&pc, addr + (i + 1) * sizeof(pc), sizeof(pc));
		if (pc == 0)
			break;
		/* dtrace_uaddr2str() leaves the address when it cannot. */
		(void)dtrace_uaddr2str(d->dtp, (pid_t)pid, pc, buf,
		    sizeof(buf));
		if (fa->n == fa->cap) {
			struct oe_frame *np;
			size_t nc = fa->cap == 0 ? 16 : fa->cap * 2;

			if ((np = prof_realloc(fa->frames, nc,
			    sizeof(*np))) == NULL)
				return (-1);
			fa->frames = np;
			fa->cap = nc;
		}
		frame_from_string(&fa->frames[fa->n++], buf, pc);
	}
	return (0);
}

static void
frames_release(struct dtotel_frames *fa)
{
	size_t i;

	for (i = 0; i < fa->n; i++) {
		free(fa->frames[i].module);
		free(fa->frames[i].symbol);
	}
	free(fa->frames);
	memset(fa, 0, sizeof(*fa));
}

/* Remember this snapshot's value of a series; return the previous one. */
static int
series_prev(struct dtotel_prof *p, const char *key, int64_t value,
    int64_t *prev)
{
	struct prof_prev *e;
	unsigned h;

	h = hash_str(key);
	*prev = 0;
	for (e = p->prev[h]; e != NULL; e = e->next)
		if (strcmp(e->key, key) == 0) {
			*prev = e->value;
			break;
		}
	if ((e = calloc(1, sizeof(*e))) == NULL ||
	    (e->key = strdup(key)) == NULL) {
		free(e);
		return (-1);
	}
	e->value = value;
	e->next = p->cur[h];
	p->cur[h] = e;
	return (0);
}

int
dtotel_prof_agg(struct dtotel *d, const dtrace_aggdata_t *agg,
    const char *aggname, const struct dtotel_keynames *ak, int is_sum,
    int64_t value)
{
	const dtrace_aggdesc_t *desc = agg->dtada_desc;
	const dtrace_recdesc_t *rec;
	struct dtotel_frames kf, uf;
	struct dtotel_prof *p;
	struct prof_group *g;
	struct prof_sample *s;
	struct oe_buf kb, vb;
	char attrname[24];
	int64_t prev, delta;
	pid_t pid;
	uint16_t vmid;
	int i, nkeys, has_stack;
	size_t j;

	nkeys = desc->dtagd_nrecs - 2;
	has_stack = 0;
	for (i = 0; i < nkeys; i++) {
		rec = &desc->dtagd_rec[i + 1];
		if (rec->dtrd_action == DTRACEACT_STACK ||
		    rec->dtrd_action == DTRACEACT_USTACK ||
		    rec->dtrd_action == DTRACEACT_JSTACK)
			has_stack = 1;
	}
	if (!has_stack || (p = prof_get(d)) == NULL)
		return (0);
	vmid = agg->dtada_edesc != NULL ? agg->dtada_edesc->dtepd_vmid : 0;
	memset(&kf, 0, sizeof(kf));
	memset(&uf, 0, sizeof(uf));
	if ((s = calloc(1, sizeof(*s))) == NULL)
		return (1);
	pid = 0;
	oe_buf_init(&kb);
	oe_buf_appendf(&kb, "a\037%u\037%s", (unsigned)vmid, aggname);
	for (i = 0; i < nkeys; i++) {
		rec = &desc->dtagd_rec[i + 1];
		switch (rec->dtrd_action) {
		case DTRACEACT_STACK:
			(void)agg_kframes(d, rec, agg->dtada_data +
			    rec->dtrd_offset, &kf);
			continue;
		case DTRACEACT_USTACK:
		case DTRACEACT_JSTACK:
			(void)agg_uframes(d, rec, agg->dtada_data +
			    rec->dtrd_offset, &uf, &pid);
			continue;
		default:
			break;
		}
		/* Any other key is a sample attribute. */
		oe_buf_init(&vb);
		dtotel_key_string(d, rec, agg->dtada_data, &vb);
		if (ak != NULL && i < ak->n)
			s->kvstr[2 * s->nkv] = strdup(ak->names[i]);
		else {
			snprintf(attrname, sizeof(attrname), "key.%d", i);
			s->kvstr[2 * s->nkv] = strdup(attrname);
		}
		s->kvstr[2 * s->nkv + 1] = vb.error ? NULL :
		    strdup(vb.data != NULL ? vb.data : "");
		oe_buf_free(&vb);
		if (s->kvstr[2 * s->nkv] != NULL &&
		    s->kvstr[2 * s->nkv + 1] != NULL) {
			s->kv[s->nkv].key = s->kvstr[2 * s->nkv];
			s->kv[s->nkv].type = OE_VAL_STRING;
			s->kv[s->nkv].s = s->kvstr[2 * s->nkv + 1];
			oe_buf_appendf(&kb, "\037%s=%s", s->kv[s->nkv].key,
			    s->kv[s->nkv].s);
			s->nkv++;
		}
	}
	for (j = 0; j < kf.n; j++)
		key_frame(&kb, &kf.frames[j]);
	oe_buf_appendf(&kb, "\037|%d", (int)pid);
	for (j = 0; j < uf.n; j++)
		key_frame(&kb, &uf.frames[j]);
	if (kb.error || series_prev(p, kb.data, value, &prev) != 0) {
		oe_buf_free(&kb);
		frames_release(&kf);
		frames_release(&uf);
		sample_free(s);
		return (1);
	}
	/* Growth since the previous snapshot; a reset counts in full. */
	delta = value >= prev ? value - prev : value;
	if (delta == 0 || (g = group_for(&p->aggs, vmid, 1, aggname)) ==
	    NULL) {
		oe_buf_free(&kb);
		frames_release(&kf);
		frames_release(&uf);
		sample_free(s);
		return (1);
	}
	g->is_sum = is_sum;
	s->key = kb.data;
	s->pid = pid;
	s->value = delta;
	if (pid != 0)
		s->ctx.flags = OE_CTX_PID;
	if (copy_frames(s, kf.frames, kf.n, uf.frames, uf.n) != 0) {
		frames_release(&kf);
		frames_release(&uf);
		sample_free(s);
		return (1);
	}
	frames_release(&kf);
	frames_release(&uf);
	*g->tail = s;
	g->tail = &s->gnext;
	g->nsamples++;
	return (1);
}

/* ---------------------------------------------------------------- */
/* Emission								*/

static void
emit_group(struct dtotel *d, const struct prof_group *g,
    const struct timespec *start, const struct timespec *end)
{
	struct oe_profile_sample *ss;
	struct oe_profile pr;
	struct oe_kv attrs[2];
	const struct prof_sample *s;
	size_t i;

	if (g->nsamples == 0)
		return;
	if ((ss = calloc(g->nsamples, sizeof(*ss))) == NULL) {
		d->error = 1;
		return;
	}
	for (i = 0, s = g->samples; s != NULL; s = s->gnext, i++) {
		ss[i].stack = s->frames;
		ss[i].nstack = s->nk;
		ss[i].ustack = s->nu > 0 ? s->frames + s->nk : NULL;
		ss[i].nustack = s->nu;
		ss[i].pid = s->pid;
		ss[i].execname = s->execname;
		ss[i].ctx = s->ctx;
		ss[i].attrs = s->kv;
		ss[i].nattrs = s->nkv;
		memcpy(ss[i].trace_id, s->trace, OE_TRACE_ID_LEN);
		memcpy(ss[i].span_id, s->span, OE_SPAN_ID_LEN);
		if (g->is_agg) {
			ss[i].has_value = 1;
			ss[i].value = s->value;
		} else {
			ss[i].timestamps = s->ts;
			ss[i].ntimestamps = s->nts;
		}
	}
	memset(&pr, 0, sizeof(pr));
	pr.profile = d->profile;
	pr.start = *start;
	pr.end = *end;
	pr.samples = ss;
	pr.nsamples = g->nsamples;
	attrs[0].type = attrs[1].type = OE_VAL_STRING;
	if (g->is_agg) {
		/* The aggregation's own value: a count, or a sum. */
		if (g->is_sum) {
			pr.sample_type = g->name[0] != '\0' ? g->name : "sum";
			pr.sample_unit = "1";
		} else {
			pr.sample_type = "samples";
			pr.sample_unit = "count";
		}
		attrs[0].key = "dtrace.profile.source";
		attrs[0].s = "aggregation";
		attrs[1].key = "dtrace.aggregation";
		attrs[1].s = g->name;
	} else {
		pr.sample_type = "samples";
		pr.sample_unit = "count";
		if (g->period > 0) {
			pr.period_type = "cpu";
			pr.period_unit = "nanoseconds";
			pr.period = g->period;
		}
		attrs[0].key = "dtrace.profile.source";
		attrs[0].s = "firings";
		attrs[1].key = "dtrace.probe";
		attrs[1].s = g->name;
	}
	pr.attrs = attrs;
	pr.nattrs = 2;
	if (oe_profile(dtotel_exporter_for(d, g->vmid, NULL), &pr) != 0)
		d->error = 1;
	free(ss);
}

void
dtotel_prof_emit(struct dtotel *d, int aggs)
{
	struct dtotel_prof *p = d->prof;
	struct prof_group *g;
	struct timespec now;

	if (p == NULL)
		return;
	clock_gettime(CLOCK_REALTIME, &now);
	for (g = p->groups; g != NULL; g = g->next)
		emit_group(d, g, &p->start, &now);
	groups_free(p->groups);
	p->groups = NULL;
	memset(p->hash, 0, sizeof(p->hash));
	p->nsamples = p->ntimes = 0;
	if (p->dropped > 0) {
		fprintf(stderr, "dtotel: %ju profile samples dropped in the "
		    "last interval\n", (uintmax_t)p->dropped);
		p->dropped = 0;
	}
	p->start = now;
	clock_gettime(CLOCK_MONOTONIC, &p->last);
	if (!aggs)
		return;
	for (g = p->aggs; g != NULL; g = g->next)
		emit_group(d, g, &p->agg_start, &now);
	groups_free(p->aggs);
	p->aggs = NULL;
	/* This snapshot's series values are the next one's baseline. */
	prev_free(p->prev);
	memcpy(p->prev, p->cur, sizeof(p->prev));
	memset(p->cur, 0, sizeof(p->cur));
	p->agg_start = now;
}

void
dtotel_prof_tick(struct dtotel *d)
{
	struct timespec now;

	if (d->prof == NULL || d->prof->groups == NULL)
		return;
	clock_gettime(CLOCK_MONOTONIC, &now);
	if (now.tv_sec - d->prof->last.tv_sec >= d->prof_interval)
		dtotel_prof_emit(d, 0);
}
