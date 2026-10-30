/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Aggregations to metric snapshots.  Walks libdtrace's typed
 * aggregation records (rather than parsing printa() text), decodes
 * every key by its action so stack()/sym()/mod() keys come out
 * symbolized, and converts each aggregating function's data to an
 * oe_snapshot in the OpenTelemetry data model:
 *
 *  - count(): a monotonic cumulative Sum; sum(): a cumulative Sum that
 *    may decrease (it adds signed values); min()/max(): Gauges;
 *  - avg(): the count and sum of the observations (a Histogram without
 *    buckets), so no information is lost to the division;
 *  - stddev(): the same count and sum, plus "<name>.stddev", a Gauge of
 *    the population standard deviation computed exactly from DTrace's
 *    128-bit sum of squares;
 *  - quantize(): an ExponentialHistogram at scale 0 (base 2): DTrace's
 *    bucket [2^k, 2^(k+1)) is index k, negative values the mirror
 *    image, and its zero bucket the zero count;
 *  - lquantize()/llquantize(): explicit-bounds Histograms carrying
 *    their complete bucket layout, with each bucket's inclusive integer
 *    upper bound.
 *
 * Values are the aggregation's own: normalize() is a printa()-time
 * division in DTrace and is carried as Metric metadata
 * ("dtrace.normalization") instead of being applied.  Every series
 * remembers its value from one snapshot to the next, so a reset
 * (clear(), or trunc() removing a key that later returns) moves the
 * series' start time; see dtotel_series below.
 */

#include <sys/param.h>

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <dtrace.h>
#include <sys/hypertrace.h>

#include "dtotel_impl.h"

/* ---------------------------------------------------------------- */
/* Aggregation key names parsed from the D source		 	*/

/*
 * Attribute names for aggregation keys.  D built-ins with an
 * OpenTelemetry semantic convention get its name, so a metric's
 * dimensions match the attributes of log records and spans; the
 * probe-description built-ins, which have none, keep short names.
 */
static const char *
builtin_key_name(const char *expr, int idx, char *buf, size_t len)
{
	static const struct {
		const char *expr, *name;
	} names[] = {
		{ "execname", "process.executable.name" },
		{ "pid", "process.pid" },
		{ "ppid", "process.parent_pid" },
		{ "curpsinfo->pr_ppid", "process.parent_pid" },
		{ "tid", "thread.id" },
		{ "uid", "process.user.id" },
		{ "curpsinfo->pr_uid", "process.real_user.id" },
		{ "gid", "process.group.id" },
		{ "curpsinfo->pr_gid", "process.real_group.id" },
		{ "cpu", "cpu.logical_number" },
		{ "curpsinfo->pr_jailid", "container.id" },
		{ "curproc->p_ucred->cr_prison->pr_id", "container.id" },
		{ "probefunc", "syscall" },
		{ "probename", "probe" },
		{ "probemod", "module" },
		{ "probeprov", "provider" },
	};
	size_t i;

	for (i = 0; i < nitems(names); i++)
		if (strcmp(expr, names[i].expr) == 0)
			return (names[i].name);
	if (expr[0] == '"')
		return ("label");
	/*
	 * this->name keys export their variable name, with "__" standing
	 * for the "." D identifiers cannot hold: this->network__io__direction
	 * is exported as network.io.direction.
	 */
	if (strncmp(expr, "this->", 6) == 0 && expr[6] != '\0') {
		char *r, *w;

		/* Compacting in place never lengthens the copy. */
		strlcpy(buf, expr + 6, len);
		for (r = w = buf; *r != '\0'; r++) {
			if (r[0] == '_' && r[1] == '_') {
				*w++ = '.';
				r++;
			} else
				*w++ = *r;
		}
		*w = '\0';
		return (buf);
	}
	snprintf(buf, len, "key.%d", idx);
	return (buf);
}

/*
 * Scan the rendered D source for @name[expr, expr, ...] patterns and
 * derive semantic attribute names for each aggregation's key tuple.
 * First occurrence of each aggregation name wins.
 */
struct dtotel_keynames *
dtotel_parse_keynames(const char *source)
{
	struct dtotel_keynames *head, *ak;
	const char *p, *namestart, *keystart, *keyend, *close;
	char aggname[128], expr[256], fallback[256];
	size_t len;
	int idx;

	head = NULL;
	for (p = strchr(source, '@'); p != NULL; p = strchr(p + 1, '@')) {
		namestart = p + 1;
		for (close = namestart; isalnum((unsigned char)*close) ||
		    *close == '_'; close++)
			;
		if (*close != '[')
			continue;
		len = (size_t)(close - namestart);
		if (len >= sizeof(aggname))
			continue;
		memcpy(aggname, namestart, len);
		aggname[len] = '\0';

		/* Skip if we already saw this aggregation. */
		for (ak = head; ak != NULL; ak = ak->next)
			if (strcmp(ak->aggname, aggname) == 0)
				break;
		if (ak != NULL)
			continue;

		ak = calloc(1, sizeof(*ak));
		if (ak == NULL)
			break;
		ak->aggname = strdup(aggname);
		if (ak->aggname == NULL) {
			free(ak);
			break;
		}

		/* Split the [...] key list on top-level commas. */
		keystart = close + 1;
		idx = 0;
		while (idx < DTOTEL_MAX_AGG_KEYS) {
			int depth = 0;

			for (keyend = keystart; *keyend != '\0'; keyend++) {
				if (*keyend == '(' || *keyend == '[')
					depth++;
				else if (*keyend == ')')
					depth--;
				else if (*keyend == ']' && depth > 0)
					depth--;
				else if ((*keyend == ',' && depth == 0) ||
				    (*keyend == ']' && depth == 0))
					break;
			}
			if (*keyend == '\0')
				break;
			/* Trim the expression. */
			while (keystart < keyend &&
			    isspace((unsigned char)*keystart))
				keystart++;
			len = (size_t)(keyend - keystart);
			while (len > 0 && isspace(
			    (unsigned char)keystart[len - 1]))
				len--;
			if (len >= sizeof(expr))
				len = sizeof(expr) - 1;
			memcpy(expr, keystart, len);
			expr[len] = '\0';
			ak->names[idx] = strdup(builtin_key_name(expr, idx,
			    fallback, sizeof(fallback)));
			if (ak->names[idx] == NULL)
				break;		/* later keys fall back to key.N */
			idx++;
			if (*keyend == ']')
				break;
			keystart = keyend + 1;
		}
		ak->n = idx;
		ak->next = head;
		head = ak;
	}
	return (head);
}

void
dtotel_free_keynames(struct dtotel_keynames *head)
{
	struct dtotel_keynames *next;
	int i;

	for (; head != NULL; head = next) {
		next = head->next;
		free(head->aggname);
		for (i = 0; i < head->n; i++)
			free(head->names[i]);
		free(head);
	}
}

/* ---------------------------------------------------------------- */
/* Typed aggregation walk						*/

struct snap_point {
	struct oe_attr	*attrs;		/* owned name/value strings */
	size_t		 nattrs;
	int		 is_histogram;
	int64_t		 scalar;
	struct oe_bucket *buckets;
	size_t		 nbuckets;
	int		 has_exp;
	struct oe_exphist exp;		/* counts below are owned */
	uint64_t	*pos, *neg;
	int		 has_stats;
	uint64_t	 count;
	double		 sum;
	int		 is_double;
	double		 dvalue;
	struct timespec	 start;		/* set by the series bookkeeping */
};

struct snap_accum {
	char		*name;		/* aggregation name ("" if anon) */
	uint16_t	 vmid;		/* the guest it came from, or 0 */
	enum oe_agg_kind kind;
	int64_t		 normal;	/* normalize() factor, 1 if none */
	struct snap_point *points;
	size_t		 npoints, cappoints;
	struct snap_accum *next;
};

struct agg_walk_ctx {
	struct dtotel	*d;
	struct dtotel_keynames *keynames;
	struct snap_accum *accums;
};

/*
 * Render kernel stack frames as module`symbol+0xoff joined by ';',
 * falling back to hex for unresolvable addresses.
 */
static void
key_frames_to_buf(dtrace_hdl_t *dtp, struct oe_buf *b, caddr_t addr,
    size_t nframes, uint16_t guest_vmid)
{
	dtrace_syminfo_t si;
	GElf_Sym sym;
	uint64_t pc;
	size_t i;

	for (i = 0; i < nframes; i++) {
		memcpy(&pc, addr + i * sizeof(pc), sizeof(pc));
		if (pc == 0)
			break;
		if (i > 0)
			oe_buf_appendstr(b, ";");
		if (guest_vmid != 0)
			oe_buf_appendf(b, "guest[%u]`0x%jx", guest_vmid,
			    (uintmax_t)pc);
		else if (dtrace_lookup_by_addr(dtp, pc, &sym, &si) == 0)
			oe_buf_appendf(b, "%s`%s+0x%jx", si.dts_object,
			    si.dts_name, (uintmax_t)(pc - sym.st_value));
		else
			oe_buf_appendf(b, "0x%jx", (uintmax_t)pc);
	}
}

/*
 * Render one aggregation key record.  Keys are not always sized
 * integers or strings: stack()/ustack()/sym()/mod() keys carry raw
 * program counters and must be dispatched by ACTION, exactly as
 * dtrace(1)'s dt_print_datum() does — treating them as char arrays
 * exports a few bytes of a raw pointer as the "key".
 */
static void
key_to_buf(dtrace_hdl_t *dtp, const dtrace_recdesc_t *rec, caddr_t base,
    struct oe_buf *b)
{
	caddr_t addr = base + rec->dtrd_offset;
	dtrace_syminfo_t si;
	GElf_Sym sym;
	uint64_t v, pid;
	uint32_t v32;
	uint16_t v16;
	uint8_t v8;
	size_t framesize, i, n, nframes;

	switch (rec->dtrd_action) {
	case DTRACEACT_STACK:
		framesize = HYPERTRACE_STACK_NFRAMES(rec->dtrd_arg) != 0 ?
		    rec->dtrd_size /
		    HYPERTRACE_STACK_NFRAMES(rec->dtrd_arg) : sizeof(uint64_t);
		if (framesize != sizeof(uint64_t))
			goto hexdump;
		key_frames_to_buf(dtp, b, addr,
		    rec->dtrd_size / sizeof(uint64_t),
		    HYPERTRACE_STACK_GUEST(rec->dtrd_arg) ?
		    HYPERTRACE_STACK_VMID(rec->dtrd_arg) : 0);
		return;
	case DTRACEACT_USTACK:
	case DTRACEACT_JSTACK:
		/*
		 * Layout: qword 0 is the pid, frames follow.  User
		 * frames stay hex — symbolizing them would need to
		 * grab the (possibly exited) process.
		 */
		if (rec->dtrd_size < sizeof(uint64_t))
			goto hexdump;
		memcpy(&pid, addr, sizeof(pid));
		oe_buf_appendf(b, "pid%u", (unsigned)pid);
		nframes = rec->dtrd_size / sizeof(uint64_t) - 1;
		if (DTRACE_USTACK_NFRAMES(rec->dtrd_arg) > 0 &&
		    DTRACE_USTACK_NFRAMES(rec->dtrd_arg) < nframes)
			nframes = DTRACE_USTACK_NFRAMES(rec->dtrd_arg);
		for (i = 0; i < nframes; i++) {
			memcpy(&v, addr + (i + 1) * sizeof(v), sizeof(v));
			if (v == 0)
				break;
			oe_buf_appendf(b, ";0x%jx", (uintmax_t)v);
		}
		return;
	case DTRACEACT_SYM:
	case DTRACEACT_MOD:
		if (rec->dtrd_size < sizeof(uint64_t))
			goto hexdump;
		memcpy(&v, addr, sizeof(v));
		if (dtrace_lookup_by_addr(dtp, v, &sym, &si) == 0) {
			if (rec->dtrd_action == DTRACEACT_MOD)
				oe_buf_appendf(b, "%s", si.dts_object);
			else
				oe_buf_appendf(b, "%s`%s", si.dts_object,
				    si.dts_name);
		} else
			oe_buf_appendf(b, "0x%jx", (uintmax_t)v);
		return;
	case DTRACEACT_USYM:
	case DTRACEACT_UMOD:
		/* Layout: pid, address. */
		if (rec->dtrd_size < 2 * sizeof(uint64_t))
			goto hexdump;
		memcpy(&v, addr + sizeof(uint64_t), sizeof(v));
		oe_buf_appendf(b, "0x%jx", (uintmax_t)v);
		return;
	default:
		break;
	}

	switch (rec->dtrd_size) {
	case sizeof(uint8_t):
		memcpy(&v8, addr, sizeof(v8));
		/* Sub-8-byte keys print unsigned, as dtrace(1) does. */
		oe_buf_appendf(b, "%u", v8);
		break;
	case sizeof(uint16_t):
		memcpy(&v16, addr, sizeof(v16));
		oe_buf_appendf(b, "%u", v16);
		break;
	case sizeof(uint32_t):
		memcpy(&v32, addr, sizeof(v32));
		oe_buf_appendf(b, "%u", v32);
		break;
	case sizeof(uint64_t):
		memcpy(&v, addr, sizeof(v));
		oe_buf_appendf(b, "%jd", (intmax_t)(int64_t)v);
		break;
	default:
		/* String key: fixed-size char array, NUL-padded. */
		n = strnlen(addr, rec->dtrd_size);
		oe_buf_append(b, addr, n);
		break;
	}
	return;

hexdump:
	for (i = 0; i < rec->dtrd_size; i++)
		oe_buf_appendf(b, "%02x", (unsigned char)addr[i]);
}

static struct snap_accum *
accum_for(struct agg_walk_ctx *ctx, const char *name, enum oe_agg_kind kind,
    uint16_t vmid)
{
	struct snap_accum *sa;

	for (sa = ctx->accums; sa != NULL; sa = sa->next)
		if (strcmp(sa->name, name) == 0 && sa->kind == kind &&
		    sa->vmid == vmid)
			return (sa);
	sa = calloc(1, sizeof(*sa));
	if (sa == NULL)
		return (NULL);
	sa->name = strdup(name);
	if (sa->name == NULL) {
		free(sa);
		return (NULL);
	}
	sa->kind = kind;
	sa->vmid = vmid;
	sa->normal = 1;
	sa->next = ctx->accums;
	ctx->accums = sa;
	return (sa);
}

static struct snap_point *
accum_add_point(struct snap_accum *sa)
{
	struct snap_point *np;

	if (sa->npoints == sa->cappoints) {
		size_t newcap = sa->cappoints == 0 ? 16 : sa->cappoints * 2;

		np = realloc(sa->points, newcap * sizeof(*np));
		if (np == NULL)
			return (NULL);
		sa->points = np;
		sa->cappoints = newcap;
	}
	np = &sa->points[sa->npoints++];
	memset(np, 0, sizeof(*np));
	return (np);
}

static void
point_add_bucket(struct snap_point *pt, int64_t upper, int64_t count,
    size_t *cap)
{
	struct oe_bucket *nb, *muts;

	muts = __DECONST(struct oe_bucket *, pt->buckets);
	if (pt->nbuckets == *cap) {
		size_t newcap = *cap == 0 ? 32 : *cap * 2;

		nb = realloc(muts, newcap * sizeof(*nb));
		if (nb == NULL)
			return;
		pt->buckets = nb;
		muts = nb;
		*cap = newcap;
	}
	muts[pt->nbuckets].upper = upper;
	muts[pt->nbuckets].count = count;
	pt->nbuckets++;
}

/*
 * Convert one llquantize data record to its complete bucket layout,
 * following the bucket-bound walk in libdtrace's dt_print_llquantize():
 * the underflow bucket (values below factor^low), factor^low ..
 * factor^(high+1) in nsteps linear steps per order of magnitude (a step
 * of at least 1), and the overflow bucket.  Each bucket is exported with
 * its inclusive upper bound; empty buckets are kept so every point of a
 * metric has the same bounds.
 */
static void
llquantize_buckets(struct snap_point *pt, const int64_t *data, size_t size,
    size_t *bcap)
{
	uint64_t arg;
	int64_t value, next, step;
	uint16_t factor, low, high, nsteps;
	int levels, bin, order;

	if (size < sizeof(uint64_t))
		return;
	arg = (uint64_t)*data++;
	size -= sizeof(uint64_t);
	factor = DTRACE_LLQUANTIZE_FACTOR(arg);
	low = DTRACE_LLQUANTIZE_LOW(arg);
	high = DTRACE_LLQUANTIZE_HIGH(arg);
	nsteps = DTRACE_LLQUANTIZE_NSTEP(arg);
	if (factor < 2 || low >= high || nsteps == 0 || factor > nsteps)
		return;
	levels = (int)(size / sizeof(uint64_t));
	if (levels == 0)
		return;

	value = 1;
	for (order = 0; order < low; order++)
		value *= factor;
	/* Underflow bucket: values < factor^low. */
	point_add_bucket(pt, value - 1, data[0], bcap);

	next = value * factor;
	step = next > nsteps ? next / nsteps : 1;
	bin = 1;
	order = low;
	while (order <= (int)high && bin < levels) {
		/* The bucket covers [value, value + step). */
		point_add_bucket(pt, value + step - 1, data[bin], bcap);
		bin++;
		if ((value += step) != next)
			continue;
		next = value * factor;
		step = next > nsteps ? next / nsteps : 1;
		order++;
	}
	/* Overflow bucket: the rest. */
	if (bin < levels)
		point_add_bucket(pt, INT64_MAX, data[bin], bcap);
}

/*
 * quantize() as a base-2 exponential histogram (scale 0).  DTrace's
 * 127 buckets are the zero bucket (63), positive buckets b > 63 holding
 * [2^(b-64), 2^(b-63)), and negative buckets b < 63 holding values v
 * with |v| in [2^(62-b), 2^(63-b)).  So positive index k = b - 64 and
 * negative index j = 62 - b, the same powers of two as the OTel buckets
 * (base^i, base^(i+1)]; DTrace closes its buckets at the lower end and
 * OTel at the upper, so an observation exactly at a power of two is
 * counted one OTel bucket higher than OTel's convention would place it.
 * The counts between the lowest and highest non-empty index are
 * exported, empty ones included, as the data model requires.
 */
static int
quantize_exp(struct snap_point *pt, const int64_t *data, size_t nbuckets)
{
	size_t b, lo, hi;

	pt->is_histogram = 1;
	pt->has_exp = 1;
	pt->exp.scale = 0;
	if (nbuckets > DTRACE_QUANTIZE_ZEROBUCKET)
		pt->exp.zero_count = (uint64_t)data[DTRACE_QUANTIZE_ZEROBUCKET];
	/* Positive: buckets ZERO+1 .. nbuckets-1. */
	lo = hi = 0;
	for (b = DTRACE_QUANTIZE_ZEROBUCKET + 1; b < nbuckets; b++) {
		if (data[b] == 0)
			continue;
		if (lo == 0)
			lo = b;
		hi = b;
	}
	if (lo != 0) {
		pt->pos = calloc(hi - lo + 1, sizeof(*pt->pos));
		if (pt->pos == NULL)
			return (-1);
		for (b = lo; b <= hi; b++)
			pt->pos[b - lo] = (uint64_t)data[b];
		pt->exp.positive.offset = (int32_t)(lo -
		    DTRACE_QUANTIZE_ZEROBUCKET - 1);
		pt->exp.positive.counts = pt->pos;
		pt->exp.positive.n = hi - lo + 1;
	}
	/* Negative: index 62 - b, so walk b downward from the zero bucket. */
	lo = hi = SIZE_MAX;
	for (b = 0; b < DTRACE_QUANTIZE_ZEROBUCKET && b < nbuckets; b++) {
		if (data[b] == 0)
			continue;
		if (lo == SIZE_MAX)
			lo = b;
		hi = b;
	}
	if (lo != SIZE_MAX) {
		pt->neg = calloc(hi - lo + 1, sizeof(*pt->neg));
		if (pt->neg == NULL)
			return (-1);
		/* Index 62 - hi (smallest magnitude) first. */
		for (b = hi + 1; b > lo; b--)
			pt->neg[hi - (b - 1)] = (uint64_t)data[b - 1];
		pt->exp.negative.offset = (int32_t)(DTRACE_QUANTIZE_ZEROBUCKET -
		    1 - hi);
		pt->exp.negative.counts = pt->neg;
		pt->exp.negative.n = hi - lo + 1;
	}
	return (0);
}

/* A copy of a point's key attributes for a second metric. */
static int
copy_attrs(struct snap_point *dst, const struct snap_point *src)
{
	size_t i;

	if (src->nattrs == 0)
		return (0);
	dst->attrs = calloc(src->nattrs, sizeof(*dst->attrs));
	if (dst->attrs == NULL)
		return (-1);
	for (i = 0; i < src->nattrs; i++) {
		dst->attrs[i].name = strdup(src->attrs[i].name);
		dst->attrs[i].value = strdup(src->attrs[i].value);
		if (dst->attrs[i].name == NULL || dst->attrs[i].value == NULL) {
			free(__DECONST(char *, dst->attrs[i].name));
			free(__DECONST(char *, dst->attrs[i].value));
			return (-1);
		}
		dst->nattrs = i + 1;
	}
	return (0);
}

/*
 * The population standard deviation sqrt((sumsq*n - sum^2) / n^2), with
 * the numerator exact in 128 bits where available: the naive long
 * double form loses catastrophically to cancellation for large values.
 */
static double
stddev_value(const int64_t v[4])
{
#ifdef __SIZEOF_INT128__
	unsigned __int128 sumsq, num, den;
	__int128 sum2;

	if (v[0] <= 0)
		return (0);
	sumsq = ((unsigned __int128)(uint64_t)v[3] << 64) | (uint64_t)v[2];
	sum2 = (__int128)v[1] * v[1];
	num = sumsq * (uint64_t)v[0];
	if (num <= (unsigned __int128)sum2)
		return (0);
	num -= (unsigned __int128)sum2;
	den = (unsigned __int128)(uint64_t)v[0] * (uint64_t)v[0];
	return ((double)sqrtl((long double)num / (long double)den));
#else
	long double cnt, sum, sumsq, var;

	if (v[0] <= 0)
		return (0);
	cnt = (long double)v[0];
	sum = (long double)v[1];
	sumsq = (long double)(uint64_t)v[2] +
	    ldexpl((long double)(uint64_t)v[3], 64);
	var = sumsq / cnt - (sum / cnt) * (sum / cnt);
	return (var > 0 ? (double)sqrtl(var) : 0);
#endif
}

static int
agg_walk(const dtrace_aggdata_t *agg, void *arg)
{
	struct agg_walk_ctx *ctx = arg;
	struct dtotel_keynames *ak;
	struct snap_accum *sa, *sd;
	struct snap_point *pt, *pd;
	dtrace_aggdesc_t *desc = agg->dtada_desc;
	const dtrace_recdesc_t *rec, *vrec;
	const char *aggname;
	caddr_t base = agg->dtada_data;
	enum oe_agg_kind kind;
	char attrname[24], sdname[256];
	size_t bcap, size, nbuckets, j;
	int64_t v[4];
	uint16_t vmid;
	int i, nkeys;

	if (desc->dtagd_nrecs < 1)
		return (DTRACE_AGGWALK_NEXT);
	vrec = &desc->dtagd_rec[desc->dtagd_nrecs - 1];

	switch (vrec->dtrd_action) {
	case DTRACEAGG_COUNT:	kind = OE_AGG_COUNT; break;
	case DTRACEAGG_SUM:	kind = OE_AGG_SUM; break;
	case DTRACEAGG_MIN:	kind = OE_AGG_MIN; break;
	case DTRACEAGG_MAX:	kind = OE_AGG_MAX; break;
	case DTRACEAGG_AVG:	kind = OE_AGG_AVG; break;
	case DTRACEAGG_STDDEV:	kind = OE_AGG_STDDEV; break;
	case DTRACEAGG_QUANTIZE: kind = OE_AGG_QUANTIZE; break;
	case DTRACEAGG_LQUANTIZE: kind = OE_AGG_LQUANTIZE; break;
	case DTRACEAGG_LLQUANTIZE: kind = OE_AGG_LLQUANTIZE; break;
	default:
		return (DTRACE_AGGWALK_NEXT);
	}

	aggname = desc->dtagd_name;
	if (aggname == NULL || strcmp(aggname, "_") == 0)
		aggname = "";	/* anonymous @ */

	/* A guest's aggregation data belongs to the guest's resource. */
	vmid = agg->dtada_edesc != NULL ? agg->dtada_edesc->dtepd_vmid : 0;
	sa = accum_for(ctx, aggname, kind, vmid);
	if (sa == NULL)
		return (DTRACE_AGGWALK_NEXT);
	/* normalize() is presentation: carried as metadata, not applied. */
	if (agg->dtada_normal > 1)
		sa->normal = (int64_t)agg->dtada_normal;
	pt = accum_add_point(sa);
	if (pt == NULL)
		return (DTRACE_AGGWALK_NEXT);

	/* Keys: records 1 .. nrecs-2 (record 0 is the varid). */
	for (ak = ctx->keynames; ak != NULL; ak = ak->next)
		if (strcmp(ak->aggname, aggname) == 0)
			break;
	nkeys = desc->dtagd_nrecs - 2;
	if (nkeys > 0) {
		pt->attrs = calloc((size_t)nkeys, sizeof(*pt->attrs));
		if (pt->attrs == NULL)
			return (DTRACE_AGGWALK_NEXT);
		for (i = 0; i < nkeys; i++) {
			struct oe_buf kb;

			rec = &desc->dtagd_rec[i + 1];
			oe_buf_init(&kb);
			key_to_buf(ctx->d->dtp, rec, base, &kb);
			if (ak != NULL && i < ak->n)
				pt->attrs[i].name = strdup(ak->names[i]);
			else {
				snprintf(attrname, sizeof(attrname),
				    "key.%d", i);
				pt->attrs[i].name = strdup(attrname);
			}
			pt->attrs[i].value = kb.error ? NULL : strdup(kb.data);
			oe_buf_free(&kb);
			if (pt->attrs[i].name == NULL ||
			    pt->attrs[i].value == NULL) {
				/* Out of memory: keep the keys made so far. */
				free(__DECONST(char *, pt->attrs[i].name));
				free(__DECONST(char *, pt->attrs[i].value));
				break;
			}
			pt->nattrs = (size_t)(i + 1);
		}
	}

	switch (kind) {
	case OE_AGG_COUNT:
	case OE_AGG_SUM:
	case OE_AGG_MIN:
	case OE_AGG_MAX:
		if (vrec->dtrd_size < sizeof(int64_t))
			break;
		memcpy(&v[0], base + vrec->dtrd_offset, sizeof(int64_t));
		pt->scalar = v[0];
		break;
	case OE_AGG_AVG:
		/* Layout: count, sum. */
		if (vrec->dtrd_size < 2 * sizeof(int64_t))
			break;
		memcpy(v, base + vrec->dtrd_offset, 2 * sizeof(int64_t));
		pt->has_stats = 1;
		pt->count = (uint64_t)v[0];
		pt->sum = (double)v[1];
		break;
	case OE_AGG_STDDEV:
		/*
		 * Layout: count, sum, sum of squares (128 bits, low then
		 * high).  The count and sum, and the deviation as a gauge
		 * of its own ("<name>.stddev").
		 */
		if (vrec->dtrd_size < 4 * sizeof(int64_t))
			break;
		memcpy(v, base + vrec->dtrd_offset, 4 * sizeof(int64_t));
		pt->has_stats = 1;
		pt->count = (uint64_t)v[0];
		pt->sum = (double)v[1];
		snprintf(sdname, sizeof(sdname), "%s.stddev",
		    aggname[0] != '\0' ? aggname : "stddev");
		sd = accum_for(ctx, sdname, OE_AGG_STDDEV, vmid);
		if (sd == NULL || (pd = accum_add_point(sd)) == NULL)
			break;
		sd->normal = sa->normal;
		if (copy_attrs(pd, pt) != 0)
			break;
		pd->is_double = 1;
		pd->dvalue = stddev_value(v);
		break;
	case OE_AGG_QUANTIZE: {
		const int64_t *data =
		    (const int64_t *)(void *)(base + vrec->dtrd_offset);

		nbuckets = vrec->dtrd_size / sizeof(int64_t);
		if (nbuckets > DTRACE_QUANTIZE_NBUCKETS)
			nbuckets = DTRACE_QUANTIZE_NBUCKETS;
		(void)quantize_exp(pt, data, nbuckets);
		break;
	}
	case OE_AGG_LQUANTIZE: {
		const int64_t *data =
		    (const int64_t *)(void *)(base + vrec->dtrd_offset);
		uint64_t larg;
		int32_t lbase;
		uint16_t step, levels;

		/*
		 * First slot carries the lquantize argument; then the
		 * underflow bucket, levels steps and the overflow bucket,
		 * all exported so every point has the same bounds.
		 */
		if (vrec->dtrd_size < sizeof(uint64_t))
			break;
		larg = (uint64_t)data[0];
		lbase = DTRACE_LQUANTIZE_BASE(larg);
		step = DTRACE_LQUANTIZE_STEP(larg);
		levels = DTRACE_LQUANTIZE_LEVELS(larg);
		pt->is_histogram = 1;
		bcap = 0;
		nbuckets = vrec->dtrd_size / sizeof(int64_t) - 1;
		for (j = 0; j < nbuckets && j < (size_t)levels + 2; j++) {
			int64_t upper;

			if (j == 0)
				upper = (int64_t)lbase - 1; /* underflow */
			else if (j == (size_t)levels + 1)
				upper = INT64_MAX;	/* overflow */
			else
				upper = lbase + (int64_t)j * step - 1;
			point_add_bucket(pt, upper, data[j + 1], &bcap);
		}
		break;
	}
	case OE_AGG_LLQUANTIZE:
		pt->is_histogram = 1;
		bcap = 0;
		size = vrec->dtrd_size;
		llquantize_buckets(pt,
		    (const int64_t *)(void *)(base + vrec->dtrd_offset),
		    size, &bcap);
		break;
	}

	return (DTRACE_AGGWALK_NEXT);
}

/* ---------------------------------------------------------------- */
/* Series bookkeeping							*/

/*
 * Every exported series (aggregation, guest and key tuple) is
 * remembered from one snapshot to the next with a measure that only
 * grows while the series accumulates: the count of count(), the number
 * of observations of avg(), stddev() and the quantize family.  A series
 * whose measure went down was reset (clear()) since the previous
 * snapshot; one that was absent from it (new, or removed by trunc() and
 * back) started after it.  Either way its start time becomes the
 * previous snapshot's time, so cumulative consumers see the reset
 * instead of a negative rate.  The first snapshot's series start with
 * the trace.  DTrace handles clear() and trunc() inside libdtrace and
 * tells the consumer nothing, so a series cleared and grown past its
 * previous measure between two snapshots goes unnoticed.  Only the
 * series of the latest snapshot are kept.
 */
#define	SERIES_HASH	256

struct dtotel_series {
	char		*key;
	uint64_t	 measure;	/* when the kind has one */
	struct timespec	 start;		/* zero: the trace's */
	struct dtotel_series *next;
};

static unsigned
series_hash(const char *s)
{
	unsigned h = 5381;

	while (*s != '\0')
		h = h * 33 + (unsigned char)*s++;
	return (h % SERIES_HASH);
}

static char *
series_key(const struct snap_accum *sa, const struct snap_point *pt)
{
	struct oe_buf b;
	size_t i;

	oe_buf_init(&b);
	oe_buf_appendf(&b, "%s\037%u\037%d", sa->name, (unsigned)sa->vmid,
	    (int)sa->kind);
	for (i = 0; i < pt->nattrs; i++)
		oe_buf_appendf(&b, "\037%s=%s", pt->attrs[i].name,
		    pt->attrs[i].value);
	if (b.error) {
		oe_buf_free(&b);
		return (NULL);
	}
	return (b.data);
}

static int
point_measure(const struct snap_accum *sa, const struct snap_point *pt,
    uint64_t *m)
{
	size_t i;

	switch (sa->kind) {
	case OE_AGG_COUNT:
		*m = (uint64_t)pt->scalar;
		return (1);
	case OE_AGG_AVG:
	case OE_AGG_STDDEV:
		if (!pt->has_stats)
			return (0);	/* the stddev gauge */
		*m = pt->count;
		return (1);
	case OE_AGG_QUANTIZE:
	case OE_AGG_LQUANTIZE:
	case OE_AGG_LLQUANTIZE:
		*m = pt->exp.zero_count;
		for (i = 0; i < pt->exp.positive.n; i++)
			*m += pt->exp.positive.counts[i];
		for (i = 0; i < pt->exp.negative.n; i++)
			*m += pt->exp.negative.counts[i];
		for (i = 0; i < pt->nbuckets; i++)
			*m += (uint64_t)pt->buckets[i].count;
		return (1);
	default:
		return (0);
	}
}

void
dtotel_series_free(struct dtotel *d)
{
	struct dtotel_series *s, *next;
	size_t i;

	if (d->series == NULL)
		return;
	for (i = 0; i < SERIES_HASH; i++)
		for (s = d->series[i]; s != NULL; s = next) {
			next = s->next;
			free(s->key);
			free(s);
		}
	free(d->series);
	d->series = NULL;
}

/*
 * Give every point its start time and remember the series for the next
 * snapshot.  Without memory for the bookkeeping, points keep the trace's
 * start (the behavior before resets were detected).
 */
static void
series_update(struct dtotel *d, struct snap_accum *accums,
    const struct timespec *now)
{
	struct dtotel_series **table, *old, *ns;
	struct snap_accum *sa;
	struct snap_point *pt;
	uint64_t m;
	unsigned h;
	size_t i;
	char *key;
	int has;

	table = calloc(SERIES_HASH, sizeof(*table));
	if (table == NULL)
		return;
	for (sa = accums; sa != NULL; sa = sa->next) {
		for (i = 0; i < sa->npoints; i++) {
			pt = &sa->points[i];
			if ((key = series_key(sa, pt)) == NULL)
				continue;
			has = point_measure(sa, pt, &m);
			h = series_hash(key);
			old = NULL;
			if (d->series != NULL)
				for (old = d->series[h]; old != NULL;
				    old = old->next)
					if (strcmp(old->key, key) == 0)
						break;
			if (old == NULL && d->nsnaps > 0)
				pt->start = d->last_snap;	/* new */
			else if (old != NULL && has && m < old->measure)
				pt->start = d->last_snap;	/* reset */
			else if (old != NULL)
				pt->start = old->start;
			ns = calloc(1, sizeof(*ns));
			if (ns == NULL) {
				free(key);
				continue;
			}
			ns->key = key;
			ns->measure = m;
			ns->start = pt->start;
			ns->next = table[h];
			table[h] = ns;
		}
	}
	dtotel_series_free(d);
	d->series = table;
	d->last_snap = *now;
	d->nsnaps++;
}

static void
emit_and_free_accums(struct dtotel *d, struct snap_accum *accums)
{
	struct snap_accum *sa, *next;
	struct snap_point *pt;
	struct oe_snapshot sn;
	struct oe_datapoint *dps;
	struct oe_attr meta;
	struct timespec now;
	char normbuf[32];
	size_t i, j;

	clock_gettime(CLOCK_REALTIME, &now);
	series_update(d, accums, &now);
	for (sa = accums; sa != NULL; sa = next) {
		next = sa->next;
		dps = calloc(sa->npoints, sizeof(*dps));
		if (dps != NULL) {
			for (i = 0; i < sa->npoints; i++) {
				pt = &sa->points[i];
				dps[i].attrs = pt->attrs;
				dps[i].nattrs = pt->nattrs;
				dps[i].is_histogram = pt->is_histogram;
				dps[i].scalar = pt->scalar;
				dps[i].buckets = pt->buckets;
				dps[i].nbuckets = pt->nbuckets;
				dps[i].exp = pt->has_exp ? &pt->exp : NULL;
				dps[i].has_stats = pt->has_stats;
				dps[i].count = pt->count;
				dps[i].sum = pt->sum;
				dps[i].is_double = pt->is_double;
				dps[i].dvalue = pt->dvalue;
				dps[i].start = pt->start;
			}
			memset(&sn, 0, sizeof(sn));
			sn.ts = now;
			sn.start = d->start;
			sn.profile = d->profile;
			sn.name = sa->name;
			sn.kind = sa->kind;
			sn.points = dps;
			sn.npoints = sa->npoints;
			/* sum() adds signed values: it may go down. */
			sn.non_monotonic = sa->kind == OE_AGG_SUM;
			if (sa->normal > 1) {
				snprintf(normbuf, sizeof(normbuf), "%jd",
				    (intmax_t)sa->normal);
				meta.name = "dtrace.normalization";
				meta.value = normbuf;
				sn.metadata = &meta;
				sn.nmetadata = 1;
			}
			if (oe_snapshot(dtotel_exporter_for(d, sa->vmid,
			    NULL), &sn) != 0)
				d->error = 1;
			free(dps);
		}
		for (i = 0; i < sa->npoints; i++) {
			pt = &sa->points[i];
			for (j = 0; j < pt->nattrs; j++) {
				free(__DECONST(char *, pt->attrs[j].name));
				free(__DECONST(char *, pt->attrs[j].value));
			}
			free(pt->attrs);
			free(__DECONST(struct oe_bucket *, pt->buckets));
			free(pt->pos);
			free(pt->neg);
		}
		free(sa->points);
		free(sa->name);
		free(sa);
	}
}

int
dtotel_aggregate(struct dtotel *d)
{
	struct agg_walk_ctx actx;
	int ret;

	if (dtrace_aggregate_snap(d->dtp) != 0) {
		fprintf(stderr, "dtotel: aggregation snapshot failed: %s\n",
		    dtrace_errmsg(d->dtp, dtrace_errno(d->dtp)));
		return (-1);
	}
	memset(&actx, 0, sizeof(actx));
	actx.d = d;
	actx.keynames = d->keynames;
	ret = 0;
	if (dtrace_aggregate_walk(d->dtp, agg_walk, &actx) != 0) {
		fprintf(stderr, "dtotel: aggregation walk failed: %s\n",
		    dtrace_errmsg(d->dtp, dtrace_errno(d->dtp)));
		ret = -1;
	}
	emit_and_free_accums(d, actx.accums);
	/* The drop and error counters go out with every snapshot. */
	dtotel_report(d, 1);
	return (ret);
}
