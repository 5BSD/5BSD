/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Aggregations to metric snapshots.  Walks libdtrace's typed
 * aggregation records (rather than parsing printa() text), decodes
 * every key by its action so stack()/sym()/mod() keys come out
 * symbolized, and converts each aggregating function's data to an
 * oe_snapshot: scalars for count/sum/min/max/avg/stddev and buckets
 * with inclusive upper bounds for the quantize family.
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
};

struct snap_accum {
	char		*name;		/* aggregation name ("" if anon) */
	uint16_t	 vmid;		/* the guest it came from, or 0 */
	enum oe_agg_kind kind;
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
 * Convert one llquantize data record to buckets, following the
 * bucket-bound walk in libdtrace's dt_print_llquantize().
 */
static void
llquantize_buckets(struct snap_point *pt, const int64_t *data, size_t size,
    int64_t normal, size_t *bcap)
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

	value = 1;
	for (order = 0; order < low; order++)
		value *= factor;
	/* Underflow bucket: values < factor^low. */
	if (levels > 0 && data[0] != 0)
		point_add_bucket(pt, value - 1, data[0] / normal, bcap);

	next = value * factor;
	step = next > nsteps ? next / nsteps : 1;
	bin = 1;
	order = low;
	while (order <= (int)high && bin < levels) {
		/*
		 * The bucket covers [value, value + step); export its
		 * inclusive upper bound, not its label (lower bound).
		 */
		if (data[bin] != 0)
			point_add_bucket(pt, value + step - 1,
			    data[bin] / normal, bcap);
		bin++;
		if ((value += step) != next)
			continue;
		next = value * factor;
		step = next > nsteps ? next / nsteps : 1;
		order++;
	}
	/* Overflow bucket: values >= factor^high. */
	if (bin < levels && data[bin] != 0)
		point_add_bucket(pt, INT64_MAX, data[bin] / normal, bcap);
}

static int
agg_walk(const dtrace_aggdata_t *agg, void *arg)
{
	struct agg_walk_ctx *ctx = arg;
	struct dtotel_keynames *ak;
	struct snap_accum *sa;
	struct snap_point *pt;
	dtrace_aggdesc_t *desc = agg->dtada_desc;
	const dtrace_recdesc_t *rec, *vrec;
	const char *aggname;
	caddr_t base = agg->dtada_data;
	enum oe_agg_kind kind;
	char attrname[24];
	size_t bcap, size, nbuckets, j;
	int64_t v[4], normal;
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
	sa = accum_for(ctx, aggname, kind, agg->dtada_edesc != NULL ?
	    agg->dtada_edesc->dtepd_vmid : 0);
	if (sa == NULL)
		return (DTRACE_AGGWALK_NEXT);
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

	/*
	 * Value.  dtada_normal carries normalize(); the reference
	 * consumer divides every exported number by it.
	 */
	normal = agg->dtada_normal != 0 ? (int64_t)agg->dtada_normal : 1;
	switch (kind) {
	case OE_AGG_COUNT:
	case OE_AGG_SUM:
	case OE_AGG_MIN:
	case OE_AGG_MAX:
		if (vrec->dtrd_size < sizeof(int64_t))
			break;
		memcpy(&v[0], base + vrec->dtrd_offset, sizeof(int64_t));
		pt->scalar = v[0] / normal;
		break;
	case OE_AGG_AVG:
		if (vrec->dtrd_size < 2 * sizeof(int64_t))
			break;
		memcpy(v, base + vrec->dtrd_offset, 2 * sizeof(int64_t));
		/* Reference order: (sum / normal) / count. */
		pt->scalar = v[0] != 0 ? v[1] / normal / v[0] : 0;
		break;
	case OE_AGG_STDDEV: {
		/*
		 * Layout: count, sum, sum-of-squares (128-bit as two
		 * 64-bit halves, low then high).  Compute
		 * sqrt((sumsq*cnt - sum^2) / cnt^2) exactly in 128-bit
		 * where available — the naive long-double form loses
		 * catastrophically to cancellation for large values.
		 */
		if (vrec->dtrd_size < 4 * sizeof(int64_t))
			break;
		memcpy(v, base + vrec->dtrd_offset, 4 * sizeof(int64_t));
#ifdef __SIZEOF_INT128__
		if (v[0] > 0) {
			unsigned __int128 sumsq, num, den;
			__int128 sum2;

			sumsq = ((unsigned __int128)(uint64_t)v[3] << 64) |
			    (uint64_t)v[2];
			sum2 = (__int128)v[1] * v[1];
			num = sumsq * (uint64_t)v[0];
			if (num > (unsigned __int128)sum2) {
				num -= (unsigned __int128)sum2;
				den = (unsigned __int128)(uint64_t)v[0] *
				    (uint64_t)v[0];
				pt->scalar = (int64_t)sqrtl(
				    (long double)(num / den)) / normal;
			} else
				pt->scalar = 0;
		} else
			pt->scalar = 0;
#else
		{
			long double cnt, sum, sumsq, var;

			cnt = (long double)v[0];
			sum = (long double)v[1];
			sumsq = (long double)(uint64_t)v[2] +
			    ldexpl((long double)(uint64_t)v[3], 64);
			if (cnt > 0) {
				var = sumsq / cnt - (sum / cnt) * (sum / cnt);
				pt->scalar = var > 0 ?
				    (int64_t)sqrtl(var) / normal : 0;
			} else
				pt->scalar = 0;
		}
#endif
		break;
	}
	case OE_AGG_QUANTIZE: {
		const int64_t *data =
		    (const int64_t *)(void *)(base + vrec->dtrd_offset);
		int64_t upper;

		pt->is_histogram = 1;
		bcap = 0;
		nbuckets = vrec->dtrd_size / sizeof(int64_t);
		if (nbuckets > DTRACE_QUANTIZE_NBUCKETS)
			nbuckets = DTRACE_QUANTIZE_NBUCKETS;
		for (j = 0; j < nbuckets; j++) {
			if (data[j] == 0)
				continue;
			/*
			 * BUCKETVAL(j) is the inclusive UPPER bound
			 * only for the negative and zero buckets; a
			 * positive bucket j covers
			 * [BUCKETVAL(j), BUCKETVAL(j+1)) so its
			 * inclusive upper is BUCKETVAL(j+1) - 1, and
			 * the top bucket is unbounded.
			 */
			if (j <= DTRACE_QUANTIZE_ZEROBUCKET)
				upper = DTRACE_QUANTIZE_BUCKETVAL(j);
			else if (j == nbuckets - 1)
				upper = INT64_MAX;
			else
				upper = DTRACE_QUANTIZE_BUCKETVAL(j + 1) - 1;
			point_add_bucket(pt, upper, data[j] / normal,
			    &bcap);
		}
		break;
	}
	case OE_AGG_LQUANTIZE: {
		const int64_t *data =
		    (const int64_t *)(void *)(base + vrec->dtrd_offset);
		uint64_t larg;
		int32_t lbase;
		uint16_t step, levels;

		/* First slot carries the lquantize argument. */
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

			if (data[j + 1] == 0)
				continue;
			if (j == 0)
				upper = (int64_t)lbase - 1; /* underflow */
			else if (j == (size_t)levels + 1)
				upper = INT64_MAX;	/* overflow */
			else
				upper = lbase + (int64_t)j * step - 1;
			point_add_bucket(pt, upper, data[j + 1] / normal,
			    &bcap);
		}
		break;
	}
	case OE_AGG_LLQUANTIZE:
		pt->is_histogram = 1;
		bcap = 0;
		size = vrec->dtrd_size;
		llquantize_buckets(pt,
		    (const int64_t *)(void *)(base + vrec->dtrd_offset),
		    size, normal, &bcap);
		break;
	}

	return (DTRACE_AGGWALK_NEXT);
}

static void
emit_and_free_accums(struct dtotel *d, struct snap_accum *accums)
{
	struct snap_accum *sa, *next;
	struct snap_point *pt;
	struct oe_snapshot sn;
	struct oe_datapoint *dps;
	size_t i, j;

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
			}
			memset(&sn, 0, sizeof(sn));
			clock_gettime(CLOCK_REALTIME, &sn.ts);
			sn.start = d->start;
			sn.profile = d->profile;
			sn.name = sa->name;
			sn.kind = sa->kind;
			sn.points = dps;
			sn.npoints = sa->npoints;
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
	return (ret);
}
