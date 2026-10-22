/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Aggregation snapshot, merge, sort and walk coverage for libdtrace's
 * dt_aggregate.c, driven offline through dtrace_vopen().
 *
 * The dtrace(4) model (DOF parsing, kernel record layout, BUFSNAP/AGGSNAP
 * rings, AGGDESC/EPROBE answers and fault injection) is reused verbatim from
 * consume-ingestion.c, which is included below; only its main() is renamed.
 * Every expected value here is computed by this file from documented D
 * semantics: the aggregating functions' arithmetic, the kernel's
 * quantize/lquantize/llquantize bucket layout, and the documented sort
 * rules (value then key, aggsortkey, aggsortrev, aggsortpos, aggsortkeypos,
 * and the explicit dtrace_aggregate_walk_*sorted orders).  No expected
 * value is captured from the library.
 *
 * Built twice: with ASan/UBSan (the default), and with -DAGG_FAULT as a
 * non-sanitized binary whose malloc family and sysctlbyname wrap libc's
 * __malloc etc. so allocation failures can be injected into the library.
 */

#define	main consume_ingestion_main
#include "consume-ingestion.c"
#undef main

#include <sys/wait.h>

#include <dlfcn.h>

#ifdef AGG_FAULT
/*
 * Allocation fault injection.  The executable's malloc family interposes on
 * the library's (FreeBSD libc exports __malloc and friends).  fault_countdown
 * counts down allocations; the allocation that brings it to zero fails.
 */
void *__malloc(size_t);
void *__calloc(size_t, size_t);
void *__realloc(void *, size_t);
void __free(void *);
static long fault_countdown = -1;
static int fault_hit;
/* When set, only allocations called directly from this function count. */
static const char *fault_only;

static int
fault_now(void *caller)
{
	Dl_info info;

	if (fault_countdown < 0)
		return (0);
	/* Only libdtrace's allocations (not the callbacks' stdio). */
	if (dladdr(caller, &info) == 0 || info.dli_fname == NULL ||
	    strstr(info.dli_fname, "libdtrace.so") == NULL)
		return (0);
	if (fault_only != NULL && (info.dli_sname == NULL ||
	    strcmp(info.dli_sname, fault_only) != 0))
		return (0);
	if (fault_countdown-- == 0) {
		fault_hit = 1;
		return (1);
	}
	return (0);
}

void *
malloc(size_t n)
{
	if (fault_now(__builtin_return_address(0))) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__malloc(n));
}

void *
calloc(size_t a, size_t b)
{
	if (fault_now(__builtin_return_address(0))) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__calloc(a, b));
}

void *
realloc(void *p, size_t n)
{
	if (fault_now(__builtin_return_address(0))) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__realloc(p, n));
}

void
free(void *p)
{
	__free(p);
}

/* kern.smp.maxid failure for dt_cpu_maxid(). */
/* The libc system call stub takes the name length (FreeBSD 12+). */
int __sysctlbyname(const char *, size_t, void *, size_t *, const void *,
    size_t);
static int fail_maxid;

int
sysctlbyname(const char *name, void *old, size_t *oldlen, const void *new,
    size_t newlen)
{
	if (fail_maxid && strcmp(name, "kern.smp.maxid") == 0) {
		errno = EPERM;
		return (-1);
	}
	return (__sysctlbyname(name, strlen(name), old, oldlen, new, newlen));
}
#endif

/* ------------------------------------------------------------------ */
/* A vector that wraps the model so individual answers can be altered. */

static int alt_uarg0;		/* AGGDESC: clear rec[0].dtrd_uarg */
static int alt_badact;		/* AGGDESC: last record not an aggregation */
static int alt_badact_id;	/* ... only for this aggregation ID */
static int alt_aggsize_unset;	/* DOFGET: aggsize reported unset */
static int alt_status_down = -1; /* dtv_status: this CPU is absent */

static int
alt_ioctl(void *varg, u_long cmd, void *arg)
{
	int req = CMD(cmd) == CMD(DTRACEIOC_AGGDESC) ?
	    (*(dtrace_aggdesc_t **)arg)->dtagd_nrecs : 0;
	int rv = model_ioctl(varg, cmd, arg);

	if (rv != 0)
		return (rv);
	if (CMD(cmd) == CMD(DTRACEIOC_AGGDESC)) {
		dtrace_aggdesc_t *d = *(dtrace_aggdesc_t **)arg;

		/* Only a complete answer carries every record. */
		if (d->dtagd_nrecs > req)
			return (0);
		if (alt_uarg0 && d->dtagd_nrecs >= 1)
			d->dtagd_rec[0].dtrd_uarg = 0;
		if ((alt_badact || (alt_badact_id != 0 &&
		    d->dtagd_id == (dtrace_aggid_t)alt_badact_id)) &&
		    d->dtagd_nrecs >= 2 &&
		    DTRACEACT_ISAGG(d->dtagd_rec[d->dtagd_nrecs - 1].
		    dtrd_action))
			d->dtagd_rec[d->dtagd_nrecs - 1].dtrd_action =
			    DTRACEACT_DIFEXPR;
	} else if (CMD(cmd) == CMD(DTRACEIOC_DOFGET) && alt_aggsize_unset) {
		dof_hdr_t *dof = *(dof_hdr_t **)arg;
		dof_sec_t *sec = (dof_sec_t *)((char *)dof + dof->dofh_secoff);
		dof_optdesc_t *o = (dof_optdesc_t *)((char *)dof +
		    sec->dofs_offset);

		if (dof->dofh_loadsz >= sec->dofs_offset + sec->dofs_size)
			o[DTRACEOPT_AGGSIZE].dofo_value = DTRACEOPT_UNSET;
	}
	return (0);
}

static int
alt_status(void *varg, processorid_t cpu)
{
	if (cpu == alt_status_down)
		return (-1);
	return (model_status(varg, cpu));
}

static const dtrace_vector_t altvec = {
	.dtv_ioctl = alt_ioctl,
	.dtv_lookup_by_addr = model_lookup,
	.dtv_status = alt_status,
	.dtv_sysconf = model_sysconf,
};

static int drop_abort, ndrops;
static uint64_t dropcount;

static int
adrop_cb(const dtrace_dropdata_t *d, void *arg)
{
	(void) arg;
	ndrops++;
	dropcount += d->dtdda_drops;
	if (d->dtdda_kind != DTRACEDROP_AGGREGATION)
		ndrops += 1000;
	return (drop_abort ? DTRACE_HANDLE_ABORT : DTRACE_HANDLE_OK);
}

static void
reset_alt(void)
{
	reset_model();
	alt_uarg0 = alt_badact = alt_badact_id = alt_aggsize_unset = 0;
	alt_status_down = -1;
	drop_abort = ndrops = 0;
	dropcount = 0;
}

/*
 * Like open_session(), with the wrapping vector, an optional "go" step and
 * options applied after the bufsize/aggsize defaults.
 */
static int
aopen(struct session *s, const char *name, const char *const *opts,
    const char *program, int go)
{
	dtrace_prog_t *prog;
	dtrace_proginfo_t info;
	int err, i;

	memset(s, 0, sizeof (*s));
	s->dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS | DTRACE_O_LP64,
	    &err, &altvec, &M);
	if (s->dtp == NULL) {
		fail(name, "dtrace_vopen", "", dtrace_errmsg(NULL, err));
		return (-1);
	}
	s->out = open_memstream(&s->text, &s->len);
	assert(s->out != NULL);
	(void) dtrace_setopt(s->dtp, "bufsize", "64k");
	(void) dtrace_setopt(s->dtp, "aggsize", "64k");
	for (i = 0; opts != NULL && opts[i] != NULL; i += 2) {
		if (dtrace_setopt(s->dtp, opts[i], opts[i + 1]) != 0) {
			fail(name, opts[i], "", dtrace_errmsg(s->dtp,
			    dtrace_errno(s->dtp)));
			return (-1);
		}
	}
	if (dtrace_handle_drop(s->dtp, adrop_cb, NULL) != 0 ||
	    dtrace_handle_err(s->dtp, err_cb, NULL) != 0) {
		fail(name, "handlers", "", "");
		return (-1);
	}
	if ((prog = dtrace_program_strcompile(s->dtp, program,
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL)) == NULL) {
		fail(name, "compile", program, dtrace_errmsg(s->dtp,
		    dtrace_errno(s->dtp)));
		return (-1);
	}
	if (dtrace_program_exec(s->dtp, prog, &info) != 0) {
		fail(name, "exec", "", dtrace_errmsg(s->dtp,
		    dtrace_errno(s->dtp)));
		return (-1);
	}
	if (go && dtrace_go(s->dtp) != 0) {
		fail(name, "go", "", dtrace_errmsg(s->dtp,
		    dtrace_errno(s->dtp)));
		return (-1);
	}
	return (0);
}

/* Library errors are compared by their public dtrace_errmsg() text. */
#define	MSG_NOMEM	"Memory allocation failure"
#define	MSG_BADAGG	"Unknown aggregating action"
#define	MSG_DROPABORT	"Abort due to drop"
#define	MSG_BADAGGVAR	"Invalid aggregation variable identifier"

static int
is_err(struct session *s, int rc, const char *msg)
{
	return (rc == -1 && strcmp(dtrace_errmsg(s->dtp,
	    dtrace_errno(s->dtp)), msg) == 0);
}

static FILE *rfp;

/* A fresh output stream; rfp follows it. */
static void
reopen_out(struct session *s)
{
	fclose(s->out);
	free(s->text);
	s->text = NULL;
	s->out = open_memstream(&s->text, &s->len);
	assert(s->out != NULL);
	rfp = s->out;
}

static void
pass(const char *name)
{
	passes++;
	printf("PASS %s\n", name);
}

/* Compare accumulated text against the expectation built with X(). */
static void
expect_text(const char *name, const char *what, const char *got)
{
	const char *want = xend();

	if (strcmp(want, got) != 0)
		fail(name, what, want, got);
	else
		pass(name);
}

static void
expect_true(const char *name, int cond, const char *what)
{
	if (!cond)
		fail(name, what, "true\n", "false\n");
	else
		pass(name);
}

/* ------------------------------------------------------------------ */
/* Independent oracles for the aggregating functions.                  */

#define	ZB	((int)DTRACE_QUANTIZE_ZEROBUCKET)	/* 63 */
#define	NQB	((int)DTRACE_QUANTIZE_NBUCKETS)

static int
ilog2(uint64_t v)
{
	int n = -1;

	while (v != 0) {
		v >>= 1;
		n++;
	}
	return (n);
}

/* Power-of-two bucket: 0 -> zero bucket, +-[2^k, 2^(k+1)) -> +-2^k. */
static int
q_idx(int64_t v)
{
	if (v == 0)
		return (ZB);
	if (v > 0)
		return (ZB + 1 + ilog2((uint64_t)v));
	return (ZB - 1 - ilog2((uint64_t)-v));
}

static int64_t
q_weight(int idx)
{
	if (idx == ZB)
		return (0);
	if (idx > ZB)
		return ((int64_t)1 << (idx - ZB - 1));
	return (-((int64_t)1 << (ZB - 1 - idx)));
}

/* lquantize(base, step, levels): underflow, levels buckets, overflow. */
static int
l_idx(int base, int step, int levels, int64_t v)
{
	if (v < base)
		return (0);
	if ((v - base) / step < levels)
		return (1 + (int)((v - base) / step));
	return (levels + 1);
}

static int64_t
l_weight(int base, int step, int levels, int idx)
{
	if (idx == 0)
		return (base - 1);
	if (idx <= levels)
		return (base + (int64_t)(idx - 1) * step);
	return (base + (int64_t)levels * step + 1);
}

/*
 * llquantize(factor, low, high, nsteps): an underflow bucket below
 * factor^low, then for each order o in [low, high] the buckets
 * factor^o + k * step below factor^(o+1), where step is
 * factor^(o+1) / nsteps once that exceeds one, then an overflow bucket.
 */
static int
ll_bounds(int f, int low, int high, int nsteps, int64_t *b, int max)
{
	int64_t lo = 1, hi, step, v;
	int n = 0, o;

	for (o = 0; o < low; o++)
		lo *= f;
	b[n++] = lo - 1;		/* underflow weight */
	for (o = low; o <= high; o++, lo = hi) {
		hi = lo * f;
		step = hi > nsteps ? hi / nsteps : 1;
		for (v = lo; v < hi; v += step) {
			assert(n < max);
			b[n++] = v;
		}
	}
	b[n++] = lo;			/* overflow weight: factor^(high+1) */
	return (n);
}

static int
ll_idx(const int64_t *b, int n, int64_t v)
{
	int i;

	if (v < b[1])
		return (0);
	if (v >= b[n - 1])
		return (n - 1);
	for (i = n - 2; i >= 1; i--)
		if (v >= b[i])
			return (i);
	abort();
}

static uint64_t
isqrt(uint64_t v)
{
	uint64_t r = 0;

	while ((r + 1) * (r + 1) <= v)
		r++;
	return (r);
}

/* ------------------------------------------------------------------ */
/* Keyed aggregations described as data, with their expected walk.     */

struct kv {
	const char *key;
	int n;
	int64_t v[4];
	int cpu[4];
};

struct aspec {
	int act;
	int p[4];	/* lquantize base/step/levels; llquantize f/l/h/n */
	struct kv d[5];
};

struct erow {
	int varid, act;
	const char *key;
	long double metric;
	int64_t zero;
	char summary[512];
};

static void
summarize(const struct aspec *a, const struct kv *k, struct erow *r)
{
	int64_t buckets[DTRACE_QUANTIZE_NBUCKETS], bounds[128];
	int nb = 0, i, j;
	int64_t sum = 0, sq = 0, mn = INT64_MAX, mx = INT64_MIN;
	FILE *fp;
	size_t len;
	char *s = NULL;

	memset(buckets, 0, sizeof (buckets));
	if (a->act == DTRACEAGG_LLQUANTIZE)
		nb = ll_bounds(a->p[0], a->p[1], a->p[2], a->p[3], bounds,
		    128);
	for (i = 0; i < k->n; i++) {
		int64_t v = k->v[i];

		sum += v;
		sq += v * v;
		mn = v < mn ? v : mn;
		mx = v > mx ? v : mx;
		if (a->act == DTRACEAGG_QUANTIZE)
			buckets[q_idx(v)]++;
		else if (a->act == DTRACEAGG_LQUANTIZE)
			buckets[l_idx(a->p[0], a->p[1], a->p[2], v)]++;
		else if (a->act == DTRACEAGG_LLQUANTIZE)
			buckets[ll_idx(bounds, nb, v)]++;
	}
	fp = open_memstream(&s, &len);
	r->zero = 0;
	switch (a->act) {
	case DTRACEAGG_COUNT:
		r->metric = k->n;
		fprintf(fp, "%d", k->n);
		break;
	case DTRACEAGG_SUM:
		r->metric = sum;
		fprintf(fp, "%lld", (long long)sum);
		break;
	case DTRACEAGG_MIN:
		r->metric = mn;
		fprintf(fp, "%lld", (long long)mn);
		break;
	case DTRACEAGG_MAX:
		r->metric = mx;
		fprintf(fp, "%lld", (long long)mx);
		break;
	case DTRACEAGG_AVG:
		r->metric = k->n ? sum / k->n : 0;
		fprintf(fp, "%d,%lld", k->n, (long long)sum);
		break;
	case DTRACEAGG_STDDEV: {
		int64_t avg = k->n ? sum / k->n : 0;

		if (avg < 0)
			avg = -avg;
		r->metric = k->n ? isqrt((uint64_t)(sq / k->n -
		    avg * avg)) : 0;
		fprintf(fp, "%d,%lld,%lld", k->n, (long long)sum,
		    (long long)sq);
		break;
	}
	case DTRACEAGG_QUANTIZE:
		r->metric = 0;
		for (j = 0; j < NQB; j++) {
			r->metric += (long double)q_weight(j) * buckets[j];
			if (buckets[j])
				fprintf(fp, "%d:%lld ", j,
				    (long long)buckets[j]);
		}
		r->zero = buckets[ZB];
		break;
	case DTRACEAGG_LQUANTIZE:
		/* DTRACE_LQUANTIZE_{STEP,LEVEL,BASE}SHIFT encoding. */
		fprintf(fp, "arg=%llx ", ((unsigned long long)(uint16_t)a->p[1]
		    << 48) | ((unsigned long long)(uint16_t)a->p[2] << 32) |
		    (unsigned long long)(uint32_t)a->p[0]);
		r->metric = 0;
		for (j = 0; j <= a->p[2] + 1; j++) {
			int64_t w = l_weight(a->p[0], a->p[1], a->p[2], j);

			r->metric += (long double)w * buckets[j];
			if (w == 0)
				r->zero = buckets[j];
			if (buckets[j])
				fprintf(fp, "%d:%lld ", j,
				    (long long)buckets[j]);
		}
		break;
	case DTRACEAGG_LLQUANTIZE:
		/* DTRACE_LLQUANTIZE_{FACTOR,LOW,HIGH,NSTEP}SHIFT encoding. */
		fprintf(fp, "arg=%llx ", ((unsigned long long)a->p[0] << 48) |
		    ((unsigned long long)a->p[1] << 32) |
		    ((unsigned long long)a->p[2] << 16) |
		    (unsigned long long)a->p[3]);
		r->metric = 0;
		for (j = 0; j < nb; j++) {
			r->metric += (long double)bounds[j] * buckets[j];
			if (buckets[j])
				fprintf(fp, "%d:%lld ", j,
				    (long long)buckets[j]);
		}
		/* The documented tie-breaker is the underflow bucket. */
		r->zero = buckets[0];
		break;
	default:
		abort();
	}
	fclose(fp);
	snprintf(r->summary, sizeof (r->summary), "%s", s);
	free(s);
}

/* Render one aggregation entry the same way, from the library's data. */
static void
render_key(FILE *fp, const dtrace_aggdata_t *a)
{
	dtrace_aggdesc_t *d = a->dtada_desc;
	dtrace_recdesc_t *rec;
	const char *p;
	int i;

	for (i = 1; i < d->dtagd_nrecs - 1; i++) {
		rec = &d->dtagd_rec[i];
		p = a->dtada_data + rec->dtrd_offset;
		switch (rec->dtrd_size) {
		case 1:
			fprintf(fp, " %d", *(const int8_t *)p);
			break;
		case 2:
			fprintf(fp, " %d", *(const int16_t *)p);
			break;
		case 4:
			fprintf(fp, " %d", *(const int32_t *)p);
			break;
		case 8:
			fprintf(fp, " %lld", *(const long long *)p);
			break;
		case 16:
			if (rec->dtrd_action == DTRACEACT_USYM ||
			    rec->dtrd_action == DTRACEACT_UMOD ||
			    rec->dtrd_action == DTRACEACT_UADDR) {
				fprintf(fp, " %llx:%llx",
				    ((const unsigned long long *)p)[0],
				    ((const unsigned long long *)p)[1]);
				break;
			}
			/* FALLTHROUGH */
		default:
			fprintf(fp, " %s", p);
		}
	}
}

static void
render_raw(FILE *fp, const dtrace_recdesc_t *rec, const int64_t *v)
{
	int i, n;

	switch (rec->dtrd_action) {
	case DTRACEAGG_COUNT:
	case DTRACEAGG_SUM:
	case DTRACEAGG_MIN:
	case DTRACEAGG_MAX:
		fprintf(fp, "%lld", (long long)v[0]);
		break;
	case DTRACEAGG_AVG:
		fprintf(fp, "%lld,%lld", (long long)v[0], (long long)v[1]);
		break;
	case DTRACEAGG_STDDEV:
		/* 128-bit sum of squares; small values only. */
		fprintf(fp, "%lld,%lld,%lld", (long long)v[0],
		    (long long)v[1], (long long)v[2]);
		break;
	case DTRACEAGG_QUANTIZE:
		for (i = 0; i < NQB; i++)
			if (v[i])
				fprintf(fp, "%d:%lld ", i, (long long)v[i]);
		break;
	case DTRACEAGG_LQUANTIZE:
	case DTRACEAGG_LLQUANTIZE:
		fprintf(fp, "arg=%llx ", (unsigned long long)v[0]);
		n = rec->dtrd_size / sizeof (int64_t) - 1;
		for (i = 0; i < n; i++)
			if (v[i + 1])
				fprintf(fp, "%d:%lld ", i, (long long)v[i + 1]);
		break;
	default:
		fprintf(fp, "?");
	}
}

static void
render_val(FILE *fp, const dtrace_aggdata_t *a)
{
	dtrace_aggdesc_t *d = a->dtada_desc;
	dtrace_recdesc_t *rec = &d->dtagd_rec[d->dtagd_nrecs - 1];

	render_raw(fp, rec, (const int64_t *)(a->dtada_data +
	    rec->dtrd_offset));
}

static void
render(FILE *fp, const dtrace_aggdata_t *a)
{
	fprintf(fp, "%lld", (long long)a->dtada_desc->dtagd_varid);
	render_key(fp, a);
	fputc(' ', fp);
	render_val(fp, a);
	fputc('\n', fp);
}

static int walk_rval = DTRACE_AGGWALK_NEXT;

static int
render_cb(const dtrace_aggdata_t *a, void *arg)
{
	(void) arg;
	render(rfp, a);
	return (walk_rval);
}

enum { O_VAL, O_KEY, O_VALVAR, O_KEYVAR };
static int omode;

static int
ecmp_key(const struct erow *a, const struct erow *b)
{
	return (strcmp(a->key, b->key));
}

static int
ecmp_val(const struct erow *a, const struct erow *b)
{
	if (a->act != b->act)
		return (a->act < b->act ? -1 : 1);
	if (a->metric != b->metric)
		return (a->metric < b->metric ? -1 : 1);
	if (a->zero != b->zero)
		return (a->zero < b->zero ? -1 : 1);
	return (0);
}

static int
ecmp(const void *l, const void *r)
{
	const struct erow *a = l, *b = r;
	int c;

	switch (omode) {
	case O_VAL:
		if (a->varid != b->varid)
			return (a->varid - b->varid);
		if ((c = ecmp_val(a, b)) != 0)
			return (c);
		return (ecmp_key(a, b));
	case O_KEY:
		if (a->varid != b->varid)
			return (a->varid - b->varid);
		return (ecmp_key(a, b));
	case O_VALVAR:
		if ((c = ecmp_val(a, b)) != 0)
			return (c);
		if ((c = ecmp_key(a, b)) != 0)
			return (c);
		return (a->varid - b->varid);
	default:
		if ((c = ecmp_key(a, b)) != 0)
			return (c);
		return (a->varid - b->varid);
	}
}

#define	MAXROWS	64

static int
expected_rows(const struct aspec *as, int nagg, struct erow *rows)
{
	int i, j, n = 0;

	for (i = 0; i < nagg; i++) {
		for (j = 0; j < 5 && as[i].d[j].key != NULL; j++) {
			rows[n].varid = i + 1;
			rows[n].act = as[i].act;
			rows[n].key = as[i].d[j].key;
			summarize(&as[i], &as[i].d[j], &rows[n]);
			n++;
		}
	}
	return (n);
}

static void
emit_rows(struct erow *rows, int n, int mode, int reverse)
{
	int i;

	omode = mode;
	qsort(rows, n, sizeof (rows[0]), ecmp);
	for (i = 0; i < n; i++) {
		struct erow *r = &rows[reverse ? n - 1 - i : i];

		X("%d %s %s\n", r->varid, r->key, r->summary);
	}
}

/* Fire every value of every aggregation of a one-string-key program. */
static void
fire_specs(const struct aspec *as, int nagg)
{
	struct val v[3 * 8];
	int i, j, k, m;

	assert(nagg <= 8);
	for (i = 0; i < nagg; i++) {
		for (j = 0; j < 5 && as[i].d[j].key != NULL; j++) {
			const struct kv *d = &as[i].d[j];

			for (k = 0; k < d->n; k++) {
				for (m = 0; m < nagg; m++) {
					struct val key = { d->key,
					    strlen(d->key) + 1, 0, 1 };
					struct val id = N(m + 1);
					struct val skip = SKIP;
					struct val agg = AGG(d->v[k], 1);

					v[3 * m] = id;
					v[3 * m + 1] = key;
					v[3 * m + 2] = m == i ? agg : skip;
				}
				fire(d->cpu[k], "test:kernel:alpha:entry", 0,
				    v, 3 * nagg);
			}
		}
	}
}

#define	LQ(b, s, l)	{ b, s, l, 0 }

/* Session A: one aggregation of each value representation. */
static const struct aspec spec_a[] = {
	{ DTRACEAGG_AVG, { 0 }, {
	    { "k1", 1, { 10 }, { 0 } },
	    { "k2", 2, { 1, 3 }, { 0, 1 } },
	    { "k3", 2, { 5, 6 }, { 1, 0 } },
	    { "k4", 1, { 5 }, { 1 } },
	    { "k5", 1, { -7 }, { 0 } } } },
	{ DTRACEAGG_STDDEV, { 0 }, {
	    { "k1", 2, { 0, 10 }, { 0, 1 } },	/* 5 */
	    { "k2", 2, { 1, 1 }, { 0, 0 } },	/* 0 */
	    { "k3", 2, { 0, 4 }, { 1, 1 } },	/* 2 */
	    { "k4", 2, { 7, 7 }, { 0, 1 } },	/* 0 */
	    { "k5", 2, { -2, 2 }, { 0, 1 } } } },	/* 2 */
	{ DTRACEAGG_QUANTIZE, { 0 }, {
	    { "k1", 1, { 4 }, { 0 } },		/* 4 */
	    { "k2", 2, { 1, 1 }, { 0, 1 } },	/* 2, zero 0 */
	    { "k3", 2, { -1, 3 }, { 1, 0 } },	/* 1 */
	    { "k4", 2, { 0, 2 }, { 0, 1 } },	/* 2, zero 1 */
	    { "k5", 3, { 0, 0, 2 }, { 1, 1, 0 } } } },	/* 2, zero 2 */
	{ DTRACEAGG_LQUANTIZE, LQ(0, 2, 5), {
	    { "k1", 2, { 0, 4 }, { 0, 1 } },	/* 4, zero 1 */
	    { "k2", 1, { 4 }, { 1 } },		/* 4, zero 0 */
	    { "k3", 2, { 2, 2 }, { 0, 1 } },	/* 4, zero 0 */
	    { "k4", 1, { -5 }, { 0 } },		/* -1 */
	    { "k5", 1, { 20 }, { 1 } } } },	/* 11 */
	{ DTRACEAGG_LLQUANTIZE, { 10, 0, 2, 10 }, {
	    { "k1", 2, { 0, 2 }, { 0, 1 } },	/* 2, underflow 1 */
	    { "k2", 1, { 2 }, { 1 } },		/* 2 */
	    { "k3", 2, { 1, 1 }, { 0, 1 } },	/* 2 */
	    { "k4", 3, { 0, 0, 2 }, { 0, 1, 0 } },	/* 2, underflow 2 */
	    { "k5", 1, { 5000 }, { 1 } } } },	/* 1000 */
	{ DTRACEAGG_MIN, { 0 }, {
	    { "k1", 2, { 3, 1 }, { 0, 1 } },
	    { "k2", 2, { 5, 6 }, { 1, 0 } },
	    { "k3", 2, { -2, 9 }, { 0, 1 } },
	    { "k4", 1, { 5 }, { 0 } } } },
	{ DTRACEAGG_MAX, { 0 }, {
	    { "k1", 2, { 3, 1 }, { 0, 1 } },
	    { "k2", 2, { 5, 6 }, { 0, 1 } },
	    { "k3", 2, { -2, 9 }, { 1, 0 } },
	    { "k4", 1, { 6 }, { 1 } } } },
};

#define	PROG_A	"test:::entry { @a[probefunc] = avg(arg0); " \
	"@s[probefunc] = stddev(arg0); @q[probefunc] = quantize(arg0); " \
	"@l[probefunc] = lquantize(arg0, 0, 10, 2); " \
	"@ll[probefunc] = llquantize(arg0, 10, 0, 2, 10); " \
	"@mn[probefunc] = min(arg0); @mx[probefunc] = max(arg0); }"

/* Session B: lquantize zero placements, llquantize low > 0, count, sum. */
static const struct aspec spec_b[] = {
	{ DTRACEAGG_LQUANTIZE, LQ(1, 1, 4), {	/* underflow weighs 0 */
	    { "k1", 2, { 0, 3 }, { 0, 1 } },
	    { "k2", 1, { 3 }, { 1 } },
	    { "k3", 2, { 1, 2 }, { 0, 1 } },
	    { "k4", 2, { 0, 3 }, { 1, 1 } } } },
	{ DTRACEAGG_LQUANTIZE, LQ(-10, 1, 9), {	/* overflow weighs 0 */
	    { "k1", 2, { -1, -4 }, { 0, 1 } },
	    { "k2", 1, { -4 }, { 1 } },
	    { "k3", 2, { -2, -2 }, { 0, 1 } },
	    { "k4", 2, { 0, -4 }, { 0, 0 } } } },
	{ DTRACEAGG_LQUANTIZE, LQ(5, 1, 5), {	/* zero not in range */
	    { "k1", 1, { 6 }, { 0 } },
	    { "k2", 1, { 6 }, { 1 } },
	    { "k3", 1, { 7 }, { 0 } } } },
	{ DTRACEAGG_LLQUANTIZE, { 2, 1, 3, 4 }, {
	    { "k1", 2, { 1, 6 }, { 0, 1 } },	/* 1 + 6, underflow 1 */
	    { "k2", 2, { 3, 4 }, { 1, 0 } },	/* 3 + 4 */
	    { "k3", 1, { 12 }, { 0 } },
	    { "k4", 1, { 100 }, { 1 } } } },	/* overflow 16 */
	{ DTRACEAGG_COUNT, { 0 }, {
	    { "k1", 3, { 0, 0, 0 }, { 0, 1, 1 } },
	    { "k2", 1, { 0 }, { 1 } },
	    { "k3", 2, { 0, 0 }, { 0, 0 } } } },
	{ DTRACEAGG_SUM, { 0 }, {
	    { "k1", 2, { 5, -9 }, { 0, 1 } },
	    { "k2", 1, { 3 }, { 1 } },
	    { "k3", 2, { 1, 2 }, { 0, 1 } } } },
	/* factor^(low+1) > nsteps from the first order. */
	{ DTRACEAGG_LLQUANTIZE, { 10, 1, 3, 10 }, {
	    { "k1", 2, { 5, 20 }, { 0, 1 } },	/* 9 + 20, underflow 1 */
	    { "k2", 1, { 29 }, { 1 } },		/* 20 */
	    { "k3", 1, { 3000 }, { 0 } },
	    { "k4", 2, { 10, 10 }, { 0, 1 } } } },	/* 20 */
	/* Several orders with factor^(o+1) <= nsteps. */
	{ DTRACEAGG_LLQUANTIZE, { 2, 0, 4, 8 }, {
	    { "k1", 2, { 0, 3 }, { 0, 1 } },	/* 0 + 3, underflow 1 */
	    { "k2", 1, { 3 }, { 1 } },
	    { "k3", 2, { 1, 2 }, { 1, 1 } },	/* 1 + 2 */
	    { "k4", 1, { 40 }, { 0 } } } },	/* overflow 32 */
};

#define	PROG_B	"test:::entry { @l1[probefunc] = lquantize(arg0, 1, 5, 1); " \
	"@l2[probefunc] = lquantize(arg0, -10, -1, 1); " \
	"@l3[probefunc] = lquantize(arg0, 5, 10, 1); " \
	"@ll[probefunc] = llquantize(arg0, 2, 1, 3, 4); " \
	"@c[probefunc] = count(); @s[probefunc] = sum(arg0); " \
	"@l7[probefunc] = llquantize(arg0, 10, 1, 3, 10); " \
	"@l8[probefunc] = llquantize(arg0, 2, 0, 4, 8); }"

#define	NSPEC(x)	((int)(sizeof (x) / sizeof ((x)[0])))

typedef int walkfn_t(dtrace_hdl_t *, dtrace_aggregate_f *, void *);

/*
 * Each walk is checked against the oracle order.  dtrace_aggregate_walk_sorted
 * follows the aggsortkey/aggsortrev options (value order, or key order, per
 * variable; reversal reverses the whole order); explicit sorted walks ignore
 * the options.
 */
static void
case_value_orders(const char *tag, const struct aspec *spec, int nspec,
    const char *prog)
{
	static const struct {
		const char *name;
		const char *opts[5];
		walkfn_t *walk;
		int mode, reverse;
	} w[] = {
		{ "sorted", { NULL }, dtrace_aggregate_walk_sorted, O_VAL, 0 },
		{ "sorted-rev", { "aggsortrev", NULL, NULL },
		    dtrace_aggregate_walk_sorted, O_VAL, 1 },
		{ "sorted-key", { "aggsortkey", NULL, NULL },
		    dtrace_aggregate_walk_sorted, O_KEY, 0 },
		{ "sorted-key-rev", { "aggsortkey", NULL, "aggsortrev", NULL,
		    NULL }, dtrace_aggregate_walk_sorted, O_KEY, 1 },
		{ "valsorted", { "aggsortrev", NULL, NULL },
		    dtrace_aggregate_walk_valsorted, O_VAL, 0 },
		{ "valrevsorted", { NULL }, dtrace_aggregate_walk_valrevsorted,
		    O_VAL, 1 },
		{ "keysorted", { NULL }, dtrace_aggregate_walk_keysorted,
		    O_KEY, 0 },
		{ "keyrevsorted", { NULL },
		    dtrace_aggregate_walk_keyrevsorted, O_KEY, 1 },
		{ "valvarsorted", { NULL },
		    dtrace_aggregate_walk_valvarsorted, O_VALVAR, 0 },
		{ "valvarrevsorted", { NULL },
		    dtrace_aggregate_walk_valvarrevsorted, O_VALVAR, 1 },
		{ "keyvarsorted", { NULL },
		    dtrace_aggregate_walk_keyvarsorted, O_KEYVAR, 0 },
		{ "keyvarrevsorted", { NULL },
		    dtrace_aggregate_walk_keyvarrevsorted, O_KEYVAR, 1 },
	};
	struct erow rows[MAXROWS];
	char name[128];
	size_t i;
	int n;

	for (i = 0; i < sizeof (w) / sizeof (w[0]); i++) {
		struct session s;

		snprintf(name, sizeof (name), "%s-%s", tag, w[i].name);
		reset_alt();
		if (aopen(&s, name, w[i].opts, prog, 1) == 0) {
			fire_specs(spec, nspec);
			rfp = s.out;
			if (dtrace_aggregate_snap(s.dtp) != 0 ||
			    w[i].walk(s.dtp, render_cb, NULL) != 0)
				fail(name, "walk", "", dtrace_errmsg(s.dtp,
				    dtrace_errno(s.dtp)));
			fflush(s.out);
			xbegin();
			n = expected_rows(spec, nspec, rows);
			emit_rows(rows, n, w[i].mode, w[i].reverse);
			expect_text(name, "order", s.text);
		}
		close_session(&s);
	}
}

/*
 * Run a case in a child so that a library crash is reported as a failure of
 * that case only.  The child reports its own PASS/FAIL lines and exit()s so
 * that its coverage profile is written.
 */
static void
in_child(const char *name, void (*fn)(void))
{
	pid_t pid;
	int status;

	fflush(stdout);
	fflush(stderr);
	if ((pid = fork()) == 0) {
		failures = passes = 0;
		fn();
		fflush(stdout);
		exit(failures != 0);
	}
	assert(pid > 0);
	while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
		continue;
	if (WIFSIGNALED(status)) {
		char buf[64];

		snprintf(buf, sizeof (buf), "killed by signal %d\n",
		    WTERMSIG(status));
		fail(name, "child", "normal exit\n", buf);
	} else if (WEXITSTATUS(status) != 0) {
		failures++;
		printf("FAIL %s: child reported failures\n", name);
	}
}

static int
clear_cb(const dtrace_aggdata_t *a, void *arg)
{
	(void) a;
	(void) arg;
	return (DTRACE_AGGWALK_CLEAR);
}

/* Expected rows after every value has been zeroed: value ties, key order. */
static void
emit_zero_rows(const struct aspec *spec, int nspec, int mode)
{
	struct aspec z[8];
	struct erow rows[MAXROWS];
	int i, j, n;

	assert(nspec <= 8);
	memcpy(z, spec, nspec * sizeof (z[0]));
	for (i = 0; i < nspec; i++)
		for (j = 0; j < 5; j++)
			z[i].d[j].n = 0;
	n = expected_rows(z, nspec, rows);
	for (i = 0; i < n; i++) {
		/* min/max were zero-filled, not reset to their identities. */
		if (rows[i].act == DTRACEAGG_MIN || rows[i].act == DTRACEAGG_MAX) {
			rows[i].metric = 0;
			snprintf(rows[i].summary, sizeof (rows[i].summary), "0");
		}
		if (rows[i].act == DTRACEAGG_AVG ||
		    rows[i].act == DTRACEAGG_STDDEV)
			snprintf(rows[i].summary, sizeof (rows[i].summary),
			    rows[i].act == DTRACEAGG_AVG ? "0,0" : "0,0,0");
	}
	emit_rows(rows, n, mode, 0);
}

/* A second round of firings, one value per key, merged after a clear. */
static const struct aspec spec_a2[] = {
	{ DTRACEAGG_AVG, { 0 }, { { "k1", 1, { 8 }, { 1 } } } },
	{ DTRACEAGG_STDDEV, { 0 }, { { "k1", 1, { 3 }, { 0 } } } },
	{ DTRACEAGG_QUANTIZE, { 0 }, { { "k1", 1, { 9 }, { 1 } } } },
	{ DTRACEAGG_LQUANTIZE, LQ(0, 2, 5), { { "k1", 2, { 7, 30 },
	    { 0, 1 } } } },
	{ DTRACEAGG_LLQUANTIZE, { 10, 0, 2, 10 }, { { "k1", 2, { 3, 300 },
	    { 1, 0 } } } },
	{ DTRACEAGG_MIN, { 0 }, { { "k1", 1, { -4 }, { 0 } } } },
	{ DTRACEAGG_MAX, { 0 }, { { "k1", 1, { 4 }, { 1 } } } },
};

/*
 * dtrace_aggregate_clear() zeroes every value but must keep each
 * lquantize()/llquantize() parameter word: later snapshots merge into the
 * cleared entries by those parameters, and the printers validate them.
 * After clearing, every row is a value tie (key order); after a second
 * round of firings the cleared k1 rows hold exactly the new values.
 */
static void
clear_api_body(void)
{
	const char *name = "clear-api-keeps-parameters";
	struct session s;
	struct erow rows[MAXROWS];
	char *mid;
	int i, n;

	reset_alt();
	if (aopen(&s, name, NULL, PROG_A, 1) == 0) {
		fire_specs(spec_a, NSPEC(spec_a));
		rfp = s.out;
		if (dtrace_aggregate_snap(s.dtp) != 0)
			fail(name, "snap", "", "");
		dtrace_aggregate_clear(s.dtp);
		if (dtrace_aggregate_walk_valsorted(s.dtp, render_cb,
		    NULL) != 0)
			fail(name, "walk", "", "");
		fflush(s.out);
		xbegin();
		emit_zero_rows(spec_a, NSPEC(spec_a), O_VAL);
		mid = strdup(xend());
		if (strcmp(mid, s.text) != 0)
			fail(name, "cleared", mid, s.text);
		free(mid);
		/* Merge new data into the cleared entries. */
		fire_specs(spec_a2, NSPEC(spec_a2));
		reopen_out(&s);
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_walk_keysorted(s.dtp, render_cb,
		    NULL) != 0)
			fail(name, "walk2", "", "");
		fflush(s.out);
		xbegin();
		n = expected_rows(spec_a2, NSPEC(spec_a2), rows);
		emit_rows(rows, n, O_KEY, 0);
		for (i = 0; i < NSPEC(spec_a); i++) {
			/* k2..k5 stay cleared. */
			(void) i;
		}
		{
			char *want = strdup(xend()), *got = strdup(s.text);
			char *line, *save = NULL, *keep = NULL;
			size_t klen = 0;
			FILE *kf = open_memstream(&keep, &klen);

			/* Keep only the k1 rows of the walk. */
			for (line = strtok_r(got, "\n", &save); line != NULL;
			    line = strtok_r(NULL, "\n", &save))
				if (strstr(line, " k1 ") != NULL)
					fprintf(kf, "%s\n", line);
			fclose(kf);
			if (strcmp(want, keep) != 0)
				fail(name, "merged", want, keep);
			free(want);
			free(got);
			free(keep);
		}
		if (dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "print", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		/* The CLEAR walk result without per-CPU copies. */
		reopen_out(&s);
		if (dtrace_aggregate_walk(s.dtp, clear_cb, NULL) != 0 ||
		    dtrace_aggregate_walk_valsorted(s.dtp, render_cb,
		    NULL) != 0)
			fail(name, "clear-walk", "", "");
		fflush(s.out);
		xbegin();
		emit_zero_rows(spec_a, NSPEC(spec_a), O_VAL);
		if (strcmp(xend(), s.text) != 0)
			fail(name, "clear-walk", xend(), s.text);
		else if (failures == 0)
			pass(name);
	}
	close_session(&s);
}


/*
 * The CLEAR walk result (D clear()) zeroes values but keeps the
 * lquantize() and llquantize() parameter words, so the cleared
 * aggregations still print and still merge new data correctly.
 */
static void
clear_walk_body(void)
{
	const char *name = "clear-walk-keeps-parameters";
	static const char *const opts[] = { "aggpercpu", NULL, NULL };
	struct session s;

	reset_alt();
	if (aopen(&s, name, opts, PROG_A, 1) == 0) {
		fire_specs(spec_a, NSPEC(spec_a));
		rfp = s.out;
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_walk(s.dtp, clear_cb, NULL) != 0)
			fail(name, "clear", "", "");
		if (dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "print-cleared", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		reopen_out(&s);
		if (dtrace_aggregate_walk_valsorted(s.dtp, render_cb,
		    NULL) != 0)
			fail(name, "walk", "", "");
		fflush(s.out);
		xbegin();
		emit_zero_rows(spec_a, NSPEC(spec_a), O_VAL);
		if (strcmp(xend(), s.text) != 0)
			fail(name, "cleared", xend(), s.text);
		fire_specs(spec_a2, NSPEC(spec_a2));
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "print-merged", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		else if (failures == 0)
			pass(name);
	}
	close_session(&s);
}

static void
case_clear(void)
{
	in_child("clear-api-keeps-parameters", clear_api_body);
	in_child("clear-walk-keeps-parameters", clear_walk_body);
}

/* ------------------------------------------------------------------ */
/* dtrace_aggregate_walk_joined().                                     */

static const struct aspec spec_j[] = {
	{ DTRACEAGG_COUNT, { 0 }, {
	    { "k1", 2, { 0, 0 }, { 0, 1 } },
	    { "k2", 1, { 0 }, { 1 } },
	    { "k3", 2, { 0, 0 }, { 1, 1 } } } },
	{ DTRACEAGG_SUM, { 0 }, {
	    { "k1", 1, { 9 }, { 0 } },
	    { "k2", 2, { 1, 2 }, { 0, 1 } } } },
	{ DTRACEAGG_LQUANTIZE, LQ(0, 2, 5), {
	    { "k2", 1, { 3 }, { 1 } } } },
	{ DTRACEAGG_LLQUANTIZE, { 10, 0, 2, 10 }, {
	    { "k3", 1, { 40 }, { 0 } } } },
	{ DTRACEAGG_LQUANTIZE, LQ(0, 1, 4), { { NULL, 0, { 0 }, { 0 } } } },
	{ DTRACEAGG_LLQUANTIZE, { 10, 0, 1, 10 },
	    { { NULL, 0, { 0 }, { 0 } } } },
};

#define	PROG_J	"test:::entry { @a[probefunc] = count(); " \
	"@b[probefunc] = sum(arg0); @l[probefunc] = lquantize(arg0, 0, 10, 2); " \
	"@ll[probefunc] = llquantize(arg0, 10, 0, 2, 10); " \
	"@z[probefunc] = lquantize(arg0, 0, 4, 1); " \
	"@zz[probefunc] = llquantize(arg0, 10, 0, 1, 10); }"

static int joined_rval;

static int
joined_cb(const dtrace_aggdata_t **data, const int ndata, void *arg)
{
	int i;

	(void) arg;
	render_key(rfp, data[0]);
	for (i = 1; i < ndata; i++) {
		fprintf(rfp, " | %lld:",
		    (long long)data[i]->dtada_desc->dtagd_varid);
		render_val(rfp, data[i]);
	}
	fputc('\n', rfp);
	return (joined_rval);
}

struct jrow {
	const char *key;
	struct erow col[8];
};

static int jn, jsortpos, jkeysort;

static int
jcmp(const void *l, const void *r)
{
	const struct jrow *a = l, *b = r;
	int i, c;

	if (jkeysort && (c = strcmp(a->key, b->key)) != 0)
		return (c);
	for (i = 0; i < jn; i++) {
		const struct erow *x = &a->col[(i + jsortpos) % jn];
		const struct erow *y = &b->col[(i + jsortpos) % jn];

		if (x->metric != y->metric)
			return (x->metric < y->metric ? -1 : 1);
		if (x->zero != y->zero)
			return (x->zero < y->zero ? -1 : 1);
	}
	return (strcmp(a->key, b->key));
}

/*
 * Expected joined walk: one row per key present in any requested
 * aggregation; a requested variable without a value for that key shows its
 * zero value (an lquantize()/llquantize() zero keeps its parameters).  Rows
 * sort by the column at aggsortpos (or 0 when out of range), then the
 * following columns cyclically, then the key; aggsortkey sorts by key and
 * aggsortrev reverses.  A variable that names no aggregation at all is
 * shown in the format of the first column, in sort order, that has data.
 */
static void
joined_expect(const struct aspec *spec, int nspec, const int *vars, int n,
    int sortpos, int keysort, int rev)
{
	struct jrow rows[16];
	const char *keys[16];
	int nkeys = 0, i, j, k, fmtvar = 0;

	for (i = 0; i < n; i++) {
		int v = vars[(i + sortpos) % n];

		if (v <= nspec && spec[v - 1].d[0].key != NULL) {
			fmtvar = v;
			break;
		}
	}
	for (i = 0; i < n; i++) {
		if (vars[i] > nspec)
			continue;
		for (j = 0; j < 5 && spec[vars[i] - 1].d[j].key; j++) {
			const char *key = spec[vars[i] - 1].d[j].key;

			for (k = 0; k < nkeys && strcmp(keys[k], key); k++)
				continue;
			if (k == nkeys)
				keys[nkeys++] = key;
		}
	}
	for (k = 0; k < nkeys; k++) {
		rows[k].key = keys[k];
		for (i = 0; i < n; i++) {
			int v = vars[i] <= nspec ? vars[i] : fmtvar;
			const struct aspec *a = &spec[v - 1];
			struct kv none = { keys[k], 0, { 0 }, { 0 } };
			const struct kv *d = &none;

			for (j = 0; j < 5 && a->d[j].key != NULL &&
			    vars[i] <= nspec; j++)
				if (strcmp(a->d[j].key, keys[k]) == 0)
					d = &a->d[j];
			summarize(a, d, &rows[k].col[i]);
			rows[k].col[i].varid = v;
		}
	}
	jn = n;
	jsortpos = sortpos < n ? sortpos : 0;
	jkeysort = keysort;
	qsort(rows, nkeys, sizeof (rows[0]), jcmp);
	for (k = 0; k < nkeys; k++) {
		struct jrow *r = &rows[rev ? nkeys - 1 - k : k];

		X(" %s", r->key);
		for (i = 0; i < n; i++)
			X(" | %d:%s", r->col[i].varid, r->col[i].summary);
		X("\n");
	}
}

static void
case_joined(void)
{
	static const struct {
		const char *name;
		int vars[4], n;
		const char *opts[5];
		int sortpos, keysort, rev, anon;
	} c[] = {
		{ "joined-count-sum", { 1, 2 }, 2, { NULL }, 0, 0, 0, 0 },
		{ "joined-sortpos", { 1, 2 }, 2, { "aggsortpos", "1", NULL },
		    1, 0, 0, 0 },
		{ "joined-sortpos-range", { 1, 2 }, 2, { "aggsortpos", "5",
		    NULL }, 0, 0, 0, 0 },
		{ "joined-rev", { 2, 1 }, 2, { "aggsortrev", NULL, NULL },
		    0, 0, 1, 0 },
		{ "joined-key", { 2, 1 }, 2, { "aggsortkey", NULL, NULL },
		    0, 1, 0, 0 },
		{ "joined-key-rev", { 1, 2 }, 2, { "aggsortkey", NULL,
		    "aggsortrev", NULL, NULL }, 0, 1, 1, 0 },
		{ "joined-duplicate", { 1, 2, 1 }, 3, { NULL }, 0, 0, 0, 0 },
		{ "joined-duplicate-sortpos", { 2, 1, 2 }, 3, { "aggsortpos",
		    "2", NULL }, 2, 0, 0, 0 },
		{ "joined-histogram-zero", { 3, 4 }, 2, { NULL }, 0, 0, 0, 0 },
		{ "joined-never-fired", { 2, 5, 6 }, 3, { NULL }, 0, 0, 0, 0 },
		{ "joined-subset", { 2 }, 1, { NULL }, 0, 0, 0, 0 },
		{ "joined-unknown-var", { 1, 50 }, 2, { NULL }, 0, 0, 0, 0 },
		{ "joined-unknown-first", { 50, 1 }, 2, { NULL }, 0, 0, 0, 0 },
		{ "joined-triplicate", { 2, 2, 2 }, 3, { NULL }, 0, 0, 0, 0 },
		{ "joined-anon", { 2, 1 }, 2, { NULL }, 0, 0, 0, 1 },
		{ "joined-anon-never-fired", { 2, 5 }, 2, { NULL }, 0, 0, 0,
		    1 },
	};
	size_t i;

	for (i = 0; i < sizeof (c) / sizeof (c[0]); i++) {
		struct session s;
		dtrace_aggvarid_t vars[4];
		int j;

		reset_alt();
		alt_uarg0 = c[i].anon;
		if (aopen(&s, c[i].name, c[i].opts, PROG_J, 1) == 0) {
			fire_specs(spec_j, NSPEC(spec_j));
			rfp = s.out;
			joined_rval = 0;
			for (j = 0; j < c[i].n; j++)
				vars[j] = c[i].vars[j];
			if (dtrace_aggregate_snap(s.dtp) != 0 ||
			    dtrace_aggregate_walk_joined(s.dtp, vars, c[i].n,
			    joined_cb, NULL) != 0)
				fail(c[i].name, "walk", "", dtrace_errmsg(s.dtp,
				    dtrace_errno(s.dtp)));
			fflush(s.out);
			xbegin();
			if (c[i].anon && c[i].vars[1] == 5) {
				/*
				 * An anonymous enabling cannot name a variable
				 * that never fired: its zero takes the format
				 * of the first column with data (@b).
				 */
				int v[2] = { 2, 99 };

				joined_expect(spec_j, NSPEC(spec_j), v, 2, 0,
				    0, 0);
			} else {
				joined_expect(spec_j, NSPEC(spec_j), c[i].vars,
				    c[i].n, c[i].sortpos, c[i].keysort,
				    c[i].rev);
			}
			expect_text(c[i].name, "joined", s.text);
		}
		close_session(&s);
	}
}

/*
 * Invalid variable lists, a variable list with no data, and a callback
 * failure.
 */
static void
case_joined_errors(void)
{
	const char *name = "joined-errors";
	struct session s;
	dtrace_aggvarid_t zero[] = { 1, 0 }, neg[] = { -3 }, none[] = { 5, 6 };
	dtrace_aggvarid_t ok[] = { 1, 2 };
	int rc;

	reset_alt();
	if (aopen(&s, name, NULL, PROG_J, 1) == 0) {
		fire_specs(spec_j, NSPEC(spec_j));
		rfp = s.out;
		joined_rval = 0;
		if (dtrace_aggregate_snap(s.dtp) != 0)
			fail(name, "snap", "", "");
		rc = dtrace_aggregate_walk_joined(s.dtp, zero, 2, joined_cb,
		    NULL);
		if (!is_err(&s, rc, MSG_BADAGGVAR))
			fail(name, "aggvar 0", "EDT_BADAGGVAR\n", "");
		rc = dtrace_aggregate_walk_joined(s.dtp, neg, 1, joined_cb,
		    NULL);
		if (!is_err(&s, rc, MSG_BADAGGVAR))
			fail(name, "aggvar -3", "EDT_BADAGGVAR\n", "");
		if (dtrace_aggregate_walk_joined(s.dtp, none, 2, joined_cb,
		    NULL) != 0)
			fail(name, "no data", "0\n", "");
		joined_rval = -1;
		rc = dtrace_aggregate_walk_joined(s.dtp, ok, 2, joined_cb,
		    NULL);
		fflush(s.out);
		if (rc != -1)
			fail(name, "callback -1", "-1\n", "");
		/* Only the first bundle was delivered: 1 line. */
		else if (strchr(s.text, '\n') == NULL ||
		    strchr(s.text, '\n')[1] != '\0')
			fail(name, "one bundle", "1 line\n", s.text);
		else
			pass(name);
	}
	close_session(&s);
}

/* ------------------------------------------------------------------ */
/* aggpercpu: per-CPU copies, their merges, clears and removal.        */

#define	PROG_P	"test:::entry { @s[probefunc] = sum(arg0); " \
	"@l[probefunc] = lquantize(arg0, 0, 10, 2); " \
	"@ll[probefunc] = llquantize(arg0, 10, 0, 2, 10); }"

static const struct aspec spec_p[] = {
	{ DTRACEAGG_SUM, { 0 }, {
	    { "k1", 3, { 5, 7, 11 }, { 0, 1, 2 } },
	    { "k2", 1, { 2 }, { 1 } } } },
	{ DTRACEAGG_LQUANTIZE, LQ(0, 2, 5), {
	    { "k1", 3, { 1, 9, 30 }, { 0, 1, 2 } },
	    { "k2", 1, { 4 }, { 1 } } } },
	{ DTRACEAGG_LLQUANTIZE, { 10, 0, 2, 10 }, {
	    { "k1", 3, { 2, 70, 700 }, { 0, 1, 2 } },
	    { "k2", 1, { 3 }, { 1 } } } },
};

static int pcpu_n;

static int
percpu_cb(const dtrace_aggdata_t *a, void *arg)
{
	dtrace_aggdesc_t *d = a->dtada_desc;
	dtrace_recdesc_t *rec = &d->dtagd_rec[d->dtagd_nrecs - 1];
	int i;

	(void) arg;
	fprintf(rfp, "%lld", (long long)d->dtagd_varid);
	render_key(rfp, a);
	for (i = 0; i < pcpu_n; i++) {
		fprintf(rfp, " | ");
		if (a->dtada_percpu == NULL)
			fprintf(rfp, "none");
		else
			render_raw(rfp, rec,
			    (const int64_t *)a->dtada_percpu[i]);
	}
	fputc('\n', rfp);
	return (walk_rval);
}

/* Per CPU (three CPUs shown): each CPU's own values, same parameters. */
static void
percpu_expect(const struct aspec *spec, int nspec, int cleared,
    const char *skipkey)
{
	struct erow r;
	int i, j, k, c;

	for (i = 0; i < nspec; i++) {
		for (j = 0; j < 5 && spec[i].d[j].key != NULL; j++) {
			const struct kv *d = &spec[i].d[j];

			if (skipkey != NULL && strcmp(d->key, skipkey) == 0 &&
			    i == 0)
				continue;
			X("%d %s", i + 1, d->key);
			for (c = 0; c < pcpu_n; c++) {
				struct kv one = { d->key, 0, { 0 }, { 0 } };

				for (k = 0; k < d->n && !cleared; k++)
					if (d->cpu[k] == c)
						one.v[one.n++] = d->v[k];
				summarize(&spec[i], &one, &r);
				X(" | %s", r.summary);
			}
			X("\n");
		}
	}
}

static int
remove_k1_sum(const dtrace_aggdata_t *a, void *arg)
{
	dtrace_aggdesc_t *d = a->dtada_desc;

	(void) arg;
	if (d->dtagd_varid == 1 && strcmp(a->dtada_data +
	    d->dtagd_rec[1].dtrd_offset, "k1") == 0)
		return (DTRACE_AGGWALK_REMOVE);
	return (DTRACE_AGGWALK_NEXT);
}

static void
percpu_body(void)
{
	const char *name = "percpu-copies";
	static const char *const opts[] = { "aggpercpu", NULL, NULL };
	struct session s;

	reset_alt();
	pcpu_n = 3;
	if (aopen(&s, name, opts, PROG_P, 1) == 0) {
		/* Two snapshots: the second merges into existing entries. */
		fire_specs(spec_p, NSPEC(spec_p));
		rfp = s.out;
		walk_rval = DTRACE_AGGWALK_NEXT;
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_walk_keysorted(s.dtp, percpu_cb,
		    NULL) != 0)
			fail(name, "walk", "", "");
		fflush(s.out);
		xbegin();
		percpu_expect(spec_p, NSPEC(spec_p), 0, NULL);
		if (strcmp(xend(), s.text) != 0)
			fail(name, "percpu", xend(), s.text);
		/* CLEAR from a walk zeroes every per-CPU copy too. */
		reopen_out(&s);
		if (dtrace_aggregate_walk(s.dtp, clear_cb, NULL) != 0 ||
		    dtrace_aggregate_walk_keysorted(s.dtp, percpu_cb,
		    NULL) != 0)
			fail(name, "clear", "", "");
		fflush(s.out);
		xbegin();
		percpu_expect(spec_p, NSPEC(spec_p), 1, NULL);
		if (strcmp(xend(), s.text) != 0)
			fail(name, "cleared", xend(), s.text);
		/* New data merges per CPU again; then the clear API. */
		fire_specs(spec_p, NSPEC(spec_p));
		reopen_out(&s);
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_walk_keysorted(s.dtp, percpu_cb,
		    NULL) != 0)
			fail(name, "walk2", "", "");
		fflush(s.out);
		xbegin();
		percpu_expect(spec_p, NSPEC(spec_p), 0, NULL);
		if (strcmp(xend(), s.text) != 0)
			fail(name, "remerged", xend(), s.text);
		dtrace_aggregate_clear(s.dtp);
		/* REMOVE drops the entry and its per-CPU copies. */
		reopen_out(&s);
		if (dtrace_aggregate_walk(s.dtp, remove_k1_sum, NULL) != 0 ||
		    dtrace_aggregate_walk_keysorted(s.dtp, percpu_cb,
		    NULL) != 0)
			fail(name, "remove", "", "");
		fflush(s.out);
		xbegin();
		percpu_expect(spec_p, NSPEC(spec_p), 1, "k1");
		if (strcmp(xend(), s.text) != 0)
			fail(name, "removed", xend(), s.text);
		else if (failures == 0)
			pass(name);
	}
	close_session(&s);
}

static void
case_percpu(void)
{
	in_child("percpu-copies", percpu_body);
}

/* ------------------------------------------------------------------ */
/* Snapshot paths: activity, aggrate, CPU selection, faults, drops.    */

#define	PROG_C	"test:::entry { @c[arg0] = count(); }"

static void
fire_c(int cpu, int64_t key)
{
	fire(cpu, "test:kernel:alpha:entry", 0, VALS(N(1), N(key), AGG(0, 1)));
}

/* Walk @c in key order into a fresh stream and compare. */
static void
expect_counts(const char *name, struct session *s, const char *want)
{
	reopen_out(s);
	walk_rval = DTRACE_AGGWALK_NEXT;
	if (dtrace_aggregate_walk_keysorted(s->dtp, render_cb, NULL) != 0)
		fail(name, "walk", "", "");
	fflush(s->out);
	if (strcmp(want, s->text) != 0)
		fail(name, "counts", want, s->text);
	else
		pass(name);
}

static void
case_snap_paths(void)
{
	struct session s;
	const char *name;
	unsigned before;
	int rc;

	/* Not running: EINVAL. */
	name = "snap-inactive";
	reset_alt();
	if (aopen(&s, name, NULL, PROG_C, 0) == 0) {
		rc = dtrace_aggregate_snap(s.dtp);
		expect_true(name, rc == -1 && dtrace_errno(s.dtp) == EINVAL &&
		    M.aggsnaps == 0, "EINVAL without AGGSNAP");
	}
	close_session(&s);

	/* aggrate=1h: a second snapshot within the interval is skipped. */
	name = "snap-aggrate-skip";
	{
		static const char *const o[] = { "aggrate", "1h", NULL };

		reset_alt();
		if (aopen(&s, name, o, PROG_C, 1) == 0) {
			fire_c(0, 5);
			rc = dtrace_aggregate_snap(s.dtp);
			before = M.aggsnaps;
			fire_c(1, 5);
			rc |= dtrace_aggregate_snap(s.dtp);
			if (rc != 0 || before != (unsigned)M.ncpu ||
			    M.aggsnaps != before)
				fail(name, "aggsnaps", "one round\n", "");
			else
				expect_counts(name, &s, "1 5 1\n");
		}
		close_session(&s);
	}

	/* aggrate=1ns: every snapshot is due; both firings merge. */
	name = "snap-aggrate-due";
	{
		static const char *const o[] = { "aggrate", "1ns", NULL };

		reset_alt();
		if (aopen(&s, name, o, PROG_C, 1) == 0) {
			fire_c(0, 5);
			rc = dtrace_aggregate_snap(s.dtp);
			fire_c(1, 5);
			usleep(1000);
			rc |= dtrace_aggregate_snap(s.dtp);
			if (rc != 0 || M.aggsnaps != 2 * (unsigned)M.ncpu)
				fail(name, "aggsnaps", "two rounds\n", "");
			else
				expect_counts(name, &s, "1 5 2\n");
		}
		close_session(&s);
	}

	/* No aggregations: aggsize is zero and nothing is snapped. */
	name = "snap-no-aggregations";
	reset_alt();
	if (aopen(&s, name, NULL, TRACE_PROG, 1) == 0) {
		rc = dtrace_aggregate_snap(s.dtp);
		expect_true(name, rc == 0 && M.aggsnaps == 0,
		    "no AGGSNAP without aggregations");
	}
	close_session(&s);

	/* An unset aggsize reloaded from the kernel also disables snaps. */
	name = "snap-aggsize-unset";
	reset_alt();
	alt_aggsize_unset = 1;
	if (aopen(&s, name, NULL, PROG_C, 1) == 0) {
		fire_c(0, 1);
		rc = dtrace_aggregate_snap(s.dtp);
		expect_true(name, rc == 0 && M.aggsnaps == 0,
		    "no AGGSNAP with unset aggsize");
	}
	close_session(&s);

	/* cpu=1: only that CPU's aggregation buffer is read. */
	name = "snap-cpu-option";
	{
		static const char *const o[] = { "cpu", "1", NULL };

		reset_alt();
		if (aopen(&s, name, o, PROG_C, 1) == 0) {
			fire_c(0, 7);
			fire_c(1, 8);
			fire_c(1, 8);
			if (dtrace_aggregate_snap(s.dtp) != 0 ||
			    M.aggsnaps != 1)
				fail(name, "aggsnaps", "1\n", "");
			else
				expect_counts(name, &s, "1 8 2\n");
		}
		close_session(&s);
	}

	/* A CPU reported absent by dtv_status is skipped. */
	name = "snap-cpu-absent";
	reset_alt();
	alt_status_down = 1;
	if (aopen(&s, name, NULL, PROG_C, 1) == 0) {
		fire_c(0, 7);
		fire_c(1, 8);
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    M.aggsnaps != (unsigned)M.ncpu - 1)
			fail(name, "aggsnaps", "ncpu - 1\n", "");
		else
			expect_counts(name, &s, "1 7 1\n");
	}
	close_session(&s);

	/* ENOENT from AGGSNAP (CPU unconfigured) is not an error. */
	name = "snap-enoent";
	reset_alt();
	if (aopen(&s, name, NULL, PROG_C, 1) == 0) {
		fire_c(0, 7);
		fire_c(1, 8);
		M.fail_cmd = CMD(DTRACEIOC_AGGSNAP);
		M.fail_errno = ENOENT;
		M.fail_after = 0;
		if (dtrace_aggregate_snap(s.dtp) != 0)
			fail(name, "snap", "0\n", "");
		else
			expect_counts(name, &s, "1 8 1\n");
	}
	close_session(&s);

	/* Any other AGGSNAP error fails the snapshot with that errno. */
	name = "snap-eio";
	reset_alt();
	if (aopen(&s, name, NULL, PROG_C, 1) == 0) {
		fire_c(0, 7);
		M.fail_cmd = CMD(DTRACEIOC_AGGSNAP);
		M.fail_errno = EIO;
		M.fail_after = 0;
		rc = dtrace_aggregate_snap(s.dtp);
		expect_true(name, rc == -1 && dtrace_errno(s.dtp) == EIO,
		    "EIO");
	}
	close_session(&s);

	/* An AGGDESC failure while resolving a record's ID. */
	name = "snap-aggdesc-error";
	reset_alt();
	if (aopen(&s, name, NULL, PROG_C, 1) == 0) {
		fire_c(0, 7);
		M.fail_cmd = CMD(DTRACEIOC_AGGDESC);
		M.fail_errno = EIO;
		M.fail_after = 0;
		rc = dtrace_aggregate_snap(s.dtp);
		expect_true(name, rc == -1 && dtrace_errno(s.dtp) == EIO,
		    "EIO");
	}
	close_session(&s);

	/* A value record whose action is not an aggregating action. */
	name = "snap-unknown-action";
	reset_alt();
	alt_badact = 1;
	if (aopen(&s, name, NULL, PROG_C, 1) == 0) {
		fire_c(0, 7);
		rc = dtrace_aggregate_snap(s.dtp);
		expect_true(name, is_err(&s, rc, MSG_BADAGG), "EDT_BADAGG");
	}
	close_session(&s);

	/*
	 * DTRACE_AGGIDNONE words are alignment filler and are skipped.  Two
	 * are prepended to CPU 0's buffer, keeping 8-byte record alignment.
	 */
	name = "snap-filler";
	reset_alt();
	if (aopen(&s, name, NULL, PROG_C, 1) == 0) {
		struct mbuf *b = &M.aggbuf[0];

		fire_c(0, 7);
		fire_c(0, 9);
		assert(b->offset + 8 <= b->size);
		memmove(b->data + 8, b->data, b->offset);
		memset(b->data, 0, 8);
		b->offset += 8;
		if (dtrace_aggregate_snap(s.dtp) != 0)
			fail(name, "snap", "0\n", "");
		else
			expect_counts(name, &s, "1 7 1\n1 9 1\n");
	}
	close_session(&s);
}

/*
 * Aggregation buffer drops are reported per CPU through the drop handler
 * (kind DTRACEDROP_AGGREGATION, with the kernel's count); a handler that
 * asks to abort fails the snapshot with EDT_DROPABORT.  The structured
 * output variant emits a DROP probe instance.
 */
/*
 * Open PROG_C without starting it, then size the aggregation buffer to hold
 * exactly two entries of the kernel layout (the model's dtrace_aggregate()
 * record size) before dtrace_go().
 */
static int
open_two_entries(struct session *s, const char *name)
{
	struct mact *a;
	char size[32];

	if (aopen(s, name, NULL, PROG_C, 0) != 0)
		return (-1);
	a = &M.set[M.agg[0].set].act[M.agg[0].act];
	snprintf(size, sizeof (size), "%u",
	    2 * (a->rec.dtrd_offset + a->rec.dtrd_size - a->base));
	if (dtrace_setopt(s->dtp, "aggsize", size) != 0 ||
	    dtrace_go(s->dtp) != 0) {
		fail(name, "go", "", "");
		return (-1);
	}
	return (0);
}

static void
case_snap_drops(void)
{
	struct session s;
	const char *name;
	int rc, i;

	name = "snap-drops";
	reset_alt();
	if (open_two_entries(&s, name) == 0) {
		/* Two entries fit; the other three firings are dropped. */
		for (i = 0; i < 5; i++)
			fire_c(0, i);
		rc = dtrace_aggregate_snap(s.dtp);
		if (rc != 0 || ndrops != 1 || dropcount != 3)
			fail(name, "drops", "1 report of 3\n", "");
		else
			expect_counts(name, &s, "1 0 1\n1 1 1\n");
	}
	close_session(&s);

	name = "snap-drops-abort";
	reset_alt();
	drop_abort = 1;
	if (open_two_entries(&s, name) == 0) {
		for (i = 0; i < 5; i++)
			fire_c(0, i);
		rc = dtrace_aggregate_snap(s.dtp);
		expect_true(name, is_err(&s, rc, MSG_DROPABORT) &&
		    ndrops == 1, "EDT_DROPABORT");
	}
	close_session(&s);

	name = "snap-drops-oformat";
	{
		FILE *json = fopen("agg-drops.json", "w");
		char line[4096];
		size_t n;

		assert(json != NULL);
		reset_alt();
		xo_set_style(NULL, XO_STYLE_JSON);
		dtrace_set_outfp(json);
		if (open_two_entries(&s, name) == 0) {
			if (dtrace_oformat_configure(s.dtp) != 0)
				fail(name, "configure", "", "");
			dtrace_oformat_setup(s.dtp);
			for (i = 0; i < 5; i++)
				fire_c(0, i);
			drop_abort = 1;
			rc = dtrace_aggregate_snap(s.dtp);
			dtrace_oformat_teardown(s.dtp);
			if (!is_err(&s, rc, MSG_DROPABORT))
				fail(name, "abort", "EDT_DROPABORT\n", "");
		}
		close_session(&s);
		xo_set_style(NULL, XO_STYLE_TEXT);
		dtrace_set_outfp(stdout);
		fclose(json);
		json = fopen("agg-drops.json", "r");
		n = fread(line, 1, sizeof (line) - 1, json);
		line[n] = '\0';
		fclose(json);
		expect_true(name, strstr(line, "\"name\":\"DROP\"") != NULL &&
		    strstr(line, "aggregation drops on CPU 0") != NULL,
		    "DROP instance with the drop message");
	}
}

/* ------------------------------------------------------------------ */
/* Hash chains and REMOVE unlinking.                                   */

/*
 * The consumer hashes an entry by the byte sum of its key records (the
 * variable ID record included) modulo DTRACE_AHASHSIZE (32779).  @a[1]
 * (varid 1) and @b[0] (varid 2) both sum to 2 but have different record
 * sizes; @s["ab"] and @s["ba"] have equal sums and sizes but different
 * bytes; @s[""] and @s[X], X being 258 0x7f bytes and one 0x0d byte, sum
 * to 3 and 3 + 32779 and so share a bucket with different hash values.
 * Every entry must stay distinct.  String keys compare as unsigned bytes,
 * so the 0x7f key sorts after "ba".
 */
#define	PROG_H	"test:::entry { @a[arg0] = count(); " \
	"@b[arg0] = quantize(arg0); @s[probefunc] = count(); }"

static char longkey[300];

static void
fire_h(const char *what, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		if (strcmp(what, "a1") == 0)
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), N(1),
			    AGG(0, 1), N(2), N(1), SKIP, N(3), S(""), SKIP));
		else if (strcmp(what, "b0") == 0)
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), N(0),
			    SKIP, N(2), N(0), AGG(0, 1), N(3), S(""), SKIP));
		else {
			struct val k = { what, strlen(what) + 1, 0, 1 };

			if (strcmp(what, "long") == 0) {
				k.bytes = longkey;
				k.len = strlen(longkey) + 1;
			} else if (strcmp(what, "empty") == 0) {
				k.bytes = "";
				k.len = 1;
			}
			fire(0, "test:kernel:alpha:entry", 0,
			    (const struct val[]){ N(1), N(0), SKIP, N(2), N(0),
			    SKIP, N(3), k, AGG(0, 1) }, 9);
		}
	}
}

static const char *remove_what;

static int
remove_cb(const dtrace_aggdata_t *a, void *arg)
{
	dtrace_aggdesc_t *d = a->dtada_desc;
	int64_t key = *(int64_t *)(a->dtada_data + d->dtagd_rec[1].dtrd_offset);

	(void) arg;
	if (strcmp(remove_what, "a1") == 0 && d->dtagd_varid == 1 && key == 1)
		return (DTRACE_AGGWALK_REMOVE);
	if (strcmp(remove_what, "b0") == 0 && d->dtagd_varid == 2 && key == 0)
		return (DTRACE_AGGWALK_REMOVE);
	return (DTRACE_AGGWALK_NEXT);
}

/* @s rows render their 513-byte keys; keep them short in the expectation. */
static int
hash_cb(const dtrace_aggdata_t *a, void *arg)
{
	dtrace_aggdesc_t *d = a->dtada_desc;
	const char *k = a->dtada_data + d->dtagd_rec[1].dtrd_offset;

	if (d->dtagd_varid == 3) {
		fprintf(rfp, "3 %s ", k == NULL ? "" : *k == '\0' ? "(empty)" :
		    strlen(k) > 8 ? "(long)" : k);
		render_val(rfp, a);
		fputc('\n', rfp);
		return (DTRACE_AGGWALK_NEXT);
	}
	return (render_cb(a, arg));
}

static void
case_hash_chains(void)
{
	static const char *const o[] = { "strsize", "512", NULL };
	static const struct {
		const char *name, *remove;
		const char *want;
	} c[] = {
		{ "hash-distinct-entries", "", "1 1 3\n2 0 63:2 \n"
		    "3 (empty) 1\n3 ab 1\n3 ba 4\n3 (long) 2\n" },
		/* @a[1] was inserted first: a chain tail with a predecessor. */
		{ "hash-remove-chain-tail", "a1", "2 0 63:2 \n"
		    "3 (empty) 1\n3 ab 1\n3 ba 4\n3 (long) 2\n" },
		/* @b[0] heads its chain and has a successor. */
		{ "hash-remove-chain-head", "b0", "1 1 3\n"
		    "3 (empty) 1\n3 ab 1\n3 ba 4\n3 (long) 2\n" },
	};
	size_t i;

	memset(longkey, 0x7f, 258);
	longkey[258] = 0x0d;
	longkey[259] = '\0';
	for (i = 0; i < sizeof (c) / sizeof (c[0]); i++) {
		struct session s;

		reset_alt();
		if (aopen(&s, c[i].name, o, PROG_H, 1) == 0) {
			fire_h("ab", 1);
			fire_h("ba", 4);
			fire_h("empty", 1);
			fire_h("long", 2);
			fire_h("a1", 3);
			fire_h("b0", 2);
			remove_what = c[i].remove;
			rfp = s.out;
			if (dtrace_aggregate_snap(s.dtp) != 0 ||
			    dtrace_aggregate_walk(s.dtp, remove_cb, NULL) != 0 ||
			    dtrace_aggregate_walk_keysorted(s.dtp, hash_cb,
			    NULL) != 0)
				fail(c[i].name, "walk", "", "");
			fflush(s.out);
			xbegin();
			X("%s", c[i].want);
			expect_text(c[i].name, "entries", s.text);
		}
		close_session(&s);
	}
}

/* ------------------------------------------------------------------ */
/* Walk callback results.                                              */

static int rval_mode;

static int
rval_cb(const dtrace_aggdata_t *a, void *arg)
{
	dtrace_aggdata_t *w = (dtrace_aggdata_t *)(uintptr_t)a;

	(void) arg;
	switch (rval_mode) {
	case 0:
		errno = ENOSPC;
		return (DTRACE_AGGWALK_ERROR);
	case 1:
		return (DTRACE_AGGWALK_ABORT);
	case 2:
		w->dtada_normal = 7;
		return (DTRACE_AGGWALK_DENORMALIZE);
	case 3:
		/* As dt_consume's normalize() leaves it, with a zero. */
		w->dtada_normal = 0;
		return (DTRACE_AGGWALK_NORMALIZE);
	case 4:
		w->dtada_normal = 4;
		return (DTRACE_AGGWALK_NORMALIZE);
	default:
		return (42);
	}
}

static int
normal_cb(const dtrace_aggdata_t *a, void *arg)
{
	fprintf(rfp, "%lld\n", (long long)a->dtada_normal);
	(void) arg;
	return (DTRACE_AGGWALK_NEXT);
}

static void
case_walk_rvals(void)
{
	static const struct {
		const char *name, *msg, *normals;
		int mode, rc, sorted, eno;
	} c[] = {
		{ "rval-error", NULL, NULL, 0, -1, 0, ENOSPC },
		{ "rval-abort", "Abort explicitly directed", NULL, 1, -1, 0, 0 },
		{ "rval-abort-sorted", "Abort explicitly directed", NULL, 1, -1,
		    1, 0 },
		{ "rval-denormalize", NULL, "1\n1\n", 2, 0, 0, 0 },
		{ "rval-normalize-zero", MSG_BADRVAL, "1\n1\n", 3, -1, 0, 0 },
		{ "rval-normalize", NULL, "4\n4\n", 4, 0, 1, 0 },
		{ "rval-invalid", MSG_BADRVAL, NULL, 5, -1, 0, 0 },
	};
	size_t i;

	for (i = 0; i < sizeof (c) / sizeof (c[0]); i++) {
		struct session s;
		int rc, ok;

		reset_alt();
		if (aopen(&s, c[i].name, NULL, PROG_C, 1) == 0) {
			fire_c(0, 1);
			fire_c(0, 2);
			rval_mode = c[i].mode;
			rfp = s.out;
			if (dtrace_aggregate_snap(s.dtp) != 0)
				fail(c[i].name, "snap", "", "");
			rc = c[i].sorted ?
			    dtrace_aggregate_walk_keysorted(s.dtp, rval_cb,
			    NULL) : dtrace_aggregate_walk(s.dtp, rval_cb, NULL);
			ok = rc == c[i].rc;
			if (ok && c[i].eno != 0)
				ok = dtrace_errno(s.dtp) == c[i].eno;
			if (ok && c[i].msg != NULL)
				ok = strcmp(dtrace_errmsg(s.dtp,
				    dtrace_errno(s.dtp)), c[i].msg) == 0;
			if (ok && c[i].normals != NULL) {
				/*
				 * The normalization reached each entry the
				 * walk visited; a failed NORMALIZE resets
				 * that entry to 1 and stops the walk.
				 */
				if (dtrace_aggregate_walk(s.dtp, normal_cb,
				    NULL) != 0)
					ok = 0;
				fflush(s.out);
				if (ok && strcmp(s.text, c[i].normals) != 0) {
					fail(c[i].name, "normal", c[i].normals,
					    s.text);
					close_session(&s);
					continue;
				}
			}
			expect_true(c[i].name, ok, "walk result");
		}
		close_session(&s);
	}
}

/* ------------------------------------------------------------------ */
/* agghist totals and aggpack bin ranges.                              */

#define	PROG_T	"test:::entry { @s[arg0] = sum(arg1); @c[arg0] = count(); " \
	"@a[arg0] = avg(arg1); @d[arg0] = stddev(arg1); " \
	"@q[arg0] = quantize(arg1); @l[arg0] = lquantize(arg1, 0, 10, 5); " \
	"@m[arg0] = max(arg1); }"

static void
fire_t(int64_t key, int64_t v)
{
	fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), N(key), AGG(v, 1),
	    N(2), N(key), AGG(v, 1), N(3), N(key), AGG(v, 1), N(4), N(key),
	    AGG(v, 1), N(5), N(key), AGG(v, 1), N(6), N(key), AGG(v, 1),
	    N(7), N(key), AGG(v, 1)));
}

static int
flags_cb(const dtrace_aggdata_t *a, void *arg)
{
	dtrace_aggdesc_t *d = a->dtada_desc;

	(void) arg;
	fprintf(rfp, "%lld %lld total=%lld flags=%#x bins=%d..%d\n",
	    (long long)d->dtagd_varid,
	    *(long long *)(a->dtada_data + d->dtagd_rec[1].dtrd_offset),
	    (long long)a->dtada_total, a->dtada_flags & ~DTRACE_A_PERCPU,
	    a->dtada_minbin, a->dtada_maxbin);
	return (DTRACE_AGGWALK_NEXT);
}

/*
 * Firings, in order: key 2 gets -6 and 4, key 3 gets 2, key 1 gets 1.
 * Per variable, agghist's total is the sum of |value| over its entries
 * (sum, count, avg and the stddev of each entry), or with aggzoom the
 * largest |value| / 0.95 truncated; HASPOSITIVES/HASNEGATIVES describe the
 * values; every member carries DTRACE_A_TOTAL.  Other kinds get nothing.
 * aggpack: quantize bins span the nonzero buckets of all entries of the
 * variable (an empty variable uses the zero bucket); lquantize always spans
 * its whole range, bins 1..levels+1.
 */
struct tvals {
	int64_t v[3][2];
	int n[3];
};

static void
totals_expect(int hist, int zoom, int pack, int cleared)
{
	/* Entries by key 1..3. */
	static const struct tvals tv = { { { 1 }, { -6, 4 }, { 2 } },
	    { 1, 2, 1 } };
	int64_t val[5][3];
	int64_t total[5] = { 0 }, k, i;
	int flags[5] = { 0 }, var, key;
	int qmin = 999, qmax = -1;

	for (var = 1; var <= 4; var++) {
		for (key = 0; key < 3; key++) {
			int64_t sum = 0, sq = 0, n = cleared ? 0 : tv.n[key];
			int64_t v;

			for (i = 0; i < n; i++) {
				sum += tv.v[key][i];
				sq += tv.v[key][i] * tv.v[key][i];
			}
			switch (var) {
			case 1:
				v = sum;
				break;
			case 2:
				v = n;
				break;
			case 3:
				v = n ? sum / n : 0;
				break;
			default: {
				int64_t avg = n ? sum / n : 0;

				v = n ? (int64_t)isqrt((uint64_t)(sq / n -
				    avg * avg)) : 0;
			}
			}
			val[var][key] = v;
			if (v > 0)
				flags[var] |= DTRACE_A_HASPOSITIVES;
			if (v < 0)
				flags[var] |= DTRACE_A_HASNEGATIVES;
			k = v < 0 ? -v : v;
			if (zoom) {
				/* Values here are far from rounding edges. */
				k = (int64_t)(k / 0.95);
				if (k > total[var])
					total[var] = k;
			} else {
				total[var] += k;
			}
		}
	}
	for (key = 0; key < 3 && !cleared; key++)
		for (i = 0; i < tv.n[key]; i++) {
			int b = q_idx(tv.v[key][i]);

			qmin = b < qmin ? b : qmin;
			qmax = b > qmax ? b : qmax;
		}
	if (cleared)
		qmin = qmax = ZB;
	for (var = 1; var <= 7; var++) {
		for (key = 1; key <= 3; key++) {
			int64_t t = 0;
			int f = 0, lo = 0, hi = 0;

			if (hist && var <= 4) {
				t = total[var];
				f = DTRACE_A_TOTAL | flags[var];
			}
			if (pack && var == 5) {
				f |= DTRACE_A_MINMAXBIN;
				lo = qmin;
				hi = qmax;
			}
			if (pack && var == 6) {
				f |= DTRACE_A_MINMAXBIN;
				lo = 1;
				hi = 2 + 1;	/* lquantize(.., 0, 10, 5) */
			}
			X("%d %d total=%lld flags=%#x bins=%d..%d\n", var, key,
			    (long long)t, f, lo, hi);
		}
	}
}

static int
strpcmp(const void *a, const void *b)
{
	return (strcmp(*(char *const *)a, *(char *const *)b));
}

/* Sort the lines of a NUL-terminated buffer in place. */
static void
sort_lines(char *text)
{
	char *copy = strdup(text), *lines[256], *p, *save = NULL;
	int n = 0, i;

	for (p = strtok_r(copy, "\n", &save); p != NULL && n < 256;
	    p = strtok_r(NULL, "\n", &save))
		lines[n++] = p;
	qsort(lines, n, sizeof (lines[0]), strpcmp);
	text[0] = '\0';
	for (i = 0; i < n; i++) {
		strcat(text, lines[i]);
		strcat(text, "\n");
	}
	free(copy);
}

static void
case_totals(void)
{
	static const struct {
		const char *name;
		const char *opts[7];
		int hist, zoom, pack;
	} c[] = {
		{ "agghist-totals", { "agghist", NULL, NULL }, 1, 0, 0 },
		{ "aggzoom-totals", { "agghist", NULL, "aggzoom", NULL, NULL },
		    1, 1, 0 },
		{ "aggpack-bins", { "aggpack", NULL, NULL }, 0, 0, 1 },
		{ "agghist-aggpack", { "agghist", NULL, "aggpack", NULL, NULL },
		    1, 0, 1 },
	};
	size_t i;
	int pass2;

	for (i = 0; i < sizeof (c) / sizeof (c[0]); i++) {
		for (pass2 = 0; pass2 < 2; pass2++) {
			struct session s;
			char name[96];

			snprintf(name, sizeof (name), "%s%s", c[i].name,
			    pass2 ? "-cleared" : "");
			reset_alt();
			if (aopen(&s, name, c[i].opts, PROG_T, 1) != 0) {
				close_session(&s);
				continue;
			}
			fire_t(2, -6);
			fire_t(2, 4);
			fire_t(3, 2);
			fire_t(1, 1);
			rfp = s.out;
			if (dtrace_aggregate_snap(s.dtp) != 0)
				fail(name, "snap", "", "");
			if (pass2)
				dtrace_aggregate_clear(s.dtp);
			if (dtrace_aggregate_walk_keysorted(s.dtp, flags_cb,
			    NULL) != 0)
				fail(name, "walk", "", "");
			fflush(s.out);
			xbegin();
			totals_expect(c[i].hist, c[i].zoom, c[i].pack, pass2);
			if (strcmp(xend(), s.text) != 0) {
				fail(name, "totals", xend(), s.text);
				close_session(&s);
				continue;
			}
			/*
			 * Afterwards, totals and bins are reset: an unsorted
			 * walk (which computes neither) sees none of them.
			 */
			reopen_out(&s);
			if (dtrace_aggregate_walk(s.dtp, flags_cb, NULL) != 0)
				fail(name, "walk2", "", "");
			fflush(s.out);
			sort_lines(s.text);
			xbegin();
			totals_expect(0, 0, 0, pass2);
			expect_text(name, "reset", s.text);
			close_session(&s);
		}
	}
}

/* ------------------------------------------------------------------ */
/* Key representations and key positions.                             */

/*
 * Keys compare by record size first, then as unsigned integers of that
 * size (so (char)-1 is 0xff), and 16-byte user address keys (usym, umod,
 * uaddr) by process ID and then address.  keyvarsorted compares keys before
 * variables, so the 1-, 2-, 4- and 8-byte keys of different variables meet.
 */
#define	PROG_K	"test:::entry { @c1[(char)arg0] = count(); " \
	"@c2[(short)arg0] = count(); @c4[(int)arg0] = count(); " \
	"@c8[arg0] = count(); }"

static void
fire_k(int which, int64_t key)
{
	struct val v[12];
	int m;

	for (m = 0; m < 4; m++) {
		struct val id = N(m + 1), k = N(key), a = AGG(0, 1),
		    skip = SKIP;

		v[3 * m] = id;
		v[3 * m + 1] = k;
		v[3 * m + 2] = m == which ? a : skip;
	}
	fire(0, "test:kernel:alpha:entry", 0, v, 12);
}

struct krow {
	int size, varid;
	int64_t key;
};

static int
krow_cmp(const void *l, const void *r)
{
	const struct krow *a = l, *b = r;
	uint64_t mask, x, y;

	if (a->size != b->size)
		return (a->size < b->size ? -1 : 1);
	mask = a->size == 8 ? UINT64_MAX : ((uint64_t)1 << (8 * a->size)) - 1;
	x = (uint64_t)a->key & mask;
	y = (uint64_t)b->key & mask;
	if (x != y)
		return (x < y ? -1 : 1);
	return (a->varid - b->varid);
}

static void
case_key_sizes(void)
{
	const char *name = "keyvar-key-sizes";
	static const int64_t keys[] = { 3, -1, 300, 70000, -70000 };
	struct krow rows[20];
	struct session s;
	int i, j, n = 0, size[] = { 1, 2, 4, 8 };

	reset_alt();
	if (aopen(&s, name, NULL, PROG_K, 1) == 0) {
		for (i = 0; i < 4; i++) {
			for (j = 0; j < 5; j++) {
				uint64_t mask = size[i] == 8 ? UINT64_MAX :
				    ((uint64_t)1 << (8 * size[i])) - 1;
				uint64_t u = (uint64_t)keys[j] & mask;
				int64_t sv;
				int k, dup = 0;

				/* The narrowed key, sign-extended. */
				sv = size[i] == 8 ? (int64_t)u :
				    (u & ((uint64_t)1 << (8 * size[i] - 1))) ?
				    (int64_t)(u | ~mask) : (int64_t)u;
				fire_k(i, keys[j]);
				for (k = 0; k < n; k++)
					if (rows[k].varid == i + 1 &&
					    rows[k].key == sv)
						dup = 1;
				if (!dup) {
					rows[n].size = size[i];
					rows[n].varid = i + 1;
					rows[n++].key = sv;
				}
			}
		}
		rfp = s.out;
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_walk_keyvarsorted(s.dtp, render_cb,
		    NULL) != 0)
			fail(name, "walk", "", "");
		fflush(s.out);
		qsort(rows, n, sizeof (rows[0]), krow_cmp);
		xbegin();
		for (i = 0; i < n; i++) {
			int cnt = 0;

			for (j = 0; j < 5; j++) {
				uint64_t mask = rows[i].size == 8 ?
				    UINT64_MAX : ((uint64_t)1 <<
				    (8 * rows[i].size)) - 1;

				if (((uint64_t)keys[j] & mask) ==
				    ((uint64_t)rows[i].key & mask))
					cnt++;
			}
			X("%d %lld %d\n", rows[i].varid,
			    (long long)rows[i].key, cnt);
		}
		expect_text(name, "order", s.text);
	}
	close_session(&s);
}

#define	PROG_U	"test:::entry { @u[usym(arg0)] = count(); " \
	"@m[umod(arg0)] = count(); @x[uaddr(arg0)] = count(); }"

static void
case_user_keys(void)
{
	const char *name = "user-address-keys";
	static const uint64_t k[][2] = {
		{ 10, 0x2000 }, { 10, 0x1000 }, { 9, 0x3000 }, { 10, 0x1000 },
		{ 9, 0x2fff },
	};
	struct session s;
	size_t i;
	int m;

	reset_alt();
	if (aopen(&s, name, NULL, PROG_U, 1) == 0) {
		for (i = 0; i < sizeof (k) / sizeof (k[0]); i++) {
			struct val v[9];

			for (m = 0; m < 3; m++) {
				struct val id = N(m + 1), key = B(k[i], 16),
				    a = AGG(0, 1);

				v[3 * m] = id;
				v[3 * m + 1] = key;
				v[3 * m + 2] = a;
			}
			fire(i & 1, "test:kernel:alpha:entry", 0, v, 9);
		}
		rfp = s.out;
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_walk_keysorted(s.dtp, render_cb,
		    NULL) != 0)
			fail(name, "walk", "", "");
		fflush(s.out);
		/*
		 * A vectored open does not resolve user symbols, so each
		 * (pid, address) stays its own key: ordered by pid, then
		 * address; the repeated (10, 0x1000) counts twice.
		 */
		xbegin();
		for (m = 1; m <= 3; m++)
			X("%d 9:2fff 1\n%d 9:3000 1\n%d a:1000 2\n"
			    "%d a:2000 1\n", m, m, m, m);
		expect_text(name, "order", s.text);
	}
	close_session(&s);
}

#define	PROG_KP	"test:::entry { @c[arg0, arg1, arg2] = count(); }"

/*
 * aggsortkeypos=p makes key p (0-based) the primary key, the following
 * keys next and the earlier keys last; a position at or past the last key
 * is treated as 0.
 */
static void
case_keypos(void)
{
	static const int64_t t[][3] = {
		{ 1, 2, 3 }, { 2, 1, 3 }, { 3, 3, 1 }, { 1, 3, 2 }, { 2, 2, 2 },
	};
	static const char *pos[] = { "0", "1", "2", "3", "4294967296" };
	size_t i, j, k;
	int order[5], tmp;

	for (i = 0; i < 5; i++) {
		static const char *o[7];
		struct session s;
		char name[64];
		/* Positions 3 (past the last key) and 2^32 act as 0. */
		int p = i == 1 ? 1 : i == 2 ? 2 : 0;

		snprintf(name, sizeof (name), "aggsortkeypos-%s",
		    i == 4 ? "2^32" : pos[i]);
		o[0] = "aggsortkey";
		o[1] = NULL;
		o[2] = "aggsortkeypos";
		o[3] = pos[i];
		o[4] = NULL;
		reset_alt();
		if (aopen(&s, name, o, PROG_KP, 1) == 0) {
			for (j = 0; j < 5; j++)
				fire(0, "test:kernel:alpha:entry", 0,
				    VALS(N(1), N(t[j][0]), N(t[j][1]),
				    N(t[j][2]), AGG(0, 1)));
			rfp = s.out;
			if (dtrace_aggregate_snap(s.dtp) != 0 ||
			    dtrace_aggregate_walk_sorted(s.dtp, render_cb,
			    NULL) != 0)
				fail(name, "walk", "", "");
			fflush(s.out);
			for (j = 0; j < 5; j++)
				order[j] = j;
			/* Insertion sort on the rotated key tuple. */
			for (j = 1; j < 5; j++) {
				for (k = j; k > 0; k--) {
					const int64_t *a = t[order[k - 1]];
					const int64_t *b = t[order[k]];
					int c = 0, q;

					for (q = 0; q < 3 && c == 0; q++) {
						int x = (p + q) % 3;

						c = a[x] < b[x] ? -1 :
						    a[x] > b[x];
					}
					if (c <= 0)
						break;
					tmp = order[k];
					order[k] = order[k - 1];
					order[k - 1] = tmp;
				}
			}
			xbegin();
			for (j = 0; j < 5; j++)
				X("1 %lld %lld %lld 1\n",
				    (long long)t[order[j]][0],
				    (long long)t[order[j]][1],
				    (long long)t[order[j]][2]);
			expect_text(name, "order", s.text);
		}
		close_session(&s);
	}
}

/* ------------------------------------------------------------------ */
/* Cross-variable comparisons and reversed integer/user-address keys.  */

/*
 * Entries of variables with different key counts order by key count first
 * in both key-first and value-first walks (@a has one key, @b two).
 */
#define	PROG_N	"test:::entry { @a[arg0] = count(); @b[arg0, arg1] = count(); }"

static void
case_key_counts(void)
{
	static const struct {
		const char *name;
		walkfn_t *walk;
		const char *want;
	} c[] = {
		{ "keycount-keyvarsorted", dtrace_aggregate_walk_keyvarsorted,
		    "1 5 1\n1 9 2\n2 1 7 2\n2 3 0 1\n" },
		{ "keycount-valvarsorted", dtrace_aggregate_walk_valvarsorted,
		    "1 5 1\n1 9 2\n2 3 0 1\n2 1 7 2\n" },
		{ "keycount-keyvarrevsorted",
		    dtrace_aggregate_walk_keyvarrevsorted,
		    "2 3 0 1\n2 1 7 2\n1 9 2\n1 5 1\n" },
	};
	size_t i;

	for (i = 0; i < sizeof (c) / sizeof (c[0]); i++) {
		struct session s;

		reset_alt();
		if (aopen(&s, c[i].name, NULL, PROG_N, 1) == 0) {
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), N(9),
			    AGG(0, 1), N(2), N(1), N(7), AGG(0, 1)));
			fire(1, "test:kernel:alpha:entry", 0, VALS(N(1), N(9),
			    AGG(0, 1), N(2), N(1), N(7), AGG(0, 1)));
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), N(5),
			    AGG(0, 1), N(2), N(3), N(0), AGG(0, 1)));
			rfp = s.out;
			if (dtrace_aggregate_snap(s.dtp) != 0 ||
			    c[i].walk(s.dtp, render_cb, NULL) != 0)
				fail(c[i].name, "walk", "", "");
			fflush(s.out);
			xbegin();
			X("%s", c[i].want);
			expect_text(c[i].name, "order", s.text);
		}
		close_session(&s);
	}
}

/*
 * usym/umod/uaddr variables with identical (pid, address) keys and equal
 * counts: key-first and value-first walks fall through to the variable
 * order; aggsortrev reverses the option-driven walk, including the
 * address comparison.
 */
static void
case_user_keys_cross(void)
{
	static const struct {
		const char *name;
		const char *opts[5];
		walkfn_t *walk;
		int keymajor, rev;
	} c[] = {
		{ "user-keys-keyvarsorted", { NULL },
		    dtrace_aggregate_walk_keyvarsorted, 1, 0 },
		{ "user-keys-valvarsorted", { NULL },
		    dtrace_aggregate_walk_valvarsorted, 1, 0 },
		{ "user-keys-sorted-rev", { "aggsortkey", NULL, "aggsortrev",
		    NULL, NULL }, dtrace_aggregate_walk_sorted, 0, 1 },
	};
	static const uint64_t k[][2] = {
		{ 10, 0x2000 }, { 10, 0x1000 }, { 9, 0x3000 }, { 9, 0x2fff },
	};
	static const char *const keys[] = { "9:2fff", "9:3000", "a:1000",
	    "a:2000" };
	size_t i, j;
	int m, r;

	for (i = 0; i < sizeof (c) / sizeof (c[0]); i++) {
		struct session s;

		reset_alt();
		if (aopen(&s, c[i].name, c[i].opts, PROG_U, 1) == 0) {
			for (j = 0; j < sizeof (k) / sizeof (k[0]); j++) {
				struct val v[9];

				for (m = 0; m < 3; m++) {
					struct val id = N(m + 1),
					    key = B(k[j], 16), a = AGG(0, 1);

					v[3 * m] = id;
					v[3 * m + 1] = key;
					v[3 * m + 2] = a;
				}
				fire(0, "test:kernel:alpha:entry", 0, v, 9);
			}
			rfp = s.out;
			if (dtrace_aggregate_snap(s.dtp) != 0 ||
			    c[i].walk(s.dtp, render_cb, NULL) != 0)
				fail(c[i].name, "walk", "", "");
			fflush(s.out);
			xbegin();
			for (r = 0; r < 12; r++) {
				int n = c[i].rev ? 11 - r : r;
				int key = c[i].keymajor ? n / 3 : n % 4;
				int var = c[i].keymajor ? n % 3 + 1 : n / 4 + 1;

				X("%d %s 1\n", var, keys[key]);
			}
			expect_text(c[i].name, "order", s.text);
		}
		close_session(&s);
	}
}

/* Integer keys under aggsortrev (one variable per comparison). */
static void
case_int_keys_rev(void)
{
	const char *name = "int-keys-sorted-rev";
	static const char *const o[] = { "aggsortkey", NULL, "aggsortrev",
	    NULL, NULL };
	struct session s;

	reset_alt();
	if (aopen(&s, name, o, PROG_C, 1) == 0) {
		fire_c(0, 4);
		fire_c(1, 2);
		fire_c(0, 9);
		fire_c(1, 4);
		if (dtrace_aggregate_snap(s.dtp) != 0)
			fail(name, "snap", "", "");
		reopen_out(&s);
		if (dtrace_aggregate_walk_sorted(s.dtp, render_cb, NULL) != 0)
			fail(name, "walk", "", "");
		fflush(s.out);
		xbegin();
		X("1 9 1\n1 4 2\n1 2 1\n");
		expect_text(name, "order", s.text);
	}
	close_session(&s);
}

/* agghist/aggpack walks over an empty aggregation deliver nothing. */
static void
case_empty_totals(void)
{
	const char *name = "agghist-aggpack-empty";
	static const char *const o[] = { "agghist", NULL, "aggpack", NULL,
	    NULL };
	struct session s;

	reset_alt();
	if (aopen(&s, name, o, PROG_T, 1) == 0) {
		int rc = dtrace_aggregate_snap(s.dtp);

		rfp = s.out;
		rc |= dtrace_aggregate_walk_sorted(s.dtp, render_cb, NULL);
		fflush(s.out);
		expect_true(name, rc == 0 && s.text[0] == '\0', "no entries");
	}
	close_session(&s);
}

static int
keysorted_walk(dtrace_hdl_t *dtp, dtrace_aggregate_f *f, void *arg)
{
	return (dtrace_aggregate_walk_keysorted(dtp, f, arg));
}

/*
 * dtrace_aggregate_print() with an explicit walker prints in that order;
 * an output stream that cannot be written fails the print.
 */
static void
case_print_paths(void)
{
	const char *name = "print-explicit-walker";
	struct session s;

	reset_alt();
	if (aopen(&s, name, NULL, PROG_C, 1) == 0) {
		FILE *ro;
		int rc;

		fire_c(0, 2);
		fire_c(0, 1);
		fire_c(1, 1);
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_print(s.dtp, s.out, keysorted_walk) != 0)
			fail(name, "print", "", "");
		fflush(s.out);
		/*
		 * Integer keys and counts print as " %16lld" each, one tuple
		 * per line; key order (the default would be value order,
		 * key 2 first).
		 */
		xbegin();
		X(" %16lld %16lld\n", 1LL, 2LL);
		X(" %16lld %16lld\n", 2LL, 1LL);
		expect_text(name, "print", s.text);
		ro = fopen("/dev/null", "r");
		assert(ro != NULL);
		rc = dtrace_aggregate_print(s.dtp, ro, NULL);
		fclose(ro);
		expect_true("print-unwritable-stream", rc == -1,
		    "print fails");
	}
	close_session(&s);
}

#ifdef AGG_FAULT
/* ------------------------------------------------------------------ */
/* Allocation failure sweeps (unsanitized build).                      */

/*
 * For N = 0, 1, ... fail the Nth allocation made by one library call.
 * Every run that hits the fault must fail with EDT_NOMEM ("Memory
 * allocation failure"); the first run that does not must produce the
 * expected result.  The session is rebuilt for every N.
 */
typedef int fault_step_t(struct session *, int phase);

static void
fault_sweep(const char *name, const char *const *opts, const char *prog,
    void (*setup)(void), fault_step_t *step, const char *want, int go)
{
	int n, faults = 0, rc;

	for (n = 0; n < 2000; n++) {
		struct session s;

		reset_alt();
		if (aopen(&s, name, opts, prog, go) != 0) {
			close_session(&s);
			return;
		}
		if (setup != NULL)
			setup();
		rfp = s.out;
		if (step(&s, 0) != 0) {
			fail(name, "prepare", "", "");
			close_session(&s);
			return;
		}
		fault_hit = 0;
		fault_countdown = n;
		rc = step(&s, 1);
		fault_countdown = -1;
		if (fault_hit) {
			faults++;
			if (!is_err(&s, rc, MSG_NOMEM)) {
				char buf[128];

				snprintf(buf, sizeof (buf), "N=%d rc %d: %s\n",
				    n, rc, dtrace_errmsg(s.dtp,
				    dtrace_errno(s.dtp)));
				fail(name, "fault", "EDT_NOMEM\n", buf);
				close_session(&s);
				return;
			}
			close_session(&s);
			continue;
		}
		if (rc != 0) {
			fail(name, "unfaulted", "0\n", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		} else if (want != NULL) {
			reopen_out(&s);
			(void) step(&s, 2);
			fflush(s.out);
			if (strcmp(want, s.text) != 0)
				fail(name, "result", want, s.text);
			else if (faults == 0)
				fail(name, "faults", "at least one\n", "none\n");
			else
				pass(name);
		} else {
			pass(name);
		}
		close_session(&s);
		return;
	}
	fail(name, "sweep", "terminates\n", "2000 faults\n");
}

static int
snap_step(struct session *s, int phase)
{
	switch (phase) {
	case 0:
		fire_specs(spec_p, NSPEC(spec_p));
		return (0);
	case 1:
		return (dtrace_aggregate_snap(s->dtp));
	default:
		pcpu_n = 3;
		return (dtrace_aggregate_walk_keysorted(s->dtp, percpu_cb,
		    NULL));
	}
}

static int
go_step(struct session *s, int phase)
{
	if (phase == 1)
		return (dtrace_go(s->dtp));
	return (0);
}

static int
sorted_step(struct session *s, int phase)
{
	switch (phase) {
	case 0:
		fire_t(2, -6);
		fire_t(2, 4);
		fire_t(3, 2);
		fire_t(1, 1);
		return (dtrace_aggregate_snap(s->dtp));
	default:
		/* agghist totals and aggpack bins exist only during a walk. */
		return (dtrace_aggregate_walk_keysorted(s->dtp, flags_cb,
		    NULL));
	}
}

static const int jvars[] = { 2, 1, 2, 3 };

static int
joined_step(struct session *s, int phase)
{
	dtrace_aggvarid_t v[4];
	int i;

	for (i = 0; i < 4; i++)
		v[i] = jvars[i];
	switch (phase) {
	case 0:
		fire_specs(spec_j, NSPEC(spec_j));
		joined_rval = 0;
		return (dtrace_aggregate_snap(s->dtp));
	default:
		return (dtrace_aggregate_walk_joined(s->dtp, v, 4, joined_cb,
		    NULL));
	}
}

static void
case_faults(void)
{
	static const char *const pcpu[] = { "aggpercpu", NULL, NULL };
	static const char *const hist[] = { "agghist", NULL, "aggpack", NULL,
	    NULL };
	char *want;

	xbegin();
	pcpu_n = 3;
	percpu_expect(spec_p, NSPEC(spec_p), 0, NULL);
	want = strdup(xend());
	fault_sweep("fault-snap-percpu", pcpu, PROG_P, NULL, snap_step, want,
	    1);
	free(want);

	/*
	 * Only dt_aggregate_go()'s own allocations: elsewhere dtrace_go()
	 * reaches dt_dof.c's dof_construct_kvartab(), which exits the process
	 * on allocation failure.
	 */
	fault_only = "dt_aggregate_go";
	fault_sweep("fault-go", NULL, PROG_C, NULL, go_step, NULL, 0);
	fault_only = NULL;

	xbegin();
	totals_expect(1, 0, 1, 0);
	want = strdup(xend());
	fault_sweep("fault-walk-sorted-totals", hist, PROG_T, NULL,
	    sorted_step, want, 1);
	free(want);

	xbegin();
	joined_expect(spec_j, NSPEC(spec_j), jvars, 4, 0, 0, 0);
	want = strdup(xend());
	fault_sweep("fault-joined", NULL, PROG_J, NULL, joined_step, want, 1);
	free(want);

	/* kern.smp.maxid unavailable: dtrace_go() fails. */
	{
		const char *name = "go-maxid-unavailable";
		struct session s;
		int rc;

		reset_alt();
		if (aopen(&s, name, NULL, PROG_C, 0) == 0) {
			fail_maxid = 1;
			rc = dtrace_go(s.dtp);
			fail_maxid = 0;
			expect_true(name, rc == -1, "dtrace_go fails");
		}
		close_session(&s);
	}
}
#endif

static int
corrupt_lq_cb(const dtrace_aggdata_t *a, void *arg)
{
	dtrace_aggdesc_t *d = a->dtada_desc;
	dtrace_recdesc_t *rec = &d->dtagd_rec[d->dtagd_nrecs - 1];

	(void) arg;
	/* A parameter word that disagrees with the record size. */
	*(uint64_t *)(uintptr_t)(a->dtada_data + rec->dtrd_offset) = 0;
	return (DTRACE_AGGWALK_NEXT);
}

/*
 * A structured-output print fails when an entry cannot be formatted: an
 * lquantize() value whose parameter word does not match its size.
 */
static void
case_print_oformat_mismatch(void)
{
	const char *name = "print-oformat-mismatch";
	struct session s;
	FILE *json = fopen("agg-mismatch.json", "w");

	assert(json != NULL);
	reset_alt();
	xo_set_style(NULL, XO_STYLE_JSON);
	dtrace_set_outfp(json);
	if (aopen(&s, name, NULL, "test:::entry { @l = lquantize(arg0, 0, "
	    "10, 2); }", 1) == 0) {
		int rc;

		if (dtrace_oformat_configure(s.dtp) != 0)
			fail(name, "configure", "", "");
		dtrace_oformat_setup(s.dtp);
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), AGG(3, 1)));
		rc = dtrace_aggregate_snap(s.dtp);
		rc |= dtrace_aggregate_walk(s.dtp, corrupt_lq_cb, NULL);
		if (rc != 0)
			fail(name, "snap", "", "");
		rc = dtrace_aggregate_print(s.dtp, s.out, NULL);
		dtrace_oformat_teardown(s.dtp);
		expect_true(name, rc == -1, "print fails");
	}
	close_session(&s);
	xo_set_style(NULL, XO_STYLE_TEXT);
	dtrace_set_outfp(stdout);
	fclose(json);
}

/*
 * sym() keys are normalized to the containing symbol's start before
 * hashing, so addresses within one function aggregate together; an
 * address outside every symbol stays as is.  A vectored open has no module
 * lookup for mod() keys, which therefore stay per address.
 */
static void
case_sym_mod_keys(void)
{
	const char *name = "sym-mod-key-normalization";
	static const uint64_t a[] = { 0xffffffff80001010ULL,
	    0xffffffff80001020ULL, 0xffffffff80002000ULL, 0x1234 };
	struct session s;
	size_t i;

	reset_alt();
	if (aopen(&s, name, NULL, "test:::entry { @s[sym(arg0)] = count(); "
	    "@m[mod(arg0)] = count(); }", 1) == 0) {
		for (i = 0; i < 4; i++)
			fire(i & 1, "test:kernel:alpha:entry", 0, VALS(N(1),
			    N(a[i]), AGG(0, 1), N(2), N(a[i]), AGG(0, 1)));
		rfp = s.out;
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_walk_keysorted(s.dtp, render_cb,
		    NULL) != 0)
			fail(name, "walk", "", "");
		fflush(s.out);
		/* Keys compare as unsigned 64-bit values. */
		xbegin();
		X("1 %lld 1\n", 0x1234LL);
		X("1 %lld 2\n", (long long)0xffffffff80001000ULL);
		X("1 %lld 1\n", (long long)0xffffffff80002000ULL);
		X("2 %lld 1\n", 0x1234LL);
		for (i = 0; i < 3; i++)
			X("2 %lld 1\n", (long long)a[i]);
		expect_text(name, "keys", s.text);
	}
	close_session(&s);
}

/*
 * A never-fired variable is zero-filled in a joined walk from its kernel
 * aggregation description alone.  A description whose value record is not
 * an aggregating action is rejected with EDT_BADAGG, as snapshots reject
 * such records, instead of reaching the value comparison (which used to
 * abort on assert(0)).  @z (aggregation 5) is the malformed one; it leads
 * the column order so its values are compared.
 */
static void
joined_badagg_body(void)
{
	const char *name = "joined-zero-fill-unknown-action";
	struct session s;
	dtrace_aggvarid_t v[] = { 5, 2 };
	int rc;

	reset_alt();
	alt_badact_id = 5;
	if (aopen(&s, name, NULL, PROG_J, 1) == 0) {
		fire_specs(spec_j, NSPEC(spec_j));
		rfp = s.out;
		joined_rval = 0;
		if (dtrace_aggregate_snap(s.dtp) != 0)
			fail(name, "snap", "", "");
		rc = dtrace_aggregate_walk_joined(s.dtp, v, 2, joined_cb, NULL);
		fflush(s.out);
		if (!is_err(&s, rc, MSG_BADAGG) || s.text[0] != '\0')
			fail(name, "walk", "EDT_BADAGG, no rows\n", s.text);
		/* The real entries are intact: a valid walk still works. */
		reopen_out(&s);
		v[0] = 1;
		if (dtrace_aggregate_walk_joined(s.dtp, v, 2, joined_cb,
		    NULL) != 0)
			fail(name, "walk2", "", "");
		fflush(s.out);
		xbegin();
		{
			int vars[2] = { 1, 2 };

			joined_expect(spec_j, NSPEC(spec_j), vars, 2, 0, 0, 0);
		}
		if (strcmp(xend(), s.text) != 0)
			fail(name, "walk2", xend(), s.text);
		else if (failures == 0)
			pass(name);
	}
	close_session(&s);
}

static void
case_joined_badagg(void)
{
	in_child("joined-zero-fill-unknown-action", joined_badagg_body);
}

#ifdef AGG_FAULT
/* ------------------------------------------------------------------ */
/* No vector: dtrace_fdopen() on a file whose ioctls the model answers. */

#include <sys/linker.h>
#include <sys/stat.h>
#include <fcntl.h>

uint64_t aw_mapping_start(uintptr_t);	/* aggregate-walk-vm.c */

int __sys_ioctl(int, unsigned long, ...);
static dev_t nodev_dev;
static ino_t nodev_ino;
static int nodev_live;

int
ioctl(int fd, unsigned long req, ...)
{
	struct stat st;
	va_list ap;
	void *arg;

	va_start(ap, req);
	arg = va_arg(ap, void *);
	va_end(ap);
	if (nodev_live && fstat(fd, &st) == 0 && st.st_dev == nodev_dev &&
	    st.st_ino == nodev_ino)
		return (alt_ioctl(&M, req, arg));
	return (__sys_ioctl(fd, req, arg));
}

/* Exported (-rdynamic) so that dladdr() names them. */
int aw_target(int);
int aw_other(int);

int __attribute__((noinline))
aw_target(int x)
{
	volatile int y = x;

	y = y * 3 + 1;
	y ^= 0x55;
	return (y);
}

int __attribute__((noinline))
aw_other(int x)
{
	return (aw_target(x) + 1);
}

/*
 * Without a vector, aggregation keys are normalized before hashing:
 * usym() to the start of the containing function (a read-only grab of
 * the traced process), umod() to the start of the containing mapping, and
 * mod() to the start of the containing kernel module's text.  Addresses
 * that cannot be resolved -- an ungrabbable pid 0, an address with no
 * symbol, an unmapped address, an address in no module -- are left as
 * they are.  Expected values come from dladdr(), kinfo_getvmmap() and
 * kldstat(), not from libproc or libdtrace.
 */
static void
case_nodev_keys(void)
{
	const char *name = "nodev-key-normalization";
	struct session s;
	struct stat st;
	uintptr_t fn = (uintptr_t)aw_target, fn2 = (uintptr_t)aw_other;
	char *heap = malloc(64);
	uint64_t u[4][2], m[4][2], k[3];
	uint64_t mapstart = 0, mstart, kbase = 0, ksize = 0;
	struct kld_file_stat ks;
	Dl_info dli;
	dtrace_prog_t *prog;
	dtrace_proginfo_t info;
	int fd, err, i, j, kid;

	(void) aw_other(1);
	assert(dladdr((void *)(fn + 4), &dli) != 0 && dli.dli_saddr != NULL);
	assert((uintptr_t)dli.dli_saddr == fn);
	mapstart = aw_mapping_start(fn);
	/* fn2 must share the mapping so that both merge. */
	mstart = aw_mapping_start(fn2);
	assert(mapstart != 0 && mstart == mapstart);
	ks.version = sizeof (ks);
	if ((kid = kldfind("kernel")) >= 0 && kldstat(kid, &ks) == 0) {
		kbase = (uintptr_t)ks.address;
		ksize = ks.size;
	}

	u[0][0] = u[1][0] = u[2][0] = getpid();
	u[0][1] = fn + 4;
	u[1][1] = fn + 8;
	u[2][1] = (uintptr_t)heap;
	u[3][0] = 0;
	u[3][1] = fn;
	m[0][0] = m[1][0] = m[2][0] = getpid();
	m[0][1] = fn;
	m[1][1] = fn2;
	m[2][1] = 0x10;
	m[3][0] = 0;
	m[3][1] = fn;
	k[0] = kbase + ksize / 2;
	k[1] = kbase + ksize / 2 + 8;
	k[2] = 0x10;

	reset_alt();
	memset(&s, 0, sizeof (s));
	fd = open("agg-model.dev", O_RDWR | O_CREAT, 0600);
	assert(fd >= 0 && fstat(fd, &st) == 0);
	nodev_dev = st.st_dev;
	nodev_ino = st.st_ino;
	nodev_live = 1;
	s.dtp = dtrace_fdopen(fd, DTRACE_VERSION, DTRACE_O_NOSYS |
	    DTRACE_O_LP64, &err);
	close(fd);
	if (s.dtp == NULL) {
		fail(name, "dtrace_fdopen", "", dtrace_errmsg(NULL, err));
		nodev_live = 0;
		free(heap);
		return;
	}
	s.out = open_memstream(&s.text, &s.len);
	(void) dtrace_setopt(s.dtp, "bufsize", "64k");
	(void) dtrace_setopt(s.dtp, "aggsize", "64k");
	if ((prog = dtrace_program_strcompile(s.dtp, "test:::entry { "
	    "@u[usym(arg0)] = count(); @m[umod(arg0)] = count(); "
	    "@k[mod(arg0)] = count(); }", DTRACE_PROBESPEC_NAME, 0, 0,
	    NULL)) == NULL || dtrace_program_exec(s.dtp, prog, &info) != 0 ||
	    dtrace_go(s.dtp) != 0) {
		fail(name, "setup", "", dtrace_errmsg(s.dtp,
		    dtrace_errno(s.dtp)));
		goto out;
	}
	for (i = 0; i < 4; i++) {
		struct val v[9];

		for (j = 0; j < 3; j++) {
			struct val id = N(j + 1), a = AGG(0, 1),
			    sk = SKIP;

			v[3 * j] = id;
			v[3 * j + 2] = (j < 2 || i < 3) ? a : sk;
		}
		{
			struct val ku = B(u[i], 16), km = B(m[i], 16),
			    kk = N(k[i < 3 ? i : 0]);

			v[1] = ku;
			v[4] = km;
			v[7] = kk;
		}
		fire(0, "test:kernel:alpha:entry", 0, v, 9);
	}
	rfp = s.out;
	if (dtrace_aggregate_snap(s.dtp) != 0 ||
	    dtrace_aggregate_walk_keysorted(s.dtp, render_cb, NULL) != 0)
		fail(name, "walk", "", dtrace_errmsg(s.dtp,
		    dtrace_errno(s.dtp)));
	fflush(s.out);
	xbegin();
	/* Keys sort by pid, then address (unsigned). */
	{
		uint64_t a = (uintptr_t)heap, b = fn;

		X("1 0:%llx 1\n", (unsigned long long)fn);
		if (a < b)
			X("1 %llx:%llx 1\n1 %llx:%llx 2\n",
			    (unsigned long long)getpid(), (unsigned long long)a,
			    (unsigned long long)getpid(), (unsigned long long)b);
		else
			X("1 %llx:%llx 2\n1 %llx:%llx 1\n",
			    (unsigned long long)getpid(), (unsigned long long)b,
			    (unsigned long long)getpid(), (unsigned long long)a);
		X("2 0:%llx 1\n", (unsigned long long)fn);
		X("2 %llx:10 1\n", (unsigned long long)getpid());
		X("2 %llx:%llx 2\n", (unsigned long long)getpid(),
		    (unsigned long long)mapstart);
		/*
		 * mod(): 0x10 lies in no module.  The two kernel addresses
		 * share the kernel's text start, which lies within the
		 * kernel file's load range at or below both addresses.
		 */
		X("3 16 1\n");
	}
	{
		const char *want = xend();
		char *nl = s.text;
		unsigned long long kt = 0;
		int kc = 0, ok;

		/* Compare all rows but the last; check it separately. */
		for (i = 0; i < 7 && nl != NULL; i++)
			nl = strchr(nl, '\n') != NULL ? strchr(nl, '\n') + 1 :
			    NULL;
		ok = nl != NULL && sscanf(nl, "3 %lld %d", (long long *)&kt,
		    &kc) == 2 && kc == 2 && kt >= kbase && kt <= k[0] &&
		    ksize != 0;
		if (nl != NULL)
			*nl = '\0';
		if (strcmp(want, s.text) != 0)
			fail(name, "keys", want, s.text);
		else if (!ok)
			fail(name, "mod", "2 kernel addresses merged\n", nl);
		else
			pass(name);
	}
out:
	close_session(&s);
	nodev_live = 0;
	free(heap);
}
#endif

int
main(void)
{
	check_phaseup();
#ifdef AGG_FAULT
	case_faults();
	case_nodev_keys();
	reset_model();
	printf("%d passed, %d failed\n", passes, failures);
	return (failures != 0);
#endif
	case_value_orders("value-a", spec_a, NSPEC(spec_a), PROG_A);
	case_value_orders("value-b", spec_b, NSPEC(spec_b), PROG_B);
	case_clear();
	case_joined();
	case_joined_errors();
	case_percpu();
	case_snap_paths();
	case_snap_drops();
	case_hash_chains();
	case_walk_rvals();
	case_totals();
	case_key_sizes();
	case_user_keys();
	case_keypos();
	case_key_counts();
	case_user_keys_cross();
	case_int_keys_rev();
	case_empty_totals();
	case_print_paths();
	case_print_oformat_mismatch();
	case_sym_mod_keys();
	case_joined_badagg();
	reset_model();
	printf("%d passed, %d failed\n", passes, failures);
	return (failures != 0);
}
