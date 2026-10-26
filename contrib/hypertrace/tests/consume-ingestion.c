/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Offline trace-buffer ingestion through the actual libdtrace consumer.
 *
 * The library is opened with dtrace_vopen(), its documented non-device
 * backend.  The vector below models the FreeBSD dtrace(4) ioctl interface:
 * it parses the DOF the library submits, applies the kernel's record layout
 * rules (dtrace_ecb_action_add, dtrace_ecb_aggregation_create and
 * dtrace_ecb_resize in uts/common/dtrace/dtrace.c), and returns BUFSNAP and
 * AGGSNAP buffers in kernel format.  D clauses are not executed: each case
 * scripts probe firings with explicit record values, and every expected
 * output below is written from D semantics, not captured from the library.
 *
 * This is consumer coverage only.  It does not exercise the kernel, DIF
 * execution, a tracing device, a guest, or HyperTrace transport.
 */

#include <sys/types.h>
#include <sys/sysctl.h>

#include <assert.h>
#include <errno.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dtrace.h>
#include <sys/hypertrace.h>
#include <libxo/xo.h>

#define	MAXPROBE	16
#define	MAXECB		64
#define	MAXSET		32
#define	MAXACT		32
#define	MAXAGG		32
#define	MAXFMT		64
#define	NCPU_MODEL		1024
#define	CMD(x)		((u_long)(x) & 0xffffffffUL)

enum { ACT_INACTIVE, ACT_ACTIVE, ACT_DRAINING, ACT_STOPPED };
#define	BUF_WRAPPED	0x1
#define	BUF_FULL	0x2
#define	BUF_CONSUMED	0x4

struct mprobe {
	const char *prov, *mod, *func, *name;
};

/* Probe IDs are array index + 1, as in dtrace_probes[]. */
static const struct mprobe probes[] = {
	{ "dtrace", "", "", "BEGIN" },
	{ "dtrace", "", "", "END" },
	{ "dtrace", "", "", "ERROR" },
	{ "test", "kernel", "alpha", "entry" },
	{ "test", "kernel", "alpha", "return" },
	{ "test", "kernel", "beta", "entry" },
	{ "test", "kernel", "beta", "return" },
	{ "profile", "", "", "tick-1sec" },
};
#define	NPROBES	((int)(sizeof (probes) / sizeof (probes[0])))

struct mact {
	dtrace_actkind_t kind;
	dtrace_recdesc_t rec;
	int intuple;
	/* Aggregations only. */
	int first;
	uint32_t base;
	int64_t initial;
	dtrace_aggid_t aggid;
	uint8_t rtkind;		/* DIFO return type kind */
	int ecb;
};

/* One action list per ECB description, shared like dtrace_ecb_create_cache. */
struct mset {
	int nact;
	struct mact act[MAXACT];
	uint32_t size, needed, align;
};

struct mecb {
	int probe;		/* index into probes[] */
	int set;
	uint64_t uarg;
	uint16_t vmid;		/* set by the CLI shim for guest enablings */
};

struct mbuf {
	char *data;
	size_t size, offset, xamot;
	uint64_t drops;
	uint32_t errors;
	int flags;
};

struct model {
	int ncpu;
	int activity;
	int64_t opt[DTRACEOPT_MAX];
	struct mset set[MAXSET];
	int nset;
	struct mecb ecb[MAXECB];
	int necb;
	struct { int set, act; } agg[MAXAGG];
	int nagg;
	char *fmt[MAXFMT];
	int nfmt;
	struct mbuf buf[NCPU_MODEL], aggbuf[NCPU_MODEL];
	uint64_t now;
	int begancpu, endcpu;
	uint32_t needed;
	uint32_t reserve;
	int speculates;
	int exiting;
	uint64_t status_errors;
	/* Fault injection: fail the Nth use of one command. */
	u_long fail_cmd;
	int fail_errno, fail_after;
	/* Observations. */
	unsigned unexpected;
	u_long last_unexpected;
	unsigned bufsnaps, aggsnaps, enables, drainables, hqueries;
	/* Handle lifetime (DTRACEIOC_HANDLE_ID/QUERY) and answer faults. */
	dtrace_handle_lifetime_t hid;
	int hid_live, hid_mode, hq_mode;
};

static struct model M;

/* ------------------------------------------------------------------ */
/* DOF parsing, following dtrace_dof_ecbdesc/actdesc/probedesc.        */

static dof_sec_t *
dof_sect(dof_hdr_t *dof, uint32_t type, dof_secidx_t i)
{
	dof_sec_t *sec;

	if (i >= dof->dofh_secnum)
		return (NULL);
	sec = (dof_sec_t *)((char *)dof + dof->dofh_secoff +
	    i * dof->dofh_secsize);
	if (type != DOF_SECT_NONE && sec->dofs_type != type)
		return (NULL);
	return (sec);
}

static const char *
dof_str(dof_hdr_t *dof, dof_sec_t *strtab, dof_stridx_t i)
{
	const char *s = (const char *)dof + strtab->dofs_offset;

	if (i >= strtab->dofs_size || memchr(s + i, '\0',
	    strtab->dofs_size - i) == NULL)
		return (NULL);
	return (s + i);
}

static int
glob(const char *pattern, const char *s)
{
	return (*pattern == '\0' || fnmatch(pattern, s, 0) == 0);
}

/* ------------------------------------------------------------------ */
/* Kernel record layout.                                               */

static uint32_t
p2roundup(uint32_t x, uint32_t align)
{
	return ((x + align - 1) & ~(align - 1));
}

static int
llquantize_bucket(int16_t factor, int16_t low, int16_t high, int16_t nsteps,
    int64_t value)
{
	/* dtrace_aggregate_llquantize_bucket() */
	int64_t this = 1, last, next;
	int base = 1, order;

	assert(factor <= nsteps);
	assert(nsteps % factor == 0);

	for (order = 0; order < low; order++)
		this *= factor;

	if (value < this)
		return (0);

	last = this;
	for (this *= factor; order <= high; order++) {
		int nbuckets = this > nsteps ? nsteps : this;

		if ((next = this * factor) < this) {
			next = INT64_MAX;
		}
		if (value < this) {
			return (base + (value - last) / (this / nbuckets));
		}
		base += nbuckets - (nbuckets / factor);
		last = this;
		this = next;
	}
	return (base);
}

static int
action_add(struct mset *s, dtrace_actkind_t kind, uint32_t ntuple,
    uint64_t arg, uint64_t uarg, const dtrace_diftype_t *rt, int hasdifo,
    const char *fmt)
{
	struct mact *a;
	uint32_t size = 0, align = 1, mask;
	uint16_t format = 0;
	int i;

	if (s->nact == MAXACT)
		return (E2BIG);
	a = &s->act[s->nact];
	memset(a, 0, sizeof (*a));

	if (DTRACEACT_ISAGG(kind)) {
		size = sizeof (uint64_t);
		for (i = 0; i < s->nact; i++) {
			if (s->act[i].kind == DTRACEACT_COMMIT ||
			    s->act[i].kind == DTRACEACT_SPECULATE)
				return (EINVAL);
		}
		switch (kind) {
		case DTRACEAGG_MIN:
			a->initial = INT64_MAX;
			break;
		case DTRACEAGG_MAX:
			a->initial = INT64_MIN;
			break;
		case DTRACEAGG_COUNT:
		case DTRACEAGG_SUM:
			break;
		case DTRACEAGG_QUANTIZE:
			size = (((sizeof (uint64_t) * NBBY) - 1) * 2 + 1) *
			    sizeof (uint64_t);
			break;
		case DTRACEAGG_LQUANTIZE: {
			uint16_t step = DTRACE_LQUANTIZE_STEP(arg);
			uint16_t levels = DTRACE_LQUANTIZE_LEVELS(arg);

			a->initial = arg;
			if (step == 0 || levels == 0)
				return (EINVAL);
			size = levels * sizeof (uint64_t) +
			    3 * sizeof (uint64_t);
			break;
		}
		case DTRACEAGG_LLQUANTIZE: {
			uint16_t factor = DTRACE_LLQUANTIZE_FACTOR(arg);
			uint16_t low = DTRACE_LLQUANTIZE_LOW(arg);
			uint16_t high = DTRACE_LLQUANTIZE_HIGH(arg);
			uint16_t nsteps = DTRACE_LLQUANTIZE_NSTEP(arg);
			int64_t v;

			a->initial = arg;
			if (factor < 2 || low >= high || nsteps < factor)
				return (EINVAL);
			for (v = factor; v < nsteps; v *= factor)
				continue;
			if ((v % nsteps) || (nsteps % factor))
				return (EINVAL);
			size = (llquantize_bucket(factor, low, high, nsteps,
			    INT64_MAX) + 2) * sizeof (uint64_t);
			break;
		}
		case DTRACEAGG_AVG:
			size = sizeof (uint64_t) * 2;
			break;
		case DTRACEAGG_STDDEV:
			size = sizeof (uint64_t) * 4;
			break;
		default:
			return (EINVAL);
		}
		if (ntuple == 0)
			return (EINVAL);
		for (i = s->nact - 1; i >= 0; i--) {
			if (DTRACEACT_ISAGG(s->act[i].kind))
				return (EINVAL);
			if (--ntuple == 0)
				break;
		}
		if (i < 0)
			return (EINVAL);
		if (M.nagg == MAXAGG)
			return (E2BIG);
		a->first = i;
		a->aggid = ++M.nagg;
		M.agg[a->aggid - 1].set = s - M.set;
		M.agg[a->aggid - 1].act = s->nact;
		if (s->act[i].rec.dtrd_alignment < sizeof (dtrace_aggid_t))
			s->act[i].rec.dtrd_alignment = sizeof (dtrace_aggid_t);
		for (; i < s->nact; i++)
			s->act[i].intuple = 1;
	} else {
		switch (kind) {
		case DTRACEACT_PRINTF:
		case DTRACEACT_PRINTA:
		case DTRACEACT_SYSTEM:
		case DTRACEACT_FREOPEN:
		case DTRACEACT_DIFEXPR:
			if (fmt != NULL) {
				if (M.nfmt == MAXFMT)
					return (E2BIG);
				M.fmt[M.nfmt++] = strdup(fmt);
				format = M.nfmt;
			}
			/* FALLTHROUGH */
		case DTRACEACT_LIBACT:
		case DTRACEACT_TRACEMEM:
		case DTRACEACT_TRACEMEM_DYNSIZE:
			if (!hasdifo)
				return (EINVAL);
			if ((size = rt->dtdt_size) != 0)
				break;
			if (rt->dtdt_kind == DIF_TYPE_STRING) {
				if (!(rt->dtdt_flags & DIF_TF_BYREF))
					return (EINVAL);
				size = M.opt[DTRACEOPT_STRSIZE];
			}
			break;
		case DTRACEACT_STACK:
			if (arg == 0)
				arg = M.opt[DTRACEOPT_STACKFRAMES];
			size = arg * sizeof (uint64_t);
			break;
		case DTRACEACT_IMMSTACK:
		case DTRACEACT_PRINTIMMSTACK:
			/* Host side (no guest hypercalls): frames x strsize. */
			if (arg == 0)
				arg = M.opt[DTRACEOPT_IMMSTACKFRAMES];
			size = arg * M.opt[DTRACEOPT_IMMSTACKSTRSIZE];
			break;
		case DTRACEACT_USTACK:
		case DTRACEACT_JSTACK: {
			uint64_t nframes = DTRACE_USTACK_NFRAMES(arg);
			uint64_t strsize = DTRACE_USTACK_STRSIZE(arg);

			if (kind == DTRACEACT_JSTACK) {
				if (strsize == 0)
					strsize = M.opt[DTRACEOPT_JSTACKSTRSIZE];
				if (nframes == 0)
					nframes = M.opt[DTRACEOPT_JSTACKFRAMES];
			} else if (nframes == 0) {
				nframes = M.opt[DTRACEOPT_USTACKFRAMES];
			}
			arg = DTRACE_USTACK_ARG(nframes, strsize);
			size = p2roundup((nframes + 1) * sizeof (uint64_t) +
			    strsize, sizeof (uintptr_t));
			break;
		}
		case DTRACEACT_SYM:
		case DTRACEACT_MOD:
			if (!hasdifo || (size = rt->dtdt_size) !=
			    sizeof (uint64_t) || (rt->dtdt_flags & DIF_TF_BYREF))
				return (EINVAL);
			break;
		case DTRACEACT_USYM:
		case DTRACEACT_UMOD:
		case DTRACEACT_UADDR:
			if (!hasdifo || rt->dtdt_size != sizeof (uint64_t) ||
			    (rt->dtdt_flags & DIF_TF_BYREF))
				return (EINVAL);
			size = 2 * sizeof (uint64_t);
			break;
		case DTRACEACT_STOP:
		case DTRACEACT_BREAKPOINT:
		case DTRACEACT_PANIC:
			break;
		case DTRACEACT_CHILL:
		case DTRACEACT_DISCARD:
		case DTRACEACT_RAISE:
			if (!hasdifo)
				return (EINVAL);
			break;
		case DTRACEACT_EXIT:
			if (!hasdifo || (size = rt->dtdt_size) < sizeof (int) ||
			    (rt->dtdt_flags & DIF_TF_BYREF))
				return (EINVAL);
			break;
		case DTRACEACT_SPECULATE:
			if (s->size > sizeof (dtrace_rechdr_t) || !hasdifo)
				return (EINVAL);
			M.speculates = 1;
			break;
		case DTRACEACT_PRINTM:
			size = rt->dtdt_size;
			break;
		case DTRACEACT_COMMIT:
			for (i = 0; i < s->nact; i++)
				if (s->act[i].kind == DTRACEACT_COMMIT)
					return (EINVAL);
			if (!hasdifo)
				return (EINVAL);
			break;
		default:
			return (EINVAL);
		}
		if (size != 0 || kind == DTRACEACT_SPECULATE) {
			for (i = 0; i < s->nact; i++)
				if (s->act[i].kind == DTRACEACT_COMMIT)
					return (EINVAL);
		}
	}

	for (mask = sizeof (uint64_t) - 1; size != 0 && mask > 0; mask >>= 1) {
		if (!(size & mask)) {
			align = mask + 1;
			break;
		}
	}
	a->kind = kind;
	a->rtkind = hasdifo ? rt->dtdt_kind : DIF_TYPE_NONE;
	a->rec.dtrd_action = kind;
	a->rec.dtrd_size = size;
	a->rec.dtrd_arg = arg;
	a->rec.dtrd_uarg = uarg;
	a->rec.dtrd_alignment = align;
	a->rec.dtrd_format = format;
	s->nact++;
	return (0);
}

static int
resize(struct mset *s)
{
	uint32_t cur = UINT32_MAX, aggbase = UINT32_MAX, needed = 0;
	int i;

	s->size = sizeof (dtrace_rechdr_t);
	s->align = sizeof (dtrace_epid_t);
	for (i = 0; i < s->nact; i++) {
		struct mact *a = &s->act[i];
		dtrace_recdesc_t *r = &a->rec;

		if (r->dtrd_alignment > s->align)
			s->align = r->dtrd_alignment;
		if (DTRACEACT_ISAGG(a->kind)) {
			a->base = aggbase;
			cur = p2roundup(cur, r->dtrd_alignment);
			r->dtrd_offset = cur;
			if (cur + r->dtrd_size < cur)
				return (EINVAL);
			cur += r->dtrd_size;
			if (cur > needed)
				needed = cur;
			aggbase = cur = UINT32_MAX;
		} else if (a->intuple) {
			if (cur == UINT32_MAX) {
				/* Offset 4 within an 8-byte block. */
				cur = ((s->size + 3) & ~7U) + 4;
				if (cur < s->size)
					cur += 8;
				aggbase = cur - sizeof (dtrace_aggid_t);
			}
			cur = p2roundup(cur, r->dtrd_alignment);
			r->dtrd_offset = cur;
			cur += r->dtrd_size;
		} else {
			s->size = p2roundup(s->size, r->dtrd_alignment);
			r->dtrd_offset = s->size;
			if (s->size + r->dtrd_size < s->size)
				return (EINVAL);
			s->size += r->dtrd_size;
			if (s->size > needed)
				needed = s->size;
		}
	}
	if (s->nact != 0 && !(s->act[0].kind == DTRACEACT_SPECULATE &&
	    s->nact == 1) && s->size == sizeof (dtrace_rechdr_t))
		s->size = 0;
	s->size = p2roundup(s->size, sizeof (dtrace_epid_t));
	s->needed = p2roundup(needed, sizeof (dtrace_epid_t));
	if (s->needed > M.needed)
		M.needed = s->needed;
	return (0);
}

/*
 * P2PHASEUP(x, 8, 4) is what the kernel uses for the first tuple record.
 * The open-coded version above must agree with it for every header size.
 */
static void
check_phaseup(void)
{
	uint32_t x, cur;

	for (x = 0; x < 64; x++) {
		cur = ((x + 3) & ~7U) + 4;
		if (cur < x)
			cur += 8;
		assert(cur == (uint32_t)(4 - (((uint32_t)4 - x) & ~7U)));
	}
}

static int
enable(dtrace_enable_io_t *p)
{
	dof_hdr_t *dof = p->dof;
	int first_set = M.nset, first_ecb = M.necb, first_agg = M.nagg;
	int first_fmt = M.nfmt, ndesc = 0, error = 0;
	uint32_t i, j;

	M.enables++;
	if (dof == NULL)
		return (0);
	p->n_matched = 0;
	p->n_desc = 0;
	if (memcmp(dof->dofh_ident, "\177DOF", 4) != 0 ||
	    dof->dofh_secsize < sizeof (dof_sec_t))
		return (EINVAL);
	if (p->vmid != 0)
		return (ENOTSUP);	/* hypertrace_check_epoch is absent */
	if (M.activity != ACT_INACTIVE)
		return (EBUSY);

	/* dtrace_dof_options() precedes matching. */
	for (i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = dof_sect(dof, DOF_SECT_NONE, i);
		size_t off;

		if (sec->dofs_type != DOF_SECT_OPTDESC)
			continue;
		if (sec->dofs_entsize < sizeof (dof_optdesc_t))
			return (EINVAL);
		for (off = 0; off < sec->dofs_size; off += sec->dofs_entsize) {
			dof_optdesc_t *o = (dof_optdesc_t *)((char *)dof +
			    sec->dofs_offset + off);

			if (o->dofo_strtab != DOF_SECIDX_NONE ||
			    o->dofo_value == (uint64_t)DTRACEOPT_UNSET ||
			    o->dofo_option >= DTRACEOPT_MAX)
				return (EINVAL);
			if (o->dofo_option != DTRACEOPT_CPU &&
			    (int64_t)o->dofo_value < 0)
				return (EINVAL);
			M.opt[o->dofo_option] = o->dofo_value;
		}
	}

	for (i = 0; i < dof->dofh_secnum && error == 0; i++) {
		dof_sec_t *sec = dof_sect(dof, DOF_SECT_NONE, i), *ps, *st, *as;
		dof_ecbdesc_t *e;
		dof_probedesc_t *pd;
		const char *pv, *md, *fn, *nm;
		struct mset *s;
		int matched = 0;

		if (sec->dofs_type != DOF_SECT_ECBDESC)
			continue;
		e = (dof_ecbdesc_t *)((char *)dof + sec->dofs_offset);
		if ((ps = dof_sect(dof, DOF_SECT_PROBEDESC,
		    e->dofe_probes)) == NULL) {
			error = EINVAL;
			break;
		}
		pd = (dof_probedesc_t *)((char *)dof + ps->dofs_offset);
		if ((st = dof_sect(dof, DOF_SECT_STRTAB,
		    pd->dofp_strtab)) == NULL ||
		    (pv = dof_str(dof, st, pd->dofp_provider)) == NULL ||
		    (md = dof_str(dof, st, pd->dofp_mod)) == NULL ||
		    (fn = dof_str(dof, st, pd->dofp_func)) == NULL ||
		    (nm = dof_str(dof, st, pd->dofp_name)) == NULL) {
			error = EINVAL;
			break;
		}
		if (M.nset == MAXSET) {
			error = E2BIG;
			break;
		}
		s = &M.set[M.nset];
		memset(s, 0, sizeof (*s));
		s->size = sizeof (dtrace_rechdr_t);

		if (e->dofe_actions != DOF_SECIDX_NONE) {
			size_t off;

			if ((as = dof_sect(dof, DOF_SECT_ACTDESC,
			    e->dofe_actions)) == NULL ||
			    as->dofs_entsize != sizeof (dof_actdesc_t)) {
				error = EINVAL;
				break;
			}
			for (off = 0; off < as->dofs_size && error == 0;
			    off += as->dofs_entsize) {
				dof_actdesc_t *ad = (dof_actdesc_t *)
				    ((char *)dof + as->dofs_offset + off);
				dtrace_actkind_t kind = ad->dofa_kind;
				dtrace_diftype_t rt = { 0 };
				const char *fmt = NULL;
				uint64_t arg = ad->dofa_arg;
				dof_sec_t *ds;

				if ((DTRACEACT_ISPRINTFLIKE(kind) &&
				    (kind != DTRACEACT_PRINTA ||
				    ad->dofa_strtab != DOF_SECIDX_NONE)) ||
				    (kind == DTRACEACT_DIFEXPR &&
				    ad->dofa_strtab != DOF_SECIDX_NONE)) {
					dof_sec_t *fs = dof_sect(dof,
					    DOF_SECT_STRTAB, ad->dofa_strtab);

					if (fs == NULL || (fmt = dof_str(dof,
					    fs, ad->dofa_arg)) == NULL ||
					    *fmt == '\0') {
						error = EINVAL;
						break;
					}
					arg = 1;	/* a kernel pointer */
				} else if (kind == DTRACEACT_PRINTA) {
					arg = 0;
				}
				if (ad->dofa_difo != DOF_SECIDX_NONE) {
					if ((ds = dof_sect(dof,
					    DOF_SECT_DIFOHDR,
					    ad->dofa_difo)) == NULL) {
						error = EINVAL;
						break;
					}
					memcpy(&rt, (char *)dof +
					    ds->dofs_offset, sizeof (rt));
				}
				error = action_add(s, kind, ad->dofa_ntuple,
				    arg, ad->dofa_uarg, &rt,
				    ad->dofa_difo != DOF_SECIDX_NONE, fmt);
			}
			if (error != 0)
				break;
		}
		if ((error = resize(s)) != 0)
			break;
		M.nset++;

		for (j = 0; j < (uint32_t)NPROBES; j++) {
			const struct mprobe *mp = &probes[j];

			if ((pd->dofp_id != 0 && pd->dofp_id != j + 1) ||
			    !glob(pv, mp->prov) || !glob(md, mp->mod) ||
			    !glob(fn, mp->func) || !glob(nm, mp->name))
				continue;
			if (M.necb == MAXECB) {
				error = E2BIG;
				break;
			}
			M.ecb[M.necb].probe = j;
			M.ecb[M.necb].set = s - M.set;
			M.ecb[M.necb].uarg = e->dofe_uarg;
			M.ecb[M.necb].vmid = 0;
			M.necb++;
			matched++;
			if (p->ps != NULL) {
				dtrace_probedesc_t *d;

				if ((size_t)(ndesc + 1) * sizeof (*d) >
				    (size_t)p->ps_bufsize) {
					error = E2BIG;
					break;
				}
				d = &p->ps[ndesc++];
				memset(d, 0, sizeof (*d));
				d->dtpd_id = j + 1;
				strlcpy(d->dtpd_provider, mp->prov,
				    sizeof (d->dtpd_provider));
				strlcpy(d->dtpd_mod, mp->mod,
				    sizeof (d->dtpd_mod));
				strlcpy(d->dtpd_func, mp->func,
				    sizeof (d->dtpd_func));
				strlcpy(d->dtpd_name, mp->name,
				    sizeof (d->dtpd_name));
			}
		}
		/* The first matching ECB owns the aggregation (dtag_ecb). */
		for (j = 0; j < (uint32_t)s->nact; j++)
			s->act[j].ecb = matched ? M.necb - matched : -1;
		p->n_matched += matched;
	}
	if (error != 0) {
		/* dtrace_enabling_rollback() */
		while (M.nfmt > first_fmt)
			free(M.fmt[--M.nfmt]);
		M.nset = first_set;
		M.necb = first_ecb;
		M.nagg = first_agg;
		p->n_matched = 0;
		return (error);
	}
	p->n_desc = ndesc;
	return (0);
}

/* ------------------------------------------------------------------ */
/* Buffers.                                                            */

static void
buffer_alloc(struct mbuf *b, size_t size)
{
	free(b->data);
	memset(b, 0, sizeof (*b));
	if (size == 0)
		return;
	b->data = calloc(1, size);
	assert(b->data != NULL);
	b->size = size;
}

static size_t
epid_size(uint32_t epid)
{
	assert(epid >= 1 && epid <= (uint32_t)M.necb);
	return (M.set[M.ecb[epid - 1].set].size);
}

/* dtrace_buffer_reserve(); returns -1 after recording a drop. */
static ssize_t
reserve(struct mbuf *b, size_t needed, size_t align)
{
	ssize_t offs = b->offset;
	size_t total, woffs;

	if (b->data == NULL) {
		b->drops++;
		return (-1);
	}
	if (M.opt[DTRACEOPT_BUFPOLICY] == DTRACEOPT_BUFPOLICY_SWITCH) {
		while (offs & (align - 1)) {
			*(uint32_t *)(b->data + offs) = DTRACE_EPIDNONE;
			offs += sizeof (uint32_t);
		}
		if (offs + needed > b->size) {
			b->drops++;
			return (-1);
		}
		return (offs);
	}
	if (M.opt[DTRACEOPT_BUFPOLICY] == DTRACEOPT_BUFPOLICY_FILL) {
		if (M.activity != ACT_DRAINING && (b->flags & BUF_FULL))
			return (-1);
		goto out;
	}
	total = needed + (offs & (align - 1));
	if ((b->flags & BUF_WRAPPED) || offs + total > b->size) {
		woffs = b->xamot;
		if (offs + total > b->size) {
			if (total > b->size) {
				b->drops++;
				return (-1);
			}
			if (!(b->flags & BUF_WRAPPED) || woffs >= (size_t)offs)
				woffs = 0;
			while ((size_t)offs < b->size)
				b->data[offs++] = 0;
			offs = 0;
			total = needed;
			b->flags |= BUF_WRAPPED;
		} else if (woffs < (size_t)offs) {
			goto out;
		}
		while (offs + total > woffs) {
			uint32_t epid = *(uint32_t *)(b->data + woffs);
			size_t size = epid == DTRACE_EPIDNONE ?
			    sizeof (uint32_t) : epid_size(epid);

			if (woffs + size == b->size) {
				if (offs == 0) {
					b->flags &= ~BUF_WRAPPED;
					b->offset = 0;
					for (woffs = total; woffs < b->size;)
						b->data[woffs++] = 0;
				}
				woffs = 0;
				break;
			}
			woffs += size;
		}
		b->xamot = woffs;
	}
out:
	while (offs & (align - 1)) {
		*(uint32_t *)(b->data + offs) = DTRACE_EPIDNONE;
		offs += sizeof (uint32_t);
	}
	if (M.opt[DTRACEOPT_BUFPOLICY] == DTRACEOPT_BUFPOLICY_FILL &&
	    offs + needed > b->size - M.reserve) {
		b->flags |= BUF_FULL;
		return (-1);
	}
	return (offs);
}

/*
 * A scripted value for one action of a firing.  Data records take bytes or
 * a little-endian integer; aggregating actions take the value and the
 * quantize increment.
 */
struct val {
	const void *bytes;
	size_t len;
	int64_t num;
	int64_t incr;
};
#define	N(x)		{ NULL, 0, (int64_t)(x), 1 }
#define	S(x)		{ (x), sizeof (x), 0, 1 }
#define	B(p, n)		{ (p), (n), 0, 1 }
#define	AGG(x, i)	{ NULL, 0, (int64_t)(x), (int64_t)(i) }
#define	SKIP		{ NULL, 0, 0, 0 }

static void
store(char *dst, uint32_t size, const struct val *v)
{
	memset(dst, 0, size);
	if (v->bytes != NULL)
		memcpy(dst, v->bytes, v->len < size ? v->len : size);
	else
		memcpy(dst, &v->num, size < 8 ? size : 8);
}

static void
aggregate(struct mact *a, uint64_t *d, int64_t nval, int64_t incr)
{
	int i;

	switch (a->kind) {
	case DTRACEAGG_COUNT:
		d[0]++;
		break;
	case DTRACEAGG_SUM:
		d[0] += nval;
		break;
	case DTRACEAGG_MIN:
		if ((int64_t)d[0] > nval)
			d[0] = nval;
		break;
	case DTRACEAGG_MAX:
		if ((int64_t)d[0] < nval)
			d[0] = nval;
		break;
	case DTRACEAGG_AVG:
		d[0]++;
		d[1] += nval;
		break;
	case DTRACEAGG_STDDEV: {
		/* dtrace_aggregate_stddev(): 128-bit sum of squares. */
		unsigned __int128 sq = (unsigned __int128)(nval < 0 ?
		    -(uint64_t)nval : (uint64_t)nval);
		unsigned __int128 acc = ((unsigned __int128)d[3] << 64) | d[2];

		d[0]++;
		d[1] += nval;
		acc += sq * sq;
		d[2] = (uint64_t)acc;
		d[3] = (uint64_t)(acc >> 64);
		break;
	}
	case DTRACEAGG_QUANTIZE: {
		int64_t v = nval;
		int zero = DTRACE_QUANTIZE_ZEROBUCKET;
		int nbuckets = DTRACE_QUANTIZE_NBUCKETS;

		if (v < 0) {
			for (i = 0; i < zero; i++) {
				if (v <= DTRACE_QUANTIZE_BUCKETVAL((unsigned)i)) {
					d[i] += incr;
					return;
				}
			}
		} else {
			for (i = zero + 1; i < nbuckets; i++) {
				if (v < DTRACE_QUANTIZE_BUCKETVAL((unsigned)i)) {
					d[i - 1] += incr;
					return;
				}
			}
			d[DTRACE_QUANTIZE_NBUCKETS - 1] += incr;
			return;
		}
		assert(0);
	}
	case DTRACEAGG_LQUANTIZE: {
		uint64_t arg = d[0];
		int32_t base = DTRACE_LQUANTIZE_BASE(arg);
		uint16_t step = DTRACE_LQUANTIZE_STEP(arg);
		uint16_t levels = DTRACE_LQUANTIZE_LEVELS(arg);
		int32_t val = (int32_t)nval, level;

		d++;
		if (val < base) {
			d[0] += incr;
			return;
		}
		level = (val - base) / step;
		if (level < levels) {
			d[level + 1] += incr;
			return;
		}
		d[levels + 1] += incr;
		break;
	}
	case DTRACEAGG_LLQUANTIZE: {
		uint64_t arg = d[0];

		d[1 + llquantize_bucket(DTRACE_LLQUANTIZE_FACTOR(arg),
		    DTRACE_LLQUANTIZE_LOW(arg), DTRACE_LLQUANTIZE_HIGH(arg),
		    DTRACE_LLQUANTIZE_NSTEP(arg), nval)] += incr;
		break;
	}
	default:
		assert(0);
	}
}

/* dtrace_aggregate(): linear search stands in for the kernel hash. */
static void
agg_store(int cpu, struct mset *s, struct mact *a, const char *ecbdata,
    int64_t nval, int64_t incr)
{
	struct mbuf *b = &M.aggbuf[cpu];
	uint32_t size = a->rec.dtrd_offset - a->base;
	uint32_t fsize = size + a->rec.dtrd_size;
	size_t offs;
	char *k;
	int i;

	if (b->data == NULL)
		return;
	for (offs = 0; offs < b->offset; ) {
		k = b->data + offs;
		if (*(dtrace_aggid_t *)k == DTRACE_AGGIDNONE) {
			offs += sizeof (uint32_t);
			continue;
		}
		if (*(dtrace_aggid_t *)k == a->aggid &&
		    memcmp(k + 4, ecbdata + a->base + 4, size - 4) == 0) {
			aggregate(a, (uint64_t *)(k + size), nval, incr);
			return;
		}
		offs += M.set[M.agg[*(dtrace_aggid_t *)k - 1].set].act
		    [M.agg[*(dtrace_aggid_t *)k - 1].act].rec.dtrd_offset +
		    M.set[M.agg[*(dtrace_aggid_t *)k - 1].set].act
		    [M.agg[*(dtrace_aggid_t *)k - 1].act].rec.dtrd_size -
		    M.set[M.agg[*(dtrace_aggid_t *)k - 1].set].act
		    [M.agg[*(dtrace_aggid_t *)k - 1].act].base;
	}
	offs = b->offset;
	while (offs & 7)
		offs += sizeof (uint32_t);
	if (offs + fsize > b->size) {
		b->drops++;
		return;
	}
	k = b->data + offs;
	b->offset = offs + fsize;
	memcpy(k, ecbdata + a->base, size);
	*(dtrace_aggid_t *)k = a->aggid;
	/* String keys are NUL padded. */
	for (i = a->first; s->act[i].intuple && &s->act[i] != a; i++) {
		struct mact *t = &s->act[i];
		uint32_t at = t->rec.dtrd_offset - a->base, n;

		/* DTRACEACT_ISSTRING() */
		if (t->kind != DTRACEACT_DIFEXPR ||
		    t->rtkind != DIF_TYPE_STRING)
			continue;
		for (n = 0; n < t->rec.dtrd_size && k[at + n] != '\0'; n++)
			continue;
		memset(k + at + n, 0, t->rec.dtrd_size - n);
	}
	memset(k + size, 0, fsize - size);
	*(uint64_t *)(k + size) = a->initial;
	aggregate(a, (uint64_t *)(k + size), nval, incr);
}

static int
find_ecb(const char *desc, int nth)
{
	char want[256];
	int i;

	for (i = 0; i < M.necb; i++) {
		const struct mprobe *p = &probes[M.ecb[i].probe];

		snprintf(want, sizeof (want), "%s:%s:%s:%s", p->prov, p->mod,
		    p->func, p->name);
		if (strcmp(want, desc) == 0 && nth-- == 0)
			return (i);
	}
	fprintf(stderr, "no ECB %s\n", desc);
	abort();
}

/* Fire one ECB on a CPU: write its data record and apply aggregations. */
static int
fire(int cpu, const char *desc, int nth, const struct val *v, int nv)
{
	int e = find_ecb(desc, nth), i;
	struct mset *s = &M.set[M.ecb[e].set];
	struct mbuf *b = &M.buf[cpu];
	char scratch[65536];
	ssize_t offs;

	if (nv != s->nact || getenv("CONSUME_DUMP") != NULL) {
		fprintf(stderr, "ECB %d %s: %d actions, size %u needed %u "
		    "align %u, %d values\n", e + 1, desc, s->nact, s->size,
		    s->needed, s->align, nv);
		for (i = 0; i < s->nact; i++)
			fprintf(stderr, "  act %d kind %#x size %u off %u "
			    "align %u tuple %d arg %#" PRIx64 "\n", i,
			    s->act[i].kind, s->act[i].rec.dtrd_size,
			    s->act[i].rec.dtrd_offset,
			    s->act[i].rec.dtrd_alignment, s->act[i].intuple,
			    s->act[i].rec.dtrd_arg);
		assert(nv == s->nact);
	}
	assert(s->needed <= sizeof (scratch));
	memset(scratch, 0, sizeof (scratch));
	/*
	 * Actions run in order, as in dtrace_probe(): every tuple of an ECB
	 * occupies the same scratch offsets, so each aggregation is applied
	 * before the next tuple overwrites its key.
	 */
	for (i = 0; i < s->nact; i++) {
		struct mact *a = &s->act[i];

		if (a->kind == DTRACEACT_EXIT)
			M.exiting = 1;
		if (DTRACEACT_ISAGG(a->kind)) {
			if (v[i].incr != 0)
				agg_store(cpu, s, a, scratch, v[i].num,
				    v[i].incr);
			continue;
		}
		if (a->rec.dtrd_size != 0)
			store(scratch + a->rec.dtrd_offset, a->rec.dtrd_size,
			    &v[i]);
	}
	if (s->size == 0)
		return (0);
	if ((offs = reserve(b, s->needed, s->align)) < 0)
		return (-1);
	M.now += 1000;
	((dtrace_rechdr_t *)scratch)->dtrh_epid = e + 1;
	DTRACE_RECORD_STORE_TIMESTAMP((dtrace_rechdr_t *)scratch, M.now);
	memcpy(b->data + offs, scratch, s->size);
	b->offset = offs + s->size;
	return (0);
}

static int
snap(dtrace_bufdesc_t **pdesc, struct mbuf *b, int aggregation)
{
	dtrace_bufdesc_t *d = *pdesc;
	size_t sz;

	if (d->dtbd_cpu >= (uint32_t)M.ncpu)
		return (ENOENT);
	if (!aggregation && M.opt[DTRACEOPT_BUFPOLICY] !=
	    DTRACEOPT_BUFPOLICY_SWITCH) {
		if (M.activity != ACT_STOPPED)
			return (EBUSY);
		if (b->flags & BUF_CONSUMED) {
			d->dtbd_size = d->dtbd_drops = d->dtbd_errors = 0;
			d->dtbd_oldest = 0;
			return (0);
		}
		sz = b->offset;
		if (b->flags & BUF_WRAPPED) {
			/* dtrace_buffer_polish() */
			if (b->offset < b->xamot)
				memset(b->data + b->offset, 0,
				    b->xamot - b->offset);
			if (b->offset > b->xamot) {
				memset(b->data + b->offset, 0,
				    b->size - b->offset);
				memset(b->data, 0, b->xamot);
			}
			sz = b->size;
		}
		if (sz > d->dtbd_size)
			return (EFAULT);
		memcpy(d->dtbd_data, b->data, sz);
		d->dtbd_size = sz;
		d->dtbd_drops = b->drops;
		d->dtbd_errors = b->errors;
		d->dtbd_oldest = b->xamot;
		d->dtbd_timestamp = ++M.now;
		b->flags |= BUF_CONSUMED;
		return (0);
	}
	if (b->data == NULL)
		return (ENOENT);
	if (b->offset > d->dtbd_size)
		return (EFAULT);
	memcpy(d->dtbd_data, b->data, b->offset);
	d->dtbd_size = b->offset;
	d->dtbd_drops = b->drops;
	d->dtbd_errors = b->errors;
	d->dtbd_oldest = 0;
	d->dtbd_timestamp = ++M.now;
	/* dtrace_buffer_switch(): the new active buffer starts empty. */
	memset(b->data, 0, b->size);
	b->offset = 0;
	b->drops = 0;
	b->errors = 0;
	return (0);
}

/* ------------------------------------------------------------------ */
/* The vector.                                                         */

static int
model_ioctl(void *varg, u_long cmd, void *arg)
{
	int error = 0, i;

	(void) varg;
	cmd = CMD(cmd);
	if (cmd == M.fail_cmd && M.fail_after-- == 0) {
		errno = M.fail_errno;
		return (-1);
	}
	if (cmd == CMD(DTRACEIOC_CONF)) {
		dtrace_conf_t *c = arg;

		memset(c, 0, sizeof (*c));
		c->dtc_difversion = DIF_VERSION;
		c->dtc_difintregs = DIF_DIR_NREGS;
		c->dtc_diftupregs = DIF_DTR_NREGS;
		c->dtc_ctfmodel = CTF_MODEL_NATIVE;
	} else if (cmd == CMD(DTRACEIOC_PROVIDER)) {
		dtrace_providerdesc_t *pvd = arg;
		dtrace_attribute_t at = { DTRACE_STABILITY_EVOLVING,
		    DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON };

		error = ESRCH;
		for (i = 0; i < NPROBES; i++) {
			if (strcmp(pvd->dtvd_name, probes[i].prov) != 0)
				continue;
			memset(&pvd->dtvd_priv, 0, sizeof (pvd->dtvd_priv));
			pvd->dtvd_attr.dtpa_provider = at;
			pvd->dtvd_attr.dtpa_mod = at;
			pvd->dtvd_attr.dtpa_func = at;
			pvd->dtvd_attr.dtpa_name = at;
			pvd->dtvd_attr.dtpa_args = at;
			error = 0;
			break;
		}
	} else if (cmd == CMD(DTRACEIOC_PROBEMATCH) ||
	    cmd == CMD(DTRACEIOC_PROBES)) {
		dtrace_probedesc_t *d = arg;
		int match = cmd == CMD(DTRACEIOC_PROBEMATCH);
		dtrace_id_t id = d->dtpd_id == DTRACE_IDNONE ? 1 : d->dtpd_id;

		/*
		 * A guest ECB's probe (the CLI shim tags guest enablings
		 * with their VMID) is described by id like a host one and
		 * keeps its VMID; matching guest descriptions is not
		 * modeled.
		 */
		error = ESRCH;
		for (i = id - 1; (d->dtpd_vmid == 0 || !match) && i < NPROBES;
		    i++) {
			if (match && (!glob(d->dtpd_provider, probes[i].prov) ||
			    !glob(d->dtpd_mod, probes[i].mod) ||
			    !glob(d->dtpd_func, probes[i].func) ||
			    !glob(d->dtpd_name, probes[i].name)))
				continue;
			d->dtpd_id = i + 1;
			strlcpy(d->dtpd_provider, probes[i].prov,
			    sizeof (d->dtpd_provider));
			strlcpy(d->dtpd_mod, probes[i].mod,
			    sizeof (d->dtpd_mod));
			strlcpy(d->dtpd_func, probes[i].func,
			    sizeof (d->dtpd_func));
			strlcpy(d->dtpd_name, probes[i].name,
			    sizeof (d->dtpd_name));
			error = 0;
			break;
		}
	} else if (cmd == CMD(DTRACEIOC_PROBEARG)) {
		dtrace_argdesc_t *a = arg;

		if (a->dtargd_id == DTRACE_IDNONE ||
		    a->dtargd_ndx == DTRACE_ARGNONE ||
		    a->dtargd_id > (dtrace_id_t)NPROBES)
			error = EINVAL;
		else
			a->dtargd_ndx = DTRACE_ARGNONE;	/* no getargdesc */
	} else if (cmd == CMD(DTRACEIOC_ENABLE)) {
		error = enable(arg);
	} else if (cmd == CMD(DTRACEIOC_EPROBE)) {
		dtrace_eprobedesc_t *d = *(dtrace_eprobedesc_t **)arg;
		int nrecs = d->dtepd_nrecs, n = 0;
		struct mset *s;

		if (d->dtepd_epid == 0 || d->dtepd_epid > (uint32_t)M.necb)
			return (errno = EINVAL, -1);
		s = &M.set[M.ecb[d->dtepd_epid - 1].set];
		d->dtepd_probeid = M.ecb[d->dtepd_epid - 1].probe + 1;
		d->dtepd_uarg = M.ecb[d->dtepd_epid - 1].uarg;
		d->dtepd_size = s->size;
		d->dtepd_vmid = M.ecb[d->dtepd_epid - 1].vmid;
		d->dtepd_nrecs = 0;
		for (i = 0; i < s->nact; i++)
			if (!DTRACEACT_ISAGG(s->act[i].kind) &&
			    !s->act[i].intuple)
				d->dtepd_nrecs++;
		for (i = 0; i < s->nact; i++) {
			if (DTRACEACT_ISAGG(s->act[i].kind) ||
			    s->act[i].intuple)
				continue;
			if (nrecs-- == 0)
				break;
			d->dtepd_rec[n++] = s->act[i].rec;
		}
	} else if (cmd == CMD(DTRACEIOC_AGGDESC)) {
		dtrace_aggdesc_t *d = *(dtrace_aggdesc_t **)arg;
		int nrecs = d->dtagd_nrecs, n = 0;
		struct mset *s;
		struct mact *a;

		if (d->dtagd_id == 0 || d->dtagd_id > (uint32_t)M.nagg)
			return (errno = EINVAL, -1);
		s = &M.set[M.agg[d->dtagd_id - 1].set];
		a = &s->act[M.agg[d->dtagd_id - 1].act];
		d->dtagd_epid = a->ecb + 1;
		d->dtagd_size = a->rec.dtrd_offset + a->rec.dtrd_size -
		    a->base;
		d->dtagd_nrecs = 0;
		for (i = a->first; i <= M.agg[d->dtagd_id - 1].act; i++)
			if (s->act[i].rec.dtrd_size != 0)
				d->dtagd_nrecs++;
		for (i = a->first; i <= M.agg[d->dtagd_id - 1].act; i++) {
			if (s->act[i].rec.dtrd_size == 0)
				continue;
			if (nrecs-- == 0)
				break;
			d->dtagd_rec[n] = s->act[i].rec;
			d->dtagd_rec[n++].dtrd_offset -= a->base;
		}
	} else if (cmd == CMD(DTRACEIOC_FORMAT)) {
		dtrace_fmtdesc_t *f = arg;
		int len;

		if (f->dtfd_format == 0 || f->dtfd_format > M.nfmt)
			return (errno = EINVAL, -1);
		len = strlen(M.fmt[f->dtfd_format - 1]) + 1;
		if (len > f->dtfd_length)
			f->dtfd_length = len;
		else
			memcpy(f->dtfd_string, M.fmt[f->dtfd_format - 1], len);
	} else if (cmd == CMD(DTRACEIOC_DOFGET)) {
		dof_hdr_t **pdof = arg, *dof;
		size_t len = sizeof (dof_hdr_t) + 64 +
		    sizeof (dof_optdesc_t) * DTRACEOPT_MAX;
		dof_sec_t *sec;
		dof_optdesc_t *o;

		dof = calloc(1, len);
		assert(dof != NULL && sizeof (dof_sec_t) <= 64);
		memcpy(dof->dofh_ident, "\177DOF", 4);
		dof->dofh_ident[DOF_ID_MODEL] = DOF_MODEL_NATIVE;
		dof->dofh_ident[DOF_ID_ENCODING] = DOF_ENCODE_NATIVE;
		dof->dofh_ident[DOF_ID_VERSION] = DOF_VERSION;
		dof->dofh_hdrsize = sizeof (dof_hdr_t);
		dof->dofh_secsize = sizeof (dof_sec_t);
		dof->dofh_secnum = 1;
		dof->dofh_secoff = sizeof (dof_hdr_t);
		dof->dofh_loadsz = dof->dofh_filesz = len;
		sec = (dof_sec_t *)(dof + 1);
		sec->dofs_type = DOF_SECT_OPTDESC;
		sec->dofs_align = sizeof (uint64_t);
		sec->dofs_entsize = sizeof (dof_optdesc_t);
		sec->dofs_offset = sizeof (dof_hdr_t) + 64;
		sec->dofs_size = sizeof (dof_optdesc_t) * DTRACEOPT_MAX;
		o = (dof_optdesc_t *)((char *)dof + sec->dofs_offset);
		for (i = 0; i < DTRACEOPT_MAX; i++) {
			o[i].dofo_option = i;
			o[i].dofo_strtab = DOF_SECIDX_NONE;
			o[i].dofo_value = M.opt[i];
		}
		memcpy(*pdof, dof, (*pdof)->dofh_loadsz < len ?
		    (*pdof)->dofh_loadsz : len);
		free(dof);
	} else if (cmd == CMD(DTRACEIOC_GO)) {
		int64_t *opt = M.opt;

		if (M.activity != ACT_INACTIVE)
			return (errno = EBUSY, -1);
		if (M.nagg == 0)
			opt[DTRACEOPT_AGGSIZE] = 0;
		else if (opt[DTRACEOPT_BUFSIZE] == DTRACEOPT_UNSET ||
		    opt[DTRACEOPT_BUFSIZE] < M.needed)
			opt[DTRACEOPT_BUFSIZE] = M.needed;
		if (!M.speculates && opt[DTRACEOPT_SPECSIZE] !=
		    DTRACEOPT_UNSET)
			opt[DTRACEOPT_SPECSIZE] = 0;
		/* dtrace_state_prereserve() */
		M.reserve = 0;
		if (opt[DTRACEOPT_BUFPOLICY] == DTRACEOPT_BUFPOLICY_FILL)
			for (i = 0; i < M.necb; i++)
				if (M.ecb[i].probe == 1)
					M.reserve += M.set[M.ecb[i].set].
					    needed + M.set[M.ecb[i].set].align;
		for (i = 0; i < M.ncpu; i++) {
			buffer_alloc(&M.buf[i], opt[DTRACEOPT_BUFSIZE] ==
			    DTRACEOPT_UNSET ? 0 : opt[DTRACEOPT_BUFSIZE]);
			buffer_alloc(&M.aggbuf[i], opt[DTRACEOPT_AGGSIZE] ==
			    DTRACEOPT_UNSET ? 0 : opt[DTRACEOPT_AGGSIZE]);
		}
		M.activity = ACT_ACTIVE;
		*(processorid_t *)arg = M.begancpu;
	} else if (cmd == CMD(DTRACEIOC_STOP)) {
		if (M.activity == ACT_INACTIVE || M.activity == ACT_STOPPED)
			return (errno = EINVAL, -1);
		M.activity = ACT_STOPPED;
		*(processorid_t *)arg = M.endcpu;
	} else if (cmd == CMD(DTRACEIOC_STATUS)) {
		dtrace_status_t *st = arg;

		memset(st, 0, sizeof (*st));
		if (M.activity == ACT_INACTIVE)
			return (errno = ENOENT, -1);
		st->dtst_exiting = M.exiting;
		st->dtst_errors = M.status_errors;
		for (i = 0; i < M.ncpu; i++) {
			if (M.buf[i].flags & BUF_FULL)
				st->dtst_filled++;
			st->dtst_errors += M.buf[i].errors;
		}
	} else if (cmd == CMD(DTRACEIOC_BUFSNAP)) {
		M.bufsnaps++;
		error = snap(arg, &M.buf[(*(dtrace_bufdesc_t **)arg)->
		    dtbd_cpu % NCPU_MODEL], 0);
	} else if (cmd == CMD(DTRACEIOC_AGGSNAP)) {
		M.aggsnaps++;
		error = snap(arg, &M.aggbuf[(*(dtrace_bufdesc_t **)arg)->
		    dtbd_cpu % NCPU_MODEL], 1);
	} else if (cmd == CMD(DTRACEIOC_HANDLE_ID)) {
		dtrace_handle_lifetime_t *h = arg;

		if (M.hid_mode == 5)
			return (errno = ENOTTY, -1);
		*h = M.hid;
		if (M.hid_mode == 1)
			h->generation[0] = h->generation[1] = 0;
		else if (M.hid_mode == 2)
			h->serial = 0;
		else if (M.hid_mode == 3)
			h->retired = 1;
		else if (M.hid_mode == 4)
			h->reserved = 1;
	} else if (cmd == CMD(DTRACEIOC_HANDLE_QUERY)) {
		/* dtrace_handle_query() */
		dtrace_handle_lifetime_t *q = arg;

		M.hqueries++;
		if (q->retired != 0 || q->reserved != 0 || q->serial == 0)
			return (errno = EINVAL, -1);
		if (M.hq_mode == 5 || q->serial > M.hid.serial ||
		    memcmp(q->generation, M.hid.generation,
		    sizeof (q->generation)) != 0)
			return (errno = ESTALE, -1);
		if (!M.hid_live || q->serial != M.hid.serial)
			q->retired = 1;
		if (M.hq_mode == 1)
			q->serial++;
		else if (M.hq_mode == 2)
			q->generation[1] ^= 1;
		else if (M.hq_mode == 3)
			q->retired = 2;
		else if (M.hq_mode == 4)
			q->reserved = 1;
	} else if (cmd == CMD(DTRACEIOC_DRAINABLE)) {
		M.drainables++;
		error = M.activity != ACT_ACTIVE ? EBUSY :
		    M.speculates ? EOPNOTSUPP : 0;
	} else {
		M.unexpected++;
		M.last_unexpected = cmd;
		error = ENOTTY;
	}
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

/*
 * Symbol lookup by address.  As in the native dtrace_lookup_by_addr(), a NULL
 * GElf_Sym asks only for the containing module and a NULL syminfo is allowed.
 */
static int
model_lookup(void *varg, GElf_Addr addr, GElf_Sym *sym, dtrace_syminfo_t *si)
{
	static const struct {
		const char *object;
		GElf_Addr base;
		GElf_Xword size;
	} mods[] = {
		{ "kernel", 0xffffffff80000000ULL, 0x100000 },
		{ "zfs", 0xffffffff90000000ULL, 0x100000 },
	};
	static const struct {
		GElf_Addr base;
		GElf_Xword size;
		const char *name;
	} syms[] = {
		{ 0xffffffff80001000ULL, 0x100, "vm_fault" },
		{ 0xffffffff80002000ULL, 0x40, "sched_tick" },
		{ 0xffffffff90000000ULL, 0x80, "zio_wait" },
	};
	size_t i, m;

	(void) varg;
	for (m = 0; m < sizeof (mods) / sizeof (mods[0]); m++)
		if (addr >= mods[m].base && addr < mods[m].base + mods[m].size)
			break;
	if (m == sizeof (mods) / sizeof (mods[0]))
		return (-1);
	if (sym == NULL) {
		if (si != NULL) {
			si->dts_object = mods[m].object;
			si->dts_name = NULL;
			si->dts_id = 0;
		}
		return (0);
	}
	for (i = 0; i < sizeof (syms) / sizeof (syms[0]); i++) {
		if (addr < syms[i].base || addr >= syms[i].base + syms[i].size)
			continue;
		memset(sym, 0, sizeof (*sym));
		sym->st_value = syms[i].base;
		sym->st_size = syms[i].size;
		sym->st_info = GELF_ST_INFO(STB_GLOBAL, STT_FUNC);
		if (si != NULL) {
			si->dts_object = mods[m].object;
			si->dts_name = syms[i].name;
			si->dts_id = 0;
		}
		return (0);
	}
	return (-1);
}

static int
model_status(void *varg, processorid_t cpu)
{
	(void) varg;
	return (cpu >= 0 && cpu < M.ncpu ? 1 : -1);
}

static long
model_sysconf(void *varg, int name)
{
	(void) varg;
	if (name == _SC_NPROCESSORS_CONF || name == _SC_NPROCESSORS_ONLN)
		return (M.ncpu);
	return (sysconf(name));
}

static const dtrace_vector_t vector = {
	.dtv_ioctl = model_ioctl,
	.dtv_lookup_by_addr = model_lookup,
	.dtv_status = model_status,
	.dtv_sysconf = model_sysconf,
};

/* ------------------------------------------------------------------ */
/* Cases.                                                              */

static int failures, passes;
/* Callback behaviour: 0 consume, 1 skip beta, 2 abort, 3 invalid value. */
static int probe_mode, rec_mode, log_flow, use_oformat;
static char *events;
static size_t eventslen;
static FILE *eventfp;

static void
reset_model(void)
{
	int i, maxid = 0;
	size_t len = sizeof (maxid);

	for (i = 0; i < NCPU_MODEL; i++) {
		free(M.buf[i].data);
		free(M.aggbuf[i].data);
	}
	for (i = 0; i < M.nfmt; i++)
		free(M.fmt[i]);
	memset(&M, 0, sizeof (M));
	/* The library sizes its CPU loops from kern.smp.maxid directly. */
	if (sysctlbyname("kern.smp.maxid", &maxid, &len, NULL, 0) != 0)
		maxid = 0;
	M.ncpu = maxid + 1;
	assert(M.ncpu >= 2 && M.ncpu <= NCPU_MODEL);
	for (i = 0; i < DTRACEOPT_MAX; i++)
		M.opt[i] = DTRACEOPT_UNSET;
	M.opt[DTRACEOPT_BUFPOLICY] = DTRACEOPT_BUFPOLICY_SWITCH;
	M.opt[DTRACEOPT_BUFRESIZE] = DTRACEOPT_BUFRESIZE_AUTO;
	M.opt[DTRACEOPT_CPU] = DTRACE_CPUALL;
	M.opt[DTRACEOPT_STRSIZE] = 256;
	M.opt[DTRACEOPT_STACKFRAMES] = 20;
	M.opt[DTRACEOPT_USTACKFRAMES] = 20;
	M.opt[DTRACEOPT_JSTACKFRAMES] = 50;
	M.opt[DTRACEOPT_JSTACKSTRSIZE] = 512;
	M.opt[DTRACEOPT_IMMSTACKSTRSIZE] = 64;
	M.opt[DTRACEOPT_IMMSTACKFRAMES] = 20;
	M.begancpu = 0;
	M.endcpu = 1;
	M.hid.generation[0] = 0x5b5d0001;
	M.hid.generation[1] = 0x20261021;
	M.hid.serial = 7;
	M.hid_live = 1;
	probe_mode = rec_mode = log_flow = use_oformat = 0;
	if (eventfp != NULL)
		fclose(eventfp);
	free(events);
	events = NULL;
	eventslen = 0;
	eventfp = open_memstream(&events, &eventslen);
	assert(eventfp != NULL);
}

static void
event(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(eventfp, fmt, ap);
	va_end(ap);
}

static int
probe_cb(const dtrace_probedata_t *data, void *arg)
{
	dtrace_probedesc_t *pd = data->dtpda_pdesc;

	(void) arg;
	event("probe cpu=%d %s:%s:%s:%s\n", data->dtpda_cpu,
	    pd->dtpd_provider, pd->dtpd_mod, pd->dtpd_func, pd->dtpd_name);
	if (log_flow)
		event("flow %d indent %d prefix \"%s\"\n", data->dtpda_flow,
		    data->dtpda_indent, data->dtpda_prefix);
	if (use_oformat)
		dtrace_oformat_probe(data->dtpda_handle, data,
		    data->dtpda_cpu, pd);
	if (probe_mode == 1 && strcmp(pd->dtpd_func, "beta") == 0)
		return (DTRACE_CONSUME_NEXT);
	if (probe_mode == 2)
		return (DTRACE_CONSUME_ABORT);
	if (probe_mode == 3)
		return (42);
	return (DTRACE_CONSUME_THIS);
}

static int
rec_cb(const dtrace_probedata_t *data, const dtrace_recdesc_t *rec,
    void *arg)
{
	(void) data;
	(void) arg;
	if (rec == NULL)
		event("end-of-probe\n");
	else if (rec->dtrd_action == DTRACEACT_EXIT) {
		/* dtrace(1) chewrec() consumes exit() without printing it. */
		event("exit %d\n", *(int *)data->dtpda_data);
		return (DTRACE_CONSUME_NEXT);
	}
	if (rec != NULL && rec_mode == 1)
		return (DTRACE_CONSUME_ABORT);
	if (rec != NULL && rec_mode == 2)
		return (17);
	return (rec == NULL ? DTRACE_CONSUME_NEXT : DTRACE_CONSUME_THIS);
}

static int
drop_cb(const dtrace_dropdata_t *d, void *arg)
{
	(void) arg;
	event("drop cpu=%d kind=%d n=%" PRIu64 ": %s", d->dtdda_cpu,
	    d->dtdda_kind, d->dtdda_drops, d->dtdda_msg);
	return (DTRACE_HANDLE_OK);
}

static int
err_cb(const dtrace_errdata_t *d, void *arg)
{
	(void) arg;
	event("error: %s", d->dteda_msg);
	return (DTRACE_HANDLE_OK);
}

struct session {
	dtrace_hdl_t *dtp;
	FILE *out;
	char *text;
	size_t len;
};

static void
fail(const char *name, const char *what, const char *expected,
    const char *actual)
{
	failures++;
	printf("FAIL %s: %s\n--- expected ---\n%s--- actual ---\n%s----\n",
	    name, what, expected ? expected : "(null)",
	    actual ? actual : "(null)");
}

static int
open_session(struct session *s, const char *name, const char *const *opts,
    const char *program)
{
	dtrace_prog_t *prog;
	dtrace_proginfo_t info;
	int err, i;

	memset(s, 0, sizeof (*s));
	s->dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS | DTRACE_O_LP64,
	    &err, &vector, &M);
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
	if (dtrace_handle_drop(s->dtp, drop_cb, NULL) != 0 ||
	    dtrace_handle_err(s->dtp, err_cb, NULL) != 0) {
		fail(name, "handlers", "", dtrace_errmsg(s->dtp,
		    dtrace_errno(s->dtp)));
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
	if (dtrace_go(s->dtp) != 0) {
		fail(name, "go", "", dtrace_errmsg(s->dtp,
		    dtrace_errno(s->dtp)));
		return (-1);
	}
	return (0);
}

static int
consume(struct session *s)
{
	return (dtrace_consume(s->dtp, s->out, probe_cb, rec_cb, NULL));
}

static void
check(const char *name, struct session *s, const char *want_out,
    const char *want_events)
{
	if (s->out != NULL)
		fflush(s->out);
	fflush(eventfp);
	if (want_out != NULL && strcmp(s->text, want_out) != 0)
		fail(name, "output", want_out, s->text);
	else if (want_events != NULL && strcmp(events, want_events) != 0)
		fail(name, "events", want_events, events);
	else if (M.unexpected != 0) {
		char buf[64];

		snprintf(buf, sizeof (buf), "%u unexpected ioctl, last %#lx\n",
		    M.unexpected, M.last_unexpected);
		fail(name, "model", "", buf);
	} else {
		passes++;
		printf("PASS %s\n", name);
	}
}

static void
close_session(struct session *s)
{
	if (s->dtp != NULL)
		dtrace_close(s->dtp);
	if (s->out != NULL)
		fclose(s->out);
	free(s->text);
}

#define	VALS(...)	(const struct val[]){ __VA_ARGS__ }, \
	(int)(sizeof ((const struct val[]){ __VA_ARGS__ }) / sizeof (struct val))

/*
 * Expected text is assembled from the documented record formats: non-quiet
 * trace() is " %8d" for 4-byte and " %16lld" for 8-byte values, aggregation
 * string keys are "  %-50s", aggregation values " %16lld", and every
 * aggregation tuple ends with a newline.  The library prints no newline after
 * a probe; dtrace(1) does that from its callbacks.
 */
static char *xbuf;
static size_t xlen;
static FILE *xfp;

static void
xbegin(void)
{
	if (xfp != NULL)
		fclose(xfp);
	free(xbuf);
	xbuf = NULL;
	xfp = open_memstream(&xbuf, &xlen);
	assert(xfp != NULL);
}

static const char *
xend(void)
{
	fflush(xfp);
	return (xbuf);
}

#define	X(...)	fprintf(xfp, __VA_ARGS__)

/* Raw bytes appended to a principal buffer, for malformed-buffer cases. */
static void
raw(int cpu, const void *p, size_t len)
{
	struct mbuf *b = &M.buf[cpu];

	assert(b->offset + len <= b->size);
	memcpy(b->data + b->offset, p, len);
	b->offset += len;
}

/* Library errors are compared by their public dtrace_errmsg() text. */
#define	MSG_DIRABORT	"Abort explicitly directed"
#define	MSG_BADRVAL	"Invalid return value from callback"

static void
expect_rc(const char *name, struct session *s, int rc, const char *want)
{
	const char *msg = dtrace_errmsg(s->dtp, dtrace_errno(s->dtp));

	if (rc != -1 || strcmp(msg, want) != 0) {
		char buf[256];

		snprintf(buf, sizeof (buf), "rc %d: %s\n", rc, msg);
		fail(name, "return", want, buf);
		s->text[0] = '\0';
	}
}

#define	TRACE_PROG	"test:::entry { trace(arg0); }"

/*
 * Not stopped: the BEGIN CPU is consumed first, in buffer order, then the
 * other CPUs.  After stopping, the END CPU is consumed last.
 */
static void
case_ordering(void)
{
	const char *name = "begin-end-cpu-ordering";
	struct session s;

	reset_model();
	if (open_session(&s, name, NULL,
	    "BEGIN { trace(1); } test:::entry { trace(arg0); } "
	    "END { trace(3); }") == 0) {
		fire(1, "test:kernel:alpha:entry", 0, VALS(N(20)));
		fire(0, "dtrace:::BEGIN", 0, VALS(N(1)));
		fire(0, "test:kernel:beta:entry", 0, VALS(N(10)));
		if (consume(&s) != 0)
			fail(name, "consume", "", "");
		fire(1, "dtrace:::END", 0, VALS(N(3)));
		if (dtrace_stop(s.dtp) != 0 || consume(&s) != 0)
			fail(name, "stop", "", "");
		xbegin();
		X(" %8d", 1);
		X(" %16lld", 10LL);
		X(" %16lld", 20LL);
		X(" %8d", 3);
		check(name, &s, xend(),
		    "probe cpu=0 dtrace:::BEGIN\nend-of-probe\n"
		    "probe cpu=0 test:kernel:beta:entry\nend-of-probe\n"
		    "probe cpu=1 test:kernel:alpha:entry\nend-of-probe\n"
		    "probe cpu=1 dtrace:::END\nend-of-probe\n");
	}
	close_session(&s);
}

/*
 * Stopped before the first consume with BEGIN and END on one CPU: BEGIN is
 * consumed alone, then the other CPUs, then the rest of the BEGIN CPU.
 */
static void
case_begin_end_same_cpu(void)
{
	const char *name = "begin-end-same-cpu";
	struct session s;

	reset_model();
	M.endcpu = 0;
	if (open_session(&s, name, NULL,
	    "BEGIN { trace(1); } test:::entry { trace(arg0); } "
	    "END { trace(3); }") == 0) {
		fire(0, "dtrace:::BEGIN", 0, VALS(N(1)));
		fire(0, "test:kernel:beta:entry", 0, VALS(N(10)));
		fire(1, "test:kernel:alpha:entry", 0, VALS(N(20)));
		fire(0, "dtrace:::END", 0, VALS(N(3)));
		if (dtrace_stop(s.dtp) != 0 || consume(&s) != 0)
			fail(name, "consume", "", "");
		xbegin();
		X(" %8d", 1);
		X(" %16lld", 20LL);
		X(" %16lld", 10LL);
		X(" %8d", 3);
		check(name, &s, xend(),
		    "probe cpu=0 dtrace:::BEGIN\nend-of-probe\n"
		    "probe cpu=1 test:kernel:alpha:entry\nend-of-probe\n"
		    "probe cpu=0 test:kernel:beta:entry\nend-of-probe\n"
		    "probe cpu=0 dtrace:::END\nend-of-probe\n");
	}
	close_session(&s);
}

/*
 * The library's ERROR enabling follows the user ECBs.  Its five records are
 * the faulting EPID, action index, DIF offset, fault and address.
 */
static void
case_error_handler(void)
{
	const char *name = "error-records";
	struct session s;

	reset_model();
	if (open_session(&s, name, NULL, TRACE_PROG) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		fire(0, "dtrace:::ERROR", 0, VALS(N(1), N(1), N(8),
		    N(DTRACEFLT_BADADDR), N(0x10)));
		fire(0, "dtrace:::ERROR", 0, VALS(N(2), N(0), N(-1),
		    N(DTRACEFLT_DIVZERO), N(0)));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X(" %16lld", 1LL);
		check(name, &s, xend(),
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n"
		    "error: error on enabled probe ID 1 (ID 4: "
		    "test:kernel:alpha:entry): invalid address (0x10) in "
		    "action #1 at DIF offset 8\n"
		    "error: error on enabled probe ID 2 (ID 6: "
		    "test:kernel:beta:entry): divide-by-zero in predicate\n");
	}
	close_session(&s);
}

/* With temporal ordering, records from all CPUs interleave by time. */
static void
case_temporal(void)
{
	const char *name = "temporal-order";
	static const char *const opts[] = { "temporal", NULL, NULL };
	struct session s;

	reset_model();
	if (open_session(&s, name, opts, TRACE_PROG) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		fire(1, "test:kernel:alpha:entry", 0, VALS(N(2)));
		fire(0, "test:kernel:beta:entry", 0, VALS(N(3)));
		fire(1, "test:kernel:beta:entry", 0, VALS(N(4)));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X(" %16lld %16lld %16lld %16lld", 1LL, 2LL, 3LL, 4LL);
		check(name, &s, xend(),
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n"
		    "probe cpu=1 test:kernel:alpha:entry\nend-of-probe\n"
		    "probe cpu=0 test:kernel:beta:entry\nend-of-probe\n"
		    "probe cpu=1 test:kernel:beta:entry\nend-of-probe\n");
	}
	close_session(&s);
}

/*
 * trace(arg0) needs 24 bytes (12-byte header, padding, 8-byte value).  A
 * 64-byte switching buffer holds two records; the rest are drops.
 */
static void
case_drops(void)
{
	const char *name = "principal-drops";
	static const char *const opts[] = { "bufsize", "64", NULL };
	struct session s;
	int i;

	reset_model();
	if (open_session(&s, name, opts, TRACE_PROG) == 0) {
		for (i = 1; i <= 4; i++)
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(i)));
		if (consume(&s) != 0)
			fail(name, "consume", "", "");
		xbegin();
		X(" %16lld %16lld", 1LL, 2LL);
		check(name, &s, xend(),
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n"
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n"
		    "drop cpu=0 kind=0 n=2: 2 drops on CPU 0\n");
	}
	close_session(&s);
}

/*
 * A 64-byte ring keeps the newest records.  Five 24-byte records leave
 * record 5 at offset 0, record 4 at offset 24 and a zeroed tail; the oldest
 * retained record (4) starts at offset 24.
 */
static void
case_ring(void)
{
	const char *name = "ring-wrap";
	static const char *const opts[] = { "bufpolicy", "ring",
	    "bufsize", "64", NULL };
	struct session s;
	int i;

	reset_model();
	if (open_session(&s, name, opts, TRACE_PROG) == 0) {
		for (i = 1; i <= 5; i++)
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(i)));
		if (M.buf[0].xamot != 24 || M.buf[0].offset != 24 ||
		    !(M.buf[0].flags & BUF_WRAPPED))
			fail(name, "model wrap state", "", "");
		if (dtrace_stop(s.dtp) != 0 || consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X(" %16lld %16lld", 4LL, 5LL);
		check(name, &s, xend(),
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n"
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n");
	}
	close_session(&s);
}

/* A fill buffer stops recording when full, without counting drops. */
static void
case_fill(void)
{
	const char *name = "fill-policy";
	static const char *const opts[] = { "bufpolicy", "fill",
	    "bufsize", "64", NULL };
	struct session s;
	int i;

	reset_model();
	if (open_session(&s, name, opts, TRACE_PROG) == 0) {
		for (i = 1; i <= 4; i++)
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(i)));
		if (!(M.buf[0].flags & BUF_FULL) || M.buf[0].drops != 0)
			fail(name, "model fill state", "", "");
		if (dtrace_stop(s.dtp) != 0 || consume(&s) != 0)
			fail(name, "consume", "", "");
		xbegin();
		X(" %16lld %16lld", 1LL, 2LL);
		check(name, &s, xend(),
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n"
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n");
	}
	close_session(&s);
}

/* exit() reaches the record callback, and STATUS then reports exiting. */
static void
case_exit(void)
{
	const char *name = "exit-status";
	struct session s;

	reset_model();
	if (open_session(&s, name, NULL, "test:::entry { exit(7); }") == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(7)));
		if (consume(&s) != 0)
			fail(name, "consume", "", "");
		if (dtrace_status(s.dtp) != DTRACE_STATUS_EXITED)
			fail(name, "status", "DTRACE_STATUS_EXITED", "");
		check(name, &s, "",
		    "probe cpu=0 test:kernel:alpha:entry\nexit 7\n"
		    "end-of-probe\n");
	}
	close_session(&s);
}

static void
case_printf_quiet(void)
{
	const char *name = "printf-quiet";
	static const char *const opts[] = { "quiet", NULL, NULL };
	struct session s;

	reset_model();
	if (open_session(&s, name, opts,
	    "test:::entry { printf(\"%s:%d:%x\\n\", probefunc, arg0, arg1); }")
	    == 0) {
		fire(0, "test:kernel:alpha:entry", 0,
		    VALS(S("alpha"), N(-5), N(255)));
		fire(0, "test:kernel:beta:entry", 0,
		    VALS(S("beta"), N(12), N(0xbeef)));
		if (consume(&s) != 0)
			fail(name, "consume", "", "");
		check(name, &s, "alpha:-5:ff\nbeta:12:beef\n",
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n"
		    "probe cpu=0 test:kernel:beta:entry\nend-of-probe\n");
	}
	close_session(&s);
}

static void
case_callbacks(void)
{
	static const struct {
		const char *name;
		int probe, rec, rc;
		const char *err;
		const char *events;
	} modes[] = {
		{ "callback-skip-probe", 1, 0, 0, NULL,
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n"
		    "probe cpu=0 test:kernel:beta:entry\n"
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n" },
		{ "callback-probe-abort", 2, 0, -1, MSG_DIRABORT,
		    "probe cpu=0 test:kernel:alpha:entry\n" },
		{ "callback-probe-invalid", 3, 0, -1, MSG_BADRVAL,
		    "probe cpu=0 test:kernel:alpha:entry\n" },
		{ "callback-record-abort", 0, 1, -1, MSG_DIRABORT,
		    "probe cpu=0 test:kernel:alpha:entry\n" },
		{ "callback-record-invalid", 0, 2, -1, MSG_BADRVAL,
		    "probe cpu=0 test:kernel:alpha:entry\n" },
	};
	size_t i;

	for (i = 0; i < sizeof (modes) / sizeof (modes[0]); i++) {
		struct session s;
		int rc;

		reset_model();
		probe_mode = modes[i].probe;
		rec_mode = modes[i].rec;
		if (open_session(&s, modes[i].name, NULL, TRACE_PROG) == 0) {
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
			fire(0, "test:kernel:beta:entry", 0, VALS(N(2)));
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(3)));
			rc = consume(&s);
			xbegin();
			if (modes[i].rc == 0) {
				if (rc != 0)
					fail(modes[i].name, "consume", "", "");
				X(" %16lld %16lld", 1LL, 3LL);
			} else {
				fflush(s.out);
				expect_rc(modes[i].name, &s, rc, modes[i].err);
			}
			check(modes[i].name, &s, xend(), modes[i].events);
		}
		close_session(&s);
	}
}

/* An EPID the kernel never issued fails consumption via EPROBE. */
static void
case_bad_epid(void)
{
	const char *name = "unknown-epid";
	struct session s;
	dtrace_rechdr_t h = { 50, 0, 1 };
	uint64_t pad[2] = { 0, 0 };

	reset_model();
	if (open_session(&s, name, NULL, TRACE_PROG) == 0) {
		raw(0, &h, sizeof (h));
		raw(0, pad, sizeof (pad) - 4);
		fflush(s.out);
		expect_rc(name, &s, consume(&s), strerror(EINVAL));
		check(name, &s, "", "");
	}
	close_session(&s);
}

/*
 * Keyed aggregations merge across CPUs.  The default sort is by variable,
 * then value: @c is beta (1) then alpha (3); @s is alpha (13) then beta (100).
 */
static void
case_aggregations(void)
{
	const char *name = "keyed-aggregations";
	struct session s;

	reset_model();
	if (open_session(&s, name, NULL,
	    "test:::entry { @c[probefunc] = count(); "
	    "@s[probefunc] = sum(arg0); }") == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"),
		    AGG(0, 1), N(2), S("alpha"), AGG(5, 1)));
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"),
		    AGG(0, 1), N(2), S("alpha"), AGG(7, 1)));
		fire(1, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"),
		    AGG(0, 1), N(2), S("alpha"), AGG(1, 1)));
		fire(0, "test:kernel:beta:entry", 0, VALS(N(1), S("beta"),
		    AGG(0, 1), N(2), S("beta"), AGG(100, 1)));
		if (consume(&s) != 0 || dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "aggregate", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X("  %-50s %16lld\n", "beta", 1LL);
		X("  %-50s %16lld\n", "alpha", 3LL);
		X("  %-50s %16lld\n", "alpha", 13LL);
		X("  %-50s %16lld\n", "beta", 100LL);
		check(name, &s, xend(), "");
	}
	close_session(&s);
}

/*
 * Keyless avg/min/max/stddev over 2, 4 and 9: mean 5, minimum 2, maximum 9,
 * and standard deviation isqrt(101 / 3 - 25) = 2.
 */
static void
case_agg_kinds(void)
{
	const char *name = "aggregation-functions";
	struct session s;
	static const int64_t v[] = { 2, 4, 9 };
	int i;

	reset_model();
	if (open_session(&s, name, NULL,
	    "test:::entry { @a = avg(arg0); @mn = min(arg0); "
	    "@mx = max(arg0); @sd = stddev(arg0); }") == 0) {
		for (i = 0; i < 3; i++)
			fire(i == 2, "test:kernel:alpha:entry", 0,
			    VALS(N(1), AGG(v[i], 1), N(2), AGG(v[i], 1),
			    N(3), AGG(v[i], 1), N(4), AGG(v[i], 1)));
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "aggregate", "", "");
		xbegin();
		X(" %16lld\n %16lld\n %16lld\n %16llu\n", 5LL, 2LL, 9LL, 2ULL);
		check(name, &s, xend(), "");
	}
	close_session(&s);
}

/*
 * Histogram output is reduced to "key" lines and "label count" rows, as in
 * printf-records-offline.py; distribution bars and padding are not compared.
 */
static char *
canon_hist(const char *text)
{
	char *out = NULL, *copy = strdup(text), *line, *save = NULL;
	size_t len = 0;
	FILE *fp = open_memstream(&out, &len);

	assert(fp != NULL && copy != NULL);
	for (line = strtok_r(copy, "\n", &save); line != NULL;
	    line = strtok_r(NULL, "\n", &save)) {
		char *bar = strchr(line, '|'), label[64], *p;
		long long count;

		while (*line == ' ')
			line++;
		for (p = line + strlen(line); p > line && p[-1] == ' ';)
			*--p = '\0';
		if (*line == '\0' || strstr(line, "Distribution") != NULL)
			continue;
		if (bar == NULL) {
			fprintf(fp, "key %s\n", line);
			continue;
		}
		*bar = '\0';
		snprintf(label, sizeof (label), "%s", line);
		for (p = label + strlen(label); p > label && p[-1] == ' ';)
			*--p = '\0';
		p = strrchr(bar + 1, ' ');
		count = strtoll(p != NULL ? p + 1 : bar + 1, NULL, 10);
		for (p = bar + 1; *p == '@' || *p == ' '; p++)
			continue;
		fprintf(fp, "%s %lld\n", label, count);
	}
	fclose(fp);
	free(copy);
	return (out);
}

/*
 * quantize: alpha 1, 2, 3, 3 gives buckets 1:1 and 2:3; beta -1, 0 gives
 * -1:1 and 0:1.  Weighted totals (7 and -1) put beta first.  lquantize(arg0,
 * 0, 10, 2) and llquantize(arg0, 10, 0, 2, 10) see all six values.  Rows run
 * from one bucket below the first nonzero bucket to one above the last.
 */
static void
case_histograms(void)
{
	const char *name = "histogram-ingestion";
	struct session s;
	static const struct { int cpu; const char *probe, *func; int64_t v; }
	    f[] = {
		{ 0, "test:kernel:alpha:entry", "alpha", 1 },
		{ 0, "test:kernel:alpha:entry", "alpha", 2 },
		{ 0, "test:kernel:alpha:entry", "alpha", 3 },
		{ 1, "test:kernel:alpha:entry", "alpha", 3 },
		{ 1, "test:kernel:beta:entry", "beta", -1 },
		{ 0, "test:kernel:beta:entry", "beta", 0 },
	};
	char *got;
	size_t i;

	reset_model();
	if (open_session(&s, name, NULL,
	    "test:::entry { @q[probefunc] = quantize(arg0); "
	    "@l = lquantize(arg0, 0, 10, 2); "
	    "@ll = llquantize(arg0, 10, 0, 2, 10); }") == 0) {
		for (i = 0; i < sizeof (f) / sizeof (f[0]); i++) {
			struct val fn = S("");

			fn.bytes = f[i].func;
			fn.len = strlen(f[i].func) + 1;
			fire(f[i].cpu, f[i].probe, 0, (const struct val[]){
			    N(1), fn, AGG(f[i].v, 1), N(2), AGG(f[i].v, 1),
			    N(3), AGG(f[i].v, 1) }, 7);
		}
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "aggregate", "", "");
		fclose(s.out);
		s.out = NULL;
		got = canon_hist(s.text);
		free(s.text);
		s.text = got;
		check(name, &s,
		    "key beta\n-2 0\n-1 1\n0 1\n1 0\n"
		    "key alpha\n0 0\n1 1\n2 3\n4 0\n"
		    "< 0 1\n0 2\n2 3\n4 0\n"
		    "< 1 2\n1 1\n2 1\n3 2\n4 0\n", "");
	}
	close_session(&s);
}

static FILE *walkfp;

static int
walk_cb(const dtrace_aggdata_t *a, void *arg)
{
	dtrace_aggdesc_t *d = a->dtada_desc;

	(void) arg;
	assert(d->dtagd_nrecs == 4);
	fprintf(walkfp, "%lld %s %lld %lld\n", (long long)d->dtagd_varid,
	    a->dtada_data + d->dtagd_rec[1].dtrd_offset,
	    *(long long *)(a->dtada_data + d->dtagd_rec[2].dtrd_offset),
	    *(long long *)(a->dtada_data + d->dtagd_rec[3].dtrd_offset));
	return (DTRACE_AGGWALK_NEXT);
}

#define	WALK_PROG	"test:::entry { @a[probefunc, arg1] = sum(arg0); " \
	"@b[probefunc, arg1] = sum(arg2); }"

static void
fire_walk(void)
{
	fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"), N(1),
	    AGG(10, 1), N(2), S("alpha"), N(1), AGG(1, 1)));
	fire(0, "test:kernel:beta:entry", 0, VALS(N(1), S("beta"), N(1),
	    AGG(20, 1), N(2), S("beta"), N(1), AGG(1, 1)));
	fire(1, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"), N(2),
	    AGG(30, 1), N(2), S("alpha"), N(2), AGG(1, 1)));
}

/*
 * Entries: @a (alpha,1)=10, (beta,1)=20, (alpha,2)=30; @b sums 1 each.
 * Keys order as (alpha,1) < (alpha,2) < (beta,1).  "rev" walks are exact
 * reversals of their forward orders.
 */
static void
case_walk_orders(void)
{
	static const char *const rows[] = {
		"1 alpha 1 10\n", "1 alpha 2 30\n", "1 beta 1 20\n",
		"2 alpha 1 1\n", "2 alpha 2 1\n", "2 beta 1 1\n",
	};
	static const struct {
		const char *name;
		int (*walk)(dtrace_hdl_t *, dtrace_aggregate_f *, void *);
		int order[6];
		int reverse;
	} walks[] = {
		{ "walk-keysorted", dtrace_aggregate_walk_keysorted,
		    { 0, 1, 2, 3, 4, 5 }, 0 },
		{ "walk-valsorted", dtrace_aggregate_walk_valsorted,
		    { 0, 2, 1, 3, 4, 5 }, 0 },
		{ "walk-keyvarsorted", dtrace_aggregate_walk_keyvarsorted,
		    { 0, 3, 1, 4, 2, 5 }, 0 },
		{ "walk-valvarsorted", dtrace_aggregate_walk_valvarsorted,
		    { 3, 4, 5, 0, 2, 1 }, 0 },
		{ "walk-keyrevsorted", dtrace_aggregate_walk_keyrevsorted,
		    { 0, 1, 2, 3, 4, 5 }, 1 },
		{ "walk-valrevsorted", dtrace_aggregate_walk_valrevsorted,
		    { 0, 2, 1, 3, 4, 5 }, 1 },
		{ "walk-keyvarrevsorted",
		    dtrace_aggregate_walk_keyvarrevsorted,
		    { 0, 3, 1, 4, 2, 5 }, 1 },
		{ "walk-valvarrevsorted",
		    dtrace_aggregate_walk_valvarrevsorted,
		    { 3, 4, 5, 0, 2, 1 }, 1 },
	};
	size_t i;
	int j;

	for (i = 0; i < sizeof (walks) / sizeof (walks[0]); i++) {
		struct session s;

		reset_model();
		if (open_session(&s, walks[i].name, NULL, WALK_PROG) != 0) {
			close_session(&s);
			continue;
		}
		fire_walk();
		walkfp = s.out;
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    walks[i].walk(s.dtp, walk_cb, NULL) != 0)
			fail(walks[i].name, "walk", "", "");
		xbegin();
		for (j = 0; j < 6; j++)
			X("%s", rows[walks[i].order[walks[i].reverse ?
			    5 - j : j]]);
		check(walks[i].name, &s, xend(), "");
		close_session(&s);
	}
}

/*
 * Value-first walks over aggregations of different kinds order entries by
 * key count, then aggregating action (count before sum), then value; they
 * used to abort on an assertion.  @c counts and @s sums share keys.
 */
static void
case_walk_mixed_kinds(void)
{
	const char *name = "walk-valvar-mixed-kinds";
	struct session s;

	reset_model();
	if (open_session(&s, name, NULL,
	    "test:::entry { @c[probefunc, arg1] = count(); "
	    "@s[probefunc, arg1] = sum(arg0); }") == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"),
		    N(1), AGG(0, 1), N(2), S("alpha"), N(1), AGG(10, 1)));
		fire(0, "test:kernel:beta:entry", 0, VALS(N(1), S("beta"),
		    N(1), AGG(0, 1), N(2), S("beta"), N(1), AGG(5, 1)));
		fire(1, "test:kernel:beta:entry", 0, VALS(N(1), S("beta"),
		    N(1), AGG(0, 1), N(2), S("beta"), N(1), AGG(5, 1)));
		walkfp = s.out;
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_walk_valvarsorted(s.dtp, walk_cb,
		    NULL) != 0 ||
		    dtrace_aggregate_walk_valvarrevsorted(s.dtp, walk_cb,
		    NULL) != 0)
			fail(name, "walk", "", "");
		check(name, &s,
		    "1 alpha 1 1\n1 beta 1 2\n2 alpha 1 10\n2 beta 1 10\n"
		    "2 beta 1 10\n2 alpha 1 10\n1 beta 1 2\n1 alpha 1 1\n", "");
	}
	close_session(&s);
}

/* Consumer sort options steer dtrace_aggregate_print(). */
static void
case_sort_options(void)
{
	static const struct {
		const char *name;
		const char *opts[5];
		int order[6];
	} cases[] = {
		{ "sort-aggsortkey", { "aggsortkey", NULL, NULL },
		    { 0, 1, 2, 3, 4, 5 } },
		{ "sort-aggsortkeypos", { "aggsortkey", NULL, "aggsortkeypos",
		    "1", NULL }, { 0, 2, 1, 3, 5, 4 } },
		{ "sort-aggsortrev", { "aggsortrev", NULL, NULL },
		    { 5, 4, 3, 1, 2, 0 } },
	};
	static const struct { const char *k; long long k1, v; } e[] = {
		{ "alpha", 1, 10 }, { "alpha", 2, 30 }, { "beta", 1, 20 },
		{ "alpha", 1, 1 }, { "alpha", 2, 1 }, { "beta", 1, 1 },
	};
	size_t i;
	int j;

	for (i = 0; i < sizeof (cases) / sizeof (cases[0]); i++) {
		struct session s;

		reset_model();
		if (open_session(&s, cases[i].name, cases[i].opts,
		    WALK_PROG) != 0) {
			close_session(&s);
			continue;
		}
		fire_walk();
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(cases[i].name, "print", "", "");
		xbegin();
		for (j = 0; j < 6; j++) {
			int k = cases[i].order[j];

			X("  %-50s %16lld %16lld\n", e[k].k, e[k].k1, e[k].v);
		}
		check(cases[i].name, &s, xend(), "");
		close_session(&s);
	}
}

#define	PRINTA_PROG	"test:::entry { @c[probefunc] = count(); " \
	"@s[probefunc] = sum(arg0); } " \
	"test:kernel:alpha:return { printa(\"%s %@d %@d\\n\", @c, @s); } " \
	"test:kernel:beta:return { normalize(@s, 2); printa(@s); " \
	"trunc(@c, 1); printa(@c); clear(@s); printa(@s); }"

static void
fire_printa_entries(void)
{
	fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"),
	    AGG(0, 1), N(2), S("alpha"), AGG(5, 1)));
	fire(1, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"),
	    AGG(0, 1), N(2), S("alpha"), AGG(8, 1)));
	fire(0, "test:kernel:beta:entry", 0, VALS(N(1), S("beta"),
	    AGG(0, 1), N(2), S("beta"), AGG(100, 1)));
}

/* A joined printa() orders tuples by the first aggregation's values. */
static void
case_printa_joined(void)
{
	const char *name = "printa-joined";
	static const char *const opts[] = { "quiet", NULL, NULL };
	struct session s;

	reset_model();
	if (open_session(&s, name, opts, PRINTA_PROG) == 0) {
		fire_printa_entries();
		fire(0, "test:kernel:alpha:return", 0, VALS(N(1), N(2)));
		if (dtrace_aggregate_snap(s.dtp) != 0 || consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		check(name, &s, "beta 1 100\nalpha 2 13\n",
		    "probe cpu=0 test:kernel:alpha:return\nend-of-probe\n");
	}
	close_session(&s);
}

/*
 * normalize(@s, 2) halves displayed sums (13 -> 6, 100 -> 50); trunc(@c, 1)
 * keeps the largest count (alpha); clear(@s) zeroes values but keeps keys.
 * Each default printa() starts with a newline.
 */
static void
case_libact(void)
{
	const char *name = "aggregation-actions";
	static const char *const opts[] = { "quiet", NULL, NULL };
	struct session s;

	reset_model();
	if (open_session(&s, name, opts, PRINTA_PROG) == 0) {
		fire_printa_entries();
		fire(0, "test:kernel:beta:return", 0, VALS(N(2), N(2), N(2),
		    N(1), N(1), N(1), N(2), N(2)));
		if (dtrace_aggregate_snap(s.dtp) != 0 || consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X("\n  %-50s %16lld\n  %-50s %16lld\n", "alpha", 6LL,
		    "beta", 50LL);
		X("\n  %-50s %16lld\n", "alpha", 2LL);
		X("\n  %-50s %16lld\n  %-50s %16lld\n", "alpha", 0LL,
		    "beta", 0LL);
		check(name, &s, xend(),
		    "probe cpu=0 test:kernel:beta:return\nend-of-probe\n");
	}
	close_session(&s);
}

/*
 * setopt("quiet") in a record changes formatting for the records that follow
 * it.  An unknown option is reported through the error handler.
 */
static void
case_setopt(void)
{
	const char *name = "setopt-record";
	struct session s;

	reset_model();
	if (open_session(&s, name, NULL,
	    "test:::entry { setopt(\"quiet\"); trace(arg0); } "
	    "test:::return { setopt(\"nosuchoption\", \"1\"); }") == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(S("quiet"),
		    N(0), N(5)));
		fire(0, "test:kernel:alpha:return", 0,
		    VALS(S("nosuchoption"), S("1")));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		check(name, &s, "5",
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n"
		    "probe cpu=0 test:kernel:alpha:return\n"
		    "error: error on enabled probe ID 3 (ID 5: "
		    "test:kernel:alpha:return): couldn't set option "
		    "\"nosuchoption\" to \"1\": Invalid option name\n"
		    "end-of-probe\n");
	}
	close_session(&s);
}

/* Entry probes indent by two after printing; returns unindent first. */
static void
case_flowindent(void)
{
	const char *name = "flowindent";
	static const char *const opts[] = { "flowindent", NULL, NULL };
	struct session s;

	reset_model();
	log_flow = 1;
	if (open_session(&s, name, opts,
	    "test:::entry, test:::return { trace(arg0); }") == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		fire(0, "test:kernel:beta:entry", 0, VALS(N(2)));
		fire(0, "test:kernel:beta:return", 0, VALS(N(3)));
		fire(0, "test:kernel:alpha:return", 0, VALS(N(4)));
		if (consume(&s) != 0)
			fail(name, "consume", "", "");
		xbegin();
		X(" %16lld %16lld %16lld %16lld", 1LL, 2LL, 3LL, 4LL);
		check(name, &s, xend(),
		    "probe cpu=0 test:kernel:alpha:entry\n"
		    "flow 0 indent 0 prefix \" -> \"\nend-of-probe\n"
		    "probe cpu=0 test:kernel:beta:entry\n"
		    "flow 0 indent 2 prefix \" -> \"\nend-of-probe\n"
		    "probe cpu=0 test:kernel:beta:return\n"
		    "flow 1 indent 2 prefix \" <- \"\nend-of-probe\n"
		    "probe cpu=0 test:kernel:alpha:return\n"
		    "flow 1 indent 0 prefix \" <- \"\nend-of-probe\n");
	}
	close_session(&s);
}

/*
 * Kernel stacks and symbols resolve through the vector: a symbol with an
 * offset, an exact symbol, a module without a symbol, and an unknown address.
 * Frames are indented by the default stackindent of 14.
 */
static void
case_stack_sym(void)
{
	const char *name = "stack-sym-mod";
	struct session s;
	static const uint64_t pcs[3] = { 0xffffffff80001010ULL,
	    0xffffffff80002000ULL, 0xffffffff90000400ULL };

	reset_model();
	if (open_session(&s, name, NULL,
	    "test:::entry { stack(3); sym(arg0); mod(arg1); }") == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(pcs,
		    sizeof (pcs)), N(0xffffffff80001010ULL), N(0x1234)));
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(pcs, 8),
		    N(0xffffffff90000400ULL), N(0xffffffff90000010ULL)));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X("\n%14skernel`vm_fault+0x10\n", "");
		X("%14skernel`sched_tick\n", "");
		X("%14szfs`0xffffffff90000400\n", "");
		X("  %-50s", "kernel`vm_fault");
		X("  %-50s", "0x1234");
		/* A zero PC ends the stack early. */
		X("\n%14skernel`vm_fault+0x10\n", "");
		X("  %-50s", "zfs`0xffffffff90000400");
		X("  %-50s", "zfs");
		check(name, &s, xend(), NULL);
	}
	close_session(&s);
}

/* tracemem() always prints a raw dump: header, offsets, hex and ASCII. */
static void
case_tracemem(void)
{
	const char *name = "tracemem-dump";
	struct session s;
	static const char mem[20] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 1 };
	int i;

	reset_model();
	if (open_session(&s, name, NULL,
	    "test:::entry { tracemem(arg0, 20); }") == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(mem,
		    sizeof (mem))));
		if (consume(&s) != 0)
			fail(name, "consume", "", "");
		xbegin();
		X("\n%11s", "");
		for (i = 0; i < 16; i++)
			X("  %c", "0123456789abcdef"[i]);
		X("  0123456789abcdef\n");
		X("%5s%5x:", "", 0);
		for (i = 0; i < 16; i++)
			X(" %02x", mem[i]);
		X("  ABCDEFGHIJKLMNOP\n");
		X("%5s%5x: 51 52 53 01", "", 16);
		for (i = 0; i < 12; i++)
			X("   ");
		X("  QRS.\n");
		check(name, &s, xend(), NULL);
	}
	close_session(&s);
}

/* dtrace_work() consumes, sees exit() through STATUS, stops and finishes. */
static void
case_work_loop(void)
{
	const char *name = "work-loop";
	struct session s;
	dtrace_workstatus_t st = DTRACE_WORKSTATUS_OKAY;
	int i;

	reset_model();
	if (open_session(&s, name, NULL,
	    "test:::entry { trace(arg0); } test:::return { exit(0); }") == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(9)));
		fire(0, "test:kernel:alpha:return", 0, VALS(N(0)));
		for (i = 0; i < 5 && st == DTRACE_WORKSTATUS_OKAY; i++)
			st = dtrace_work(s.dtp, s.out, probe_cb, rec_cb, NULL);
		if (st != DTRACE_WORKSTATUS_DONE || M.activity != ACT_STOPPED)
			fail(name, "status", "DONE and stopped", "");
		xbegin();
		X(" %16lld", 9LL);
		check(name, &s, xend(),
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n"
		    "probe cpu=0 test:kernel:alpha:return\nexit 0\n"
		    "end-of-probe\n");
	}
	close_session(&s);
}

/*
 * Structured output: the harness writes oformat.json, and the driver parses
 * it and checks the probe, printf message, traced value and aggregation.
 * Upstream emits the printf message and then each consumed argument as a raw
 * value (dt_consume_cpu() still processes the records it formatted).
 */
static void
case_oformat(void)
{
	const char *name = "oformat-json";
	static const char *const opts[] = { "quiet", NULL, NULL };
	struct session s;
	FILE *json;

	reset_model();
	use_oformat = 1;
	json = fopen("oformat.json", "w");
	assert(json != NULL);
	xo_set_style(NULL, XO_STYLE_JSON);
	dtrace_set_outfp(json);
	if (open_session(&s, name, opts,
	    "test:::entry { printf(\"%s:%d\\n\", probefunc, arg0); "
	    "trace(arg1); @c[probefunc] = count(); }") == 0) {
		if (dtrace_oformat_configure(s.dtp) != 0 ||
		    !dtrace_oformat(s.dtp))
			fail(name, "configure", "", "");
		dtrace_oformat_setup(s.dtp);
		fire(0, "test:kernel:alpha:entry", 0, VALS(S("alpha"), N(5),
		    N(7), N(1), S("alpha"), AGG(0, 1)));
		if (consume(&s) != 0 || dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		/* dtrace_close() calls xo_finish() for structured output. */
		dtrace_oformat_teardown(s.dtp);
		check(name, &s, "", "probe cpu=0 test:kernel:alpha:entry\n"
		    "end-of-probe\n");
	}
	close_session(&s);
	xo_set_style(NULL, XO_STYLE_TEXT);
	dtrace_set_outfp(stdout);
	fclose(json);
}

/* ---------------- Fresh-session drain and handle identity ------------ */

static int
quiesced(struct session *s, FILE *fp)
{
	dtrace_consumer_t con = { .dc_consume_probe = probe_cb,
	    .dc_consume_rec = rec_cb };

	return (dtrace_consume_quiesced(s->dtp, fp, &con, NULL));
}

static void
expect_errno(const char *name, struct session *s, int rc, int want)
{
	char buf[128];

	if (rc == -1 && dtrace_errno(s->dtp) == want)
		return;
	snprintf(buf, sizeof (buf), "rc %d errno %d\n", rc,
	    dtrace_errno(s->dtp));
	fail(name, "errno", strerror(want), buf);
	s->text[0] = '\0';
}

/*
 * One quiesced drain consumes every CPU once, checks DRAINABLE before and
 * after the aggregation snapshot, and flushes the output stream.
 */
static void
quiesced_drain_case(const char *name, const char **opts)
{
	struct session s;

	reset_model();
	if (open_session(&s, name, opts, TRACE_PROG) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		fire(1, "test:kernel:beta:entry", 0, VALS(N(2)));
		if (quiesced(&s, s.out) != 0)
			fail(name, "drain", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		if (M.drainables != 2)
			fail(name, "DRAINABLE count", "2", "");
		xbegin();
		X(" %16lld %16lld", 1LL, 2LL);
		check(name, &s, xend(),
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n"
		    "probe cpu=1 test:kernel:beta:entry\nend-of-probe\n");
	}
	close_session(&s);
}

static void
case_quiesced_drain(void)
{
	static const char *temporal[] = { "temporal", NULL, NULL };

	quiesced_drain_case("quiesced-drain", NULL);
	/* Temporal ordering flushes its queue behind the producer fence
	 * instead of refusing: the same two records, in time order. */
	quiesced_drain_case("quiesced-drain-temporal", temporal);
}

/*
 * The drain certifies principal-buffer output only.  It refuses ring
 * consumption, compiled aggregations, speculations (kernel DRAINABLE), a
 * state that is no longer active, and a failed flush; none of these may
 * consume records.
 */
static void
case_quiesced_refusals(void)
{
	static const struct {
		const char *name;
		const char *opts[5];
		const char *prog;
		int stop, devfull, err;
	} cases[] = {
		{ "quiesced-ring", { "bufpolicy", "ring", NULL }, TRACE_PROG,
		    0, 0, EOPNOTSUPP },
		{ "quiesced-aggregation", { NULL },
		    "test:::entry { trace(arg0); @c = count(); }",
		    0, 0, EOPNOTSUPP },
		{ "quiesced-speculation", { NULL },
		    "test:::entry { speculate(1); trace(arg0); }",
		    0, 0, EOPNOTSUPP },
		{ "quiesced-stopped", { NULL }, TRACE_PROG, 1, 0, EBUSY },
		{ "quiesced-flush", { NULL }, TRACE_PROG, 0, 1, ENOSPC },
	};
	size_t i;

	for (i = 0; i < sizeof (cases) / sizeof (cases[0]); i++) {
		struct session s;
		FILE *fp;

		reset_model();
		if (open_session(&s, cases[i].name, cases[i].opts,
		    cases[i].prog) != 0) {
			close_session(&s);
			continue;
		}
		if (cases[i].stop && dtrace_stop(s.dtp) != 0)
			fail(cases[i].name, "stop", "", "");
		fp = s.out;
		if (cases[i].devfull) {
			fp = fopen("/dev/full", "w");
			assert(fp != NULL);
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		}
		expect_errno(cases[i].name, &s, quiesced(&s, fp),
		    cases[i].err);
		if (cases[i].devfull)
			fclose(fp);
		/* The flush case consumed into /dev/full; others nothing. */
		check(cases[i].name, &s, "", cases[i].devfull ?
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n" : "");
		close_session(&s);
	}
}

/*
 * Before dtrace_go() draining is refused.  Options are loaded only by GO, so
 * the unset buffer policy is rejected (EOPNOTSUPP) before the inactive check.
 */
static void
case_quiesced_inactive(void)
{
	const char *name = "quiesced-inactive";
	struct session s;
	dtrace_consumer_t con = { 0 };
	int err;

	reset_model();
	memset(&s, 0, sizeof (s));
	s.dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS | DTRACE_O_LP64,
	    &err, &vector, &M);
	assert(s.dtp != NULL);
	s.out = open_memstream(&s.text, &s.len);
	expect_errno(name, &s, quiesced(&s, s.out), EOPNOTSUPP);
	if (dtrace_consume_quiesced(s.dtp, s.out, NULL, NULL) != -1 ||
	    dtrace_consume_quiesced(NULL, s.out, &con, NULL) != -1)
		fail(name, "null arguments", "-1", "");
	check(name, &s, "", "");
	close_session(&s);
}

/* After dtrace_output_discard(), the work loop refuses with ESHUTDOWN. */
static void
case_output_discard(void)
{
	const char *name = "output-discard";
	struct session s;

	reset_model();
	if (open_session(&s, name, NULL, TRACE_PROG) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		if (dtrace_output_discard(s.dtp, s.out) != 0)
			fail(name, "discard", "", "");
		if (dtrace_work(s.dtp, s.out, probe_cb, rec_cb, NULL) !=
		    DTRACE_WORKSTATUS_ERROR ||
		    dtrace_errno(s.dtp) != ESHUTDOWN)
			fail(name, "work", "ERROR/ESHUTDOWN", "");
		if (dtrace_output_discard(NULL, NULL) != -1 || errno != EINVAL)
			fail(name, "null handle", "EINVAL", "");
		check(name, &s, "", "");
	}
	close_session(&s);
}

/*
 * Handle identity comes from the kernel and is validated: a zero generation
 * or serial, a retired flag or reserved bits are protocol errors, and the
 * caller's output stays untouched on every failure.
 */
static void
case_handle_identity(void)
{
	const char *name = "handle-identity";
	struct session s;
	dtrace_handle_lifetime_t id, sentinel;
	static const struct { const char *what; int mode, err; } bad[] = {
		{ "zero generation", 1, EPROTO },
		{ "zero serial", 2, EPROTO },
		{ "retired", 3, EPROTO },
		{ "reserved", 4, EPROTO },
		{ "ioctl failure", 5, ENOTTY },
	};
	size_t i;
	int retired;

	reset_model();
	if (open_session(&s, name, NULL, TRACE_PROG) != 0) {
		close_session(&s);
		return;
	}
	memset(&sentinel, 0xa5, sizeof (sentinel));
	for (i = 0; i < sizeof (bad) / sizeof (bad[0]); i++) {
		id = sentinel;
		M.hid_mode = bad[i].mode;
		if (dtrace_handle_identity(s.dtp, &id) != -1 ||
		    dtrace_errno(s.dtp) != bad[i].err ||
		    memcmp(&id, &sentinel, sizeof (id)) != 0)
			fail(name, bad[i].what, strerror(bad[i].err), "");
	}
	M.hid_mode = 0;
	if (dtrace_handle_identity(s.dtp, NULL) != -1 ||
	    dtrace_errno(s.dtp) != EINVAL ||
	    dtrace_handle_identity(NULL, &id) != -1 || errno != EINVAL)
		fail(name, "null arguments", "EINVAL", "");
	if (dtrace_handle_identity(s.dtp, &id) != 0 ||
	    id.generation[0] != M.hid.generation[0] ||
	    id.generation[1] != M.hid.generation[1] ||
	    id.serial != M.hid.serial || id.retired != 0)
		fail(name, "valid identity", "", "");

	/* Kernel query semantics: live, then retired once the state is gone. */
	retired = -1;
	if (dtrace_handle_retired(s.dtp, &id, &retired) != 0 || retired != 0)
		fail(name, "live query", "0", "");
	M.hid_live = 0;
	if (dtrace_handle_retired(s.dtp, &id, &retired) != 0 || retired != 1)
		fail(name, "retired query", "1", "");

	/* Answers that do not echo the query, or that are malformed. */
	for (i = 1; i <= 4; i++) {
		M.hq_mode = i;
		retired = -1;
		if (dtrace_handle_retired(s.dtp, &id, &retired) != -1 ||
		    dtrace_errno(s.dtp) != EPROTO || retired != -1)
			fail(name, "malformed query answer", "EPROTO", "");
	}
	M.hq_mode = 5;
	if (dtrace_handle_retired(s.dtp, &id, &retired) != -1 ||
	    dtrace_errno(s.dtp) != ESTALE)
		fail(name, "stale query", "ESTALE", "");
	M.hq_mode = 0;

	/* Malformed caller identities never reach the kernel. */
	{
		dtrace_handle_lifetime_t q = id;
		unsigned before = M.hqueries;

		q.serial = 0;
		if (dtrace_handle_retired(s.dtp, &q, &retired) != -1 ||
		    dtrace_errno(s.dtp) != EINVAL)
			fail(name, "zero serial query", "EINVAL", "");
		q = id;
		q.retired = 1;
		if (dtrace_handle_retired(s.dtp, &q, &retired) != -1)
			fail(name, "retired query input", "EINVAL", "");
		q = id;
		q.generation[0] = q.generation[1] = 0;
		if (dtrace_handle_retired(s.dtp, &q, &retired) != -1)
			fail(name, "zero generation query", "EINVAL", "");
		q = id;
		q.reserved = 1;
		if (dtrace_handle_retired(s.dtp, &q, &retired) != -1 ||
		    dtrace_handle_retired(s.dtp, &id, NULL) != -1 ||
		    dtrace_handle_retired(s.dtp, NULL, &retired) != -1)
			fail(name, "invalid query input", "EINVAL", "");
		if (dtrace_handle_retired(NULL, &id, &retired) != -1 ||
		    errno != EINVAL)
			fail(name, "null handle", "EINVAL", "");
		if (M.hqueries != before)
			fail(name, "invalid input reached the kernel", "", "");
	}
	check(name, &s, "", "");
	close_session(&s);
}

/* ---------------- Kernel failures reported through the vector -------- */

/*
 * Open, compile, execute and start with one injected ioctl failure.  Returns
 * the failing stage (0 none, 1 compile, 2 exec, 3 go) and the library's
 * message for it.
 */
static int
try_session(struct session *s, const char *const *opts, const char *prog,
    const char **msg)
{
	dtrace_prog_t *p;
	dtrace_proginfo_t info;
	int err, i;

	memset(s, 0, sizeof (*s));
	s->dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS | DTRACE_O_LP64,
	    &err, &vector, &M);
	assert(s->dtp != NULL);
	s->out = open_memstream(&s->text, &s->len);
	(void) dtrace_setopt(s->dtp, "bufsize", "64k");
	(void) dtrace_setopt(s->dtp, "aggsize", "64k");
	for (i = 0; opts != NULL && opts[i] != NULL; i += 2)
		(void) dtrace_setopt(s->dtp, opts[i], opts[i + 1]);
	(void) dtrace_handle_err(s->dtp, err_cb, NULL);
	(void) dtrace_handle_drop(s->dtp, drop_cb, NULL);
	*msg = NULL;
	if ((p = dtrace_program_strcompile(s->dtp, prog,
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL)) == NULL)
		i = 1;
	else if (dtrace_program_exec(s->dtp, p, &info) != 0)
		i = 2;
	else if (dtrace_go(s->dtp) != 0)
		i = 3;
	else
		return (0);
	*msg = dtrace_errmsg(s->dtp, dtrace_errno(s->dtp));
	return (i);
}

static void
inject(u_long cmd, int after, int error)
{
	M.fail_cmd = CMD(cmd);
	M.fail_after = after;
	M.fail_errno = error;
}

/*
 * ENABLE and GO errnos map to the documented library errors; anything else
 * passes through.  The program is the first ENABLE, the library's ERROR
 * program the second, and the options DOF the third.
 */
static void
case_enable_go_errors(void)
{
	static const struct {
		const char *name;
		u_long cmd;
		int after, error, stage;
		const char *msg;
	} cases[] = {
		{ "exec-einval", DTRACEIOC_ENABLE, 0, EINVAL, 2,
		    "DIF program content is invalid" },
		{ "exec-efault", DTRACEIOC_ENABLE, 0, EFAULT, 2,
		    "DIF program contains invalid pointer" },
		{ "exec-e2big", DTRACEIOC_ENABLE, 0, E2BIG, 2,
		    "DIF program exceeds maximum program size" },
		{ "exec-ebusy", DTRACEIOC_ENABLE, 0, EBUSY, 2,
		    "Failed to enable probe" },
		{ "exec-eperm", DTRACEIOC_ENABLE, 0, EPERM, 2, NULL },
		{ "go-errprog-eio", DTRACEIOC_ENABLE, 1, EIO, 3, NULL },
		{ "go-options-eio", DTRACEIOC_ENABLE, 2, EIO, 3, NULL },
		{ "go-options-enotty", DTRACEIOC_ENABLE, 2, ENOTTY, 0, NULL },
		{ "go-eacces", DTRACEIOC_GO, 0, EACCES, 3,
		    "Destructive actions not allowed" },
		{ "go-ealready", DTRACEIOC_GO, 0, EALREADY, 3,
		    "Can't claim anonymous state and enable probes" },
		{ "go-enoent", DTRACEIOC_GO, 0, ENOENT, 3,
		    "No anonymous tracing state" },
		{ "go-e2big", DTRACEIOC_GO, 0, E2BIG, 3,
		    "END enablings exceed size of principal buffer" },
		{ "go-enospc", DTRACEIOC_GO, 0, ENOSPC, 3,
		    "Enabling exceeds size of buffer" },
		{ "go-eio", DTRACEIOC_GO, 0, EIO, 3, NULL },
		{ "go-dofget-eio", DTRACEIOC_DOFGET, 0, EIO, 3, NULL },
	};
	size_t i;

	for (i = 0; i < sizeof (cases) / sizeof (cases[0]); i++) {
		struct session s;
		const char *msg, *want = cases[i].msg;
		int stage;

		reset_model();
		inject(cases[i].cmd, cases[i].after, cases[i].error);
		stage = try_session(&s, NULL, TRACE_PROG, &msg);
		if (want == NULL && cases[i].stage != 0)
			want = strerror(cases[i].error);
		if (stage != cases[i].stage || (want != NULL &&
		    (msg == NULL || strcmp(msg, want) != 0))) {
			char buf[256];

			snprintf(buf, sizeof (buf), "stage %d: %s\n", stage,
			    msg ? msg : "(none)");
			fail(cases[i].name, "error", want ? want : "success",
			    buf);
		} else {
			passes++;
			printf("PASS %s\n", cases[i].name);
		}
		close_session(&s);
	}
}

/*
 * Failures while consuming: description lookups (EPROBE, the re-query for
 * multiple records, PROBES, FORMAT), buffer snapshots and aggregation
 * descriptions all fail the call with the kernel errno.  ENOENT from a
 * snapshot means an absent CPU and is not an error.
 */
static void
case_consume_errors(void)
{
	static const struct {
		const char *name;
		const char *prog;
		u_long cmd;
		int after, error, agg;
		int ok;
	} cases[] = {
		{ "consume-eprobe-enomem", TRACE_PROG, DTRACEIOC_EPROBE, 0,
		    ENOMEM, 0, 0 },
		{ "consume-eprobe-requery", "test:::entry { trace(arg0); "
		    "trace(arg1); }", DTRACEIOC_EPROBE, 1, EIO, 0, 0 },
		{ "consume-probes-esrch", TRACE_PROG, DTRACEIOC_PROBES, 0,
		    ESRCH, 0, 0 },
		{ "consume-format-einval", "test:::entry { printf(\"%d\", "
		    "arg0); }", DTRACEIOC_FORMAT, 0, EINVAL, 0, 0 },
		{ "consume-bufsnap-efault", TRACE_PROG, DTRACEIOC_BUFSNAP, 0,
		    EFAULT, 0, 0 },
		{ "consume-bufsnap-enoent", TRACE_PROG, DTRACEIOC_BUFSNAP, 0,
		    ENOENT, 0, 1 },
		{ "aggsnap-eio", "test:::entry { @c = count(); }",
		    DTRACEIOC_AGGSNAP, 0, EIO, 1, 0 },
		{ "aggsnap-enoent", "test:::entry { @c = count(); }",
		    DTRACEIOC_AGGSNAP, 0, ENOENT, 1, 1 },
		{ "aggdesc-einval", "test:::entry { @c = count(); }",
		    DTRACEIOC_AGGDESC, 0, EINVAL, 1, 0 },
	};
	size_t i;

	for (i = 0; i < sizeof (cases) / sizeof (cases[0]); i++) {
		struct session s;
		const char *msg;
		int rc;

		reset_model();
		if (try_session(&s, NULL, cases[i].prog, &msg) != 0) {
			fail(cases[i].name, "open", "", msg);
			close_session(&s);
			continue;
		}
		if (cases[i].agg)
			fire(0, "test:kernel:alpha:entry", 0,
			    VALS(N(1), AGG(0, 1)));
		else if (strstr(cases[i].prog, "arg1") != NULL)
			fire(0, "test:kernel:alpha:entry", 0,
			    VALS(N(1), N(2)));
		else
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		inject(cases[i].cmd, cases[i].after, cases[i].error);
		rc = cases[i].agg ? dtrace_aggregate_snap(s.dtp) :
		    consume(&s);
		if (cases[i].ok ? rc != 0 : (rc != -1 ||
		    dtrace_errno(s.dtp) != cases[i].error)) {
			char buf[128];

			snprintf(buf, sizeof (buf), "rc %d errno %d\n", rc,
			    dtrace_errno(s.dtp));
			fail(cases[i].name, "result", cases[i].ok ? "0" :
			    strerror(cases[i].error), buf);
		} else {
			passes++;
			printf("PASS %s\n", cases[i].name);
		}
		close_session(&s);
	}
}

/* STATUS and STOP failures surface from dtrace_status() and dtrace_stop(). */
static void
case_status_stop_errors(void)
{
	static const struct {
		const char *name;
		u_long cmd;
		int after;
		int stop;
	} cases[] = {
		{ "status-eio", DTRACEIOC_STATUS, 0, 0 },
		{ "stop-eio", DTRACEIOC_STOP, 0, 1 },
		{ "stop-status-eio", DTRACEIOC_STATUS, 0, 1 },
	};
	size_t i;

	for (i = 0; i < sizeof (cases) / sizeof (cases[0]); i++) {
		struct session s;
		const char *msg;
		int rc;

		reset_model();
		if (try_session(&s, NULL, TRACE_PROG, &msg) != 0) {
			fail(cases[i].name, "open", "", msg);
			close_session(&s);
			continue;
		}
		inject(cases[i].cmd, cases[i].after, EIO);
		rc = cases[i].stop ? dtrace_stop(s.dtp) : dtrace_status(s.dtp);
		if (rc != -1 || dtrace_errno(s.dtp) != EIO) {
			fail(cases[i].name, "result", strerror(EIO), "");
		} else {
			passes++;
			printf("PASS %s\n", cases[i].name);
		}
		M.fail_cmd = 0;
		close_session(&s);
	}
}

/*
 * Structured output for histograms, avg/stddev, symbol and stack keys,
 * principal-buffer stack/sym/mod/tracemem and a default printa().  The
 * harness writes oformat2.json; the driver checks the parsed values.
 * Two firings with arg2 = 1 and 3: avg 2, stddev 1, quantize buckets 1 and 2.
 */
static void
case_oformat_aggregations(void)
{
	const char *name = "oformat-aggregations";
	static const char *const opts[] = { "quiet", NULL, NULL };
	static const uint64_t pcs[2] = { 0xffffffff80001010ULL,
	    0xffffffff80002000ULL };
	static const char mem[4] = { 'D', 'T', 0x01, 'X' };
	const uint64_t sym = 0xffffffff80001010ULL;
	struct session s;
	FILE *json;
	int i;

	reset_model();
	use_oformat = 1;
	json = fopen("oformat2.json", "w");
	assert(json != NULL);
	xo_set_style(NULL, XO_STYLE_JSON);
	dtrace_set_outfp(json);
	if (open_session(&s, name, opts,
	    "test:::entry { stack(2); sym(arg0); mod(arg0); "
	    "tracemem(arg1, 4); "
	    "@q = quantize(arg2); @l = lquantize(arg2, 0, 4, 1); "
	    "@ll = llquantize(arg2, 2, 0, 3, 2); @a = avg(arg2); "
	    "@sd = stddev(arg2); @ks[sym(arg0), mod(arg0)] = count(); "
	    "@st[stack(2)] = count(); } "
	    "test:::return { printa(@q); }") == 0) {
		if (dtrace_oformat_configure(s.dtp) != 0)
			fail(name, "configure", "", "");
		dtrace_oformat_setup(s.dtp);
		for (i = 0; i < 2; i++) {
			int64_t v = i == 0 ? 1 : 3;

			fire(i, "test:kernel:alpha:entry", 0, VALS(
			    B(pcs, sizeof (pcs)), N(sym), N(sym),
			    B(mem, sizeof (mem)),
			    N(1), AGG(v, 1), N(2), AGG(v, 1), N(3), AGG(v, 1),
			    N(4), AGG(v, 1), N(5), AGG(v, 1),
			    N(6), N(sym), N(sym), AGG(0, 1),
			    N(7), B(pcs, sizeof (pcs)), AGG(0, 1)));
		}
		if (dtrace_aggregate_snap(s.dtp) != 0)
			fail(name, "snap", "", "");
		fire(0, "test:kernel:alpha:return", 0, VALS(N(1)));
		if (consume(&s) != 0 ||
		    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		dtrace_oformat_teardown(s.dtp);
		check(name, &s, "", NULL);
	}
	close_session(&s);
	xo_set_style(NULL, XO_STYLE_TEXT);
	dtrace_set_outfp(stdout);
	fclose(json);
}

/*
 * print() renders typed data from the D compiler's CTF container.  D lays
 * out bit-fields with libctf's rule: each member starts at the next byte
 * boundary rounded to its type's alignment, and a 5-bit integer type has
 * byte alignment, so "hi" occupies byte 17 rather than packing after "lo"
 * as C would.
 * Integers print as %#x/%#llx of their unsigned bits, char arrays as strings.
 *
 * Values and structure text must both reach the caller's stream; libxo's
 * default output (stdout here) is left alone.
 */
struct print_fixture {
	int32_t a;
	uint8_t b[4];
	int64_t c;
	uint8_t lo;		/* lo:3 at bit 128 */
	uint8_t hi;		/* hi:5 at bit 136 in D */
	uint8_t pad[6];
	void *p;
};

static void
case_print(void)
{
	const char *name = "print-typed";
	struct session s;
	static const struct print_fixture v = { -5, { 'a', 'b', 'c', 0 },
	    0x1122334455667788LL, 0xfd, 0xf5, { 0 },
	    (void *)0xffffffff80001010ULL };

	reset_model();
	if (open_session(&s, name, NULL,
	    "struct pf { int a; char b[4]; long c; "
	    "unsigned int lo:3; unsigned int hi:5; void *p; }; "
	    "test:::entry { print(*(struct pf *)arg0); }") == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(&v, sizeof (v))));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		check(name, &s,
		    "struct pf {\n"
		    "    int a = 0xfffffffb\n"
		    "    char [4] b = [ \"abc\" ]\n"
		    "    long c = 0x1122334455667788\n"
		    "    unsigned int lo :3 = 0x5\n"
		    "    unsigned int hi :5 = 0x15\n"
		    "    void *p = 0xffffffff80001010\n"
		    "}", "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n");
	}
	close_session(&s);
}

/* ---------------- User/guest stacks, immstack, packed output --------- */

/*
 * Under a vector open, user stacks and modules print raw addresses (no
 * process is grabbed).  A guest-tagged user stack prints a guest header,
 * a guest-tagged uaddr uses the HyperTrace guest format, and usym with pid 0
 * prints the raw address.
 */
static void
case_user_symbols(void)
{
	const char *name = "user-and-guest-symbols";
	struct session s;
	uint64_t host[1 + 3], guest[1 + 3];
	uint64_t uaddr_guest[2], usym_host[2], umod_host[2];

	host[0] = 0;
	host[1] = 0x400100;
	host[2] = 0x400200;
	host[3] = 0;
	guest[0] = HYPERTRACE_USTACK_ENCODE(7, 42);
	guest[1] = 0x500100;
	guest[2] = 0;
	guest[3] = 0;
	uaddr_guest[0] = HYPERTRACE_UADDR_ENCODE(7, 42);
	uaddr_guest[1] = 0x401234;
	usym_host[0] = 0;
	usym_host[1] = 0x401234;
	umod_host[0] = 0;
	umod_host[1] = 0x402000;

	reset_model();
	if (open_session(&s, name, NULL,
	    "test:kernel:alpha:entry { ustack(3); uaddr(arg0); usym(arg0); "
	    "umod(arg0); } test:kernel:beta:entry { ustack(3); }") == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(host,
		    sizeof (host)), B(uaddr_guest, sizeof (uaddr_guest)),
		    B(usym_host, sizeof (usym_host)),
		    B(umod_host, sizeof (umod_host))));
		fire(0, "test:kernel:beta:entry", 0, VALS(B(guest,
		    sizeof (guest))));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X("\n%14s0x400100\n%14s0x400200\n", "", "");
		X("  %-50s", "guest[7]:pid[42]`0x401234");
		X("  %-50s", "0x401234");
		X("  %-50s", "0x402000");
		X("\n%14s[guest vmid=7 pid=42]\n%14s0x500100\n", "", "");
		check(name, &s, xend(), NULL);
	}
	close_session(&s);
}

/*
 * A kernel stack from a guest probe carries the guest tag and VM id in its
 * record argument (the kernel encodes it for probes with a nonzero VM id);
 * frames then print as guest[vmid]`pc.
 */
static void
case_guest_kernel_stack(void)
{
	const char *name = "guest-kernel-stack";
	struct session s;
	static const uint64_t pcs[2] = { 0xffffffff81000010ULL,
	    0xffffffff81000020ULL };
	struct mset *set;
	int i;

	reset_model();
	if (open_session(&s, name, NULL, "test:kernel:alpha:entry { stack(2); }")
	    == 0) {
		/* What dtrace_ecb_action_add() records for a VM probe. */
		set = &M.set[M.ecb[find_ecb("test:kernel:alpha:entry", 0)].set];
		for (i = 0; i < set->nact; i++)
			if (set->act[i].kind == DTRACEACT_STACK)
				set->act[i].rec.dtrd_arg =
				    HYPERTRACE_STACK_ENCODE(9, 2);
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(pcs,
		    sizeof (pcs))));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X("\n%14sguest[9]`0xffffffff81000010\n", "");
		X("%14sguest[9]`0xffffffff81000020\n", "");
		check(name, &s, xend(), NULL);
	}
	close_session(&s);
}

/*
 * immstack() records pre-symbolized frames: each 64-byte entry holds a NUL
 * terminated name followed, at the next 8-byte boundary, by a 64-bit offset.
 * Printing stops at the first empty entry.
 */
static void
case_immstack(void)
{
	const char *name = "immstack";
	struct session s;
	char rec[20 * 64];
	uint64_t off;

	memset(rec, 0, sizeof (rec));
	strcpy(rec, "vm_fault");
	off = 0x10;
	memcpy(rec + 16, &off, sizeof (off));	/* after "vm_fault\0", aligned */
	strcpy(rec + 64, "sched_tick");
	off = 0x4;
	memcpy(rec + 64 + 16, &off, sizeof (off));

	reset_model();
	if (open_session(&s, name, NULL, "test:kernel:alpha:entry { immstack(); }")
	    == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(rec,
		    sizeof (rec))));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X("\n%14svm_fault+0x10\n%14ssched_tick+0x4\n", "", "");
		check(name, &s, xend(), NULL);
	}
	close_session(&s);
}

/*
 * agghist renders each key's value as a bar of round(value * 40 / total)
 * characters (ASCII '@', or U+2588 blocks with encoding=utf8), keys right
 * aligned in 16 columns under a "key" header.
 */
static void
case_agghist(void)
{
	static const struct { const char *name, *encoding; } modes[] = {
		{ "agghist-ascii", "ascii" },
		{ "agghist-utf8", "utf8" },
	};
	size_t m;
	int i;

	for (m = 0; m < sizeof (modes) / sizeof (modes[0]); m++) {
		const char *opts[] = { "agghist", NULL, "encoding",
		    modes[m].encoding, NULL };
		struct session s;

		reset_model();
		if (open_session(&s, modes[m].name, opts,
		    "test:::entry { @c[probefunc] = count(); }") != 0) {
			close_session(&s);
			continue;
		}
		for (i = 0; i < 3; i++)
			fire(i % 2, "test:kernel:alpha:entry", 0, VALS(N(1),
			    S("alpha"), AGG(0, 1)));
		fire(0, "test:kernel:beta:entry", 0, VALS(N(1), S("beta"),
		    AGG(0, 1)));
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(modes[m].name, "print", "", "");
		xbegin();
		X("\n%17s %41s %-9s\n", "key",
		    "------------- Distribution -------------", "count");
		X(" %16s |", "beta");
		for (i = 0; i < 10; i++)
			X("%s", m == 0 ? "@" : "\xe2\x96\x88");
		X("%30s %-9d\n", "", 1);
		X(" %16s |", "alpha");
		for (i = 0; i < 30; i++)
			X("%s", m == 0 ? "@" : "\xe2\x96\x88");
		X("%10s %-9d\n", "", 3);
		check(modes[m].name, &s, xend(), "");
		close_session(&s);
	}
}

/*
 * aggpack prints one line per key: a header naming min and max, then one
 * glyph per bucket and the count.  With encoding=ascii the busiest bucket
 * is the top level 'X' and empty buckets are blank.
 */
static void
case_aggpack(void)
{
	const char *name = "aggpack-ascii";
	static const char *const opts[] = { "aggpack", NULL, "encoding",
	    "ascii", NULL };
	struct session s;
	static const int64_t v[] = { 1, 2, 3, 3, 3 };
	size_t i;
	char *line, *nl;

	reset_model();
	if (open_session(&s, name, opts,
	    "test:::entry { @q[probefunc] = quantize(arg0); }") == 0) {
		for (i = 0; i < sizeof (v) / sizeof (v[0]); i++)
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1),
			    S("alpha"), AGG(v[i], 1)));
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "print", "", "");
		fflush(s.out);
		/* Header, then the key line. */
		line = strstr(s.text, "min .");
		nl = line != NULL ? strchr(line, '\n') : NULL;
		if (line == NULL || nl == NULL ||
		    strstr(line, ". max") == NULL ||
		    strstr(nl + 1, "alpha") == NULL ||
		    strstr(nl + 1, "| 5") == NULL ||
		    strchr(nl + 1, 'X') == NULL)
			fail(name, "structure", "header, key, X peak, | 5",
			    s.text);
		else {
			passes++;
			printf("PASS %s\n", name);
		}
	}
	close_session(&s);
}

/* printm(size, ptr) records the length and bytes; output is a raw dump. */
static void
case_printm(void)
{
	const char *name = "printm-dump";
	struct session s;
	unsigned char rec[8 + 16];
	size_t n = 4;
	int i;

	memset(rec, 0, sizeof (rec));
	memcpy(rec, &n, sizeof (n));
	memcpy(rec + 8, "PRNT", 4);

	reset_model();
	if (open_session(&s, name, NULL,
	    "test:kernel:alpha:entry { printm(4, (uintptr_t *)arg0); }") == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(rec,
		    sizeof (rec))));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X("\n%11s", "");
		for (i = 0; i < 16; i++)
			X("  %c", "0123456789abcdef"[i]);
		X("  0123456789abcdef\n");
		X("%5s%5x: 50 52 4e 54", "", 0);
		for (i = 0; i < 12; i++)
			X("   ");
		X("  PRNT\n");
		check(name, &s, xend(), NULL);
	}
	close_session(&s);
}

/*
 * Stopped with BEGIN and END on one CPU, the BEGIN pass reports only errors
 * induced by BEGIN; the later pass reports the others.
 */
static void
case_begin_error_interposition(void)
{
	const char *name = "begin-error-interposition";
	struct session s;

	reset_model();
	M.endcpu = 0;
	if (open_session(&s, name, NULL,
	    "BEGIN { trace(1); } test:::entry { trace(arg0); } "
	    "END { trace(3); }") == 0) {
		fire(0, "dtrace:::BEGIN", 0, VALS(N(1)));
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(20)));
		fire(0, "dtrace:::ERROR", 0, VALS(N(2), N(1), N(4),
		    N(DTRACEFLT_DIVZERO), N(0)));
		fire(0, "dtrace:::ERROR", 0, VALS(N(1), N(1), N(8),
		    N(DTRACEFLT_BADADDR), N(0x20)));
		fire(0, "dtrace:::END", 0, VALS(N(3)));
		if (dtrace_stop(s.dtp) != 0 || consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X(" %8d %16lld %8d", 1, 20LL, 3);
		check(name, &s, xend(),
		    "probe cpu=0 dtrace:::BEGIN\nend-of-probe\n"
		    "error: error on enabled probe ID 1 (ID 1: dtrace:::BEGIN): "
		    "invalid address (0x20) in action #1 at DIF offset 8\n"
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n"
		    "error: error on enabled probe ID 2 (ID 4: "
		    "test:kernel:alpha:entry): divide-by-zero in action #1 at "
		    "DIF offset 4\n"
		    "probe cpu=0 dtrace:::END\nend-of-probe\n");
	}
	close_session(&s);
}

/* denormalize() restores raw values after normalize(). */
static void
case_denormalize(void)
{
	const char *name = "denormalize";
	static const char *const opts[] = { "quiet", NULL, NULL };
	struct session s;

	reset_model();
	if (open_session(&s, name, opts,
	    "test:kernel:alpha:entry { @s[probefunc] = sum(arg0); } "
	    "test:kernel:alpha:return { normalize(@s, 4); denormalize(@s); "
	    "printa(@s); }") == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"),
		    AGG(12, 1)));
		fire(0, "test:kernel:alpha:return", 0, VALS(N(1), N(4), N(1),
		    N(1)));
		if (dtrace_aggregate_snap(s.dtp) != 0 || consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X("\n  %-50s %16lld\n", "alpha", 12LL);
		check(name, &s, xend(), NULL);
	}
	close_session(&s);
}

/*
 * NULL callbacks: the default probe callback consumes each probe and the
 * default record callback skips its records, so the buffers drain without
 * output.
 */
static void
case_default_callbacks(void)
{
	const char *name = "default-callbacks";
	struct session s;

	reset_model();
	if (open_session(&s, name, NULL, TRACE_PROG) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(4)));
		fire(1, "test:kernel:beta:entry", 0, VALS(N(5)));
		if (dtrace_consume(s.dtp, s.out, NULL, NULL, NULL) != 0)
			fail(name, "consume", "", "");
		if (M.buf[0].offset != 0 || M.buf[1].offset != 0)
			fail(name, "drain", "both CPU buffers drained", "");
		check(name, &s, "", "");
	}
	close_session(&s);
}

int
main(void)
{
	check_phaseup();
	case_ordering();
	case_begin_end_same_cpu();
	case_error_handler();
	case_temporal();
	case_drops();
	case_ring();
	case_fill();
	case_exit();
	case_printf_quiet();
	case_callbacks();
	case_bad_epid();
	case_aggregations();
	case_agg_kinds();
	case_histograms();
	case_walk_orders();
	case_walk_mixed_kinds();
	case_sort_options();
	case_printa_joined();
	case_libact();
	case_setopt();
	case_flowindent();
	case_stack_sym();
	case_tracemem();
	case_work_loop();
	case_oformat();
	case_quiesced_drain();
	case_quiesced_refusals();
	case_quiesced_inactive();
	case_output_discard();
	case_handle_identity();
	case_enable_go_errors();
	case_consume_errors();
	case_status_stop_errors();
	case_oformat_aggregations();
	case_print();
	case_user_symbols();
	case_guest_kernel_stack();
	case_immstack();
	case_agghist();
	case_aggpack();
	case_printm();
	case_begin_error_interposition();
	case_denormalize();
	case_default_callbacks();
	reset_model();
	printf("%d passed, %d failed\n", passes, failures);
	return (failures != 0);
}
