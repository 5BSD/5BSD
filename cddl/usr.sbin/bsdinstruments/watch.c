/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The watch run loop: ties a rendered profile, libdtrace, and an
 * exporter together.
 *
 * Two backend paths share compile/exec/go/work/stop:
 *
 * 1. Text — libdtrace writes its formatted printf output directly to
 *    stdout via dtrace_work(fp).  ANSI color when stdout is a TTY.
 *    The exporter is a pass-through; libdtrace owns the stream.
 *
 * 2. Structured — libdtrace's formatted output is intercepted via
 *    dtrace_handle_buffered() and delivered as typed events to the
 *    exporter (JSONL, OTLP, collapsed).  Aggregations are walked as
 *    typed records and emitted as snapshots.
 */

#include <ctype.h>
#include <err.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <dtrace.h>

#include "otelexport.h"
#include "bsdinstruments.h"

#define	USTACK_MARKER	"__BSDINSTRUMENTS_USTACK__"

static volatile sig_atomic_t got_signal;

static void
signal_handler(int sig __unused)
{

	got_signal = 1;
}

static void
install_signal_handlers(void)
{
	struct sigaction sa;

	got_signal = 0;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

/* ---------------------------------------------------------------- */
/* Aggregation key names parsed from the D source		 	*/

#define	MAX_AGG_KEYS	16

struct agg_keynames {
	char		*aggname;
	char		*names[MAX_AGG_KEYS];
	int		 n;
	struct agg_keynames *next;
};

static const char *
builtin_key_name(const char *expr, int idx, char *buf, size_t len)
{

	if (strcmp(expr, "execname") == 0 || strcmp(expr, "pid") == 0 ||
	    strcmp(expr, "tid") == 0 || strcmp(expr, "cpu") == 0)
		return (expr);
	if (strcmp(expr, "probefunc") == 0)
		return ("syscall");
	if (strcmp(expr, "probename") == 0)
		return ("probe");
	if (strcmp(expr, "probemod") == 0)
		return ("module");
	if (strcmp(expr, "probeprov") == 0)
		return ("provider");
	if (expr[0] == '"')
		return ("label");
	snprintf(buf, len, "key.%d", idx);
	return (buf);
}

/*
 * Scan the rendered D source for @name[expr, expr, ...] patterns and
 * derive semantic attribute names for each aggregation's key tuple.
 * First occurrence of each aggregation name wins.
 */
static struct agg_keynames *
parse_agg_keynames(const char *source)
{
	struct agg_keynames *head, *ak;
	const char *p, *namestart, *keystart, *keyend, *close;
	char aggname[128], expr[256], fallback[24];
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

		/* Split the [...] key list on top-level commas. */
		keystart = close + 1;
		idx = 0;
		while (idx < MAX_AGG_KEYS) {
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

static void
free_agg_keynames(struct agg_keynames *head)
{
	struct agg_keynames *next;
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
/* Structured backend: buffered-output event accumulation	 	*/

struct frame_array {
	struct oe_frame	*frames;
	size_t		 n, cap;
};

struct watch_state {
	struct oe_exporter *exporter;
	const char	*profile_name;
	dtrace_hdl_t	*dtp;

	/* Pending event accumulation. */
	char		*body;
	struct timespec	 body_ts;
	struct frame_array kstack;
	struct frame_array ustack;
	int		 in_ustack;
	int		 error;
};

static void
frame_array_free(struct frame_array *fa)
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
frame_array_push(struct frame_array *fa, const char *line)
{
	struct oe_frame *np;

	if (fa->n == fa->cap) {
		size_t newcap = fa->cap == 0 ? 16 : fa->cap * 2;

		np = realloc(fa->frames, newcap * sizeof(*np));
		if (np == NULL)
			return;
		fa->frames = np;
		fa->cap = newcap;
	}
	parse_stack_frame(line, &fa->frames[fa->n]);
	fa->n++;
}

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

static void
flush_pending(struct watch_state *ws)
{
	struct oe_event ev;
	char execname[MAXCOMLEN + 1];
	pid_t pid;

	if (ws->body == NULL)
		return;
	parse_body_metadata(ws->body, execname, sizeof(execname), &pid);
	memset(&ev, 0, sizeof(ev));
	ev.ts = ws->body_ts;
	ev.profile = ws->profile_name;
	ev.probe = "";
	ev.pid = pid;
	ev.execname = execname;
	ev.body = ws->body;
	ev.stack = ws->kstack.frames;
	ev.nstack = ws->kstack.n;
	ev.ustack = ws->ustack.frames;
	ev.nustack = ws->ustack.n;
	if (oe_event(ws->exporter, &ev) != 0)
		ws->error = 1;
	free(ws->body);
	ws->body = NULL;
	frame_array_free(&ws->kstack);
	frame_array_free(&ws->ustack);
	ws->in_ustack = 0;
}

/*
 * Buffered output handler.  libdtrace calls this synchronously from
 * dtrace_work() for every printf/printa output chunk instead of
 * writing to a FILE.  Aggregation fragments are filtered out here —
 * they're captured as typed metrics via the aggregation walk.
 *
 * Chunks may contain several lines (stack() output in particular).
 * Stack frames arrive as whitespace-prefixed lines containing a
 * backtick or hex address; everything else starts a new event.
 */
static int
buffered_handler(const dtrace_bufdata_t *bufdata, void *arg)
{
	struct watch_state *ws = arg;
	const char *chunk, *line, *nl;
	char *linebuf;
	const char *trimmed;
	size_t linelen, tlen;
	int is_stack_frame;

	if (bufdata->dtbda_flags & (DTRACE_BUFDATA_AGGKEY |
	    DTRACE_BUFDATA_AGGVAL | DTRACE_BUFDATA_AGGFORMAT |
	    DTRACE_BUFDATA_AGGLAST))
		return (DTRACE_HANDLE_OK);

	chunk = bufdata->dtbda_buffered;
	if (chunk == NULL)
		return (DTRACE_HANDLE_OK);

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

			if (tlen >= sizeof(frameline))
				tlen = sizeof(frameline) - 1;
			memcpy(frameline, trimmed, tlen);
			frameline[tlen] = '\0';
			frame_array_push(ws->in_ustack ? &ws->ustack :
			    &ws->kstack, frameline);
		} else if (tlen == strlen(USTACK_MARKER) &&
		    strncmp(trimmed, USTACK_MARKER, tlen) == 0) {
			/* Marker between stack() and ustack() output. */
			ws->in_ustack = 1;
		} else {
			/* New event: flush pending, start accumulating. */
			flush_pending(ws);
			ws->body = strndup(trimmed, tlen);
			clock_gettime(CLOCK_REALTIME, &ws->body_ts);
		}
		free(linebuf);
		if (nl == NULL)
			break;
	}

	return (ws->error ? DTRACE_HANDLE_ABORT : DTRACE_HANDLE_OK);
}

static int
drop_handler(const dtrace_dropdata_t *drop, void *arg)
{
	struct watch_state *ws = arg;

	/*
	 * Log the drop and keep running — matches dtrace(1)'s
	 * behavior when probe rates exceed the consumer's drain rate.
	 * Without this handler libdtrace aborts on the first drop.
	 */
	fprintf(stderr, "bsdinstruments: dropped %ju record(s) (%s)\n",
	    (uintmax_t)drop->dtdda_drops, drop->dtdda_msg);
	oe_report_drops(ws->exporter, drop->dtdda_drops);
	return (DTRACE_HANDLE_OK);
}

/* ---------------------------------------------------------------- */
/* Structured backend: typed aggregation walk			 	*/

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
	enum oe_agg_kind kind;
	struct snap_point *points;
	size_t		 npoints, cappoints;
	struct snap_accum *next;
};

struct agg_walk_ctx {
	struct watch_state *ws;
	struct agg_keynames *keynames;
	struct snap_accum *accums;
};

/*
 * Render kernel stack frames as module`symbol+0xoff joined by ';',
 * falling back to hex for unresolvable addresses.
 */
static void
key_frames_to_buf(dtrace_hdl_t *dtp, struct oe_buf *b, caddr_t addr,
    size_t nframes)
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
		if (dtrace_lookup_by_addr(dtp, pc, &sym, &si) == 0)
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
		framesize = rec->dtrd_arg != 0 ?
		    rec->dtrd_size / rec->dtrd_arg : sizeof(uint64_t);
		if (framesize != sizeof(uint64_t))
			goto hexdump;
		key_frames_to_buf(dtp, b, addr,
		    rec->dtrd_size / sizeof(uint64_t));
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
accum_for(struct agg_walk_ctx *ctx, const char *name, enum oe_agg_kind kind)
{
	struct snap_accum *sa;

	for (sa = ctx->accums; sa != NULL; sa = sa->next)
		if (strcmp(sa->name, name) == 0 && sa->kind == kind)
			return (sa);
	sa = calloc(1, sizeof(*sa));
	if (sa == NULL)
		return (NULL);
	sa->name = strdup(name);
	sa->kind = kind;
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
	struct agg_keynames *ak;
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

	sa = accum_for(ctx, aggname, kind);
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
			key_to_buf(ctx->ws->dtp, rec, base, &kb);
			if (ak != NULL && i < ak->n)
				pt->attrs[i].name = strdup(ak->names[i]);
			else {
				snprintf(attrname, sizeof(attrname),
				    "key.%d", i);
				pt->attrs[i].name = strdup(attrname);
			}
			pt->attrs[i].value = strdup(kb.data != NULL ?
			    kb.data : "");
			oe_buf_free(&kb);
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
emit_and_free_accums(struct watch_state *ws, struct snap_accum *accums)
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
			sn.profile = ws->profile_name;
			sn.name = sa->name;
			sn.kind = sa->kind;
			sn.points = dps;
			sn.npoints = sa->npoints;
			if (oe_snapshot(ws->exporter, &sn) != 0)
				ws->error = 1;
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

/* ---------------------------------------------------------------- */
/* Consumer callbacks for dtrace_work()				 	*/

static int
chew(const dtrace_probedata_t *data __unused, void *arg __unused)
{

	return (DTRACE_CONSUME_THIS);
}

static int
chewrec(const dtrace_probedata_t *data __unused,
    const dtrace_recdesc_t *rec, void *arg __unused)
{

	if (rec == NULL)
		return (DTRACE_CONSUME_NEXT);
	if (rec->dtrd_action == DTRACEACT_EXIT)
		return (DTRACE_CONSUME_NEXT);
	return (DTRACE_CONSUME_THIS);
}

/* ---------------------------------------------------------------- */
/* Run loop							 	*/

static int
setopt_or_warn(dtrace_hdl_t *dtp, const char *opt, const char *value)
{

	if (dtrace_setopt(dtp, opt, value) != 0) {
		fprintf(stderr, "bsdinstruments: failed to set %s=%s: %s\n",
		    opt, value != NULL ? value : "(null)",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return (-1);
	}
	return (0);
}

int
watch_run(const struct profile *p, const char *rendered,
    const struct watch_opts *wo)
{
	struct watch_state ws;
	struct agg_walk_ctx actx;
	struct agg_keynames *keynames;
	struct oe_exporter *exporter;
	struct oe_resource resource;
	struct oe_env env;
	struct oe_otlp_config ocfg;
	dtrace_hdl_t *dtp;
	dtrace_prog_t *prog;
	dtrace_proginfo_t info;
	dtrace_workstatus_t status;
	char hostname[256], arch[64], osrel[64];
	const char *endpoint;
	int done, err_ret, is_text, use_color;

	err_ret = 1;
	exporter = NULL;
	keynames = NULL;
	dtp = NULL;
	is_text = wo->format == FORMAT_TEXT;

	oe_env_load(&env);
	oe_host_name(hostname, sizeof(hostname));
	oe_host_arch(arch, sizeof(arch));
	oe_os_version(osrel, sizeof(osrel));
	memset(&resource, 0, sizeof(resource));
	resource.service_name = env.service_name != NULL ? env.service_name :
	    "bsdinstruments";
	resource.host_name = hostname;
	resource.host_arch = arch;
	resource.os_name = "freebsd";
	resource.os_version = osrel;
	resource.service_version = BSDINSTRUMENTS_VERSION;
	resource.custom = env.resource_attrs;
	resource.ncustom = env.nresource_attrs;

	switch (wo->format) {
	case FORMAT_TEXT:
		exporter = oe_text_new(stdout);
		break;
	case FORMAT_JSON:
		exporter = oe_jsonl_new(stdout, p->name);
		break;
	case FORMAT_OTEL:
		/*
		 * An explicit --endpoint takes precedence over
		 * OTEL_EXPORTER_OTLP_ENDPOINT; the env var only
		 * overrides the compiled-in default.
		 */
		endpoint = wo->endpoint;
		if (strcmp(endpoint, "http://localhost:4318") == 0 &&
		    env.endpoint != NULL)
			endpoint = env.endpoint;
		memset(&ocfg, 0, sizeof(ocfg));
		ocfg.endpoint = endpoint;
		ocfg.profile = p->name;
		ocfg.resource = &resource;
		ocfg.max_retries = -1;
		ocfg.timeout = env.timeout_ms > 0 ?
		    (double)env.timeout_ms / 1000.0 : 0;
		ocfg.headers = env.headers;
		ocfg.nheaders = env.nheaders;
		ocfg.compression = env.compression;
		exporter = oe_otlp_new(&ocfg);
		break;
	case FORMAT_COLLAPSED:
		exporter = oe_collapsed_new(stdout);
		break;
	}
	if (exporter == NULL) {
		fprintf(stderr, "bsdinstruments: failed to create "
		    "exporter\n");
		goto out;
	}

	/*
	 * Parse aggregation key names from the source so OTLP data
	 * points get semantic attribute names instead of key.N.
	 */
	keynames = parse_agg_keynames(rendered);

	dtp = dtrace_open(DTRACE_VERSION, 0, &done);
	if (dtp == NULL) {
		fprintf(stderr, "bsdinstruments: failed to open libdtrace: "
		    "%s. Are you root?\n", dtrace_errmsg(NULL, done));
		goto out;
	}

	/*
	 * libdtrace defaults.  switchrate=50ms (vs dtrace(1)'s 1s)
	 * keeps --duration short profiles responsive.  Structured
	 * output gets 16m per-CPU buffers for headroom before kernel
	 * drops at high probe rates.
	 */
	if (setopt_or_warn(dtp, "bufsize", wo->bufsize != NULL ?
	    wo->bufsize : (is_text ? "4m" : "16m")) != 0 ||
	    setopt_or_warn(dtp, "aggsize", "4m") != 0 ||
	    setopt_or_warn(dtp, "switchrate", wo->switchrate != NULL ?
	    wo->switchrate : "50ms") != 0 ||
	    setopt_or_warn(dtp, "quiet", NULL) != 0)
		goto out;

	memset(&ws, 0, sizeof(ws));
	ws.exporter = exporter;
	ws.profile_name = p->name;
	ws.dtp = dtp;

	if (dtrace_handle_drop(dtp, drop_handler, &ws) != 0) {
		fprintf(stderr, "bsdinstruments: failed to install drop "
		    "handler: %s\n", dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto out;
	}
	if (!is_text && dtrace_handle_buffered(dtp, buffered_handler,
	    &ws) != 0) {
		fprintf(stderr, "bsdinstruments: failed to install buffered "
		    "handler: %s\n", dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto out;
	}

	prog = dtrace_program_strcompile(dtp, rendered,
	    DTRACE_PROBESPEC_NAME, DTRACE_C_ZDEFS, 0, NULL);
	if (prog == NULL) {
		fprintf(stderr, "bsdinstruments: profile '%s' failed to "
		    "compile: %s\n", p->name,
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto out;
	}
	if (dtrace_program_exec(dtp, prog, &info) != 0) {
		fprintf(stderr, "bsdinstruments: failed to enable probes: "
		    "%s\n", dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto out;
	}

	if (oe_start(exporter) != 0)
		goto out;

	install_signal_handlers();

	use_color = is_text && isatty(STDOUT_FILENO);
	if (is_text) {
		/*
		 * Line-buffer stdout so each printf line shows up
		 * immediately.  Wrap live event output in cyan when
		 * stdout is a terminal; piped output stays plain.
		 */
		setvbuf(stdout, NULL, _IOLBF, 0);
		if (use_color) {
			fputs("\033[36m", stdout);
			fflush(stdout);
		}
	}

	if (dtrace_go(dtp) != 0) {
		if (use_color)
			fputs("\033[0m", stdout);
		fprintf(stderr, "bsdinstruments: failed to start trace: "
		    "%s\n", dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto out;
	}

	done = 0;
	while (!done && !got_signal && !ws.error) {
		dtrace_sleep(dtp);
		status = dtrace_work(dtp, is_text ? stdout : NULL, chew,
		    chewrec, NULL);
		switch (status) {
		case DTRACE_WORKSTATUS_OKAY:
			break;
		case DTRACE_WORKSTATUS_DONE:
			done = 1;
			break;
		case DTRACE_WORKSTATUS_ERROR:
			fprintf(stderr, "bsdinstruments: libdtrace work() "
			    "failed: %s\n",
			    dtrace_errmsg(dtp, dtrace_errno(dtp)));
			done = 1;
			break;
		}
	}

	(void)dtrace_stop(dtp);

	/*
	 * One more work pass after stop, as dtrace(1) does: stopping
	 * fires dtrace:::END, and the STOPPED status makes this final
	 * pass force-drain the buffers — without it END-probe printf
	 * output and the tail of the event stream are lost.
	 */
	(void)dtrace_work(dtp, is_text ? stdout : NULL, chew, chewrec,
	    NULL);

	/* Flush any pending structured event. */
	if (!is_text)
		flush_pending(&ws);

	/* Snapshot aggregations. */
	if (use_color) {
		/* Magenta for the aggregation table. */
		fputs("\033[0m\033[35m", stdout);
		fflush(stdout);
	}
	if (dtrace_aggregate_snap(dtp) != 0)
		fprintf(stderr, "bsdinstruments: aggregation snapshot "
		    "failed: %s\n", dtrace_errmsg(dtp, dtrace_errno(dtp)));
	else if (is_text) {
		if (dtrace_aggregate_print(dtp, stdout, NULL) != 0)
			fprintf(stderr, "bsdinstruments: aggregation print "
			    "failed: %s\n",
			    dtrace_errmsg(dtp, dtrace_errno(dtp)));
	} else {
		memset(&actx, 0, sizeof(actx));
		actx.ws = &ws;
		actx.keynames = keynames;
		if (dtrace_aggregate_walk(dtp, agg_walk, &actx) != 0)
			fprintf(stderr, "bsdinstruments: aggregation walk "
			    "failed: %s\n",
			    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		emit_and_free_accums(&ws, actx.accums);
	}
	if (use_color) {
		fputs("\033[0m", stdout);
		fflush(stdout);
	}

	oe_flush(exporter);
	oe_shutdown(exporter);
	err_ret = ws.error ? 1 : 0;

out:
	if (dtp != NULL)
		dtrace_close(dtp);
	if (exporter != NULL)
		oe_exporter_free(exporter);
	free_agg_keynames(keynames);
	oe_env_free(&env);
	return (err_ret);
}
