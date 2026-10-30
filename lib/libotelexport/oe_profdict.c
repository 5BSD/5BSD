/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Profiles dictionary builder; see oe_profdict.h.
 *
 * Frames become locations as libdtrace symbolized them:
 *
 *	module`symbol[+0xoff]	mapping "module", function "symbol"
 *	symbol[+0xoff]		function "symbol", no mapping
 *	module`0xaddr		mapping "module" (for example a HyperTrace
 *				guest's "guest[<vmid>]"), address, no line
 *	0xaddr			address only
 *
 * Locations are per function, not per instruction: the offset within
 * the function is not part of a location (DTrace reports no source
 * lines), so every sample in a function shares its location.
 *
 * Samples of the same identity (stack, attribute set, link and shape)
 * merge: value-only samples add their values, timestamped samples
 * append their observations.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "otelexport.h"
#include "oe_otlpenc.h"
#include "oe_profdict.h"

/* Sample shapes: never merged across. */
#define	SHAPE_VALUE	0	/* values only */
#define	SHAPE_TIMES	1	/* timestamps only (each value 1) */
#define	SHAPE_BOTH	2	/* a value per timestamp */

/* Key tags: one map holds every table's values. */
#define	TAG_STRING	's'
#define	TAG_MAPPING	'm'
#define	TAG_FUNCTION	'f'
#define	TAG_LOCATION	'l'
#define	TAG_STACK	'k'
#define	TAG_LINK	'n'
#define	TAG_ATTR	'a'
#define	TAG_SAMPLE	'p'

struct pd_ent {
	char		*key;		/* NULL: empty slot */
	size_t		 klen;
	uint32_t	 hash;
	int32_t		 index;
};

struct oe_pd_map {
	struct pd_ent	*ents;
	size_t		 cap;		/* power of two */
	size_t		 n;
};

static uint32_t
pd_hash(const void *key, size_t len)
{
	const unsigned char *p = key;
	uint32_t h = 2166136261u;

	while (len-- > 0)
		h = (h ^ *p++) * 16777619u;
	return (h);
}

static int
map_grow(struct oe_pd_map *m)
{
	struct pd_ent *ents;
	size_t cap, i, j;

	cap = m->cap == 0 ? 256 : m->cap * 2;
	if ((ents = calloc(cap, sizeof(*ents))) == NULL)
		return (-1);
	for (i = 0; i < m->cap; i++) {
		if (m->ents[i].key == NULL)
			continue;
		for (j = m->ents[i].hash & (cap - 1); ents[j].key != NULL;
		    j = (j + 1) & (cap - 1))
			;
		ents[j] = m->ents[i];
	}
	free(m->ents);
	m->ents = ents;
	m->cap = cap;
	return (0);
}

/* The slot of key: a match, or the empty slot where it belongs. */
static struct pd_ent *
map_slot(struct oe_pd_map *m, const void *key, size_t klen, uint32_t h)
{
	struct pd_ent *e;
	size_t i;

	for (i = h & (m->cap - 1);; i = (i + 1) & (m->cap - 1)) {
		e = &m->ents[i];
		if (e->key == NULL || (e->hash == h && e->klen == klen &&
		    memcmp(e->key, key, klen) == 0))
			return (e);
	}
}

/*
 * Look key up; when absent and "next" is not negative, insert it with
 * index "next".  Returns the index, -2 when absent (lookup only), or -1
 * without memory.
 */
static int32_t
map_get(struct oe_profdict *d, const void *key, size_t klen, int32_t next)
{
	struct oe_pd_map *m = d->map;
	struct pd_ent *e;
	uint32_t h;

	h = pd_hash(key, klen);
	if (m->cap > 0) {
		e = map_slot(m, key, klen, h);
		if (e->key != NULL)
			return (e->index);
	}
	if (next < 0)
		return (-2);
	if ((m->n + 1) * 4 > m->cap * 3 && map_grow(m) != 0)
		return (-1);
	e = map_slot(m, key, klen, h);
	if ((e->key = malloc(klen)) == NULL)
		return (-1);
	memcpy(e->key, key, klen);
	e->klen = klen;
	e->hash = h;
	e->index = next;
	m->n++;
	return (next);
}

/*
 * reallocarray() through realloc(), so allocation-failure tests that wrap
 * the allocators reach every allocation here; tables are bounded (max)
 * and sample arrays by the caller's counts, far below an overflow.
 */
static void *
pd_realloc(void *p, size_t n, size_t size)
{

	return (realloc(p, n * size));
}

/* Room for one more entry in a table; -1 at the bound or without memory. */
static int
grow(struct oe_profdict *d, void **arr, size_t *n, size_t *cap, size_t size)
{
	void *p;
	size_t nc;

	if (*n >= d->max) {
		errno = E2BIG;
		return (-1);
	}
	if (*n < *cap)
		return (0);
	nc = *cap == 0 ? 64 : *cap * 2;
	if ((p = pd_realloc(*arr, nc, size)) == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	*arr = p;
	*cap = nc;
	return (0);
}

#define	GROW(d, what)							\
	grow((d), (void **)&(d)->what, &(d)->n##what, &(d)->cap##what,	\
	    sizeof(*(d)->what))

/* A failure: allocation sets "error"; a bound is counted by the caller. */
static int32_t
fail(struct oe_profdict *d)
{

	if (errno != E2BIG)
		d->error = 1;
	return (-1);
}

/*
 * A key: the tag byte, a fixed part and a variable part, in a small
 * buffer when it fits, else malloc'd.  NULL without memory; release with
 * key_free().
 */
struct pd_key {
	unsigned char	 small[64];
	unsigned char	*p;
	size_t		 len;
};

static unsigned char *
key_make(struct pd_key *k, int tag, const void *a, size_t alen,
    const void *b, size_t blen)
{

	k->len = 1 + alen + blen;
	k->p = k->len <= sizeof(k->small) ? k->small : malloc(k->len);
	if (k->p == NULL)
		return (NULL);
	k->p[0] = (unsigned char)tag;
	/* memcpy() of nothing from NULL is undefined. */
	if (alen > 0)
		memcpy(k->p + 1, a, alen);
	if (blen > 0)
		memcpy(k->p + 1 + alen, b, blen);
	return (k->p);
}

static void
key_free(struct pd_key *k)
{

	if (k->p != k->small)
		free(k->p);
}

int
oe_profdict_init(struct oe_profdict *d, size_t max)
{

	memset(d, 0, sizeof(*d));
	d->max = max > 0 ? max : OE_PROFDICT_DEFAULT_MAX;
	if ((d->map = calloc(1, sizeof(*d->map))) == NULL)
		return (-1);
	/* Every table's first entry is its zero value. */
	if (oe_profdict_string(d, "") != 0 || GROW(d, mappings) != 0 ||
	    GROW(d, functions) != 0 || GROW(d, locations) != 0 ||
	    GROW(d, stacks) != 0 || GROW(d, links) != 0 ||
	    GROW(d, attrs) != 0) {
		oe_profdict_fini(d);
		return (-1);
	}
	memset(&d->mappings[d->nmappings++], 0, sizeof(*d->mappings));
	memset(&d->functions[d->nfunctions++], 0, sizeof(*d->functions));
	memset(&d->locations[d->nlocations++], 0, sizeof(*d->locations));
	memset(&d->stacks[d->nstacks++], 0, sizeof(*d->stacks));
	memset(&d->links[d->nlinks++], 0, sizeof(*d->links));
	memset(&d->attrs[d->nattrs++], 0, sizeof(*d->attrs));
	return (0);
}

void
oe_profdict_fini(struct oe_profdict *d)
{
	size_t i;

	for (i = 0; i < d->nstrings; i++)
		free(d->strings[i]);
	for (i = 0; i < d->nstacks; i++)
		free(d->stacks[i].locations);
	for (i = 0; i < d->nattrs; i++)
		free(d->attrs[i].s);
	for (i = 0; i < d->nsamples; i++) {
		free(d->samples[i].attrs);
		free(d->samples[i].values);
		free(d->samples[i].timestamps);
	}
	if (d->map != NULL) {
		for (i = 0; i < d->map->cap; i++)
			free(d->map->ents[i].key);
		free(d->map->ents);
		free(d->map);
	}
	free(d->strings);
	free(d->mappings);
	free(d->functions);
	free(d->locations);
	free(d->stacks);
	free(d->links);
	free(d->attrs);
	free(d->samples);
	memset(d, 0, sizeof(*d));
}

int32_t
oe_profdict_string(struct oe_profdict *d, const char *s)
{
	struct pd_key k;
	int32_t idx;
	char *copy;

	if (key_make(&k, TAG_STRING, s, strlen(s), NULL, 0) == NULL) {
		errno = ENOMEM;
		return (fail(d));
	}
	idx = map_get(d, k.p, k.len, -1);
	if (idx >= 0 || GROW(d, strings) != 0 ||
	    (copy = strdup(s)) == NULL) {
		key_free(&k);
		if (idx >= 0)
			return (idx);
		/* GROW() set errno; so may strdup(), but not every one. */
		if (d->nstrings < d->max)
			errno = ENOMEM;
		return (fail(d));
	}
	idx = map_get(d, k.p, k.len, (int32_t)d->nstrings);
	key_free(&k);
	if (idx < 0) {
		free(copy);
		errno = ENOMEM;
		return (fail(d));
	}
	d->strings[d->nstrings++] = copy;
	return (idx);
}

/*
 * Intern a fixed-size entry: look its key up, else append it to its
 * table (whose room the caller made) and index it.
 */
static int32_t
intern(struct oe_profdict *d, int tag, const void *val, size_t len,
    size_t *n)
{
	struct pd_key k;
	int32_t idx;

	/* Keys of fixed-size entries fit the small buffer. */
	(void)key_make(&k, tag, val, len, NULL, 0);
	idx = map_get(d, k.p, k.len, -1);
	if (idx >= 0)
		return (idx);
	idx = map_get(d, k.p, k.len, (int32_t)*n);
	if (idx < 0) {
		errno = ENOMEM;
		return (fail(d));
	}
	(*n)++;
	return (idx);
}

static int32_t
intern_mapping(struct oe_profdict *d, const char *module)
{
	struct oe_pd_mapping m;
	int32_t idx;

	if (module == NULL || module[0] == '\0')
		return (0);
	memset(&m, 0, sizeof(m));
	if ((m.filename = oe_profdict_string(d, module)) < 0)
		return (-1);
	if (GROW(d, mappings) != 0)
		return (fail(d));
	d->mappings[d->nmappings] = m;
	idx = intern(d, TAG_MAPPING, &m, sizeof(m), &d->nmappings);
	return (idx);
}

static int32_t
intern_function(struct oe_profdict *d, const char *symbol)
{
	struct oe_pd_function f;

	memset(&f, 0, sizeof(f));
	if ((f.name = oe_profdict_string(d, symbol)) < 0)
		return (-1);
	f.system_name = f.name;
	if (GROW(d, functions) != 0)
		return (fail(d));
	d->functions[d->nfunctions] = f;
	return (intern(d, TAG_FUNCTION, &f, sizeof(f), &d->nfunctions));
}

/* "0x" and hex digits only: an unsymbolized address. */
static int
hex_symbol(const char *s, uint64_t *addr)
{
	char *end;

	if (s == NULL || s[0] != '0' || s[1] != 'x' || s[2] == '\0')
		return (0);
	errno = 0;
	*addr = strtoull(s + 2, &end, 16);
	return (*end == '\0' && errno == 0);
}

static int32_t
intern_location(struct oe_profdict *d, const struct oe_frame *f)
{
	struct oe_pd_location l;
	uint64_t addr;

	memset(&l, 0, sizeof(l));
	if ((l.mapping = intern_mapping(d, f->module)) < 0)
		return (-1);
	if (hex_symbol(f->symbol, &addr))
		l.address = addr;
	else if (f->symbol != NULL && f->symbol[0] != '\0') {
		if ((l.function = intern_function(d, f->symbol)) < 0)
			return (-1);
	} else
		l.address = f->addr;
	if (GROW(d, locations) != 0)
		return (fail(d));
	d->locations[d->nlocations] = l;
	return (intern(d, TAG_LOCATION, &l, sizeof(l), &d->nlocations));
}

static int32_t
intern_stack(struct oe_profdict *d, const struct oe_profile_sample *s)
{
	struct pd_key k;
	int32_t *locs, idx;
	size_t i, n;

	n = s->nstack + s->nustack;
	if (n == 0)
		return (0);
	if ((locs = calloc(n, sizeof(*locs))) == NULL) {
		d->error = 1;
		return (-1);
	}
	for (i = 0; i < n; i++)
		if ((locs[i] = intern_location(d, i < s->nstack ?
		    &s->stack[i] : &s->ustack[i - s->nstack])) < 0) {
			free(locs);
			return (-1);
		}
	if (key_make(&k, TAG_STACK, locs, n * sizeof(*locs), NULL, 0) ==
	    NULL) {
		free(locs);
		errno = ENOMEM;
		return (fail(d));
	}
	idx = map_get(d, k.p, k.len, -1);
	if (idx >= 0 || GROW(d, stacks) != 0) {
		key_free(&k);
		free(locs);
		return (idx >= 0 ? idx : fail(d));
	}
	idx = map_get(d, k.p, k.len, (int32_t)d->nstacks);
	key_free(&k);
	if (idx < 0) {
		free(locs);
		errno = ENOMEM;
		return (fail(d));
	}
	d->stacks[d->nstacks].locations = locs;
	d->stacks[d->nstacks++].n = n;
	return (idx);
}

/*
 * The identity of an attribute: its key index and type, then the value's
 * bytes (a string's text, or the number).
 */
struct pd_attr_id {
	int32_t		 key;
	int32_t		 type;
	int64_t		 i;
	double		 d;
};

int32_t
oe_profdict_attr(struct oe_profdict *d, const struct oe_kv *kv)
{
	struct pd_attr_id id;
	struct pd_key k;
	const char *str;
	int32_t idx;

	memset(&id, 0, sizeof(id));
	if ((id.key = oe_profdict_string(d, kv->key)) < 0)
		return (-1);
	id.type = (int32_t)kv->type;
	str = "";
	switch (kv->type) {
	case OE_VAL_STRING:
		if (kv->s != NULL)
			str = kv->s;
		break;
	case OE_VAL_BOOL:
		id.i = kv->i != 0;
		break;
	case OE_VAL_INT:
		id.i = kv->i;
		break;
	case OE_VAL_DOUBLE:
		id.d = kv->d;
		break;
	}
	if (key_make(&k, TAG_ATTR, &id, sizeof(id), str, strlen(str)) ==
	    NULL) {
		errno = ENOMEM;
		return (fail(d));
	}
	idx = map_get(d, k.p, k.len, -1);
	if (idx >= 0 || GROW(d, attrs) != 0) {
		key_free(&k);
		return (idx >= 0 ? idx : fail(d));
	}
	memset(&d->attrs[d->nattrs], 0, sizeof(*d->attrs));
	if (kv->type == OE_VAL_STRING &&
	    (d->attrs[d->nattrs].s = strdup(str)) == NULL) {
		key_free(&k);
		errno = ENOMEM;
		return (fail(d));
	}
	idx = map_get(d, k.p, k.len, (int32_t)d->nattrs);
	key_free(&k);
	if (idx < 0) {
		free(d->attrs[d->nattrs].s);
		errno = ENOMEM;
		return (fail(d));
	}
	d->attrs[d->nattrs].key = id.key;
	d->attrs[d->nattrs].type = kv->type;
	d->attrs[d->nattrs].i = id.i;
	d->attrs[d->nattrs].d = id.d;
	d->nattrs++;
	return (idx);
}

static int32_t
intern_link(struct oe_profdict *d, const struct oe_profile_sample *s)
{
	struct oe_pd_link l;

	if (oe_id_is_zero(s->trace_id, OE_TRACE_ID_LEN))
		return (0);
	memcpy(l.trace_id, s->trace_id, OE_TRACE_ID_LEN);
	memcpy(l.span_id, s->span_id, OE_SPAN_ID_LEN);
	if (GROW(d, links) != 0)
		return (fail(d));
	d->links[d->nlinks] = l;
	return (intern(d, TAG_LINK, &l, sizeof(l), &d->nlinks));
}

static int
int32_cmp(const void *a, const void *b)
{
	int32_t x = *(const int32_t *)a, y = *(const int32_t *)b;

	return (x < y ? -1 : x > y);
}

/*
 * The sample's attribute indices, sorted (their set is part of the
 * sample's identity), keys unique with a later key replacing an
 * earlier one.  *np is set; NULL with *np 0 when there are none.
 */
static int
sample_attrs(struct oe_profdict *d, const struct oe_profile_sample *s,
    int32_t **idxp, size_t *np)
{
	struct oe_kv ctxkv[OE_CONTEXT_MAXKV];
	const struct oe_kv *kv;
	char jid[16];
	int32_t *idx;
	size_t nctx, total, i, j, n;

	*idxp = NULL;
	*np = 0;
	nctx = oe_context_kvs(s->pid, s->execname, &s->ctx, ctxkv, jid);
	total = nctx + s->nattrs;
	if (total == 0)
		return (0);
	if ((idx = calloc(total, sizeof(*idx))) == NULL) {
		d->error = 1;
		return (-1);
	}
	n = 0;
	for (i = 0; i < total; i++) {
		kv = i < nctx ? &ctxkv[i] : &s->attrs[i - nctx];
		/* A later entry with the same key wins. */
		for (j = i + 1; j < total; j++)
			if (strcmp((j < nctx ? &ctxkv[j] :
			    &s->attrs[j - nctx])->key, kv->key) == 0)
				break;
		if (j < total)
			continue;
		if ((idx[n++] = oe_profdict_attr(d, kv)) < 0) {
			free(idx);
			return (-1);
		}
	}
	qsort(idx, n, sizeof(*idx), int32_cmp);
	*idxp = idx;
	*np = n;
	return (0);
}

static int
push_value(struct oe_pd_sample *ps, int64_t v)
{
	int64_t *p;
	size_t nc;

	if (ps->nvalues == ps->capvalues) {
		nc = ps->capvalues == 0 ? 4 : ps->capvalues * 2;
		if ((p = pd_realloc(ps->values, nc, sizeof(*p))) == NULL)
			return (-1);
		ps->values = p;
		ps->capvalues = nc;
	}
	ps->values[ps->nvalues++] = v;
	return (0);
}

static int
push_time(struct oe_pd_sample *ps, const struct timespec *ts)
{
	uint64_t *p;
	size_t nc;

	if (ps->ntimestamps == ps->captimestamps) {
		nc = ps->captimestamps == 0 ? 4 : ps->captimestamps * 2;
		if ((p = pd_realloc(ps->timestamps, nc, sizeof(*p))) == NULL)
			return (-1);
		ps->timestamps = p;
		ps->captimestamps = nc;
	}
	ps->timestamps[ps->ntimestamps++] = ts->tv_sec < 0 ? 0 :
	    (uint64_t)ts->tv_sec * 1000000000ULL + (uint64_t)ts->tv_nsec;
	return (0);
}

/* Add the sample's observations to ps. */
static int
observe(struct oe_pd_sample *ps, const struct oe_profile_sample *s,
    int64_t value)
{
	size_t i;

	if (ps->shape == SHAPE_VALUE) {
		if (ps->nvalues == 0)
			return (push_value(ps, value));
		ps->values[0] += value;
		return (0);
	}
	for (i = 0; i < s->ntimestamps; i++) {
		if (push_time(ps, &s->timestamps[i]) != 0)
			return (-1);
		if (ps->shape == SHAPE_BOTH && push_value(ps, value) != 0)
			return (-1);
	}
	return (0);
}

int
oe_profdict_sample(struct oe_profdict *d, const struct oe_profile_sample *s)
{
	struct oe_pd_sample *ps;
	struct pd_key k;
	int32_t stack, link, *attrs, idx, id[3];
	size_t nattrs;
	int64_t value;
	int shape;

	if (d->error)
		return (-1);
	/* A sample without values or times is one observation. */
	value = s->has_value ? s->value : 1;
	shape = s->ntimestamps == 0 ? SHAPE_VALUE : s->has_value ?
	    SHAPE_BOTH : SHAPE_TIMES;
	attrs = NULL;
	if ((stack = intern_stack(d, s)) < 0 ||
	    (link = intern_link(d, s)) < 0 ||
	    sample_attrs(d, s, &attrs, &nattrs) != 0)
		goto drop;
	id[0] = stack;
	id[1] = link;
	id[2] = shape;
	if (key_make(&k, TAG_SAMPLE, id, sizeof(id), attrs, nattrs *
	    sizeof(*attrs)) == NULL) {
		d->error = 1;
		goto drop;
	}
	idx = map_get(d, k.p, k.len, -1);
	if (idx >= 0) {
		key_free(&k);
		free(attrs);
		if (observe(&d->samples[idx], s, value) != 0) {
			d->error = 1;
			return (-1);
		}
		return (0);
	}
	if (GROW(d, samples) != 0) {
		key_free(&k);
		(void)fail(d);
		goto drop;
	}
	ps = &d->samples[d->nsamples];
	memset(ps, 0, sizeof(*ps));
	ps->stack = stack;
	ps->link = link;
	ps->shape = shape;
	ps->attrs = attrs;
	ps->nattrs = nattrs;
	if (observe(ps, s, value) != 0 ||
	    map_get(d, k.p, k.len, (int32_t)d->nsamples) < 0) {
		key_free(&k);
		free(ps->values);
		free(ps->timestamps);
		d->error = 1;
		goto drop;
	}
	key_free(&k);
	d->nsamples++;
	return (0);
drop:
	/* The attributes are never a committed sample's here. */
	free(attrs);
	if (!d->error)
		d->dropped++;
	return (-1);
}
