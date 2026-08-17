/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Collapsed-stack exporter for flamegraph generation.  Accumulates
 * stack traces during the run and emits folded stacks at shutdown in
 * the format consumed by flamegraph.pl, speedscope, and pprof:
 *
 *	execname;module`func;module`func 42
 *
 * When both kernel and user stacks are present the kernel stack goes
 * on the bottom, separated from the user stack by a "--" frame.
 * DTrace reports stacks leaf-first; flamegraphs read root-first, so
 * frames are reversed on the way in.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "otelexport.h"

struct fold_entry {
	struct fold_entry *next;
	char		*stack;
	uint64_t	 count;
};

#define	FOLD_NBUCKETS	4096

struct oe_collapsed {
	struct oe_exporter e;
	FILE		*out;
	struct fold_entry *buckets[FOLD_NBUCKETS];
	size_t		 nentries;
};

static uint32_t
fold_hash(const char *s)
{
	uint32_t h = 2166136261u;

	while (*s != '\0') {
		h ^= (unsigned char)*s++;
		h *= 16777619u;
	}
	return (h);
}

static int
collapsed_start(struct oe_exporter *e __unused)
{

	return (0);
}

static void
append_reversed(struct oe_buf *b, const struct oe_frame *frames, size_t n)
{
	char frame[256];
	size_t i;

	for (i = n; i > 0; i--) {
		oe_frame_format(&frames[i - 1], frame, sizeof(frame));
		oe_buf_appendstr(b, ";");
		oe_buf_appendstr(b, frame);
	}
}

static int
collapsed_event(struct oe_exporter *e, const struct oe_event *ev)
{
	struct oe_collapsed *c = (struct oe_collapsed *)e;
	struct fold_entry *fe;
	struct oe_buf b;
	uint32_t idx;

	if (ev->nstack == 0 && ev->nustack == 0)
		return (0);

	oe_buf_init(&b);
	/* Process name is the root frame. */
	oe_buf_appendstr(&b, ev->execname != NULL ? ev->execname : "");
	append_reversed(&b, ev->stack, ev->nstack);
	if (ev->nstack > 0 && ev->nustack > 0)
		oe_buf_appendstr(&b, ";--");
	append_reversed(&b, ev->ustack, ev->nustack);
	if (b.error) {
		oe_buf_free(&b);
		return (-1);
	}

	idx = fold_hash(b.data) % FOLD_NBUCKETS;
	for (fe = c->buckets[idx]; fe != NULL; fe = fe->next) {
		if (strcmp(fe->stack, b.data) == 0) {
			fe->count++;
			oe_buf_free(&b);
			return (0);
		}
	}
	fe = malloc(sizeof(*fe));
	if (fe == NULL) {
		oe_buf_free(&b);
		return (-1);
	}
	fe->stack = b.data;	/* steal the buffer */
	fe->count = 1;
	fe->next = c->buckets[idx];
	c->buckets[idx] = fe;
	c->nentries++;
	return (0);
}

static int
collapsed_snapshot(struct oe_exporter *e __unused,
    const struct oe_snapshot *sn __unused)
{

	return (0);
}

static int
collapsed_flush(struct oe_exporter *e __unused)
{

	return (0);
}

static int
fold_cmp(const void *a, const void *b)
{
	const struct fold_entry *fa = *(const struct fold_entry * const *)a;
	const struct fold_entry *fb = *(const struct fold_entry * const *)b;

	return (strcmp(fa->stack, fb->stack));
}

static int
collapsed_shutdown(struct oe_exporter *e)
{
	struct oe_collapsed *c = (struct oe_collapsed *)e;
	struct fold_entry **sorted, *fe;
	size_t i, n;

	sorted = malloc(c->nentries * sizeof(*sorted));
	if (sorted == NULL)
		return (-1);
	n = 0;
	for (i = 0; i < FOLD_NBUCKETS; i++)
		for (fe = c->buckets[i]; fe != NULL; fe = fe->next)
			sorted[n++] = fe;
	/* Sort by stack path for stable output. */
	qsort(sorted, n, sizeof(*sorted), fold_cmp);
	for (i = 0; i < n; i++)
		fprintf(c->out, "%s %ju\n", sorted[i]->stack,
		    (uintmax_t)sorted[i]->count);
	free(sorted);
	fflush(c->out);
	return (0);
}

static void
collapsed_free(struct oe_exporter *e)
{
	struct oe_collapsed *c = (struct oe_collapsed *)e;
	struct fold_entry *fe, *next;
	size_t i;

	for (i = 0; i < FOLD_NBUCKETS; i++) {
		for (fe = c->buckets[i]; fe != NULL; fe = next) {
			next = fe->next;
			free(fe->stack);
			free(fe);
		}
	}
	free(c);
}

static const struct oe_exporter_ops collapsed_ops = {
	.start = collapsed_start,
	.event = collapsed_event,
	.snapshot = collapsed_snapshot,
	.flush = collapsed_flush,
	.shutdown = collapsed_shutdown,
	.free = collapsed_free,
};

struct oe_exporter *
oe_collapsed_new(FILE *out)
{
	struct oe_collapsed *c;

	c = calloc(1, sizeof(*c));
	if (c == NULL)
		return (NULL);
	c->e.ops = &collapsed_ops;
	c->out = out;
	return (&c->e);
}
