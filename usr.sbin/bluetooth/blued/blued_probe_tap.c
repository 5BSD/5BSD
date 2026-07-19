/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * In-process probe tap backend for blued -- see blued_probe_tap.h.
 *
 * Selected by -DWITH_PROBE_TAP.  Dependency-free (only libc), no locking:
 * the ring is only ever touched from the single thread that drives the
 * protocol under test.
 */

#include <stdarg.h>
#include <string.h>

#include "blued_probe_tap.h"

static struct probe_rec	ring[PROBE_TAP_RING_SIZE];
static size_t		ring_total;	/* total records ever appended */

void
probe_tap_reset(void)
{

	memset(ring, 0, sizeof(ring));
	ring_total = 0;
}

size_t
probe_tap_count(void)
{

	if (ring_total < PROBE_TAP_RING_SIZE)
		return (ring_total);
	return (PROBE_TAP_RING_SIZE);
}

const struct probe_rec *
probe_tap_get(size_t i)
{
	size_t start;

	if (i >= probe_tap_count())
		return (NULL);
	/*
	 * Once the ring has wrapped, the oldest surviving record is at
	 * ring_total % SIZE.  Before wrapping, records are chronological
	 * from index 0.
	 */
	if (ring_total <= PROBE_TAP_RING_SIZE)
		return (&ring[i]);
	start = ring_total % PROBE_TAP_RING_SIZE;
	return (&ring[(start + i) % PROBE_TAP_RING_SIZE]);
}

size_t
probe_tap_find(const char *name, size_t from)
{
	size_t n, i;

	n = probe_tap_count();
	for (i = from; i < n; i++) {
		const struct probe_rec *r = probe_tap_get(i);

		if (r != NULL && r->name != NULL && strcmp(r->name, name) == 0)
			return (i);
	}
	return (n);	/* not found: == count(), a valid "end" sentinel */
}

/*
 * Append a record.  Common tail shared by the arity-specific helpers.
 */
static void
probe_tap_append(const char *name, const char *str, unsigned nargs,
    const uint64_t *args)
{
	struct probe_rec *r = &ring[ring_total % PROBE_TAP_RING_SIZE];

	memset(r, 0, sizeof(*r));
	r->name = name;
	if (nargs > PROBE_TAP_MAX_ARGS)
		nargs = PROBE_TAP_MAX_ARGS;
	r->nargs = nargs;
	for (unsigned i = 0; i < nargs; i++)
		r->args[i] = args[i];
	if (str != NULL) {
		strlcpy(r->str, str, sizeof(r->str));
		r->has_str = 1;
	} else {
		r->str[0] = '\0';
		r->has_str = 0;
	}
	ring_total++;
}

void
probe_tap_rec0(const char *name, const char *str)
{

	probe_tap_append(name, str, 0, NULL);
}

void
probe_tap_rec1(const char *name, const char *str, uint64_t a0)
{
	uint64_t a[1] = { a0 };

	probe_tap_append(name, str, 1, a);
}

void
probe_tap_rec2(const char *name, const char *str, uint64_t a0, uint64_t a1)
{
	uint64_t a[2] = { a0, a1 };

	probe_tap_append(name, str, 2, a);
}

void
probe_tap_rec3(const char *name, const char *str, uint64_t a0, uint64_t a1,
    uint64_t a2)
{
	uint64_t a[3] = { a0, a1, a2 };

	probe_tap_append(name, str, 3, a);
}

void
probe_tap_rec4(const char *name, const char *str, uint64_t a0, uint64_t a1,
    uint64_t a2, uint64_t a3)
{
	uint64_t a[4] = { a0, a1, a2, a3 };

	probe_tap_append(name, str, 4, a);
}
