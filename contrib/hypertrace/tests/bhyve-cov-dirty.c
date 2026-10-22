/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Production-configuration tests of migration_dirty.c (device DMA dirty
 * tracker) and migration_precopy.c (CPU+device dirty-log transaction).  The
 * original sources are included in this translation unit with the production
 * preprocessor view so their internal state can be driven to exhaustion;
 * coverage-bhyve.py credits them only through mappings identical to the
 * production objects.  libvmmapi's result validator is linked unchanged.
 *
 * Oracles: an independent reference model of the dirty tracker contract
 * (marks are page-granular and clamped to the tracked range; CLEAR returns
 * and clears pages marked since the last successful CLEAR, abort or a failure
 * returns captured pages to the active set, OBSERVE never clears; identities
 * and generations advance exactly as documented; exhaustion is terminal) is
 * compared against the implementation over seeded random operation
 * sequences, plus exact checks of the pre-copy transaction states, the union
 * of CPU and device bitmaps, and the free-page hint set.
 */
#include "migration_dirty.c"
#include "migration_precopy.c"
#include <dev/vmm/vmm_dirty_log.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: CHECK(%s) failed (seed %u step %d)\n", \
	__FILE__, __LINE__, #x, seed, step); abort(); } } while (0)

static unsigned seed;
static int step;

struct vmctx { int id; };
static struct vmctx vm_a = { 1 }, vm_b = { 2 };

/* ------------------------------------------------- libvmmapi boundary */
static int dirty_log_error, dirty_log_mutation;
static uint64_t kernel_identity = 77, kernel_generation = 1;
static uint8_t kernel_bitmap[4096];

int
vm_dirty_log_request(struct vmctx *ctx, const struct vmm_dirty_log_request *request)
{
	struct vmm_dirty_log_result *result;
	size_t bytes;

	CHECK(ctx != NULL);
	if (dirty_log_error != 0) {
		errno = dirty_log_error == -1 ? 0 : dirty_log_error;
		return (-1);
	}
	if (request->operation == VMM_DIRTY_LOG_REQUEST_ENABLE ||
	    request->operation == VMM_DIRTY_LOG_REQUEST_DISABLE)
		return (0);
	result = (void *)(uintptr_t)request->output_address;
	bytes = request->output_bytes - sizeof(*result);
	memset(result, 0, sizeof(*result));
	result->version = VMM_DIRTY_LOG_RESULT_VERSION;
	result->size = VMM_DIRTY_LOG_RESULT_SIZE;
	result->operation = request->operation;
	result->gpa = request->gpa;
	result->length = request->length;
	result->identity = kernel_identity;
	result->map_generation = 1;
	result->dirty_generation = kernel_generation++;
	result->bitmap_offset = sizeof(*result);
	result->bitmap_bytes = bytes;
	memcpy(result + 1, kernel_bitmap, bytes);
	switch (dirty_log_mutation) {
	case 1: result->flags = 1; break;			/* validator rejects */
	case 2: result->gpa += VMM_DIRTY_LOG_GRANULARITY; break;	/* mismatch */
	case 3: result->identity = 0; result->map_generation = 0; break;
	case 4: result->operation = request->operation == VMM_DIRTY_LOG_REQUEST_CLEAR ?
	    VMM_DIRTY_LOG_REQUEST_OBSERVE : VMM_DIRTY_LOG_REQUEST_CLEAR; break;
	case 5: result->length -= VMM_DIRTY_LOG_GRANULARITY; break;
	case 6: result->bitmap_bytes--; break;
	}
	return (0);
}

static int precopy_validate_error;
int
pci_migration_precopy_validate(void)
{
	return (precopy_validate_error);
}

/* ------------------------------------------------- reference model */
#define MAX_PAGES 256
struct model {
	bool on, collecting, exhausted;
	struct vmctx *owner;
	uint64_t gpa, length, identity, generation;
	uint64_t cgpa, clength;
	int cmode, failure;
	uint8_t active[MAX_PAGES], captured[MAX_PAGES];
};
static struct model m;
#define PG MIGRATION_DIRTY_GRANULARITY

static int
model_enable(struct vmctx *ctx, uint64_t gpa, uint64_t length)
{
	if (ctx == NULL || length == 0 || gpa % PG != 0 || length % PG != 0 ||
	    gpa > UINT64_MAX - (length - 1))
		return (EINVAL);
	if (m.exhausted)
		return (EOVERFLOW);
	if (m.on)
		return (EBUSY);
	m.identity++;
	m.on = true;
	m.owner = ctx;
	m.gpa = gpa;
	m.length = length;
	m.generation = 1;
	m.failure = 0;
	m.collecting = false;
	memset(m.active, 0, sizeof(m.active));
	memset(m.captured, 0, sizeof(m.captured));
	return (0);
}

static int
model_disable(struct vmctx *ctx)
{
	if (ctx == NULL)
		return (EINVAL);
	if (m.exhausted)
		return (EOVERFLOW);
	if (!m.on || m.owner != ctx)
		return (ENOENT);
	if (m.collecting)
		return (EBUSY);
	m.on = false;
	m.owner = NULL;
	m.identity++;
	return (0);
}

static int
model_mark(struct vmctx *ctx, uint64_t gpa, size_t length)
{
	if (ctx == NULL)
		return (EINVAL);
	if (length == 0)
		return (0);
	if (gpa > UINT64_MAX - (length - 1))
		return (EOVERFLOW);
	if (!m.on || m.owner != ctx)
		return (0);
	if (m.exhausted)
		return (EOVERFLOW);
	if (m.failure != 0)
		return (m.failure);
	for (uint64_t p = 0; p < m.length / PG; p++) {
		uint64_t start = m.gpa + p * PG, end = start + PG - 1;
		if (end >= gpa && start <= gpa + length - 1)
			m.active[p] = 1;
	}
	return (0);
}

static int
model_begin(struct vmctx *ctx, uint64_t gpa, uint64_t length, int mode, uint8_t *expect)
{
	if (m.exhausted)
		return (EOVERFLOW);
	if (!m.on || m.collecting || m.owner != ctx)
		return (!m.on ? ENOENT : EBUSY);
	if (gpa < m.gpa || gpa - m.gpa >= m.length || length > m.length - (gpa - m.gpa))
		return (ERANGE);
	if (m.failure != 0)
		return (m.failure);
	m.identity++;
	memset(expect, 0, MAX_PAGES / 8);
	for (uint64_t i = 0; i < length / PG; i++) {
		uint64_t p = (gpa - m.gpa) / PG + i;
		if (!m.active[p])
			continue;
		expect[i / 8] |= (uint8_t)(1U << (i % 8));
		if (mode == MIGRATION_DIRTY_CLEAR) {
			m.captured[p] = 1;
			m.active[p] = 0;
		}
	}
	m.collecting = true;
	m.cgpa = gpa;
	m.clength = length;
	m.cmode = mode;
	return (0);
}

static int
model_settle(bool aborting)
{
	int error = 0;

	if (!m.collecting)
		return (ESTALE);
	if (m.failure != 0) {
		error = m.failure;
		aborting = true;
	}
	if (m.cmode == MIGRATION_DIRTY_CLEAR) {
		for (int p = 0; p < MAX_PAGES; p++) {
			if (aborting && m.captured[p])
				m.active[p] = 1;
			m.captured[p] = 0;
		}
		if (!aborting)
			m.generation++;
	}
	m.collecting = false;
	return (error);
}

static void
test_tracker_model(void)
{
	struct migration_dirty_ticket ticket = {0}, stale;
	uint8_t bitmap[MAX_PAGES / 8], expect[MAX_PAGES / 8];
	bool have_ticket = false;
	int operations = 0;

	for (seed = 1; seed <= 40; seed++) {
		srandom(seed);
		/* Fresh state for each sequence. */
		memset(&migration_dirty_tracker.phase, 0, sizeof(migration_dirty_tracker.phase));
		free(migration_dirty_tracker.active);
		free(migration_dirty_tracker.captured);
		migration_dirty_tracker.active = migration_dirty_tracker.captured = NULL;
		migration_dirty_tracker.owner = NULL;
		migration_dirty_tracker.identity = 0;
		migration_dirty_tracker.phase = MIGRATION_DIRTY_OFF;
		memset(&m, 0, sizeof(m));
		have_ticket = false;
		for (step = 0; step < 500; step++, operations++) {
			int op = (int)(random() % 9), a, b;
			struct vmctx *ctx = random() % 8 == 0 ? &vm_b : &vm_a;
			uint64_t gpa = (uint64_t)(random() % 64) * PG + (random() % 16 == 0 ? 7 : 0);
			uint64_t length = (uint64_t)(random() % 64 + (random() % 32 == 0 ? 0 : 1)) * PG;
			switch (op) {
			case 0:
				a = migration_dirty_enable(ctx, gpa, length);
				b = model_enable(ctx, gpa, length);
				CHECK(a == b);
				break;
			case 1:
				a = migration_dirty_disable(ctx);
				b = model_disable(ctx);
				CHECK(a == b);
				break;
			case 2:
			case 3: {
				uint64_t g = (uint64_t)(random() % (80 * PG));
				size_t l = (size_t)(random() % (3 * PG));
				a = migration_dirty_mark(ctx, g, l);
				b = model_mark(ctx, g, l);
				CHECK(a == b);
				break;
			}
			case 4: {
				int mode = random() % 2 ? MIGRATION_DIRTY_CLEAR : MIGRATION_DIRTY_OBSERVE;
				uint64_t g = m.on ? m.gpa + (uint64_t)(random() % (m.length / PG)) * PG : gpa;
				uint64_t l = m.on ? (uint64_t)(random() % ((m.gpa + m.length - g) / PG) + 1) * PG : length;
				size_t bytes;
				if (random() % 10 == 0)
					l += PG;	/* past the tracked range */
				if (migration_dirty_range_bitmap_bytes(g, l, &bytes) != 0 || bytes > sizeof(bitmap))
					break;
				a = migration_dirty_begin_range(ctx, g, l, mode, bitmap, bytes, &ticket);
				b = model_begin(ctx, g, l, mode, expect);
				CHECK(a == b);
				if (a == 0) {
					CHECK(memcmp(bitmap, expect, bytes) == 0);
					CHECK(ticket.identity == m.identity && ticket.generation == m.generation);
					have_ticket = true;
				}
				break;
			}
			case 5:
			case 6:
				if (!have_ticket)
					break;
				stale = ticket;
				if (random() % 8 == 0) {
					stale.generation++;
					CHECK(migration_dirty_finish(&vm_a, &stale) == ESTALE);
				}
				a = op == 5 ? migration_dirty_finish(m.owner ? m.owner : &vm_a, &ticket) :
				    migration_dirty_abort(m.owner ? m.owner : &vm_a, &ticket);
				b = model_settle(op == 6);
				CHECK(a == b);
				have_ticket = false;
				break;
			case 7:
				if (random() % 4 == 0) {
					int e = random() % 2 ? EIO : ENOSPC;
					migration_dirty_fail(ctx, e);
					if (m.on && m.owner == ctx && m.failure == 0 && !m.exhausted)
						m.failure = e;
				}
				break;
			case 8: {
				size_t bytes = 0;
				a = migration_dirty_bitmap_bytes(ctx, &bytes);
				b = !m.on || m.owner != ctx ? ENOENT : 0;
				CHECK(a == b);
				if (a == 0)
					CHECK(bytes == (m.length / PG + 7) / 8);
				break;
			}
			}
		}
		if (migration_dirty_tracker.phase == MIGRATION_DIRTY_COLLECTING)
			(void)migration_dirty_abort(migration_dirty_tracker.owner, &ticket);
	}
	printf("dirty tracker: %d model-checked operations over 40 seeds\n", operations);
}

static void
test_tracker_edges(void)
{
	struct migration_dirty_ticket ticket;
	uint8_t bitmap[8];
	size_t bytes;

	seed = 0;
	step = 0;
	/* Argument contracts. */
	CHECK(migration_dirty_range_bitmap_bytes(0, PG, NULL) == EINVAL);
	CHECK(migration_dirty_range_bitmap_bytes(0, 0, &bytes) == EINVAL);
	CHECK(migration_dirty_range_bitmap_bytes(UINT64_MAX - PG + 1, 2 * PG, &bytes) == EINVAL);
	CHECK(migration_dirty_range_bitmap_bytes(0, 9 * PG, &bytes) == 0 && bytes == 2);
	CHECK(migration_dirty_enable(NULL, 0, PG) == EINVAL);
	CHECK(migration_dirty_disable(NULL) == EINVAL);
	CHECK(migration_dirty_bitmap_bytes(NULL, &bytes) == EINVAL);
	CHECK(migration_dirty_bitmap_bytes(&vm_a, NULL) == EINVAL);
	CHECK(migration_dirty_mark(NULL, 0, 1) == EINVAL);
	CHECK(migration_dirty_mark(&vm_a, UINT64_MAX, 2) == EOVERFLOW);
	migration_dirty_fail(NULL, EIO);
	migration_dirty_fail(&vm_a, 0);
	CHECK(migration_dirty_begin(NULL, MIGRATION_DIRTY_CLEAR, bitmap, 1, &ticket) == EINVAL);
	CHECK(migration_dirty_begin_range(&vm_a, 0, PG, 9, bitmap, 1, &ticket) == EINVAL);
	CHECK(migration_dirty_begin_range(&vm_a, 0, PG, MIGRATION_DIRTY_CLEAR, bitmap, 2,
	    &ticket) == EINVAL);
	/* Bitmap overlapping the ticket. */
	CHECK(migration_dirty_begin_range(&vm_a, 0, 8 * PG, MIGRATION_DIRTY_CLEAR,
	    (uint8_t *)&ticket, 1, &ticket) == EINVAL);
	CHECK(migration_dirty_finish(NULL, &ticket) == EINVAL);
	CHECK(migration_dirty_abort(&vm_a, NULL) == EINVAL);
	CHECK(migration_dirty_begin(&vm_a, MIGRATION_DIRTY_CLEAR, bitmap, 1, &ticket) == ENOENT);
	/* Allocation failure of either bitmap leaves the tracker off. */
	{
		extern void dirty_fail_next_calloc(int);
		dirty_fail_next_calloc(1);
		CHECK(migration_dirty_enable(&vm_a, 0, 8 * PG) == ENOMEM);
		dirty_fail_next_calloc(2);
		CHECK(migration_dirty_enable(&vm_a, 0, 8 * PG) == ENOMEM);
		CHECK(migration_dirty_tracker.phase == MIGRATION_DIRTY_OFF);
	}
	/* begin() covers the whole range; a reserved ticket field is stale. */
	CHECK(migration_dirty_enable(&vm_a, 0, 8 * PG) == 0);
	CHECK(migration_dirty_mark(&vm_a, 3 * PG, 1) == 0);
	CHECK(migration_dirty_begin(&vm_a, MIGRATION_DIRTY_CLEAR, bitmap, 1, &ticket) == 0);
	CHECK(bitmap[0] == 0x08);
	ticket.reserved = 1;
	CHECK(migration_dirty_finish(&vm_a, &ticket) == ESTALE);
	ticket.reserved = 0;
	CHECK(migration_dirty_disable(&vm_a) == EBUSY);
	CHECK(migration_dirty_finish(&vm_a, &ticket) == 0);
	/* Every ticket field is checked; a mark of zero bytes is a no-op. */
	CHECK(migration_dirty_mark(&vm_a, 0, 0) == 0);
	CHECK(migration_dirty_begin(&vm_a, MIGRATION_DIRTY_OBSERVE, bitmap, 1, &ticket) == 0);
	{
		struct migration_dirty_ticket bad;
		uint8_t other[8];
		struct migration_dirty_ticket other_ticket;
		bad = ticket; bad.identity++;
		CHECK(migration_dirty_abort(&vm_a, &bad) == ESTALE);
		bad = ticket; bad.gpa += PG;
		CHECK(migration_dirty_abort(&vm_a, &bad) == ESTALE);
		bad = ticket; bad.length -= PG;
		CHECK(migration_dirty_abort(&vm_a, &bad) == ESTALE);
		bad = ticket; bad.mode = MIGRATION_DIRTY_CLEAR;
		CHECK(migration_dirty_abort(&vm_a, &bad) == ESTALE);
		CHECK(migration_dirty_abort(&vm_b, &ticket) == ESTALE);
		/* A second collection while one is open is busy. */
		CHECK(migration_dirty_begin_range(&vm_a, 0, 8 * PG, MIGRATION_DIRTY_OBSERVE,
		    other, 1, &other_ticket) == EBUSY);
		CHECK(migration_dirty_begin_range(NULL, 0, 8 * PG, MIGRATION_DIRTY_OBSERVE,
		    other, 1, &other_ticket) == EINVAL);
		CHECK(migration_dirty_begin_range(&vm_a, 0, 8 * PG, MIGRATION_DIRTY_OBSERVE,
		    NULL, 1, &other_ticket) == EINVAL);
		CHECK(migration_dirty_begin_range(&vm_a, 0, 8 * PG, MIGRATION_DIRTY_OBSERVE,
		    other, 1, NULL) == EINVAL);
		CHECK(migration_dirty_begin_range(&vm_a, 1, 8 * PG, MIGRATION_DIRTY_OBSERVE,
		    other, 1, &other_ticket) == EINVAL);
	}
	CHECK(migration_dirty_finish(&vm_a, &ticket) == 0);
	CHECK(migration_dirty_finish(&vm_a, &ticket) == ESTALE);	/* not collecting */
	/* Another VM's collection is refused while this one tracks. */
	CHECK(migration_dirty_begin_range(&vm_b, 0, 8 * PG, MIGRATION_DIRTY_OBSERVE,
	    bitmap, 1, &ticket) == EBUSY);
	/* OBSERVE at the last generation does not exhaust. */
	migration_dirty_tracker.generation = UINT64_MAX;
	CHECK(migration_dirty_begin(&vm_a, MIGRATION_DIRTY_OBSERVE, bitmap, 1, &ticket) == 0);
	CHECK(migration_dirty_finish(&vm_a, &ticket) == 0);
	/* CLEAR at the last generation exhausts the tracker for good. */
	migration_dirty_tracker.generation = UINT64_MAX;
	CHECK(migration_dirty_begin(&vm_a, MIGRATION_DIRTY_CLEAR, bitmap, 1, &ticket) == EOVERFLOW);
	CHECK(migration_dirty_tracker.phase == MIGRATION_DIRTY_EXHAUSTED);
	CHECK(migration_dirty_enable(&vm_a, 0, PG) == EOVERFLOW);
	CHECK(migration_dirty_disable(&vm_a) == EOVERFLOW);
	CHECK(migration_dirty_bitmap_bytes(&vm_a, &bytes) == EOVERFLOW);
	CHECK(migration_dirty_mark(&vm_a, 0, 1) == EOVERFLOW);
	CHECK(migration_dirty_begin(&vm_a, MIGRATION_DIRTY_OBSERVE, bitmap, 1, &ticket) == EOVERFLOW);
	CHECK(migration_dirty_begin_range(&vm_a, 0, 8 * PG, MIGRATION_DIRTY_OBSERVE, bitmap, 1,
	    &ticket) == EOVERFLOW);
	migration_dirty_fail(&vm_a, EIO);
	CHECK(migration_dirty_tracker.failure == EOVERFLOW);
	/* Identity exhaustion on enable/disable/begin. */
	free(migration_dirty_tracker.active);
	free(migration_dirty_tracker.captured);
	memset(&migration_dirty_tracker.owner, 0, sizeof(migration_dirty_tracker) -
	    offsetof(struct migration_dirty_tracker, owner));
	migration_dirty_tracker.identity = UINT64_MAX;
	CHECK(migration_dirty_enable(&vm_a, 0, PG) == EOVERFLOW);
	CHECK(migration_dirty_tracker.phase == MIGRATION_DIRTY_EXHAUSTED);
	memset(&migration_dirty_tracker.owner, 0, sizeof(migration_dirty_tracker) -
	    offsetof(struct migration_dirty_tracker, owner));
	CHECK(migration_dirty_enable(&vm_a, 0, PG) == 0);
	migration_dirty_tracker.identity = UINT64_MAX;
	CHECK(migration_dirty_disable(&vm_a) == EOVERFLOW);
	free(migration_dirty_tracker.active);
	free(migration_dirty_tracker.captured);
	memset(&migration_dirty_tracker.owner, 0, sizeof(migration_dirty_tracker) -
	    offsetof(struct migration_dirty_tracker, owner));
	CHECK(migration_dirty_enable(&vm_a, 0, PG) == 0);
	migration_dirty_tracker.identity = UINT64_MAX;
	CHECK(migration_dirty_begin(&vm_a, MIGRATION_DIRTY_OBSERVE, bitmap, 1, &ticket) == EOVERFLOW);
	printf("dirty tracker edges: 46 checks\n");
}

/* ------------------------------------------------------- calloc fault */
static int calloc_countdown;
void *__real_calloc(size_t, size_t);

void
dirty_fail_next_calloc(int nth)
{
	calloc_countdown = nth;
}

void *
__wrap_calloc(size_t n, size_t size)
{
	if (calloc_countdown > 0 && --calloc_countdown == 0) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_calloc(n, size));
}

/* ------------------------------------------------------- pre-copy */
struct cpu_model {
	void (*hook)(void);
	int enable_error, disable_error, collect_error, zero_generation;
	int enables, disables, collects;
	uint8_t bitmap[64];
};

static int
cpu_enable(void *arg, uint64_t gpa, uint64_t length)
{
	struct cpu_model *c = arg;
	(void)gpa;
	(void)length;
	c->enables++;
	return (c->enable_error);
}

static int
cpu_disable(void *arg)
{
	struct cpu_model *c = arg;
	c->disables++;
	return (c->disable_error);
}

static int
cpu_collect(void *arg, uint64_t gpa, uint64_t length, enum migration_dirty_collect_mode mode,
    uint8_t *bitmap, size_t bytes, struct migration_precopy_cpu_generation *g)
{
	struct cpu_model *c = arg;
	(void)gpa;
	(void)length;
	(void)mode;
	c->collects++;
	if (c->hook != NULL)
		c->hook();
	if (c->collect_error != 0)
		return (c->collect_error);
	memcpy(bitmap, c->bitmap, bytes);
	g->identity = c->zero_generation == 1 ? 0 : 5;
	g->map_generation = c->zero_generation == 2 ? 0 : 6;
	g->dirty_generation = c->zero_generation == 3 ? 0 : (uint64_t)c->collects;
	return (0);
}

static const struct migration_precopy_cpu_ops cpu_ops = {
	.enable = cpu_enable, .collect = cpu_collect, .disable = cpu_disable,
};

/* Concurrent device-side events while the CPU log is being collected. */
static void
device_fails(void)
{
	migration_dirty_fail(&vm_a, EIO);
}

static void
ticket_invalidated(void)
{
	migration_dirty_tracker.generation += 7;
}

static void
reset_dirty(void)
{
	free(migration_dirty_tracker.active);
	free(migration_dirty_tracker.captured);
	memset(&migration_dirty_tracker.owner, 0, sizeof(migration_dirty_tracker) -
	    offsetof(struct migration_dirty_tracker, owner));
	migration_precopy_session_reset(&migration_precopy_session);
}

static void
test_precopy(void)
{
	struct cpu_model c;
	struct migration_precopy_generation g;
	uint8_t bitmap[2];
	const uint64_t length = 16 * PG;
	static const struct migration_precopy_cpu_ops broken = { .enable = cpu_enable };

	seed = 0;
	step = 0;
	reset_dirty();
	memset(&c, 0, sizeof(c));
	/* Argument contracts. */
	CHECK(migration_precopy_enable_with_ops(NULL, 0, length, &cpu_ops, &c) == EINVAL);
	CHECK(migration_precopy_enable_with_ops(&vm_a, 0, length, &broken, &c) == EINVAL);
	CHECK(migration_precopy_enable_with_ops(&vm_a, 0, length, NULL, &c) == EINVAL);
	CHECK(migration_precopy_enable_with_ops(&vm_a, 1, length, &cpu_ops, &c) == EINVAL);
	CHECK(migration_precopy_disable_with_ops(NULL, &cpu_ops, &c) == EINVAL);
	CHECK(migration_precopy_disable_with_ops(&vm_a, &cpu_ops, &c) == ENOENT);
	CHECK(migration_precopy_collect_with_ops(NULL, 0, length, MIGRATION_DIRTY_CLEAR,
	    bitmap, 2, &g, &cpu_ops, &c) == EINVAL);
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, 9, bitmap, 2, &g, &cpu_ops,
	    &c) == EINVAL);
	CHECK(migration_precopy_collect_with_ops(&vm_a, 1, length, MIGRATION_DIRTY_CLEAR,
	    bitmap, 2, &g, &cpu_ops, &c) == EINVAL);
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR,
	    bitmap, 1, &g, &cpu_ops, &c) == EINVAL);
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR,
	    (uint8_t *)&g, 2, &g, &cpu_ops, &c) == EINVAL);
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR,
	    bitmap, 2, &g, &cpu_ops, &c) == ENOENT);
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR,
	    NULL, 2, &g, &cpu_ops, &c) == EINVAL);
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR,
	    bitmap, 2, NULL, &cpu_ops, &c) == EINVAL);
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR,
	    bitmap, 2, &g, &broken, &c) == EINVAL);
	{
		/* A range whose bitmap exceeds one kernel publication. */
		uint64_t huge = (VMM_DIRTY_LOG_MAX_BITMAP_BYTES + 1) * 8 * PG;
		static uint8_t big[VMM_DIRTY_LOG_MAX_BITMAP_BYTES + 1];
		CHECK(migration_precopy_collect_with_ops(&vm_a, 0, huge, MIGRATION_DIRTY_CLEAR,
		    big, sizeof(big), &g, &cpu_ops, &c) == EINVAL);
	}
	/* CPU enable failure leaves everything off. */
	c.enable_error = EIO;
	CHECK(migration_precopy_enable_with_ops(&vm_a, 0, length, &cpu_ops, &c) == EIO);
	CHECK(migration_precopy_session.phase == MIGRATION_PRECOPY_OFF);
	c.enable_error = 0;
	/* Device enable failure rolls the CPU log back. */
	migration_dirty_tracker.phase = MIGRATION_DIRTY_TRACKING;	/* busy */
	CHECK(migration_precopy_enable_with_ops(&vm_a, 0, length, &cpu_ops, &c) == EBUSY);
	CHECK(c.disables == 1 && migration_precopy_session.phase == MIGRATION_PRECOPY_OFF);
	/* ... and a failed rollback poisons the session. */
	c.disable_error = EIO;
	CHECK(migration_precopy_enable_with_ops(&vm_a, 0, length, &cpu_ops, &c) == EPROTO);
	CHECK(migration_precopy_session.phase == MIGRATION_PRECOPY_FAILED);
	CHECK(migration_precopy_enable_with_ops(&vm_a, 0, length, &cpu_ops, &c) == EPROTO);
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR,
	    bitmap, 2, &g, &cpu_ops, &c) == EPROTO);
	/* Disabling a failed session retries the CPU disable; failure keeps it. */
	migration_dirty_tracker.phase = MIGRATION_DIRTY_OFF;
	CHECK(migration_precopy_disable_with_ops(&vm_a, &cpu_ops, &c) == EIO);
	CHECK(migration_precopy_session.phase == MIGRATION_PRECOPY_FAILED);
	c.disable_error = 0;
	CHECK(migration_precopy_disable_with_ops(&vm_b, &cpu_ops, &c) == ESTALE);
	CHECK(migration_precopy_disable_with_ops(&vm_a, &cpu_ops, &c) == 0);
	CHECK(migration_precopy_session.phase == MIGRATION_PRECOPY_OFF);
	/* A healthy transaction: the result is the union of CPU and device. */
	reset_dirty();
	memset(&c, 0, sizeof(c));
	CHECK(migration_precopy_enable_with_ops(&vm_a, 0, length, &cpu_ops, &c) == 0);
	CHECK(migration_precopy_enable_with_ops(&vm_a, 0, length, &cpu_ops, &c) == EBUSY);
	c.bitmap[0] = 0x81;
	CHECK(migration_dirty_mark(&vm_a, 9 * PG, 1) == 0);
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR,
	    bitmap, 2, &g, &cpu_ops, &c) == 0);
	CHECK(bitmap[0] == 0x81 && bitmap[1] == 0x02);
	CHECK(g.cpu_identity == 5 && g.cpu_map_generation == 6 && g.cpu_dirty_generation == 1);
	CHECK(g.device_identity != 0 && g.device_mode == MIGRATION_DIRTY_OBSERVE &&
	    g.cpu_mode == MIGRATION_DIRTY_CLEAR);
	/* Collection outside the enabled range, from another owner. */
	CHECK(migration_precopy_collect_with_ops(&vm_a, 16 * PG, PG, MIGRATION_DIRTY_CLEAR,
	    bitmap, 1, &g, &cpu_ops, &c) == ERANGE);
	CHECK(migration_precopy_collect_with_ops(&vm_b, 0, length, MIGRATION_DIRTY_CLEAR,
	    bitmap, 2, &g, &cpu_ops, &c) == ESTALE);
	/* OBSERVE failure is retryable; CLEAR failure poisons. */
	c.collect_error = EIO;
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_OBSERVE,
	    bitmap, 2, &g, &cpu_ops, &c) == EIO);
	CHECK(migration_precopy_session.phase == MIGRATION_PRECOPY_ACTIVE);
	/* A CPU generation with a zero identity is a protocol error. */
	c.collect_error = 0;
	c.zero_generation = 2;
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_OBSERVE,
	    bitmap, 2, &g, &cpu_ops, &c) == EPROTO);
	CHECK(migration_precopy_session.phase == MIGRATION_PRECOPY_FAILED);
	c.zero_generation = 0;
	CHECK(migration_precopy_disable_with_ops(&vm_a, &cpu_ops, &c) == 0);
	/* Device finish failure after a CPU CLEAR cannot be retried. */
	reset_dirty();
	CHECK(migration_precopy_enable_with_ops(&vm_a, 0, length, &cpu_ops, &c) == 0);
	migration_dirty_fail(&vm_a, ENOSPC);
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR,
	    bitmap, 2, &g, &cpu_ops, &c) == ENOSPC);
	reset_dirty();
	CHECK(migration_precopy_enable_with_ops(&vm_a, 0, length, &cpu_ops, &c) == 0);
	c.collect_error = EIO;
	migration_dirty_tracker.identity = UINT64_MAX - 1;	/* abort exhausts */
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR,
	    bitmap, 2, &g, &cpu_ops, &c) == EIO);
	CHECK(migration_precopy_session.phase == MIGRATION_PRECOPY_FAILED);
	c.collect_error = 0;
	/* A device failure reported during the CPU collection: the CPU CLEAR
	 * already happened, so the transaction cannot be retried. */
	reset_dirty();
	memset(&c, 0, sizeof(c));
	CHECK(migration_precopy_enable_with_ops(&vm_a, 0, length, &cpu_ops, &c) == 0);
	c.hook = device_fails;
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR,
	    bitmap, 2, &g, &cpu_ops, &c) == EPROTO);
	CHECK(migration_precopy_session.phase == MIGRATION_PRECOPY_FAILED);
	/* Abort that cannot settle the device ticket (CPU failure path and
	 * zero-generation path). */
	reset_dirty();
	memset(&c, 0, sizeof(c));
	CHECK(migration_precopy_enable_with_ops(&vm_a, 0, length, &cpu_ops, &c) == 0);
	c.hook = ticket_invalidated;
	c.collect_error = EIO;
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_OBSERVE,
	    bitmap, 2, &g, &cpu_ops, &c) == EPROTO);
	CHECK(migration_precopy_session.phase == MIGRATION_PRECOPY_FAILED);
	reset_dirty();
	memset(&c, 0, sizeof(c));
	CHECK(migration_precopy_enable_with_ops(&vm_a, 0, length, &cpu_ops, &c) == 0);
	c.hook = ticket_invalidated;
	c.zero_generation = 1;
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_OBSERVE,
	    bitmap, 2, &g, &cpu_ops, &c) == EPROTO);
	reset_dirty();
	memset(&c, 0, sizeof(c));
	CHECK(migration_precopy_enable_with_ops(&vm_a, 0, length, &cpu_ops, &c) == 0);
	c.zero_generation = 3;
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_OBSERVE,
	    bitmap, 2, &g, &cpu_ops, &c) == EPROTO);
	c.zero_generation = 0;
	/* Partially populated operation tables are refused. */
	{
		static const struct migration_precopy_cpu_ops no_collect = {
			.enable = cpu_enable, .disable = cpu_disable };
		static const struct migration_precopy_cpu_ops no_disable = {
			.enable = cpu_enable, .collect = cpu_collect };
		CHECK(migration_precopy_disable_with_ops(&vm_a, &no_collect, &c) == EINVAL);
		CHECK(migration_precopy_disable_with_ops(&vm_a, &no_disable, &c) == EINVAL);
	}
	reset_dirty();
	/* Device disable failure on disable poisons the session. */
	reset_dirty();
	CHECK(migration_precopy_enable_with_ops(&vm_a, 0, length, &cpu_ops, &c) == 0);
	migration_dirty_tracker.phase = MIGRATION_DIRTY_COLLECTING;
	CHECK(migration_precopy_disable_with_ops(&vm_a, &cpu_ops, &c) == EBUSY);
	CHECK(migration_precopy_session.phase == MIGRATION_PRECOPY_FAILED);
	migration_dirty_tracker.phase = MIGRATION_DIRTY_TRACKING;
	CHECK(migration_precopy_disable_with_ops(&vm_a, &cpu_ops, &c) == 0);
	/* Allocation failure of the union bitmaps. */
	reset_dirty();
	CHECK(migration_precopy_enable_with_ops(&vm_a, 0, length, &cpu_ops, &c) == 0);
	dirty_fail_next_calloc(2);
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR,
	    bitmap, 2, &g, &cpu_ops, &c) == ENOMEM);
	CHECK(migration_precopy_session.phase == MIGRATION_PRECOPY_ACTIVE);
	/* Collection while another transaction is in progress. */
	migration_precopy_session.phase = MIGRATION_PRECOPY_COLLECTING;
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR,
	    bitmap, 2, &g, &cpu_ops, &c) == EBUSY);
	CHECK(migration_precopy_disable_with_ops(&vm_a, &cpu_ops, &c) == EBUSY);
	migration_precopy_session.phase = MIGRATION_PRECOPY_ACTIVE;
	/* Device begin failure (range outside the device tracker). */
	migration_dirty_tracker.length = PG;
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR,
	    bitmap, 2, &g, &cpu_ops, &c) == ERANGE);
	migration_dirty_tracker.length = length;
	CHECK(migration_precopy_disable_with_ops(&vm_a, &cpu_ops, &c) == 0);
	printf("pre-copy transactions: 52 checks\n");
}

static void
test_precopy_vm(void)
{
	struct migration_precopy_generation g;
	uint8_t bitmap[2];
	const uint64_t length = 16 * PG;

	seed = 0;
	step = 0;
	reset_dirty();
	/* Device fabric not ready for pre-copy. */
	precopy_validate_error = EOPNOTSUPP;
	CHECK(migration_precopy_enable(&vm_a, 0, length) == EOPNOTSUPP);
	precopy_validate_error = 0;
	CHECK(migration_precopy_enable(&vm_a, 0, length) == 0);
	kernel_bitmap[0] = 0x11;
	kernel_bitmap[1] = 0x80;
	CHECK(migration_precopy_collect(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR, bitmap, 2, &g) == 0);
	CHECK(bitmap[0] == 0x11 && bitmap[1] == 0x80 && g.cpu_identity == kernel_identity);
	/* A malformed kernel publication is refused (OBSERVE: not poisoned). */
	dirty_log_mutation = 1;
	CHECK(migration_precopy_collect(&vm_a, 0, length, MIGRATION_DIRTY_OBSERVE, bitmap, 2, &g) == EINVAL);
	dirty_log_mutation = 2;
	CHECK(migration_precopy_collect(&vm_a, 0, length, MIGRATION_DIRTY_OBSERVE, bitmap, 2, &g) == EPROTO);
	dirty_log_mutation = 4;	/* the other collection operation */
	CHECK(migration_precopy_collect(&vm_a, 0, length, MIGRATION_DIRTY_OBSERVE, bitmap, 2, &g) == EPROTO);
	dirty_log_mutation = 5;	/* 15 pages still use two bitmap bytes */
	CHECK(migration_precopy_collect(&vm_a, 0, length, MIGRATION_DIRTY_OBSERVE, bitmap, 2, &g) == EPROTO);
	dirty_log_mutation = 0;
	CHECK(migration_precopy_cpu_collect(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR, NULL, 2,
	    &(struct migration_precopy_cpu_generation){0}) == EINVAL);
	CHECK(migration_precopy_cpu_collect(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR, bitmap, 2,
	    NULL) == EINVAL);
	/* ioctl failure, with and without errno. */
	dirty_log_error = ENXIO;
	CHECK(migration_precopy_collect(&vm_a, 0, length, MIGRATION_DIRTY_OBSERVE, bitmap, 2, &g) == ENXIO);
	dirty_log_error = -1;
	CHECK(migration_precopy_collect(&vm_a, 0, length, MIGRATION_DIRTY_OBSERVE, bitmap, 2, &g) == EIO);
	dirty_log_error = 0;
	/* A bitmap too large for one publication. */
	CHECK(migration_precopy_cpu_collect(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR, bitmap,
	    SIZE_MAX, &(struct migration_precopy_cpu_generation){0}) == EINVAL);
	CHECK(migration_precopy_cpu_collect(&vm_a, 0, length, 9, bitmap, 2,
	    &(struct migration_precopy_cpu_generation){0}) == EINVAL);
	CHECK(migration_precopy_cpu_collect(NULL, 0, length, MIGRATION_DIRTY_CLEAR, bitmap, 2,
	    &(struct migration_precopy_cpu_generation){0}) == EINVAL);
	dirty_fail_next_calloc(1);
	CHECK(migration_precopy_cpu_collect(&vm_a, 0, length, MIGRATION_DIRTY_CLEAR, bitmap, 2,
	    &(struct migration_precopy_cpu_generation){0}) == ENOMEM);
	CHECK(migration_precopy_disable(&vm_a) == 0);
	printf("pre-copy kernel publication: 13 checks\n");
}

static void
test_free_set(void)
{
	struct migration_precopy_free_set set;

	seed = 0;
	step = 0;
	CHECK(migration_precopy_free_set_init(NULL, 0, PG) == EINVAL);
	CHECK(migration_precopy_free_set_init(&set, 1, PG) == EINVAL);
	CHECK(migration_precopy_free_set_init(&set, PG, 16 * PG) == 0);
	CHECK(!migration_precopy_free_set_contains(&set, 2 * PG));	/* not committed */
	CHECK(migration_precopy_free_set_mark(NULL, 0, 1) == EINVAL);
	CHECK(migration_precopy_free_set_mark(&set, UINT64_MAX, 2) == EINVAL);
	CHECK(migration_precopy_free_set_mark(&set, 0, 0) == 0);
	/* Partial pages are never claimed free; clamping to the window. */
	CHECK(migration_precopy_free_set_mark(&set, PG + 1, PG) == 0);
	CHECK(migration_precopy_free_set_mark(&set, 0, PG) == 0);	/* outside */
	CHECK(migration_precopy_free_set_mark(&set, 0, 3 * PG) == 0);	/* pages 0,1 */
	CHECK(migration_precopy_free_set_mark(&set, 16 * PG, 4 * PG) == 0);	/* clamped */
	migration_precopy_free_set_commit(&set);
	migration_precopy_free_set_commit(NULL);
	CHECK(migration_precopy_free_set_contains(&set, PG));
	CHECK(migration_precopy_free_set_contains(&set, 2 * PG));
	CHECK(!migration_precopy_free_set_contains(&set, 3 * PG));
	CHECK(migration_precopy_free_set_contains(&set, 16 * PG));
	CHECK(!migration_precopy_free_set_contains(&set, 17 * PG));
	CHECK(!migration_precopy_free_set_contains(&set, 0));
	CHECK(!migration_precopy_free_set_contains(&set, PG + 7));
	CHECK(!migration_precopy_free_set_contains(NULL, PG));
	/* The hint applies only to the initial generation. */
	CHECK(migration_precopy_free_set_skip(&set, true, PG));
	CHECK(!migration_precopy_free_set_skip(&set, false, PG));
	migration_precopy_free_set_reset(&set);
	migration_precopy_free_set_reset(NULL);
	CHECK(set.bitmap == NULL && !set.valid);
	CHECK(migration_precopy_free_set_mark(&set, PG, PG) == EINVAL);
	dirty_fail_next_calloc(1);
	CHECK(migration_precopy_free_set_init(&set, 0, PG) == ENOMEM);
	printf("pre-copy free-page hints: 26 checks\n");
}

/*
 * Remaining argument and ownership contracts.  Oracles are the documented
 * errors: an unaligned length is EINVAL; a NULL output is EINVAL; a range
 * below or beyond the tracked window is ERANGE; another VM's begin is ENOENT
 * while this VM tracks; a pre-copy call naming other CPU ops or another
 * argument is ESTALE; ops without disable are EINVAL; a kernel result
 * describing a different bitmap size is refused by the validator (EINVAL); free-page sets without a
 * bitmap are never committed or consulted.
 */
static void
test_remaining_contracts(void)
{
	struct migration_dirty_ticket ticket;
	struct migration_precopy_generation g;
	struct migration_precopy_free_set set;
	struct cpu_model c, other_arg;
	static const struct migration_precopy_cpu_ops no_disable = {
		.enable = cpu_enable, .collect = cpu_collect };
	static const struct migration_precopy_cpu_ops no_enable = {
		.collect = cpu_collect, .disable = cpu_disable };
	static const struct migration_precopy_cpu_ops other_ops = {
		.enable = cpu_enable, .collect = cpu_collect, .disable = cpu_disable };
	uint8_t bitmap[2];
	size_t bytes = 99;
	int checks = 0;

	seed = 0;
	step = 0;
	reset_dirty();
	CHECK(migration_dirty_range_bitmap_bytes(0, PG + 1, &bytes) == EINVAL && bytes == 99);
	CHECK(migration_dirty_range_bitmap_bytes(0, PG, NULL) == EINVAL);
	checks += 2;
	/* Device tracker window [16 PG, 32 PG). */
	CHECK(migration_dirty_enable(&vm_a, 16 * PG, 16 * PG) == 0);
	CHECK(migration_dirty_begin_range(&vm_a, 0, 16 * PG, MIGRATION_DIRTY_OBSERVE,
	    bitmap, 2, &ticket) == ERANGE);
	CHECK(migration_dirty_begin_range(&vm_a, 32 * PG, 8 * PG, MIGRATION_DIRTY_OBSERVE,
	    bitmap, 1, &ticket) == ERANGE);
	CHECK(migration_dirty_begin(&vm_b, MIGRATION_DIRTY_OBSERVE, bitmap, 2,
	    &ticket) == ENOENT);
	CHECK(migration_dirty_disable(&vm_a) == 0);
	checks += 4;
	/* Pre-copy session window [16 PG, 32 PG) with CPU model C. */
	reset_dirty();
	memset(&c, 0, sizeof(c));
	CHECK(migration_precopy_enable_with_ops(&vm_a, 16 * PG, 16 * PG, &cpu_ops, &c) == 0);
	CHECK(migration_precopy_collect_with_ops(&vm_a, 0, 16 * PG, MIGRATION_DIRTY_OBSERVE,
	    bitmap, 2, &g, &cpu_ops, &c) == ERANGE);
	CHECK(migration_precopy_collect_with_ops(&vm_a, 24 * PG, 16 * PG,
	    MIGRATION_DIRTY_OBSERVE, bitmap, 2, &g, &cpu_ops, &c) == ERANGE);
	CHECK(migration_precopy_collect_with_ops(&vm_a, 16 * PG, 16 * PG,
	    MIGRATION_DIRTY_OBSERVE, bitmap, 2, &g, &other_ops, &c) == ESTALE);
	CHECK(migration_precopy_collect_with_ops(&vm_a, 16 * PG, 16 * PG,
	    MIGRATION_DIRTY_OBSERVE, bitmap, 2, &g, &cpu_ops, &other_arg) == ESTALE);
	CHECK(migration_precopy_disable_with_ops(&vm_a, &no_disable, &c) == EINVAL);
	CHECK(migration_precopy_disable_with_ops(&vm_a, &no_enable, &c) == EINVAL);
	/* Either scratch bitmap failing to allocate is ENOMEM; the session stays
	 * usable (nothing was collected or cleared). */
	{
		extern void dirty_fail_next_calloc(int);
		for (int nth = 1; nth <= 2; nth++) {
			int collects = c.collects;
			dirty_fail_next_calloc(nth);
			CHECK(migration_precopy_collect_with_ops(&vm_a, 16 * PG, 16 * PG,
			    MIGRATION_DIRTY_CLEAR, bitmap, 2, &g, &cpu_ops, &c) == ENOMEM);
			CHECK(c.collects == collects &&
			    migration_precopy_session.phase == MIGRATION_PRECOPY_ACTIVE);
			checks += 2;
		}
		dirty_fail_next_calloc(0);
	}
	CHECK(migration_precopy_session.phase == MIGRATION_PRECOPY_ACTIVE);
	CHECK(migration_precopy_disable_with_ops(&vm_a, &cpu_ops, &c) == 0);
	checks += 8;
	/* A kernel publication describing a smaller bitmap: the shared
	 * validator already ties bitmap_bytes to length, so it refuses it. */
	reset_dirty();
	CHECK(migration_precopy_enable(&vm_a, 0, 16 * PG) == 0);
	dirty_log_mutation = 6;
	CHECK(migration_precopy_collect(&vm_a, 0, 16 * PG, MIGRATION_DIRTY_OBSERVE, bitmap,
	    2, &g) == EINVAL);
	dirty_log_mutation = 0;
	CHECK(migration_precopy_disable(&vm_a) == 0);
	checks += 2;
	/* Free-page sets. */
	migration_precopy_free_set_commit(NULL);
	memset(&set, 0, sizeof(set));
	set.gpa = 0;
	set.length = PG;
	migration_precopy_free_set_commit(&set);
	CHECK(!set.valid);
	set.valid = true;	/* even a forged flag needs a bitmap */
	CHECK(!migration_precopy_free_set_contains(&set, 0));
	checks += 2;
	reset_dirty();
	printf("dirty/pre-copy remaining contracts: %d checks\n", checks);
}

int
main(void)
{
	test_tracker_edges();
	test_tracker_model();
	test_precopy();
	test_precopy_vm();
	test_free_set();
	test_remaining_contracts();
	printf("PASS: dirty tracker and pre-copy transactions\n");
	return (0);
}
