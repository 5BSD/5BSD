/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vmmapi.h>

#include <dev/vmm/vmm_address_range.h>

#include "migration_dirty.h"
#include "migration_eligibility.h"
#include "migration_precopy.h"

enum migration_precopy_phase {
	MIGRATION_PRECOPY_OFF,
	MIGRATION_PRECOPY_ENABLING,
	MIGRATION_PRECOPY_ACTIVE,
	MIGRATION_PRECOPY_COLLECTING,
	MIGRATION_PRECOPY_DISABLING,
	MIGRATION_PRECOPY_FAILED,
};

struct migration_precopy_session {
	pthread_mutex_t lock;
	struct vmctx *owner;
	const struct migration_precopy_cpu_ops *ops;
	void *ops_arg;
	uint64_t gpa;
	uint64_t length;
	uint32_t phase;
	bool cpu_owned;
	bool device_owned;
};

/* A bhyve process owns one VM and therefore one migration coordinator. */
static struct migration_precopy_session migration_precopy_session = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

static void
migration_precopy_session_reset(struct migration_precopy_session *session)
{

	session->owner = NULL;
	session->ops = NULL;
	session->ops_arg = NULL;
	session->gpa = 0;
	session->length = 0;
	session->phase = MIGRATION_PRECOPY_OFF;
	session->cpu_owned = false;
	session->device_owned = false;
}

static bool
migration_precopy_session_matches(
    const struct migration_precopy_session *session, struct vmctx *ctx,
    const struct migration_precopy_cpu_ops *ops, void *arg)
{

	return (session->owner == ctx && session->ops == ops &&
	    session->ops_arg == arg);
}

static int
migration_precopy_cpu_request(void *arg, uint16_t operation, uint64_t gpa,
    uint64_t length, void *output, size_t output_bytes)
{
	struct vmm_dirty_log_request request;

	if (arg == NULL)
		return (EINVAL);
	memset(&request, 0, sizeof(request));
	request.version = VMM_DIRTY_LOG_REQUEST_VERSION;
	request.size = VMM_DIRTY_LOG_REQUEST_SIZE;
	request.operation = operation;
	request.gpa = gpa;
	request.length = length;
	if (output != NULL) {
		request.output_address = (uint64_t)(uintptr_t)output;
		request.output_bytes = output_bytes;
	}
	if (vm_dirty_log_request(arg, &request) == 0)
		return (0);
	return (errno == 0 ? EIO : errno);
}

static int
migration_precopy_cpu_enable(void *arg, uint64_t gpa, uint64_t length)
{

	return (migration_precopy_cpu_request(arg,
	    VMM_DIRTY_LOG_REQUEST_ENABLE, gpa, length, NULL, 0));
}

static int
migration_precopy_cpu_disable(void *arg)
{

	return (migration_precopy_cpu_request(arg,
	    VMM_DIRTY_LOG_REQUEST_DISABLE, 0, 0, NULL, 0));
}

static int
migration_precopy_cpu_collect(void *arg, uint64_t gpa, uint64_t length,
    enum migration_dirty_collect_mode mode, uint8_t *bitmap,
    size_t bitmap_bytes, struct migration_precopy_cpu_generation *generation)
{
	struct vmm_dirty_log_result *result;
	void *publication;
	size_t output_bytes;
	uint16_t operation;
	int error;

	if (bitmap == NULL || generation == NULL ||
	    (mode != MIGRATION_DIRTY_OBSERVE &&
	    mode != MIGRATION_DIRTY_CLEAR) ||
	    bitmap_bytes > SIZE_MAX - sizeof(*result))
		return (EINVAL);
	operation = mode == MIGRATION_DIRTY_OBSERVE ?
	    VMM_DIRTY_LOG_REQUEST_OBSERVE : VMM_DIRTY_LOG_REQUEST_CLEAR;
	output_bytes = sizeof(*result) + bitmap_bytes;
	publication = calloc(output_bytes, 1);
	if (publication == NULL)
		return (ENOMEM);
	error = migration_precopy_cpu_request(arg, operation, gpa, length,
	    publication, output_bytes);
	if (error != 0)
		goto done;
	result = (struct vmm_dirty_log_result *)publication;
	error = vm_dirty_log_result_validate(result, output_bytes);
	if (error != 0)
		goto done;
	if (result->operation != operation || result->gpa != gpa ||
	    result->length != length || result->bitmap_bytes != bitmap_bytes) {
		error = EPROTO;
		goto done;
	}
	memcpy(bitmap, (uint8_t *)publication + result->bitmap_offset,
	    bitmap_bytes);
	*generation = (struct migration_precopy_cpu_generation) {
		.identity = result->identity,
		.map_generation = result->map_generation,
		.dirty_generation = result->dirty_generation,
	};
done:
	free(publication);
	return (error);
}

static const struct migration_precopy_cpu_ops migration_precopy_vm_ops = {
	.enable = migration_precopy_cpu_enable,
	.collect = migration_precopy_cpu_collect,
	.disable = migration_precopy_cpu_disable,
};

static int
migration_precopy_ops_validate(const struct migration_precopy_cpu_ops *ops)
{

	return (ops == NULL || ops->enable == NULL || ops->collect == NULL ||
	    ops->disable == NULL ? EINVAL : 0);
}

int
migration_precopy_enable_with_ops(struct vmctx *ctx, uint64_t gpa,
    uint64_t length, const struct migration_precopy_cpu_ops *ops, void *arg)
{
	struct migration_precopy_session *session;
	size_t ignored;
	int error, rollback_error;

	if (ctx == NULL || migration_precopy_ops_validate(ops) != 0)
		return (EINVAL);
	error = migration_dirty_range_bitmap_bytes(gpa, length, &ignored);
	if (error != 0)
		return (error);
	session = &migration_precopy_session;
	pthread_mutex_lock(&session->lock);
	if (session->phase == MIGRATION_PRECOPY_FAILED)
		error = EPROTO;
	else if (session->phase != MIGRATION_PRECOPY_OFF)
		error = EBUSY;
	else {
		session->owner = ctx;
		session->ops = ops;
		session->ops_arg = arg;
		session->gpa = gpa;
		session->length = length;
		session->phase = MIGRATION_PRECOPY_ENABLING;
		session->cpu_owned = false;
		session->device_owned = false;
		error = 0;
	}
	pthread_mutex_unlock(&session->lock);
	if (error != 0)
		return (error);
	error = ops->enable(arg, gpa, length);
	if (error != 0) {
		pthread_mutex_lock(&session->lock);
		migration_precopy_session_reset(session);
		pthread_mutex_unlock(&session->lock);
		return (error);
	}
	pthread_mutex_lock(&session->lock);
	session->cpu_owned = true;
	pthread_mutex_unlock(&session->lock);
	error = migration_dirty_enable(ctx, gpa, length);
	if (error == 0) {
		pthread_mutex_lock(&session->lock);
		session->device_owned = true;
		session->phase = MIGRATION_PRECOPY_ACTIVE;
		pthread_mutex_unlock(&session->lock);
		return (0);
	}
	rollback_error = ops->disable(arg);
	pthread_mutex_lock(&session->lock);
	if (rollback_error == 0)
		migration_precopy_session_reset(session);
	else
		session->phase = MIGRATION_PRECOPY_FAILED;
	pthread_mutex_unlock(&session->lock);
	return (rollback_error == 0 ? error : EPROTO);
}

int
migration_precopy_disable_with_ops(struct vmctx *ctx,
    const struct migration_precopy_cpu_ops *ops, void *arg)
{
	struct migration_precopy_session *session;
	bool cpu_owned, device_owned;
	int cpu_error, device_error, error;

	if (ctx == NULL || migration_precopy_ops_validate(ops) != 0)
		return (EINVAL);
	session = &migration_precopy_session;
	pthread_mutex_lock(&session->lock);
	if (session->phase == MIGRATION_PRECOPY_OFF)
		error = ENOENT;
	else if (!migration_precopy_session_matches(session, ctx, ops, arg))
		error = ESTALE;
	else if (session->phase != MIGRATION_PRECOPY_ACTIVE &&
	    session->phase != MIGRATION_PRECOPY_FAILED)
		error = EBUSY;
	else {
		cpu_owned = session->cpu_owned;
		device_owned = session->device_owned;
		session->phase = MIGRATION_PRECOPY_DISABLING;
		error = 0;
	}
	pthread_mutex_unlock(&session->lock);
	if (error != 0)
		return (error);

	device_error = device_owned ? migration_dirty_disable(ctx) : 0;
	if (device_error != 0) {
		pthread_mutex_lock(&session->lock);
		session->phase = MIGRATION_PRECOPY_FAILED;
		pthread_mutex_unlock(&session->lock);
		return (device_error);
	}
	cpu_error = cpu_owned ? ops->disable(arg) : 0;
	pthread_mutex_lock(&session->lock);
	if (device_owned)
		session->device_owned = false;
	if (cpu_error == 0) {
		session->cpu_owned = false;
		migration_precopy_session_reset(session);
	} else {
		session->phase = MIGRATION_PRECOPY_FAILED;
	}
	pthread_mutex_unlock(&session->lock);
	return (cpu_error);
}

int
migration_precopy_collect_with_ops(struct vmctx *ctx, uint64_t gpa,
    uint64_t length, enum migration_dirty_collect_mode mode, uint8_t *bitmap,
    size_t bitmap_bytes, struct migration_precopy_generation *generation,
    const struct migration_precopy_cpu_ops *ops, void *arg)
{
	struct migration_precopy_session *session;
	struct migration_dirty_ticket device_ticket;
	struct migration_precopy_cpu_generation cpu_generation;
	struct migration_precopy_generation candidate;
	enum migration_dirty_collect_mode device_mode;
	uint8_t *cpu_bitmap, *device_bitmap;
	size_t required;
	bool failed;
	int abort_error, error;

	if (ctx == NULL || bitmap == NULL || generation == NULL ||
	    migration_precopy_ops_validate(ops) != 0 ||
	    (mode != MIGRATION_DIRTY_OBSERVE && mode != MIGRATION_DIRTY_CLEAR))
		return (EINVAL);
	error = migration_dirty_range_bitmap_bytes(gpa, length, &required);
	if (error != 0)
		return (error);
	if (bitmap_bytes != required ||
	    bitmap_bytes > VMM_DIRTY_LOG_MAX_BITMAP_BYTES ||
	    vmm_address_ranges_overlap(bitmap, bitmap_bytes, generation,
	    sizeof(*generation)))
		return (EINVAL);
	session = &migration_precopy_session;
	pthread_mutex_lock(&session->lock);
	if (!migration_precopy_session_matches(session, ctx, ops, arg))
		error = session->phase == MIGRATION_PRECOPY_OFF ? ENOENT : ESTALE;
	else if (session->phase == MIGRATION_PRECOPY_FAILED)
		error = EPROTO;
	else if (session->phase != MIGRATION_PRECOPY_ACTIVE)
		error = EBUSY;
	else if (gpa < session->gpa || gpa - session->gpa >= session->length ||
	    length > session->length - (gpa - session->gpa))
		error = ERANGE;
	else {
		session->phase = MIGRATION_PRECOPY_COLLECTING;
		error = 0;
	}
	pthread_mutex_unlock(&session->lock);
	if (error != 0)
		return (error);
	failed = false;
	/*
	 * Hardware CPU dirty bits are edge-tracked: a write after CLEAR marks the
	 * page again.  Device DMA is accounted when a writable mapping is handed
	 * to an asynchronous backend, and that mapping can remain live after this
	 * collection returns.  Clearing the device bitmap here could therefore
	 * lose a write performed through an older mapping.  Keep device dirties
	 * cumulative for every iterative round and the final, device-quiesced
	 * round; migration_dirty_disable() retires the bitmap after the cut.
	 */
	device_mode = MIGRATION_DIRTY_OBSERVE;
	cpu_bitmap = calloc(bitmap_bytes, 1);
	device_bitmap = calloc(bitmap_bytes, 1);
	if (cpu_bitmap == NULL || device_bitmap == NULL) {
		error = ENOMEM;
		goto settle;
	}
	memset(&device_ticket, 0, sizeof(device_ticket));
	error = migration_dirty_begin_range(ctx, gpa, length, device_mode,
	    device_bitmap, bitmap_bytes, &device_ticket);
	if (error != 0)
		goto settle;
	memset(&cpu_generation, 0, sizeof(cpu_generation));
	error = ops->collect(arg, gpa, length, mode, cpu_bitmap, bitmap_bytes,
	    &cpu_generation);
	if (error != 0) {
		abort_error = migration_dirty_abort(ctx, &device_ticket);
		/*
		 * An injected CPU backend cannot prove whether a failed CLEAR
		 * reached its irreversible cut.  Preserve correctness by making
		 * that session cleanup-only.  The concrete ioctl contract avoids
		 * this ambiguity by returning failure before the kernel clear.
		 */
		if (mode == MIGRATION_DIRTY_CLEAR)
			failed = true;
		if (abort_error != 0) {
			error = EPROTO;
			failed = true;
		}
		goto settle;
	}
	if (cpu_generation.identity == 0 ||
	    cpu_generation.map_generation == 0 ||
	    cpu_generation.dirty_generation == 0) {
		error = EPROTO;
		abort_error = migration_dirty_abort(ctx, &device_ticket);
		failed = true;
		if (abort_error != 0) {
			error = EPROTO;
			failed = true;
		}
		goto settle;
	}
	for (size_t i = 0; i < bitmap_bytes; i++)
		cpu_bitmap[i] |= device_bitmap[i];
	candidate = (struct migration_precopy_generation) {
		.gpa = gpa,
		.length = length,
		.cpu_identity = cpu_generation.identity,
		.cpu_map_generation = cpu_generation.map_generation,
		.cpu_dirty_generation = cpu_generation.dirty_generation,
		.device_identity = device_ticket.identity,
		.device_dirty_generation = device_ticket.generation,
		.cpu_mode = mode,
		.device_mode = device_mode,
	};
	error = migration_dirty_finish(ctx, &device_ticket);
	if (error != 0) {
		/* CPU clear succeeded; the union can no longer be retried safely. */
		error = EPROTO;
		failed = true;
		goto settle;
	}
	memcpy(bitmap, cpu_bitmap, bitmap_bytes);
	*generation = candidate;
settle:
	pthread_mutex_lock(&session->lock);
	session->phase = failed ? MIGRATION_PRECOPY_FAILED :
	    MIGRATION_PRECOPY_ACTIVE;
	pthread_mutex_unlock(&session->lock);
	free(device_bitmap);
	free(cpu_bitmap);
	return (error);
}

int
migration_precopy_enable(struct vmctx *ctx, uint64_t gpa, uint64_t length)
{
	int error;

	error = pci_migration_precopy_validate();
	if (error != 0)
		return (error);
	return (migration_precopy_enable_with_ops(ctx, gpa, length,
	    &migration_precopy_vm_ops, ctx));
}

int
migration_precopy_disable(struct vmctx *ctx)
{

	return (migration_precopy_disable_with_ops(ctx,
	    &migration_precopy_vm_ops, ctx));
}

int
migration_precopy_collect(struct vmctx *ctx, uint64_t gpa, uint64_t length,
    enum migration_dirty_collect_mode mode, uint8_t *bitmap,
    size_t bitmap_bytes, struct migration_precopy_generation *generation)
{

	return (migration_precopy_collect_with_ops(ctx, gpa, length, mode,
	    bitmap, bitmap_bytes, generation, &migration_precopy_vm_ops, ctx));
}

/* ------------------------------------------------------------------------- */
/* Advisory free-page set (pure; shares the dirty bitmap granularity).       */
/* ------------------------------------------------------------------------- */

int
migration_precopy_free_set_init(struct migration_precopy_free_set *set,
    uint64_t gpa, uint64_t length)
{
	size_t bytes;
	int error;

	if (set == NULL)
		return (EINVAL);
	memset(set, 0, sizeof(*set));
	error = migration_dirty_range_bitmap_bytes(gpa, length, &bytes);
	if (error != 0)
		return (error);
	if (bytes != 0) {
		set->bitmap = calloc(bytes, 1);
		if (set->bitmap == NULL)
			return (ENOMEM);
	}
	set->gpa = gpa;
	set->length = length;
	set->bitmap_bytes = bytes;
	set->valid = false;
	return (0);
}

void
migration_precopy_free_set_reset(struct migration_precopy_free_set *set)
{

	if (set == NULL)
		return;
	free(set->bitmap);
	memset(set, 0, sizeof(*set));
}

/*
 * Record a reported-free range.  Only whole MIGRATION_DIRTY_GRANULARITY pages
 * that lie entirely within both the reported range and the covered window are
 * marked; any partial page, out-of-range fragment, or overflow is dropped, so
 * the set never claims a page free that the guest did not fully report.
 */
int
migration_precopy_free_set_mark(struct migration_precopy_free_set *set,
    uint64_t gpa, uint64_t length)
{
	uint64_t start, end, page, first_page, last_page;

	if (set == NULL || set->bitmap == NULL)
		return (EINVAL);
	if (length == 0)
		return (0);
	if (gpa > UINT64_MAX - length)
		return (EINVAL);
	/* Clamp the reported range to the covered window. */
	start = gpa < set->gpa ? set->gpa : gpa;
	end = gpa + length;
	if (end > set->gpa + set->length)
		end = set->gpa + set->length;
	if (start >= end)
		return (0);
	/* Round inward to whole covered pages. */
	start += (MIGRATION_DIRTY_GRANULARITY - 1);
	start -= start % MIGRATION_DIRTY_GRANULARITY;
	end -= end % MIGRATION_DIRTY_GRANULARITY;
	if (start >= end)
		return (0);
	first_page = (start - set->gpa) / MIGRATION_DIRTY_GRANULARITY;
	last_page = (end - set->gpa) / MIGRATION_DIRTY_GRANULARITY;
	for (page = first_page; page < last_page; page++) {
		size_t index = (size_t)(page / NBBY);

		if (index >= set->bitmap_bytes)
			break;
		set->bitmap[index] |= (uint8_t)(1U << (page % NBBY));
	}
	return (0);
}

void
migration_precopy_free_set_commit(struct migration_precopy_free_set *set)
{

	if (set != NULL && set->bitmap != NULL)
		set->valid = true;
}

bool
migration_precopy_free_set_contains(
    const struct migration_precopy_free_set *set, uint64_t gpa)
{
	uint64_t page;
	size_t index;

	if (set == NULL || set->bitmap == NULL || !set->valid)
		return (false);
	if (gpa < set->gpa || gpa - set->gpa >= set->length)
		return (false);
	if ((gpa - set->gpa) % MIGRATION_DIRTY_GRANULARITY != 0)
		return (false);
	page = (gpa - set->gpa) / MIGRATION_DIRTY_GRANULARITY;
	index = (size_t)(page / NBBY);
	if (index >= set->bitmap_bytes)
		return (false);
	return ((set->bitmap[index] & (uint8_t)(1U << (page % NBBY))) != 0);
}

bool
migration_precopy_free_set_skip(const struct migration_precopy_free_set *set,
    bool initial_generation, uint64_t gpa)
{

	/*
	 * The free hint is honored only for the very first, initial copy.  Every
	 * dirty-driven round after it is governed purely by dirty tracking, so a
	 * page written after being reported free is always re-copied.
	 */
	if (!initial_generation)
		return (false);
	return (migration_precopy_free_set_contains(set, gpa));
}
