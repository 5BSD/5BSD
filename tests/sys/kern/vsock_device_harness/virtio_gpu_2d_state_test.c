/*
 * Independent VirtIO 1.4 section 5.7 resource-state tests.
 */
#include <sys/endian.h>

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <atf-c.h>

#include "virtio_gpu_2d_protocol.c"
#include "virtio_gpu_2d_state.c"

#define	DOC_CREATE_2D		0x0101U
#define	DOC_UNREF		0x0102U
#define	DOC_SET_SCANOUT		0x0103U
#define	DOC_FLUSH		0x0104U
#define	DOC_TRANSFER		0x0105U
#define	DOC_ATTACH		0x0106U
#define	DOC_DETACH		0x0107U
#define	DOC_UPDATE_CURSOR	0x0300U
#define	DOC_MOVE_CURSOR		0x0301U
#define	DOC_CREATE_BLOB		0x010cU
#define	DOC_SET_SCANOUT_BLOB	0x010dU
#define	DOC_MAP_BLOB		0x0208U
#define	DOC_UNMAP_BLOB		0x0209U
#define	DOC_OK_NODATA		0x1100U
#define	DOC_ERR_UNSPEC		0x1200U
#define	DOC_ERR_NOMEM		0x1201U
#define	DOC_ERR_SCANOUT		0x1202U
#define	DOC_ERR_RESOURCE	0x1203U
#define	DOC_ERR_PARAMETER	0x1205U

struct fixture {
	struct virtio_gpu_2d_state *state;
	uint8_t guest[32768];
	uint64_t fail_at;
	enum virtio_gpu_2d_dma_access last_validate_access;
	unsigned int display_updates;
	unsigned int cursor_updates;
	unsigned int display_resets;
	unsigned int scanout_updates;
	uint32_t cursor_resource;
	uint32_t cursor_hot_x;
	uint32_t cursor_hot_y;
	uint32_t scanout_resource;
	uint32_t scanout_x;
	uint32_t scanout_y;
	uint32_t scanout_width;
	uint32_t scanout_height;
	uint32_t display_x;
	uint32_t display_y;
	uint32_t display_width;
	uint32_t display_height;
	uint8_t display_first_pixel[4];
	bool check_display_pixels;
};

/*
 * A display callback is outside the GPU state mutex so it may query the
 * presentation state.  This fixture holds the first reset callback while a
 * second thread destroys the state.  The destroy callback itself returns,
 * leaving only the original callback as the lifetime owner.
 */
struct destruction_context {
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	struct virtio_gpu_2d_state *state;
	unsigned int callbacks;
	bool first_entered;
	bool release_first;
	bool destroy_callback_seen;
	bool destroy_finished;
};

struct snapshot_lifetime_context {
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	struct virtio_gpu_2d_state *state;
	bool validation_entered;
	bool validation_release;
	bool destroy_reset_seen;
	bool destroy_finished;
	int validation_result;
};

struct destroy_snapshot_context {
	struct fixture fixture;
	struct virtio_gpu_2d_state *state;
	unsigned int callbacks;
	int snapshot_result;
	uint8_t snapshot[GPU_STATE_HEADER_SIZE];
};

static void
destruction_display_reset(void *arg)
{
	struct destruction_context *context;

	context = arg;
	pthread_mutex_lock(&context->mutex);
	context->callbacks++;
	if (context->callbacks == 1) {
		context->first_entered = true;
		(void)pthread_cond_broadcast(&context->condition);
		while (!context->release_first)
			(void)pthread_cond_wait(&context->condition, &context->mutex);
	} else {
		context->destroy_callback_seen = true;
		(void)pthread_cond_broadcast(&context->condition);
	}
	pthread_mutex_unlock(&context->mutex);
}

static void *
destruction_reset_thread(void *arg)
{
	struct destruction_context *context;

	context = arg;
	virtio_gpu_2d_state_reset(context->state);
	return (NULL);
}

static void *
destruction_destroy_thread(void *arg)
{
	struct destruction_context *context;

	context = arg;
	virtio_gpu_2d_state_destroy(context->state);
	pthread_mutex_lock(&context->mutex);
	context->destroy_finished = true;
	(void)pthread_cond_broadcast(&context->condition);
	pthread_mutex_unlock(&context->mutex);
	return (NULL);
}

static int
snapshot_dma_validate(void *arg, uint64_t address, size_t length,
    enum virtio_gpu_2d_dma_access access)
{
	struct snapshot_lifetime_context *context;

	context = arg;
	ATF_CHECK_EQ(address, 0);
	ATF_CHECK_EQ(length, 4);
	ATF_CHECK_EQ(access, VIRTIO_GPU_2D_DMA_DEVICE_READ);
	pthread_mutex_lock(&context->mutex);
	context->validation_entered = true;
	(void)pthread_cond_broadcast(&context->condition);
	while (!context->validation_release)
		(void)pthread_cond_wait(&context->condition, &context->mutex);
	pthread_mutex_unlock(&context->mutex);
	return (0);
}

static void
snapshot_display_reset(void *arg)
{
	struct snapshot_lifetime_context *context;

	context = arg;
	pthread_mutex_lock(&context->mutex);
	context->destroy_reset_seen = true;
	(void)pthread_cond_broadcast(&context->condition);
	pthread_mutex_unlock(&context->mutex);
}

static void
destroy_snapshot_display_reset(void *arg)
{
	struct destroy_snapshot_context *context;

	/* fixture is the first member, so the callback argument is the context. */
	context = arg;
	context->callbacks++;
	context->snapshot_result = virtio_gpu_2d_state_snapshot_validate(
	    context->state, context->snapshot, sizeof(context->snapshot));
}

static void *
snapshot_validate_thread(void *arg)
{
	struct snapshot_lifetime_context *context;
	uint8_t *snapshot;

	context = arg;
	snapshot = (uint8_t *)(context + 1);
	context->validation_result = virtio_gpu_2d_state_snapshot_validate(
	    context->state, snapshot, 164);
	return (NULL);
}

static void *
snapshot_destroy_thread(void *arg)
{
	struct snapshot_lifetime_context *context;

	context = arg;
	virtio_gpu_2d_state_destroy(context->state);
	pthread_mutex_lock(&context->mutex);
	context->destroy_finished = true;
	(void)pthread_cond_broadcast(&context->condition);
	pthread_mutex_unlock(&context->mutex);
	return (NULL);
}

static void
destruction_wait(struct destruction_context *context, bool *predicate)
{
	struct timespec deadline;
	int error;

	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &deadline), 0);
	deadline.tv_sec++;
	pthread_mutex_lock(&context->mutex);
	while (!*predicate) {
		error = pthread_cond_timedwait(&context->condition, &context->mutex,
		    &deadline);
		ATF_REQUIRE_MSG(error == 0, "GPU callback phase timed out: %s",
		    strerror(error));
	}
	pthread_mutex_unlock(&context->mutex);
}

static void
snapshot_wait(struct snapshot_lifetime_context *context, bool *predicate)
{
	struct timespec deadline;
	int error;

	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &deadline), 0);
	deadline.tv_sec++;
	pthread_mutex_lock(&context->mutex);
	while (!*predicate) {
		error = pthread_cond_timedwait(&context->condition, &context->mutex,
		    &deadline);
		ATF_REQUIRE_MSG(error == 0,
		    "GPU snapshot lifetime phase timed out: %s", strerror(error));
	}
	pthread_mutex_unlock(&context->mutex);
}

static int
dma_validate(void *arg, uint64_t address, size_t length,
    enum virtio_gpu_2d_dma_access access)
{
	struct fixture *fixture;

	fixture = arg;
	fixture->last_validate_access = access;
	if (address >= fixture->fail_at)
		return (EIO);
	if (address > sizeof(fixture->guest) ||
	    length > sizeof(fixture->guest) - address)
		return (EFAULT);
	return (0);
}

static int
dma_read(void *arg, uint64_t address, void *output, size_t length)
{
	struct fixture *fixture;

	fixture = arg;
	if (address >= fixture->fail_at)
		return (EIO);
	if (address > sizeof(fixture->guest) ||
	    length > sizeof(fixture->guest) - address)
		return (EFAULT);
	memcpy(output, fixture->guest + address, length);
	return (0);
}

static void
display_reset(void *arg)
{
	struct fixture *fixture;

	fixture = arg;
	fixture->display_resets++;
}

static void
display_update(void *arg, uint32_t scanout_id, uint32_t resource_id,
    uint32_t x, uint32_t y, uint32_t width, uint32_t height)
{
	struct fixture *fixture;
	uint8_t pixel[4];
	uint32_t format;

	fixture = arg;
	ATF_CHECK_EQ(scanout_id, 0);
	ATF_CHECK_EQ(resource_id, 1);
	ATF_CHECK_EQ(x, fixture->display_x);
	ATF_CHECK_EQ(y, fixture->display_y);
	ATF_CHECK_EQ(width, fixture->display_width);
	ATF_CHECK_EQ(height, fixture->display_height);
	if (fixture->check_display_pixels) {
		ATF_REQUIRE(fixture->state != NULL);
		ATF_REQUIRE_EQ(virtio_gpu_2d_state_copy_scanout(
		    fixture->state, x, y, 1, 1, pixel, sizeof(pixel),
		    &format), 0);
		ATF_CHECK_EQ(format, 1);
		ATF_CHECK_EQ(memcmp(pixel, fixture->display_first_pixel,
		    sizeof(pixel)), 0);
	}
	fixture->display_updates++;
}

static void
scanout_update(void *arg, uint32_t scanout_id, uint32_t resource_id,
    uint32_t x, uint32_t y, uint32_t width, uint32_t height)
{
	struct fixture *fixture;

	fixture = arg;
	ATF_CHECK_EQ(scanout_id, 0);
	if (resource_id == 0) {
		ATF_CHECK_EQ(x, 0);
		ATF_CHECK_EQ(y, 0);
		ATF_CHECK_EQ(width, 0);
		ATF_CHECK_EQ(height, 0);
	}
	fixture->scanout_resource = resource_id;
	fixture->scanout_x = x;
	fixture->scanout_y = y;
	fixture->scanout_width = width;
	fixture->scanout_height = height;
	fixture->scanout_updates++;
}

static void
cursor_update(void *arg, uint32_t scanout_id, uint32_t resource_id,
    uint32_t x, uint32_t y, uint32_t hot_x, uint32_t hot_y)
{
	struct fixture *fixture;

	fixture = arg;
	ATF_CHECK_EQ(scanout_id, 0);
	ATF_CHECK_EQ(x, 7);
	ATF_CHECK_EQ(y, 9);
	fixture->cursor_resource = resource_id;
	fixture->cursor_hot_x = hot_x;
	fixture->cursor_hot_y = hot_y;
	fixture->cursor_updates++;
}

static struct virtio_gpu_2d_state *
new_state(struct fixture *fixture, uint32_t resources, uint64_t host_bytes)
{
	struct virtio_gpu_2d_limits limits;
	struct virtio_gpu_2d_ops ops;
	struct virtio_gpu_2d_state *state;

	limits = (struct virtio_gpu_2d_limits) {
		.max_resources = resources,
		.max_host_bytes = host_bytes,
		.scanout_width = 1024,
		.scanout_height = 768,
	};
	ops = (struct virtio_gpu_2d_ops) {
		.dma_validate = dma_validate,
		.dma_read = dma_read,
		.display_reset = display_reset,
		.scanout_update = scanout_update,
		.display_update = display_update,
		.cursor_update = cursor_update,
		.arg = fixture,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_create(&limits, &ops, &state), 0);
	fixture->state = state;
	return (state);
}

static struct virtio_gpu_2d_state *
new_blob_state(struct fixture *fixture)
{
	struct virtio_gpu_2d_limits limits;
	struct virtio_gpu_2d_ops ops;
	struct virtio_gpu_2d_state *state;

	limits = (struct virtio_gpu_2d_limits) {
		.max_resources = 4,
		.max_host_bytes = 32768,
		.max_blob_bytes = 32768,
		.blob_alignment = 16,
		.scanout_width = 1024,
		.scanout_height = 768,
	};
	ops = (struct virtio_gpu_2d_ops) {
		.dma_validate = dma_validate,
		.dma_read = dma_read,
		.display_reset = display_reset,
		.scanout_update = scanout_update,
		.display_update = display_update,
		.cursor_update = cursor_update,
		.arg = fixture,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_create(&limits, &ops, &state), 0);
	fixture->state = state;
	return (state);
}

static struct virtio_gpu_2d_command
create_command(uint32_t id, uint32_t width, uint32_t height)
{

	return ((struct virtio_gpu_2d_command) {
		.type = DOC_CREATE_2D,
		.resource_id = id,
		.format = 1,
		.width = width,
		.height = height,
	});
}

static size_t
attach_request(uint8_t *request, uint32_t resource_id,
    const uint64_t *addresses, const uint32_t *lengths, uint32_t count)
{
	size_t offset;

	memset(request, 0, 32 + (size_t)count * 16);
	le32enc(request, DOC_ATTACH);
	le32enc(request + 24, resource_id);
	le32enc(request + 28, count);
	for (uint32_t i = 0; i < count; i++) {
		offset = 32 + (size_t)i * 16;
		le64enc(request + offset, addresses[i]);
		le32enc(request + offset + 8, lengths[i]);
	}
	return (32 + (size_t)count * 16);
}

ATF_TC_WITHOUT_HEAD(state_requires_complete_dma_contract);
ATF_TC_BODY(state_requires_complete_dma_contract, tc)
{
	struct virtio_gpu_2d_limits limits;
	struct virtio_gpu_2d_ops ops;
	struct virtio_gpu_2d_state *state;
	size_t resource_array_size;
	size_t row_size, transfer_size;
	int expected;

	limits = (struct virtio_gpu_2d_limits) {
		.max_resources = 1,
		.max_host_bytes = 4096,
		.scanout_width = 64,
		.scanout_height = 64,
	};
	memset(&ops, 0, sizeof(ops));
	ATF_CHECK_EQ(virtio_gpu_2d_state_create(&limits, NULL, &state),
	    EINVAL);
	ops.dma_read = dma_read;
	ATF_CHECK_EQ(virtio_gpu_2d_state_create(&limits, &ops, &state),
	    EINVAL);
	ops.dma_validate = dma_validate;
	ops.dma_read = NULL;
	ATF_CHECK_EQ(virtio_gpu_2d_state_create(&limits, &ops, &state),
	    EINVAL);
	ops.dma_read = dma_read;
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_create(&limits, &ops, &state), 0);
	virtio_gpu_2d_state_destroy(state);

	/*
	 * The private resource table is not a wire allocation, but its extent is
	 * later used by alias checks.  Keep the arithmetic correct on both native
	 * word sizes without attempting a deliberately enormous allocation.
	 */
#if SIZE_MAX <= UINT32_MAX
	expected = UINT32_MAX > SIZE_MAX / sizeof(struct gpu_resource) ?
	    EOVERFLOW : 0;
#else
	expected = 0;
#endif
	ATF_CHECK_EQ(gpu_resource_array_size(UINT32_MAX, &resource_array_size),
	    expected);
	if (expected == 0)
		ATF_CHECK_EQ(resource_array_size,
		    (size_t)UINT32_MAX * sizeof(struct gpu_resource));
	ATF_CHECK_EQ(gpu_resource_array_size(1, NULL), EINVAL);

	ATF_CHECK_EQ(gpu_transfer_size(1, 2, &row_size, &transfer_size), 0);
	ATF_CHECK_EQ(row_size, 4);
	ATF_CHECK_EQ(transfer_size, 8);
	ATF_CHECK_EQ(gpu_transfer_size(0, 1, &row_size, &transfer_size),
	    EINVAL);
	ATF_CHECK_EQ(gpu_transfer_size(UINT32_MAX, UINT32_MAX, &row_size,
	    &transfer_size), EOVERFLOW);
}

ATF_TC_WITHOUT_HEAD(resource_limits_and_reset);
ATF_TC_BODY(resource_limits_and_reset, tc)
{
	struct fixture fixture;
	struct virtio_gpu_2d_command command;
	struct virtio_gpu_2d_state *state;

	memset(&fixture, 0, sizeof(fixture));
	fixture.fail_at = UINT64_MAX;
	state = new_state(&fixture, 2, 64);
	command = create_command(1, 4, 2);
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 1);
	ATF_CHECK_EQ(virtio_gpu_2d_state_host_bytes(state), 32);
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_RESOURCE);
	command = create_command(2, 4, 2);
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	command = create_command(3, 1, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_NOMEM);
	virtio_gpu_2d_state_reset(state);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 0);
	ATF_CHECK_EQ(virtio_gpu_2d_state_host_bytes(state), 0);
	ATF_CHECK_EQ(fixture.display_resets, 1);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(zero_resource_id_never_matches_empty_slot);
ATF_TC_BODY(zero_resource_id_never_matches_empty_slot, tc)
{
	struct fixture fixture;
	struct virtio_gpu_2d_command command;
	struct virtio_gpu_2d_state *state;

	memset(&fixture, 0, sizeof(fixture));
	fixture.fail_at = UINT64_MAX;
	state = new_state(&fixture, 2, 64);

	command = create_command(0, 1, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_PARAMETER);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 0);
	ATF_CHECK_EQ(virtio_gpu_2d_state_host_bytes(state), 0);

	command = (struct virtio_gpu_2d_command) {
		.type = DOC_UNREF,
		.resource_id = 0,
	};
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_RESOURCE);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 0);
	ATF_CHECK_EQ(virtio_gpu_2d_state_host_bytes(state), 0);
	ATF_CHECK_EQ(virtio_gpu_2d_state_blob_bytes(state), 0);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(blob_guest_ownership_and_map_rejection);
ATF_TC_BODY(blob_guest_ownership_and_map_rejection, tc)
{
	struct fixture fixture;
	struct virtio_gpu_2d_command command;
	struct virtio_gpu_2d_state *state;
	uint8_t request[72], *corrupt, *snapshot;
	size_t snapshot_size;

	memset(&fixture, 0, sizeof(fixture));
	fixture.fail_at = UINT64_MAX;
	for (size_t i = 0; i < 32; i++)
		fixture.guest[64 + i] = (uint8_t)(0x80 + i);
	state = new_blob_state(&fixture);
	memset(request, 0, sizeof(request));
	le32enc(request, DOC_CREATE_BLOB);
	le32enc(request + 24, 1);
	le32enc(request + 28, 1);	/* BLOB_MEM_GUEST */
	le32enc(request + 32, 1);	/* USE_MAPPABLE */
	le32enc(request + 36, 1);
	le64enc(request + 40, UINT64_C(0x1122334455667788));
	le64enc(request + 48, 32);
	le64enc(request + 56, 64);
	le32enc(request + 64, 32);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_CREATE_BLOB,
		.resource_id = 1,
		.entry_count = 1,
		.blob_memory = 1,
		.blob_flags = 1,
		.blob_id = UINT64_C(0x1122334455667788),
		.blob_size = 32,
	};
	command.blob_size = 31;
	le64enc(request + 48, 31);
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, request,
	    sizeof(request)), DOC_ERR_PARAMETER);
	command.blob_size = 32;
	command.blob_flags = 5;		/* unsupported CROSS_DEVICE */
	le64enc(request + 48, 32);
	le32enc(request + 32, 5);
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, request,
	    sizeof(request)), DOC_ERR_PARAMETER);
	command.blob_flags = 8;		/* reserved blob-flag bit */
	le32enc(request + 32, 8);
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, request,
	    sizeof(request)), DOC_ERR_PARAMETER);
	/* GUEST blobs cannot promise the host-only MAP_BLOB operation. */
	command.blob_flags = 1;
	le32enc(request + 32, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, request,
	    sizeof(request)), DOC_ERR_PARAMETER);
	command.blob_flags = 2;		/* USE_SHAREABLE */
	le32enc(request + 32, 2);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, request,
	    sizeof(request)), DOC_OK_NODATA);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 1);
	ATF_CHECK_EQ(virtio_gpu_2d_state_blob_bytes(state), 32);

	command = (struct virtio_gpu_2d_command) {
		.type = DOC_MAP_BLOB,
		.resource_id = 1,
		.offset = 3,
	};
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_PARAMETER);
	command.offset = 64;
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_PARAMETER);

	/* A second ordinary GUEST blob remains valid and independently owned. */
	le32enc(request + 24, 2);
	le32enc(request + 32, 2);	/* USE_SHAREABLE */
	le64enc(request + 40, UINT64_C(0x8877665544332211));
	le64enc(request + 56, 128);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_CREATE_BLOB,
		.resource_id = 2,
		.entry_count = 1,
		.blob_memory = 1,
		.blob_flags = 2,
		.blob_id = UINT64_C(0x8877665544332211),
		.blob_size = 32,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, request,
	    sizeof(request)), DOC_OK_NODATA);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_size(state, &snapshot_size),
	    0);
	snapshot = malloc(snapshot_size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_save(state, snapshot,
	    snapshot_size), 0);
	ATF_CHECK_EQ(le16dec(snapshot + 4), 3);
	ATF_CHECK_EQ(le64dec(snapshot + 64), 64);
	corrupt = malloc(snapshot_size);
	ATF_REQUIRE(corrupt != NULL);
	memcpy(corrupt, snapshot, snapshot_size);
	/* Checkpoint input must not recreate an impossible reserved flag. */
	le32enc(corrupt + 72 + 52, 9);
	ATF_CHECK_EQ(virtio_gpu_2d_state_snapshot_validate(state, corrupt,
	    snapshot_size), EPROTO);
	memcpy(corrupt, snapshot, snapshot_size);
	/* Retained backing must map completely in the incoming DMA view. */
	le64enc(corrupt + 72 + 72, sizeof(fixture.guest) - 8);
	ATF_CHECK_EQ(virtio_gpu_2d_state_snapshot_validate(state, corrupt,
	    snapshot_size), EFAULT);
	free(corrupt);
	virtio_gpu_2d_state_reset(state);
	ATF_CHECK_EQ(virtio_gpu_2d_state_blob_bytes(state), 0);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_validate(state, snapshot,
	    snapshot_size), 0);
	ATF_CHECK_EQ(fixture.last_validate_access,
	    VIRTIO_GPU_2D_DMA_DEVICE_READ);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_restore(state, snapshot,
	    snapshot_size), 0);
	ATF_CHECK_EQ(virtio_gpu_2d_state_blob_bytes(state), 64);
	free(snapshot);


	command = (struct virtio_gpu_2d_command) {
		.type = DOC_DETACH,
		.resource_id = 1,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	command.type = DOC_UNMAP_BLOB;
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_UNSPEC);
	command.type = DOC_UNREF;
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	command.resource_id = 2;
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(virtio_gpu_2d_state_blob_bytes(state), 0);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(blob_scanout_and_snapshot);
ATF_TC_BODY(blob_scanout_and_snapshot, tc)
{
	struct fixture fixture;
	struct virtio_gpu_2d_command command;
	struct virtio_gpu_2d_state *state;
	uint8_t actual[32], before[32], request[72], pixels[32], *obsolete,
	    *snapshot;
	size_t snapshot_size;

	memset(&fixture, 0, sizeof(fixture));
	fixture.fail_at = UINT64_MAX;
	for (size_t i = 0; i < sizeof(pixels); i++)
		fixture.guest[64 + i] = (uint8_t)(0x40 + i);
	state = new_blob_state(&fixture);

	memset(request, 0, sizeof(request));
	le32enc(request, DOC_CREATE_BLOB);
	le32enc(request + 24, 1);
	le32enc(request + 28, 1);	/* BLOB_MEM_GUEST */
	le32enc(request + 32, 2);	/* USE_SHAREABLE */
	le32enc(request + 36, 1);
	le64enc(request + 40, UINT64_C(0x123456789abcdef0));
	le64enc(request + 48, sizeof(pixels));
	le64enc(request + 56, 64);
	le32enc(request + 64, sizeof(pixels));
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_CREATE_BLOB,
		.resource_id = 1,
		.entry_count = 1,
		.blob_memory = 1,
		.blob_flags = 2,
		.blob_id = UINT64_C(0x123456789abcdef0),
		.blob_size = sizeof(pixels),
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, request,
	    sizeof(request)), DOC_OK_NODATA);

	/*
	 * Linux may transfer before SET_SCANOUT_BLOB communicates the stride.
	 * That transfer is validated but the later command imports all rows.
	 */
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_TRANSFER,
		.resource_id = 1,
		.width = 4,
		.height = 3,
	};
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_PARAMETER);
	command.height = 2;
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_SET_SCANOUT_BLOB,
		.resource_id = 1,
		.width = 4,
		.height = 2,
		.resource_width = 4,
		.resource_height = 2,
		.format = VIRTIO_GPU_2D_FORMAT_B8G8R8A8_UNORM,
	};
	command.strides[0] = 16;
	command.width = 0;
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_PARAMETER);
	command.width = 4;
	command.height = 0;
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_PARAMETER);
	command.height = 2;
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(fixture.scanout_updates, 1);
	ATF_CHECK_EQ(fixture.scanout_resource, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_state_host_bytes(state), sizeof(pixels));
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_read_resource(state, 1, 0, pixels,
	    sizeof(pixels)), 0);
	ATF_CHECK_EQ(memcmp(pixels, fixture.guest + 64, sizeof(pixels)), 0);

	fixture.guest[64] ^= 0xff;
	fixture.display_x = 0;
	fixture.display_y = 0;
	fixture.display_width = 4;
	fixture.display_height = 2;
	memcpy(fixture.display_first_pixel, fixture.guest + 64, 4);
	fixture.check_display_pixels = true;
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_FLUSH,
		.resource_id = 1,
		.width = 4,
		.height = 2,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(fixture.display_updates, 1);

	/* A later-row DMA fault must not publish an earlier blob row. */
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_read_resource(state, 1, 0, before,
	    sizeof(before)), 0);
	for (size_t i = 0; i < sizeof(pixels); i++)
		fixture.guest[64 + i] ^= 0x5a;
	fixture.fail_at = 80;	/* Second 16-byte row. */
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_UNSPEC);
	ATF_CHECK_EQ(fixture.display_updates, 1);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_read_resource(state, 1, 0, actual,
	    sizeof(actual)), 0);
	ATF_CHECK_EQ(memcmp(actual, before, sizeof(actual)), 0);
	fixture.fail_at = UINT64_MAX;
	memcpy(fixture.display_first_pixel, fixture.guest + 64, 4);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(fixture.display_updates, 2);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_UPDATE_CURSOR,
		.resource_id = 1,
		.x = 7,
		.y = 9,
	};
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_PARAMETER);
	ATF_CHECK_EQ(virtio_gpu_2d_state_host_bytes(state), sizeof(pixels));
	ATF_CHECK_EQ(fixture.cursor_updates, 0);

	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_size(state,
	    &snapshot_size), 0);
	snapshot = malloc(snapshot_size);
	obsolete = malloc(snapshot_size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE(obsolete != NULL);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_save(state, snapshot,
	    snapshot_size), 0);
	ATF_CHECK_EQ(le16dec(snapshot + 4), 3);
	ATF_CHECK_EQ(le64dec(snapshot + 16), sizeof(pixels));
	ATF_CHECK_EQ(le64dec(snapshot + 64), sizeof(pixels));

	/* Unreleased predecessor encodings are intentionally unsupported. */
	memcpy(obsolete, snapshot, snapshot_size);
	le16enc(obsolete + 4, 2);
	ATF_CHECK_EQ(virtio_gpu_2d_state_snapshot_validate(state, obsolete,
	    snapshot_size), EPROTO);
	free(obsolete);

	virtio_gpu_2d_state_reset(state);
	fixture.check_display_pixels = false;
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_validate(state, snapshot,
	    snapshot_size), 0);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_restore(state, snapshot,
	    snapshot_size), 0);
	ATF_CHECK_EQ(virtio_gpu_2d_state_host_bytes(state), sizeof(pixels));
	ATF_CHECK_EQ(virtio_gpu_2d_state_blob_bytes(state), sizeof(pixels));
	ATF_CHECK_EQ(fixture.scanout_resource, 1);

	/* Plane-offset corruption must be rejected transactionally. */
	le32enc(snapshot + 72 + 28, 16);
	ATF_CHECK_EQ(virtio_gpu_2d_state_snapshot_validate(state, snapshot,
	    snapshot_size), EPROTO);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 1);

	command = (struct virtio_gpu_2d_command) {
		.type = DOC_UNREF,
		.resource_id = 1,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(virtio_gpu_2d_state_host_bytes(state), 0);
	ATF_CHECK_EQ(virtio_gpu_2d_state_blob_bytes(state), 0);
	free(snapshot);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(blob_cursor_and_snapshot);
ATF_TC_BODY(blob_cursor_and_snapshot, tc)
{
	struct fixture fixture;
	struct virtio_gpu_2d_command command;
	struct virtio_gpu_2d_state *state;
	uint8_t request[72], pixels[16], *snapshot;
	size_t snapshot_size;

	memset(&fixture, 0, sizeof(fixture));
	fixture.fail_at = UINT64_MAX;
	for (size_t i = 0; i < 64 * 64 * 4; i++)
		fixture.guest[i] = (uint8_t)(i ^ (i >> 8));
	state = new_blob_state(&fixture);
	memset(request, 0, sizeof(request));
	le32enc(request, DOC_CREATE_BLOB);
	le32enc(request + 24, 1);
	le32enc(request + 28, 1);
	le32enc(request + 32, 2);	/* USE_SHAREABLE */
	le32enc(request + 36, 1);
	le64enc(request + 40, UINT64_C(0xc0dec0dec0dec0de));
	le64enc(request + 48, 64 * 64 * 4);
	le64enc(request + 56, 0);
	le32enc(request + 64, 64 * 64 * 4);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_CREATE_BLOB,
		.resource_id = 1,
		.entry_count = 1,
		.blob_memory = 1,
		.blob_flags = 2,
		.blob_id = UINT64_C(0xc0dec0dec0dec0de),
		.blob_size = 64 * 64 * 4,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, request,
	    sizeof(request)), DOC_OK_NODATA);

	/* The upstream Linux cursor path transfers before UPDATE_CURSOR. */
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_TRANSFER,
		.resource_id = 1,
		.width = 64,
		.height = 64,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_UPDATE_CURSOR,
		.resource_id = 1,
		.scanout_id = 0,
		.x = 7,
		.y = 9,
		.hot_x = 64,
		.hot_y = 4,
	};
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_PARAMETER);
	ATF_CHECK_EQ(virtio_gpu_2d_state_host_bytes(state), 0);
	command.hot_x = 3;
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(fixture.cursor_updates, 1);
	ATF_CHECK_EQ(fixture.cursor_resource, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_state_host_bytes(state), 64 * 64 * 4);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_read_resource(state, 1, 0, pixels,
	    sizeof(pixels)), 0);
	ATF_CHECK_EQ(memcmp(pixels, fixture.guest, sizeof(pixels)), 0);

	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_size(state,
	    &snapshot_size), 0);
	snapshot = malloc(snapshot_size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_save(state, snapshot,
	    snapshot_size), 0);
	virtio_gpu_2d_state_reset(state);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_restore(state, snapshot,
	    snapshot_size), 0);
	ATF_CHECK_EQ(fixture.cursor_updates, 2);
	ATF_CHECK_EQ(fixture.cursor_resource, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_state_blob_bytes(state), 64 * 64 * 4);
	ATF_CHECK_EQ(virtio_gpu_2d_state_host_bytes(state), 64 * 64 * 4);
	free(snapshot);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(obsolete_snapshot_versions_rejected);
ATF_TC_BODY(obsolete_snapshot_versions_rejected, tc)
{
	struct fixture fixture;
	struct virtio_gpu_2d_state *state;
	uint8_t image[72 + 48 + 4];

	memset(&fixture, 0, sizeof(fixture));
	fixture.fail_at = UINT64_MAX;
	state = new_state(&fixture, 1, 64);
	memset(image, 0, sizeof(image));
	le32enc(image, UINT32_C(0x44324756));
	le16enc(image + 4, 1);
	le16enc(image + 6, 72);
	le32enc(image + 8, 1);
	le64enc(image + 16, 4);
	le32enc(image + 72, 9);
	le32enc(image + 76, 1);
	le32enc(image + 80, 1);
	le32enc(image + 84, 1);
	le32enc(image + 88, 4);
	le64enc(image + 96, 4);
	image[120] = 0x11;
	image[121] = 0x22;
	image[122] = 0x33;
	image[123] = 0x44;
	ATF_CHECK_EQ(virtio_gpu_2d_state_snapshot_validate(state, image,
	    sizeof(image)), EPROTO);
	le16enc(image + 4, 2);
	ATF_CHECK_EQ(virtio_gpu_2d_state_snapshot_restore(state, image,
	    sizeof(image)), EPROTO);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 0);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(backing_transfer_is_atomic);
ATF_TC_BODY(backing_transfer_is_atomic, tc)
{
	struct fixture fixture;
	struct virtio_gpu_2d_command attach, command;
	struct virtio_gpu_2d_state *state;
	uint64_t addresses[2] = { 8, 30 };
	uint32_t lengths[2] = { 10, 22 };
	uint8_t request[64], actual[32], zero[32];
	size_t request_len;

	memset(&fixture, 0, sizeof(fixture));
	fixture.fail_at = UINT64_MAX;
	for (size_t i = 0; i < sizeof(actual); i++) {
		if (i < lengths[0])
			fixture.guest[addresses[0] + i] = (uint8_t)(i + 1);
		else
			fixture.guest[addresses[1] + i - lengths[0]] =
			    (uint8_t)(i + 1);
	}
	state = new_state(&fixture, 2, 64);
	command = create_command(1, 4, 2);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	request_len = attach_request(request, 1, addresses, lengths, 2);
	attach = (struct virtio_gpu_2d_command) {
		.type = DOC_ATTACH,
		.resource_id = 1,
		.entry_count = 2,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &attach, request,
	    request_len), DOC_OK_NODATA);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_TRANSFER,
		.resource_id = 1,
		.width = 4,
		.height = 2,
	};
	fixture.fail_at = 30;
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_UNSPEC);
	memset(zero, 0, sizeof(zero));
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_read_resource(state, 1, 0, actual,
	    sizeof(actual)), 0);
	ATF_CHECK_EQ(memcmp(actual, zero, sizeof(actual)), 0);
	fixture.fail_at = UINT64_MAX;
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_read_resource(state, 1, 0, actual,
	    sizeof(actual)), 0);
	for (size_t i = 0; i < sizeof(actual); i++)
		ATF_CHECK_EQ(actual[i], (uint8_t)(i + 1));
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(backing_transaction_and_detach);
ATF_TC_BODY(backing_transaction_and_detach, tc)
{
	struct fixture fixture;
	struct virtio_gpu_2d_command attach, command;
	struct virtio_gpu_2d_state *state;
	uint64_t address = 8;
	uint32_t length = 32;
	uint8_t request[48];
	size_t request_len;

	memset(&fixture, 0, sizeof(fixture));
	fixture.fail_at = UINT64_MAX;
	state = new_state(&fixture, 1, 64);
	command = create_command(1, 4, 2);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	request_len = attach_request(request, 1, &address, &length, 1);
	attach = (struct virtio_gpu_2d_command) {
		.type = DOC_ATTACH,
		.resource_id = 1,
		.entry_count = 1,
	};
	le32enc(request + 24, 2);
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &attach, request,
	    request_len), DOC_ERR_PARAMETER);
	le32enc(request + 24, 1);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &attach, request,
	    request_len), DOC_OK_NODATA);
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &attach, request,
	    request_len), DOC_ERR_UNSPEC);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_DETACH,
		.resource_id = 1,
	};
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_UNSPEC);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(scanout_flush_and_unref);
ATF_TC_BODY(scanout_flush_and_unref, tc)
{
	struct fixture fixture;
	struct virtio_gpu_2d_command attach, command;
	struct virtio_gpu_2d_state *state;
	uint64_t address = 0;
	uint32_t length = 32;
	uint32_t resource, x, y, width, height;
	uint8_t request[48];

	memset(&fixture, 0, sizeof(fixture));
	fixture.fail_at = UINT64_MAX;
	state = new_state(&fixture, 1, 64);
	command = create_command(1, 4, 2);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_SET_SCANOUT,
		.resource_id = 1,
		.width = 4,
		.height = 2,
	};
	/* Section 5.7.6.1 requires backing before scanout selection. */
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_UNSPEC);
	attach_request(request, 1, &address, &length, 1);
	attach = (struct virtio_gpu_2d_command) {
		.type = DOC_ATTACH,
		.resource_id = 1,
		.entry_count = 1,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &attach, request,
	    sizeof(request)), DOC_OK_NODATA);
	command.scanout_id = 1;
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_SCANOUT);
	command.scanout_id = 0;
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(fixture.scanout_updates, 1);
	ATF_CHECK_EQ(fixture.scanout_resource, 1);
	ATF_CHECK_EQ(fixture.scanout_width, 4);
	ATF_CHECK_EQ(fixture.scanout_height, 2);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_scanout(state, &resource, &x, &y,
	    &width, &height), 0);
	ATF_CHECK_EQ(resource, 1);
	ATF_CHECK_EQ(width, 4);
	ATF_CHECK_EQ(height, 2);
	command.type = DOC_FLUSH;
	fixture.display_width = 4;
	fixture.display_height = 2;
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(fixture.display_updates, 1);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_SET_SCANOUT,
		.resource_id = 1,
		.x = 1,
		.width = 2,
		.height = 2,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(fixture.scanout_updates, 2);
	ATF_CHECK_EQ(fixture.scanout_resource, 1);
	ATF_CHECK_EQ(fixture.scanout_x, 1);
	ATF_CHECK_EQ(fixture.scanout_width, 2);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_FLUSH,
		.resource_id = 1,
		.width = 4,
		.height = 2,
	};
	fixture.display_width = 2;
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(fixture.display_updates, 2);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_UNREF,
		.resource_id = 1,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(fixture.scanout_updates, 3);
	ATF_CHECK_EQ(fixture.scanout_resource, 0);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_scanout(state, &resource, &x, &y,
	    &width, &height), 0);
	ATF_CHECK_EQ(resource, 0);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(scanout_respects_configured_extent);
ATF_TC_BODY(scanout_respects_configured_extent, tc)
{
	struct fixture fixture;
	struct virtio_gpu_2d_command attach, command;
	struct virtio_gpu_2d_state *state;
	uint64_t address;
	uint32_t length;
	uint8_t request[48], *snapshot;
	size_t snapshot_size;

	memset(&fixture, 0, sizeof(fixture));
	fixture.fail_at = UINT64_MAX;
	state = new_state(&fixture, 1, 8192);
	command = create_command(1, 1025, 1);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	address = 0;
	length = 1025 * 4;
	attach_request(request, 1, &address, &length, 1);
	attach = (struct virtio_gpu_2d_command) {
		.type = DOC_ATTACH,
		.resource_id = 1,
		.entry_count = 1,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &attach, request,
	    sizeof(request)), DOC_OK_NODATA);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_SET_SCANOUT,
		.resource_id = 1,
		.width = 1025,
		.height = 1,
	};
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_PARAMETER);
	command.width = 1024;
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);

	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_size(state,
	    &snapshot_size), 0);
	snapshot = malloc(snapshot_size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_save(state, snapshot,
	    snapshot_size), 0);
	/* Fixed-width snapshot field: active scanout width at byte 36. */
	le32enc(snapshot + 36, 1025);
	ATF_CHECK_EQ(virtio_gpu_2d_state_snapshot_validate(state, snapshot,
	    snapshot_size), EPROTO);
	free(snapshot);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(cursor_validation_and_callbacks);
ATF_TC_BODY(cursor_validation_and_callbacks, tc)
{
	struct fixture fixture;
	struct virtio_gpu_2d_command command;
	struct virtio_gpu_2d_state *state;
	uint32_t format, hot_x, hot_y, x, y;
	uint8_t *pixels;

	memset(&fixture, 0, sizeof(fixture));
	fixture.fail_at = UINT64_MAX;
	state = new_state(&fixture, 2, 65536);
	pixels = malloc(VIRTIO_GPU_2D_CURSOR_BYTES);
	ATF_REQUIRE(pixels != NULL);
	ATF_CHECK_EQ(virtio_gpu_2d_state_copy_cursor(state, pixels,
	    VIRTIO_GPU_2D_CURSOR_BYTES, &format, &x, &y, &hot_x, &hot_y),
	    ENOENT);
	command = create_command(1, 32, 64);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_UPDATE_CURSOR,
		.resource_id = 1,
		.x = 7,
		.y = 9,
	};
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_PARAMETER);
	command = create_command(2, 64, 64);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_UPDATE_CURSOR,
		.resource_id = 2,
		.x = 7,
		.y = 9,
		.hot_x = 3,
		.hot_y = 4,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(fixture.cursor_updates, 1);
	ATF_CHECK_EQ(fixture.cursor_resource, 2);
	ATF_CHECK_EQ(fixture.cursor_hot_x, 3);
	ATF_CHECK_EQ(fixture.cursor_hot_y, 4);
	memset(pixels, 0xa5, VIRTIO_GPU_2D_CURSOR_BYTES);
	ATF_CHECK_EQ(virtio_gpu_2d_state_copy_cursor(state, pixels,
	    VIRTIO_GPU_2D_CURSOR_BYTES - 1, &format, &x, &y, &hot_x, &hot_y),
	    EMSGSIZE);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_copy_cursor(state, pixels,
	    VIRTIO_GPU_2D_CURSOR_BYTES, &format, &x, &y, &hot_x, &hot_y), 0);
	ATF_CHECK_EQ(format, 1);
	ATF_CHECK_EQ(x, 7);
	ATF_CHECK_EQ(y, 9);
	ATF_CHECK_EQ(hot_x, 3);
	ATF_CHECK_EQ(hot_y, 4);
	for (size_t i = 0; i < VIRTIO_GPU_2D_CURSOR_BYTES; i++)
		ATF_CHECK_EQ(pixels[i], 0);
	command.type = DOC_MOVE_CURSOR;
	command.resource_id = 0;
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(fixture.cursor_updates, 2);
	ATF_CHECK_EQ(fixture.cursor_resource, 2);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_UNREF,
		.resource_id = 2,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(fixture.cursor_updates, 3);
	ATF_CHECK_EQ(fixture.cursor_resource, 0);
	ATF_CHECK_EQ(fixture.cursor_hot_x, 0);
	ATF_CHECK_EQ(fixture.cursor_hot_y, 0);
	ATF_CHECK_EQ(virtio_gpu_2d_state_copy_cursor(state, pixels,
	    VIRTIO_GPU_2D_CURSOR_BYTES, &format, &x, &y, &hot_x, &hot_y),
	    ENOENT);
	free(pixels);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(scanout_copy_is_atomic_and_cropped);
ATF_TC_BODY(scanout_copy_is_atomic_and_cropped, tc)
{
	struct fixture fixture;
	struct virtio_gpu_2d_command attach, command;
	struct virtio_gpu_2d_state *state;
	uint64_t address;
	uint32_t format, length;
	uint8_t actual[8], request[48];
	const uint8_t expected[8] = { 4, 5, 6, 7, 12, 13, 14, 15 };

	memset(&fixture, 0, sizeof(fixture));
	for (size_t i = 0; i < 16; i++)
		fixture.guest[i] = (uint8_t)i;
	fixture.fail_at = UINT64_MAX;
	state = new_state(&fixture, 1, 16);
	command = create_command(1, 2, 2);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	address = 0;
	length = 16;
	attach_request(request, 1, &address, &length, 1);
	attach = (struct virtio_gpu_2d_command) {
		.type = DOC_ATTACH,
		.resource_id = 1,
		.entry_count = 1,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &attach, request,
	    sizeof(request)), DOC_OK_NODATA);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_TRANSFER,
		.resource_id = 1,
		.width = 2,
		.height = 2,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_SET_SCANOUT,
		.resource_id = 1,
		.width = 2,
		.height = 2,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_copy_scanout(state, 1, 0, 1, 2,
	    actual, sizeof(actual), &format), 0);
	ATF_CHECK_EQ(format, 1);
	ATF_CHECK_EQ(memcmp(actual, expected, sizeof(expected)), 0);
	{
		uint32_t captured_width, captured_height;
		size_t captured_bytes;
		uint8_t full[16];

		ATF_REQUIRE_EQ(virtio_gpu_2d_state_capture_scanout(state, full,
		    sizeof(full), &captured_width, &captured_height, &format,
		    &captured_bytes), 0);
		ATF_CHECK_EQ(captured_width, 2);
		ATF_CHECK_EQ(captured_height, 2);
		ATF_CHECK_EQ(format, 1);
		ATF_CHECK_EQ(captured_bytes, sizeof(full));
		ATF_CHECK_EQ(memcmp(full, fixture.guest, sizeof(full)), 0);
		ATF_CHECK_EQ(virtio_gpu_2d_state_capture_scanout(state, full,
		    sizeof(full) - 1, &captured_width, &captured_height,
		    &format, &captured_bytes), EMSGSIZE);
		ATF_CHECK_EQ(virtio_gpu_2d_state_capture_scanout(state,
		    state->resources[0].pixels, sizeof(full), &captured_width,
		    &captured_height, &format, &captured_bytes), EINVAL);
		ATF_CHECK_EQ(virtio_gpu_2d_state_capture_scanout(state, full,
		    sizeof(full), &state->resources[0].width,
		    &captured_height, &format, &captured_bytes), EINVAL);
	}
	ATF_CHECK_EQ(virtio_gpu_2d_state_copy_scanout(state, 0, 0, 2, 2,
	    state->resources[0].pixels, 16, &format), EINVAL);
	ATF_CHECK_EQ(virtio_gpu_2d_state_read_resource(state, 1, 0,
	    state->resources[0].pixels, 16), EINVAL);
	ATF_CHECK_EQ(virtio_gpu_2d_state_copy_scanout(state, 0, 0, 1, 2,
	    actual, sizeof(actual) - 1, &format), EMSGSIZE);
	ATF_CHECK_EQ(virtio_gpu_2d_state_copy_scanout(state, 2, 0, 1, 1,
	    actual, 4, &format), ERANGE);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_SET_SCANOUT,
		.resource_id = 0,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(fixture.scanout_updates, 2);
	ATF_CHECK_EQ(fixture.scanout_resource, 0);
	ATF_CHECK_EQ(virtio_gpu_2d_state_copy_scanout(state, 0, 0, 1, 1,
	    actual, 4, &format), ENOENT);
	{
		uint32_t captured_width = UINT32_MAX;
		uint32_t captured_height = UINT32_MAX;
		size_t captured_bytes = SIZE_MAX;

		ATF_REQUIRE_EQ(virtio_gpu_2d_state_capture_scanout(state, actual,
		    sizeof(actual), &captured_width, &captured_height, &format,
		    &captured_bytes), 0);
		ATF_CHECK_EQ(captured_width, 0);
		ATF_CHECK_EQ(captured_height, 0);
		ATF_CHECK_EQ(format, 0);
		ATF_CHECK_EQ(captured_bytes, 0);
	}
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(scanout_requires_nonempty_rectangle);
ATF_TC_BODY(scanout_requires_nonempty_rectangle, tc)
{
	struct fixture fixture;
	struct virtio_gpu_2d_command command;
	struct virtio_gpu_2d_state *state;

	memset(&fixture, 0, sizeof(fixture));
	fixture.fail_at = UINT64_MAX;
	state = new_state(&fixture, 1, 64);
	command = create_command(1, 2, 2);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_SET_SCANOUT,
		.resource_id = 1,
		.width = 0,
		.height = 1,
	};
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_PARAMETER);
	command.width = 1;
	command.height = 0;
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_ERR_PARAMETER);
	/* A resource-id of zero is the distinct, allowed disabled representation. */
	command.resource_id = 0;
	ATF_CHECK_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(portable_snapshot_transaction);
ATF_TC_BODY(portable_snapshot_transaction, tc)
{
	struct fixture fixture;
	struct virtio_gpu_2d_command attach, command;
	struct virtio_gpu_2d_state *state;
	uint64_t address = 8;
	uint32_t length = 40;
	uint8_t request[48], pixels[40];
	uint8_t *snapshot, *corrupt;
	size_t snapshot_size;

	memset(&fixture, 0, sizeof(fixture));
	fixture.fail_at = UINT64_MAX;
	for (size_t i = 0; i < sizeof(pixels); i++)
		fixture.guest[address + i] = (uint8_t)(0x80 + i);
	state = new_state(&fixture, 2, 65536);
	command = create_command(1, 5, 2);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	attach_request(request, 1, &address, &length, 1);
	attach = (struct virtio_gpu_2d_command) {
		.type = DOC_ATTACH,
		.resource_id = 1,
		.entry_count = 1,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &attach, request,
	    sizeof(request)), DOC_OK_NODATA);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_TRANSFER,
		.resource_id = 1,
		.width = 5,
		.height = 2,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	command.type = DOC_SET_SCANOUT;
	command.x = 1;
	command.width = 4;
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	command = create_command(2, 64, 64);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_UPDATE_CURSOR,
		.resource_id = 2,
		.scanout_id = 0,
		.x = 7,
		.y = 9,
		.hot_x = 3,
		.hot_y = 4,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(fixture.cursor_updates, 1);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_size(state,
	    &snapshot_size), 0);
	snapshot = malloc(snapshot_size);
	corrupt = malloc(snapshot_size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE(corrupt != NULL);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_save(state, snapshot,
	    snapshot_size), 0);
	ATF_CHECK_EQ(le32dec(snapshot), UINT32_C(0x44324756));
	ATF_CHECK_EQ(le16dec(snapshot + 4), 3);
	ATF_CHECK_EQ(le16dec(snapshot + 6), 72);
	ATF_CHECK_EQ(le32dec(snapshot + 8), 2);
	virtio_gpu_2d_state_reset(state);
	ATF_CHECK_EQ(fixture.display_resets, 1);
	fixture.display_x = 0;
	fixture.display_y = 0;
	fixture.display_width = 4;
	fixture.display_height = 2;
	memcpy(fixture.display_first_pixel, fixture.guest + address + 4,
	    sizeof(fixture.display_first_pixel));
	fixture.check_display_pixels = true;
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_validate(state, snapshot,
	    snapshot_size), 0);
	ATF_CHECK_EQ(fixture.last_validate_access,
	    VIRTIO_GPU_2D_DMA_DEVICE_READ);
	ATF_CHECK_EQ(fixture.display_updates, 0);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 0);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_restore(state, snapshot,
	    snapshot_size), 0);
	ATF_CHECK_EQ(fixture.display_resets, 2);
	ATF_CHECK_EQ(fixture.scanout_updates, 2);
	ATF_CHECK_EQ(fixture.scanout_resource, 1);
	ATF_CHECK_EQ(fixture.scanout_x, 1);
	ATF_CHECK_EQ(fixture.scanout_width, 4);
	ATF_CHECK_EQ(fixture.scanout_height, 2);
	ATF_CHECK_EQ(fixture.display_updates, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 2);
	ATF_CHECK_EQ(fixture.cursor_updates, 2);
	ATF_CHECK_EQ(fixture.cursor_resource, 2);
	ATF_CHECK_EQ(fixture.cursor_hot_x, 3);
	ATF_CHECK_EQ(fixture.cursor_hot_y, 4);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_read_resource(state, 1, 0, pixels,
	    sizeof(pixels)), 0);
	for (size_t i = 0; i < sizeof(pixels); i++)
		ATF_CHECK_EQ(pixels[i], (uint8_t)(0x80 + i));

	memcpy(corrupt, snapshot, snapshot_size);
	le16enc(corrupt + 4, 4);
	ATF_CHECK_EQ(virtio_gpu_2d_state_snapshot_validate(state, corrupt,
	    snapshot_size), EPROTO);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 2);
	ATF_CHECK_EQ(virtio_gpu_2d_state_snapshot_restore(state, corrupt,
	    snapshot_size), EPROTO);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 2);
	ATF_CHECK_EQ(virtio_gpu_2d_state_snapshot_restore(state, snapshot,
	    snapshot_size - 1), EPROTO);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 2);
	memcpy(corrupt, snapshot, snapshot_size);
	corrupt[64] = 1;
	ATF_CHECK_EQ(virtio_gpu_2d_state_snapshot_restore(state, corrupt,
	    snapshot_size), E2BIG);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 2);
	free(corrupt);
	free(snapshot);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(empty_restore_clears_destination_presentation);
ATF_TC_BODY(empty_restore_clears_destination_presentation, tc)
{
	struct fixture empty_fixture, fixture;
	struct virtio_gpu_2d_command attach, command;
	struct virtio_gpu_2d_state *empty, *target;
	uint64_t address;
	uint32_t length;
	uint8_t request[48];
	uint8_t *snapshot;
	size_t snapshot_size;

	memset(&fixture, 0, sizeof(fixture));
	fixture.fail_at = UINT64_MAX;
	memset(&empty_fixture, 0, sizeof(empty_fixture));
	empty_fixture.fail_at = UINT64_MAX;
	target = new_state(&fixture, 4, 4096);
	empty = new_state(&empty_fixture, 4, 4096);
	command = create_command(1, 4, 2);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(target, &command, NULL, 0),
	    DOC_OK_NODATA);
	address = 0;
	length = 32;
	attach_request(request, 1, &address, &length, 1);
	attach = (struct virtio_gpu_2d_command) {
		.type = DOC_ATTACH,
		.resource_id = 1,
		.entry_count = 1,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(target, &attach, request,
	    sizeof(request)), DOC_OK_NODATA);
	command = (struct virtio_gpu_2d_command) {
		.type = DOC_SET_SCANOUT,
		.resource_id = 1,
		.scanout_id = 0,
		.width = 4,
		.height = 2,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(target, &command, NULL, 0),
	    DOC_OK_NODATA);
	fixture.display_width = 4;
	fixture.display_height = 2;
	command.type = DOC_FLUSH;
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(target, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_CHECK_EQ(fixture.display_updates, 1);

	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_size(empty,
	    &snapshot_size), 0);
	snapshot = malloc(snapshot_size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_save(empty, snapshot,
	    snapshot_size), 0);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_restore(target, snapshot,
	    snapshot_size), 0);
	ATF_CHECK_EQ(fixture.display_resets, 1);
	ATF_CHECK_EQ(fixture.display_updates, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(target), 0);

	free(snapshot);
	virtio_gpu_2d_state_destroy(empty);
	virtio_gpu_2d_state_destroy(target);
}

ATF_TC_WITHOUT_HEAD(snapshot_output_alias_is_rejected);
ATF_TC_BODY(snapshot_output_alias_is_rejected, tc)
{
	struct fixture fixture;
	struct virtio_gpu_2d_command command;
	struct virtio_gpu_2d_state *state;
	uint8_t original[16], *snapshot;
	size_t snapshot_size;

	memset(&fixture, 0, sizeof(fixture));
	fixture.fail_at = UINT64_MAX;
	state = new_state(&fixture, 1, 64);
	command = create_command(1, 2, 2);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(state, &command, NULL, 0),
	    DOC_OK_NODATA);
	ATF_REQUIRE(state->resources[0].pixels != NULL);
	for (size_t i = 0; i < sizeof(original); i++)
		state->resources[0].pixels[i] = (uint8_t)(0xa0 + i);
	memcpy(original, state->resources[0].pixels, sizeof(original));
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_snapshot_size(state,
	    &snapshot_size), 0);

	/*
	 * The requested output extent is intentionally larger than either
	 * aliased object.  A conforming writer must reject the range without
	 * touching it, rather than relying on the caller's allocation size.
	 */
	ATF_CHECK_EQ(virtio_gpu_2d_state_snapshot_save(state, state,
	    snapshot_size), EINVAL);
	ATF_CHECK_EQ(virtio_gpu_2d_state_snapshot_save(state,
	    state->resources[0].pixels, snapshot_size), EINVAL);
	ATF_CHECK_EQ(virtio_gpu_2d_state_snapshot_validate(state, state,
	    snapshot_size), EINVAL);
	ATF_CHECK_EQ(virtio_gpu_2d_state_snapshot_restore(state,
	    state->resources, snapshot_size), EINVAL);
	ATF_CHECK_EQ(memcmp(state->resources[0].pixels, original,
	    sizeof(original)), 0);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 1);

	snapshot = malloc(snapshot_size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_CHECK_EQ(virtio_gpu_2d_state_snapshot_save(state, snapshot,
	    snapshot_size), 0);
	free(snapshot);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(destroy_drains_external_presentation_callbacks);
ATF_TC_BODY(destroy_drains_external_presentation_callbacks, tc)
{
	struct destruction_context context;
	struct virtio_gpu_2d_limits limits;
	struct virtio_gpu_2d_ops ops;
	pthread_condattr_t attr;
	pthread_t reset_thread, destroy_thread;

	memset(&context, 0, sizeof(context));
	ATF_REQUIRE_EQ(pthread_mutex_init(&context.mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_condattr_init(&attr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_setclock(&attr, CLOCK_MONOTONIC), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&context.condition, &attr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_destroy(&attr), 0);
	limits = (struct virtio_gpu_2d_limits) {
		.max_resources = 1,
		.max_host_bytes = 4096,
		.scanout_width = 1,
		.scanout_height = 1,
	};
	ops = (struct virtio_gpu_2d_ops) {
		.dma_validate = dma_validate,
		.dma_read = dma_read,
		.display_reset = destruction_display_reset,
		.arg = &context,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_create(&limits, &ops,
	    &context.state), 0);
	ATF_REQUIRE_EQ(pthread_create(&reset_thread, NULL,
	    destruction_reset_thread, &context), 0);
	destruction_wait(&context, &context.first_entered);
	ATF_REQUIRE_EQ(pthread_create(&destroy_thread, NULL,
	    destruction_destroy_thread, &context), 0);
	destruction_wait(&context, &context.destroy_callback_seen);
	pthread_mutex_lock(&context.mutex);
	ATF_CHECK(!context.destroy_finished);
	context.release_first = true;
	(void)pthread_cond_broadcast(&context.condition);
	pthread_mutex_unlock(&context.mutex);
	ATF_REQUIRE_EQ(pthread_join(reset_thread, NULL), 0);
	ATF_REQUIRE_EQ(pthread_join(destroy_thread, NULL), 0);
	pthread_mutex_lock(&context.mutex);
	ATF_CHECK(context.destroy_finished);
	ATF_CHECK_EQ(context.callbacks, 2);
	pthread_mutex_unlock(&context.mutex);
	ATF_REQUIRE_EQ(pthread_cond_destroy(&context.condition), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&context.mutex), 0);
}

ATF_TC_WITHOUT_HEAD(destroy_drains_snapshot_dma_validation);
ATF_TC_BODY(destroy_drains_snapshot_dma_validation, tc)
{
	struct snapshot_lifetime_context *context;
	struct virtio_gpu_2d_limits limits;
	struct virtio_gpu_2d_ops ops;
	pthread_condattr_t attr;
	pthread_t validation_thread, destroy_thread;
	uint8_t *snapshot;

	context = calloc(1, sizeof(*context) + 164);
	ATF_REQUIRE(context != NULL);
	snapshot = (uint8_t *)(context + 1);
	/* Independent GPU1 version-3 wire image: one 1x1 2D resource. */
	le32enc(snapshot, 0x44324756U);
	le16enc(snapshot + 4, 3);
	le16enc(snapshot + 6, 72);
	le32enc(snapshot + 8, 1);
	le64enc(snapshot + 16, 4);
	le32enc(snapshot + 72, 1);
	le32enc(snapshot + 76, 1);
	le32enc(snapshot + 80, 1);
	le32enc(snapshot + 84, 1);
	le32enc(snapshot + 88, 1);
	le32enc(snapshot + 92, 4);
	le32enc(snapshot + 96, 1);
	le64enc(snapshot + 104, 4);
	le64enc(snapshot + 112, 4);
	snapshot[144] = 0x12;
	snapshot[145] = 0x34;
	snapshot[146] = 0x56;
	snapshot[147] = 0x78;
	le32enc(snapshot + 156, 4);
	ATF_REQUIRE_EQ(pthread_mutex_init(&context->mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_condattr_init(&attr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_setclock(&attr, CLOCK_MONOTONIC), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&context->condition, &attr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_destroy(&attr), 0);
	limits = (struct virtio_gpu_2d_limits) {
		.max_resources = 1,
		.max_host_bytes = 4,
		.scanout_width = 1,
		.scanout_height = 1,
	};
	ops = (struct virtio_gpu_2d_ops) {
		.dma_validate = snapshot_dma_validate,
		.dma_read = dma_read,
		.display_reset = snapshot_display_reset,
		.arg = context,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_create(&limits, &ops,
	    &context->state), 0);
	ATF_REQUIRE_EQ(pthread_create(&validation_thread, NULL,
	    snapshot_validate_thread, context), 0);
	snapshot_wait(context, &context->validation_entered);
	ATF_REQUIRE_EQ(pthread_create(&destroy_thread, NULL,
	    snapshot_destroy_thread, context), 0);
	snapshot_wait(context, &context->destroy_reset_seen);
	pthread_mutex_lock(&context->mutex);
	ATF_CHECK(!context->destroy_finished);
	context->validation_release = true;
	(void)pthread_cond_broadcast(&context->condition);
	pthread_mutex_unlock(&context->mutex);
	ATF_REQUIRE_EQ(pthread_join(validation_thread, NULL), 0);
	ATF_REQUIRE_EQ(pthread_join(destroy_thread, NULL), 0);
	ATF_CHECK_EQ(context->validation_result, 0);
	pthread_mutex_lock(&context->mutex);
	ATF_CHECK(context->destroy_finished);
	pthread_mutex_unlock(&context->mutex);
	ATF_REQUIRE_EQ(pthread_cond_destroy(&context->condition), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&context->mutex), 0);
	free(context);
}

ATF_TC_WITHOUT_HEAD(destroy_rejects_reentrant_snapshot_once);
ATF_TC_BODY(destroy_rejects_reentrant_snapshot_once, tc)
{
	struct destroy_snapshot_context context;
	struct virtio_gpu_2d_limits limits;
	struct virtio_gpu_2d_ops ops;

	memset(&context, 0, sizeof(context));
	context.fixture.fail_at = UINT64_MAX;
	context.snapshot_result = -1;
	limits = (struct virtio_gpu_2d_limits) {
		.max_resources = 1,
		.max_host_bytes = 4096,
		.scanout_width = 1,
		.scanout_height = 1,
	};
	ops = (struct virtio_gpu_2d_ops) {
		.dma_validate = dma_validate,
		.dma_read = dma_read,
		.display_reset = destroy_snapshot_display_reset,
		.arg = &context,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_create(&limits, &ops,
	    &context.state), 0);
	context.fixture.state = context.state;

	/*
	 * destroy marks the state before invoking display_reset.  A callback
	 * which re-enters snapshot validation must observe ECANCELED and release
	 * exactly the one mutex acquisition made by the decoder.
	 */
	virtio_gpu_2d_state_destroy(context.state);
	ATF_CHECK_EQ(context.callbacks, 1);
	ATF_CHECK_EQ(context.snapshot_result, ECANCELED);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, state_requires_complete_dma_contract);
	ATF_TP_ADD_TC(tp, resource_limits_and_reset);
	ATF_TP_ADD_TC(tp, zero_resource_id_never_matches_empty_slot);
	ATF_TP_ADD_TC(tp, blob_guest_ownership_and_map_rejection);
	ATF_TP_ADD_TC(tp, blob_scanout_and_snapshot);
	ATF_TP_ADD_TC(tp, blob_cursor_and_snapshot);
	ATF_TP_ADD_TC(tp, obsolete_snapshot_versions_rejected);
	ATF_TP_ADD_TC(tp, backing_transfer_is_atomic);
	ATF_TP_ADD_TC(tp, backing_transaction_and_detach);
	ATF_TP_ADD_TC(tp, scanout_flush_and_unref);
	ATF_TP_ADD_TC(tp, scanout_respects_configured_extent);
	ATF_TP_ADD_TC(tp, cursor_validation_and_callbacks);
	ATF_TP_ADD_TC(tp, scanout_copy_is_atomic_and_cropped);
	ATF_TP_ADD_TC(tp, scanout_requires_nonempty_rectangle);
	ATF_TP_ADD_TC(tp, portable_snapshot_transaction);
	ATF_TP_ADD_TC(tp, empty_restore_clears_destination_presentation);
	ATF_TP_ADD_TC(tp, snapshot_output_alias_is_rejected);
	ATF_TP_ADD_TC(tp, destroy_drains_external_presentation_callbacks);
	ATF_TP_ADD_TC(tp, destroy_drains_snapshot_dma_validation);
	ATF_TP_ADD_TC(tp, destroy_rejects_reentrant_snapshot_once);
	return (atf_no_error());
}
