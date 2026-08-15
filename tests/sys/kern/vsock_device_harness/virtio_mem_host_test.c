/*
 * Independent VirtIO 1.4 section 5.15 memory-device state tests.
 */
#include <sys/endian.h>
#include <sys/param.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_mem_host.c"

#define	DOC_REQ_PLUG		0U
#define	DOC_REQ_UNPLUG		1U
#define	DOC_REQ_UNPLUG_ALL	2U
#define	DOC_REQ_STATE		3U
#define	DOC_RESP_ACK		0U
#define	DOC_RESP_NACK		1U
#define	DOC_RESP_BUSY		2U
#define	DOC_RESP_ERROR		3U
#define	DOC_STATE_PLUGGED	0U
#define	DOC_STATE_UNPLUGGED	1U
#define	DOC_STATE_MIXED		2U
#define	DOC_BLOCK		UINT64_C(0x200000)
#define	DOC_BASE		UINT64_C(0x10000000)

struct memory_model {
	bool plugged[8];
	bool touched[8];
	unsigned int calls;
	int fail;
	unsigned int fail_call;
	unsigned int fail_call2;
	unsigned int config_changes;
	struct virtio_mem_host *host;
	/* Used only by the destruction-versus-platform-callback regression. */
	pthread_mutex_t callback_mutex;
	pthread_cond_t callback_cond;
	bool block_set_range;
	bool set_range_entered;
	bool release_set_range;
	bool destroy_started;
	bool destroy_complete;
	uint8_t *mutate_snapshot;
	size_t mutate_offset;
	uint8_t mutate_xor;
	unsigned int mutate_call;
};

struct memory_request_context {
	struct virtio_mem_host *host;
	uint8_t request[DOC_REQ_STATE + 21];
	uint8_t response[10];
	size_t used;
	int error;
};

static void *
memory_request_thread(void *argument)
{
	struct memory_request_context *context;

	context = argument;
	context->error = virtio_mem_host_request(context->host, context->request,
	    sizeof(context->request), context->response, sizeof(context->response),
	    &context->used);
	return (NULL);
}

static void *
memory_destroy_thread(void *argument)
{
	struct memory_model *model;
	struct virtio_mem_host *host;

	model = argument;
	pthread_mutex_lock(&model->callback_mutex);
	model->destroy_started = true;
	pthread_cond_broadcast(&model->callback_cond);
	pthread_mutex_unlock(&model->callback_mutex);
	host = model->host;
	virtio_mem_host_destroy(host);
	pthread_mutex_lock(&model->callback_mutex);
	model->destroy_complete = true;
	pthread_cond_broadcast(&model->callback_cond);
	pthread_mutex_unlock(&model->callback_mutex);
	return (NULL);
}

struct restore_validate_context {
	struct virtio_mem_host *host;
	const void *snapshot;
	size_t snapshot_size;
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	bool started;
	bool completed;
	int error;
};

static void *
restore_validate_thread(void *argument)
{
	struct restore_validate_context *context;

	context = argument;
	pthread_mutex_lock(&context->mutex);
	context->started = true;
	pthread_cond_broadcast(&context->condition);
	pthread_mutex_unlock(&context->mutex);
	context->error = virtio_mem_host_restore_validate(context->host,
	    context->snapshot, context->snapshot_size);
	pthread_mutex_lock(&context->mutex);
	context->completed = true;
	pthread_cond_broadcast(&context->condition);
	pthread_mutex_unlock(&context->mutex);
	return (NULL);
}

static int
model_set_range(void *arg, uint64_t address, uint64_t length, bool plug)
{
	struct memory_model *model;
	uint64_t first, count;

	model = arg;
	model->calls++;
	if (model->mutate_snapshot != NULL &&
	    model->calls == model->mutate_call)
		model->mutate_snapshot[model->mutate_offset] ^=
		    model->mutate_xor;
	if (model->block_set_range) {
		pthread_mutex_lock(&model->callback_mutex);
		model->set_range_entered = true;
		pthread_cond_broadcast(&model->callback_cond);
		while (!model->release_set_range)
			ATF_REQUIRE_EQ(pthread_cond_wait(&model->callback_cond,
			    &model->callback_mutex), 0);
		pthread_mutex_unlock(&model->callback_mutex);
	}
	if (model->fail != 0 &&
	    (model->fail_call == 0 || model->calls == model->fail_call ||
	    model->calls == model->fail_call2))
		return (model->fail);
	ATF_REQUIRE(address >= DOC_BASE);
	ATF_REQUIRE_EQ((address - DOC_BASE) % DOC_BLOCK, 0);
	ATF_REQUIRE_EQ(length % DOC_BLOCK, 0);
	first = (address - DOC_BASE) / DOC_BLOCK;
	count = length / DOC_BLOCK;
	ATF_REQUIRE(first + count <= nitems(model->plugged));
	for (uint64_t i = 0; i < count; i++) {
		model->touched[first + i] = true;
		model->plugged[first + i] = plug;
	}
	return (0);
}

static void
model_config_changed(void *arg,
    const struct virtio_mem_host_config *config)
{
	struct memory_model *model;

	model = arg;
	model->config_changes++;
	/*
	 * The host passes an immutable snapshot so a callback does not have to
	 * re-enter the model while destruction is draining the outer operation.
	 */
	ATF_REQUIRE(config != NULL);
	ATF_REQUIRE(config->requested_size <= config->usable_region_size);
}

static struct virtio_mem_host *
new_host(struct memory_model *model, uint64_t requested)
{
	const struct virtio_mem_host_limits limits = {
		.block_size = DOC_BLOCK,
		.address = DOC_BASE,
		.region_size = DOC_BLOCK * 8,
		.usable_region_size = DOC_BLOCK * 8,
		.requested_size = requested,
		.max_blocks = 8,
	};
	const struct virtio_mem_host_ops ops = {
		.set_range = model_set_range,
		.config_changed = model_config_changed,
		.arg = model,
	};
	struct virtio_mem_host *host;

	ATF_REQUIRE_EQ(virtio_mem_host_create(&limits, &ops, &host), 0);
	model->host = host;
	return (host);
}

static struct virtio_mem_host *
new_geometry_host(struct memory_model *model, uint32_t blocks,
    uint64_t requested)
{
	struct virtio_mem_host_limits limits;
	const struct virtio_mem_host_ops ops = {
		.set_range = model_set_range,
		.config_changed = model_config_changed,
		.arg = model,
	};
	struct virtio_mem_host *host;

	memset(&limits, 0, sizeof(limits));
	limits.block_size = DOC_BLOCK;
	limits.address = DOC_BASE;
	limits.region_size = (uint64_t)blocks * DOC_BLOCK;
	limits.usable_region_size = limits.region_size;
	limits.requested_size = requested;
	limits.max_blocks = blocks;
	ATF_REQUIRE_EQ(virtio_mem_host_create(&limits, &ops, &host), 0);
	model->host = host;
	return (host);
}

static void
make_request(uint8_t request[24], uint16_t type, uint64_t address,
    uint16_t blocks)
{

	memset(request, 0, 24);
	le16enc(request, type);
	le64enc(request + 8, address);
	le16enc(request + 16, blocks);
}

static uint16_t
run_request(struct virtio_mem_host *host, uint8_t request[24],
    uint16_t *state)
{
	uint8_t response[10];
	size_t used;

	memset(response, 0xa5, sizeof(response));
	ATF_REQUIRE_EQ(virtio_mem_host_request(host, request, 24, response,
	    sizeof(response), &used), 0);
	ATF_REQUIRE_EQ(used, sizeof(response));
	for (size_t i = 2; i < 8; i++)
		ATF_CHECK_EQ(response[i], 0);
	if (state != NULL)
		*state = le16dec(response + 8);
	return (le16dec(response));
}

static struct virtio_mem_host *
new_seeded_host(struct memory_model *model, unsigned int bitmap)
{
	struct virtio_mem_host *host;
	uint8_t request[24];

	host = new_host(model, DOC_BLOCK * 8);
	for (unsigned int block = 0; block < 4; block++) {
		if ((bitmap & (1U << block)) == 0)
			continue;
		make_request(request, DOC_REQ_PLUG,
		    DOC_BASE + (uint64_t)block * DOC_BLOCK, 1);
		ATF_REQUIRE_EQ(run_request(host, request, NULL), DOC_RESP_ACK);
	}
	return (host);
}

ATF_TC_WITHOUT_HEAD(exhaustive_small_region_requests);
ATF_TC_BODY(exhaustive_small_region_requests, tc)
{
	struct memory_model model;
	struct virtio_mem_host_config config;
	struct virtio_mem_host *host;
	uint8_t request[24];
	uint16_t expected_state, state;
	unsigned int after, before, count, first, mask, range_mask;
	bool all_desired, plug;

	/*
	 * Exercise every state of a four-block region and every nonempty
	 * contiguous subrange.  Constants and expected transitions come from
	 * the independent section 5.15 model above rather than implementation
	 * headers.
	 */
	for (mask = 0; mask < 16; mask++) {
		memset(&model, 0, sizeof(model));
		host = new_seeded_host(&model, mask);
		for (first = 0; first < 4; first++) {
			for (count = 1; first + count <= 4; count++) {
				range_mask = ((1U << count) - 1) << first;
				if ((mask & range_mask) == 0)
					expected_state = DOC_STATE_UNPLUGGED;
				else if ((mask & range_mask) == range_mask)
					expected_state = DOC_STATE_PLUGGED;
				else
					expected_state = DOC_STATE_MIXED;
				make_request(request, DOC_REQ_STATE,
				    DOC_BASE + (uint64_t)first * DOC_BLOCK,
				    count);
				ATF_CHECK_EQ(run_request(host, request,
				    &state), DOC_RESP_ACK);
				ATF_CHECK_EQ(state, expected_state);
			}
		}
		virtio_mem_host_destroy(host);
	}

	/*
	 * Repeat from a fresh model for each state-changing request.  This
	 * proves both all-or-nothing rejection and exact bitmap/accounting
	 * publication for every legal four-block transition.
	 */
	for (plug = false;; plug = true) {
		for (mask = 0; mask < 16; mask++) {
			for (first = 0; first < 4; first++) {
				for (count = 1; first + count <= 4; count++) {
					memset(&model, 0, sizeof(model));
					host = new_seeded_host(&model, mask);
					range_mask =
					    ((1U << count) - 1) << first;
					all_desired = plug ?
					    (mask & range_mask) == 0 :
					    (mask & range_mask) == range_mask;
					before = __builtin_popcount(mask);
					make_request(request, plug ?
					    DOC_REQ_PLUG : DOC_REQ_UNPLUG,
					    DOC_BASE +
					    (uint64_t)first * DOC_BLOCK,
					    count);
					if (all_desired) {
						ATF_CHECK_EQ(run_request(host,
						    request, NULL),
						    DOC_RESP_ACK);
						after = plug ?
						    before + count :
						    before - count;
					} else {
						ATF_CHECK_EQ(run_request(host,
						    request, NULL),
						    DOC_RESP_ERROR);
						after = before;
					}
					virtio_mem_host_get_config(host,
					    &config);
					ATF_CHECK_EQ(config.plugged_size,
					    (uint64_t)after * DOC_BLOCK);
					for (unsigned int block = 0;
					    block < 4; block++) {
						bool expected;

						expected =
						    (mask &
						    (1U << block)) != 0;
						if (all_desired &&
						    block >= first &&
						    block < first + count)
							expected = plug;
						ATF_CHECK_EQ(
						    model.plugged[block],
						    expected);
					}
					virtio_mem_host_destroy(host);
				}
			}
		}
		if (plug)
			break;
	}
}

ATF_TC_WITHOUT_HEAD(config_and_request_lifecycle);
ATF_TC_BODY(config_and_request_lifecycle, tc)
{
	struct memory_model model;
	struct virtio_mem_host *host;
	uint8_t config[56], request[24];
	uint16_t state;

	memset(&model, 0, sizeof(model));
	host = new_host(&model, DOC_BLOCK * 4);
	ATF_REQUIRE_EQ(virtio_mem_host_config_encode(host, config), 0);
	ATF_CHECK_EQ(le64dec(config + 0), DOC_BLOCK);
	ATF_CHECK_EQ(le16dec(config + 8), 0);
	for (size_t i = 10; i < 16; i++)
		ATF_CHECK_EQ(config[i], 0);
	ATF_CHECK_EQ(le64dec(config + 16), DOC_BASE);
	ATF_CHECK_EQ(le64dec(config + 24), DOC_BLOCK * 8);
	ATF_CHECK_EQ(le64dec(config + 32), DOC_BLOCK * 8);
	ATF_CHECK_EQ(le64dec(config + 40), 0);
	ATF_CHECK_EQ(le64dec(config + 48), DOC_BLOCK * 4);

	make_request(request, DOC_REQ_PLUG, DOC_BASE + DOC_BLOCK, 2);
	ATF_CHECK_EQ(run_request(host, request, NULL), DOC_RESP_ACK);
	ATF_CHECK(model.plugged[1]);
	ATF_CHECK(model.plugged[2]);
	make_request(request, DOC_REQ_STATE, DOC_BASE, 4);
	ATF_CHECK_EQ(run_request(host, request, &state), DOC_RESP_ACK);
	ATF_CHECK_EQ(state, DOC_STATE_MIXED);
	make_request(request, DOC_REQ_STATE, DOC_BASE + DOC_BLOCK, 2);
	ATF_CHECK_EQ(run_request(host, request, &state), DOC_RESP_ACK);
	ATF_CHECK_EQ(state, DOC_STATE_PLUGGED);
	make_request(request, DOC_REQ_UNPLUG, DOC_BASE + DOC_BLOCK, 2);
	ATF_CHECK_EQ(run_request(host, request, NULL), DOC_RESP_ACK);
	ATF_CHECK_EQ(model.calls, 2);
	make_request(request, DOC_REQ_STATE, DOC_BASE + DOC_BLOCK, 2);
	ATF_CHECK_EQ(run_request(host, request, &state), DOC_RESP_ACK);
	ATF_CHECK_EQ(state, DOC_STATE_UNPLUGGED);
	virtio_mem_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(validation_capacity_and_busy);
ATF_TC_BODY(validation_capacity_and_busy, tc)
{
	struct memory_model model;
	struct virtio_mem_host *host;
	uint8_t request[24], response[10];
	size_t used;

	memset(&model, 0, sizeof(model));
	host = new_host(&model, DOC_BLOCK);
	make_request(request, DOC_REQ_PLUG, DOC_BASE, 2);
	ATF_CHECK_EQ(run_request(host, request, NULL), DOC_RESP_NACK);
	make_request(request, DOC_REQ_PLUG, DOC_BASE, 1);
	model.fail = EBUSY;
	ATF_CHECK_EQ(run_request(host, request, NULL), DOC_RESP_BUSY);
	/*
	 * A transient platform failure on the request path must map to BUSY so
	 * the guest retries; only a permanent error becomes ERROR.  EAGAIN and
	 * EBUSY are both transient, while any other errno is permanent.
	 */
	model.fail = EAGAIN;
	ATF_CHECK_EQ(run_request(host, request, NULL), DOC_RESP_BUSY);
	model.fail = EIO;
	ATF_CHECK_EQ(run_request(host, request, NULL), DOC_RESP_ERROR);
	model.fail = 0;
	ATF_CHECK_EQ(run_request(host, request, NULL), DOC_RESP_ACK);
	for (unsigned int i = 0; i < 1000; i++)
		ATF_CHECK_EQ(run_request(host, request, NULL), DOC_RESP_ERROR);
	make_request(request, DOC_REQ_STATE, DOC_BASE, 1);
	ATF_CHECK_EQ(run_request(host, request, NULL), DOC_RESP_ACK);
	make_request(request, DOC_REQ_UNPLUG, DOC_BASE + DOC_BLOCK * 7, 2);
	ATF_CHECK_EQ(run_request(host, request, NULL), DOC_RESP_ERROR);
	make_request(request, 0xffff, DOC_BASE, 1);
	ATF_CHECK_EQ(run_request(host, request, NULL), DOC_RESP_ERROR);
	make_request(request, DOC_REQ_STATE, DOC_BASE, 1);
	request[2] = 1;
	request[18] = 1;
	ATF_CHECK_EQ(run_request(host, request, NULL), DOC_RESP_ACK);
	ATF_CHECK_EQ(virtio_mem_host_request(host, request, 23, response,
	    sizeof(response), &used), EMSGSIZE);
	ATF_CHECK_EQ(used, 0);
	virtio_mem_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(unplug_all_reset_and_requested_size);
ATF_TC_BODY(unplug_all_reset_and_requested_size, tc)
{
	struct memory_model model;
	struct virtio_mem_host_config config;
	struct virtio_mem_host *host;
	uint8_t request[24];

	memset(&model, 0, sizeof(model));
	host = new_host(&model, DOC_BLOCK * 4);
	make_request(request, DOC_REQ_PLUG, DOC_BASE, 2);
	ATF_REQUIRE_EQ(run_request(host, request, NULL), DOC_RESP_ACK);
	ATF_REQUIRE_EQ(virtio_mem_host_set_requested_size(host,
	    DOC_BLOCK * 2), 0);
	ATF_CHECK_EQ(model.config_changes, 1);
	ATF_REQUIRE_EQ(virtio_mem_host_set_requested_size(host,
	    DOC_BLOCK * 2), 0);
	ATF_CHECK_EQ(model.config_changes, 1);
	make_request(request, DOC_REQ_UNPLUG_ALL, 0, 0);
	memset(request + 2, 0x5a, sizeof(request) - 2);
	ATF_CHECK_EQ(run_request(host, request, NULL), DOC_RESP_ACK);
	virtio_mem_host_get_config(host, &config);
	ATF_CHECK_EQ(config.plugged_size, 0);
	ATF_CHECK_EQ(config.usable_region_size, DOC_BLOCK * 2);
	ATF_CHECK_EQ(virtio_mem_host_set_requested_size(host,
	    DOC_BLOCK * 3), 0);
	ATF_CHECK_EQ(model.config_changes, 2);
	virtio_mem_host_get_config(host, &config);
	ATF_CHECK_EQ(config.usable_region_size, DOC_BLOCK * 3);
	make_request(request, DOC_REQ_PLUG, DOC_BASE, 1);
	ATF_REQUIRE_EQ(run_request(host, request, NULL), DOC_RESP_ACK);
	model.fail = EAGAIN;
	ATF_CHECK_EQ(virtio_mem_host_reset(host), 0);
	virtio_mem_host_get_config(host, &config);
	ATF_CHECK_EQ(config.plugged_size, DOC_BLOCK);
	ATF_CHECK(model.plugged[0]);
	ATF_CHECK_EQ(virtio_mem_host_system_reset(host), EBUSY);
	virtio_mem_host_get_config(host, &config);
	ATF_CHECK_EQ(config.plugged_size, DOC_BLOCK);
	model.fail = 0;
	ATF_CHECK_EQ(virtio_mem_host_system_reset(host), 0);
	ATF_CHECK(!model.plugged[0]);
	virtio_mem_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(portable_snapshot_and_repeat_restore);
ATF_TC_BODY(portable_snapshot_and_repeat_restore, tc)
{
	struct memory_model source_model, target_model;
	struct virtio_mem_host_config config;
	struct virtio_mem_host *source, *target;
	uint8_t request[24], *snapshot, *corrupt;
	size_t size;

	memset(&source_model, 0, sizeof(source_model));
	memset(&target_model, 0, sizeof(target_model));
	source = new_host(&source_model, DOC_BLOCK * 4);
	target = new_host(&target_model, DOC_BLOCK * 4);
	make_request(request, DOC_REQ_PLUG, DOC_BASE + DOC_BLOCK, 2);
	ATF_REQUIRE_EQ(run_request(source, request, NULL), DOC_RESP_ACK);
	ATF_REQUIRE_EQ(virtio_mem_host_snapshot_size(source, &size), 0);
	ATF_REQUIRE_EQ(size, 73);
	snapshot = malloc(size);
	corrupt = malloc(size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE(corrupt != NULL);
	ATF_REQUIRE_EQ(virtio_mem_host_snapshot(source, snapshot, size), 0);
	ATF_CHECK_EQ(le32dec(snapshot), UINT32_C(0x314d5456));
	ATF_CHECK_EQ(le16dec(snapshot + 4), 1);
	ATF_CHECK_EQ(le16dec(snapshot + 6), 72);
	ATF_CHECK_EQ(snapshot[72], UINT8_C(0x06));
	memcpy(corrupt, snapshot, size);
	corrupt[72] ^= 1;
	ATF_CHECK_EQ(virtio_mem_host_restore_validate(target, corrupt, size),
	    EPROTO);
	ATF_CHECK_EQ(virtio_mem_host_restore(target, corrupt, size), EPROTO);
	ATF_REQUIRE_EQ(virtio_mem_host_restore_validate(target, snapshot,
	    size), 0);
	ATF_CHECK_EQ(target_model.calls, 0);
	ATF_REQUIRE_EQ(virtio_mem_host_restore(target, snapshot, size), 0);
	ATF_CHECK_EQ(virtio_mem_host_restore(target, snapshot, size), 0);
	virtio_mem_host_get_config(target, &config);
	ATF_CHECK_EQ(config.plugged_size, DOC_BLOCK * 2);
	ATF_CHECK(target_model.plugged[1]);
	ATF_CHECK(target_model.plugged[2]);
	free(corrupt);
	free(snapshot);
	virtio_mem_host_destroy(target);
	virtio_mem_host_destroy(source);
}

ATF_TC_WITHOUT_HEAD(restore_compensation_failure_is_recoverable);
ATF_TC_BODY(restore_compensation_failure_is_recoverable, tc)
{
	struct memory_model source_model, target_model;
	struct virtio_mem_host_config config;
	struct virtio_mem_host *source, *target;
	uint8_t request[24], *snapshot, *target_buffer;
	size_t size;

	memset(&source_model, 0, sizeof(source_model));
	memset(&target_model, 0, sizeof(target_model));
	source = new_host(&source_model, DOC_BLOCK * 4);
	target = new_host(&target_model, DOC_BLOCK * 4);
	make_request(request, DOC_REQ_PLUG, DOC_BASE, 1);
	ATF_REQUIRE_EQ(run_request(source, request, NULL), DOC_RESP_ACK);
	make_request(request, DOC_REQ_PLUG, DOC_BASE + DOC_BLOCK * 2, 1);
	ATF_REQUIRE_EQ(run_request(source, request, NULL), DOC_RESP_ACK);
	ATF_REQUIRE_EQ(virtio_mem_host_snapshot_size(source, &size), 0);
	snapshot = malloc(size);
	target_buffer = malloc(size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE(target_buffer != NULL);
	ATF_REQUIRE_EQ(virtio_mem_host_snapshot(source, snapshot, size), 0);

	/*
	 * Fail the second reconstruction callback and then its compensation.
	 * Published state remains empty while a private recovery bitmap records
	 * the physical range that still needs to be removed.
	 */
	target_model.fail = EIO;
	target_model.fail_call = target_model.calls + 2;
	target_model.fail_call2 = target_model.calls + 3;
	ATF_CHECK_EQ(virtio_mem_host_restore(target, snapshot, size), EIO);
	virtio_mem_host_get_config(target, &config);
	ATF_CHECK_EQ(config.plugged_size, 0);
	ATF_CHECK(target_model.plugged[0]);
	ATF_CHECK(!target_model.plugged[2]);
	ATF_CHECK_EQ(virtio_mem_host_snapshot(target, target_buffer, size),
	    EBUSY);
	ATF_CHECK_EQ(virtio_mem_host_set_requested_size(target,
	    DOC_BLOCK * 3), EBUSY);
	ATF_CHECK_EQ(virtio_mem_host_reset(target), EBUSY);
	make_request(request, DOC_REQ_STATE, DOC_BASE, 1);
	ATF_CHECK_EQ(run_request(target, request, NULL), DOC_RESP_BUSY);

	/*
	 * A retry first removes the retained physical range, then reconstructs
	 * the complete source image and publishes it atomically.
	 */
	target_model.fail = 0;
	target_model.fail_call = 0;
	target_model.fail_call2 = 0;
	ATF_REQUIRE_EQ(virtio_mem_host_restore(target, snapshot, size), 0);
	virtio_mem_host_get_config(target, &config);
	ATF_CHECK_EQ(config.plugged_size, DOC_BLOCK * 2);
	ATF_CHECK(target_model.plugged[0]);
	ATF_CHECK(target_model.plugged[2]);

	free(target_buffer);
	free(snapshot);
	virtio_mem_host_destroy(target);
	virtio_mem_host_destroy(source);
}

ATF_TC_WITHOUT_HEAD(restore_uses_one_validated_image);
ATF_TC_BODY(restore_uses_one_validated_image, tc)
{
	struct memory_model source_model, target_model;
	struct virtio_mem_host_config config;
	struct virtio_mem_host *source, *target;
	uint8_t request[24], *snapshot;
	size_t size;

	memset(&source_model, 0, sizeof(source_model));
	memset(&target_model, 0, sizeof(target_model));
	source = new_host(&source_model, DOC_BLOCK * 4);
	target = new_host(&target_model, DOC_BLOCK * 4);
	make_request(request, DOC_REQ_PLUG, DOC_BASE, 1);
	ATF_REQUIRE_EQ(run_request(source, request, NULL), DOC_RESP_ACK);
	make_request(request, DOC_REQ_PLUG, DOC_BASE + DOC_BLOCK * 2, 1);
	ATF_REQUIRE_EQ(run_request(source, request, NULL), DOC_RESP_ACK);
	ATF_REQUIRE_EQ(virtio_mem_host_snapshot_size(source, &size), 0);
	snapshot = malloc(size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE_EQ(virtio_mem_host_snapshot(source, snapshot, size), 0);
	ATF_REQUIRE_EQ(snapshot[VTMEM_STATE_HEADER_SIZE], UINT8_C(0x05));

	/*
	 * Reconstructing the first disjoint run invokes external platform code.
	 * Alter the caller-owned bitmap there.  Restore must continue from the
	 * same private image whose digest it validated, not from these changed
	 * caller bytes.
	 */
	target_model.mutate_snapshot = snapshot;
	target_model.mutate_offset = VTMEM_STATE_HEADER_SIZE;
	target_model.mutate_xor = UINT8_C(0x04);
	target_model.mutate_call = 1;
	ATF_REQUIRE_EQ(virtio_mem_host_restore(target, snapshot, size), 0);
	ATF_CHECK(target_model.plugged[0]);
	ATF_CHECK(target_model.plugged[2]);
	virtio_mem_host_get_config(target, &config);
	ATF_CHECK_EQ(config.plugged_size, DOC_BLOCK * 2);
	ATF_CHECK_EQ(target->bitmap[0], UINT8_C(0x05));

	free(snapshot);
	virtio_mem_host_destroy(target);
	virtio_mem_host_destroy(source);
}

ATF_TC_WITHOUT_HEAD(construction_and_restore_rejection);
ATF_TC_BODY(construction_and_restore_rejection, tc)
{
	struct memory_model source_model, target_model;
	struct virtio_mem_host_limits limits;
	struct virtio_mem_host_ops ops;
	struct virtio_mem_host *source, *target;
	uint8_t request[24], *snapshot, *corrupt;
	size_t size;

	memset(&source_model, 0, sizeof(source_model));
	memset(&target_model, 0, sizeof(target_model));
	memset(&limits, 0, sizeof(limits));
	memset(&ops, 0, sizeof(ops));
	ATF_CHECK_EQ(vtmem_bitmap_size(UINT32_MAX),
	    ((size_t)UINT32_MAX + 7U) / 8U);
	ATF_CHECK_EQ(virtio_mem_host_create(NULL, &ops, &source), EINVAL);
	ATF_CHECK_EQ(virtio_mem_host_restore(NULL, NULL, 0), EINVAL);
	ATF_CHECK_EQ(virtio_mem_host_restore_validate(NULL, NULL, 0), EINVAL);
	limits.block_size = 3;
	limits.address = DOC_BASE;
	limits.region_size = DOC_BLOCK;
	limits.usable_region_size = DOC_BLOCK;
	limits.requested_size = DOC_BLOCK;
	limits.max_blocks = 1;
	ops.set_range = model_set_range;
	ops.arg = &source_model;
	ATF_CHECK_EQ(virtio_mem_host_create(&limits, &ops, &source), EINVAL);
	limits.block_size = DOC_BLOCK;
	limits.address = UINT64_MAX - DOC_BLOCK + 2;
	ATF_CHECK_EQ(virtio_mem_host_create(&limits, &ops, &source), EINVAL);
	limits.address = DOC_BASE;
	limits.region_size = DOC_BLOCK * 2;
	ATF_CHECK_EQ(virtio_mem_host_create(&limits, &ops, &source), E2BIG);
	limits.max_blocks = 2;
	limits.usable_region_size = DOC_BLOCK;
	limits.requested_size = DOC_BLOCK * 2;
	ATF_CHECK_EQ(virtio_mem_host_create(&limits, &ops, &source), EINVAL);

	source = new_host(&source_model, DOC_BLOCK * 4);
	target = new_host(&target_model, DOC_BLOCK * 4);
	make_request(request, DOC_REQ_PLUG, DOC_BASE, 1);
	ATF_REQUIRE_EQ(run_request(source, request, NULL), DOC_RESP_ACK);
	make_request(request, DOC_REQ_PLUG, DOC_BASE + DOC_BLOCK * 2, 1);
	ATF_REQUIRE_EQ(run_request(source, request, NULL), DOC_RESP_ACK);
	ATF_REQUIRE_EQ(virtio_mem_host_snapshot_size(source, &size), 0);
	snapshot = malloc(size);
	corrupt = malloc(size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE(corrupt != NULL);
	ATF_REQUIRE_EQ(virtio_mem_host_snapshot(source, snapshot, size), 0);
	ATF_CHECK_EQ(virtio_mem_host_restore(target, snapshot, size - 1),
	    EPROTO);
	memcpy(corrupt, snapshot, size);
	le32enc(corrupt + 60, 3);
	le64enc(corrupt + 64, 0);
	le64enc(corrupt + 64, vtmem_digest(corrupt, size));
	ATF_CHECK_EQ(virtio_mem_host_restore(target, corrupt, size), EINVAL);
	memcpy(corrupt, snapshot, size);
	le64enc(corrupt + 40, DOC_BLOCK * 2);
	le64enc(corrupt + 48, DOC_BLOCK * 2);
	le64enc(corrupt + 64, 0);
	le64enc(corrupt + 64, vtmem_digest(corrupt, size));
	ATF_CHECK_EQ(virtio_mem_host_restore(target, corrupt, size), EINVAL);

	target_model.fail = EIO;
	target_model.fail_call = target_model.calls + 2;
	ATF_CHECK_EQ(virtio_mem_host_restore(target, snapshot, size), EIO);
	for (size_t i = 0; i < nitems(target_model.plugged); i++)
		ATF_CHECK(!target_model.plugged[i]);
	ATF_CHECK(target_model.touched[0]);
	for (size_t i = 1; i < nitems(target_model.touched); i++)
		ATF_CHECK(!target_model.touched[i]);
	target_model.fail = 0;
	ATF_REQUIRE_EQ(virtio_mem_host_restore(target, snapshot, size), 0);
	make_request(request, DOC_REQ_UNPLUG, DOC_BASE, 1);
	ATF_REQUIRE_EQ(run_request(target, request, NULL), DOC_RESP_ACK);
	ATF_CHECK_EQ(virtio_mem_host_restore(target, snapshot, size), EBUSY);

	free(corrupt);
	free(snapshot);
	virtio_mem_host_destroy(target);
	virtio_mem_host_destroy(source);
}

ATF_TC_WITHOUT_HEAD(snapshot_output_alias_is_rejected);
ATF_TC_BODY(snapshot_output_alias_is_rejected, tc)
{
	struct memory_model model;
	struct virtio_mem_host *host;
	uint8_t *snapshot;
	size_t size;

	memset(&model, 0, sizeof(model));
	host = new_host(&model, DOC_BLOCK * 4);
	ATF_REQUIRE_EQ(virtio_mem_host_snapshot_size(host, &size), 0);
	ATF_CHECK_EQ(virtio_mem_host_snapshot(host, host, size), EINVAL);
	ATF_CHECK_EQ(virtio_mem_host_snapshot(host, host->bitmap, size),
	    EINVAL);
	ATF_CHECK_EQ(virtio_mem_host_restore_validate(host, host, size),
	    EINVAL);
	ATF_CHECK_EQ(virtio_mem_host_restore(host, host->bitmap, size),
	    EINVAL);
	ATF_CHECK_EQ(host->plugged_blocks, 0);
	ATF_CHECK_EQ(host->bitmap[0], 0);
	snapshot = malloc(size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_CHECK_EQ(virtio_mem_host_snapshot(host, snapshot, size), 0);
	free(snapshot);
	virtio_mem_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(restore_rejects_changed_destination_geometry);
ATF_TC_BODY(restore_rejects_changed_destination_geometry, tc)
{
	struct memory_model source_model, larger_model, smaller_model;
	struct virtio_mem_host *source, *larger, *smaller;
	uint8_t *snapshot;
	size_t size;

	memset(&source_model, 0, sizeof(source_model));
	memset(&larger_model, 0, sizeof(larger_model));
	memset(&smaller_model, 0, sizeof(smaller_model));
	source = new_geometry_host(&source_model, 8, DOC_BLOCK * 4);
	larger = new_geometry_host(&larger_model, 16, DOC_BLOCK * 4);
	smaller = new_geometry_host(&smaller_model, 4, DOC_BLOCK * 4);
	ATF_REQUIRE_EQ(virtio_mem_host_snapshot_size(source, &size), 0);
	snapshot = malloc(size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE_EQ(virtio_mem_host_snapshot(source, snapshot, size), 0);

	/*
	 * addr, block_size, and region_size are immutable guest-visible
	 * configuration.  A larger destination is not automatically compatible:
	 * exposing its extra capacity after restore would change the device ABI.
	 * A smaller destination cannot represent the source bitmap either.  Both
	 * failures must occur before any platform range is reconstructed.
	 */
	ATF_CHECK_EQ(virtio_mem_host_restore_validate(larger, snapshot, size),
	    EPROTO);
	ATF_CHECK_EQ(virtio_mem_host_restore(larger, snapshot, size), EPROTO);
	ATF_CHECK_EQ(virtio_mem_host_restore_validate(smaller, snapshot, size),
	    EPROTO);
	ATF_CHECK_EQ(virtio_mem_host_restore(smaller, snapshot, size), EPROTO);
	ATF_CHECK_EQ(larger_model.calls, 0U);
	ATF_CHECK_EQ(smaller_model.calls, 0U);

	free(snapshot);
	virtio_mem_host_destroy(smaller);
	virtio_mem_host_destroy(larger);
	virtio_mem_host_destroy(source);
}

ATF_TC_WITHOUT_HEAD(public_api_aliases_are_rejected);
ATF_TC_BODY(public_api_aliases_are_rejected, tc)
{
	struct memory_model model;
	struct virtio_mem_host_config config;
	struct virtio_mem_host *host;
	uint8_t request[24], response[10];
	size_t used;

	memset(&model, 0, sizeof(model));
	host = new_host(&model, DOC_BLOCK * 4);
	make_request(request, DOC_REQ_PLUG, DOC_BASE, 1);
	memset(response, 0xa5, sizeof(response));

	ATF_CHECK_EQ(virtio_mem_host_config_encode(host,
	    (uint8_t *)(void *)host), EINVAL);
	virtio_mem_host_get_config(host,
	    (struct virtio_mem_host_config *)(void *)host);
	ATF_CHECK_EQ(virtio_mem_host_snapshot_size(host,
	    (size_t *)(void *)host), EINVAL);

	used = 91;
	ATF_CHECK_EQ(virtio_mem_host_request(host, request, sizeof(request),
	    host, sizeof(response), &used), EINVAL);
	ATF_CHECK_EQ(used, 91);
	ATF_CHECK_EQ(model.calls, 0U);
	ATF_CHECK_EQ(virtio_mem_host_request(host, request, sizeof(request),
	    response, sizeof(response), (size_t *)(void *)request), EINVAL);
	ATF_CHECK_EQ(model.calls, 0U);
	ATF_CHECK_EQ(virtio_mem_host_request(host, request, sizeof(request),
	    response, sizeof(response), (size_t *)(void *)response), EINVAL);
	ATF_CHECK_EQ(model.calls, 0U);
	ATF_CHECK_EQ(virtio_mem_host_request(host, request, sizeof(request),
	    request, sizeof(response), &used), EINVAL);
	ATF_CHECK_EQ(used, 91);
	ATF_CHECK_EQ(model.calls, 0U);

	ATF_REQUIRE_EQ(virtio_mem_host_request(host, request, sizeof(request),
	    response, sizeof(response), &used), 0);
	ATF_CHECK_EQ(used, sizeof(response));
	ATF_CHECK_EQ(le16dec(response), DOC_RESP_ACK);
	ATF_CHECK_EQ(model.calls, 1U);
	virtio_mem_host_get_config(host, &config);
	ATF_CHECK_EQ(config.plugged_size, DOC_BLOCK);
	virtio_mem_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(restore_validation_serializes_with_mutation);
ATF_TC_BODY(restore_validation_serializes_with_mutation, tc)
{
	struct memory_model source_model, target_model;
	struct restore_validate_context context;
	struct virtio_mem_host *source, *target;
	pthread_t thread;
	uint8_t *snapshot;
	size_t size;

	memset(&source_model, 0, sizeof(source_model));
	memset(&target_model, 0, sizeof(target_model));
	source = new_host(&source_model, DOC_BLOCK * 4);
	target = new_host(&target_model, DOC_BLOCK * 4);
	ATF_REQUIRE_EQ(virtio_mem_host_snapshot_size(source, &size), 0);
	snapshot = malloc(size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE_EQ(virtio_mem_host_snapshot(source, snapshot, size), 0);

	/*
	 * Restore validation reads mutable destination geometry.  Holding the
	 * operation lock models an in-flight request which can update it: the
	 * public validator must wait rather than validate a stale view.
	 */
	memset(&context, 0, sizeof(context));
	context.host = target;
	context.snapshot = snapshot;
	context.snapshot_size = size;
	ATF_REQUIRE_EQ(pthread_mutex_init(&context.mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&context.condition, NULL), 0);
	pthread_mutex_lock(&target->operation_mutex);
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL, restore_validate_thread,
	    &context), 0);
	pthread_mutex_lock(&context.mutex);
	while (!context.started)
		ATF_REQUIRE_EQ(pthread_cond_wait(&context.condition,
		    &context.mutex), 0);
	ATF_CHECK(!context.completed);
	pthread_mutex_unlock(&context.mutex);
	pthread_mutex_unlock(&target->operation_mutex);
	ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
	ATF_CHECK_EQ(context.error, 0);
	pthread_cond_destroy(&context.condition);
	pthread_mutex_destroy(&context.mutex);
	free(snapshot);
	virtio_mem_host_destroy(target);
	virtio_mem_host_destroy(source);
}

ATF_TC_WITHOUT_HEAD(destroy_drains_platform_callback);
ATF_TC_BODY(destroy_drains_platform_callback, tc)
{
	struct memory_model model;
	struct memory_request_context request;
	struct virtio_mem_host *host;
	pthread_t destroy_thread, request_thread;

	memset(&model, 0, sizeof(model));
	ATF_REQUIRE_EQ(pthread_mutex_init(&model.callback_mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&model.callback_cond, NULL), 0);
	model.block_set_range = true;
	host = new_host(&model, DOC_BLOCK);
	memset(&request, 0, sizeof(request));
	request.host = host;
	make_request(request.request, DOC_REQ_PLUG, DOC_BASE, 1);
	ATF_REQUIRE_EQ(pthread_create(&request_thread, NULL, memory_request_thread,
	    &request), 0);
	pthread_mutex_lock(&model.callback_mutex);
	while (!model.set_range_entered)
		ATF_REQUIRE_EQ(pthread_cond_wait(&model.callback_cond,
		    &model.callback_mutex), 0);
	ATF_REQUIRE_EQ(pthread_create(&destroy_thread, NULL, memory_destroy_thread,
	    &model), 0);
	while (!model.destroy_started)
		ATF_REQUIRE_EQ(pthread_cond_wait(&model.callback_cond,
		    &model.callback_mutex), 0);
	/* The blocked callback retains the model and its callback argument. */
	ATF_CHECK(!model.destroy_complete);
	model.release_set_range = true;
	pthread_cond_broadcast(&model.callback_cond);
	pthread_mutex_unlock(&model.callback_mutex);
	ATF_REQUIRE_EQ(pthread_join(request_thread, NULL), 0);
	ATF_CHECK_EQ(request.error, 0);
	ATF_CHECK_EQ(request.used, sizeof(request.response));
	ATF_CHECK_EQ(le16dec(request.response), DOC_RESP_ACK);
	ATF_REQUIRE_EQ(pthread_join(destroy_thread, NULL), 0);
	ATF_CHECK(model.destroy_complete);
	pthread_cond_destroy(&model.callback_cond);
	pthread_mutex_destroy(&model.callback_mutex);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, exhaustive_small_region_requests);
	ATF_TP_ADD_TC(tp, config_and_request_lifecycle);
	ATF_TP_ADD_TC(tp, validation_capacity_and_busy);
	ATF_TP_ADD_TC(tp, unplug_all_reset_and_requested_size);
	ATF_TP_ADD_TC(tp, portable_snapshot_and_repeat_restore);
	ATF_TP_ADD_TC(tp, construction_and_restore_rejection);
	ATF_TP_ADD_TC(tp, restore_compensation_failure_is_recoverable);
	ATF_TP_ADD_TC(tp, restore_uses_one_validated_image);
	ATF_TP_ADD_TC(tp, snapshot_output_alias_is_rejected);
	ATF_TP_ADD_TC(tp, restore_rejects_changed_destination_geometry);
	ATF_TP_ADD_TC(tp, public_api_aliases_are_rejected);
	ATF_TP_ADD_TC(tp, restore_validation_serializes_with_mutation);
	ATF_TP_ADD_TC(tp, destroy_drains_platform_callback);
	return (atf_no_error());
}
