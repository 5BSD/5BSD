/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#include "virtio_device_parts.c"
#include "virtio_device_parts_handler.c"
#include "virtio_admin.c"
#include "virtio_admin_capability.c"
#include "virtio_admin_resource.c"
#include "virtio_admin_device_parts.c"
#include "virtio_1_4_spec.h"

struct race_context {
	pthread_barrier_t barrier;
	struct virtio_admin_device_parts *parts;
	int create_error;
	int reduce_error;
};

struct composed_context {
	bool stopped;
	unsigned int commits;
	unsigned int discards;
};

static bool
composed_member(void *argument, uint64_t member)
{

	(void)argument;
	return (member == 7 || member == 8);
}

static int
composed_admin_process(struct virtio_admin_owner *owner, uint16_t opcode,
    uint64_t member, const void *specific, size_t specific_size, void *output,
    size_t output_size, size_t *written)
{
	uint8_t input[128];

	ATF_REQUIRE(BHYVE_VIRTIO_ADMIN_HEADER_SIZE + specific_size <=
	    sizeof(input));
	memset(input, 0, sizeof(input));
	le16enc(input, opcode);
	le16enc(input + 2, BHYVE_VIRTIO_ADMIN_GROUP_SRIOV);
	le64enc(input + 16, member);
	if (specific_size != 0)
		memcpy(input + BHYVE_VIRTIO_ADMIN_HEADER_SIZE, specific,
		    specific_size);
	return (virtio_admin_process_group(owner,
	    BHYVE_VIRTIO_ADMIN_GROUP_SRIOV, composed_member, NULL, input,
	    BHYVE_VIRTIO_ADMIN_HEADER_SIZE + specific_size, output,
	    output_size, written));
}

static int
composed_schema(void *argument, uint64_t member, void *output,
    size_t capacity, size_t *used)
{

	(void)argument;
	(void)output;
	(void)capacity;
	if (member != 7)
		return (ENXIO);
	*used = 0;
	return (0);
}

static int
composed_capture(void *argument, uint64_t member, uint8_t type,
    const void *selection, size_t selection_size, void *output,
    size_t capacity, size_t *used)
{

	(void)argument;
	(void)type;
	(void)selection;
	(void)selection_size;
	(void)output;
	(void)capacity;
	if (member != 7)
		return (ENXIO);
	*used = 0;
	return (0);
}

static int
composed_mode_get(void *argument, uint64_t member, bool *stopped)
{
	struct composed_context *context;

	if (member != 7)
		return (ENXIO);
	context = argument;
	*stopped = context->stopped;
	return (0);
}

static int
composed_mode_set(void *argument, uint64_t member, bool stopped)
{
	struct composed_context *context;

	if (member != 7)
		return (ENXIO);
	context = argument;
	context->stopped = stopped;
	return (0);
}

static int
composed_prepare(void *argument, uint64_t member, const void *input,
    size_t length, void **transaction)
{

	(void)input;
	(void)length;
	if (member != 7)
		return (ENXIO);
	*transaction = argument;
	return (0);
}

static void
composed_commit(void *argument, uint64_t member, void *transaction)
{
	struct composed_context *context;

	(void)member;
	ATF_REQUIRE_EQ(argument, transaction);
	context = argument;
	context->commits++;
}

static void
composed_discard(void *argument, uint64_t member, void *transaction)
{
	struct composed_context *context;

	(void)member;
	ATF_REQUIRE_EQ(argument, transaction);
	context = argument;
	context->discards++;
}

static void *
create_racer(void *argument)
{
	struct race_context *context;
	uint8_t object[8] = { 0 };

	context = argument;
	(void)pthread_barrier_wait(&context->barrier);
	context->create_error = virtio_admin_device_parts_resource_create(
	    context->parts, 1, 0, object, sizeof(object));
	return (NULL);
}

static void *
reduce_racer(void *argument)
{
	struct race_context *context;
	uint8_t limits[2] = { 1, 1 };

	context = argument;
	(void)pthread_barrier_wait(&context->barrier);
	context->reduce_error = virtio_admin_device_parts_set_driver(
	    context->parts, limits, sizeof(limits));
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(capability_limits_control_objects);
ATF_TC_BODY(capability_limits_control_objects, tc)
{
	struct virtio_admin_device_parts *parts;
	uint8_t get_object[8] = { 0 }, set_object[8] = { 1 };
	uint8_t limits[2] = { 3, 2 }, current[2];
	bool driver_set;
	size_t size;
	uint32_t count, id_limit;

	ATF_REQUIRE_EQ(virtio_admin_device_parts_create(&parts, 4, 3), 0);

	/* No object exists before the driver selects nonzero limits. */
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_create(parts, 0, 0,
	    get_object, sizeof(get_object)), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_set_driver(parts,
	    limits, sizeof(limits)), 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_resource_create(parts, 2, 0,
	    get_object, sizeof(get_object)), 0);
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_create(parts, 3, 0,
	    get_object, sizeof(get_object)), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_resource_create(parts, 1, 0,
	    set_object, sizeof(set_object)), 0);
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_create(parts, 1, 0,
	    get_object, sizeof(get_object)), EEXIST);
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_create(parts, 0, 1,
	    get_object, sizeof(get_object)), EINVAL);
	set_object[7] = 1;
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_create(parts, 0, 0,
	    set_object, sizeof(set_object)), EINVAL);
	set_object[7] = 0;

	ATF_REQUIRE_EQ(virtio_admin_device_parts_resource_usage(parts, 0,
	    &count, &id_limit), 0);
	ATF_CHECK_EQ(count, 1);
	ATF_CHECK_EQ(id_limit, 3);

	/* Active object IDs make a capability reduction fail atomically. */
	limits[0] = 2;
	ATF_CHECK_EQ(virtio_admin_device_parts_set_driver(parts,
	    limits, sizeof(limits)), EBUSY);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_get_driver(parts, current,
	    sizeof(current), &size, &driver_set), 0);
	ATF_CHECK(driver_set);
	ATF_CHECK_EQ(current[0], 3);
	ATF_CHECK_EQ(current[1], 2);
	limits[0] = 3;
	limits[1] = 1;
	ATF_CHECK_EQ(virtio_admin_device_parts_set_driver(parts,
	    limits, sizeof(limits)), EBUSY);

	ATF_REQUIRE_EQ(virtio_admin_device_parts_resource_destroy(parts, 2),
	    0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_resource_destroy(parts, 1),
	    0);
	limits[0] = 2;
	limits[1] = 1;
	ATF_REQUIRE_EQ(virtio_admin_device_parts_set_driver(parts,
	    limits, sizeof(limits)), 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_resource_create(parts, 1, 0,
	    get_object, sizeof(get_object)), 0);
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_create(parts, 2, 0,
	    get_object, sizeof(get_object)), EINVAL);

	virtio_admin_device_parts_reset(parts);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_get_driver(parts, current,
	    sizeof(current), &size, &driver_set), 0);
	ATF_CHECK(!driver_set);
	ATF_CHECK_EQ(current[0], 0);
	ATF_CHECK_EQ(current[1], 0);
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_create(parts, 0, 0,
	    get_object, sizeof(get_object)), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_resource_usage(parts, 0,
	    &count, &id_limit), 0);
	ATF_CHECK_EQ(count, 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_resource_usage(parts, 1,
	    &count, &id_limit), 0);
	ATF_CHECK_EQ(count, 0);
	virtio_admin_device_parts_destroy(parts);
}

ATF_TC_WITHOUT_HEAD(zero_device_limits);
ATF_TC_BODY(zero_device_limits, tc)
{
	struct virtio_admin_device_parts *parts;
	uint8_t object[8] = { 0 }, zero[2] = { 0 };

	ATF_REQUIRE_EQ(virtio_admin_device_parts_create(&parts, 0, 0), 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_set_driver(parts, zero,
	    sizeof(zero)), 0);
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_create(parts, 0, 0,
	    object,
	    sizeof(object)), EINVAL);
	virtio_admin_device_parts_destroy(parts);
}

ATF_TC_WITHOUT_HEAD(resources_are_scoped_to_group_member);
ATF_TC_BODY(resources_are_scoped_to_group_member, tc)
{
	struct virtio_admin_device_parts *parts;
	uint8_t get_object[8] = { 0 }, set_object[8] = { 1 }, result[8];
	uint8_t limits[2] = { 4, 4 };
	uint64_t flags, member;
	size_t size;

	ATF_REQUIRE_EQ(virtio_admin_device_parts_create(&parts, 4, 4), 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_set_driver(parts, limits,
	    sizeof(limits)), 0);
	ATF_REQUIRE_EQ(
	    virtio_admin_device_parts_resource_create_for_member(parts, 1, 2,
	    0, get_object, sizeof(get_object)), 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_resource_member(parts, 2,
	    &member), 0);
	ATF_CHECK_EQ(member, 1);

	ATF_CHECK_EQ(
	    virtio_admin_device_parts_resource_query_for_member(parts, 2, 2,
	    &flags, result, sizeof(result), &size), ENXIO);
	ATF_CHECK_EQ(
	    virtio_admin_device_parts_resource_modify_for_member(parts, 2, 2,
	    set_object, sizeof(set_object)), ENXIO);
	ATF_CHECK_EQ(
	    virtio_admin_device_parts_resource_destroy_for_member(parts, 2, 2),
	    ENXIO);
	ATF_REQUIRE_EQ(
	    virtio_admin_device_parts_resource_query_for_member(parts, 1, 2,
	    &flags, result, sizeof(result), &size), 0);
	ATF_CHECK_EQ(flags, 0);
	ATF_CHECK_EQ(size, sizeof(result));
	ATF_CHECK_EQ(memcmp(result, get_object, sizeof(result)), 0);

	/*
	 * IDs are global within the device-parts resource type, not per VF or
	 * per GET/SET subtype.
	 */
	ATF_CHECK_EQ(
	    virtio_admin_device_parts_resource_create_for_member(parts, 2, 2,
	    0, set_object, sizeof(set_object)), EEXIST);
	ATF_REQUIRE_EQ(
	    virtio_admin_device_parts_resource_modify_for_member(parts, 1, 2,
	    set_object, sizeof(set_object)), 0);
	ATF_REQUIRE_EQ(
	    virtio_admin_device_parts_resource_query_for_member(parts, 1, 2,
	    &flags, result, sizeof(result), &size), 0);
	ATF_CHECK_EQ(memcmp(result, set_object, sizeof(result)), 0);
	ATF_REQUIRE_EQ(
	    virtio_admin_device_parts_resource_destroy_for_member(parts, 1, 2),
	    0);
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_member(parts, 2,
	    &member), ENXIO);

	ATF_REQUIRE_EQ(
	    virtio_admin_device_parts_resource_create_for_member(parts,
	    UINT64_MAX, 1, 0, get_object, sizeof(get_object)), 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_resource_member(parts, 1,
	    &member), 0);
	ATF_CHECK_EQ(member, UINT64_MAX);
	virtio_admin_device_parts_reset(parts);
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_member(parts, 1,
	    &member), ENXIO);
	virtio_admin_device_parts_destroy(parts);
}

ATF_TC_WITHOUT_HEAD(portable_state_is_transactional);
ATF_TC_BODY(portable_state_is_transactional, tc)
{
	struct virtio_admin_device_parts *parts, *small;
	uint8_t get_object[8] = { 0 }, set_object[8] = { 1 };
	uint8_t current[2], limits[2] = { 4, 3 };
	uint8_t *bad, *state;
	uint64_t member;
	size_t current_size, state_size;
	bool driver_set;

	ATF_REQUIRE_EQ(virtio_admin_device_parts_create(&parts, 4, 3), 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_set_driver(parts, limits,
	    sizeof(limits)), 0);
	ATF_REQUIRE_EQ(
	    virtio_admin_device_parts_resource_create_for_member(parts, 7, 3,
	    0, get_object, sizeof(get_object)), 0);
	ATF_REQUIRE_EQ(
	    virtio_admin_device_parts_resource_create_for_member(parts, 9, 2,
	    0, set_object, sizeof(set_object)), 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_snapshot_size(parts,
	    &state_size), 0);
	state = malloc(state_size);
	bad = malloc(state_size);
	ATF_REQUIRE(state != NULL);
	ATF_REQUIRE(bad != NULL);
	ATF_CHECK_EQ(virtio_admin_device_parts_snapshot(parts, parts,
	    state_size), EINVAL);
	ATF_CHECK_EQ(virtio_admin_device_parts_restore(parts, parts,
	    state_size), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_snapshot(parts, state,
	    state_size), 0);
	ATF_CHECK_EQ(le32dec(state), UINT32_C(0x31535044));
	ATF_CHECK_EQ(le16dec(state + 4), 1);
	ATF_CHECK_EQ(le16dec(state + 6), 48);
	ATF_CHECK_EQ(le32dec(state + 8), state_size);
	ATF_CHECK_EQ(le32dec(state + 20), 2);

	/* A failed parse leaves limits, resources, and ownership untouched. */
	memcpy(bad, state, state_size);
	bad[state_size - 1] ^= 1;
	ATF_CHECK_EQ(virtio_admin_device_parts_restore(parts, bad,
	    state_size), EPROTO);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_resource_member(parts, 3,
	    &member), 0);
	ATF_CHECK_EQ(member, 7);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_get_driver(parts, current,
	    sizeof(current), &current_size, &driver_set), 0);
	ATF_CHECK(driver_set);
	ATF_CHECK_EQ(current[0], 4);
	ATF_CHECK_EQ(current[1], 3);

	ATF_REQUIRE_EQ(
	    virtio_admin_device_parts_resource_destroy_for_member(parts, 7, 3),
	    0);
	ATF_REQUIRE_EQ(
	    virtio_admin_device_parts_resource_destroy_for_member(parts, 9, 2),
	    0);
	limits[0] = 1;
	limits[1] = 1;
	ATF_REQUIRE_EQ(virtio_admin_device_parts_set_driver(parts, limits,
	    sizeof(limits)), 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_restore(parts, state,
	    state_size), 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_resource_member(parts, 3,
	    &member), 0);
	ATF_CHECK_EQ(member, 7);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_resource_member(parts, 2,
	    &member), 0);
	ATF_CHECK_EQ(member, 9);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_get_driver(parts, current,
	    sizeof(current), &current_size, &driver_set), 0);
	ATF_CHECK(driver_set);
	ATF_CHECK_EQ(current[0], 4);
	ATF_CHECK_EQ(current[1], 3);

	/* Destination device policy is not overwritten by source state. */
	ATF_REQUIRE_EQ(virtio_admin_device_parts_create(&small, 3, 3), 0);
	ATF_CHECK_EQ(virtio_admin_device_parts_restore(small, state,
	    state_size), ENOTSUP);
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_member(small, 3,
	    &member), ENXIO);
	virtio_admin_device_parts_destroy(small);

	free(bad);
	free(state);
	virtio_admin_device_parts_destroy(parts);
}

ATF_TC_WITHOUT_HEAD(handler_operations_hold_resource_authority);
ATF_TC_BODY(handler_operations_hold_resource_authority, tc)
{
	struct virtio_admin_device_parts *parts;
	struct virtio_device_parts_handler *handler;
	struct composed_context context = { 0 };
	const struct virtio_device_parts_handler_config config = {
		.ops = {
			.schema = composed_schema,
			.capture = composed_capture,
			.mode_get = composed_mode_get,
			.mode_set = composed_mode_set,
			.prepare_restore = composed_prepare,
			.commit_restore = composed_commit,
			.discard_restore = composed_discard,
		},
		.argument = &context,
		.maximum_parts_size = 32,
		.maximum_part_count = 1,
	};
	uint8_t get_object[8] = { 0 }, limits[2] = { 2, 2 };
	uint8_t set_object[8] = { 1 }, output[32], state[32], features[8] = { 0 };
	size_t state_size, used;

	ATF_REQUIRE_EQ(virtio_device_parts_handler_create(&handler, &config),
	    0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_create(&parts, 2, 2), 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_bind_handler(parts, handler),
	    0);
	ATF_CHECK_EQ(virtio_admin_device_parts_bind_handler(parts, handler),
	    EBUSY);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_set_driver(parts, limits,
	    sizeof(limits)), 0);
	ATF_REQUIRE_EQ(
	    virtio_admin_device_parts_resource_create_for_member(parts, 7, 0,
	    0, get_object, sizeof(get_object)), 0);
	ATF_REQUIRE_EQ(
	    virtio_admin_device_parts_resource_create_for_member(parts, 7, 1,
	    0, set_object, sizeof(set_object)), 0);

	ATF_REQUIRE_EQ(virtio_admin_device_parts_metadata(parts, 7, 0,
	    BHYVE_VIRTIO_DEVICE_PARTS_METADATA_SIZE, output, sizeof(output),
	    &used), 0);
	ATF_CHECK_EQ(used, 8);
	ATF_CHECK_EQ(le32dec(output), 32);
	ATF_CHECK_EQ(virtio_admin_device_parts_metadata(parts, 8, 0,
	    BHYVE_VIRTIO_DEVICE_PARTS_METADATA_SIZE, output, sizeof(output),
	    &used), ENXIO);
	ATF_CHECK_EQ(virtio_admin_device_parts_metadata(parts, 7, 1,
	    BHYVE_VIRTIO_DEVICE_PARTS_METADATA_SIZE, output, sizeof(output),
	    &used), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_get(parts, 7, 0,
	    BHYVE_VIRTIO_DEVICE_PARTS_GET_ALL, NULL, 0, output,
	    sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, 0);

	state_size = 0;
	ATF_REQUIRE_EQ(virtio_device_part_append(state, sizeof(state),
	    &state_size, BHYVE_VIRTIO_DEV_PART_DEV_FEATURES,
	    BHYVE_VIRTIO_DEV_PART_F_OPTIONAL, 0, features,
	    sizeof(features)), 0);
	ATF_CHECK_EQ(virtio_admin_device_parts_set(parts, 7, 1, state,
	    state_size),
	    EBUSY);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_mode_set(parts, 7,
	    BHYVE_VIRTIO_DEVICE_MODE_STOPPED), 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_set(parts, 7, 1, state,
	    state_size), 0);
	ATF_CHECK_EQ(context.commits, 1);
	ATF_CHECK_EQ(context.discards, 1);
	ATF_CHECK_EQ(virtio_admin_device_parts_set(parts, 7, 0, state,
	    state_size), EINVAL);
	ATF_CHECK_EQ(virtio_admin_device_parts_mode_set(parts, 7, 2),
	    EINVAL);

	virtio_admin_device_parts_destroy(parts);
	virtio_device_parts_handler_destroy(handler);
}

ATF_TC_WITHOUT_HEAD(complete_command_family_uses_literal_wire_shapes);
ATF_TC_BODY(complete_command_family_uses_literal_wire_shapes, tc)
{
	struct virtio_admin_device_parts *parts;
	struct virtio_device_parts_handler *handler;
	struct virtio_admin_owner *owner;
	struct composed_context context = { 0 };
	const struct virtio_device_parts_handler_config config = {
		.ops = {
			.schema = composed_schema,
			.capture = composed_capture,
			.mode_get = composed_mode_get,
			.mode_set = composed_mode_set,
			.prepare_restore = composed_prepare,
			.commit_restore = composed_commit,
			.discard_restore = composed_discard,
		},
		.argument = &context,
		.maximum_parts_size = 32,
		.maximum_part_count = 1,
	};
	uint8_t input[64], limits[2] = { 2, 2 }, output[32], features[8] = { 0 };
	uint64_t command_mask;
	size_t part_size, written;

	ATF_REQUIRE_EQ(virtio_device_parts_handler_create(&handler, &config),
	    0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_create(&parts, 2, 2), 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_bind_handler(parts, handler),
	    0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_set_driver(parts, limits,
	    sizeof(limits)), 0);
	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_register_commands(parts,
	    owner), 0);
	ATF_CHECK_EQ(virtio_admin_device_parts_register_commands(parts, owner),
	    EALREADY);

	command_mask = 0;
	for (uint16_t opcode = BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_CREATE;
	    opcode <= BHYVE_VIRTIO_ADMIN_CMD_DEV_MODE_SET; opcode++)
		command_mask |= UINT64_C(1) << opcode;
	le64enc(input, command_mask);
	ATF_REQUIRE_EQ(composed_admin_process(owner,
	    BHYVE_VIRTIO_ADMIN_CMD_LIST_USE, 0, input, 8, output,
	    sizeof(output), &written), 0);
	ATF_CHECK_EQ(le16dec(output), 0);

	/*
	 * Missing command-specific fields read as zero.  This selects running
	 * mode and then creates type-zero, ID-zero, flags-zero GET object zero
	 * without supplying either fixed structure.
	 */
	ATF_REQUIRE_EQ(composed_admin_process(owner,
	    BHYVE_VIRTIO_ADMIN_CMD_DEV_MODE_SET, 7, NULL, 0, output,
	    sizeof(output), &written), 0);
	ATF_CHECK_EQ(le16dec(output), 0);
	ATF_CHECK(!context.stopped);
	ATF_REQUIRE_EQ(composed_admin_process(owner,
	    BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_CREATE, 7, NULL, 0,
	    output, sizeof(output), &written), 0);
	ATF_CHECK_EQ(le16dec(output), 0);

	memset(input, 0, sizeof(input));
	input[8] = BHYVE_VIRTIO_DEVICE_PARTS_METADATA_SIZE;
	ATF_REQUIRE_EQ(composed_admin_process(owner,
	    BHYVE_VIRTIO_ADMIN_CMD_DEV_PARTS_METADATA_GET, 7, input, 9,
	    output, sizeof(output), &written), 0);
	ATF_CHECK_EQ(le16dec(output), 0);
	ATF_CHECK_EQ(le32dec(output + 8), 32);
	ATF_CHECK_EQ(written, 16);
	ATF_REQUIRE_EQ(composed_admin_process(owner,
	    BHYVE_VIRTIO_ADMIN_CMD_DEV_PARTS_METADATA_GET, 7, input, 16,
	    output, 8, &written), 0);
	ATF_CHECK_EQ(le16dec(output), VIRTIO14_ADMIN_STATUS_ENOMEM);
	ATF_CHECK_EQ(written, 8);

	/* Create a SET object in the same global ID space at ID 1. */
	memset(input, 0, sizeof(input));
	le32enc(input + 4, 1);
	input[16] = BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_SET;
	ATF_REQUIRE_EQ(composed_admin_process(owner,
	    BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_CREATE, 7, input, 24,
	    output, sizeof(output), &written), 0);
	ATF_CHECK_EQ(le16dec(output), 0);

	memset(input, 0, sizeof(input));
	le32enc(input + 4, 1);
	part_size = 0;
	ATF_REQUIRE_EQ(virtio_device_part_append(input + 8,
	    sizeof(input) - 8, &part_size,
	    BHYVE_VIRTIO_DEV_PART_DEV_FEATURES,
	    BHYVE_VIRTIO_DEV_PART_F_OPTIONAL, 0, features,
	    sizeof(features)), 0);
	ATF_REQUIRE_EQ(composed_admin_process(owner,
	    BHYVE_VIRTIO_ADMIN_CMD_DEV_PARTS_SET, 7, input, 8 + part_size,
	    output, sizeof(output), &written), 0);
	ATF_CHECK_EQ(le16dec(output), VIRTIO14_ADMIN_STATUS_EBUSY);
	input[0] = BHYVE_VIRTIO_DEVICE_MODE_STOPPED;
	ATF_REQUIRE_EQ(composed_admin_process(owner,
	    BHYVE_VIRTIO_ADMIN_CMD_DEV_MODE_SET, 7, input, 1, output,
	    sizeof(output), &written), 0);
	ATF_CHECK_EQ(le16dec(output), 0);
	memset(input, 0, sizeof(input));
	le32enc(input + 4, 1);
	part_size = 0;
	ATF_REQUIRE_EQ(virtio_device_part_append(input + 8,
	    sizeof(input) - 8, &part_size,
	    BHYVE_VIRTIO_DEV_PART_DEV_FEATURES,
	    BHYVE_VIRTIO_DEV_PART_F_OPTIONAL, 0, features,
	    sizeof(features)), 0);
	ATF_REQUIRE_EQ(composed_admin_process(owner,
	    BHYVE_VIRTIO_ADMIN_CMD_DEV_PARTS_SET, 7, input, 8 + part_size,
	    output, sizeof(output), &written), 0);
	ATF_CHECK_EQ(le16dec(output), 0);
	ATF_CHECK_EQ(context.commits, 1);

	/* The object is owned by member 7, not merely by its numeric ID. */
	ATF_REQUIRE_EQ(composed_admin_process(owner,
	    BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_DESTROY, 8, input, 8,
	    output, sizeof(output), &written), 0);
	ATF_CHECK_EQ(le16dec(output), VIRTIO14_ADMIN_STATUS_ENXIO);

	virtio_admin_owner_destroy(owner);
	virtio_admin_device_parts_destroy(parts);
	virtio_device_parts_handler_destroy(handler);
}

ATF_TC_WITHOUT_HEAD(limit_reduction_and_create_are_serialized);
ATF_TC_BODY(limit_reduction_and_create_are_serialized, tc)
{
	struct virtio_admin_device_parts *parts;
	struct race_context context;
	uint8_t limits[2] = { 2, 1 };
	pthread_t creator, reducer;

	ATF_REQUIRE_EQ(virtio_admin_device_parts_create(&parts, 2, 1), 0);
	for (unsigned int iteration = 0; iteration < 1000; iteration++) {
		ATF_REQUIRE_EQ(virtio_admin_device_parts_set_driver(parts,
		    limits, sizeof(limits)), 0);
		context = (struct race_context) {
			.parts = parts,
		};
		ATF_REQUIRE_EQ(pthread_barrier_init(&context.barrier, NULL, 2),
		    0);
		ATF_REQUIRE_EQ(pthread_create(&creator, NULL, create_racer,
		    &context), 0);
		ATF_REQUIRE_EQ(pthread_create(&reducer, NULL, reduce_racer,
		    &context), 0);
		ATF_REQUIRE_EQ(pthread_join(creator, NULL), 0);
		ATF_REQUIRE_EQ(pthread_join(reducer, NULL), 0);
		ATF_REQUIRE_EQ(pthread_barrier_destroy(&context.barrier), 0);
		ATF_CHECK((context.create_error == 0 &&
		    context.reduce_error == EBUSY) ||
		    (context.create_error == EINVAL &&
		    context.reduce_error == 0));
		if (context.create_error == 0)
			ATF_REQUIRE_EQ(
			    virtio_admin_device_parts_resource_destroy(parts, 1),
			    0);
	}
	virtio_admin_device_parts_destroy(parts);
}

ATF_TC_WITHOUT_HEAD(publication_aliases_are_rejected);
ATF_TC_BODY(publication_aliases_are_rejected, tc)
{
	struct virtio_admin_device_parts *parts;
	uint8_t limits[2] = { 2, 1 }, object[8] = { 0 }, output[8];
	union {
		uint64_t align;
		uint8_t bytes[32];
	} pair;
	bool driver_set;
	uint64_t flags, member;
	uint32_t count, id_limit;
	size_t size;

	ATF_REQUIRE_EQ(virtio_admin_device_parts_create(&parts, 2, 1), 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_set_driver(parts, limits,
	    sizeof(limits)), 0);
	ATF_REQUIRE_EQ(virtio_admin_device_parts_resource_create(parts, 0, 0,
	    object, sizeof(object)), 0);
	ATF_CHECK_EQ(virtio_admin_device_parts_set_driver(parts, parts,
	    sizeof(limits)), EINVAL);
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_modify(parts, 0, parts,
	    sizeof(object)), EINVAL);
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_create(parts, 1, 0,
	    parts, sizeof(object)), EINVAL);

	flags = UINT64_MAX;
	size = SIZE_MAX;
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_query(parts, 0,
	    (uint64_t *)parts, output, sizeof(output), &size), EINVAL);
	ATF_CHECK_EQ(size, SIZE_MAX);
	memset(&pair, 0xa5, sizeof(pair));
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_query(parts, 0,
	    (uint64_t *)pair.bytes, pair.bytes, sizeof(object),
	    (size_t *)(pair.bytes + 16)), EINVAL);
	ATF_CHECK_EQ(pair.bytes[0], 0xa5);
	member = UINT64_MAX;
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_member(parts, 0,
	    (uint64_t *)parts), EINVAL);
	ATF_CHECK_EQ(member, UINT64_MAX);
	ATF_CHECK_EQ(virtio_admin_device_parts_get_driver(parts, parts, 1,
	    &size, &driver_set), EINVAL);
	count = UINT32_MAX;
	id_limit = UINT32_MAX;
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_usage(parts, 0,
	    (uint32_t *)parts, &id_limit), EINVAL);
	ATF_CHECK_EQ(id_limit, UINT32_MAX);
	ATF_CHECK_EQ(virtio_admin_device_parts_resource_usage(parts, 0,
	    &count, &count), EINVAL);
	ATF_CHECK_EQ(count, UINT32_MAX);
	ATF_CHECK_EQ(virtio_admin_device_parts_snapshot_size(parts,
	    (size_t *)parts), EINVAL);

	ATF_REQUIRE_EQ(virtio_admin_device_parts_resource_query(parts, 0,
	    &flags, output, sizeof(output), &size), 0);
	ATF_CHECK_EQ(flags, 0);
	ATF_CHECK_EQ(size, sizeof(object));
	ATF_CHECK_EQ(memcmp(output, object, sizeof(output)), 0);
	virtio_admin_device_parts_destroy(parts);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, capability_limits_control_objects);
	ATF_TP_ADD_TC(tp, zero_device_limits);
	ATF_TP_ADD_TC(tp, resources_are_scoped_to_group_member);
	ATF_TP_ADD_TC(tp, portable_state_is_transactional);
	ATF_TP_ADD_TC(tp, handler_operations_hold_resource_authority);
	ATF_TP_ADD_TC(tp, complete_command_family_uses_literal_wire_shapes);
	ATF_TP_ADD_TC(tp, limit_reduction_and_create_are_serialized);
	ATF_TP_ADD_TC(tp, publication_aliases_are_rejected);
	return (atf_no_error());
}
