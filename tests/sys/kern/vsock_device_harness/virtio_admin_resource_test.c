/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <atf-c.h>
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "virtio_admin.c"
#include "virtio_admin_resource.c"

/*
 * Independent VirtIO 1.4 CS01 oracle.  In particular, QUERY is 0x0b and
 * MODIFY is 0x0c; these values intentionally do not come from bhyve headers.
 */
#define	ADMIN_LIST_QUERY	0x0000
#define	ADMIN_LIST_USE		0x0001
#define	ADMIN_RESOURCE_CREATE	0x000a
#define	ADMIN_RESOURCE_QUERY	0x000b
#define	ADMIN_RESOURCE_MODIFY	0x000c
#define	ADMIN_RESOURCE_DESTROY	0x000d
#define	ADMIN_SELF_GROUP	0x0000
#define	ADMIN_RESULT_SIZE	8
#define	ADMIN_STATUS_BUSY	16
#define	ADMIN_QUAL_TRYAGAIN	7

static void
resource_type(struct virtio_admin_resource_manager *manager, uint16_t type,
    uint32_t limit, size_t size)
{
	const struct virtio_admin_resource_type config = {
		.type = type,
		.limit = limit,
		.minimum_size = size,
		.maximum_size = size,
		.valid_flags = 0,
	};

	ATF_REQUIRE_EQ(virtio_admin_resource_register_type(manager, &config), 0);
}

struct resource_validation_observation {
	const void *source;
	bool detached;
};

static int
resource_validate_private_candidate(void *argument, uint64_t flags,
    const void *data, size_t size, uint32_t *limit)
{
	struct resource_validation_observation *observation;
	const uint8_t *bytes;

	observation = argument;
	bytes = data;
	observation->detached = data != observation->source;
	if (flags != 0 || size != 4 || bytes == NULL || bytes[0] != 0x5a)
		return (EINVAL);
	*limit = 1;
	return (0);
}

ATF_TC_WITHOUT_HEAD(validation_uses_private_candidate);
ATF_TC_BODY(validation_uses_private_candidate, tc)
{
	struct virtio_admin_resource_manager *manager;
	struct resource_validation_observation observation;
	const struct virtio_admin_resource_type config = {
		.type = 9,
		.limit = 1,
		.minimum_size = 4,
		.maximum_size = 4,
		.valid_flags = 0,
		.validate = resource_validate_private_candidate,
		.validate_argument = &observation,
	};
	uint8_t first[4] = { 0x5a }, second[4] = { 0x5a };

	ATF_REQUIRE_EQ(virtio_admin_resource_manager_create(&manager), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_register_type(manager, &config), 0);
	observation = (struct resource_validation_observation) {
		.source = first,
	};
	ATF_REQUIRE_EQ(virtio_admin_resource_create(manager, 9, 0, 0, first,
	    sizeof(first)), 0);
	ATF_CHECK(observation.detached);
	observation = (struct resource_validation_observation) {
		.source = second,
	};
	ATF_REQUIRE_EQ(virtio_admin_resource_modify(manager, 9, 0, second,
	    sizeof(second)), 0);
	ATF_CHECK(observation.detached);
	virtio_admin_resource_manager_destroy(manager);
}

struct resource_validation_policy {
	bool busy;
};

static int
resource_validate_busy(void *argument, uint64_t flags __unused,
    const void *data __unused, size_t size __unused, uint32_t *limit __unused)
{
	const struct resource_validation_policy *policy;

	policy = argument;
	return (policy->busy ? EBUSY : 0);
}

ATF_TC_WITHOUT_HEAD(validation_errno_is_preserved);
ATF_TC_BODY(validation_errno_is_preserved, tc)
{
	struct virtio_admin_resource_manager *manager;
	struct resource_validation_policy policy = { .busy = false };
	const struct virtio_admin_resource_type config = {
		.type = 10,
		.limit = 1,
		.minimum_size = 4,
		.maximum_size = 4,
		.valid_flags = 0,
		.validate = resource_validate_busy,
		.validate_argument = &policy,
	};
	uint8_t value[4] = { 0 };

	ATF_REQUIRE_EQ(virtio_admin_resource_manager_create(&manager), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_register_type(manager, &config), 0);
	policy.busy = true;
	ATF_CHECK_EQ(virtio_admin_resource_create(manager, 10, 0, 0, value,
	    sizeof(value)), EBUSY);
	policy.busy = false;
	ATF_REQUIRE_EQ(virtio_admin_resource_create(manager, 10, 0, 0, value,
	    sizeof(value)), 0);
	policy.busy = true;
	ATF_CHECK_EQ(virtio_admin_resource_modify(manager, 10, 0, value,
	    sizeof(value)), EBUSY);
	virtio_admin_resource_manager_destroy(manager);
}

ATF_TC_WITHOUT_HEAD(id_lifecycle_and_last_value);
ATF_TC_BODY(id_lifecycle_and_last_value, tc)
{
	struct virtio_admin_resource_manager *manager;
	uint8_t first[8], second[8], output[8];
	uint64_t flags;
	size_t size;

	memset(first, 0x11, sizeof(first));
	memset(second, 0x22, sizeof(second));
	ATF_REQUIRE_EQ(virtio_admin_resource_manager_create(&manager), 0);
	resource_type(manager, 0, 2, sizeof(first));

	ATF_CHECK_EQ(virtio_admin_resource_create(manager, 0, 0, 0,
	    first, sizeof(first)), 0);
	ATF_CHECK_EQ(virtio_admin_resource_create(manager, 0, 1, 0,
	    second, sizeof(second)), 0);
	ATF_CHECK_EQ(virtio_admin_resource_create(manager, 0, 2, 0,
	    first, sizeof(first)), EINVAL);
	ATF_CHECK_EQ(virtio_admin_resource_create(manager, 0, 0, 0,
	    first, sizeof(first)), EEXIST);
	ATF_CHECK_EQ(virtio_admin_resource_create(manager, 0, 1, 1,
	    first, sizeof(first)), EINVAL);

	memset(output, 0, sizeof(output));
	ATF_REQUIRE_EQ(virtio_admin_resource_query(manager, 0, 1, &flags,
	    output, sizeof(output), &size), 0);
	ATF_CHECK_EQ(flags, 0);
	ATF_CHECK_EQ(size, sizeof(second));
	ATF_CHECK_EQ(memcmp(output, second, sizeof(output)), 0);

	ATF_REQUIRE_EQ(virtio_admin_resource_modify(manager, 0, 1, first,
	    sizeof(first)), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_query(manager, 0, 1, &flags,
	    output, 3, &size), 0);
	ATF_CHECK_EQ(size, sizeof(first));
	ATF_CHECK_EQ(memcmp(output, first, 3), 0);

	ATF_REQUIRE_EQ(virtio_admin_resource_destroy_object(manager, 0, 1), 0);
	ATF_CHECK_EQ(virtio_admin_resource_query(manager, 0, 1, &flags,
	    output, sizeof(output), &size), ENXIO);
	ATF_REQUIRE_EQ(virtio_admin_resource_create(manager, 0, 1, 0,
	    second, sizeof(second)), 0);

	virtio_admin_resource_manager_reset(manager);
	ATF_CHECK_EQ(virtio_admin_resource_query(manager, 0, 0, &flags,
	    output, sizeof(output), &size), ENXIO);
	ATF_CHECK_EQ(virtio_admin_resource_query(manager, 0, 1, &flags,
	    output, sizeof(output), &size), ENXIO);
	virtio_admin_resource_manager_destroy(manager);
}

ATF_TC_WITHOUT_HEAD(dependency_reverse_order);
ATF_TC_BODY(dependency_reverse_order, tc)
{
	struct virtio_admin_resource_manager *manager;
	uint64_t value;

	value = UINT64_C(0x1122334455667788);
	ATF_REQUIRE_EQ(virtio_admin_resource_manager_create(&manager), 0);
	resource_type(manager, 10, 2, sizeof(value));
	resource_type(manager, 11, 2, sizeof(value));
	ATF_REQUIRE_EQ(virtio_admin_resource_create(manager, 10, 0, 0,
	    &value, sizeof(value)), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_create(manager, 11, 0, 0,
	    &value, sizeof(value)), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_add_dependency(manager, 11, 0,
	    10, 0), 0);
	ATF_CHECK_EQ(virtio_admin_resource_add_dependency(manager, 11, 0,
	    10, 0), EEXIST);
	ATF_CHECK_EQ(virtio_admin_resource_destroy_object(manager, 10, 0),
	    EBUSY);
	ATF_CHECK_EQ(virtio_admin_resource_modify(manager, 10, 0, &value,
	    sizeof(value)), EBUSY);
	ATF_REQUIRE_EQ(virtio_admin_resource_destroy_object(manager, 11, 0),
	    0);
	ATF_REQUIRE_EQ(virtio_admin_resource_destroy_object(manager, 10, 0),
	    0);

	/* A dependency can only refer from a newer object to an older one. */
	ATF_REQUIRE_EQ(virtio_admin_resource_create(manager, 11, 1, 0,
	    &value, sizeof(value)), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_create(manager, 10, 1, 0,
	    &value, sizeof(value)), 0);
	ATF_CHECK_EQ(virtio_admin_resource_add_dependency(manager, 11, 1,
	    10, 1), EINVAL);
	ATF_CHECK_EQ(virtio_admin_resource_add_dependency(manager, 11, 1,
	    11, 1), EINVAL);
	virtio_admin_resource_manager_destroy(manager);
}

struct subtype_limits {
	uint32_t limit[2];
};

static int
subtype_validate(void *argument, uint64_t flags, const void *data, size_t size,
    uint32_t *limit)
{
	struct subtype_limits *limits;
	const uint8_t *bytes;

	limits = argument;
	bytes = data;
	if (flags != 0 || size != 8 || bytes == NULL || bytes[0] > 1)
		return (EINVAL);
	for (size_t i = 1; i < size; i++) {
		if (bytes[i] != 0)
			return (EINVAL);
	}
	*limit = limits->limit[bytes[0]];
	return (0);
}

static bool
subtype_match(void *argument, uint64_t flags, const void *data, size_t size)
{
	const uint8_t *bytes;

	bytes = data;
	return (flags == 0 && size == 8 && bytes != NULL &&
	    bytes[0] == (uint8_t)(uintptr_t)argument);
}

ATF_TC_WITHOUT_HEAD(capability_scoped_subtype_limits);
ATF_TC_BODY(capability_scoped_subtype_limits, tc)
{
	struct virtio_admin_resource_manager *manager;
	struct subtype_limits limits = { .limit = { 2, 3 } };
	const struct virtio_admin_resource_type config = {
		.type = 0,
		.limit = 4,
		.minimum_size = 8,
		.maximum_size = 8,
		.valid_flags = 0,
		.validate = subtype_validate,
		.validate_argument = &limits,
	};
	uint8_t get_object[8] = { 0 }, set_object[8] = { 1 }, output[8];
	uint32_t count;
	uint64_t flags;
	size_t size;

	ATF_REQUIRE_EQ(virtio_admin_resource_manager_create(&manager), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_register_type(manager, &config), 0);
	ATF_CHECK_EQ(virtio_admin_resource_create(manager, 0, 2, 0,
	    get_object, sizeof(get_object)), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_resource_create(manager, 0, 2, 0,
	    set_object, sizeof(set_object)), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_count(manager, 0, NULL, NULL,
	    &count), 0);
	ATF_CHECK_EQ(count, 1);
	ATF_REQUIRE_EQ(virtio_admin_resource_count(manager, 0, subtype_match,
	    (void *)(uintptr_t)1, &count), 0);
	ATF_CHECK_EQ(count, 1);
	ATF_REQUIRE_EQ(virtio_admin_resource_count(manager, 0, subtype_match,
	    (void *)(uintptr_t)0, &count), 0);
	ATF_CHECK_EQ(count, 0);
	ATF_CHECK_EQ(virtio_admin_resource_count(manager, 99, NULL, NULL,
	    &count), ENXIO);
	ATF_CHECK_EQ(virtio_admin_resource_modify(manager, 0, 2, get_object,
	    sizeof(get_object)), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_resource_query(manager, 0, 2, &flags,
	    output, sizeof(output), &size), 0);
	ATF_CHECK_EQ(memcmp(output, set_object, sizeof(output)), 0);
	limits.limit[1] = 2;
	ATF_CHECK_EQ(virtio_admin_resource_create(manager, 0, 2, 0,
	    set_object, sizeof(set_object)), EINVAL);
	virtio_admin_resource_manager_destroy(manager);
}

static void
admin_header(uint8_t *input, size_t length, uint16_t opcode, uint64_t member)
{

	memset(input, 0, length);
	le16enc(input, opcode);
	le16enc(input + 2, ADMIN_SELF_GROUP);
	le64enc(input + 16, member);
}

static void
object_header(uint8_t *input, uint16_t type, uint32_t id)
{

	le16enc(input, type);
	le32enc(input + 4, id);
}

static uint16_t
process(struct virtio_admin_owner *owner, uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_length, size_t *written)
{

	memset(output, 0xa5, output_length);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, input_length, output,
	    output_length, written), 0);
	return (le16dec(output));
}

ATF_TC_WITHOUT_HEAD(wire_commands_and_errors);
ATF_TC_BODY(wire_commands_and_errors, tc)
{
	struct virtio_admin_resource_manager *manager;
	struct virtio_admin_owner *owner;
	const struct virtio_admin_resource_type late_type = {
		.type = 1,
		.limit = 1,
		.minimum_size = 8,
		.maximum_size = 8,
	};
	const uint64_t commands = (UINT64_C(1) << ADMIN_LIST_QUERY) |
	    (UINT64_C(1) << ADMIN_LIST_USE) |
	    (UINT64_C(1) << ADMIN_RESOURCE_CREATE) |
	    (UINT64_C(1) << ADMIN_RESOURCE_QUERY) |
	    (UINT64_C(1) << ADMIN_RESOURCE_MODIFY) |
	    (UINT64_C(1) << ADMIN_RESOURCE_DESTROY);
	uint8_t input[56], output[24], value[8], changed[8];
	size_t written;

	memset(value, 0x33, sizeof(value));
	memset(changed, 0x44, sizeof(changed));
	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_manager_create(&manager), 0);
	resource_type(manager, 0, 2, sizeof(value));
	ATF_REQUIRE_EQ(virtio_admin_resource_register_commands(manager, owner),
	    0);
	ATF_CHECK_EQ(virtio_admin_resource_register_commands(manager, owner),
	    EALREADY);
	ATF_CHECK_EQ(virtio_admin_resource_register_type(manager, &late_type),
	    EBUSY);

	admin_header(input, 32, ADMIN_LIST_USE, 0);
	le64enc(input + 24, commands);
	ATF_CHECK_EQ(process(owner, input, 32, output, 8, &written), 0);

	/*
	 * A completely omitted command-specific CREATE structure reads as
	 * zero.  Type zero, ID zero, flags zero, and the fixed eight-byte
	 * object are therefore all valid and the object is zero-filled.
	 */
	admin_header(input, 24, ADMIN_RESOURCE_CREATE, 0);
	ATF_CHECK_EQ(process(owner, input, 24, output, 8, &written), 0);
	admin_header(input, sizeof(input), ADMIN_RESOURCE_QUERY, 0);
	memset(input + 24, 0xa5, sizeof(input) - 24);
	input[24] = 0;
	input[25] = 0;
	input[26] = 0;
	input[27] = 0;
	le32enc(input + 28, 0);
	ATF_CHECK_EQ(process(owner, input, sizeof(input), output, 16,
	    &written), 0);
	ATF_CHECK_EQ(memcmp(output + 8, (uint8_t[8]){ 0 }, 8), 0);
	/*
	 * DESTROY has only the common object header.  Its nonzero extension
	 * is ignored rather than treated as a malformed command.
	 */
	admin_header(input, sizeof(input), ADMIN_RESOURCE_DESTROY, 0);
	object_header(input + 24, 0, 0);
	memset(input + 32, 0xa5, sizeof(input) - 32);
	ATF_CHECK_EQ(process(owner, input, sizeof(input), output, 8,
	    &written), 0);

	admin_header(input, 48, ADMIN_RESOURCE_CREATE, 0);
	object_header(input + 24, 0, 1);
	le64enc(input + 32, 0);
	memcpy(input + 40, value, sizeof(value));
	ATF_CHECK_EQ(process(owner, input, 48, output, 8, &written), 0);
	ATF_CHECK_EQ(written, ADMIN_RESULT_SIZE);
	ATF_CHECK_EQ(process(owner, input, 48, output, 8, &written), EEXIST);
	ATF_CHECK_EQ(le16dec(output + 2), 1);

	admin_header(input, 32, ADMIN_RESOURCE_QUERY, 0);
	object_header(input + 24, 0, 1);
	ATF_CHECK_EQ(process(owner, input, 32, output, 16, &written), 0);
	ATF_CHECK_EQ(written, 16);
	ATF_CHECK_EQ(memcmp(output + 8, value, sizeof(value)), 0);

	admin_header(input, 40, ADMIN_RESOURCE_MODIFY, 0);
	object_header(input + 24, 0, 1);
	memcpy(input + 32, changed, sizeof(changed));
	ATF_CHECK_EQ(process(owner, input, 40, output, 8, &written), 0);

	admin_header(input, 32, ADMIN_RESOURCE_QUERY, 0);
	object_header(input + 24, 0, 1);
	ATF_CHECK_EQ(process(owner, input, 32, output, 16, &written), 0);
	ATF_CHECK_EQ(memcmp(output + 8, changed, sizeof(changed)), 0);

	/* A short MODIFY payload is zero-extended to the object size. */
	admin_header(input, 32, ADMIN_RESOURCE_MODIFY, 0);
	object_header(input + 24, 0, 1);
	ATF_CHECK_EQ(process(owner, input, 32, output, 8, &written), 0);
	admin_header(input, 32, ADMIN_RESOURCE_QUERY, 0);
	object_header(input + 24, 0, 1);
	ATF_CHECK_EQ(process(owner, input, 32, output, 16, &written), 0);
	ATF_CHECK_EQ(memcmp(output + 8, (uint8_t[8]){ 0 }, 8), 0);

	input[26] = 1;
	ATF_CHECK_EQ(process(owner, input, 32, output, 16, &written), EINVAL);
	ATF_CHECK_EQ(le16dec(output + 2), 3);
	input[26] = 0;
	le64enc(input + 16, 1);
	ATF_CHECK_EQ(process(owner, input, 32, output, 16, &written), EINVAL);
	ATF_CHECK_EQ(le16dec(output + 2), 5);

	admin_header(input, 32, ADMIN_RESOURCE_DESTROY, 0);
	object_header(input + 24, 0, 1);
	ATF_CHECK_EQ(process(owner, input, 32, output, 8, &written), 0);
	ATF_CHECK_EQ(process(owner, input, 32, output, 8, &written), ENXIO);

	virtio_admin_owner_reset(owner);
	virtio_admin_resource_manager_reset(manager);
	virtio_admin_resource_manager_destroy(manager);
	virtio_admin_owner_destroy(owner);
}

ATF_TC_WITHOUT_HEAD(wire_policy_busy_is_retryable);
ATF_TC_BODY(wire_policy_busy_is_retryable, tc)
{
	struct virtio_admin_resource_manager *manager;
	struct virtio_admin_owner *owner;
	struct resource_validation_policy policy = { .busy = true };
	const struct virtio_admin_resource_type config = {
		.type = 0,
		.limit = 1,
		.minimum_size = 4,
		.maximum_size = 4,
		.valid_flags = 0,
		.validate = resource_validate_busy,
		.validate_argument = &policy,
	};
	uint8_t input[40], output[8];
	size_t written;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_manager_create(&manager), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_register_type(manager, &config), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_register_commands(manager, owner), 0);
	admin_header(input, 32, ADMIN_LIST_USE, 0);
	le64enc(input + 24, UINT64_C(1) << ADMIN_RESOURCE_CREATE);
	ATF_REQUIRE_EQ(process(owner, input, 32, output, sizeof(output),
	    &written), 0);
	admin_header(input, sizeof(input), ADMIN_RESOURCE_CREATE, 0);
	object_header(input + 24, 0, 0);
	ATF_CHECK_EQ(process(owner, input, sizeof(input), output,
	    sizeof(output), &written), ADMIN_STATUS_BUSY);
	ATF_CHECK_EQ(written, ADMIN_RESULT_SIZE);
	ATF_CHECK_EQ(le16dec(output + 2), ADMIN_QUAL_TRYAGAIN);
	virtio_admin_resource_manager_destroy(manager);
	virtio_admin_owner_destroy(owner);
}

ATF_TC_WITHOUT_HEAD(command_registration_is_atomic);
ATF_TC_BODY(command_registration_is_atomic, tc)
{
	struct virtio_admin_resource_manager *manager;
	struct virtio_admin_owner *owner;
	uint8_t input[24], output[16];
	size_t written;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_manager_create(&manager), 0);
	ATF_REQUIRE_EQ(virtio_admin_owner_register_command(owner,
	    ADMIN_RESOURCE_QUERY, vadmin_resource_command, NULL), 0);
	ATF_CHECK_EQ(virtio_admin_resource_register_commands(manager, owner),
	    EEXIST);

	admin_header(input, sizeof(input), ADMIN_LIST_QUERY, 0);
	ATF_CHECK_EQ(process(owner, input, sizeof(input), output,
	    sizeof(output), &written), 0);
	ATF_CHECK_EQ(le64dec(output + 8),
	    (UINT64_C(1) << ADMIN_LIST_QUERY) |
	    (UINT64_C(1) << ADMIN_LIST_USE) |
	    (UINT64_C(1) << ADMIN_RESOURCE_QUERY));
	virtio_admin_resource_manager_destroy(manager);
	virtio_admin_owner_destroy(owner);
}

ATF_TC_WITHOUT_HEAD(portable_transactional_state);
ATF_TC_BODY(portable_transactional_state, tc)
{
	struct virtio_admin_resource_manager *source, *target, *small;
	struct virtio_admin_resource_restore_stage *stage;
	uint8_t value[8], dependent[8], changed[8], output[8];
	uint8_t *state, *corrupt;
	uint64_t flags;
	size_t size, state_size;

	memset(value, 0x51, sizeof(value));
	memset(dependent, 0x62, sizeof(dependent));
	memset(changed, 0x73, sizeof(changed));
	ATF_REQUIRE_EQ(virtio_admin_resource_manager_create(&source), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_manager_create(&target), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_manager_create(&small), 0);
	resource_type(source, 20, 2, sizeof(value));
	resource_type(source, 21, 2, sizeof(value));
	resource_type(target, 20, 2, sizeof(value));
	resource_type(target, 21, 2, sizeof(value));
	resource_type(small, 20, 1, sizeof(value));
	resource_type(small, 21, 2, sizeof(value));
	ATF_REQUIRE_EQ(virtio_admin_resource_create(source, 20, 1, 0,
	    value, sizeof(value)), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_create(source, 21, 0, 0,
	    dependent, sizeof(dependent)), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_add_dependency(source, 21, 0,
	    20, 1), 0);

	ATF_REQUIRE_EQ(virtio_admin_resource_snapshot_size(source,
	    &state_size), 0);
	ATF_CHECK_EQ(state_size, 120);
	state = malloc(state_size);
	corrupt = malloc(state_size);
	ATF_REQUIRE(state != NULL);
	ATF_REQUIRE(corrupt != NULL);
	ATF_CHECK_EQ(virtio_admin_resource_snapshot(source, source,
	    state_size), EINVAL);
	ATF_CHECK_EQ(virtio_admin_resource_restore(source, source,
	    state_size), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_resource_snapshot(source, state,
	    state_size), 0);
	ATF_CHECK_EQ(le32dec(state), UINT32_C(0x31534f52));
	ATF_CHECK_EQ(le16dec(state + 4), 1);
	ATF_CHECK_EQ(le16dec(state + 6), 32);
	ATF_CHECK_EQ(le32dec(state + 8), state_size);
	ATF_CHECK_EQ(le32dec(state + 12), 2);

	ATF_REQUIRE_EQ(virtio_admin_resource_restore(target, state,
	    state_size), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_query(target, 20, 1, &flags,
	    output, sizeof(output), &size), 0);
	ATF_CHECK_EQ(memcmp(output, value, sizeof(value)), 0);
	ATF_CHECK_EQ(virtio_admin_resource_destroy_object(target, 20, 1),
	    EBUSY);

	/* A mutation after prepare cannot be overwritten by stale commit. */
	ATF_REQUIRE_EQ(virtio_admin_resource_restore_prepare(target, state,
	    state_size, &stage), 0);
	ATF_REQUIRE_EQ(virtio_admin_resource_modify(target, 21, 0, changed,
	    sizeof(changed)), 0);
	ATF_CHECK_EQ(virtio_admin_resource_restore_commit(target, stage),
	    EBUSY);
	virtio_admin_resource_restore_stage_destroy(stage);
	ATF_REQUIRE_EQ(virtio_admin_resource_query(target, 21, 0, &flags,
	    output, sizeof(output), &size), 0);
	ATF_CHECK_EQ(memcmp(output, changed, sizeof(changed)), 0);

	/* A smaller destination rejects the record without losing old state. */
	ATF_REQUIRE_EQ(virtio_admin_resource_create(small, 20, 0, 0,
	    dependent, sizeof(dependent)), 0);
	ATF_CHECK_EQ(virtio_admin_resource_restore(small, state, state_size),
	    ENOTSUP);
	ATF_REQUIRE_EQ(virtio_admin_resource_query(small, 20, 0, &flags,
	    output, sizeof(output), &size), 0);
	ATF_CHECK_EQ(memcmp(output, dependent, sizeof(dependent)), 0);

	/* Recomputed checksums cannot hide malformed reserved state. */
	memcpy(corrupt, state, state_size);
	corrupt[35] = 1;
	le64enc(corrupt + 24, vadmin_resource_digest(corrupt, state_size));
	ATF_CHECK_EQ(virtio_admin_resource_restore(target, corrupt,
	    state_size), EPROTO);
	ATF_REQUIRE_EQ(virtio_admin_resource_query(target, 20, 1, &flags,
	    output, sizeof(output), &size), 0);
	ATF_CHECK_EQ(memcmp(output, value, sizeof(value)), 0);

	free(corrupt);
	free(state);
	virtio_admin_resource_manager_destroy(small);
	virtio_admin_resource_manager_destroy(target);
	virtio_admin_resource_manager_destroy(source);
}

ATF_TC_WITHOUT_HEAD(snapshot_alignment_overflow);
ATF_TC_BODY(snapshot_alignment_overflow, tc)
{
	struct virtio_admin_resource_manager *manager;
	size_t state_size;

	ATF_REQUIRE_EQ(virtio_admin_resource_manager_create(&manager), 0);
	resource_type(manager, 0, 1, 1);
	manager->types[0].objects[0].present = true;
	manager->types[0].objects[0].size =
	    SIZE_MAX - BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_ENTRY_SIZE;
	ATF_CHECK_EQ(virtio_admin_resource_snapshot_size(manager, &state_size),
	    EOVERFLOW);
	virtio_admin_resource_manager_destroy(manager);
}

ATF_TC_WITHOUT_HEAD(publication_aliases_are_rejected);
ATF_TC_BODY(publication_aliases_are_rejected, tc)
{
	struct virtio_admin_resource_manager *manager;
	struct virtio_admin_resource_restore_stage *stage;
	struct virtio_admin_resource_type config = {
		.type = 0,
		.limit = 2,
		.minimum_size = sizeof(uint64_t),
		.maximum_size = sizeof(uint64_t),
	};
	uint64_t value, flags, pair;
	uint8_t short_output[4], output[sizeof(value)];
	uint32_t count, limit;
	void *state;
	size_t size, state_size;

	value = UINT64_C(0x1122334455667788);
	ATF_REQUIRE_EQ(virtio_admin_resource_manager_create(&manager), 0);
	ATF_CHECK_EQ(virtio_admin_resource_register_type(manager,
	    (const struct virtio_admin_resource_type *)manager), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_resource_register_type(manager, &config), 0);
	ATF_CHECK_EQ(virtio_admin_resource_create(manager, 0, 0, 0, manager,
	    sizeof(value)), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_resource_create(manager, 0, 0, 0, &value,
	    sizeof(value)), 0);
	ATF_CHECK_EQ(virtio_admin_resource_modify(manager, 0, 0, manager,
	    sizeof(value)), EINVAL);

	flags = UINT64_MAX;
	size = SIZE_MAX;
	ATF_CHECK_EQ(virtio_admin_resource_query(manager, 0, 0,
	    (uint64_t *)manager, output, sizeof(output), &size), EINVAL);
	ATF_CHECK_EQ(size, SIZE_MAX);
	ATF_CHECK_EQ(virtio_admin_resource_query(manager, 0, 0, &flags,
	    manager, 1, &size), EINVAL);
	ATF_CHECK_EQ(flags, UINT64_MAX);
	pair = UINT64_MAX;
	ATF_CHECK_EQ(virtio_admin_resource_query(manager, 0, 0, &pair, &pair,
	    sizeof(pair), &size), EINVAL);
	ATF_CHECK_EQ(pair, UINT64_MAX);
	count = UINT32_MAX;
	limit = UINT32_MAX;
	ATF_CHECK_EQ(virtio_admin_resource_usage(manager, 0, NULL, NULL,
	    (uint32_t *)manager, &limit), EINVAL);
	ATF_CHECK_EQ(limit, UINT32_MAX);
	ATF_CHECK_EQ(virtio_admin_resource_usage(manager, 0, NULL, NULL,
	    &count, &count), EINVAL);
	ATF_CHECK_EQ(count, UINT32_MAX);
	ATF_CHECK_EQ(virtio_admin_resource_snapshot_size(manager,
	    (size_t *)manager), EINVAL);

	ATF_REQUIRE_EQ(virtio_admin_resource_snapshot_size(manager,
	    &state_size), 0);
	state = malloc(state_size);
	ATF_REQUIRE(state != NULL);
	ATF_REQUIRE_EQ(virtio_admin_resource_snapshot(manager, state,
	    state_size), 0);
	ATF_CHECK_EQ(virtio_admin_resource_restore_prepare(manager, state,
	    state_size,
	    (struct virtio_admin_resource_restore_stage **)manager), EINVAL);
	ATF_CHECK_EQ(virtio_admin_resource_restore_prepare(manager, state,
	    state_size,
	    (struct virtio_admin_resource_restore_stage **)state), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_resource_restore_prepare(manager, state,
	    state_size, &stage), 0);
	ATF_CHECK_EQ(virtio_admin_resource_restore_stage_count(stage, 0, NULL,
	    NULL, (uint32_t *)stage), EINVAL);
	flags = UINT64_MAX;
	size = SIZE_MAX;
	memset(short_output, 0xa5, sizeof(short_output));
	ATF_CHECK_EQ(virtio_admin_resource_restore_stage_query(stage, 0, 0,
	    &flags, short_output, sizeof(short_output), &size), ENOSPC);
	ATF_CHECK_EQ(flags, UINT64_MAX);
	ATF_CHECK_EQ(size, SIZE_MAX);
	ATF_CHECK_EQ(short_output[0], 0xa5);
	ATF_CHECK_EQ(virtio_admin_resource_restore_stage_query(stage, 0, 0,
	    (uint64_t *)stage, output, sizeof(output), &size), EINVAL);
	pair = UINT64_MAX;
	ATF_CHECK_EQ(virtio_admin_resource_restore_stage_query(stage, 0, 0,
	    &pair, &pair, sizeof(pair), &size), EINVAL);
	ATF_CHECK_EQ(pair, UINT64_MAX);

	ATF_REQUIRE_EQ(virtio_admin_resource_restore_stage_query(stage, 0, 0,
	    &flags, output, sizeof(output), &size), 0);
	ATF_CHECK_EQ(flags, 0);
	ATF_CHECK_EQ(size, sizeof(value));
	ATF_CHECK_EQ(memcmp(output, &value, sizeof(value)), 0);
	virtio_admin_resource_restore_stage_destroy(stage);
	free(state);
	virtio_admin_resource_manager_destroy(manager);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, id_lifecycle_and_last_value);
	ATF_TP_ADD_TC(tp, validation_uses_private_candidate);
	ATF_TP_ADD_TC(tp, validation_errno_is_preserved);
	ATF_TP_ADD_TC(tp, dependency_reverse_order);
	ATF_TP_ADD_TC(tp, capability_scoped_subtype_limits);
	ATF_TP_ADD_TC(tp, wire_commands_and_errors);
	ATF_TP_ADD_TC(tp, wire_policy_busy_is_retryable);
	ATF_TP_ADD_TC(tp, command_registration_is_atomic);
	ATF_TP_ADD_TC(tp, portable_transactional_state);
	ATF_TP_ADD_TC(tp, snapshot_alignment_overflow);
	ATF_TP_ADD_TC(tp, publication_aliases_are_rejected);
	return (atf_no_error());
}
