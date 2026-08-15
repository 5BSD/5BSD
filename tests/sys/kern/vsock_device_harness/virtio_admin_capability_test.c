/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "virtio_admin.c"
#include "virtio_admin_capability.c"

#define	ADMIN_LIST_QUERY	0x0000
#define	ADMIN_LIST_USE		0x0001
#define	ADMIN_CAP_LIST		0x0007
#define	ADMIN_CAP_GET		0x0008
#define	ADMIN_CAP_SET		0x0009
#define	ADMIN_STATUS_BUSY	16
#define	ADMIN_QUAL_TRYAGAIN	7

struct cap_context {
	bool busy;
	bool applied_set;
	bool bad_apply_size;
	uint8_t applied[2];
	unsigned int apply_count;
};

static int
validate_limits(void *argument, const void *device_data, size_t device_size,
    const void *driver_data, size_t driver_size)
{
	struct cap_context *context;
	const uint8_t *device, *driver;

	context = argument;
	device = device_data;
	driver = driver_data;
	if (device_size != 2 || driver_size != 2 ||
	    driver[0] > device[0] || driver[1] > device[1])
		return (EINVAL);
	if (context->busy && (driver[0] == 0 || driver[1] == 0))
		return (EBUSY);
	return (0);
}

static void
apply_limits(void *argument, const void *driver_data, size_t driver_size,
    bool driver_set)
{
	struct cap_context *context;

	context = argument;
	if (driver_size != sizeof(context->applied)) {
		context->bad_apply_size = true;
		return;
	}
	memcpy(context->applied, driver_data, driver_size);
	context->applied_set = driver_set;
	context->apply_count++;
}

static void
admin_header(uint8_t *input, size_t length, uint16_t opcode, uint64_t member)
{

	memset(input, 0, length);
	le16enc(input, opcode);
	le64enc(input + 16, member);
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

ATF_TC_WITHOUT_HEAD(linux_sized_wire_commands);
ATF_TC_BODY(linux_sized_wire_commands, tc)
{
	struct virtio_admin_capability_manager *manager;
	struct virtio_admin_owner *owner;
	struct cap_context context = { 0 };
	const uint8_t device_limits[2] = { 8, 6 };
	const struct virtio_admin_capability_config config = {
		.id = 0,
		.device_data = device_limits,
		.size = sizeof(device_limits),
		.validate = validate_limits,
		.validate_argument = &context,
		.apply = apply_limits,
		.apply_argument = &context,
	};
	const uint64_t commands = (UINT64_C(1) << ADMIN_LIST_QUERY) |
	    (UINT64_C(1) << ADMIN_LIST_USE) |
	    (UINT64_C(1) << ADMIN_CAP_LIST) |
	    (UINT64_C(1) << ADMIN_CAP_GET) |
	    (UINT64_C(1) << ADMIN_CAP_SET);
	uint8_t input[40], output[16], driver[2];
	bool driver_set;
	size_t size, written;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	ATF_REQUIRE_EQ(virtio_admin_capability_manager_create(&manager), 0);
	ATF_REQUIRE_EQ(virtio_admin_capability_register(manager, &config), 0);
	ATF_REQUIRE_EQ(virtio_admin_capability_register_commands(manager,
	    owner), 0);
	ATF_CHECK_EQ(virtio_admin_capability_register_commands(manager, owner),
	    EALREADY);

	admin_header(input, 32, ADMIN_LIST_USE, 0);
	le64enc(input + 24, commands);
	ATF_CHECK_EQ(process(owner, input, 32, output, 8, &written), 0);

	admin_header(input, 24, ADMIN_CAP_LIST, 0);
	ATF_CHECK_EQ(process(owner, input, 24, output, 16, &written), 0);
	ATF_CHECK_EQ(written, 16);
	ATF_CHECK_EQ(le64dec(output + 8), 1);

	/* CAP_ID_LIST_QUERY has no input; longer extension bytes are ignored. */
	admin_header(input, sizeof(input), ADMIN_CAP_LIST, 0);
	memset(input + 24, 0xa5, sizeof(input) - 24);
	ATF_CHECK_EQ(process(owner, input, sizeof(input), output, 16,
	    &written), 0);
	ATF_CHECK_EQ(written, 16);
	ATF_CHECK_EQ(le64dec(output + 8), 1);

	admin_header(input, 32, ADMIN_CAP_GET, 0);
	ATF_CHECK_EQ(process(owner, input, 32, output, 10, &written), 0);
	ATF_CHECK_EQ(written, 10);
	ATF_CHECK_EQ(output[8], 8);
	ATF_CHECK_EQ(output[9], 6);

	/*
	 * Linux sends an eight-byte capability header plus the literal
	 * two-byte device-parts capability: 34 readable bytes in total.
	 */
	admin_header(input, 34, ADMIN_CAP_SET, 0);
	input[32] = 5;
	input[33] = 4;
	ATF_CHECK_EQ(process(owner, input, 34, output, 8, &written), 0);
	ATF_REQUIRE_EQ(virtio_admin_capability_get_driver(manager, 0, driver,
	    sizeof(driver), &size, &driver_set), 0);
	ATF_CHECK(driver_set);
	ATF_CHECK_EQ(size, 2);
	ATF_CHECK_EQ(driver[0], 5);
	ATF_CHECK_EQ(driver[1], 4);
	ATF_CHECK_EQ(context.apply_count, 1);
	ATF_CHECK(context.applied_set);
	ATF_CHECK_EQ(context.applied[0], 5);

	input[32] = 9;
	ATF_CHECK_EQ(process(owner, input, 34, output, 8, &written), EINVAL);
	ATF_CHECK_EQ(le16dec(output + 2), 3);
	ATF_REQUIRE_EQ(virtio_admin_capability_get_driver(manager, 0, driver,
	    sizeof(driver), &size, &driver_set), 0);
	ATF_CHECK_EQ(driver[0], 5);
	ATF_CHECK_EQ(context.apply_count, 1);

	context.busy = true;
	input[32] = 0;
	input[33] = 0;
	ATF_CHECK_EQ(process(owner, input, 34, output, 8, &written), EBUSY);
	ATF_CHECK_EQ(le16dec(output), ADMIN_STATUS_BUSY);
	ATF_CHECK_EQ(le16dec(output + 2), ADMIN_QUAL_TRYAGAIN);
	ATF_CHECK_EQ(context.apply_count, 1);

	admin_header(input, 32, ADMIN_CAP_GET, 1);
	ATF_CHECK_EQ(process(owner, input, 32, output, 10, &written), EINVAL);
	ATF_CHECK_EQ(le16dec(output + 2), 5);
	admin_header(input, 32, ADMIN_CAP_GET, 0);
	le16enc(input + 24, 1);
	ATF_CHECK_EQ(process(owner, input, 32, output, 10, &written), ENXIO);

	virtio_admin_capability_manager_reset(manager);
	ATF_REQUIRE_EQ(virtio_admin_capability_get_driver(manager, 0, driver,
	    sizeof(driver), &size, &driver_set), 0);
	ATF_CHECK(!driver_set);
	ATF_CHECK_EQ(driver[0], 0);
	ATF_CHECK_EQ(driver[1], 0);
	ATF_CHECK_EQ(context.apply_count, 2);
	ATF_CHECK(!context.applied_set);
	ATF_CHECK(!context.bad_apply_size);
	virtio_admin_capability_manager_destroy(manager);
	virtio_admin_owner_destroy(owner);
}

ATF_TC_WITHOUT_HEAD(bitmap_boundaries_and_registration);
ATF_TC_BODY(bitmap_boundaries_and_registration, tc)
{
	struct virtio_admin_capability_manager *manager;
	struct virtio_admin_owner *owner;
	const uint8_t data = 1;
	struct virtio_admin_capability_config config = {
		.device_data = &data,
		.size = sizeof(data),
	};
	uint8_t input[32], output[80];
	size_t written;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	ATF_REQUIRE_EQ(virtio_admin_capability_manager_create(&manager), 0);
	config.id = 0;
	ATF_REQUIRE_EQ(virtio_admin_capability_register(manager, &config), 0);
	ATF_CHECK_EQ(virtio_admin_capability_register(manager, &config),
	    EEXIST);
	config.id = 64;
	ATF_REQUIRE_EQ(virtio_admin_capability_register(manager, &config), 0);
	config.id = 4096;
	ATF_CHECK_EQ(virtio_admin_capability_register(manager, &config),
	    EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_capability_register_commands(manager,
	    owner), 0);
	config.id = 65;
	ATF_CHECK_EQ(virtio_admin_capability_register(manager, &config),
	    EBUSY);

	admin_header(input, 32, ADMIN_LIST_USE, 0);
	le64enc(input + 24, (UINT64_C(1) << ADMIN_LIST_QUERY) |
	    (UINT64_C(1) << ADMIN_LIST_USE) |
	    (UINT64_C(1) << ADMIN_CAP_LIST));
	ATF_REQUIRE_EQ(process(owner, input, 32, output, 8, &written), 0);
	admin_header(input, 24, ADMIN_CAP_LIST, 0);
	ATF_REQUIRE_EQ(process(owner, input, 24, output, sizeof(output),
	    &written), 0);
	ATF_CHECK_EQ(written, 24);
	ATF_CHECK_EQ(le64dec(output + 8), 1);
	ATF_CHECK_EQ(le64dec(output + 16), 1);
	for (size_t i = 24; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0xa5);

	virtio_admin_capability_manager_destroy(manager);
	virtio_admin_owner_destroy(owner);
}

ATF_TC_WITHOUT_HEAD(exact_publication_is_bounded_and_validated);
ATF_TC_BODY(exact_publication_is_bounded_and_validated, tc)
{
	struct virtio_admin_capability_manager *manager;
	struct cap_context context = { 0 };
	const uint8_t device_limits[2] = { 8, 6 };
	const struct virtio_admin_capability_config config = {
		.id = 0,
		.device_data = device_limits,
		.size = sizeof(device_limits),
		.validate = validate_limits,
		.validate_argument = &context,
		.apply = apply_limits,
		.apply_argument = &context,
	};
	const uint8_t good[2] = { 5, 4 };
	const uint8_t bad[2] = { 9, 4 };
	uint8_t current[2];
	bool driver_set;
	size_t size;

	ATF_REQUIRE_EQ(virtio_admin_capability_manager_create(&manager), 0);
	ATF_REQUIRE_EQ(virtio_admin_capability_register(manager, &config), 0);
	ATF_CHECK_EQ(virtio_admin_capability_set_driver_exact(manager, 0,
	    good, 1), EMSGSIZE);
	ATF_CHECK_EQ(virtio_admin_capability_set_driver_exact(manager, 1,
	    good, sizeof(good)), ENXIO);
	ATF_CHECK_EQ(virtio_admin_capability_set_driver_exact(manager, 0,
	    bad, sizeof(bad)), EINVAL);
	ATF_CHECK_EQ(context.apply_count, 0);
	ATF_REQUIRE_EQ(virtio_admin_capability_set_driver_exact(manager, 0,
	    good, sizeof(good)), 0);
	ATF_REQUIRE_EQ(virtio_admin_capability_get_driver(manager, 0, current,
	    sizeof(current), &size, &driver_set), 0);
	ATF_CHECK(driver_set);
	ATF_CHECK_EQ(size, sizeof(current));
	ATF_CHECK_EQ(memcmp(current, good, sizeof(good)), 0);
	ATF_CHECK_EQ(context.apply_count, 1);

	virtio_admin_capability_manager_destroy(manager);
}

ATF_TC_WITHOUT_HEAD(portable_state_is_transactional);
ATF_TC_BODY(portable_state_is_transactional, tc)
{
	struct virtio_admin_capability_manager *destination, *source;
	struct cap_context destination_context = { 0 };
	struct cap_context source_context = { 0 };
	const uint8_t device_limits[2] = { 8, 6 };
	const uint8_t other_device = 0xff;
	struct virtio_admin_capability_config limits = {
		.id = 0,
		.device_data = device_limits,
		.size = sizeof(device_limits),
		.validate = validate_limits,
		.validate_argument = &source_context,
		.apply = apply_limits,
		.apply_argument = &source_context,
	};
	const struct virtio_admin_capability_config other = {
		.id = 64,
		.device_data = &other_device,
		.size = sizeof(other_device),
	};
	uint8_t current[2], driver_limits[2] = { 5, 4 };
	uint8_t *bad, *state;
	bool driver_set;
	size_t size, state_size;

	ATF_REQUIRE_EQ(virtio_admin_capability_manager_create(&source), 0);
	ATF_REQUIRE_EQ(virtio_admin_capability_register(source, &limits), 0);
	ATF_REQUIRE_EQ(virtio_admin_capability_register(source, &other), 0);
	ATF_REQUIRE_EQ(virtio_admin_capability_set_driver(source, 0,
	    driver_limits, sizeof(driver_limits)), 0);
	ATF_REQUIRE_EQ(virtio_admin_capability_snapshot_size(source,
	    &state_size), 0);
	ATF_REQUIRE(state_size > 64);
	state = malloc(state_size);
	bad = malloc(state_size);
	ATF_REQUIRE(state != NULL);
	ATF_REQUIRE(bad != NULL);
	ATF_CHECK_EQ(virtio_admin_capability_snapshot(source, source,
	    state_size), EINVAL);
	ATF_CHECK_EQ(virtio_admin_capability_restore(source, source,
	    state_size), EINVAL);
	/*
	 * Both owned capability allocations are part of the manager graph.
	 * The state record is deliberately larger than either allocation;
	 * reject it before snapshot can overwrite policy or restore can read
	 * beyond the internal object.
	 */
	ATF_CHECK_EQ(virtio_admin_capability_snapshot(source,
	    source->capabilities[0].device_data, state_size), EINVAL);
	ATF_CHECK_EQ(virtio_admin_capability_restore(source,
	    source->capabilities[0].device_data, state_size), EINVAL);
	ATF_CHECK_EQ(virtio_admin_capability_snapshot(source,
	    source->capabilities[0].driver_data, state_size), EINVAL);
	ATF_CHECK_EQ(virtio_admin_capability_restore(source,
	    source->capabilities[0].driver_data, state_size), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_capability_snapshot(source, state,
	    state_size), 0);
	ATF_CHECK_EQ(le32dec(state), VADMIN_CAPABILITY_STATE_MAGIC);
	ATF_CHECK_EQ(le16dec(state + 4), 1);
	ATF_CHECK_EQ(le32dec(state + 12), 2);
	ATF_CHECK_EQ(virtio_admin_capability_snapshot(source, state,
	    state_size - 1), EMSGSIZE);

	ATF_REQUIRE_EQ(virtio_admin_capability_manager_create(&destination),
	    0);
	struct virtio_admin_capability_config destination_limits = limits;
	destination_limits.validate_argument = &destination_context;
	destination_limits.apply_argument = &destination_context;
	ATF_REQUIRE_EQ(virtio_admin_capability_register(destination,
	    &destination_limits), 0);
	ATF_REQUIRE_EQ(virtio_admin_capability_register(destination, &other),
	    0);
	ATF_REQUIRE_EQ(virtio_admin_capability_restore(destination, state,
	    state_size), 0);
	ATF_REQUIRE_EQ(virtio_admin_capability_get_driver(destination, 0,
	    current, sizeof(current), &size, &driver_set), 0);
	ATF_CHECK(driver_set);
	ATF_CHECK_EQ(size, 2);
	ATF_CHECK_EQ(current[0], 5);
	ATF_CHECK_EQ(current[1], 4);
	ATF_CHECK_EQ(destination_context.apply_count, 1);
	ATF_CHECK(!destination_context.bad_apply_size);
	ATF_REQUIRE_EQ(virtio_admin_capability_get_driver(destination, 64,
	    current, sizeof(current), &size, &driver_set), 0);
	ATF_CHECK(!driver_set);
	ATF_CHECK_EQ(current[0], 0);

	/* A checksum failure must not alter the previously restored state. */
	memcpy(bad, state, state_size);
	bad[state_size - 1] ^= 1;
	ATF_CHECK_EQ(virtio_admin_capability_restore(destination, bad,
	    state_size), EPROTO);
	ATF_REQUIRE_EQ(virtio_admin_capability_get_driver(destination, 0,
	    current, sizeof(current), &size, &driver_set), 0);
	ATF_CHECK_EQ(current[0], 5);
	ATF_CHECK_EQ(destination_context.apply_count, 1);

	/* Reserved bytes and unset nonzero data are structural failures. */
	memcpy(bad, state, state_size);
	bad[16] = 1;
	le64enc(bad + VADMIN_CAPABILITY_STATE_DIGEST_OFFSET,
	    vadmin_capability_digest(bad, state_size));
	ATF_CHECK_EQ(virtio_admin_capability_restore(destination, bad,
	    state_size), EPROTO);
	ATF_CHECK_EQ(destination_context.apply_count, 1);
	memcpy(bad, state, state_size);
	size_t second = BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_HEADER_SIZE +
	    vadmin_capability_align(
	    BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_ENTRY_SIZE + 2);
	ATF_REQUIRE_EQ(le16dec(bad + second), 64);
	bad[second + BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_ENTRY_SIZE] = 1;
	le64enc(bad + VADMIN_CAPABILITY_STATE_DIGEST_OFFSET,
	    vadmin_capability_digest(bad, state_size));
	ATF_CHECK_EQ(virtio_admin_capability_restore(destination, bad,
	    state_size), EPROTO);

	/* Destination policy rejection is ENOTSUP and remains transactional. */
	memcpy(bad, state, state_size);
	size_t first_data = BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_HEADER_SIZE +
	    BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_ENTRY_SIZE;
	bad[first_data] = 9;
	le64enc(bad + VADMIN_CAPABILITY_STATE_DIGEST_OFFSET,
	    vadmin_capability_digest(bad, state_size));
	ATF_CHECK_EQ(virtio_admin_capability_restore(destination, bad,
	    state_size), ENOTSUP);
	ATF_REQUIRE_EQ(virtio_admin_capability_get_driver(destination, 0,
	    current, sizeof(current), &size, &driver_set), 0);
	ATF_CHECK_EQ(current[0], 5);
	ATF_CHECK_EQ(destination_context.apply_count, 1);

	/* A destination capability-size mismatch is incompatible. */
	struct virtio_admin_capability_manager *incompatible;
	const uint8_t wider_device[3] = { 8, 6, 1 };
	const struct virtio_admin_capability_config wider = {
		.id = 0,
		.device_data = wider_device,
		.size = sizeof(wider_device),
	};
	ATF_REQUIRE_EQ(virtio_admin_capability_manager_create(&incompatible),
	    0);
	ATF_REQUIRE_EQ(virtio_admin_capability_register(incompatible, &wider),
	    0);
	ATF_REQUIRE_EQ(virtio_admin_capability_register(incompatible, &other),
	    0);
	ATF_CHECK_EQ(virtio_admin_capability_restore(incompatible, state,
	    state_size), ENOTSUP);

	virtio_admin_capability_manager_destroy(incompatible);
	virtio_admin_capability_manager_destroy(destination);
	virtio_admin_capability_manager_destroy(source);
	free(bad);
	free(state);
}

ATF_TC_WITHOUT_HEAD(snapshot_alignment_overflow);
ATF_TC_BODY(snapshot_alignment_overflow, tc)
{
	struct virtio_admin_capability_manager *manager;
	const uint8_t device = 0;
	const struct virtio_admin_capability_config config = {
		.id = 0,
		.device_data = &device,
		.size = sizeof(device),
	};
	size_t state_size;

	ATF_REQUIRE_EQ(virtio_admin_capability_manager_create(&manager), 0);
	ATF_REQUIRE_EQ(virtio_admin_capability_register(manager, &config), 0);
	manager->capabilities[0].size =
	    SIZE_MAX - BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_ENTRY_SIZE;
	ATF_CHECK_EQ(virtio_admin_capability_snapshot_size(manager, &state_size),
	    EOVERFLOW);
	virtio_admin_capability_manager_destroy(manager);
}

ATF_TC_WITHOUT_HEAD(publication_aliases_are_rejected);
ATF_TC_BODY(publication_aliases_are_rejected, tc)
{
	struct virtio_admin_capability_manager *manager;
	struct virtio_admin_capability_config config;
	const uint8_t device[2] = { 8, 6 };
	const uint8_t driver[2] = { 4, 3 };
	union {
		uint64_t align;
		uint8_t bytes[32];
	} outputs;
	bool driver_set;
	size_t size;
	uint8_t current[2];

	ATF_REQUIRE_EQ(virtio_admin_capability_manager_create(&manager), 0);
	memset(&config, 0, sizeof(config));
	config.device_data = manager;
	config.size = 1;
	ATF_CHECK_EQ(virtio_admin_capability_register(manager, &config),
	    EINVAL);
	ATF_CHECK_EQ(virtio_admin_capability_register(manager,
	    (const struct virtio_admin_capability_config *)manager), EINVAL);

	config.device_data = device;
	config.size = sizeof(device);
	ATF_REQUIRE_EQ(virtio_admin_capability_register(manager, &config), 0);
	ATF_CHECK_EQ(virtio_admin_capability_set_driver(manager, 0, manager,
	    sizeof(driver)), EINVAL);
	ATF_CHECK_EQ(virtio_admin_capability_set_driver_exact(manager, 0,
	    manager, sizeof(driver)), EINVAL);

	size = 0xfeed;
	driver_set = true;
	ATF_CHECK_EQ(virtio_admin_capability_get_driver(manager, 0, manager, 1,
	    &size, &driver_set), EINVAL);
	ATF_CHECK_EQ(size, 0xfeed);
	ATF_CHECK(driver_set);
	memset(&outputs, 0xa5, sizeof(outputs));
	ATF_CHECK_EQ(virtio_admin_capability_get_driver(manager, 0,
	    outputs.bytes, sizeof(driver), (size_t *)outputs.bytes,
	    (bool *)(outputs.bytes + 16)), EINVAL);
	ATF_CHECK_EQ(outputs.bytes[0], 0xa5);
	ATF_CHECK_EQ(virtio_admin_capability_snapshot_size(manager,
	    (size_t *)manager), EINVAL);

	ATF_REQUIRE_EQ(virtio_admin_capability_set_driver_exact(manager, 0,
	    driver, sizeof(driver)), 0);
	ATF_REQUIRE_EQ(virtio_admin_capability_get_driver(manager, 0, current,
	    sizeof(current), &size, &driver_set), 0);
	ATF_CHECK_EQ(size, sizeof(current));
	ATF_CHECK(driver_set);
	ATF_CHECK_EQ(memcmp(current, driver, sizeof(current)), 0);
	virtio_admin_capability_manager_destroy(manager);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, linux_sized_wire_commands);
	ATF_TP_ADD_TC(tp, bitmap_boundaries_and_registration);
	ATF_TP_ADD_TC(tp, exact_publication_is_bounded_and_validated);
	ATF_TP_ADD_TC(tp, portable_state_is_transactional);
	ATF_TP_ADD_TC(tp, snapshot_alignment_overflow);
	ATF_TP_ADD_TC(tp, publication_aliases_are_rejected);
	return (atf_no_error());
}
