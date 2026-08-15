/*
 * Independent VirtIO 1.4 sections 2.12 and 2.13 administration tests.
 */
#include <sys/endian.h>

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_admin.c"
#include "virtio_admin_group.c"
#include "virtio_admin_queue.c"
#include "virtio_admin_sriov.c"
#include "virtio_1_4_spec.h"

#define	ADMIN_STATE_SIZE	32U
#define	ADMIN_STATE_MAGIC	UINT32_C(0x314d4441)
#define	ADMIN_STATE_VERSION	1U
#define	ADMIN_STATE_DIGEST_OFF	24U
#define	ADMIN_BASE_MASK		((UINT64_C(1) << \
    VIRTIO14_ADMIN_CMD_LIST_QUERY) | (UINT64_C(1) << \
    VIRTIO14_ADMIN_CMD_LIST_USE))
#define	PCI_CONTROLLER_STATE_MAGIC	UINT32_C(0x31435041)
#define	PCI_CONTROLLER_STATE_VERSION	1U
#define	PCI_CONTROLLER_STATE_HEADER_SIZE	32U
#define	PCI_CONTROLLER_STATE_DIGEST_OFF	24U

static void
admin_command(uint8_t *input, size_t length, uint16_t opcode,
    uint16_t group)
{

	memset(input, 0, length);
	le16enc(input, opcode);
	le16enc(input + 2, group);
}

static void
check_result(const uint8_t *output, uint16_t status, uint16_t qualifier)
{

	ATF_CHECK_EQ(le16dec(output), status);
	ATF_CHECK_EQ(le16dec(output + 2), qualifier);
	ATF_CHECK_EQ(le32dec(output + 4), 0);
}

static uint64_t
state_digest(const uint8_t *bytes, size_t length)
{
	uint64_t digest;

	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < length; i++) {
		uint8_t byte;

		byte = i >= ADMIN_STATE_DIGEST_OFF &&
		    i < ADMIN_STATE_DIGEST_OFF + sizeof(uint64_t) ?
		    0 : bytes[i];
		digest ^= byte;
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

struct registered_command_context {
	uint64_t calls;
	uint64_t member;
	size_t input_length;
};

static bool
alias_group_available(void *argument)
{

	(void)argument;
	return (true);
}

static bool
alias_group_member(void *argument, uint64_t member)
{

	(void)argument;
	return (member == 0);
}

ATF_TC_WITHOUT_HEAD(status_values_match_specification);
ATF_TC_BODY(status_values_match_specification, tc)
{

	ATF_CHECK_EQ(BHYVE_VIRTIO_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_STATUS_OK);
	ATF_CHECK_EQ(BHYVE_VIRTIO_ADMIN_STATUS_ENXIO,
	    VIRTIO14_ADMIN_STATUS_ENXIO);
	ATF_CHECK_EQ(BHYVE_VIRTIO_ADMIN_STATUS_EAGAIN,
	    VIRTIO14_ADMIN_STATUS_EAGAIN);
	ATF_CHECK_EQ(BHYVE_VIRTIO_ADMIN_STATUS_ENOMEM,
	    VIRTIO14_ADMIN_STATUS_ENOMEM);
	ATF_CHECK_EQ(BHYVE_VIRTIO_ADMIN_STATUS_EBUSY,
	    VIRTIO14_ADMIN_STATUS_EBUSY);
	ATF_CHECK_EQ(BHYVE_VIRTIO_ADMIN_STATUS_EEXIST,
	    VIRTIO14_ADMIN_STATUS_EEXIST);
	ATF_CHECK_EQ(BHYVE_VIRTIO_ADMIN_STATUS_EINVAL,
	    VIRTIO14_ADMIN_STATUS_EINVAL);
	ATF_CHECK_EQ(BHYVE_VIRTIO_ADMIN_STATUS_ENOSPC,
	    VIRTIO14_ADMIN_STATUS_ENOSPC);

	ATF_CHECK_EQ(virtio_admin_status_from_errno(0),
	    VIRTIO14_ADMIN_STATUS_OK);
	ATF_CHECK_EQ(virtio_admin_status_from_errno(ENXIO),
	    VIRTIO14_ADMIN_STATUS_ENXIO);
	ATF_CHECK_EQ(virtio_admin_status_from_errno(EAGAIN),
	    VIRTIO14_ADMIN_STATUS_EAGAIN);
	ATF_CHECK_EQ(virtio_admin_status_from_errno(ENOMEM),
	    VIRTIO14_ADMIN_STATUS_ENOMEM);
	ATF_CHECK_EQ(virtio_admin_status_from_errno(EBUSY),
	    VIRTIO14_ADMIN_STATUS_EBUSY);
	ATF_CHECK_EQ(virtio_admin_status_from_errno(EEXIST),
	    VIRTIO14_ADMIN_STATUS_EEXIST);
	ATF_CHECK_EQ(virtio_admin_status_from_errno(EINVAL),
	    VIRTIO14_ADMIN_STATUS_EINVAL);
	ATF_CHECK_EQ(virtio_admin_status_from_errno(ENOSPC),
	    VIRTIO14_ADMIN_STATUS_ENOSPC);
	ATF_CHECK_EQ(virtio_admin_status_from_errno(EIO),
	    VIRTIO14_ADMIN_STATUS_EINVAL);
}

ATF_TC_WITHOUT_HEAD(core_publication_aliases_are_rejected);
ATF_TC_BODY(core_publication_aliases_are_rejected, tc)
{
	const struct virtio_admin_group_config config = {
		.group_type = VIRTIO14_ADMIN_GROUP_SELF,
		.available = alias_group_available,
		.member_valid = alias_group_member,
	};
	struct virtio_admin_group_fabric *fabric;
	struct virtio_admin_owner *owner, *group_owner;
	uint8_t input[VIRTIO14_ADMIN_HEADER_SIZE], output[16];
	size_t written;
	uint16_t status, qualifier;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	written = 91;
	ATF_CHECK_EQ(virtio_admin_process(owner, input, sizeof(input), owner,
	    sizeof(output), &written), EINVAL);
	ATF_CHECK_EQ(written, 91);
	ATF_CHECK(!owner->sealed);
	ATF_CHECK_EQ(virtio_admin_process(owner, owner, sizeof(input), output,
	    sizeof(output), &written), EINVAL);
	ATF_CHECK_EQ(written, 91);
	ATF_CHECK(!owner->sealed);
	ATF_CHECK_EQ(virtio_admin_process(owner, input, sizeof(input), output,
	    sizeof(output), (size_t *)(void *)owner), EINVAL);
	ATF_CHECK(!owner->sealed);
	ATF_CHECK_EQ(virtio_admin_process(owner, input, sizeof(input), input,
	    sizeof(output), &written), EINVAL);
	ATF_CHECK_EQ(written, 91);
	ATF_CHECK(!owner->sealed);
	ATF_CHECK_EQ(virtio_admin_process(owner, input, sizeof(input), output,
	    sizeof(output), (size_t *)(void *)output), EINVAL);
	ATF_CHECK(!owner->sealed);

	status = 92;
	qualifier = 93;
	ATF_CHECK(!virtio_admin_prevalidate_group(owner,
	    VIRTIO14_ADMIN_GROUP_SELF, vadmin_self_member, NULL, input,
	    sizeof(input), (uint16_t *)(void *)owner, &qualifier));
	ATF_CHECK_EQ(qualifier, 93);
	ATF_CHECK(!virtio_admin_prevalidate_group(owner,
	    VIRTIO14_ADMIN_GROUP_SELF, vadmin_self_member, NULL, input,
	    sizeof(input), &status, &status));
	ATF_CHECK_EQ(status, 92);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, sizeof(input), output,
	    sizeof(output), &written), 0);
	ATF_CHECK(owner->sealed);
	ATF_CHECK_EQ(written, sizeof(output));
	virtio_admin_owner_destroy(owner);

	ATF_REQUIRE_EQ(virtio_admin_group_fabric_create(&fabric), 0);
	ATF_CHECK_EQ(virtio_admin_group_register(fabric,
	    (const struct virtio_admin_group_config *)(const void *)fabric,
	    &group_owner), EINVAL);
	ATF_CHECK_EQ(virtio_admin_group_register(fabric, &config,
	    (struct virtio_admin_owner **)(void *)fabric), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_group_register(fabric, &config,
	    &group_owner), 0);

	written = 94;
	ATF_CHECK_EQ(virtio_admin_group_process(fabric, input, sizeof(input),
	    fabric, sizeof(output), &written), EINVAL);
	ATF_CHECK_EQ(written, 94);
	ATF_CHECK(!atomic_load(&fabric->sealed));
	ATF_CHECK_EQ(virtio_admin_group_process(fabric, input, sizeof(input),
	    input, sizeof(output), &written), EINVAL);
	ATF_CHECK_EQ(written, 94);
	ATF_CHECK(!atomic_load(&fabric->sealed));
	ATF_CHECK_EQ(virtio_admin_group_process(fabric, input, sizeof(input),
	    output, sizeof(output), (size_t *)(void *)fabric), EINVAL);
	ATF_CHECK(!atomic_load(&fabric->sealed));
	ATF_CHECK_EQ(virtio_admin_group_snapshot_size(fabric,
	    (size_t *)(void *)fabric), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_group_process(fabric, input, sizeof(input),
	    output, sizeof(output), &written), 0);
	ATF_CHECK(atomic_load(&fabric->sealed));
	ATF_CHECK_EQ(written, sizeof(output));
	virtio_admin_group_fabric_destroy(fabric);
}

static void
registered_command(void *argument, uint64_t member, const void *input,
    size_t input_length, void *output, size_t output_length,
    struct virtio_admin_command_result *result)
{
	struct registered_command_context *context;

	context = argument;
	context->calls++;
	context->member = member;
	context->input_length = input_length;
	if (member != 0) {
		result->status = VIRTIO14_ADMIN_STATUS_EINVAL;
		result->qualifier = VIRTIO14_ADMIN_QUALIFIER_INVALID_MEMBER;
		return;
	}
	if (input_length >= sizeof(uint64_t) &&
	    le64dec(input) != UINT64_C(0x0102030405060708)) {
		result->status = VIRTIO14_ADMIN_STATUS_EINVAL;
		result->qualifier = VIRTIO14_ADMIN_QUALIFIER_INVALID_FIELD;
		return;
	}
	if (output_length >= sizeof(uint64_t))
		le64enc(output, UINT64_C(0x8877665544332211));
	result->result_length = sizeof(uint64_t);
}

static void
successful_command_with_bad_qualifier(void *argument __unused,
    uint64_t member __unused, const void *input __unused,
    size_t input_length __unused, void *output __unused,
    size_t output_length __unused,
    struct virtio_admin_command_result *result)
{

	result->status = VIRTIO14_ADMIN_STATUS_OK;
	result->qualifier = VIRTIO14_ADMIN_QUALIFIER_INVALID_FIELD;
}

static void
command_with_private_status(void *argument __unused, uint64_t member __unused,
    const void *input __unused, size_t input_length __unused,
    void *output __unused, size_t output_length __unused,
    struct virtio_admin_command_result *result)
{

	result->status = UINT16_MAX;
	result->qualifier = UINT16_MAX;
}

static void
command_with_private_qualifier(void *argument __unused,
    uint64_t member __unused, const void *input __unused,
    size_t input_length __unused, void *output __unused,
    size_t output_length __unused,
    struct virtio_admin_command_result *result)
{

	result->status = VIRTIO14_ADMIN_STATUS_EBUSY;
	result->qualifier = UINT16_MAX;
}

ATF_TC_WITHOUT_HEAD(callback_private_status_is_rejected);
ATF_TC_BODY(callback_private_status_is_rejected, tc)
{
	struct virtio_admin_owner *owner;
	uint8_t input[VIRTIO14_ADMIN_HEADER_SIZE + VIRTIO14_ADMIN_LIST_SIZE];
	uint8_t output[VIRTIO14_ADMIN_RESULT_HEADER_SIZE];
	size_t written;
	const uint64_t commands = ADMIN_BASE_MASK | (UINT64_C(1) << 7) |
	    (UINT64_C(1) << 8);

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	ATF_REQUIRE_EQ(virtio_admin_owner_register_command(owner, 7,
	    command_with_private_status, NULL), 0);
	ATF_REQUIRE_EQ(virtio_admin_owner_register_command(owner, 8,
	    command_with_private_qualifier, NULL), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_USE,
	    VIRTIO14_ADMIN_GROUP_SELF);
	le64enc(input + VIRTIO14_ADMIN_HEADER_SIZE, commands);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, sizeof(input),
	    output, sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);

	admin_command(input, VIRTIO14_ADMIN_HEADER_SIZE, 7,
	    VIRTIO14_ADMIN_GROUP_SELF);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input,
	    VIRTIO14_ADMIN_HEADER_SIZE, output, sizeof(output), &written), 0);
	ATF_CHECK_EQ(written, sizeof(output));
	check_result(output, VIRTIO14_ADMIN_STATUS_EINVAL,
	    VIRTIO14_ADMIN_QUALIFIER_INVALID_COMMAND);

	admin_command(input, VIRTIO14_ADMIN_HEADER_SIZE, 8,
	    VIRTIO14_ADMIN_GROUP_SELF);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input,
	    VIRTIO14_ADMIN_HEADER_SIZE, output, sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_EBUSY,
	    VIRTIO14_ADMIN_QUALIFIER_INVALID_COMMAND);
	virtio_admin_owner_destroy(owner);
}

ATF_TC_WITHOUT_HEAD(list_query_lengths);
ATF_TC_BODY(list_query_lengths, tc)
{
	struct virtio_admin_owner *owner;
	uint8_t input[40], output[24];
	size_t written;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	for (size_t input_length = 8; input_length <= sizeof(input);
	    input_length += 8) {
		admin_command(input, input_length,
		    VIRTIO14_ADMIN_CMD_LIST_QUERY,
		    VIRTIO14_ADMIN_GROUP_SELF);
		for (size_t output_length = 8; output_length <= sizeof(output);
		    output_length += 8) {
			memset(output, 0xa5, sizeof(output));
			ATF_REQUIRE_EQ(virtio_admin_process(owner, input,
			    input_length, output, output_length, &written), 0);
			ATF_CHECK_EQ(written, output_length == 8 ? 8 : 16);
			check_result(output, VIRTIO14_ADMIN_STATUS_OK,
			    VIRTIO14_ADMIN_QUALIFIER_OK);
			if (output_length >= 16)
				ATF_CHECK_EQ(le64dec(output + 8),
				    ADMIN_BASE_MASK);
			if (output_length > 16) {
				for (size_t i = 16; i < output_length; i++)
					ATF_CHECK_EQ(output[i], 0xa5);
			}
		}
	}
	virtio_admin_owner_destroy(owner);
}

ATF_TC_WITHOUT_HEAD(zero_lengths_are_transport_errors);
ATF_TC_BODY(zero_lengths_are_transport_errors, tc)
{
	struct virtio_admin_owner *owner;
	uint8_t input[24], output[16];
	size_t written;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	written = 99;
	ATF_CHECK_EQ(virtio_admin_process(owner, input, 0, output,
	    sizeof(output), &written), EINVAL);
	ATF_CHECK_EQ(written, 0);
	ATF_CHECK_EQ(virtio_admin_process(owner, input, sizeof(input), output,
	    0, &written), EINVAL);
	for (size_t input_length = 1; input_length < 8; input_length++) {
		memset(output, 0xa5, sizeof(output));
		ATF_REQUIRE_EQ(virtio_admin_process(owner, input, input_length,
		    output, sizeof(output), &written), 0);
		ATF_CHECK_EQ(written, sizeof(output));
		check_result(output, VIRTIO14_ADMIN_STATUS_OK,
		    VIRTIO14_ADMIN_QUALIFIER_OK);
		ATF_CHECK_EQ(le64dec(output + 8), ADMIN_BASE_MASK);
	}
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, sizeof(input), output,
	    9, &written), 0);
	ATF_CHECK_EQ(written, 9);
	ATF_CHECK_EQ(output[8], ADMIN_BASE_MASK & 0xff);
	for (size_t output_length = 1; output_length < 8; output_length++) {
		memset(output, 0xa5, sizeof(output));
		ATF_REQUIRE_EQ(virtio_admin_process(owner, input,
		    sizeof(input), output, output_length, &written), 0);
		ATF_CHECK_EQ(written, output_length);
		for (size_t i = 0; i < output_length; i++)
			ATF_CHECK_EQ(output[i], 0);
		for (size_t i = output_length; i < sizeof(output); i++)
			ATF_CHECK_EQ(output[i], 0xa5);
	}
	virtio_admin_owner_destroy(owner);
}

ATF_TC_WITHOUT_HEAD(command_validation);
ATF_TC_BODY(command_validation, tc)
{
	struct virtio_admin_owner *owner;
	uint8_t input[40], output[16];
	size_t written;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_QUERY, 1);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, sizeof(input),
	    output, sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_EINVAL,
	    VIRTIO14_ADMIN_QUALIFIER_INVALID_GROUP);

	admin_command(input, sizeof(input), 63, VIRTIO14_ADMIN_GROUP_SELF);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, sizeof(input),
	    output, sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_EINVAL,
	    VIRTIO14_ADMIN_QUALIFIER_INVALID_OPCODE);

	/*
	 * LIST_QUERY and LIST_USE do not use group_member_id.  A conforming
	 * driver sets it to zero, but the device only validates the field for
	 * commands which use it.
	 */
	admin_command(input, 24, VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	le64enc(input + 16, UINT64_MAX);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, 24, output,
	    sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);
	ATF_CHECK_EQ(le64dec(output + 8), ADMIN_BASE_MASK);

	admin_command(input, 32, VIRTIO14_ADMIN_CMD_LIST_USE,
	    VIRTIO14_ADMIN_GROUP_SELF);
	le64enc(input + 16, UINT64_MAX);
	le64enc(input + 24, ADMIN_BASE_MASK);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, 32, output, 8,
	    &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);
	virtio_admin_owner_destroy(owner);
}

ATF_TC_WITHOUT_HEAD(success_qualifier_is_zero);
ATF_TC_BODY(success_qualifier_is_zero, tc)
{
	struct virtio_admin_owner *owner;
	uint8_t input[32], output[8];
	size_t written;
	const uint64_t commands = ADMIN_BASE_MASK | (UINT64_C(1) << 7);

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	ATF_REQUIRE_EQ(virtio_admin_owner_register_command(owner, 7,
	    successful_command_with_bad_qualifier, NULL), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_USE,
	    VIRTIO14_ADMIN_GROUP_SELF);
	le64enc(input + 24, commands);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, sizeof(input), output,
	    sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);

	admin_command(input, 24, 7, VIRTIO14_ADMIN_GROUP_SELF);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, 24, output,
	    sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);
	virtio_admin_owner_destroy(owner);
}

ATF_TC_WITHOUT_HEAD(list_use_validation);
ATF_TC_BODY(list_use_validation, tc)
{
	struct virtio_admin_owner *owner;
	uint8_t input[40], output[8], state[ADMIN_STATE_SIZE];
	size_t written;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	ATF_REQUIRE_EQ(virtio_admin_snapshot(owner, state, sizeof(state)), 0);
	ATF_CHECK_EQ(le64dec(state + 8), ADMIN_BASE_MASK);
	admin_command(input, 24, VIRTIO14_ADMIN_CMD_LIST_USE,
	    VIRTIO14_ADMIN_GROUP_SELF);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, 24, output,
	    sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);
	ATF_REQUIRE_EQ(virtio_admin_snapshot(owner, state, sizeof(state)), 0);
	ATF_CHECK_EQ(le64dec(state + 8), 0);
	admin_command(input, 24, VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, 24, output,
	    sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_EINVAL,
	    VIRTIO14_ADMIN_QUALIFIER_INVALID_OPCODE);
	virtio_admin_owner_reset(owner);

	admin_command(input, 32, VIRTIO14_ADMIN_CMD_LIST_USE,
	    VIRTIO14_ADMIN_GROUP_SELF);
	le64enc(input + 24, UINT64_C(1) <<
	    VIRTIO14_ADMIN_CMD_LIST_USE);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, 32, output,
	    sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);
	ATF_REQUIRE_EQ(virtio_admin_snapshot(owner, state, sizeof(state)), 0);
	ATF_CHECK_EQ(le64dec(state + 8), UINT64_C(1) <<
	    VIRTIO14_ADMIN_CMD_LIST_USE);

	le64enc(input + 24, ADMIN_BASE_MASK | (UINT64_C(1) << 7));
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, 32, output,
	    sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_EINVAL,
	    VIRTIO14_ADMIN_QUALIFIER_INVALID_FIELD);

	/*
	 * Command-specific extensions are byte-granular, but bytes beyond the
	 * specified LIST_USE bitmap are ignored even when nonzero.
	 */
	admin_command(input, 33, VIRTIO14_ADMIN_CMD_LIST_USE,
	    VIRTIO14_ADMIN_GROUP_SELF);
	le64enc(input + 24, ADMIN_BASE_MASK);
	input[32] = 0;
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, 33, output,
	    sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);
	input[32] = 1;
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, 33, output,
	    sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);

	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_USE,
	    VIRTIO14_ADMIN_GROUP_SELF);
	le64enc(input + 24, ADMIN_BASE_MASK);
	le64enc(input + 32, 1);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, sizeof(input),
	    output, sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);

	le64enc(input + 32, 0);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, sizeof(input),
	    output, sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);
	ATF_REQUIRE_EQ(virtio_admin_snapshot(owner, state, sizeof(state)), 0);
	ATF_CHECK_EQ(le64dec(state + 8), ADMIN_BASE_MASK);
	ATF_CHECK_EQ(le64dec(state + 16), 7);

	virtio_admin_owner_reset(owner);
	ATF_REQUIRE_EQ(virtio_admin_snapshot(owner, state, sizeof(state)), 0);
	ATF_CHECK_EQ(le64dec(state + 8), ADMIN_BASE_MASK);
	ATF_CHECK_EQ(le64dec(state + 16), 8);
	virtio_admin_owner_destroy(owner);
}

ATF_TC_WITHOUT_HEAD(portable_transactional_state);
ATF_TC_BODY(portable_transactional_state, tc)
{
	struct virtio_admin_owner *source, *target;
	struct virtio_admin_owner **owners_alias;
	struct virtio_admin_owner *owners[2];
	const void **buffers_alias;
	const void *buffers[2];
	uint8_t input[32], output[8], state[ADMIN_STATE_SIZE];
	uint8_t corrupt[ADMIN_STATE_SIZE], before[ADMIN_STATE_SIZE];
	size_t written;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&source), 0);
	ATF_REQUIRE_EQ(virtio_admin_owner_create(&target), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_USE,
	    VIRTIO14_ADMIN_GROUP_SELF);
	le64enc(input + 24, ADMIN_BASE_MASK);
	ATF_REQUIRE_EQ(virtio_admin_process(source, input, sizeof(input),
	    output, sizeof(output), &written), 0);
	ATF_CHECK_EQ(virtio_admin_snapshot(source, source, sizeof(state)),
	    EINVAL);
	ATF_CHECK_EQ(virtio_admin_restore_validate(source, source,
	    sizeof(state)), EINVAL);
	ATF_CHECK_EQ(virtio_admin_restore(source, source, sizeof(state)),
	    EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_snapshot(source, state, sizeof(state)), 0);
	/*
	 * Restore keeps both pointer vectors live until after publication.  A
	 * vector embedded in the destination would otherwise be overwritten by
	 * that publication and could turn the ordered unlock into a bad-pointer
	 * dereference.
	 */
	owners_alias = (void *)&target->used_commands;
	owners_alias[0] = target;
	buffers[0] = state;
	ATF_CHECK_EQ(virtio_admin_restore_many(owners_alias, buffers, 1,
	    sizeof(state)), EINVAL);
	buffers_alias = (void *)&target->generation;
	buffers_alias[0] = state;
	owners[0] = target;
	ATF_CHECK_EQ(virtio_admin_restore_many(owners, buffers_alias, 1,
	    sizeof(state)), EINVAL);
	virtio_admin_owner_destroy(target);
	ATF_REQUIRE_EQ(virtio_admin_owner_create(&target), 0);
	owners[0] = source;
	owners[1] = target;
	buffers[0] = target;
	buffers[1] = state;
	ATF_CHECK_EQ(virtio_admin_restore_many(owners, buffers,
	    nitems(owners), sizeof(state)), EINVAL);
	buffers[0] = state;
	buffers[1] = source;
	ATF_CHECK_EQ(virtio_admin_restore_many(owners, buffers,
	    nitems(owners), sizeof(state)), EINVAL);
	ATF_CHECK_EQ(le32dec(state), ADMIN_STATE_MAGIC);
	ATF_CHECK_EQ(le16dec(state + 4), ADMIN_STATE_VERSION);
	ATF_CHECK_EQ(le16dec(state + 6), ADMIN_STATE_SIZE);
	ATF_CHECK_EQ(le64dec(state + ADMIN_STATE_DIGEST_OFF),
	    state_digest(state, sizeof(state)));
	ATF_CHECK_EQ(virtio_admin_snapshot(source, state,
	    sizeof(state) - 1), EMSGSIZE);
	ATF_CHECK_EQ(virtio_admin_restore(target, state,
	    sizeof(state) - 1), EMSGSIZE);

	ATF_REQUIRE_EQ(virtio_admin_snapshot(target, before, sizeof(before)),
	    0);
	for (size_t offset = 0; offset <= 24; offset += 8) {
		memcpy(corrupt, state, sizeof(corrupt));
		corrupt[offset] ^= 0x80;
		ATF_CHECK_EQ(virtio_admin_restore(target, corrupt,
		    sizeof(corrupt)), EPROTO);
	}
	memcpy(corrupt, state, sizeof(corrupt));
	le64enc(corrupt + 8, UINT64_C(1) << 7);
	le64enc(corrupt + ADMIN_STATE_DIGEST_OFF,
	    state_digest(corrupt, sizeof(corrupt)));
	ATF_CHECK_EQ(virtio_admin_restore(target, corrupt,
	    sizeof(corrupt)), ENOTSUP);
	ATF_REQUIRE_EQ(virtio_admin_snapshot(target, corrupt,
	    sizeof(corrupt)), 0);
	ATF_CHECK_EQ(memcmp(before, corrupt, sizeof(before)), 0);

	ATF_REQUIRE_EQ(virtio_admin_restore(target, state, sizeof(state)), 0);
	ATF_REQUIRE_EQ(virtio_admin_snapshot(target, corrupt,
	    sizeof(corrupt)), 0);
	ATF_CHECK_EQ(memcmp(state, corrupt, sizeof(state)), 0);
	virtio_admin_owner_destroy(target);
	virtio_admin_owner_destroy(source);
}

ATF_TC_WITHOUT_HEAD(registered_command_dispatch);
ATF_TC_BODY(registered_command_dispatch, tc)
{
	struct registered_command_context context;
	struct virtio_admin_owner *owner;
	uint8_t input[32], output[16], state[ADMIN_STATE_SIZE];
	size_t written;
	const uint64_t supported = ADMIN_BASE_MASK | (UINT64_C(1) << 7);

	memset(&context, 0, sizeof(context));
	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	ATF_CHECK_EQ(virtio_admin_owner_register_command(owner, 0,
	    registered_command, &context), EINVAL);
	ATF_CHECK_EQ(virtio_admin_owner_register_command(owner,
	    VIRTIO14_ADMIN_CMD_RESERVED_0012, registered_command, &context),
	    EINVAL);
	ATF_CHECK_EQ(virtio_admin_owner_register_command(owner, 64,
	    registered_command, &context), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_owner_register_command(owner, 7,
	    registered_command, &context), 0);
	ATF_CHECK_EQ(virtio_admin_owner_register_command(owner, 7,
	    registered_command, &context), EEXIST);

	admin_command(input, 24, VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, 24, output,
	    sizeof(output), &written), 0);
	ATF_CHECK_EQ(written, sizeof(output));
	ATF_CHECK_EQ(le64dec(output + 8), supported);

	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_USE,
	    VIRTIO14_ADMIN_GROUP_SELF);
	le64enc(input + 24, supported);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, sizeof(input),
	    output, 8, &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);

	admin_command(input, sizeof(input), 7, VIRTIO14_ADMIN_GROUP_SELF);
	le64enc(input + 24, UINT64_C(0x0102030405060708));
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, sizeof(input),
	    output, sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);
	ATF_CHECK_EQ(written, sizeof(output));
	ATF_CHECK_EQ(le64dec(output + 8), UINT64_C(0x8877665544332211));
	ATF_CHECK_EQ(context.calls, 1);
	ATF_CHECK_EQ(context.member, 0);
	ATF_CHECK_EQ(context.input_length, 8);

	le64enc(input + 16, 1);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, sizeof(input),
	    output, sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_EINVAL,
	    VIRTIO14_ADMIN_QUALIFIER_INVALID_MEMBER);
	ATF_CHECK_EQ(written, 8);

	ATF_REQUIRE_EQ(virtio_admin_snapshot(owner, state, sizeof(state)), 0);
	virtio_admin_owner_destroy(owner);
	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	ATF_CHECK_EQ(virtio_admin_restore(owner, state, sizeof(state)),
	    ENOTSUP);
	ATF_REQUIRE_EQ(virtio_admin_owner_register_command(owner, 7,
	    registered_command, &context), 0);
	ATF_CHECK_EQ(virtio_admin_restore(owner, state, sizeof(state)), 0);
	virtio_admin_owner_destroy(owner);
}

ATF_TC_WITHOUT_HEAD(owner_seal_is_permanent);
ATF_TC_BODY(owner_seal_is_permanent, tc)
{
	struct registered_command_context context;
	struct virtio_admin_owner *owner;
	uint8_t input[VIRTIO14_ADMIN_HEADER_SIZE];
	uint8_t output[VIRTIO14_ADMIN_RESULT_HEADER_SIZE +
	    VIRTIO14_ADMIN_LIST_SIZE];
	size_t written;

	memset(&context, 0, sizeof(context));
	ATF_CHECK_EQ(virtio_admin_owner_seal(NULL), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	ATF_REQUIRE_EQ(virtio_admin_owner_register_command(owner, 7,
	    registered_command, &context), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	ATF_REQUIRE_EQ(virtio_admin_process(owner, input, sizeof(input), output,
	    sizeof(output), &written), 0);
	ATF_REQUIRE_EQ(virtio_admin_owner_seal(owner), 0);
	ATF_REQUIRE_EQ(virtio_admin_owner_seal(owner), 0);
	ATF_CHECK_EQ(virtio_admin_owner_register_command(owner, 8,
	    registered_command, &context), EBUSY);
	virtio_admin_owner_destroy(owner);
}

struct concurrent_context {
	struct virtio_admin_owner *owner;
	unsigned int iterations;
};

static void *
query_thread(void *arg)
{
	struct concurrent_context *context;
	uint8_t input[24], output[16];
	size_t written;

	context = arg;
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	for (unsigned int i = 0; i < context->iterations; i++) {
		if (virtio_admin_process(context->owner, input, sizeof(input),
		    output, sizeof(output), &written) != 0 ||
		    written != sizeof(output) ||
		    le64dec(output + 8) != ADMIN_BASE_MASK)
			return ((void *)(uintptr_t)1);
	}
	return (NULL);
}

static void *
use_thread(void *arg)
{
	struct concurrent_context *context;
	uint8_t input[32], output[8];
	size_t written;

	context = arg;
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_USE,
	    VIRTIO14_ADMIN_GROUP_SELF);
	le64enc(input + 24, ADMIN_BASE_MASK);
	for (unsigned int i = 0; i < context->iterations; i++) {
		if (virtio_admin_process(context->owner, input, sizeof(input),
		    output, sizeof(output), &written) != 0 ||
		    written != sizeof(output) ||
		    le16dec(output) != VIRTIO14_ADMIN_STATUS_OK)
			return ((void *)(uintptr_t)1);
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(concurrent_command_serialization);
ATF_TC_BODY(concurrent_command_serialization, tc)
{
	struct concurrent_context context;
	struct virtio_admin_owner *owner;
	pthread_t query, use;
	void *query_result, *use_result;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	context.owner = owner;
	context.iterations = 10000;
	ATF_REQUIRE_EQ(pthread_create(&query, NULL, query_thread, &context), 0);
	ATF_REQUIRE_EQ(pthread_create(&use, NULL, use_thread, &context), 0);
	ATF_REQUIRE_EQ(pthread_join(query, &query_result), 0);
	ATF_REQUIRE_EQ(pthread_join(use, &use_result), 0);
	ATF_CHECK_EQ(query_result, NULL);
	ATF_CHECK_EQ(use_result, NULL);
	virtio_admin_owner_destroy(owner);
}

struct reset_drain_context {
	struct virtio_admin_owner *owner;
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	bool entered;
	bool release;
	bool completed;
};

static void
blocking_command(void *argument, uint64_t member __unused,
    const void *input __unused, size_t input_length __unused,
    void *output __unused, size_t output_length __unused,
    struct virtio_admin_command_result *result __unused)
{
	struct reset_drain_context *context;

	context = argument;
	pthread_mutex_lock(&context->mutex);
	context->entered = true;
	pthread_cond_broadcast(&context->condition);
	while (!context->release)
		pthread_cond_wait(&context->condition, &context->mutex);
	pthread_mutex_unlock(&context->mutex);
}

static void *
blocking_command_thread(void *argument)
{
	struct reset_drain_context *context;
	uint8_t input[24], output[8];
	size_t written;
	int error;

	context = argument;
	admin_command(input, sizeof(input), 7, VIRTIO14_ADMIN_GROUP_SELF);
	error = virtio_admin_process(context->owner, input, sizeof(input),
	    output, sizeof(output), &written);
	return ((void *)(uintptr_t)(error != 0 || written != sizeof(output)));
}

static void *
owner_reset_thread(void *argument)
{
	struct reset_drain_context *context;

	context = argument;
	virtio_admin_owner_reset(context->owner);
	pthread_mutex_lock(&context->mutex);
	context->completed = true;
	pthread_cond_broadcast(&context->condition);
	pthread_mutex_unlock(&context->mutex);
	return (NULL);
}

static void *
owner_destroy_thread(void *argument)
{
	struct reset_drain_context *context;

	context = argument;
	pthread_mutex_lock(&context->mutex);
	context->completed = false;
	pthread_cond_broadcast(&context->condition);
	pthread_mutex_unlock(&context->mutex);
	virtio_admin_owner_destroy(context->owner);
	pthread_mutex_lock(&context->mutex);
	context->completed = true;
	pthread_cond_broadcast(&context->condition);
	pthread_mutex_unlock(&context->mutex);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(reset_drains_active_command);
ATF_TC_BODY(reset_drains_active_command, tc)
{
	struct reset_drain_context context = { 0 };
	pthread_t command_thread, reset_thread;
	uint8_t input[32], output[8], state[ADMIN_STATE_SIZE];
	void *command_result;
	size_t written;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&context.owner), 0);
	ATF_REQUIRE_EQ(pthread_mutex_init(&context.mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&context.condition, NULL), 0);
	ATF_REQUIRE_EQ(virtio_admin_owner_register_command(context.owner, 7,
	    blocking_command, &context), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_USE,
	    VIRTIO14_ADMIN_GROUP_SELF);
	le64enc(input + VIRTIO14_ADMIN_HEADER_SIZE,
	    ADMIN_BASE_MASK | (UINT64_C(1) << 7));
	ATF_REQUIRE_EQ(virtio_admin_process(context.owner, input,
	    sizeof(input), output, sizeof(output), &written), 0);
	ATF_REQUIRE_EQ(le16dec(output), VIRTIO14_ADMIN_STATUS_OK);
	ATF_REQUIRE_EQ(virtio_admin_snapshot(context.owner, state,
	    sizeof(state)), 0);

	ATF_REQUIRE_EQ(pthread_create(&command_thread, NULL,
	    blocking_command_thread, &context), 0);
	pthread_mutex_lock(&context.mutex);
	while (!context.entered)
		pthread_cond_wait(&context.condition, &context.mutex);
	pthread_mutex_unlock(&context.mutex);

	ATF_REQUIRE_EQ(pthread_create(&reset_thread, NULL, owner_reset_thread,
	    &context), 0);
	pthread_mutex_lock(&context.owner->mutex);
	while (!context.owner->resetting)
		pthread_cond_wait(&context.owner->quiesced,
		    &context.owner->mutex);
	pthread_mutex_unlock(&context.owner->mutex);

	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	ATF_REQUIRE_EQ(virtio_admin_process(context.owner, input,
	    sizeof(input), output, sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_EAGAIN,
	    VIRTIO14_ADMIN_QUALIFIER_TRYAGAIN);
	admin_command(input, sizeof(input), 63,
	    VIRTIO14_ADMIN_GROUP_SELF);
	ATF_REQUIRE_EQ(virtio_admin_process(context.owner, input,
	    sizeof(input), output, sizeof(output), &written), 0);
	check_result(output, VIRTIO14_ADMIN_STATUS_EAGAIN,
	    VIRTIO14_ADMIN_QUALIFIER_TRYAGAIN);
	ATF_CHECK_EQ(virtio_admin_snapshot(context.owner, state,
	    sizeof(state)), EBUSY);
	ATF_CHECK_EQ(virtio_admin_restore(context.owner, state,
	    sizeof(state)), EBUSY);

	pthread_mutex_lock(&context.mutex);
	ATF_CHECK(!context.completed);
	context.release = true;
	pthread_cond_broadcast(&context.condition);
	pthread_mutex_unlock(&context.mutex);

	ATF_REQUIRE_EQ(pthread_join(command_thread, &command_result), 0);
	ATF_REQUIRE_EQ(pthread_join(reset_thread, NULL), 0);
	ATF_CHECK_EQ(command_result, NULL);
	ATF_CHECK(context.completed);
	ATF_CHECK_EQ(context.owner->active_commands, 0);
	ATF_CHECK(!context.owner->resetting);
	/* LIST_USE creates generation one; the drained reset creates two. */
	ATF_CHECK_EQ(context.owner->generation, 2);

	pthread_cond_destroy(&context.condition);
	pthread_mutex_destroy(&context.mutex);
	virtio_admin_owner_destroy(context.owner);
}

ATF_TC_WITHOUT_HEAD(destroy_drains_active_command);
ATF_TC_BODY(destroy_drains_active_command, tc)
{
	struct reset_drain_context context = { 0 };
	pthread_t command_thread, destroy_thread;
	uint8_t input[32], output[8];
	void *command_result;
	size_t written;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&context.owner), 0);
	ATF_REQUIRE_EQ(pthread_mutex_init(&context.mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&context.condition, NULL), 0);
	ATF_REQUIRE_EQ(virtio_admin_owner_register_command(context.owner, 7,
	    blocking_command, &context), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_USE,
	    VIRTIO14_ADMIN_GROUP_SELF);
	le64enc(input + VIRTIO14_ADMIN_HEADER_SIZE,
	    ADMIN_BASE_MASK | (UINT64_C(1) << 7));
	ATF_REQUIRE_EQ(virtio_admin_process(context.owner, input,
	    sizeof(input), output, sizeof(output), &written), 0);
	ATF_REQUIRE_EQ(le16dec(output), VIRTIO14_ADMIN_STATUS_OK);

	ATF_REQUIRE_EQ(pthread_create(&command_thread, NULL,
	    blocking_command_thread, &context), 0);
	pthread_mutex_lock(&context.mutex);
	while (!context.entered)
		pthread_cond_wait(&context.condition, &context.mutex);
	context.completed = true;
	pthread_mutex_unlock(&context.mutex);

	ATF_REQUIRE_EQ(pthread_create(&destroy_thread, NULL,
	    owner_destroy_thread, &context), 0);
	/*
	 * Do not merely race the release against owner_destroy().  The owner
	 * must first close command admission and enter its active-command
	 * drain, otherwise this test would pass even if destruction released
	 * callback storage before the dispatched handler retired.
	 */
	pthread_mutex_lock(&context.owner->mutex);
	while (!context.owner->resetting)
		pthread_cond_wait(&context.owner->quiesced,
		    &context.owner->mutex);
	pthread_mutex_unlock(&context.owner->mutex);
	pthread_mutex_lock(&context.mutex);
	while (context.completed)
		pthread_cond_wait(&context.condition, &context.mutex);
	ATF_CHECK(!context.completed);
	context.release = true;
	pthread_cond_broadcast(&context.condition);
	pthread_mutex_unlock(&context.mutex);

	ATF_REQUIRE_EQ(pthread_join(command_thread, &command_result), 0);
	ATF_REQUIRE_EQ(pthread_join(destroy_thread, NULL), 0);
	ATF_CHECK_EQ(command_result, NULL);
	ATF_CHECK(context.completed);

	pthread_cond_destroy(&context.condition);
	pthread_mutex_destroy(&context.mutex);
}

ATF_TC_WITHOUT_HEAD(fragmented_queue_adapter);
ATF_TC_BODY(fragmented_queue_adapter, tc)
{
	struct virtio_admin_owner *owner;
	struct iovec iov[6];
	uint8_t input[24], output[24], input_scratch[24], output_scratch[24];
	uint32_t used;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	memset(output, 0xa5, sizeof(output));
	iov[0] = (struct iovec){ .iov_base = input, .iov_len = 3 };
	iov[1] = (struct iovec){ .iov_base = input + 3, .iov_len = 7 };
	iov[2] = (struct iovec){ .iov_base = input + 10, .iov_len = 14 };
	iov[3] = (struct iovec){ .iov_base = output, .iov_len = 3 };
	iov[4] = (struct iovec){ .iov_base = output + 3, .iov_len = 5 };
	iov[5] = (struct iovec){ .iov_base = output + 8, .iov_len = 16 };
	ATF_REQUIRE_EQ(virtio_admin_process_iov(owner, iov, 6, 3,
	    input_scratch, sizeof(input_scratch), output_scratch,
	    sizeof(output_scratch), &used), 0);
	ATF_CHECK_EQ(used, 16);
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);
	ATF_CHECK_EQ(le64dec(output + 8), ADMIN_BASE_MASK);
	for (size_t i = 16; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0xa5);
	virtio_admin_owner_destroy(owner);
}

ATF_TC_WITHOUT_HEAD(queue_adapter_rejects_bad_chains);
ATF_TC_BODY(queue_adapter_rejects_bad_chains, tc)
{
	struct virtio_admin_owner *owner;
	struct iovec iov[2];
	uint8_t input[24], output[16], input_scratch[24], output_scratch[16];
	uint32_t used;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	memset(output, 0xa5, sizeof(output));
	iov[0] = (struct iovec){ .iov_base = input, .iov_len = sizeof(input) };
	iov[1] = (struct iovec){ .iov_base = output, .iov_len = sizeof(output) };
	ATF_CHECK_EQ(virtio_admin_process_iov(owner, iov, 2, 1,
	    input_scratch, sizeof(input_scratch) - 1, output_scratch,
	    sizeof(output_scratch), &used), EMSGSIZE);
	ATF_CHECK_EQ(used, 0);
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0xa5);
	ATF_CHECK_EQ(virtio_admin_process_iov(owner, iov, 2, 0,
	    input_scratch, sizeof(input_scratch), output_scratch,
	    sizeof(output_scratch), &used), EINVAL);
	iov[0].iov_len--;
	ATF_CHECK_EQ(virtio_admin_process_iov(owner, iov, 2, 1,
	    input_scratch, sizeof(input_scratch), output_scratch,
	    sizeof(output_scratch), &used), 0);
	ATF_CHECK_EQ(used, 16);
	iov[0].iov_len = 1;
	iov[1].iov_len = 1;
	memset(output, 0xa5, sizeof(output));
	ATF_CHECK_EQ(virtio_admin_process_iov(owner, iov, 2, 1,
	    input_scratch, sizeof(input_scratch), output_scratch,
	    sizeof(output_scratch), &used), 0);
	ATF_CHECK_EQ(used, 1);
	ATF_CHECK_EQ(output[0], 0);
	ATF_CHECK_EQ(output[1], 0xa5);
	iov[0].iov_len = 0;
	ATF_CHECK_EQ(virtio_admin_process_iov(owner, iov, 2, 1,
	    input_scratch, sizeof(input_scratch), output_scratch,
	    sizeof(output_scratch), &used), EINVAL);
	ATF_CHECK_EQ(used, 0);
	iov[0].iov_len = sizeof(input);
	iov[1].iov_len = sizeof(output);
	iov[1].iov_base = NULL;
	ATF_CHECK_EQ(virtio_admin_process_iov(owner, iov, 2, 1,
	    input_scratch, sizeof(input_scratch), output_scratch,
	    sizeof(output_scratch), &used), EFAULT);
	virtio_admin_owner_destroy(owner);
}

ATF_TC_WITHOUT_HEAD(queue_adapter_allows_empty_iov_segments);
ATF_TC_BODY(queue_adapter_allows_empty_iov_segments, tc)
{
	struct virtio_admin_owner *owner;
	struct iovec iov[6];
	uint8_t input[24], output[16], input_scratch[24], output_scratch[16];
	uint32_t used;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	memset(output, 0xa5, sizeof(output));
	iov[0] = (struct iovec){ .iov_base = NULL, .iov_len = 0 };
	iov[1] = (struct iovec){ .iov_base = input, .iov_len = sizeof(input) };
	iov[2] = (struct iovec){ .iov_base = NULL, .iov_len = 0 };
	iov[3] = (struct iovec){ .iov_base = NULL, .iov_len = 0 };
	iov[4] = (struct iovec){ .iov_base = output,
	    .iov_len = sizeof(output) };
	iov[5] = (struct iovec){ .iov_base = NULL, .iov_len = 0 };
	ATF_REQUIRE_EQ(virtio_admin_process_iov(owner, iov, nitems(iov), 3,
	    input_scratch, sizeof(input_scratch), output_scratch,
	    sizeof(output_scratch), &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);
	ATF_CHECK_EQ(le64dec(output + 8), ADMIN_BASE_MASK);
	virtio_admin_owner_destroy(owner);
}

ATF_TC_WITHOUT_HEAD(queue_adapter_rejects_aliases_transactionally);
ATF_TC_BODY(queue_adapter_rejects_aliases_transactionally, tc)
{
	struct virtio_admin_owner *owner;
	struct iovec iov[3];
	uint8_t input[24], output[16], before[16];
	uint8_t input_scratch[24], output_scratch[16];
	uint32_t used;

	ATF_REQUIRE_EQ(virtio_admin_owner_create(&owner), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	memset(output, 0xa5, sizeof(output));
	memcpy(before, output, sizeof(before));
	iov[0] = (struct iovec){ .iov_base = input, .iov_len = sizeof(input) };
	iov[1] = (struct iovec){ .iov_base = output, .iov_len = 8 };
	iov[2] = (struct iovec){ .iov_base = output + 8, .iov_len = 8 };

	used = UINT32_C(0x11223344);
	ATF_CHECK_EQ(virtio_admin_process_iov(owner, iov, nitems(iov), 1,
	    input_scratch, sizeof(input_scratch), output,
	    sizeof(output_scratch), &used), EINVAL);
	ATF_CHECK_EQ(used, UINT32_C(0x11223344));
	ATF_CHECK_EQ(memcmp(output, before, sizeof(output)), 0);

	used = UINT32_C(0x55667788);
	ATF_CHECK_EQ(virtio_admin_process_iov(owner, iov, nitems(iov), 1,
	    input_scratch, sizeof(input_scratch), output_scratch,
	    sizeof(output_scratch), (uint32_t *)output), EINVAL);
	ATF_CHECK_EQ(memcmp(output, before, sizeof(output)), 0);

	iov[2].iov_base = output + 4;
	used = UINT32_C(0x99aabbcc);
	ATF_CHECK_EQ(virtio_admin_process_iov(owner, iov, nitems(iov), 1,
	    input_scratch, sizeof(input_scratch), output_scratch,
	    sizeof(output_scratch), &used), EINVAL);
	ATF_CHECK_EQ(used, UINT32_C(0x99aabbcc));
	ATF_CHECK_EQ(memcmp(output, before, sizeof(output)), 0);

	iov[2].iov_base = output + 8;
	used = 99;
	ATF_REQUIRE_EQ(virtio_admin_process_iov(owner, iov, nitems(iov), 1,
	    input_scratch, sizeof(input_scratch), output_scratch,
	    sizeof(output_scratch), &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);
	virtio_admin_owner_destroy(owner);
}

static bool
bank_group_available(void *argument __unused)
{

	return (true);
}

static bool
bank_group_member(void *argument __unused, uint64_t member)
{

	return (member == 0);
}

static int
bank_fixture_create(struct virtio_admin_group_fabric **fabricp,
    struct virtio_admin_owner **ownerp, struct virtio_admin_queue_bank **bankp,
    uint16_t queues)
{
	const struct virtio_admin_group_config config = {
		.group_type = VIRTIO14_ADMIN_GROUP_SELF,
		.available = bank_group_available,
		.member_valid = bank_group_member,
	};
	int error;

	error = virtio_admin_group_fabric_create(fabricp);
	if (error != 0)
		return (error);
	error = virtio_admin_group_register(*fabricp, &config, ownerp);
	if (error != 0) {
		virtio_admin_group_fabric_destroy(*fabricp);
		return (error);
	}
	error = virtio_admin_queue_bank_create(bankp, *fabricp, queues, 64, 64);
	if (error != 0)
		virtio_admin_group_fabric_destroy(*fabricp);
	return (error);
}

ATF_TC_WITHOUT_HEAD(pci_admin_queue_range_contract);
ATF_TC_BODY(pci_admin_queue_range_contract, tc)
{

	/* Literal boundaries from VirtIO 1.4 section 4.1.4.3.1. */
	ATF_CHECK(virtio_admin_pci_queue_range_valid(0, 0, 1));
	ATF_CHECK(virtio_admin_pci_queue_range_valid(3, 3, 1));
	ATF_CHECK(virtio_admin_pci_queue_range_valid(3, 4, 2));
	ATF_CHECK(virtio_admin_pci_queue_range_valid(65535, 65535, 1));
	ATF_CHECK(!virtio_admin_pci_queue_range_valid(3, 2, 1));
	ATF_CHECK(!virtio_admin_pci_queue_range_valid(3, 3, 0));
	ATF_CHECK(!virtio_admin_pci_queue_range_valid(65535, 65535, 2));
	ATF_CHECK(!virtio_admin_pci_queue_range_valid(65536, 65535, 1));
	ATF_CHECK(!virtio_admin_pci_queue_range_valid(0, 65536, 1));
	ATF_CHECK(!virtio_admin_pci_queue_range_valid(0, 0, 65536));
}

ATF_TC_WITHOUT_HEAD(pci_admin_queue_namespace_contract);
ATF_TC_BODY(pci_admin_queue_namespace_contract, tc)
{
	struct virtio_admin_pci_queue_namespace name_space, unchanged;
	uint16_t local;

	memset(&name_space, 0xa5, sizeof(name_space));
	unchanged = name_space;
	ATF_CHECK_EQ(virtio_admin_pci_queue_namespace_init(&name_space,
	    3, 4, 2), 0);
	ATF_CHECK_EQ(name_space.ordinary_count, 3);
	ATF_CHECK_EQ(name_space.admin_index, 4);
	ATF_CHECK_EQ(name_space.admin_count, 2);

	local = 0xbeef;
	ATF_CHECK_EQ(virtio_admin_pci_queue_resolve(&name_space, 0, &local),
	    VIRTIO_ADMIN_PCI_QUEUE_ORDINARY);
	ATF_CHECK_EQ(local, 0);
	ATF_CHECK_EQ(virtio_admin_pci_queue_resolve(&name_space, 2, &local),
	    VIRTIO_ADMIN_PCI_QUEUE_ORDINARY);
	ATF_CHECK_EQ(local, 2);

	local = 0xbeef;
	ATF_CHECK_EQ(virtio_admin_pci_queue_resolve(&name_space, 3, &local),
	    VIRTIO_ADMIN_PCI_QUEUE_UNAVAILABLE);
	ATF_CHECK_EQ(local, 0xbeef);
	ATF_CHECK_EQ(virtio_admin_pci_queue_resolve(&name_space, 4, &local),
	    VIRTIO_ADMIN_PCI_QUEUE_ADMIN);
	ATF_CHECK_EQ(local, 0);
	ATF_CHECK_EQ(virtio_admin_pci_queue_resolve(&name_space, 5, &local),
	    VIRTIO_ADMIN_PCI_QUEUE_ADMIN);
	ATF_CHECK_EQ(local, 1);

	local = 0xbeef;
	ATF_CHECK_EQ(virtio_admin_pci_queue_resolve(&name_space, 6, &local),
	    VIRTIO_ADMIN_PCI_QUEUE_UNAVAILABLE);
	ATF_CHECK_EQ(local, 0xbeef);
	ATF_CHECK_EQ(virtio_admin_pci_queue_resolve(&name_space, 65536,
	    &local), VIRTIO_ADMIN_PCI_QUEUE_UNAVAILABLE);
	ATF_CHECK_EQ(local, 0xbeef);
	ATF_CHECK_EQ(virtio_admin_pci_queue_resolve(NULL, 0, &local),
	    VIRTIO_ADMIN_PCI_QUEUE_UNAVAILABLE);
	ATF_CHECK_EQ(virtio_admin_pci_queue_resolve(&name_space, 0, NULL),
	    VIRTIO_ADMIN_PCI_QUEUE_UNAVAILABLE);

	name_space = unchanged;
	ATF_CHECK_EQ(virtio_admin_pci_queue_namespace_init(&name_space,
	    3, 2, 1), EINVAL);
	ATF_CHECK_EQ(memcmp(&name_space, &unchanged, sizeof(name_space)), 0);
	ATF_CHECK_EQ(virtio_admin_pci_queue_namespace_init(NULL, 0, 0, 1),
	    EINVAL);

	ATF_REQUIRE_EQ(virtio_admin_pci_queue_namespace_init(&name_space,
	    65535, 65535, 1), 0);
	ATF_CHECK_EQ(virtio_admin_pci_queue_resolve(&name_space, 65534,
	    &local), VIRTIO_ADMIN_PCI_QUEUE_ORDINARY);
	ATF_CHECK_EQ(local, 65534);
	ATF_CHECK_EQ(virtio_admin_pci_queue_resolve(&name_space, 65535,
	    &local), VIRTIO_ADMIN_PCI_QUEUE_ADMIN);
	ATF_CHECK_EQ(local, 0);
}

static int
bank_process(struct virtio_admin_queue_bank *bank, uint16_t queue,
    uint8_t *input, size_t input_length, uint8_t *output,
    size_t output_length, uint32_t *used)
{
	struct iovec iov[2];

	iov[0] = (struct iovec) {
		.iov_base = input,
		.iov_len = input_length,
	};
	iov[1] = (struct iovec) {
		.iov_base = output,
		.iov_len = output_length,
	};
	return (virtio_admin_queue_bank_process(bank, queue, iov, nitems(iov),
	    1, used));
}

ATF_TC_WITHOUT_HEAD(pci_admin_controller_self_group);
ATF_TC_BODY(pci_admin_controller_self_group, tc)
{
	struct virtio_admin_pci_controller *controller;
	const struct virtio_admin_pci_queue_namespace *name_space;
	struct virtio_admin_queue_bank *bank;
	uint8_t input[VIRTIO14_ADMIN_HEADER_SIZE];
	uint8_t output[VIRTIO14_ADMIN_RESULT_HEADER_SIZE +
	    VIRTIO14_ADMIN_LIST_SIZE];
	uint32_t used;

	controller = (void *)(uintptr_t)1;
	ATF_CHECK_EQ(virtio_admin_pci_controller_create(&controller,
	    3, 2, 1, 64, 64), EINVAL);
	ATF_CHECK_EQ(controller, NULL);
	ATF_CHECK_EQ(virtio_admin_pci_controller_create(NULL,
	    3, 3, 1, 64, 64), EINVAL);

	ATF_REQUIRE_EQ(virtio_admin_pci_controller_create(&controller,
	    3, 4, 2, 64, 64), 0);
	name_space = virtio_admin_pci_controller_namespace(controller);
	ATF_REQUIRE(name_space != NULL);
	ATF_CHECK_EQ(name_space->ordinary_count, 3);
	ATF_CHECK_EQ(name_space->admin_index, 4);
	ATF_CHECK_EQ(name_space->admin_count, 2);
	ATF_REQUIRE(virtio_admin_pci_controller_self_owner(controller) != NULL);
	bank = virtio_admin_pci_controller_queue_bank(controller);
	ATF_REQUIRE(bank != NULL);
	ATF_CHECK_EQ(virtio_admin_queue_bank_count(bank), 2);

	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	memset(output, 0xa5, sizeof(output));
	ATF_REQUIRE_EQ(bank_process(bank, 1, input, sizeof(input), output,
	    sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);
	ATF_CHECK_EQ(le64dec(output + VIRTIO14_ADMIN_RESULT_HEADER_SIZE),
	    ADMIN_BASE_MASK);
	memset(output, 0xa5, sizeof(output));
	ATF_REQUIRE_EQ(virtio_admin_pci_controller_process(controller, 5,
	    (struct iovec[]) {
		{ .iov_base = input, .iov_len = sizeof(input) },
		{ .iov_base = output, .iov_len = sizeof(output) },
	    }, 2, 1, &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);
	ATF_CHECK_EQ(virtio_admin_pci_controller_process(controller, 0,
	    NULL, 0, 0, &used), ENOENT);
	ATF_CHECK_EQ(virtio_admin_pci_controller_process(controller, 3,
	    NULL, 0, 0, &used), ENOENT);
	ATF_CHECK_EQ(virtio_admin_pci_controller_process(controller, 6,
	    NULL, 0, 0, &used), ENOENT);
	ATF_CHECK_EQ(virtio_admin_pci_controller_process(NULL, 5,
	    NULL, 0, 0, &used), EINVAL);
	ATF_CHECK_EQ(virtio_admin_pci_controller_drain_queue(controller, 4),
	    0);
	ATF_CHECK_EQ(virtio_admin_pci_controller_drain_queue(controller, 0),
	    ENOENT);
	ATF_CHECK_EQ(virtio_admin_pci_controller_drain_queue(NULL, 4), EINVAL);
	virtio_admin_pci_controller_reset(controller);
	virtio_admin_pci_controller_reset(NULL);

	virtio_admin_pci_controller_destroy(controller);
	virtio_admin_pci_controller_destroy(NULL);
	ATF_CHECK_EQ(virtio_admin_pci_controller_namespace(NULL), NULL);
	ATF_CHECK_EQ(virtio_admin_pci_controller_self_owner(NULL), NULL);
	ATF_CHECK_EQ(virtio_admin_pci_controller_queue_bank(NULL), NULL);
}

ATF_TC_WITHOUT_HEAD(pci_admin_controller_portable_state);
ATF_TC_WITHOUT_HEAD(pci_admin_controller_sriov_topology);
ATF_TC_BODY(pci_admin_controller_sriov_topology, tc)
{
	struct virtio_admin_pci_controller *controller;
	struct virtio_admin_owner *sriov_owner;
	struct virtio_admin_sriov_lifecycle *lifecycle;
	struct virtio_admin_group_config config;
	uint8_t input[VIRTIO14_ADMIN_HEADER_SIZE];
	uint8_t output[VIRTIO14_ADMIN_RESULT_HEADER_SIZE +
	    VIRTIO14_ADMIN_LIST_SIZE];
	struct iovec iov[2];
	uint32_t used;

	ATF_REQUIRE_EQ(virtio_admin_sriov_lifecycle_create(&lifecycle), 0);
	ATF_REQUIRE_EQ(virtio_admin_sriov_lifecycle_update(lifecycle, true,
	    true, false, 4), 0);
	config = (struct virtio_admin_group_config) {
		.group_type = VIRTIO14_ADMIN_GROUP_SRIOV,
		.available = virtio_admin_sriov_group_available,
		.member_valid = virtio_admin_sriov_member_valid,
		.begin = virtio_admin_sriov_group_begin,
		.end = virtio_admin_sriov_group_end,
		.argument = lifecycle,
	};
	ATF_REQUIRE_EQ(virtio_admin_pci_controller_create(&controller,
	    2, 4, 1, 64, 64), 0);
	ATF_CHECK_EQ(virtio_admin_pci_controller_register_group(NULL, &config,
	    &sriov_owner), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_pci_controller_register_group(controller,
	    &config, &sriov_owner), 0);
	ATF_REQUIRE(sriov_owner != NULL);
	ATF_CHECK_EQ(virtio_admin_pci_controller_seal(NULL), EINVAL);

	/* Linux probes LIST_QUERY in the SR-IOV group immediately. */
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SRIOV);
	memset(output, 0xa5, sizeof(output));
	iov[0] = (struct iovec) {
		.iov_base = input,
		.iov_len = sizeof(input),
	};
	iov[1] = (struct iovec) {
		.iov_base = output,
		.iov_len = sizeof(output),
	};
	ATF_REQUIRE_EQ(virtio_admin_pci_controller_process(controller, 4,
	    iov, nitems(iov), 1, &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);
	ATF_CHECK_EQ(le64dec(output + VIRTIO14_ADMIN_RESULT_HEADER_SIZE),
	    ADMIN_BASE_MASK);
	/* First execution seals the complete group and command topology. */
	ATF_REQUIRE_EQ(virtio_admin_pci_controller_seal(controller), 0);
	ATF_REQUIRE_EQ(virtio_admin_pci_controller_seal(controller), 0);
	ATF_CHECK_EQ(virtio_admin_pci_controller_register_group(controller,
	    &config, &sriov_owner), EBUSY);
	ATF_CHECK_EQ(virtio_admin_owner_register_command(sriov_owner, 7,
	    registered_command, NULL), EBUSY);
	virtio_admin_pci_controller_destroy(controller);
	virtio_admin_sriov_lifecycle_destroy(lifecycle);
}

ATF_TC_BODY(pci_admin_controller_portable_state, tc)
{
	struct virtio_admin_pci_controller *controller, *incompatible;
	uint8_t *before, *after, *corrupt;
	size_t state_size;

	ATF_REQUIRE_EQ(virtio_admin_pci_controller_create(&controller,
	    3, 4, 2, 64, 64), 0);
	ATF_REQUIRE_EQ(virtio_admin_pci_controller_snapshot_size(controller,
	    &state_size), 0);
	ATF_REQUIRE(state_size > PCI_CONTROLLER_STATE_HEADER_SIZE);
	before = malloc(state_size);
	after = malloc(state_size);
	corrupt = malloc(state_size);
	ATF_REQUIRE(before != NULL);
	ATF_REQUIRE(after != NULL);
	ATF_REQUIRE(corrupt != NULL);

	ATF_CHECK_EQ(virtio_admin_pci_controller_snapshot(NULL, before,
	    state_size), EINVAL);
	ATF_CHECK_EQ(virtio_admin_pci_controller_snapshot(controller, NULL,
	    state_size), EINVAL);
	memset(before, 0xa5, state_size);
	ATF_CHECK_EQ(virtio_admin_pci_controller_snapshot(controller, before,
	    state_size - 1), EMSGSIZE);
	for (size_t i = 0; i < state_size; i++)
		ATF_CHECK_EQ(before[i], 0xa5);
	ATF_CHECK_EQ(virtio_admin_pci_controller_snapshot(controller,
	    controller->bank, state_size), EINVAL);
	ATF_CHECK_EQ(virtio_admin_pci_controller_restore(controller,
	    controller->bank, state_size), EINVAL);
	ATF_CHECK_EQ(virtio_admin_pci_controller_snapshot(controller,
	    controller->bank->queues[0].input, state_size), EINVAL);
	ATF_CHECK_EQ(virtio_admin_pci_controller_restore(controller,
	    controller->bank->queues[0].input, state_size), EINVAL);

	ATF_REQUIRE_EQ(virtio_admin_pci_controller_snapshot(controller,
	    before, state_size), 0);
	ATF_CHECK_EQ(le32dec(before), PCI_CONTROLLER_STATE_MAGIC);
	ATF_CHECK_EQ(le32dec(before + 4), PCI_CONTROLLER_STATE_VERSION);
	ATF_CHECK_EQ(le16dec(before + 8), 3);
	ATF_CHECK_EQ(le16dec(before + 10), 4);
	ATF_CHECK_EQ(le16dec(before + 12), 2);
	ATF_CHECK_EQ(le16dec(before + 14), 0);
	ATF_CHECK_EQ(le64dec(before + 16),
	    state_size - PCI_CONTROLLER_STATE_HEADER_SIZE);
	ATF_CHECK_EQ(le64dec(before + PCI_CONTROLLER_STATE_DIGEST_OFF),
	    state_digest(before, state_size));
	virtio_admin_queue_bank_reset(controller->bank);
	ATF_REQUIRE_EQ(virtio_admin_pci_controller_restore(controller, before,
	    state_size), 0);
	ATF_REQUIRE_EQ(virtio_admin_pci_controller_snapshot(controller, after,
	    state_size), 0);
	ATF_CHECK_EQ(memcmp(before, after, state_size), 0);

	ATF_CHECK_EQ(virtio_admin_pci_controller_restore(controller, before,
	    PCI_CONTROLLER_STATE_HEADER_SIZE - 1), EMSGSIZE);
	memcpy(corrupt, before, state_size);
	corrupt[state_size - 1] ^= 0x80;
	ATF_CHECK_EQ(virtio_admin_pci_controller_restore(controller, corrupt,
	    state_size), EPROTO);
	memcpy(corrupt, before, state_size);
	le16enc(corrupt + 14, 1);
	le64enc(corrupt + PCI_CONTROLLER_STATE_DIGEST_OFF,
	    state_digest(corrupt, state_size));
	ATF_CHECK_EQ(virtio_admin_pci_controller_restore(controller, corrupt,
	    state_size), EPROTO);
	ATF_REQUIRE_EQ(virtio_admin_pci_controller_snapshot(controller, after,
	    state_size), 0);
	ATF_CHECK_EQ(memcmp(before, after, state_size), 0);

	ATF_REQUIRE_EQ(virtio_admin_pci_controller_create(&incompatible,
	    3, 5, 2, 64, 64), 0);
	ATF_CHECK_EQ(virtio_admin_pci_controller_restore(incompatible, before,
	    state_size), ENOTSUP);
	virtio_admin_pci_controller_destroy(incompatible);

	free(corrupt);
	free(after);
	free(before);
	virtio_admin_pci_controller_destroy(controller);
}

ATF_TC_WITHOUT_HEAD(pci_admin_controller_chain_metadata);
ATF_TC_BODY(pci_admin_controller_chain_metadata, tc)
{
	struct virtio_admin_pci_controller *controller;
	struct iovec iov[2];
	uint8_t input[VIRTIO14_ADMIN_HEADER_SIZE];
	uint8_t output[VIRTIO14_ADMIN_RESULT_HEADER_SIZE +
	    VIRTIO14_ADMIN_LIST_SIZE];
	uint8_t unchanged[sizeof(output)];
	uint32_t used;

	ATF_REQUIRE_EQ(virtio_admin_pci_controller_create(&controller,
	    2, 4, 1, 64, 64), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	memset(output, 0xa5, sizeof(output));
	memcpy(unchanged, output, sizeof(output));
	iov[0] = (struct iovec) {
		.iov_base = input,
		.iov_len = sizeof(input),
	};
	iov[1] = (struct iovec) {
		.iov_base = output,
		.iov_len = sizeof(output),
	};

	used = UINT32_C(0xfeedface);
	ATF_CHECK_EQ(virtio_admin_pci_controller_process_chain(controller, 4,
	    iov, nitems(iov), 1, 1, false, true, sizeof(output), &used),
	    EINVAL);
	ATF_CHECK_EQ(used, UINT32_C(0xfeedface));
	ATF_CHECK_EQ(memcmp(output, unchanged, sizeof(output)), 0);
	ATF_CHECK_EQ(virtio_admin_pci_controller_process_chain(controller, 4,
	    iov, nitems(iov), 1, 1, true, false, sizeof(output), &used),
	    EINVAL);
	ATF_CHECK_EQ(virtio_admin_pci_controller_process_chain(controller, 4,
	    iov, nitems(iov), 1, 0, true, true, sizeof(output), &used),
	    EINVAL);
	ATF_CHECK_EQ(virtio_admin_pci_controller_process_chain(controller, 4,
	    iov, nitems(iov), 1, 1, true, true, sizeof(output) - 1, &used),
	    EINVAL);
	ATF_CHECK_EQ(virtio_admin_pci_controller_process_chain(controller, 3,
	    iov, nitems(iov), 1, 1, true, true, sizeof(output), &used),
	    ENOENT);

	ATF_REQUIRE_EQ(virtio_admin_pci_controller_process_chain(controller, 4,
	    iov, nitems(iov), 1, 1, true, true, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);
	virtio_admin_pci_controller_destroy(controller);
}

ATF_TC_WITHOUT_HEAD(queue_bank_bounds_and_fragmentation);
ATF_TC_BODY(queue_bank_bounds_and_fragmentation, tc)
{
	struct virtio_admin_group_fabric *fabric;
	struct virtio_admin_owner *owner;
	struct virtio_admin_queue_bank *bank, *bad;
	struct iovec iov[6];
	uint8_t input[24], output[16];
	uint32_t used;

	bad = (void *)(uintptr_t)1;
	ATF_CHECK_EQ(virtio_admin_queue_bank_create(&bad, NULL, 1, 64, 64),
	    EINVAL);
	ATF_CHECK_EQ(bad, NULL);
	ATF_REQUIRE_EQ(bank_fixture_create(&fabric, &owner, &bank, 2), 0);
	ATF_CHECK_EQ(virtio_admin_queue_bank_count(bank), 2);
	ATF_CHECK_EQ(virtio_admin_queue_bank_count(NULL), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	memset(output, 0xa5, sizeof(output));
	iov[0] = (struct iovec){ .iov_base = input, .iov_len = 3 };
	iov[1] = (struct iovec){ .iov_base = input + 3, .iov_len = 7 };
	iov[2] = (struct iovec){ .iov_base = input + 10, .iov_len = 14 };
	iov[3] = (struct iovec){ .iov_base = output, .iov_len = 3 };
	iov[4] = (struct iovec){ .iov_base = output + 3, .iov_len = 5 };
	iov[5] = (struct iovec){ .iov_base = output + 8, .iov_len = 8 };
	ATF_REQUIRE_EQ(virtio_admin_queue_bank_process(bank, 1, iov,
	    nitems(iov), 3, &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	check_result(output, VIRTIO14_ADMIN_STATUS_OK,
	    VIRTIO14_ADMIN_QUALIFIER_OK);
	ATF_CHECK_EQ(le64dec(output + 8), ADMIN_BASE_MASK);
	ATF_CHECK_EQ(virtio_admin_queue_bank_process(bank, 2, iov,
	    nitems(iov), 3, &used), EINVAL);
	virtio_admin_queue_bank_destroy(bank);
	virtio_admin_group_fabric_destroy(fabric);
}

struct bank_thread_context {
	struct virtio_admin_queue_bank *bank;
	struct reset_drain_context *blocking;
	uint16_t queue;
	bool completed;
	int error;
};

static void *
bank_command_thread(void *argument)
{
	struct bank_thread_context *context;
	uint8_t input[24], output[8];
	uint32_t used;

	context = argument;
	admin_command(input, sizeof(input), 7, VIRTIO14_ADMIN_GROUP_SELF);
	context->error = bank_process(context->bank, context->queue, input,
	    sizeof(input), output, sizeof(output), &used);
	if (context->error == 0 && used != sizeof(output))
		context->error = EIO;
	return (NULL);
}

static void *
bank_reset_thread(void *argument)
{
	struct bank_thread_context *context;

	context = argument;
	virtio_admin_queue_bank_reset(context->bank);
	pthread_mutex_lock(&context->blocking->mutex);
	context->completed = true;
	pthread_cond_broadcast(&context->blocking->condition);
	pthread_mutex_unlock(&context->blocking->mutex);
	return (NULL);
}

static void *
bank_drain_thread(void *argument)
{
	struct bank_thread_context *context;

	context = argument;
	context->error = virtio_admin_queue_bank_drain(context->bank,
	    context->queue);
	pthread_mutex_lock(&context->blocking->mutex);
	context->completed = true;
	pthread_cond_broadcast(&context->blocking->condition);
	pthread_mutex_unlock(&context->blocking->mutex);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(queue_bank_parallelism_and_reset_drain);
ATF_TC_BODY(queue_bank_parallelism_and_reset_drain, tc)
{
	struct virtio_admin_group_fabric *fabric;
	struct virtio_admin_owner *owner;
	struct virtio_admin_queue_bank *bank;
	struct reset_drain_context blocking = { 0 };
	struct bank_thread_context command_context, drain_context, reset_context;
	pthread_t command_thread, drain_thread, reset_thread;
	uint8_t input[32], output[16];
	uint32_t used;

	ATF_REQUIRE_EQ(bank_fixture_create(&fabric, &owner, &bank, 2), 0);
	ATF_REQUIRE_EQ(pthread_mutex_init(&blocking.mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&blocking.condition, NULL), 0);
	ATF_REQUIRE_EQ(virtio_admin_owner_register_command(owner, 7,
	    blocking_command, &blocking), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_USE,
	    VIRTIO14_ADMIN_GROUP_SELF);
	le64enc(input + VIRTIO14_ADMIN_HEADER_SIZE,
	    ADMIN_BASE_MASK | (UINT64_C(1) << 7));
	ATF_REQUIRE_EQ(bank_process(bank, 0, input, sizeof(input), output, 8,
	    &used), 0);
	ATF_REQUIRE_EQ(le16dec(output), VIRTIO14_ADMIN_STATUS_OK);

	command_context = (struct bank_thread_context) {
		.bank = bank,
		.blocking = &blocking,
		.queue = 0,
	};
	ATF_REQUIRE_EQ(pthread_create(&command_thread, NULL,
	    bank_command_thread, &command_context), 0);
	pthread_mutex_lock(&blocking.mutex);
	while (!blocking.entered)
		pthread_cond_wait(&blocking.condition, &blocking.mutex);
	pthread_mutex_unlock(&blocking.mutex);

	/*
	 * Queue one remains usable while queue zero's handler is blocked.
	 * This would deadlock if the bank accidentally serialized all queues.
	 */
	admin_command(input, 24, VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	ATF_REQUIRE_EQ(bank_process(bank, 1, input, 24, output,
	    sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	ATF_CHECK_EQ(le64dec(output + 8),
	    ADMIN_BASE_MASK | (UINT64_C(1) << 7));
	ATF_CHECK_EQ(virtio_admin_queue_bank_drain(bank, 1), 0);
	ATF_CHECK_EQ(virtio_admin_queue_bank_drain(bank, 2), EINVAL);
	drain_context = (struct bank_thread_context) {
		.bank = bank,
		.blocking = &blocking,
		.queue = 0,
	};
	ATF_REQUIRE_EQ(pthread_create(&drain_thread, NULL, bank_drain_thread,
	    &drain_context), 0);

	reset_context = (struct bank_thread_context) {
		.bank = bank,
		.blocking = &blocking,
	};
	ATF_REQUIRE_EQ(pthread_create(&reset_thread, NULL, bank_reset_thread,
	    &reset_context), 0);
	pthread_mutex_lock(&blocking.mutex);
	ATF_CHECK(!drain_context.completed);
	ATF_CHECK(!reset_context.completed);
	blocking.release = true;
	pthread_cond_broadcast(&blocking.condition);
	pthread_mutex_unlock(&blocking.mutex);

	ATF_REQUIRE_EQ(pthread_join(command_thread, NULL), 0);
	ATF_REQUIRE_EQ(pthread_join(drain_thread, NULL), 0);
	ATF_REQUIRE_EQ(pthread_join(reset_thread, NULL), 0);
	ATF_CHECK_EQ(command_context.error, 0);
	ATF_CHECK_EQ(drain_context.error, 0);
	ATF_CHECK(drain_context.completed);
	ATF_CHECK(reset_context.completed);
	admin_command(input, 24, VIRTIO14_ADMIN_CMD_LIST_QUERY,
	    VIRTIO14_ADMIN_GROUP_SELF);
	ATF_REQUIRE_EQ(bank_process(bank, 0, input, 24, output,
	    sizeof(output), &used), 0);
	ATF_CHECK_EQ(le64dec(output + 8),
	    ADMIN_BASE_MASK | (UINT64_C(1) << 7));

	pthread_cond_destroy(&blocking.condition);
	pthread_mutex_destroy(&blocking.mutex);
	virtio_admin_queue_bank_destroy(bank);
	virtio_admin_group_fabric_destroy(fabric);
}

ATF_TC_WITHOUT_HEAD(queue_bank_snapshot_restore);
ATF_TC_BODY(queue_bank_snapshot_restore, tc)
{
	struct virtio_admin_group_fabric *fabric, *wrong_fabric;
	struct virtio_admin_owner *owner, *wrong_owner;
	struct virtio_admin_queue_bank *bank, *wrong_bank;
	uint8_t input[32], output[16];
	uint8_t short_buffer[16];
	uint8_t *before, *after, *corrupt;
	uint32_t used;
	size_t state_size;

	ATF_REQUIRE_EQ(bank_fixture_create(&fabric, &owner, &bank, 2), 0);
	admin_command(input, sizeof(input), VIRTIO14_ADMIN_CMD_LIST_USE,
	    VIRTIO14_ADMIN_GROUP_SELF);
	le64enc(input + VIRTIO14_ADMIN_HEADER_SIZE,
	    UINT64_C(1) << VIRTIO14_ADMIN_CMD_LIST_USE);
	ATF_REQUIRE_EQ(bank_process(bank, 0, input, sizeof(input), output, 8,
	    &used), 0);
	ATF_REQUIRE_EQ(virtio_admin_queue_bank_snapshot_size(bank,
	    &state_size), 0);
	before = malloc(state_size);
	after = malloc(state_size);
	corrupt = malloc(state_size);
	ATF_REQUIRE(before != NULL);
	ATF_REQUIRE(after != NULL);
	ATF_REQUIRE(corrupt != NULL);
	ATF_CHECK_EQ(virtio_admin_queue_bank_snapshot(bank, bank, state_size),
	    EINVAL);
	ATF_CHECK_EQ(virtio_admin_queue_bank_restore(bank, bank, state_size),
	    EINVAL);
	ATF_CHECK_EQ(virtio_admin_queue_bank_snapshot(bank,
	    bank->queues[0].input, state_size), EINVAL);
	ATF_CHECK_EQ(virtio_admin_queue_bank_restore(bank,
	    bank->queues[0].input, state_size), EINVAL);
	ATF_CHECK_EQ(virtio_admin_queue_bank_snapshot(bank,
	    bank->queues[0].output, state_size), EINVAL);
	ATF_CHECK_EQ(virtio_admin_queue_bank_restore(bank,
	    bank->queues[0].output, state_size), EINVAL);
	memset(short_buffer, 0xa5, sizeof(short_buffer));
	ATF_CHECK_EQ(virtio_admin_queue_bank_snapshot(bank, short_buffer,
	    sizeof(short_buffer)), EMSGSIZE);
	for (size_t i = 0; i < sizeof(short_buffer); i++)
		ATF_CHECK_EQ(short_buffer[i], 0xa5);
	ATF_REQUIRE_EQ(virtio_admin_queue_bank_snapshot(bank, before,
	    state_size), 0);
	ATF_CHECK_EQ(le32dec(before), UINT32_C(0x31425141));
	ATF_CHECK_EQ(le16dec(before + 8), 2);
	ATF_CHECK_EQ(le32dec(before + 12), 64);
	ATF_CHECK_EQ(le32dec(before + 16), 64);
	virtio_admin_queue_bank_reset(bank);
	ATF_REQUIRE_EQ(virtio_admin_queue_bank_restore(bank, before,
	    state_size), 0);
	ATF_REQUIRE_EQ(virtio_admin_queue_bank_snapshot(bank, after,
	    state_size), 0);
	ATF_CHECK_EQ(memcmp(before, after, state_size), 0);
	ATF_CHECK_EQ(virtio_admin_queue_bank_restore(bank, before,
	    state_size - 1), EPROTO);

	memcpy(corrupt, before, state_size);
	corrupt[state_size - 1] ^= 0x80;
	ATF_CHECK_EQ(virtio_admin_queue_bank_restore(bank, corrupt,
	    state_size), EPROTO);
	ATF_REQUIRE_EQ(virtio_admin_queue_bank_snapshot(bank, after,
	    state_size), 0);
	ATF_CHECK_EQ(memcmp(before, after, state_size), 0);

	/* Destination queue-bank topology is policy, not mutable state. */
	ATF_REQUIRE_EQ(bank_fixture_create(&wrong_fabric, &wrong_owner,
	    &wrong_bank, 1), 0);
	ATF_CHECK_EQ(virtio_admin_queue_bank_restore(wrong_bank, before,
	    state_size), ENOTSUP);
	virtio_admin_queue_bank_destroy(wrong_bank);
	virtio_admin_group_fabric_destroy(wrong_fabric);

	ATF_REQUIRE_EQ(virtio_admin_group_fabric_create(&wrong_fabric), 0);
	{
		const struct virtio_admin_group_config config = {
			.group_type = VIRTIO14_ADMIN_GROUP_SELF,
			.available = bank_group_available,
			.member_valid = bank_group_member,
		};

		ATF_REQUIRE_EQ(virtio_admin_group_register(wrong_fabric,
		    &config, &wrong_owner), 0);
	}
	ATF_REQUIRE_EQ(virtio_admin_queue_bank_create(&wrong_bank,
	    wrong_fabric, 2, 32, 64), 0);
	ATF_CHECK_EQ(virtio_admin_queue_bank_restore(wrong_bank, before,
	    state_size), ENOTSUP);
	virtio_admin_queue_bank_destroy(wrong_bank);
	virtio_admin_group_fabric_destroy(wrong_fabric);

	free(corrupt);
	free(after);
	free(before);
	virtio_admin_queue_bank_destroy(bank);
	virtio_admin_group_fabric_destroy(fabric);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, status_values_match_specification);
	ATF_TP_ADD_TC(tp, core_publication_aliases_are_rejected);
	ATF_TP_ADD_TC(tp, callback_private_status_is_rejected);
	ATF_TP_ADD_TC(tp, list_query_lengths);
	ATF_TP_ADD_TC(tp, zero_lengths_are_transport_errors);
	ATF_TP_ADD_TC(tp, command_validation);
	ATF_TP_ADD_TC(tp, success_qualifier_is_zero);
	ATF_TP_ADD_TC(tp, list_use_validation);
	ATF_TP_ADD_TC(tp, portable_transactional_state);
	ATF_TP_ADD_TC(tp, registered_command_dispatch);
	ATF_TP_ADD_TC(tp, owner_seal_is_permanent);
	ATF_TP_ADD_TC(tp, concurrent_command_serialization);
	ATF_TP_ADD_TC(tp, reset_drains_active_command);
	ATF_TP_ADD_TC(tp, destroy_drains_active_command);
	ATF_TP_ADD_TC(tp, fragmented_queue_adapter);
	ATF_TP_ADD_TC(tp, queue_adapter_rejects_bad_chains);
	ATF_TP_ADD_TC(tp, queue_adapter_allows_empty_iov_segments);
	ATF_TP_ADD_TC(tp, queue_adapter_rejects_aliases_transactionally);
	ATF_TP_ADD_TC(tp, pci_admin_queue_range_contract);
	ATF_TP_ADD_TC(tp, pci_admin_queue_namespace_contract);
	ATF_TP_ADD_TC(tp, pci_admin_controller_self_group);
	ATF_TP_ADD_TC(tp, pci_admin_controller_sriov_topology);
	ATF_TP_ADD_TC(tp, pci_admin_controller_portable_state);
	ATF_TP_ADD_TC(tp, pci_admin_controller_chain_metadata);
	ATF_TP_ADD_TC(tp, queue_bank_bounds_and_fragmentation);
	ATF_TP_ADD_TC(tp, queue_bank_parallelism_and_reset_drain);
	ATF_TP_ADD_TC(tp, queue_bank_snapshot_restore);
	return (atf_no_error());
}
