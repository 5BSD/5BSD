/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_device_parts.c"
#include "virtio_device_parts_handler.c"

struct handler_context {
	uint8_t state[128];
	size_t state_size;
	bool stopped;
	bool fail_prepare;
	bool malformed_capture;
	bool omit_last_capture;
	unsigned int commits;
	unsigned int discards;
	unsigned int mode_sets;
};

static int
mock_schema(void *argument, uint64_t member, void *output, size_t capacity,
    size_t *used)
{
	struct handler_context *context;
	struct virtio_device_parts_iterator iterator;
	struct virtio_device_part part;
	int error;

	if (member != 7)
		return (ENXIO);
	context = argument;
	*used = 0;
	virtio_device_parts_iterator_init(&iterator, context->state,
	    context->state_size);
	while ((error = virtio_device_parts_next(&iterator, &part)) == 0) {
		error = virtio_device_part_header_append(output, capacity, used,
		    part.type, part.flags, part.selector, part.length);
		if (error != 0)
			return (error);
	}
	return (error == ENOENT ? 0 : error);
}

static int
mock_capture(void *argument, uint64_t member, uint8_t type,
    const void *selection, size_t selection_size, void *output,
    size_t capacity, size_t *used)
{
	struct handler_context *context;
	struct virtio_device_parts_iterator iterator;
	struct virtio_device_part requested, state_part;
	size_t output_size;
	int error;

	if (member != 7)
		return (ENXIO);
	context = argument;
	output_size = context->state_size;
	if (type == BHYVE_VIRTIO_DEVICE_PARTS_GET_SELECTED) {
		output_size = 0;
		for (size_t offset = 0; offset < selection_size;
		    offset += BHYVE_VIRTIO_DEV_PART_HEADER_SIZE) {
			struct virtio_device_parts_iterator state_iterator;

			virtio_device_part_selection_iterator_init(&iterator,
			    (const uint8_t *)selection + offset,
			    BHYVE_VIRTIO_DEV_PART_HEADER_SIZE);
			ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator,
			    &requested), 0);
			virtio_device_parts_iterator_init(&state_iterator,
			    context->state, context->state_size);
			while ((error = virtio_device_parts_next(&state_iterator,
			    &state_part)) == 0) {
				if (state_part.type == requested.type &&
				    state_part.selector == requested.selector &&
				    state_part.length == requested.length &&
				    state_part.flags == requested.flags &&
				    state_iterator.offset > output_size)
					output_size = state_iterator.offset;
			}
			ATF_REQUIRE_EQ(error, ENOENT);
		}
	}
	if (context->omit_last_capture &&
	    output_size == context->state_size)
		output_size -= BHYVE_VIRTIO_DEV_PART_HEADER_SIZE + 1;
	if (capacity < output_size)
		return (ENOSPC);
	memcpy(output, context->state, output_size);
	*used = output_size;
	if (context->malformed_capture)
		((uint8_t *)output)[3] = 1;
	return (0);
}

static int
mock_mode_get(void *argument, uint64_t member, bool *stopped)
{
	struct handler_context *context;

	if (member != 7)
		return (ENXIO);
	context = argument;
	*stopped = context->stopped;
	return (0);
}

static int
mock_mode_set(void *argument, uint64_t member, bool stopped)
{
	struct handler_context *context;

	if (member != 7)
		return (ENXIO);
	context = argument;
	context->stopped = stopped;
	context->mode_sets++;
	return (0);
}

static int
mock_prepare(void *argument, uint64_t member, const void *input, size_t length,
    void **result)
{
	struct handler_context *context;
	uint8_t *copy;

	if (member != 7)
		return (ENXIO);
	context = argument;
	if (context->fail_prepare)
		return (EIO);
	copy = malloc(length + sizeof(size_t));
	if (copy == NULL)
		return (ENOMEM);
	memcpy(copy, &length, sizeof(length));
	if (length != 0)
		memcpy(copy + sizeof(length), input, length);
	*result = copy;
	return (0);
}

static void
mock_commit(void *argument, uint64_t member, void *transaction)
{
	struct handler_context *context;
	uint8_t *copy;
	size_t length;

	(void)member;
	context = argument;
	copy = transaction;
	memcpy(&length, copy, sizeof(length));
	ATF_REQUIRE(length <= sizeof(context->state));
	if (length != 0)
		memcpy(context->state, copy + sizeof(length), length);
	context->state_size = length;
	context->commits++;
}

static void
mock_discard(void *argument, uint64_t member, void *transaction)
{
	struct handler_context *context;

	(void)member;
	context = argument;
	free(transaction);
	context->discards++;
}

static void
build_state(struct handler_context *context, uint8_t status)
{
	uint8_t common[2] = { 0 }, features[8] = { 0 };

	context->state_size = 0;
	ATF_REQUIRE_EQ(virtio_device_part_append(context->state,
	    sizeof(context->state), &context->state_size,
	    BHYVE_VIRTIO_DEV_PART_DEV_FEATURES,
	    BHYVE_VIRTIO_DEV_PART_F_OPTIONAL, 0, features,
	    sizeof(features)), 0);
	ATF_REQUIRE_EQ(virtio_device_part_append(context->state,
	    sizeof(context->state), &context->state_size,
	    BHYVE_VIRTIO_DEV_PART_DRV_FEATURES, 0, 0, features,
	    sizeof(features)), 0);
	ATF_REQUIRE_EQ(virtio_device_part_append(context->state,
	    sizeof(context->state), &context->state_size,
	    BHYVE_VIRTIO_DEV_PART_PCI_COMMON_CFG, 0, 18, common,
	    sizeof(common)), 0);
	ATF_REQUIRE_EQ(virtio_device_part_append(context->state,
	    sizeof(context->state), &context->state_size,
	    BHYVE_VIRTIO_DEV_PART_DEVICE_STATUS, 0, 0, &status,
	    sizeof(status)), 0);
}

static struct virtio_device_parts_handler *
create_handler(struct handler_context *context)
{
	const struct virtio_device_parts_handler_config config = {
		.ops = {
			.schema = mock_schema,
			.capture = mock_capture,
			.mode_get = mock_mode_get,
			.mode_set = mock_mode_set,
			.prepare_restore = mock_prepare,
			.commit_restore = mock_commit,
			.discard_restore = mock_discard,
		},
		.argument = context,
		.maximum_parts_size = sizeof(context->state),
		.maximum_part_count = 4,
	};
	struct virtio_device_parts_handler *handler;

	ATF_REQUIRE_EQ(virtio_device_parts_handler_create(&handler, &config),
	    0);
	return (handler);
}

ATF_TC_WITHOUT_HEAD(metadata_and_get_are_bounded);
ATF_TC_BODY(metadata_and_get_are_bounded, tc)
{
	struct virtio_device_parts_handler *handler;
	struct handler_context context = { 0 };
	uint8_t output[160], selection[64];
	size_t selection_size, used;

	build_state(&context, 4);
	handler = create_handler(&context);
	ATF_REQUIRE_EQ(virtio_device_parts_handler_metadata(handler, 7,
	    BHYVE_VIRTIO_DEVICE_PARTS_METADATA_SIZE, output,
	    sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, 8);
	ATF_CHECK_EQ(le32dec(output), sizeof(context.state));
	ATF_CHECK_EQ(le32dec(output + 4), 0);
	ATF_REQUIRE_EQ(virtio_device_parts_handler_metadata(handler, 7,
	    BHYVE_VIRTIO_DEVICE_PARTS_METADATA_COUNT, output,
	    sizeof(output), &used), 0);
	ATF_CHECK_EQ(le32dec(output), 4);
	ATF_REQUIRE_EQ(virtio_device_parts_handler_metadata(handler, 7,
	    BHYVE_VIRTIO_DEVICE_PARTS_METADATA_LIST, output,
	    sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, 8 + 4 * BHYVE_VIRTIO_DEV_PART_HEADER_SIZE);
	ATF_CHECK_EQ(le32dec(output), 4);
	ATF_CHECK_EQ(virtio_device_parts_handler_metadata(handler, 7,
	    BHYVE_VIRTIO_DEVICE_PARTS_METADATA_LIST, output, used - 1,
	    &used), ENOSPC);

	ATF_REQUIRE_EQ(virtio_device_parts_handler_get(handler, 7,
	    BHYVE_VIRTIO_DEVICE_PARTS_GET_ALL, NULL, 0, output,
	    sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, context.state_size);
	memset(output, 0, sizeof(output));
	ATF_REQUIRE_EQ(virtio_device_parts_handler_get(handler, 7,
	    BHYVE_VIRTIO_DEVICE_PARTS_GET_ALL, NULL, 0, output, 8, &used),
	    0);
	ATF_CHECK_EQ(used, context.state_size);
	ATF_CHECK_EQ(memcmp(output, context.state, 8), 0);
	selection_size = 0;
	ATF_REQUIRE_EQ(virtio_device_part_header_append(selection,
	    sizeof(selection), &selection_size,
	    BHYVE_VIRTIO_DEV_PART_DEV_FEATURES,
	    BHYVE_VIRTIO_DEV_PART_F_OPTIONAL, 0, 8), 0);
	ATF_REQUIRE_EQ(virtio_device_parts_handler_get(handler, 7,
	    BHYVE_VIRTIO_DEVICE_PARTS_GET_SELECTED, selection,
	    selection_size, output, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, BHYVE_VIRTIO_DEV_PART_HEADER_SIZE + 8);
	selection_size = 0;
	ATF_REQUIRE_EQ(virtio_device_part_header_append(selection,
	    sizeof(selection), &selection_size,
	    BHYVE_VIRTIO_DEV_PART_DEVICE_STATUS, 0, 0, 1), 0);
	ATF_REQUIRE_EQ(virtio_device_parts_handler_get(handler, 7,
	    BHYVE_VIRTIO_DEVICE_PARTS_GET_SELECTED, selection,
	    selection_size, output, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, context.state_size);
	context.omit_last_capture = true;
	ATF_CHECK_EQ(virtio_device_parts_handler_get(handler, 7,
	    BHYVE_VIRTIO_DEVICE_PARTS_GET_SELECTED, selection,
	    selection_size, output, sizeof(output), &used), EPROTO);
	context.omit_last_capture = false;
	context.malformed_capture = true;
	ATF_CHECK_EQ(virtio_device_parts_handler_get(handler, 7,
	    BHYVE_VIRTIO_DEVICE_PARTS_GET_ALL, NULL, 0, output,
	    sizeof(output), &used), EPROTO);
	ATF_CHECK_EQ(virtio_device_parts_handler_get(handler, 8,
	    BHYVE_VIRTIO_DEVICE_PARTS_GET_ALL, NULL, 0, output,
	    sizeof(output), &used), ENXIO);
	virtio_device_parts_handler_destroy(handler);
}

ATF_TC_WITHOUT_HEAD(set_requires_stopped_and_is_transactional);
ATF_TC_BODY(set_requires_stopped_and_is_transactional, tc)
{
	struct virtio_device_parts_handler *handler;
	struct handler_context context = { 0 }, replacement = { 0 };
	uint8_t malformed[128];

	build_state(&context, 4);
	build_state(&replacement, 8);
	handler = create_handler(&context);
	ATF_CHECK_EQ(virtio_device_parts_handler_set(handler, 7,
	    replacement.state, replacement.state_size), EBUSY);
	ATF_CHECK_EQ(context.commits, 0);
	ATF_REQUIRE_EQ(virtio_device_parts_handler_mode_set(handler, 7,
	    BHYVE_VIRTIO_DEVICE_MODE_STOPPED), 0);
	ATF_CHECK(context.stopped);
	ATF_REQUIRE_EQ(virtio_device_parts_handler_mode_set(handler, 7,
	    BHYVE_VIRTIO_DEVICE_MODE_STOPPED), 0);
	ATF_CHECK_EQ(context.mode_sets, 2);
	context.fail_prepare = true;
	ATF_CHECK_EQ(virtio_device_parts_handler_set(handler, 7,
	    replacement.state, replacement.state_size), EIO);
	ATF_CHECK_EQ(context.commits, 0);
	ATF_CHECK_EQ(context.discards, 1);
	context.fail_prepare = false;
	ATF_REQUIRE_EQ(virtio_device_parts_handler_set(handler, 7,
	    replacement.state, replacement.state_size), 0);
	ATF_CHECK_EQ(context.commits, 1);
	ATF_CHECK_EQ(context.discards, 2);
	ATF_CHECK_EQ(context.state[context.state_size - 1], 8);

	memcpy(malformed, replacement.state, replacement.state_size);
	malformed[3] = 1;
	ATF_CHECK_EQ(virtio_device_parts_handler_set(handler, 7, malformed,
	    replacement.state_size), EPROTO);
	ATF_CHECK_EQ(context.commits, 1);
	ATF_CHECK_EQ(virtio_device_parts_handler_mode_set(handler, 7, 2),
	    EINVAL);
	ATF_REQUIRE_EQ(virtio_device_parts_handler_mode_set(handler, 7, 0),
	    0);
	ATF_CHECK(!context.stopped);
	virtio_device_parts_handler_destroy(handler);
}

ATF_TC_WITHOUT_HEAD(publication_aliases_are_rejected);
ATF_TC_BODY(publication_aliases_are_rejected, tc)
{
	struct virtio_device_parts_handler *handler;
	struct handler_context context = { 0 };
	union {
		uint64_t align;
		uint8_t bytes[32];
	} pair;
	uint8_t output[128];
	size_t used;

	build_state(&context, 4);
	handler = create_handler(&context);
	used = SIZE_MAX;
	ATF_CHECK_EQ(virtio_device_parts_handler_metadata(handler, 7, 0,
	    handler, 1, &used), EINVAL);
	ATF_CHECK_EQ(used, SIZE_MAX);
	memset(&pair, 0xa5, sizeof(pair));
	ATF_CHECK_EQ(virtio_device_parts_handler_metadata(handler, 7, 0,
	    pair.bytes, sizeof(uint64_t), (size_t *)pair.bytes), EINVAL);
	ATF_CHECK_EQ(pair.bytes[0], 0xa5);
	ATF_CHECK_EQ(virtio_device_parts_handler_get(handler, 7, 0, handler,
	    BHYVE_VIRTIO_DEV_PART_HEADER_SIZE, output, sizeof(output), &used),
	    EINVAL);
	ATF_CHECK_EQ(virtio_device_parts_handler_set(handler, 7, handler,
	    BHYVE_VIRTIO_DEV_PART_HEADER_SIZE), EINVAL);
	ATF_REQUIRE_EQ(virtio_device_parts_handler_metadata(handler, 7, 0,
	    output, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, sizeof(uint64_t));
	virtio_device_parts_handler_destroy(handler);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, metadata_and_get_are_bounded);
	ATF_TP_ADD_TC(tp, set_requires_stopped_and_is_transactional);
	ATF_TP_ADD_TC(tp, publication_aliases_are_rejected);
	return (atf_no_error());
}
