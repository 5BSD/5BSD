/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "virtio_admin.c"
#include "virtio_admin_group.c"

#define	ADMIN_LIST_QUERY	0
#define	ADMIN_LIST_USE		1
#define	ADMIN_TEST_COMMAND	10
#define	ADMIN_GROUP_SELF	0
#define	ADMIN_GROUP_SRIOV	1

struct group_context {
	bool available;
	bool active;
	bool bad_end;
	uint64_t last_member;
	unsigned int begins;
	unsigned int ends;
	unsigned int resets;
	uint16_t members;
	int begin_error;
	uint16_t begin_qualifier;
};

struct blocking_context {
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	bool entered;
	bool release;
	struct virtio_admin_owner *owner;
	uint8_t input[32];
	uint8_t output[24];
	size_t written;
	int error;
};

struct teardown_context {
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	struct virtio_admin_group_fabric *fabric;
	bool end_entered;
	bool release_end;
	bool destroy_started;
	bool destroy_done;
	uint8_t input[32];
	uint8_t output[24];
	size_t written;
	int error;
};

static bool
group_available(void *argument)
{

	return (((struct group_context *)argument)->available);
}

static int
group_begin(void *argument, uint16_t *qualifier)
{
	struct group_context *context;

	context = argument;
	if (!context->available) {
		*qualifier = BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_GROUP;
		return (ENXIO);
	}
	if (context->begin_error != 0) {
		*qualifier = context->begin_qualifier;
		return (context->begin_error);
	}
	context->active = true;
	context->begins++;
	return (0);
}

static void
group_end(void *argument)
{
	struct group_context *context;

	context = argument;
	if (!context->active)
		context->bad_end = true;
	context->active = false;
	context->ends++;
}

static void
group_reset(void *argument)
{

	((struct group_context *)argument)->resets++;
}

static bool
group_member(void *argument, uint64_t member)
{
	struct group_context *context;

	context = argument;
	return (member >= 1 && member <= context->members);
}

static bool
self_member(void *argument, uint64_t member)
{

	(void)argument;
	return (member == 0);
}

static void
test_command(void *argument, uint64_t member, const void *input,
    size_t input_length, void *output, size_t output_length,
    struct virtio_admin_command_result *result)
{
	struct group_context *context;

	(void)input;
	(void)input_length;
	(void)output;
	(void)output_length;
	context = argument;
	context->last_member = member;
	result->result_length = 0;
}

static void
blocking_command(void *argument, uint64_t member, const void *input,
    size_t input_length, void *output, size_t output_length,
    struct virtio_admin_command_result *result)
{
	struct blocking_context *context;

	(void)member;
	(void)input;
	(void)input_length;
	(void)output;
	(void)output_length;
	context = argument;
	pthread_mutex_lock(&context->mutex);
	context->entered = true;
	pthread_cond_broadcast(&context->condition);
	while (!context->release)
		pthread_cond_wait(&context->condition, &context->mutex);
	pthread_mutex_unlock(&context->mutex);
	result->result_length = 0;
}

static void
command(uint8_t *bytes, uint16_t opcode, uint16_t group, uint64_t member)
{

	memset(bytes, 0, 32);
	le16enc(bytes, opcode);
	le16enc(bytes + 2, group);
	le64enc(bytes + 16, member);
}

static uint16_t
process(struct virtio_admin_group_fabric *fabric, uint8_t *input,
    size_t input_length, uint8_t *output, size_t *written)
{

	memset(output, 0xa5, 24);
	ATF_REQUIRE_EQ(virtio_admin_group_process(fabric, input, input_length,
	    output, 24, written), 0);
	return (le16dec(output + 2));
}

static void *
blocking_process(void *argument)
{
	struct blocking_context *context;

	context = argument;
	context->error = virtio_admin_process_group(context->owner,
	    ADMIN_GROUP_SRIOV, group_member, &(struct group_context) {
		.members = 1,
	    }, context->input, 24, context->output, sizeof(context->output),
	    &context->written);
	return (NULL);
}

static void
teardown_end(void *argument)
{
	struct teardown_context *context;

	context = argument;
	pthread_mutex_lock(&context->mutex);
	context->end_entered = true;
	pthread_cond_broadcast(&context->condition);
	while (!context->release_end)
		pthread_cond_wait(&context->condition, &context->mutex);
	pthread_mutex_unlock(&context->mutex);
}

static int
teardown_begin(void *argument, uint16_t *qualifier)
{

	(void)argument;
	(void)qualifier;
	return (0);
}

static bool
teardown_available(void *argument)
{

	(void)argument;
	return (true);
}

static bool
teardown_member(void *argument, uint64_t member)
{

	(void)argument;
	return (member == 1);
}

static void *
teardown_process(void *argument)
{
	struct teardown_context *context;

	context = argument;
	context->error = virtio_admin_group_process(context->fabric,
	    context->input, 24, context->output, sizeof(context->output),
	    &context->written);
	return (NULL);
}

static void *
teardown_destroy(void *argument)
{
	struct teardown_context *context;

	context = argument;
	pthread_mutex_lock(&context->mutex);
	context->destroy_started = true;
	pthread_cond_broadcast(&context->condition);
	pthread_mutex_unlock(&context->mutex);
	virtio_admin_group_fabric_destroy(context->fabric);
	pthread_mutex_lock(&context->mutex);
	context->destroy_done = true;
	pthread_cond_broadcast(&context->condition);
	pthread_mutex_unlock(&context->mutex);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(independent_groups_and_member_precedence);
ATF_TC_BODY(independent_groups_and_member_precedence, tc)
{
	struct virtio_admin_group_fabric *fabric;
	struct virtio_admin_owner *self_owner, *sriov_owner;
	struct group_context sriov = {
		.members = 2,
	};
	const struct virtio_admin_group_config self_config = {
		.group_type = ADMIN_GROUP_SELF,
		.available = group_available,
		.member_valid = self_member,
		.argument = &(struct group_context) { .available = true },
	};
	const struct virtio_admin_group_config sriov_config = {
		.group_type = ADMIN_GROUP_SRIOV,
		.available = group_available,
		.member_valid = group_member,
		.begin = group_begin,
		.end = group_end,
		.reset = group_reset,
		.argument = &sriov,
	};
	uint8_t input[32], output[24];
	uint8_t *bad, *state;
	size_t state_size, written;

	ATF_REQUIRE_EQ(virtio_admin_group_fabric_create(&fabric), 0);
	ATF_REQUIRE_EQ(virtio_admin_group_register(fabric, &self_config,
	    &self_owner), 0);
	ATF_REQUIRE_EQ(virtio_admin_group_register(fabric, &sriov_config,
	    &sriov_owner), 0);
	ATF_CHECK_EQ(virtio_admin_group_register(fabric, &sriov_config,
	    &sriov_owner), EEXIST);
	ATF_REQUIRE_EQ(virtio_admin_owner_register_command(self_owner,
	    ADMIN_TEST_COMMAND, test_command, &sriov), 0);
	ATF_REQUIRE_EQ(virtio_admin_owner_register_command(sriov_owner,
	    ADMIN_TEST_COMMAND, test_command, &sriov), 0);

	/*
	 * The fabric must preserve the core's byte-granular short-buffer
	 * contract.  One zero opcode byte selects LIST_QUERY in self group;
	 * the one-byte result is a truncated zero status.
	 */
	input[0] = ADMIN_LIST_QUERY;
	output[0] = 0xa5;
	ATF_REQUIRE_EQ(virtio_admin_group_process(fabric, input, 1, output, 1,
	    &written), 0);
	ATF_CHECK_EQ(written, 1);
	ATF_CHECK_EQ(output[0], 0);

	command(input, ADMIN_LIST_QUERY, ADMIN_GROUP_SRIOV, 0);
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written), 4);
	ATF_CHECK_EQ(le16dec(output), EINVAL);
	sriov.available = true;
	sriov.begin_error = EBUSY;
	sriov.begin_qualifier = BHYVE_VIRTIO_ADMIN_QUALIFIER_TRYAGAIN;
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written),
	    BHYVE_VIRTIO_ADMIN_QUALIFIER_TRYAGAIN);
	ATF_CHECK_EQ(le16dec(output), BHYVE_VIRTIO_ADMIN_STATUS_EAGAIN);
	ATF_CHECK_EQ(sriov.begins, 0);
	ATF_CHECK_EQ(sriov.ends, 0);
	sriov.begin_error = 0;
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written), 0);
	ATF_CHECK_EQ(le64dec(output + 8),
	    (UINT64_C(1) << ADMIN_LIST_QUERY) |
	    (UINT64_C(1) << ADMIN_LIST_USE) |
	    (UINT64_C(1) << ADMIN_TEST_COMMAND));

	command(input, ADMIN_LIST_USE, ADMIN_GROUP_SRIOV, 0);
	le64enc(input + 24, (UINT64_C(1) << ADMIN_LIST_QUERY) |
	    (UINT64_C(1) << ADMIN_LIST_USE) |
	    (UINT64_C(1) << ADMIN_TEST_COMMAND));
	ATF_CHECK_EQ(process(fabric, input, 32, output, &written), 0);
	command(input, ADMIN_TEST_COMMAND, ADMIN_GROUP_SRIOV, 1);
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written), 0);
	ATF_CHECK_EQ(sriov.last_member, 1);
	ATF_CHECK_EQ(sriov.begins, sriov.ends);
	ATF_CHECK(!sriov.active);
	ATF_CHECK(!sriov.bad_end);

	ATF_REQUIRE_EQ(virtio_admin_group_snapshot_size(fabric,
	    &state_size), 0);
	ATF_CHECK_EQ(state_size, 128);
	state = malloc(state_size);
	bad = malloc(state_size);
	ATF_REQUIRE(state != NULL);
	ATF_REQUIRE(bad != NULL);
	ATF_CHECK_EQ(virtio_admin_group_snapshot(fabric, fabric, state_size),
	    EINVAL);
	ATF_CHECK_EQ(virtio_admin_group_restore(fabric, fabric, state_size),
	    EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_group_snapshot(fabric, state,
	    state_size), 0);
	command(input, ADMIN_LIST_USE, ADMIN_GROUP_SRIOV, 0);
	le64enc(input + 24, (UINT64_C(1) << ADMIN_LIST_QUERY) |
	    (UINT64_C(1) << ADMIN_LIST_USE));
	ATF_REQUIRE_EQ(process(fabric, input, 32, output, &written), 0);
	command(input, ADMIN_TEST_COMMAND, ADMIN_GROUP_SRIOV, 1);
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written), 2);
	memcpy(bad, state, state_size);
	bad[state_size - 1] ^= 1;
	ATF_CHECK_EQ(virtio_admin_group_restore_validate(fabric, bad,
	    state_size), EPROTO);
	ATF_CHECK_EQ(virtio_admin_group_restore(fabric, bad, state_size),
	    EPROTO);
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written), 2);
	ATF_REQUIRE_EQ(virtio_admin_group_restore_validate(fabric, state,
	    state_size), 0);
	/* Validation parses the complete image but cannot publish it. */
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written), 2);
	ATF_REQUIRE_EQ(virtio_admin_group_restore(fabric, state, state_size),
	    0);
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written), 0);
	command(input, ADMIN_TEST_COMMAND, ADMIN_GROUP_SRIOV, 0);
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written), 5);
	command(input, ADMIN_TEST_COMMAND, ADMIN_GROUP_SRIOV, 3);
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written), 5);

	/*
	 * Opcode validation precedes both member validation and the external
	 * lifecycle lease.  A malformed command must not be converted into a
	 * retryable lifecycle error or invoke begin/end callbacks.
	 */
	sriov.begin_error = EBUSY;
	sriov.begin_qualifier = BHYVE_VIRTIO_ADMIN_QUALIFIER_TRYAGAIN;
	{
		unsigned int begins, ends;

		begins = sriov.begins;
		ends = sriov.ends;
		command(input, 63, ADMIN_GROUP_SRIOV, 99);
		ATF_CHECK_EQ(process(fabric, input, 24, output, &written),
		    BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_OPCODE);
		ATF_CHECK_EQ(le16dec(output),
		    BHYVE_VIRTIO_ADMIN_STATUS_EINVAL);
		ATF_CHECK_EQ(sriov.begins, begins);
		ATF_CHECK_EQ(sriov.ends, ends);
	}
	sriov.begin_error = 0;

	/* Opcode validation also precedes member validation. */
	command(input, 63, ADMIN_GROUP_SRIOV, 99);
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written), 2);
	command(input, ADMIN_LIST_QUERY, ADMIN_GROUP_SRIOV, 1);
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written), 0);
	command(input, ADMIN_LIST_QUERY, 7, 0);
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written), 4);

	/* Selecting commands in SR-IOV does not select them in self. */
	command(input, ADMIN_TEST_COMMAND, ADMIN_GROUP_SELF, 0);
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written), 2);
	virtio_admin_group_fabric_reset(fabric);
	ATF_CHECK_EQ(sriov.resets, 1);
	command(input, ADMIN_TEST_COMMAND, ADMIN_GROUP_SRIOV, 1);
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written), 2);

	ATF_CHECK(virtio_admin_group_owner(fabric, ADMIN_GROUP_SELF) ==
	    self_owner);
	ATF_CHECK(virtio_admin_group_owner(fabric, 9) == NULL);
	virtio_admin_group_fabric_destroy(fabric);
	free(bad);
	free(state);
}

ATF_TC_WITHOUT_HEAD(restore_is_atomic_when_member_busy);
ATF_TC_BODY(restore_is_atomic_when_member_busy, tc)
{
	struct virtio_admin_group_fabric *fabric;
	struct virtio_admin_owner *self_owner, *sriov_owner;
	struct group_context self = { .available = true };
	struct group_context sriov = { .available = true, .members = 1 };
	struct blocking_context blocking;
	const struct virtio_admin_group_config self_config = {
		.group_type = ADMIN_GROUP_SELF,
		.available = group_available,
		.member_valid = self_member,
		.argument = &self,
	};
	const struct virtio_admin_group_config sriov_config = {
		.group_type = ADMIN_GROUP_SRIOV,
		.available = group_available,
		.member_valid = group_member,
		.argument = &sriov,
	};
	pthread_t thread;
	uint8_t input[32], output[24];
	uint8_t *failed, *state;
	size_t state_size, written;

	memset(&blocking, 0, sizeof(blocking));
	ATF_REQUIRE_EQ(pthread_mutex_init(&blocking.mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&blocking.condition, NULL), 0);
	ATF_REQUIRE_EQ(virtio_admin_group_fabric_create(&fabric), 0);
	ATF_REQUIRE_EQ(virtio_admin_group_register(fabric, &self_config,
	    &self_owner), 0);
	ATF_REQUIRE_EQ(virtio_admin_group_register(fabric, &sriov_config,
	    &sriov_owner), 0);
	ATF_REQUIRE_EQ(virtio_admin_owner_register_command(self_owner,
	    ADMIN_TEST_COMMAND, test_command, &self), 0);
	ATF_REQUIRE_EQ(virtio_admin_owner_register_command(sriov_owner,
	    ADMIN_TEST_COMMAND, blocking_command, &blocking), 0);

	for (uint16_t group = ADMIN_GROUP_SELF; group <= ADMIN_GROUP_SRIOV;
	    group++) {
		command(input, ADMIN_LIST_USE, group, 0);
		le64enc(input + 24, (UINT64_C(1) << ADMIN_LIST_QUERY) |
		    (UINT64_C(1) << ADMIN_LIST_USE) |
		    (UINT64_C(1) << ADMIN_TEST_COMMAND));
		ATF_REQUIRE_EQ(process(fabric, input, sizeof(input), output,
		    &written), 0);
	}
	ATF_REQUIRE_EQ(virtio_admin_group_snapshot_size(fabric,
	    &state_size), 0);
	state = malloc(state_size);
	ATF_REQUIRE(state != NULL);
	failed = malloc(state_size);
	ATF_REQUIRE(failed != NULL);
	ATF_REQUIRE_EQ(virtio_admin_group_snapshot(fabric, state,
	    state_size), 0);

	/* Make the first group observably different from the snapshot. */
	command(input, ADMIN_LIST_USE, ADMIN_GROUP_SELF, 0);
	le64enc(input + 24, (UINT64_C(1) << ADMIN_LIST_QUERY) |
	    (UINT64_C(1) << ADMIN_LIST_USE));
	ATF_REQUIRE_EQ(process(fabric, input, sizeof(input), output, &written),
	    0);
	command(input, ADMIN_TEST_COMMAND, ADMIN_GROUP_SELF, 0);
	ATF_REQUIRE_EQ(process(fabric, input, 24, output, &written),
	    BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_OPCODE);

	blocking.owner = sriov_owner;
	command(blocking.input, ADMIN_TEST_COMMAND, ADMIN_GROUP_SRIOV, 1);
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL, blocking_process,
	    &blocking), 0);
	pthread_mutex_lock(&blocking.mutex);
	while (!blocking.entered)
		pthread_cond_wait(&blocking.condition, &blocking.mutex);
	pthread_mutex_unlock(&blocking.mutex);

	memset(failed, 0xa5, state_size);
	ATF_CHECK_EQ(virtio_admin_group_snapshot(fabric, failed, state_size),
	    EBUSY);
	for (size_t i = 0; i < state_size; i++)
		ATF_CHECK_EQ(failed[i], 0xa5);
	ATF_CHECK_EQ(virtio_admin_group_restore(fabric, state, state_size),
	    EBUSY);
	/* The first owner must remain unchanged after the failed transaction. */
	command(input, ADMIN_TEST_COMMAND, ADMIN_GROUP_SELF, 0);
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written),
	    BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_OPCODE);

	pthread_mutex_lock(&blocking.mutex);
	blocking.release = true;
	pthread_cond_broadcast(&blocking.condition);
	pthread_mutex_unlock(&blocking.mutex);
	ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
	ATF_CHECK_EQ(blocking.error, 0);
	ATF_REQUIRE_EQ(virtio_admin_group_restore(fabric, state, state_size),
	    0);
	command(input, ADMIN_TEST_COMMAND, ADMIN_GROUP_SELF, 0);
	ATF_CHECK_EQ(process(fabric, input, 24, output, &written), 0);

	free(failed);
	free(state);
	virtio_admin_group_fabric_destroy(fabric);
	pthread_cond_destroy(&blocking.condition);
	pthread_mutex_destroy(&blocking.mutex);
}

ATF_TC_WITHOUT_HEAD(destroy_drains_group_end_callback);
ATF_TC_BODY(destroy_drains_group_end_callback, tc)
{
	struct virtio_admin_owner *owner;
	struct teardown_context context;
	struct timespec deadline;
	const struct virtio_admin_group_config config = {
		.group_type = ADMIN_GROUP_SRIOV,
		.available = teardown_available,
		.member_valid = teardown_member,
		.begin = teardown_begin,
		.end = teardown_end,
		.argument = &context,
	};
	pthread_t destroy_thread, process_thread;
	uint8_t input[32], output[24];
	size_t written;
	int error;

	memset(&context, 0, sizeof(context));
	ATF_REQUIRE_EQ(pthread_mutex_init(&context.mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&context.condition, NULL), 0);
	ATF_REQUIRE_EQ(virtio_admin_group_fabric_create(&context.fabric), 0);
	ATF_REQUIRE_EQ(virtio_admin_group_register(context.fabric, &config,
	    &owner), 0);
	ATF_REQUIRE_EQ(virtio_admin_owner_register_command(owner,
	    ADMIN_TEST_COMMAND, test_command,
	    &(struct group_context) { 0 }), 0);
	/* Do not block the setup LIST_USE transaction's end callback. */
	context.release_end = true;
	command(input, ADMIN_LIST_USE, ADMIN_GROUP_SRIOV, 0);
	le64enc(input + 24, (UINT64_C(1) << ADMIN_LIST_QUERY) |
	    (UINT64_C(1) << ADMIN_LIST_USE) |
	    (UINT64_C(1) << ADMIN_TEST_COMMAND));
	ATF_REQUIRE_EQ(process(context.fabric, input, sizeof(input), output,
	    &written), 0);
	context.end_entered = false;
	context.release_end = false;

	command(context.input, ADMIN_TEST_COMMAND, ADMIN_GROUP_SRIOV, 1);
	ATF_REQUIRE_EQ(pthread_create(&process_thread, NULL, teardown_process,
	    &context), 0);
	pthread_mutex_lock(&context.mutex);
	while (!context.end_entered)
		pthread_cond_wait(&context.condition, &context.mutex);
	pthread_mutex_unlock(&context.mutex);

	ATF_REQUIRE_EQ(pthread_create(&destroy_thread, NULL, teardown_destroy,
	    &context), 0);
	pthread_mutex_lock(&context.mutex);
	while (!context.destroy_started)
		pthread_cond_wait(&context.condition, &context.mutex);
	ATF_REQUIRE_EQ(clock_gettime(CLOCK_REALTIME, &deadline), 0);
	deadline.tv_nsec += 100 * 1000 * 1000;
	if (deadline.tv_nsec >= 1000 * 1000 * 1000) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000 * 1000 * 1000;
	}
	error = 0;
	while (!context.destroy_done && error == 0)
		error = pthread_cond_timedwait(&context.condition, &context.mutex,
		    &deadline);
	ATF_CHECK_EQ(error, ETIMEDOUT);
	ATF_CHECK(!context.destroy_done);
	context.release_end = true;
	pthread_cond_broadcast(&context.condition);
	pthread_mutex_unlock(&context.mutex);

	ATF_REQUIRE_EQ(pthread_join(process_thread, NULL), 0);
	ATF_REQUIRE_EQ(pthread_join(destroy_thread, NULL), 0);
	ATF_CHECK_EQ(context.error, 0);
	ATF_CHECK(context.destroy_done);
	pthread_cond_destroy(&context.condition);
	pthread_mutex_destroy(&context.mutex);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, independent_groups_and_member_precedence);
	ATF_TP_ADD_TC(tp, restore_is_atomic_when_member_busy);
	ATF_TP_ADD_TC(tp, destroy_drains_group_end_callback);
	return (atf_no_error());
}
