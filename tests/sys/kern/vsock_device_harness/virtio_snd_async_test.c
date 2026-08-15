/*
 * Rootless tests for the bounded, generation-fenced VirtIO sound PCM owner.
 */
#include <sys/errno.h>
#include <sys/param.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>
#include <pthread.h>

#include "virtio_snd_async.c"

enum model_mode {
	MODE_NORMAL,
	MODE_EAGAIN,
	MODE_ZERO,
	MODE_OVERSIZED,
	MODE_EAGAIN_PROGRESS,
	MODE_FATAL,
};

struct async_model {
	struct virtio_snd_async *async;
	enum model_mode mode;
	size_t quantum;
	unsigned int progress_calls;
	unsigned int complete_calls;
	uintptr_t token;
	enum virtio_snd_async_status status;
	uint8_t playback[32];
	size_t playback_len;
	uint8_t capture[32];
	size_t capture_len;
	bool callback_saw_unlocked_owner;
	bool progress_callback_saw_unlocked_owner;
	bool reenter_pending;
	bool block_progress;
	bool progress_entered;
	bool release_progress;
	bool block_complete;
	bool complete_entered;
	bool release_complete;
	pthread_mutex_t race_mutex;
	pthread_cond_t race_cond;
};

static int
model_progress(void *arg, enum virtio_snd_async_direction direction,
    void *buffer, size_t remaining, size_t *progress)
{
	struct async_model *model;
	size_t amount;

	model = arg;
	model->progress_calls++;
	if (model->reenter_pending) {
		bool pending;
		size_t outstanding;

		ATF_REQUIRE_EQ(virtio_snd_async_pending(model->async, 0,
		    &pending, &outstanding), 0);
		ATF_REQUIRE(pending);
		ATF_REQUIRE_EQ(outstanding, remaining);
		model->progress_callback_saw_unlocked_owner = true;
	}
	if (model->block_progress) {
		ATF_REQUIRE_EQ(pthread_mutex_lock(&model->race_mutex), 0);
		model->progress_entered = true;
		ATF_REQUIRE_EQ(pthread_cond_broadcast(&model->race_cond), 0);
		while (!model->release_progress)
			ATF_REQUIRE_EQ(pthread_cond_wait(&model->race_cond,
			    &model->race_mutex), 0);
		ATF_REQUIRE_EQ(pthread_mutex_unlock(&model->race_mutex), 0);
	}
	switch (model->mode) {
	case MODE_EAGAIN:
		*progress = 0;
		return (EAGAIN);
	case MODE_ZERO:
		*progress = 0;
		return (0);
	case MODE_OVERSIZED:
		*progress = remaining + 1;
		return (0);
	case MODE_EAGAIN_PROGRESS:
		*progress = 1;
		return (EAGAIN);
	case MODE_FATAL:
		*progress = 0;
		return (ENXIO);
	case MODE_NORMAL:
		break;
	}
	amount = model->quantum == 0 || model->quantum > remaining ?
	    remaining : model->quantum;
	if (direction == BHYVE_VTSND_ASYNC_PLAYBACK) {
		ATF_REQUIRE(model->playback_len + amount <=
		    sizeof(model->playback));
		memcpy(model->playback + model->playback_len, buffer, amount);
		model->playback_len += amount;
	} else {
		memset(buffer, (uint8_t)(0x40 + model->progress_calls), amount);
	}
	*progress = amount;
	return (0);
}

static void
model_complete(void *arg, uintptr_t token,
    enum virtio_snd_async_status status, const void *capture,
    size_t capture_len)
{
	struct async_model *model;
	bool pending;
	size_t remaining;

	model = arg;
	model->complete_calls++;
	model->token = token;
	model->status = status;
	model->capture_len = capture_len;
	if (capture_len != 0) {
		ATF_REQUIRE(capture != NULL);
		ATF_REQUIRE(capture_len <= sizeof(model->capture));
		memcpy(model->capture, capture, capture_len);
	} else
		ATF_REQUIRE(capture == NULL);
	/*
	 * Completion must run after the job is detached and the owner mutex is
	 * released.  A real PCI completion needs exactly this property.
	 */
	ATF_REQUIRE_EQ(virtio_snd_async_pending(model->async, 0, &pending,
	    &remaining), 0);
	model->callback_saw_unlocked_owner = true;
	if (model->block_complete) {
		ATF_REQUIRE_EQ(pthread_mutex_lock(&model->race_mutex), 0);
		model->complete_entered = true;
		ATF_REQUIRE_EQ(pthread_cond_broadcast(&model->race_cond), 0);
		while (!model->release_complete)
			ATF_REQUIRE_EQ(pthread_cond_wait(&model->race_cond,
			    &model->race_mutex), 0);
		ATF_REQUIRE_EQ(pthread_mutex_unlock(&model->race_mutex), 0);
	}
}

static struct virtio_snd_async *
new_async(struct async_model *model, size_t max_bytes)
{
	const struct virtio_snd_async_ops ops = {
		.progress = model_progress,
		.complete = model_complete,
		.arg = model,
	};

	ATF_REQUIRE_EQ(virtio_snd_async_create(&ops, max_bytes,
	    &model->async), 0);
	return (model->async);
}

struct race_args {
	struct virtio_snd_async *async;
	uint64_t generation;
	int result;
};

static void *
race_progress(void *arg)
{
	struct race_args *args;

	args = arg;
	args->result = virtio_snd_async_progress(args->async, 0,
	    args->generation);
	return (NULL);
}

static void *
race_cancel(void *arg)
{
	struct race_args *args;

	args = arg;
	args->result = virtio_snd_async_cancel(args->async, 0,
	    args->generation);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(arguments_and_bounded_ownership);
ATF_TC_BODY(arguments_and_bounded_ownership, tc)
{
	struct async_model model;
	struct virtio_snd_async *async;
	struct virtio_snd_async_ops bad_ops;
	struct iovec iov[2];
	uint8_t payload[9];

	memset(&model, 0, sizeof(model));
	memset(&bad_ops, 0, sizeof(bad_ops));
	ATF_CHECK_EQ(virtio_snd_async_create(NULL, 8, &async), EINVAL);
	ATF_CHECK_EQ(virtio_snd_async_create(&bad_ops, 8, &async), EINVAL);
	ATF_CHECK_EQ(virtio_snd_async_destroy(NULL), EINVAL);
	async = new_async(&model, 8);
	memset(payload, 0x31, sizeof(payload));
	ATF_CHECK_EQ(virtio_snd_async_submit(NULL, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 1, 1, payload, 8), EINVAL);
	ATF_CHECK_EQ(virtio_snd_async_submit(async, 2,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 1, 1, payload, 8), EINVAL);
	ATF_CHECK_EQ(virtio_snd_async_submit(async, 0, 99, 1, 1, payload, 8),
	    EINVAL);
	ATF_CHECK_EQ(virtio_snd_async_submit(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 0, 1, payload, 8), EINVAL);
	ATF_CHECK_EQ(virtio_snd_async_submit(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 1, 0, payload, 8), EINVAL);
	ATF_CHECK_EQ(virtio_snd_async_submit(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 1, 1, payload, 0), EINVAL);
	ATF_CHECK_EQ(virtio_snd_async_submit(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 1, 1, payload, 9), EINVAL);
	ATF_CHECK_EQ(virtio_snd_async_submit(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 1, 1, NULL, 8), EINVAL);
	ATF_CHECK_EQ(virtio_snd_async_submit(async, 0,
	    BHYVE_VTSND_ASYNC_CAPTURE, 1, 1, payload, 8), EINVAL);
	iov[0] = (struct iovec){ .iov_base = payload, .iov_len = 4 };
	iov[1] = (struct iovec){ .iov_base = payload + 4, .iov_len = 4 };
	ATF_CHECK_EQ(virtio_snd_async_submit_iov(async, 2,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 1, 1, iov, 2, 0, 8), EINVAL);
	ATF_CHECK_EQ(virtio_snd_async_submit_iov(async, 0,
	    BHYVE_VTSND_ASYNC_CAPTURE, 1, 1, iov, 2, 0, 8), EINVAL);
	ATF_CHECK_EQ(virtio_snd_async_submit_iov(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 1, 1, iov, 2, 4, 5), EMSGSIZE);
	iov[1].iov_base = NULL;
	ATF_CHECK_EQ(virtio_snd_async_submit_iov(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 1, 1, iov, 2, 0, 8), EINVAL);
	ATF_CHECK_EQ(virtio_snd_async_quiesce(async), 0);
	ATF_CHECK_EQ(virtio_snd_async_submit(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 2, 2, payload, 8), EBUSY);
	ATF_CHECK_EQ(virtio_snd_async_resume(async), 0);
	ATF_CHECK_EQ(virtio_snd_async_submit(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 2, 2, payload, 8), 0);
	ATF_CHECK_EQ(virtio_snd_async_cancel(async, 0, 2), 0);
	ATF_CHECK_EQ(virtio_snd_async_destroy(async), 0);
}

ATF_TC_WITHOUT_HEAD(partial_playback_never_replays_guest_memory);
ATF_TC_BODY(partial_playback_never_replays_guest_memory, tc)
{
	struct async_model model;
	struct virtio_snd_async *async;
	uint8_t payload[8], expected[8];
	bool pending;
	size_t remaining;

	memset(&model, 0, sizeof(model));
	async = new_async(&model, sizeof(payload));
	for (size_t i = 0; i < sizeof(payload); i++)
		payload[i] = expected[i] = (uint8_t)(0x10 + i);
	model.quantum = 3;
	ATF_REQUIRE_EQ(virtio_snd_async_submit(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 11, 7, payload, sizeof(payload)), 0);
	memset(payload, 0xff, sizeof(payload));
	ATF_CHECK_EQ(virtio_snd_async_destroy(async), EBUSY);
	ATF_CHECK_EQ(virtio_snd_async_progress(async, 0, 6), ESTALE);
	ATF_CHECK_EQ(virtio_snd_async_progress(async, 0, 7), EINPROGRESS);
	ATF_REQUIRE_EQ(virtio_snd_async_pending(async, 0, &pending,
	    &remaining), 0);
	ATF_CHECK(pending);
	ATF_CHECK_EQ(remaining, 5);
	model.mode = MODE_EAGAIN;
	ATF_CHECK_EQ(virtio_snd_async_progress(async, 0, 7), EAGAIN);
	model.mode = MODE_NORMAL;
	ATF_CHECK_EQ(virtio_snd_async_progress(async, 0, 7), EINPROGRESS);
	ATF_CHECK_EQ(virtio_snd_async_progress(async, 0, 7), 0);
	ATF_CHECK_EQ(model.complete_calls, 1);
	ATF_CHECK_EQ(model.token, 11);
	ATF_CHECK_EQ(model.status, BHYVE_VTSND_ASYNC_OK);
	ATF_CHECK_EQ(model.capture_len, 0);
	ATF_CHECK(model.callback_saw_unlocked_owner);
	ATF_CHECK_EQ(memcmp(model.playback, expected, sizeof(expected)), 0);
	ATF_CHECK_EQ(virtio_snd_async_progress(async, 0, 7), ENOENT);
	ATF_CHECK_EQ(virtio_snd_async_quiesce(async), 0);
	ATF_CHECK_EQ(virtio_snd_async_destroy(async), 0);
}

ATF_TC_WITHOUT_HEAD(fragmented_playback_copy_is_atomic);
ATF_TC_BODY(fragmented_playback_copy_is_atomic, tc)
{
	struct async_model model;
	struct virtio_snd_async *async;
	struct iovec iov[3];
	uint8_t a[3] = { 0xaa, 1, 2 };
	uint8_t b[2] = { 3, 4 };
	uint8_t c[4] = { 5, 6, 7, 0xbb };
	const uint8_t expected[7] = { 1, 2, 3, 4, 5, 6, 7 };

	memset(&model, 0, sizeof(model));
	async = new_async(&model, sizeof(expected));
	iov[0] = (struct iovec){ .iov_base = a, .iov_len = sizeof(a) };
	iov[1] = (struct iovec){ .iov_base = b, .iov_len = sizeof(b) };
	iov[2] = (struct iovec){ .iov_base = c, .iov_len = sizeof(c) };
	ATF_REQUIRE_EQ(virtio_snd_async_submit_iov(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 12, 8, iov, nitems(iov), 1,
	    sizeof(expected)), 0);
	memset(a, 0, sizeof(a));
	memset(b, 0, sizeof(b));
	memset(c, 0, sizeof(c));
	ATF_CHECK_EQ(virtio_snd_async_progress(async, 0, 8), 0);
	ATF_CHECK_EQ(model.playback_len, sizeof(expected));
	ATF_CHECK_EQ(memcmp(model.playback, expected, sizeof(expected)), 0);
	ATF_CHECK_EQ(virtio_snd_async_destroy(async), 0);
}

ATF_TC_WITHOUT_HEAD(capture_is_private_until_atomic_completion);
ATF_TC_BODY(capture_is_private_until_atomic_completion, tc)
{
	struct async_model model;
	struct virtio_snd_async *async;
	const uint8_t expected[] = {
		0x41, 0x41, 0x41, 0x42, 0x42, 0x42, 0x43, 0x43
	};

	memset(&model, 0, sizeof(model));
	async = new_async(&model, sizeof(expected));
	model.quantum = 3;
	ATF_REQUIRE_EQ(virtio_snd_async_submit(async, 1,
	    BHYVE_VTSND_ASYNC_CAPTURE, 22, 9, NULL, sizeof(expected)), 0);
	ATF_CHECK_EQ(virtio_snd_async_progress(async, 1, 9), EINPROGRESS);
	ATF_CHECK_EQ(model.complete_calls, 0);
	ATF_CHECK_EQ(virtio_snd_async_progress(async, 1, 9), EINPROGRESS);
	ATF_CHECK_EQ(virtio_snd_async_progress(async, 1, 9), 0);
	ATF_CHECK_EQ(model.complete_calls, 1);
	ATF_CHECK_EQ(model.token, 22);
	ATF_CHECK_EQ(model.status, BHYVE_VTSND_ASYNC_OK);
	ATF_CHECK_EQ(model.capture_len, sizeof(expected));
	ATF_CHECK_EQ(memcmp(model.capture, expected, sizeof(expected)), 0);
	ATF_CHECK_EQ(virtio_snd_async_destroy(async), 0);
}

ATF_TC_WITHOUT_HEAD(backend_contract_violations_fail_closed);
ATF_TC_BODY(backend_contract_violations_fail_closed, tc)
{
	static const enum model_mode modes[] = {
		MODE_ZERO, MODE_OVERSIZED, MODE_EAGAIN_PROGRESS, MODE_FATAL
	};
	struct async_model model;
	struct virtio_snd_async *async;
	uint8_t payload[4] = { 1, 2, 3, 4 };
	int expected;

	for (size_t i = 0; i < nitems(modes); i++) {
		memset(&model, 0, sizeof(model));
		async = new_async(&model, sizeof(payload));
		model.mode = modes[i];
		ATF_REQUIRE_EQ(virtio_snd_async_submit(async, 0,
		    BHYVE_VTSND_ASYNC_PLAYBACK, 30 + i, 1, payload,
		    sizeof(payload)), 0);
		expected = modes[i] == MODE_FATAL ? ENXIO : EIO;
		ATF_CHECK_EQ(virtio_snd_async_progress(async, 0, 1),
		    expected);
		ATF_CHECK_EQ(model.complete_calls, 1);
		ATF_CHECK_EQ(model.status, BHYVE_VTSND_ASYNC_IO_ERR);
		ATF_CHECK_EQ(model.capture_len, 0);
		ATF_CHECK_EQ(virtio_snd_async_quiesce(async), 0);
		ATF_CHECK_EQ(virtio_snd_async_destroy(async), 0);
	}
}

ATF_TC_WITHOUT_HEAD(cancel_generation_and_stream_independence);
ATF_TC_BODY(cancel_generation_and_stream_independence, tc)
{
	struct async_model model;
	struct virtio_snd_async *async;
	uint8_t payload[4] = { 1, 2, 3, 4 };
	bool pending;
	size_t remaining;

	memset(&model, 0, sizeof(model));
	async = new_async(&model, sizeof(payload));
	ATF_REQUIRE_EQ(virtio_snd_async_submit(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 41, 2, payload, sizeof(payload)), 0);
	ATF_CHECK_EQ(virtio_snd_async_submit(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 42, 2, payload, sizeof(payload)),
	    EBUSY);
	ATF_REQUIRE_EQ(virtio_snd_async_submit(async, 1,
	    BHYVE_VTSND_ASYNC_CAPTURE, 43, 3, NULL, sizeof(payload)), 0);
	ATF_CHECK_EQ(virtio_snd_async_quiesce(async), EBUSY);
	/*
	 * A failed quiesce has not closed admission.  Retire the existing
	 * stream-0 job first: submit is deliberately one-job-per-stream, so a
	 * second job may only prove admission after that slot is genuinely idle.
	 */
	ATF_CHECK_EQ(virtio_snd_async_cancel(async, 0, 2), 0);
	ATF_CHECK_EQ(virtio_snd_async_submit(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 44, 4, payload, sizeof(payload)), 0);
	model.complete_calls = 0;
	ATF_CHECK_EQ(virtio_snd_async_cancel(async, 0, 1), ESTALE);
	ATF_CHECK_EQ(model.complete_calls, 0);
	ATF_CHECK_EQ(virtio_snd_async_cancel(async, 0, 4), 0);
	ATF_CHECK_EQ(model.complete_calls, 1);
	ATF_CHECK_EQ(model.token, 44);
	ATF_CHECK_EQ(model.status, BHYVE_VTSND_ASYNC_IO_ERR);
	ATF_REQUIRE_EQ(virtio_snd_async_pending(async, 1, &pending,
	    &remaining), 0);
	ATF_CHECK(pending);
	ATF_CHECK_EQ(remaining, sizeof(payload));
	ATF_CHECK_EQ(virtio_snd_async_cancel(async, 1, 3), 0);
	ATF_CHECK_EQ(model.complete_calls, 2);
	ATF_CHECK_EQ(virtio_snd_async_cancel(async, 1, 3), ENOENT);
	ATF_CHECK_EQ(virtio_snd_async_quiesce(async), 0);
	ATF_CHECK_EQ(virtio_snd_async_destroy(async), 0);
}

ATF_TC_WITHOUT_HEAD(progress_and_cancel_serialize_one_completion);
ATF_TC_BODY(progress_and_cancel_serialize_one_completion, tc)
{
	struct async_model model;
	struct race_args cancel_args, progress_args;
	struct virtio_snd_async *async;
	pthread_t cancel_thread, progress_thread;
	uint8_t payload[4] = { 1, 2, 3, 4 };
	bool pending;
	size_t remaining;

	memset(&model, 0, sizeof(model));
	ATF_REQUIRE_EQ(pthread_mutex_init(&model.race_mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&model.race_cond, NULL), 0);
	async = new_async(&model, sizeof(payload));
	model.block_progress = true;
	ATF_REQUIRE_EQ(virtio_snd_async_submit(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 51, 5, payload, sizeof(payload)), 0);
	progress_args = (struct race_args){
		.async = async, .generation = 5, .result = -1
	};
	cancel_args = (struct race_args){
		.async = async, .generation = 5, .result = -1
	};
	ATF_REQUIRE_EQ(pthread_create(&progress_thread, NULL, race_progress,
	    &progress_args), 0);
	ATF_REQUIRE_EQ(pthread_mutex_lock(&model.race_mutex), 0);
	while (!model.progress_entered)
		ATF_REQUIRE_EQ(pthread_cond_wait(&model.race_cond,
		    &model.race_mutex), 0);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&model.race_mutex), 0);
	/*
	 * progress() is outside the owner mutex, but its pin keeps all lifecycle
	 * edges fail-closed while the backend owns the job buffer.
	 */
	ATF_REQUIRE_EQ(virtio_snd_async_pending(async, 0, &pending,
	    &remaining), 0);
	ATF_CHECK(pending);
	ATF_CHECK_EQ(remaining, sizeof(payload));
	ATF_CHECK_EQ(virtio_snd_async_quiesce(async), EBUSY);
	ATF_CHECK_EQ(virtio_snd_async_destroy(async), EBUSY);
	ATF_CHECK_EQ(virtio_snd_async_progress(async, 0, 5), EBUSY);
	ATF_CHECK_EQ(virtio_snd_async_cancel(async, 0, 5), EBUSY);
	ATF_REQUIRE_EQ(pthread_create(&cancel_thread, NULL, race_cancel,
	    &cancel_args), 0);
	ATF_REQUIRE_EQ(pthread_mutex_lock(&model.race_mutex), 0);
	model.release_progress = true;
	ATF_REQUIRE_EQ(pthread_cond_broadcast(&model.race_cond), 0);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&model.race_mutex), 0);
	ATF_REQUIRE_EQ(pthread_join(progress_thread, NULL), 0);
	ATF_REQUIRE_EQ(pthread_join(cancel_thread, NULL), 0);
	ATF_CHECK_EQ(progress_args.result, 0);
	ATF_CHECK(cancel_args.result == EBUSY ||
	    cancel_args.result == ENOENT);
	ATF_CHECK_EQ(model.complete_calls, 1);
	ATF_CHECK_EQ(model.token, 51);
	ATF_CHECK_EQ(model.status, BHYVE_VTSND_ASYNC_OK);
	ATF_CHECK_EQ(virtio_snd_async_destroy(async), 0);
	ATF_REQUIRE_EQ(pthread_cond_destroy(&model.race_cond), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&model.race_mutex), 0);
}

ATF_TC_WITHOUT_HEAD(completion_callback_remains_owned_until_return);
ATF_TC_BODY(completion_callback_remains_owned_until_return, tc)
{
	struct async_model model;
	struct race_args progress_args;
	struct virtio_snd_async *async;
	pthread_t progress_thread;
	uint8_t payload[4] = { 1, 2, 3, 4 };
	bool pending;
	size_t remaining;

	memset(&model, 0, sizeof(model));
	ATF_REQUIRE_EQ(pthread_mutex_init(&model.race_mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&model.race_cond, NULL), 0);
	async = new_async(&model, sizeof(payload));
	model.block_complete = true;
	ATF_REQUIRE_EQ(virtio_snd_async_submit(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 61, 6, payload, sizeof(payload)), 0);
	progress_args = (struct race_args){
		.async = async, .generation = 6, .result = -1
	};
	ATF_REQUIRE_EQ(pthread_create(&progress_thread, NULL, race_progress,
	    &progress_args), 0);
	ATF_REQUIRE_EQ(pthread_mutex_lock(&model.race_mutex), 0);
	while (!model.complete_entered)
		ATF_REQUIRE_EQ(pthread_cond_wait(&model.race_cond,
		    &model.race_mutex), 0);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&model.race_mutex), 0);

	ATF_REQUIRE_EQ(virtio_snd_async_pending(async, 0, &pending,
	    &remaining), 0);
	ATF_CHECK(pending);
	ATF_CHECK_EQ(remaining, 0);
	ATF_CHECK_EQ(virtio_snd_async_quiesce(async), EBUSY);
	ATF_CHECK_EQ(virtio_snd_async_destroy(async), EBUSY);
	ATF_CHECK_EQ(virtio_snd_async_submit(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 62, 7, payload, sizeof(payload)),
	    EBUSY);
	ATF_CHECK_EQ(virtio_snd_async_progress(async, 0, 6), EBUSY);
	ATF_CHECK_EQ(virtio_snd_async_cancel(async, 0, 6), EBUSY);

	ATF_REQUIRE_EQ(pthread_mutex_lock(&model.race_mutex), 0);
	model.release_complete = true;
	ATF_REQUIRE_EQ(pthread_cond_broadcast(&model.race_cond), 0);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&model.race_mutex), 0);
	ATF_REQUIRE_EQ(pthread_join(progress_thread, NULL), 0);
	ATF_CHECK_EQ(progress_args.result, 0);
	ATF_CHECK_EQ(model.complete_calls, 1);
	ATF_CHECK_EQ(virtio_snd_async_quiesce(async), 0);
	ATF_CHECK_EQ(virtio_snd_async_destroy(async), 0);
	ATF_REQUIRE_EQ(pthread_cond_destroy(&model.race_cond), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&model.race_mutex), 0);
}

ATF_TC_WITHOUT_HEAD(progress_callback_runs_unlocked_while_job_is_pinned);
ATF_TC_BODY(progress_callback_runs_unlocked_while_job_is_pinned, tc)
{
	struct async_model model;
	struct virtio_snd_async *async;
	uint8_t payload[4] = { 1, 2, 3, 4 };
	bool pending;
	size_t remaining;

	memset(&model, 0, sizeof(model));
	async = new_async(&model, sizeof(payload));
	model.reenter_pending = true;
	ATF_REQUIRE_EQ(virtio_snd_async_submit(async, 0,
	    BHYVE_VTSND_ASYNC_PLAYBACK, 71, 7, payload, sizeof(payload)), 0);
	ATF_CHECK_EQ(virtio_snd_async_progress(async, 0, 7), 0);
	ATF_CHECK(model.progress_callback_saw_unlocked_owner);
	ATF_REQUIRE_EQ(virtio_snd_async_pending(async, 0, &pending,
	    &remaining), 0);
	ATF_CHECK(!pending);
	ATF_CHECK_EQ(remaining, 0);
	ATF_CHECK_EQ(model.complete_calls, 1);
	ATF_CHECK_EQ(virtio_snd_async_destroy(async), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, arguments_and_bounded_ownership);
	ATF_TP_ADD_TC(tp, partial_playback_never_replays_guest_memory);
	ATF_TP_ADD_TC(tp, fragmented_playback_copy_is_atomic);
	ATF_TP_ADD_TC(tp, capture_is_private_until_atomic_completion);
	ATF_TP_ADD_TC(tp, backend_contract_violations_fail_closed);
	ATF_TP_ADD_TC(tp, cancel_generation_and_stream_independence);
	ATF_TP_ADD_TC(tp, progress_and_cancel_serialize_one_completion);
	ATF_TP_ADD_TC(tp, completion_callback_remains_owned_until_return);
	ATF_TP_ADD_TC(tp, progress_callback_runs_unlocked_while_job_is_pinned);
	return (atf_no_error());
}
