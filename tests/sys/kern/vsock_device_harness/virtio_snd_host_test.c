/*
 * Independent VirtIO 1.4 section 5.14 sound protocol and lifecycle tests.
 */
#include <sys/endian.h>
#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_1_4_spec.h"
#include "virtio_snd_host.c"

#define	DOC_R_PCM_INFO		VIRTIO14_SND_R_PCM_INFO
#define	DOC_R_PCM_SET_PARAMS	VIRTIO14_SND_R_PCM_SET_PARAMS
#define	DOC_R_PCM_PREPARE	VIRTIO14_SND_R_PCM_PREPARE
#define	DOC_R_PCM_RELEASE	VIRTIO14_SND_R_PCM_RELEASE
#define	DOC_R_PCM_START		VIRTIO14_SND_R_PCM_START
#define	DOC_R_PCM_STOP		VIRTIO14_SND_R_PCM_STOP
#define	DOC_S_OK		VIRTIO14_SND_S_OK
#define	DOC_S_BAD_MSG		VIRTIO14_SND_S_BAD_MSG
#define	DOC_S_NOT_SUPP		VIRTIO14_SND_S_NOT_SUPP
#define	DOC_S_IO_ERR		VIRTIO14_SND_S_IO_ERR
#define	DOC_FMT_S16		VIRTIO14_SND_PCM_FMT_S16
#define	DOC_RATE_44100		VIRTIO14_SND_PCM_RATE_44100
#define	DOC_RATE_48000		VIRTIO14_SND_PCM_RATE_48000

struct sound_model {
	struct virtio_snd_host *host;
	unsigned int set_params_calls;
	unsigned int prepare_calls;
	unsigned int start_calls;
	unsigned int stop_calls;
	unsigned int release_calls;
	unsigned int playback_calls;
	unsigned int capture_calls;
	int fail;
	unsigned int fail_set_params_call;
	int fail_prepare;
	int fail_stop;
	int fail_release;
	uint8_t playback_digest;
	pthread_mutex_t callback_mutex;
	pthread_cond_t callback_cond;
	bool block_set_params;
	bool set_params_entered;
	bool release_set_params;
};

static int
model_set_params(void *arg, uint32_t stream_id,
    const struct virtio_snd_host_params *params)
{
	struct sound_model *model;
	enum virtio_snd_host_stream_state state;
	struct virtio_snd_host_params current;

	model = arg;
	ATF_REQUIRE(stream_id < 2);
	ATF_REQUIRE(params->channels >= 1);
	/* Backends may inspect committed state without a state-lock deadlock. */
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(model->host, stream_id,
	    &state, &current), 0);
	if (model->block_set_params) {
		pthread_mutex_lock(&model->callback_mutex);
		model->set_params_entered = true;
		pthread_cond_broadcast(&model->callback_cond);
		while (!model->release_set_params)
			pthread_cond_wait(&model->callback_cond,
			    &model->callback_mutex);
		pthread_mutex_unlock(&model->callback_mutex);
	}
	model->set_params_calls++;
	if (model->fail_set_params_call != 0 &&
	    model->set_params_calls == model->fail_set_params_call)
		return (EIO);
	return (model->fail);
}

static int
model_prepare(void *arg, uint32_t stream_id)
{
	struct sound_model *model = arg;

	ATF_REQUIRE(stream_id < 2);
	model->prepare_calls++;
	return (model->fail_prepare != 0 ? model->fail_prepare : model->fail);
}

static int
model_start(void *arg, uint32_t stream_id)
{
	struct sound_model *model = arg;

	ATF_REQUIRE(stream_id < 2);
	model->start_calls++;
	return (model->fail);
}

static int
model_stop(void *arg, uint32_t stream_id)
{
	struct sound_model *model = arg;

	ATF_REQUIRE(stream_id < 2);
	model->stop_calls++;
	return (model->fail_stop != 0 ? model->fail_stop : model->fail);
}

static int
model_release(void *arg, uint32_t stream_id)
{
	struct sound_model *model = arg;

	ATF_REQUIRE(stream_id < 2);
	model->release_calls++;
	return (model->fail_release != 0 ? model->fail_release : model->fail);
}

static int
model_playback(void *arg, uint32_t stream_id, const void *payload, size_t size)
{
	const uint8_t *bytes;
	struct sound_model *model;

	model = arg;
	ATF_REQUIRE_EQ(stream_id, 0);
	bytes = payload;
	for (size_t i = 0; i < size; i++)
		model->playback_digest ^= bytes[i];
	model->playback_calls++;
	return (model->fail);
}

static int
model_capture(void *arg, uint32_t stream_id, void *payload, size_t size)
{
	struct sound_model *model;

	model = arg;
	ATF_REQUIRE_EQ(stream_id, 1);
	memset(payload, 0x5a, size);
	model->capture_calls++;
	return (model->fail);
}

static struct virtio_snd_host *
new_host(struct sound_model *model)
{
	const struct virtio_snd_host_ops ops = {
		.set_params = model_set_params,
		.prepare = model_prepare,
		.start = model_start,
		.stop = model_stop,
		.release = model_release,
		.playback = model_playback,
		.capture = model_capture,
		.arg = model,
	};

	ATF_REQUIRE_EQ(virtio_snd_host_create(&ops, &model->host), 0);
	return (model->host);
}

struct sound_control_thread {
	struct virtio_snd_host *host;
	uint8_t request[24];
	uint8_t response[4];
	size_t used;
	int error;
};

struct sound_destroy_thread {
	struct virtio_snd_host *host;
};

static void *
sound_set_params_thread(void *arg)
{
	struct sound_control_thread *context;

	context = arg;
	context->error = virtio_snd_host_control(context->host,
	    context->request, sizeof(context->request), context->response,
	    sizeof(context->response), &context->used);
	return (NULL);
}

static void *
sound_destroy_thread(void *arg)
{
	struct sound_destroy_thread *context;

	context = arg;
	virtio_snd_host_destroy(context->host);
	return (NULL);
}

static uint32_t
control(struct virtio_snd_host *host, const void *request, size_t request_size,
    uint8_t *response, size_t response_size, size_t *used)
{

	memset(response, 0xa5, response_size);
	ATF_REQUIRE_EQ(virtio_snd_host_control(host, request, request_size,
	    response, response_size, used), 0);
	ATF_REQUIRE(*used >= 4);
	return (le32dec(response));
}

static void
make_params(uint8_t request[24], uint32_t stream_id)
{

	memset(request, 0, 24);
	le32enc(request, DOC_R_PCM_SET_PARAMS);
	le32enc(request + 4, stream_id);
	le32enc(request + 8, 4096);
	le32enc(request + 12, 1024);
	request[20] = 2;
	request[21] = DOC_FMT_S16;
	request[22] = DOC_RATE_48000;
}

static uint32_t
lifecycle(struct virtio_snd_host *host, uint32_t code, uint32_t stream_id)
{
	uint8_t request[8], response[4];
	size_t used;

	memset(request, 0, sizeof(request));
	le32enc(request, code);
	le32enc(request + 4, stream_id);
	return (control(host, request, sizeof(request), response,
	    sizeof(response), &used));
}

ATF_TC_WITHOUT_HEAD(config_and_stream_information);
ATF_TC_BODY(config_and_stream_information, tc)
{
	struct sound_model model;
	struct virtio_snd_host *host;
	uint8_t config[16], request[16], response[68];
	size_t used;

	memset(&model, 0, sizeof(model));
	host = new_host(&model);
	ATF_REQUIRE_EQ(virtio_snd_host_config_encode(config), 0);
	ATF_CHECK_EQ(le32dec(config), 0);
	ATF_CHECK_EQ(le32dec(config + 4), 2);
	ATF_CHECK_EQ(le32dec(config + 8), 0);
	ATF_CHECK_EQ(le32dec(config + 12), 0);

	memset(request, 0, sizeof(request));
	le32enc(request, DOC_R_PCM_INFO);
	le32enc(request + 8, 2);
	le32enc(request + 12, 32);
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_OK);
	ATF_CHECK_EQ(used, sizeof(response));
	ATF_CHECK_EQ(le64dec(response + 12), UINT64_C(1) << DOC_FMT_S16);
	ATF_CHECK_EQ(le64dec(response + 20),
	    (UINT64_C(1) << DOC_RATE_44100) |
	    (UINT64_C(1) << DOC_RATE_48000));
	ATF_CHECK_EQ(response[28], 0);
	ATF_CHECK_EQ(response[60], 1);
	for (size_t i = 31; i < 36; i++)
		ATF_CHECK_EQ(response[i], 0);
	for (size_t i = 63; i < 68; i++)
		ATF_CHECK_EQ(response[i], 0);
	virtio_snd_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(information_bounds_are_atomic);
ATF_TC_BODY(information_bounds_are_atomic, tc)
{
	struct sound_model model;
	struct virtio_snd_host *host;
	uint8_t request[16], response[68];
	size_t used;

	memset(&model, 0, sizeof(model));
	host = new_host(&model);
	memset(request, 0, sizeof(request));
	le32enc(request, DOC_R_PCM_INFO);
	le32enc(request + 4, UINT32_MAX);
	le32enc(request + 8, 2);
	le32enc(request + 12, 32);
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_BAD_MSG);
	ATF_CHECK_EQ(used, 4);
	for (size_t i = 4; i < sizeof(response); i++)
		ATF_CHECK_EQ(response[i], 0xa5);

	le32enc(request + 4, 0);
	le32enc(request + 8, 2);
	ATF_CHECK_EQ(control(host, request, sizeof(request), response, 67,
	    &used), DOC_S_BAD_MSG);
	ATF_CHECK_EQ(used, 4);
	le32enc(request + 12, 31);
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_BAD_MSG);
	virtio_snd_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(parameter_and_lifecycle_state_machine);
ATF_TC_BODY(parameter_and_lifecycle_state_machine, tc)
{
	struct sound_model model;
	struct virtio_snd_host *host;
	enum virtio_snd_host_stream_state state;
	struct virtio_snd_host_params params;
	uint8_t request[24], response[4];
	size_t used;

	memset(&model, 0, sizeof(model));
	host = new_host(&model);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_START, 0), DOC_S_BAD_MSG);
	make_params(request, 0);
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_PREPARE, 0), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_START, 0), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_RELEASE, 0), DOC_S_BAD_MSG);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_STOP, 0), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_START, 0), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_STOP, 0), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_RELEASE, 0), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_PREPARE, 0), DOC_S_OK);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(host, 0, &state, &params), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_PREPARED);
	ATF_CHECK_EQ(params.buffer_bytes, 4096);
	memset(&params, 0, sizeof(params));
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(host, 0, NULL, &params), 0);
	ATF_CHECK_EQ(params.buffer_bytes, 4096);
	state = BHYVE_VTSND_RELEASED;
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(host, 0, &state, NULL), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_PREPARED);
	ATF_CHECK_EQ(virtio_snd_host_stream_get(host, 0, NULL, NULL), EINVAL);
	ATF_CHECK_EQ(model.set_params_calls, 1);
	ATF_CHECK_EQ(model.prepare_calls, 2);
	ATF_CHECK_EQ(model.start_calls, 2);
	ATF_CHECK_EQ(model.stop_calls, 2);
	ATF_CHECK_EQ(model.release_calls, 1);
	virtio_snd_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(parameters_reject_unsupported_and_reserved_values);
ATF_TC_BODY(parameters_reject_unsupported_and_reserved_values, tc)
{
	struct sound_model model;
	struct virtio_snd_host *host;
	uint8_t request[24], response[4];
	size_t used;

	memset(&model, 0, sizeof(model));
	host = new_host(&model);
	make_params(request, 0);
	request[23] = 1;
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_BAD_MSG);
	make_params(request, 0);
	le32enc(request + 16, 1);
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_NOT_SUPP);
	make_params(request, 0);
	le32enc(request + 12, 1000);
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_NOT_SUPP);
	make_params(request, 0);
	le32enc(request + 8, BHYVE_VTSND_MAX_BUFFER_BYTES + 1);
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_NOT_SUPP);
	make_params(request, 0);
	request[21] = 24;
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_NOT_SUPP);
	/* Zero channels are invalid (and would divide by a zero frame size). */
	make_params(request, 0);
	request[20] = 0;
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_NOT_SUPP);
	/* More than two channels are unsupported even when frame-aligned. */
	make_params(request, 0);
	le32enc(request + 8, 4092);
	le32enc(request + 12, 2046);
	request[20] = 3;
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_NOT_SUPP);
	/* A zero period is invalid (and would divide the buffer by zero). */
	make_params(request, 0);
	le32enc(request + 12, 0);
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_NOT_SUPP);
	/*
	 * The period must be a whole number of frames.  buffer=2044,
	 * period=1022 with two S16 channels (4-byte frames) divides evenly
	 * yet the period is not frame-aligned (1022 % 4 == 2).
	 */
	make_params(request, 0);
	le32enc(request + 8, 2044);
	le32enc(request + 12, 1022);
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_NOT_SUPP);
	make_params(request, 2);
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_BAD_MSG);
	ATF_CHECK_EQ(model.set_params_calls, 0);
	memset(request, 0, sizeof(request));
	le32enc(request, 0xdeadbeef);
	ATF_CHECK_EQ(control(host, request, 4, response, sizeof(response),
	    &used), DOC_S_NOT_SUPP);
	virtio_snd_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(lifecycle_transition_matrix_and_reconfigure_rollback);
ATF_TC_BODY(lifecycle_transition_matrix_and_reconfigure_rollback, tc)
{
	struct sound_model model;
	struct virtio_snd_host *host;
	enum virtio_snd_host_stream_state state;
	struct virtio_snd_host_params current;
	uint8_t request[24], response[4];
	size_t used;

	memset(&model, 0, sizeof(model));
	host = new_host(&model);
	make_params(request, 0);
	ATF_REQUIRE_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_OK);
	/* SET PARAMETERS may repeat from its own state. */
	ATF_REQUIRE_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_OK);
	ATF_REQUIRE_EQ(lifecycle(host, DOC_R_PCM_PREPARE, 0), DOC_S_OK);

	/* PREPARE permits SET PARAMETERS and a PREPARE self-transition. */
	le32enc(request + 8, 8192);
	model.fail = EIO;
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_IO_ERR);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(host, 0, &state,
	    &current), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_PREPARED);
	ATF_CHECK_EQ(current.buffer_bytes, 4096);
	model.fail = 0;
	ATF_REQUIRE_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_OK);
	ATF_REQUIRE_EQ(lifecycle(host, DOC_R_PCM_PREPARE, 0), DOC_S_OK);
	ATF_REQUIRE_EQ(lifecycle(host, DOC_R_PCM_PREPARE, 0), DOC_S_OK);

	ATF_REQUIRE_EQ(lifecycle(host, DOC_R_PCM_START, 0), DOC_S_OK);
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_BAD_MSG);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_PREPARE, 0), DOC_S_BAD_MSG);
	ATF_REQUIRE_EQ(lifecycle(host, DOC_R_PCM_STOP, 0), DOC_S_OK);
	ATF_CHECK_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_BAD_MSG);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_PREPARE, 0), DOC_S_BAD_MSG);
	ATF_REQUIRE_EQ(lifecycle(host, DOC_R_PCM_RELEASE, 0), DOC_S_OK);

	/* RELEASE permits both SET PARAMETERS and PREPARE. */
	ATF_REQUIRE_EQ(control(host, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_OK);
	ATF_REQUIRE_EQ(lifecycle(host, DOC_R_PCM_PREPARE, 0), DOC_S_OK);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(host, 0, &state,
	    &current), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_PREPARED);
	ATF_CHECK_EQ(current.buffer_bytes, 8192);
	ATF_CHECK_EQ(model.set_params_calls, 5);
	ATF_CHECK_EQ(model.prepare_calls, 4);
	ATF_CHECK_EQ(model.start_calls, 1);
	ATF_CHECK_EQ(model.stop_calls, 1);
	ATF_CHECK_EQ(model.release_calls, 1);
	virtio_snd_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(data_queues_enforce_direction_state_and_frames);
ATF_TC_BODY(data_queues_enforce_direction_state_and_frames, tc)
{
	struct sound_model model;
	struct virtio_snd_host *host;
	uint8_t params[24], xfer[4], payload[1024], status[8];
	size_t used;

	memset(&model, 0, sizeof(model));
	memset(payload, 0x3c, sizeof(payload));
	host = new_host(&model);
	make_params(params, 0);
	ATF_CHECK_EQ(control(host, params, sizeof(params), status,
	    sizeof(status), &used), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_PREPARE, 0), DOC_S_OK);
	le32enc(xfer, 0);
	ATF_REQUIRE_EQ(virtio_snd_host_playback(host, xfer, sizeof(xfer),
	    payload, sizeof(payload), status, sizeof(status), &used), 0);
	ATF_CHECK_EQ(le32dec(status), DOC_S_OK);
	ATF_CHECK_EQ(model.playback_calls, 1);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_START, 0), DOC_S_OK);
	ATF_REQUIRE_EQ(virtio_snd_host_playback(host, xfer, sizeof(xfer),
	    payload, sizeof(payload), status, sizeof(status), &used), 0);
	ATF_CHECK_EQ(le32dec(status), DOC_S_OK);
	ATF_CHECK_EQ(model.playback_calls, 2);
	ATF_REQUIRE_EQ(virtio_snd_host_playback(host, xfer, sizeof(xfer),
	    payload, sizeof(payload), status, 7, &used), EMSGSIZE);
	ATF_CHECK_EQ(model.playback_calls, 2);
	le32enc(xfer, 1);
	ATF_REQUIRE_EQ(virtio_snd_host_playback(host, xfer, sizeof(xfer),
	    payload, sizeof(payload), status, sizeof(status), &used), 0);
	ATF_CHECK_EQ(le32dec(status), DOC_S_IO_ERR);

	make_params(params, 1);
	ATF_CHECK_EQ(control(host, params, sizeof(params), status,
	    sizeof(status), &used), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_PREPARE, 1), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_START, 1), DOC_S_OK);
	le32enc(xfer, 1);
	memset(payload, 0, sizeof(payload));
	ATF_REQUIRE_EQ(virtio_snd_host_capture(host, xfer, sizeof(xfer),
	    payload, sizeof(payload), status, sizeof(status), &used), 0);
	ATF_CHECK_EQ(le32dec(status), DOC_S_OK);
	ATF_CHECK_EQ(payload[0], 0x5a);
	ATF_CHECK_EQ(model.capture_calls, 1);
	ATF_REQUIRE_EQ(virtio_snd_host_capture(host, xfer, sizeof(xfer),
	    payload, sizeof(payload), status, 7, &used), EMSGSIZE);
	ATF_CHECK_EQ(model.capture_calls, 1);
	ATF_REQUIRE_EQ(virtio_snd_host_capture(host, xfer, sizeof(xfer),
	    payload, 3, status, sizeof(status), &used), 0);
	ATF_CHECK_EQ(le32dec(status), DOC_S_IO_ERR);
	virtio_snd_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(backend_errors_rollback_and_reset_is_bounded);
ATF_TC_BODY(backend_errors_rollback_and_reset_is_bounded, tc)
{
	struct sound_model model;
	struct virtio_snd_host *host;
	enum virtio_snd_host_stream_state state;
	struct virtio_snd_host_params current;
	uint8_t params[24], response[4];
	size_t used;

	memset(&model, 0, sizeof(model));
	host = new_host(&model);
	make_params(params, 0);
	model.fail = EIO;
	ATF_CHECK_EQ(control(host, params, sizeof(params), response,
	    sizeof(response), &used), DOC_S_IO_ERR);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(host, 0, &state, &current), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_RELEASED);
	model.fail = 0;
	ATF_CHECK_EQ(control(host, params, sizeof(params), response,
	    sizeof(response), &used), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_PREPARE, 0), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_START, 0), DOC_S_OK);
	ATF_REQUIRE_EQ(virtio_snd_host_reset(host), 0);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(host, 0, &state, &current), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_RELEASED);
	ATF_CHECK_EQ(model.stop_calls, 1);
	ATF_CHECK_EQ(model.release_calls, 1);
	make_params(params, 1);
	ATF_CHECK_EQ(control(host, params, sizeof(params), response,
	    sizeof(response), &used), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_PREPARE, 1), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_START, 1), DOC_S_OK);
	model.fail = EIO;
	ATF_REQUIRE_EQ(virtio_snd_host_reset(host), EIO);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(host, 1, &state, &current), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_RUNNING);
	model.fail = 0;
	ATF_REQUIRE_EQ(virtio_snd_host_reset(host), 0);
	virtio_snd_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(async_claim_fences_lifecycle_and_stale_completion);
ATF_TC_BODY(async_claim_fences_lifecycle_and_stale_completion, tc)
{
	struct sound_model model;
	struct virtio_snd_host *host;
	struct virtio_snd_host_xfer_claim claim, duplicate, next;
	uint8_t params[24], response[4], state_bytes[BHYVE_VTSND_STATE_SIZE];
	uint8_t xfer[4];
	size_t used;

	memset(&model, 0, sizeof(model));
	host = new_host(&model);
	make_params(params, 0);
	ATF_REQUIRE_EQ(control(host, params, sizeof(params), response,
	    sizeof(response), &used), DOC_S_OK);
	ATF_REQUIRE_EQ(lifecycle(host, DOC_R_PCM_PREPARE, 0), DOC_S_OK);
	ATF_REQUIRE_EQ(virtio_snd_host_state_encode(host, state_bytes,
	    sizeof(state_bytes)), 0);
	le32enc(xfer, 0);

	ATF_REQUIRE_EQ(virtio_snd_host_xfer_claim(host, xfer, sizeof(xfer),
	    BHYVE_VTSND_OUTPUT, 8, &claim), 0);
	ATF_CHECK_EQ(claim.stream_id, 0);
	ATF_CHECK_EQ(claim.direction, BHYVE_VTSND_OUTPUT);
	ATF_CHECK(claim.generation != 0);
	duplicate = claim;
	memset(&next, 0xa5, sizeof(next));
	ATF_CHECK_EQ(virtio_snd_host_xfer_claim(host, xfer, sizeof(xfer),
	    BHYVE_VTSND_OUTPUT, 8, &next), EBUSY);
	ATF_CHECK_EQ(next.generation, 0);

	/* RELEASE, reset, restore, and snapshot may not pass pending PCM I/O. */
	ATF_CHECK_EQ(lifecycle(host, DOC_R_PCM_RELEASE, 0), DOC_S_IO_ERR);
	ATF_CHECK_EQ(model.release_calls, 0);
	ATF_CHECK_EQ(virtio_snd_host_reset(host), EBUSY);
	ATF_CHECK_EQ(model.release_calls, 0);
	ATF_CHECK_EQ(virtio_snd_host_state_encode(host, state_bytes,
	    sizeof(state_bytes)), EBUSY);
	ATF_CHECK_EQ(virtio_snd_host_state_restore(host, state_bytes,
	    sizeof(state_bytes)), EBUSY);

	ATF_REQUIRE_EQ(virtio_snd_host_xfer_finish(host, &claim), 0);
	ATF_CHECK_EQ(claim.generation, 0);
	ATF_REQUIRE_EQ(virtio_snd_host_state_encode(host, state_bytes,
	    sizeof(state_bytes)), 0);
	ATF_REQUIRE_EQ(virtio_snd_host_xfer_claim(host, xfer, sizeof(xfer),
	    BHYVE_VTSND_OUTPUT, 8, &next), 0);
	ATF_CHECK(next.generation != duplicate.generation);
	ATF_CHECK_EQ(virtio_snd_host_xfer_finish(host, &duplicate), ESTALE);
	ATF_CHECK_EQ(virtio_snd_host_state_encode(host, state_bytes,
	    sizeof(state_bytes)), EBUSY);
	ATF_REQUIRE_EQ(virtio_snd_host_xfer_finish(host, &next), 0);
	ATF_CHECK_EQ(virtio_snd_host_xfer_finish(host, &next), EINVAL);

	ATF_REQUIRE_EQ(lifecycle(host, DOC_R_PCM_RELEASE, 0), DOC_S_OK);
	ATF_CHECK_EQ(model.release_calls, 1);
	ATF_REQUIRE_EQ(virtio_snd_host_reset(host), 0);
	make_params(params, 0);
	ATF_REQUIRE_EQ(control(host, params, sizeof(params), response,
	    sizeof(response), &used), DOC_S_OK);
	ATF_REQUIRE_EQ(lifecycle(host, DOC_R_PCM_PREPARE, 0), DOC_S_OK);
	host->next_xfer_generation = UINT64_MAX;
	ATF_CHECK_EQ(virtio_snd_host_xfer_claim(host, xfer, sizeof(xfer),
	    BHYVE_VTSND_OUTPUT, 8, &next), EOVERFLOW);
	ATF_CHECK_EQ(next.generation, 0);
	virtio_snd_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(portable_state_roundtrip_and_restore_rollback);
ATF_TC_BODY(portable_state_roundtrip_and_restore_rollback, tc)
{
	struct sound_model source_model, target_model;
	struct virtio_snd_host *source, *target;
	enum virtio_snd_host_stream_state state;
	struct virtio_snd_host_params current;
	uint8_t params[24], response[4];
	uint8_t clean_state[BHYVE_VTSND_STATE_SIZE];
	uint8_t state_bytes[BHYVE_VTSND_STATE_SIZE], corrupt[sizeof(state_bytes)];
	size_t used;

	memset(&source_model, 0, sizeof(source_model));
	memset(&target_model, 0, sizeof(target_model));
	source = new_host(&source_model);
	target = new_host(&target_model);
	ATF_REQUIRE_EQ(virtio_snd_host_state_encode(target, clean_state,
	    sizeof(clean_state)), 0);
	make_params(params, 0);
	ATF_CHECK_EQ(control(source, params, sizeof(params), response,
	    sizeof(response), &used), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(source, DOC_R_PCM_PREPARE, 0), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(source, DOC_R_PCM_START, 0), DOC_S_OK);
	make_params(params, 1);
	ATF_CHECK_EQ(control(source, params, sizeof(params), response,
	    sizeof(response), &used), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(source, DOC_R_PCM_PREPARE, 1), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(source, DOC_R_PCM_START, 1), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(source, DOC_R_PCM_STOP, 1), DOC_S_OK);

	ATF_REQUIRE_EQ(virtio_snd_host_state_encode(source, state_bytes,
	    sizeof(state_bytes)), 0);
	ATF_CHECK_EQ(le32dec(state_bytes), 0x31444e53U);
	ATF_CHECK_EQ(le32dec(state_bytes + 4), 1);
	ATF_CHECK_EQ(le32dec(state_bytes + 8), 2);
	ATF_CHECK_EQ(le32dec(state_bytes + 16), BHYVE_VTSND_RUNNING);
	ATF_CHECK_EQ(le32dec(state_bytes + 40), BHYVE_VTSND_STOPPED);
	ATF_REQUIRE_EQ(virtio_snd_host_state_validate(state_bytes,
	    sizeof(state_bytes)), 0);
	ATF_CHECK_EQ(target_model.set_params_calls, 0);
	ATF_CHECK_EQ(target_model.prepare_calls, 0);
	ATF_CHECK_EQ(target_model.start_calls, 0);
	ATF_CHECK_EQ(target_model.stop_calls, 0);
	ATF_REQUIRE_EQ(virtio_snd_host_state_restore(target, state_bytes,
	    sizeof(state_bytes)), 0);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(target, 0, &state,
	    &current), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_RUNNING);
	ATF_CHECK_EQ(current.buffer_bytes, 4096);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(target, 1, &state,
	    &current), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_STOPPED);
	ATF_CHECK_EQ(target_model.set_params_calls, 2);
	ATF_CHECK_EQ(target_model.prepare_calls, 2);
	ATF_CHECK_EQ(target_model.start_calls, 2);
	ATF_CHECK_EQ(target_model.stop_calls, 1);
	/*
	 * State represents control lifecycle only.  A restored RUNNING stream is
	 * restarted through the destination backend, but no source PCM buffer is
	 * retained or replayed as a side effect of restoration.
	 */
	ATF_CHECK_EQ(target_model.playback_calls, 0);
	ATF_CHECK_EQ(target_model.capture_calls, 0);
	ATF_REQUIRE_EQ(virtio_snd_host_state_restore(target, state_bytes,
	    sizeof(state_bytes)), 0);
	ATF_CHECK_EQ(target_model.set_params_calls, 2);
	ATF_CHECK_EQ(target_model.prepare_calls, 2);
	ATF_CHECK_EQ(target_model.start_calls, 2);
	ATF_CHECK_EQ(target_model.stop_calls, 1);
	ATF_CHECK_EQ(target_model.playback_calls, 0);
	ATF_CHECK_EQ(target_model.capture_calls, 0);
	ATF_CHECK_EQ(virtio_snd_host_state_restore(target, clean_state,
	    sizeof(clean_state)), EBUSY);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(target, 0, &state,
	    &current), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_RUNNING);

	memcpy(corrupt, state_bytes, sizeof(corrupt));
	corrupt[12] = 1;
	ATF_CHECK_EQ(virtio_snd_host_state_validate(corrupt,
	    sizeof(corrupt)), EINVAL);
	ATF_CHECK_EQ(virtio_snd_host_state_restore(target, corrupt,
	    sizeof(corrupt)), EINVAL);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(target, 0, &state,
	    &current), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_RUNNING);
	ATF_CHECK_EQ(virtio_snd_host_state_restore(target, state_bytes,
	    sizeof(state_bytes) - 1), EMSGSIZE);

	ATF_REQUIRE_EQ(virtio_snd_host_reset(target), 0);
	target_model.fail_prepare = EIO;
	ATF_CHECK_EQ(virtio_snd_host_state_restore(target, state_bytes,
	    sizeof(state_bytes)), EIO);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(target, 0, &state,
	    &current), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_RELEASED);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(target, 1, &state,
	    &current), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_RELEASED);

	target_model.fail_release = EAGAIN;
	ATF_CHECK_EQ(virtio_snd_host_state_restore(target, state_bytes,
	    sizeof(state_bytes)), EIO);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(target, 0, &state,
	    &current), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_PARAMS);
	ATF_CHECK_EQ(virtio_snd_host_state_encode(target, corrupt,
	    sizeof(corrupt)), EBUSY);
	target_model.fail_prepare = 0;
	ATF_CHECK_EQ(virtio_snd_host_state_restore(target, state_bytes,
	    sizeof(state_bytes)), EAGAIN);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(target, 0, &state,
	    &current), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_PARAMS);
	target_model.fail_release = 0;
	ATF_REQUIRE_EQ(virtio_snd_host_state_restore(target, state_bytes,
	    sizeof(state_bytes)), 0);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(target, 0, &state,
	    &current), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_RUNNING);

	virtio_snd_host_destroy(target);
	virtio_snd_host_destroy(source);
}

ATF_TC_WITHOUT_HEAD(state_encode_rejects_host_alias);
ATF_TC_BODY(state_encode_rejects_host_alias, tc)
{
	struct sound_model model;
	struct virtio_snd_host *host;
	uint8_t state_bytes[BHYVE_VTSND_STATE_SIZE];

	memset(&model, 0, sizeof(model));
	host = new_host(&model);
	ATF_CHECK_EQ(virtio_snd_host_state_encode(host, host,
	    sizeof(state_bytes)), EINVAL);
	ATF_CHECK_EQ(virtio_snd_host_state_encode(host,
	    (uint8_t *)host + sizeof(*host) - 1, sizeof(state_bytes)), EINVAL);
	ATF_CHECK_EQ(virtio_snd_host_state_restore(host, host,
	    sizeof(state_bytes)), EINVAL);
	ATF_CHECK_EQ(virtio_snd_host_state_encode(host, state_bytes,
	    sizeof(state_bytes)), 0);
	ATF_CHECK_EQ(virtio_snd_host_state_validate(state_bytes,
	    sizeof(state_bytes)), 0);
	virtio_snd_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(restore_replays_release_lifecycle);
ATF_TC_BODY(restore_replays_release_lifecycle, tc)
{
	struct sound_model source_model, target_model;
	struct virtio_snd_host *source, *target;
	enum virtio_snd_host_stream_state state;
	struct virtio_snd_host_params current;
	uint8_t params[24], response[4];
	uint8_t state_bytes[BHYVE_VTSND_STATE_SIZE];
	size_t used;

	memset(&source_model, 0, sizeof(source_model));
	memset(&target_model, 0, sizeof(target_model));
	source = new_host(&source_model);
	target = new_host(&target_model);
	make_params(params, 0);
	ATF_CHECK_EQ(control(source, params, sizeof(params), response,
	    sizeof(response), &used), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(source, DOC_R_PCM_PREPARE, 0), DOC_S_OK);
	ATF_CHECK_EQ(lifecycle(source, DOC_R_PCM_RELEASE, 0), DOC_S_OK);
	ATF_REQUIRE_EQ(virtio_snd_host_state_encode(source, state_bytes,
	    sizeof(state_bytes)), 0);
	ATF_CHECK_EQ(le32dec(state_bytes + 16), BHYVE_VTSND_RELEASED);
	ATF_CHECK_EQ(le32dec(state_bytes + 20), VTSND_STATE_PARAMS_VALID);

	ATF_REQUIRE_EQ(virtio_snd_host_state_restore(target, state_bytes,
	    sizeof(state_bytes)), 0);
	ATF_CHECK_EQ(target_model.set_params_calls, 1);
	ATF_CHECK_EQ(target_model.prepare_calls, 1);
	ATF_CHECK_EQ(target_model.release_calls, 1);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(target, 0, &state,
	    &current), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_RELEASED);
	ATF_CHECK_EQ(current.buffer_bytes, 4096);

	ATF_REQUIRE_EQ(virtio_snd_host_state_restore(target, state_bytes,
	    sizeof(state_bytes)), 0);
	ATF_CHECK_EQ(target_model.set_params_calls, 1);
	ATF_CHECK_EQ(target_model.prepare_calls, 1);
	ATF_CHECK_EQ(target_model.release_calls, 1);
	virtio_snd_host_destroy(target);
	virtio_snd_host_destroy(source);
}

ATF_TC_WITHOUT_HEAD(released_stream_restore_rollback_is_retryable);
ATF_TC_BODY(released_stream_restore_rollback_is_retryable, tc)
{
	struct sound_model source_model, target_model;
	struct virtio_snd_host *source, *target;
	enum virtio_snd_host_stream_state state;
	uint8_t params[24], response[4];
	uint8_t state_bytes[BHYVE_VTSND_STATE_SIZE];
	size_t used;

	memset(&source_model, 0, sizeof(source_model));
	memset(&target_model, 0, sizeof(target_model));
	source = new_host(&source_model);
	target = new_host(&target_model);

	make_params(params, 0);
	ATF_REQUIRE_EQ(control(source, params, sizeof(params), response,
	    sizeof(response), &used), DOC_S_OK);
	ATF_REQUIRE_EQ(lifecycle(source, DOC_R_PCM_PREPARE, 0), DOC_S_OK);
	ATF_REQUIRE_EQ(lifecycle(source, DOC_R_PCM_RELEASE, 0), DOC_S_OK);
	make_params(params, 1);
	ATF_REQUIRE_EQ(control(source, params, sizeof(params), response,
	    sizeof(response), &used), DOC_S_OK);
	ATF_REQUIRE_EQ(virtio_snd_host_state_encode(source, state_bytes,
	    sizeof(state_bytes)), 0);

	target_model.fail_set_params_call = 2;
	ATF_CHECK_EQ(virtio_snd_host_state_restore(target, state_bytes,
	    sizeof(state_bytes)), EIO);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(target, 0, &state, NULL), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_RELEASED);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(target, 1, &state, NULL), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_RELEASED);

	target_model.fail_set_params_call = 0;
	ATF_REQUIRE_EQ(virtio_snd_host_state_restore(target, state_bytes,
	    sizeof(state_bytes)), 0);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(target, 0, &state, NULL), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_RELEASED);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(target, 1, &state, NULL), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_PARAMS);

	virtio_snd_host_destroy(target);
	virtio_snd_host_destroy(source);
}

ATF_TC_WITHOUT_HEAD(incomplete_restore_blocks_guest_operations);
ATF_TC_BODY(incomplete_restore_blocks_guest_operations, tc)
{
	struct sound_model source_model, target_model;
	struct virtio_snd_host *source, *target;
	uint8_t params[24], request[8], response[8];
	uint8_t state_bytes[BHYVE_VTSND_STATE_SIZE];
	uint8_t xfer[4], payload[4];
	size_t used;
	unsigned int stop_calls;

	memset(&source_model, 0, sizeof(source_model));
	memset(&target_model, 0, sizeof(target_model));
	source = new_host(&source_model);
	target = new_host(&target_model);

	make_params(params, 0);
	ATF_REQUIRE_EQ(control(source, params, sizeof(params), response,
	    sizeof(response), &used), DOC_S_OK);
	ATF_REQUIRE_EQ(lifecycle(source, DOC_R_PCM_PREPARE, 0), DOC_S_OK);
	ATF_REQUIRE_EQ(lifecycle(source, DOC_R_PCM_START, 0), DOC_S_OK);
	make_params(params, 1);
	ATF_REQUIRE_EQ(control(source, params, sizeof(params), response,
	    sizeof(response), &used), DOC_S_OK);
	ATF_REQUIRE_EQ(virtio_snd_host_state_encode(source, state_bytes,
	    sizeof(state_bytes)), 0);

	/*
	 * Stream zero reaches RUNNING, reconstruction of stream one fails, and
	 * stopping stream zero during compensation fails.  The backend therefore
	 * retains ownership that is not safe for ordinary guest requests.
	 */
	target_model.fail_set_params_call = 2;
	target_model.fail_stop = EAGAIN;
	ATF_CHECK_EQ(virtio_snd_host_state_restore(target, state_bytes,
	    sizeof(state_bytes)), EIO);
	ATF_CHECK(virtio_snd_host_restore_incomplete(target));
	stop_calls = target_model.stop_calls;

	memset(request, 0, sizeof(request));
	le32enc(request, DOC_R_PCM_STOP);
	ATF_CHECK_EQ(control(target, request, sizeof(request), response,
	    sizeof(response), &used), DOC_S_IO_ERR);
	ATF_CHECK_EQ(target_model.stop_calls, stop_calls);

	le32enc(xfer, 0);
	memset(payload, 0x3c, sizeof(payload));
	ATF_REQUIRE_EQ(virtio_snd_host_playback(target, xfer, sizeof(xfer),
	    payload, sizeof(payload), response, sizeof(response), &used), 0);
	ATF_CHECK_EQ(le32dec(response), DOC_S_IO_ERR);
	ATF_CHECK_EQ(target_model.playback_calls, 0);

	/*
	 * Reset is the explicit recovery operation.  Once the backend accepts
	 * cleanup, ordinary control requests become available again.
	 */
	target_model.fail_stop = 0;
	target_model.fail_set_params_call = 0;
	ATF_REQUIRE_EQ(virtio_snd_host_reset(target), 0);
	ATF_CHECK(!virtio_snd_host_restore_incomplete(target));
	make_params(params, 0);
	ATF_CHECK_EQ(control(target, params, sizeof(params), response,
	    sizeof(response), &used), DOC_S_OK);

	virtio_snd_host_destroy(target);
	virtio_snd_host_destroy(source);
}

ATF_TC_WITHOUT_HEAD(public_api_aliases_are_rejected);
ATF_TC_BODY(public_api_aliases_are_rejected, tc)
{
	struct sound_model model;
	struct virtio_snd_host *host;
	struct virtio_snd_host_xfer_claim claim;
	union {
		size_t used;
		uint8_t bytes[16];
	} response;
	uint8_t request[8];
	size_t used;

	memset(&model, 0, sizeof(model));
	host = new_host(&model);
	memset(request, 0, sizeof(request));
	le32enc(request, UINT32_MAX);
	memset(&response, 0xa5, sizeof(response));
	used = 77;
	ATF_CHECK_EQ(virtio_snd_host_control(host, request, sizeof(request),
	    host, 4, &used), EINVAL);
	ATF_CHECK_EQ(used, 77);
	ATF_CHECK_EQ(virtio_snd_host_control(host, request, sizeof(request),
	    request, 4, &used), EINVAL);
	ATF_CHECK_EQ(used, 77);
	ATF_CHECK_EQ(le32dec(request), UINT32_MAX);
	ATF_CHECK_EQ(virtio_snd_host_control(host, request, sizeof(request),
	    response.bytes, sizeof(response.bytes), &response.used), EINVAL);
	for (size_t i = 0; i < sizeof(response.bytes); i++)
		ATF_CHECK_EQ(response.bytes[i], 0xa5);

	claim = (struct virtio_snd_host_xfer_claim) {
		.generation = 19,
		.stream_id = 1,
	};
	ATF_CHECK_EQ(virtio_snd_host_xfer_claim(host, request,
	    sizeof(request), BHYVE_VTSND_OUTPUT, 8,
	    (struct virtio_snd_host_xfer_claim *)host), EINVAL);
	ATF_CHECK_EQ(virtio_snd_host_xfer_claim(host, &claim, sizeof(claim),
	    BHYVE_VTSND_OUTPUT, 8, &claim), EINVAL);
	ATF_CHECK_EQ(claim.generation, 19);
	ATF_CHECK_EQ(claim.stream_id, 1);
	ATF_CHECK_EQ(virtio_snd_host_stream_get(host, 0,
	    (enum virtio_snd_host_stream_state *)host, NULL), EINVAL);

	ATF_REQUIRE_EQ(virtio_snd_host_control(host, request, sizeof(request),
	    response.bytes, sizeof(response.bytes), &used), 0);
	ATF_CHECK_EQ(used, VIRTIO14_SND_STATUS_SIZE);
	ATF_CHECK_EQ(le32dec(response.bytes), DOC_S_NOT_SUPP);
	virtio_snd_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(destroy_drains_selected_backend_callback);
ATF_TC_BODY(destroy_drains_selected_backend_callback, tc)
{
	struct sound_control_thread control_context;
	struct sound_destroy_thread destroy_context;
	struct sound_model model;
	struct virtio_snd_host *host;
	pthread_t control_thread, destroy_thread;

	memset(&model, 0, sizeof(model));
	ATF_REQUIRE_EQ(pthread_mutex_init(&model.callback_mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&model.callback_cond, NULL), 0);
	host = new_host(&model);
	model.block_set_params = true;
	memset(&control_context, 0, sizeof(control_context));
	control_context.host = host;
	make_params(control_context.request, 0);
	ATF_REQUIRE_EQ(pthread_create(&control_thread, NULL,
	    sound_set_params_thread, &control_context), 0);

	/* The operation now owns operation_mutex inside the backend callback. */
	pthread_mutex_lock(&model.callback_mutex);
	while (!model.set_params_entered)
		pthread_cond_wait(&model.callback_cond, &model.callback_mutex);
	pthread_mutex_unlock(&model.callback_mutex);
	destroy_context.host = host;
	ATF_REQUIRE_EQ(pthread_create(&destroy_thread, NULL,
	    sound_destroy_thread, &destroy_context), 0);

	/*
	 * Releasing the callback permits the operation to publish its stream state
	 * and then permits destruction.  Before the destruction fence, freeing the
	 * host here raced that post-callback publication.
	 */
	pthread_mutex_lock(&model.callback_mutex);
	model.release_set_params = true;
	pthread_cond_broadcast(&model.callback_cond);
	pthread_mutex_unlock(&model.callback_mutex);
	ATF_REQUIRE_EQ(pthread_join(control_thread, NULL), 0);
	ATF_REQUIRE_EQ(pthread_join(destroy_thread, NULL), 0);
	ATF_CHECK_EQ(control_context.error, 0);
	ATF_CHECK_EQ(control_context.used, BHYVE_VTSND_STATUS_SIZE);
	ATF_CHECK_EQ(le32dec(control_context.response), DOC_S_OK);
	pthread_cond_destroy(&model.callback_cond);
	pthread_mutex_destroy(&model.callback_mutex);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, config_and_stream_information);
	ATF_TP_ADD_TC(tp, information_bounds_are_atomic);
	ATF_TP_ADD_TC(tp, parameter_and_lifecycle_state_machine);
	ATF_TP_ADD_TC(tp, parameters_reject_unsupported_and_reserved_values);
	ATF_TP_ADD_TC(tp,
	    lifecycle_transition_matrix_and_reconfigure_rollback);
	ATF_TP_ADD_TC(tp, data_queues_enforce_direction_state_and_frames);
	ATF_TP_ADD_TC(tp, backend_errors_rollback_and_reset_is_bounded);
	ATF_TP_ADD_TC(tp,
	    async_claim_fences_lifecycle_and_stale_completion);
	ATF_TP_ADD_TC(tp, portable_state_roundtrip_and_restore_rollback);
	ATF_TP_ADD_TC(tp, state_encode_rejects_host_alias);
	ATF_TP_ADD_TC(tp, restore_replays_release_lifecycle);
	ATF_TP_ADD_TC(tp, released_stream_restore_rollback_is_retryable);
	ATF_TP_ADD_TC(tp, incomplete_restore_blocks_guest_operations);
	ATF_TP_ADD_TC(tp, public_api_aliases_are_rejected);
	ATF_TP_ADD_TC(tp, destroy_drains_selected_backend_callback);
	return (atf_no_error());
}
