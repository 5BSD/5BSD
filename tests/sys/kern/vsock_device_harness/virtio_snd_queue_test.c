/*
 * Independent VirtIO 1.4 section 5.14 descriptor-boundary tests.
 */
#include <sys/endian.h>
#include <sys/uio.h>

#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_1_4_spec.h"
#include "virtio_snd_host.c"
#include "virtio_snd_queue.c"

struct queue_model {
	unsigned int playback_calls;
	unsigned int capture_calls;
};

static int
ok_params(void *arg __unused, uint32_t id __unused,
    const struct virtio_snd_host_params *params __unused)
{
	return (0);
}

static int
ok_lifecycle(void *arg __unused, uint32_t id __unused)
{
	return (0);
}

static int
playback(void *arg, uint32_t id, const void *data, size_t size)
{
	const uint8_t *bytes;
	struct queue_model *model;

	model = arg;
	bytes = data;
	ATF_REQUIRE_EQ(id, 0);
	ATF_REQUIRE_EQ(size, 1024);
	ATF_REQUIRE_EQ(bytes[0], 0x31);
	ATF_REQUIRE_EQ(bytes[size - 1], 0x79);
	model->playback_calls++;
	return (0);
}

static int
capture(void *arg, uint32_t id, void *data, size_t size)
{
	struct queue_model *model;

	model = arg;
	ATF_REQUIRE_EQ(id, 1);
	memset(data, 0x5c, size);
	model->capture_calls++;
	return (0);
}

static struct virtio_snd_host *
new_host(struct queue_model *model)
{
	const struct virtio_snd_host_ops ops = {
		.set_params = ok_params,
		.prepare = ok_lifecycle,
		.start = ok_lifecycle,
		.stop = ok_lifecycle,
		.release = ok_lifecycle,
		.playback = playback,
		.capture = capture,
		.arg = model,
	};
	struct virtio_snd_host *host;

	ATF_REQUIRE_EQ(virtio_snd_host_create(&ops, &host), 0);
	return (host);
}

static uint32_t
control(struct virtio_snd_host *host, uint8_t *request, size_t request_size)
{
	struct iovec input[2], output[2];
	uint8_t response[8];
	size_t used;

	memset(response, 0, sizeof(response));
	input[0].iov_base = request;
	input[0].iov_len = 3;
	input[1].iov_base = request + 3;
	input[1].iov_len = request_size - 3;
	output[0].iov_base = response;
	output[0].iov_len = 1;
	output[1].iov_base = response + 1;
	output[1].iov_len = sizeof(response) - 1;
	ATF_REQUIRE_EQ(virtio_snd_queue_control(host, input, 2, output, 2,
	    &used), 0);
	ATF_REQUIRE_EQ(used, VIRTIO14_SND_STATUS_SIZE);
	return (le32dec(response));
}

static void
configure(struct virtio_snd_host *host, uint32_t id)
{
	uint8_t request[24];

	memset(request, 0, sizeof(request));
	le32enc(request, VIRTIO14_SND_R_PCM_SET_PARAMS);
	le32enc(request + 4, id);
	le32enc(request + 8, 4096);
	le32enc(request + 12, 1024);
	request[20] = 2;
	request[21] = VIRTIO14_SND_PCM_FMT_S16;
	request[22] = VIRTIO14_SND_PCM_RATE_48000;
	ATF_REQUIRE_EQ(control(host, request, sizeof(request)),
	    VIRTIO14_SND_S_OK);
	memset(request, 0, 8);
	le32enc(request, VIRTIO14_SND_R_PCM_PREPARE);
	le32enc(request + 4, id);
	ATF_REQUIRE_EQ(control(host, request, 8), VIRTIO14_SND_S_OK);
	le32enc(request, VIRTIO14_SND_R_PCM_START);
	ATF_REQUIRE_EQ(control(host, request, 8), VIRTIO14_SND_S_OK);
}

ATF_TC_WITHOUT_HEAD(fragmented_control_and_playback);
ATF_TC_BODY(fragmented_control_and_playback, tc)
{
	struct queue_model model;
	struct virtio_snd_host *host;
	struct iovec input[3], output[2];
	uint8_t first[5], middle[511], last[512], status[8];
	size_t used;

	memset(&model, 0, sizeof(model));
	host = new_host(&model);
	configure(host, 0);
	le32enc(first, 0);
	first[4] = 0x31;
	memset(middle, 0x44, sizeof(middle));
	memset(last, 0x55, sizeof(last));
	last[sizeof(last) - 1] = 0x79;
	input[0] = (struct iovec){ first, sizeof(first) };
	input[1] = (struct iovec){ middle, sizeof(middle) };
	input[2] = (struct iovec){ last, sizeof(last) };
	output[0] = (struct iovec){ status, 3 };
	output[1] = (struct iovec){ status + 3, 5 };
	ATF_REQUIRE_EQ(virtio_snd_queue_playback(host, input, 3, output, 2,
	    &used), 0);
	ATF_CHECK_EQ(used, sizeof(status));
	ATF_CHECK_EQ(le32dec(status), VIRTIO14_SND_S_OK);
	ATF_CHECK_EQ(le32dec(status + 4), 0);
	ATF_CHECK_EQ(model.playback_calls, 1);
	virtio_snd_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(capture_places_status_after_fragmented_payload);
ATF_TC_BODY(capture_places_status_after_fragmented_payload, tc)
{
	struct queue_model model;
	struct virtio_snd_host *host;
	struct iovec input, output[3];
	uint8_t request[4], first[333], second[691], status[8];
	size_t used;

	memset(&model, 0, sizeof(model));
	host = new_host(&model);
	configure(host, 1);
	le32enc(request, 1);
	memset(first, 0, sizeof(first));
	memset(second, 0, sizeof(second));
	memset(status, 0xa5, sizeof(status));
	input = (struct iovec){ request, sizeof(request) };
	output[0] = (struct iovec){ first, sizeof(first) };
	output[1] = (struct iovec){ second, sizeof(second) };
	output[2] = (struct iovec){ status, sizeof(status) };
	ATF_REQUIRE_EQ(virtio_snd_queue_capture(host, &input, 1, output, 3,
	    &used), 0);
	ATF_CHECK_EQ(used, 1032);
	ATF_CHECK_EQ(first[0], 0x5c);
	ATF_CHECK_EQ(second[sizeof(second) - 1], 0x5c);
	ATF_CHECK_EQ(le32dec(status), VIRTIO14_SND_S_OK);
	ATF_CHECK_EQ(le32dec(status + 4), 0);
	ATF_CHECK_EQ(model.capture_calls, 1);
	virtio_snd_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(malformed_geometry_has_no_backend_side_effect);
ATF_TC_BODY(malformed_geometry_has_no_backend_side_effect, tc)
{
	struct queue_model model;
	struct virtio_snd_host *host;
	struct iovec input, output;
	uint8_t request[4], status[8];
	size_t used;

	memset(&model, 0, sizeof(model));
	host = new_host(&model);
	le32enc(request, 0);
	input = (struct iovec){ request, sizeof(request) };
	output = (struct iovec){ status, sizeof(status) };
	ATF_CHECK_EQ(virtio_snd_queue_playback(host, &input, 1, &output, 1,
	    &used), EINVAL);
	ATF_CHECK_EQ(model.playback_calls, 0);
	input.iov_len = 3;
	ATF_CHECK_EQ(virtio_snd_queue_capture(host, &input, 1, &output, 1,
	    &used), EINVAL);
	ATF_CHECK_EQ(model.capture_calls, 0);
	output.iov_base = NULL;
	ATF_CHECK_EQ(virtio_snd_queue_control(host, &input, 1, &output, 1,
	    &used), EINVAL);
	virtio_snd_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(async_prepare_and_completion_are_backend_free);
ATF_TC_BODY(async_prepare_and_completion_are_backend_free, tc)
{
	struct queue_model model;
	struct virtio_snd_host *host;
	struct virtio_snd_host_xfer_claim claim;
	struct iovec input[2], output[3];
	uint8_t request[4], playback[8], capture[8], produced[8], status[8];
	size_t payload_size, used;

	memset(&model, 0, sizeof(model));
	host = new_host(&model);
	configure(host, 0);
	configure(host, 1);

	le32enc(request, 0);
	memset(playback, 0x67, sizeof(playback));
	memset(status, 0xa5, sizeof(status));
	input[0] = (struct iovec){ request, sizeof(request) };
	input[1] = (struct iovec){ playback, sizeof(playback) };
	output[0] = (struct iovec){ status, 3 };
	output[1] = (struct iovec){ status + 3, 5 };
	ATF_REQUIRE_EQ(virtio_snd_queue_playback_prepare(host, input, 2,
	    output, 2, &claim, &payload_size), 0);
	ATF_CHECK_EQ(claim.stream_id, 0);
	ATF_CHECK(claim.generation != 0);
	ATF_CHECK_EQ(payload_size, sizeof(playback));
	ATF_CHECK_EQ(model.playback_calls, 0);
	ATF_REQUIRE_EQ(virtio_snd_queue_playback_complete(output, 2, 0,
	    &used), 0);
	ATF_REQUIRE_EQ(virtio_snd_host_xfer_finish(host, &claim), 0);
	ATF_CHECK_EQ(used, sizeof(status));
	ATF_CHECK_EQ(le32dec(status), VIRTIO14_SND_S_OK);
	ATF_CHECK_EQ(le32dec(status + 4), 0);

	le32enc(request, 1);
	memset(capture, 0xa5, sizeof(capture));
	memset(status, 0xa5, sizeof(status));
	input[0] = (struct iovec){ request, sizeof(request) };
	output[0] = (struct iovec){ capture, 3 };
	output[1] = (struct iovec){ capture + 3, 5 };
	output[2] = (struct iovec){ status, sizeof(status) };
	ATF_REQUIRE_EQ(virtio_snd_queue_capture_prepare(host, input, 1,
	    output, 3, &claim, &payload_size), 0);
	ATF_CHECK_EQ(claim.stream_id, 1);
	ATF_CHECK(claim.generation != 0);
	ATF_CHECK_EQ(payload_size, sizeof(capture));
	ATF_CHECK_EQ(model.capture_calls, 0);
	ATF_REQUIRE_EQ(virtio_snd_queue_capture_complete(output, 3, NULL,
	    payload_size, EIO, &used), 0);
	ATF_REQUIRE_EQ(virtio_snd_host_xfer_finish(host, &claim), 0);
	ATF_CHECK_EQ(used, sizeof(capture) + sizeof(status));
	for (size_t i = 0; i < sizeof(capture); i++)
		ATF_CHECK_EQ(capture[i], 0);
	ATF_CHECK_EQ(le32dec(status), VIRTIO14_SND_S_IO_ERR);
	ATF_CHECK_EQ(le32dec(status + 4), 0);
	for (size_t i = 0; i < sizeof(produced); i++)
		produced[i] = (uint8_t)(0x20 + i);
	memset(capture, 0, sizeof(capture));
	memset(status, 0xa5, sizeof(status));
	ATF_REQUIRE_EQ(virtio_snd_queue_capture_prepare(host, input, 1,
	    output, 3, &claim, &payload_size), 0);
	ATF_REQUIRE_EQ(virtio_snd_queue_capture_complete(output, 3,
	    produced, payload_size, 0, &used), 0);
	for (size_t i = 0; i < sizeof(capture); i++)
		ATF_CHECK_EQ(capture[i], produced[i]);
	ATF_CHECK_EQ(le32dec(status), VIRTIO14_SND_S_OK);
	ATF_CHECK_EQ(le32dec(status + 4), 0);
	ATF_CHECK_EQ(virtio_snd_queue_capture_complete(output, 3, produced,
	    SIZE_MAX, 0, &used), EINVAL);
	ATF_REQUIRE_EQ(virtio_snd_host_xfer_finish(host, &claim), 0);
	virtio_snd_host_destroy(host);
}

ATF_TC_WITHOUT_HEAD(release_error_completions_are_backend_independent);
ATF_TC_BODY(release_error_completions_are_backend_independent, tc)
{
	struct iovec input[2], output[2];
	uint8_t request[4], payload[16], recorded[16], status[8];
	uint32_t code, stream_id;
	size_t used;

	le32enc(request, 0);
	memset(payload, 0x31, sizeof(payload));
	memset(recorded, 0xa5, sizeof(recorded));
	memset(status, 0xa5, sizeof(status));
	input[0] = (struct iovec){ request, sizeof(request) };
	input[1] = (struct iovec){ payload, sizeof(payload) };
	output[0] = (struct iovec){ status, 3 };
	output[1] = (struct iovec){ status + 3, 5 };
	ATF_REQUIRE_EQ(virtio_snd_queue_playback_error(input, 2, output, 2,
	    &used), 0);
	ATF_CHECK_EQ(used, sizeof(status));
	ATF_CHECK_EQ(le32dec(status), VIRTIO14_SND_S_IO_ERR);
	ATF_CHECK_EQ(le32dec(status + 4), 0);

	le32enc(request, 1);
	input[0] = (struct iovec){ request, 2 };
	input[1] = (struct iovec){ request + 2, 2 };
	output[0] = (struct iovec){ recorded, sizeof(recorded) };
	output[1] = (struct iovec){ status, sizeof(status) };
	ATF_REQUIRE_EQ(virtio_snd_queue_capture_error(input, 2, output, 2,
	    &used), 0);
	ATF_CHECK_EQ(used, sizeof(recorded) + sizeof(status));
	for (size_t i = 0; i < sizeof(recorded); i++)
		ATF_CHECK_EQ(recorded[i], 0);
	ATF_CHECK_EQ(le32dec(status), VIRTIO14_SND_S_IO_ERR);
	ATF_CHECK_EQ(le32dec(status + 4), 0);

	uint8_t control_request[8];

	le32enc(control_request, VIRTIO14_SND_R_PCM_RELEASE);
	le32enc(control_request + 4, 1);
	input[0] = (struct iovec){ control_request, 3 };
	input[1] = (struct iovec){ control_request + 3, 5 };
	ATF_REQUIRE_EQ(virtio_snd_queue_control_header(input, 2, &code,
	    &stream_id), 0);
	ATF_CHECK_EQ(code, VIRTIO14_SND_R_PCM_RELEASE);
	ATF_CHECK_EQ(stream_id, 1);
	input[1].iov_len = 4;
	ATF_CHECK_EQ(virtio_snd_queue_control_header(input, 2, &code,
	    &stream_id), EMSGSIZE);
}

ATF_TC_WITHOUT_HEAD(publication_aliases_are_rejected);
ATF_TC_BODY(publication_aliases_are_rejected, tc)
{
	struct queue_model model;
	struct virtio_snd_host *host;
	struct virtio_snd_host_xfer_claim claim;
	struct iovec input[2], output[2];
	union {
		struct virtio_snd_host_xfer_claim alignment;
		uint8_t bytes[32];
	} request;
	uint8_t payload[8], status[16];
	size_t original_length, payload_size, used;
	uint32_t word;

	memset(&model, 0, sizeof(model));
	host = new_host(&model);
	configure(host, 0);
	memset(&request, 0, sizeof(request));
	memset(payload, 0x31, sizeof(payload));
	memset(status, 0xa5, sizeof(status));
	le32enc(request.bytes, 0);
	input[0] = (struct iovec){ request.bytes, 4 };
	input[1] = (struct iovec){ payload, sizeof(payload) };
	output[0] = (struct iovec){ status, 8 };

	original_length = output[0].iov_len;
	ATF_CHECK_EQ(virtio_snd_queue_playback_complete(output, 1, 0,
	    &output[0].iov_len), EINVAL);
	ATF_CHECK_EQ(output[0].iov_len, original_length);

	used = 99;
	output[0].iov_base = &used;
	ATF_CHECK_EQ(virtio_snd_queue_playback_complete(output, 1, 0,
	    &used), EINVAL);
	ATF_CHECK_EQ(used, 99);

	output[0].iov_base = host;
	ATF_CHECK_EQ(virtio_snd_queue_control(host, input, 1, output, 1,
	    &used), EINVAL);
	ATF_CHECK_EQ(used, 99);

	output[0] = (struct iovec){ status, 6 };
	output[1] = (struct iovec){ status + 4, 6 };
	ATF_CHECK_EQ(virtio_snd_queue_playback_complete(output, 2, 0,
	    &used), EINVAL);
	ATF_CHECK_EQ(used, 99);

	output[0] = (struct iovec){ status, sizeof(payload) + 8 };
	ATF_CHECK_EQ(virtio_snd_queue_capture_complete(output, 1, status,
	    sizeof(payload), 0, &used), EINVAL);
	ATF_CHECK_EQ(used, 99);
	ATF_CHECK_EQ(status[0], 0xa5);

	claim = (struct virtio_snd_host_xfer_claim) {
		.generation = 77,
		.stream_id = 88,
	};
	payload_size = 66;
	ATF_CHECK_EQ(virtio_snd_queue_playback_prepare(host, input, 2,
	    output, 1, (struct virtio_snd_host_xfer_claim *)request.bytes,
	    &payload_size), EINVAL);
	ATF_CHECK_EQ(le32dec(request.bytes), 0);
	ATF_CHECK_EQ(payload_size, 66);
	ATF_CHECK_EQ(virtio_snd_queue_playback_prepare(host, input, 2,
	    output, 1, &claim, (size_t *)&claim.generation), EINVAL);
	ATF_CHECK_EQ(claim.generation, 77);
	ATF_CHECK_EQ(claim.stream_id, 88);

	word = 55;
	ATF_CHECK_EQ(virtio_snd_queue_control_header(input, 1, &word, &word),
	    EINVAL);
	ATF_CHECK_EQ(word, 55);

	output[0] = (struct iovec){ status, 8 };
	ATF_REQUIRE_EQ(virtio_snd_queue_playback_complete(output, 1, 0,
	    &used), 0);
	ATF_CHECK_EQ(used, 8);
	ATF_CHECK_EQ(le32dec(status), VIRTIO14_SND_S_OK);
	virtio_snd_host_destroy(host);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fragmented_control_and_playback);
	ATF_TP_ADD_TC(tp, capture_places_status_after_fragmented_payload);
	ATF_TP_ADD_TC(tp, malformed_geometry_has_no_backend_side_effect);
	ATF_TP_ADD_TC(tp, async_prepare_and_completion_are_backend_free);
	ATF_TP_ADD_TC(tp,
	    release_error_completions_are_backend_independent);
	ATF_TP_ADD_TC(tp, publication_aliases_are_rejected);
	return (atf_no_error());
}
