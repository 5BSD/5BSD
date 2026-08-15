/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_snd_host.h"
#include "virtio_state_range.h"

#define	VTSND_R_PCM_INFO	0x0100U
#define	VTSND_R_PCM_SET_PARAMS	0x0101U
#define	VTSND_R_PCM_PREPARE	0x0102U
#define	VTSND_R_PCM_RELEASE	BHYVE_VTSND_R_PCM_RELEASE
#define	VTSND_R_PCM_START	0x0104U
#define	VTSND_R_PCM_STOP	0x0105U

#define	VTSND_S_OK		BHYVE_VTSND_S_OK
#define	VTSND_S_BAD_MSG		0x8001U
#define	VTSND_S_NOT_SUPP	0x8002U
#define	VTSND_S_IO_ERR		BHYVE_VTSND_S_IO_ERR


#define	VTSND_STATE_MAGIC	0x31444e53U	/* "SND1" */
#define	VTSND_STATE_VERSION	1U
#define	VTSND_STATE_HEADER_SIZE	16U
#define	VTSND_STATE_STREAM_SIZE	24U
#define	VTSND_STATE_PARAMS_VALID	0x00000001U

struct virtio_snd_host_stream {
	enum virtio_snd_host_stream_state state;
	struct virtio_snd_host_params params;
	bool params_valid;
	bool xfer_active;
	enum virtio_snd_host_direction xfer_direction;
	uint64_t xfer_generation;
};

struct virtio_snd_host {
	pthread_mutex_t operation_mutex;
	pthread_mutex_t state_mutex;
	struct virtio_snd_host_ops ops;
	struct virtio_snd_host_stream streams[BHYVE_VTSND_STREAMS];
	uint64_t next_xfer_generation;
	bool restore_incomplete;
};

bool
virtio_snd_host_storage_overlaps(struct virtio_snd_host *host,
    const void *storage, size_t length)
{

	if (host == NULL || length == 0)
		return (false);
	return (virtio_state_ranges_overlap(storage, length, host,
	    sizeof(*host)));
}

static int
vtsnd_host_validate_io(struct virtio_snd_host *host,
    const void *request, size_t request_size, const void *payload,
    size_t payload_size, bool payload_writable, void *response,
    size_t response_size, size_t *used)
{

	if (virtio_snd_host_storage_overlaps(host, request, request_size) ||
	    virtio_snd_host_storage_overlaps(host, payload, payload_size) ||
	    virtio_snd_host_storage_overlaps(host, response, response_size) ||
	    virtio_snd_host_storage_overlaps(host, used, sizeof(*used)) ||
	    virtio_state_ranges_overlap(response, response_size, used,
	    sizeof(*used)) ||
	    virtio_state_ranges_overlap(response, response_size, request,
	    request_size) ||
	    virtio_state_ranges_overlap(response, response_size, payload,
	    payload_size) ||
	    virtio_state_ranges_overlap(used, sizeof(*used), request,
	    request_size) ||
	    virtio_state_ranges_overlap(used, sizeof(*used), payload,
	    payload_size) ||
	    (payload_writable && virtio_state_ranges_overlap(payload,
	    payload_size, request, request_size)))
		return (EINVAL);
	return (0);
}

static void
vtsnd_status_encode(void *response, uint32_t status)
{

	le32enc(response, status);
}

static uint32_t
vtsnd_direction(uint32_t stream_id)
{

	return (stream_id == 0 ? BHYVE_VTSND_OUTPUT : BHYVE_VTSND_INPUT);
}

static bool
vtsnd_params_supported(const struct virtio_snd_host_params *params)
{

	return (params->features == 0);
}

static bool
vtsnd_params_valid(const struct virtio_snd_host_params *params)
{
	uint32_t frame_bytes;

	if (params->buffer_bytes == 0 ||
	    params->buffer_bytes > BHYVE_VTSND_MAX_BUFFER_BYTES ||
	    params->period_bytes == 0 ||
	    params->period_bytes > params->buffer_bytes ||
	    params->buffer_bytes % params->period_bytes != 0 ||
	    params->channels < 1 || params->channels > 2 ||
	    params->format != BHYVE_VTSND_FMT_S16 ||
	    (params->rate != BHYVE_VTSND_RATE_44100 &&
	    params->rate != BHYVE_VTSND_RATE_48000))
		return (false);
	frame_bytes = (uint32_t)params->channels * 2U;
	return (params->buffer_bytes % frame_bytes == 0 &&
	    params->period_bytes % frame_bytes == 0);
}

static void
vtsnd_pcm_info_encode(uint8_t info[BHYVE_VTSND_PCM_INFO_SIZE],
    uint32_t stream_id)
{

	memset(info, 0, BHYVE_VTSND_PCM_INFO_SIZE);
	/* hda_fn_nid and stream feature bits remain zero. */
	le64enc(info + 8, UINT64_C(1) << BHYVE_VTSND_FMT_S16);
	le64enc(info + 16, (UINT64_C(1) << BHYVE_VTSND_RATE_44100) |
	    (UINT64_C(1) << BHYVE_VTSND_RATE_48000));
	info[24] = (uint8_t)vtsnd_direction(stream_id);
	info[25] = 1;
	info[26] = 2;
}

int
virtio_snd_host_create(const struct virtio_snd_host_ops *ops,
    struct virtio_snd_host **result)
{
	struct virtio_snd_host *host;
	int error;

	if (ops == NULL || result == NULL || ops->set_params == NULL ||
	    ops->prepare == NULL || ops->start == NULL || ops->stop == NULL ||
	    ops->release == NULL || ops->playback == NULL ||
	    ops->capture == NULL)
		return (EINVAL);
	host = calloc(1, sizeof(*host));
	if (host == NULL)
		return (ENOMEM);
	error = pthread_mutex_init(&host->operation_mutex, NULL);
	if (error != 0) {
		free(host);
		return (error);
	}
	error = pthread_mutex_init(&host->state_mutex, NULL);
	if (error != 0) {
		pthread_mutex_destroy(&host->operation_mutex);
		free(host);
		return (error);
	}
	host->ops = *ops;
	*result = host;
	return (0);
}

void
virtio_snd_host_destroy(struct virtio_snd_host *host)
{

	if (host == NULL)
		return;
	/*
	 * Every public operation holds operation_mutex while it invokes the
	 * selected backend callback.  Take it before destroying either mutex so
	 * teardown cannot free the model or its callback argument while a backend
	 * operation is still in progress.  The state lock is acquired second to
	 * preserve the public operation lock order.
	 */
	pthread_mutex_lock(&host->operation_mutex);
	pthread_mutex_lock(&host->state_mutex);
	pthread_mutex_unlock(&host->state_mutex);
	pthread_mutex_unlock(&host->operation_mutex);
	pthread_mutex_destroy(&host->state_mutex);
	pthread_mutex_destroy(&host->operation_mutex);
	free(host);
}

int
virtio_snd_host_config_encode(uint8_t config[BHYVE_VTSND_CONFIG_SIZE])
{

	if (config == NULL)
		return (EINVAL);
	memset(config, 0, BHYVE_VTSND_CONFIG_SIZE);
	/* jacks=0, streams=2, chmaps=0, controls=0. */
	le32enc(config + 4, BHYVE_VTSND_STREAMS);
	return (0);
}

static uint32_t
vtsnd_info(const uint8_t *request, size_t request_size, uint8_t *response,
    size_t response_size, size_t *used)
{
	uint32_t start, count, size;
	size_t required;

	if (request_size != BHYVE_VTSND_QUERY_SIZE)
		return (VTSND_S_BAD_MSG);
	start = le32dec(request + 4);
	count = le32dec(request + 8);
	size = le32dec(request + 12);
	if (size != BHYVE_VTSND_PCM_INFO_SIZE ||
	    start > BHYVE_VTSND_STREAMS ||
	    count > BHYVE_VTSND_STREAMS - start)
		return (VTSND_S_BAD_MSG);
	required = BHYVE_VTSND_STATUS_SIZE +
	    (size_t)count * BHYVE_VTSND_PCM_INFO_SIZE;
	if (response_size < required)
		return (VTSND_S_BAD_MSG);
	for (uint32_t i = 0; i < count; i++)
		vtsnd_pcm_info_encode(response + BHYVE_VTSND_STATUS_SIZE +
		    (size_t)i * BHYVE_VTSND_PCM_INFO_SIZE, start + i);
	*used = required;
	return (VTSND_S_OK);
}

static uint32_t
vtsnd_set_params(struct virtio_snd_host *host, const uint8_t *request,
    size_t request_size)
{
	struct virtio_snd_host_params params;
	uint32_t stream_id;
	int error;

	if (request_size != BHYVE_VTSND_PCM_PARAMS_SIZE || request[23] != 0)
		return (VTSND_S_BAD_MSG);
	stream_id = le32dec(request + 4);
	if (stream_id >= BHYVE_VTSND_STREAMS)
		return (VTSND_S_BAD_MSG);
	memset(&params, 0, sizeof(params));
	params.buffer_bytes = le32dec(request + 8);
	params.period_bytes = le32dec(request + 12);
	params.features = le32dec(request + 16);
	params.channels = request[20];
	params.format = request[21];
	params.rate = request[22];
	if (!vtsnd_params_supported(&params))
		return (VTSND_S_NOT_SUPP);
	if (!vtsnd_params_valid(&params))
		return (VTSND_S_NOT_SUPP);

	pthread_mutex_lock(&host->state_mutex);
	if (host->streams[stream_id].state == BHYVE_VTSND_RUNNING ||
	    host->streams[stream_id].state == BHYVE_VTSND_STOPPED) {
		pthread_mutex_unlock(&host->state_mutex);
		return (VTSND_S_BAD_MSG);
	}
	pthread_mutex_unlock(&host->state_mutex);
	error = host->ops.set_params(host->ops.arg, stream_id, &params);
	if (error != 0)
		return (VTSND_S_IO_ERR);
	pthread_mutex_lock(&host->state_mutex);
	host->streams[stream_id].params = params;
	host->streams[stream_id].params_valid = true;
	host->streams[stream_id].state = BHYVE_VTSND_PARAMS;
	pthread_mutex_unlock(&host->state_mutex);
	return (VTSND_S_OK);
}

static uint32_t
vtsnd_lifecycle(struct virtio_snd_host *host, uint32_t code,
    const uint8_t *request, size_t request_size)
{
	enum virtio_snd_host_stream_state state, next;
	uint32_t stream_id;
	int (*operation)(void *, uint32_t);
	int error;
	bool params_valid;

	if (request_size != BHYVE_VTSND_PCM_HEADER_SIZE)
		return (VTSND_S_BAD_MSG);
	stream_id = le32dec(request + 4);
	if (stream_id >= BHYVE_VTSND_STREAMS)
		return (VTSND_S_BAD_MSG);
	pthread_mutex_lock(&host->state_mutex);
	state = host->streams[stream_id].state;
	params_valid = host->streams[stream_id].params_valid;
	pthread_mutex_unlock(&host->state_mutex);

	operation = NULL;
	switch (code) {
	case VTSND_R_PCM_PREPARE:
		if (!params_valid || (state != BHYVE_VTSND_PARAMS &&
		    state != BHYVE_VTSND_PREPARED &&
		    state != BHYVE_VTSND_RELEASED))
			return (VTSND_S_BAD_MSG);
		operation = host->ops.prepare;
		next = BHYVE_VTSND_PREPARED;
		break;
	case VTSND_R_PCM_START:
		if (state != BHYVE_VTSND_PREPARED &&
		    state != BHYVE_VTSND_STOPPED)
			return (VTSND_S_BAD_MSG);
		operation = host->ops.start;
		next = BHYVE_VTSND_RUNNING;
		break;
	case VTSND_R_PCM_STOP:
		if (state != BHYVE_VTSND_RUNNING)
			return (VTSND_S_BAD_MSG);
		operation = host->ops.stop;
		next = BHYVE_VTSND_STOPPED;
		break;
	case VTSND_R_PCM_RELEASE:
		if (state != BHYVE_VTSND_PREPARED &&
		    state != BHYVE_VTSND_STOPPED)
			return (VTSND_S_BAD_MSG);
		/*
		 * Section 5.14.6.6.5 requires every pending I/O request to be
		 * completed before RELEASE itself completes.  The transport
		 * owns that ordering; fail closed if it tries to release the
		 * backend while an admitted asynchronous request still exists.
		 */
		if (host->streams[stream_id].xfer_active)
			return (VTSND_S_IO_ERR);
		operation = host->ops.release;
		next = BHYVE_VTSND_RELEASED;
		break;
	default:
		return (VTSND_S_NOT_SUPP);
	}
	error = operation(host->ops.arg, stream_id);
	if (error != 0)
		return (VTSND_S_IO_ERR);
	pthread_mutex_lock(&host->state_mutex);
	host->streams[stream_id].state = next;
	pthread_mutex_unlock(&host->state_mutex);
	return (VTSND_S_OK);
}

int
virtio_snd_host_control(struct virtio_snd_host *host, const void *request,
    size_t request_size, void *response, size_t response_size, size_t *used)
{
	const uint8_t *bytes;
	uint32_t code, status;
	int error;

	if (host == NULL || request == NULL || response == NULL || used == NULL)
		return (EINVAL);
	error = vtsnd_host_validate_io(host, request, request_size, NULL, 0,
	    false, response, response_size, used);
	if (error != 0)
		return (error);
	*used = 0;
	if (response_size < BHYVE_VTSND_STATUS_SIZE)
		return (EMSGSIZE);
	if (request_size < sizeof(uint32_t)) {
		vtsnd_status_encode(response, VTSND_S_BAD_MSG);
		*used = BHYVE_VTSND_STATUS_SIZE;
		return (0);
	}
	bytes = request;
	code = le32dec(bytes);
	pthread_mutex_lock(&host->operation_mutex);
	if (host->restore_incomplete)
		status = VTSND_S_IO_ERR;
	else {
		switch (code) {
		case VTSND_R_PCM_INFO:
			status = vtsnd_info(bytes, request_size, response,
			    response_size, used);
			break;
		case VTSND_R_PCM_SET_PARAMS:
			status = vtsnd_set_params(host, bytes, request_size);
			break;
		case VTSND_R_PCM_PREPARE:
		case VTSND_R_PCM_RELEASE:
		case VTSND_R_PCM_START:
		case VTSND_R_PCM_STOP:
			status = vtsnd_lifecycle(host, code, bytes, request_size);
			break;
		default:
			status = VTSND_S_NOT_SUPP;
			break;
		}
	}
	pthread_mutex_unlock(&host->operation_mutex);
	vtsnd_status_encode(response, status);
	if (*used == 0)
		*used = BHYVE_VTSND_STATUS_SIZE;
	return (0);
}

static int
vtsnd_xfer_begin(struct virtio_snd_host *host, const void *request,
    size_t request_size, uint32_t expected_direction, size_t payload_size,
    uint32_t *stream_id)
{
	struct virtio_snd_host_stream stream;
	uint32_t frame_bytes;

	if (request_size != BHYVE_VTSND_PCM_XFER_SIZE)
		return (EINVAL);
	*stream_id = le32dec(request);
	if (*stream_id >= BHYVE_VTSND_STREAMS ||
	    vtsnd_direction(*stream_id) != expected_direction)
		return (EINVAL);
	pthread_mutex_lock(&host->state_mutex);
	stream = host->streams[*stream_id];
	pthread_mutex_unlock(&host->state_mutex);
	if (!stream.params_valid || payload_size == 0 ||
	    payload_size > stream.params.buffer_bytes)
		return (EINVAL);
	frame_bytes = (uint32_t)stream.params.channels * 2U;
	if (payload_size % frame_bytes != 0)
		return (EINVAL);
	/*
	 * Section 5.14.6.6.1 places output prebuffering between PREPARE and
	 * START.  Input, on the other hand, begins only after START.  Keep the
	 * direction-specific state rule here so direct callers and every
	 * transport enforce the same lifecycle.
	 */
	if (expected_direction == BHYVE_VTSND_OUTPUT) {
		if (stream.state != BHYVE_VTSND_PREPARED &&
		    stream.state != BHYVE_VTSND_RUNNING)
			return (EINVAL);
	} else if (stream.state != BHYVE_VTSND_RUNNING) {
		return (EINVAL);
	}
	return (0);
}

static int
vtsnd_pcm_status(void *response, size_t response_size, size_t *used,
    uint32_t status)
{

	if (response == NULL || used == NULL)
		return (EINVAL);
	*used = 0;
	if (response_size < BHYVE_VTSND_PCM_STATUS_SIZE)
		return (EMSGSIZE);
	memset(response, 0, BHYVE_VTSND_PCM_STATUS_SIZE);
	le32enc(response, status);
	*used = BHYVE_VTSND_PCM_STATUS_SIZE;
	return (0);
}

int
virtio_snd_host_xfer_claim(struct virtio_snd_host *host,
    const void *request, size_t request_size,
    enum virtio_snd_host_direction direction, size_t payload_size,
    struct virtio_snd_host_xfer_claim *claim)
{
	uint32_t stream_id;
	uint64_t generation;
	int error;

	if (host == NULL || request == NULL || claim == NULL ||
	    (direction != BHYVE_VTSND_OUTPUT &&
	    direction != BHYVE_VTSND_INPUT))
		return (EINVAL);
	if (virtio_snd_host_storage_overlaps(host, request, request_size) ||
	    virtio_snd_host_storage_overlaps(host, claim, sizeof(*claim)) ||
	    virtio_state_ranges_overlap(request, request_size, claim,
	    sizeof(*claim)))
		return (EINVAL);
	memset(claim, 0, sizeof(*claim));
	pthread_mutex_lock(&host->operation_mutex);
	if (host->restore_incomplete)
		error = EBUSY;
	else
		error = vtsnd_xfer_begin(host, request, request_size, direction,
		    payload_size, &stream_id);
	if (error == 0 && host->streams[stream_id].xfer_active)
		error = EBUSY;
	if (error == 0) {
		if (host->next_xfer_generation == UINT64_MAX)
			error = EOVERFLOW;
		else
			generation = ++host->next_xfer_generation;
	}
	if (error == 0) {
		host->streams[stream_id].xfer_active = true;
		host->streams[stream_id].xfer_direction = direction;
		host->streams[stream_id].xfer_generation = generation;
		claim->generation = generation;
		claim->stream_id = stream_id;
		claim->direction = direction;
	}
	pthread_mutex_unlock(&host->operation_mutex);
	return (error);
}

int
virtio_snd_host_xfer_finish(struct virtio_snd_host *host,
    struct virtio_snd_host_xfer_claim *claim)
{
	struct virtio_snd_host_stream *stream;
	int error;

	if (host == NULL || claim == NULL)
		return (EINVAL);
	if (virtio_snd_host_storage_overlaps(host, claim, sizeof(*claim)))
		return (EINVAL);
	if (claim->generation == 0 || claim->stream_id >= BHYVE_VTSND_STREAMS ||
	    (claim->direction != BHYVE_VTSND_OUTPUT &&
	    claim->direction != BHYVE_VTSND_INPUT))
		return (EINVAL);
	pthread_mutex_lock(&host->operation_mutex);
	stream = &host->streams[claim->stream_id];
	if (!stream->xfer_active ||
	    stream->xfer_generation != claim->generation ||
	    stream->xfer_direction != claim->direction) {
		error = ESTALE;
	} else {
		stream->xfer_active = false;
		stream->xfer_generation = 0;
		stream->xfer_direction = 0;
		memset(claim, 0, sizeof(*claim));
		error = 0;
	}
	pthread_mutex_unlock(&host->operation_mutex);
	return (error);
}

int
virtio_snd_host_playback(struct virtio_snd_host *host, const void *request,
    size_t request_size, const void *payload, size_t payload_size,
    void *response, size_t response_size, size_t *used)
{
	uint32_t stream_id, status;
	int error;

	if (host == NULL || request == NULL || payload == NULL)
		return (EINVAL);
	if (response == NULL || used == NULL)
		return (EINVAL);
	error = vtsnd_host_validate_io(host, request, request_size, payload,
	    payload_size, false, response, response_size, used);
	if (error != 0)
		return (error);
	*used = 0;
	if (response_size < BHYVE_VTSND_PCM_STATUS_SIZE)
		return (EMSGSIZE);
	pthread_mutex_lock(&host->operation_mutex);
	if (host->restore_incomplete)
		status = VTSND_S_IO_ERR;
	else if (vtsnd_xfer_begin(host, request, request_size,
	    BHYVE_VTSND_OUTPUT,
	    payload_size, &stream_id) != 0)
		status = VTSND_S_IO_ERR;
	else if (host->ops.playback(host->ops.arg, stream_id, payload,
	    payload_size) != 0)
		status = VTSND_S_IO_ERR;
	else
		status = VTSND_S_OK;
	pthread_mutex_unlock(&host->operation_mutex);
	return (vtsnd_pcm_status(response, response_size, used, status));
}

int
virtio_snd_host_capture(struct virtio_snd_host *host, const void *request,
    size_t request_size, void *payload, size_t payload_size, void *response,
    size_t response_size, size_t *used)
{
	uint32_t stream_id, status;
	int error;

	if (host == NULL || request == NULL || payload == NULL)
		return (EINVAL);
	if (response == NULL || used == NULL)
		return (EINVAL);
	error = vtsnd_host_validate_io(host, request, request_size, payload,
	    payload_size, true, response, response_size, used);
	if (error != 0)
		return (error);
	*used = 0;
	if (response_size < BHYVE_VTSND_PCM_STATUS_SIZE)
		return (EMSGSIZE);
	pthread_mutex_lock(&host->operation_mutex);
	if (host->restore_incomplete)
		status = VTSND_S_IO_ERR;
	else if (vtsnd_xfer_begin(host, request, request_size,
	    BHYVE_VTSND_INPUT,
	    payload_size, &stream_id) != 0)
		status = VTSND_S_IO_ERR;
	else if (host->ops.capture(host->ops.arg, stream_id, payload,
	    payload_size) != 0)
		status = VTSND_S_IO_ERR;
	else
		status = VTSND_S_OK;
	pthread_mutex_unlock(&host->operation_mutex);
	return (vtsnd_pcm_status(response, response_size, used, status));
}

int
virtio_snd_host_stream_get(struct virtio_snd_host *host, uint32_t stream_id,
    enum virtio_snd_host_stream_state *state,
    struct virtio_snd_host_params *params)
{

	if (host == NULL || stream_id >= BHYVE_VTSND_STREAMS ||
	    (state == NULL && params == NULL))
		return (EINVAL);
	if (virtio_snd_host_storage_overlaps(host, state,
	    state == NULL ? 0 : sizeof(*state)) ||
	    virtio_snd_host_storage_overlaps(host, params,
	    params == NULL ? 0 : sizeof(*params)) ||
	    virtio_state_ranges_overlap(state, state == NULL ? 0 :
	    sizeof(*state), params, params == NULL ? 0 : sizeof(*params)))
		return (EINVAL);
	pthread_mutex_lock(&host->state_mutex);
	if (state != NULL)
		*state = host->streams[stream_id].state;
	if (params != NULL)
		*params = host->streams[stream_id].params;
	pthread_mutex_unlock(&host->state_mutex);
	return (0);
}

static int
vtsnd_reset_locked(struct virtio_snd_host *host)
{
	int error, first_error;

	for (uint32_t stream_id = 0; stream_id < BHYVE_VTSND_STREAMS;
	    stream_id++) {
		if (host->streams[stream_id].xfer_active)
			return (EBUSY);
	}
	first_error = 0;
	for (uint32_t stream_id = 0; stream_id < BHYVE_VTSND_STREAMS;
	    stream_id++) {
		pthread_mutex_lock(&host->state_mutex);
		enum virtio_snd_host_stream_state state =
		    host->streams[stream_id].state;
		pthread_mutex_unlock(&host->state_mutex);
		if (state == BHYVE_VTSND_RUNNING) {
			error = host->ops.stop(host->ops.arg, stream_id);
			if (error != 0) {
				if (first_error == 0)
					first_error = error;
				continue;
			}
			pthread_mutex_lock(&host->state_mutex);
			host->streams[stream_id].state = BHYVE_VTSND_STOPPED;
			pthread_mutex_unlock(&host->state_mutex);
			state = BHYVE_VTSND_STOPPED;
		}
		if (state != BHYVE_VTSND_RELEASED) {
			error = host->ops.release(host->ops.arg, stream_id);
			if (error != 0) {
				if (first_error == 0)
					first_error = error;
				continue;
			}
		}
		pthread_mutex_lock(&host->state_mutex);
		memset(&host->streams[stream_id], 0,
		    sizeof(host->streams[stream_id]));
		pthread_mutex_unlock(&host->state_mutex);
	}
	return (first_error);
}

int
virtio_snd_host_reset(struct virtio_snd_host *host)
{
	int error;

	if (host == NULL)
		return (EINVAL);
	pthread_mutex_lock(&host->operation_mutex);
	for (uint32_t stream_id = 0; stream_id < BHYVE_VTSND_STREAMS;
	    stream_id++) {
		/*
		 * No backend operation has occurred yet, so this is an ordinary
		 * retryable quiesce failure rather than an incomplete reset.
		 */
		if (host->streams[stream_id].xfer_active) {
			pthread_mutex_unlock(&host->operation_mutex);
			return (EBUSY);
		}
	}
	error = vtsnd_reset_locked(host);
	host->restore_incomplete = error != 0;
	pthread_mutex_unlock(&host->operation_mutex);
	return (error);
}

int
virtio_snd_host_state_encode(struct virtio_snd_host *host, void *buffer,
    size_t buffer_size)
{
	struct virtio_snd_host_stream streams[BHYVE_VTSND_STREAMS];
	uint8_t *bytes;

	if (host == NULL || buffer == NULL)
		return (EINVAL);
	if (buffer_size != BHYVE_VTSND_STATE_SIZE)
		return (EMSGSIZE);
	/*
	 * The state object contains both mutexes and the stream records being
	 * encoded.  Reject an aliased destination before acquiring either
	 * mutex so serialization cannot overwrite its own synchronization or
	 * source state.
	 */
	if (virtio_state_ranges_overlap(buffer, buffer_size, host,
	    sizeof(*host)))
		return (EINVAL);
	pthread_mutex_lock(&host->operation_mutex);
	if (host->restore_incomplete) {
		pthread_mutex_unlock(&host->operation_mutex);
		return (EBUSY);
	}
	for (uint32_t stream_id = 0; stream_id < BHYVE_VTSND_STREAMS;
	    stream_id++) {
		if (host->streams[stream_id].xfer_active) {
			pthread_mutex_unlock(&host->operation_mutex);
			return (EBUSY);
		}
	}
	pthread_mutex_lock(&host->state_mutex);
	memcpy(streams, host->streams, sizeof(streams));
	pthread_mutex_unlock(&host->state_mutex);
	pthread_mutex_unlock(&host->operation_mutex);

	bytes = buffer;
	memset(bytes, 0, buffer_size);
	le32enc(bytes, VTSND_STATE_MAGIC);
	le32enc(bytes + 4, VTSND_STATE_VERSION);
	le32enc(bytes + 8, BHYVE_VTSND_STREAMS);
	for (uint32_t stream_id = 0; stream_id < BHYVE_VTSND_STREAMS;
	    stream_id++) {
		struct virtio_snd_host_stream *stream;
		uint8_t *entry;

		stream = &streams[stream_id];
		entry = bytes + VTSND_STATE_HEADER_SIZE +
		    (size_t)stream_id * VTSND_STATE_STREAM_SIZE;
		le32enc(entry, stream->state);
		le32enc(entry + 4, stream->params_valid ?
		    VTSND_STATE_PARAMS_VALID : 0);
		le32enc(entry + 8, stream->params.buffer_bytes);
		le32enc(entry + 12, stream->params.period_bytes);
		le32enc(entry + 16, stream->params.features);
		entry[20] = stream->params.channels;
		entry[21] = stream->params.format;
		entry[22] = stream->params.rate;
	}
	return (0);
}

static int
vtsnd_state_decode(const void *buffer, size_t buffer_size,
    struct virtio_snd_host_stream streams[BHYVE_VTSND_STREAMS])
{
	const uint8_t *bytes;

	if (buffer == NULL)
		return (EINVAL);
	if (buffer_size != BHYVE_VTSND_STATE_SIZE)
		return (EMSGSIZE);
	bytes = buffer;
	if (le32dec(bytes) != VTSND_STATE_MAGIC ||
	    le32dec(bytes + 4) != VTSND_STATE_VERSION ||
	    le32dec(bytes + 8) != BHYVE_VTSND_STREAMS ||
	    le32dec(bytes + 12) != 0)
		return (EINVAL);
	memset(streams, 0, sizeof(*streams) * BHYVE_VTSND_STREAMS);
	for (uint32_t stream_id = 0; stream_id < BHYVE_VTSND_STREAMS;
	    stream_id++) {
		struct virtio_snd_host_stream *stream;
		const uint8_t *entry;
		uint32_t flags, state;

		stream = &streams[stream_id];
		entry = bytes + VTSND_STATE_HEADER_SIZE +
		    (size_t)stream_id * VTSND_STATE_STREAM_SIZE;
		state = le32dec(entry);
		flags = le32dec(entry + 4);
		if (state > BHYVE_VTSND_STOPPED ||
		    (flags & ~VTSND_STATE_PARAMS_VALID) != 0 ||
		    entry[23] != 0)
			return (EINVAL);
		stream->state = state;
		stream->params_valid =
		    (flags & VTSND_STATE_PARAMS_VALID) != 0;
		stream->params.buffer_bytes = le32dec(entry + 8);
		stream->params.period_bytes = le32dec(entry + 12);
		stream->params.features = le32dec(entry + 16);
		stream->params.channels = entry[20];
		stream->params.format = entry[21];
		stream->params.rate = entry[22];
		if (!stream->params_valid) {
			if (state != BHYVE_VTSND_RELEASED ||
			    stream->params.buffer_bytes != 0 ||
			    stream->params.period_bytes != 0 ||
			    stream->params.features != 0 ||
			    stream->params.channels != 0 ||
			    stream->params.format != 0 ||
			    stream->params.rate != 0)
				return (EINVAL);
		} else if (!vtsnd_params_supported(&stream->params) ||
		    !vtsnd_params_valid(&stream->params)) {
			return (EINVAL);
		}
	}
	return (0);
}

static bool
vtsnd_stream_equal(const struct virtio_snd_host_stream *left,
    const struct virtio_snd_host_stream *right)
{

	return (left->state == right->state &&
	    left->params_valid == right->params_valid &&
	    left->params.buffer_bytes == right->params.buffer_bytes &&
	    left->params.period_bytes == right->params.period_bytes &&
	    left->params.features == right->params.features &&
	    left->params.channels == right->params.channels &&
	    left->params.format == right->params.format &&
	    left->params.rate == right->params.rate);
}

int
virtio_snd_host_state_validate(const void *buffer, size_t buffer_size)
{
	struct virtio_snd_host_stream streams[BHYVE_VTSND_STREAMS];

	return (vtsnd_state_decode(buffer, buffer_size, streams));
}

int
virtio_snd_host_state_restore(struct virtio_snd_host *host,
    const void *buffer, size_t buffer_size)
{
	struct virtio_snd_host_stream current[BHYVE_VTSND_STREAMS];
	struct virtio_snd_host_stream streams[BHYVE_VTSND_STREAMS];
	bool identical;
	int error;

	if (host == NULL)
		return (EINVAL);
	if (buffer == NULL ||
	    virtio_state_ranges_overlap(buffer, buffer_size, host,
	    sizeof(*host)))
		return (EINVAL);
	error = vtsnd_state_decode(buffer, buffer_size, streams);
	if (error != 0)
		return (error);
	pthread_mutex_lock(&host->operation_mutex);
	for (uint32_t stream_id = 0; stream_id < BHYVE_VTSND_STREAMS;
	    stream_id++) {
		if (host->streams[stream_id].xfer_active) {
			pthread_mutex_unlock(&host->operation_mutex);
			return (EBUSY);
		}
	}
	if (host->restore_incomplete) {
		error = vtsnd_reset_locked(host);
		if (error != 0) {
			pthread_mutex_unlock(&host->operation_mutex);
			return (error);
		}
		host->restore_incomplete = false;
	}
	pthread_mutex_lock(&host->state_mutex);
	memcpy(current, host->streams, sizeof(current));
	pthread_mutex_unlock(&host->state_mutex);
	identical = true;
	for (uint32_t stream_id = 0; stream_id < BHYVE_VTSND_STREAMS;
	    stream_id++) {
		if (!vtsnd_stream_equal(&current[stream_id],
		    &streams[stream_id]))
			identical = false;
	}
	if (identical) {
		pthread_mutex_unlock(&host->operation_mutex);
		return (0);
	}
	for (uint32_t stream_id = 0; stream_id < BHYVE_VTSND_STREAMS;
	    stream_id++) {
		if (current[stream_id].state != BHYVE_VTSND_RELEASED ||
		    current[stream_id].params_valid) {
			pthread_mutex_unlock(&host->operation_mutex);
			return (EBUSY);
		}
	}
	for (uint32_t stream_id = 0; stream_id < BHYVE_VTSND_STREAMS;
	    stream_id++) {
		const struct virtio_snd_host_stream *stream;

		stream = &streams[stream_id];
		if (!stream->params_valid)
			continue;
		error = host->ops.set_params(host->ops.arg, stream_id,
		    &stream->params);
		if (error != 0)
			goto failed;
		pthread_mutex_lock(&host->state_mutex);
		host->streams[stream_id].params = stream->params;
		host->streams[stream_id].params_valid = true;
		host->streams[stream_id].state = BHYVE_VTSND_PARAMS;
		pthread_mutex_unlock(&host->state_mutex);
		if (stream->state == BHYVE_VTSND_PARAMS)
			continue;
		error = host->ops.prepare(host->ops.arg, stream_id);
		if (error != 0)
			goto failed;
		pthread_mutex_lock(&host->state_mutex);
		host->streams[stream_id].state = BHYVE_VTSND_PREPARED;
		pthread_mutex_unlock(&host->state_mutex);
		if (stream->state == BHYVE_VTSND_RELEASED) {
			/*
			 * RELEASED with retained parameters means that the source
			 * completed SET_PARAMS -> PREPARE -> RELEASE.  Reconstruct
			 * that lifecycle; a backend need not accept RELEASE
			 * directly from SET_PARAMS.
			 */
			error = host->ops.release(host->ops.arg, stream_id);
			if (error != 0)
				goto failed;
			pthread_mutex_lock(&host->state_mutex);
			host->streams[stream_id].state = BHYVE_VTSND_RELEASED;
			pthread_mutex_unlock(&host->state_mutex);
			continue;
		}
		if (stream->state == BHYVE_VTSND_PREPARED)
			continue;
		error = host->ops.start(host->ops.arg, stream_id);
		if (error != 0)
			goto failed;
		pthread_mutex_lock(&host->state_mutex);
		host->streams[stream_id].state = BHYVE_VTSND_RUNNING;
		pthread_mutex_unlock(&host->state_mutex);
		if (stream->state == BHYVE_VTSND_RUNNING)
			continue;
		error = host->ops.stop(host->ops.arg, stream_id);
		if (error != 0)
			goto failed;
		pthread_mutex_lock(&host->state_mutex);
		host->streams[stream_id].state = BHYVE_VTSND_STOPPED;
		pthread_mutex_unlock(&host->state_mutex);
	}
	pthread_mutex_lock(&host->state_mutex);
	memcpy(host->streams, streams, sizeof(streams));
	pthread_mutex_unlock(&host->state_mutex);
	host->restore_incomplete = false;
	pthread_mutex_unlock(&host->operation_mutex);
	return (0);

failed:
	/*
	 * Roll back only stages known to have reached the backend.  Do this
	 * directly because operation_mutex is already held.
	 */
	host->restore_incomplete = false;
	for (uint32_t stream_id = 0; stream_id < BHYVE_VTSND_STREAMS;
	    stream_id++) {
		enum virtio_snd_host_stream_state state;
		int cleanup_error;

		pthread_mutex_lock(&host->state_mutex);
		state = host->streams[stream_id].state;
		pthread_mutex_unlock(&host->state_mutex);
		if (state == BHYVE_VTSND_RUNNING) {
			cleanup_error = host->ops.stop(host->ops.arg, stream_id);
			if (cleanup_error != 0) {
				host->restore_incomplete = true;
				continue;
			}
			state = BHYVE_VTSND_STOPPED;
			pthread_mutex_lock(&host->state_mutex);
			host->streams[stream_id].state = state;
			pthread_mutex_unlock(&host->state_mutex);
		}
		if (state == BHYVE_VTSND_RELEASED) {
			/*
			 * A restored RELEASED stream has already surrendered all
			 * backend ownership.  Its retained parameters belong to
			 * the source-visible final state, not to rollback state.
			 */
			pthread_mutex_lock(&host->state_mutex);
			memset(&host->streams[stream_id], 0,
			    sizeof(host->streams[stream_id]));
			pthread_mutex_unlock(&host->state_mutex);
			continue;
		}
		cleanup_error = host->ops.release(host->ops.arg, stream_id);
		if (cleanup_error != 0) {
			host->restore_incomplete = true;
			continue;
		}
		pthread_mutex_lock(&host->state_mutex);
		memset(&host->streams[stream_id], 0,
		    sizeof(host->streams[stream_id]));
		pthread_mutex_unlock(&host->state_mutex);
	}
	pthread_mutex_unlock(&host->operation_mutex);
	return (error);
}

bool
virtio_snd_host_restore_incomplete(struct virtio_snd_host *host)
{
	bool incomplete;

	if (host == NULL)
		return (true);
	pthread_mutex_lock(&host->operation_mutex);
	incomplete = host->restore_incomplete;
	pthread_mutex_unlock(&host->operation_mutex);
	return (incomplete);
}
