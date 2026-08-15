/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/uio.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_snd_host.h"
#include "virtio_snd_queue.h"
#include "virtio_state_range.h"

#define	VTSND_CONTROL_REQUEST_MAX	BHYVE_VTSND_PCM_PARAMS_SIZE
#define	VTSND_CONTROL_RESPONSE_MAX	(BHYVE_VTSND_STATUS_SIZE + \
	BHYVE_VTSND_STREAMS * BHYVE_VTSND_PCM_INFO_SIZE)

static int
vtsnd_iov_validate_ownership(struct virtio_snd_host *host,
    const struct iovec *readable, size_t nreadable,
    const struct iovec *writable, size_t nwritable,
    const void *publication1, size_t publication1_size,
    const void *publication2, size_t publication2_size,
    const void *source, size_t source_size)
{
	const struct iovec *sets[2] = { readable, writable };
	const size_t counts[2] = { nreadable, nwritable };
	size_t metadata_size[2];

	if (nreadable > BHYVE_VTSND_MAX_CHAIN_SEGMENTS ||
	    nwritable > BHYVE_VTSND_MAX_CHAIN_SEGMENTS ||
	    nreadable > SIZE_MAX / sizeof(*readable) ||
	    nwritable > SIZE_MAX / sizeof(*writable))
		return (EOVERFLOW);
	metadata_size[0] = nreadable * sizeof(*readable);
	metadata_size[1] = nwritable * sizeof(*writable);
	if (virtio_state_ranges_overlap(readable, metadata_size[0], writable,
	    metadata_size[1]) ||
	    virtio_state_ranges_overlap(readable, metadata_size[0],
	    publication1, publication1_size) ||
	    virtio_state_ranges_overlap(readable, metadata_size[0],
	    publication2, publication2_size) ||
	    virtio_state_ranges_overlap(writable, metadata_size[1],
	    publication1, publication1_size) ||
	    virtio_state_ranges_overlap(writable, metadata_size[1],
	    publication2, publication2_size) ||
	    virtio_state_ranges_overlap(readable, metadata_size[0], source,
	    source_size) ||
	    virtio_state_ranges_overlap(writable, metadata_size[1], source,
	    source_size) ||
	    virtio_state_ranges_overlap(publication1, publication1_size,
	    publication2, publication2_size) ||
	    virtio_state_ranges_overlap(publication1, publication1_size,
	    source, source_size) ||
	    virtio_state_ranges_overlap(publication2, publication2_size,
	    source, source_size) ||
	    virtio_snd_host_storage_overlaps(host, readable,
	    metadata_size[0]) ||
	    virtio_snd_host_storage_overlaps(host, writable,
	    metadata_size[1]) ||
	    virtio_snd_host_storage_overlaps(host, publication1,
	    publication1_size) ||
	    virtio_snd_host_storage_overlaps(host, publication2,
	    publication2_size) ||
	    virtio_snd_host_storage_overlaps(host, source, source_size))
		return (EINVAL);
	for (size_t set = 0; set < 2; set++) {
		for (size_t i = 0; i < counts[set]; i++) {
			if (virtio_state_ranges_overlap(sets[set][i].iov_base,
			    sets[set][i].iov_len, readable, metadata_size[0]) ||
			    virtio_state_ranges_overlap(sets[set][i].iov_base,
			    sets[set][i].iov_len, writable, metadata_size[1]) ||
			    virtio_state_ranges_overlap(sets[set][i].iov_base,
			    sets[set][i].iov_len, publication1,
			    publication1_size) ||
			    virtio_state_ranges_overlap(sets[set][i].iov_base,
			    sets[set][i].iov_len, publication2,
			    publication2_size) ||
			    virtio_snd_host_storage_overlaps(host,
			    sets[set][i].iov_base, sets[set][i].iov_len) ||
			    (set == 1 && virtio_state_ranges_overlap(
			    sets[set][i].iov_base, sets[set][i].iov_len,
			    source, source_size)))
				return (EINVAL);
		}
	}
	for (size_t i = 0; i < nwritable; i++) {
		for (size_t j = i + 1; j < nwritable; j++) {
			if (virtio_state_ranges_overlap(writable[i].iov_base,
			    writable[i].iov_len, writable[j].iov_base,
			    writable[j].iov_len))
				return (EINVAL);
		}
	}
	return (0);
}

static int
vtsnd_iov_size(const struct iovec *iov, size_t niov, size_t *total)
{
	size_t size;

	if ((iov == NULL && niov != 0) || total == NULL ||
	    niov > BHYVE_VTSND_MAX_CHAIN_SEGMENTS)
		return (EINVAL);
	size = 0;
	for (size_t i = 0; i < niov; i++) {
		if (iov[i].iov_base == NULL || iov[i].iov_len == 0 ||
		    iov[i].iov_len > SIZE_MAX - size)
			return (EINVAL);
		size += iov[i].iov_len;
	}
	*total = size;
	return (0);
}

static int
vtsnd_iov_copyin(const struct iovec *iov, size_t niov, size_t offset,
    void *buffer, size_t length)
{
	uint8_t *destination;
	size_t available, copied;

	if (buffer == NULL && length != 0)
		return (EINVAL);
	destination = buffer;
	copied = 0;
	for (size_t i = 0; i < niov && copied < length; i++) {
		size_t chunk;

		if (offset >= iov[i].iov_len) {
			offset -= iov[i].iov_len;
			continue;
		}
		available = iov[i].iov_len - offset;
		chunk = available < length - copied ? available :
		    length - copied;
		memcpy(destination + copied,
		    (const uint8_t *)iov[i].iov_base + offset, chunk);
		copied += chunk;
		offset = 0;
	}
	return (copied == length ? 0 : EMSGSIZE);
}

static int
vtsnd_iov_copyout(const void *buffer, size_t length,
    const struct iovec *iov, size_t niov, size_t offset)
{
	const uint8_t *source;
	size_t available, copied;

	if (buffer == NULL && length != 0)
		return (EINVAL);
	source = buffer;
	copied = 0;
	for (size_t i = 0; i < niov && copied < length; i++) {
		size_t chunk;

		if (offset >= iov[i].iov_len) {
			offset -= iov[i].iov_len;
			continue;
		}
		available = iov[i].iov_len - offset;
		chunk = available < length - copied ? available :
		    length - copied;
		memcpy((uint8_t *)iov[i].iov_base + offset, source + copied,
		    chunk);
		copied += chunk;
		offset = 0;
	}
	return (copied == length ? 0 : EMSGSIZE);
}

static int
vtsnd_iov_zero(const struct iovec *iov, size_t niov, size_t offset,
    size_t length)
{
	size_t available, cleared;

	cleared = 0;
	for (size_t i = 0; i < niov && cleared < length; i++) {
		size_t chunk;

		if (offset >= iov[i].iov_len) {
			offset -= iov[i].iov_len;
			continue;
		}
		available = iov[i].iov_len - offset;
		chunk = available < length - cleared ? available :
		    length - cleared;
		memset((uint8_t *)iov[i].iov_base + offset, 0, chunk);
		cleared += chunk;
		offset = 0;
	}
	return (cleared == length ? 0 : EMSGSIZE);
}

int
virtio_snd_queue_control_header(const struct iovec *readable,
    size_t nreadable, uint32_t *code, uint32_t *stream_id)
{
	uint8_t header[BHYVE_VTSND_PCM_HEADER_SIZE];
	size_t readable_size;
	int error;

	if (code == NULL || stream_id == NULL)
		return (EINVAL);
	error = vtsnd_iov_validate_ownership(NULL, readable, nreadable, NULL,
	    0, code, sizeof(*code), stream_id, sizeof(*stream_id), NULL, 0);
	if (error != 0)
		return (error);
	*code = 0;
	*stream_id = UINT32_MAX;
	error = vtsnd_iov_size(readable, nreadable, &readable_size);
	if (error != 0)
		return (error);
	if (readable_size < sizeof(header))
		return (EMSGSIZE);
	error = vtsnd_iov_copyin(readable, nreadable, 0, header,
	    sizeof(header));
	if (error != 0)
		return (error);
	*code = le32dec(header);
	*stream_id = le32dec(header + sizeof(uint32_t));
	return (0);
}

static void
vtsnd_pcm_error_encode(uint8_t response[BHYVE_VTSND_PCM_STATUS_SIZE])
{

	memset(response, 0, BHYVE_VTSND_PCM_STATUS_SIZE);
	le32enc(response, BHYVE_VTSND_S_IO_ERR);
}

static void
vtsnd_pcm_status_encode(uint8_t response[BHYVE_VTSND_PCM_STATUS_SIZE],
    int backend_error)
{

	memset(response, 0, BHYVE_VTSND_PCM_STATUS_SIZE);
	le32enc(response, backend_error == 0 ? BHYVE_VTSND_S_OK :
	    BHYVE_VTSND_S_IO_ERR);
}

int
virtio_snd_queue_playback_prepare(struct virtio_snd_host *host,
    const struct iovec *readable, size_t nreadable,
    const struct iovec *writable, size_t nwritable,
    struct virtio_snd_host_xfer_claim *claim,
    size_t *payload_size)
{
	uint8_t request[BHYVE_VTSND_PCM_XFER_SIZE];
	size_t readable_size, writable_size;
	int error;

	if (host == NULL || claim == NULL || payload_size == NULL)
		return (EINVAL);
	error = vtsnd_iov_validate_ownership(host, readable, nreadable,
	    writable, nwritable, claim, sizeof(*claim), payload_size,
	    sizeof(*payload_size), NULL, 0);
	if (error != 0)
		return (error);
	memset(claim, 0, sizeof(*claim));
	*payload_size = 0;
	error = vtsnd_iov_size(readable, nreadable, &readable_size);
	if (error != 0 || readable_size <= sizeof(request) ||
	    readable_size - sizeof(request) > BHYVE_VTSND_MAX_BUFFER_BYTES)
		return (EINVAL);
	error = vtsnd_iov_size(writable, nwritable, &writable_size);
	if (error != 0 || writable_size < BHYVE_VTSND_PCM_STATUS_SIZE)
		return (EINVAL);
	error = vtsnd_iov_copyin(readable, nreadable, 0, request,
	    sizeof(request));
	if (error != 0)
		return (error);
	*payload_size = readable_size - sizeof(request);
	error = virtio_snd_host_xfer_claim(host, request, sizeof(request),
	    BHYVE_VTSND_OUTPUT, *payload_size, claim);
	if (error != 0) {
		memset(claim, 0, sizeof(*claim));
		*payload_size = 0;
	}
	return (error);
}

int
virtio_snd_queue_capture_prepare(struct virtio_snd_host *host,
    const struct iovec *readable, size_t nreadable,
    const struct iovec *writable, size_t nwritable,
    struct virtio_snd_host_xfer_claim *claim,
    size_t *payload_size)
{
	uint8_t request[BHYVE_VTSND_PCM_XFER_SIZE];
	size_t readable_size, writable_size;
	int error;

	if (host == NULL || claim == NULL || payload_size == NULL)
		return (EINVAL);
	error = vtsnd_iov_validate_ownership(host, readable, nreadable,
	    writable, nwritable, claim, sizeof(*claim), payload_size,
	    sizeof(*payload_size), NULL, 0);
	if (error != 0)
		return (error);
	memset(claim, 0, sizeof(*claim));
	*payload_size = 0;
	error = vtsnd_iov_size(readable, nreadable, &readable_size);
	if (error != 0 || readable_size != sizeof(request))
		return (EINVAL);
	error = vtsnd_iov_size(writable, nwritable, &writable_size);
	if (error != 0 || writable_size <= BHYVE_VTSND_PCM_STATUS_SIZE ||
	    writable_size - BHYVE_VTSND_PCM_STATUS_SIZE >
	    BHYVE_VTSND_MAX_BUFFER_BYTES)
		return (EINVAL);
	error = vtsnd_iov_copyin(readable, nreadable, 0, request,
	    sizeof(request));
	if (error != 0)
		return (error);
	*payload_size = writable_size - BHYVE_VTSND_PCM_STATUS_SIZE;
	error = virtio_snd_host_xfer_claim(host, request, sizeof(request),
	    BHYVE_VTSND_INPUT, *payload_size, claim);
	if (error != 0) {
		memset(claim, 0, sizeof(*claim));
		*payload_size = 0;
	}
	return (error);
}

int
virtio_snd_queue_playback_complete(const struct iovec *writable,
    size_t nwritable, int backend_error, size_t *used)
{
	uint8_t response[BHYVE_VTSND_PCM_STATUS_SIZE];
	size_t writable_size;
	int error;

	if (used == NULL)
		return (EINVAL);
	error = vtsnd_iov_validate_ownership(NULL, NULL, 0, writable,
	    nwritable, used, sizeof(*used), NULL, 0, NULL, 0);
	if (error != 0)
		return (error);
	*used = 0;
	error = vtsnd_iov_size(writable, nwritable, &writable_size);
	if (error != 0 || writable_size < sizeof(response))
		return (EINVAL);
	vtsnd_pcm_status_encode(response, backend_error);
	error = vtsnd_iov_copyout(response, sizeof(response), writable,
	    nwritable, 0);
	if (error == 0)
		*used = sizeof(response);
	return (error);
}

int
virtio_snd_queue_capture_complete(const struct iovec *writable,
    size_t nwritable, const void *payload, size_t payload_size,
    int backend_error, size_t *used)
{
	uint8_t response[BHYVE_VTSND_PCM_STATUS_SIZE];
	size_t writable_size;
	int error;

	if (used == NULL || payload_size == 0 ||
	    payload_size > BHYVE_VTSND_MAX_BUFFER_BYTES ||
	    (backend_error == 0 && payload == NULL))
		return (EINVAL);
	error = vtsnd_iov_validate_ownership(NULL, NULL, 0, writable,
	    nwritable, used, sizeof(*used), NULL, 0,
	    backend_error == 0 ? payload : NULL,
	    backend_error == 0 ? payload_size : 0);
	if (error != 0)
		return (error);
	*used = 0;
	error = vtsnd_iov_size(writable, nwritable, &writable_size);
	if (error != 0 || payload_size > SIZE_MAX - sizeof(response) ||
	    writable_size != payload_size + sizeof(response))
		return (EINVAL);
	if (backend_error == 0)
		error = vtsnd_iov_copyout(payload, payload_size, writable,
		    nwritable, 0);
	else
		error = vtsnd_iov_zero(writable, nwritable, 0, payload_size);
	if (error != 0)
		return (error);
	vtsnd_pcm_status_encode(response, backend_error);
	error = vtsnd_iov_copyout(response, sizeof(response), writable,
	    nwritable, payload_size);
	if (error == 0)
		*used = writable_size;
	return (error);
}

int
virtio_snd_queue_playback_error(const struct iovec *readable,
    size_t nreadable, const struct iovec *writable, size_t nwritable,
    size_t *used)
{
	uint8_t response[BHYVE_VTSND_PCM_STATUS_SIZE];
	size_t readable_size, writable_size;
	int error;

	if (used == NULL)
		return (EINVAL);
	error = vtsnd_iov_validate_ownership(NULL, readable, nreadable,
	    writable, nwritable, used, sizeof(*used), NULL, 0, NULL, 0);
	if (error != 0)
		return (error);
	*used = 0;
	error = vtsnd_iov_size(readable, nreadable, &readable_size);
	if (error != 0 || readable_size <= BHYVE_VTSND_PCM_XFER_SIZE ||
	    readable_size - BHYVE_VTSND_PCM_XFER_SIZE >
	    BHYVE_VTSND_MAX_BUFFER_BYTES)
		return (EINVAL);
	error = vtsnd_iov_size(writable, nwritable, &writable_size);
	if (error != 0 || writable_size < sizeof(response))
		return (EINVAL);
	vtsnd_pcm_error_encode(response);
	error = vtsnd_iov_copyout(response, sizeof(response), writable,
	    nwritable, 0);
	if (error == 0)
		*used = sizeof(response);
	return (error);
}

int
virtio_snd_queue_capture_error(const struct iovec *readable,
    size_t nreadable, const struct iovec *writable, size_t nwritable,
    size_t *used)
{
	uint8_t response[BHYVE_VTSND_PCM_STATUS_SIZE];
	size_t payload_size, readable_size, writable_size;
	int error;

	if (used == NULL)
		return (EINVAL);
	error = vtsnd_iov_validate_ownership(NULL, readable, nreadable,
	    writable, nwritable, used, sizeof(*used), NULL, 0, NULL, 0);
	if (error != 0)
		return (error);
	*used = 0;
	error = vtsnd_iov_size(readable, nreadable, &readable_size);
	if (error != 0 || readable_size != BHYVE_VTSND_PCM_XFER_SIZE)
		return (EINVAL);
	error = vtsnd_iov_size(writable, nwritable, &writable_size);
	if (error != 0 || writable_size <= sizeof(response) ||
	    writable_size - sizeof(response) > BHYVE_VTSND_MAX_BUFFER_BYTES)
		return (EINVAL);
	payload_size = writable_size - sizeof(response);
	error = vtsnd_iov_zero(writable, nwritable, 0, payload_size);
	if (error != 0)
		return (error);
	vtsnd_pcm_error_encode(response);
	error = vtsnd_iov_copyout(response, sizeof(response), writable,
	    nwritable, payload_size);
	if (error == 0)
		*used = writable_size;
	return (error);
}

int
virtio_snd_queue_control(struct virtio_snd_host *host,
    const struct iovec *readable, size_t nreadable,
    const struct iovec *writable, size_t nwritable, size_t *used)
{
	uint8_t request[VTSND_CONTROL_REQUEST_MAX];
	uint8_t response[VTSND_CONTROL_RESPONSE_MAX];
	size_t request_size, response_size, writable_size;
	int error;

	if (host == NULL || used == NULL)
		return (EINVAL);
	error = vtsnd_iov_validate_ownership(host, readable, nreadable,
	    writable, nwritable, used, sizeof(*used), NULL, 0, NULL, 0);
	if (error != 0)
		return (error);
	*used = 0;
	error = vtsnd_iov_size(readable, nreadable, &request_size);
	if (error != 0 || request_size < sizeof(uint32_t) ||
	    request_size > sizeof(request))
		return (EINVAL);
	error = vtsnd_iov_size(writable, nwritable, &writable_size);
	if (error != 0 || writable_size < BHYVE_VTSND_STATUS_SIZE)
		return (EINVAL);
	error = vtsnd_iov_copyin(readable, nreadable, 0, request,
	    request_size);
	if (error != 0)
		return (error);
	response_size = 0;
	error = virtio_snd_host_control(host, request, request_size, response,
	    MIN(writable_size, sizeof(response)), &response_size);
	if (error != 0)
		return (error);
	error = vtsnd_iov_copyout(response, response_size, writable,
	    nwritable, 0);
	if (error == 0)
		*used = response_size;
	return (error);
}

int
virtio_snd_queue_playback(struct virtio_snd_host *host,
    const struct iovec *readable, size_t nreadable,
    const struct iovec *writable, size_t nwritable, size_t *used)
{
	uint8_t request[BHYVE_VTSND_PCM_XFER_SIZE];
	uint8_t response[BHYVE_VTSND_PCM_STATUS_SIZE];
	uint8_t *payload;
	size_t payload_size, readable_size, response_size, writable_size;
	int error;

	if (host == NULL || used == NULL)
		return (EINVAL);
	error = vtsnd_iov_validate_ownership(host, readable, nreadable,
	    writable, nwritable, used, sizeof(*used), NULL, 0, NULL, 0);
	if (error != 0)
		return (error);
	*used = 0;
	error = vtsnd_iov_size(readable, nreadable, &readable_size);
	if (error != 0 || readable_size <= sizeof(request) ||
	    readable_size - sizeof(request) > BHYVE_VTSND_MAX_BUFFER_BYTES)
		return (EINVAL);
	error = vtsnd_iov_size(writable, nwritable, &writable_size);
	if (error != 0 || writable_size < sizeof(response))
		return (EINVAL);
	payload_size = readable_size - sizeof(request);
	payload = calloc(1, payload_size);
	if (payload == NULL)
		return (ENOMEM);
	error = vtsnd_iov_copyin(readable, nreadable, 0, request,
	    sizeof(request));
	if (error == 0)
		error = vtsnd_iov_copyin(readable, nreadable, sizeof(request),
		    payload, payload_size);
	response_size = 0;
	if (error == 0)
		error = virtio_snd_host_playback(host, request, sizeof(request),
		    payload, payload_size, response, sizeof(response),
		    &response_size);
	free(payload);
	if (error == 0)
		error = vtsnd_iov_copyout(response, response_size, writable,
		    nwritable, 0);
	if (error == 0)
		*used = response_size;
	return (error);
}

int
virtio_snd_queue_capture(struct virtio_snd_host *host,
    const struct iovec *readable, size_t nreadable,
    const struct iovec *writable, size_t nwritable, size_t *used)
{
	uint8_t request[BHYVE_VTSND_PCM_XFER_SIZE];
	uint8_t response[BHYVE_VTSND_PCM_STATUS_SIZE];
	uint8_t *payload;
	size_t payload_size, readable_size, response_size, writable_size;
	int error;

	if (host == NULL || used == NULL)
		return (EINVAL);
	error = vtsnd_iov_validate_ownership(host, readable, nreadable,
	    writable, nwritable, used, sizeof(*used), NULL, 0, NULL, 0);
	if (error != 0)
		return (error);
	*used = 0;
	error = vtsnd_iov_size(readable, nreadable, &readable_size);
	if (error != 0 || readable_size != sizeof(request))
		return (EINVAL);
	error = vtsnd_iov_size(writable, nwritable, &writable_size);
	if (error != 0 || writable_size <= sizeof(response) ||
	    writable_size - sizeof(response) > BHYVE_VTSND_MAX_BUFFER_BYTES)
		return (EINVAL);
	payload_size = writable_size - sizeof(response);
	payload = calloc(1, payload_size);
	if (payload == NULL)
		return (ENOMEM);
	error = vtsnd_iov_copyin(readable, nreadable, 0, request,
	    sizeof(request));
	response_size = 0;
	if (error == 0)
		error = virtio_snd_host_capture(host, request, sizeof(request),
		    payload, payload_size, response, sizeof(response),
		    &response_size);
	if (error == 0)
		error = vtsnd_iov_copyout(payload, payload_size, writable,
		    nwritable, 0);
	free(payload);
	if (error == 0)
		error = vtsnd_iov_copyout(response, response_size, writable,
		    nwritable, payload_size);
	if (error == 0)
		*used = payload_size + response_size;
	return (error);
}
