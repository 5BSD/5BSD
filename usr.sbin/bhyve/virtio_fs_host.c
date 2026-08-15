/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtio_fs_host.h"
#include "virtio_state_range.h"

#define	FUSE_IN_HEADER_SIZE	40U
#define	FUSE_OUT_HEADER_SIZE	16U
#define	FUSE_COMPAT_INIT_IN_SIZE	16U
#define	FUSE_COMPAT_INIT_OUT_SIZE 8U
#define	FUSE_INIT_MAJOR_IN_OFFSET FUSE_IN_HEADER_SIZE
#define	FUSE_INIT_MAJOR_OFFSET	FUSE_OUT_HEADER_SIZE
#define	FUSE_MAX_ERRNO		4095
#define	FUSE_HIPRIO_BODY_SIZE	8U
#define	FUSE_FORGET_ONE_SIZE	16U
#define	FUSE_OPCODE_OFFSET	4U
#define	FUSE_UNIQUE_OFFSET	8U

#define	FUSE_OPCODE_FORGET	2U
#define	FUSE_OPCODE_INIT	26U
#define	FUSE_OPCODE_INTERRUPT	36U
#define	FUSE_OPCODE_BATCH_FORGET 42U

static uint32_t
virtio_fs_decode32(const uint8_t *bytes, enum virtio_fs_byte_order order)
{

	return (order == VIRTIO_FS_BYTE_ORDER_BIG ?
	    be32dec(bytes) : le32dec(bytes));
}

static uint64_t
virtio_fs_decode64(const uint8_t *bytes, enum virtio_fs_byte_order order)
{

	return (order == VIRTIO_FS_BYTE_ORDER_BIG ?
	    be64dec(bytes) : le64dec(bytes));
}

static bool
virtio_fs_hiprio_opcode(uint32_t opcode)
{

	return (opcode == FUSE_OPCODE_INTERRUPT ||
	    opcode == FUSE_OPCODE_FORGET ||
	    opcode == FUSE_OPCODE_BATCH_FORGET);
}

static bool
virtio_fs_valid_utf8(const uint8_t *bytes, size_t len)
{
	uint32_t codepoint, minimum;
	size_t i;
	uint8_t first;
	unsigned int continuation;

	for (i = 0; i < len;) {
		first = bytes[i++];
		/*
		 * NUL is padding, not part of a configured tag.  Linux also
		 * refuses newline because the tag is exposed through sysfs,
		 * uevents, and mount command lines.
		 */
		if (first == 0 || first == '\n')
			return (false);
		if (first < 0x80)
			continue;
		if (first >= 0xc2 && first <= 0xdf) {
			continuation = 1;
			codepoint = first & 0x1f;
			minimum = 0x80;
		} else if (first >= 0xe0 && first <= 0xef) {
			continuation = 2;
			codepoint = first & 0x0f;
			minimum = 0x800;
		} else if (first >= 0xf0 && first <= 0xf4) {
			continuation = 3;
			codepoint = first & 0x07;
			minimum = 0x10000;
		} else {
			return (false);
		}
		if (continuation > len - i)
			return (false);
		while (continuation-- != 0) {
			if ((bytes[i] & 0xc0) != 0x80)
				return (false);
			codepoint = (codepoint << 6) | (bytes[i++] & 0x3f);
		}
		if (codepoint < minimum || codepoint > 0x10ffff ||
		    (codepoint >= 0xd800 && codepoint <= 0xdfff))
			return (false);
	}
	return (true);
}

int
virtio_fs_config_encode(const void *tag, size_t tag_len,
    uint32_t num_request_queues,
    uint8_t config[BHYVE_VIRTIO_FS_CONFIG_SIZE])

{

	return (virtio_fs_config_encode_notification(tag, tag_len,
	    num_request_queues, 0, config));
}

int
virtio_fs_config_encode_notification(const void *tag, size_t tag_len,
    uint32_t num_request_queues, uint32_t notify_buf_size,
    uint8_t config[BHYVE_VIRTIO_FS_CONFIG_SIZE])
{
	uint8_t saved_tag[BHYVE_VIRTIO_FS_TAG_SIZE];

	if (config == NULL || (tag == NULL && tag_len != 0) ||
	    tag_len == 0 || tag_len > BHYVE_VIRTIO_FS_TAG_SIZE ||
	    num_request_queues == 0 ||
	    !virtio_fs_valid_utf8(tag, tag_len))
		return (EINVAL);
	/*
	 * The config buffer is a natural place for callers to stage a short
	 * tag.  Preserve it before clearing padding so partial or complete
	 * source/destination overlap has defined behavior.
	 */
	memcpy(saved_tag, tag, tag_len);
	memset(config, 0, BHYVE_VIRTIO_FS_CONFIG_SIZE);
	memcpy(config, saved_tag, tag_len);
	le32enc(config + BHYVE_VIRTIO_FS_TAG_SIZE, num_request_queues);
	le32enc(config + BHYVE_VIRTIO_FS_TAG_SIZE + sizeof(uint32_t),
	    notify_buf_size);
	return (0);
}

void
virtio_fs_session_reset(struct virtio_fs_session *session)
{

	if (session == NULL)
		return;
	session->byte_order = VIRTIO_FS_BYTE_ORDER_UNKNOWN;
	session->initialized = false;
	if (session->incarnation != UINT64_MAX)
		session->incarnation++;
}

int
virtio_fs_request_accept(struct virtio_fs_session *session,
    enum virtio_fs_queue_class queue_class, const void *request,
    size_t request_len, size_t response_capacity,
    struct virtio_fs_request_context *context)
{
	const uint8_t *in;
	enum virtio_fs_byte_order order;
	uint64_t request_unique;
	uint32_t batch_count, declared_len, opcode;

	if (session == NULL || context == NULL ||
	    (request == NULL && request_len != 0) ||
	    (queue_class != VIRTIO_FS_QUEUE_REQUEST &&
	    queue_class != VIRTIO_FS_QUEUE_HIPRIO))
		return (EINVAL);
	if (virtio_state_ranges_overlap(session, sizeof(*session), context,
	    sizeof(*context)) ||
	    virtio_state_ranges_overlap(request, request_len, session,
	    sizeof(*session)) ||
	    virtio_state_ranges_overlap(request, request_len, context,
	    sizeof(*context)))
		return (EINVAL);
	if (session->initialized && session->incarnation == 0)
		return (EPROTO);
	if (request_len < FUSE_IN_HEADER_SIZE ||
	    request_len > BHYVE_VIRTIO_FS_MAX_MESSAGE)
		return (EPROTO);

	in = request;
	order = session->byte_order;
	/*
	 * Every INIT begins a new session and may change byte order, including
	 * after a previously initialized session.
	 */
	if (le32dec(in + FUSE_OPCODE_OFFSET) == FUSE_OPCODE_INIT)
		order = VIRTIO_FS_BYTE_ORDER_LITTLE;
	else if (be32dec(in + FUSE_OPCODE_OFFSET) == FUSE_OPCODE_INIT)
		order = VIRTIO_FS_BYTE_ORDER_BIG;
	else if (order == VIRTIO_FS_BYTE_ORDER_UNKNOWN)
		return (EPROTO);
	declared_len = virtio_fs_decode32(in, order);
	opcode = virtio_fs_decode32(in + FUSE_OPCODE_OFFSET, order);
	request_unique = virtio_fs_decode64(in + FUSE_UNIQUE_OFFSET, order);
	if (declared_len != request_len || request_unique == 0)
		return (EPROTO);
	if (opcode == FUSE_OPCODE_INIT &&
	    (request_len < FUSE_IN_HEADER_SIZE + FUSE_COMPAT_INIT_IN_SIZE ||
	    virtio_fs_decode32(in + FUSE_INIT_MAJOR_IN_OFFSET, order) == 0))
		return (EPROTO);
	if ((opcode == FUSE_OPCODE_FORGET ||
	    opcode == FUSE_OPCODE_INTERRUPT) &&
	    request_len != FUSE_IN_HEADER_SIZE + FUSE_HIPRIO_BODY_SIZE)
		return (EPROTO);
	if (opcode == FUSE_OPCODE_BATCH_FORGET) {
		if (request_len < FUSE_IN_HEADER_SIZE +
		    FUSE_HIPRIO_BODY_SIZE)
			return (EPROTO);
		batch_count = virtio_fs_decode32(in + FUSE_IN_HEADER_SIZE,
		    order);
		if (batch_count > (BHYVE_VIRTIO_FS_MAX_MESSAGE -
		    FUSE_IN_HEADER_SIZE - FUSE_HIPRIO_BODY_SIZE) /
		    FUSE_FORGET_ONE_SIZE ||
		    request_len != FUSE_IN_HEADER_SIZE +
		    FUSE_HIPRIO_BODY_SIZE +
		    (size_t)batch_count * FUSE_FORGET_ONE_SIZE)
			return (EPROTO);
	}
	if ((queue_class == VIRTIO_FS_QUEUE_HIPRIO) !=
	    virtio_fs_hiprio_opcode(opcode))
		return (EPROTO);
	if (!session->initialized && opcode != FUSE_OPCODE_INIT)
		return (EPROTO);
	if (opcode != FUSE_OPCODE_FORGET &&
	    opcode != FUSE_OPCODE_BATCH_FORGET &&
	    response_capacity < FUSE_OUT_HEADER_SIZE)
		return (EPROTO);
	if (opcode == FUSE_OPCODE_INIT &&
	    response_capacity < FUSE_OUT_HEADER_SIZE +
	    FUSE_COMPAT_INIT_OUT_SIZE)
		return (EPROTO);

	memset(context, 0, sizeof(*context));
	context->byte_order = order;
	context->opcode = opcode;
	context->init_major = opcode == FUSE_OPCODE_INIT ?
	    virtio_fs_decode32(in + FUSE_INIT_MAJOR_IN_OFFSET, order) : 0;
	context->unique = request_unique;
	context->expects_reply = opcode != FUSE_OPCODE_FORGET &&
	    opcode != FUSE_OPCODE_BATCH_FORGET;
	context->initializes = opcode == FUSE_OPCODE_INIT;
	if (opcode == FUSE_OPCODE_INIT) {
		if (session->incarnation == UINT64_MAX)
			return (EOVERFLOW);
		/*
		 * FUSE_INIT terminates the prior session when accepted, not
		 * after its asynchronous reply.  Normal requests are therefore
		 * barred until this incarnation receives a valid success reply.
		 */
		session->byte_order = order;
		session->initialized = false;
		session->incarnation++;
	}
	context->incarnation = session->incarnation;
	return (0);
}

int
virtio_fs_response_complete(struct virtio_fs_session *session,
    const struct virtio_fs_request_context *context, const void *response,
    size_t response_len)
{
	const uint8_t *out;
	uint32_t output_len, output_major;
	int32_t output_error;

	if (session == NULL || context == NULL ||
	    (response == NULL && response_len != 0))
		return (EINVAL);
	if (virtio_state_ranges_overlap(session, sizeof(*session), context,
	    sizeof(*context)) ||
	    virtio_state_ranges_overlap(response, response_len, session,
	    sizeof(*session)))
		return (EINVAL);
	if ((context->byte_order != VIRTIO_FS_BYTE_ORDER_LITTLE &&
	    context->byte_order != VIRTIO_FS_BYTE_ORDER_BIG) ||
	    context->unique == 0 || context->incarnation == 0 ||
	    context->initializes != (context->opcode == FUSE_OPCODE_INIT) ||
	    context->initializes != (context->init_major != 0) ||
	    context->expects_reply != !(context->opcode == FUSE_OPCODE_FORGET ||
	    context->opcode == FUSE_OPCODE_BATCH_FORGET))
		return (EINVAL);
	if (session->incarnation != context->incarnation)
		return (ESTALE);
	if (!context->expects_reply)
		return (response_len == 0 ? 0 : EPROTO);
	if (response_len < FUSE_OUT_HEADER_SIZE ||
	    response_len > BHYVE_VIRTIO_FS_MAX_MESSAGE)
		return (EPROTO);
	out = response;
	output_len = virtio_fs_decode32(out, context->byte_order);
	output_error = (int32_t)virtio_fs_decode32(out + 4,
	    context->byte_order);
	if (output_len != response_len || output_error > 0 ||
	    output_error < -FUSE_MAX_ERRNO ||
	    virtio_fs_decode64(out + 8, context->byte_order) !=
	    context->unique)
		return (EPROTO);
	if (context->initializes && output_error == 0 &&
	    (response_len < FUSE_OUT_HEADER_SIZE +
	    FUSE_COMPAT_INIT_OUT_SIZE ||
	    virtio_fs_decode32(out + FUSE_INIT_MAJOR_OFFSET,
	    context->byte_order) == 0))
		return (EPROTO);
	if (context->initializes && output_error == 0) {
		output_major = virtio_fs_decode32(out + FUSE_INIT_MAJOR_OFFSET,
		    context->byte_order);
		/*
		 * A lower major is a negotiation response.  The kernel must
		 * issue another INIT using that major before ordinary requests
		 * become admissible.
		 */
		if (output_major > context->init_major)
			return (EPROTO);
		session->initialized = output_major == context->init_major;
	}
	return (0);
}

int
virtio_fs_process_request(struct virtio_fs_session *session,
    enum virtio_fs_queue_class queue_class, const void *request,
    size_t request_len, void *response, size_t response_capacity,
    virtio_fs_backend_request_cb backend, void *backend_arg, size_t *written)
{
	struct virtio_fs_request_context context;
	size_t backend_capacity, backend_written;
	int error;

	if (written == NULL || backend == NULL ||
	    (response == NULL && response_capacity != 0))
		return (EINVAL);
	if (virtio_state_ranges_overlap(session, sizeof(*session), request,
	    request_len) ||
	    virtio_state_ranges_overlap(session, sizeof(*session), response,
	    response_capacity) ||
	    virtio_state_ranges_overlap(session, sizeof(*session), written,
	    sizeof(*written)) ||
	    virtio_state_ranges_overlap(request, request_len, response,
	    response_capacity) ||
	    virtio_state_ranges_overlap(request, request_len, written,
	    sizeof(*written)) ||
	    virtio_state_ranges_overlap(response, response_capacity, written,
	    sizeof(*written)))
		return (EINVAL);
	*written = 0;
	error = virtio_fs_request_accept(session, queue_class, request,
	    request_len, response_capacity, &context);
	if (error != 0)
		return (error);
	backend_written = 0;
	backend_capacity = MIN(response_capacity,
	    (size_t)BHYVE_VIRTIO_FS_MAX_MESSAGE);
	error = backend(backend_arg, request, request_len, response,
	    backend_capacity, &backend_written);
	if (error != 0)
		return (error);
	if (backend_written > response_capacity ||
	    backend_written > BHYVE_VIRTIO_FS_MAX_MESSAGE)
		return (EPROTO);
	error = virtio_fs_response_complete(session, &context, response,
	    backend_written);
	if (error != 0)
		return (error);
	*written = backend_written;
	return (0);
}
