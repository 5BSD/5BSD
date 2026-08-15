/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtio_fs_backend.h"
#include "virtio_fs_host.h"
#include "virtio_fs_state.h"
#include "virtio_state_range.h"

#define	VFS1_OFF_MAGIC			0U
#define	VFS1_OFF_VERSION		4U
#define	VFS1_OFF_HEADER_SIZE		6U
#define	VFS1_OFF_TOTAL_SIZE		8U
#define	VFS1_OFF_FLAGS			12U
#define	VFS1_OFF_REQUEST_QUEUES		16U
#define	VFS1_OFF_TAG_LEN		20U
#define	VFS1_OFF_BYTE_ORDER		22U
#define	VFS1_OFF_INITIALIZED		23U
#define	VFS1_OFF_VIRTIO_FEATURES	24U
#define	VFS1_OFF_FUSE_INCARNATION	32U
#define	VFS1_OFF_BACKEND_INCARNATION	40U
#define	VFS1_OFF_BACKEND_VERSION	48U
#define	VFS1_OFF_RESERVED		50U
#define	VFS1_OFF_IDENTITY_LEN		52U
#define	VFS1_OFF_BACKEND_STATE_LEN	56U
#define	VFS1_OFF_BACKEND_FEATURES	60U
#define	VFS1_OFF_BACKEND_MAX_MESSAGE	64U
#define	VFS1_OFF_BACKEND_MAX_INFLIGHT	68U
#define	VFS1_OFF_BACKEND_MAX_PENDING	72U

static bool
virtio_fs_state_encode_overlaps(const struct virtio_fs_state_source *source,
    const void *output, size_t output_len, const size_t *written)
{

	return (virtio_state_ranges_overlap(output, output_len, source,
	    sizeof(*source)) ||
	    virtio_state_ranges_overlap(output, output_len,
	    source->fuse_session, sizeof(*source->fuse_session)) ||
	    virtio_state_ranges_overlap(output, output_len,
	    source->backend_session, sizeof(*source->backend_session)) ||
	    virtio_state_ranges_overlap(output, output_len, source->tag,
	    source->tag_len) ||
	    virtio_state_ranges_overlap(output, output_len,
	    source->backend_identity, source->backend_identity_len) ||
	    virtio_state_ranges_overlap(output, output_len,
	    source->backend_state, source->backend_state_len) ||
	    virtio_state_ranges_overlap(output, output_len, written,
	    sizeof(*written)) ||
	    virtio_state_ranges_overlap(written, sizeof(*written), source,
	    sizeof(*source)) ||
	    virtio_state_ranges_overlap(written, sizeof(*written),
	    source->fuse_session, sizeof(*source->fuse_session)) ||
	    virtio_state_ranges_overlap(written, sizeof(*written),
	    source->backend_session, sizeof(*source->backend_session)) ||
	    virtio_state_ranges_overlap(written, sizeof(*written),
	    source->tag, source->tag_len) ||
	    virtio_state_ranges_overlap(written, sizeof(*written),
	    source->backend_identity, source->backend_identity_len) ||
	    virtio_state_ranges_overlap(written, sizeof(*written),
	    source->backend_state, source->backend_state_len));
}

static int
virtio_fs_state_source_validate(const struct virtio_fs_state_source *source,
    size_t *total_size)
{
	uint8_t config[BHYVE_VIRTIO_FS_CONFIG_SIZE];
	size_t total;

	if (source == NULL || total_size == NULL ||
	    source->fuse_session == NULL || source->backend_session == NULL ||
	    source->backend_identity == NULL ||
	    source->backend_identity_len == 0 ||
	    source->backend_identity_len > VIRTIO_FS_STATE_IDENTITY_MAX ||
	    (source->backend_state == NULL && source->backend_state_len != 0) ||
	    source->backend_state_len > VIRTIO_FS_STATE_BACKEND_MAX)
		return (EINVAL);
	if (source->pending_requests != 0)
		return (EBUSY);
	if (virtio_fs_config_encode(source->tag, source->tag_len,
	    source->num_request_queues, config) != 0)
		return (EINVAL);
	if (source->backend_session->phase != VIRTIO_FS_BACKEND_QUIESCED ||
	    source->backend_session->version != VIRTIO_FS_BACKEND_VERSION ||
	    (source->backend_session->features &
	    ~VIRTIO_FS_BACKEND_F_ALL) != 0 ||
	    (source->backend_session->features &
	    VIRTIO_FS_BACKEND_F_FREEZE) == 0 ||
	    (source->backend_session->features &
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER) == 0 ||
	    source->backend_session->maximum_message == 0 ||
	    source->backend_session->maximum_message >
	    VIRTIO_FS_BACKEND_MAX_FRAME ||
	    source->backend_session->maximum_inflight == 0 ||
	    source->backend_session->maximum_inflight >
	    VIRTIO_FS_BACKEND_MAX_INFLIGHT ||
	    source->backend_session->maximum_pending_bytes <
	    source->backend_session->maximum_message ||
	    source->backend_session->maximum_pending_bytes >
	    VIRTIO_FS_BACKEND_MAX_PENDING_BYTES ||
	    source->backend_state_len >
	    source->backend_session->maximum_message ||
	    source->backend_session->incarnation == 0 ||
	    source->backend_session->pending_control_id != 0)
		return (EBUSY);
	if ((source->negotiated_features & BHYVE_VIRTIO_FS_F_NOTIFICATION) != 0 &&
	    (source->backend_session->features &
	    VIRTIO_FS_BACKEND_F_NOTIFICATION) == 0)
		return (EINVAL);
	if ((source->fuse_session->initialized &&
	    source->fuse_session->byte_order ==
	    VIRTIO_FS_BYTE_ORDER_UNKNOWN) ||
	    (source->fuse_session->initialized &&
	    source->fuse_session->incarnation == 0) ||
	    source->fuse_session->byte_order > VIRTIO_FS_BYTE_ORDER_BIG)
		return (EINVAL);
	total = VIRTIO_FS_STATE_HEADER_SIZE;
	if (source->tag_len > SIZE_MAX - total)
		return (EOVERFLOW);
	total += source->tag_len;
	if (source->backend_identity_len > SIZE_MAX - total)
		return (EOVERFLOW);
	total += source->backend_identity_len;
	if (source->backend_state_len > SIZE_MAX - total)
		return (EOVERFLOW);
	total += source->backend_state_len;
	if (total > UINT32_MAX)
		return (EOVERFLOW);
	*total_size = total;
	return (0);
}

int
virtio_fs_state_size(const struct virtio_fs_state_source *source,
    size_t *size)
{

	return (virtio_fs_state_source_validate(source, size));
}

int
virtio_fs_state_encode(const struct virtio_fs_state_source *source,
    void *output, size_t output_capacity, size_t *written)
{
	uint8_t *bytes;
	size_t offset, total;
	int error;

	if (written == NULL)
		return (EINVAL);
	error = virtio_fs_state_source_validate(source, &total);
	if (error != 0)
		return (error);
	if (output == NULL || output_capacity < total)
		return (EMSGSIZE);
	if (virtio_fs_state_encode_overlaps(source, output, total, written))
		return (EINVAL);
	*written = 0;
	bytes = output;
	memset(bytes, 0, total);
	le32enc(bytes + VFS1_OFF_MAGIC, VIRTIO_FS_STATE_MAGIC);
	le16enc(bytes + VFS1_OFF_VERSION, VIRTIO_FS_STATE_VERSION);
	le16enc(bytes + VFS1_OFF_HEADER_SIZE, VIRTIO_FS_STATE_HEADER_SIZE);
	le32enc(bytes + VFS1_OFF_TOTAL_SIZE, (uint32_t)total);
	le32enc(bytes + VFS1_OFF_REQUEST_QUEUES,
	    source->num_request_queues);
	le16enc(bytes + VFS1_OFF_TAG_LEN, (uint16_t)source->tag_len);
	bytes[VFS1_OFF_BYTE_ORDER] = source->fuse_session->byte_order;
	bytes[VFS1_OFF_INITIALIZED] = source->fuse_session->initialized;
	le64enc(bytes + VFS1_OFF_VIRTIO_FEATURES,
	    source->negotiated_features);
	le64enc(bytes + VFS1_OFF_FUSE_INCARNATION,
	    source->fuse_session->incarnation);
	le64enc(bytes + VFS1_OFF_BACKEND_INCARNATION,
	    source->backend_session->incarnation);
	le16enc(bytes + VFS1_OFF_BACKEND_VERSION,
	    source->backend_session->version);
	le32enc(bytes + VFS1_OFF_IDENTITY_LEN,
	    (uint32_t)source->backend_identity_len);
	le32enc(bytes + VFS1_OFF_BACKEND_STATE_LEN,
	    (uint32_t)source->backend_state_len);
	le32enc(bytes + VFS1_OFF_BACKEND_FEATURES,
	    source->backend_session->features);
	le32enc(bytes + VFS1_OFF_BACKEND_MAX_MESSAGE,
	    source->backend_session->maximum_message);
	le32enc(bytes + VFS1_OFF_BACKEND_MAX_INFLIGHT,
	    source->backend_session->maximum_inflight);
	le32enc(bytes + VFS1_OFF_BACKEND_MAX_PENDING,
	    source->backend_session->maximum_pending_bytes);
	offset = VIRTIO_FS_STATE_HEADER_SIZE;
	memcpy(bytes + offset, source->tag, source->tag_len);
	offset += source->tag_len;
	memcpy(bytes + offset, source->backend_identity,
	    source->backend_identity_len);
	offset += source->backend_identity_len;
	if (source->backend_state_len != 0)
		memcpy(bytes + offset, source->backend_state,
		    source->backend_state_len);
	*written = total;
	return (0);
}

int
virtio_fs_state_decode(const void *input, size_t input_len,
    const void *expected_tag, size_t expected_tag_len,
    uint32_t expected_request_queues, uint64_t available_virtio_features,
    const void *expected_backend_identity,
    size_t expected_backend_identity_len,
    const struct virtio_fs_backend_session *expected_backend,
    struct virtio_fs_state_decoded *decoded)
{
	struct virtio_fs_state_decoded candidate;
	const uint8_t *bytes, *identity, *tag;
	uint32_t backend_features, backend_maximum_inflight;
	uint32_t backend_maximum_pending_bytes;
	uint32_t backend_maximum_message, backend_state_len, identity_len;
	uint32_t request_queues, total_size;
	uint16_t backend_version, header_size, tag_len, version;
	uint8_t byte_order, config[BHYVE_VIRTIO_FS_CONFIG_SIZE], initialized;
	size_t expected_size, offset;

	if (input == NULL || decoded == NULL ||
	    expected_backend == NULL ||
	    expected_backend_identity == NULL ||
	    expected_backend_identity_len == 0 ||
	    expected_backend_identity_len > VIRTIO_FS_STATE_IDENTITY_MAX ||
	    virtio_fs_config_encode(expected_tag, expected_tag_len,
	    expected_request_queues, config) != 0)
		return (EINVAL);
	if (virtio_state_ranges_overlap(decoded, sizeof(*decoded), input,
	    input_len) ||
	    /*
	     * The expected values name the already-prepared destination backend.
	     * They must not be borrowed from the untrusted source image: doing so
	     * would make the tag or identity comparison a self-comparison and
	     * could validate a restored image against source-controlled contract
	     * bytes.  Keep the decoder's source and destination domains disjoint
	     * before it reads either one.
	     */
	    virtio_state_ranges_overlap(input, input_len, expected_tag,
	    expected_tag_len) ||
	    virtio_state_ranges_overlap(input, input_len,
	    expected_backend_identity, expected_backend_identity_len) ||
	    virtio_state_ranges_overlap(input, input_len, expected_backend,
	    sizeof(*expected_backend)) ||
	    virtio_state_ranges_overlap(decoded, sizeof(*decoded),
	    expected_tag, expected_tag_len) ||
	    virtio_state_ranges_overlap(decoded, sizeof(*decoded),
	    expected_backend_identity, expected_backend_identity_len) ||
	    virtio_state_ranges_overlap(decoded, sizeof(*decoded),
	    expected_backend, sizeof(*expected_backend)))
		return (EINVAL);
	if (input_len < VIRTIO_FS_STATE_HEADER_SIZE)
		return (EMSGSIZE);
	bytes = input;
	if (le32dec(bytes + VFS1_OFF_MAGIC) != VIRTIO_FS_STATE_MAGIC)
		return (EPROTO);
	version = le16dec(bytes + VFS1_OFF_VERSION);
	header_size = le16dec(bytes + VFS1_OFF_HEADER_SIZE);
	total_size = le32dec(bytes + VFS1_OFF_TOTAL_SIZE);
	if (version != VIRTIO_FS_STATE_VERSION ||
	    header_size != VIRTIO_FS_STATE_HEADER_SIZE)
		return (ENOTSUP);
	if (total_size != input_len)
		return (EMSGSIZE);
	if (le32dec(bytes + VFS1_OFF_FLAGS) != 0 ||
	    le16dec(bytes + VFS1_OFF_RESERVED) != 0)
		return (EPROTO);
	request_queues = le32dec(bytes + VFS1_OFF_REQUEST_QUEUES);
	tag_len = le16dec(bytes + VFS1_OFF_TAG_LEN);
	byte_order = bytes[VFS1_OFF_BYTE_ORDER];
	initialized = bytes[VFS1_OFF_INITIALIZED];
	backend_version = le16dec(bytes + VFS1_OFF_BACKEND_VERSION);
	identity_len = le32dec(bytes + VFS1_OFF_IDENTITY_LEN);
	backend_state_len = le32dec(bytes + VFS1_OFF_BACKEND_STATE_LEN);
	backend_features = le32dec(bytes + VFS1_OFF_BACKEND_FEATURES);
	backend_maximum_message =
	    le32dec(bytes + VFS1_OFF_BACKEND_MAX_MESSAGE);
	backend_maximum_inflight =
	    le32dec(bytes + VFS1_OFF_BACKEND_MAX_INFLIGHT);
	backend_maximum_pending_bytes =
	    le32dec(bytes + VFS1_OFF_BACKEND_MAX_PENDING);
	if (request_queues != expected_request_queues ||
	    tag_len != expected_tag_len ||
	    initialized > 1 || byte_order > VIRTIO_FS_BYTE_ORDER_BIG ||
	    (initialized && byte_order == VIRTIO_FS_BYTE_ORDER_UNKNOWN) ||
	    backend_version != VIRTIO_FS_BACKEND_VERSION ||
	    (backend_features & ~VIRTIO_FS_BACKEND_F_ALL) != 0 ||
	    (backend_features & VIRTIO_FS_BACKEND_F_FREEZE) == 0 ||
	    (backend_features & VIRTIO_FS_BACKEND_F_STATE_TRANSFER) == 0 ||
	    backend_maximum_message == 0 ||
	    backend_maximum_message > VIRTIO_FS_BACKEND_MAX_FRAME ||
	    backend_maximum_inflight == 0 ||
	    backend_maximum_inflight > VIRTIO_FS_BACKEND_MAX_INFLIGHT ||
	    backend_maximum_pending_bytes < backend_maximum_message ||
	    backend_maximum_pending_bytes >
	    VIRTIO_FS_BACKEND_MAX_PENDING_BYTES ||
	    backend_state_len > backend_maximum_message ||
	    identity_len != expected_backend_identity_len ||
	    identity_len == 0 || identity_len > VIRTIO_FS_STATE_IDENTITY_MAX ||
	    backend_state_len > VIRTIO_FS_STATE_BACKEND_MAX)
		return (EINVAL);
	if (((le64dec(bytes + VFS1_OFF_VIRTIO_FEATURES) &
	    BHYVE_VIRTIO_FS_F_NOTIFICATION) != 0 &&
	    (backend_features & VIRTIO_FS_BACKEND_F_NOTIFICATION) == 0) ||
	    (le64dec(bytes + VFS1_OFF_VIRTIO_FEATURES) &
	    ~available_virtio_features) != 0 ||
	    expected_backend->phase != VIRTIO_FS_BACKEND_QUIESCED ||
	    expected_backend->incarnation == 0 ||
	    expected_backend->pending_control_id != 0 ||
	    backend_version != expected_backend->version ||
	    backend_features != expected_backend->features ||
	    backend_maximum_message != expected_backend->maximum_message ||
	    backend_maximum_inflight != expected_backend->maximum_inflight ||
	    backend_maximum_pending_bytes !=
	    expected_backend->maximum_pending_bytes)
		return (ENOTSUP);
	expected_size = VIRTIO_FS_STATE_HEADER_SIZE;
	if (tag_len > SIZE_MAX - expected_size)
		return (EOVERFLOW);
	expected_size += tag_len;
	if (identity_len > SIZE_MAX - expected_size)
		return (EOVERFLOW);
	expected_size += identity_len;
	if (backend_state_len > SIZE_MAX - expected_size)
		return (EOVERFLOW);
	expected_size += backend_state_len;
	if (expected_size != input_len)
		return (EMSGSIZE);
	offset = VIRTIO_FS_STATE_HEADER_SIZE;
	tag = bytes + offset;
	offset += tag_len;
	identity = bytes + offset;
	offset += identity_len;
	if (memcmp(tag, expected_tag, tag_len) != 0 ||
	    memcmp(identity, expected_backend_identity, identity_len) != 0)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.num_request_queues = request_queues;
	candidate.negotiated_features =
	    le64dec(bytes + VFS1_OFF_VIRTIO_FEATURES);
	candidate.fuse_session.byte_order = byte_order;
	candidate.fuse_session.initialized = initialized != 0;
	candidate.fuse_session.incarnation =
	    le64dec(bytes + VFS1_OFF_FUSE_INCARNATION);
	if (candidate.fuse_session.initialized &&
	    candidate.fuse_session.incarnation == 0)
		return (EINVAL);
	candidate.backend_incarnation =
	    le64dec(bytes + VFS1_OFF_BACKEND_INCARNATION);
	if (candidate.backend_incarnation == 0)
		return (EINVAL);
	candidate.backend_protocol_version = backend_version;
	candidate.backend_features = backend_features;
	candidate.backend_maximum_message = backend_maximum_message;
	candidate.backend_maximum_inflight = backend_maximum_inflight;
	candidate.backend_maximum_pending_bytes =
	    backend_maximum_pending_bytes;
	candidate.backend_state = bytes + offset;
	candidate.backend_state_len = backend_state_len;
	*decoded = candidate;
	return (0);
}
