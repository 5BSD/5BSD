/*
 * Independent VFS1 portable-state tests.
 */
#include <sys/endian.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_fs_host.c"
#include "virtio_fs_state.c"

#define	DOC_VFS1_MAGIC		UINT32_C(0x31534656)
#define	DOC_VFS1_VERSION	1U
#define	DOC_VFS1_HEADER_SIZE	76U
/* Section 5.11 bit zero; kept independent of the implementation header. */
#define	DOC_VIRTIO_FS_F_NOTIFICATION	UINT64_C(1)
#define	DOC_VFSB_F_NOTIFICATION	(UINT32_C(1) << 3)

static struct virtio_fs_state_source
state_source(struct virtio_fs_session *fuse,
    struct virtio_fs_backend_session *backend)
{
	static const uint8_t tag[] = { 'w', 'a', 's', 'p' };
	static const uint8_t identity[] = { 0x10, 0x20, 0x30 };
	static const uint8_t state[] = { 0xaa, 0xbb, 0xcc, 0xdd };

	return ((struct virtio_fs_state_source) {
		.tag = tag,
		.tag_len = sizeof(tag),
		.num_request_queues = 2,
		.negotiated_features = UINT64_C(0x100000000),
		.fuse_session = fuse,
		.backend_session = backend,
		.backend_identity = identity,
		.backend_identity_len = sizeof(identity),
		.backend_state = state,
		.backend_state_len = sizeof(state),
	});
}

static void
sessions(struct virtio_fs_session *fuse,
    struct virtio_fs_backend_session *backend)
{

	*fuse = (struct virtio_fs_session) {
		.byte_order = VIRTIO_FS_BYTE_ORDER_LITTLE,
		.initialized = true,
		.incarnation = 11,
	};
	*backend = (struct virtio_fs_backend_session) {
		.phase = VIRTIO_FS_BACKEND_QUIESCED,
		.version = 1,
		.features = VIRTIO_FS_BACKEND_F_FREEZE |
		    VIRTIO_FS_BACKEND_F_STATE_TRANSFER,
		.maximum_message = 1024,
		.maximum_inflight = 8,
		.maximum_pending_bytes = 8192,
		.incarnation = 7,
	};
}

ATF_TC_WITHOUT_HEAD(round_trip_and_literal_layout);
ATF_TC_BODY(round_trip_and_literal_layout, tc)
{
	static const uint8_t tag[] = { 'w', 'a', 's', 'p' };
	static const uint8_t identity[] = { 0x10, 0x20, 0x30 };
	struct virtio_fs_backend_session backend;
	struct virtio_fs_state_decoded decoded;
	struct virtio_fs_session fuse;
	struct virtio_fs_state_source source;
	uint8_t bytes[128];
	size_t size, written;

	sessions(&fuse, &backend);
	source = state_source(&fuse, &backend);
	ATF_REQUIRE_EQ(virtio_fs_state_size(&source, &size), 0);
	ATF_CHECK_EQ(size, DOC_VFS1_HEADER_SIZE + 4 + 3 + 4);
	ATF_REQUIRE_EQ(virtio_fs_state_encode(&source, bytes, sizeof(bytes),
	    &written), 0);
	ATF_CHECK_EQ(written, size);
	ATF_CHECK_EQ(le32dec(bytes), DOC_VFS1_MAGIC);
	ATF_CHECK_EQ(le16dec(bytes + 4), DOC_VFS1_VERSION);
	ATF_CHECK_EQ(le16dec(bytes + 6), DOC_VFS1_HEADER_SIZE);
	ATF_CHECK_EQ(le32dec(bytes + 8), written);
	ATF_CHECK_EQ(le32dec(bytes + 16), 2);
	ATF_CHECK_EQ(le16dec(bytes + 20), 4);
	ATF_CHECK_EQ(bytes[22], VIRTIO_FS_BYTE_ORDER_LITTLE);
	ATF_CHECK_EQ(bytes[23], 1);
	ATF_CHECK_EQ(le64dec(bytes + 32), 11);
	ATF_CHECK_EQ(le64dec(bytes + 40), 7);
	ATF_CHECK_EQ(le32dec(bytes + 60), VIRTIO_FS_BACKEND_F_FREEZE |
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER);
	ATF_CHECK_EQ(le32dec(bytes + 64), 1024);
	ATF_CHECK_EQ(le32dec(bytes + 68), 8);
	ATF_CHECK_EQ(le32dec(bytes + 72), 8192);
	ATF_REQUIRE_EQ(virtio_fs_state_decode(bytes, written, tag,
	    sizeof(tag), 2, UINT64_MAX, identity, sizeof(identity), &backend,
	    &decoded), 0);
	ATF_CHECK_EQ(decoded.num_request_queues, 2);
	ATF_CHECK_EQ(decoded.negotiated_features,
	    source.negotiated_features);
	ATF_CHECK(decoded.fuse_session.initialized);
	ATF_CHECK_EQ(decoded.fuse_session.incarnation, 11);
	ATF_CHECK_EQ(decoded.backend_incarnation, 7);
	ATF_CHECK_EQ(decoded.backend_features, VIRTIO_FS_BACKEND_F_FREEZE |
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER);
	ATF_CHECK_EQ(decoded.backend_maximum_message, 1024);
	ATF_CHECK_EQ(decoded.backend_maximum_inflight, 8);
	ATF_CHECK_EQ(decoded.backend_maximum_pending_bytes, 8192);
	ATF_CHECK_EQ(decoded.backend_state_len, 4);
	ATF_CHECK(memcmp(decoded.backend_state, source.backend_state, 4) == 0);
	/*
	 * The checkpoint retains the source backend incarnation for traceability,
	 * but restore authenticates and thaws through the destination backend's
	 * current session.  A destination incarnation is deliberately local state,
	 * so it must not be required to equal the source value.
	 */
	backend.incarnation = 19;
	memset(&decoded, 0, sizeof(decoded));
	ATF_REQUIRE_EQ(virtio_fs_state_decode(bytes, written, tag,
	    sizeof(tag), 2, UINT64_MAX, identity, sizeof(identity), &backend,
	    &decoded), 0);
	ATF_CHECK_EQ(decoded.backend_incarnation, 7);
}

ATF_TC_WITHOUT_HEAD(save_requires_exact_freeze);
ATF_TC_BODY(save_requires_exact_freeze, tc)
{
	struct virtio_fs_backend_session backend;
	struct virtio_fs_session fuse;
	struct virtio_fs_state_source source;
	uint8_t bytes[128];
	size_t written;

	sessions(&fuse, &backend);
	source = state_source(&fuse, &backend);
	backend.phase = VIRTIO_FS_BACKEND_ACTIVE;
	ATF_CHECK_EQ(virtio_fs_state_encode(&source, bytes, sizeof(bytes),
	    &written), EBUSY);
	backend.phase = VIRTIO_FS_BACKEND_QUIESCED;
	backend.features = 0;
	ATF_CHECK_EQ(virtio_fs_state_encode(&source, bytes, sizeof(bytes),
	    &written), EBUSY);
	backend.features = VIRTIO_FS_BACKEND_F_FREEZE |
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER;
	backend.pending_control_id = 8;
	ATF_CHECK_EQ(virtio_fs_state_encode(&source, bytes, sizeof(bytes),
	    &written), EBUSY);
	backend.pending_control_id = 0;
	source.pending_requests = 1;
	ATF_CHECK_EQ(virtio_fs_state_encode(&source, bytes, sizeof(bytes),
	    &written), EBUSY);
	source.pending_requests = 0;
	source.backend_state_len = backend.maximum_message + 1;
	ATF_CHECK_EQ(virtio_fs_state_encode(&source, bytes, sizeof(bytes),
	    &written), EBUSY);
	source.backend_state_len = 4;
	ATF_CHECK_EQ(virtio_fs_state_encode(&source, bytes,
	    DOC_VFS1_HEADER_SIZE, &written), EMSGSIZE);
	fuse.incarnation = 0;
	ATF_CHECK_EQ(virtio_fs_state_encode(&source, bytes, sizeof(bytes),
	    &written), EINVAL);
}

ATF_TC_WITHOUT_HEAD(notification_requires_backend_contract);
ATF_TC_BODY(notification_requires_backend_contract, tc)
{
	struct virtio_fs_backend_session backend;
	struct virtio_fs_session fuse;
	struct virtio_fs_state_source source;
	uint8_t bytes[128];
	size_t written;

	sessions(&fuse, &backend);
	source = state_source(&fuse, &backend);
	source.negotiated_features |= DOC_VIRTIO_FS_F_NOTIFICATION;
	/* A saved notification queue without its backend ingress contract is bad. */
	ATF_CHECK_EQ(virtio_fs_state_encode(&source, bytes, sizeof(bytes),
	    &written), EINVAL);
	backend.features |= DOC_VFSB_F_NOTIFICATION;
	ATF_REQUIRE_EQ(virtio_fs_state_encode(&source, bytes, sizeof(bytes),
	    &written), 0);
	backend.features &= ~DOC_VFSB_F_NOTIFICATION;
	/* The image is well-formed, but the destination cannot honor it. */
	ATF_CHECK_EQ(virtio_fs_state_decode(bytes, written, source.tag,
	    source.tag_len, source.num_request_queues,
	    source.negotiated_features, source.backend_identity,
	    source.backend_identity_len, &backend,
	    &(struct virtio_fs_state_decoded){ 0 }), ENOTSUP);
}

/*
 * VFS1 is a portable checkpoint record.  In particular, its bytes must not
 * depend on the addresses of the source-session, backend-session, tag,
 * identity, or opaque backend-state objects.  The production queue uses
 * uintptr_t cookies for live request ownership, so this independently guards
 * against accidentally extending the durable record with such runtime data.
 */
ATF_TC_WITHOUT_HEAD(portable_encoding_is_address_independent);
ATF_TC_BODY(portable_encoding_is_address_independent, tc)
{
	uint8_t backend_state_a[] = { 0xaa, 0xbb, 0xcc, 0xdd };
	uint8_t backend_state_b[] = { 0xaa, 0xbb, 0xcc, 0xdd };
	uint8_t bytes_a[128], bytes_b[128];
	uint8_t identity_a[] = { 0x10, 0x20, 0x30 };
	uint8_t identity_b[] = { 0x10, 0x20, 0x30 };
	uint8_t tag_a[] = { 'w', 'a', 's', 'p' };
	uint8_t tag_b[] = { 'w', 'a', 's', 'p' };
	struct virtio_fs_backend_session backend_a, backend_b;
	struct virtio_fs_session fuse_a, fuse_b;
	struct virtio_fs_state_source source_a, source_b;
	size_t written_a, written_b;

	sessions(&fuse_a, &backend_a);
	sessions(&fuse_b, &backend_b);
	source_a = state_source(&fuse_a, &backend_a);
	source_b = state_source(&fuse_b, &backend_b);
	source_a.tag = tag_a;
	source_a.backend_identity = identity_a;
	source_a.backend_state = backend_state_a;
	source_b.tag = tag_b;
	source_b.backend_identity = identity_b;
	source_b.backend_state = backend_state_b;

	ATF_REQUIRE((const void *)&fuse_a != (const void *)&fuse_b);
	ATF_REQUIRE((const void *)&backend_a != (const void *)&backend_b);
	ATF_REQUIRE((const void *)tag_a != (const void *)tag_b);
	ATF_REQUIRE((const void *)identity_a != (const void *)identity_b);
	ATF_REQUIRE((const void *)backend_state_a !=
	    (const void *)backend_state_b);
	ATF_REQUIRE_EQ(virtio_fs_state_encode(&source_a, bytes_a,
	    sizeof(bytes_a), &written_a), 0);
	ATF_REQUIRE_EQ(virtio_fs_state_encode(&source_b, bytes_b,
	    sizeof(bytes_b), &written_b), 0);
	ATF_CHECK_EQ(written_a, written_b);
	ATF_CHECK(memcmp(bytes_a, bytes_b, written_a) == 0);
}

ATF_TC_WITHOUT_HEAD(restore_rejects_corruption_and_mismatch);
ATF_TC_BODY(restore_rejects_corruption_and_mismatch, tc)
{
	static const uint8_t tag[] = { 'w', 'a', 's', 'p' };
	static const uint8_t other_tag[] = { 'n', 'o', 'p', 'e' };
	static const uint8_t identity[] = { 0x10, 0x20, 0x30 };
	static const uint8_t other_identity[] = { 0x10, 0x20, 0x31 };
	struct virtio_fs_backend_session backend;
	struct virtio_fs_state_decoded decoded, unchanged;
	struct virtio_fs_session fuse;
	struct virtio_fs_state_source source;
	uint8_t bytes[128], saved[128];
	size_t written;

	sessions(&fuse, &backend);
	source = state_source(&fuse, &backend);
	ATF_REQUIRE_EQ(virtio_fs_state_encode(&source, saved, sizeof(saved),
	    &written), 0);
	memset(&unchanged, 0xa5, sizeof(unchanged));

	memcpy(bytes, saved, written);
	bytes[12] = 1;
	decoded = unchanged;
	ATF_CHECK_EQ(virtio_fs_state_decode(bytes, written, tag, sizeof(tag),
	    2, UINT64_MAX, identity, sizeof(identity), &backend, &decoded),
	    EPROTO);
	ATF_CHECK(memcmp(&decoded, &unchanged, sizeof(decoded)) == 0);

	memcpy(bytes, saved, written);
	bytes[4] = 2;
	ATF_CHECK_EQ(virtio_fs_state_decode(bytes, written, tag, sizeof(tag),
	    2, UINT64_MAX, identity, sizeof(identity), &backend, &decoded),
	    ENOTSUP);
	ATF_CHECK_EQ(virtio_fs_state_decode(saved, written - 1, tag,
	    sizeof(tag), 2, UINT64_MAX, identity, sizeof(identity), &backend,
	    &decoded), EMSGSIZE);
	ATF_CHECK_EQ(virtio_fs_state_decode(saved, written, other_tag,
	    sizeof(other_tag), 2, UINT64_MAX, identity, sizeof(identity),
	    &backend, &decoded), EINVAL);
	ATF_CHECK_EQ(virtio_fs_state_decode(saved, written, tag, sizeof(tag),
	    2, UINT64_MAX, other_identity, sizeof(other_identity), &backend,
	    &decoded), EINVAL);
	ATF_CHECK_EQ(virtio_fs_state_decode(saved, written, tag, sizeof(tag),
	    1, UINT64_MAX, identity, sizeof(identity), &backend, &decoded),
	    EINVAL);
	memcpy(bytes, saved, written);
	le32enc(bytes + 72, 1);	/* Aggregate budget below max message. */
	ATF_CHECK_EQ(virtio_fs_state_decode(bytes, written, tag, sizeof(tag),
	    2, UINT64_MAX, identity, sizeof(identity), &backend, &decoded),
	    EINVAL);
	memcpy(bytes, saved, written);
	le32enc(bytes + 56, 1025); /* State exceeds negotiated frame. */
	ATF_CHECK_EQ(virtio_fs_state_decode(bytes, written, tag, sizeof(tag),
	    2, UINT64_MAX, identity, sizeof(identity), &backend, &decoded),
	    EINVAL);
	memcpy(bytes, saved, written);
	le64enc(bytes + 32, 0);	/* Initialized FUSE session needs a generation. */
	ATF_CHECK_EQ(virtio_fs_state_decode(bytes, written, tag, sizeof(tag),
	    2, UINT64_MAX, identity, sizeof(identity), &backend, &decoded),
	    EINVAL);

	ATF_CHECK_EQ(virtio_fs_state_decode(saved, written, tag, sizeof(tag),
	    2, 0, identity, sizeof(identity), &backend, &decoded), ENOTSUP);
	backend.maximum_inflight++;
	ATF_CHECK_EQ(virtio_fs_state_decode(saved, written, tag, sizeof(tag),
	    2, UINT64_MAX, identity, sizeof(identity), &backend, &decoded),
	    ENOTSUP);
	backend.maximum_inflight--;
	backend.phase = VIRTIO_FS_BACKEND_ACTIVE;
	ATF_CHECK_EQ(virtio_fs_state_decode(saved, written, tag, sizeof(tag),
	    2, UINT64_MAX, identity, sizeof(identity), &backend, &decoded),
	    ENOTSUP);
}

ATF_TC_WITHOUT_HEAD(aliasing_is_rejected_transactionally);
ATF_TC_BODY(aliasing_is_rejected_transactionally, tc)
{
	static const uint8_t tag[] = { 'w', 'a', 's', 'p' };
	static const uint8_t identity[] = { 0x10, 0x20, 0x30 };
	union {
		struct virtio_fs_state_decoded decoded;
		uint8_t bytes[128];
	} overlap;
	struct virtio_fs_backend_session backend;
	struct virtio_fs_state_decoded decoded, unchanged;
	struct virtio_fs_session fuse;
	struct virtio_fs_state_source source;
	uint8_t bytes[128], saved[128];
	size_t written;

	sessions(&fuse, &backend);
	source = state_source(&fuse, &backend);
	memset(bytes, 0x5a, sizeof(bytes));
	ATF_REQUIRE_EQ(virtio_fs_state_encode(&source, bytes, sizeof(bytes),
	    &written), 0);
	memcpy(saved, bytes, sizeof(saved));

	source.backend_state = bytes + 80;
	source.backend_state_len = 4;
	ATF_CHECK_EQ(virtio_fs_state_encode(&source, bytes, sizeof(bytes),
	    &written), EINVAL);
	ATF_CHECK(memcmp(bytes, saved, sizeof(bytes)) == 0);

	source = state_source(&fuse, &backend);
	ATF_CHECK_EQ(virtio_fs_state_encode(&source, bytes, sizeof(bytes),
	    (size_t *)(void *)bytes), EINVAL);
	ATF_CHECK(memcmp(bytes, saved, sizeof(bytes)) == 0);

	memcpy(overlap.bytes, saved, written);
	ATF_CHECK_EQ(virtio_fs_state_decode(overlap.bytes, written, tag,
	    sizeof(tag), 2, UINT64_MAX, identity, sizeof(identity), &backend,
	    &overlap.decoded), EINVAL);

	ATF_CHECK_EQ(virtio_fs_state_decode(saved, written, tag, sizeof(tag),
	    2, UINT64_MAX, identity, sizeof(identity), &backend,
	    (struct virtio_fs_state_decoded *)(void *)&backend), EINVAL);

	/*
	 * Expected tag, identity, and backend inputs are destination facts.  They
	 * must not be borrowed from the saved image, or the decoder could compare
	 * a source-controlled field with itself instead of the destination.
	 */
	memset(&unchanged, 0xa5, sizeof(unchanged));
	decoded = unchanged;
	ATF_CHECK_EQ(virtio_fs_state_decode(saved, written, saved + 76,
	    sizeof(tag), 2, UINT64_MAX, identity, sizeof(identity), &backend,
	    &decoded), EINVAL);
	ATF_CHECK(memcmp(&decoded, &unchanged, sizeof(decoded)) == 0);
	decoded = unchanged;
	ATF_CHECK_EQ(virtio_fs_state_decode(saved, written, tag, sizeof(tag),
	    2, UINT64_MAX, saved + 76 + sizeof(tag), sizeof(identity), &backend,
	    &decoded), EINVAL);
	ATF_CHECK(memcmp(&decoded, &unchanged, sizeof(decoded)) == 0);
	decoded = unchanged;
	ATF_CHECK_EQ(virtio_fs_state_decode(saved, written, tag, sizeof(tag),
	    2, UINT64_MAX, identity, sizeof(identity),
	    (const struct virtio_fs_backend_session *)(const void *)saved,
	    &decoded), EINVAL);
	ATF_CHECK(memcmp(&decoded, &unchanged, sizeof(decoded)) == 0);

	memset(&decoded, 0, sizeof(decoded));
	ATF_REQUIRE_EQ(virtio_fs_state_decode(saved, written, tag, sizeof(tag),
	    2, UINT64_MAX, identity, sizeof(identity), &backend, &decoded), 0);
	ATF_CHECK_EQ(decoded.backend_state_len, 4);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, round_trip_and_literal_layout);
	ATF_TP_ADD_TC(tp, save_requires_exact_freeze);
	ATF_TP_ADD_TC(tp, notification_requires_backend_contract);
	ATF_TP_ADD_TC(tp, portable_encoding_is_address_independent);
	ATF_TP_ADD_TC(tp, restore_rejects_corruption_and_mismatch);
	ATF_TP_ADD_TC(tp, aliasing_is_rejected_transactionally);
	return (atf_no_error());
}
