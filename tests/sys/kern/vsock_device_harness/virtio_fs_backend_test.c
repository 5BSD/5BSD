/*
 * Independent tests for the private, versioned bhyve/backend protocol.
 */
#include <sys/endian.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_fs_backend.c"

#define	DOC_VFSB_MAGIC			UINT32_C(0x42534656)
#define	DOC_VFSB_VERSION		1U
#define	DOC_VFSB_HEADER_SIZE		40U
#define	DOC_VFSB_HELLO_SIZE		20U
#define	DOC_VFSB_F_CANCEL		(UINT32_C(1) << 0)
#define	DOC_VFSB_F_FREEZE		(UINT32_C(1) << 1)
#define	DOC_VFSB_F_STATE_TRANSFER	(UINT32_C(1) << 2)
#define	DOC_VFSB_F_NOTIFICATION	(UINT32_C(1) << 3)
#define	DOC_VFSB_MSG_F_NOREPLY		(UINT16_C(1) << 0)
#define	DOC_VFSB_CONTROL_ID_BIT		(UINT64_C(1) << 63)
#define	CONTROL_ID(value)		(DOC_VFSB_CONTROL_ID_BIT | (value))

_Static_assert(VIRTIO_FS_BACKEND_MAGIC == DOC_VFSB_MAGIC,
    "backend ABI magic drift");
_Static_assert(VIRTIO_FS_BACKEND_VERSION == DOC_VFSB_VERSION,
    "backend ABI version drift");
_Static_assert(VIRTIO_FS_BACKEND_HEADER_SIZE == DOC_VFSB_HEADER_SIZE,
    "backend ABI header size drift");
_Static_assert(VIRTIO_FS_BACKEND_HELLO_SIZE == DOC_VFSB_HELLO_SIZE,
    "backend ABI hello size drift");
_Static_assert(VIRTIO_FS_BACKEND_F_CANCEL == DOC_VFSB_F_CANCEL,
    "backend ABI cancel feature drift");
_Static_assert(VIRTIO_FS_BACKEND_F_FREEZE == DOC_VFSB_F_FREEZE,
    "backend ABI freeze feature drift");
_Static_assert(VIRTIO_FS_BACKEND_F_STATE_TRANSFER ==
    DOC_VFSB_F_STATE_TRANSFER, "backend ABI state-transfer feature drift");
_Static_assert(VIRTIO_FS_BACKEND_F_NOTIFICATION ==
    DOC_VFSB_F_NOTIFICATION, "backend ABI notification feature drift");
_Static_assert(VIRTIO_FS_BACKEND_MSG_F_NOREPLY == DOC_VFSB_MSG_F_NOREPLY,
    "backend ABI no-reply flag drift");

static struct virtio_fs_backend_hello
default_hello(void)
{

	return ((struct virtio_fs_backend_hello) {
		.minimum_version = 1,
		.maximum_version = 1,
		.features = DOC_VFSB_F_CANCEL | DOC_VFSB_F_FREEZE |
		    DOC_VFSB_F_STATE_TRANSFER,
		.maximum_message = 1024 * 1024,
		.maximum_inflight = 128,
		.maximum_pending_bytes = 8 * 1024 * 1024,
	});
}

static struct virtio_fs_backend_header
header(enum virtio_fs_backend_message_type type, uint64_t id, uint64_t gen)
{

	return ((struct virtio_fs_backend_header) {
		.version = DOC_VFSB_VERSION,
		.type = type,
		.request_id = id,
		.incarnation = gen,
	});
}

ATF_TC_WITHOUT_HEAD(header_wire_and_negative);
ATF_TC_BODY(header_wire_and_negative, tc)
{
	struct virtio_fs_backend_header in, out;
	uint8_t bytes[DOC_VFSB_HEADER_SIZE];

	in = header(VIRTIO_FS_BACKEND_REQUEST, UINT64_C(0x0102030405060708),
	    UINT64_C(0x1112131415161718));
	in.flags = DOC_VFSB_MSG_F_NOREPLY;
	in.payload_len = 0x10203;
	ATF_REQUIRE_EQ(virtio_fs_backend_header_encode(&in, bytes), 0);
	ATF_CHECK_EQ(bytes[0], 'V');
	ATF_CHECK_EQ(bytes[1], 'F');
	ATF_CHECK_EQ(bytes[2], 'S');
	ATF_CHECK_EQ(bytes[3], 'B');
	ATF_CHECK_EQ(le32dec(bytes), DOC_VFSB_MAGIC);
	ATF_CHECK_EQ(le16dec(bytes + 8), DOC_VFSB_HEADER_SIZE);
	ATF_CHECK_EQ(le64dec(bytes + 16), in.request_id);
	ATF_CHECK_EQ(le64dec(bytes + 24), in.incarnation);
	ATF_REQUIRE_EQ(virtio_fs_backend_header_decode(bytes, sizeof(bytes),
	    &out), 0);
	ATF_CHECK_EQ(out.type, in.type);
	ATF_CHECK_EQ(out.flags, in.flags);
	ATF_CHECK_EQ(out.payload_len, in.payload_len);
	ATF_CHECK_EQ(out.request_id, in.request_id);

	bytes[36] = 1;
	ATF_CHECK_EQ(virtio_fs_backend_header_decode(bytes, sizeof(bytes),
	    &out), EPROTO);
	bytes[36] = 0;
	bytes[8] = 39;
	ATF_CHECK_EQ(virtio_fs_backend_header_decode(bytes, sizeof(bytes),
	    &out), EPROTO);
	ATF_CHECK_EQ(virtio_fs_backend_header_decode(bytes, sizeof(bytes) - 1,
	    &out), EMSGSIZE);
	ATF_CHECK_EQ(virtio_fs_backend_header_decode(NULL, sizeof(bytes),
	    &out), EINVAL);

	in = header(VIRTIO_FS_BACKEND_REQUEST, 0, 1);
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), EINVAL);
	in.request_id = 1;
	in.status = -EIO;
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), EINVAL);
	in = header(VIRTIO_FS_BACKEND_RESPONSE, 1, 1);
	in.status = EIO;
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), EINVAL);
	in = header(VIRTIO_FS_BACKEND_CANCEL, 1, 1);
	in.payload_len = 1;
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), EINVAL);
	in = header(VIRTIO_FS_BACKEND_REQUEST, 1, 0);
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), EINVAL);
	in = header(VIRTIO_FS_BACKEND_HELLO, 1, 1);
	in.payload_len = DOC_VFSB_HELLO_SIZE;
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), EINVAL);
	in = header(VIRTIO_FS_BACKEND_HELLO_REPLY, 1, 0);
	in.status = -ECONNREFUSED;
	in.payload_len = DOC_VFSB_HELLO_SIZE;
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), EINVAL);
	in.payload_len = 0;
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), 0);
	in = header(VIRTIO_FS_BACKEND_RESPONSE, 1, 1);
	in.status = -EIO;
	in.payload_len = 1;
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), EINVAL);
	in = header(VIRTIO_FS_BACKEND_REQUEST, CONTROL_ID(1), 1);
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), EINVAL);
	in = header(VIRTIO_FS_BACKEND_QUIESCE, 1, 1);
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), EINVAL);
	in = header(VIRTIO_FS_BACKEND_QUIESCE_REPLY, CONTROL_ID(1), 1);
	in.payload_len = 17;
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), 0);
	in.status = -EIO;
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), EINVAL);
	in = header(VIRTIO_FS_BACKEND_THAW, CONTROL_ID(2), 1);
	in.payload_len = 17;
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), 0);
	in = header(VIRTIO_FS_BACKEND_THAW_REPLY, CONTROL_ID(2), 1);
	in.payload_len = 1;
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), EINVAL);
	in = header(VIRTIO_FS_BACKEND_NOTIFICATION, 0, 1);
	in.payload_len = 1;
	ATF_REQUIRE_EQ(virtio_fs_backend_header_encode(&in, bytes), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_header_decode(bytes, sizeof(bytes),
	    &out), 0);
	ATF_CHECK_EQ(out.type, VIRTIO_FS_BACKEND_NOTIFICATION);
	in.request_id = 1;
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), EINVAL);
	in.request_id = 0;
	in.payload_len = 0;
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), EINVAL);
	in.payload_len = 1;
	in.status = -EIO;
	ATF_CHECK_EQ(virtio_fs_backend_header_encode(&in, bytes), EINVAL);
}

ATF_TC_WITHOUT_HEAD(hello_wire_and_bounds);
ATF_TC_BODY(hello_wire_and_bounds, tc)
{
	struct virtio_fs_backend_hello in, out;
	uint8_t bytes[DOC_VFSB_HELLO_SIZE];

	in = default_hello();
	ATF_REQUIRE_EQ(virtio_fs_backend_hello_encode(&in, bytes), 0);
	ATF_CHECK_EQ(le16dec(bytes), 1);
	ATF_CHECK_EQ(le16dec(bytes + 2), 1);
	ATF_CHECK_EQ(le32dec(bytes + 4),
	    DOC_VFSB_F_CANCEL | DOC_VFSB_F_FREEZE |
	    DOC_VFSB_F_STATE_TRANSFER);
	ATF_CHECK_EQ(le32dec(bytes + 16), 8 * 1024 * 1024);
	ATF_REQUIRE_EQ(virtio_fs_backend_hello_decode(bytes, sizeof(bytes),
	    &out), 0);
	ATF_CHECK_EQ(out.maximum_message, in.maximum_message);
	ATF_CHECK_EQ(out.maximum_inflight, in.maximum_inflight);
	ATF_CHECK_EQ(out.maximum_pending_bytes, in.maximum_pending_bytes);

	in.minimum_version = 2;
	in.maximum_version = 2;
	ATF_CHECK_EQ(virtio_fs_backend_hello_encode(&in, bytes), EINVAL);
	in = default_hello();
	in.maximum_version = DOC_VFSB_VERSION + 1;
	ATF_CHECK_EQ(virtio_fs_backend_hello_encode(&in, bytes), EINVAL);
	in = default_hello();
	in.features |= UINT32_C(0x80000000);
	ATF_CHECK_EQ(virtio_fs_backend_hello_encode(&in, bytes), EINVAL);
	in = default_hello();
	in.features = DOC_VFSB_F_STATE_TRANSFER;
	ATF_CHECK_EQ(virtio_fs_backend_hello_encode(&in, bytes), EINVAL);
	in = default_hello();
	in.maximum_message = VIRTIO_FS_BACKEND_MAX_FRAME + 1U;
	ATF_CHECK_EQ(virtio_fs_backend_hello_encode(&in, bytes), EINVAL);
	in = default_hello();
	in.maximum_inflight = 0;
	ATF_CHECK_EQ(virtio_fs_backend_hello_encode(&in, bytes), EINVAL);
	in = default_hello();
	in.maximum_pending_bytes = in.maximum_message - 1;
	ATF_CHECK_EQ(virtio_fs_backend_hello_encode(&in, bytes), EINVAL);
	ATF_CHECK_EQ(virtio_fs_backend_hello_decode(bytes, sizeof(bytes) - 1,
	    &out), EMSGSIZE);
}

ATF_TC_WITHOUT_HEAD(negotiation_is_bounded_and_atomic);
ATF_TC_BODY(negotiation_is_bounded_and_atomic, tc)
{
	struct virtio_fs_backend_session session;
	struct virtio_fs_backend_hello offer, selected;
	struct virtio_fs_backend_header reply;

	offer = default_hello();
	selected = offer;
	selected.features = VIRTIO_FS_BACKEND_F_FREEZE;
	selected.maximum_message /= 2;
	selected.maximum_inflight /= 2;
	selected.maximum_pending_bytes /= 2;
	virtio_fs_backend_session_init(&session);
	ATF_REQUIRE_EQ(virtio_fs_backend_start_hello(&session, 9, &offer), 0);
	ATF_CHECK_EQ(session.phase, VIRTIO_FS_BACKEND_NEGOTIATING);
	ATF_CHECK_EQ(virtio_fs_backend_start_hello(&session, 10, &offer),
	    EBUSY);
	reply = header(VIRTIO_FS_BACKEND_HELLO_REPLY, 9, 0);
	reply.payload_len = VIRTIO_FS_BACKEND_HELLO_SIZE;
	reply.flags = UINT16_C(0x8000);
	ATF_CHECK_EQ(virtio_fs_backend_finish_hello(&session, &reply,
	    &selected), EPROTO);
	ATF_CHECK_EQ(session.phase, VIRTIO_FS_BACKEND_NEGOTIATING);
	reply.flags = 0;
	ATF_REQUIRE_EQ(virtio_fs_backend_finish_hello(&session, &reply,
	    &selected), 0);
	ATF_CHECK_EQ(session.phase, VIRTIO_FS_BACKEND_ACTIVE);
	ATF_CHECK_EQ(session.features, VIRTIO_FS_BACKEND_F_FREEZE);
	ATF_CHECK_EQ(session.maximum_message, selected.maximum_message);
	ATF_CHECK_EQ(session.incarnation, 1);

	virtio_fs_backend_disconnect(&session);
	ATF_REQUIRE_EQ(virtio_fs_backend_start_hello(&session, 10, &offer), 0);
	reply = header(VIRTIO_FS_BACKEND_HELLO_REPLY, 10, 0);
	reply.status = -ECONNREFUSED;
	ATF_CHECK_EQ(virtio_fs_backend_finish_hello(&session, &reply, NULL),
	    ECONNREFUSED);
	ATF_CHECK_EQ(session.phase, VIRTIO_FS_BACKEND_DISCONNECTED);

	ATF_REQUIRE_EQ(virtio_fs_backend_start_hello(&session, 11, &offer), 0);
	selected = offer;
	selected.maximum_inflight++;
	reply.request_id = 11;
	reply.status = 0;
	reply.payload_len = DOC_VFSB_HELLO_SIZE;
	ATF_CHECK_EQ(virtio_fs_backend_finish_hello(&session, &reply,
	    &selected), EPROTO);
	ATF_CHECK_EQ(session.phase, VIRTIO_FS_BACKEND_DISCONNECTED);

	/* A reconnect receives a fresh incarnation rather than reusing one. */
	selected = offer;
	ATF_REQUIRE_EQ(virtio_fs_backend_start_hello(&session, 12, &offer), 0);
	reply.request_id = 12;
	ATF_REQUIRE_EQ(virtio_fs_backend_finish_hello(&session, &reply,
	    &selected), 0);
	ATF_CHECK_EQ(session.incarnation, 4);

	virtio_fs_backend_disconnect(&session);
	session.incarnation = UINT64_MAX;
	ATF_CHECK_EQ(virtio_fs_backend_start_hello(&session, 13, &offer),
	    EOVERFLOW);
	ATF_CHECK_EQ(session.phase, VIRTIO_FS_BACKEND_DISCONNECTED);
}

ATF_TC_WITHOUT_HEAD(control_lifecycle_and_failures);
ATF_TC_BODY(control_lifecycle_and_failures, tc)
{
	struct virtio_fs_backend_session session;
	struct virtio_fs_backend_hello offer;
	struct virtio_fs_backend_header reply;

	offer = default_hello();
	virtio_fs_backend_session_init(&session);
	ATF_REQUIRE_EQ(virtio_fs_backend_start_hello(&session, 1, &offer), 0);
	reply = header(VIRTIO_FS_BACKEND_HELLO_REPLY, 1, 0);
	reply.payload_len = VIRTIO_FS_BACKEND_HELLO_SIZE;
	ATF_REQUIRE_EQ(virtio_fs_backend_finish_hello(&session, &reply,
	    &offer), 0);

	ATF_REQUIRE_EQ(virtio_fs_backend_start_control(&session,
	    VIRTIO_FS_BACKEND_QUIESCE, CONTROL_ID(2)), 0);
	reply = header(VIRTIO_FS_BACKEND_QUIESCE_REPLY, CONTROL_ID(2),
	    session.incarnation);
	reply.payload_len = 123;
	ATF_REQUIRE_EQ(virtio_fs_backend_finish_control(&session, &reply), 0);
	ATF_CHECK_EQ(session.phase, VIRTIO_FS_BACKEND_QUIESCED);
	ATF_REQUIRE_EQ(virtio_fs_backend_start_control(&session,
	    VIRTIO_FS_BACKEND_THAW, CONTROL_ID(3)), 0);
	reply = header(VIRTIO_FS_BACKEND_THAW_REPLY, CONTROL_ID(3),
	    session.incarnation);
	reply.status = -EIO;
	ATF_CHECK_EQ(virtio_fs_backend_finish_control(&session, &reply), EIO);
	ATF_CHECK_EQ(session.phase, VIRTIO_FS_BACKEND_QUIESCED);
	ATF_REQUIRE_EQ(virtio_fs_backend_start_control(&session,
	    VIRTIO_FS_BACKEND_THAW, CONTROL_ID(4)), 0);
	reply.request_id = CONTROL_ID(4);
	reply.status = 0;
	ATF_REQUIRE_EQ(virtio_fs_backend_finish_control(&session, &reply), 0);
	ATF_CHECK_EQ(session.phase, VIRTIO_FS_BACKEND_ACTIVE);
	ATF_REQUIRE_EQ(virtio_fs_backend_start_control(&session,
	    VIRTIO_FS_BACKEND_SHUTDOWN, CONTROL_ID(5)), 0);
	reply = header(VIRTIO_FS_BACKEND_SHUTDOWN_REPLY, CONTROL_ID(5),
	    session.incarnation);
	reply.status = -EBUSY;
	ATF_CHECK_EQ(virtio_fs_backend_finish_control(&session, &reply), EIO);
	ATF_CHECK_EQ(session.phase, VIRTIO_FS_BACKEND_ACTIVE);
	ATF_REQUIRE_EQ(virtio_fs_backend_start_control(&session,
	    VIRTIO_FS_BACKEND_SHUTDOWN, CONTROL_ID(6)), 0);
	reply = header(VIRTIO_FS_BACKEND_SHUTDOWN_REPLY, CONTROL_ID(6),
	    session.incarnation);
	ATF_REQUIRE_EQ(virtio_fs_backend_finish_control(&session, &reply), 0);
	ATF_CHECK_EQ(session.phase, VIRTIO_FS_BACKEND_CLOSED);

	/* Shutdown failure must preserve a quiesced source for recovery. */
	virtio_fs_backend_session_init(&session);
	ATF_REQUIRE_EQ(virtio_fs_backend_start_hello(&session, 7, &offer), 0);
	reply = header(VIRTIO_FS_BACKEND_HELLO_REPLY, 7, 0);
	reply.payload_len = VIRTIO_FS_BACKEND_HELLO_SIZE;
	ATF_REQUIRE_EQ(virtio_fs_backend_finish_hello(&session, &reply,
	    &offer), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_start_control(&session,
	    VIRTIO_FS_BACKEND_QUIESCE, CONTROL_ID(8)), 0);
	reply = header(VIRTIO_FS_BACKEND_QUIESCE_REPLY, CONTROL_ID(8),
	    session.incarnation);
	ATF_REQUIRE_EQ(virtio_fs_backend_finish_control(&session, &reply), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_start_control(&session,
	    VIRTIO_FS_BACKEND_SHUTDOWN, CONTROL_ID(9)), 0);
	reply = header(VIRTIO_FS_BACKEND_SHUTDOWN_REPLY, CONTROL_ID(9),
	    session.incarnation);
	reply.status = -EBUSY;
	ATF_CHECK_EQ(virtio_fs_backend_finish_control(&session, &reply), EIO);
	ATF_CHECK_EQ(session.phase, VIRTIO_FS_BACKEND_QUIESCED);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, header_wire_and_negative);
	ATF_TP_ADD_TC(tp, hello_wire_and_bounds);
	ATF_TP_ADD_TC(tp, negotiation_is_bounded_and_atomic);
	ATF_TP_ADD_TC(tp, control_lifecycle_and_failures);
	return (atf_no_error());
}
