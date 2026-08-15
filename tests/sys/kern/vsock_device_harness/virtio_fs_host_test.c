/*
 * Independent VirtIO 1.4 section 5.11 FUSE transport-boundary tests.
 */
#include <sys/endian.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_fs_host.c"
#include "virtio_1_4_spec.h"

#define	DOC_FUSE_IN_HEADER_SIZE		VIRTIO14_FUSE_IN_HEADER_SIZE
#define	DOC_FUSE_INIT_IN_MIN_SIZE	56U
#define	DOC_FUSE_OUT_HEADER_SIZE	VIRTIO14_FUSE_OUT_HEADER_SIZE
#define	DOC_FUSE_INIT_OUT_MIN_SIZE	24U
#define	DOC_FUSE_INIT			VIRTIO14_FUSE_INIT
#define	DOC_FUSE_FORGET			VIRTIO14_FUSE_FORGET
#define	DOC_FUSE_INTERRUPT		VIRTIO14_FUSE_INTERRUPT
#define	DOC_FUSE_BATCH_FORGET		42U
#define	DOC_FS_TAG_SIZE			VIRTIO14_FS_TAG_SIZE
#define	DOC_FS_CONFIG_SIZE		VIRTIO14_FS_CONFIG_BASE_SIZE
#define	DOC_FS_NOTIFICATION_CONFIG_SIZE \
	VIRTIO14_FS_CONFIG_NOTIFICATION_SIZE

struct backend_state {
	int error;
	size_t response_len;
	int32_t response_error;
	uint64_t unique;
	bool big_endian;
	unsigned int calls;
};

static void
encode_request(uint8_t request[DOC_FUSE_IN_HEADER_SIZE], uint32_t opcode,
    uint64_t unique, bool big_endian)
{

	memset(request, 0, DOC_FUSE_IN_HEADER_SIZE);
	if (big_endian) {
		be32enc(request, DOC_FUSE_IN_HEADER_SIZE);
		be32enc(request + 4, opcode);
		be64enc(request + 8, unique);
	} else {
		le32enc(request, DOC_FUSE_IN_HEADER_SIZE);
		le32enc(request + 4, opcode);
		le64enc(request + 8, unique);
	}
}

static void
encode_init_request(uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE],
    uint64_t unique, bool big_endian)
{

	memset(request, 0, DOC_FUSE_INIT_IN_MIN_SIZE);
	encode_request(request, DOC_FUSE_INIT, unique, big_endian);
	if (big_endian) {
		be32enc(request, DOC_FUSE_INIT_IN_MIN_SIZE);
		be32enc(request + DOC_FUSE_IN_HEADER_SIZE, 7);
		be32enc(request + DOC_FUSE_IN_HEADER_SIZE + 4, 31);
	} else {
		le32enc(request, DOC_FUSE_INIT_IN_MIN_SIZE);
		le32enc(request + DOC_FUSE_IN_HEADER_SIZE, 7);
		le32enc(request + DOC_FUSE_IN_HEADER_SIZE + 4, 31);
	}
}

static void
encode_hiprio_request(uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE],
    uint32_t opcode, uint64_t unique)
{

	memset(request, 0, DOC_FUSE_INIT_IN_MIN_SIZE);
	encode_request(request, opcode, unique, false);
	le32enc(request, DOC_FUSE_IN_HEADER_SIZE + 8);
}

static int
backend_request(void *arg, const void *request __unused,
    size_t request_len __unused, void *response, size_t response_capacity,
    size_t *written)
{
	struct backend_state *state;
	uint8_t *bytes;

	state = arg;
	state->calls++;
	if (state->error != 0)
		return (state->error);
	*written = state->response_len;
	if (state->response_len == 0)
		return (0);
	ATF_REQUIRE(response_capacity >= DOC_FUSE_OUT_HEADER_SIZE);
	bytes = response;
	memset(bytes, 0, MIN(response_capacity, state->response_len));
	if (state->big_endian) {
		be32enc(bytes, state->response_len);
		be32enc(bytes + 4, (uint32_t)state->response_error);
		be64enc(bytes + 8, state->unique);
	} else {
		le32enc(bytes, state->response_len);
		le32enc(bytes + 4, (uint32_t)state->response_error);
		le64enc(bytes + 8, state->unique);
	}
	if (response_capacity >= DOC_FUSE_INIT_OUT_MIN_SIZE &&
	    state->response_len >= DOC_FUSE_INIT_OUT_MIN_SIZE &&
	    state->response_error == 0) {
		if (state->big_endian) {
			be32enc(bytes + 16, 7);
			be32enc(bytes + 20, 31);
		} else {
			le32enc(bytes + 16, 7);
			le32enc(bytes + 20, 31);
		}
	}
	return (0);
}

ATF_TC_WITHOUT_HEAD(configuration_layout_and_utf8);
ATF_TC_BODY(configuration_layout_and_utf8, tc)
{
	static const uint8_t tag[] = {
		'w', 'a', 's', 'p', 0xe2, 0x98, 0x83,
	};
	static const uint8_t maximum_scalar[] = {
		0xf4, 0x8f, 0xbf, 0xbf,
	};
	uint8_t config[DOC_FS_NOTIFICATION_CONFIG_SIZE];
	uint8_t invalid[DOC_FS_TAG_SIZE + 1];

	/* The oracle, not the implementation header, fixes both wire lengths. */
	ATF_REQUIRE_EQ(BHYVE_VIRTIO_FS_CONFIG_BASE_SIZE, DOC_FS_CONFIG_SIZE);
	ATF_REQUIRE_EQ(BHYVE_VIRTIO_FS_CONFIG_SIZE,
	    DOC_FS_NOTIFICATION_CONFIG_SIZE);

	memset(config, 0xa5, sizeof(config));
	ATF_REQUIRE_EQ(virtio_fs_config_encode(tag, sizeof(tag), 0x01020304,
	    config), 0);
	ATF_CHECK(memcmp(config, tag, sizeof(tag)) == 0);
	for (size_t i = sizeof(tag); i < DOC_FS_TAG_SIZE; i++)
		ATF_CHECK_EQ(config[i], 0);
	ATF_CHECK_EQ(config[36], 0x04);
	ATF_CHECK_EQ(config[37], 0x03);
	ATF_CHECK_EQ(config[38], 0x02);
	ATF_CHECK_EQ(config[39], 0x01);
	ATF_CHECK_EQ(le32dec(config + 40), 0);
	ATF_REQUIRE_EQ(virtio_fs_config_encode_notification(tag, sizeof(tag),
	    3, 65536, config), 0);
	ATF_CHECK_EQ(le32dec(config + 36), 3);
	ATF_CHECK_EQ(le32dec(config + 40), 65536);

	memcpy(config + 5, tag, sizeof(tag));
	ATF_REQUIRE_EQ(virtio_fs_config_encode(config + 5, sizeof(tag), 2,
	    config), 0);
	ATF_CHECK(memcmp(config, tag, sizeof(tag)) == 0);
	ATF_CHECK_EQ(le32dec(config + DOC_FS_TAG_SIZE), 2);

	ATF_CHECK_EQ(virtio_fs_config_encode(tag, 0, 1, config), EINVAL);
	ATF_CHECK_EQ(virtio_fs_config_encode(tag, sizeof(tag), 0, config),
	    EINVAL);
	memset(invalid, 'a', sizeof(invalid));
	ATF_CHECK_EQ(virtio_fs_config_encode(invalid, sizeof(invalid), 1,
	    config), EINVAL);
	invalid[0] = 0xc0;	/* Overlong sequence starter. */
	ATF_CHECK_EQ(virtio_fs_config_encode(invalid, 2, 1, config), EINVAL);
	invalid[0] = 0xed;	/* UTF-16 surrogate U+D800. */
	invalid[1] = 0xa0;
	invalid[2] = 0x80;
	ATF_CHECK_EQ(virtio_fs_config_encode(invalid, 3, 1, config), EINVAL);
	invalid[0] = 'a';
	invalid[1] = 0;
	ATF_CHECK_EQ(virtio_fs_config_encode(invalid, 2, 1, config), EINVAL);
	invalid[0] = 'a';
	invalid[1] = '\n';	/* Linux sysfs/uevent compatibility. */
	ATF_CHECK_EQ(virtio_fs_config_encode(invalid, 2, 1, config), EINVAL);
	invalid[0] = 0x80;	/* Stray continuation byte. */
	ATF_CHECK_EQ(virtio_fs_config_encode(invalid, 1, 1, config), EINVAL);
	invalid[0] = 0xe2;	/* Incomplete three-byte sequence. */
	invalid[1] = 0x98;
	ATF_CHECK_EQ(virtio_fs_config_encode(invalid, 2, 1, config), EINVAL);
	invalid[0] = 0xf4;	/* Above U+10FFFF. */
	invalid[1] = 0x90;
	invalid[2] = 0x80;
	invalid[3] = 0x80;
	ATF_CHECK_EQ(virtio_fs_config_encode(invalid, 4, 1, config), EINVAL);
	ATF_CHECK_EQ(virtio_fs_config_encode(maximum_scalar,
	    sizeof(maximum_scalar), 1, config), 0);
	ATF_CHECK_EQ(virtio_fs_config_encode(NULL, 1, 1, config), EINVAL);
	ATF_CHECK_EQ(virtio_fs_config_encode(tag, sizeof(tag), 1, NULL),
	    EINVAL);
}

ATF_TC_WITHOUT_HEAD(little_and_big_endian_init);
ATF_TC_BODY(little_and_big_endian_init, tc)
{
	struct virtio_fs_session session;
	struct backend_state backend;
	uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE], response[64];
	size_t written;

	memset(&session, 0, sizeof(session));
	memset(&backend, 0, sizeof(backend));
	backend.response_len = DOC_FUSE_INIT_OUT_MIN_SIZE;
	backend.unique = 0x0102030405060708;
	encode_init_request(request, backend.unique, false);
	ATF_REQUIRE_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), 0);
	ATF_CHECK_EQ(written, DOC_FUSE_INIT_OUT_MIN_SIZE);
	ATF_CHECK_EQ(session.byte_order, VIRTIO_FS_BYTE_ORDER_LITTLE);
	ATF_CHECK(session.initialized);
	ATF_CHECK_EQ(session.incarnation, 1);

	virtio_fs_session_reset(&session);
	backend.big_endian = true;
	encode_init_request(request, backend.unique, true);
	ATF_REQUIRE_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), 0);
	ATF_CHECK_EQ(session.byte_order, VIRTIO_FS_BYTE_ORDER_BIG);
	ATF_CHECK_EQ(session.incarnation, 3);

	/* A later INIT is allowed to replace the session and byte order. */
	backend.big_endian = false;
	encode_init_request(request, backend.unique, false);
	ATF_REQUIRE_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), 0);
	ATF_CHECK_EQ(session.byte_order, VIRTIO_FS_BYTE_ORDER_LITTLE);
	ATF_CHECK_EQ(session.incarnation, 4);
}

ATF_TC_WITHOUT_HEAD(queue_class_and_no_reply);
ATF_TC_BODY(queue_class_and_no_reply, tc)
{
	struct virtio_fs_session session = {
		.byte_order = VIRTIO_FS_BYTE_ORDER_LITTLE,
		.initialized = true,
		.incarnation = 1,
	};
	struct backend_state backend;
	uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE], response[64];
	size_t written;

	memset(&backend, 0, sizeof(backend));
	encode_hiprio_request(request, DOC_FUSE_FORGET, 9);
	ATF_REQUIRE_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_HIPRIO, request, le32dec(request), response,
	    sizeof(response), backend_request, &backend, &written), 0);
	ATF_CHECK_EQ(written, 0);
	ATF_CHECK_EQ(backend.calls, 1);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, le32dec(request), response,
	    sizeof(response), backend_request, &backend, &written), EPROTO);

	backend.response_len = DOC_FUSE_OUT_HEADER_SIZE;
	backend.unique = 10;
	encode_hiprio_request(request, DOC_FUSE_INTERRUPT, backend.unique);
	ATF_REQUIRE_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_HIPRIO, request, le32dec(request), response,
	    sizeof(response), backend_request, &backend, &written), 0);
	ATF_CHECK_EQ(written, DOC_FUSE_OUT_HEADER_SIZE);

	encode_request(request, DOC_FUSE_FORGET, 11, false);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_HIPRIO, request, DOC_FUSE_IN_HEADER_SIZE, response,
	    sizeof(response), backend_request, &backend, &written), EPROTO);
	encode_hiprio_request(request, DOC_FUSE_BATCH_FORGET, 12);
	le32enc(request + DOC_FUSE_IN_HEADER_SIZE, 1);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_HIPRIO, request, le32dec(request), response,
	    sizeof(response), backend_request, &backend, &written), EPROTO);
}

ATF_TC_WITHOUT_HEAD(malformed_requests_are_not_forwarded);
ATF_TC_BODY(malformed_requests_are_not_forwarded, tc)
{
	struct virtio_fs_session session;
	struct backend_state backend;
	uint8_t init_request[DOC_FUSE_INIT_IN_MIN_SIZE];
	uint8_t request[DOC_FUSE_IN_HEADER_SIZE], response[64];
	size_t written;

	memset(&session, 0, sizeof(session));
	memset(&backend, 0, sizeof(backend));
	backend.response_len = DOC_FUSE_OUT_HEADER_SIZE;
	backend.unique = 1;
	encode_request(request, 1, backend.unique, false);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), EPROTO);
	ATF_CHECK_EQ(backend.calls, 0);

	encode_request(request, DOC_FUSE_INIT, 0, false);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), EPROTO);
	le32enc(request, sizeof(request) - 1);
	le64enc(request + 8, 1);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), EPROTO);
	ATF_CHECK_EQ(backend.calls, 0);

	/* Header-only INIT is truncated and must not advance the session. */
	encode_request(request, DOC_FUSE_INIT, 1, false);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), EPROTO);
	ATF_CHECK_EQ(backend.calls, 0);

	/*
	 * A well-formed, full-length INIT whose only defect is a zero unique
	 * must be rejected during acceptance, before the backend is consulted.
	 * Header size alone would otherwise mask the zero-unique rule.
	 */
	encode_init_request(init_request, 0, false);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, init_request, sizeof(init_request), response,
	    sizeof(response), backend_request, &backend, &written), EPROTO);
	ATF_CHECK_EQ(backend.calls, 0);

	encode_init_request(init_request, 1, false);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, init_request, sizeof(init_request), response,
	    DOC_FUSE_OUT_HEADER_SIZE - 1, backend_request, &backend, &written),
	    EPROTO);
	ATF_CHECK_EQ(backend.calls, 0);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, init_request, sizeof(init_request), response,
	    DOC_FUSE_OUT_HEADER_SIZE, backend_request, &backend, &written),
	    EPROTO);
	ATF_CHECK_EQ(backend.calls, 0);

	session.incarnation = UINT64_MAX;
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, init_request, sizeof(init_request), response,
	    sizeof(response), backend_request, &backend, &written), EOVERFLOW);
	ATF_CHECK_EQ(backend.calls, 0);
}

ATF_TC_WITHOUT_HEAD(response_validation_is_atomic);
ATF_TC_BODY(response_validation_is_atomic, tc)
{
	struct virtio_fs_session session;
	struct backend_state backend;
	uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE], response[64];
	size_t written;

	memset(&session, 0, sizeof(session));
	memset(&backend, 0, sizeof(backend));
	backend.response_len = DOC_FUSE_OUT_HEADER_SIZE;
	backend.unique = 7;
	encode_init_request(request, backend.unique, false);

	backend.response_error = 1;
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), EPROTO);
	ATF_CHECK(!session.initialized);
	backend.response_error = -4096;
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), EPROTO);
	ATF_CHECK(!session.initialized);
	backend.response_error = -EIO;
	backend.unique++;
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), EPROTO);
	ATF_CHECK(!session.initialized);
	backend.unique--;
	ATF_REQUIRE_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), 0);
	ATF_CHECK(!session.initialized);
	ATF_CHECK_EQ(session.byte_order, VIRTIO_FS_BYTE_ORDER_LITTLE);
	ATF_CHECK_EQ(session.incarnation, 4);

	virtio_fs_session_reset(&session);
	backend.response_error = 0;
	backend.response_len = DOC_FUSE_OUT_HEADER_SIZE;
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), EPROTO);
	ATF_CHECK(!session.initialized);

	backend.response_len = sizeof(response) + 1;
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), EPROTO);
	ATF_CHECK(!session.initialized);

	backend.response_len = DOC_FUSE_OUT_HEADER_SIZE;
	backend.error = ECONNRESET;
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written),
	    ECONNRESET);
	ATF_CHECK(!session.initialized);
}

ATF_TC_WITHOUT_HEAD(asynchronous_init_and_stale_completion);
ATF_TC_BODY(asynchronous_init_and_stale_completion, tc)
{
	struct virtio_fs_request_context first, second;
	struct virtio_fs_session session;
	uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE], response[64];

	memset(&session, 0, sizeof(session));
	encode_init_request(request, 11, false);
	ATF_REQUIRE_EQ(virtio_fs_request_accept(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request),
	    sizeof(response), &first), 0);
	ATF_CHECK_EQ(session.incarnation, 1);
	ATF_CHECK(!session.initialized);
	ATF_CHECK_EQ(session.byte_order, VIRTIO_FS_BYTE_ORDER_LITTLE);

	encode_init_request(request, 12, true);
	ATF_REQUIRE_EQ(virtio_fs_request_accept(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request),
	    sizeof(response), &second), 0);
	ATF_CHECK_EQ(session.incarnation, 2);
	ATF_CHECK_EQ(session.byte_order, VIRTIO_FS_BYTE_ORDER_BIG);

	memset(response, 0, sizeof(response));
	le32enc(response, DOC_FUSE_OUT_HEADER_SIZE);
	le64enc(response + 8, 11);
	ATF_CHECK_EQ(virtio_fs_response_complete(&session, &first, response,
	    DOC_FUSE_OUT_HEADER_SIZE), ESTALE);
	ATF_CHECK(!session.initialized);

	be32enc(response, DOC_FUSE_INIT_OUT_MIN_SIZE);
	be32enc(response + 4, 0);
	be64enc(response + 8, 12);
	be32enc(response + 16, 7);
	be32enc(response + 20, 31);
	ATF_REQUIRE_EQ(virtio_fs_response_complete(&session, &second,
	    response, DOC_FUSE_INIT_OUT_MIN_SIZE), 0);
	ATF_CHECK(session.initialized);

	second.byte_order = VIRTIO_FS_BYTE_ORDER_UNKNOWN;
	ATF_CHECK_EQ(virtio_fs_response_complete(&session, &second, response,
	    DOC_FUSE_OUT_HEADER_SIZE), EINVAL);
}

ATF_TC_WITHOUT_HEAD(newer_major_requires_a_second_init);
ATF_TC_BODY(newer_major_requires_a_second_init, tc)
{
	struct virtio_fs_request_context context;
	struct virtio_fs_session session;
	uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE], response[64];

	memset(&session, 0, sizeof(session));
	encode_init_request(request, 19, false);
	le32enc(request + DOC_FUSE_IN_HEADER_SIZE, 8);
	ATF_REQUIRE_EQ(virtio_fs_request_accept(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request),
	    sizeof(response), &context), 0);
	ATF_CHECK_EQ(context.init_major, 8);

	memset(response, 0, sizeof(response));
	le32enc(response, DOC_FUSE_INIT_OUT_MIN_SIZE);
	le64enc(response + 8, 19);
	le32enc(response + 16, 7);
	le32enc(response + 20, 35);
	ATF_REQUIRE_EQ(virtio_fs_response_complete(&session, &context,
	    response, DOC_FUSE_INIT_OUT_MIN_SIZE), 0);
	ATF_CHECK(!session.initialized);

	encode_request(request, 1, 20, false);
	ATF_CHECK_EQ(virtio_fs_request_accept(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, DOC_FUSE_IN_HEADER_SIZE,
	    sizeof(response), &context), EPROTO);

	encode_init_request(request, 21, false);
	ATF_REQUIRE_EQ(virtio_fs_request_accept(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request),
	    sizeof(response), &context), 0);
	le32enc(response, DOC_FUSE_INIT_OUT_MIN_SIZE);
	le64enc(response + 8, 21);
	le32enc(response + 16, 7);
	le32enc(response + 20, 35);
	ATF_REQUIRE_EQ(virtio_fs_response_complete(&session, &context,
	    response, DOC_FUSE_INIT_OUT_MIN_SIZE), 0);
	ATF_CHECK(session.initialized);

	/* A daemon cannot select a major newer than the kernel offered. */
	encode_init_request(request, 22, false);
	ATF_REQUIRE_EQ(virtio_fs_request_accept(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request),
	    sizeof(response), &context), 0);
	le64enc(response + 8, 22);
	le32enc(response + 16, 8);
	ATF_CHECK_EQ(virtio_fs_response_complete(&session, &context,
	    response, DOC_FUSE_INIT_OUT_MIN_SIZE), EPROTO);
	ATF_CHECK(!session.initialized);
}

ATF_TC_WITHOUT_HEAD(api_contract_validation);
ATF_TC_BODY(api_contract_validation, tc)
{
	struct virtio_fs_session session;
	struct backend_state backend;
	uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE], response[64];
	size_t written;

	memset(&session, 0, sizeof(session));
	memset(&backend, 0, sizeof(backend));
	backend.response_len = DOC_FUSE_OUT_HEADER_SIZE;
	backend.unique = 1;
	encode_init_request(request, backend.unique, false);

	ATF_CHECK_EQ(virtio_fs_process_request(NULL,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), EINVAL);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    (enum virtio_fs_queue_class)99, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), EINVAL);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, NULL, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), EINVAL);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), NULL,
	    sizeof(response), backend_request, &backend, &written), EINVAL);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), NULL, &backend, &written), EINVAL);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, NULL), EINVAL);

	session.incarnation = UINT64_MAX;
	virtio_fs_session_reset(&session);
	ATF_CHECK_EQ(session.incarnation, UINT64_MAX);
	ATF_CHECK_EQ(session.byte_order, VIRTIO_FS_BYTE_ORDER_UNKNOWN);
	ATF_CHECK(!session.initialized);
	virtio_fs_session_reset(NULL);
}

ATF_TC_WITHOUT_HEAD(publication_aliases_are_rejected);
ATF_TC_BODY(publication_aliases_are_rejected, tc)
{
	struct virtio_fs_request_context context;
	struct virtio_fs_session session, saved;
	struct backend_state backend;
	uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE], response[64];
	size_t written;

	memset(&session, 0, sizeof(session));
	memset(&backend, 0, sizeof(backend));
	backend.response_len = DOC_FUSE_INIT_OUT_MIN_SIZE;
	backend.unique = 9;
	encode_init_request(request, backend.unique, false);
	saved = session;
	written = 77;
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend,
	    (size_t *)&session), EINVAL);
	ATF_CHECK_EQ(memcmp(&session, &saved, sizeof(session)), 0);
	ATF_CHECK_EQ(backend.calls, 0);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), &session,
	    sizeof(response), backend_request, &backend, &written), EINVAL);
	ATF_CHECK_EQ(written, 77);
	ATF_CHECK_EQ(memcmp(&session, &saved, sizeof(session)), 0);
	ATF_CHECK_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), request,
	    sizeof(request), backend_request, &backend, &written), EINVAL);
	ATF_CHECK_EQ(written, 77);
	ATF_CHECK_EQ(le32dec(request), DOC_FUSE_INIT_IN_MIN_SIZE);

	ATF_CHECK_EQ(virtio_fs_request_accept(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), sizeof(response),
	    (struct virtio_fs_request_context *)&session), EINVAL);
	ATF_CHECK_EQ(memcmp(&session, &saved, sizeof(session)), 0);
	ATF_CHECK_EQ(virtio_fs_request_accept(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), sizeof(response),
	    (struct virtio_fs_request_context *)request), EINVAL);
	ATF_CHECK_EQ(le32dec(request), DOC_FUSE_INIT_IN_MIN_SIZE);

	ATF_REQUIRE_EQ(virtio_fs_request_accept(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), sizeof(response),
	    &context), 0);
	saved = session;
	ATF_CHECK_EQ(virtio_fs_response_complete(&session, &context, &session,
	    DOC_FUSE_INIT_OUT_MIN_SIZE), EINVAL);
	ATF_CHECK_EQ(memcmp(&session, &saved, sizeof(session)), 0);

	memset(&session, 0, sizeof(session));
	ATF_REQUIRE_EQ(virtio_fs_process_request(&session,
	    VIRTIO_FS_QUEUE_REQUEST, request, sizeof(request), response,
	    sizeof(response), backend_request, &backend, &written), 0);
	ATF_CHECK_EQ(written, DOC_FUSE_INIT_OUT_MIN_SIZE);
	ATF_CHECK(session.initialized);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, api_contract_validation);
	ATF_TP_ADD_TC(tp, publication_aliases_are_rejected);
	ATF_TP_ADD_TC(tp, asynchronous_init_and_stale_completion);
	ATF_TP_ADD_TC(tp, little_and_big_endian_init);
	ATF_TP_ADD_TC(tp, configuration_layout_and_utf8);
	ATF_TP_ADD_TC(tp, queue_class_and_no_reply);
	ATF_TP_ADD_TC(tp, malformed_requests_are_not_forwarded);
	ATF_TP_ADD_TC(tp, newer_major_requires_a_second_init);
	ATF_TP_ADD_TC(tp, response_validation_is_atomic);
	return (atf_no_error());
}
