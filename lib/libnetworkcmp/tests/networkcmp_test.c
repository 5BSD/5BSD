#include <sys/types.h>
#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <netdb.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "networkcmp.h"

union message_buffer {
	max_align_t align;
	struct {
		struct networkcmp_msg msg;
		uint8_t payload[NETWORKCMP_MAX_MESSAGE -
		    sizeof(struct networkcmp_msg)];
	} wire;
};

static struct networkcmp_msg *
make_message(union message_buffer *buffer, uint16_t opcode, bool reply,
    size_t payload)
{
	struct networkcmp_msg *msg;

	memset(buffer, 0, sizeof(*buffer));
	msg = &buffer->wire.msg;
	msg->magic = NETWORKCMP_MAGIC;
	msg->version = NETWORKCMP_ABI_VERSION;
	msg->opcode = opcode;
	msg->flags = reply ? NETWORKCMP_MSG_F_REPLY : 0;
	msg->length = sizeof(*msg) + payload;
	msg->request_id = 0xbadcafeU;
	return (msg);
}

static void
reject(struct networkcmp_msg *msg, size_t length)
{

	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_validate_message(msg, length));
	ATF_CHECK_EQ(EPROTO, errno);
}

ATF_TC(common_header);
ATF_TC_HEAD(common_header, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NetworkCmp validates every common-header invariant");
}
ATF_TC_BODY(common_header, tc)
{
	union message_buffer buffer;
	struct networkcmp_msg *msg;

	msg = make_message(&buffer, NETWORKCMP_OP_NOTIFY, false, 0);
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, msg->length));
#define	REJECT(field, value) do {					\
	msg = make_message(&buffer, NETWORKCMP_OP_NOTIFY, false, 0);	\
	msg->field = (value);						\
	reject(msg, msg->length);					\
} while (0)
	REJECT(magic, 0);
	REJECT(version, NETWORKCMP_ABI_VERSION + 1);
	REJECT(opcode, 0);
	REJECT(opcode, NETWORKCMP_OP_NOTIFY + 1);
	REJECT(flags, 0x80000000U);
	REJECT(reserved, 1);
	REJECT(status, -EPERM);
	REJECT(length, sizeof(*msg) - 1);
#undef REJECT
	msg = make_message(&buffer, NETWORKCMP_OP_HELLO, false,
	    sizeof(struct networkcmp_hello));
	msg->request_id = 0;
	reject(msg, msg->length);
	msg = make_message(&buffer, NETWORKCMP_OP_HELLO, true, 0);
	msg->status = -ELAST - 1;
	reject(msg, msg->length);
	reject(NULL, 0);
	msg = make_message(&buffer, NETWORKCMP_OP_NOTIFY, false, 0);
	reject(msg, sizeof(*msg) - 1);
	reject(msg, sizeof(*msg) + 1);
}

ATF_TC(component_binding);
ATF_TC_HEAD(component_binding, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NetworkCmp opens only manifest-injected local component names");
}
ATF_TC_BODY(component_binding, tc)
{

	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_open(""));
	ATF_CHECK_EQ(EINVAL, errno);

	/*
	 * This test process has not called service_init().  A provider-name
	 * lookup fallback would produce a different result or side effect.
	 */
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_open(NULL));
	ATF_CHECK_EQ(ENOTCONN, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_open("egress"));
	ATF_CHECK_EQ(ENOTCONN, errno);

	ATF_REQUIRE_EQ(0, setenv(NETWORKCMP_ENV, "", 1));
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_open(NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_REQUIRE_EQ(0, unsetenv(NETWORKCMP_ENV));
}

ATF_TC(request_shapes);
ATF_TC_HEAD(request_shapes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Every NetworkCmp request opcode has an exact payload shape");
}
ATF_TC_BODY(request_shapes, tc)
{
	union message_buffer buffer;
	struct networkcmp_msg *msg;
	struct networkcmp_setopt_request *setopt;
	size_t sizes[] = {
		[NETWORKCMP_OP_HELLO] = sizeof(struct networkcmp_hello),
		[NETWORKCMP_OP_SOCKET] =
		    sizeof(struct networkcmp_socket_request),
		[NETWORKCMP_OP_BIND] =
		    sizeof(struct networkcmp_endpoint_request),
		[NETWORKCMP_OP_CONNECT] =
		    sizeof(struct networkcmp_endpoint_request),
		[NETWORKCMP_OP_LISTEN] =
		    sizeof(struct networkcmp_listen_request),
		[NETWORKCMP_OP_ACCEPT] =
		    sizeof(struct networkcmp_close_request),
		[NETWORKCMP_OP_SHUTDOWN] =
		    sizeof(struct networkcmp_shutdown_request),
		[NETWORKCMP_OP_CLOSE] =
		    sizeof(struct networkcmp_close_request),
		[NETWORKCMP_OP_RESOLVE] =
		    sizeof(struct networkcmp_resolve_request) + 3 + 2,
		[NETWORKCMP_OP_ATTACH_RINGS] =
		    sizeof(struct networkcmp_ring_request),
		[NETWORKCMP_OP_NOTIFY] = 0,
	};
	unsigned opcode;

	for (opcode = NETWORKCMP_OP_HELLO; opcode <= NETWORKCMP_OP_NOTIFY;
	    opcode++) {
		if (opcode == NETWORKCMP_OP_SETOPT ||
		    opcode == NETWORKCMP_OP_RESOLVE)
			continue;
		msg = make_message(&buffer, opcode, false, sizes[opcode]);
		switch (opcode) {
		case NETWORKCMP_OP_HELLO:
			((struct networkcmp_hello *)(msg + 1))->max_version =
			    NETWORKCMP_ABI_VERSION;
			break;
		case NETWORKCMP_OP_SOCKET:
			((struct networkcmp_socket_request *)(msg + 1))->family =
			    NETWORKCMP_AF_INET4;
			((struct networkcmp_socket_request *)(msg + 1))->type =
			    NETWORKCMP_SOCK_STREAM;
			break;
		case NETWORKCMP_OP_BIND:
		case NETWORKCMP_OP_CONNECT:
			((struct networkcmp_endpoint_request *)(msg + 1))->
			    endpoint.family = NETWORKCMP_AF_INET4;
			break;
		case NETWORKCMP_OP_ATTACH_RINGS:
			((struct networkcmp_ring_request *)(msg + 1))->tx_mode = 1;
			((struct networkcmp_ring_request *)(msg + 1))->rx_mode = 1;
			break;
		default:
			break;
		}
		ATF_CHECK_EQ_MSG(0, networkcmp_validate_message(msg, msg->length),
		    "opcode %u", opcode);
		msg->length++;
		reject(msg, msg->length);
	}
	msg = make_message(&buffer, NETWORKCMP_OP_SETOPT, false,
	    sizeof(*setopt) + 8);
	setopt = (void *)(msg + 1);
	setopt->value_length = 8;
	ATF_CHECK_EQ(0, networkcmp_validate_message(msg, msg->length));
	setopt->value_length = UINT32_MAX;
	reject(msg, msg->length);

	msg = make_message(&buffer, NETWORKCMP_OP_RESOLVE, false,
	    sizeof(struct networkcmp_resolve_request) + 3 + 2);
	struct networkcmp_resolve_request *resolve = (void *)(msg + 1);
	resolve->host_length = 3;
	resolve->service_length = 2;
	resolve->family = NETWORKCMP_AF_UNSPEC;
	resolve->socket_type = NETWORKCMP_SOCK_STREAM;
	resolve->max_results = 4;
	memcpy(resolve + 1, "www53", 5);
	ATF_CHECK_EQ(0, networkcmp_validate_message(msg, msg->length));
	resolve->max_results = 0;
	reject(msg, msg->length);
	resolve->max_results = 4;
	resolve->flags = ~NETWORKCMP_RESOLVE_F_MASK;
	reject(msg, msg->length);
	resolve->flags = 0;
	resolve->host_length = NETWORKCMP_NAME_MAX + 1;
	reject(msg, msg->length);
	resolve->host_length = 3;
	((char *)(resolve + 1))[1] = '\0';
	reject(msg, msg->length);

	msg = make_message(&buffer, NETWORKCMP_OP_LISTEN, false,
	    sizeof(struct networkcmp_listen_request));
	((struct networkcmp_listen_request *)(msg + 1))->reserved = 1;
	reject(msg, msg->length);
	msg = make_message(&buffer, NETWORKCMP_OP_BIND, false,
	    sizeof(struct networkcmp_endpoint_request));
	((struct networkcmp_endpoint_request *)(msg + 1))->endpoint.family =
	    NETWORKCMP_AF_INET4;
	((struct networkcmp_endpoint_request *)(msg + 1))->endpoint.prefix = 1;
	reject(msg, msg->length);
}

ATF_TC(reply_shapes);
ATF_TC_HEAD(reply_shapes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NetworkCmp success and error replies have canonical shapes");
}
ATF_TC_BODY(reply_shapes, tc)
{
	union message_buffer buffer;
	struct networkcmp_msg *msg;

	msg = make_message(&buffer, NETWORKCMP_OP_HELLO, true,
	    sizeof(struct networkcmp_hello_reply));
	((struct networkcmp_hello_reply *)(msg + 1))->version =
	    NETWORKCMP_ABI_VERSION;
	ATF_CHECK_EQ(0, networkcmp_validate_message(msg, msg->length));
	msg = make_message(&buffer, NETWORKCMP_OP_SOCKET, true,
	    sizeof(struct networkcmp_handle_reply));
	ATF_CHECK_EQ(0, networkcmp_validate_message(msg, msg->length));
	msg = make_message(&buffer, NETWORKCMP_OP_CONNECT, true, 0);
	ATF_CHECK_EQ(0, networkcmp_validate_message(msg, msg->length));
	msg = make_message(&buffer, NETWORKCMP_OP_CONNECT, true, 0);
	msg->status = -ECONNREFUSED;
	ATF_CHECK_EQ(0, networkcmp_validate_message(msg, msg->length));
	msg->length++;
	reject(msg, msg->length);
	msg = make_message(&buffer, NETWORKCMP_OP_CONNECT, true, 0);
	msg->status = 1;
	reject(msg, msg->length);

	msg = make_message(&buffer, NETWORKCMP_OP_RESOLVE, true,
	    sizeof(struct networkcmp_resolve_reply) +
	    2 * sizeof(struct networkcmp_resolve_result) + 7);
	struct networkcmp_resolve_reply *resolve = (void *)(msg + 1);
	resolve->result_count = 2;
	resolve->canonname_length = 7;
	resolve->ttl_seconds = 60;
	struct networkcmp_resolve_result *results = (void *)(resolve + 1);
	results[0].endpoint.family = NETWORKCMP_AF_INET4;
	results[0].socket_type = NETWORKCMP_SOCK_STREAM;
	results[1].endpoint.family = NETWORKCMP_AF_INET6;
	results[1].socket_type = NETWORKCMP_SOCK_STREAM;
	memcpy(results + 2, "example", 7);
	ATF_CHECK_EQ(0, networkcmp_validate_message(msg, msg->length));
	resolve->result_count = NETWORKCMP_RESOLVE_MAX_RESULTS + 1;
	reject(msg, msg->length);
	resolve->result_count = 2;
	((char *)(results + 2))[1] = '\0';
	reject(msg, msg->length);
}

ATF_TC(semantic_invariants);
ATF_TC_HEAD(semantic_invariants, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NetworkCmp rejects noncanonical fields within valid frame sizes");
}
ATF_TC_BODY(semantic_invariants, tc)
{
	union message_buffer buffer;
	struct networkcmp_msg *msg;
	struct networkcmp_hello *hello;
	struct networkcmp_hello_reply *hello_reply;
	struct networkcmp_socket_request *socket;
	struct networkcmp_endpoint_request *endpoint;
	struct networkcmp_setopt_request *setopt;
	struct networkcmp_shutdown_request *shutdown;

	msg = make_message(&buffer, NETWORKCMP_OP_HELLO, false,
	    sizeof(*hello));
	hello = (void *)(msg + 1);
	hello->max_version = NETWORKCMP_ABI_VERSION;
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, msg->length));
	hello->reserved = 1;
	reject(msg, msg->length);
	hello->reserved = 0;
	hello->min_version = NETWORKCMP_ABI_VERSION + 1;
	hello->max_version = NETWORKCMP_ABI_VERSION + 1;
	reject(msg, msg->length);
	hello->min_version = 0;
	hello->max_version = NETWORKCMP_ABI_VERSION;
	hello->features = 0x80000000U;
	reject(msg, msg->length);
	hello->features = NETWORKCMP_FEATURE_SHM_RINGS;
	hello->reserved2 = 1;
	reject(msg, msg->length);
	hello->reserved2 = 0;
	hello->preferred_tx_ring_size = NETWORKCMP_RING_MIN_SIZE + 1;
	reject(msg, msg->length);
	hello->preferred_tx_ring_size = NETWORKCMP_RING_MIN_SIZE;
	hello->preferred_rx_ring_size = NETWORKCMP_RING_MAX_SIZE + 1U;
	reject(msg, msg->length);
	hello->preferred_rx_ring_size = NETWORKCMP_RING_MIN_SIZE;
	hello->preferred_max_datagram = NETWORKCMP_RING_MAX_SIZE;
	reject(msg, msg->length);

	msg = make_message(&buffer, NETWORKCMP_OP_SOCKET, false,
	    sizeof(*socket));
	socket = (void *)(msg + 1);
	socket->family = NETWORKCMP_AF_INET4;
	socket->type = NETWORKCMP_SOCK_STREAM;
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, msg->length));
	socket->flags = 1;
	reject(msg, msg->length);
	socket->flags = 0;
	socket->family = NETWORKCMP_AF_UNSPEC;
	reject(msg, msg->length);
	socket->family = NETWORKCMP_AF_INET4;
	socket->type = NETWORKCMP_SOCK_ANY;
	reject(msg, msg->length);

	msg = make_message(&buffer, NETWORKCMP_OP_CONNECT, false,
	    sizeof(*endpoint));
	endpoint = (void *)(msg + 1);
	endpoint->endpoint.family = NETWORKCMP_AF_INET4;
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, msg->length));
	endpoint->endpoint.scope_id = 1;
	reject(msg, msg->length);
	endpoint->endpoint.scope_id = 0;
	endpoint->endpoint.address[15] = 1;
	reject(msg, msg->length);
	endpoint->endpoint.address[15] = 0;
	endpoint->endpoint.family = NETWORKCMP_AF_UNSPEC;
	reject(msg, msg->length);

	msg = make_message(&buffer, NETWORKCMP_OP_SETOPT, false,
	    sizeof(*setopt));
	setopt = (void *)(msg + 1);
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, msg->length));
	setopt->reserved = 1;
	reject(msg, msg->length);

	msg = make_message(&buffer, NETWORKCMP_OP_SHUTDOWN, false,
	    sizeof(*shutdown));
	shutdown = (void *)(msg + 1);
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, msg->length));
	shutdown->how = 3;
	reject(msg, msg->length);
	shutdown->how = 0;
	shutdown->reserved = 1;
	reject(msg, msg->length);

	msg = make_message(&buffer, NETWORKCMP_OP_HELLO, true,
	    sizeof(*hello_reply));
	hello_reply = (void *)(msg + 1);
	hello_reply->version = NETWORKCMP_ABI_VERSION;
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, msg->length));
	hello_reply->version = 0;
	reject(msg, msg->length);
	hello_reply->version = NETWORKCMP_ABI_VERSION;
	hello_reply->features = 0x80000000U;
	reject(msg, msg->length);
	hello_reply->features = NETWORKCMP_FEATURE_SHM_RINGS;
	hello_reply->max_ring_size = NETWORKCMP_RING_DEFAULT_SIZE;
	hello_reply->tx_ring_size = NETWORKCMP_RING_DEFAULT_SIZE;
	hello_reply->rx_ring_size = NETWORKCMP_RING_DEFAULT_SIZE;
	hello_reply->max_datagram = NETWORKCMP_DATAGRAM_DEFAULT_MAX;
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, msg->length));
	hello_reply->tx_ring_size++;
	reject(msg, msg->length);
	hello_reply->tx_ring_size = NETWORKCMP_RING_DEFAULT_SIZE;
	hello_reply->max_datagram = NETWORKCMP_RING_DEFAULT_SIZE;
	reject(msg, msg->length);
	hello_reply->max_datagram = NETWORKCMP_DATAGRAM_DEFAULT_MAX;
	hello_reply->features = 0;
	reject(msg, msg->length);

	msg = make_message(&buffer, NETWORKCMP_OP_ATTACH_RINGS, false,
	    sizeof(struct networkcmp_ring_request));
	struct networkcmp_ring_request *rings = (void *)(msg + 1);
	rings->tx_mode = 1;
	rings->rx_mode = 1;
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, msg->length));
	rings->rx_mode = 2;
	reject(msg, msg->length);
	rings->tx_mode = 0;
	rings->rx_mode = 0;
	reject(msg, msg->length);
}

ATF_TC(descriptor_contract);
ATF_TC_HEAD(descriptor_contract, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Only ATTACH_RINGS accepts exactly eight role-separated fds");
}
ATF_TC_BODY(descriptor_contract, tc)
{
	union message_buffer buffer;
	struct networkcmp_msg *msg;

	msg = make_message(&buffer, NETWORKCMP_OP_SOCKET, false,
	    sizeof(struct networkcmp_socket_request));
	ATF_CHECK_EQ(0, networkcmp_validate_fds(msg, 0));
	ATF_CHECK_EQ(-1, networkcmp_validate_fds(msg, 1));
	ATF_CHECK_EQ(EPROTO, errno);
	msg = make_message(&buffer, NETWORKCMP_OP_ATTACH_RINGS, false,
	    sizeof(struct networkcmp_ring_request));
	ATF_CHECK_EQ(0, networkcmp_validate_fds(msg, NETWORKCMP_RING_FDS));
	ATF_CHECK_EQ(-1, networkcmp_validate_fds(msg,
	    NETWORKCMP_RING_FDS - 1));
	ATF_CHECK_EQ(EPROTO, errno);
	msg->flags = NETWORKCMP_MSG_F_REPLY;
	ATF_CHECK_EQ(0, networkcmp_validate_fds(msg, 0));
	ATF_CHECK_EQ(-1, networkcmp_validate_fds(NULL, 0));
	ATF_CHECK_EQ(EINVAL, errno);
}

ATF_TC(abi);
ATF_TC_HEAD(abi, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NetworkCmp wire constants and structures cannot drift silently");
}
ATF_TC_BODY(abi, tc)
{

	ATF_CHECK_EQ(0x4e434d50U, NETWORKCMP_MAGIC);
	ATF_CHECK_STREQ("org.5bsd.cmp.network", NETWORKCMP_INTERFACE);
	ATF_CHECK_STREQ("1.0.0", NETWORKCMP_INTERFACE_VERSION);
	ATF_CHECK_EQ(32, sizeof(struct networkcmp_msg));
	ATF_CHECK_EQ(32, sizeof(struct networkcmp_hello));
	ATF_CHECK_EQ(32, sizeof(struct networkcmp_hello_reply));
	ATF_CHECK_EQ(16, sizeof(struct networkcmp_handle));
	ATF_CHECK_EQ(40, sizeof(struct networkcmp_endpoint_request));
	ATF_CHECK_EQ(24, sizeof(struct networkcmp_resolve_request));
	ATF_CHECK_EQ(32, sizeof(struct networkcmp_resolve_result));
}

ATF_TC(typed_api_arguments);
ATF_TC_HEAD(typed_api_arguments, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Typed NetworkCmp calls reject unsafe arguments before transport");
}
ATF_TC_BODY(typed_api_arguments, tc)
{
	struct networkcmp_handle handle;
	struct networkcmp_preferences preferences;
	struct networkcmp_resolve_result result;
	struct addrinfo hints, *addresses;
	size_t nresults;
	int error;

	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_socket(-1, NETWORKCMP_AF_UNSPEC,
	    NETWORKCMP_SOCK_STREAM, 0, 0, &handle));
	ATF_CHECK_EQ(EINVAL, errno);

	memset(&preferences, 0, sizeof(preferences));
	preferences.tx_ring_size = NETWORKCMP_RING_MIN_SIZE + 1;
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_negotiate(-1, &preferences,
	    (struct networkcmp_hello_reply *)&result));
	ATF_CHECK_EQ(EINVAL, errno);
	memset(&preferences, 0, sizeof(preferences));
	preferences.reserved = 1;
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_client_open(NULL, &preferences, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	nresults = 1;
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_resolve(-1, NULL, NULL,
	    NETWORKCMP_AF_UNSPEC, NETWORKCMP_SOCK_ANY, 0, &result, &nresults,
	    NULL, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	nresults = NETWORKCMP_RESOLVE_MAX_RESULTS + 1;
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_resolve(-1, "example.test", "443",
	    NETWORKCMP_AF_UNSPEC, NETWORKCMP_SOCK_STREAM, 0, &result,
	    &nresults, NULL, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNIX;
	addresses = (void *)(uintptr_t)1;
	error = networkcmp_getaddrinfo(-1, "example.test", "443", &hints,
	    &addresses);
	ATF_CHECK_EQ(EAI_FAMILY, error);
	ATF_CHECK_EQ(NULL, addresses);
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = 0x40000000;
	error = networkcmp_getaddrinfo(-1, "example.test", "443", &hints,
	    &addresses);
	ATF_CHECK_EQ(EAI_BADFLAGS, error);
	ATF_CHECK_EQ(NULL, addresses);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, common_header);
	ATF_TP_ADD_TC(tp, component_binding);
	ATF_TP_ADD_TC(tp, request_shapes);
	ATF_TP_ADD_TC(tp, reply_shapes);
	ATF_TP_ADD_TC(tp, semantic_invariants);
	ATF_TP_ADD_TC(tp, descriptor_contract);
	ATF_TP_ADD_TC(tp, abi);
	ATF_TP_ADD_TC(tp, typed_api_arguments);
	return (atf_no_error());
}
