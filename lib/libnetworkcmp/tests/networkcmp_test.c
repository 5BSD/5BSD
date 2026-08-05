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
#include "networkcmp_server.h"

union message_buffer {
	max_align_t align;
	struct {
		struct networkcmp_msg msg;
		uint8_t payload[NETWORKCMP_MAX_MESSAGE -
		    sizeof(struct networkcmp_msg)];
	} wire;
};

static size_t wire_length;
static enum networkcmp_message_role wire_role;

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
	wire_length = sizeof(*msg) + payload;
	wire_role = reply ? NETWORKCMP_MESSAGE_REPLY :
	    NETWORKCMP_MESSAGE_REQUEST;
	return (msg);
}

static void
reject(struct networkcmp_msg *msg, size_t length)
{

	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_validate_message(msg, length, wire_role));
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

	msg = make_message(&buffer, NETWORKCMP_OP_CLOSE, false,
	    sizeof(struct networkcmp_close_request));
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, wire_length,
	    wire_role));
#define	REJECT(field, value) do {					\
	msg = make_message(&buffer, NETWORKCMP_OP_CLOSE, false,		\
	    sizeof(struct networkcmp_close_request));			\
	msg->field = (value);						\
	reject(msg, wire_length);					\
} while (0)
	REJECT(magic, 0);
	REJECT(version, NETWORKCMP_ABI_VERSION + 1);
	REJECT(opcode, 0);
	REJECT(opcode, NETWORKCMP_OP_CONNECT_STATUS + 1);
	REJECT(flags, 0x80000000U);
	REJECT(status, -EPERM);
#undef REJECT
	msg = make_message(&buffer, NETWORKCMP_OP_HELLO, true, 0);
	msg->status = -ELAST - 1;
	reject(msg, wire_length);
	reject(NULL, 0);
	msg = make_message(&buffer, NETWORKCMP_OP_CLOSE, false,
	    sizeof(struct networkcmp_close_request));
	reject(msg, sizeof(*msg) - 1);
	reject(msg, sizeof(*msg) + 1);
}

ATF_TC(component_binding);
ATF_TC_HEAD(component_binding, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NetworkCmp opens only its injected local authority descriptor");
}
ATF_TC_BODY(component_binding, tc)
{
	struct networkcmp_client *client;

	errno = 0;
	ATF_REQUIRE_EQ(0, setenv("NETWORKCMP", "", 1));
	ATF_CHECK_EQ(-1, networkcmp_client_open(&client));
	ATF_CHECK_EQ(EBADF, errno);
	ATF_REQUIRE_EQ(0, unsetenv("NETWORKCMP"));

	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_client_open(&client));
	ATF_CHECK_EQ(EBADF, errno);
	errno = 0;
	ATF_REQUIRE_EQ(0, setenv("NETWORKCMP", "egress", 1));
	ATF_CHECK_EQ(-1, networkcmp_client_open(&client));
	ATF_CHECK_EQ(EBADF, errno);
	ATF_REQUIRE_EQ(0, unsetenv("NETWORKCMP"));

	ATF_REQUIRE_EQ(0, setenv("NETWORKCMP", "", 1));
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_client_open(&client));
	ATF_CHECK_EQ(EBADF, errno);
	ATF_REQUIRE_EQ(0, unsetenv("NETWORKCMP"));
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
		[NETWORKCMP_OP_SEND] =
		    sizeof(struct networkcmp_inline_request) + 3,
		[NETWORKCMP_OP_RECV] =
		    sizeof(struct networkcmp_inline_request),
		[NETWORKCMP_OP_CONNECT_STATUS] =
		    sizeof(struct networkcmp_close_request),
	};
	unsigned opcode;

	for (opcode = NETWORKCMP_OP_HELLO;
	    opcode <= NETWORKCMP_OP_CONNECT_STATUS;
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
		case NETWORKCMP_OP_SEND:
		case NETWORKCMP_OP_RECV:
			((struct networkcmp_inline_request *)(msg + 1))->length = 3;
			break;
		default:
			break;
		}
		ATF_CHECK_EQ_MSG(0, networkcmp_validate_message(msg, wire_length, wire_role),
		    "opcode %u", opcode);
		wire_length++;
		reject(msg, wire_length);
	}
	msg = make_message(&buffer, NETWORKCMP_OP_SETOPT, false,
	    sizeof(*setopt) + 8);
	setopt = (void *)(msg + 1);
	setopt->value_length = 8;
	ATF_CHECK_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	setopt->value_length = UINT32_MAX;
	reject(msg, wire_length);

	msg = make_message(&buffer, NETWORKCMP_OP_RESOLVE, false,
	    sizeof(struct networkcmp_resolve_request) + 3 + 2);
	struct networkcmp_resolve_request *resolve = (void *)(msg + 1);
	resolve->host_length = 3;
	resolve->service_length = 2;
	resolve->family = NETWORKCMP_AF_UNSPEC;
	resolve->socket_type = NETWORKCMP_SOCK_STREAM;
	resolve->max_results = 4;
	memcpy(resolve + 1, "www53", 5);
	ATF_CHECK_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	resolve->max_results = 0;
	reject(msg, wire_length);
	resolve->max_results = 4;
	resolve->flags = ~NETWORKCMP_RESOLVE_F_MASK;
	reject(msg, wire_length);
	resolve->flags = 0;
	resolve->host_length = NETWORKCMP_NAME_MAX + 1;
	reject(msg, wire_length);
	resolve->host_length = 3;
	((char *)(resolve + 1))[1] = '\0';
	reject(msg, wire_length);

	msg = make_message(&buffer, NETWORKCMP_OP_LISTEN, false,
	    sizeof(struct networkcmp_listen_request));
	((struct networkcmp_listen_request *)(msg + 1))->reserved = 1;
	reject(msg, wire_length);
	msg = make_message(&buffer, NETWORKCMP_OP_BIND, false,
	    sizeof(struct networkcmp_endpoint_request));
	((struct networkcmp_endpoint_request *)(msg + 1))->endpoint.family =
	    NETWORKCMP_AF_INET4;
	((struct networkcmp_endpoint_request *)(msg + 1))->endpoint.prefix = 1;
	reject(msg, wire_length);
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
	*(struct networkcmp_hello_reply *)(msg + 1) =
	    (struct networkcmp_hello_reply){
		.version = NETWORKCMP_ABI_VERSION,
		.max_sockets = 1,
		.max_inline = NETWORKCMP_INLINE_MAX,
		.max_datagram = NETWORKCMP_INLINE_MAX,
		.max_resolve_results = 1,
		.io_timeout_max = NETWORKCMP_IO_TIMEOUT_MAX,
	    };
	ATF_CHECK_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	msg = make_message(&buffer, NETWORKCMP_OP_SOCKET, true,
	    sizeof(struct networkcmp_handle_reply));
	ATF_CHECK_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	msg = make_message(&buffer, NETWORKCMP_OP_CONNECT, true, 0);
	ATF_CHECK_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	msg = make_message(&buffer, NETWORKCMP_OP_CONNECT, true, 0);
	msg->status = -ECONNREFUSED;
	ATF_CHECK_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	wire_length++;
	reject(msg, wire_length);
	msg = make_message(&buffer, NETWORKCMP_OP_CONNECT, true, 0);
	msg->status = 1;
	reject(msg, wire_length);

	msg = make_message(&buffer, NETWORKCMP_OP_SEND, true,
	    sizeof(struct networkcmp_inline_reply));
	((struct networkcmp_inline_reply *)(msg + 1))->length = 3;
	ATF_CHECK_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	msg = make_message(&buffer, NETWORKCMP_OP_RECV, true,
	    sizeof(struct networkcmp_inline_reply) + 3);
	((struct networkcmp_inline_reply *)(msg + 1))->length = 3;
	ATF_CHECK_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	((struct networkcmp_inline_reply *)(msg + 1))->flags =
	    ~NETWORKCMP_IO_F_MASK;
	reject(msg, wire_length);

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
	ATF_CHECK_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	resolve->result_count = NETWORKCMP_RESOLVE_MAX_RESULTS + 1;
	reject(msg, wire_length);
	resolve->result_count = 2;
	((char *)(results + 2))[1] = '\0';
	reject(msg, wire_length);
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
	struct networkcmp_inline_request *io;

	msg = make_message(&buffer, NETWORKCMP_OP_HELLO, false,
	    sizeof(*hello));
	hello = (void *)(msg + 1);
	hello->max_version = NETWORKCMP_ABI_VERSION;
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	hello->reserved = 1;
	reject(msg, wire_length);
	hello->reserved = 0;
	hello->min_version = NETWORKCMP_ABI_VERSION + 1;
	hello->max_version = NETWORKCMP_ABI_VERSION + 1;
	reject(msg, wire_length);
	hello->min_version = 0;
	hello->max_version = NETWORKCMP_ABI_VERSION;
	hello->features = 0x80000000U;
	reject(msg, wire_length);

	msg = make_message(&buffer, NETWORKCMP_OP_SOCKET, false,
	    sizeof(*socket));
	socket = (void *)(msg + 1);
	socket->family = NETWORKCMP_AF_INET4;
	socket->type = NETWORKCMP_SOCK_STREAM;
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	socket->flags = 1;
	reject(msg, wire_length);
	socket->flags = 0;
	socket->family = NETWORKCMP_AF_UNSPEC;
	reject(msg, wire_length);
	socket->family = NETWORKCMP_AF_INET4;
	socket->type = NETWORKCMP_SOCK_ANY;
	reject(msg, wire_length);

	msg = make_message(&buffer, NETWORKCMP_OP_CONNECT, false,
	    sizeof(*endpoint));
	endpoint = (void *)(msg + 1);
	endpoint->endpoint.family = NETWORKCMP_AF_INET4;
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	endpoint->endpoint.scope_id = 1;
	reject(msg, wire_length);
	endpoint->endpoint.scope_id = 0;
	endpoint->endpoint.address[15] = 1;
	reject(msg, wire_length);
	endpoint->endpoint.address[15] = 0;
	endpoint->endpoint.family = NETWORKCMP_AF_UNSPEC;
	reject(msg, wire_length);

	msg = make_message(&buffer, NETWORKCMP_OP_SETOPT, false,
	    sizeof(*setopt));
	setopt = (void *)(msg + 1);
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	setopt->reserved = 1;
	reject(msg, wire_length);

	msg = make_message(&buffer, NETWORKCMP_OP_SHUTDOWN, false,
	    sizeof(*shutdown));
	shutdown = (void *)(msg + 1);
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	shutdown->how = 3;
	reject(msg, wire_length);
	shutdown->how = 0;
	shutdown->reserved = 1;
	reject(msg, wire_length);

	msg = make_message(&buffer, NETWORKCMP_OP_HELLO, true,
	    sizeof(*hello_reply));
	hello_reply = (void *)(msg + 1);
	hello_reply->version = NETWORKCMP_ABI_VERSION;
	hello_reply->max_inline = NETWORKCMP_INLINE_MAX;
	hello_reply->max_datagram = NETWORKCMP_INLINE_MAX;
	hello_reply->max_resolve_results = NETWORKCMP_RESOLVE_MAX_RESULTS;
	hello_reply->io_timeout_max = NETWORKCMP_IO_TIMEOUT_MAX;
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	hello_reply->version = 0;
	reject(msg, wire_length);
	hello_reply->version = NETWORKCMP_ABI_VERSION;
	hello_reply->features = 0x80000000U;
	reject(msg, wire_length);
	hello_reply->features = 0;
	hello_reply->max_inline = 0;
	reject(msg, wire_length);
	hello_reply->max_inline = NETWORKCMP_INLINE_MAX;
	hello_reply->max_datagram = NETWORKCMP_INLINE_MAX + 1;
	reject(msg, wire_length);
	hello_reply->max_datagram = NETWORKCMP_INLINE_MAX;
	hello_reply->max_resolve_results = 0;
	reject(msg, wire_length);
	hello_reply->max_resolve_results = NETWORKCMP_RESOLVE_MAX_RESULTS;
	hello_reply->io_timeout_max = NETWORKCMP_IO_TIMEOUT_MAX + 1;
	reject(msg, wire_length);

	msg = make_message(&buffer, NETWORKCMP_OP_RECV, false, sizeof(*io));
	io = (void *)(msg + 1);
	io->length = 1;
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	io->length = 0;
	reject(msg, wire_length);
	io->length = 1;
	io->timeout_ms = 1;
	reject(msg, wire_length);
	io->timeout_ms = NETWORKCMP_IO_TIMEOUT_MAX + 1;
	reject(msg, wire_length);
	io->timeout_ms = 0;
	io->flags = 1;
	reject(msg, wire_length);

	msg = make_message(&buffer, NETWORKCMP_OP_SEND, false,
	    sizeof(*io) + 1);
	io = (void *)(msg + 1);
	io->length = 1;
	ATF_REQUIRE_EQ(0, networkcmp_validate_message(msg, wire_length, wire_role));
	io->timeout_ms = 1;
	reject(msg, wire_length);
}

ATF_TC(descriptor_contract);
ATF_TC_HEAD(descriptor_contract, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The baseline NetworkCmp protocol accepts no descriptors");
}
ATF_TC_BODY(descriptor_contract, tc)
{
	union message_buffer buffer;
	struct networkcmp_msg *msg;

	msg = make_message(&buffer, NETWORKCMP_OP_SOCKET, false,
	    sizeof(struct networkcmp_socket_request));
	ATF_CHECK_EQ(0, networkcmp_validate_fds(msg, 0, wire_role));
	ATF_CHECK_EQ(-1, networkcmp_validate_fds(msg, 1, wire_role));
	ATF_CHECK_EQ(EPROTO, errno);
	wire_role = NETWORKCMP_MESSAGE_REPLY;
	ATF_CHECK_EQ(0, networkcmp_validate_fds(msg, 0, wire_role));
	ATF_CHECK_EQ(-1, networkcmp_validate_fds(NULL, 0, wire_role));
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
	ATF_CHECK_STREQ("org.5bsd.network", NETWORKCMP_INTERFACE);
	ATF_CHECK_STREQ("1.0.0", NETWORKCMP_INTERFACE_VERSION);
	ATF_CHECK_EQ(16, sizeof(struct networkcmp_msg));
	ATF_CHECK_EQ(16, sizeof(struct networkcmp_hello));
	ATF_CHECK_EQ(36, sizeof(struct networkcmp_hello_reply));
	ATF_CHECK_EQ(16, sizeof(struct networkcmp_handle));
	ATF_CHECK_EQ(40, sizeof(struct networkcmp_endpoint_request));
	ATF_CHECK_EQ(24, sizeof(struct networkcmp_resolve_request));
	ATF_CHECK_EQ(32, sizeof(struct networkcmp_resolve_result));
	ATF_CHECK_EQ(32, sizeof(struct networkcmp_inline_request));
	ATF_CHECK_EQ(16, sizeof(struct networkcmp_inline_reply));
	ATF_CHECK_EQ(11, NETWORKCMP_OP_SEND);
	ATF_CHECK_EQ(12, NETWORKCMP_OP_RECV);
	ATF_CHECK_EQ(13, NETWORKCMP_OP_CONNECT_STATUS);
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
	struct networkcmp_resolve_result result;
	struct addrinfo hints, *addresses;
	size_t nresults;
	char byte;
	int error;

	byte = 0;
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_socket(NULL, NETWORKCMP_AF_UNSPEC,
	    NETWORKCMP_SOCK_STREAM, 0, 0, &handle));
	ATF_CHECK_EQ(EINVAL, errno);

	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_send_inline(NULL, handle, NULL, 1));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_send_inline(NULL, handle, &byte, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_send_inline(NULL, handle, &byte,
	    NETWORKCMP_INLINE_MAX + 1));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_recv_inline(NULL, handle, NULL, 1, 0,
	    NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_recv_inline(NULL, handle, &byte, 0, 0,
	    NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_recv_inline(NULL, handle, &byte, 1,
	    NETWORKCMP_IO_TIMEOUT_MAX + 1, NULL));
	ATF_CHECK_EQ(EINVAL, errno);

	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_client_open(NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	nresults = 1;
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_resolve(NULL, NULL, NULL,
	    NETWORKCMP_AF_UNSPEC, NETWORKCMP_SOCK_ANY, 0, &result, &nresults,
	    NULL, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	nresults = NETWORKCMP_RESOLVE_MAX_RESULTS + 1;
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_resolve(NULL, "example.test", "443",
	    NETWORKCMP_AF_UNSPEC, NETWORKCMP_SOCK_STREAM, 0, &result,
	    &nresults, NULL, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNIX;
	addresses = (void *)(uintptr_t)1;
	error = networkcmp_getaddrinfo(NULL, "example.test", "443", &hints,
	    &addresses);
	ATF_CHECK_EQ(EAI_FAMILY, error);
	ATF_CHECK_EQ(NULL, addresses);
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = 0x40000000;
	error = networkcmp_getaddrinfo(NULL, "example.test", "443", &hints,
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
