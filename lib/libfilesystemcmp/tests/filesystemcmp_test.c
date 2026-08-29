#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "filesystemcmp.h"
#include "filesystemcmp_server.h"

union message_buffer {
	max_align_t align;
	struct {
		struct filesystemcmp_msg msg;
		uint8_t payload[FILESYSTEMCMP_MAX_MESSAGE -
		    sizeof(struct filesystemcmp_msg)];
	} wire;
};

static size_t wire_length;
static enum filesystemcmp_message_role wire_role;

static struct filesystemcmp_msg *
make_message(union message_buffer *buffer, uint16_t opcode, bool reply,
    size_t payload)
{
	struct filesystemcmp_msg *msg;

	memset(buffer, 0, sizeof(*buffer));
	msg = &buffer->wire.msg;
	msg->magic = FILESYSTEMCMP_MAGIC;
	msg->version = FILESYSTEMCMP_ABI_VERSION;
	msg->opcode = opcode;
	wire_length = sizeof(*msg) + payload;
	wire_role = reply ? FILESYSTEMCMP_MESSAGE_REPLY :
	    FILESYSTEMCMP_MESSAGE_REQUEST;
	return (msg);
}

static void
check_rejected(struct filesystemcmp_msg *msg, size_t length)
{

	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_validate_message(msg, length,
	    wire_role));
	ATF_CHECK_EQ(EPROTO, errno);
}

ATF_TC(common_header);
ATF_TC_HEAD(common_header, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FileSystemCmp validates every common-header invariant");
}
ATF_TC_BODY(common_header, tc)
{
	union message_buffer buffer;
	struct filesystemcmp_msg *msg;

	msg = make_message(&buffer, FILESYSTEMCMP_OP_OPEN_ROOT, false, 0);
	ATF_REQUIRE_EQ(0, filesystemcmp_validate_message(msg, wire_length,
	    wire_role));
#define	REJECT(field, value) do {					\
	msg = make_message(&buffer, FILESYSTEMCMP_OP_OPEN_ROOT, false, 0);\
	msg->field = (value);						\
	check_rejected(msg, wire_length);				\
} while (0)
	REJECT(magic, 0);
	REJECT(version, FILESYSTEMCMP_ABI_VERSION + 1);
	REJECT(opcode, 0);
	REJECT(opcode, FILESYSTEMCMP_OP_DUP + 1);
	REJECT(flags, 0x80000000U);
	REJECT(status, -EPERM);
#undef REJECT
	msg = make_message(&buffer, FILESYSTEMCMP_OP_OPEN_ROOT, true, 0);
	msg->status = -ELAST - 1;
	check_rejected(msg, wire_length);
	check_rejected(NULL, 0);
	msg = make_message(&buffer, FILESYSTEMCMP_OP_OPEN_ROOT, false, 0);
	check_rejected(msg, sizeof(*msg) - 1);
	check_rejected(msg, wire_length + 1);
}

ATF_TC(component_binding);
ATF_TC_HEAD(component_binding, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FileSystemCmp opens only its injected local authority descriptor");
}
ATF_TC_BODY(component_binding, tc)
{
	struct filesystemcmp_client *client;

	errno = 0;
	ATF_REQUIRE_EQ(0, setenv("FILESYSTEMCMP", "", 1));
	ATF_CHECK_EQ(-1, filesystemcmp_open(&client));
	ATF_CHECK_EQ(EBADF, errno);
	ATF_REQUIRE_EQ(0, unsetenv("FILESYSTEMCMP"));

	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_open(&client));
	ATF_CHECK_EQ(EBADF, errno);
	errno = 0;
	ATF_REQUIRE_EQ(0, setenv("FILESYSTEMCMP", "scratch", 1));
	ATF_CHECK_EQ(-1, filesystemcmp_open(&client));
	ATF_CHECK_EQ(EBADF, errno);
	ATF_REQUIRE_EQ(0, unsetenv("FILESYSTEMCMP"));

	ATF_REQUIRE_EQ(0, setenv("FILESYSTEMCMP", "", 1));
	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_open(&client));
	ATF_CHECK_EQ(EBADF, errno);
	ATF_REQUIRE_EQ(0, unsetenv("FILESYSTEMCMP"));
}

ATF_TC(request_shapes);
ATF_TC_HEAD(request_shapes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Every request opcode has an exact, overflow-safe payload shape");
}
ATF_TC_BODY(request_shapes, tc)
{
	union message_buffer buffer;
	struct filesystemcmp_msg *msg;
	struct filesystemcmp_lookup_request *lookup;
	struct filesystemcmp_create_request *create;
	struct filesystemcmp_io_request *io;
	struct filesystemcmp_rename_request *rename;
	size_t fixed[] = {
		[FILESYSTEMCMP_OP_HELLO] =
		    sizeof(struct filesystemcmp_hello),
		[FILESYSTEMCMP_OP_OPEN_ROOT] = 0,
		[FILESYSTEMCMP_OP_OPEN] =
		    sizeof(struct filesystemcmp_open_request),
		[FILESYSTEMCMP_OP_READ] =
		    sizeof(struct filesystemcmp_io_request),
		[FILESYSTEMCMP_OP_STAT] =
		    sizeof(struct filesystemcmp_close_request),
		[FILESYSTEMCMP_OP_CLOSE] =
		    sizeof(struct filesystemcmp_close_request),
		[FILESYSTEMCMP_OP_OPEN_NAMESPACE] =
		    sizeof(struct filesystemcmp_namespace_request),
		[FILESYSTEMCMP_OP_SYNC] =
		    sizeof(struct filesystemcmp_close_request),
		[FILESYSTEMCMP_OP_DUP] =
		    sizeof(struct filesystemcmp_close_request),
	};
	unsigned opcode;

	for (opcode = FILESYSTEMCMP_OP_HELLO;
	    opcode <= FILESYSTEMCMP_OP_DUP; opcode++) {
		if (opcode == FILESYSTEMCMP_OP_LOOKUP ||
		    opcode == FILESYSTEMCMP_OP_CREATE ||
		    opcode == FILESYSTEMCMP_OP_WRITE ||
		    opcode == FILESYSTEMCMP_OP_UNLINK ||
		    opcode == FILESYSTEMCMP_OP_RENAME)
			continue;
		msg = make_message(&buffer, opcode, false, fixed[opcode]);
		switch (opcode) {
		case FILESYSTEMCMP_OP_HELLO:
			((struct filesystemcmp_hello *)(msg + 1))->max_version =
			    FILESYSTEMCMP_ABI_VERSION;
			break;
		case FILESYSTEMCMP_OP_OPEN_NAMESPACE:
			((struct filesystemcmp_namespace_request *)(msg + 1))->
			    namespace = FILESYSTEMCMP_NAMESPACE_SCRATCH;
			break;
		default:
			break;
		}
		ATF_CHECK_EQ_MSG(0,
		    filesystemcmp_validate_message(msg, wire_length, wire_role),
		    "opcode %u", opcode);
		wire_length++;
		check_rejected(msg, wire_length);
	}

	msg = make_message(&buffer, FILESYSTEMCMP_OP_LOOKUP, false,
	    sizeof(*lookup) + 4);
	lookup = (void *)(msg + 1);
	lookup->name_length = 4;
	memcpy(lookup + 1, "name", 4);
	ATF_CHECK_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	lookup->name_length = UINT32_MAX;
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_CREATE, false,
	    sizeof(*create) + 5);
	create = (void *)(msg + 1);
	create->name_length = 5;
	memcpy(create + 1, "entry", 5);
	ATF_CHECK_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	create->name_length = 6;
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_WRITE, false,
	    sizeof(*io) + 7);
	io = (void *)(msg + 1);
	io->length = 7;
	ATF_CHECK_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	io->length = UINT32_MAX;
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_UNLINK, false,
	    sizeof(struct filesystemcmp_unlink_request) + 3);
	((struct filesystemcmp_unlink_request *)(msg + 1))->name_length = 3;
	memcpy((struct filesystemcmp_unlink_request *)(msg + 1) + 1, "old", 3);
	ATF_CHECK_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));

	msg = make_message(&buffer, FILESYSTEMCMP_OP_RENAME, false,
	    sizeof(*rename) + 3 + 6);
	rename = (void *)(msg + 1);
	rename->old_name_length = 3;
	rename->new_name_length = 6;
	memcpy(rename + 1, "oldnewone", 9);
	ATF_CHECK_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	rename->new_name_length = UINT32_MAX;
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_LOOKUP, false,
	    sizeof(*lookup) + 2);
	lookup = (void *)(msg + 1);
	lookup->name_length = 2;
	memcpy(lookup + 1, "..", 2);
	check_rejected(msg, wire_length);
	msg = make_message(&buffer, FILESYSTEMCMP_OP_OPEN, false,
	    sizeof(struct filesystemcmp_open_request));
	((struct filesystemcmp_open_request *)(msg + 1))->reserved = 1;
	check_rejected(msg, wire_length);
}

ATF_TC(reply_shapes);
ATF_TC_HEAD(reply_shapes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Success and error replies have canonical payloads and status");
}
ATF_TC_BODY(reply_shapes, tc)
{
	union message_buffer buffer;
	struct filesystemcmp_msg *msg;
	struct filesystemcmp_io_reply *io;

	msg = make_message(&buffer, FILESYSTEMCMP_OP_HELLO, true,
	    sizeof(struct filesystemcmp_hello_reply));
	((struct filesystemcmp_hello_reply *)(msg + 1))->version =
	    FILESYSTEMCMP_ABI_VERSION;
	ATF_CHECK_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	msg->status = 1;
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_LOOKUP, true,
	    sizeof(struct filesystemcmp_handle_reply));
	((struct filesystemcmp_handle_reply *)(msg + 1))->type =
	    FILESYSTEMCMP_TYPE_REGULAR;
	ATF_CHECK_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));

	msg = make_message(&buffer, FILESYSTEMCMP_OP_OPEN_NAMESPACE, true,
	    sizeof(struct filesystemcmp_handle_reply));
	((struct filesystemcmp_handle_reply *)(msg + 1))->type =
	    FILESYSTEMCMP_TYPE_DIRECTORY;
	ATF_CHECK_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));

	msg = make_message(&buffer, FILESYSTEMCMP_OP_READ, true,
	    sizeof(*io) + 11);
	io = (void *)(msg + 1);
	io->length = 11;
	ATF_CHECK_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	io->length = 12;
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_STAT, true,
	    sizeof(struct filesystemcmp_stat_reply));
	((struct filesystemcmp_stat_reply *)(msg + 1))->type =
	    FILESYSTEMCMP_TYPE_REGULAR;
	ATF_CHECK_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));

	msg = make_message(&buffer, FILESYSTEMCMP_OP_CREATE, true, 0);
	msg->status = -ENOSPC;
	ATF_CHECK_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	wire_length++;
	check_rejected(msg, wire_length);
}

ATF_TC(semantic_invariants);
ATF_TC_HEAD(semantic_invariants, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "FileSystemCmp rejects unsafe names, flags and reserved fields");
}
ATF_TC_BODY(semantic_invariants, tc)
{
	union message_buffer buffer;
	struct filesystemcmp_msg *msg;
	struct filesystemcmp_hello *hello;
	struct filesystemcmp_hello_reply *hello_reply;
	struct filesystemcmp_lookup_request *lookup;
	struct filesystemcmp_open_request *open;
	struct filesystemcmp_create_request *create;
	struct filesystemcmp_io_request *io;
	struct filesystemcmp_unlink_request *unlink;
	struct filesystemcmp_rename_request *rename;
	struct filesystemcmp_handle_reply *handle;
	struct filesystemcmp_io_reply *io_reply;
	struct filesystemcmp_stat_reply *stat_reply;
	struct filesystemcmp_namespace_request *namespace_request;

	msg = make_message(&buffer, FILESYSTEMCMP_OP_HELLO, false,
	    sizeof(*hello));
	hello = (void *)(msg + 1);
	hello->max_version = FILESYSTEMCMP_ABI_VERSION;
	ATF_REQUIRE_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	hello->reserved = 1;
	check_rejected(msg, wire_length);
	hello->reserved = 0;
	hello->features = 0x80000000U;
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_LOOKUP, false,
	    sizeof(*lookup) + 4);
	lookup = (void *)(msg + 1);
	lookup->name_length = 4;
	memcpy(lookup + 1, "name", 4);
	ATF_REQUIRE_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	lookup->flags = 1;
	check_rejected(msg, wire_length);
	lookup->flags = 0;
	memcpy(lookup + 1, "a/bb", 4);
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_OPEN, false,
	    sizeof(*open));
	open = (void *)(msg + 1);
	ATF_REQUIRE_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	open->flags = ~FILESYSTEMCMP_OPEN_MASK;
	check_rejected(msg, wire_length);
	open->flags = 0;
	open->reserved = 1;
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_CREATE, false,
	    sizeof(*create) + 3);
	create = (void *)(msg + 1);
	create->name_length = 3;
	memcpy(create + 1, "new", 3);
	ATF_REQUIRE_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	create->flags = ~FILESYSTEMCMP_CREATE_MASK;
	check_rejected(msg, wire_length);
	create->flags = 0;
	create->reserved = 1;
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_READ, false, sizeof(*io));
	io = (void *)(msg + 1);
	ATF_REQUIRE_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	io->flags = 1;
	check_rejected(msg, wire_length);
	io->flags = 0;
	io->length = FILESYSTEMCMP_INLINE_MAX + 1;
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_UNLINK, false,
	    sizeof(*unlink) + 3);
	unlink = (void *)(msg + 1);
	unlink->name_length = 3;
	memcpy(unlink + 1, "old", 3);
	ATF_REQUIRE_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	unlink->flags = 1;
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_RENAME, false,
	    sizeof(*rename) + 3 + 3);
	rename = (void *)(msg + 1);
	rename->old_name_length = 3;
	rename->new_name_length = 3;
	memcpy(rename + 1, "oldnew", 6);
	ATF_REQUIRE_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	rename->flags = 1;
	check_rejected(msg, wire_length);
	rename->flags = 0;
	rename->reserved = 1;
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_HELLO, true,
	    sizeof(*hello_reply));
	hello_reply = (void *)(msg + 1);
	hello_reply->version = FILESYSTEMCMP_ABI_VERSION;
	ATF_REQUIRE_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	hello_reply->features = 0x80000000U;
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_OPEN_NAMESPACE, false,
	    sizeof(*namespace_request));
	namespace_request = (void *)(msg + 1);
	namespace_request->namespace = FILESYSTEMCMP_NAMESPACE_PERSISTENT;
	ATF_REQUIRE_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	namespace_request->namespace = 0;
	check_rejected(msg, wire_length);
	namespace_request->namespace = FILESYSTEMCMP_NAMESPACE_BUNDLE;
	namespace_request->reserved = 1;
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_LOOKUP, true,
	    sizeof(*handle));
	handle = (void *)(msg + 1);
	handle->type = FILESYSTEMCMP_TYPE_REGULAR;
	ATF_REQUIRE_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	handle->reserved = 1;
	check_rejected(msg, wire_length);
	handle->reserved = 0;
	handle->type = 0;
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_WRITE, true,
	    sizeof(*io_reply));
	io_reply = (void *)(msg + 1);
	ATF_REQUIRE_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	io_reply->reserved = 1;
	check_rejected(msg, wire_length);

	msg = make_message(&buffer, FILESYSTEMCMP_OP_STAT, true,
	    sizeof(*stat_reply));
	stat_reply = (void *)(msg + 1);
	stat_reply->type = FILESYSTEMCMP_TYPE_DIRECTORY;
	ATF_REQUIRE_EQ(0, filesystemcmp_validate_message(msg, wire_length, wire_role));
	stat_reply->type = 0;
	check_rejected(msg, wire_length);
}

ATF_TC(descriptor_contract);
ATF_TC_HEAD(descriptor_contract, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The baseline filesystem protocol accepts no descriptors");
}
ATF_TC_BODY(descriptor_contract, tc)
{
	union message_buffer buffer;
	struct filesystemcmp_msg *msg;

	msg = make_message(&buffer, FILESYSTEMCMP_OP_OPEN_ROOT, false, 0);
	ATF_CHECK_EQ(0, filesystemcmp_validate_fds(msg, 0, wire_role));
	ATF_CHECK_EQ(-1, filesystemcmp_validate_fds(msg, 1, wire_role));
	ATF_CHECK_EQ(EPROTO, errno);

	wire_role = FILESYSTEMCMP_MESSAGE_REPLY;
	ATF_CHECK_EQ(0, filesystemcmp_validate_fds(msg, 0, wire_role));
	ATF_CHECK_EQ(-1, filesystemcmp_validate_fds(NULL, 0, wire_role));
	ATF_CHECK_EQ(EINVAL, errno);
}

ATF_TC(abi);
ATF_TC_HEAD(abi, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Wire constants and structure sizes cannot drift silently");
}
ATF_TC_BODY(abi, tc)
{

	ATF_CHECK_EQ(0x46434d50U, FILESYSTEMCMP_MAGIC);
	ATF_CHECK_STREQ("system.Filesystem",
	    FILESYSTEMCMP_INTERFACE);
	ATF_CHECK_STREQ("1.0.0", FILESYSTEMCMP_INTERFACE_VERSION);
	ATF_CHECK_EQ(16, sizeof(struct filesystemcmp_msg));
	ATF_CHECK_EQ(16, sizeof(struct filesystemcmp_handle));
	ATF_CHECK_EQ(32, sizeof(struct filesystemcmp_io_request));
	ATF_CHECK_EQ(8, sizeof(struct filesystemcmp_namespace_request));
	ATF_CHECK_EQ(12, FILESYSTEMCMP_OP_OPEN_NAMESPACE);
	ATF_CHECK_EQ(13, FILESYSTEMCMP_OP_SYNC);
	ATF_CHECK_EQ(14, FILESYSTEMCMP_OP_DUP);
	ATF_CHECK_EQ(4096, FILESYSTEMCMP_PATH_MAX);
}

ATF_TC(typed_api_arguments);
ATF_TC_HEAD(typed_api_arguments, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Typed FileSystemCmp calls reject unsafe names and sizes locally");
}
ATF_TC_BODY(typed_api_arguments, tc)
{
	struct filesystemcmp_handle handle = { 1, 1 };
	struct filesystemcmp_handle_reply reply;
	char buffer[1];

	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_open_namespace(NULL, 0, &handle));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_open_namespace(NULL,
	    FILESYSTEMCMP_NAMESPACE_SCRATCH, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_lookup(NULL, handle, "..", &reply));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_lookup(NULL, handle, "a/b", &reply));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_pread(NULL, handle, buffer,
	    FILESYSTEMCMP_INLINE_MAX + 1, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_open_handle(NULL, handle,
	    ~FILESYSTEMCMP_OPEN_MASK, &reply));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_dup(NULL, handle, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_path_context_open(0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_path_chdir(NULL, "."));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_path_lookup(NULL, "/", &reply));
	ATF_CHECK_EQ(EINVAL, errno);
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
