/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../devicecmp.c"

struct service_session {
	int failed;
};

enum fault {
	FAULT_NONE,
	FAULT_CALL,
	FAULT_STATUS,
	FAULT_WRONG_OPCODE,
	FAULT_NONZERO_FLAGS,
	FAULT_ERROR_WITH_BODY,
	FAULT_ERROR_WITH_FD,
	FAULT_OPEN_ELEVATED_RIGHTS,
	FAULT_OPEN_RESERVED,
	FAULT_OPEN_NAME_LENGTH,
	FAULT_OPEN_MISSING_FD,
	FAULT_LIST_RESERVED,
	FAULT_LIST_COUNT,
	FAULT_LIST_NAME,
	FAULT_LIST_RIGHTS,
	FAULT_LIST_FLAGS,
	FAULT_LIST_CURSOR,
	FAULT_HELLO_VERSION,
	FAULT_HELLO_RESERVED,
};

static enum fault next_fault;
static unsigned open_count, close_count, fail_count;
static int last_received_fd = -1;

static void
fake_reset(void)
{

	next_fault = FAULT_NONE;
	open_count = 0;
	close_count = 0;
	fail_count = 0;
	last_received_fd = -1;
}

static void
fake_fault(enum fault fault)
{

	next_fault = fault;
}

int
service_open(const char *name, int *fdp)
{

	ATF_REQUIRE_STREQ(DEVICECMP_INTERFACE, name);
	ATF_REQUIRE(fdp != NULL);
	*fdp = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(*fdp >= 0);
	open_count++;
	return (0);
}

int
service_session_create(int fd, struct service_session **sessionp)
{
	struct service_session *session;

	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(sessionp != NULL);
	session = calloc(1, sizeof(*session));
	ATF_REQUIRE(session != NULL);
	close(fd);
	*sessionp = session;
	return (0);
}

void
service_session_close(struct service_session *session)
{

	if (session != NULL) {
		close_count++;
		free(session);
	}
}

int
service_session_fail(struct service_session *session, int error)
{

	ATF_REQUIRE(session != NULL);
	ATF_REQUIRE_EQ(EPROTO, error);
	session->failed = error;
	fail_count++;
	return (0);
}

static void
reply_header(struct devicecmp_msg *reply, uint16_t opcode)
{

	memset(reply, 0, sizeof(*reply));
	reply->magic = DEVICECMP_MAGIC;
	reply->version = DEVICECMP_ABI_VERSION;
	reply->opcode = opcode;
}

int
service_session_call(struct service_session *session,
    const struct service_message *outgoing, struct service_reply *incoming,
    const struct service_call_options *options)
{
	const struct devicecmp_msg *request;
	enum fault fault;
	int fd;

	ATF_REQUIRE(session != NULL);
	ATF_REQUIRE(outgoing != NULL);
	ATF_REQUIRE(incoming != NULL);
	ATF_REQUIRE(options != NULL);
	if (session->failed != 0)
		return (errno = session->failed, -1);
	fault = next_fault;
	next_fault = FAULT_NONE;
	if (fault == FAULT_CALL)
		return (errno = ECONNRESET, -1);
	request = outgoing->data;
	incoming->nfds = 0;

	switch (request->opcode) {
	case DEVICECMP_OP_OPEN: {
		const struct devicecmp_open_body *body;
		struct {
			struct devicecmp_msg msg;
			struct devicecmp_open_body body;
		} *reply = incoming->data;

		body = (const void *)(request + 1);
		memset(reply, 0, sizeof(*reply));
		reply_header(&reply->msg, request->opcode);
		reply->body.rights = body->rights;
		incoming->length = sizeof(*reply);
		fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		ATF_REQUIRE(fd >= 0);
		last_received_fd = fd;
		if (incoming->fds != NULL)
			incoming->fds[0] = fd;
		incoming->nfds = 1;
		if (fault == FAULT_STATUS || fault == FAULT_ERROR_WITH_BODY ||
		    fault == FAULT_ERROR_WITH_FD) {
			reply->msg.status = -EPERM;
			if (fault != FAULT_ERROR_WITH_BODY)
				incoming->length = sizeof(reply->msg);
			if (fault != FAULT_ERROR_WITH_FD) {
				close(fd);
				last_received_fd = -1;
				incoming->nfds = 0;
			}
		} else if (fault == FAULT_OPEN_ELEVATED_RIGHTS) {
			reply->body.rights |= DEVICECMP_RIGHT_WRITE;
		} else if (fault == FAULT_OPEN_RESERVED) {
			reply->body.reserved = 1;
		} else if (fault == FAULT_OPEN_NAME_LENGTH) {
			reply->body.name_length = 1;
		} else if (fault == FAULT_OPEN_MISSING_FD) {
			close(fd);
			last_received_fd = -1;
			incoming->nfds = 0;
		}
		break;
	}
	case DEVICECMP_OP_LIST: {
		struct {
			struct devicecmp_msg msg;
			struct devicecmp_list_reply body;
		} *reply = incoming->data;

		memset(reply, 0, sizeof(*reply));
		reply_header(&reply->msg, request->opcode);
		reply->body.count = 2;
		reply->body.next_cursor = 2;
		strlcpy(reply->body.entries[0].name, "null",
		    sizeof(reply->body.entries[0].name));
		reply->body.entries[0].rights = DEVICECMP_RIGHT_READ;
		strlcpy(reply->body.entries[1].name, "zero",
		    sizeof(reply->body.entries[1].name));
		reply->body.entries[1].rights = DEVICECMP_RIGHT_EVENT;
		incoming->length = sizeof(*reply);
		if (fault == FAULT_STATUS) {
			reply->msg.status = -EPERM;
			incoming->length = sizeof(reply->msg);
		} else if (fault == FAULT_LIST_RESERVED) {
			reply->body.reserved[0] = 1;
		} else if (fault == FAULT_LIST_COUNT) {
			reply->body.count = DEVICECMP_LIST_MAX + 1;
		} else if (fault == FAULT_LIST_NAME) {
			memset(reply->body.entries[0].name, 'x',
			    sizeof(reply->body.entries[0].name));
		} else if (fault == FAULT_LIST_RIGHTS) {
			reply->body.entries[0].rights = 0x80000000U;
		} else if (fault == FAULT_LIST_FLAGS) {
			reply->body.entries[0].flags = 0x80000000U;
		} else if (fault == FAULT_LIST_CURSOR) {
			reply->body.next_cursor = 0;
			reply->body.count = 0;
			reply->body.next_cursor = 1;
		}
		break;
	}
	case DEVICECMP_OP_HELLO: {
		struct {
			struct devicecmp_msg msg;
			struct devicecmp_hello_reply hello;
		} *reply = incoming->data;

		memset(reply, 0, sizeof(*reply));
		reply_header(&reply->msg, request->opcode);
		reply->hello.version = DEVICECMP_ABI_VERSION;
		incoming->length = sizeof(*reply);
		if (fault == FAULT_STATUS) {
			reply->msg.status = -EPERM;
			incoming->length = sizeof(reply->msg);
		} else if (fault == FAULT_HELLO_VERSION) {
			reply->hello.version++;
		} else if (fault == FAULT_HELLO_RESERVED) {
			reply->hello.reserved[1] = 1;
		}
		break;
	}
	default:
		ATF_REQUIRE_MSG(0, "unexpected opcode %u", request->opcode);
	}

	if (fault == FAULT_WRONG_OPCODE)
		((struct devicecmp_msg *)incoming->data)->opcode++;
	else if (fault == FAULT_NONZERO_FLAGS)
		((struct devicecmp_msg *)incoming->data)->flags = 1;
	return (0);
}

ATF_TC_WITHOUT_HEAD(success_matrix);
ATF_TC_BODY(success_matrix, tc)
{
	struct devicecmp_list_entry entries[2];
	uint32_t count, granted, next;
	int fd;

	fake_reset();
	ATF_REQUIRE_EQ(0, devicecmp_hello(NULL));
	ATF_REQUIRE_EQ(0, devicecmp_open(NULL, "null", DEVICECMP_RIGHT_READ,
	    &granted, &fd));
	ATF_CHECK_EQ(DEVICECMP_RIGHT_READ, granted);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	memset(entries, 0, sizeof(entries));
	ATF_CHECK_ERRNO(ENOMEM,
	    devicecmp_list(NULL, 0, entries, 1, &count, &next) == -1);
	ATF_CHECK_EQ(2, count);
	ATF_CHECK_EQ(0, next);
	ATF_REQUIRE_EQ(0, devicecmp_list(NULL, 0, entries, 2, &count, &next));
	ATF_CHECK_EQ(2, count);
	ATF_CHECK_EQ(2, next);
	ATF_CHECK_STREQ("null", entries[0].name);
	ATF_CHECK_STREQ("zero", entries[1].name);
	ATF_CHECK_EQ(1, open_count);
}

ATF_TC_WITHOUT_HEAD(transport_failure_reconnects);
ATF_TC_BODY(transport_failure_reconnects, tc)
{

	fake_reset();
	fake_fault(FAULT_CALL);
	ATF_CHECK_ERRNO(ECONNRESET, devicecmp_hello(NULL) == -1);
	ATF_REQUIRE_EQ(0, devicecmp_hello(NULL));
	ATF_CHECK_EQ(2, open_count);
	ATF_CHECK_EQ(1, close_count);
}

ATF_TC_WITHOUT_HEAD(semantic_error_keeps_session);
ATF_TC_BODY(semantic_error_keeps_session, tc)
{

	fake_reset();
	fake_fault(FAULT_STATUS);
	ATF_CHECK_ERRNO(EPERM, devicecmp_hello(NULL) == -1);
	ATF_REQUIRE_EQ(0, devicecmp_hello(NULL));
	ATF_CHECK_EQ(1, open_count);
	ATF_CHECK_EQ(0, fail_count);
}

ATF_TC_WITHOUT_HEAD(open_reply_validation);
ATF_TC_BODY(open_reply_validation, tc)
{
	static const enum fault faults[] = {
		FAULT_WRONG_OPCODE, FAULT_NONZERO_FLAGS,
		FAULT_OPEN_ELEVATED_RIGHTS, FAULT_OPEN_RESERVED,
		FAULT_OPEN_NAME_LENGTH, FAULT_OPEN_MISSING_FD,
		FAULT_ERROR_WITH_BODY, FAULT_ERROR_WITH_FD,
	};
	uint32_t granted;
	int fd;
	size_t i;

	fake_reset();
	for (i = 0; i < nitems(faults); i++) {
		fake_fault(faults[i]);
		fd = 99;
		granted = 99;
		ATF_CHECK_ERRNO(EPROTO, devicecmp_open(NULL, "null",
		    DEVICECMP_RIGHT_READ, &granted, &fd) == -1);
		ATF_CHECK_EQ(-1, fd);
		ATF_CHECK_EQ(0, granted);
	}
	ATF_CHECK_EQ(nitems(faults), fail_count);
	ATF_CHECK_EQ(nitems(faults), close_count);
	errno = 0;
	ATF_CHECK_ERRNO(EBADF, fcntl(last_received_fd, F_GETFD) == -1);
}

ATF_TC_WITHOUT_HEAD(list_reply_validation);
ATF_TC_BODY(list_reply_validation, tc)
{
	static const enum fault faults[] = {
		FAULT_WRONG_OPCODE, FAULT_NONZERO_FLAGS, FAULT_LIST_RESERVED,
		FAULT_LIST_COUNT, FAULT_LIST_NAME, FAULT_LIST_RIGHTS,
		FAULT_LIST_FLAGS, FAULT_LIST_CURSOR,
	};
	struct devicecmp_list_entry entry;
	uint32_t count, next;
	size_t i;

	fake_reset();
	for (i = 0; i < nitems(faults); i++) {
		fake_fault(faults[i]);
		count = next = 99;
		ATF_CHECK_ERRNO(EPROTO, devicecmp_list(NULL, 1, &entry, 1,
		    &count, &next) == -1);
		ATF_CHECK_EQ(0, count);
		ATF_CHECK_EQ(0, next);
	}
	ATF_CHECK_EQ(nitems(faults), fail_count);
}

ATF_TC_WITHOUT_HEAD(hello_reply_validation);
ATF_TC_BODY(hello_reply_validation, tc)
{
	static const enum fault faults[] = {
		FAULT_WRONG_OPCODE, FAULT_NONZERO_FLAGS, FAULT_HELLO_VERSION,
		FAULT_HELLO_RESERVED,
	};
	size_t i;

	fake_reset();
	for (i = 0; i < nitems(faults); i++) {
		fake_fault(faults[i]);
		ATF_CHECK_ERRNO(EPROTO, devicecmp_hello(NULL) == -1);
	}
	ATF_CHECK_EQ(nitems(faults), fail_count);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, success_matrix);
	ATF_TP_ADD_TC(tp, transport_failure_reconnects);
	ATF_TP_ADD_TC(tp, semantic_error_keeps_session);
	ATF_TP_ADD_TC(tp, open_reply_validation);
	ATF_TP_ADD_TC(tp, list_reply_validation);
	ATF_TP_ADD_TC(tp, hello_reply_validation);
	return (atf_no_error());
}
