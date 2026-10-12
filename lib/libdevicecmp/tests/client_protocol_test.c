/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The system.Device client against a scripted bsd.device.v1 server over a
 * real capability channel (service_open is faked to hand out a fresh
 * channel to a forked server).  Covers reply validation, session reuse,
 * reconnection after transport or protocol failure, descriptor cleanup and
 * version negotiation.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <assert.h>
#include <atf-c.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fake_service_open(const char *, int *);
#define service_open fake_service_open
#include "../devicecmp.c"
#undef service_open

enum fault {
	FAULT_NONE,
	FAULT_CALL,		/* close the connection instead of replying */
	FAULT_STATUS,		/* application error EPERM */
	FAULT_BAD_ERRNO,	/* error 0 is not an errno */
	FAULT_FUTURE,		/* wire version 2 */
	FAULT_OPEN_ELEVATED_RIGHTS,
	FAULT_OPEN_ZERO_RIGHTS,
	FAULT_OPEN_UNKNOWN_RIGHTS,
	FAULT_LIST_NAME_SLASH,
	FAULT_LIST_NAME_DOT,
	FAULT_LIST_NAME_NUL,
	FAULT_LIST_RIGHTS,
	FAULT_LIST_FLAGS,
	FAULT_LIST_WHITELIST_WITHOUT_IOCTL,
	FAULT_LIST_CURSOR,
	FAULT_LIST_EMPTY_WITH_CURSOR,
};

/* Shared with the forked servers. */
static struct script {
	enum fault fault;
	unsigned opens;
} *script;
static pid_t servers[16];
static unsigned nservers;

static void
info(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	struct bsd_device_v1_ProtocolInfo v = { DEVICECMP_WIRE_VERSION };
	(void)x;
	(void)e;
	if (script->fault == FAULT_FUTURE)
		v.wire_version++;
	assert(bsd_device_v1_Device_GetProtocolInfo_reply(c, r, &v) == 0);
}

static void
open_handler(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_device_v1_OpenRequest *q)
{
	struct bsd_device_v1_Device_Open_Result v = {
		.tag = bsd_device_v1_Device_Open_Result_response_tag
	};
	int fd;
	(void)x;
	switch (script->fault) {
	case FAULT_CALL:
		fidl_bsd_connection_close(c, EPIPE);
		return;
	case FAULT_STATUS:
	case FAULT_BAD_ERRNO:
		v.tag = bsd_device_v1_Device_Open_Result_err_tag;
		v.value.err = script->fault == FAULT_STATUS ? EPERM : 0;
		assert(bsd_device_v1_Device_Open_reply(c, r, &v) == 0);
		return;
	default:
		break;
	}
	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	assert(fd >= 0);
	v.value.response.device = fd;
	v.value.response.rights = q->rights;
	if (script->fault == FAULT_OPEN_ELEVATED_RIGHTS)
		v.value.response.rights |= DEVICECMP_RIGHT_WRITE;
	else if (script->fault == FAULT_OPEN_ZERO_RIGHTS)
		v.value.response.rights = 0;
	else if (script->fault == FAULT_OPEN_UNKNOWN_RIGHTS)
		v.value.response.rights |= 0x40000000U;
	assert(bsd_device_v1_Device_Open_reply(c, r, &v) == 0);
	close(fd);
}

static void
list_handler(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_device_v1_ListRequest *q)
{
	struct bsd_device_v1_Device_List_Result v = {
		.tag = bsd_device_v1_Device_List_Result_response_tag
	};
	struct bsd_device_v1_DeviceEntry e[2] = {
		{ "null", 4, DEVICECMP_RIGHT_READ, 0 },
		{ "zero", 4, DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_IOCTL,
		    DEVICECMP_LIST_FLAG_IOCTL_WHITELIST },
	};
	(void)x;
	v.value.response.entries = e;
	v.value.response.entries_size = 2;
	v.value.response.next_cursor = q->cursor + 2;
	switch (script->fault) {
	case FAULT_CALL:
		fidl_bsd_connection_close(c, EPIPE);
		return;
	case FAULT_STATUS:
	case FAULT_BAD_ERRNO:
		v.tag = bsd_device_v1_Device_List_Result_err_tag;
		v.value.err = script->fault == FAULT_STATUS ? EPERM : 0;
		break;
	case FAULT_LIST_NAME_SLASH:
		e[0].name = "a/b";
		e[0].name_size = 3;
		break;
	case FAULT_LIST_NAME_DOT:
		e[0].name = ".x";
		e[0].name_size = 2;
		break;
	case FAULT_LIST_NAME_NUL:
		e[0].name = "nu\0l";
		break;
	case FAULT_LIST_RIGHTS:
		e[0].rights = 0;
		break;
	case FAULT_LIST_FLAGS:
		e[0].flags = 0x80;
		break;
	case FAULT_LIST_WHITELIST_WITHOUT_IOCTL:
		e[0].flags = DEVICECMP_LIST_FLAG_IOCTL_WHITELIST;
		break;
	case FAULT_LIST_CURSOR:
		v.value.response.next_cursor = q->cursor;
		break;
	case FAULT_LIST_EMPTY_WITH_CURSOR:
		v.value.response.entries_size = 0;
		break;
	default:
		break;
	}
	assert(bsd_device_v1_Device_List_reply(c, r, &v) == 0);
}

static int
fake_service_open(const char *name, int *fdp)
{
	struct bsd_device_v1_Device_server handlers = {
		.GetProtocolInfo = info,
		.Open = open_handler,
		.List = list_handler
	};
	struct fidl_bsd_connection *connection;
	int ends[2];
	pid_t child;

	ATF_REQUIRE_STREQ(DEVICECMP_INTERFACE, name);
	ATF_REQUIRE(nservers < nitems(servers));
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(ends[0]);
		assert(fidl_bsd_connection_create(ends[1], FIDL_BSD_SERVER,
		    &connection) == 0);
		assert(bsd_device_v1_Device_bind(connection, &handlers,
		    NULL) == 0);
		while (fidl_bsd_connection_poll(connection, 10000) == 0)
			;
		_exit(0);
	}
	close(ends[1]);
	servers[nservers++] = child;
	script->opens++;
	*fdp = ends[0];
	return (0);
}

static void
setup(void)
{
	int fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);

	if (fd < 0)
		atf_tc_skip("capability plane unavailable: %s",
		    strerror(errno));
	close(fd);
	script = mmap(NULL, sizeof(*script), PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_SHARED, -1, 0);
	ATF_REQUIRE(script != MAP_FAILED);
	memset(script, 0, sizeof(*script));
}

static void
teardown(void)
{
	int status;

	pthread_mutex_lock(&devicecmp_lock);
	session_drop();
	pthread_mutex_unlock(&devicecmp_lock);
	for (unsigned i = 0; i < nservers; i++) {
		(void)kill(servers[i], SIGTERM);
		(void)waitpid(servers[i], &status, 0);
	}
	nservers = 0;
}

static unsigned
open_descriptors(void)
{
	unsigned n = 0;

	for (int fd = 0; fd < 512; fd++)
		if (fcntl(fd, F_GETFD) != -1)
			n++;
	return (n);
}

ATF_TC_WITHOUT_HEAD(success_matrix);
ATF_TC_BODY(success_matrix, tc)
{
	struct devicecmp_list_entry entries[2];
	uint32_t granted = 0, count = 0, next = 0;
	int fd = -1;

	setup();
	ATF_REQUIRE_EQ(0, devicecmp_open(NULL, "null", DEVICECMP_RIGHT_READ,
	    &granted, &fd));
	ATF_CHECK_EQ(DEVICECMP_RIGHT_READ, granted);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_ERRNO(ENOMEM,
	    devicecmp_list(NULL, 0, entries, 1, &count, &next) == -1);
	ATF_CHECK_EQ(2, count);
	ATF_REQUIRE_EQ(0, devicecmp_list(NULL, 0, entries, 2, &count, &next));
	ATF_CHECK_EQ(2, count);
	ATF_CHECK_EQ(2, next);
	ATF_CHECK_STREQ("null", entries[0].name);
	ATF_CHECK_STREQ("zero", entries[1].name);
	ATF_CHECK_EQ(DEVICECMP_LIST_FLAG_IOCTL_WHITELIST, entries[1].flags);
	/* One session served all of it. */
	ATF_CHECK_EQ(1, script->opens);
	teardown();
}

ATF_TC_WITHOUT_HEAD(transport_failure_reconnects);
ATF_TC_BODY(transport_failure_reconnects, tc)
{
	uint32_t count, next;
	struct devicecmp_list_entry entries[2];

	setup();
	script->fault = FAULT_CALL;
	ATF_CHECK_EQ(-1, devicecmp_list(NULL, 0, entries, 2, &count, &next));
	ATF_CHECK(errno != 0 && errno != EPROTO);
	script->fault = FAULT_NONE;
	ATF_REQUIRE_EQ(0, devicecmp_list(NULL, 0, entries, 2, &count, &next));
	ATF_CHECK_EQ(2, script->opens);
	teardown();
}

ATF_TC_WITHOUT_HEAD(semantic_error_keeps_session);
ATF_TC_BODY(semantic_error_keeps_session, tc)
{
	uint32_t count, next;
	struct devicecmp_list_entry entries[2];
	int fd = -1;

	setup();
	script->fault = FAULT_STATUS;
	ATF_CHECK_ERRNO(EPERM, devicecmp_open(NULL, "null",
	    DEVICECMP_RIGHT_READ, NULL, &fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_ERRNO(EPERM,
	    devicecmp_list(NULL, 0, entries, 2, &count, &next) == -1);
	script->fault = FAULT_NONE;
	ATF_REQUIRE_EQ(0, devicecmp_list(NULL, 0, entries, 2, &count, &next));
	ATF_CHECK_EQ(1, script->opens);
	teardown();
}

ATF_TC_WITHOUT_HEAD(open_reply_validation);
ATF_TC_BODY(open_reply_validation, tc)
{
	static const enum fault faults[] = {
		FAULT_BAD_ERRNO,
		FAULT_OPEN_ELEVATED_RIGHTS,
		FAULT_OPEN_ZERO_RIGHTS,
		FAULT_OPEN_UNKNOWN_RIGHTS,
	};
	uint32_t granted;
	unsigned before;
	int fd;

	setup();
	before = open_descriptors();
	for (size_t i = 0; i < nitems(faults); i++) {
		script->fault = faults[i];
		granted = 99;
		fd = 99;
		ATF_CHECK_ERRNO(EPROTO, devicecmp_open(NULL, "null",
		    DEVICECMP_RIGHT_READ, &granted, &fd) == -1);
		ATF_CHECK_EQ(-1, fd);
		ATF_CHECK_EQ(0, granted);
	}
	/* Each malformed reply dropped its session... */
	ATF_CHECK_EQ(nitems(faults), script->opens);
	/* ...and no delivered descriptor leaked. */
	ATF_CHECK_EQ(before, open_descriptors());
	teardown();
}

ATF_TC_WITHOUT_HEAD(list_reply_validation);
ATF_TC_BODY(list_reply_validation, tc)
{
	static const enum fault faults[] = {
		FAULT_BAD_ERRNO,
		FAULT_LIST_NAME_SLASH,
		FAULT_LIST_NAME_DOT,
		FAULT_LIST_NAME_NUL,
		FAULT_LIST_RIGHTS,
		FAULT_LIST_FLAGS,
		FAULT_LIST_WHITELIST_WITHOUT_IOCTL,
		FAULT_LIST_CURSOR,
		FAULT_LIST_EMPTY_WITH_CURSOR,
	};
	struct devicecmp_list_entry entries[2];
	uint32_t count, next;

	setup();
	for (size_t i = 0; i < nitems(faults); i++) {
		script->fault = faults[i];
		count = next = 99;
		ATF_CHECK_ERRNO(EPROTO, devicecmp_list(NULL, 1, entries, 2,
		    &count, &next) == -1);
		ATF_CHECK_EQ(0, count);
		ATF_CHECK_EQ(0, next);
	}
	ATF_CHECK_EQ(nitems(faults), script->opens);
	teardown();
}

ATF_TC_WITHOUT_HEAD(future_version_rejected);
ATF_TC_BODY(future_version_rejected, tc)
{
	int fd = -1;

	setup();
	script->fault = FAULT_FUTURE;
	ATF_CHECK_ERRNO(EPROTONOSUPPORT, devicecmp_open(NULL, "null",
	    DEVICECMP_RIGHT_READ, NULL, &fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	teardown();
}

ATF_TC_WITHOUT_HEAD(fork_opens_new_session);
ATF_TC_BODY(fork_opens_new_session, tc)
{
	struct devicecmp_list_entry entries[2];
	uint32_t count, next;
	int status;
	pid_t child;

	setup();
	ATF_REQUIRE_EQ(0, devicecmp_list(NULL, 0, entries, 2, &count, &next));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0)
		_exit(devicecmp_list(NULL, 0, entries, 2, &count, &next) == 0 &&
		    script->opens == 2 ? 0 : 1);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	/* The parent keeps using its own session. */
	ATF_REQUIRE_EQ(0, devicecmp_list(NULL, 0, entries, 2, &count, &next));
	ATF_CHECK_EQ(2, script->opens);
	teardown();
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, success_matrix);
	ATF_TP_ADD_TC(tp, transport_failure_reconnects);
	ATF_TP_ADD_TC(tp, semantic_error_keeps_session);
	ATF_TP_ADD_TC(tp, open_reply_validation);
	ATF_TP_ADD_TC(tp, list_reply_validation);
	ATF_TP_ADD_TC(tp, future_version_rejected);
	ATF_TP_ADD_TC(tp, fork_opens_new_session);
	return (atf_no_error());
}
