/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../tzfsd.c"

struct service_session {
	int fd;
};

static struct service_session fake_session;
static struct tzfsd_request last_request;
static bool fail_open;
static bool fail_create;
static bool fail_call;
static bool close_called;
static bool mount_fail;
static unsigned reply_mode;

enum {
	REPLY_OK,
	REPLY_SHORT,
	REPLY_RESERVED,
	REPLY_BAD_STATUS,
	REPLY_UNEXPECTED_FD,
	REPLY_MISSING_FD,
	REPLY_ERROR_WITH_FD,
	REPLY_STATUS_ERROR
};

static void
reset_fake(void)
{
	memset(&last_request, 0, sizeof(last_request));
	fake_session.fd = -1;
	fail_open = false;
	fail_create = false;
	fail_call = false;
	close_called = false;
	mount_fail = false;
	reply_mode = REPLY_OK;
}

int
service_open(const char *name, int *fdp)
{
	ATF_REQUIRE_STREQ(TZFSD_SERVICE_NAME, name);
	ATF_REQUIRE(fdp != NULL);
	if (fail_open) {
		errno = ENOENT;
		return (-1);
	}
	*fdp = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(*fdp >= 0);
	return (0);
}

int
service_session_create(int fd, struct service_session **sessionp)
{
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(sessionp != NULL);
	if (fail_create) {
		errno = EIO;
		return (-1);
	}
	fake_session.fd = fd;
	*sessionp = &fake_session;
	return (0);
}

void
service_session_close(struct service_session *session)
{
	ATF_REQUIRE_EQ(&fake_session, session);
	ATF_REQUIRE(fake_session.fd >= 0);
	ATF_REQUIRE_EQ(0, close(fake_session.fd));
	fake_session.fd = -1;
	close_called = true;
}

int
service_session_call(struct service_session *session,
    const struct service_message *message, struct service_reply *reply,
    const struct service_call_options *options)
{
	struct tzfsd_reply response;
	bool wants_fd;
	int fd;

	ATF_REQUIRE_EQ(&fake_session, session);
	ATF_REQUIRE(message != NULL);
	ATF_REQUIRE_EQ(sizeof(*message), message->size);
	ATF_REQUIRE_EQ(sizeof(last_request), message->length);
	ATF_REQUIRE(message->data != NULL);
	ATF_REQUIRE_EQ(0, message->nfds);
	ATF_REQUIRE(reply != NULL);
	ATF_REQUIRE_EQ(sizeof(*reply), reply->size);
	ATF_REQUIRE(reply->capacity >= sizeof(response));
	ATF_REQUIRE_EQ(1, reply->fd_capacity);
	ATF_REQUIRE(options != NULL);
	ATF_REQUIRE_EQ(sizeof(*options), options->size);
	memcpy(&last_request, message->data, sizeof(last_request));
	if (fail_call) {
		errno = EIO;
		return (-1);
	}

	memset(&response, 0, sizeof(response));
	strlcpy(response.dataset, "pool/components/claim",
	    sizeof(response.dataset));
	wants_fd = last_request.op == TZFSD_OP_REQUEST;
	if (reply_mode == REPLY_RESERVED)
		response._reserved = 1;
	else if (reply_mode == REPLY_BAD_STATUS)
		response.status = ELAST + 1;
	else if (reply_mode == REPLY_STATUS_ERROR ||
	    reply_mode == REPLY_ERROR_WITH_FD)
		response.status = EACCES;
	memcpy(reply->data, &response, sizeof(response));
	reply->length = reply_mode == REPLY_SHORT ? sizeof(response) - 1 :
	    sizeof(response);
	reply->nfds = 0;
	if ((wants_fd && reply_mode != REPLY_MISSING_FD &&
	    reply_mode != REPLY_STATUS_ERROR) ||
	    (!wants_fd && reply_mode == REPLY_UNEXPECTED_FD) ||
	    reply_mode == REPLY_ERROR_WITH_FD) {
		fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		ATF_REQUIRE(fd >= 0);
		reply->fds[0] = fd;
		reply->nfds = 1;
	}
	return (0);
}

int
tzfs_mount(int handle_fd, bool rdonly)
{
	ATF_REQUIRE(handle_fd >= 0);
	if (mount_fail) {
		errno = EIO;
		return (-1);
	}
	return (rdonly ? 102 : 101);
}

static struct tzfsd_client *
open_client(void)
{
	struct tzfsd_client *client;

	client = tzfsd_connect();
	ATF_REQUIRE(client != NULL);
	return (client);
}

ATF_TC(connect_lifecycle);
ATF_TC_HEAD(connect_lifecycle, tc)
{
	atf_tc_set_md_var(tc, "descr", "connect/adopt ownership and close");
}
ATF_TC_BODY(connect_lifecycle, tc)
{
	struct tzfsd_client *client;
	int fd;

	reset_fake();
	client = open_client();
	tzfsd_close(client);
	ATF_CHECK(close_called);
	tzfsd_close(NULL);

	reset_fake();
	fail_open = true;
	ATF_CHECK_ERRNO(ENOENT, tzfsd_connect() == NULL);

	reset_fake();
	fail_create = true;
	client = tzfsd_connect();
	ATF_CHECK_ERRNO(EIO, client == NULL);

	reset_fake();
	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	fail_create = true;
	ATF_CHECK_ERRNO(EIO, tzfsd_adopt(fd) == NULL);
	ATF_CHECK(fcntl(fd, F_GETFD) != -1);
	(void)close(fd);
}

ATF_TC(request_and_quota);
ATF_TC_HEAD(request_and_quota, tc)
{
	atf_tc_set_md_var(tc, "descr", "request serialization and grant framing");
}
ATF_TC_BODY(request_and_quota, tc)
{
	struct tzfsd_client *client;
	struct tzfsd_grant grant;
	struct tzfsd_req req;

	reset_fake();
	client = open_client();
	memset(&req, 0, sizeof(req));
	strlcpy(req.dataset, "claim", sizeof(req.dataset));
	req.rights = 0x1234;
	req.flags = 7;
	req.lifetime = TZFSD_CACHE;
	req.owner_uid = 1001;
	req.owner_gid = 1002;
	ATF_REQUIRE_EQ(0, tzfsd_request_quota(client, &req, 65536, &grant));
	ATF_CHECK_EQ(TZFSD_OP_REQUEST, last_request.op);
	ATF_CHECK_EQ(req.rights, last_request.rights);
	ATF_CHECK_EQ(req.flags, last_request.flags);
	ATF_CHECK_EQ(req.lifetime, last_request.lifetime);
	ATF_CHECK_EQ(req.owner_uid, last_request.owner_uid);
	ATF_CHECK_EQ(req.owner_gid, last_request.owner_gid);
	ATF_CHECK_EQ(65536, last_request.quota);
	ATF_CHECK_STREQ("claim", last_request.dataset);
	ATF_CHECK_STREQ("pool/components/claim", grant.dataset);
	ATF_CHECK(grant.handle_fd >= 0);
	(void)close(grant.handle_fd);
	tzfsd_close(client);
}

ATF_TC(request_validation);
ATF_TC_HEAD(request_validation, tc)
{
	atf_tc_set_md_var(tc, "descr", "invalid and unterminated keys fail locally");
}
ATF_TC_BODY(request_validation, tc)
{
	struct tzfsd_client *client;
	struct tzfsd_grant grant;
	struct tzfsd_req req;

	reset_fake();
	client = open_client();
	memset(&req, 0, sizeof(req));
	ATF_CHECK_ERRNO(EINVAL, tzfsd_request(client, &req, &grant) == -1);
	memset(req.dataset, 'x', sizeof(req.dataset));
	ATF_CHECK_ERRNO(ENAMETOOLONG,
	    tzfsd_request(client, &req, &grant) == -1);
	ATF_CHECK_ERRNO(EINVAL, tzfsd_request(NULL, &req, &grant) == -1);
	ATF_CHECK_ERRNO(EINVAL, tzfsd_request(client, NULL, &grant) == -1);
	ATF_CHECK_ERRNO(EINVAL, tzfsd_request(client, &req, NULL) == -1);
	tzfsd_close(client);
}

ATF_TC(reply_validation);
ATF_TC_HEAD(reply_validation, tc)
{
	atf_tc_set_md_var(tc, "descr", "malformed reply and descriptor shapes close safely");
}
ATF_TC_BODY(reply_validation, tc)
{
	struct tzfsd_client *client;
	struct tzfsd_grant grant;
	struct tzfsd_req req;
	unsigned modes[] = { REPLY_SHORT, REPLY_RESERVED, REPLY_BAD_STATUS,
	    REPLY_MISSING_FD, REPLY_ERROR_WITH_FD };
	unsigned i;

	reset_fake();
	client = open_client();
	memset(&req, 0, sizeof(req));
	strlcpy(req.dataset, "claim", sizeof(req.dataset));
	for (i = 0; i < nitems(modes); i++) {
		reply_mode = modes[i];
		ATF_CHECK_ERRNO(EPROTO,
		    tzfsd_request(client, &req, &grant) == -1);
	}
	reply_mode = REPLY_STATUS_ERROR;
	ATF_CHECK_ERRNO(EACCES, tzfsd_request(client, &req, &grant) == -1);
	reply_mode = REPLY_UNEXPECTED_FD;
	ATF_CHECK_ERRNO(EPROTO, tzfsd_ping(client) == -1);
	fail_call = true;
	ATF_CHECK_ERRNO(EIO, tzfsd_ping(client) == -1);
	tzfsd_close(client);
}

ATF_TC(other_commands);
ATF_TC_HEAD(other_commands, tc)
{
	atf_tc_set_md_var(tc, "descr", "ping, release, destroy and session requests");
}
ATF_TC_BODY(other_commands, tc)
{
	struct tzfsd_client *client;
	char session[TZFSD_SESSION_MAX];

	reset_fake();
	client = open_client();
	ATF_REQUIRE_EQ(0, tzfsd_ping(client));
	ATF_CHECK_EQ(TZFSD_OP_PING, last_request.op);
	ATF_REQUIRE_EQ(0, tzfsd_release(client, "claim"));
	ATF_CHECK_EQ(TZFSD_OP_RELEASE, last_request.op);
	ATF_CHECK_STREQ("claim", last_request.dataset);
	ATF_REQUIRE_EQ(0, tzfsd_destroy(client, "claim", TZFSD_PERSISTENT));
	ATF_CHECK_EQ(TZFSD_OP_DESTROY, last_request.op);
	ATF_CHECK_EQ(TZFSD_PERSISTENT, last_request.lifetime);
	ATF_CHECK_ERRNO(EINVAL,
	    tzfsd_destroy(client, "claim", TZFSD_LEASE) == -1);
	memset(session, 'a', sizeof(session) - 1);
	session[sizeof(session) - 1] = '\0';
	ATF_REQUIRE_EQ(0, tzfsd_begin_session(client, session));
	ATF_CHECK_EQ(TZFSD_OP_BEGIN_SESSION, last_request.op);
	ATF_CHECK_STREQ(session, last_request.session);
	ATF_CHECK_ERRNO(EINVAL, tzfsd_release(client, "") == -1);
	ATF_CHECK_ERRNO(EINVAL, tzfsd_begin_session(client, "short") == -1);
	tzfsd_close(client);
}

ATF_TC(mount_wrapper);
ATF_TC_HEAD(mount_wrapper, tc)
{
	atf_tc_set_md_var(tc, "descr", "mount wrapper preserves mode and errors");
}
ATF_TC_BODY(mount_wrapper, tc)
{
	reset_fake();
	ATF_CHECK_EQ(101, tzfsd_mount_dir(7, 0));
	ATF_CHECK_EQ(102, tzfsd_mount_dir(7, 1));
	mount_fail = true;
	ATF_CHECK_ERRNO(EIO, tzfsd_mount_dir(7, 0) == -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, connect_lifecycle);
	ATF_TP_ADD_TC(tp, request_and_quota);
	ATF_TP_ADD_TC(tp, request_validation);
	ATF_TP_ADD_TC(tp, reply_validation);
	ATF_TP_ADD_TC(tp, other_commands);
	ATF_TP_ADD_TC(tp, mount_wrapper);
	return (atf_no_error());
}
