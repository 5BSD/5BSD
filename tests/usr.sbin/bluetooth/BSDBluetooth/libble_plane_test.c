/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <libservice.h>
#include <string.h>
#include <unistd.h>
#include "ble.h"
#include "blued_plane.h"

static int status, attachment, delivered, session_fd, reused;
int __wrap_service_open(const char *, int *);
int __wrap_service_session_create(int, struct service_session **);
void __wrap_service_session_close(struct service_session *);
int __wrap_service_session_call(struct service_session *,
    const struct service_message *, struct service_reply *,
    const struct service_call_options *);
int
__wrap_service_open(const char *name, int *fd)
{
	ATF_REQUIRE_STREQ(BLUED_PLANE_SERVICE, name);
	*fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(*fd >= 0);
	return (0);
}
int
__wrap_service_session_create(int fd, struct service_session **session)
{
	session_fd = dup(fd);
	ATF_REQUIRE(session_fd >= 0);
	close(fd);
	reused = open("/dev/null", O_RDONLY);
	ATF_REQUIRE_EQ(fd, reused);
	*session = (void *)1;
	return (0);
}
void
__wrap_service_session_close(struct service_session *session __unused)
{
	close(session_fd);
}
int
__wrap_service_session_call(struct service_session *session __unused,
    const struct service_message *request __unused, struct service_reply *reply,
    const struct service_call_options *options __unused)
{
	struct blued_plane_msg message = { BLUED_PLANE_MAGIC,
	    BLUED_PLANE_OP_ATTACH, status };
	memcpy(reply->data, &message, sizeof(message));
	reply->length = sizeof(message);
	reply->nfds = attachment;
	delivered = -1;
	if (attachment) {
		delivered = open("/dev/null", O_RDONLY);
		ATF_REQUIRE(delivered >= 0);
		reply->fds[0] = delivered;
	}
	return (0);
}
ATF_TC_WITHOUT_HEAD(reply_errors_and_ownership);
ATF_TC_BODY(reply_errors_and_ownership, tc)
{
	const int statuses[] = { -1, ELAST + 1, EPERM, 0, EPERM };
	const int attachments[] = { 0, 0, 0, 0, 1 };
	const int errors[] = { EPROTO, EPROTO, EPERM, EPROTO, EPROTO };
	for (unsigned i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++) {
		status = statuses[i];
		attachment = attachments[i];
		ATF_CHECK(ble_open_plane() == NULL);
		ATF_CHECK_EQ(errors[i], errno);
		ATF_CHECK(fcntl(reused, F_GETFD) != -1);
		close(reused);
		if (delivered >= 0)
			ATF_CHECK_ERRNO(EBADF, fcntl(delivered, F_GETFD) == -1);
		ATF_CHECK_ERRNO(EBADF, fcntl(session_fd, F_GETFD) == -1);
	}
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, reply_errors_and_ownership);
	return (atf_no_error());
}
