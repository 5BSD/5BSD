/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libservice.h>
#include <oes_broker_protocol.h>
#include <security/oes/oes.h>
#include <service_runtime.h>
#include <unistd.h>

#include "oes_factory.h"
static pid_t
start_factory(int *clientfd)
{
	int pair[2], rootfd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(rootfd >= 0);
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(pair));
	pid_t child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(pair[0]);
		_exit(bsdfilesystem_oes_serve(rootfd, pair[1]));
	}
	close(pair[1]);
	close(rootfd);
	*clientfd = pair[0];
	return (child);
}
static void
wait_factory(pid_t child, int expected)
{
	int status;
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(expected, WEXITSTATUS(status));
}
static void
exchange(bool malformed, bool nonroot)
{
	int input, received = -1;
	pid_t child = start_factory(&input);
	struct service_session *session;
	struct oes_broker_message request = { .magic = OES_BROKER_MAGIC,
		.version = OES_BROKER_VERSION,
		.operation = OES_BROKER_OPEN_NOTIFY },
				  reply;
	struct service_message outgoing = { .size = sizeof(outgoing),
		.data = &request,
		.length = sizeof(request) };
	struct service_reply incoming = { .size = sizeof(incoming),
		.data = &reply,
		.capacity = sizeof(reply),
		.fds = &received,
		.fd_capacity = 1 };
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	options.timeout_ms = 5000;
	if (nonroot) {
		ATF_REQUIRE_EQ(0, setgroups(0, NULL));
		ATF_REQUIRE_EQ(0, setgid(65534));
		ATF_REQUIRE_EQ(0, setuid(65534));
		ATF_REQUIRE_EQ(65534, geteuid());
	}
	ATF_REQUIRE_EQ(0, service_session_create(input, &session));
	ATF_REQUIRE_ERRNO(EBADF, fcntl(input, F_GETFD) == -1);
	if (malformed)
		request.reserved = 1;
	ATF_REQUIRE_EQ(0,
	    service_session_call(session, &outgoing, &incoming, &options));
	ATF_REQUIRE_EQ(0,
	    oes_broker_validate(&reply, incoming.length, incoming.nfds, true));
	ATF_REQUIRE_EQ(malformed ? EPROTO : 0, reply.status);
	service_session_close(session);
	wait_factory(child, 0);
	if (malformed) {
		ATF_REQUIRE_EQ(-1, received);
		return;
	}
	ATF_REQUIRE(received >= 0);
	struct oes_mode_args mode = { 0 };
	ATF_REQUIRE_EQ(0, ioctl(received, OES_IOC_GET_MODE, &mode));
	ATF_REQUIRE_EQ(OES_MODE_NOTIFY, mode.ema_mode);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_xfer_limit(received, CAP_XFER_ONCE) == -1);
	mode.ema_mode = OES_MODE_AUTH;
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    ioctl(received, OES_IOC_SET_MODE, &mode) == -1);
	ATF_REQUIRE_EQ(0, close(received));
}
ATF_TC(real_handoff);
ATF_TC_HEAD(real_handoff, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(real_handoff, tc)
{
	exchange(false, false);
}
ATF_TC(nonroot_handoff);
ATF_TC_HEAD(nonroot_handoff, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "non-root recipient receives a restricted OES client from the privileged factory");
}
ATF_TC_BODY(nonroot_handoff, tc)
{
	int status;
	pid_t child = fork();

	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		exchange(false, true);
		_exit(0);
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(0, WEXITSTATUS(status));
}
ATF_TC(malformed_request);
ATF_TC_HEAD(malformed_request, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(malformed_request, tc)
{
	exchange(true, false);
}
ATF_TC(idle_timeout);
ATF_TC_HEAD(idle_timeout, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(idle_timeout, tc)
{
	int fd;
	uint64_t start = service_monotime_ms();
	pid_t child = start_factory(&fd);
	wait_factory(child, 1);
	close(fd);
	ATF_REQUIRE(service_monotime_ms() - start >= 4900);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, real_handoff);
	ATF_TP_ADD_TC(tp, nonroot_handoff);
	ATF_TP_ADD_TC(tp, malformed_request);
	ATF_TP_ADD_TC(tp, idle_timeout);
	return (atf_no_error());
}
