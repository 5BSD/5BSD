/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <auditcmp.h>
#include <auditcmp_server.h>
#include <libservice.h>

#include "auditcmp_submit.h"
#include "auditcmp_test.h"

struct fixture {
	struct auditcmp_client *client;
	pid_t child;
};

struct raw_fixture {
	struct service_session	*session;
	pid_t			 child;
};

static int
backend_submit(int event __unused, int result_error __unused,
    const char *provider __unused, const char *subject __unused,
    const char *operation __unused, void *context)
{
	int error;

	error = *(int *)context;
	if (error != 0)
		return (errno = error, -1);
	return (0);
}

static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE_MSG(control >= 0, "open mac_capability: %s",
	    strerror(errno));
	memset(&connect, 0, sizeof(connect));
	strlcpy(connect.name, name, sizeof(connect.name));
	if (ioctl(control, MAC_CAPABILITY_CONNECT, &connect) == -1) {
		error = errno;
		close(control);
		errno = error;
		return (-1);
	}
	close(control);
	return (connect.fd);
}

static void
channel_pair(int *client, int *provider)
{
	struct mac_capability_recvmsg_args receive;
	struct mac_capability_sendmsg_args send;
	uint32_t operation;

	*client = capability_connect("channel");
	ATF_REQUIRE(*client >= 0);
	operation = CHANNEL_OP_CREATE;
	memset(&send, 0, sizeof(send));
	send.payload = &operation;
	send.payload_len = sizeof(operation);
	ATF_REQUIRE_EQ(0, ioctl(*client, MAC_CAPABILITY_SENDMSG, &send));
	memset(&receive, 0, sizeof(receive));
	receive.fds = provider;
	receive.nfds = 1;
	ATF_REQUIRE_EQ(0, ioctl(*client, MAC_CAPABILITY_RECVMSG, &receive));
	ATF_REQUIRE_EQ(1, receive.nfds);
}

static void
fixture_create(struct fixture *fixture, int backend_error)
{
	struct auditcmp_backend backend;
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		backend.submit = backend_submit;
		backend.context = &backend_error;
		_exit(auditcmp_test_serve(provider, "org.test.audit", 999,
		    &backend));
	}
	close(provider);
	ATF_REQUIRE_EQ(0, auditcmp_client_adopt(client, &fixture->client));
}

static void
fixture_destroy(struct fixture *fixture)
{
	int status;

	auditcmp_client_close(fixture->client);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
}

static void
raw_fixture_create(struct raw_fixture *fixture)
{
	struct auditcmp_backend backend;
	int backend_error, client, provider;

	memset(fixture, 0, sizeof(*fixture));
	backend_error = 0;
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		backend.submit = backend_submit;
		backend.context = &backend_error;
		_exit(auditcmp_test_serve(provider, "org.test.audit", 999,
		    &backend));
	}
	close(provider);
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

static void
raw_fixture_destroy(struct raw_fixture *fixture, int expected_status)
{
	int status;

	service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(expected_status, WEXITSTATUS(status));
}

static int
raw_call_with_attachment(struct service_session *session, int fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct auditcmp_msg request;
	uint8_t reply[AUDITCMP_MAX_MESSAGE];

	ATF_REQUIRE_EQ(0, auditcmp_message_init(&request, AUDITCMP_OP_HELLO, 0));
	outgoing = (struct service_message){
		.size = sizeof(outgoing),
		.data = &request,
		.length = sizeof(request),
		.fds = &fd,
		.nfds = 1,
	};
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 2000;
	return (service_session_call(session, &outgoing, &incoming, &options));
}

ATF_TC(provider_submit_and_stats);
ATF_TC_HEAD(provider_submit_and_stats, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_submit_and_stats, tc)
{
	struct auditcmp_stats stats;
	struct fixture fixture;

	fixture_create(&fixture, 0);
	ATF_REQUIRE_EQ(0, auditcmp_submit(fixture.client, "org.test.subject",
	    "create", 0));
	ATF_REQUIRE_EQ(0, auditcmp_stats(fixture.client, &stats));
	ATF_CHECK_EQ(1, stats.submitted);
	ATF_CHECK_EQ(0, stats.rejected);
	fixture_destroy(&fixture);
}

ATF_TC(provider_backend_error);
ATF_TC_HEAD(provider_backend_error, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC(provider_unexpected_descriptor_is_terminal);
ATF_TC_HEAD(provider_unexpected_descriptor_is_terminal, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "An unexpected descriptor poisons only its AuditCmp session");
}
ATF_TC_BODY(provider_unexpected_descriptor_is_terminal, tc)
{
	struct raw_fixture fixture;
	int fd;

	raw_fixture_create(&fixture);
	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK(raw_call_with_attachment(fixture.session, fd) == -1);
	ATF_CHECK(fcntl(fd, F_GETFD) >= 0);
	close(fd);
	raw_fixture_destroy(&fixture, 1);
}
ATF_TC_BODY(provider_backend_error, tc)
{
	struct auditcmp_stats stats;
	struct fixture fixture;

	fixture_create(&fixture, EIO);
	ATF_CHECK_ERRNO(EIO, auditcmp_submit(fixture.client,
	    "org.test.subject", "create", 0) == -1);
	ATF_REQUIRE_EQ(0, auditcmp_stats(fixture.client, &stats));
	ATF_CHECK_EQ(0, stats.submitted);
	ATF_CHECK_EQ(1, stats.rejected);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{
	struct auditcmp_backend backend = {
		.submit = backend_submit,
		.context = &(int){ 0 }
	};

	ATF_CHECK_ERRNO(EINVAL,
	    auditcmp_test_serve(-1, "org.test", 1, &backend) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    auditcmp_test_serve(0, "", 1, &backend) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    auditcmp_test_serve(0, "org.test", 0, &backend) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    auditcmp_test_serve(0, "org.test", 1, NULL) == -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, provider_submit_and_stats);
	ATF_TP_ADD_TC(tp, provider_backend_error);
	ATF_TP_ADD_TC(tp, provider_unexpected_descriptor_is_terminal);
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
