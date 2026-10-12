/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <channel.h>
#include <fidl/bsd.oes.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libservice.h>
#include <liboes.h>
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
struct handoff {
	bool done;
	int error;
	int status;
	int fd;
};

static void
handoff_info(void *p, int error, struct bsd_oes_v1_ProtocolInfo *v)
{
	struct handoff *h = p;

	h->done = true;
	h->error = error;
	if (!error)
		h->status = v->wire_version == OES_BROKER_VERSION ? 0 : EPROTO;
}

static void
handoff_notify(void *p, int error,
    struct bsd_oes_v1_Broker_OpenNotify_Result *v)
{
	struct handoff *h = p;

	h->done = true;
	h->error = error;
	if (error)
		return;
	if (v->tag == bsd_oes_v1_Broker_OpenNotify_Result_err_tag)
		h->status = (int)v->value.err;
	else
		h->fd = fidl_bsd_take_fd(&v->value.response.client);
}

static void
handoff_wait(struct fidl_bsd_connection *c, struct handoff *h)
{
	struct timespec deadline;

	ATF_REQUIRE_EQ(0, fidl_bsd_sync_deadline(&deadline, 5000));
	if (h->error == 0)
		h->error = fidl_bsd_sync_wait(c, &h->done, &deadline);
}

/* A raw OpenNotify carrying a body it does not have closes the session. */
static void
malformed_exchange(int input)
{
	struct {
		uint32_t txid;
		uint8_t flags[3], magic;
		uint64_t ordinal;
		uint64_t junk;
	} frame = { 3, { 2, 0, 0 }, 1, UINT64_C(0x4dba6398e6892924), 0 };
	struct service_session *session;
	struct service_message outgoing = { .size = sizeof(outgoing),
		.data = &frame, .length = sizeof(frame) };
	uint8_t reply[64];
	int received = -1;
	struct service_reply incoming = { .size = sizeof(incoming),
		.data = reply, .capacity = sizeof(reply), .fds = &received,
		.fd_capacity = 1 };
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;

	options.timeout_ms = 5000;
	ATF_REQUIRE_EQ(0, service_session_create(input, &session));
	ATF_CHECK_EQ(-1,
	    service_session_call(session, &outgoing, &incoming, &options));
	ATF_CHECK(errno != ETIMEDOUT);
	ATF_CHECK_EQ(-1, received);
	service_session_close(session);
}

static void
exchange(bool malformed, bool nonroot)
{
	int input, received;
	pid_t child = start_factory(&input);
	struct fidl_bsd_connection *connection;
	struct fidl_bsd_empty empty = { 0 };
	struct handoff h = { .fd = -1 };
	uint32_t txid;

	if (nonroot) {
		ATF_REQUIRE_EQ(0, setgroups(0, NULL));
		ATF_REQUIRE_EQ(0, setgid(65534));
		ATF_REQUIRE_EQ(0, setuid(65534));
		ATF_REQUIRE_EQ(65534, geteuid());
	}
	if (malformed) {
		malformed_exchange(input);
		/* The broker served nothing. */
		wait_factory(child, 1);
		return;
	}
	ATF_REQUIRE_EQ(0, fidl_bsd_connection_create(input, FIDL_BSD_CLIENT,
	    &connection));
	ATF_REQUIRE_ERRNO(EBADF, fcntl(input, F_GETFD) == -1);
	h.error = bsd_oes_v1_Broker_GetProtocolInfo(connection, &empty,
	    handoff_info, &h, &txid);
	handoff_wait(connection, &h);
	ATF_REQUIRE_EQ(0, h.error);
	ATF_REQUIRE_EQ(0, h.status);
	h = (struct handoff){ .fd = -1 };
	h.error = bsd_oes_v1_Broker_OpenNotify(connection, &empty,
	    handoff_notify, &h, &txid);
	handoff_wait(connection, &h);
	ATF_REQUIRE_EQ(0, h.error);
	ATF_REQUIRE_EQ(0, h.status);
	received = h.fd;
	fidl_bsd_connection_destroy(connection);
	wait_factory(child, 0);
	ATF_REQUIRE(received >= 0);
	struct oes_mode_args mode = { 0 };
	ATF_REQUIRE_EQ(0, ioctl(received, OES_IOC_GET_MODE, &mode));
	ATF_REQUIRE_EQ(OES_MODE_NOTIFY, mode.ema_mode);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_xfer_limit(received, CAP_XFER_ONCE) == -1);
	mode.ema_mode = OES_MODE_AUTH;
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    ioctl(received, OES_IOC_SET_MODE, &mode) == -1);
	/* Exercise the public wrapper after the factory session has closed. */
	oes_client_t *client = oes_client_adopt_fd(received);
	oes_event_type_t event = OES_EVENT_NOTIFY_EXEC;
	uint32_t client_mode, scope;
	uint64_t auth[2], notify[2];
	struct oes_stats stats;

	ATF_REQUIRE(client != NULL);
	ATF_REQUIRE_EQ(received, oes_client_fd(client));
	ATF_REQUIRE_EQ(0, oes_get_mode(client, &client_mode, NULL, NULL));
	ATF_REQUIRE_EQ(OES_MODE_NOTIFY, client_mode);
	ATF_REQUIRE_EQ(0, oes_get_scope(client, &scope));
	ATF_REQUIRE_EQ(OES_SCOPE_GLOBAL, scope);
	ATF_REQUIRE_EQ(0, oes_subscribe(client, &event, 1, OES_SUB_REPLACE));
	ATF_REQUIRE_EQ(0, oes_get_subscriptions(client, auth, notify));
	ATF_REQUIRE_EQ(0, auth[0] | auth[1]);
	ATF_REQUIRE(notify[0] != 0 || notify[1] != 0);
	ATF_REQUIRE_EQ(0, oes_get_stats(client, &stats));
	ATF_REQUIRE_EQ(0, oes_unsubscribe_all(client));
	ATF_REQUIRE_EQ(0, oes_get_subscriptions(client, auth, notify));
	ATF_REQUIRE_EQ(0, auth[0] | auth[1] | notify[0] | notify[1]);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE, oes_set_descendants_scope(client) == -1);
	oes_client_destroy(client);
	ATF_REQUIRE_ERRNO(EBADF, fcntl(received, F_GETFD) == -1);
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
