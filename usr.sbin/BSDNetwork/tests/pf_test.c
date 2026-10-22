/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * system.Network.PF over bsd.network.v1 NetworkPf: the real worker
 * (pf_session.c network_pf_serve) on a real capability channel, driven by
 * the real libnetworkcmp function (its source, with discovery replaced by
 * the test channel) and by the generated client bindings.  The worker is
 * handed a stand-in for /dev/pf narrowed exactly as network_pf_open() does,
 * so the delivered rights, ioctl list and one-transfer state are those of
 * production without a pf(4) device; binding a jailed client to its vnet
 * needs a vnet jail and is not exercised here.
 */
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <fidl/bsd.network.v1/c/bsd.h>
#include <libservice.h>
#include <networkcmp.h>

static int test_client_fd = -1;

static int
test_service_open(const char *name, int *fd)
{
	ATF_REQUIRE_STREQ(NETWORKCMP_PF_INTERFACE, name);
	*fd = test_client_fd;
	test_client_fd = -1;
	return (*fd < 0 ? (errno = ENOENT, -1) : 0);
}

#define service_open test_service_open
#include "../../../lib/libnetworkcmp/networkcmp.c"
#undef service_open

#include "pf_session.h"

static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (control < 0)
		atf_tc_skip("capability plane unavailable: /dev/mac_capability: "
		    "%s", strerror(errno));
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

/*
 * A stand-in for the descriptor network_pf_open() hands a worker: /dev/null
 * narrowed exactly as /dev/pf is (rights, both ioctls, no fcntls, one
 * transfer after one fork).
 */
static int
narrowed_stand_in(void)
{
	static const unsigned long commands[] = { DIOCGETSTATES,
	    DIOCBINDJAIL };
	cap_rights_t rights;
	int fd;

	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	cap_rights_init(&rights, CAP_READ, CAP_FSTAT, CAP_IOCTL);
	ATF_REQUIRE_EQ(0, cap_rights_limit(fd, &rights));
	ATF_REQUIRE_EQ(0, cap_ioctls_limit(fd, commands, nitems(commands)));
	ATF_REQUIRE_EQ(0, cap_fcntls_limit(fd, 0));
	ATF_REQUIRE_EQ(0, service_harden_fd(fd, SERVICE_HARDEN_XFER_ONCE |
	    SERVICE_HARDEN_CLOFORK_ONCE));
	return (fd);
}

/* Fork the real worker on a fresh channel; returns the client end. */
static pid_t
start_worker(int pf_fd, int open_error, int *client)
{
	pid_t child;
	int provider;

	channel_pair(client, &provider);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(*client);
		_exit(network_pf_serve(provider, pf_fd, open_error));
	}
	close(provider);
	if (pf_fd >= 0)
		close(pf_fd);
	return (child);
}

static int
reap(pid_t child)
{
	int status;

	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	return (WEXITSTATUS(status));
}

/* Exactly CAP_READ|CAP_FSTAT|CAP_IOCTL, DIOCGETSTATES alone, no fcntls. */
static void
check_delivered(int fd)
{
	cap_rights_t rights, expected;
	cap_ioctl_t commands[2];
	uint32_t fcntls;

	ATF_REQUIRE_EQ(0, cap_rights_get(fd, &rights));
	cap_rights_init(&expected, CAP_READ, CAP_FSTAT, CAP_IOCTL);
	ATF_CHECK(cap_rights_contains(&expected, &rights));
	ATF_CHECK(cap_rights_contains(&rights, &expected));
	ATF_CHECK_EQ(1, cap_ioctls_get(fd, commands, nitems(commands)));
	ATF_CHECK_EQ(DIOCGETSTATES, commands[0]);
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_WRITE));
	ATF_REQUIRE_EQ(0, cap_fcntls_get(fd, &fcntls));
	ATF_CHECK_EQ(0, fcntls);
	/* The bind right went with the worker: DIOCBINDJAIL is refused. */
	ATF_CHECK_EQ(-1, ioctl(fd, DIOCBINDJAIL, &(int){ 0 }));
	ATF_CHECK_EQ(ENOTCAPABLE, errno);
}

/* One generated-binding call's outcome. */
struct reply {
	bool done;
	int error;		/* transport */
	int status;		/* application errno, 0 on success */
	int fd;
};

static void
wait_reply(struct fidl_bsd_connection *connection, struct reply *reply)
{
	int error;

	while (!reply->done) {
		error = fidl_bsd_connection_poll(connection, 10000);
		if (error != 0 && !reply->done) {
			reply->done = true;
			reply->error = error;
		}
	}
}

static void
info_cb(void *context, int error, struct bsd_network_v1_ProtocolInfo *value)
{
	struct reply *reply = context;

	reply->done = true;
	reply->error = error;
	if (error == 0)
		reply->status = value->wire_version == NETWORKCMP_WIRE_VERSION ?
		    0 : EPROTONOSUPPORT;
}

static void
states_cb(void *context, int error,
    struct bsd_network_v1_NetworkPf_OpenStates_Result *value)
{
	struct reply *reply = context;

	reply->done = true;
	reply->error = error;
	if (error != 0)
		return;
	if (value->tag == bsd_network_v1_NetworkPf_OpenStates_Result_err_tag)
		reply->status = (int)value->value.err;
	else if (value->tag ==
	    bsd_network_v1_NetworkPf_OpenStates_Result_response_tag)
		reply->fd = fidl_bsd_take_fd(&value->value.response.pf);
	else
		reply->status = EPROTO;
}

static void
pf_negotiate(struct fidl_bsd_connection *connection)
{
	struct fidl_bsd_empty empty = { 0 };
	struct reply reply = { .fd = -1 };
	uint32_t txid;

	ATF_REQUIRE_EQ(0, bsd_network_v1_NetworkPf_GetProtocolInfo(connection,
	    &empty, info_cb, &reply, &txid));
	wait_reply(connection, &reply);
	ATF_REQUIRE_EQ(0, reply.error);
	ATF_REQUIRE_EQ(0, reply.status);
}

static void
open_states(struct fidl_bsd_connection *connection, struct reply *reply)
{
	struct fidl_bsd_empty empty = { 0 };
	uint32_t txid;

	*reply = (struct reply){ .fd = -1 };
	ATF_REQUIRE_EQ(0, bsd_network_v1_NetworkPf_OpenStates(connection,
	    &empty, states_cb, reply, &txid));
	wait_reply(connection, reply);
}

ATF_TC(pf_open_delivers_narrowed_descriptor);
ATF_TC_HEAD(pf_open_delivers_narrowed_descriptor, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "networkcmp_pf_open() returns the "
	    "worker's descriptor with exactly CAP_READ|CAP_FSTAT|CAP_IOCTL and "
	    "DIOCGETSTATES as its only ioctl");
}
ATF_TC_BODY(pf_open_delivers_narrowed_descriptor, tc)
{
	pid_t worker;
	int fd = 12345;

	worker = start_worker(narrowed_stand_in(), 0, &test_client_fd);
	ATF_REQUIRE_EQ(0, networkcmp_pf_open(&fd));
	ATF_REQUIRE(fd >= 0);
	check_delivered(fd);
	/* Held for good by the library: no further transfer. */
	ATF_CHECK_EQ(0, reap(worker));
	close(fd);
}

ATF_TC(pf_open_error_delivers_no_descriptor);
ATF_TC_HEAD(pf_open_error_delivers_no_descriptor, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "A worker without /dev/pf reports the "
	    "open error as the application error and attaches nothing");
}
ATF_TC_BODY(pf_open_error_delivers_no_descriptor, tc)
{
	pid_t worker;
	int fd = 12345;

	worker = start_worker(-1, ENXIO, &test_client_fd);
	ATF_REQUIRE_EQ(-1, networkcmp_pf_open(&fd));
	ATF_CHECK_EQ(ENXIO, errno);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(0, reap(worker));
}

ATF_TC(pf_library_refuses_wider_descriptor);
ATF_TC_HEAD(pf_library_refuses_wider_descriptor, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "A descriptor with more than the "
	    "promised rights is refused by the client library with EPROTO");
}
ATF_TC_BODY(pf_library_refuses_wider_descriptor, tc)
{
	pid_t worker;
	int fd = 12345, wide;

	/* Not narrowed: every right, only the ioctl list the worker sets. */
	wide = open("/dev/null", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE(wide >= 0);
	worker = start_worker(wide, 0, &test_client_fd);
	ATF_REQUIRE_EQ(-1, networkcmp_pf_open(&fd));
	ATF_CHECK_EQ(EPROTO, errno);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(0, reap(worker));
}

ATF_TC(pf_second_request_rejected);
ATF_TC_HEAD(pf_second_request_rejected, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "A session delivers one descriptor; a "
	    "second OpenStates fails with EALREADY and attaches nothing");
}
ATF_TC_BODY(pf_second_request_rejected, tc)
{
	struct fidl_bsd_connection *connection;
	struct reply reply;
	pid_t worker;
	int client;

	worker = start_worker(narrowed_stand_in(), 0, &client);
	ATF_REQUIRE_EQ(0, fidl_bsd_connection_create(client, FIDL_BSD_CLIENT,
	    &connection));
	pf_negotiate(connection);
	open_states(connection, &reply);
	ATF_REQUIRE_EQ(0, reply.error);
	ATF_REQUIRE_EQ(0, reply.status);
	ATF_REQUIRE(reply.fd >= 0);
	check_delivered(reply.fd);
	close(reply.fd);
	open_states(connection, &reply);
	ATF_CHECK_EQ(0, reply.error);
	ATF_CHECK_EQ(EALREADY, reply.status);
	ATF_CHECK_EQ(-1, reply.fd);
	/* Negotiation may be repeated; the session itself stays open. */
	pf_negotiate(connection);
	fidl_bsd_connection_destroy(connection);
	ATF_CHECK_EQ(0, reap(worker));
}

ATF_TC(pf_request_before_negotiation_ends_session);
ATF_TC_HEAD(pf_request_before_negotiation_ends_session, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "OpenStates before GetProtocolInfo is "
	    "a protocol violation: no descriptor, session closed, worker "
	    "exits 1");
}
ATF_TC_BODY(pf_request_before_negotiation_ends_session, tc)
{
	struct fidl_bsd_connection *connection;
	struct reply reply;
	pid_t worker;
	int client;

	worker = start_worker(narrowed_stand_in(), 0, &client);
	ATF_REQUIRE_EQ(0, fidl_bsd_connection_create(client, FIDL_BSD_CLIENT,
	    &connection));
	open_states(connection, &reply);
	ATF_CHECK(reply.error != 0);
	ATF_CHECK_EQ(-1, reply.fd);
	fidl_bsd_connection_destroy(connection);
	ATF_CHECK_EQ(1, reap(worker));
}

ATF_TC(pf_malformed_request_ends_session);
ATF_TC_HEAD(pf_malformed_request_ends_session, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "An attached descriptor, the pre-FIDL "
	    "PFS1 record and an unknown ordinal each end the session without "
	    "a descriptor; the worker exits 1");
}
ATF_TC_BODY(pf_malformed_request_ends_session, tc)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_session *session;
	struct service_message outgoing;
	struct service_reply response;
	struct { uint32_t magic; int32_t error; } record = { 0x50465331, 0 };
	/* A FIDL frame header: txid, flags {2,0,0}, magic 1, ordinal. */
	struct {
		uint32_t txid;
		uint8_t flags[3], magic;
		uint64_t ordinal;
	} frame;
	uint8_t reply[256];
	int replied_fds[2];
	pid_t worker;
	int client, pipefd[2];

	ATF_REQUIRE_EQ(0, pipe(pipefd));
	memset(&frame, 0, sizeof(frame));
	frame.txid = 1;
	frame.flags[0] = 2;
	frame.magic = 1;
	frame.ordinal = 1;	/* unknown to NetworkPf */
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	memset(&response, 0, sizeof(response));
	response.size = sizeof(response);
	response.data = reply;
	response.capacity = sizeof(reply);
	response.fds = replied_fds;
	response.fd_capacity = nitems(replied_fds);
	options.timeout_ms = 5000;

	for (int variant = 0; variant < 3; variant++) {
		worker = start_worker(narrowed_stand_in(), 0, &client);
		ATF_REQUIRE_EQ(0, service_session_create(client, &session));
		if (variant == 0) {
			/* A well-formed header carrying a descriptor. */
			outgoing.data = &frame;
			outgoing.length = sizeof(frame);
			outgoing.fds = &pipefd[0];
			outgoing.nfds = 1;
		} else if (variant == 1) {
			/* The pre-FIDL record. */
			outgoing.data = &record;
			outgoing.length = sizeof(record);
			outgoing.fds = NULL;
			outgoing.nfds = 0;
		} else {
			/* An unknown ordinal on a closed protocol. */
			outgoing.data = &frame;
			outgoing.length = sizeof(frame);
			outgoing.fds = NULL;
			outgoing.nfds = 0;
		}
		response.nfds = 0;
		ATF_CHECK_EQ(-1, service_session_call(session, &outgoing,
		    &response, &options));
		ATF_CHECK_EQ(0, response.nfds);
		service_session_close(session);
		ATF_CHECK_EQ(1, reap(worker));
	}
	close(pipefd[0]);
	close(pipefd[1]);
}

ATF_TC(pf_session_lifetime_bounded);
ATF_TC_HEAD(pf_session_lifetime_bounded, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
	atf_tc_set_md_var(tc, "descr", "An idle client cannot hold a PF "
	    "worker: it exits about five seconds after it started");
}
ATF_TC_BODY(pf_session_lifetime_bounded, tc)
{
	struct timespec started, ended;
	long elapsed_ms;
	pid_t worker;
	int client;

	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &started));
	worker = start_worker(narrowed_stand_in(), 0, &client);
	/* Nothing was delivered, so the worker reports 1. */
	ATF_CHECK_EQ(1, reap(worker));
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &ended));
	elapsed_ms = (ended.tv_sec - started.tv_sec) * 1000 +
	    (ended.tv_nsec - started.tv_nsec) / 1000000;
	ATF_CHECK(elapsed_ms >= NETWORK_PF_SESSION_MS - 100);
	ATF_CHECK(elapsed_ms < NETWORK_PF_SESSION_MS * 4);
	close(client);
}

ATF_TC_WITHOUT_HEAD(pf_admission_requires_read_right);
ATF_TC_BODY(pf_admission_requires_read_right, tc)
{

	/* The per-session right main() checks after SwitchBoard's anointment. */
	ATF_CHECK(!network_pf_admit(SERVICE_RIGHTS_NONE));
	ATF_CHECK(!network_pf_admit((service_rights_t)2));
	ATF_CHECK(network_pf_admit(NETWORK_PF_RIGHT_READ));
	ATF_CHECK(network_pf_admit(SERVICE_RIGHTS_ALL));
}

ATF_TC_WITHOUT_HEAD(pf_open_argument);
ATF_TC_BODY(pf_open_argument, tc)
{

	ATF_CHECK_EQ(-1, networkcmp_pf_open(NULL));
	ATF_CHECK_EQ(EINVAL, errno);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, pf_open_delivers_narrowed_descriptor);
	ATF_TP_ADD_TC(tp, pf_open_error_delivers_no_descriptor);
	ATF_TP_ADD_TC(tp, pf_library_refuses_wider_descriptor);
	ATF_TP_ADD_TC(tp, pf_second_request_rejected);
	ATF_TP_ADD_TC(tp, pf_request_before_negotiation_ends_session);
	ATF_TP_ADD_TC(tp, pf_malformed_request_ends_session);
	ATF_TP_ADD_TC(tp, pf_session_lifetime_bounded);
	ATF_TP_ADD_TC(tp, pf_admission_requires_read_right);
	ATF_TP_ADD_TC(tp, pf_open_argument);
	return (atf_no_error());
}
