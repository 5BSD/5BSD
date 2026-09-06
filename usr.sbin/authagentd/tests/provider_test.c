/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Plane-level provider tests for system.AuthAgent.  Each test stands the real
 * handle_request() up over a capability channel (authagentd_test_serve) and
 * drives it as a client, synthesizing the serviced-stamped caller identity
 * directly — which is precisely what lets these tests vary the caller's rights,
 * the dimension serviced would otherwise control.
 *
 * COVERAGE NOTE.  The caller-gate (EPERM) and request-validation (EINVAL) paths
 * answer BEFORE any mint or Casper lookup, so they are driven here end-to-end
 * with no serviced/Casper state (authagentd_test_configure(NULL, NULL, NULL,
 * -1)).  In particular the non-ADMIN caller -> EPERM assertion IS driven over
 * the plane here, because the fixture supplies the identity.  The happy-path
 * mint (returns a session fd) and the unknown-uid ENOENT case require a live
 * serviced bootstrap channel and Casper cap_pwd; those belong to the
 * capd_test_harness stack (a .sh integration test) and are not attempted from
 * this self-contained C provider.  The pure gate_test covers the escalation
 * predicate a second way, independent of the plane.
 *
 * These tests require /dev/mac_capability and so run only under a live plane
 * (a VM); in a sandbox without the device they are compile-only.
 */

#include <sys/param.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include <authagent_proto.h>

#include "authagentd_test.h"

struct fixture {
	struct service_session	*session;
	pid_t			 child;
};

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

/*
 * Bring up authagentd's provider session for one connection, stamping the
 * child's view of the caller with `rights`.  The mint/Casper state is left
 * empty: every test here answers before those are consulted.
 */
static void
fixture_create(struct fixture *fixture, service_rights_t rights)
{
	struct service_identity identity;
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		strlcpy(identity.client_label, "org.test.caller",
		    sizeof(identity.client_label));
		identity.rights = rights;
		authagentd_test_configure(NULL, -1);
		_exit(authagentd_test_serve(provider, &identity) == 0 ? 0 : 1);
	}
	close(provider);
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

static void
fixture_destroy(struct fixture *fixture)
{
	int status;

	service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
}

/*
 * Send `req_len` bytes of `req` (optionally attaching `attach_fd`) and return
 * the daemon's reply.  On a successful round-trip the reply status is stored in
 * *status_out and the number of returned descriptors in *nfds_out.
 */
static int
mint_call(struct service_session *session, const void *req, size_t req_len,
    int attach_fd, int32_t *status_out, size_t *nfds_out)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct authagent_mint_reply reply;
	int fds[1];
	int result;

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = req;
	outgoing.length = req_len;
	if (attach_fd >= 0) {
		outgoing.fds = &attach_fd;
		outgoing.nfds = 1;
	}
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	incoming.fds = fds;
	incoming.fd_capacity = nitems(fds);
	options.timeout_ms = 2000;

	result = service_session_call(session, &outgoing, &incoming, &options);
	if (result == 0) {
		*status_out = incoming.length >= sizeof(reply) ? reply.status :
		    -1;
		*nfds_out = incoming.nfds;
		while (incoming.nfds-- > 0)
			(void)close(fds[incoming.nfds]);
	}
	return (result);
}

static struct authagent_mint_req
well_formed_request(void)
{
	struct authagent_mint_req req;

	memset(&req, 0, sizeof(req));
	req.version = AUTHAGENTD_PROTO_VERSION;
	req.op = AUTHAGENT_OP_MINT_SESSION;
	req.uid = 0;
	req.flags = 0;
	return (req);
}

/*
 * THE escalation regression, driven over the plane: a caller without
 * SERVICE_RIGHTS_ADMIN — modelled as every right but ADMIN — is refused EPERM
 * before any mint, and receives no descriptor.
 */
ATF_TC(non_admin_caller_is_denied_eperm);
ATF_TC_HEAD(non_admin_caller_is_denied_eperm, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A caller lacking SERVICE_RIGHTS_ADMIN is refused a mint (EPERM) "
	    "with no descriptor -- the proxy privilege-escalation guard");
}
ATF_TC_BODY(non_admin_caller_is_denied_eperm, tc)
{
	struct authagent_mint_req req = well_formed_request();
	struct fixture fixture;
	int32_t status;
	size_t nfds;

	fixture_create(&fixture, SERVICE_RIGHTS_ALL & ~SERVICE_RIGHTS_ADMIN);
	ATF_REQUIRE_EQ(0, mint_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EPERM, status);
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);
}

/* A zero-rights (unknown/empty identity) caller is likewise refused EPERM. */
ATF_TC(zero_rights_caller_is_denied_eperm);
ATF_TC_HEAD(zero_rights_caller_is_denied_eperm, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(zero_rights_caller_is_denied_eperm, tc)
{
	struct authagent_mint_req req = well_formed_request();
	struct fixture fixture;
	int32_t status;
	size_t nfds;

	fixture_create(&fixture, SERVICE_RIGHTS_NONE);
	ATF_REQUIRE_EQ(0, mint_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EPERM, status);
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);
}

/*
 * An ADMIN caller sending a malformed request is rejected EINVAL: a bad
 * version, a bad op, reserved flag bits set, a short body, or an unexpected
 * attached descriptor.  Validation runs after the gate but before any mint, so
 * these need no serviced/Casper state.
 */
ATF_TC(admin_caller_malformed_request_is_einval);
ATF_TC_HEAD(admin_caller_malformed_request_is_einval, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(admin_caller_malformed_request_is_einval, tc)
{
	struct fixture fixture;
	struct authagent_mint_req req;
	int32_t status;
	size_t nfds;
	int devnull;

	fixture_create(&fixture, SERVICE_RIGHTS_ADMIN);

	/* Bad protocol version. */
	req = well_formed_request();
	req.version = AUTHAGENTD_PROTO_VERSION + 1;
	ATF_REQUIRE_EQ(0, mint_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	ATF_CHECK_EQ(0, nfds);

	/* Unknown opcode. */
	req = well_formed_request();
	req.op = AUTHAGENT_OP_MINT_SESSION + 99;
	ATF_REQUIRE_EQ(0, mint_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);

	/* Reserved flag bit set. */
	req = well_formed_request();
	req.flags = ~AUTHAGENT_FLAG_FORWARDABLE;
	ATF_REQUIRE_EQ(0, mint_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);

	/* Short body: length != sizeof(req). */
	req = well_formed_request();
	ATF_REQUIRE_EQ(0, mint_call(fixture.session, &req, sizeof(req) - 1, -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);

	/* An unexpected descriptor (fd_count != 0) on the request. */
	devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(devnull >= 0);
	req = well_formed_request();
	ATF_REQUIRE_EQ(0, mint_call(fixture.session, &req, sizeof(req), devnull,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	ATF_CHECK_EQ(0, nfds);
	close(devnull);

	fixture_destroy(&fixture);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, non_admin_caller_is_denied_eperm);
	ATF_TP_ADD_TC(tp, zero_rights_caller_is_denied_eperm);
	ATF_TP_ADD_TC(tp, admin_caller_malformed_request_is_einval);
	return (atf_no_error());
}
