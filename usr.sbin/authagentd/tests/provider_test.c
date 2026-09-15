/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Plane-level provider tests for system.AuthAgent.  Each test stands the real
 * handle_request() up over a capability channel (authagentd_test_serve) and
 * drives it as a client, synthesizing the switchboard-stamped caller identity
 * directly — which is precisely what lets these tests vary the caller's rights
 * and label, the dimensions switchboard would otherwise control.
 *
 * COVERAGE NOTE.  The caller gates (EPERM), request validation (EINVAL), the
 * ELEVATE policy check, rate limit and in-agent password verification all
 * answer BEFORE any mint, so they are driven here end-to-end with no
 * switchboard (authagentd_test_configure(NULL, -1) or a temp policy) and
 * synthetic identity / master.passwd descriptors.  A successful mint (returns
 * a session fd) requires a live switchboard bootstrap channel; with none the
 * mint answers EINVAL, which these tests use as the marker "the password was
 * accepted and the request reached the mint".  The live happy paths are in
 * elevate_integration_test.sh.  The pure elevate_test covers each decision a
 * second way, independent of the plane.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include <authagent_proto.h>

#include "authagentd_test.h"

/* How the child (the served daemon) is configured before serving. */
struct fixture_options {
	service_rights_t	 rights;
	const char		*label;
	const char		*policy;	/* NULL: no policy (fd -1) */
	const char		*passwd;	/* NULL: identity fds -1 */
	const char		*group;
	const char		*masterpw;	/* NULL: master.passwd fd -1 */
};

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

/* Write `text` to an unlinked temp file and return a read-only fd. */
static int
text_fd(const char *text)
{
	char path[] = "/tmp/authagent_provider.XXXXXX";
	int fd, rfd;

	if (text == NULL)
		return (-1);
	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ((ssize_t)strlen(text), write(fd, text, strlen(text)));
	rfd = open(path, O_RDONLY);
	ATF_REQUIRE(rfd >= 0);
	(void)unlink(path);
	(void)close(fd);
	return (rfd);
}

/*
 * Bring up authagentd's provider session for one connection, stamping the
 * child's view of the caller with the supplied rights and label, and the
 * daemon's state with the supplied files (any may be NULL -> absent).
 */
static void
fixture_create(struct fixture *fixture, const struct fixture_options *opt)
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
		strlcpy(identity.client_label, opt->label,
		    sizeof(identity.client_label));
		identity.rights = opt->rights;
		authagentd_test_configure(NULL, text_fd(opt->policy));
		authagentd_test_identity_configure(text_fd(opt->passwd),
		    text_fd(opt->group));
		authagentd_test_masterpw_configure(text_fd(opt->masterpw));
		_exit(authagentd_test_serve(provider, &identity) == 0 ? 0 : 1);
	}
	close(provider);
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

static void
fixture_create_simple(struct fixture *fixture, service_rights_t rights,
    const char *label)
{
	struct fixture_options opt;

	memset(&opt, 0, sizeof(opt));
	opt.rights = rights;
	opt.label = label;
	fixture_create(fixture, &opt);
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
agent_call(struct service_session *session, const void *req, size_t req_len,
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
	options.timeout_ms = 5000;

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
well_formed_mint(void)
{
	struct authagent_mint_req req;

	memset(&req, 0, sizeof(req));
	req.version = AUTHAGENTD_PROTO_VERSION;
	req.op = AUTHAGENT_OP_MINT_SESSION;
	req.uid = 0;
	req.flags = 0;
	return (req);
}

static struct authagent_elevate_req
well_formed_elevate(const char *name, const char *password)
{
	struct authagent_elevate_req req;

	memset(&req, 0, sizeof(req));
	req.version = AUTHAGENTD_PROTO_VERSION;
	req.op = AUTHAGENT_OP_ELEVATE;
	strlcpy(req.name, name, sizeof(req.name));
	strlcpy(req.password, password, sizeof(req.password));
	return (req);
}

/* Elevate as the caller and return only the reply status. */
static int32_t
elevate_status(struct fixture *fixture, const char *name,
    const char *password, size_t *nfds)
{
	struct authagent_elevate_req req = well_formed_elevate(name, password);
	int32_t status;

	ATF_REQUIRE_EQ(0, agent_call(fixture->session, &req, sizeof(req), -1,
	    &status, nfds));
	explicit_bzero(&req, sizeof(req));
	return (status);
}

/*
 * The test runs as root, so the kernel stamps every request with uid 0 --
 * the identity the daemon resolves.  Synthetic databases give uid 0 a
 * policy entry of the test's choosing, so the ELEVATE decision can be
 * driven in both directions without depending on the host's real policy.
 */
#define	PASSWD_TEXT \
	"root:*:0:0:Charlie &:/root:/bin/sh\n" \
	"capability:*:976:976:Capability:/nonexistent:/usr/sbin/nologin\n"
#define	GROUP_TEXT \
	"wheel:*:0:root\n" \
	"operators:*:500:root\n"
#define	POLICY_ROOT_MAY_ELEVATE \
	"principals {\n" \
	"  root { uids = [0]; anointments = [\"system.trace.client\"];" \
	" may_elevate = [\"system.notify.system\"]; admin_rights = false; }\n" \
	"  default { anointments = []; }\n" \
	"}\n"
#define	POLICY_ROOT_MAY_NOT_ELEVATE \
	"principals {\n" \
	"  root { uids = [0]; anointments = [\"system.trace.client\"]; }\n" \
	"  default { anointments = []; }\n" \
	"}\n"
#define	GOOD_PASSWORD	"correct horse battery staple"

static char *
masterpw_for_root(const char *password)
{
	char *hash, *text;

	hash = crypt(password, "$6$providertestsalt$");
	ATF_REQUIRE(hash != NULL);
	ATF_REQUIRE(asprintf(&text,
	    "root:%s:0:0::0:0:Charlie &:/root:/bin/sh\n"
	    "capability:*:976:976::0:0:Capability:/nonexistent:/usr/sbin/nologin\n",
	    hash) > 0);
	return (text);
}

static void
elevate_fixture(struct fixture *fixture, const char *policy,
    const char *masterpw, const char *label)
{
	struct fixture_options opt;

	memset(&opt, 0, sizeof(opt));
	opt.rights = SERVICE_RIGHTS_NONE;	/* a session: no ADMIN bit */
	opt.label = label;
	opt.policy = policy;
	opt.passwd = PASSWD_TEXT;
	opt.group = GROUP_TEXT;
	opt.masterpw = masterpw;
	fixture_create(fixture, &opt);
}

/* ---- MINT: the caller gate is unchanged --------------------------------- */

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
	struct authagent_mint_req req = well_formed_mint();
	struct fixture fixture;
	int32_t status;
	size_t nfds;

	fixture_create_simple(&fixture, SERVICE_RIGHTS_ALL & ~SERVICE_RIGHTS_ADMIN,
	    "org.test.caller");
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
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
	struct authagent_mint_req req = well_formed_mint();
	struct fixture fixture;
	int32_t status;
	size_t nfds;

	fixture_create_simple(&fixture, SERVICE_RIGHTS_NONE, "org.test.caller");
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EPERM, status);
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);
}

/*
 * With system.authagent now user-resolvable (for ELEVATE), a login SESSION
 * that sends MINT_SESSION{uid=0} is still refused: the MINT gate is the held
 * ADMIN right, not the label, and a session is stamped without it.  This is
 * the guard that keeps "open to sessions" meaning "ELEVATE only".
 */
ATF_TC(session_caller_cannot_mint);
ATF_TC_HEAD(session_caller_cannot_mint, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A session-labelled caller without ADMIN is refused MINT_SESSION");
}
ATF_TC_BODY(session_caller_cannot_mint, tc)
{
	struct authagent_mint_req req = well_formed_mint();
	struct fixture fixture;
	int32_t status;
	size_t nfds;

	fixture_create_simple(&fixture, SERVICE_RIGHTS_NONE,
	    AUTHAGENT_SESSION_LABEL);
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EPERM, status);
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);
}

/*
 * An ADMIN caller sending a malformed request is rejected EINVAL: a bad
 * version, a bad op, reserved flag bits set, a short body, or an unexpected
 * attached descriptor.  Validation runs after the gate but before any mint, so
 * these need no switchboard or identity state.
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

	fixture_create_simple(&fixture, SERVICE_RIGHTS_ADMIN, "org.test.login");

	/* Bad protocol version. */
	req = well_formed_mint();
	req.version = AUTHAGENTD_PROTO_VERSION + 1;
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	ATF_CHECK_EQ(0, nfds);

	/* Unknown opcode. */
	req = well_formed_mint();
	req.op = AUTHAGENT_OP_ELEVATE + 99;
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);

	/* Reserved flag bit set. */
	req = well_formed_mint();
	req.flags = ~AUTHAGENT_FLAG_FORWARDABLE;
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);

	/* Short body: length != sizeof(req). */
	req = well_formed_mint();
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req) - 1, -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);

	/* Too short to even carry (version, op). */
	req = well_formed_mint();
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, 4, -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);

	/* An unexpected descriptor (fd_count != 0) on the request. */
	devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(devnull >= 0);
	req = well_formed_mint();
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), devnull,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	ATF_CHECK_EQ(0, nfds);
	close(devnull);

	fixture_destroy(&fixture);
}

/* ---- ELEVATE ------------------------------------------------------------- */

/* E5: a unit -- even one holding every right -- cannot elevate. */
ATF_TC(elevate_unit_label_is_eperm);
ATF_TC_HEAD(elevate_unit_label_is_eperm, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "E5: ELEVATE from a unit's channel is EPERM; units declare");
}
ATF_TC_BODY(elevate_unit_label_is_eperm, tc)
{
	struct fixture fixture;
	size_t nfds;

	elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE,
	    NULL /* no master.passwd: would be ENXIO if reached */,
	    "com.example.pub");
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);

	/* Nor with every right, nor with an empty label. */
	{
		struct fixture_options opt;

		memset(&opt, 0, sizeof(opt));
		opt.rights = SERVICE_RIGHTS_ALL;
		opt.label = "system.Switchboard";
		opt.policy = POLICY_ROOT_MAY_ELEVATE;
		opt.passwd = PASSWD_TEXT;
		opt.group = GROUP_TEXT;
		fixture_create(&fixture, &opt);
		ATF_CHECK_EQ(EPERM, elevate_status(&fixture,
		    "system.notify.system", GOOD_PASSWORD, &nfds));
		fixture_destroy(&fixture);

		opt.label = "";
		fixture_create(&fixture, &opt);
		ATF_CHECK_EQ(EPERM, elevate_status(&fixture,
		    "system.notify.system", GOOD_PASSWORD, &nfds));
		fixture_destroy(&fixture);
	}
}

/*
 * S6 / P5: a session whose principal may not elevate to NAME is refused
 * EPERM before the password path.  master.passwd is deliberately absent:
 * had the password been consulted the answer would be ENXIO, not EPERM.
 */
ATF_TC(elevate_name_not_permitted_is_eperm_before_password);
ATF_TC_HEAD(elevate_name_not_permitted_is_eperm_before_password, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "S6/P5: a name outside may_elevate is EPERM without any password check");
}
ATF_TC_BODY(elevate_name_not_permitted_is_eperm_before_password, tc)
{
	struct fixture fixture;
	size_t nfds;

	/* P5: operator-like entry, a different name. */
	elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, NULL,
	    AUTHAGENT_SESSION_LABEL);
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.storage.admin",
	    GOOD_PASSWORD, &nfds));
	ATF_CHECK_EQ(0, nfds);
	/* A name held from login is not thereby elevatable either. */
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.trace.client",
	    GOOD_PASSWORD, &nfds));
	fixture_destroy(&fixture);

	/* S6: an entry with no may_elevate at all. */
	elevate_fixture(&fixture, POLICY_ROOT_MAY_NOT_ELEVATE, NULL,
	    AUTHAGENT_SESSION_LABEL);
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);

	/* P10: no policy at all -> historical rule -> nobody elevates. */
	elevate_fixture(&fixture, NULL, NULL, AUTHAGENT_SESSION_LABEL);
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	fixture_destroy(&fixture);
}

/*
 * E4: identity comes only from the kernel stamp.  The payload has no uid
 * field to forge, so the only way to smuggle one is extra bytes -- which is
 * a malformed request -- or a MINT_SESSION{uid} request, which the ADMIN
 * gate refuses (session_caller_cannot_mint).  And the uid that IS used is
 * the sender's: with a policy where uid 0 may not elevate, no payload can
 * change the answer.
 */
ATF_TC(elevate_payload_identity_is_ignored);
ATF_TC_HEAD(elevate_payload_identity_is_ignored, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "E4: a request with forged identity bytes appended is EINVAL; "
	    "the decision uses the kernel-stamped sender uid");
}
ATF_TC_BODY(elevate_payload_identity_is_ignored, tc)
{
	struct fixture fixture;
	struct {
		struct authagent_elevate_req req;
		uint32_t forged_uid;
		char forged_label[64];
	} forged;
	int32_t status;
	size_t nfds;

	elevate_fixture(&fixture, POLICY_ROOT_MAY_NOT_ELEVATE, NULL,
	    AUTHAGENT_SESSION_LABEL);
	memset(&forged, 0, sizeof(forged));
	forged.req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	forged.forged_uid = 1002;
	strlcpy(forged.forged_label, AUTHAGENT_SESSION_LABEL,
	    sizeof(forged.forged_label));
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &forged, sizeof(forged),
	    -1, &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);
}

/* Malformed ELEVATE requests from a session are EINVAL, never anything else. */
ATF_TC(elevate_malformed_is_einval);
ATF_TC_HEAD(elevate_malformed_is_einval, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(elevate_malformed_is_einval, tc)
{
	struct fixture fixture;
	struct authagent_elevate_req req;
	int32_t status;
	size_t nfds;
	int devnull;

	/* Everything is permitted and configured: only the shape is wrong. */
	{
		char *mpw = masterpw_for_root(GOOD_PASSWORD);

		elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, mpw,
		    AUTHAGENT_SESSION_LABEL);
		free(mpw);
	}

	/* Bad version. */
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	req.version = AUTHAGENTD_PROTO_VERSION + 1;
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	ATF_CHECK_EQ(0, nfds);

	/* Flags set. */
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	req.flags = 1;
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);

	/* Reserved set. */
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	req.reserved = 1;
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);

	/* Short body. */
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req) - 1, -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);

	/* A MINT-sized body with the ELEVATE op. */
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req,
	    sizeof(struct authagent_mint_req), -1, &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);

	/* Attached descriptor. */
	devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(devnull >= 0);
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), devnull,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	ATF_CHECK_EQ(0, nfds);
	close(devnull);

	/* Unterminated name. */
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	memset(req.name, 'a', sizeof(req.name));
	req.name[1] = '.';
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);

	/* Unterminated password. */
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	memset(req.password, 'p', sizeof(req.password));
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);

	/* "*" and other non-names are requests for nothing. */
	req = well_formed_elevate("*", GOOD_PASSWORD);
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	req = well_formed_elevate("", GOOD_PASSWORD);
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	req = well_formed_elevate("nodot", GOOD_PASSWORD);
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);

	/* And the well-formed one still gets past validation (reaches mint). */
	ATF_CHECK_EQ(EINVAL, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);
}

/* P4: a wrong password fails closed (EACCES), no channel. */
ATF_TC(elevate_wrong_password_is_eacces);
ATF_TC_HEAD(elevate_wrong_password_is_eacces, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "P4: wrong password -> EACCES, no descriptor; locked -> EPERM");
}
ATF_TC_BODY(elevate_wrong_password_is_eacces, tc)
{
	struct fixture fixture;
	char *mpw;
	size_t nfds;

	mpw = masterpw_for_root(GOOD_PASSWORD);
	elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, mpw,
	    AUTHAGENT_SESSION_LABEL);
	free(mpw);
	ATF_CHECK_EQ(EACCES, elevate_status(&fixture, "system.notify.system",
	    "wrong", &nfds));
	ATF_CHECK_EQ(0, nfds);
	ATF_CHECK_EQ(EACCES, elevate_status(&fixture, "system.notify.system",
	    "", &nfds));
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);

	/* A locked account (the stock "*" hash) is EPERM, even with "". */
	elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE,
	    "root:*:0:0::0:0:Charlie &:/root:/bin/sh\n",
	    AUTHAGENT_SESSION_LABEL);
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.notify.system",
	    "", &nfds));
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);

	/* No master.passwd record for the uid. */
	elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE,
	    "someone:*:5:5::0:0:x:/:/bin/sh\n", AUTHAGENT_SESSION_LABEL);
	ATF_CHECK_EQ(ENOENT, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	fixture_destroy(&fixture);
}

/*
 * P3 (up to the mint): the correct password is accepted.  With no
 * switchboard context the mint itself answers EINVAL, which is the marker
 * that the policy, rate-limit and password stages all passed; the live
 * mint is elevate_integration_test.sh.
 */
ATF_TC(elevate_correct_password_reaches_mint);
ATF_TC_HEAD(elevate_correct_password_reaches_mint, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(elevate_correct_password_reaches_mint, tc)
{
	struct fixture fixture;
	char *mpw;
	size_t nfds;
	int32_t status;

	mpw = masterpw_for_root(GOOD_PASSWORD);
	elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, mpw,
	    AUTHAGENT_SESSION_LABEL);
	free(mpw);
	status = elevate_status(&fixture, "system.notify.system", GOOD_PASSWORD,
	    &nfds);
	ATF_CHECK_MSG(status != EACCES && status != EPERM && status != EAGAIN &&
	    status != ENXIO, "password not accepted: status %d", status);
	ATF_CHECK_EQ(EINVAL, status);	/* NULL mint context */
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);
}

/* master.passwd not granted: ELEVATE fails closed (ENXIO), MINT unaffected. */
ATF_TC(elevate_without_masterpw_is_enxio);
ATF_TC_HEAD(elevate_without_masterpw_is_enxio, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(elevate_without_masterpw_is_enxio, tc)
{
	struct fixture fixture;
	size_t nfds;

	elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, NULL,
	    AUTHAGENT_SESSION_LABEL);
	ATF_CHECK_EQ(ENXIO, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);
}

/*
 * Rate limit over the plane: five wrong passwords, then the sixth request
 * -- even with the CORRECT password -- is EAGAIN without a password check.
 */
ATF_TC(elevate_rate_limited_after_five_failures);
ATF_TC_HEAD(elevate_rate_limited_after_five_failures, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(elevate_rate_limited_after_five_failures, tc)
{
	struct fixture fixture;
	char *mpw;
	size_t nfds;
	unsigned i;

	mpw = masterpw_for_root(GOOD_PASSWORD);
	elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, mpw,
	    AUTHAGENT_SESSION_LABEL);
	free(mpw);
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES; i++)
		ATF_CHECK_EQ(EACCES, elevate_status(&fixture,
		    "system.notify.system", "wrong", &nfds));
	ATF_CHECK_EQ(EAGAIN, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	ATF_CHECK_EQ(0, nfds);
	ATF_CHECK_EQ(EAGAIN, elevate_status(&fixture, "system.notify.system",
	    "wrong", &nfds));
	/* Policy still answers first: a forbidden name is EPERM, not EAGAIN. */
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.storage.admin",
	    GOOD_PASSWORD, &nfds));
	fixture_destroy(&fixture);

	/* Four failures then success (reaches mint) does not lock out. */
	mpw = masterpw_for_root(GOOD_PASSWORD);
	elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, mpw,
	    AUTHAGENT_SESSION_LABEL);
	free(mpw);
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES - 1; i++)
		ATF_CHECK_EQ(EACCES, elevate_status(&fixture,
		    "system.notify.system", "wrong", &nfds));
	ATF_CHECK_EQ(EINVAL, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	/* ...and the counter was reset by that success. */
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES - 1; i++)
		ATF_CHECK_EQ(EACCES, elevate_status(&fixture,
		    "system.notify.system", "wrong", &nfds));
	ATF_CHECK_EQ(EINVAL, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	fixture_destroy(&fixture);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, non_admin_caller_is_denied_eperm);
	ATF_TP_ADD_TC(tp, zero_rights_caller_is_denied_eperm);
	ATF_TP_ADD_TC(tp, session_caller_cannot_mint);
	ATF_TP_ADD_TC(tp, admin_caller_malformed_request_is_einval);
	ATF_TP_ADD_TC(tp, elevate_unit_label_is_eperm);
	ATF_TP_ADD_TC(tp, elevate_name_not_permitted_is_eperm_before_password);
	ATF_TP_ADD_TC(tp, elevate_payload_identity_is_ignored);
	ATF_TP_ADD_TC(tp, elevate_malformed_is_einval);
	ATF_TP_ADD_TC(tp, elevate_wrong_password_is_eacces);
	ATF_TP_ADD_TC(tp, elevate_correct_password_reaches_mint);
	ATF_TP_ADD_TC(tp, elevate_without_masterpw_is_enxio);
	ATF_TP_ADD_TC(tp, elevate_rate_limited_after_five_failures);
	return (atf_no_error());
}
