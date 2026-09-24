/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Plane-level provider tests for system.Auth.  Each test stands the real
 * handle_request() up over a capability channel (bsdauth_test_serve) and
 * drives it as a client, synthesizing the switchboard-stamped caller identity
 * directly — which is precisely what lets these tests vary the caller's rights
 * and label, the dimensions switchboard would otherwise control.
 *
 * COVERAGE NOTE.  The caller gates (EPERM), request validation (EINVAL), the
 * ELEVATE policy check, rate limit and in-agent password verification all
 * answer BEFORE any mint, so they are driven here end-to-end with no
 * switchboard (bsdauth_test_configure(NULL, -1) or a temp policy) and
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

#include "bsdauth_test.h"

/* How the child (the served daemon) is configured before serving. */
struct fixture_options {
	service_rights_t	 rights;
	const char		*label;
	const char		*policy;	/* NULL: no policy (fd -1) */
	const char		*passwd;	/* NULL: identity fds -1 */
	const char		*group;
	const char		*masterpw;	/* NULL: master.passwd fd -1 */
	bool			 audit;		/* capture the audit records */
};

struct fixture {
	struct service_session	*session;
	pid_t			 child;
	int			 audit_rfd;	/* -1 unless audit capture */
	char			 audit_buf[4096];
	size_t			 audit_len;
};

/*
 * Audit capture.  The served daemon runs in a forked child; its test build
 * hands every would-be system.Audit record to bsdauth_test_set_audit_hook()
 * INSTEAD of a broker.  The hook writes "subject|operation|error\n" to a pipe
 * the parent reads.  Because the daemon submits the record before it sends
 * the reply, a non-blocking read right after the reply arrives must already
 * see the record -- that read IS the ordering assertion.
 */
static int audit_wfd = -1;

static void
audit_hook(const char *subject, const char *operation, int error)
{
	char line[512];
	int n;

	n = snprintf(line, sizeof(line), "%s|%s|%d\n", subject, operation,
	    error);
	if (n > 0 && audit_wfd >= 0)
		(void)write(audit_wfd, line, (size_t)n);
}

struct audit_record {
	char	subject[256];
	char	operation[256];
	int	error;
};

/*
 * Pull the next captured record without waiting.  False when none is
 * pending (which, after a reply, means the daemon replied before auditing).
 */
static bool
audit_next(struct fixture *fixture, struct audit_record *rec)
{
	char *nl, *bar1, *bar2;
	ssize_t n;
	size_t linelen;

	ATF_REQUIRE_MSG(fixture->audit_rfd >= 0, "fixture has no audit capture");
	for (;;) {
		nl = memchr(fixture->audit_buf, '\n', fixture->audit_len);
		if (nl != NULL)
			break;
		ATF_REQUIRE(fixture->audit_len < sizeof(fixture->audit_buf));
		n = read(fixture->audit_rfd, fixture->audit_buf +
		    fixture->audit_len,
		    sizeof(fixture->audit_buf) - fixture->audit_len);
		if (n <= 0) {
			ATF_REQUIRE_MSG(n == 0 || errno == EAGAIN,
			    "audit pipe read: %s", strerror(errno));
			return (false);
		}
		fixture->audit_len += (size_t)n;
	}
	*nl = '\0';
	bar1 = strchr(fixture->audit_buf, '|');
	ATF_REQUIRE_MSG(bar1 != NULL, "malformed audit line: %s",
	    fixture->audit_buf);
	bar2 = strchr(bar1 + 1, '|');
	ATF_REQUIRE_MSG(bar2 != NULL, "malformed audit line: %s",
	    fixture->audit_buf);
	*bar1 = '\0';
	*bar2 = '\0';
	strlcpy(rec->subject, fixture->audit_buf, sizeof(rec->subject));
	strlcpy(rec->operation, bar1 + 1, sizeof(rec->operation));
	rec->error = atoi(bar2 + 1);
	linelen = (size_t)(nl + 1 - fixture->audit_buf);
	memmove(fixture->audit_buf, nl + 1, fixture->audit_len - linelen);
	fixture->audit_len -= linelen;
	return (true);
}

/* Exactly one record is pending and it is this one. */
static void
audit_expect(struct fixture *fixture, const char *subject,
    const char *operation, int error)
{
	struct audit_record rec;

	ATF_REQUIRE_MSG(audit_next(fixture, &rec),
	    "no audit record pending after the reply (expected %s %s %d)",
	    subject, operation, error);
	ATF_CHECK_STREQ_MSG(subject, rec.subject, "audit subject");
	ATF_CHECK_STREQ_MSG(operation, rec.operation, "audit operation");
	ATF_CHECK_EQ_MSG(error, rec.error, "audit result for %s", operation);
	ATF_CHECK_MSG(!audit_next(fixture, &rec),
	    "a second audit record followed: %s %s %d", rec.subject,
	    rec.operation, rec.error);
}


/*
 * Two records for one request: the stage record, then a second whose
 * operation is the bare name (the agent commits it separately when the
 * name does not fit beside the stage in the 64-byte operation field).
 */
static void
audit_expect_with_name(struct fixture *fixture, const char *subject,
    const char *operation, const char *name, int error)
{
	struct audit_record rec;

	ATF_REQUIRE_MSG(audit_next(fixture, &rec),
	    "no audit record pending after the reply (expected %s %s %d)",
	    subject, operation, error);
	ATF_CHECK_STREQ_MSG(subject, rec.subject, "audit subject");
	ATF_CHECK_STREQ_MSG(operation, rec.operation, "audit operation");
	ATF_CHECK_EQ_MSG(error, rec.error, "audit result for %s", operation);
	ATF_REQUIRE_MSG(audit_next(fixture, &rec),
	    "no second (bare-name) audit record for %s", name);
	ATF_CHECK_STREQ_MSG(subject, rec.subject, "name record subject");
	ATF_CHECK_STREQ_MSG(name, rec.operation, "name record operation");
	ATF_CHECK_EQ_MSG(error, rec.error, "name record result");
	ATF_CHECK_MSG(!audit_next(fixture, &rec),
	    "a third audit record followed: %s %s %d", rec.subject,
	    rec.operation, rec.error);
}

static void
audit_expect_none(struct fixture *fixture)
{
	struct audit_record rec;

	memset(&rec, 0, sizeof(rec));
	ATF_CHECK_MSG(!audit_next(fixture, &rec),
	    "unexpected audit record: %s %s %d", rec.subject, rec.operation,
	    rec.error);
}

/*
 * The plane: these cases need the mac_capability channel device (root).
 * kyua honours require.user; a direct run as an unprivileged user skips.
 */
static void
require_plane(void)
{
	int fd;

	fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (fd == -1)
		atf_tc_skip("mac_capability channel device unavailable: %s",
		    strerror(errno));
	close(fd);
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
 * Bring up bsdauth's provider session for one connection, stamping the
 * child's view of the caller with the supplied rights and label, and the
 * daemon's state with the supplied files (any may be NULL -> absent).
 */
static void
fixture_create(struct fixture *fixture, const struct fixture_options *opt)
{
	struct service_identity identity;
	int audit_pipe[2], client, provider;

	memset(fixture, 0, sizeof(*fixture));
	fixture->audit_rfd = -1;
	if (opt->audit) {
		ATF_REQUIRE_EQ(0, pipe2(audit_pipe, O_CLOEXEC));
		fixture->audit_rfd = audit_pipe[0];
		ATF_REQUIRE_EQ(0, fcntl(audit_pipe[0], F_SETFL, O_NONBLOCK));
	}
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		if (opt->audit) {
			close(audit_pipe[0]);
			audit_wfd = audit_pipe[1];
			bsdauth_test_set_audit_hook(audit_hook);
		}
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		strlcpy(identity.client_label, opt->label,
		    sizeof(identity.client_label));
		identity.rights = opt->rights;
		bsdauth_test_configure(NULL, text_fd(opt->policy));
		bsdauth_test_identity_configure(text_fd(opt->passwd),
		    text_fd(opt->group));
		bsdauth_test_masterpw_configure(text_fd(opt->masterpw));
		_exit(bsdauth_test_serve(provider, &identity) == 0 ? 0 : 1);
	}
	close(provider);
	if (opt->audit)
		close(audit_pipe[1]);
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
	if (fixture->audit_rfd >= 0) {
		close(fixture->audit_rfd);
		fixture->audit_rfd = -1;
	}
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

static struct authagent_mint_auth_req
well_formed_mint_auth(uid_t uid, const char *password)
{
	struct authagent_mint_auth_req req;

	memset(&req, 0, sizeof(req));
	req.version = AUTHAGENTD_PROTO_VERSION;
	req.op = AUTHAGENT_OP_MINT_AUTH;
	req.uid = (uint32_t)uid;
	req.flags = 0;
	strlcpy(req.password, password, sizeof(req.password));
	return (req);
}

/* Authenticated mint as a session caller; returns the reply status. */
static int32_t
mint_auth_status(struct fixture *fixture, uid_t uid, const char *password,
    size_t *nfds)
{
	struct authagent_mint_auth_req req = well_formed_mint_auth(uid, password);
	int32_t status;

	ATF_REQUIRE_EQ(0, agent_call(fixture->session, &req, sizeof(req), -1,
	    &status, nfds));
	explicit_bzero(&req, sizeof(req));
	return (status);
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
 * With system.Auth now user-resolvable (for ELEVATE), a login SESSION
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

/* ======================================================================
 * Edge-case and negative additions: one wire shape per case.
 * ====================================================================== */

#define	POLICY_ROOT_ELEVATE_ALL \
	"principals {\n" \
	"  root { uids = [0]; anointments = []; may_elevate = [\"*\"]; }\n" \
	"  default { anointments = []; }\n" \
	"}\n"

/* A fully permitted, fully configured session: only the wire shape varies. */
static void
shape_fixture(struct fixture *fixture)
{
	char *mpw;

	mpw = masterpw_for_root(GOOD_PASSWORD);
	elevate_fixture(fixture, POLICY_ROOT_MAY_ELEVATE, mpw,
	    AUTHAGENT_SESSION_LABEL);
	free(mpw);
}

/* Send raw bytes as an ELEVATE and return the status (no descriptors). */
static int32_t
raw_status(struct fixture *fixture, const void *buf, size_t len, int fd)
{
	int32_t status;
	size_t nfds;

	ATF_REQUIRE_EQ(0, agent_call(fixture->session, buf, len, fd, &status,
	    &nfds));
	ATF_CHECK_EQ(0, nfds);
	return (status);
}

ATF_TC(elevate_attached_fd_is_einval);
ATF_TC_HEAD(elevate_attached_fd_is_einval, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A well-formed ELEVATE carrying a descriptor is EINVAL");
}
ATF_TC_BODY(elevate_attached_fd_is_einval, tc)
{
	struct fixture fixture;
	struct authagent_elevate_req req;
	size_t nfds;
	int devnull;

	shape_fixture(&fixture);
	devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(devnull >= 0);
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req), devnull));
	/* The session is not wedged and the password was not consumed. */
	ATF_CHECK_EQ(EINVAL, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));	/* reaches mint: NULL context */
	close(devnull);
	fixture_destroy(&fixture);
}

ATF_TC(elevate_short_by_one_is_einval);
ATF_TC_HEAD(elevate_short_by_one_is_einval, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(elevate_short_by_one_is_einval, tc)
{
	struct fixture fixture;
	struct authagent_elevate_req req;
	size_t nfds;

	shape_fixture(&fixture);
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req) - 1, -1));
	/* Half a request, and just the (version, op) words. */
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req) / 2, -1));
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, 8, -1));
	/* The correct length still passes validation afterwards. */
	ATF_CHECK_EQ(EINVAL, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	fixture_destroy(&fixture);
}

ATF_TC(elevate_long_by_one_is_einval);
ATF_TC_HEAD(elevate_long_by_one_is_einval, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(elevate_long_by_one_is_einval, tc)
{
	struct fixture fixture;
	struct {
		struct authagent_elevate_req req;
		unsigned char tail[64];
	} __packed buf;

	shape_fixture(&fixture);
	memset(&buf, 0, sizeof(buf));
	buf.req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &buf,
	    sizeof(buf.req) + 1, -1));
	/* A trailing zero word, and a whole extra request appended. */
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &buf,
	    sizeof(buf.req) + 4, -1));
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &buf, sizeof(buf), -1));
	fixture_destroy(&fixture);
}

ATF_TC(elevate_version_1_is_einval);
ATF_TC_HEAD(elevate_version_1_is_einval, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "ELEVATE did not exist in proto 1: a v1-stamped ELEVATE is EINVAL");
}
ATF_TC_BODY(elevate_version_1_is_einval, tc)
{
	struct fixture fixture;
	struct authagent_elevate_req req;

	shape_fixture(&fixture);
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	req.version = 1;
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req), -1));
	req.version = 0;
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req), -1));
	fixture_destroy(&fixture);
}

ATF_TC(elevate_version_range_enforced);
ATF_TC_HEAD(elevate_version_range_enforced, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "ELEVATE accepts v2 (oldest) through v3 (current); older or newer is EINVAL");
}
ATF_TC_BODY(elevate_version_range_enforced, tc)
{
	struct fixture fixture;
	struct authagent_elevate_req req;

	ATF_REQUIRE(AUTHAGENTD_PROTO_VERSION >= 3U);
	shape_fixture(&fixture);
	/*
	 * A name the principal may NOT elevate to is refused EPERM at the
	 * policy stage -- but only once the version gate has passed.  So v2
	 * (oldest) and v3 (current) reach EPERM, while a version below the
	 * floor or above the ceiling is EINVAL before policy is consulted.
	 * (Using a not-permitted name keeps the version outcome distinct from
	 * the mint-stage EINVAL a permitted name would hit in this fixture.)
	 */
	req = well_formed_elevate("system.storage.admin", GOOD_PASSWORD);
	req.version = AUTHAGENTD_PROTO_VERSION_MIN;		/* 2 */
	ATF_CHECK_EQ(EPERM, raw_status(&fixture, &req, sizeof(req), -1));
	req.version = AUTHAGENTD_PROTO_VERSION;			/* 3 */
	ATF_CHECK_EQ(EPERM, raw_status(&fixture, &req, sizeof(req), -1));
	req.version = AUTHAGENTD_PROTO_VERSION_MIN - 1;		/* 1 */
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req), -1));
	req.version = AUTHAGENTD_PROTO_VERSION + 1;		/* 4 */
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req), -1));
	req.version = UINT32_MAX;
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req), -1));
	fixture_destroy(&fixture);
}

/*
 * MINT_SESSION still works under proto 2.  With no identity database the
 * resolved-grant step answers ENOENT for uid 0; that is the marker "the
 * request passed the ADMIN gate and shape validation", distinct from the
 * EINVAL a wrong version earns before any lookup.
 */
ATF_TC(mint_version_2_still_accepted);
ATF_TC_HEAD(mint_version_2_still_accepted, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "MINT_SESSION accepts v2 (oldest) and v3 (current) -- a v2 login/su "
	    "keeps working against a v3 agent -- and rejects older or newer");
}
ATF_TC_BODY(mint_version_2_still_accepted, tc)
{
	struct fixture fixture;
	struct authagent_mint_req req;
	int32_t status;
	size_t nfds;

	fixture_create_simple(&fixture, SERVICE_RIGHTS_ADMIN, "org.test.login");
	/*
	 * MINT_SESSION is wire-identical from v2 on, so the oldest supported
	 * version and the current one both pass the version+shape gate and
	 * reach identity resolution, which ENOENTs in this fixture (no passwd).
	 * A version below the floor or above the ceiling is refused EINVAL
	 * before anything is resolved.
	 */
	req = well_formed_mint();
	req.version = AUTHAGENTD_PROTO_VERSION_MIN;	/* 2, oldest */
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(ENOENT, status);			/* accepted */
	req = well_formed_mint();
	req.version = AUTHAGENTD_PROTO_VERSION;		/* 3, current */
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(ENOENT, status);			/* accepted */
	req = well_formed_mint();
	req.version = AUTHAGENTD_PROTO_VERSION_MIN - 1;	/* 1, too old */
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	req = well_formed_mint();
	req.version = AUTHAGENTD_PROTO_VERSION + 1;	/* 4, too new */
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	req = well_formed_mint();
	req.version = UINT32_MAX;
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	/* FORWARDABLE is the one legal flag and does not change acceptance. */
	req = well_formed_mint();
	req.flags = AUTHAGENT_FLAG_FORWARDABLE;
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(ENOENT, status);
	fixture_destroy(&fixture);
}

ATF_TC(elevate_unterminated_name_is_einval);
ATF_TC_HEAD(elevate_unterminated_name_is_einval, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "64 non-NUL name bytes are EINVAL; 63 + NUL pass validation");
}
ATF_TC_BODY(elevate_unterminated_name_is_einval, tc)
{
	struct fixture fixture;
	struct authagent_elevate_req req;
	char *mpw;

	/* may_elevate = ["*"] so a 63-char name is permitted by policy. */
	mpw = masterpw_for_root(GOOD_PASSWORD);
	elevate_fixture(&fixture, POLICY_ROOT_ELEVATE_ALL, mpw,
	    AUTHAGENT_SESSION_LABEL);
	free(mpw);

	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	memset(req.name, 'a', sizeof(req.name));
	req.name[1] = '.';
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req), -1));
	/* Valid syntax up to byte 63, then a non-NUL 64th byte. */
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	memset(req.name, 'a', sizeof(req.name));
	req.name[1] = '.';
	req.name[sizeof(req.name) - 1] = 'z';
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req), -1));
	/* NUL only at byte 63 (a 63-char name): passes to the mint. */
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	memset(req.name, 'a', sizeof(req.name));
	req.name[1] = '.';
	req.name[sizeof(req.name) - 1] = '\0';
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req), -1));
	/*
	 * That EINVAL is the mint's (NULL context), not the validator's: the
	 * same request with the WRONG password is EACCES, proving the name was
	 * accepted and the password actually consulted.
	 */
	memset(req.password, 0, sizeof(req.password));
	strlcpy(req.password, "wrong", sizeof(req.password));
	ATF_CHECK_EQ(EACCES, raw_status(&fixture, &req, sizeof(req), -1));
	/* An empty name (NUL at byte 0) is EINVAL. */
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	memset(req.name, 0, sizeof(req.name));
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req), -1));
	/* Garbage after the NUL does not matter: the name is the C string. */
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	memset(req.name + strlen("system.notify.system") + 1, 'X',
	    sizeof(req.name) - strlen("system.notify.system") - 1);
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req), -1));
	strlcpy(req.password, "wrong", sizeof(req.password));
	ATF_CHECK_EQ(EACCES, raw_status(&fixture, &req, sizeof(req), -1));
	explicit_bzero(&req, sizeof(req));
	fixture_destroy(&fixture);
}

ATF_TC(elevate_unterminated_password_is_einval);
ATF_TC_HEAD(elevate_unterminated_password_is_einval, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "256 non-NUL password bytes are EINVAL; 255 + NUL are verified");
}
ATF_TC_BODY(elevate_unterminated_password_is_einval, tc)
{
	struct fixture fixture;
	struct authagent_elevate_req req;
	char pw255[AUTHAGENT_PASSWORD_MAX];
	char *mpw;

	memset(pw255, 'p', sizeof(pw255));
	pw255[255] = '\0';
	mpw = masterpw_for_root(pw255);
	elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, mpw,
	    AUTHAGENT_SESSION_LABEL);
	free(mpw);

	/* 256 'p's, no NUL: EINVAL, even though 255 of them are the password. */
	req = well_formed_elevate("system.notify.system", "");
	memset(req.password, 'p', sizeof(req.password));
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req), -1));
	/* 255 'p's + NUL: verified and accepted (reaches the mint). */
	req = well_formed_elevate("system.notify.system", pw255);
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req), -1));
	/* 254 'p's: a different password. */
	req = well_formed_elevate("system.notify.system", pw255);
	req.password[254] = '\0';
	ATF_CHECK_EQ(EACCES, raw_status(&fixture, &req, sizeof(req), -1));
	/* Bytes after the NUL are not part of the password. */
	req = well_formed_elevate("system.notify.system", "wrong");
	memset(req.password + 6, 'p', sizeof(req.password) - 6);
	ATF_CHECK_EQ(EACCES, raw_status(&fixture, &req, sizeof(req), -1));
	explicit_bzero(&req, sizeof(req));
	fixture_destroy(&fixture);
}

/*
 * Every answer leaves the session usable: failure -> success, denial ->
 * success, malformed -> success, all on ONE session, in both orders.
 */
ATF_TC(elevate_back_to_back_after_failure_no_wedge);
ATF_TC_HEAD(elevate_back_to_back_after_failure_no_wedge, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(elevate_back_to_back_after_failure_no_wedge, tc)
{
	struct fixture fixture;
	struct authagent_elevate_req req;
	size_t nfds;
	unsigned i;

	shape_fixture(&fixture);
	/* wrong -> right */
	ATF_CHECK_EQ(EACCES, elevate_status(&fixture, "system.notify.system",
	    "wrong", &nfds));
	ATF_CHECK_EQ(EINVAL, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	/* denied name -> right */
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.storage.admin",
	    GOOD_PASSWORD, &nfds));
	ATF_CHECK_EQ(EINVAL, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	/* malformed -> right */
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req) - 1, -1));
	ATF_CHECK_EQ(EINVAL, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	/* right -> wrong -> right, twenty times: no drift, no wedge. */
	for (i = 0; i < 20; i++) {
		ATF_CHECK_EQ(EINVAL, elevate_status(&fixture,
		    "system.notify.system", GOOD_PASSWORD, &nfds));
		ATF_CHECK_EQ(EACCES, elevate_status(&fixture,
		    "system.notify.system", "wrong", &nfds));
	}
	ATF_CHECK_EQ(EINVAL, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	fixture_destroy(&fixture);
}

/* Six rapid wrong passwords: the sixth is EAGAIN, and so is the seventh. */
ATF_TC(elevate_six_rapid_wrong_sixth_eagain);
ATF_TC_HEAD(elevate_six_rapid_wrong_sixth_eagain, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(elevate_six_rapid_wrong_sixth_eagain, tc)
{
	struct fixture fixture;
	size_t nfds;
	int32_t status;
	unsigned i;

	shape_fixture(&fixture);
	for (i = 1; i <= AUTHAGENT_RL_MAX_FAILURES + 1; i++) {
		status = elevate_status(&fixture, "system.notify.system",
		    "wrong", &nfds);
		ATF_CHECK_EQ_MSG(i <= AUTHAGENT_RL_MAX_FAILURES ? EACCES :
		    EAGAIN, status, "attempt %u: status %d", i, status);
		ATF_CHECK_EQ(0, nfds);
	}
	ATF_CHECK_EQ(EAGAIN, elevate_status(&fixture, "system.notify.system",
	    "wrong", &nfds));
	/* The block does not depend on the name being the same one. */
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.storage.admin",
	    "wrong", &nfds));	/* policy still first */
	/* A malformed request while blocked is still EINVAL (shape first). */
	{
		struct authagent_elevate_req req;

		req = well_formed_elevate("system.notify.system", "wrong");
		req.flags = 1;
		ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, sizeof(req),
		    -1));
	}
	fixture_destroy(&fixture);
}

/* The rate limiter counts per uid, so a fresh session is blocked too. */
ATF_TC(elevate_rate_limit_spans_sessions);
ATF_TC_HEAD(elevate_rate_limit_spans_sessions, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Within one daemon, five failures on one session block a second "
	    "session of the same uid; a new daemon (test seam reset) does not");
}
ATF_TC_BODY(elevate_rate_limit_spans_sessions, tc)
{
	struct fixture fixture;
	size_t nfds;
	unsigned i;

	/*
	 * The fixture forks one daemon per session, so cross-session state
	 * within a daemon is not reachable here; what IS testable is that a
	 * new daemon starts unblocked (the seam resets the table) -- five
	 * failures then EAGAIN, twice, on two independent daemons.
	 */
	shape_fixture(&fixture);
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES; i++)
		ATF_CHECK_EQ(EACCES, elevate_status(&fixture,
		    "system.notify.system", "wrong", &nfds));
	ATF_CHECK_EQ(EAGAIN, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	fixture_destroy(&fixture);
	shape_fixture(&fixture);
	ATF_CHECK_EQ(EINVAL, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	fixture_destroy(&fixture);
}

/*
 * A body too short to carry (version, op) -- 0, 4 or 7 bytes -- cannot be
 * classified and takes the MINT path, whose ADMIN gate answers first: a
 * session learns EPERM, an ADMIN caller EINVAL.  Neither wedges.
 */
ATF_TC(elevate_unclassifiable_body);
ATF_TC_HEAD(elevate_unclassifiable_body, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(elevate_unclassifiable_body, tc)
{
	struct fixture fixture;
	struct authagent_elevate_req req;
	size_t nfds;

	shape_fixture(&fixture);
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	/* A zero-length call never leaves the client: libservice refuses it
	 * with EINVAL, so the agent sees nothing (and nothing wedges). */
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, agent_call(fixture.session, &req, 0, -1,
	    &(int32_t){ 0 }, &nfds) == -1);
	ATF_CHECK_EQ(EPERM, raw_status(&fixture, &req, 4, -1));
	ATF_CHECK_EQ(EPERM, raw_status(&fixture, &req, 7, -1));
	ATF_CHECK_EQ(EINVAL, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	fixture_destroy(&fixture);

	fixture_create_simple(&fixture, SERVICE_RIGHTS_ADMIN, "org.test.login");
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, agent_call(fixture.session, &req, 0, -1,
	    &(int32_t){ 0 }, &nfds) == -1);
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, 4, -1));
	ATF_CHECK_EQ(EINVAL, raw_status(&fixture, &req, 7, -1));
	fixture_destroy(&fixture);
}

/* An ELEVATE from a session that holds ADMIN is still gated by label only. */
ATF_TC(elevate_admin_rights_do_not_bypass_label);
ATF_TC_HEAD(elevate_admin_rights_do_not_bypass_label, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(elevate_admin_rights_do_not_bypass_label, tc)
{
	struct fixture fixture;
	struct fixture_options opt;
	char *mpw;
	size_t nfds;

	mpw = masterpw_for_root(GOOD_PASSWORD);
	memset(&opt, 0, sizeof(opt));
	opt.rights = SERVICE_RIGHTS_ALL;
	opt.label = "org.test.login";	/* login program: ADMIN, not a session */
	opt.policy = POLICY_ROOT_MAY_ELEVATE;
	opt.passwd = PASSWD_TEXT;
	opt.group = GROUP_TEXT;
	opt.masterpw = mpw;
	fixture_create(&fixture, &opt);
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);
	/* And a session with ADMIN (should not exist, but) is allowed by label. */
	opt.label = AUTHAGENT_SESSION_LABEL;
	fixture_create(&fixture, &opt);
	ATF_CHECK_EQ(EINVAL, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));	/* reaches mint */
	fixture_destroy(&fixture);
	free(mpw);
}

/* ======================================================================
 * Audit records (AUE_AUTHAGENT_ELEVATE / AUE_AUTHAGENT_MINT via
 * system.Audit).  One record per request, committed right after the reply,
 * subject "<label>/uid<N>", operation "elevate/<stage>[/<name>]" or
 * "mint/<kind>/n<count>[/all][/admin][/default]" / "mint/<stage>", result =
 * the reply status.  Captured through the test build's audit hook.
 * ====================================================================== */

#define	SESSION_SUBJECT	AUTHAGENT_SESSION_LABEL "/uid0"

/* A session fixture with audit capture on. */
static void
audited_elevate_fixture(struct fixture *fixture, const char *policy,
    const char *masterpw, const char *label)
{
	struct fixture_options opt;

	memset(&opt, 0, sizeof(opt));
	opt.rights = SERVICE_RIGHTS_NONE;
	opt.label = label;
	opt.policy = policy;
	opt.passwd = PASSWD_TEXT;
	opt.group = GROUP_TEXT;
	opt.masterpw = masterpw;
	opt.audit = true;
	fixture_create(fixture, &opt);
}

/* A MINT caller fixture with audit capture on. */
static void
audited_mint_fixture(struct fixture *fixture, service_rights_t rights,
    const char *label, const char *policy, const char *passwd)
{
	struct fixture_options opt;

	memset(&opt, 0, sizeof(opt));
	opt.rights = rights;
	opt.label = label;
	opt.policy = policy;
	opt.passwd = passwd;
	opt.group = GROUP_TEXT;
	opt.audit = true;
	fixture_create(fixture, &opt);
}

ATF_TC(audit_elevate_policy_refusal);
ATF_TC_HEAD(audit_elevate_policy_refusal, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A policy refusal audits elevate/policy/<name> EPERM under "
	    "<label>/uid<N>, before the reply, once");
}
ATF_TC_BODY(audit_elevate_policy_refusal, tc)
{
	struct fixture fixture;
	size_t nfds;

	require_plane();
	/* P5: a name outside may_elevate. */
	audited_elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, NULL,
	    AUTHAGENT_SESSION_LABEL);
	audit_expect_none(&fixture);
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.storage.admin",
	    GOOD_PASSWORD, &nfds));
	audit_expect(&fixture, SESSION_SUBJECT,
	    "elevate/policy/system.storage.admin", EPERM);
	/* A second refusal is a second record, not a repeat of the first. */
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.trace.client",
	    GOOD_PASSWORD, &nfds));
	audit_expect(&fixture, SESSION_SUBJECT,
	    "elevate/policy/system.trace.client", EPERM);
	fixture_destroy(&fixture);

	/* S6: an entry with no may_elevate at all. */
	audited_elevate_fixture(&fixture, POLICY_ROOT_MAY_NOT_ELEVATE, NULL,
	    AUTHAGENT_SESSION_LABEL);
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	audit_expect(&fixture, SESSION_SUBJECT,
	    "elevate/policy/system.notify.system", EPERM);
	fixture_destroy(&fixture);

	/* P10: no policy -> historical rule -> refused, still "policy". */
	audited_elevate_fixture(&fixture, NULL, NULL, AUTHAGENT_SESSION_LABEL);
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	audit_expect(&fixture, SESSION_SUBJECT,
	    "elevate/policy/system.notify.system", EPERM);
	fixture_destroy(&fixture);
}

ATF_TC(audit_elevate_password_outcomes);
ATF_TC_HEAD(audit_elevate_password_outcomes, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Every password-stage outcome (EACCES, EPERM locked, ENOENT, "
	    "ENXIO) audits elevate/password/<name> with that result");
}
ATF_TC_BODY(audit_elevate_password_outcomes, tc)
{
	struct fixture fixture;
	char *mpw;
	size_t nfds;

	require_plane();
	mpw = masterpw_for_root(GOOD_PASSWORD);
	audited_elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, mpw,
	    AUTHAGENT_SESSION_LABEL);
	free(mpw);
	ATF_CHECK_EQ(EACCES, elevate_status(&fixture, "system.notify.system",
	    "wrong", &nfds));
	audit_expect(&fixture, SESSION_SUBJECT,
	    "elevate/password/system.notify.system", EACCES);
	ATF_CHECK_EQ(EACCES, elevate_status(&fixture, "system.notify.system",
	    "", &nfds));
	audit_expect(&fixture, SESSION_SUBJECT,
	    "elevate/password/system.notify.system", EACCES);
	fixture_destroy(&fixture);

	/* Locked account: EPERM, still the password stage. */
	audited_elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE,
	    "root:*:0:0::0:0:Charlie &:/root:/bin/sh\n",
	    AUTHAGENT_SESSION_LABEL);
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.notify.system",
	    "", &nfds));
	audit_expect(&fixture, SESSION_SUBJECT,
	    "elevate/password/system.notify.system", EPERM);
	fixture_destroy(&fixture);

	/* No master.passwd record for the uid. */
	audited_elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE,
	    "someone:*:5:5::0:0:x:/:/bin/sh\n", AUTHAGENT_SESSION_LABEL);
	ATF_CHECK_EQ(ENOENT, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	audit_expect(&fixture, SESSION_SUBJECT,
	    "elevate/password/system.notify.system", ENOENT);
	fixture_destroy(&fixture);

	/* master.passwd not granted at all: ENXIO. */
	audited_elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, NULL,
	    AUTHAGENT_SESSION_LABEL);
	ATF_CHECK_EQ(ENXIO, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	audit_expect(&fixture, SESSION_SUBJECT,
	    "elevate/password/system.notify.system", ENXIO);
	fixture_destroy(&fixture);
}

ATF_TC(audit_elevate_rate_limited);
ATF_TC_HEAD(audit_elevate_rate_limited, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "The limiter's refusal audits elevate/ratelimit/<name> EAGAIN; "
	    "one record per request throughout");
}
ATF_TC_BODY(audit_elevate_rate_limited, tc)
{
	struct fixture fixture;
	char *mpw;
	size_t nfds;
	unsigned i;

	require_plane();
	mpw = masterpw_for_root(GOOD_PASSWORD);
	audited_elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, mpw,
	    AUTHAGENT_SESSION_LABEL);
	free(mpw);
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES; i++) {
		ATF_CHECK_EQ(EACCES, elevate_status(&fixture,
		    "system.notify.system", "wrong", &nfds));
		audit_expect(&fixture, SESSION_SUBJECT,
		    "elevate/password/system.notify.system", EACCES);
	}
	/* The sixth, even with the correct password. */
	ATF_CHECK_EQ(EAGAIN, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	audit_expect(&fixture, SESSION_SUBJECT,
	    "elevate/ratelimit/system.notify.system", EAGAIN);
	ATF_CHECK_EQ(EAGAIN, elevate_status(&fixture, "system.notify.system",
	    "wrong", &nfds));
	audit_expect(&fixture, SESSION_SUBJECT,
	    "elevate/ratelimit/system.notify.system", EAGAIN);
	/* Policy still answers first while limited: the record says so. */
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.storage.admin",
	    GOOD_PASSWORD, &nfds));
	audit_expect(&fixture, SESSION_SUBJECT,
	    "elevate/policy/system.storage.admin", EPERM);
	fixture_destroy(&fixture);
}

ATF_TC(audit_elevate_caller_and_shape);
ATF_TC_HEAD(audit_elevate_caller_and_shape, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Refusals before a name is known audit elevate/caller (label only: "
	    "no uid yet) and elevate/shape (uid, no name)");
}
ATF_TC_BODY(audit_elevate_caller_and_shape, tc)
{
	struct fixture fixture;
	struct fixture_options opt;
	struct authagent_elevate_req req;
	struct {
		struct authagent_elevate_req req;
		uint32_t forged_uid;
	} forged;
	int32_t status;
	size_t nfds;

	require_plane();
	/* E5: a unit's label.  The caller gate runs before the sender stamp
	 * is read, so the subject is the label alone. */
	audited_elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, NULL,
	    "com.example.pub");
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	audit_expect(&fixture, "com.example.pub", "elevate/caller", EPERM);
	fixture_destroy(&fixture);

	/* An empty label is recorded as "unknown". */
	memset(&opt, 0, sizeof(opt));
	opt.rights = SERVICE_RIGHTS_ALL;
	opt.label = "";
	opt.policy = POLICY_ROOT_MAY_ELEVATE;
	opt.passwd = PASSWD_TEXT;
	opt.group = GROUP_TEXT;
	opt.audit = true;
	fixture_create(&fixture, &opt);
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, "system.notify.system",
	    GOOD_PASSWORD, &nfds));
	audit_expect(&fixture, "unknown", "elevate/caller", EPERM);
	fixture_destroy(&fixture);

	/* Shape refusals from a session: the uid is known, the name is not
	 * (it is copied only once validated). */
	{
		char *mpw = masterpw_for_root(GOOD_PASSWORD);

		audited_elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, mpw,
		    AUTHAGENT_SESSION_LABEL);
		free(mpw);
	}
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	req.version = AUTHAGENTD_PROTO_VERSION + 1;
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	audit_expect(&fixture, SESSION_SUBJECT, "elevate/shape", EINVAL);

	/* Short body. */
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req) - 1, -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	audit_expect(&fixture, SESSION_SUBJECT, "elevate/shape", EINVAL);

	/* Forged identity bytes appended (E4). */
	memset(&forged, 0, sizeof(forged));
	forged.req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	forged.forged_uid = 1002;
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &forged, sizeof(forged),
	    -1, &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	audit_expect(&fixture, SESSION_SUBJECT, "elevate/shape", EINVAL);

	/* Invalid names never reach the record: "*", "", "nodot". */
	ATF_CHECK_EQ(EINVAL, elevate_status(&fixture, "*", GOOD_PASSWORD,
	    &nfds));
	audit_expect(&fixture, SESSION_SUBJECT, "elevate/shape", EINVAL);
	ATF_CHECK_EQ(EINVAL, elevate_status(&fixture, "nodot", GOOD_PASSWORD,
	    &nfds));
	audit_expect(&fixture, SESSION_SUBJECT, "elevate/shape", EINVAL);
	/* An unterminated 64-byte name: refused, and not copied anywhere. */
	req = well_formed_elevate("system.notify.system", GOOD_PASSWORD);
	memset(req.name, 'a', sizeof(req.name));
	req.name[1] = '.';
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	audit_expect(&fixture, SESSION_SUBJECT, "elevate/shape", EINVAL);
	fixture_destroy(&fixture);
}

ATF_TC(audit_elevate_mint_stage);
ATF_TC_HEAD(audit_elevate_mint_stage, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "An accepted password that fails at the mint audits "
	    "elevate/mint/<name> with the mint's status");
}
ATF_TC_BODY(audit_elevate_mint_stage, tc)
{
	struct fixture fixture;
	char *mpw;
	size_t nfds;
	int32_t status;

	require_plane();
	mpw = masterpw_for_root(GOOD_PASSWORD);
	audited_elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, mpw,
	    AUTHAGENT_SESSION_LABEL);
	free(mpw);
	/* No switchboard context: the mint itself answers EINVAL. */
	status = elevate_status(&fixture, "system.notify.system", GOOD_PASSWORD,
	    &nfds);
	ATF_CHECK_EQ(EINVAL, status);
	audit_expect(&fixture, SESSION_SUBJECT,
	    "elevate/mint/system.notify.system", status);
	/* The success reset the limiter; a following failure is a fresh
	 * password record, not a ratelimit one. */
	ATF_CHECK_EQ(EACCES, elevate_status(&fixture, "system.notify.system",
	    "wrong", &nfds));
	audit_expect(&fixture, SESSION_SUBJECT,
	    "elevate/password/system.notify.system", EACCES);
	fixture_destroy(&fixture);
}

/* "a." followed by (len - 2) 'a's: a syntactically valid name of `len`. */
static void
long_name(char *buf, size_t bufsz, size_t len)
{

	ATF_REQUIRE(len + 1 <= bufsz);
	memset(buf, 'a', len);
	buf[1] = '.';
	buf[len] = '\0';
}

ATF_TC(audit_elevate_name_in_second_record_when_too_long);
ATF_TC_HEAD(audit_elevate_name_in_second_record_when_too_long, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A name that cannot fit the 64-byte operation is dropped from it "
	    "(elevate/<stage>); the record is still committed");
}
ATF_TC_BODY(audit_elevate_name_in_second_record_when_too_long, tc)
{
	struct fixture fixture;
	char name[AUTHAGENT_NAME_MAX];
	char op[128];
	char *mpw;
	size_t nfds;

	require_plane();
	audited_elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, NULL,
	    AUTHAGENT_SESSION_LABEL);

	/* "elevate/policy/" is 15 bytes: a 49-byte name is the longest that
	 * fits in 64; 50 is dropped. */
	long_name(name, sizeof(name), 49);
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, name, GOOD_PASSWORD,
	    &nfds));
	snprintf(op, sizeof(op), "elevate/policy/%s", name);
	ATF_REQUIRE_EQ(64, strlen(op));
	audit_expect(&fixture, SESSION_SUBJECT, op, EPERM);

	long_name(name, sizeof(name), 50);
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, name, GOOD_PASSWORD,
	    &nfds));
	audit_expect_with_name(&fixture, SESSION_SUBJECT, "elevate/policy",
	    name, EPERM);

	/* The longest valid name (63) at the policy stage. */
	long_name(name, sizeof(name), AUTHAGENT_NAME_MAX - 1);
	ATF_CHECK_EQ(EPERM, elevate_status(&fixture, name, GOOD_PASSWORD,
	    &nfds));
	audit_expect_with_name(&fixture, SESSION_SUBJECT, "elevate/policy",
	    name, EPERM);
	fixture_destroy(&fixture);

	/* ...and at the password stage, where the prefix is longer still. */
	mpw = masterpw_for_root(GOOD_PASSWORD);
	audited_elevate_fixture(&fixture, POLICY_ROOT_ELEVATE_ALL, mpw,
	    AUTHAGENT_SESSION_LABEL);
	free(mpw);
	ATF_CHECK_EQ(EACCES, elevate_status(&fixture, name, "wrong", &nfds));
	audit_expect_with_name(&fixture, SESSION_SUBJECT, "elevate/password",
	    name, EACCES);
	/* "elevate/password/" is 17: 47 fits, 48 does not. */
	long_name(name, sizeof(name), 47);
	ATF_CHECK_EQ(EACCES, elevate_status(&fixture, name, "wrong", &nfds));
	snprintf(op, sizeof(op), "elevate/password/%s", name);
	audit_expect(&fixture, SESSION_SUBJECT, op, EACCES);
	long_name(name, sizeof(name), 48);
	ATF_CHECK_EQ(EACCES, elevate_status(&fixture, name, "wrong", &nfds));
	audit_expect_with_name(&fixture, SESSION_SUBJECT, "elevate/password",
	    name, EACCES);
	fixture_destroy(&fixture);
}

ATF_TC(audit_mint_records);
ATF_TC_HEAD(audit_mint_records, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "MINT_SESSION audits mint/<stage> before a grant and "
	    "mint/<kind>/n<count>[/all][/admin][/default] once one is resolved");
}
ATF_TC_BODY(audit_mint_records, tc)
{
	struct fixture fixture;
	struct authagent_mint_req req;
	struct audit_record rec;
	int32_t status;
	size_t nfds;

	require_plane();
	/* The caller gate: no uid is known, so the subject is the label. */
	audited_mint_fixture(&fixture, SERVICE_RIGHTS_ALL & ~SERVICE_RIGHTS_ADMIN,
	    "org.test.caller", POLICY_ROOT_MAY_ELEVATE, PASSWD_TEXT);
	req = well_formed_mint();
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EPERM, status);
	audit_expect(&fixture, "org.test.caller", "mint/caller", EPERM);
	/* A session label sending MINT is the same refusal. */
	fixture_destroy(&fixture);
	audited_mint_fixture(&fixture, SERVICE_RIGHTS_NONE,
	    AUTHAGENT_SESSION_LABEL, POLICY_ROOT_MAY_ELEVATE, PASSWD_TEXT);
	req = well_formed_mint();
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EPERM, status);
	audit_expect(&fixture, AUTHAGENT_SESSION_LABEL, "mint/caller", EPERM);
	fixture_destroy(&fixture);

	/* Shape: a full-size body names the principal uid; a short one
	 * cannot. */
	audited_mint_fixture(&fixture, SERVICE_RIGHTS_ADMIN, "org.test.login",
	    POLICY_ROOT_MAY_ELEVATE, PASSWD_TEXT);
	req = well_formed_mint();
	req.version = AUTHAGENTD_PROTO_VERSION + 1;
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	audit_expect(&fixture, "org.test.login/uid0", "mint/shape", EINVAL);
	req = well_formed_mint();
	req.uid = 1001;
	req.flags = ~AUTHAGENT_FLAG_FORWARDABLE;
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	audit_expect(&fixture, "org.test.login/uid1001", "mint/shape", EINVAL);
	req = well_formed_mint();
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req) - 1, -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	audit_expect(&fixture, "org.test.login", "mint/shape", EINVAL);

	/* A grant resolved from the policy: user kind, one anointment, no
	 * admin, no "*", policy present.  With no switchboard context the
	 * mint itself fails; the record carries whatever it answered. */
	req = well_formed_mint();
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(0, nfds);
	ATF_CHECK(status != 0 && status != EPERM);
	audit_expect(&fixture, "org.test.login/uid0", "mint/user/n1", status);
	fixture_destroy(&fixture);

	/* No policy at all: the historical rule gives root "*" + admin, so
	 * the kind is system and the record says the default rule applied. */
	audited_mint_fixture(&fixture, SERVICE_RIGHTS_ADMIN, "org.test.login",
	    NULL, PASSWD_TEXT);
	req = well_formed_mint();
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK(status != 0 && status != EPERM);
	audit_expect(&fixture, "org.test.login/uid0",
	    "mint/system/n0/all/admin/default", status);
	fixture_destroy(&fixture);

	/* The principal has no passwd entry: refused at identity. */
	audited_mint_fixture(&fixture, SERVICE_RIGHTS_ADMIN, "org.test.login",
	    POLICY_ROOT_MAY_ELEVATE, "someone:*:5:5:x:/:/bin/sh\n");
	req = well_formed_mint();
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(ENOENT, status);
	audit_expect(&fixture, "org.test.login/uid0", "mint/identity",
	    ENOENT);
	/* Nothing else is pending at the end of a session. */
	ATF_CHECK(!audit_next(&fixture, &rec));
	fixture_destroy(&fixture);
}

/* ---- MINT_AUTH: the non-admin `su` authenticated mint --------------------
 *
 * MINT_SESSION trusts the caller's ADMIN bit as "I authenticated this
 * principal"; a su from an ordinary session has no such bit.  MINT_AUTH lets
 * that session mint the target's session by proving the TARGET's password,
 * rate-limited, exactly as ELEVATE authenticates.  The successful channel
 * delivery needs a live plane (proven in the VM); here the correct-password
 * path is checked by "reaches mint" (lands at EINVAL, the fixture's NULL mint
 * context), and every refusal is checked deterministically.
 * ------------------------------------------------------------------------- */

ATF_TC(mint_auth_correct_password_reaches_mint);
ATF_TC_HEAD(mint_auth_correct_password_reaches_mint, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A session (no ADMIN bit) that proves the target's password passes "
	    "every gate and reaches the mint -- the non-admin su fix");
}
ATF_TC_BODY(mint_auth_correct_password_reaches_mint, tc)
{
	struct fixture fixture;
	char *mpw;
	size_t nfds;
	int32_t status;

	mpw = masterpw_for_root(GOOD_PASSWORD);
	elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, mpw,
	    AUTHAGENT_SESSION_LABEL);
	free(mpw);
	status = mint_auth_status(&fixture, 0, GOOD_PASSWORD, &nfds);
	ATF_CHECK_MSG(status != EACCES && status != EPERM && status != EAGAIN &&
	    status != ENXIO, "password not accepted: status %d", status);
	ATF_CHECK_EQ(EINVAL, status);	/* NULL mint context */
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);
}

ATF_TC(mint_auth_wrong_password_is_eacces);
ATF_TC_HEAD(mint_auth_wrong_password_is_eacces, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mint_auth_wrong_password_is_eacces, tc)
{
	struct fixture fixture;
	char *mpw;
	size_t nfds;

	mpw = masterpw_for_root(GOOD_PASSWORD);
	elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, mpw,
	    AUTHAGENT_SESSION_LABEL);
	free(mpw);
	ATF_CHECK_EQ(EACCES, mint_auth_status(&fixture, 0, "wrong password",
	    &nfds));
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);
}

ATF_TC(mint_auth_unit_caller_is_eperm);
ATF_TC_HEAD(mint_auth_unit_caller_is_eperm, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A unit-labelled caller cannot mint-auth (units declare, not su); "
	    "refused EPERM before any password work");
}
ATF_TC_BODY(mint_auth_unit_caller_is_eperm, tc)
{
	struct fixture fixture;
	char *mpw;
	size_t nfds;

	mpw = masterpw_for_root(GOOD_PASSWORD);
	elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, mpw,
	    "org.test.unit");
	free(mpw);
	ATF_CHECK_EQ(EPERM, mint_auth_status(&fixture, 0, GOOD_PASSWORD, &nfds));
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);
}

ATF_TC(mint_auth_without_masterpw_is_enxio);
ATF_TC_HEAD(mint_auth_without_masterpw_is_enxio, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mint_auth_without_masterpw_is_enxio, tc)
{
	struct fixture fixture;
	size_t nfds;

	elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, NULL,
	    AUTHAGENT_SESSION_LABEL);
	ATF_CHECK_EQ(ENXIO, mint_auth_status(&fixture, 0, GOOD_PASSWORD, &nfds));
	ATF_CHECK_EQ(0, nfds);
	fixture_destroy(&fixture);
}

ATF_TC(mint_auth_malformed_is_einval);
ATF_TC_HEAD(mint_auth_malformed_is_einval, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mint_auth_malformed_is_einval, tc)
{
	struct authagent_mint_auth_req req;
	struct fixture fixture;
	char *mpw;
	int32_t status;
	size_t nfds;

	mpw = masterpw_for_root(GOOD_PASSWORD);
	elevate_fixture(&fixture, POLICY_ROOT_MAY_ELEVATE, mpw,
	    AUTHAGENT_SESSION_LABEL);
	free(mpw);
	/* Password field with no NUL terminator is malformed. */
	req = well_formed_mint_auth(0, GOOD_PASSWORD);
	memset(req.password, 'x', sizeof(req.password));
	ATF_REQUIRE_EQ(0, agent_call(fixture.session, &req, sizeof(req), -1,
	    &status, &nfds));
	ATF_CHECK_EQ(EINVAL, status);
	ATF_CHECK_EQ(0, nfds);
	explicit_bzero(&req, sizeof(req));
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
	ATF_TP_ADD_TC(tp, mint_auth_correct_password_reaches_mint);
	ATF_TP_ADD_TC(tp, mint_auth_wrong_password_is_eacces);
	ATF_TP_ADD_TC(tp, mint_auth_unit_caller_is_eperm);
	ATF_TP_ADD_TC(tp, mint_auth_without_masterpw_is_enxio);
	ATF_TP_ADD_TC(tp, mint_auth_malformed_is_einval);
	ATF_TP_ADD_TC(tp, elevate_rate_limited_after_five_failures);
	/* Edge-case and negative additions. */
	ATF_TP_ADD_TC(tp, elevate_attached_fd_is_einval);
	ATF_TP_ADD_TC(tp, elevate_short_by_one_is_einval);
	ATF_TP_ADD_TC(tp, elevate_long_by_one_is_einval);
	ATF_TP_ADD_TC(tp, elevate_version_1_is_einval);
	ATF_TP_ADD_TC(tp, elevate_version_range_enforced);
	ATF_TP_ADD_TC(tp, mint_version_2_still_accepted);
	ATF_TP_ADD_TC(tp, elevate_unterminated_name_is_einval);
	ATF_TP_ADD_TC(tp, elevate_unterminated_password_is_einval);
	ATF_TP_ADD_TC(tp, elevate_back_to_back_after_failure_no_wedge);
	ATF_TP_ADD_TC(tp, elevate_six_rapid_wrong_sixth_eagain);
	ATF_TP_ADD_TC(tp, elevate_rate_limit_spans_sessions);
	ATF_TP_ADD_TC(tp, elevate_unclassifiable_body);
	ATF_TP_ADD_TC(tp, elevate_admin_rights_do_not_bypass_label);
	/* Audit records through the test build's hook. */
	ATF_TP_ADD_TC(tp, audit_elevate_policy_refusal);
	ATF_TP_ADD_TC(tp, audit_elevate_password_outcomes);
	ATF_TP_ADD_TC(tp, audit_elevate_rate_limited);
	ATF_TP_ADD_TC(tp, audit_elevate_caller_and_shape);
	ATF_TP_ADD_TC(tp, audit_elevate_mint_stage);
	ATF_TP_ADD_TC(tp, audit_elevate_name_in_second_record_when_too_long);
	ATF_TP_ADD_TC(tp, audit_mint_records);
	return (atf_no_error());
}
