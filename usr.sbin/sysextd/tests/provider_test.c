/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Plane-level suite for sysextd(8): drive the REAL per-client request handler
 * (sysext_worker -> sysext_request) over a REAL mac_capability channel via the
 * -DSYSEXTD_TESTING serve entry point, and assert the fail-closed reply framing.
 *
 * These cases require the capability plane (/dev/mac_capability + the stack
 * kmods) and root; they skip cleanly where the plane is absent.  None of them
 * exercises the ENSURE happy path, so no kldload(2) ever runs: every case is
 * refused by the allow-list or the message validator before ensure_extension is
 * reached, and we assert only the decision and the reply framing.
 */

#include <sys/param.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "sysext_proto.h"
#include "sysextd.h"

struct fixture {
	struct service_session	*session;
	pid_t			 child;
};

static void
require_plane(void)
{
	int fd;

	fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (fd == -1)
		atf_tc_skip("mac_capability device unavailable: %s",
		    strerror(errno));
	close(fd);
}

static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE_MSG(control >= 0, "open mac_capability: %s", strerror(errno));
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
 * Stand up a worker serving cfg as its resolved allow-list on one end of a fresh
 * channel and a client service_session on the other.
 */
static void
fixture_create_cfg(struct fixture *fixture, const struct sysext_config *cfg)
{
	int client, provider;

	require_plane();
	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(sysext_test_serve(provider, "test.client", cfg));
	}
	close(provider);
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

/*
 * Convenience wrapper: serve the default (built-in) allow-list.
 */
static void
fixture_create(struct fixture *fixture)
{
	struct sysext_config cfg;

	sysext_config_defaults(&cfg);
	fixture_create_cfg(fixture, &cfg);
}

/*
 * Build a config whose allow-list is exactly the single module name, so a plane
 * test can STAT a name it controls (e.g. one guaranteed loaded, or one
 * guaranteed absent) while still exercising the real allow-list gate.
 */
static void
config_allow_one(struct sysext_config *cfg, const char *name)
{

	memset(cfg, 0, sizeof(*cfg));
	strlcpy(cfg->allow[0], name, SYSEXT_NAME_MAX);
	cfg->nallow = 1;
}

static void
fixture_destroy(struct fixture *fixture)
{
	int status;

	service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_CHECK(WIFEXITED(status));
}

/*
 * Issue one request and return the reply status.  data/length describe the
 * exact wire bytes to send (so a test can send an intentionally wrong length);
 * fd, when >= 0, is attached to the message.  Requires that a reply arrives.
 */
static int
call_status(struct fixture *fixture, const void *data, size_t length, int fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct sysext_reply reply;

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = data;
	outgoing.length = length;
	if (fd >= 0) {
		outgoing.fds = &fd;
		outgoing.nfds = 1;
	}
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 2000;
	ATF_REQUIRE_EQ(0,
	    service_session_call(fixture->session, &outgoing, &incoming, &options));
	ATF_REQUIRE_EQ(sizeof(reply), incoming.length);
	return (reply.status);
}

static struct sysext_request
ensure_request(const char *name)
{
	struct sysext_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = SYSEXT_OP_ENSURE;
	if (name != NULL)
		strlcpy(rq.name, name, sizeof(rq.name));
	return (rq);
}

static struct sysext_request
stat_request(const char *name)
{
	struct sysext_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = SYSEXT_OP_STAT;
	if (name != NULL)
		strlcpy(rq.name, name, sizeof(rq.name));
	return (rq);
}

/*
 * Issue one STAT request and return the full stat reply (status + loaded).
 * data/length describe the exact wire bytes so a test can send a wrong length;
 * fd, when >= 0, is attached.  Requires that a correctly framed reply arrives.
 */
static struct sysext_stat_reply
call_stat(struct fixture *fixture, const void *data, size_t length, int fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct sysext_stat_reply reply;

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = data;
	outgoing.length = length;
	if (fd >= 0) {
		outgoing.fds = &fd;
		outgoing.nfds = 1;
	}
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 2000;
	ATF_REQUIRE_EQ(0,
	    service_session_call(fixture->session, &outgoing, &incoming, &options));
	ATF_REQUIRE_EQ(sizeof(reply), incoming.length);
	return (reply);
}

/*
 * THE plane-level security regression: an ENSURE for a module that is not on
 * the allow-list is refused with EPERM (fail-closed), never loaded — even though
 * the name is syntactically valid and the client already reached the provider.
 */
ATF_TC(provider_denies_non_allowlisted_module);
ATF_TC_HEAD(provider_denies_non_allowlisted_module, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_denies_non_allowlisted_module, tc)
{
	struct fixture fixture;
	struct sysext_request rq;

	fixture_create(&fixture);
	rq = ensure_request("evil");
	ATF_CHECK_EQ(EPERM, call_status(&fixture, &rq, sizeof(rq), -1));
	/* Syntactically valid dotted name, still not allow-listed. */
	rq = ensure_request("if_evil.ko");
	ATF_CHECK_EQ(EPERM, call_status(&fixture, &rq, sizeof(rq), -1));
	fixture_destroy(&fixture);
}

/*
 * An unknown opcode is rejected with EINVAL before any load decision.
 */
ATF_TC(provider_rejects_unknown_op);
ATF_TC_HEAD(provider_rejects_unknown_op, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_rejects_unknown_op, tc)
{
	struct fixture fixture;
	struct sysext_request rq;

	fixture_create(&fixture);
	rq = ensure_request("cryptodev");
	rq.op = 0xdead;
	ATF_CHECK_EQ(EINVAL, call_status(&fixture, &rq, sizeof(rq), -1));
	fixture_destroy(&fixture);
}

/*
 * A request whose module name is not NUL-terminated within the wire buffer (an
 * oversized/unterminated name) is rejected with EINVAL — the validator refuses
 * it rather than reading past the field.
 */
ATF_TC(provider_rejects_unterminated_name);
ATF_TC_HEAD(provider_rejects_unterminated_name, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_rejects_unterminated_name, tc)
{
	struct fixture fixture;
	struct sysext_request rq;

	fixture_create(&fixture);
	memset(&rq, 0, sizeof(rq));
	rq.op = SYSEXT_OP_ENSURE;
	memset(rq.name, 'a', sizeof(rq.name));	/* no NUL in the name field */
	ATF_CHECK_EQ(EINVAL, call_status(&fixture, &rq, sizeof(rq), -1));
	fixture_destroy(&fixture);
}

/*
 * A message of the wrong length is malformed and rejected with EPROTO (the
 * length check runs before any name/allow-list decision).
 */
ATF_TC(provider_rejects_wrong_length);
ATF_TC_HEAD(provider_rejects_wrong_length, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_rejects_wrong_length, tc)
{
	struct fixture fixture;
	struct sysext_request rq;

	fixture_create(&fixture);
	rq = ensure_request("cryptodev");
	/* Short by one byte: length != sizeof(struct sysext_request). */
	ATF_CHECK_EQ(EPROTO, call_status(&fixture, &rq, sizeof(rq) - 1, -1));
	fixture_destroy(&fixture);
}

/*
 * A request that carries an unexpected descriptor is malformed: sysextd takes
 * no descriptors on this interface, so an attached fd is rejected with EPROTO.
 */
ATF_TC(provider_rejects_attached_descriptor);
ATF_TC_HEAD(provider_rejects_attached_descriptor, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_rejects_attached_descriptor, tc)
{
	struct fixture fixture;
	struct sysext_request rq;
	int fd;

	fixture_create(&fixture);
	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	rq = ensure_request("cryptodev");
	ATF_CHECK_EQ(EPROTO, call_status(&fixture, &rq, sizeof(rq), fd));
	close(fd);
	fixture_destroy(&fixture);
}

/*
 * STAT of an allow-listed module that IS loaded reports loaded=1, status 0,
 * without loading anything.  "kernel" (the running kernel image, fileid 1) is
 * guaranteed present in any kernel, so the allow-list is set to exactly
 * {"kernel"} for this case and kldfind(2) must find it.
 *
 * kldfind(2) is a read-only query and is not gated (module enumeration is
 * deliberately open), so the query succeeds in any environment and loaded=1
 * is asserted unconditionally.
 */
ATF_TC(provider_stat_reports_loaded_module);
ATF_TC_HEAD(provider_stat_reports_loaded_module, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_stat_reports_loaded_module, tc)
{
	struct sysext_config cfg;
	struct sysext_stat_reply reply;
	struct fixture fixture;
	struct sysext_request rq;

	config_allow_one(&cfg, "kernel");
	fixture_create_cfg(&fixture, &cfg);
	rq = stat_request("kernel");
	reply = call_stat(&fixture, &rq, sizeof(rq), -1);
	ATF_CHECK_EQ(0, reply.status);
	ATF_CHECK_EQ(1, reply.loaded);
	fixture_destroy(&fixture);
}

/*
 * STAT of an allow-listed module that is NOT loaded reports loaded=0, status 0
 * (a completed query, not an error).  The allow-list is set to a single made-up
 * name that no kernel has loaded, so kldfind(2) returns ENOENT and the handler
 * maps that to the not-loaded answer.  kldfind is ungated, so the assertion is
 * unconditional.
 */
ATF_TC(provider_stat_reports_unloaded_module);
ATF_TC_HEAD(provider_stat_reports_unloaded_module, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_stat_reports_unloaded_module, tc)
{
	struct sysext_config cfg;
	struct sysext_stat_reply reply;
	struct fixture fixture;
	struct sysext_request rq;

	config_allow_one(&cfg, "sysext_absent_mod");
	fixture_create_cfg(&fixture, &cfg);
	rq = stat_request("sysext_absent_mod");
	reply = call_stat(&fixture, &rq, sizeof(rq), -1);
	ATF_CHECK_EQ(0, reply.status);
	ATF_CHECK_EQ(0, reply.loaded);
	fixture_destroy(&fixture);
}

/*
 * THE STAT security regression: a STAT for a module that is not on the
 * allow-list is refused with EPERM before any query — never answered with a
 * loaded/not-loaded result.  A client may STAT only a module it could ENSURE, so
 * denial leaks no information about which modules exist or are loaded.  The
 * denial happens before kldfind(2) is reached.  loaded stays 0 on a denial.
 */
ATF_TC(provider_stat_denies_non_allowlisted_module);
ATF_TC_HEAD(provider_stat_denies_non_allowlisted_module, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_stat_denies_non_allowlisted_module, tc)
{
	struct sysext_stat_reply reply;
	struct fixture fixture;
	struct sysext_request rq;

	/* Default allow-list ({cryptodev,vhid,zfs}); "kernel" is not on it. */
	fixture_create(&fixture);
	rq = stat_request("kernel");
	reply = call_stat(&fixture, &rq, sizeof(rq), -1);
	ATF_CHECK_EQ(EPERM, reply.status);
	ATF_CHECK_EQ(0, reply.loaded);
	/* Syntactically valid dotted name, still not allow-listed. */
	rq = stat_request("if_evil.ko");
	reply = call_stat(&fixture, &rq, sizeof(rq), -1);
	ATF_CHECK_EQ(EPERM, reply.status);
	ATF_CHECK_EQ(0, reply.loaded);
	fixture_destroy(&fixture);
}

/*
 * A STAT whose module name is not NUL-terminated within the wire buffer is
 * rejected with EINVAL — the validator refuses it rather than reading past the
 * field — before any allow-list or query decision.
 */
ATF_TC(provider_stat_rejects_unterminated_name);
ATF_TC_HEAD(provider_stat_rejects_unterminated_name, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_stat_rejects_unterminated_name, tc)
{
	struct sysext_stat_reply reply;
	struct fixture fixture;
	struct sysext_request rq;

	fixture_create(&fixture);
	memset(&rq, 0, sizeof(rq));
	rq.op = SYSEXT_OP_STAT;
	memset(rq.name, 'a', sizeof(rq.name));	/* no NUL in the name field */
	reply = call_stat(&fixture, &rq, sizeof(rq), -1);
	ATF_CHECK_EQ(EINVAL, reply.status);
	fixture_destroy(&fixture);
}

/*
 * A STAT of the wrong length is malformed and rejected with EPROTO; a STAT that
 * carries an unexpected descriptor is likewise EPROTO (this interface takes no
 * descriptors).  Both fail closed before any name/allow-list/query decision.
 */
ATF_TC(provider_stat_rejects_malformed_framing);
ATF_TC_HEAD(provider_stat_rejects_malformed_framing, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_stat_rejects_malformed_framing, tc)
{
	struct sysext_stat_reply reply;
	struct fixture fixture;
	struct sysext_request rq;
	int fd;

	fixture_create(&fixture);
	rq = stat_request("cryptodev");
	/* Short by one byte: length != sizeof(struct sysext_request). */
	reply = call_stat(&fixture, &rq, sizeof(rq) - 1, -1);
	ATF_CHECK_EQ(EPROTO, reply.status);
	/* An attached descriptor on a no-descriptor interface. */
	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	rq = stat_request("cryptodev");
	reply = call_stat(&fixture, &rq, sizeof(rq), fd);
	ATF_CHECK_EQ(EPROTO, reply.status);
	close(fd);
	fixture_destroy(&fixture);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, provider_denies_non_allowlisted_module);
	ATF_TP_ADD_TC(tp, provider_rejects_unknown_op);
	ATF_TP_ADD_TC(tp, provider_rejects_unterminated_name);
	ATF_TP_ADD_TC(tp, provider_rejects_wrong_length);
	ATF_TP_ADD_TC(tp, provider_rejects_attached_descriptor);
	ATF_TP_ADD_TC(tp, provider_stat_reports_loaded_module);
	ATF_TP_ADD_TC(tp, provider_stat_reports_unloaded_module);
	ATF_TP_ADD_TC(tp, provider_stat_denies_non_allowlisted_module);
	ATF_TP_ADD_TC(tp, provider_stat_rejects_unterminated_name);
	ATF_TP_ADD_TC(tp, provider_stat_rejects_malformed_framing);
	return (atf_no_error());
}
