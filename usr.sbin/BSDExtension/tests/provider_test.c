/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Plane-level suite for bsdextension(8): drive the REAL per-client bsd.extension.v1
 * server (sysext_worker -> sysext_handle) over a REAL mac_capability channel via
 * the -DBSDEXTENSION_TESTING serve entry point, with the real libextensioncmp
 * client for well-formed requests and hand-built frames for the fail-closed
 * cases.
 *
 * These cases use the public capability-channel syscall and need no privilege;
 * they skip only where that syscall is unavailable.  None of them
 * exercises the ENSURE happy path, so no kldload(2) ever runs: every case is
 * refused by the allow-list or the message validator before ensure_extension is
 * reached, and we assert only the decision and the session's fate.
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
#include <string.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>
#include <extensioncmp.h>

#include "sysext_proto.h"
#include "bsdextension.h"

struct fixture {
	struct extensioncmp_session *client;	/* libextensioncmp */
	struct service_session	*session;	/* raw frames */
	pid_t			 child;
};

/* FIDL v2 transactional message header. */
struct wire_header {
	uint32_t txid;
	uint8_t flags[3], magic;
	uint64_t ordinal;
};
_Static_assert(sizeof(struct wire_header) == 16, "FIDL header");

#define	ORD_INFO	UINT64_C(0x4a2b741dd0bedaa8)
#define	ORD_ENSURE	UINT64_C(0x20729fc6bf255a8d)
#define	ORD_STAT	UINT64_C(0x318126ca32fd13e1)
#define	ORD_LIST	UINT64_C(0x27d9ac31c7bce8c3)
#define	ORD_RELOAD	UINT64_C(0x42969f6472d4b6ef)

/* Use the public channel-pair API.  The production plane deliberately
 * denies ambient opens of /dev/mac_capability, including opens by root. */
static void
channel_pair(int *client, int *provider)
{
	int pair[2];

	if (mac_capability_channel_create(pair) == -1) {
		if (errno == ENOSYS)
			atf_tc_skip("capability channel syscall unavailable");
		atf_tc_fail("channel creation: %s", strerror(errno));
	}
	*client = pair[0];
	*provider = pair[1];
}

/*
 * Stand up a worker serving cfg as its resolved allow-list on one end of a fresh
 * channel and, on the other, a libextensioncmp session or (raw) a libservice
 * session for hand-built frames.
 */
static void
fixture_start(struct fixture *fixture, const struct sysext_config *cfg,
    bool raw)
{
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(sysext_test_serve(provider, "test.client", cfg));
	}
	close(provider);
	if (raw)
		ATF_REQUIRE_EQ(0, service_session_create(client,
		    &fixture->session));
	else
		ATF_REQUIRE_EQ(0, extensioncmp_session_create(client,
		    &fixture->client));
}

static void
fixture_create_cfg(struct fixture *fixture, const struct sysext_config *cfg)
{

	fixture_start(fixture, cfg, false);
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

	if (fixture->client != NULL)
		extensioncmp_session_close(fixture->client);
	if (fixture->session != NULL)
		service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
}

/*
 * Send raw bytes (and optionally one descriptor).  Returns -1 when the
 * provider closed the session instead of answering, else the reply's errno
 * (0 for a success response).
 */
static int
send_raw(struct service_session *session, const void *data, size_t length,
    int attach_fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	uint8_t reply[4096];
	uint64_t tag;
	uint32_t value;
	int fd, received = -1;

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = data;
	outgoing.length = length;
	if (attach_fd >= 0) {
		fd = attach_fd;
		outgoing.fds = &fd;
		outgoing.nfds = 1;
	}
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(reply);
	incoming.fds = &received;
	incoming.fd_capacity = 1;
	options.timeout_ms = 5000;
	if (service_session_call(session, &outgoing, &incoming, &options) == -1) {
		/* Closed, not merely unanswered. */
		ATF_CHECK(errno != ETIMEDOUT);
		return (-1);
	}
	if (incoming.nfds != 0 && received >= 0)
		(void)close(received);
	/* GetProtocolInfo answers a struct; methods answer a result union. */
	if (incoming.length < sizeof(struct wire_header) + 16)
		return (0);
	memcpy(&tag, reply + sizeof(struct wire_header), sizeof(tag));
	memcpy(&value, reply + sizeof(struct wire_header) + 8, sizeof(value));
	return (tag == 2 ? (int)value : 0);
}

/* A raw frame: header plus `body` bytes. */
static int
send_frame(struct service_session *session, uint64_t ordinal,
    const void *body, size_t body_length, int attach_fd)
{
	uint8_t frame[256];
	struct wire_header header = { 3, { 2, 0, 0 }, 1, ordinal };

	ATF_REQUIRE(sizeof(header) + body_length <= sizeof(frame));
	memcpy(frame, &header, sizeof(header));
	if (body_length != 0)
		memcpy(frame + sizeof(header), body, body_length);
	return (send_raw(session, frame, sizeof(header) + body_length,
	    attach_fd));
}

/* A Module body: string header {size, presence} and the padded name bytes. */
struct module_frame {
	uint64_t size;
	uint64_t presence;
	char name[64];
};

static size_t
module_frame(struct module_frame *f, const char *name, size_t length)
{

	memset(f, 0, sizeof(*f));
	f->size = length;
	f->presence = UINT64_MAX;
	memcpy(f->name, name, length);
	return (16 + ((length + 7) & ~(size_t)7));
}

/* A negotiated raw session over the default allow-list. */
static void
raw_negotiated(struct fixture *fixture)
{
	struct sysext_config cfg;

	sysext_config_defaults(&cfg);
	fixture_start(fixture, &cfg, true);
	ATF_REQUIRE_EQ(0, send_frame(fixture->session, ORD_INFO, NULL, 0, -1));
}

/*
 * The frame is refused by closing the session: no reply, and nothing later on
 * the session is honoured.
 */
static void
reject(bool negotiate, uint64_t ordinal, const void *body, size_t length,
    int attach_fd)
{
	struct sysext_config cfg;
	struct fixture fixture;

	if (negotiate)
		raw_negotiated(&fixture);
	else {
		sysext_config_defaults(&cfg);
		fixture_start(&fixture, &cfg, true);
	}
	ATF_CHECK_EQ(-1, send_frame(fixture.session, ordinal, body, length,
	    attach_fd));
	ATF_CHECK_EQ(-1, send_frame(fixture.session, ORD_INFO, NULL, 0, -1));
	fixture_destroy(&fixture);
}

/*
 * THE plane-level security regression: an Ensure for a module that is not on
 * the allow-list is refused with EPERM (fail-closed), never loaded -- even though
 * the name is syntactically valid and the client already reached the provider.
 */
ATF_TC(provider_denies_non_allowlisted_module);
ATF_TC_HEAD(provider_denies_non_allowlisted_module, tc)
{
	atf_tc_set_md_var(tc, "descr", "Real capability-channel request validation");
}
ATF_TC_BODY(provider_denies_non_allowlisted_module, tc)
{
	struct fixture fixture;

	fixture_create(&fixture);
	ATF_CHECK_ERRNO(EPERM, extensioncmp_load(fixture.client, "evil") == -1);
	/* Syntactically valid dotted name, still not allow-listed. */
	ATF_CHECK_ERRNO(EPERM,
	    extensioncmp_load(fixture.client, "if_evil.ko") == -1);
	fixture_destroy(&fixture);
}

/*
 * Malformed frames close the session before any load decision: a method
 * before negotiation, an unknown method, a truncated or missing body, a name
 * over the 63-byte bound, trailing bytes, a pre-FIDL record and an attached
 * descriptor (whose provider copy is closed).
 */
ATF_TC(provider_rejects_malformed_frames);
ATF_TC_HEAD(provider_rejects_malformed_frames, tc)
{
	atf_tc_set_md_var(tc, "descr", "Real capability-channel request validation");
}
ATF_TC_BODY(provider_rejects_malformed_frames, tc)
{
	struct module_frame frame;
	struct sysext_request legacy;
	struct sysext_config cfg;
	struct fixture fixture;
	uint64_t trailing = 0;
	size_t length;
	int pipefd[2];
	char byte;

	length = module_frame(&frame, "cryptodev", 9);
	reject(false, ORD_ENSURE, &frame, length, -1);
	reject(true, UINT64_C(0x7fff), NULL, 0, -1);
	reject(true, ORD_ENSURE, NULL, 0, -1);
	reject(true, ORD_ENSURE, &frame, length - 8, -1);
	reject(true, ORD_LIST, &trailing, sizeof(trailing), -1);
	reject(true, ORD_RELOAD, &trailing, sizeof(trailing), -1);
	memset(frame.name, 'a', sizeof(frame.name));
	frame.size = 64;
	reject(true, ORD_STAT, &frame, sizeof(frame), -1);
	/* A pre-FIDL ENSURE record. */
	memset(&legacy, 0, sizeof(legacy));
	legacy.op = SYSEXT_OP_ENSURE;
	strlcpy(legacy.name, "cryptodev", sizeof(legacy.name));
	sysext_config_defaults(&cfg);
	fixture_start(&fixture, &cfg, true);
	ATF_CHECK_EQ(-1, send_raw(fixture.session, &legacy, sizeof(legacy), -1));
	fixture_destroy(&fixture);
	/* An attached descriptor: rejected, and the provider's copy closed. */
	ATF_REQUIRE_EQ(0, pipe(pipefd));
	length = module_frame(&frame, "cryptodev", 9);
	reject(true, ORD_STAT, &frame, length, pipefd[1]);
	close(pipefd[1]);
	ATF_REQUIRE(fcntl(pipefd[0], F_SETFL, O_NONBLOCK) != -1);
	ATF_CHECK_EQ(0, read(pipefd[0], &byte, 1));
	close(pipefd[0]);
}

/*
 * A module name with an embedded NUL would be truncated: the provider refuses
 * it EINVAL before any allow-list or query decision, and the session lives.
 */
ATF_TC(provider_rejects_embedded_nul);
ATF_TC_HEAD(provider_rejects_embedded_nul, tc)
{
	atf_tc_set_md_var(tc, "descr", "Real capability-channel request validation");
}
ATF_TC_BODY(provider_rejects_embedded_nul, tc)
{
	struct module_frame frame;
	struct fixture fixture;
	size_t length;

	raw_negotiated(&fixture);
	length = module_frame(&frame, "zfs\0evil", 8);
	ATF_CHECK_EQ(EINVAL, send_frame(fixture.session, ORD_ENSURE, &frame,
	    length, -1));
	ATF_CHECK_EQ(EINVAL, send_frame(fixture.session, ORD_STAT, &frame,
	    length, -1));
	/* Not allow-listed: an answer, so the session survived. */
	length = module_frame(&frame, "kernel", 6);
	ATF_CHECK_EQ(EPERM, send_frame(fixture.session, ORD_STAT, &frame,
	    length, -1));
	fixture_destroy(&fixture);
}

/*
 * Stat of an allow-listed module that IS loaded reports loaded=1 without
 * loading anything.  "kernel" (the running kernel image, fileid 1) is
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
	atf_tc_set_md_var(tc, "descr", "Real capability-channel request validation");
}
ATF_TC_BODY(provider_stat_reports_loaded_module, tc)
{
	struct sysext_config cfg;
	struct fixture fixture;
	int loaded = -1;

	config_allow_one(&cfg, "kernel");
	fixture_create_cfg(&fixture, &cfg);
	ATF_CHECK_EQ(0, extensioncmp_stat(fixture.client, "kernel", &loaded));
	ATF_CHECK_EQ(1, loaded);
	fixture_destroy(&fixture);
}

/*
 * Stat of an allow-listed module that is NOT loaded reports loaded=0 (a
 * completed query, not an error).  The allow-list is set to a single made-up
 * name that no kernel has loaded, so kldfind(2) returns ENOENT and the handler
 * maps that to the not-loaded answer.
 */
ATF_TC(provider_stat_reports_unloaded_module);
ATF_TC_HEAD(provider_stat_reports_unloaded_module, tc)
{
	atf_tc_set_md_var(tc, "descr", "Real capability-channel request validation");
}
ATF_TC_BODY(provider_stat_reports_unloaded_module, tc)
{
	struct sysext_config cfg;
	struct fixture fixture;
	int loaded = -1;

	config_allow_one(&cfg, "sysext_absent_mod");
	fixture_create_cfg(&fixture, &cfg);
	ATF_CHECK_EQ(0, extensioncmp_stat(fixture.client, "sysext_absent_mod",
	    &loaded));
	ATF_CHECK_EQ(0, loaded);
	fixture_destroy(&fixture);
}

/*
 * THE Stat security regression: a Stat for a module that is not on the
 * allow-list is refused with EPERM before any query -- never answered with a
 * loaded/not-loaded result.  A client may Stat only a module it could Ensure,
 * so denial leaks no information about which modules exist or are loaded.
 */
ATF_TC(provider_stat_denies_non_allowlisted_module);
ATF_TC_HEAD(provider_stat_denies_non_allowlisted_module, tc)
{
	atf_tc_set_md_var(tc, "descr", "Real capability-channel request validation");
}
ATF_TC_BODY(provider_stat_denies_non_allowlisted_module, tc)
{
	struct fixture fixture;
	int loaded = -1;

	/* Default allow-list ({cryptodev,vhid,zfs}); "kernel" is not on it. */
	fixture_create(&fixture);
	ATF_CHECK_ERRNO(EPERM, extensioncmp_stat(fixture.client, "kernel",
	    &loaded) == -1);
	ATF_CHECK_EQ(0, loaded);
	ATF_CHECK_ERRNO(EPERM, extensioncmp_stat(fixture.client, "if_evil.ko",
	    &loaded) == -1);
	ATF_CHECK_EQ(0, loaded);
	fixture_destroy(&fixture);
}

/*
 * List enumerates the allow-listed module names so a consumer can discover what
 * it may Ensure without Stat-probing blindly.  With a known multi-entry
 * allow-list, List returns exactly that set and is not itself gated by the
 * allow-list (no name is supplied).
 */
ATF_TC(provider_list_returns_allowlist);
ATF_TC_HEAD(provider_list_returns_allowlist, tc)
{
	atf_tc_set_md_var(tc, "descr", "Real capability-channel request validation");
}
ATF_TC_BODY(provider_list_returns_allowlist, tc)
{
	char names[SERVICE_EXTENSION_LIST_MAX][SERVICE_EXTENSION_NAME_MAX];
	struct sysext_config cfg;
	struct fixture fixture;
	size_t count = 0;

	memset(&cfg, 0, sizeof(cfg));
	strlcpy(cfg.allow[0], "cryptodev", SYSEXT_NAME_MAX);
	strlcpy(cfg.allow[1], "zfs", SYSEXT_NAME_MAX);
	strlcpy(cfg.allow[2], "if_foo.ko", SYSEXT_NAME_MAX);
	cfg.nallow = 3;

	fixture_create_cfg(&fixture, &cfg);
	ATF_REQUIRE_EQ(0, extensioncmp_list(fixture.client, names,
	    SERVICE_EXTENSION_LIST_MAX, &count));
	ATF_REQUIRE_EQ(3, count);
	ATF_CHECK_STREQ("cryptodev", names[0]);
	ATF_CHECK_STREQ("zfs", names[1]);
	ATF_CHECK_STREQ("if_foo.ko", names[2]);
	/* A buffer too small for the page fails EMSGSIZE with the count. */
	ATF_CHECK_ERRNO(EMSGSIZE, extensioncmp_list(fixture.client, names, 2,
	    &count) == -1);
	ATF_CHECK_EQ(3, count);
	fixture_destroy(&fixture);
}

/*
 * An empty allow-list is handled: List completes with count 0 (a valid, empty
 * enumeration), never an error.
 */
ATF_TC(provider_list_empty_allowlist);
ATF_TC_HEAD(provider_list_empty_allowlist, tc)
{
	atf_tc_set_md_var(tc, "descr", "Real capability-channel request validation");
}
ATF_TC_BODY(provider_list_empty_allowlist, tc)
{
	char names[1][SERVICE_EXTENSION_NAME_MAX];
	struct sysext_config cfg;
	struct fixture fixture;
	size_t count = 1;

	memset(&cfg, 0, sizeof(cfg));	/* nallow == 0 */
	fixture_create_cfg(&fixture, &cfg);
	ATF_CHECK_EQ(0, extensioncmp_list(fixture.client, names, 1, &count));
	ATF_CHECK_EQ(0, count);
	fixture_destroy(&fixture);
}

ATF_TC(provider_reload_requires_admin);
ATF_TC_HEAD(provider_reload_requires_admin, tc)
{
	atf_tc_set_md_var(tc, "descr", "Real capability-channel request validation");
}
ATF_TC_BODY(provider_reload_requires_admin, tc)
{
	struct fixture fixture;

	fixture_create(&fixture);
	ATF_CHECK_ERRNO(EPERM, extensioncmp_reload(fixture.client) == -1);
	/* The session survives an application error. */
	ATF_CHECK_ERRNO(EPERM, extensioncmp_reload(fixture.client) == -1);
	fixture_destroy(&fixture);
}

ATF_TC(provider_management_requires_admin);
ATF_TC_HEAD(provider_management_requires_admin, tc)
{
	atf_tc_set_md_var(tc, "descr", "Real capability-channel request validation");
}
ATF_TC_BODY(provider_management_requires_admin, tc)
{
	static const enum service_extension_action actions[] = {
		SERVICE_EXTENSION_ALLOW, SERVICE_EXTENSION_DENY,
		SERVICE_EXTENSION_RESET, SERVICE_EXTENSION_ENABLE,
		SERVICE_EXTENSION_DISABLE, SERVICE_EXTENSION_RESTORE
	};
	struct fixture fixture;

	fixture_create(&fixture);
	for (size_t i = 0; i < nitems(actions); i++)
		ATF_CHECK_ERRNO(EPERM, extensioncmp_manage(fixture.client,
		    actions[i], "zfs") == -1);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(provider_discovery_over_list_limit);
ATF_TC_BODY(provider_discovery_over_list_limit, tc)
{
	struct fixture fixture;
	struct sysext_config cfg = {0};
	struct service_extension_info info;
	char names[SERVICE_EXTENSION_LIST_MAX][SERVICE_EXTENSION_NAME_MAX];
	char cursor[SERVICE_EXTENSION_NAME_MAX] = "";
	size_t count, i;

	cfg.nallow = SYSEXT_LIST_MAX + 8;
	for (i = 0; i < cfg.nallow; i++)
		snprintf(cfg.allow[i], SYSEXT_NAME_MAX, "sysext_test_%03zu", i);
	fixture_create_cfg(&fixture, &cfg);
	ATF_CHECK_ERRNO(EOVERFLOW, extensioncmp_list(fixture.client,
	    names, SERVICE_EXTENSION_LIST_MAX, &count) == -1);
	for (i = 0; i < cfg.nallow; i++) {
		ATF_REQUIRE_EQ(0, extensioncmp_info(fixture.client,
		    cursor, 1, &info));
		ATF_CHECK_STREQ(cfg.allow[i], info.name);
		ATF_CHECK(info.allowed && !info.enabled && !info.overridden);
		strlcpy(cursor, info.name, sizeof(cursor));
	}
	ATF_CHECK_ERRNO(ENOENT, extensioncmp_info(fixture.client,
	    cursor, 1, &info) == -1);
	/* A loaded but denied module must not disclose its loaded state. */
	ATF_REQUIRE_EQ(0, extensioncmp_info(fixture.client,
	    "kernel", 0, &info));
	ATF_CHECK(!info.allowed && !info.loaded);
	fixture_destroy(&fixture);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, provider_denies_non_allowlisted_module);
	ATF_TP_ADD_TC(tp, provider_reload_requires_admin);
	ATF_TP_ADD_TC(tp, provider_management_requires_admin);
	ATF_TP_ADD_TC(tp, provider_discovery_over_list_limit);
	ATF_TP_ADD_TC(tp, provider_rejects_malformed_frames);
	ATF_TP_ADD_TC(tp, provider_rejects_embedded_nul);
	ATF_TP_ADD_TC(tp, provider_stat_reports_loaded_module);
	ATF_TP_ADD_TC(tp, provider_stat_reports_unloaded_module);
	ATF_TP_ADD_TC(tp, provider_stat_denies_non_allowlisted_module);

	ATF_TP_ADD_TC(tp, provider_list_returns_allowlist);
	ATF_TP_ADD_TC(tp, provider_list_empty_allowlist);
	return (atf_no_error());
}
