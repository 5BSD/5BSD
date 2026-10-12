/*- SPDX-License-Identifier: BSD-2-Clause */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/sysctl.h>
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
#include <sysctlcmp.h>

#include "config.h"
#include "bsdsysctl_test.h"

#define	TEST_LABEL	"org.test.sysctl"

/*
 * The real reactor runs in a forked child; the test drives it with the real
 * libsysctlcmp client (bsd.sysctl.v1), or with hand-built frames on a raw
 * libservice session.
 */
struct raw_fixture {
	struct sysctlcmp_client	*client;
	struct service_session	*session;	/* raw-frame cases */
	pid_t			 child;
};

/* FIDL v2 transactional message header. */
struct wire_header {
	uint32_t txid;
	uint8_t flags[3], magic;
	uint64_t ordinal;
};
#define ORD_INFO	UINT64_C(0x435c275e0f8b3d3f)
#define ORD_GET		UINT64_C(0x256a360cdcdb641a)

static void
require_plane(void)
{
	int fd;

	fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		atf_tc_skip("plane device /dev/mac_capability unavailable: %s",
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

/*
 * A minimal default-deny policy: the default ACL permits reading exactly one
 * variable ("kern.ostype") and permits no writes.  The worker inherits a copy
 * of *config across the fork, so the per-label gating in handle_request() runs
 * on this exact policy.
 */
static void
make_config(struct sysctlcmp_config *config)
{

	memset(config, 0, sizeof(*config));
	strlcpy(config->default_acl.read[0], "kern.ostype",
	    sizeof(config->default_acl.read[0]));
	config->default_acl.nread = 1;
	config->default_acl.nwrite = 0;
	config->nclients = 0;
}

/*
 * Stand up a per-label provider worker bound to a caller-supplied client label
 * and policy, running the real serve/dispatch path over a plane channel.
 */
static void
fixture_start(struct raw_fixture *fixture, const char *label,
    const struct sysctlcmp_config *config, bool raw)
{
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(sysctlcmp_test_serve(provider, label, config));
	}
	close(provider);
	if (raw)
		ATF_REQUIRE_EQ(0, service_session_create(client,
		    &fixture->session));
	else
		ATF_REQUIRE_EQ(0, sysctlcmp_client_create(client,
		    &fixture->client));
}

static void
raw_fixture_create(struct raw_fixture *fixture, const char *label,
    const struct sysctlcmp_config *config)
{

	fixture_start(fixture, label, config, false);
}

static void
raw_fixture_destroy(struct raw_fixture *fixture, int expected_status)
{
	int status;

	if (fixture->client != NULL)
		sysctlcmp_client_close(fixture->client);
	if (fixture->session != NULL)
		service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(expected_status, WEXITSTATUS(status));
}

/*
 * One operation through the real client, by historical opcode.  Returns the
 * provider's errno-style status (0 on success, positive errno on a policy or
 * kernel rejection).  On a value-bearing success the value is copied through
 * out/outlen (outlen carries the buffer size in, the value length out);
 * OIDFMT values are rebuilt in the {kind; format} wire layout.
 */
static int
sysctl_op(struct sysctlcmp_client *client, uint16_t opcode, const char *name,
    const void *newval, size_t newlen, void *out, size_t *outlen)
{
	uint8_t scratch[SYSCTLCMP_MAX_VALUE];
	size_t scratch_len = sizeof(scratch);
	int result;

	if (out == NULL || outlen == NULL) {
		out = scratch;
		outlen = &scratch_len;
	}
	switch (opcode) {
	case SYSCTLCMP_OP_GET:
		result = sysctlcmp_get(client, name, out, outlen);
		break;
	case SYSCTLCMP_OP_SET:
		result = sysctlcmp_set(client, name, newval, newlen);
		break;
	case SYSCTLCMP_OP_OIDFMT: {
		char fmt[SYSCTLCMP_MAX_NAME];
		size_t fmtlen = sizeof(fmt);
		unsigned int kind;
		uint32_t kind32;

		result = sysctlcmp_oidfmt(client, name, &kind, fmt, &fmtlen);
		if (result == 0) {
			kind32 = kind;
			ATF_REQUIRE(sizeof(kind32) + fmtlen <= *outlen);
			memcpy(out, &kind32, sizeof(kind32));
			memcpy((uint8_t *)out + sizeof(kind32), fmt, fmtlen);
			*outlen = sizeof(kind32) + fmtlen;
		}
		break;
	}
	case SYSCTLCMP_OP_DESCR:
		result = sysctlcmp_describe(client, name, out, outlen);
		break;
	case SYSCTLCMP_OP_NEXT:
		result = sysctlcmp_next(client, name, out, outlen);
		break;
	default:
		atf_tc_fail("opcode %u", opcode);
	}
	return (result == 0 ? 0 : errno);
}

/* A raw frame on a raw session; returns the call result. */
static int
raw_frame(struct service_session *session, const void *data, size_t length)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	uint8_t reply[256];

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = data;
	outgoing.length = length;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 2000;
	return (service_session_call(session, &outgoing, &incoming, &options));
}

/*
 * The dispatch handlers honour the per-label read/write policy: a GET of a policy-permitted read-only variable returns a value; a GET of a
 * non-permitted variable is refused EPERM before any sysctl(3); a SET is
 * refused EPERM because the policy grants no writes.
 */
ATF_TC(policy_gated_get_and_set);
ATF_TC_HEAD(policy_gated_get_and_set, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "GET/SET dispatch honours the per-label read/write policy");
}
ATF_TC_BODY(policy_gated_get_and_set, tc)
{
	struct sysctlcmp_config config;
	struct raw_fixture fixture;
	uint8_t value[SYSCTLCMP_MAX_VALUE];
	size_t len;

	require_plane();
	make_config(&config);
	raw_fixture_create(&fixture, TEST_LABEL, &config);

	/* GET of the one permitted variable returns a non-empty value. */
	len = sizeof(value);
	ATF_CHECK_EQ(0, sysctl_op(fixture.client, SYSCTLCMP_OP_GET,
	    "kern.ostype", NULL, 0, value, &len));
	ATF_CHECK(len > 0);
	ATF_CHECK(len <= sizeof(value));
	ATF_CHECK_EQ('\0', value[len - 1]);

	/* GET of a non-permitted variable is denied by policy: EPERM. */
	len = sizeof(value);
	ATF_CHECK_EQ(EPERM, sysctl_op(fixture.client, SYSCTLCMP_OP_GET,
	    "kern.osrelease", NULL, 0, value, &len));

	/* SET is denied by policy (no writes granted): EPERM, no write attempted. */
	ATF_CHECK_EQ(EPERM, sysctl_op(fixture.client, SYSCTLCMP_OP_SET,
	    "kern.ostype", "x", 1, NULL, NULL));

	raw_fixture_destroy(&fixture, 0);
}

/*
 * OIDFMT and DESCR on a permitted variable return introspection data: OIDFMT a
 * kind word plus a format string, DESCR a NUL-terminated description.  Both are
 * read-policy gated, so a non-permitted variable is refused EPERM.
 */
ATF_TC(introspection_is_gated);
ATF_TC_HEAD(introspection_is_gated, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "OIDFMT and DESCR return data for permitted names and deny others");
}
ATF_TC_BODY(introspection_is_gated, tc)
{
	struct sysctlcmp_config config;
	struct raw_fixture fixture;
	uint8_t value[SYSCTLCMP_MAX_VALUE];
	size_t len;

	require_plane();
	make_config(&config);
	raw_fixture_create(&fixture, TEST_LABEL, &config);

	/* OIDFMT: at least the leading uint32_t kind word is present. */
	len = sizeof(value);
	ATF_CHECK_EQ(0, sysctl_op(fixture.client, SYSCTLCMP_OP_OIDFMT,
	    "kern.ostype", NULL, 0, value, &len));
	ATF_CHECK(len >= sizeof(uint32_t));

	/* DESCR: a non-empty, NUL-terminated description string. */
	len = sizeof(value);
	ATF_CHECK_EQ(0, sysctl_op(fixture.client, SYSCTLCMP_OP_DESCR,
	    "kern.ostype", NULL, 0, value, &len));
	ATF_CHECK(len > 0);
	ATF_CHECK_EQ('\0', value[len - 1]);

	/* Both are read gated: a non-permitted name is EPERM. */
	len = sizeof(value);
	ATF_CHECK_EQ(EPERM, sysctl_op(fixture.client, SYSCTLCMP_OP_OIDFMT,
	    "kern.osrelease", NULL, 0, value, &len));
	len = sizeof(value);
	ATF_CHECK_EQ(EPERM, sysctl_op(fixture.client, SYSCTLCMP_OP_DESCR,
	    "kern.osrelease", NULL, 0, value, &len));

	raw_fixture_destroy(&fixture, 0);
}

/*
 * NEXT enumeration filters against the read policy: every name it yields is one
 * the label may read, it surfaces the single permitted variable, and it
 * terminates with ENOENT past the last permitted name -- never leaking a name
 * outside the caller's policy.
 */
ATF_TC(next_never_reveals_denied_names);
ATF_TC_HEAD(next_never_reveals_denied_names, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NEXT enumerates only policy-permitted names and ends with ENOENT");
}
ATF_TC_BODY(next_never_reveals_denied_names, tc)
{
	struct sysctlcmp_config config;
	struct raw_fixture fixture;
	char name[SYSCTLCMP_MAX_NAME];
	uint8_t value[SYSCTLCMP_MAX_NAME];
	size_t len, iterations;
	bool saw_ostype;
	int status;

	require_plane();
	make_config(&config);
	raw_fixture_create(&fixture, TEST_LABEL, &config);

	name[0] = '\0';
	saw_ostype = false;
	for (iterations = 0; iterations < 64; iterations++) {
		len = sizeof(value);
		status = sysctl_op(fixture.client, SYSCTLCMP_OP_NEXT, name,
		    NULL, 0, value, &len);
		if (status == ENOENT)
			break;			/* enumeration exhausted */
		ATF_REQUIRE_EQ_MSG(0, status, "NEXT failed: %s",
		    strerror(status));
		ATF_REQUIRE(len > 0 && len <= sizeof(value));
		ATF_REQUIRE_EQ('\0', value[len - 1]);
		/* Every yielded name must be permitted by the read policy. */
		ATF_CHECK_MSG(sysctlcmp_config_permits(&config, TEST_LABEL,
		    (const char *)value, false),
		    "NEXT leaked non-permitted name \"%s\"", (const char *)value);
		if (strcmp((const char *)value, "kern.ostype") == 0)
			saw_ostype = true;
		strlcpy(name, (const char *)value, sizeof(name));
	}
	ATF_CHECK(status == ENOENT);
	ATF_CHECK(saw_ostype);

	raw_fixture_destroy(&fixture, 0);
}

/*
 * The provider fails closed on a malformed request: a pre-FIDL record, a
 * method before negotiation, an unknown method, a truncated frame or a frame
 * with trailing bytes closes the session without a reply, and the reactor
 * reports the protocol failure (the worker exits 1) rather than acting on
 * the frame.
 */
ATF_TC(malformed_request_fails_closed);
ATF_TC_HEAD(malformed_request_fails_closed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A malformed request is rejected fail-closed (session torn down)");
}
ATF_TC_BODY(malformed_request_fails_closed, tc)
{
	struct sysctlcmp_config config;
	struct raw_fixture fixture;
	struct {
		struct sysctlcmp_msg msg;
		struct sysctlcmp_body body;
		char name[12];
	} legacy;
	struct wire_header info = { 1, { 2, 0, 0 }, 1, ORD_INFO };
	struct {
		struct wire_header header;
		uint64_t size, presence;
		char name[16];
	} get = { { 2, { 2, 0, 0 }, 1, ORD_GET }, 11, UINT64_MAX,
		"kern.ostype" };
	uint8_t trailing[sizeof(get) + 8];
	int mode;

	require_plane();
	make_config(&config);
	for (mode = 0; mode < 6; mode++) {
		fixture_start(&fixture, TEST_LABEL, &config, true);
		if (mode >= 2)
			ATF_REQUIRE_EQ(0, raw_frame(fixture.session, &info,
			    sizeof(info)));
		switch (mode) {
		case 0:	/* A pre-FIDL GET record. */
			memset(&legacy, 0, sizeof(legacy));
			legacy.msg.magic = SYSCTLCMP_MAGIC;
			legacy.msg.opcode = SYSCTLCMP_OP_GET;
			legacy.body.name_length = sizeof(legacy.name);
			memcpy(legacy.name, "kern.ostype", sizeof(legacy.name));
			ATF_CHECK_EQ(-1, raw_frame(fixture.session, &legacy,
			    sizeof(legacy)));
			break;
		case 1:	/* A well-formed Get before negotiation. */
			ATF_CHECK_EQ(-1, raw_frame(fixture.session, &get,
			    sizeof(get)));
			break;
		case 2:	/* The same Get after negotiation is served. */
			ATF_CHECK_EQ(0, raw_frame(fixture.session, &get,
			    sizeof(get)));
			break;
		case 3:	/* Unknown strict method. */
			get.header.ordinal = 0x7fff;
			ATF_CHECK_EQ(-1, raw_frame(fixture.session, &get,
			    sizeof(get)));
			get.header.ordinal = ORD_GET;
			break;
		case 4:	/* Truncated (the name is cut short). */
			ATF_CHECK_EQ(-1, raw_frame(fixture.session, &get,
			    sizeof(get) - 8));
			break;
		case 5:	/* Trailing bytes. */
			memset(trailing, 0, sizeof(trailing));
			memcpy(trailing, &get, sizeof(get));
			ATF_CHECK_EQ(-1, raw_frame(fixture.session, trailing,
			    sizeof(trailing)));
			break;
		}
		/* A rejected frame was a protocol failure: the worker exits 1. */
		raw_fixture_destroy(&fixture, mode == 2 ? 0 : 1);
	}
}

/* An embedded NUL never truncates a name into a different variable. */
ATF_TC(embedded_nul_is_einval);
ATF_TC_HEAD(embedded_nul_is_einval, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A name with an embedded NUL is EINVAL and keeps the session");
}
ATF_TC_BODY(embedded_nul_is_einval, tc)
{
	struct sysctlcmp_config config;
	struct raw_fixture fixture;
	struct wire_header info = { 1, { 2, 0, 0 }, 1, ORD_INFO };
	struct {
		struct wire_header header;
		uint64_t size, presence;
		char name[16];
	} get = { { 2, { 2, 0, 0 }, 1, ORD_GET }, 13, UINT64_MAX,
		"kern.ostype\0x" };
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing = { .size = sizeof(outgoing),
		.data = &get, .length = sizeof(get) };
	uint8_t reply[64];
	struct service_reply incoming = { .size = sizeof(incoming),
		.data = reply, .capacity = sizeof(reply) };
	uint64_t tag;
	uint32_t err;

	require_plane();
	make_config(&config);
	fixture_start(&fixture, TEST_LABEL, &config, true);
	ATF_REQUIRE_EQ(0, raw_frame(fixture.session, &info, sizeof(info)));
	options.timeout_ms = 2000;
	ATF_REQUIRE_EQ(0, service_session_call(fixture.session, &outgoing,
	    &incoming, &options));
	ATF_REQUIRE(incoming.length >= 28);
	memcpy(&tag, reply + 16, sizeof(tag));
	memcpy(&err, reply + 24, sizeof(err));
	ATF_CHECK_EQ(2, tag);
	ATF_CHECK_EQ(EINVAL, err);
	raw_fixture_destroy(&fixture, 0);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{
	struct sysctlcmp_config config;

	make_config(&config);
	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_test_serve(-1, TEST_LABEL, &config)
	    == -1);
	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_test_serve(0, NULL, &config) == -1);
	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_test_serve(0, "", &config) == -1);
	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_test_serve(0, TEST_LABEL, NULL) == -1);
}

/*
 * SET converts the wire text value to the OID's native binary type before the
 * write.  The wire carries a value as text; a typed node (here the integer
 * kern.maxfiles) needs it parsed into a 4-byte int, or the ASCII bytes would be
 * stored verbatim (and a multi-digit value's length would not even match the
 * int handler, so a raw-bytes write would fail).  Read the current value, SET
 * it back as decimal text (a net no-op), and confirm it round-trips unchanged.
 */
ATF_TC(set_encodes_typed_value);
ATF_TC_HEAD(set_encodes_typed_value, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SET encodes the wire text to the OID's binary type (int round-trip)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(set_encodes_typed_value, tc)
{
	struct sysctlcmp_config config;
	struct raw_fixture fixture;
	int cur, again;
	char txt[32];
	size_t len;

	require_plane();
	/*
	 * Without a held SYS_GATE_SYSCTL token the worker writes with a direct
	 * sysctlbyname(2).  On a live plane the plane's SYSCTL claim refuses that
	 * ambient write with EPERM for every non-owner, root included (and the
	 * test cannot claim the gate itself), so the round trip is only
	 * observable on a plane-free boot.  Probe with the same no-op write.
	 */
	len = sizeof(cur);
	ATF_REQUIRE_EQ(0, sysctlbyname("kern.maxfiles", &cur, &len, NULL, 0));
	if (sysctlbyname("kern.maxfiles", NULL, NULL, &cur, sizeof(cur)) == -1) {
		if (errno == EPERM)
			atf_tc_skip("kern.maxfiles write is gated by the live "
			    "plane's SYS_GATE_SYSCTL claim; run plane-off");
		atf_tc_fail("probe write of kern.maxfiles: %s",
		    strerror(errno));
	}
	memset(&config, 0, sizeof(config));
	strlcpy(config.default_acl.read[0], "kern.maxfiles",
	    sizeof(config.default_acl.read[0]));
	config.default_acl.nread = 1;
	strlcpy(config.default_acl.write[0], "kern.maxfiles",
	    sizeof(config.default_acl.write[0]));
	config.default_acl.nwrite = 1;
	config.nclients = 0;
	raw_fixture_create(&fixture, TEST_LABEL, &config);

	/* Current value, as a raw 4-byte int. */
	len = sizeof(cur);
	ATF_REQUIRE_EQ(0, sysctl_op(fixture.client, SYSCTLCMP_OP_GET,
	    "kern.maxfiles", NULL, 0, &cur, &len));
	ATF_REQUIRE_EQ(sizeof(cur), len);

	/* Write it back as decimal text: proves the text -> int encoding. */
	snprintf(txt, sizeof(txt), "%d", cur);
	ATF_CHECK_EQ(0, sysctl_op(fixture.client, SYSCTLCMP_OP_SET,
	    "kern.maxfiles", txt, strlen(txt) + 1, NULL, NULL));

	/* Unchanged: the text encoded to the same binary int. */
	len = sizeof(again);
	ATF_REQUIRE_EQ(0, sysctl_op(fixture.client, SYSCTLCMP_OP_GET,
	    "kern.maxfiles", NULL, 0, &again, &len));
	ATF_CHECK_EQ(cur, again);

	raw_fixture_destroy(&fixture, 0);
}

ATF_TC(multiplexed_clients);
ATF_TC_HEAD(multiplexed_clients, tc)
{
	atf_tc_set_md_var(tc, "timeout", "15");
	atf_tc_set_md_var(tc, "descr", "Idle clients cannot block others or share their label policy");
}
ATF_TC_BODY(multiplexed_clients, tc)
{
	struct sysctlcmp_config config;
	struct sysctlcmp_client *sessions[2];
	const char *labels[] = { "idle", "denied", TEST_LABEL };
	int clients[3], providers[3], status;
	pid_t child;
	char value[128];
	size_t length;
	unsigned i;

	require_plane();
	make_config(&config);
	config.nclients = 1;
	strlcpy(config.clients[0].label, "denied", sizeof(config.clients[0].label));
	/* The named ACL is empty: no reads despite the default's safe read. */
	for (i = 0; i < 3; i++)
		channel_pair(&clients[i], &providers[i]);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		for (i = 0; i < 3; i++)
			close(clients[i]);
		_exit(sysctlcmp_test_serve_many(providers, labels, 3, &config, 10000));
	}
	for (i = 0; i < 3; i++)
		close(providers[i]);
	for (i = 0; i < 2; i++)
		ATF_REQUIRE_EQ(0, sysctlcmp_client_create(clients[i + 1],
		    &sessions[i]));
	/* Client zero stays open and silent throughout both request streams. */
	for (i = 0; i < 4; i++) {
		length = sizeof(value);
		ATF_CHECK_EQ(EPERM, sysctl_op(sessions[0], SYSCTLCMP_OP_GET,
		    "kern.ostype", NULL, 0, value, &length));
		length = sizeof(value);
		ATF_CHECK_EQ(0, sysctl_op(sessions[1], SYSCTLCMP_OP_GET,
		    "kern.ostype", NULL, 0, value, &length));
		ATF_CHECK(length > 0);
	}
	for (i = 0; i < 2; i++)
		sysctlcmp_client_close(sessions[i]);
	close(clients[0]);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
}

ATF_TC(idle_session_expires);
ATF_TC_HEAD(idle_session_expires, tc)
{
	atf_tc_set_md_var(tc, "timeout", "5");
	atf_tc_set_md_var(tc, "descr", "Silent channels expire without client closure");
}
ATF_TC_BODY(idle_session_expires, tc)
{
	struct sysctlcmp_config config;
	const char *label = TEST_LABEL;
	int client, provider, status;
	pid_t child;

	require_plane();
	make_config(&config);
	channel_pair(&client, &provider);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(client);
		_exit(sysctlcmp_test_serve_many(&provider, &label, 1, &config, 100));
	}
	close(provider);
	/* Holding the client open must not prevent the server's idle expiry. */
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	close(client);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, policy_gated_get_and_set);
	ATF_TP_ADD_TC(tp, set_encodes_typed_value);
	ATF_TP_ADD_TC(tp, introspection_is_gated);
	ATF_TP_ADD_TC(tp, next_never_reveals_denied_names);
	ATF_TP_ADD_TC(tp, malformed_request_fails_closed);
	ATF_TP_ADD_TC(tp, embedded_nul_is_einval);
	ATF_TP_ADD_TC(tp, arguments);
	ATF_TP_ADD_TC(tp, multiplexed_clients);
	ATF_TP_ADD_TC(tp, idle_session_expires);
	return (atf_no_error());
}
