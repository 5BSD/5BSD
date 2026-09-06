/*- SPDX-License-Identifier: BSD-2-Clause */

#include <sys/types.h>
#include <sys/ioctl.h>
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
#include <devicecmp_protocol.h>

#include "policy.h"
#include "localdevice_test.h"

struct raw_fixture {
	struct service_session	*session;
	pid_t			 child;
};

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
 * Stand up a per-label provider worker bound to a caller-supplied client label.
 * The policy the worker enforces must already have been installed via
 * localdevice_test_set_config() before the fork.
 */
static void
raw_fixture_create(struct raw_fixture *fixture, const char *label)
{
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(localdevice_test_serve(provider, label));
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

static void
raw_fixture_destroy_any(struct raw_fixture *fixture)
{
	int status;

	service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
}

/*
 * A single-entry default-deny policy granting one label one /dev leaf a rights
 * mask.  Installed before forking a fixture; the worker inherits it as its
 * compiled config.
 */
static void
set_single_policy(const char *label, const char *device, uint32_t rights)
{
	struct devicecmp_config cfg;
	struct devicecmp_device_policy *pol;

	devicecmp_config_defaults(&cfg);
	pol = &cfg.entries[0];
	memset(pol, 0, sizeof(*pol));
	strlcpy(pol->label, label, sizeof(pol->label));
	strlcpy(pol->device, device, sizeof(pol->device));
	pol->rights = rights;
	pol->nioctls = 0;
	cfg.nentries = 1;
	localdevice_test_set_config(&cfg);
}

/*
 * Append one (label, device, rights) entry to a config being assembled for a
 * multi-label scoping test.
 */
static void
add_policy(struct devicecmp_config *cfg, const char *label, const char *device,
    uint32_t rights)
{
	struct devicecmp_device_policy *pol;

	ATF_REQUIRE(cfg->nentries < DEVICECMP_MAX_POLICY);
	pol = &cfg->entries[cfg->nentries++];
	memset(pol, 0, sizeof(*pol));
	strlcpy(pol->label, label, sizeof(pol->label));
	strlcpy(pol->device, device, sizeof(pol->device));
	pol->rights = rights;
	pol->nioctls = 0;
}

/*
 * Send a DEVICECMP_OP_LIST request with the given cursor and return the daemon's
 * errno-style status (0 on success).  On success, the page's entries are copied
 * to entries[] (up to max), *countp gets the count, *nextp the next cursor.
 */
static int
device_list(struct raw_fixture *fixture, uint32_t cursor,
    struct devicecmp_list_entry *entries, uint32_t max, uint32_t *countp,
    uint32_t *nextp)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct {
		struct devicecmp_msg msg;
		struct devicecmp_list_request body;
	} request;
	struct {
		struct devicecmp_msg msg;
		struct devicecmp_list_reply body;
	} reply;
	uint32_t count;

	memset(&request, 0, sizeof(request));
	request.msg.magic = DEVICECMP_MAGIC;
	request.msg.version = DEVICECMP_ABI_VERSION;
	request.msg.opcode = DEVICECMP_OP_LIST;
	request.body.cursor = cursor;

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &request;
	outgoing.length = sizeof(request);
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 2000;
	ATF_REQUIRE_EQ(0, service_session_call(fixture->session, &outgoing,
	    &incoming, &options));
	if (reply.msg.status == 0) {
		ATF_REQUIRE_EQ(sizeof(reply), incoming.length);
		count = reply.body.count;
		ATF_REQUIRE(count <= DEVICECMP_LIST_MAX && count <= max);
		if (entries != NULL)
			memcpy(entries, reply.body.entries,
			    (size_t)count * sizeof(entries[0]));
		if (countp != NULL)
			*countp = count;
		if (nextp != NULL)
			*nextp = reply.body.next_cursor;
	}
	return (-reply.msg.status);
}

/*
 * Send a well-formed DEVICECMP_OP_OPEN request (header + body + NUL-terminated
 * name) and return the daemon's errno-style status (0 on success, positive
 * errno on rejection).  On success the granted-rights mask is returned through
 * granted and the delivered descriptor through out_fd.
 */
static int
device_open(struct raw_fixture *fixture, const char *name, uint32_t rights,
    uint32_t *granted, int *out_fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct devicecmp_msg msg;
	struct devicecmp_open_body body;
	struct {
		struct devicecmp_msg msg;
		struct devicecmp_open_body body;
	} reply;
	uint8_t request[sizeof(struct devicecmp_msg) +
	    sizeof(struct devicecmp_open_body) + DEVICECMP_MAX_NAME];
	size_t name_length, length;
	int fd;

	name_length = strlen(name) + 1;
	ATF_REQUIRE(name_length <= DEVICECMP_MAX_NAME);
	memset(&msg, 0, sizeof(msg));
	msg.magic = DEVICECMP_MAGIC;
	msg.version = DEVICECMP_ABI_VERSION;
	msg.opcode = DEVICECMP_OP_OPEN;
	memset(&body, 0, sizeof(body));
	body.rights = rights;
	body.name_length = (uint16_t)name_length;
	length = sizeof(msg) + sizeof(body) + name_length;
	memset(request, 0, sizeof(request));
	memcpy(request, &msg, sizeof(msg));
	memcpy(request + sizeof(msg), &body, sizeof(body));
	memcpy(request + sizeof(msg) + sizeof(body), name, name_length);

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = request;
	outgoing.length = length;
	fd = -1;
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	if (out_fd != NULL) {
		incoming.fds = &fd;
		incoming.fd_capacity = 1;
	}
	options.timeout_ms = 2000;
	ATF_REQUIRE_EQ(0, service_session_call(fixture->session, &outgoing,
	    &incoming, &options));
	if (out_fd != NULL)
		*out_fd = fd;
	if (granted != NULL)
		*granted = reply.body.rights;
	return (-reply.msg.status);
}

/*
 * Send an arbitrary (possibly malformed) request; return service_session_call's
 * result and, when a reply arrives, its errno-style status.
 */
static int
send_raw(struct service_session *session, const void *data, size_t length,
    int attach_fd, int *status)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct {
		struct devicecmp_msg msg;
		struct devicecmp_open_body body;
	} reply;
	int rc, fd;

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = data;
	outgoing.length = length;
	if (attach_fd >= 0) {
		fd = attach_fd;
		outgoing.fds = &fd;
		outgoing.nfds = 1;
	}
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 2000;
	rc = service_session_call(session, &outgoing, &incoming, &options);
	if (rc == 0 && status != NULL)
		*status = -reply.msg.status;
	return (rc);
}

/*
 * A granted label reaches its policy device and gets a working descriptor: an
 * open of /dev/null with READ|WRITE yields granted == READ|WRITE, and the
 * delivered fd both accepts a write and reports EOF on read (proving a live,
 * rights-bearing descriptor rather than a token).  A separate READ grant on
 * /dev/zero returns zeroed bytes.
 */
ATF_TC(granted_open_reads_and_writes);
ATF_TC_HEAD(granted_open_reads_and_writes, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A granted label opens its device and gets a working descriptor");
}
ATF_TC_BODY(granted_open_reads_and_writes, tc)
{
	struct raw_fixture fixture;
	uint32_t granted;
	uint8_t buf[8];
	int fd;

	require_plane();

	/* READ|WRITE on /dev/null. */
	set_single_policy("org.test.dev", "null",
	    DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_WRITE);
	raw_fixture_create(&fixture, "org.test.dev");

	granted = 0;
	fd = -1;
	ATF_CHECK_EQ(0, device_open(&fixture, "null",
	    DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_WRITE, &granted, &fd));
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_WRITE, granted);
	ATF_CHECK_EQ(1, write(fd, "x", 1));
	ATF_CHECK_EQ(0, read(fd, buf, 1));
	close(fd);

	raw_fixture_destroy(&fixture, 0);

	/* READ on /dev/zero returns zeroed bytes. */
	set_single_policy("org.test.dev", "zero", DEVICECMP_RIGHT_READ);
	raw_fixture_create(&fixture, "org.test.dev");

	granted = 0;
	fd = -1;
	ATF_CHECK_EQ(0, device_open(&fixture, "zero", DEVICECMP_RIGHT_READ,
	    &granted, &fd));
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(DEVICECMP_RIGHT_READ, granted);
	memset(buf, 0xff, sizeof(buf));
	ATF_CHECK_EQ((ssize_t)sizeof(buf), read(fd, buf, sizeof(buf)));
	ATF_CHECK_EQ(0, buf[0]);
	ATF_CHECK_EQ(0, buf[sizeof(buf) - 1]);
	close(fd);

	raw_fixture_destroy(&fixture, 0);
}

/*
 * The granted rights are the intersection of the request and the policy, and
 * that narrowing reaches the delivered descriptor: a READ-only policy against a
 * READ|WRITE request yields granted == READ, and the CAP_READ-limited fd fails
 * a write with ENOTCAPABLE.
 */
ATF_TC(rights_are_narrowed_to_policy);
ATF_TC_HEAD(rights_are_narrowed_to_policy, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Delivered rights are the request intersected with policy, enforced "
	    "by Capsicum on the fd");
}
ATF_TC_BODY(rights_are_narrowed_to_policy, tc)
{
	struct raw_fixture fixture;
	uint32_t granted;
	int fd;

	require_plane();
	set_single_policy("org.test.dev", "null", DEVICECMP_RIGHT_READ);
	raw_fixture_create(&fixture, "org.test.dev");

	granted = 0;
	fd = -1;
	ATF_CHECK_EQ(0, device_open(&fixture, "null",
	    DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_WRITE, &granted, &fd));
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(DEVICECMP_RIGHT_READ, granted);
	/* The delivered fd is CAP_READ-limited: a write must fail ENOTCAPABLE. */
	ATF_CHECK_ERRNO(ENOTCAPABLE, write(fd, "x", 1) == -1);
	close(fd);

	raw_fixture_destroy(&fixture, 0);
}

/*
 * Default-deny: a label with no policy entry is refused (EACCES), and a granted
 * label reaching a device outside its policy is likewise refused (EACCES).
 */
ATF_TC(ungranted_label_or_device_denied);
ATF_TC_HEAD(ungranted_label_or_device_denied, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "An unpolicied label or an out-of-policy device is denied EACCES");
}
ATF_TC_BODY(ungranted_label_or_device_denied, tc)
{
	struct raw_fixture fixture;
	int fd;

	require_plane();

	/* Label with no entry at all: policy grants org.test.dev, not this. */
	set_single_policy("org.test.dev", "null", DEVICECMP_RIGHT_READ);
	raw_fixture_create(&fixture, "org.test.other");
	fd = -1;
	ATF_CHECK_EQ(EACCES, device_open(&fixture, "null", DEVICECMP_RIGHT_READ,
	    NULL, &fd));
	ATF_CHECK_EQ(-1, fd);
	raw_fixture_destroy(&fixture, 0);

	/* Granted label, but a device ("random") outside its single entry. */
	set_single_policy("org.test.dev", "null", DEVICECMP_RIGHT_READ);
	raw_fixture_create(&fixture, "org.test.dev");
	fd = -1;
	ATF_CHECK_EQ(EACCES, device_open(&fixture, "random",
	    DEVICECMP_RIGHT_READ, NULL, &fd));
	ATF_CHECK_EQ(-1, fd);
	raw_fixture_destroy(&fixture, 0);
}

/*
 * Unsafe leaf names are rejected with EINVAL before any openat(2): a parent
 * traversal, a path separator, a leading dot, and an empty name.
 */
ATF_TC(unsafe_names_rejected);
ATF_TC_HEAD(unsafe_names_rejected, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Unsafe /dev leaf names are rejected EINVAL before any open");
}
ATF_TC_BODY(unsafe_names_rejected, tc)
{
	static const char *const unsafe[] = { "..", "bus/pci", ".hidden", "" };
	struct raw_fixture fixture;
	size_t i;
	int fd;

	require_plane();
	set_single_policy("org.test.dev", "null", DEVICECMP_RIGHT_READ);
	raw_fixture_create(&fixture, "org.test.dev");

	for (i = 0; i < nitems(unsafe); i++) {
		fd = -1;
		ATF_CHECK_EQ_MSG(EINVAL, device_open(&fixture, unsafe[i],
		    DEVICECMP_RIGHT_READ, NULL, &fd),
		    "name \"%s\" not rejected EINVAL", unsafe[i]);
		ATF_CHECK_EQ(-1, fd);
	}

	raw_fixture_destroy(&fixture, 0);
}

/*
 * The provider fails closed on malformed requests: a bad magic, a bad version,
 * an out-of-range opcode, a truncated body, a length not matching
 * header+name_length, and a non-NUL-terminated name are all rejected without
 * reaching openat(2).  A bad header (magic/version/opcode) is EPROTO; a
 * well-formed header with a malformed OPEN body is EINVAL, exactly as request()
 * dictates.  An attached descriptor on any request is EPROTO.
 */
ATF_TC(malformed_request_is_rejected);
ATF_TC_HEAD(malformed_request_is_rejected, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Malformed device requests are rejected fail-closed");
}
ATF_TC_BODY(malformed_request_is_rejected, tc)
{
	struct raw_fixture fixture, attach;
	struct devicecmp_msg msg;
	struct devicecmp_open_body body;
	uint8_t request[sizeof(struct devicecmp_msg) +
	    sizeof(struct devicecmp_open_body) + 8];
	size_t base;
	int status, rc, pipefd[2];

	require_plane();
	set_single_policy("org.test.dev", "null", DEVICECMP_RIGHT_READ);
	raw_fixture_create(&fixture, "org.test.dev");

	base = sizeof(msg) + sizeof(body);

	/* Helper builds a valid OPEN of "null" then the case mutates it. */
	memset(&msg, 0, sizeof(msg));
	msg.magic = DEVICECMP_MAGIC;
	msg.version = DEVICECMP_ABI_VERSION;
	msg.opcode = DEVICECMP_OP_OPEN;
	memset(&body, 0, sizeof(body));
	body.rights = DEVICECMP_RIGHT_READ;
	body.name_length = 5;			/* "null\0" */
	memset(request, 0, sizeof(request));
	memcpy(request, &msg, sizeof(msg));
	memcpy(request + sizeof(msg), &body, sizeof(body));
	memcpy(request + base, "null", 5);

	/* Bad magic: header rejected EPROTO. */
	msg.magic = DEVICECMP_MAGIC ^ 0xffU;
	memcpy(request, &msg, sizeof(msg));
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, request, base + 5, -1,
	    &status));
	ATF_CHECK_EQ(EPROTO, status);

	/* Bad version: header rejected EPROTO. */
	msg.magic = DEVICECMP_MAGIC;
	msg.version = DEVICECMP_ABI_VERSION + 1;
	memcpy(request, &msg, sizeof(msg));
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, request, base + 5, -1,
	    &status));
	ATF_CHECK_EQ(EPROTO, status);

	/* Out-of-range opcode: header ok, opcode falls through to EPROTO. */
	msg.version = DEVICECMP_ABI_VERSION;
	msg.opcode = 99;
	memcpy(request, &msg, sizeof(msg));
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, request, base + 5, -1,
	    &status));
	ATF_CHECK_EQ(EPROTO, status);

	/* Truncated body: an OPEN with only the header present is EPROTO
	 * (length < header + body, so the OPEN branch is never taken). */
	msg.opcode = DEVICECMP_OP_OPEN;
	memcpy(request, &msg, sizeof(msg));
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, request, sizeof(msg), -1,
	    &status));
	ATF_CHECK_EQ(EPROTO, status);

	/* Length does not match header + name_length: name_length says 5 but
	 * only 4 name bytes are sent.  EINVAL from the OPEN body check. */
	memcpy(request, &msg, sizeof(msg));
	body.name_length = 5;
	memcpy(request + sizeof(msg), &body, sizeof(body));
	memcpy(request + base, "null", 4);
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, request, base + 4, -1,
	    &status));
	ATF_CHECK_EQ(EINVAL, status);

	/* Name not NUL-terminated: name_length bytes present but last != NUL.
	 * EINVAL from the OPEN body check. */
	body.name_length = 4;
	memcpy(request + sizeof(msg), &body, sizeof(body));
	memcpy(request + base, "null", 4);
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, request, base + 4, -1,
	    &status));
	ATF_CHECK_EQ(EINVAL, status);

	raw_fixture_destroy(&fixture, 0);

	/*
	 * An attached descriptor on an otherwise-valid OPEN must not be
	 * interpreted: the handler requires fd_count == 0 and replies EPROTO.
	 * Run on a fresh session so a terminal channel policy cannot mask it.
	 */
	set_single_policy("org.test.dev", "null", DEVICECMP_RIGHT_READ);
	raw_fixture_create(&attach, "org.test.dev");
	ATF_REQUIRE_EQ(0, pipe(pipefd));
	body.name_length = 5;
	memcpy(request, &msg, sizeof(msg));
	memcpy(request + sizeof(msg), &body, sizeof(body));
	memcpy(request + base, "null", 5);
	status = 0;
	rc = send_raw(attach.session, request, base + 5, pipefd[0], &status);
	if (rc == 0)
		ATF_CHECK_EQ(EPROTO, status);
	else
		ATF_CHECK_EQ(-1, rc);
	close(pipefd[0]);
	close(pipefd[1]);
	raw_fixture_destroy_any(&attach);
}

/* Locate an entry by device name within a returned LIST page. */
static const struct devicecmp_list_entry *
find_entry(const struct devicecmp_list_entry *entries, uint32_t count,
    const char *device)
{
	uint32_t i;

	for (i = 0; i < count; i++)
		if (strcmp(entries[i].name, device) == 0)
			return (&entries[i]);
	return (NULL);
}

/*
 * LIST is label-scoped: a caller sees exactly the devices its own policy label
 * grants — with the policy-max rights and the ioctl-whitelist flag — and never
 * another label's devices.  This is the hard scoping invariant: the same config
 * carries entries for two labels, but a client connected as one label lists only
 * its own.
 */
ATF_TC(list_is_label_scoped);
ATF_TC_HEAD(list_is_label_scoped, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "LIST returns only the caller-label's devices, never another's");
}
ATF_TC_BODY(list_is_label_scoped, tc)
{
	struct devicecmp_config cfg;
	struct raw_fixture fixture;
	struct devicecmp_list_entry entries[DEVICECMP_LIST_MAX];
	const struct devicecmp_list_entry *e;
	uint32_t count, next;

	require_plane();

	/*
	 * org.test.dev grants two devices (one with an ioctl whitelist);
	 * org.test.other grants a third the first label must never see.
	 */
	devicecmp_config_defaults(&cfg);
	add_policy(&cfg, "org.test.dev", "null",
	    DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_WRITE);
	add_policy(&cfg, "org.test.other", "random", DEVICECMP_RIGHT_READ);
	add_policy(&cfg, "org.test.dev", "zero",
	    DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_IOCTL);
	cfg.entries[2].nioctls = 1;
	cfg.entries[2].ioctls[0] = 1;
	localdevice_test_set_config(&cfg);

	raw_fixture_create(&fixture, "org.test.dev");
	count = 99;
	next = 99;
	memset(entries, 0, sizeof(entries));
	ATF_CHECK_EQ(0, device_list(&fixture, 0, entries, nitems(entries),
	    &count, &next));
	/* Exactly org.test.dev's two devices, and the last page. */
	ATF_CHECK_EQ(2, count);
	ATF_CHECK_EQ(0, next);

	e = find_entry(entries, count, "null");
	ATF_REQUIRE(e != NULL);
	ATF_CHECK_EQ(DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_WRITE, e->rights);
	ATF_CHECK_EQ(0, e->flags);

	e = find_entry(entries, count, "zero");
	ATF_REQUIRE(e != NULL);
	ATF_CHECK_EQ(DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_IOCTL, e->rights);
	ATF_CHECK_EQ(DEVICECMP_LIST_FLAG_IOCTL_WHITELIST, e->flags);

	/* The other label's device is never visible. */
	ATF_CHECK(find_entry(entries, count, "random") == NULL);
	raw_fixture_destroy(&fixture, 0);

	/* Connected as the other label: only its own single device appears. */
	localdevice_test_set_config(&cfg);
	raw_fixture_create(&fixture, "org.test.other");
	count = 99;
	next = 99;
	memset(entries, 0, sizeof(entries));
	ATF_CHECK_EQ(0, device_list(&fixture, 0, entries, nitems(entries),
	    &count, &next));
	ATF_CHECK_EQ(1, count);
	ATF_CHECK_EQ(0, next);
	ATF_CHECK(find_entry(entries, count, "random") != NULL);
	ATF_CHECK(find_entry(entries, count, "null") == NULL);
	ATF_CHECK(find_entry(entries, count, "zero") == NULL);
	raw_fixture_destroy(&fixture, 0);
}

/*
 * A label with no policy entry lists empty (default-deny), not an error, even
 * when the config carries entries for other labels.
 */
ATF_TC(list_empty_for_unpolicied_label);
ATF_TC_HEAD(list_empty_for_unpolicied_label, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "An unpolicied label lists empty, not an error");
}
ATF_TC_BODY(list_empty_for_unpolicied_label, tc)
{
	struct raw_fixture fixture;
	struct devicecmp_list_entry entries[DEVICECMP_LIST_MAX];
	uint32_t count, next;

	require_plane();
	set_single_policy("org.test.dev", "null", DEVICECMP_RIGHT_READ);
	raw_fixture_create(&fixture, "org.test.nobody");
	count = 99;
	next = 99;
	ATF_CHECK_EQ(0, device_list(&fixture, 0, entries, nitems(entries),
	    &count, &next));
	ATF_CHECK_EQ(0, count);
	ATF_CHECK_EQ(0, next);
	raw_fixture_destroy(&fixture, 0);
}

/*
 * A malformed LIST fails closed: a nonzero (reserved) flags word is EINVAL, and
 * a LIST whose length does not match the request struct never yields a success
 * page.
 */
ATF_TC(malformed_list_is_rejected);
ATF_TC_HEAD(malformed_list_is_rejected, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Malformed LIST requests are rejected fail-closed");
}
ATF_TC_BODY(malformed_list_is_rejected, tc)
{
	struct raw_fixture fixture;
	struct {
		struct devicecmp_msg msg;
		struct devicecmp_list_request body;
	} request;
	int status;

	require_plane();
	set_single_policy("org.test.dev", "null", DEVICECMP_RIGHT_READ);
	raw_fixture_create(&fixture, "org.test.dev");

	memset(&request, 0, sizeof(request));
	request.msg.magic = DEVICECMP_MAGIC;
	request.msg.version = DEVICECMP_ABI_VERSION;
	request.msg.opcode = DEVICECMP_OP_LIST;

	/* Nonzero reserved flags: EINVAL. */
	request.body.flags = 1;
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, &request, sizeof(request), -1,
	    &status));
	ATF_CHECK_EQ(EINVAL, status);

	/* Nonzero reserved word: EINVAL. */
	request.body.flags = 0;
	request.body.reserved[0] = 7;
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, &request, sizeof(request), -1,
	    &status));
	ATF_CHECK_EQ(EINVAL, status);

	/* Wrong length (header only): opcode is LIST but the body is missing,
	 * so the LIST branch is never taken and the request is EPROTO. */
	request.body.reserved[0] = 0;
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, &request,
	    sizeof(request.msg), -1, &status));
	ATF_CHECK_EQ(EPROTO, status);

	raw_fixture_destroy(&fixture, 0);
}

/* A HELLO liveness probe over the raw session returns a valid, fd-free reply. */
ATF_TC(hello_liveness);
ATF_TC_HEAD(hello_liveness, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "HELLO returns a valid liveness reply");
}
ATF_TC_BODY(hello_liveness, tc)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct raw_fixture fixture;
	struct devicecmp_msg msg;
	struct {
		struct devicecmp_msg msg;
		struct devicecmp_hello_reply hello;
	} reply;

	require_plane();
	set_single_policy("org.test.dev", "null", DEVICECMP_RIGHT_READ);
	raw_fixture_create(&fixture, "org.test.dev");

	memset(&msg, 0, sizeof(msg));
	msg.magic = DEVICECMP_MAGIC;
	msg.version = DEVICECMP_ABI_VERSION;
	msg.opcode = DEVICECMP_OP_HELLO;
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &msg;
	outgoing.length = sizeof(msg);
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 2000;
	ATF_REQUIRE_EQ(0, service_session_call(fixture.session, &outgoing,
	    &incoming, &options));
	ATF_CHECK_EQ(sizeof(reply), incoming.length);
	ATF_CHECK_EQ(0, incoming.nfds);
	ATF_CHECK_EQ(0, reply.msg.status);
	ATF_CHECK_EQ(DEVICECMP_OP_HELLO, reply.msg.opcode);
	ATF_CHECK_EQ((uint32_t)DEVICECMP_ABI_VERSION, reply.hello.version);
	raw_fixture_destroy(&fixture, 0);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{

	ATF_CHECK_ERRNO(EINVAL, localdevice_test_serve(-1, "x") == -1);
	ATF_CHECK_ERRNO(EINVAL, localdevice_test_serve(0, NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, localdevice_test_serve(0, "") == -1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, granted_open_reads_and_writes);
	ATF_TP_ADD_TC(tp, rights_are_narrowed_to_policy);
	ATF_TP_ADD_TC(tp, ungranted_label_or_device_denied);
	ATF_TP_ADD_TC(tp, unsafe_names_rejected);
	ATF_TP_ADD_TC(tp, malformed_request_is_rejected);
	ATF_TP_ADD_TC(tp, list_is_label_scoped);
	ATF_TP_ADD_TC(tp, list_empty_for_unpolicied_label);
	ATF_TP_ADD_TC(tp, malformed_list_is_rejected);
	ATF_TP_ADD_TC(tp, hello_liveness);
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
