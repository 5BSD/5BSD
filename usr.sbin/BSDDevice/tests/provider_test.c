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
#include <devicecmp.h>
#include <fidl/bsd.device.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>

#include "policy.h"
#include "bsddevice_test.h"

/*
 * The test drives BSDDevice's real per-session FIDL server in a forked child.
 * Well-formed requests use the generated bsd.device.v1 client bindings (the
 * same encoder libdevicecmp uses); adversarial frames go through a raw
 * libservice session instead.
 */
struct raw_fixture {
	struct fidl_bsd_connection *client;	/* generated client */
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
 * bsddevice_test_set_config() before the fork.
 */
struct result {
	bool done;
	int error;		/* transport error */
	int status;		/* application errno */
	uint32_t value;
	int fd;
	struct devicecmp_list_entry *entries;
	uint32_t max, count, next;
};

static void
wait_result(struct raw_fixture *fixture, struct result *r)
{
	struct timespec deadline;

	ATF_REQUIRE_EQ(0, fidl_bsd_sync_deadline(&deadline, 5000));
	if (r->error == 0)
		r->error = fidl_bsd_sync_wait(fixture->client, &r->done,
		    &deadline);
}

static void
info_done(void *p, int error, struct bsd_device_v1_ProtocolInfo *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (!error)
		r->value = v->wire_version;
}

static void
raw_fixture_start(struct raw_fixture *fixture, const char *label, bool raw)
{
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { .fd = -1 };
	uint32_t txid;
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(bsddevice_test_serve(provider, label));
	}
	close(provider);
	if (raw) {
		ATF_REQUIRE_EQ(0, service_session_create(client,
		    &fixture->session));
		return;
	}
	ATF_REQUIRE_EQ(0, fidl_bsd_connection_create(client, FIDL_BSD_CLIENT,
	    &fixture->client));
	r.error = bsd_device_v1_Device_GetProtocolInfo(fixture->client, &empty,
	    info_done, &r, &txid);
	wait_result(fixture, &r);
	ATF_REQUIRE_EQ(0, r.error);
	ATF_REQUIRE_EQ(DEVICECMP_WIRE_VERSION, r.value);
}

static void
raw_fixture_create(struct raw_fixture *fixture, const char *label)
{

	raw_fixture_start(fixture, label, false);
}

static void
raw_fixture_destroy(struct raw_fixture *fixture, int expected_status)
{
	int status;

	if (fixture->client != NULL)
		fidl_bsd_connection_destroy(fixture->client);
	if (fixture->session != NULL)
		service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(expected_status, WEXITSTATUS(status));
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
	bsddevice_test_set_config(&cfg);
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

static void
list_done(void *p, int error, struct bsd_device_v1_Device_List_Result *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (error)
		return;
	if (v->tag == bsd_device_v1_Device_List_Result_err_tag) {
		r->status = (int)v->value.err;
		return;
	}
	ATF_REQUIRE(v->value.response.entries_size <= DEVICECMP_LIST_MAX);
	r->count = (uint32_t)v->value.response.entries_size;
	r->next = v->value.response.next_cursor;
	for (uint32_t i = 0; i < r->count && i < r->max; i++) {
		const struct bsd_device_v1_DeviceEntry *e =
		    &v->value.response.entries[i];

		ATF_REQUIRE(e->name_size < DEVICECMP_MAX_NAME);
		memset(&r->entries[i], 0, sizeof(r->entries[i]));
		memcpy(r->entries[i].name, e->name, e->name_size);
		r->entries[i].rights = e->rights;
		r->entries[i].flags = e->flags;
	}
}

/*
 * List with the given cursor; return the provider's application errno (0 on
 * success) and the page.  A transport failure fails the test.
 */
static int
device_list(struct raw_fixture *fixture, uint32_t cursor,
    struct devicecmp_list_entry *entries, uint32_t max, uint32_t *countp,
    uint32_t *nextp)
{
	struct bsd_device_v1_ListRequest request = { cursor };
	struct result r = { .fd = -1, .entries = entries, .max = max };
	uint32_t txid;

	r.error = bsd_device_v1_Device_List(fixture->client, &request,
	    list_done, &r, &txid);
	wait_result(fixture, &r);
	ATF_REQUIRE_EQ(0, r.error);
	if (r.status == 0) {
		ATF_REQUIRE(r.count <= max);
		if (countp != NULL)
			*countp = r.count;
		if (nextp != NULL)
			*nextp = r.next;
	}
	return (r.status);
}

static void
open_done(void *p, int error, struct bsd_device_v1_Device_Open_Result *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (error)
		return;
	if (v->tag == bsd_device_v1_Device_Open_Result_err_tag) {
		r->status = (int)v->value.err;
		return;
	}
	r->fd = fidl_bsd_take_fd(&v->value.response.device);
	r->value = v->value.response.rights;
}

/*
 * Open `name` with `rights`; return the provider's application errno (0 on
 * success).  On success the granted rights and delivered descriptor are
 * returned.  A transport failure fails the test.
 */
static int
device_open(struct raw_fixture *fixture, const char *name, uint32_t rights,
    uint32_t *granted, int *out_fd)
{
	struct bsd_device_v1_OpenRequest request = { name, strlen(name),
		rights };
	struct result r = { .fd = -1 };
	uint32_t txid;

	r.error = bsd_device_v1_Device_Open(fixture->client, &request,
	    open_done, &r, &txid);
	wait_result(fixture, &r);
	ATF_REQUIRE_EQ(0, r.error);
	if (granted != NULL)
		*granted = r.value;
	if (out_fd != NULL)
		*out_fd = r.fd;
	else if (r.fd >= 0)
		close(r.fd);
	return (r.status);
}

/* Send raw bytes (and optionally one descriptor); return the call result. */
static int
send_raw(struct service_session *session, const void *data, size_t length,
    int attach_fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	uint8_t reply[64];
	int fd, received = -1, rc;

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
	options.timeout_ms = 2000;
	rc = service_session_call(session, &outgoing, &incoming, &options);
	if (rc == 0 && incoming.nfds != 0 && received >= 0)
		(void)close(received);
	return (rc);
}

#define ORD_INFO	UINT64_C(0x042670afe7b0c259)
#define ORD_OPEN	UINT64_C(0x75fa02401ef2ac3e)
#define ORD_LIST	UINT64_C(0x5a28aff45b6caf3d)

/* A raw frame: header plus `body` bytes. */
static int
send_frame(struct service_session *session, uint64_t ordinal,
    const void *body, size_t body_length, int attach_fd)
{
	uint8_t frame[128];
	struct wire_header header = { 3, { 2, 0, 0 }, 1, ordinal };

	ATF_REQUIRE(sizeof(header) + body_length <= sizeof(frame));
	memcpy(frame, &header, sizeof(header));
	if (body_length != 0)
		memcpy(frame + sizeof(header), body, body_length);
	return (send_raw(session, frame, sizeof(header) + body_length,
	    attach_fd));
}

/*
 * A raw session that has negotiated, so a rejection is the provider's
 * decoding or validation, not the negotiation rule.
 */
static void
raw_negotiated(struct raw_fixture *fixture, const char *label)
{

	raw_fixture_start(fixture, label, true);
	ATF_REQUIRE_EQ(0, send_frame(fixture->session, ORD_INFO, NULL, 0, -1));
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
	/*
	 * The provider hardens each delivered descriptor to survive exactly one
	 * more fork, and the FIDL transport keeps that state (it does not lock
	 * inheritance): a forked child can still use it.
	 */
	{
		pid_t child = fork();
		int status;

		ATF_REQUIRE(child >= 0);
		if (child == 0)
			_exit(write(fd, "x", 1) == 1 ? 0 : 1);
		ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "delivered descriptor did not survive one fork");
	}
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
 * The provider fails closed on malformed requests: a method before
 * negotiation, an unknown method, a truncated frame, an Open without its body,
 * a name longer than the schema bound, an out-of-line size that disagrees
 * with the bytes present, a pre-FIDL record and an attached descriptor all
 * close the session without reaching openat(2) or replying.  A name with an
 * embedded NUL decodes but is refused EINVAL, keeping the session.
 */
static void
reject(bool negotiate, uint64_t ordinal, const void *body, size_t length,
    int attach_fd)
{
	struct raw_fixture fixture;

	set_single_policy("org.test.dev", "null", DEVICECMP_RIGHT_READ);
	if (negotiate)
		raw_negotiated(&fixture, "org.test.dev");
	else
		raw_fixture_start(&fixture, "org.test.dev", true);
	ATF_CHECK_EQ(-1, send_frame(fixture.session, ordinal, body, length,
	    attach_fd));
	ATF_CHECK(errno != ETIMEDOUT);
	/* Nothing later on the session is honoured. */
	ATF_CHECK_EQ(-1, send_frame(fixture.session, ORD_INFO, NULL, 0, -1));
	raw_fixture_destroy(&fixture, 0);
}

/* Open body: string header {size, presence}, rights, then name bytes. */
struct open_frame {
	uint64_t size;
	uint64_t presence;
	uint32_t rights;
	uint32_t pad;
	char name[8];
};

ATF_TC(malformed_request_is_rejected);
ATF_TC_HEAD(malformed_request_is_rejected, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Malformed device requests are rejected fail-closed");
}
ATF_TC_BODY(malformed_request_is_rejected, tc)
{
	struct open_frame good = { 4, UINT64_MAX, DEVICECMP_RIGHT_READ, 0,
		"null" };
	struct open_frame bad;
	struct devicecmp_msg legacy;
	struct raw_fixture fixture;
	int pipefd[2];
	char byte;

	require_plane();

	/* The well-formed frame is accepted (and returns a descriptor). */
	set_single_policy("org.test.dev", "null", DEVICECMP_RIGHT_READ);
	raw_negotiated(&fixture, "org.test.dev");
	ATF_CHECK_EQ(0, send_frame(fixture.session, ORD_OPEN, &good,
	    sizeof(good), -1));
	raw_fixture_destroy(&fixture, 0);

	/* Before negotiation. */
	reject(false, ORD_OPEN, &good, sizeof(good), -1);
	/* Unknown strict method. */
	reject(true, UINT64_C(0x7fff), &good, sizeof(good), -1);
	/* Truncated header (8 of 16 bytes). */
	{
		struct raw_fixture f;
		struct wire_header h = { 3, { 2, 0, 0 }, 1, ORD_OPEN };

		set_single_policy("org.test.dev", "null", DEVICECMP_RIGHT_READ);
		raw_negotiated(&f, "org.test.dev");
		ATF_CHECK_EQ(-1, send_raw(f.session, &h, 8, -1));
		raw_fixture_destroy(&f, 0);
	}
	/* Open without its body. */
	{
		struct raw_fixture f;

		set_single_policy("org.test.dev", "null", DEVICECMP_RIGHT_READ);
		raw_negotiated(&f, "org.test.dev");
		ATF_CHECK_EQ(-1, send_frame(f.session, ORD_OPEN, NULL, 0, -1));
		raw_fixture_destroy(&f, 0);
	}
	/* A name over the 255-byte bound. */
	bad = good;
	bad.size = 256;
	reject(true, ORD_OPEN, &bad, sizeof(bad), -1);
	/* Declared size larger than the bytes present. */
	bad = good;
	bad.size = 9;
	reject(true, ORD_OPEN, &bad, sizeof(bad), -1);
	/* A pre-FIDL OPEN record. */
	{
		struct raw_fixture f;

		memset(&legacy, 0, sizeof(legacy));
		legacy.magic = DEVICECMP_MAGIC;
		legacy.opcode = DEVICECMP_OP_OPEN;
		set_single_policy("org.test.dev", "null", DEVICECMP_RIGHT_READ);
		raw_fixture_start(&f, "org.test.dev", true);
		ATF_CHECK_EQ(-1, send_raw(f.session, &legacy, sizeof(legacy),
		    -1));
		raw_fixture_destroy(&f, 0);
	}
	/* An attached descriptor: rejected, and the provider's copy closed. */
	ATF_REQUIRE_EQ(0, pipe(pipefd));
	reject(true, ORD_OPEN, &good, sizeof(good), pipefd[1]);
	close(pipefd[1]);
	ATF_REQUIRE(fcntl(pipefd[0], F_SETFL, O_NONBLOCK) != -1);
	ATF_CHECK_EQ(0, read(pipefd[0], &byte, 1));
	close(pipefd[0]);

	/* An embedded NUL decodes but is refused EINVAL; the session lives. */
	set_single_policy("org.test.dev", "null", DEVICECMP_RIGHT_READ);
	raw_fixture_create(&fixture, "org.test.dev");
	{
		struct bsd_device_v1_OpenRequest request = { "nu\0l", 4,
			DEVICECMP_RIGHT_READ };
		struct result r = { .fd = -1 };
		uint32_t txid;

		r.error = bsd_device_v1_Device_Open(fixture.client, &request,
		    open_done, &r, &txid);
		wait_result(&fixture, &r);
		ATF_REQUIRE_EQ(0, r.error);
		ATF_CHECK_EQ(EINVAL, r.status);
		ATF_CHECK_EQ(-1, r.fd);
	}
	ATF_CHECK_EQ(0, device_open(&fixture, "null", DEVICECMP_RIGHT_READ,
	    NULL, NULL));
	raw_fixture_destroy(&fixture, 0);
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
	bsddevice_test_set_config(&cfg);

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
	bsddevice_test_set_config(&cfg);
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
 * A malformed List fails closed: a missing or trailing body closes the
 * session without a page.
 */
ATF_TC(malformed_list_is_rejected);
ATF_TC_HEAD(malformed_list_is_rejected, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Malformed List requests are rejected fail-closed");
}
ATF_TC_BODY(malformed_list_is_rejected, tc)
{
	uint8_t body[16] = { 0 };

	require_plane();
	/* Missing body. */
	reject(true, ORD_LIST, NULL, 0, -1);
	/* Trailing bytes after the 8-byte body. */
	reject(true, ORD_LIST, body, sizeof(body), -1);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{

	ATF_CHECK_ERRNO(EINVAL, bsddevice_test_serve(-1, "x") == -1);
	ATF_CHECK_ERRNO(EINVAL, bsddevice_test_serve(0, NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, bsddevice_test_serve(0, "") == -1);
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
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
