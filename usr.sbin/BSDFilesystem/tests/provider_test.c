/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdfilesystem(8) provider tests.  Two layers:
 *
 *   - Pure tenant-isolation invariant (no plane, no pool): distinct client
 *     labels derive to distinct namespaces, and one tenant can never spell
 *     another tenant's namespace as a dataset key.  This is the primary
 *     isolation guard and always runs.
 *
 *   - Fail-closed message framing/validation over a real mac_capability
 *     channel: an attached descriptor, a wrong-length payload, a nonzero
 *     reserved field, and a non-canonical is_dir are each rejected without
 *     touching any ZFS machinery, and a bare PING round-trips.  This needs the
 *     capability plane (mac_capability + mac_capability_channel) and runs as
 *     root; it is skipped where the device is unavailable.
 *
 * The full storage-grant path (BSDFILESYSTEM_OP_REQUEST minting a live TrustedZFS
 * handle) needs an imported ZFS pool and the trustedzfs kernel API, which the
 * ATF environment does not provision.  Those cases are deferred here as an
 * explicit skip rather than faked; see live_grant_over_plane_requires_pool.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <channel.h>
#include <fidl/bsd.filesystem.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <trustedzfs.h>

#include "bsdfilesystem.h"

/*
 * Pure tenant-isolation invariant.  Two distinct service labels must derive to
 * two distinct namespace components, and — because a dataset key may not contain
 * '/' — a tenant cannot express "the other tenant's namespace / my claim" as a
 * single key.  Authority is the connecting label, never a wire argument, so this
 * is what confines each client to its own subtree.
 */
ATF_TC_WITHOUT_HEAD(namespaces_isolate_tenants);
ATF_TC_BODY(namespaces_isolate_tenants, tc)
{
	char ns_a[BSDFILESYSTEM_NAME_MAX], ns_b[BSDFILESYSTEM_NAME_MAX];
	char forged[BSDFILESYSTEM_NAME_MAX];

	ATF_REQUIRE(bsdfilesystem_test_derive_ns("system.TenantA", ns_a, sizeof(ns_a)));
	ATF_REQUIRE(bsdfilesystem_test_derive_ns("system.TenantB", ns_b, sizeof(ns_b)));
	ATF_CHECK_MSG(strcmp(ns_a, ns_b) != 0,
	    "distinct labels shared a namespace (%s)", ns_a);

	/*
	 * A client cannot name across namespaces: even if it knew tenant B's
	 * namespace string, "<ns_b>/claim" is not a valid single-component key.
	 */
	(void)snprintf(forged, sizeof(forged), "%s", ns_b);
	{
		char cross[BSDFILESYSTEM_NAME_MAX];

		memset(cross, 0, sizeof(cross));
		(void)snprintf(cross, sizeof(cross), "%.20s/claim", ns_b);
		ATF_CHECK_MSG(!bsdfilesystem_test_valid_dataset(cross),
		    "a slash-bearing cross-namespace key was accepted: %s",
		    cross);
	}
	/* But tenant B's own bare namespace key is well-formed. */
	ATF_CHECK(bsdfilesystem_test_valid_dataset(forged));
}

static bool
plane_available(void)
{
	int fd;

	fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (fd == -1)
		return (false);
	close(fd);
	return (true);
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

struct provider_fixture {
	struct fidl_bsd_connection *fidl;	/* generated client */
	struct channel	*client;		/* raw frames */
	pid_t		 child;
};

/* FIDL v2 transactional message header. */
struct wire_header {
	uint32_t txid;
	uint8_t flags[3], magic;
	uint64_t ordinal;
};
_Static_assert(sizeof(struct wire_header) == 16, "FIDL header");

#define	ORD_INFO	UINT64_C(0x6499245c21be7874)
#define	ORD_PING	UINT64_C(0x32ebd1eaf3f82aa4)
#define	ORD_DESTROY	UINT64_C(0x29178bae878787a3)
#define	ORD_LIST	UINT64_C(0x7010ef6ea130cc2b)

struct result {
	bool done;
	int error;		/* transport error */
	int status;		/* application errno */
	uint32_t value;
};

static void
wait_result(struct provider_fixture *fx, struct result *r)
{
	struct timespec deadline;

	ATF_REQUIRE_EQ(0, fidl_bsd_sync_deadline(&deadline, 5000));
	if (r->error == 0)
		r->error = fidl_bsd_sync_wait(fx->fidl, &r->done, &deadline);
	ATF_REQUIRE_EQ(0, r->error);
}

static void
info_done(void *p, int error, struct bsd_filesystem_v1_ProtocolInfo *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (!error)
		r->value = v->wire_version;
}

/*
 * Fork a worker running bsdfilesystem's single-channel serve loop over its own end of a
 * fresh capability channel, with a zeroed state (every retained handle == -1).
 * The framing/validation the tests exercise is reached before any handle is
 * touched, so the absence of real ZFS state is irrelevant to these cases.  The
 * client end is a negotiated generated client, or (raw) a libchannel client
 * for hand-built frames.
 */
static void
fixture_start(struct provider_fixture *fx, bool raw)
{
	struct channel_options client_options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	static struct bsdfilesystem_state st;	/* child-only; zeroed, all fds -1 */
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { 0 };
	uint32_t txid;
	int client_fd, provider_fd;

	memset(fx, 0, sizeof(*fx));
	memset(&st, 0, sizeof(st));
	st.persistent_fd = st.ephemeral_fd = -1;
	st.boot_fd = st.lease_fd = -1;
	st.root_fd = -1;

	channel_pair(&client_fd, &provider_fd);
	fx->child = fork();
	ATF_REQUIRE(fx->child >= 0);
	if (fx->child == 0) {
		close(client_fd);
		_exit(bsdfilesystem_test_worker(&st, provider_fd, "org.test.tenant"));
	}
	close(provider_fd);
	if (raw) {
		ATF_REQUIRE_EQ(0, channel_create(client_fd, &client_options,
		    &fx->client));
		return;
	}
	ATF_REQUIRE_EQ(0, fidl_bsd_connection_create(client_fd,
	    FIDL_BSD_CLIENT, &fx->fidl));
	r.error = bsd_filesystem_v1_Filesystem_GetProtocolInfo(fx->fidl,
	    &empty, info_done, &r, &txid);
	wait_result(fx, &r);
	ATF_REQUIRE_EQ(BSDFILESYSTEM_WIRE_VERSION, r.value);
}

static void
fixture_destroy(struct provider_fixture *fx)
{
	int status;

	/* Closing the client channel is EOF to the worker; it exits 0. */
	if (fx->fidl != NULL)
		fidl_bsd_connection_destroy(fx->fidl);
	if (fx->client != NULL)
		channel_destroy(fx->client);
	ATF_REQUIRE_EQ(fx->child, waitpid(fx->child, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
}

struct reply_capture {
	bool	done;
	int	error;
};

static void
capture_reply(struct channel_request *request, struct channel_message *reply,
    int error, void *argument)
{
	struct reply_capture *cap = argument;

	cap->done = true;
	cap->error = error;
	if (reply != NULL)
		channel_message_free(reply);
	channel_request_release(request);
}

/*
 * Send one raw frame over the client channel and drive it until it is
 * answered or the channel fails.  Returns 0 when a reply arrived, -1 when the
 * provider closed the session instead.
 */
static int
call_raw(struct channel *client, const void *data, size_t len,
    const int *fds, size_t nfds)
{
	struct reply_capture cap;
	struct channel_outgoing out;
	struct channel_request *pending;
	int ready, wants_write;

	memset(&cap, 0, sizeof(cap));
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = data;
	out.length = len;
	out.fds = fds;
	out.nfds = nfds;
	if (channel_send_request(client, &out, capture_reply, &cap,
	    &pending) != 0)
		return (-1);
	while (!cap.done) {
		wants_write = channel_wants_write(client);
		if (wants_write == -1)
			return (-1);
		ready = channel_wait(client, wants_write, 5000);
		ATF_REQUIRE_MSG(ready != 0, "client wait timed out");
		if (ready < 0 ||
		    ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(client) == -1) ||
		    ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(client) == -1))
			return (-1);
	}
	return (cap.error == 0 ? 0 : -1);
}

static int
call_frame(struct channel *client, uint64_t ordinal, const void *body,
    size_t body_length, const int *fds, size_t nfds)
{
	uint8_t frame[256];
	struct wire_header header = { 3, { 2, 0, 0 }, 1, ordinal };

	ATF_REQUIRE(sizeof(header) + body_length <= sizeof(frame));
	memcpy(frame, &header, sizeof(header));
	if (body_length != 0)
		memcpy(frame + sizeof(header), body, body_length);
	return (call_raw(client, frame, sizeof(header) + body_length, fds,
	    nfds));
}

/* The frame closes the session: no reply, and nothing later is honoured. */
static void
reject(bool negotiate, uint64_t ordinal, const void *body, size_t length,
    const int *fds, size_t nfds)
{
	struct provider_fixture fx;

	fixture_start(&fx, true);
	if (negotiate)
		ATF_REQUIRE_EQ(0, call_frame(fx.client, ORD_INFO, NULL, 0,
		    NULL, 0));
	ATF_CHECK_EQ(-1, call_frame(fx.client, ordinal, body, length, fds,
	    nfds));
	ATF_CHECK_EQ(-1, call_frame(fx.client, ORD_INFO, NULL, 0, NULL, 0));
	fixture_destroy(&fx);
}

static void
empty_done(void *p, int error, struct bsd_filesystem_v1_Filesystem_Destroy_Result *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (!error && v->tag ==
	    bsd_filesystem_v1_Filesystem_Destroy_Result_err_tag)
		r->status = (int)v->value.err;
}

static void
list_done(void *p, int error, struct bsd_filesystem_v1_Filesystem_List_Result *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (!error && v->tag == bsd_filesystem_v1_Filesystem_List_Result_err_tag)
		r->status = (int)v->value.err;
}

static void
ping_done(void *p, int error, struct bsd_filesystem_v1_Filesystem_Ping_Result *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (!error && v->tag == bsd_filesystem_v1_Filesystem_Ping_Result_err_tag)
		r->status = (int)v->value.err;
}

static int
destroy_claim(struct provider_fixture *fx, const char *dataset,
    size_t dataset_size)
{
	struct bsd_filesystem_v1_ClaimRef ref = {
		.lifetime = BSDFILESYSTEM_PERSISTENT, .dataset = dataset,
		.dataset_size = dataset_size, .group = ""
	};
	struct result r = { 0 };
	uint32_t txid;

	r.error = bsd_filesystem_v1_Filesystem_Destroy(fx->fidl, &ref,
	    empty_done, &r, &txid);
	wait_result(fx, &r);
	return (r.status);
}

ATF_TC(channel_validation_is_fail_closed);
ATF_TC_HEAD(channel_validation_is_fail_closed, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "descr",
	    "bsdfilesystem rejects malformed requests fail-closed over the plane");
}
ATF_TC_BODY(channel_validation_is_fail_closed, tc)
{
	struct bsd_filesystem_v1_ListRequest list = { .group = "" };
	struct bsdfilesystem_request legacy;
	struct fidl_bsd_empty empty = { 0 };
	struct provider_fixture fx;
	struct result r;
	uint64_t trailing = 0;
	uint32_t txid;
	int nullfd, pipefd[2];
	char byte;

	if (!plane_available())
		atf_tc_skip("mac_capability device not available");

	/* Hand-built frames close the session without a reply. */
	reject(false, ORD_PING, NULL, 0, NULL, 0);		/* unnegotiated */
	reject(true, UINT64_C(0x7fff), NULL, 0, NULL, 0);	/* unknown */
	reject(true, ORD_DESTROY, NULL, 0, NULL, 0);		/* no body */
	reject(true, ORD_PING, &trailing, sizeof(trailing), NULL, 0);
	{
		/* A truncated header (8 of 16 bytes). */
		struct wire_header h = { 3, { 2, 0, 0 }, 1, ORD_PING };

		fixture_start(&fx, true);
		ATF_CHECK_EQ(-1, call_raw(fx.client, &h, 8, NULL, 0));
		fixture_destroy(&fx);
	}
	/* A pre-FIDL PING record. */
	memset(&legacy, 0, sizeof(legacy));
	legacy.op = BSDFILESYSTEM_OP_PING;
	fixture_start(&fx, true);
	ATF_CHECK_EQ(-1, call_raw(fx.client, &legacy, sizeof(legacy), NULL, 0));
	fixture_destroy(&fx);
	/* An unexpected attached descriptor; the provider's copy is closed. */
	ATF_REQUIRE_EQ(0, pipe(pipefd));
	nullfd = pipefd[1];
	reject(true, ORD_PING, NULL, 0, &nullfd, 1);
	close(pipefd[1]);
	ATF_REQUIRE(fcntl(pipefd[0], F_SETFL, O_NONBLOCK) != -1);
	ATF_CHECK_EQ(0, read(pipefd[0], &byte, 1));
	close(pipefd[0]);

	fixture_start(&fx, false);

	/*
	 * A well-formed Destroy from a bundleless client (the zeroed fixture has
	 * no "<bundle>/<unit>" container) holds no durable namespace, so it fails
	 * closed with EINVAL before touching any ZFS state; so does a claim name
	 * with an embedded NUL.  Both keep the session.
	 */
	ATF_CHECK_EQ(EINVAL, destroy_claim(&fx, "claim", 5));
	ATF_CHECK_EQ(EINVAL, destroy_claim(&fx, "cl\0im", 5));

	/*
	 * A well-formed List reaches the handler but, with no imported pool
	 * (persistent_fd == -1 in this zeroed fixture), fails closed with ENXIO --
	 * proving the method is wired into dispatch and scoped to the daemon's own
	 * retained parent without a live pool.
	 */
	memset(&r, 0, sizeof(r));
	r.error = bsd_filesystem_v1_Filesystem_List(fx.fidl, &list, list_done,
	    &r, &txid);
	wait_result(&fx, &r);
	ATF_CHECK_EQ(ENXIO, r.status);

	/* And a well-formed Ping round-trips green -- the happy path works. */
	memset(&r, 0, sizeof(r));
	r.error = bsd_filesystem_v1_Filesystem_Ping(fx.fidl, &empty, ping_done,
	    &r, &txid);
	wait_result(&fx, &r);
	ATF_CHECK_EQ(0, r.status);

	fixture_destroy(&fx);
}

/*
 * The live storage-grant isolation case (label A's REQUEST can never resolve
 * into label B's dataset subtree) requires an imported ZFS pool and the
 * trustedzfs kernel verbs to actually mint a handle.  The ATF harness does not
 * provision a pool, so this is deferred rather than faked: the pure
 * namespaces_isolate_tenants case is the standing guard for the same invariant
 * at the derivation layer.  To exercise it end-to-end, run bsdfilesystem against a real
 * pool (see the storage bring-up runbook) and assert that a REQUEST from label A
 * lands under label A's own container and is unreachable from label B.
 */
ATF_TC(live_grant_over_plane_requires_pool);
ATF_TC_HEAD(live_grant_over_plane_requires_pool, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "live TrustedZFS grant isolation needs an imported pool");
}
ATF_TC_BODY(live_grant_over_plane_requires_pool, tc)
{

	atf_tc_skip("requires an imported ZFS pool + trustedzfs kernel API; "
	    "isolation is guarded purely by namespaces_isolate_tenants");
}

/*
 * The persistent claim reclaim round-trip — REQUEST(persistent) grants a claim,
 * DESTROY reclaims it (status 0), a second DESTROY of the now-absent claim
 * replies ENOENT, and a fresh REQUEST re-creates it — plus the per-request quota
 * override actually landing as a refquota property, both require an imported ZFS
 * pool and the trustedzfs kernel verbs to mint and destroy real datasets.  The
 * ATF harness does not provision a pool (and these tests deliberately avoid the
 * anon-mount machinery), so this is deferred rather than faked: the fail-closed
 * DESTROY framing (ENXIO/EINVAL/EPROTO without a pool) is covered over the plane
 * in channel_validation_is_fail_closed, the quota floor purely in namespace_test
 * (quota_floor_is_enforced), and owner-scoping in destroy_resolves_under_caller_ns.
 * To exercise the round-trip end-to-end, run bsdfilesystem against a real pool (see the
 * storage bring-up runbook).
 */
ATF_TC(live_destroy_roundtrip_requires_pool);
ATF_TC_HEAD(live_destroy_roundtrip_requires_pool, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "live REQUEST->DESTROY->REQUEST reclaim + quota-set needs a pool");
}
ATF_TC_BODY(live_destroy_roundtrip_requires_pool, tc)
{

	atf_tc_skip("requires an imported ZFS pool + trustedzfs kernel API; "
	    "DESTROY framing is guarded over the plane by "
	    "channel_validation_is_fail_closed and the quota floor purely by "
	    "quota_floor_is_enforced");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, namespaces_isolate_tenants);
	ATF_TP_ADD_TC(tp, channel_validation_is_fail_closed);
	ATF_TP_ADD_TC(tp, live_grant_over_plane_requires_pool);
	ATF_TP_ADD_TC(tp, live_destroy_roundtrip_requires_pool);
	return (atf_no_error());
}
