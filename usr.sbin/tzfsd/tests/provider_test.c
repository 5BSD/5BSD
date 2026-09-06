/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsd(8) provider tests.  Two layers:
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
 * The full storage-grant path (TZFSD_OP_REQUEST minting a live TrustedZFS
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

#include "tzfsd.h"

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
	char ns_a[TZFSD_NAME_MAX], ns_b[TZFSD_NAME_MAX];
	char forged[TZFSD_NAME_MAX];

	ATF_REQUIRE(tzfsd_test_derive_ns("system.TenantA", ns_a, sizeof(ns_a)));
	ATF_REQUIRE(tzfsd_test_derive_ns("system.TenantB", ns_b, sizeof(ns_b)));
	ATF_CHECK_MSG(strcmp(ns_a, ns_b) != 0,
	    "distinct labels shared a namespace (%s)", ns_a);

	/*
	 * A client cannot name across namespaces: even if it knew tenant B's
	 * namespace string, "<ns_b>/claim" is not a valid single-component key.
	 */
	(void)snprintf(forged, sizeof(forged), "%s", ns_b);
	{
		char cross[TZFSD_NAME_MAX];

		memset(cross, 0, sizeof(cross));
		(void)snprintf(cross, sizeof(cross), "%.20s/claim", ns_b);
		ATF_CHECK_MSG(!tzfsd_test_valid_dataset(cross),
		    "a slash-bearing cross-namespace key was accepted: %s",
		    cross);
	}
	/* But tenant B's own bare namespace key is well-formed. */
	ATF_CHECK(tzfsd_test_valid_dataset(forged));
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
	struct channel	*client;
	pid_t		 child;
};

/*
 * Fork a worker running tzfsd's single-channel serve loop over its own end of a
 * fresh capability channel, with a zeroed state (every retained handle == -1).
 * The framing/validation the tests exercise is reached before any handle is
 * touched, so the absence of real ZFS state is irrelevant to these cases.
 */
static void
fixture_create(struct provider_fixture *fx)
{
	struct channel_options client_options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	static struct tzfsd_state st;	/* child-only; zeroed, all fds -1 */
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
		_exit(tzfsd_test_worker(&st, provider_fd, "org.test.tenant"));
	}
	close(provider_fd);
	ATF_REQUIRE_EQ(0, channel_create(client_fd, &client_options,
	    &fx->client));
}

static void
fixture_destroy(struct provider_fixture *fx)
{
	int status;

	/* Closing the client channel is EOF to the worker; it exits 0. */
	channel_destroy(fx->client);
	ATF_REQUIRE_EQ(fx->child, waitpid(fx->child, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
}

struct reply_capture {
	bool	done;
	int	error;
	int32_t	status;
};

static void
capture_reply(struct channel_request *request, struct channel_message *reply,
    int error, void *argument)
{
	struct reply_capture *cap = argument;

	cap->done = true;
	cap->error = error;
	if (error == 0 && reply != NULL) {
		if (channel_message_length(reply) >=
		    sizeof(struct tzfsd_reply)) {
			const struct tzfsd_reply *rp =
			    channel_message_data(reply);

			cap->status = rp->status;
		}
		channel_message_free(reply);
	}
	channel_request_release(request);
}

/*
 * Send one request over the client channel and drive it until the reply lands.
 * Returns the tzfsd_reply.status (errno) the provider sent back.
 */
static int32_t
call_status(struct channel *client, const void *data, size_t len,
    const int *fds, size_t nfds)
{
	struct reply_capture cap;
	struct channel_outgoing out;
	struct channel_request *pending;
	int ready, wants_write;

	memset(&cap, 0, sizeof(cap));
	cap.status = -1;
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = data;
	out.length = len;
	out.fds = fds;
	out.nfds = nfds;
	ATF_REQUIRE_EQ(0, channel_send_request(client, &out, capture_reply,
	    &cap, &pending));
	while (!cap.done) {
		wants_write = channel_wants_write(client);
		ATF_REQUIRE(wants_write != -1);
		ready = channel_wait(client, wants_write, 5000);
		ATF_REQUIRE_MSG(ready > 0, "client wait: %s",
		    ready == 0 ? "timed out" : strerror(errno));
		if ((ready & CHANNEL_WAIT_WRITE) != 0)
			ATF_REQUIRE(channel_flush(client) != -1);
		if ((ready & CHANNEL_WAIT_READ) != 0)
			ATF_REQUIRE(channel_dispatch(client) != -1);
	}
	ATF_CHECK_EQ(0, cap.error);
	return (cap.status);
}

ATF_TC(channel_validation_is_fail_closed);
ATF_TC_HEAD(channel_validation_is_fail_closed, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "descr",
	    "tzfsd rejects malformed requests fail-closed over the plane");
}
ATF_TC_BODY(channel_validation_is_fail_closed, tc)
{
	struct provider_fixture fx;
	struct tzfsd_request rq;
	struct tzfsd_open_request orq;
	int nullfd;

	if (!plane_available())
		atf_tc_skip("mac_capability device not available");

	fixture_create(&fx);

	/* An unexpected attached descriptor is a protocol error. */
	nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(nullfd >= 0);
	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_PING;
	ATF_CHECK_EQ(EPROTO,
	    call_status(fx.client, &rq, sizeof(rq), &nullfd, 1));
	close(nullfd);

	/* A payload of the wrong length is a protocol error. */
	{
		uint8_t junk[8] = { 0 };

		ATF_CHECK_EQ(EPROTO,
		    call_status(fx.client, junk, sizeof(junk), NULL, 0));
	}

	/* A correctly-sized request with a nonzero reserved byte is EINVAL. */
	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_REQUEST;
	rq.rights = 1;
	rq.lifetime = TZFSD_PERSISTENT;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));
	rq._reserved[0] = 0x01;
	ATF_CHECK_EQ(EINVAL,
	    call_status(fx.client, &rq, sizeof(rq), NULL, 0));

	/* A non-canonical is_dir on an OPEN request is EINVAL (message hygiene). */
	memset(&orq, 0, sizeof(orq));
	orq.op = TZFSD_OP_OPEN;
	orq.rights = TZFSD_OPEN_READ;
	orq.is_dir = 42;
	(void)strlcpy(orq.path, "/dev/null", sizeof(orq.path));
	ATF_CHECK_EQ(EINVAL,
	    call_status(fx.client, &orq, sizeof(orq), NULL, 0));

	/* A DESTROY with a nonzero reserved byte is EINVAL (message hygiene). */
	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_DESTROY;
	rq.lifetime = TZFSD_PERSISTENT;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));
	rq._reserved[1] = 0x01;
	ATF_CHECK_EQ(EINVAL,
	    call_status(fx.client, &rq, sizeof(rq), NULL, 0));

	/* A DESTROY carrying rights (which it must not) is EINVAL. */
	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_DESTROY;
	rq.lifetime = TZFSD_PERSISTENT;
	rq.rights = 1;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));
	ATF_CHECK_EQ(EINVAL,
	    call_status(fx.client, &rq, sizeof(rq), NULL, 0));

	/*
	 * A well-formed DESTROY reaches the handler but, with no imported pool
	 * (persistent_fd == -1 in this zeroed fixture), fails closed with ENXIO
	 * rather than touching any ZFS state.  This proves the op is wired into
	 * dispatch and validated without needing a live pool.
	 */
	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_DESTROY;
	rq.lifetime = TZFSD_PERSISTENT;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));
	ATF_CHECK_EQ(ENXIO,
	    call_status(fx.client, &rq, sizeof(rq), NULL, 0));

	/* An attached descriptor on a DESTROY is a protocol error. */
	nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(nullfd >= 0);
	ATF_CHECK_EQ(EPROTO,
	    call_status(fx.client, &rq, sizeof(rq), &nullfd, 1));
	close(nullfd);

	/* And a well-formed PING round-trips green — the happy path works. */
	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_PING;
	ATF_CHECK_EQ(0, call_status(fx.client, &rq, sizeof(rq), NULL, 0));

	fixture_destroy(&fx);
}

/*
 * The live storage-grant isolation case (label A's REQUEST can never resolve
 * into label B's dataset subtree) requires an imported ZFS pool and the
 * trustedzfs kernel verbs to actually mint a handle.  The ATF harness does not
 * provision a pool, so this is deferred rather than faked: the pure
 * namespaces_isolate_tenants case is the standing guard for the same invariant
 * at the derivation layer.  To exercise it end-to-end, run tzfsd against a real
 * pool (see the storage bring-up runbook) and assert that a REQUEST from label A
 * lands under u<hash(A)> and is unreachable from label B.
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
 * To exercise the round-trip end-to-end, run tzfsd against a real pool (see the
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
