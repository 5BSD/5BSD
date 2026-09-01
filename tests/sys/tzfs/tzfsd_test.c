/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Integration tests for tzfsd(8): start the real daemon on a scratch pool and
 * drive it through libtzfsd, covering bare dataset requests, the anonymous
 * mount, rights attenuation, lifetime, and negatives.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include <trustedzfs.h>
#include "tzfsd.h"
#include "tzfs_test_helpers.h"

static bool
has_ioctl(const cap_ioctl_t *cmds, size_t ncmds, cap_ioctl_t wanted)
{
	size_t i;

	for (i = 0; i < ncmds; i++) {
		if (cmds[i] == wanted)
			return (true);
	}
	return (false);
}

static void
begin_test_session(int chan)
{

	ATF_REQUIRE_EQ(0, tzfsd_begin_session(chan,
	    "00000000000000000000000000000001"));
}

/* A bare lease claim: create, mount to a dir, release. */
ATF_TC_WITH_CLEANUP(bare_lease);
ATF_TC_HEAD(bare_lease, tc)
{
	atf_tc_set_md_var(tc, "descr", "bare lease request mounts and releases");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(bare_lease, tc)
{
	struct tzfsd_req req;
	struct tzfsd_grant g;
	int chan, dir;
	struct stat sb;

	tzt_require();
	tzt_pool_create(tc);
	tzt_daemon_start();

	chan = tzfsd_connect();
	ATF_REQUIRE(chan != -1);
	begin_test_session(chan);

	memset(&req, 0, sizeof(req));
	strlcpy(req.dataset, "t1", sizeof(req.dataset));
	req.rights = ZH_MOUNT | ZH_PROPS_READ;
	req.lifetime = TZFSD_LEASE;
	ATF_REQUIRE_EQ(0, tzfsd_request(chan, &req, &g));
	ATF_CHECK(strstr(g.dataset, "/ephemeral/lease-") != NULL);
	ATF_CHECK((fcntl(g.handle_fd, F_GETFD) & FD_CLOEXEC) != 0);

	dir = tzfsd_mount_dir(g.handle_fd, 0);
	ATF_REQUIRE(dir != -1);
	ATF_CHECK_EQ(0, fstat(dir, &sb));
	ATF_CHECK(S_ISDIR(sb.st_mode));
	(void)close(dir);
	(void)close(g.handle_fd);

	ATF_REQUIRE_EQ(0, tzfsd_release(chan, "t1"));
	/* Release is idempotent. */
	ATF_CHECK_EQ(0, tzfsd_release(chan, "t1"));
	(void)close(chan);
}
ATF_TC_CLEANUP(bare_lease, tc) { tzt_cleanup(); }

/* A handle granted without ZH_MOUNT cannot be mounted. */
ATF_TC_WITH_CLEANUP(rights_attenuation);
ATF_TC_HEAD(rights_attenuation, tc)
{
	atf_tc_set_md_var(tc, "descr", "granted handle carries only requested rights");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(rights_attenuation, tc)
{
	struct tzfsd_req req;
	struct tzfsd_grant g;
	struct zfd_info_args info;
	const cap_ioctl_t expected[] = {
		ZFD_LIMIT, ZFD_INFO, ZFD_DERIVE, ZFD_OPENAT, ZFD_STAT, ZFD_GET_PROPS,
		ZFD_GET_ONE_PROP, ZFD_LIST_SNAPS, ZFD_HOLDS,
		ZFD_LIST_BOOKMARKS,
	};
	cap_ioctl_t cmds[16];
	ssize_t ncmds;
	size_t i;
	int chan;

	tzt_require();
	tzt_pool_create(tc);
	tzt_daemon_start();

	chan = tzfsd_connect();
	ATF_REQUIRE(chan != -1);
	begin_test_session(chan);

	memset(&req, 0, sizeof(req));
	strlcpy(req.dataset, "r1", sizeof(req.dataset));
	req.rights = ZH_PROPS_READ;		/* deliberately no ZH_MOUNT */
	req.lifetime = TZFSD_LEASE;
	ATF_REQUIRE_EQ(0, tzfsd_request(chan, &req, &g));
	ATF_REQUIRE_EQ(0, tzfs_info(g.handle_fd, &info));
	ATF_CHECK_EQ(0, info.zi_flags & ZHF_SUBTREE);

	/* The daemon installs the exact implicit read/watch ioctl profile. */
	ncmds = cap_ioctls_get(g.handle_fd, cmds, nitems(cmds));
	ATF_REQUIRE_EQ(nitems(expected), (size_t)ncmds);
	for (i = 0; i < nitems(expected); i++)
		ATF_CHECK(has_ioctl(cmds, (size_t)ncmds, expected[i]));
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    tzfs_snapshot(g.handle_fd, "blocked-by-ioctl-profile") == -1);

	/* Mount must be refused: the handle lacks ZH_MOUNT. */
	ATF_CHECK_EQ(-1, tzfs_mount(g.handle_fd, false));
	ATF_CHECK_EQ(ENOTCAPABLE, errno);
	/* No-subtree was requested and must not be inherited from provisioning. */
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    tzfs_openat(g.handle_fd, "child", 0, 0) == -1);
	(void)close(g.handle_fd);
	(void)tzfsd_release(chan, "r1");
	(void)close(chan);
}
ATF_TC_CLEANUP(rights_attenuation, tc) { tzt_cleanup(); }

/* A persistent claim's dataset survives; a bad name is rejected. */
ATF_TC_WITH_CLEANUP(persistent_and_badname);
ATF_TC_HEAD(persistent_and_badname, tc)
{
	atf_tc_set_md_var(tc, "descr", "persistent claim persists; bad name rejected");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(persistent_and_badname, tc)
{
	struct tzfsd_req req;
	struct tzfsd_grant g;
	int chan;

	tzt_require();
	tzt_pool_create(tc);
	tzt_daemon_start();

	chan = tzfsd_connect();
	ATF_REQUIRE(chan != -1);
	begin_test_session(chan);

	memset(&req, 0, sizeof(req));
	strlcpy(req.dataset, "p1", sizeof(req.dataset));
	req.rights = ZH_PROPS_READ;
	req.lifetime = TZFSD_PERSISTENT;
	ATF_REQUIRE_EQ(0, tzfsd_request(chan, &req, &g));
	(void)close(g.handle_fd);
	/* The persistent dataset exists. */
	ATF_CHECK_EQ(0, tzt_systemf("zfs list %s/Capabilities/persistent/p1 "
	    ">/dev/null 2>&1", tzt_pool));

	/* A name with a slash is rejected. */
	memset(&req, 0, sizeof(req));
	strlcpy(req.dataset, "bad/name", sizeof(req.dataset));
	req.rights = ZH_PROPS_READ;
	req.lifetime = TZFSD_LEASE;
	ATF_CHECK_EQ(-1, tzfsd_request(chan, &req, &g));
	ATF_CHECK_EQ(EINVAL, errno);

	/* Unknown handle-scope flags must not cross the protocol boundary. */
	memset(&req, 0, sizeof(req));
	strlcpy(req.dataset, "badflags", sizeof(req.dataset));
	req.rights = ZH_PROPS_READ;
	req.flags = UINT32_C(0x80000000);
	req.lifetime = TZFSD_LEASE;
	ATF_CHECK_EQ(-1, tzfsd_request(chan, &req, &g));
	ATF_CHECK_EQ(EINVAL, errno);
	(void)close(chan);
}
ATF_TC_CLEANUP(persistent_and_badname, tc) { tzt_cleanup(); }

static int
raw_request(int chan, const void *request, size_t len, struct tzfsd_reply *rp)
{
	ssize_t n;

	n = send(chan, request, len, MSG_NOSIGNAL);
	if (n != (ssize_t)len)
		return (-1);
	n = recv(chan, rp, sizeof(*rp), 0);
	return (n == (ssize_t)sizeof(*rp) ? 0 : -1);
}

ATF_TC_WITH_CLEANUP(protocol_malformed);
ATF_TC_HEAD(protocol_malformed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "daemon rejects short, unterminated, reserved, and ambiguous requests");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(protocol_malformed, tc)
{
	struct tzfsd_request rq;
	struct tzfsd_reply rp;
	int chan;

	tzt_require(); tzt_pool_create(tc); tzt_daemon_start();
	chan = tzfsd_connect();
	ATF_REQUIRE(chan >= 0);
	begin_test_session(chan);
	memset(&rq, 0, sizeof(rq)); rq.op = TZFSD_OP_PING;
	ATF_REQUIRE_EQ(0, raw_request(chan, &rq, sizeof(rq) - 1, &rp));
	ATF_CHECK_EQ(EPROTO, rp.status);
	ATF_REQUIRE_EQ(0, tzfsd_ping(chan));

	memset(&rq, 0, sizeof(rq)); rq.op = TZFSD_OP_REQUEST;
	rq.rights = ZH_PROPS_READ; rq.lifetime = TZFSD_LEASE;
	memset(rq.dataset, 'x', sizeof(rq.dataset));
	ATF_REQUIRE_EQ(0, raw_request(chan, &rq, sizeof(rq), &rp));
	ATF_CHECK_EQ(EINVAL, rp.status);

	memset(&rq, 0, sizeof(rq)); rq.op = TZFSD_OP_REQUEST;
	rq.rights = ZH_PROPS_READ; rq.lifetime = TZFSD_LEASE;
	strlcpy(rq.dataset, "reserved", sizeof(rq.dataset)); rq._reserved[2] = 1;
	ATF_REQUIRE_EQ(0, raw_request(chan, &rq, sizeof(rq), &rp));
	ATF_CHECK_EQ(EINVAL, rp.status);

	memset(&rq, 0, sizeof(rq)); rq.op = TZFSD_OP_PING; rq.rights = 1;
	ATF_REQUIRE_EQ(0, raw_request(chan, &rq, sizeof(rq), &rp));
	ATF_CHECK_EQ(EINVAL, rp.status);
	memset(&rq, 0, sizeof(rq)); rq.op = UINT32_MAX;
	ATF_REQUIRE_EQ(0, raw_request(chan, &rq, sizeof(rq), &rp));
	ATF_CHECK_EQ(EOPNOTSUPP, rp.status);
	close(chan);
}
ATF_TC_CLEANUP(protocol_malformed, tc) { tzt_cleanup(); }

ATF_TC_WITH_CLEANUP(idle_client_isolated);
ATF_TC_HEAD(idle_client_isolated, tc)
{
	atf_tc_set_md_var(tc, "descr", "an idle client cannot block another client");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(idle_client_isolated, tc)
{
	struct tzfsd_request rq;
	struct tzfsd_reply rp;
	struct pollfd pfd;
	int idle, active;

	tzt_require(); tzt_pool_create(tc); tzt_daemon_start();
	idle = tzfsd_connect();
	active = tzfsd_connect();
	ATF_REQUIRE(idle >= 0 && active >= 0);
	begin_test_session(idle);
	begin_test_session(active);
	memset(&rq, 0, sizeof(rq)); rq.op = TZFSD_OP_PING;
	ATF_REQUIRE_EQ((ssize_t)sizeof(rq), send(active, &rq, sizeof(rq), 0));
	pfd.fd = active; pfd.events = POLLIN; pfd.revents = 0;
	ATF_REQUIRE_EQ(1, poll(&pfd, 1, 2000));
	ATF_REQUIRE_EQ((ssize_t)sizeof(rp), recv(active, &rp, sizeof(rp), 0));
	ATF_CHECK_EQ(0, rp.status);
	close(active); close(idle);
}
ATF_TC_CLEANUP(idle_client_isolated, tc) { tzt_cleanup(); }

ATF_TC_WITH_CLEANUP(lifetimes_and_session_recovery);
ATF_TC_HEAD(lifetimes_and_session_recovery, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "all lifetimes select the right generation and recover across restart");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(lifetimes_and_session_recovery, tc)
{
	static const char session_a[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	static const char session_b[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	struct tzfsd_req req;
	struct tzfsd_grant persistent, cache, boot, lease, resumed;
	char lease_dataset[TZFSD_DATASET_MAX], boot_dataset[TZFSD_DATASET_MAX];
	int chan;

	tzt_require(); tzt_pool_create(tc); tzt_daemon_start();
	chan = tzfsd_connect();
	ATF_REQUIRE(chan >= 0);
	memset(&req, 0, sizeof(req));
	strlcpy(req.dataset, "no-session", sizeof(req.dataset));
	req.rights = ZH_PROPS_READ;
	req.lifetime = TZFSD_LEASE;
	ATF_CHECK_ERRNO(ENXIO, tzfsd_request(chan, &req, &resumed) == -1);
	ATF_CHECK_ERRNO(EINVAL, tzfsd_begin_session(chan, "short") == -1);
	ATF_CHECK_ERRNO(EINVAL, tzfsd_begin_session(chan,
	    "gggggggggggggggggggggggggggggggg") == -1);
	ATF_REQUIRE_EQ(0, tzfsd_begin_session(chan, session_a));

#define REQUEST_ONE(key, life, result) do { \
	memset(&req, 0, sizeof(req)); \
	strlcpy(req.dataset, (key), sizeof(req.dataset)); \
	req.rights = ZH_PROPS_READ; \
	req.lifetime = (life); \
	ATF_REQUIRE_EQ(0, tzfsd_request(chan, &req, &(result))); \
	close((result).handle_fd); \
} while (0)
	REQUEST_ONE("p-life", TZFSD_PERSISTENT, persistent);
	REQUEST_ONE("c-life", TZFSD_CACHE, cache);
	REQUEST_ONE("b-life", TZFSD_BOOT, boot);
	REQUEST_ONE("l-life", TZFSD_LEASE, lease);
#undef REQUEST_ONE
	ATF_CHECK(strstr(persistent.dataset, "/persistent/p-life") != NULL);
	ATF_CHECK(strstr(cache.dataset, "/persistent/c-life") != NULL);
	ATF_CHECK(strstr(boot.dataset, "/ephemeral/boot-") != NULL);
	ATF_CHECK(strstr(lease.dataset, "/ephemeral/lease-") != NULL);
	strlcpy(lease_dataset, lease.dataset, sizeof(lease_dataset));
	strlcpy(boot_dataset, boot.dataset, sizeof(boot_dataset));
	close(chan);

	/*
	 * A storage-daemon restart reaps orphaned ephemeral leases at startup:
	 * nothing is connected yet, so every lease-* is a prior-life orphan and
	 * is destroyed.  The persistent roots and the current boot generation
	 * survive.  The service reconnects and gets a fresh lease of the same
	 * deterministic name.
	 */
	tzt_daemon_stop();
	tzt_daemon_start();
	chan = tzfsd_connect();
	ATF_REQUIRE(chan >= 0);
	ATF_CHECK_EQ(0, tzt_systemf("zfs list %s >/dev/null 2>&1",
	    boot_dataset));
	ATF_CHECK_EQ(0, tzt_systemf("zfs list %s >/dev/null 2>&1",
	    persistent.dataset));
	ATF_CHECK_EQ(0, tzt_systemf("zfs list %s >/dev/null 2>&1",
	    cache.dataset));
	ATF_CHECK(tzt_systemf("zfs list %s >/dev/null 2>&1", lease_dataset) != 0);
	ATF_REQUIRE_EQ(0, tzfsd_begin_session(chan, session_a));
	memset(&req, 0, sizeof(req));
	strlcpy(req.dataset, "l-life", sizeof(req.dataset));
	req.rights = ZH_PROPS_READ;
	req.lifetime = TZFSD_LEASE;
	ATF_REQUIRE_EQ(0, tzfsd_request(chan, &req, &resumed));
	ATF_CHECK_STREQ(lease_dataset, resumed.dataset);
	close(resumed.handle_fd);

	/*
	 * Concurrent sessions coexist: beginning a different session on another
	 * connection never reaps a live lease begun elsewhere.  Reaping is for
	 * orphans only, at startup — session-begin creates or opens, never
	 * destroys a sibling's lease.
	 */
	{
		int chan2 = tzfsd_connect();

		ATF_REQUIRE(chan2 >= 0);
		ATF_REQUIRE_EQ(0, tzfsd_begin_session(chan2, session_b));
		ATF_CHECK_EQ(0, tzt_systemf("zfs list %s >/dev/null 2>&1",
		    lease_dataset));
		close(chan2);
	}
	close(chan);
}
ATF_TC_CLEANUP(lifetimes_and_session_recovery, tc) { tzt_cleanup(); }

ATF_TC_WITH_CLEANUP(session_reconcile_refuses_snapshot_loss);
ATF_TC_HEAD(session_reconcile_refuses_snapshot_loss, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "reconciliation refuses to silently discard retained snapshots");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(session_reconcile_refuses_snapshot_loss, tc)
{
	struct tzfsd_req req;
	struct tzfsd_grant grant;
	int chan;

	tzt_require(); tzt_pool_create(tc); tzt_daemon_start();
	chan = tzfsd_connect();
	ATF_REQUIRE(chan >= 0);
	ATF_REQUIRE_EQ(0, tzfsd_begin_session(chan,
	    "11111111111111111111111111111111"));
	memset(&req, 0, sizeof(req));
	strlcpy(req.dataset, "retained", sizeof(req.dataset));
	req.rights = ZH_SNAPSHOT | ZH_PROPS_READ;
	req.lifetime = TZFSD_LEASE;
	ATF_REQUIRE_EQ(0, tzfsd_request(chan, &req, &grant));
	ATF_REQUIRE_EQ(0, tzfs_snapshot(grant.handle_fd, "keep"));
	close(grant.handle_fd);
	ATF_CHECK(tzfsd_begin_session(chan,
	    "22222222222222222222222222222222") == -1);
	ATF_CHECK_EQ(0, tzt_systemf("zfs list -t snapshot %s@keep "
	    ">/dev/null 2>&1", grant.dataset));
	close(chan);
}
ATF_TC_CLEANUP(session_reconcile_refuses_snapshot_loss, tc) { tzt_cleanup(); }

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, bare_lease);
	ATF_TP_ADD_TC(tp, rights_attenuation);
	ATF_TP_ADD_TC(tp, persistent_and_badname);
	ATF_TP_ADD_TC(tp, protocol_malformed);
	ATF_TP_ADD_TC(tp, idle_client_isolated);
	ATF_TP_ADD_TC(tp, lifetimes_and_session_recovery);
	ATF_TP_ADD_TC(tp, session_reconcile_refuses_snapshot_loss);
	return (atf_no_error());
}
