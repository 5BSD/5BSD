/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Pure-unit tests for bsdfilesystem(8)'s tenant-isolation core: the label->namespace
 * derivation and the request-validation predicates.  These exercise the
 * file-private logic of request.c directly through the BSDFILESYSTEM_TESTING accessors,
 * with no capability plane and no ZFS pool, so they run anywhere.  The tenant-
 * isolation invariant — distinct client labels always land in distinct dataset
 * namespaces, and a client can never name a bare "..", "/", or slash-bearing
 * key — is asserted here as the primary guard.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/mount.h>
#include <sys/zfshandle.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

#include "bsdfilesystem.h"

/*
 * valid_dataset() scans BSDFILESYSTEM_NAME_MAX bytes looking for the terminating NUL, so
 * every candidate must be materialized in a full-width, zero-filled key buffer
 * rather than passed as a bare short string literal.
 */
static bool
check_dataset(const char *s)
{
	char key[BSDFILESYSTEM_NAME_MAX];

	memset(key, 0, sizeof(key));
	ATF_REQUIRE(strlen(s) < sizeof(key));
	memcpy(key, s, strlen(s));
	return (bsdfilesystem_test_valid_dataset(key));
}

/*
 * The isolation property: many distinct client owners must derive to many
 * distinct namespace keys with no collision, and each key must be a single safe
 * dataset component (no '/').  derive_ns now names the namespace by the owner
 * key verbatim (so the container name is the ownership record for the
 * reconcile), so distinctness is inherent -- but the test still guards it, since
 * a regression that folded distinct owners together would alias one tenant's
 * storage onto another's.
 */
ATF_TC_WITHOUT_HEAD(distinct_labels_derive_distinct_namespaces);
ATF_TC_BODY(distinct_labels_derive_distinct_namespaces, tc)
{
#define	NLABELS	256
	static char ns[NLABELS][BSDFILESYSTEM_NAME_MAX];
	char label[64];
	unsigned i, j;

	for (i = 0; i < NLABELS; i++) {
		(void)snprintf(label, sizeof(label), "org.tenant.%u.svc", i);
		ATF_REQUIRE_MSG(bsdfilesystem_test_derive_ns(label, ns[i],
		    sizeof(ns[i])), "derive_ns failed for %s", label);
		ATF_CHECK_MSG(strcmp(ns[i], label) == 0,
		    "ns %s is not the owner key %s verbatim", ns[i], label);
		ATF_CHECK_MSG(strchr(ns[i], '/') == NULL,
		    "ns %s is not a single component", ns[i]);
		/* A derived namespace must itself be a valid dataset key. */
		ATF_CHECK_MSG(check_dataset(ns[i]),
		    "derived ns %s is not a valid dataset key", ns[i]);
	}
	for (i = 0; i < NLABELS; i++)
		for (j = i + 1; j < NLABELS; j++)
			ATF_CHECK_MSG(strcmp(ns[i], ns[j]) != 0,
			    "namespace collision: label %u and %u both -> %s",
			    i, j, ns[i]);
#undef NLABELS
}

/* derive_ns() must be a pure function of the label: stable across calls. */
ATF_TC_WITHOUT_HEAD(same_label_is_deterministic);
ATF_TC_BODY(same_label_is_deterministic, tc)
{
	char a[BSDFILESYSTEM_NAME_MAX], b[BSDFILESYSTEM_NAME_MAX];

	ATF_REQUIRE(bsdfilesystem_test_derive_ns("system.Bluetooth", a, sizeof(a)));
	ATF_REQUIRE(bsdfilesystem_test_derive_ns("system.Bluetooth", b, sizeof(b)));
	ATF_CHECK_STREQ(a, b);

	/* A different label must not collide with it. */
	ATF_REQUIRE(bsdfilesystem_test_derive_ns("system.Network", b, sizeof(b)));
	ATF_CHECK(strcmp(a, b) != 0);

	/* Empty/NULL owners are rejected, never silently namespaced. */
	ATF_CHECK(!bsdfilesystem_test_derive_ns("", a, sizeof(a)));
	ATF_CHECK(!bsdfilesystem_test_derive_ns(NULL, a, sizeof(a)));

	/* An owner key must be a single safe component: a '/' or a bare
	 * "."/".." must be refused so it can never escape its own subtree. */
	ATF_CHECK(!bsdfilesystem_test_derive_ns("has/slash", a, sizeof(a)));
	ATF_CHECK(!bsdfilesystem_test_derive_ns(".", a, sizeof(a)));
	ATF_CHECK(!bsdfilesystem_test_derive_ns("..", a, sizeof(a)));
}

/*
 * A dataset key must be a single safe path component: reject empty, ".", "..",
 * "/", and any name containing '/'; accept a normal component.
 */
ATF_TC_WITHOUT_HEAD(valid_dataset_accepts_only_safe_component);
ATF_TC_BODY(valid_dataset_accepts_only_safe_component, tc)
{

	ATF_CHECK(!check_dataset(""));
	ATF_CHECK(!check_dataset("/"));
	ATF_CHECK(!check_dataset("."));
	ATF_CHECK(!check_dataset(".."));
	ATF_CHECK(!check_dataset("a/b"));
	ATF_CHECK(!check_dataset("/leading"));
	ATF_CHECK(!check_dataset("trailing/"));
	ATF_CHECK(!check_dataset("../escape"));

	ATF_CHECK(check_dataset("claim"));
	ATF_CHECK(check_dataset("my-claim.0"));
	ATF_CHECK(check_dataset("foo..bar"));	/* embedded dots are legal */
}

/*
 * The C6 fix: ".." rejection is component-wise, not a substring scan.  A real
 * ".." path component (a ".." between slashes) is rejected, but a component that
 * merely embeds ".." (e.g. a device unit /dev/foo..bar) is accepted.
 */
ATF_TC_WITHOUT_HEAD(dotdot_is_component_wise);
ATF_TC_BODY(dotdot_is_component_wise, tc)
{

	/* Real ".." components -> rejected. */
	ATF_CHECK(bsdfilesystem_test_has_dotdot_component("/a/../b"));
	ATF_CHECK(bsdfilesystem_test_has_dotdot_component("/.."));
	ATF_CHECK(bsdfilesystem_test_has_dotdot_component("/../b"));
	ATF_CHECK(bsdfilesystem_test_has_dotdot_component("/a/.."));
	ATF_CHECK(bsdfilesystem_test_has_dotdot_component("/a/b/../c"));

	/* Embedded dots inside a component -> accepted (no ".." component). */
	ATF_CHECK(!bsdfilesystem_test_has_dotdot_component("/dev/foo..bar"));
	ATF_CHECK(!bsdfilesystem_test_has_dotdot_component("/a/..b/c"));
	ATF_CHECK(!bsdfilesystem_test_has_dotdot_component("/a/b../c"));
	ATF_CHECK(!bsdfilesystem_test_has_dotdot_component("/..a"));
	ATF_CHECK(!bsdfilesystem_test_has_dotdot_component("/a/b/c"));
	ATF_CHECK(!bsdfilesystem_test_has_dotdot_component("/"));
}

/*
 * BSDFILESYSTEM_OP_OPEN is independent of the ZFS dataset plane.  Installer media has
 * no zroot yet, so the provider must still be able to broker a policy-granted
 * path from its retained root descriptor while every pool descriptor is -1.
 */
ATF_TC_WITHOUT_HEAD(isolated_open_does_not_require_pool);
ATF_TC_BODY(isolated_open_does_not_require_pool, tc)
{
	static const char label[] = "system.Auth/bsdauth";
	static const char contents[] = "installer-policy\n";
	struct bsdfilesystem_open_policy *pol;
	struct bsdfilesystem_open_request rq;
	struct bsdfilesystem_state st;
	char path[] = "/tmp/bsdfilesystem-open.XXXXXX";
	char buf[sizeof(contents)];
	int fd, seed;

	seed = mkstemp(path);
	ATF_REQUIRE(seed >= 0);
	ATF_REQUIRE_EQ((ssize_t)(sizeof(contents) - 1),
	    write(seed, contents, sizeof(contents) - 1));
	ATF_REQUIRE_EQ(0, close(seed));

	memset(&st, 0, sizeof(st));
	st.persistent_fd = st.ephemeral_fd = -1;
	st.boot_fd = st.lease_fd = -1;
	st.root_fd = open("/", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(st.root_fd >= 0);
	st.cfg.nopen_policy = 1;
	pol = &st.cfg.open_policy[0];
	(void)strlcpy(pol->label, label, sizeof(pol->label));
	(void)strlcpy(pol->path, path, sizeof(pol->path));
	pol->rights = BSDFILESYSTEM_OPEN_READ;

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_OPEN;
	rq.rights = BSDFILESYSTEM_OPEN_READ;
	(void)strlcpy(rq.path, path, sizeof(rq.path));
	fd = bsdfilesystem_test_grant_open(&st, label, &rq);
	ATF_REQUIRE_MSG(fd >= 0, "isolated open without pool: %s",
	    strerror(errno));
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE_EQ((ssize_t)(sizeof(contents) - 1),
	    read(fd, buf, sizeof(buf) - 1));
	ATF_CHECK_STREQ(contents, buf);

	ATF_REQUIRE_EQ(0, close(fd));
	ATF_REQUIRE_EQ(0, close(st.root_fd));
	ATF_REQUIRE_EQ(0, unlink(path));
}

/*
 * Only the expected no-pool condition on a read-only ISO is quiet.  A missing
 * pool on an installed system, or any other error on installer media, must
 * still reach the operator as a warning.
 */
ATF_TC_WITHOUT_HEAD(installer_media_missing_pool_is_expected);
ATF_TC_BODY(installer_media_missing_pool_is_expected, tc)
{

	ATF_CHECK(bsdfilesystem_test_pool_missing_expected("cd9660", MNT_RDONLY,
	    ENOENT));
	ATF_CHECK(!bsdfilesystem_test_pool_missing_expected("cd9660", 0, ENOENT));
	ATF_CHECK(!bsdfilesystem_test_pool_missing_expected("zfs", MNT_RDONLY,
	    ENOENT));
	ATF_CHECK(!bsdfilesystem_test_pool_missing_expected("cd9660", MNT_RDONLY,
	    EIO));
}

/* Installer-selected ZFS pool names, including legal colons, configure the
 * complete derived dataset layout rather than leaving it bound to zroot. */
ATF_TC_WITHOUT_HEAD(config_accepts_selected_pool_name);
ATF_TC_BODY(config_accepts_selected_pool_name, tc)
{
	struct bsdfilesystem_config cfg;
	char path[] = "/tmp/bsdfilesystem-config.XXXXXX";
	static const char text[] = "pool = \"fast:pool-1\";\n";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ((ssize_t)(sizeof(text) - 1),
	    write(fd, text, sizeof(text) - 1));
	ATF_REQUIRE_EQ(0, close(fd));
	bsdfilesystem_config_defaults(&cfg);
	ATF_REQUIRE_EQ(0, bsdfilesystem_config_load(&cfg, path));
	ATF_CHECK_STREQ("fast:pool-1", cfg.pool);
	ATF_CHECK_STREQ("fast:pool-1/Capabilities", cfg.base);
	ATF_CHECK_STREQ("fast:pool-1/Capabilities/Data", cfg.persistent);
	ATF_CHECK_STREQ("fast:pool-1/Capabilities/ephemeral", cfg.ephemeral);
	ATF_REQUIRE_EQ(0, unlink(path));
}

/*
 * The reconcile cadence is configurable but bounded: a value inside
 * [MIN, MAX] is taken, anything else (too small, too large, not an integer)
 * is a config error rather than a silently clamped grace window.
 */
static int
load_text(struct bsdfilesystem_config *cfg, const char *text)
{
	char path[] = "/tmp/bsdfilesystem-config.XXXXXX";
	int fd, rc;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ((ssize_t)strlen(text), write(fd, text, strlen(text)));
	ATF_REQUIRE_EQ(0, close(fd));
	bsdfilesystem_config_defaults(cfg);
	rc = bsdfilesystem_config_load(cfg, path);
	(void)unlink(path);
	return (rc);
}

ATF_TC_WITHOUT_HEAD(config_reclaim_interval_is_bounded);
ATF_TC_BODY(config_reclaim_interval_is_bounded, tc)
{
	struct bsdfilesystem_config cfg;

	ATF_REQUIRE_EQ(0, load_text(&cfg, "pool = \"zroot\";\n"));
	ATF_CHECK_EQ((unsigned)BSDFILESYSTEM_RECLAIM_INTERVAL_DEFAULT, cfg.reclaim_interval);
	ATF_REQUIRE_EQ(0, load_text(&cfg, "reclaim_interval = 20;\n"));
	ATF_CHECK_EQ(20u, cfg.reclaim_interval);
	ATF_REQUIRE_EQ(0, load_text(&cfg, "reclaim_interval = 10;\n"));
	ATF_CHECK_EQ(10u, cfg.reclaim_interval);
	ATF_REQUIRE_EQ(0, load_text(&cfg, "reclaim_interval = 86400;\n"));
	ATF_CHECK_EQ(86400u, cfg.reclaim_interval);
	/* UCL time suffixes are accepted */
	ATF_REQUIRE_EQ(0, load_text(&cfg, "reclaim_interval = 5min;\n"));
	ATF_CHECK_EQ(300u, cfg.reclaim_interval);
	ATF_REQUIRE_EQ(0, load_text(&cfg, "reclaim_interval = 1h;\n"));
	ATF_CHECK_EQ(3600u, cfg.reclaim_interval);
	/* out of range keeps the default rather than failing the load */
	ATF_REQUIRE_EQ(0, load_text(&cfg, "reclaim_interval = 9;\n"));
	ATF_CHECK_EQ((unsigned)BSDFILESYSTEM_RECLAIM_INTERVAL_DEFAULT, cfg.reclaim_interval);
	ATF_REQUIRE_EQ(0, load_text(&cfg, "reclaim_interval = 0;\n"));
	ATF_CHECK_EQ((unsigned)BSDFILESYSTEM_RECLAIM_INTERVAL_DEFAULT, cfg.reclaim_interval);
	ATF_REQUIRE_EQ(0, load_text(&cfg, "reclaim_interval = -20;\n"));
	ATF_CHECK_EQ((unsigned)BSDFILESYSTEM_RECLAIM_INTERVAL_DEFAULT, cfg.reclaim_interval);
	ATF_REQUIRE_EQ(0, load_text(&cfg, "reclaim_interval = 86401;\n"));
	ATF_CHECK_EQ((unsigned)BSDFILESYSTEM_RECLAIM_INTERVAL_DEFAULT, cfg.reclaim_interval);
	ATF_REQUIRE_EQ(0, load_text(&cfg, "reclaim_interval = 2d;\n"));
	ATF_CHECK_EQ((unsigned)BSDFILESYSTEM_RECLAIM_INTERVAL_DEFAULT, cfg.reclaim_interval);
	/* the wrong type is still a config error */
	ATF_CHECK_EQ(-1, load_text(&cfg, "reclaim_interval = \"20\";\n"));
	ATF_CHECK_EQ(-1, load_text(&cfg, "reclaim_interval = true;\n"));
}

/*
 * Request-message hygiene: any nonzero byte in the reserved field makes the
 * message ambiguous and must be rejected, and a well-formed REQUEST must be
 * accepted.  This is the storage-request half of the _reserved validation.
 */
ATF_TC_WITHOUT_HEAD(request_reserved_must_be_zero);
ATF_TC_BODY(request_reserved_must_be_zero, tc)
{
	struct bsdfilesystem_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_REQUEST;
	rq.rights = 1;
	rq.lifetime = BSDFILESYSTEM_PERSISTENT;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));
	/* session must be empty for REQUEST; dataset non-empty. */
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));

	/* Any nonzero reserved byte -> rejected. */
	rq._reserved[0] = 1;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq._reserved[0] = 0;
	rq._reserved[0] = 0x80;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq._reserved[0] = 0;

	/* An out-of-range deliver mode -> rejected. */
	rq.deliver = BSDFILESYSTEM_DELIVER_MOUNTED_RO + 1;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.deliver = 0;

	/* An unterminated dataset field is also rejected. */
	memset(rq.dataset, 'x', sizeof(rq.dataset));
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
}

/*
 * A REQUEST may carry a nonzero quota (per-claim refquota override); it is a
 * first-class field, not reserved space, so validation must accept it.  The
 * floor (too-small values) is enforced later in grant(), asserted separately.
 */
ATF_TC_WITHOUT_HEAD(request_accepts_quota_override);
ATF_TC_BODY(request_accepts_quota_override, tc)
{
	struct bsdfilesystem_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_REQUEST;
	rq.rights = 1;
	rq.lifetime = BSDFILESYSTEM_PERSISTENT;
	rq.quota = BSDFILESYSTEM_MIN_REFQUOTA;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));

	/* 0 (use the configured default) is equally well-formed. */
	rq.quota = 0;
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
}

/*
 * BSDFILESYSTEM_OP_DESTROY message shape: it names a claim exactly as REQUEST does
 * (dataset + lifetime) and must carry no rights, flags, quota, or session, and
 * a nonzero reserved byte is rejected as ambiguous.  This is the validation
 * half of the owner-scoped reclaim op — the handler then binds it to the
 * caller's own namespace (see destroy_resolves_under_caller_ns).
 */
ATF_TC_WITHOUT_HEAD(destroy_request_shape_is_validated);
ATF_TC_BODY(destroy_request_shape_is_validated, tc)
{
	struct bsdfilesystem_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_DESTROY;
	rq.lifetime = BSDFILESYSTEM_PERSISTENT;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));

	/* CACHE shares the persistent tree and is equally destroyable. */
	rq.lifetime = BSDFILESYSTEM_CACHE;
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));

	/* Any nonzero reserved byte -> rejected. */
	rq._reserved[0] = 0x7f;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq._reserved[0] = 0;

	/* rights, flags, quota, and session must all be zero for DESTROY. */
	rq.rights = 1;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.rights = 0;
	rq.flags = 1;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.flags = 0;
	rq.quota = BSDFILESYSTEM_MIN_REFQUOTA;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.quota = 0;
	rq.session[0] = 'a';
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.session[0] = '\0';

	/* An unterminated dataset field is rejected (message hygiene). */
	memset(rq.dataset, 'x', sizeof(rq.dataset));
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
}

/*
 * grant()'s quota floor: a nonzero per-request quota below BSDFILESYSTEM_MIN_REFQUOTA is
 * rejected with EINVAL before any ZFS handle is opened, so this runs purely
 * against a zeroed state (every retained fd == -1).  quota == 0 (the default)
 * and a sane quota fall through to the ZFS path, which is exercised only in the
 * live provider case.
 */
ATF_TC_WITHOUT_HEAD(quota_floor_is_enforced);
ATF_TC_BODY(quota_floor_is_enforced, tc)
{
	struct bsdfilesystem_state st;
	struct bsdfilesystem_request rq;
	char ds[BSDFILESYSTEM_DATASET_MAX];

	memset(&st, 0, sizeof(st));
	st.persistent_fd = st.ephemeral_fd = -1;
	st.boot_fd = st.lease_fd = st.root_fd = -1;

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_REQUEST;
	rq.rights = 1;			/* ZH_PROPS_READ; any nonzero right */
	rq.lifetime = BSDFILESYSTEM_PERSISTENT;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));

	/* A minimal-but-nonzero quota (1 byte) is below the floor -> EINVAL. */
	rq.quota = 1;
	errno = 0;
	ATF_CHECK_EQ(-1,
	    bsdfilesystem_test_grant(&st, "org.test.tenant", &rq, ds, sizeof(ds)));
	ATF_CHECK_EQ(EINVAL, errno);

	/* One byte under the floor is still rejected. */
	rq.quota = BSDFILESYSTEM_MIN_REFQUOTA - 1;
	errno = 0;
	ATF_CHECK_EQ(-1,
	    bsdfilesystem_test_grant(&st, "org.test.tenant", &rq, ds, sizeof(ds)));
	ATF_CHECK_EQ(EINVAL, errno);
}

/*
 * A syntactically valid storage request on installer/live media has no pool
 * descriptor.  The provider must report the unavailable backend as ENXIO,
 * rather than accidentally passing fd -1 into TrustedZFS and leaking EBADF.
 */
ATF_TC_WITHOUT_HEAD(request_without_pool_is_enxio);
ATF_TC_BODY(request_without_pool_is_enxio, tc)
{
	struct bsdfilesystem_state st;
	struct bsdfilesystem_request rq;
	char ds[BSDFILESYSTEM_DATASET_MAX];

	memset(&st, 0, sizeof(st));
	st.persistent_fd = st.ephemeral_fd = -1;
	st.boot_fd = st.lease_fd = st.root_fd = -1;

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_REQUEST;
	rq.rights = 1;
	rq.lifetime = BSDFILESYSTEM_PERSISTENT;
	(void)strlcpy(rq.dataset, "state", sizeof(rq.dataset));

	/*
	 * grant() receives the flat resource owner switchboard stamps on the
	 * channel ("cap.<hex>"), never a raw label -- so the client here is a
	 * slash-free owner key, which derive_ns accepts; the request is otherwise
	 * valid, so the missing pool (not a bad owner) is what must surface, as
	 * ENXIO.
	 */
	errno = 0;
	ATF_CHECK_EQ(-1,
	    bsdfilesystem_test_grant(&st, "cap.00112233445566778899aabbccddeeff", &rq,
	    ds, sizeof(ds)));
	ATF_CHECK_EQ(ENXIO, errno);
}

/*
 * The DESTROY owner-scoping invariant, asserted at the derivation layer the
 * handler relies on: DESTROY resolves the claim under derive_ns(caller_label),
 * exactly as REQUEST does.  Because distinct labels derive to distinct
 * namespaces and a dataset key may not contain '/', a caller can only ever name
 * — and thus destroy — a claim inside its own namespace, never another label's.
 */
ATF_TC_WITHOUT_HEAD(destroy_resolves_under_caller_ns);
ATF_TC_BODY(destroy_resolves_under_caller_ns, tc)
{
	char ns_a[BSDFILESYSTEM_NAME_MAX], ns_b[BSDFILESYSTEM_NAME_MAX];
	char cross[BSDFILESYSTEM_NAME_MAX];

	ATF_REQUIRE(bsdfilesystem_test_derive_ns("system.TenantA", ns_a, sizeof(ns_a)));
	ATF_REQUIRE(bsdfilesystem_test_derive_ns("system.TenantB", ns_b, sizeof(ns_b)));
	/* A DESTROY from A can never resolve into B's namespace. */
	ATF_CHECK_MSG(strcmp(ns_a, ns_b) != 0,
	    "two labels shared a namespace (%s); DESTROY would cross tenants",
	    ns_a);

	/*
	 * Even armed with B's namespace string, A cannot express "B's ns / claim"
	 * as a DESTROY dataset key: it contains '/', so valid_dataset rejects it.
	 */
	memset(cross, 0, sizeof(cross));
	(void)snprintf(cross, sizeof(cross), "%.20s/claim", ns_b);
	ATF_CHECK_MSG(!bsdfilesystem_test_valid_dataset(cross),
	    "a slash-bearing cross-namespace DESTROY key was accepted: %s",
	    cross);
}

/*
 * BSDFILESYSTEM_OP_LIST message hygiene and fail-closed scoping, asserted directly
 * against grant_list() with a zeroed state (every retained fd == -1): the
 * additive flags/_reserved fields must be zero, an unnamespaceable caller label
 * is rejected, and a well-formed LIST with no imported pool fails closed with
 * ENXIO — proving the walk is gated on the daemon's own retained persistent
 * parent (derived from the caller's label) and never touches ZFS without one.
 */
ATF_TC_WITHOUT_HEAD(list_request_hygiene_and_no_pool);
ATF_TC_BODY(list_request_hygiene_and_no_pool, tc)
{
	struct bsdfilesystem_state st;
	struct bsdfilesystem_list_request rq;
	struct bsdfilesystem_list_reply rp;

	memset(&st, 0, sizeof(st));
	st.persistent_fd = st.ephemeral_fd = -1;
	st.boot_fd = st.lease_fd = st.root_fd = -1;

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_LIST;

	/* A nonzero flags field is ambiguous -> EINVAL before anything is walked. */
	memset(&rp, 0, sizeof(rp));
	rq.flags = 1;
	errno = 0;
	ATF_CHECK_EQ(-1,
	    bsdfilesystem_test_grant_list(&st, "org.test.tenant", &rq, &rp));
	ATF_CHECK_EQ(EINVAL, errno);
	rq.flags = 0;

	/* A nonzero reserved field is likewise rejected. */
	memset(&rp, 0, sizeof(rp));
	rq._reserved = 0x80;
	errno = 0;
	ATF_CHECK_EQ(-1,
	    bsdfilesystem_test_grant_list(&st, "org.test.tenant", &rq, &rp));
	ATF_CHECK_EQ(EINVAL, errno);
	rq._reserved = 0;

	/*
	 * With no pool imported (persistent_fd == -1) the walk is rooted at the
	 * daemon's own retained Data parent, so it fails closed with ENXIO before
	 * ever consulting the caller's container -- an unavailable backend is
	 * reported as unavailable, never as another label's storage.  This holds
	 * for an empty container (a bundleless caller) and a well-formed one alike.
	 */
	memset(&rp, 0, sizeof(rp));
	errno = 0;
	ATF_CHECK_EQ(-1, bsdfilesystem_test_grant_list(&st, "", &rq, &rp));
	ATF_CHECK_EQ(ENXIO, errno);

	memset(&rp, 0, sizeof(rp));
	errno = 0;
	ATF_CHECK_EQ(-1,
	    bsdfilesystem_test_grant_list(&st, "Bundle/unit", &rq, &rp));
	ATF_CHECK_EQ(ENXIO, errno);
}

/*
 * The LIST owner-scoping invariant, asserted at the derivation layer the
 * handler roots its walk at: grant_list enumerates only children of
 * derive_ns(caller_label).  Because distinct labels derive to distinct
 * namespaces, one label's LIST can never enumerate another label's claims —
 * there is no wire argument that could redirect the walk to a different ns.
 */
ATF_TC_WITHOUT_HEAD(list_scopes_to_caller_ns);
ATF_TC_BODY(list_scopes_to_caller_ns, tc)
{
	char ns_a[BSDFILESYSTEM_NAME_MAX], ns_b[BSDFILESYSTEM_NAME_MAX];

	ATF_REQUIRE(bsdfilesystem_test_derive_ns("system.TenantA", ns_a, sizeof(ns_a)));
	ATF_REQUIRE(bsdfilesystem_test_derive_ns("system.TenantB", ns_b, sizeof(ns_b)));
	ATF_CHECK_MSG(strcmp(ns_a, ns_b) != 0,
	    "two labels shared a namespace (%s); LIST would cross tenants", ns_a);
}

/*
 * bsdfilesystem_destroy_tree is the reaper's only destructive primitive: it must refuse
 * anything but a single relative component (a '/' could name a subtree outside
 * the caller's owner, and the reaper's owner keys are single components) and
 * never touch a bad parent descriptor.  No pool is needed to prove the guards.
 */
ATF_TC_WITHOUT_HEAD(destroy_tree_rejects_malformed_relnames);
ATF_TC_BODY(destroy_tree_rejects_malformed_relnames, tc)
{
	ATF_CHECK_ERRNO(EINVAL, bsdfilesystem_destroy_tree(-1, NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, bsdfilesystem_destroy_tree(-1, "") == -1);
	ATF_CHECK_ERRNO(EINVAL, bsdfilesystem_destroy_tree(-1, "a/b") == -1);
	ATF_CHECK_ERRNO(EINVAL, bsdfilesystem_destroy_tree(-1, "/a") == -1);
	ATF_CHECK_ERRNO(EINVAL, bsdfilesystem_destroy_tree(-1, "a/") == -1);
	/* A well-formed name against a bad parent fails on the parent, not silently. */
	ATF_CHECK_EQ(-1, bsdfilesystem_destroy_tree(-1, "Bundle"));
	ATF_CHECK(errno == EBADF || errno == ENOTCAPABLE || errno == EINVAL);
	/*
	 * The snapshot sweep the reap runs before destroying a dataset fails on
	 * a bad handle rather than reporting "no snapshots" (which would let the
	 * destroy proceed to a misleading EBUSY).
	 */
	ATF_CHECK_EQ(-1, bsdfilesystem_destroy_snapshots(-1));
	ATF_CHECK(errno == EBADF || errno == ENOTCAPABLE || errno == EINVAL);
}

/*
 * Container scopes (docs/capability-container-model.md): UNIT is the private
 * container, SHARED the bundle's shared one, GROUP a cross-bundle container the
 * caller's bundle must be a stamped member of.  A bundleless client has none,
 * and a group name is validated as a single safe component even when listed.
 */
ATF_TC_WITHOUT_HEAD(scoped_namespaces_and_group_membership);
ATF_TC_BODY(scoped_namespaces_and_group_membership, tc)
{
	static const char groups[4][64] = { "org.example.shared", "", "team", "" };
	char ns[256];

	ATF_CHECK(bsdfilesystem_test_scoped_ns("Test/worker", groups, BSDFILESYSTEM_SCOPE_UNIT,
	    "", BSDFILESYSTEM_PERSISTENT, ns, sizeof(ns)));
	ATF_CHECK_STREQ("Test/worker/persistent", ns);
	ATF_CHECK(bsdfilesystem_test_scoped_ns("Test/worker", groups, BSDFILESYSTEM_SCOPE_UNIT,
	    "", BSDFILESYSTEM_CACHE, ns, sizeof(ns)));
	ATF_CHECK_STREQ("Test/worker/cache", ns);
	ATF_CHECK(bsdfilesystem_test_scoped_ns("Test/worker", groups, BSDFILESYSTEM_SCOPE_SHARED,
	    "", BSDFILESYSTEM_PERSISTENT, ns, sizeof(ns)));
	ATF_CHECK_STREQ("Test/shared/persistent", ns);
	ATF_CHECK(bsdfilesystem_test_scoped_ns("Test/other", groups, BSDFILESYSTEM_SCOPE_SHARED,
	    "", BSDFILESYSTEM_CACHE, ns, sizeof(ns)));
	ATF_CHECK_STREQ("Test/shared/cache", ns);		/* any unit of Test */
	ATF_CHECK(bsdfilesystem_test_scoped_ns("Test/worker", groups, BSDFILESYSTEM_SCOPE_GROUP,
	    "org.example.shared", BSDFILESYSTEM_PERSISTENT, ns, sizeof(ns)));
	ATF_CHECK_STREQ("Shared/org.example.shared/persistent", ns);
	ATF_CHECK(bsdfilesystem_test_scoped_ns("Test/worker", groups, BSDFILESYSTEM_SCOPE_GROUP,
	    "team", BSDFILESYSTEM_CACHE, ns, sizeof(ns)));
	ATF_CHECK_STREQ("Shared/team/cache", ns);
	/* Not a member: denied, even for a well-formed group. */
	ATF_CHECK(!bsdfilesystem_test_scoped_ns("Test/worker", groups, BSDFILESYSTEM_SCOPE_GROUP,
	    "org.example.other", BSDFILESYSTEM_PERSISTENT, ns, sizeof(ns)));
	/* Empty slots never match an empty or bogus group. */
	ATF_CHECK(!bsdfilesystem_test_scoped_ns("Test/worker", groups, BSDFILESYSTEM_SCOPE_GROUP,
	    "", BSDFILESYSTEM_PERSISTENT, ns, sizeof(ns)));
	ATF_CHECK(!bsdfilesystem_test_scoped_ns("Test/worker", groups, BSDFILESYSTEM_SCOPE_GROUP,
	    NULL, BSDFILESYSTEM_PERSISTENT, ns, sizeof(ns)));
	/* No stamped membership at all (a bundleless or unlisted client). */
	ATF_CHECK(!bsdfilesystem_test_scoped_ns("Test/worker", NULL, BSDFILESYSTEM_SCOPE_GROUP,
	    "team", BSDFILESYSTEM_PERSISTENT, ns, sizeof(ns)));
	/* A listed name that is not a safe component is still refused. */
	{
		static const char evil[4][64] = { "../up", "a/b", "", "" };

		ATF_CHECK(!bsdfilesystem_test_scoped_ns("Test/worker", evil,
		    BSDFILESYSTEM_SCOPE_GROUP, "../up", BSDFILESYSTEM_PERSISTENT, ns, sizeof(ns)));
		ATF_CHECK(!bsdfilesystem_test_scoped_ns("Test/worker", evil,
		    BSDFILESYSTEM_SCOPE_GROUP, "a/b", BSDFILESYSTEM_PERSISTENT, ns, sizeof(ns)));
	}
	/* Bundleless clients hold no durable storage in any scope. */
	ATF_CHECK(!bsdfilesystem_test_scoped_ns("", groups, BSDFILESYSTEM_SCOPE_UNIT, "",
	    BSDFILESYSTEM_PERSISTENT, ns, sizeof(ns)));
	ATF_CHECK(!bsdfilesystem_test_scoped_ns("", groups, BSDFILESYSTEM_SCOPE_SHARED, "",
	    BSDFILESYSTEM_PERSISTENT, ns, sizeof(ns)));
	ATF_CHECK(!bsdfilesystem_test_scoped_ns("", groups, BSDFILESYSTEM_SCOPE_GROUP, "team",
	    BSDFILESYSTEM_PERSISTENT, ns, sizeof(ns)));
	/* Unknown scope. */
	ATF_CHECK(!bsdfilesystem_test_scoped_ns("Test/worker", groups, 3, "",
	    BSDFILESYSTEM_PERSISTENT, ns, sizeof(ns)));
	/* Too small an output buffer never yields a truncated namespace. */
	ATF_CHECK(!bsdfilesystem_test_scoped_ns("Test/worker", groups, BSDFILESYSTEM_SCOPE_GROUP,
	    "org.example.shared", BSDFILESYSTEM_PERSISTENT, ns, 8));
}

/* Wire rules for scope/group on every op. */
ATF_TC_WITHOUT_HEAD(request_scope_rules);
/*
 * Delivery shapes: DELIVER_MOUNTED and DELIVER_MOUNTED_RO both require the
 * claim to carry ZH_MOUNT (bsdfilesystem mounts server-side); an unknown deliver value
 * is rejected; a non-REQUEST op never carries a deliver mode.
 */
ATF_TC_WITHOUT_HEAD(deliver_mode_rules);
ATF_TC_BODY(deliver_mode_rules, tc)
{
	struct bsdfilesystem_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_REQUEST;
	rq.rights = ZH_MOUNT;
	rq.lifetime = BSDFILESYSTEM_PERSISTENT;
	strlcpy(rq.dataset, "env", sizeof(rq.dataset));
	rq.deliver = BSDFILESYSTEM_DELIVER_HANDLE;
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	rq.deliver = BSDFILESYSTEM_DELIVER_MOUNTED;
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	rq.deliver = BSDFILESYSTEM_DELIVER_MOUNTED_RO;
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	rq.scope = BSDFILESYSTEM_SCOPE_SHARED;		/* the shared-env shape */
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	/* a read-only view never sizes the store; the caller's own uid/gid
	 * (what the library always sends) is tolerated and ignored */
	rq.quota = 1 << 20;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.quota = 0;
	rq.owner_uid = 1001;
	rq.owner_gid = 1001;
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	rq.owner_uid = 0;
	rq.owner_gid = 0;
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	rq.deliver = BSDFILESYSTEM_DELIVER_MOUNTED;
	rq.quota = 1 << 20;
	rq.owner_uid = 1001;
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));	/* RW may size and own */
	rq.quota = 0;
	rq.owner_uid = 0;
	rq.deliver = BSDFILESYSTEM_DELIVER_MOUNTED_RO;
	rq.deliver = BSDFILESYSTEM_DELIVER_MOUNTED_RO + 1;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));	/* unknown shape */
	rq.deliver = 0xff;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	/* Mounted delivery of a claim without ZH_MOUNT is meaningless. */
	rq.rights = ZH_PROPS_READ;
	rq.deliver = BSDFILESYSTEM_DELIVER_MOUNTED;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.deliver = BSDFILESYSTEM_DELIVER_MOUNTED_RO;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.deliver = BSDFILESYSTEM_DELIVER_HANDLE;
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	/* DESTROY/RELEASE/PING never carry a deliver mode. */
	rq.rights = 0;
	rq.scope = 0;
	rq.lifetime = 0;
	rq.op = BSDFILESYSTEM_OP_RELEASE;
	rq.deliver = BSDFILESYSTEM_DELIVER_MOUNTED_RO;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.op = BSDFILESYSTEM_OP_DESTROY;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.op = BSDFILESYSTEM_OP_PING;
	rq.dataset[0] = '\0';
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.deliver = 0;
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	/* no op but REQUEST carries owner credentials */
	rq.owner_uid = 1;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.owner_uid = 0;
	rq.op = BSDFILESYSTEM_OP_RELEASE;
	strlcpy(rq.dataset, "x", sizeof(rq.dataset));
	rq.owner_gid = 1;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.owner_gid = 0;
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
}

/*
 * Claim and container names are a positive charset.  A leading '@', '#' or
 * '%' would name a snapshot, bookmark or receive placeholder of the PARENT
 * (one level above the claim); '/' and '..' would escape; a leading '.' or
 * '-' is a hazard for every tool.  The reserved names "Shared" (the group
 * container root) and "shared" (the bundle-shared scope) may not be a
 * bundle or unit.
 */
ATF_TC_WITHOUT_HEAD(names_are_a_positive_charset);
ATF_TC_BODY(names_are_a_positive_charset, tc)
{
	const char *good[] = { "state", "env", "a.b-c_d:e", "X1", "org.example.x" };
	const char *bad[] = { "", ".", "..", "@snap", "#bm", "%recv", "-x",
	    ".hidden", "a/b", "/a", "a/", " x", "x ", "a\nb", "a\tb", "a b",
	    "\xc3\xa9", "a*b", "a?b", "a@b" };
	size_t i;

	for (i = 0; i < sizeof(good) / sizeof(good[0]); i++)
		ATF_CHECK_MSG(bsdfilesystem_test_valid_dataset(good[i]),
		    "rejected valid name '%s'", good[i]);
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
		ATF_CHECK_MSG(!bsdfilesystem_test_valid_dataset(bad[i]),
		    "accepted invalid name '%s'", bad[i]);
	ATF_CHECK(bsdfilesystem_test_valid_container("App/worker"));
	ATF_CHECK(bsdfilesystem_test_valid_container("Test/reclaimprobe"));
	ATF_CHECK(!bsdfilesystem_test_valid_container("Shared/worker"));
	ATF_CHECK(!bsdfilesystem_test_valid_container("shared/worker"));
	ATF_CHECK(!bsdfilesystem_test_valid_container("SHARED/worker"));
	ATF_CHECK(!bsdfilesystem_test_valid_container("App/shared"));
	ATF_CHECK(!bsdfilesystem_test_valid_container("App/Shared"));
	ATF_CHECK(!bsdfilesystem_test_valid_container("App/@x"));
	ATF_CHECK(!bsdfilesystem_test_valid_container("@x/unit"));
	ATF_CHECK(!bsdfilesystem_test_valid_container("App"));
	ATF_CHECK(!bsdfilesystem_test_valid_container("App/u/v"));
	ATF_CHECK(!bsdfilesystem_test_valid_container("/u"));
	ATF_CHECK(!bsdfilesystem_test_valid_container("App/"));
	ATF_CHECK(!bsdfilesystem_test_valid_container(NULL));
}

/*
 * A connection anchors one mount PER CLAIM: several claims coexist, a
 * re-claim of the same dataset replaces its anchor (never leaving the mount
 * unanchored), RELEASE/DESTROY drop exactly the named claim's anchor, the
 * table is bounded (EMFILE, the descriptor left to the caller), and teardown
 * closes everything.  Driven with pipe descriptors; closing is observable as
 * EBADF on the old descriptor.
 */
ATF_TC_WITHOUT_HEAD(anchors_are_per_claim);
ATF_TC_BODY(anchors_are_per_claim, tc)
{
	struct tzfs_conn *conn = bsdfilesystem_test_conn_new();
	char name[64];
	int p[2], fds[BSDFILESYSTEM_CONN_MAX_CLAIMS + 1], i, extra, again;

	ATF_REQUIRE(conn != NULL);
	ATF_REQUIRE_EQ(0, pipe(p));
	ATF_CHECK_EQ(0u, bsdfilesystem_test_anchor_live(conn));

	/* persistent + cache of one unit coexist (the reclaimprobe shape) */
	fds[0] = dup(p[0]); fds[1] = dup(p[0]);
	ATF_CHECK_EQ(0, bsdfilesystem_test_anchor_add(conn,
	    "zroot/Capabilities/Data/T/u/persistent/state", fds[0]));
	ATF_CHECK_EQ(0, bsdfilesystem_test_anchor_add(conn,
	    "zroot/Capabilities/Data/T/u/cache/scratch", fds[1]));
	ATF_CHECK_EQ(2u, bsdfilesystem_test_anchor_live(conn));
	ATF_CHECK(fcntl(fds[0], F_GETFD) != -1);	/* first claim still anchored */

	/* re-claim replaces: the OLD anchor closes, the new one is held */
	again = dup(p[0]);
	ATF_CHECK_EQ(0, bsdfilesystem_test_anchor_add(conn,
	    "zroot/Capabilities/Data/T/u/persistent/state", again));
	ATF_CHECK_EQ(2u, bsdfilesystem_test_anchor_live(conn));
	ATF_CHECK_ERRNO(EBADF, fcntl(fds[0], F_GETFD) == -1);
	ATF_CHECK(fcntl(again, F_GETFD) != -1);

	/* dropping is by the EXACT full name: nothing shorter matches */
	bsdfilesystem_test_anchor_drop(conn, "u/cache/scratch");
	ATF_CHECK_EQ(2u, bsdfilesystem_test_anchor_live(conn));
	bsdfilesystem_test_anchor_drop(conn, "zroot/Capabilities/Data/T/u/cache/scratch");
	ATF_CHECK_EQ(1u, bsdfilesystem_test_anchor_live(conn));
	ATF_CHECK_ERRNO(EBADF, fcntl(fds[1], F_GETFD) == -1);
	ATF_CHECK(fcntl(again, F_GETFD) != -1);
	/* a boot-scoped and a lease-scoped claim of one name are distinct */
	fds[1] = dup(p[0]);
	ATF_CHECK_EQ(0, bsdfilesystem_test_anchor_add(conn,
	    "zroot/Capabilities/ephemeral/boot-1/cap.x/scratch", fds[1]));
	fds[2] = dup(p[0]);
	ATF_CHECK_EQ(0, bsdfilesystem_test_anchor_add(conn,
	    "zroot/Capabilities/ephemeral/lease-1/cap.x/scratch", fds[2]));
	bsdfilesystem_test_anchor_drop(conn,
	    "zroot/Capabilities/ephemeral/lease-1/cap.x/scratch");
	ATF_CHECK_EQ(2u, bsdfilesystem_test_anchor_live(conn));
	ATF_CHECK(fcntl(fds[1], F_GETFD) != -1);	/* boot claim untouched */
	ATF_CHECK_ERRNO(EBADF, fcntl(fds[2], F_GETFD) == -1);
	bsdfilesystem_test_anchor_drop(conn,
	    "zroot/Capabilities/ephemeral/boot-1/cap.x/scratch");
	bsdfilesystem_test_anchor_drop(conn, "zroot/Capabilities/Data/T/u/persistent/state");
	ATF_CHECK_EQ(0u, bsdfilesystem_test_anchor_live(conn));
	ATF_CHECK_ERRNO(EBADF, fcntl(again, F_GETFD) == -1);

	/* bounded: the (MAX+1)th distinct claim is refused with EMFILE and its
	 * descriptor is left to the caller (not closed behind its back) */
	for (i = 0; i < BSDFILESYSTEM_CONN_MAX_CLAIMS; i++) {
		fds[i] = dup(p[0]);
		snprintf(name, sizeof(name), "zroot/Data/T/u/persistent/c%d", i);
		ATF_REQUIRE_EQ(0, bsdfilesystem_test_anchor_add(conn, name, fds[i]));
	}
	ATF_CHECK_EQ((unsigned)BSDFILESYSTEM_CONN_MAX_CLAIMS, bsdfilesystem_test_anchor_live(conn));
	extra = dup(p[0]);
	ATF_CHECK_ERRNO(EMFILE, bsdfilesystem_test_anchor_add(conn,
	    "zroot/Data/T/u/persistent/overflow", extra) == -1);
	ATF_CHECK(fcntl(extra, F_GETFD) != -1);
	close(extra);
	/* a re-claim of a held dataset still succeeds when full */
	again = dup(p[0]);
	ATF_CHECK_EQ(0, bsdfilesystem_test_anchor_add(conn,
	    "zroot/Data/T/u/persistent/c3", again));
	ATF_CHECK_ERRNO(EBADF, fcntl(fds[3], F_GETFD) == -1);

	/* teardown closes every anchor */
	bsdfilesystem_test_conn_free(conn);
	ATF_CHECK_ERRNO(EBADF, fcntl(again, F_GETFD) == -1);
	ATF_CHECK_ERRNO(EBADF, fcntl(fds[0], F_GETFD) == -1);
	close(p[0]); close(p[1]);
}

/*
 * The read-only view narrows a store directory with Capsicum rights: reads and
 * lookups under it work, every mutating operation fails ENOTCAPABLE, and a
 * descriptor opened beneath it inherits the narrowing.  A plain tmp dir stands
 * in for the mounted store; rights are a property of the descriptor.
 */
ATF_TC_WITHOUT_HEAD(readonly_view_is_enforced_by_rights);
ATF_TC_BODY(readonly_view_is_enforced_by_rights, tc)
{
	char buf[16];
	int dfd, fd, sub;

	ATF_REQUIRE_EQ(0, mkdir("store", 0755));
	ATF_REQUIRE_EQ(0, mkdir("store/sub", 0755));
	fd = open("store/env", O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE_EQ(6, write(fd, "KEY=1\n", 6));
	close(fd);
	dfd = open("store", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dfd != -1);
	ATF_REQUIRE_EQ(0, bsdfilesystem_limit_readonly_dir(dfd));

	/* reading works, through openat and through a derived dir fd */
	fd = openat(dfd, "env", O_RDONLY);
	ATF_REQUIRE(fd != -1);
	ATF_CHECK_EQ(6, read(fd, buf, sizeof(buf)));
	close(fd);
	sub = openat(dfd, "sub", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(sub != -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE, openat(sub, "new", O_CREAT | O_WRONLY,
	    0644) == -1);
	close(sub);

	/* every mutation is refused at the capability, not by the filesystem */
	ATF_CHECK_ERRNO(ENOTCAPABLE, openat(dfd, "env", O_WRONLY) == -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE, openat(dfd, "env", O_RDWR) == -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE, openat(dfd, "env", O_RDONLY | O_TRUNC) == -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE, openat(dfd, "new", O_CREAT | O_WRONLY,
	    0644) == -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE, unlinkat(dfd, "env", 0) == -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE, mkdirat(dfd, "d", 0755) == -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE, renameat(dfd, "env", dfd, "env2") == -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE, fchmodat(dfd, "env", 0600, 0) == -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE, fchmod(dfd, 0700) == -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE, symlinkat("env", dfd, "lnk") == -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE, unlinkat(dfd, "sub", AT_REMOVEDIR) == -1);
	/* the narrowing is monotonic: rights cannot be widened again */
	{
		cap_rights_t wide;

		cap_rights_init(&wide, CAP_READ, CAP_WRITE, CAP_LOOKUP);
		ATF_CHECK_ERRNO(ENOTCAPABLE, cap_rights_limit(dfd, &wide) == -1);
	}
	/* and the file is untouched */
	fd = openat(dfd, "env", O_RDONLY);
	ATF_REQUIRE(fd != -1);
	ATF_CHECK_EQ(6, read(fd, buf, sizeof(buf)));
	close(fd);
	close(dfd);
}

ATF_TC_BODY(request_scope_rules, tc)
{
	struct bsdfilesystem_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_REQUEST;
	rq.rights = 1;
	rq.lifetime = BSDFILESYSTEM_PERSISTENT;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));		/* UNIT, no group */
	rq.scope = BSDFILESYSTEM_SCOPE_SHARED;
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	rq.scope = BSDFILESYSTEM_SCOPE_GROUP;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));		/* GROUP needs a group */
	(void)strlcpy(rq.group, "org.example.shared", sizeof(rq.group));
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	rq.scope = BSDFILESYSTEM_SCOPE_UNIT;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));		/* group without GROUP */
	rq.scope = BSDFILESYSTEM_SCOPE_GROUP;
	(void)strlcpy(rq.group, "bad/name", sizeof(rq.group));
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	(void)strlcpy(rq.group, "org.example.shared", sizeof(rq.group));
	rq.scope = BSDFILESYSTEM_SCOPE_GROUP + 1;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));		/* unknown scope */
	rq.scope = BSDFILESYSTEM_SCOPE_GROUP;
	memset(rq.group, 'g', sizeof(rq.group));		/* unterminated */
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	memset(rq.group, 0, sizeof(rq.group));
	/* Scopes apply to durable claims only. */
	rq.scope = BSDFILESYSTEM_SCOPE_SHARED;
	rq.lifetime = BSDFILESYSTEM_BOOT;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.lifetime = BSDFILESYSTEM_LEASE;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.lifetime = BSDFILESYSTEM_CACHE;
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	/* DESTROY takes a scope exactly like REQUEST. */
	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_DESTROY;
	rq.lifetime = BSDFILESYSTEM_PERSISTENT;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));
	rq.scope = BSDFILESYSTEM_SCOPE_GROUP;
	(void)strlcpy(rq.group, "team", sizeof(rq.group));
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	rq.group[0] = '\0';
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	/* Every other op must carry no scope and no group. */
	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_RELEASE;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	rq.scope = BSDFILESYSTEM_SCOPE_SHARED;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.scope = BSDFILESYSTEM_SCOPE_UNIT;
	(void)strlcpy(rq.group, "team", sizeof(rq.group));
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
}

/*
 * grant_open() is the ENTIRE security boundary of an OP_OPEN grant: bsdfilesystem is
 * ambient (not in capability mode), so default-deny policy matching plus
 * O_NOFOLLOW | O_RESOLVE_BENEATH relative to the retained root fd is what keeps a
 * consumer inside its declared paths.  The following exercise that boundary
 * directly through bsdfilesystem_test_grant_open().
 */
static void
open_state_init(struct bsdfilesystem_state *st, int root_fd)
{

	memset(st, 0, sizeof(*st));
	st->persistent_fd = st->ephemeral_fd = -1;
	st->boot_fd = st->lease_fd = -1;
	st->root_fd = root_fd;
}

static void
open_policy_set(struct bsdfilesystem_state *st, const char *label,
    const char *path, unsigned rights, bool prefix)
{
	struct bsdfilesystem_open_policy *pol;

	st->cfg.nopen_policy = 1;
	pol = &st->cfg.open_policy[0];
	memset(pol, 0, sizeof(*pol));
	(void)strlcpy(pol->label, label, sizeof(pol->label));
	(void)strlcpy(pol->path, path, sizeof(pol->path));
	pol->rights = rights;
	pol->prefix = prefix;
}

static void
open_request_set(struct bsdfilesystem_open_request *rq, const char *path,
    unsigned rights)
{

	memset(rq, 0, sizeof(*rq));
	rq->op = BSDFILESYSTEM_OP_OPEN;
	rq->rights = rights;
	if (path != NULL)
		(void)strlcpy(rq->path, path, sizeof(rq->path));
}

/* Default-deny: an absent policy, a foreign label, or a non-matching path. */
ATF_TC_WITHOUT_HEAD(grant_open_default_deny);
ATF_TC_BODY(grant_open_default_deny, tc)
{
	static const char label[] = "system.Auth/bsdauth";
	struct bsdfilesystem_open_request rq;
	struct bsdfilesystem_state st;
	char path[] = "/tmp/bsdfs-deny.XXXXXX";
	int seed;

	seed = mkstemp(path);
	ATF_REQUIRE(seed >= 0);
	ATF_REQUIRE_EQ(0, close(seed));
	open_state_init(&st, open("/", O_DIRECTORY | O_RDONLY | O_CLOEXEC));
	ATF_REQUIRE(st.root_fd >= 0);

	/* No policy at all -> EACCES. */
	open_request_set(&rq, path, BSDFILESYSTEM_OPEN_READ);
	ATF_CHECK_EQ(-1, bsdfilesystem_test_grant_open(&st, label, &rq));
	ATF_CHECK_EQ(EACCES, errno);

	/* Policy for a DIFFERENT label -> EACCES for this caller. */
	open_policy_set(&st, "system.Other/x", path, BSDFILESYSTEM_OPEN_READ,
	    false);
	ATF_CHECK_EQ(-1, bsdfilesystem_test_grant_open(&st, label, &rq));
	ATF_CHECK_EQ(EACCES, errno);

	/* Right label, but a path the policy does not name -> EACCES. */
	open_policy_set(&st, label, "/tmp/bsdfs-other", BSDFILESYSTEM_OPEN_READ,
	    false);
	ATF_CHECK_EQ(-1, bsdfilesystem_test_grant_open(&st, label, &rq));
	ATF_CHECK_EQ(EACCES, errno);

	ATF_REQUIRE_EQ(0, close(st.root_fd));
	ATF_REQUIRE_EQ(0, unlink(path));
}

/* A request may never exceed the rights its policy entry grants. */
ATF_TC_WITHOUT_HEAD(grant_open_refuses_rights_escalation);
ATF_TC_BODY(grant_open_refuses_rights_escalation, tc)
{
	static const char label[] = "system.Auth/bsdauth";
	struct bsdfilesystem_open_request rq;
	struct bsdfilesystem_state st;
	char path[] = "/tmp/bsdfs-esc.XXXXXX";
	int seed;

	seed = mkstemp(path);
	ATF_REQUIRE(seed >= 0);
	ATF_REQUIRE_EQ(0, close(seed));
	open_state_init(&st, open("/", O_DIRECTORY | O_RDONLY | O_CLOEXEC));
	ATF_REQUIRE(st.root_fd >= 0);

	/* READ-only policy; a WRITE request must be refused (rights & ~pol). */
	open_policy_set(&st, label, path, BSDFILESYSTEM_OPEN_READ, false);
	open_request_set(&rq, path, BSDFILESYSTEM_OPEN_WRITE);
	ATF_CHECK_EQ(-1, bsdfilesystem_test_grant_open(&st, label, &rq));
	ATF_CHECK_EQ(EACCES, errno);

	/* READ|WRITE against a READ-only policy is likewise refused. */
	open_request_set(&rq, path,
	    BSDFILESYSTEM_OPEN_READ | BSDFILESYSTEM_OPEN_WRITE);
	ATF_CHECK_EQ(-1, bsdfilesystem_test_grant_open(&st, label, &rq));
	ATF_CHECK_EQ(EACCES, errno);

	ATF_REQUIRE_EQ(0, close(st.root_fd));
	ATF_REQUIRE_EQ(0, unlink(path));
}

/*
 * O_NOFOLLOW refuses a symlink AT the granted leaf, and O_RESOLVE_BENEATH refuses
 * an intermediate symlink that would escape the retained root — the two halves of
 * the grant's symlink-safety promise.
 */
ATF_TC_WITHOUT_HEAD(grant_open_refuses_symlinks);
ATF_TC_BODY(grant_open_refuses_symlinks, tc)
{
	static const char label[] = "system.Auth/bsdauth";
	struct bsdfilesystem_open_request rq;
	struct bsdfilesystem_state st;
	char root[] = "/tmp/bsdfs-slroot.XXXXXX";
	char p[PATH_MAX];
	int rfd, fd;

	ATF_REQUIRE(mkdtemp(root) != NULL);
	rfd = open(root, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(rfd >= 0);
	/* A real target file, a leaf symlink to it, and a dir symlink escaping. */
	(void)snprintf(p, sizeof(p), "%s/real", root);
	fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, close(fd));
	(void)snprintf(p, sizeof(p), "%s/leaf", root);
	ATF_REQUIRE_EQ(0, symlink("real", p));
	(void)snprintf(p, sizeof(p), "%s/esc", root);
	ATF_REQUIRE_EQ(0, symlink("/etc", p));	/* absolute, outside root */

	open_state_init(&st, rfd);

	/* Leaf symlink: O_NOFOLLOW refuses it. */
	open_policy_set(&st, label, "/leaf", BSDFILESYSTEM_OPEN_READ, false);
	open_request_set(&rq, "/leaf", BSDFILESYSTEM_OPEN_READ);
	fd = bsdfilesystem_test_grant_open(&st, label, &rq);
	ATF_CHECK_MSG(fd < 0, "leaf symlink was followed (fd=%d)", fd);
	ATF_CHECK_MSG(errno == EMLINK || errno == ELOOP,
	    "unexpected errno for leaf symlink: %s", strerror(errno));
	if (fd >= 0)
		(void)close(fd);

	/* Intermediate symlink escaping root: O_RESOLVE_BENEATH refuses it. */
	open_policy_set(&st, label, "/esc/passwd", BSDFILESYSTEM_OPEN_READ,
	    false);
	open_request_set(&rq, "/esc/passwd", BSDFILESYSTEM_OPEN_READ);
	fd = bsdfilesystem_test_grant_open(&st, label, &rq);
	ATF_CHECK_MSG(fd < 0, "escape via intermediate symlink succeeded (fd=%d)",
	    fd);
	ATF_CHECK_MSG(errno == ENOTCAPABLE,
	    "unexpected errno for beneath escape: %s", strerror(errno));
	if (fd >= 0)
		(void)close(fd);

	ATF_REQUIRE_EQ(0, close(rfd));
	(void)snprintf(p, sizeof(p), "%s/real", root);
	(void)unlink(p);
	(void)snprintf(p, sizeof(p), "%s/leaf", root);
	(void)unlink(p);
	(void)snprintf(p, sizeof(p), "%s/esc", root);
	(void)unlink(p);
	(void)rmdir(root);
}

/*
 * A prefix policy (device-unit grant) admits the base path and a single trailing
 * component, but never a deeper subpath.
 */
ATF_TC_WITHOUT_HEAD(grant_open_prefix_policy);
ATF_TC_BODY(grant_open_prefix_policy, tc)
{
	static const char label[] = "system.Bluetooth/blued";
	struct bsdfilesystem_open_request rq;
	struct bsdfilesystem_state st;
	char root[] = "/tmp/bsdfs-pfxroot.XXXXXX";
	char p[PATH_MAX];
	int rfd, fd;

	ATF_REQUIRE(mkdtemp(root) != NULL);
	rfd = open(root, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(rfd >= 0);
	/* Materialize base "/vhid", unit "/vhid0", and a subdir "/vhid/sub". */
	(void)snprintf(p, sizeof(p), "%s/vhid", root);
	fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, close(fd));
	(void)snprintf(p, sizeof(p), "%s/vhid0", root);
	fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, close(fd));

	open_state_init(&st, rfd);
	open_policy_set(&st, label, "/vhid", BSDFILESYSTEM_OPEN_READ, true);

	/* Base path itself: admitted. */
	open_request_set(&rq, "/vhid", BSDFILESYSTEM_OPEN_READ);
	fd = bsdfilesystem_test_grant_open(&st, label, &rq);
	ATF_CHECK_MSG(fd >= 0, "prefix base refused: %s", strerror(errno));
	if (fd >= 0)
		(void)close(fd);

	/* One trailing component (a device unit): admitted. */
	open_request_set(&rq, "/vhid0", BSDFILESYSTEM_OPEN_READ);
	fd = bsdfilesystem_test_grant_open(&st, label, &rq);
	ATF_CHECK_MSG(fd >= 0, "prefix unit refused: %s", strerror(errno));
	if (fd >= 0)
		(void)close(fd);

	/* A deeper subpath (a '/' in the suffix): refused by policy -> EACCES. */
	open_request_set(&rq, "/vhid/sub", BSDFILESYSTEM_OPEN_READ);
	ATF_CHECK_EQ(-1, bsdfilesystem_test_grant_open(&st, label, &rq));
	ATF_CHECK_EQ(EACCES, errno);

	ATF_REQUIRE_EQ(0, close(rfd));
	(void)snprintf(p, sizeof(p), "%s/vhid", root);
	(void)unlink(p);
	(void)snprintf(p, sizeof(p), "%s/vhid0", root);
	(void)unlink(p);
	(void)rmdir(root);
}

/* Message-hygiene guards on the open request all reject with EINVAL. */
ATF_TC_WITHOUT_HEAD(grant_open_einval_guards);
ATF_TC_BODY(grant_open_einval_guards, tc)
{
	static const char label[] = "system.Auth/bsdauth";
	struct bsdfilesystem_open_request rq;
	struct bsdfilesystem_state st;

	open_state_init(&st, open("/", O_DIRECTORY | O_RDONLY | O_CLOEXEC));
	ATF_REQUIRE(st.root_fd >= 0);
	open_policy_set(&st, label, "/etc/hosts", BSDFILESYSTEM_OPEN_READ, false);

	/* rights == 0. */
	open_request_set(&rq, "/etc/hosts", 0);
	ATF_CHECK_EQ(-1, bsdfilesystem_test_grant_open(&st, label, &rq));
	ATF_CHECK_EQ(EINVAL, errno);

	/* An unknown rights bit above BSDFILESYSTEM_OPEN_RIGHTS_ALL. */
	open_request_set(&rq, "/etc/hosts",
	    (BSDFILESYSTEM_OPEN_RIGHTS_ALL << 1) | BSDFILESYSTEM_OPEN_READ);
	ATF_CHECK_EQ(-1, bsdfilesystem_test_grant_open(&st, label, &rq));
	ATF_CHECK_EQ(EINVAL, errno);

	/* A non-absolute path. */
	open_request_set(&rq, "etc/hosts", BSDFILESYSTEM_OPEN_READ);
	ATF_CHECK_EQ(-1, bsdfilesystem_test_grant_open(&st, label, &rq));
	ATF_CHECK_EQ(EINVAL, errno);

	/* A ".." traversal component. */
	open_request_set(&rq, "/etc/../etc/hosts", BSDFILESYSTEM_OPEN_READ);
	ATF_CHECK_EQ(-1, bsdfilesystem_test_grant_open(&st, label, &rq));
	ATF_CHECK_EQ(EINVAL, errno);

	ATF_REQUIRE_EQ(0, close(st.root_fd));
}

/*
 * The delivered descriptor is capsicum-narrowed to exactly the granted rights:
 * a READ grant's fd rejects write(2) with ENOTCAPABLE even though bsdfilesystem
 * itself is ambient (per-fd capsicum rights bind regardless of process mode).
 */
ATF_TC_WITHOUT_HEAD(grant_open_narrows_delivered_rights);
ATF_TC_BODY(grant_open_narrows_delivered_rights, tc)
{
	static const char label[] = "system.Auth/bsdauth";
	static const char contents[] = "narrow\n";
	struct bsdfilesystem_open_request rq;
	struct bsdfilesystem_state st;
	char path[] = "/tmp/bsdfs-narrow.XXXXXX";
	char buf[sizeof(contents)];
	int seed, fd;

	seed = mkstemp(path);
	ATF_REQUIRE(seed >= 0);
	ATF_REQUIRE_EQ((ssize_t)(sizeof(contents) - 1),
	    write(seed, contents, sizeof(contents) - 1));
	ATF_REQUIRE_EQ(0, close(seed));
	open_state_init(&st, open("/", O_DIRECTORY | O_RDONLY | O_CLOEXEC));
	ATF_REQUIRE(st.root_fd >= 0);
	open_policy_set(&st, label, path, BSDFILESYSTEM_OPEN_READ, false);

	open_request_set(&rq, path, BSDFILESYSTEM_OPEN_READ);
	fd = bsdfilesystem_test_grant_open(&st, label, &rq);
	ATF_REQUIRE_MSG(fd >= 0, "read grant failed: %s", strerror(errno));

	/* read() is permitted... */
	memset(buf, 0, sizeof(buf));
	ATF_CHECK_EQ((ssize_t)(sizeof(contents) - 1),
	    read(fd, buf, sizeof(buf) - 1));
	/* ...but write() on the READ-only capability is denied. */
	ATF_CHECK_EQ(-1, write(fd, "x", 1));
	ATF_CHECK_EQ(ENOTCAPABLE, errno);

	ATF_REQUIRE_EQ(0, close(fd));
	ATF_REQUIRE_EQ(0, close(st.root_fd));
	ATF_REQUIRE_EQ(0, unlink(path));
}

/*
 * STAT_CLAIM and SET_QUOTA name a claim exactly as DESTROY does (dataset +
 * lifetime + optional scope/group); STAT carries no quota, SET_QUOTA carries the
 * new refquota.  Both reject stray fields (rights/flags/owner/session/deliver)
 * and an out-of-range lifetime.
 */
ATF_TC_WITHOUT_HEAD(stat_and_set_quota_request_shape);
ATF_TC_BODY(stat_and_set_quota_request_shape, tc)
{
	struct bsdfilesystem_request rq;

	/* STAT_CLAIM: a bare claim name is valid. */
	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_STAT_CLAIM;
	rq.lifetime = BSDFILESYSTEM_PERSISTENT;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	/* CACHE lifetime is allowed; anything past it is not. */
	rq.lifetime = BSDFILESYSTEM_CACHE;
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	rq.lifetime = BSDFILESYSTEM_CACHE + 1;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.lifetime = BSDFILESYSTEM_PERSISTENT;
	/* A quota on STAT_CLAIM is a stray field. */
	rq.quota = 1u << 20;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.quota = 0;
	/* Any delivered-fd/rights/owner field is stray. */
	rq.rights = ZH_PROPS_READ;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.rights = 0;

	/* SET_QUOTA: a claim name plus a quota is valid (quota may be 0). */
	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_SET_QUOTA;
	rq.lifetime = BSDFILESYSTEM_PERSISTENT;
	rq.quota = 4u << 20;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	rq.quota = 0;			/* clearing the ceiling is valid shape */
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	/* rights/owner/session remain stray. */
	rq.owner_uid = 1000;
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
	rq.owner_uid = 0;
	(void)strlcpy(rq.session, "s", sizeof(rq.session));
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));

	/* Both accept a GROUP scope with a group name (like DESTROY). */
	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_STAT_CLAIM;
	rq.lifetime = BSDFILESYSTEM_PERSISTENT;
	rq.scope = BSDFILESYSTEM_SCOPE_GROUP;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));
	(void)strlcpy(rq.group, "team", sizeof(rq.group));
	ATF_CHECK(bsdfilesystem_test_valid_request(&rq));
	/* GROUP scope demands a group name. */
	rq.group[0] = '\0';
	ATF_CHECK(!bsdfilesystem_test_valid_request(&rq));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, distinct_labels_derive_distinct_namespaces);
	ATF_TP_ADD_TC(tp, same_label_is_deterministic);
	ATF_TP_ADD_TC(tp, valid_dataset_accepts_only_safe_component);
	ATF_TP_ADD_TC(tp, dotdot_is_component_wise);
	ATF_TP_ADD_TC(tp, isolated_open_does_not_require_pool);
	ATF_TP_ADD_TC(tp, installer_media_missing_pool_is_expected);
	ATF_TP_ADD_TC(tp, config_accepts_selected_pool_name);
	ATF_TP_ADD_TC(tp, request_reserved_must_be_zero);
	ATF_TP_ADD_TC(tp, request_accepts_quota_override);
	ATF_TP_ADD_TC(tp, destroy_request_shape_is_validated);
	ATF_TP_ADD_TC(tp, quota_floor_is_enforced);
	ATF_TP_ADD_TC(tp, request_without_pool_is_enxio);
	ATF_TP_ADD_TC(tp, destroy_resolves_under_caller_ns);
	ATF_TP_ADD_TC(tp, list_request_hygiene_and_no_pool);
	ATF_TP_ADD_TC(tp, list_scopes_to_caller_ns);
	ATF_TP_ADD_TC(tp, destroy_tree_rejects_malformed_relnames);
	ATF_TP_ADD_TC(tp, scoped_namespaces_and_group_membership);
	ATF_TP_ADD_TC(tp, request_scope_rules);
	ATF_TP_ADD_TC(tp, deliver_mode_rules);
	ATF_TP_ADD_TC(tp, names_are_a_positive_charset);
	ATF_TP_ADD_TC(tp, config_reclaim_interval_is_bounded);
	ATF_TP_ADD_TC(tp, anchors_are_per_claim);
	ATF_TP_ADD_TC(tp, readonly_view_is_enforced_by_rights);
	ATF_TP_ADD_TC(tp, grant_open_default_deny);
	ATF_TP_ADD_TC(tp, grant_open_refuses_rights_escalation);
	ATF_TP_ADD_TC(tp, grant_open_refuses_symlinks);
	ATF_TP_ADD_TC(tp, grant_open_prefix_policy);
	ATF_TP_ADD_TC(tp, grant_open_einval_guards);
	ATF_TP_ADD_TC(tp, grant_open_narrows_delivered_rights);
	ATF_TP_ADD_TC(tp, stat_and_set_quota_request_shape);
	return (atf_no_error());
}
