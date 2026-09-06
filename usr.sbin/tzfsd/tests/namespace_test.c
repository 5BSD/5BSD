/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Pure-unit tests for tzfsd(8)'s tenant-isolation core: the label->namespace
 * derivation and the request-validation predicates.  These exercise the
 * file-private logic of request.c directly through the TZFSD_TESTING accessors,
 * with no capability plane and no ZFS pool, so they run anywhere.  The tenant-
 * isolation invariant — distinct client labels always land in distinct dataset
 * namespaces, and a client can never name a bare "..", "/", or slash-bearing
 * key — is asserted here as the primary guard.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "tzfsd.h"

/*
 * valid_dataset() scans TZFSD_NAME_MAX bytes looking for the terminating NUL, so
 * every candidate must be materialized in a full-width, zero-filled key buffer
 * rather than passed as a bare short string literal.
 */
static bool
check_dataset(const char *s)
{
	char key[TZFSD_NAME_MAX];

	memset(key, 0, sizeof(key));
	ATF_REQUIRE(strlen(s) < sizeof(key));
	memcpy(key, s, strlen(s));
	return (tzfsd_test_valid_dataset(key));
}

/*
 * The isolation property: many distinct client labels must derive to many
 * distinct namespace keys with no collision, and each key must be a single safe
 * dataset component (starts with 'u', contains no '/').  A collision here would
 * let one tenant's storage alias another's.
 */
ATF_TC_WITHOUT_HEAD(distinct_labels_derive_distinct_namespaces);
ATF_TC_BODY(distinct_labels_derive_distinct_namespaces, tc)
{
#define	NLABELS	256
	static char ns[NLABELS][TZFSD_NAME_MAX];
	char label[64];
	unsigned i, j;

	for (i = 0; i < NLABELS; i++) {
		(void)snprintf(label, sizeof(label), "org.tenant.%u.svc", i);
		ATF_REQUIRE_MSG(tzfsd_test_derive_ns(label, ns[i],
		    sizeof(ns[i])), "derive_ns failed for %s", label);
		ATF_CHECK_MSG(ns[i][0] == 'u', "ns %s not 'u'-prefixed", ns[i]);
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
	char a[TZFSD_NAME_MAX], b[TZFSD_NAME_MAX];

	ATF_REQUIRE(tzfsd_test_derive_ns("system.Bluetooth", a, sizeof(a)));
	ATF_REQUIRE(tzfsd_test_derive_ns("system.Bluetooth", b, sizeof(b)));
	ATF_CHECK_STREQ(a, b);

	/* A different label must not collide with it. */
	ATF_REQUIRE(tzfsd_test_derive_ns("system.Network", b, sizeof(b)));
	ATF_CHECK(strcmp(a, b) != 0);

	/* Empty/NULL labels are rejected, never silently namespaced. */
	ATF_CHECK(!tzfsd_test_derive_ns("", a, sizeof(a)));
	ATF_CHECK(!tzfsd_test_derive_ns(NULL, a, sizeof(a)));
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
	ATF_CHECK(tzfsd_test_has_dotdot_component("/a/../b"));
	ATF_CHECK(tzfsd_test_has_dotdot_component("/.."));
	ATF_CHECK(tzfsd_test_has_dotdot_component("/../b"));
	ATF_CHECK(tzfsd_test_has_dotdot_component("/a/.."));
	ATF_CHECK(tzfsd_test_has_dotdot_component("/a/b/../c"));

	/* Embedded dots inside a component -> accepted (no ".." component). */
	ATF_CHECK(!tzfsd_test_has_dotdot_component("/dev/foo..bar"));
	ATF_CHECK(!tzfsd_test_has_dotdot_component("/a/..b/c"));
	ATF_CHECK(!tzfsd_test_has_dotdot_component("/a/b../c"));
	ATF_CHECK(!tzfsd_test_has_dotdot_component("/..a"));
	ATF_CHECK(!tzfsd_test_has_dotdot_component("/a/b/c"));
	ATF_CHECK(!tzfsd_test_has_dotdot_component("/"));
}

/*
 * Request-message hygiene: any nonzero byte in the reserved field makes the
 * message ambiguous and must be rejected, and a well-formed REQUEST must be
 * accepted.  This is the storage-request half of the _reserved validation.
 */
ATF_TC_WITHOUT_HEAD(request_reserved_must_be_zero);
ATF_TC_BODY(request_reserved_must_be_zero, tc)
{
	struct tzfsd_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_REQUEST;
	rq.rights = 1;
	rq.lifetime = TZFSD_PERSISTENT;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));
	/* session must be empty for REQUEST; dataset non-empty. */
	ATF_CHECK(tzfsd_test_valid_request(&rq));

	/* Any nonzero reserved byte -> rejected. */
	rq._reserved[0] = 1;
	ATF_CHECK(!tzfsd_test_valid_request(&rq));
	rq._reserved[0] = 0;
	rq._reserved[1] = 0x80;
	ATF_CHECK(!tzfsd_test_valid_request(&rq));
	rq._reserved[1] = 0;

	/* An out-of-range deliver mode -> rejected. */
	rq.deliver = TZFSD_DELIVER_MOUNTED + 1;
	ATF_CHECK(!tzfsd_test_valid_request(&rq));
	rq.deliver = 0;

	/* An unterminated dataset field is also rejected. */
	memset(rq.dataset, 'x', sizeof(rq.dataset));
	ATF_CHECK(!tzfsd_test_valid_request(&rq));
}

/*
 * A REQUEST may carry a nonzero quota (per-claim refquota override); it is a
 * first-class field, not reserved space, so validation must accept it.  The
 * floor (too-small values) is enforced later in grant(), asserted separately.
 */
ATF_TC_WITHOUT_HEAD(request_accepts_quota_override);
ATF_TC_BODY(request_accepts_quota_override, tc)
{
	struct tzfsd_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_REQUEST;
	rq.rights = 1;
	rq.lifetime = TZFSD_PERSISTENT;
	rq.quota = TZFSD_MIN_REFQUOTA;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));
	ATF_CHECK(tzfsd_test_valid_request(&rq));

	/* 0 (use the configured default) is equally well-formed. */
	rq.quota = 0;
	ATF_CHECK(tzfsd_test_valid_request(&rq));
}

/*
 * TZFSD_OP_DESTROY message shape: it names a claim exactly as REQUEST does
 * (dataset + lifetime) and must carry no rights, flags, quota, or session, and
 * a nonzero reserved byte is rejected as ambiguous.  This is the validation
 * half of the owner-scoped reclaim op — the handler then binds it to the
 * caller's own namespace (see destroy_resolves_under_caller_ns).
 */
ATF_TC_WITHOUT_HEAD(destroy_request_shape_is_validated);
ATF_TC_BODY(destroy_request_shape_is_validated, tc)
{
	struct tzfsd_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_DESTROY;
	rq.lifetime = TZFSD_PERSISTENT;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));
	ATF_CHECK(tzfsd_test_valid_request(&rq));

	/* CACHE shares the persistent tree and is equally destroyable. */
	rq.lifetime = TZFSD_CACHE;
	ATF_CHECK(tzfsd_test_valid_request(&rq));

	/* Any nonzero reserved byte -> rejected. */
	rq._reserved[1] = 0x7f;
	ATF_CHECK(!tzfsd_test_valid_request(&rq));
	rq._reserved[1] = 0;

	/* rights, flags, quota, and session must all be zero for DESTROY. */
	rq.rights = 1;
	ATF_CHECK(!tzfsd_test_valid_request(&rq));
	rq.rights = 0;
	rq.flags = 1;
	ATF_CHECK(!tzfsd_test_valid_request(&rq));
	rq.flags = 0;
	rq.quota = TZFSD_MIN_REFQUOTA;
	ATF_CHECK(!tzfsd_test_valid_request(&rq));
	rq.quota = 0;
	rq.session[0] = 'a';
	ATF_CHECK(!tzfsd_test_valid_request(&rq));
	rq.session[0] = '\0';

	/* An unterminated dataset field is rejected (message hygiene). */
	memset(rq.dataset, 'x', sizeof(rq.dataset));
	ATF_CHECK(!tzfsd_test_valid_request(&rq));
}

/*
 * grant()'s quota floor: a nonzero per-request quota below TZFSD_MIN_REFQUOTA is
 * rejected with EINVAL before any ZFS handle is opened, so this runs purely
 * against a zeroed state (every retained fd == -1).  quota == 0 (the default)
 * and a sane quota fall through to the ZFS path, which is exercised only in the
 * live provider case.
 */
ATF_TC_WITHOUT_HEAD(quota_floor_is_enforced);
ATF_TC_BODY(quota_floor_is_enforced, tc)
{
	struct tzfsd_state st;
	struct tzfsd_request rq;
	char ds[TZFSD_DATASET_MAX];

	memset(&st, 0, sizeof(st));
	st.persistent_fd = st.ephemeral_fd = -1;
	st.boot_fd = st.lease_fd = st.root_fd = -1;

	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_REQUEST;
	rq.rights = 1;			/* ZH_PROPS_READ; any nonzero right */
	rq.lifetime = TZFSD_PERSISTENT;
	(void)strlcpy(rq.dataset, "claim", sizeof(rq.dataset));

	/* A minimal-but-nonzero quota (1 byte) is below the floor -> EINVAL. */
	rq.quota = 1;
	errno = 0;
	ATF_CHECK_EQ(-1,
	    tzfsd_test_grant(&st, "org.test.tenant", &rq, ds, sizeof(ds)));
	ATF_CHECK_EQ(EINVAL, errno);

	/* One byte under the floor is still rejected. */
	rq.quota = TZFSD_MIN_REFQUOTA - 1;
	errno = 0;
	ATF_CHECK_EQ(-1,
	    tzfsd_test_grant(&st, "org.test.tenant", &rq, ds, sizeof(ds)));
	ATF_CHECK_EQ(EINVAL, errno);
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
	char ns_a[TZFSD_NAME_MAX], ns_b[TZFSD_NAME_MAX];
	char cross[TZFSD_NAME_MAX];

	ATF_REQUIRE(tzfsd_test_derive_ns("system.TenantA", ns_a, sizeof(ns_a)));
	ATF_REQUIRE(tzfsd_test_derive_ns("system.TenantB", ns_b, sizeof(ns_b)));
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
	ATF_CHECK_MSG(!tzfsd_test_valid_dataset(cross),
	    "a slash-bearing cross-namespace DESTROY key was accepted: %s",
	    cross);
}

/*
 * TZFSD_OP_LIST message hygiene and fail-closed scoping, asserted directly
 * against grant_list() with a zeroed state (every retained fd == -1): the
 * additive flags/_reserved fields must be zero, an unnamespaceable caller label
 * is rejected, and a well-formed LIST with no imported pool fails closed with
 * ENXIO — proving the walk is gated on the daemon's own retained persistent
 * parent (derived from the caller's label) and never touches ZFS without one.
 */
ATF_TC_WITHOUT_HEAD(list_request_hygiene_and_no_pool);
ATF_TC_BODY(list_request_hygiene_and_no_pool, tc)
{
	struct tzfsd_state st;
	struct tzfsd_list_request rq;
	struct tzfsd_list_reply rp;

	memset(&st, 0, sizeof(st));
	st.persistent_fd = st.ephemeral_fd = -1;
	st.boot_fd = st.lease_fd = st.root_fd = -1;

	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_LIST;

	/* A nonzero flags field is ambiguous -> EINVAL before anything is walked. */
	memset(&rp, 0, sizeof(rp));
	rq.flags = 1;
	errno = 0;
	ATF_CHECK_EQ(-1,
	    tzfsd_test_grant_list(&st, "org.test.tenant", &rq, &rp));
	ATF_CHECK_EQ(EINVAL, errno);
	rq.flags = 0;

	/* A nonzero reserved field is likewise rejected. */
	memset(&rp, 0, sizeof(rp));
	rq._reserved = 0x80;
	errno = 0;
	ATF_CHECK_EQ(-1,
	    tzfsd_test_grant_list(&st, "org.test.tenant", &rq, &rp));
	ATF_CHECK_EQ(EINVAL, errno);
	rq._reserved = 0;

	/* An empty caller label can never be namespaced -> EINVAL (no default ns). */
	memset(&rp, 0, sizeof(rp));
	errno = 0;
	ATF_CHECK_EQ(-1, tzfsd_test_grant_list(&st, "", &rq, &rp));
	ATF_CHECK_EQ(EINVAL, errno);

	/*
	 * Well-formed, but no pool imported (persistent_fd == -1): the walk is
	 * rooted at the daemon's own retained parent, so it fails closed with
	 * ENXIO rather than touching ZFS or another label's storage.
	 */
	memset(&rp, 0, sizeof(rp));
	errno = 0;
	ATF_CHECK_EQ(-1,
	    tzfsd_test_grant_list(&st, "org.test.tenant", &rq, &rp));
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
	char ns_a[TZFSD_NAME_MAX], ns_b[TZFSD_NAME_MAX];

	ATF_REQUIRE(tzfsd_test_derive_ns("system.TenantA", ns_a, sizeof(ns_a)));
	ATF_REQUIRE(tzfsd_test_derive_ns("system.TenantB", ns_b, sizeof(ns_b)));
	ATF_CHECK_MSG(strcmp(ns_a, ns_b) != 0,
	    "two labels shared a namespace (%s); LIST would cross tenants", ns_a);
}

/*
 * The reclaim crown jewel, asserted at the seam the capability-cleanup handler
 * uses: a reclaim ALWAYS targets exactly derive_ns(label) and never another
 * label's namespace.  tzfsd_test_reclaim reports (in *ns) the namespace the
 * reclaim resolved to, so we can assert reclaim of label A computes u<hash(A)>,
 * reclaim of label B computes u<hash(B)>, and the two never coincide — there is
 * no wire argument or shared target that could let retiring A destroy B's
 * storage.  This runs against a zeroed state (persistent_fd == -1): the target
 * namespace is computed before the (absent) pool is touched, so the reclaim
 * returns ENXIO without any ZFS work, yet *ns still records exactly the subtree
 * it would have destroyed.
 */
ATF_TC_WITHOUT_HEAD(reclaim_targets_caller_namespace_only);
ATF_TC_BODY(reclaim_targets_caller_namespace_only, tc)
{
	struct tzfsd_state st;
	char expect_a[TZFSD_NAME_MAX], expect_b[TZFSD_NAME_MAX];
	char got_a[TZFSD_NAME_MAX], got_b[TZFSD_NAME_MAX];

	memset(&st, 0, sizeof(st));
	st.persistent_fd = st.ephemeral_fd = -1;
	st.boot_fd = st.lease_fd = st.root_fd = -1;

	/* The namespace each label's storage is confined to. */
	ATF_REQUIRE(tzfsd_test_derive_ns("system.TenantA", expect_a,
	    sizeof(expect_a)));
	ATF_REQUIRE(tzfsd_test_derive_ns("system.TenantB", expect_b,
	    sizeof(expect_b)));
	ATF_REQUIRE_MSG(strcmp(expect_a, expect_b) != 0,
	    "two labels shared a namespace (%s); reclaim would cross tenants",
	    expect_a);

	/*
	 * Reclaiming A resolves to A's namespace and only A's; reclaiming B to
	 * B's.  (ENXIO here: the zeroed state has no retained pool, so nothing is
	 * actually destroyed — the point is which subtree was targeted.)
	 */
	memset(got_a, 0, sizeof(got_a));
	errno = 0;
	ATF_CHECK_EQ(-1, tzfsd_test_reclaim(&st, "system.TenantA", got_a,
	    sizeof(got_a)));
	ATF_CHECK_EQ(ENXIO, errno);
	ATF_CHECK_STREQ(expect_a, got_a);

	memset(got_b, 0, sizeof(got_b));
	errno = 0;
	ATF_CHECK_EQ(-1, tzfsd_test_reclaim(&st, "system.TenantB", got_b,
	    sizeof(got_b)));
	ATF_CHECK_EQ(ENXIO, errno);
	ATF_CHECK_STREQ(expect_b, got_b);

	/* Crown jewel: A's reclaim target is never B's namespace. */
	ATF_CHECK_MSG(strcmp(got_a, got_b) != 0,
	    "reclaim of A and B resolved to the same namespace (%s)", got_a);
	ATF_CHECK_MSG(strcmp(got_a, expect_b) != 0,
	    "reclaim of A resolved into B's namespace (%s)", got_a);
	/* And the target is a single '/'-free component tzfsd_destroy_tree accepts. */
	ATF_CHECK_MSG(strchr(got_a, '/') == NULL,
	    "reclaim target %s is not a single component", got_a);
}

/*
 * Reclaim is fail-safe: an unnamespaceable label (empty/NULL) is rejected with
 * EINVAL and a NULL state likewise, before anything is touched; and with no
 * retained pool a well-formed label fails closed with ENXIO rather than reaching
 * ZFS.  No input makes the handler destroy anything it should not, or crash.
 */
ATF_TC_WITHOUT_HEAD(reclaim_is_failsafe_on_bad_input);
ATF_TC_BODY(reclaim_is_failsafe_on_bad_input, tc)
{
	struct tzfsd_state st;
	char ns[TZFSD_NAME_MAX];

	memset(&st, 0, sizeof(st));
	st.persistent_fd = st.ephemeral_fd = -1;
	st.boot_fd = st.lease_fd = st.root_fd = -1;

	/* An empty label can never be namespaced -> EINVAL (no default ns). */
	errno = 0;
	ATF_CHECK_EQ(-1, tzfsd_test_reclaim(&st, "", ns, sizeof(ns)));
	ATF_CHECK_EQ(EINVAL, errno);

	/* A NULL label likewise. */
	errno = 0;
	ATF_CHECK_EQ(-1, tzfsd_test_reclaim(&st, NULL, ns, sizeof(ns)));
	ATF_CHECK_EQ(EINVAL, errno);

	/* A NULL state (defensive) -> EINVAL, never a deref. */
	errno = 0;
	ATF_CHECK_EQ(-1, tzfsd_test_reclaim(NULL, "system.Tenant", ns,
	    sizeof(ns)));
	ATF_CHECK_EQ(EINVAL, errno);

	/* Well-formed label, but no retained pool -> ENXIO, no ZFS touched. */
	errno = 0;
	ATF_CHECK_EQ(-1, tzfsd_test_reclaim(&st, "system.Tenant", ns,
	    sizeof(ns)));
	ATF_CHECK_EQ(ENXIO, errno);

	/*
	 * The production callback swallows all of these (idempotent, non-fatal):
	 * calling it directly must never crash or throw, whatever the input.
	 */
	tzfsd_reclaim_label("system.Tenant", &st);
	tzfsd_reclaim_label("", &st);
	tzfsd_reclaim_label(NULL, &st);
	tzfsd_reclaim_label("system.Tenant", NULL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, distinct_labels_derive_distinct_namespaces);
	ATF_TP_ADD_TC(tp, same_label_is_deterministic);
	ATF_TP_ADD_TC(tp, valid_dataset_accepts_only_safe_component);
	ATF_TP_ADD_TC(tp, dotdot_is_component_wise);
	ATF_TP_ADD_TC(tp, request_reserved_must_be_zero);
	ATF_TP_ADD_TC(tp, request_accepts_quota_override);
	ATF_TP_ADD_TC(tp, destroy_request_shape_is_validated);
	ATF_TP_ADD_TC(tp, quota_floor_is_enforced);
	ATF_TP_ADD_TC(tp, destroy_resolves_under_caller_ns);
	ATF_TP_ADD_TC(tp, list_request_hygiene_and_no_pool);
	ATF_TP_ADD_TC(tp, list_scopes_to_caller_ns);
	ATF_TP_ADD_TC(tp, reclaim_targets_caller_namespace_only);
	ATF_TP_ADD_TC(tp, reclaim_is_failsafe_on_bad_input);
	return (atf_no_error());
}
