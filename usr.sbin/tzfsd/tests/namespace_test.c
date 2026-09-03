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
	rq._reserved[2] = 0x80;
	ATF_CHECK(!tzfsd_test_valid_request(&rq));

	/* An unterminated dataset field is also rejected. */
	rq._reserved[2] = 0;
	memset(rq.dataset, 'x', sizeof(rq.dataset));
	ATF_CHECK(!tzfsd_test_valid_request(&rq));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, distinct_labels_derive_distinct_namespaces);
	ATF_TP_ADD_TC(tp, same_label_is_deterministic);
	ATF_TP_ADD_TC(tp, valid_dataset_accepts_only_safe_component);
	ATF_TP_ADD_TC(tp, dotdot_is_component_wise);
	ATF_TP_ADD_TC(tp, request_reserved_must_be_zero);
	return (atf_no_error());
}
