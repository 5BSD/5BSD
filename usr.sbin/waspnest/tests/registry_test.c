/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Pure-unit tests for vmd(8)'s label->window ownership registry and request
 * validation.  These drive the accept-loop statics directly (via the
 * VMD_TESTING wrappers) with no channel, no fork, and no vsock, so they run
 * anywhere.  The headline invariant is the anti-squat property: two DISTINCT
 * labels must NEVER be assigned the same concrete vsock port window.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/vsock.h>

#include <atf-c.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "vmd_proto.h"
#include "waspnest_test.h"

/*
 * A window base must sit on a VMD_PORTS_PER_LABEL boundary above VMD_PORT_BASE
 * and inside the VMD_LABEL_WINDOWS-slot space.  Return the slot index it names.
 */
static uint32_t
base_to_index(uint32_t base)
{

	ATF_REQUIRE(base >= VMD_PORT_BASE);
	ATF_REQUIRE_EQ(0, (base - VMD_PORT_BASE) % VMD_PORTS_PER_LABEL);
	return ((base - VMD_PORT_BASE) / VMD_PORTS_PER_LABEL);
}

/*
 * The anti-squat invariant.  Resolve windows for many distinct labels —
 * including a pair deliberately chosen to hash to the SAME home slot (the exact
 * case the old lossy 4096-window hash aliased onto one shared port range) — and
 * assert no two distinct labels ever land on the same window/port range.
 */
ATF_TC_WITHOUT_HEAD(distinct_labels_never_share_a_window);
ATF_TC_BODY(distinct_labels_never_share_a_window, tc)
{
	static const unsigned COUNT = 200;
	char labels[200][64];
	uint32_t bases[200];
	char collide_a[64], collide_b[64];
	uint32_t base_a, base_b, home_a;
	unsigned i, j, found;

	vmd_test_registry_reset();

	/*
	 * First prove the hostile case explicitly: two DISTINCT labels whose
	 * FNV home slot is identical.  Under a bare hash they would share a
	 * window; the full-label registry must relocate one so they do not.
	 */
	(void)snprintf(collide_a, sizeof(collide_a), "org.test.vm.aaaa");
	home_a = vmd_test_label_hash(collide_a) % VMD_LABEL_WINDOWS;
	found = 0;
	for (i = 0; i < 1000000u; i++) {
		(void)snprintf(collide_b, sizeof(collide_b),
		    "org.test.vm.collide-%u", i);
		if (strcmp(collide_b, collide_a) == 0)
			continue;
		if (vmd_test_label_hash(collide_b) % VMD_LABEL_WINDOWS ==
		    home_a) {
			found = 1;
			break;
		}
	}
	ATF_REQUIRE_MSG(found, "no colliding label generated");
	ATF_REQUIRE(vmd_test_resolve_window(collide_a, &base_a));
	ATF_REQUIRE(vmd_test_resolve_window(collide_b, &base_b));
	ATF_CHECK_MSG(base_a != base_b,
	    "hash-colliding distinct labels %s / %s shared window base %#x",
	    collide_a, collide_b, base_a);

	/*
	 * Now the population property: 200 distinct labels, every one resolving,
	 * and every assigned window distinct from every other.
	 */
	vmd_test_registry_reset();
	for (i = 0; i < COUNT; i++) {
		(void)snprintf(labels[i], sizeof(labels[i]),
		    "org.test.vm.client-%u", i);
		ATF_REQUIRE_MSG(vmd_test_resolve_window(labels[i], &bases[i]),
		    "resolve failed for %s", labels[i]);
		(void)base_to_index(bases[i]);
	}
	for (i = 0; i < COUNT; i++)
		for (j = i + 1; j < COUNT; j++)
			ATF_CHECK_MSG(bases[i] != bases[j],
			    "labels %s and %s share window base %#x",
			    labels[i], labels[j], bases[i]);
}

/*
 * Reconnect stability: resolving the same label again — even after other labels
 * have claimed slots in between — returns the identical window.
 */
ATF_TC_WITHOUT_HEAD(same_label_is_deterministic);
ATF_TC_BODY(same_label_is_deterministic, tc)
{
	uint32_t first, again, other;
	unsigned i;

	vmd_test_registry_reset();
	ATF_REQUIRE(vmd_test_resolve_window("org.test.vm.stable", &first));
	ATF_REQUIRE(vmd_test_resolve_window("org.test.vm.stable", &again));
	ATF_CHECK_EQ(first, again);

	for (i = 0; i < 50; i++) {
		char label[64];

		(void)snprintf(label, sizeof(label), "org.test.vm.noise-%u", i);
		ATF_REQUIRE(vmd_test_resolve_window(label, &other));
		ATF_CHECK(other != first);
	}
	ATF_REQUIRE(vmd_test_resolve_window("org.test.vm.stable", &again));
	ATF_CHECK_EQ(first, again);
}

/*
 * Once every one of the VMD_LABEL_WINDOWS slots is owned by a distinct label, a
 * further distinct label is refused (false), never silently aliased onto an
 * occupied window.  An already-known label must still resolve.
 */
ATF_TC_WITHOUT_HEAD(registry_full_is_refused);
ATF_TC_BODY(registry_full_is_refused, tc)
{
	char label[64];
	uint32_t base, again;
	uint32_t first_base;
	char first_label[64];
	unsigned i;

	vmd_test_registry_reset();
	(void)snprintf(first_label, sizeof(first_label), "org.test.vm.fill-0");
	for (i = 0; i < VMD_LABEL_WINDOWS; i++) {
		(void)snprintf(label, sizeof(label), "org.test.vm.fill-%u", i);
		ATF_REQUIRE_MSG(vmd_test_resolve_window(label, &base),
		    "slot %u of %u should have been assignable", i,
		    VMD_LABEL_WINDOWS);
		if (i == 0)
			first_base = base;
	}
	/* A brand-new distinct label has nowhere to go: refused, not aliased. */
	(void)snprintf(label, sizeof(label), "org.test.vm.overflow");
	ATF_CHECK(!vmd_test_resolve_window(label, &base));
	/* A label already owning a slot still resolves to its window. */
	ATF_REQUIRE(vmd_test_resolve_window(first_label, &again));
	ATF_CHECK_EQ(first_base, again);
}

/*
 * valid_request enforces the wire contract for VSOCK_BIND: op known, cid must
 * be zero (BIND scopes to the caller's label, never a wire CID), and the port
 * index must fall inside a caller's window.  Unknown ops are refused.
 */
ATF_TC_WITHOUT_HEAD(valid_request_enforces_wire_contract);
ATF_TC_BODY(valid_request_enforces_wire_contract, tc)
{
	struct vmd_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = VMD_OP_VSOCK_BIND;
	rq.port = 0;
	rq.backlog = 0;
	rq.cid = 0;
	ATF_CHECK(vmd_test_valid_request(&rq));

	/* Highest legal index within a window is still accepted. */
	rq.port = VMD_PORTS_PER_LABEL - 1;
	ATF_CHECK(vmd_test_valid_request(&rq));

	/* A BIND naming a nonzero cid is rejected (would map to EINVAL). */
	rq.port = 0;
	rq.cid = 1;
	ATF_CHECK(!vmd_test_valid_request(&rq));
	rq.cid = 0;

	/* Unknown op is rejected (past the highest known op, VMD_OP_VSOCK_LIST). */
	rq.op = VMD_OP_VSOCK_LIST + 1;
	ATF_CHECK(!vmd_test_valid_request(&rq));
	rq.op = 0;
	ATF_CHECK(!vmd_test_valid_request(&rq));
	rq.op = VMD_OP_VSOCK_BIND;

	/* A port index at or beyond the window width names another's port. */
	rq.port = VMD_PORTS_PER_LABEL;
	ATF_CHECK(!vmd_test_valid_request(&rq));
	rq.port = 0xffffffffu;
	ATF_CHECK(!vmd_test_valid_request(&rq));
}

/*
 * valid_request enforces the wire contract for VSOCK_CONNECT: op known, backlog
 * must be zero (unused by connect), cid must not be the wildcard
 * VMADDR_CID_ANY, and — unlike BIND — port is a concrete target with no window
 * bound (connect owns and scopes nothing).
 */
ATF_TC_WITHOUT_HEAD(valid_connect_enforces_wire_contract);
ATF_TC_BODY(valid_connect_enforces_wire_contract, tc)
{
	struct vmd_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = VMD_OP_VSOCK_CONNECT;
	rq.port = VMD_PORT_BASE + 3;	/* a concrete, out-of-window port */
	rq.backlog = 0;
	rq.cid = VMADDR_CID_LOCAL;
	ATF_CHECK(vmd_test_valid_request(&rq));

	/* Any concrete port is legal — no window-index bound applies. */
	rq.port = 0xffffffffu;
	ATF_CHECK(vmd_test_valid_request(&rq));
	rq.port = VMD_PORT_BASE + 3;

	/* backlog is unused by connect and MUST be zero. */
	rq.backlog = 1;
	ATF_CHECK(!vmd_test_valid_request(&rq));
	rq.backlog = 0;

	/* The wildcard CID is not a dialable peer. */
	rq.cid = VMADDR_CID_ANY;
	ATF_CHECK(!vmd_test_valid_request(&rq));
	rq.cid = VMADDR_CID_LOCAL;
	ATF_CHECK(vmd_test_valid_request(&rq));
}

/*
 * valid_request enforces the wire contract for VSOCK_LIST: op known, and — since
 * LIST owns and scopes nothing (it merely reports the caller's own window) —
 * every other wire field (port, backlog, cid) MUST be zero.  Any stray bit is
 * rejected (would map to EINVAL) so the request can carry no smuggled selector.
 */
ATF_TC_WITHOUT_HEAD(valid_list_enforces_wire_contract);
ATF_TC_BODY(valid_list_enforces_wire_contract, tc)
{
	struct vmd_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = VMD_OP_VSOCK_LIST;
	ATF_CHECK(vmd_test_valid_request(&rq));

	/* A nonzero port is a stray selector: rejected. */
	rq.port = 1;
	ATF_CHECK(!vmd_test_valid_request(&rq));
	rq.port = 0;

	/* A nonzero backlog is unused by LIST: rejected. */
	rq.backlog = 1;
	ATF_CHECK(!vmd_test_valid_request(&rq));
	rq.backlog = 0;

	/* A nonzero cid is unused by LIST: rejected. */
	rq.cid = VMADDR_CID_LOCAL;
	ATF_CHECK(!vmd_test_valid_request(&rq));
	rq.cid = 0;

	/* Sanity: the all-zero LIST request is the only accepted shape. */
	ATF_CHECK(vmd_test_valid_request(&rq));
}

/*
 * Backlog clamp: 0 becomes the default, an over-range uint32 is clamped to
 * SOMAXCONN, and nothing is ever handed to listen(2) as a sign-flipped negative
 * int.
 */
ATF_TC_WITHOUT_HEAD(backlog_is_clamped_and_never_negative);
ATF_TC_BODY(backlog_is_clamped_and_never_negative, tc)
{

	ATF_CHECK(vmd_test_clamp_backlog(0) > 0);
	ATF_CHECK_EQ(SOMAXCONN, vmd_test_clamp_backlog((uint32_t)SOMAXCONN + 1));
	ATF_CHECK_EQ(SOMAXCONN, vmd_test_clamp_backlog(0xffffffffu));
	ATF_CHECK_EQ(1, vmd_test_clamp_backlog(1));
	if (SOMAXCONN > 1)
		ATF_CHECK_EQ(SOMAXCONN, vmd_test_clamp_backlog(SOMAXCONN));
	/* No input produces a negative backlog. */
	ATF_CHECK(vmd_test_clamp_backlog(0) >= 0);
	ATF_CHECK(vmd_test_clamp_backlog(0x80000000u) >= 0);
	ATF_CHECK(vmd_test_clamp_backlog(0xffffffffu) >= 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, distinct_labels_never_share_a_window);
	ATF_TP_ADD_TC(tp, same_label_is_deterministic);
	ATF_TP_ADD_TC(tp, registry_full_is_refused);
	ATF_TP_ADD_TC(tp, valid_request_enforces_wire_contract);
	ATF_TP_ADD_TC(tp, valid_connect_enforces_wire_contract);
	ATF_TP_ADD_TC(tp, valid_list_enforces_wire_contract);
	ATF_TP_ADD_TC(tp, backlog_is_clamped_and_never_negative);
	return (atf_no_error());
}
