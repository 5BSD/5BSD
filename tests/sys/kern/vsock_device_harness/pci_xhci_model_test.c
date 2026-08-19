/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>

#include "pci_xhci_model.h"

ATF_TC_WITHOUT_HEAD(deadline_arithmetic);
ATF_TC_BODY(deadline_arithmetic, tc)
{
	struct timespec now, deadline;

	/* No nanosecond carry. */
	now.tv_sec = 5;
	now.tv_nsec = 600000000L;
	deadline = pci_xhci_drain_deadline(now, 100000000ULL);
	ATF_CHECK_EQ(5, deadline.tv_sec);
	ATF_CHECK_EQ(700000000L, deadline.tv_nsec);

	/* Nanosecond carry into the seconds field. */
	now.tv_sec = 1;
	now.tv_nsec = 999999999L;
	deadline = pci_xhci_drain_deadline(now, 1ULL);
	ATF_CHECK_EQ(2, deadline.tv_sec);
	ATF_CHECK_EQ(0L, deadline.tv_nsec);

	/* Multi-second timeout with fractional remainder. */
	now.tv_sec = 5;
	now.tv_nsec = 600000000L;
	deadline = pci_xhci_drain_deadline(now, 2500000000ULL);
	ATF_CHECK_EQ(8, deadline.tv_sec);
	ATF_CHECK_EQ(100000000L, deadline.tv_nsec);
}

ATF_TC_WITHOUT_HEAD(deadline_expiry);
ATF_TC_BODY(deadline_expiry, tc)
{
	struct timespec now, deadline;

	deadline.tv_sec = 10;
	deadline.tv_nsec = 500000000L;

	/* Strictly earlier. */
	now.tv_sec = 10;
	now.tv_nsec = 499999999L;
	ATF_CHECK(!pci_xhci_drain_deadline_expired(now, deadline));
	now.tv_sec = 9;
	now.tv_nsec = 999999999L;
	ATF_CHECK(!pci_xhci_drain_deadline_expired(now, deadline));

	/* Exactly at the deadline counts as expired. */
	now.tv_sec = 10;
	now.tv_nsec = 500000000L;
	ATF_CHECK(pci_xhci_drain_deadline_expired(now, deadline));

	/* Later in either field. */
	now.tv_sec = 10;
	now.tv_nsec = 500000001L;
	ATF_CHECK(pci_xhci_drain_deadline_expired(now, deadline));
	now.tv_sec = 11;
	now.tv_nsec = 0L;
	ATF_CHECK(pci_xhci_drain_deadline_expired(now, deadline));
}

ATF_TC_WITHOUT_HEAD(event_ring_geometry_is_immutable);
ATF_TC_BODY(event_ring_geometry_is_immutable, tc)
{
	const uint64_t base = UINT64_C(0x4000);

	ATF_CHECK(pci_xhci_event_ring_geometry_matches(8, base, 8, base));
	/* A guest cannot enlarge or shrink the mapped ring in its ERST entry. */
	ATF_CHECK(!pci_xhci_event_ring_geometry_matches(8, base, 64, base));
	ATF_CHECK(!pci_xhci_event_ring_geometry_matches(8, base, 4, base));
	/* Nor can it redirect the already-mapped ring to another guest address. */
	ATF_CHECK(!pci_xhci_event_ring_geometry_matches(8, base, 8,
	    UINT64_C(0x8000)));
	ATF_CHECK(!pci_xhci_event_ring_geometry_matches(0, base, 0, base));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, deadline_arithmetic);
	ATF_TP_ADD_TC(tp, deadline_expiry);
	ATF_TP_ADD_TC(tp, event_ring_geometry_is_immutable);
	return (atf_no_error());
}
