/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#include <sys/types.h>

#include <atf-c.h>
#include <limits.h>

#include "pci_e82545_model.h"

/* Intel 8254x TCTL fields used as an independent register oracle. */
#define	TEST_TCTL_EN		UINT32_C(0x00000002)
#define	TEST_TCTL_PSP		UINT32_C(0x00000008)
#define	TEST_TCTL_RTLC		UINT32_C(0x01000000)
#define	TEST_TCTL_RESERVED	UINT32_C(0xfe800005)

ATF_TC_WITHOUT_HEAD(tctl_writable_state);
ATF_TC_BODY(tctl_writable_state, tc)
{
	uint32_t initial, updated;

	initial = pci_e82545_tctl_value(TEST_TCTL_EN | TEST_TCTL_PSP);
	updated = pci_e82545_tctl_value(TEST_TCTL_EN | TEST_TCTL_RTLC |
	    TEST_TCTL_RESERVED);

	ATF_CHECK_EQ(TEST_TCTL_EN | TEST_TCTL_PSP, initial);
	ATF_CHECK_EQ(TEST_TCTL_EN | TEST_TCTL_RTLC, updated);
	ATF_CHECK_EQ(TEST_TCTL_EN, initial & TEST_TCTL_EN);
	ATF_CHECK_EQ(TEST_TCTL_EN, updated & TEST_TCTL_EN);
	ATF_CHECK_EQ(0, updated & TEST_TCTL_RESERVED);
	ATF_CHECK(initial != updated);
}

ATF_TC_WITHOUT_HEAD(tso_lengths);
ATF_TC_BODY(tso_lengths, tc)
{

	ATF_CHECK(pci_e82545_tso_lengths_valid(1500, 54, 1446, 1460));
	ATF_CHECK(pci_e82545_tso_lengths_valid(54, 54, 0, 1460));
	ATF_CHECK(!pci_e82545_tso_lengths_valid(1500, 54, 1446, 0));
	ATF_CHECK(!pci_e82545_tso_lengths_valid(53, 54, 0, 1460));
	ATF_CHECK(!pci_e82545_tso_lengths_valid(1500, 54, 1447, 1460));
}

ATF_TC_WITHOUT_HEAD(tso_ip_header);
ATF_TC_BODY(tso_ip_header, tc)
{

	ATF_CHECK(pci_e82545_tso_ip_header_valid(20, 14, true));
	ATF_CHECK(!pci_e82545_tso_ip_header_valid(19, 14, true));
	ATF_CHECK(pci_e82545_tso_ip_header_valid(54, 14, false));
	ATF_CHECK(!pci_e82545_tso_ip_header_valid(53, 14, false));
	ATF_CHECK(!pci_e82545_tso_ip_header_valid(64, UINT32_MAX,
	    false));
}

ATF_TC_WITHOUT_HEAD(rx_descriptor_count);
ATF_TC_BODY(rx_descriptor_count, tc)
{

	/* Whole and partial descriptors round up. */
	ATF_CHECK_EQ(1, pci_e82545_rx_descriptor_count(1500, 2048, 1));
	ATF_CHECK_EQ(2, pci_e82545_rx_descriptor_count(1024, 512, 3));
	ATF_CHECK_EQ(3, pci_e82545_rx_descriptor_count(1536, 512, 3));
	ATF_CHECK_EQ(3, pci_e82545_rx_descriptor_count(1200, 512, 3));

	/*
	 * Regression: the raw ceil() would be maxpktdesc+1 here (1537 over a
	 * 512-byte buffer needs four descriptors), but only three were mapped
	 * and verified free.  The count must clamp to maxpktdesc.
	 */
	ATF_CHECK_EQ(3, pci_e82545_rx_descriptor_count(1537, 512, 3));
	/* Jumbo single-descriptor buffer: CRC add-back overflows the one map. */
	ATF_CHECK_EQ(1, pci_e82545_rx_descriptor_count(16388, 16384, 1));

	/* Degenerate inputs never index the iovec. */
	ATF_CHECK_EQ(0, pci_e82545_rx_descriptor_count(0, 512, 3));
	ATF_CHECK_EQ(0, pci_e82545_rx_descriptor_count(1500, 0, 3));
	ATF_CHECK_EQ(0, pci_e82545_rx_descriptor_count(1500, 512, 0));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, tctl_writable_state);
	ATF_TP_ADD_TC(tp, tso_lengths);
	ATF_TP_ADD_TC(tp, tso_ip_header);
	ATF_TP_ADD_TC(tp, rx_descriptor_count);
	return (atf_no_error());
}
