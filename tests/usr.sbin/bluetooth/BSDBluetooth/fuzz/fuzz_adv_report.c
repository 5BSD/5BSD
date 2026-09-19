/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for the LE advertising-report parsers in blued's
 * scan path (hci_scan.c).  These consume advertising and scan-response
 * data straight off the air -- fully attacker-controlled -- and feed
 * parsed name / manufacturer / service-UUID fields up to libble scan
 * results.  This is the same bug class as the adv_data over-read found
 * in hccontrol, but on the daemon side.
 *
 * Two entry points are exercised:
 *   hci_parse_ext_adv_report() -- a whole LE Extended Advertising Report
 *                                 (24-byte header + AD data).
 *   hci_parse_ad_fields()      -- the AD-structure TLV walker, fed the
 *                                 raw input directly so short/oversized
 *                                 length fields are explored without the
 *                                 header gate.
 *
 * Reference: Core Spec Vol 4 Part E 7.7.65.13 (LE Extended Advertising
 * Report), Vol 3 Part C 11 (AD format).
 */

#include <sys/types.h>

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hci_util.h"		/* struct ble_scan_result */
#include "hci_internal.h"	/* hci_parse_* */

/*
 * Globals referenced by the hci_*.c logging macros.  We link the real
 * hci_log.c (as hci_offline_test does), so do NOT pull in test_common.h's
 * hci_log stubs -- that would multiply-define them.
 */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct ble_scan_result sr;
	uint8_t *copy;

	if (size > 8192)
		size = 8192;
	copy = malloc(size == 0 ? 1 : size);
	if (copy == NULL)
		abort();
	if (size != 0)
		memcpy(copy, data, size);

	/* Whole extended advertising report (header + AD payload). */
	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = 0xFFFF;
	(void)hci_parse_ext_adv_report(copy, size, &sr);

	/* AD-field walker fed the raw bytes (no header gate). */
	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = 0xFFFF;
	hci_parse_ad_fields(copy, size, &sr);

	free(copy);
	return (0);
}
