/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for the LEGACY LE Advertising Report / scan-response
 * receive path in blued's scan code (hci_scan.c).
 *
 * The legacy report walk lives INLINE inside hci_le_scan() /
 * hci_le_ext_scan() (subevent NG_HCI_LEEV_ADVREP, 0x02): for each report
 * it length-gates event_type(1)+addr_type(1)+addr(6)+data_len(1)+data+
 * rssi(1), runs the AD-structure walker over the report body, then
 * de-duplicates by Bluetooth address, folding a repeat sighting (e.g. a
 * SCAN_RSP following an ADV_IND) into the earlier entry via the static
 * scan_result_merge().  Those loops are welded to a live HCI socket +
 * bt_devreq(), so there is no exported "parse one legacy report" entry.
 *
 * To reach the static scan_result_merge() this harness #includes hci_scan.c
 * (the same TU-include idiom the kernel-L2CAP harnesses use); the rest of
 * the HCI object set is linked normally (SCAN_SRCS = the HCI sources minus
 * hci_scan.c, which now lives in this TU).  The fuzz input is framed as a
 * legacy LE Advertising Report subevent payload and walked with the exact
 * bounds logic of the production loop, driving the real hci_parse_ad_fields()
 * (in SCAN_RSP merge mode) and the real scan_result_merge() dedup path.
 *
 * REDUNDANCY NOTE: the AD-structure walker itself (hci_parse_ad /
 * hci_parse_ad_fields) and the EXTENDED report header parse
 * (hci_parse_ext_adv_report) are already fuzzed directly by fuzz_adv_report.
 * The genuinely-new surface here is the multi-report framing feeding the
 * static scan_result_merge() (name/mfr/UUID-array merge into an existing
 * result), which the single-report fuzz_adv_report cannot reach.
 *
 * Reference: Core Spec Vol 4 Part E 7.7.65.2 (LE Advertising Report),
 * Vol 3 Part C 11 (AD format).
 */

#include <sys/types.h>

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hci_util.h"		/* struct ble_scan_result */
#include "hci_internal.h"	/* hci_parse_* */

/*
 * Globals referenced by the hci_*.c logging macros.  hci_log.c is linked
 * (part of SCAN_SRCS), so define the globals here (as fuzz_adv_report does)
 * rather than pulling in test_common.h's stubs.
 */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

/*
 * Pull in hci_scan.c so the static scan_result_merge() (and the exported AD
 * parsers) are reachable in this TU.  hci_scan.c is therefore excluded from
 * the linked SCAN_SRCS to avoid duplicate symbols.
 */
#include "hci_scan.c"

#define FZ_MAX_RESULTS	32

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct ble_scan_result	 results[FZ_MAX_RESULTS];
	const uint8_t		*p;
	size_t			 remain;
	uint8_t			 num_reports;
	int			 count = 0, i;

	if (size > 8192)
		size = 8192;
	if (size < 1)
		return (0);

	/*
	 * Frame the input as a legacy LE Advertising Report subevent payload:
	 *   num_reports(1) |
	 *   report[]{ event_type(1) addr_type(1) addr(6)
	 *             data_len(1) data[data_len] rssi(1) }
	 * walked with the identical bounds logic of hci_le_scan(), driving the
	 * real hci_parse_ad_fields() + scan_result_merge().
	 */
	p = data;
	remain = size;
	num_reports = p[0];
	p++;
	remain--;
	if (num_reports == 0 || num_reports > 25)
		return (0);

	for (i = 0; i < num_reports && count < FZ_MAX_RESULTS; i++) {
		uint8_t			 addr_type, data_len;
		struct ble_scan_result	*sr;
		bool			 dup;
		int			 j;

		if (remain < 10 || p[0] > 0x04 || p[1] > 0x03)
			break;

		p++;			/* skip event_type */
		remain--;

		addr_type = p[0];
		p++;
		remain--;

		sr = &results[count];
		memset(sr, 0, sizeof(*sr));
		sr->mfr_id = 0xFFFF;
		memcpy(sr->addr, p, 6);
		sr->addr_type = (addr_type == 0x01 || addr_type == 0x03) ?
		    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
		p += 6;
		remain -= 6;

		if (remain < 1)
			break;
		data_len = p[0];
		p++;
		remain--;

		if (data_len > 31 || remain < (size_t)data_len + 1)
			break;

		hci_parse_ad_fields(p, data_len, sr);

		p += data_len;
		remain -= data_len;

		sr->rssi = (int8_t)p[0];
		p++;
		remain--;

		/* Dedup by address -> exercises the static scan_result_merge(). */
		dup = false;
		for (j = 0; j < count; j++) {
			if (results[j].addr_type == sr->addr_type &&
			    memcmp(results[j].addr, sr->addr, 6) == 0) {
				scan_result_merge(&results[j], sr);
				dup = true;
				break;
			}
		}
		if (!dup)
			count++;
	}

	return (0);
}
