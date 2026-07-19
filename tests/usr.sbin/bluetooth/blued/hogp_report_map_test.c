/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for HOGP (HID over GATT Profile) report-map handling,
 * Report Reference classification, and report routing by report ID.
 *
 * NOTE ON REACHABILITY
 * --------------------
 * blued does NOT contain a HID Report Descriptor *item* parser: the
 * Report Map characteristic (UUID 0x2A4B) is read into an opaque buffer
 * (hogp_device.report_map) and forwarded verbatim to the kernel vhid
 * device (see hogp_process_service() / hogp_setup_vhid() in
 * usr.sbin/bluetooth/blued/blued_central.c).  Report classification is
 * driven entirely by the 2-byte Report Reference descriptor
 * (UUID 0x2908): ref[0]=report_id, ref[1]=report_type.
 *
 * The real report-map / routing routines (hogp_process_service,
 * hogp_handle_vhid_output, hogp_setup_boot_protocol, hogp_find_feature_
 * handle) live in blued_central.c, which cannot be linked into a unit
 * test because it pulls in blued_internal.h (Capsicum, kqueue,
 * bluetooth.h, libservice, and the full daemon state).  As with the
 * sibling hogp_test.c, this file therefore uses local copies of the
 * reachable logic that MUST be kept byte-for-byte in sync with the
 * production source.  Each copy documents its source line range.
 *
 * The HID item walker (hid_walk) is a TEST-LOCAL model of what a HID
 * host parser must do; it is NOT production code.  It is used to (a)
 * prove the real boot report maps are structurally well-formed and (b)
 * exercise malformed descriptors (truncated items, long-item overrun,
 * zero-length) to assert a bounds-checked walk never reads past the
 * buffer.  Malformed buffers are heap-allocated at their exact size so
 * an over-read is caught under ASan.
 */

#include <atf-c.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "spec_hogp_report_map_oracles.h"

/* From blued_internal.h (Report Reference report types). */
#define HOGP_MAX_REPORTS	16

struct hogp_report {
	uint16_t	value_handle;
	uint16_t	cccd_handle;
	uint8_t		report_id;
	uint8_t		report_type;
};

struct hogp_device {
	char			_pad[256]; /* stands in for att/smp/bond_db */
	struct hogp_report	reports[HOGP_MAX_REPORTS];
	int			nreports;
};

/*
 * parse_report_reference -- local copy of the Report Reference
 * classification in hogp_process_service() (blued_central.c ~603-626).
 *
 * The characteristic entry is initialised report_id=0, report_type=0
 * and only overwritten when the descriptor read yields >= 2 bytes.
 */
static void
parse_report_reference(const uint8_t *ref, size_t len, struct hogp_report *rpt)
{

	rpt->report_id = 0;	/* blued_central.c:603 */
	rpt->report_type = 0;	/* blued_central.c:604 */

	if (len >= 2) {		/* blued_central.c:623 */
		rpt->report_id = ref[0];
		rpt->report_type = ref[1];
	}
}

/*
 * hogp_route_output -- local copy of the routing core of
 * hogp_handle_vhid_output() (blued_central.c ~1442-1494).
 *
 * Given a raw report buffer read from the kernel vhid device, decide
 * the report ID (present only if any report on the device uses a
 * non-zero ID), strip the ID byte, and return the Output Report value
 * handle to write to (0 if none matches).  *out_len receives the length
 * of the stripped payload.
 */
static uint16_t
hogp_route_output(struct hogp_device *dev, const uint8_t *buf, size_t n,
    uint8_t *out_id, size_t *out_len)
{
	uint8_t report_id;
	const uint8_t *report_data;
	size_t report_len;
	bool has_report_ids = false;
	int i;

	*out_id = 0;
	*out_len = 0;

	if (n == 0)
		return (0);

	for (i = 0; i < dev->nreports; i++) {
		if (dev->reports[i].report_id != 0) {
			has_report_ids = true;
			break;
		}
	}

	if (has_report_ids && n >= 1) {
		report_id = buf[0];
		report_data = buf + 1;
		report_len = n - 1;
	} else {
		report_id = 0;
		report_data = buf;
		report_len = n;
	}

	*out_id = report_id;
	*out_len = report_len;
	(void)report_data;

	for (i = 0; i < dev->nreports; i++) {
		struct hogp_report *rpt = &dev->reports[i];

		if (rpt->report_type != BT_HOGP_SPEC_REPORT_OUTPUT)
			continue;
		if (rpt->report_id != report_id)
			continue;
		return (rpt->value_handle);
	}
	return (0);
}

/*
 * Real Boot Protocol report maps, copied verbatim from
 * hogp_setup_boot_protocol() (blued_central.c ~1027 and ~1063).
 * Kept in sync to validate they parse as well-formed HID descriptors.
 */
/*
 * hid_walk -- TEST-LOCAL bounds-checked HID Report Descriptor walker.
 * (There is no such parser in blued; see the file header.)
 *
 * Walks short and long items.  Returns 0 on a clean, fully consumed
 * descriptor and -1 on any item whose declared length would run past
 * the buffer.  It NEVER reads a byte at an index >= len.  On success,
 * *nitems / *nreport_ids receive the item and Report ID (Global tag
 * 0x85) counts.
 *
 * Short item header:  bTag(4) bType(2) bSize(2); bSize 0/1/2/3 encode
 *   0/1/2/4 following data bytes.
 * Long item header:   prefix 0xFE, then bDataSize, then bLongItemTag,
 *   then bDataSize data bytes.
 */
static int
hid_walk(const uint8_t *p, size_t len, size_t *nitems, size_t *nreport_ids)
{
	size_t i = 0;
	size_t items = 0, rids = 0;

	while (i < len) {
		uint8_t prefix = p[i];

		if (prefix == BT_HID_SPEC_LONG_ITEM_PREFIX) {
			/* Long item: need prefix + size + tag (3 bytes). */
			if (i + 2 >= len)
				return (-1);
			size_t dsize = p[i + 1];
			size_t total = 3 + dsize;
			if (i + total > len)
				return (-1);
			i += total;
		} else {
			static const size_t szmap[4] = { 0, 1, 2, 4 };
			size_t dsize = szmap[prefix & BT_HID_SPEC_ITEM_SIZE_MASK];
			size_t total = 1 + dsize;
			if (i + total > len)
				return (-1);
			/* Global Report ID item = tag 8, type Global, size 1. */
			if ((prefix & BT_HID_SPEC_ITEM_TAG_TYPE_MASK) ==
			    BT_HID_SPEC_REPORT_ID_ITEM)
				rids++;
			i += total;
		}
		items++;
	}

	if (nitems != NULL)
		*nitems = items;
	if (nreport_ids != NULL)
		*nreport_ids = rids;
	return (0);
}

/* ================================================================
 * Report Reference classification
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_refdesc_input);
ATF_TC_BODY(test_refdesc_input, tc)
{
	struct hogp_report rpt;
	uint8_t ref[2] = { 0x01, BT_HOGP_SPEC_REPORT_INPUT };

	parse_report_reference(ref, sizeof(ref), &rpt);
	ATF_CHECK_EQ(rpt.report_id, 0x01);
	ATF_CHECK_EQ(rpt.report_type, BT_HOGP_SPEC_REPORT_INPUT);
}

ATF_TC_WITHOUT_HEAD(test_refdesc_output_feature);
ATF_TC_BODY(test_refdesc_output_feature, tc)
{
	struct hogp_report rpt;
	uint8_t out[2] = { 0x02, BT_HOGP_SPEC_REPORT_OUTPUT };
	uint8_t feat[2] = { 0x03, BT_HOGP_SPEC_REPORT_FEATURE };

	parse_report_reference(out, sizeof(out), &rpt);
	ATF_CHECK_EQ(rpt.report_id, 0x02);
	ATF_CHECK_EQ(rpt.report_type, BT_HOGP_SPEC_REPORT_OUTPUT);

	parse_report_reference(feat, sizeof(feat), &rpt);
	ATF_CHECK_EQ(rpt.report_id, 0x03);
	ATF_CHECK_EQ(rpt.report_type, BT_HOGP_SPEC_REPORT_FEATURE);
}

/* Truncated Report Reference (<2 bytes) leaves defaults, no over-read. */
ATF_TC_WITHOUT_HEAD(test_refdesc_truncated);
ATF_TC_BODY(test_refdesc_truncated, tc)
{
	struct hogp_report rpt;
	uint8_t *ref;

	/* One-byte descriptor at end of an exact-size allocation. */
	ref = malloc(1);
	ATF_REQUIRE(ref != NULL);
	ref[0] = 0x07;

	parse_report_reference(ref, 1, &rpt);
	ATF_CHECK_EQ(rpt.report_id, 0);
	ATF_CHECK_EQ(rpt.report_type, 0);
	free(ref);

	/* Zero-length descriptor. */
	parse_report_reference(NULL, 0, &rpt);
	ATF_CHECK_EQ(rpt.report_id, 0);
	ATF_CHECK_EQ(rpt.report_type, 0);
}

/* ================================================================
 * Output report routing by report ID
 * ================================================================ */

/* Device with report IDs: first byte of the buffer is the ID, stripped. */
ATF_TC_WITHOUT_HEAD(test_route_output_with_ids);
ATF_TC_BODY(test_route_output_with_ids, tc)
{
	struct hogp_device dev;
	uint8_t out_id;
	size_t out_len;
	uint16_t h;
	/* report_id byte 0x02 followed by one data byte */
	uint8_t buf[2] = { 0x02, 0xAB };

	memset(&dev, 0, sizeof(dev));
	dev.reports[0].value_handle = 0x0030;
	dev.reports[0].report_id = 0x02;
	dev.reports[0].report_type = BT_HOGP_SPEC_REPORT_OUTPUT;
	dev.reports[1].value_handle = 0x0040;
	dev.reports[1].report_id = 0x03;
	dev.reports[1].report_type = BT_HOGP_SPEC_REPORT_OUTPUT;
	dev.nreports = 2;

	h = hogp_route_output(&dev, buf, sizeof(buf), &out_id, &out_len);
	ATF_CHECK_EQ(h, 0x0030);
	ATF_CHECK_EQ(out_id, 0x02);
	ATF_CHECK_EQ(out_len, 1);	/* ID byte stripped */
}

/* Device without report IDs: no byte is stripped, id 0 matches. */
ATF_TC_WITHOUT_HEAD(test_route_output_no_ids);
ATF_TC_BODY(test_route_output_no_ids, tc)
{
	struct hogp_device dev;
	uint8_t out_id;
	size_t out_len;
	uint16_t h;
	uint8_t buf[3] = { 0x11, 0x22, 0x33 };

	memset(&dev, 0, sizeof(dev));
	dev.reports[0].value_handle = 0x0050;
	dev.reports[0].report_id = 0;	/* no IDs in use */
	dev.reports[0].report_type = BT_HOGP_SPEC_REPORT_OUTPUT;
	dev.nreports = 1;

	h = hogp_route_output(&dev, buf, sizeof(buf), &out_id, &out_len);
	ATF_CHECK_EQ(h, 0x0050);
	ATF_CHECK_EQ(out_id, 0);
	ATF_CHECK_EQ(out_len, 3);	/* nothing stripped */
}

/* Unknown report ID and zero-length inputs route to no handle. */
ATF_TC_WITHOUT_HEAD(test_route_output_unmatched);
ATF_TC_BODY(test_route_output_unmatched, tc)
{
	struct hogp_device dev;
	uint8_t out_id;
	size_t out_len;
	uint16_t h;
	uint8_t buf[2] = { 0x09, 0xFF };	/* id 9 not present */

	memset(&dev, 0, sizeof(dev));
	dev.reports[0].value_handle = 0x0030;
	dev.reports[0].report_id = 0x02;
	dev.reports[0].report_type = BT_HOGP_SPEC_REPORT_OUTPUT;
	/* An Input report must never be selected for output routing. */
	dev.reports[1].value_handle = 0x0060;
	dev.reports[1].report_id = 0x09;
	dev.reports[1].report_type = BT_HOGP_SPEC_REPORT_INPUT;
	dev.nreports = 2;

	h = hogp_route_output(&dev, buf, sizeof(buf), &out_id, &out_len);
	ATF_CHECK_EQ(h, 0);	/* 0x09 is Input, not Output */

	/* Zero-length buffer: no routing, no over-read. */
	h = hogp_route_output(&dev, buf, 0, &out_id, &out_len);
	ATF_CHECK_EQ(h, 0);
	ATF_CHECK_EQ(out_len, 0);
}

/* ================================================================
 * Real boot report maps parse cleanly (structural validation)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_boot_kb_map_valid);
ATF_TC_BODY(test_boot_kb_map_valid, tc)
{
	size_t nitems = 0, nrids = 0;

	ATF_CHECK_EQ(hid_walk(bt_hid_spec_boot_keyboard_descriptor,
	    sizeof(bt_hid_spec_boot_keyboard_descriptor),
	    &nitems, &nrids), 0);
	ATF_CHECK(nitems > 0);
	/* Boot keyboard uses no Report IDs -> boot report_id is 0. */
	ATF_CHECK_EQ(nrids, 0);
}

ATF_TC_WITHOUT_HEAD(test_boot_mouse_map_valid);
ATF_TC_BODY(test_boot_mouse_map_valid, tc)
{
	size_t nitems = 0, nrids = 0;

	ATF_CHECK_EQ(hid_walk(bt_hid_spec_boot_mouse_descriptor,
	    sizeof(bt_hid_spec_boot_mouse_descriptor), &nitems, &nrids), 0);
	ATF_CHECK(nitems > 0);
	ATF_CHECK_EQ(nrids, 0);
}

/* ================================================================
 * Malformed HID descriptors: bounded walk, no over-read
 * ================================================================ */

/* Zero-length descriptor is a clean, empty walk. */
ATF_TC_WITHOUT_HEAD(test_map_zero_length);
ATF_TC_BODY(test_map_zero_length, tc)
{
	size_t nitems = 99, nrids = 99;

	ATF_CHECK_EQ(hid_walk((const uint8_t *)"", 0, &nitems, &nrids), 0);
	ATF_CHECK_EQ(nitems, 0);
	ATF_CHECK_EQ(nrids, 0);
}

/* Short item whose declared data runs past the buffer end. */
ATF_TC_WITHOUT_HEAD(test_map_truncated_short_item);
ATF_TC_BODY(test_map_truncated_short_item, tc)
{
	uint8_t *p;

	/*
	 * 0x75 = Report Size, size field 1 -> expects 1 data byte, but the
	 * buffer ends immediately.  Exact-size allocation so any over-read
	 * trips ASan.
	 */
	p = malloc(1);
	ATF_REQUIRE(p != NULL);
	p[0] = 0x75;
	ATF_CHECK_EQ(hid_walk(p, 1, NULL, NULL), -1);
	free(p);
}

/* Long item whose bDataSize runs past the buffer end. */
ATF_TC_WITHOUT_HEAD(test_map_long_item_overrun);
ATF_TC_BODY(test_map_long_item_overrun, tc)
{
	uint8_t *p;

	/* 0xFE long item, claims 0x40 data bytes, but only 3 bytes exist. */
	p = malloc(3);
	ATF_REQUIRE(p != NULL);
	p[0] = BT_HID_SPEC_LONG_ITEM_PREFIX;
	p[1] = 0x40;	/* bDataSize = 64 */
	p[2] = 0x01;	/* bLongItemTag */
	ATF_CHECK_EQ(hid_walk(p, 3, NULL, NULL), -1);
	free(p);

	/* Long item prefix with no room for size/tag bytes at all. */
	p = malloc(1);
	ATF_REQUIRE(p != NULL);
	p[0] = BT_HID_SPEC_LONG_ITEM_PREFIX;
	ATF_CHECK_EQ(hid_walk(p, 1, NULL, NULL), -1);
	free(p);
}

/*
 * Structurally valid but "aggressive" values (oversized Report Count,
 * unusual Usage Page) are just item data and must walk cleanly -- they
 * do not authorise any over-read.
 */
ATF_TC_WITHOUT_HEAD(test_map_large_values_ok);
ATF_TC_BODY(test_map_large_values_ok, tc)
{
	/*
	 * Usage Page (0xFFFF vendor), Report Count (0xFFFF), Report Size
	 * (0xFF), then a well-formed Input item.  All structurally valid.
	 */
	uint8_t desc[] = {
	    0x06, 0xFF, 0xFF,	/* Usage Page (vendor, 2-byte data) */
	    0x96, 0xFF, 0xFF,	/* Report Count (0xFFFF) */
	    0x75, 0xFF,		/* Report Size (255) */
	    0x81, 0x02		/* Input (Data,Var,Abs) */
	};
	size_t nitems = 0;

	ATF_CHECK_EQ(hid_walk(desc, sizeof(desc), &nitems, NULL), 0);
	ATF_CHECK_EQ(nitems, 4);
}

/* ================================================================
 * Registration
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_refdesc_input);
	ATF_TP_ADD_TC(tp, test_refdesc_output_feature);
	ATF_TP_ADD_TC(tp, test_refdesc_truncated);
	ATF_TP_ADD_TC(tp, test_route_output_with_ids);
	ATF_TP_ADD_TC(tp, test_route_output_no_ids);
	ATF_TP_ADD_TC(tp, test_route_output_unmatched);
	ATF_TP_ADD_TC(tp, test_boot_kb_map_valid);
	ATF_TP_ADD_TC(tp, test_boot_mouse_map_valid);
	ATF_TP_ADD_TC(tp, test_map_zero_length);
	ATF_TP_ADD_TC(tp, test_map_truncated_short_item);
	ATF_TP_ADD_TC(tp, test_map_long_item_overrun);
	ATF_TP_ADD_TC(tp, test_map_large_values_ok);

	return (atf_no_error());
}
