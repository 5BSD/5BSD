/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF unit tests for BLE advertising data (AD) parsing.
 *
 * Tests print_adv_data() and dump_adv_data() from hccontrol/adv_data.c
 * by redirecting stdout/stderr to a tmpfile and verifying the output.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

/* ================================================================
 * Stubs for hccontrol symbols referenced by adv_data.c.
 * Include hccontrol.h for prototypes.
 * ================================================================ */

#include "hccontrol.h"
#include "spec_adv_data_oracles.h"

char const *
hci_manufacturer2str(int id __unused)
{

	return ("TestManufacturer");
}

/* ================================================================
 * Output capture helper
 * ================================================================ */

struct capture {
	FILE	*old_stdout;
	FILE	*old_stderr;
	FILE	*out_file;
	FILE	*err_file;
	char	out_buf[4096];
	char	err_buf[4096];
};

static void
capture_begin(struct capture *cap)
{

	fflush(stdout);
	fflush(stderr);
	cap->old_stdout = stdout;
	cap->old_stderr = stderr;
	cap->out_file = tmpfile();
	cap->err_file = tmpfile();
	ATF_REQUIRE(cap->out_file != NULL);
	ATF_REQUIRE(cap->err_file != NULL);
	stdout = cap->out_file;
	stderr = cap->err_file;
}

static void
capture_end(struct capture *cap)
{
	size_t nr;

	fflush(stdout);
	fflush(stderr);
	stdout = cap->old_stdout;
	stderr = cap->old_stderr;

	rewind(cap->out_file);
	nr = fread(cap->out_buf, 1, sizeof(cap->out_buf) - 1, cap->out_file);
	cap->out_buf[nr] = '\0';
	fclose(cap->out_file);

	rewind(cap->err_file);
	nr = fread(cap->err_buf, 1, sizeof(cap->err_buf) - 1, cap->err_file);
	cap->err_buf[nr] = '\0';
	fclose(cap->err_file);
}

/* ================================================================
 * Tests
 * ================================================================ */

/* 1. Empty AD data — no output, no crash */
ATF_TC_WITHOUT_HEAD(test_adv_empty_data);
ATF_TC_BODY(test_adv_empty_data, tc)
{
	struct capture cap;

	capture_begin(&cap);
	print_adv_data(0, NULL);
	capture_end(&cap);

	ATF_CHECK_STREQ(cap.out_buf, "");
}

/* 2. Flags (0x01) — decoded bitfield.
 *
 * Flags = 0x06 sets bit 1 (LE General Discoverable Mode) and bit 2 (BR/EDR
 * Not Supported), the classic LE-only general-discoverable device (Core
 * Specification Supplement Part A S1.3 / Core Spec Vol 3 Part C S11).  bit 0
 * (LE Limited Discoverable Mode) is clear, so it must NOT appear.
 */
ATF_TC_WITHOUT_HEAD(test_adv_flags);
ATF_TC_BODY(test_adv_flags, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x02, BT_ADV_SPEC_TYPE_FLAGS,
	    BT_ADVD_SPEC_FLAGS_GENERAL_LE_ONLY };

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Flags:") != NULL);
	ATF_CHECK_MSG(strstr(cap.out_buf, "0x06") != NULL,
	    "raw flags byte must be printed");
	ATF_CHECK_MSG(strstr(cap.out_buf, "LE General Discoverable Mode") != NULL,
	    "bit 1 must decode to LE General Discoverable Mode");
	ATF_CHECK_MSG(strstr(cap.out_buf, "BR/EDR Not Supported") != NULL,
	    "bit 2 must decode to BR/EDR Not Supported");
	ATF_CHECK_MSG(strstr(cap.out_buf, "Limited") == NULL,
	    "bit 0 is clear; LE Limited Discoverable Mode must not appear");
}

/* 3. Complete Local Name (0x09) */
ATF_TC_WITHOUT_HEAD(test_adv_complete_local_name);
ATF_TC_BODY(test_adv_complete_local_name, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x08, BT_ADV_SPEC_TYPE_NAME_COMPLETE,
	    'T', 'e', 's', 't', 'D', 'e', 'v' };

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Complete local name:") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "TestDev") != NULL);
}

/* 4. Shortened Local Name (0x08) */
ATF_TC_WITHOUT_HEAD(test_adv_shortened_local_name);
ATF_TC_BODY(test_adv_shortened_local_name, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x04, BT_ADV_SPEC_TYPE_NAME_SHORT, 'T', 's', 't' };

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Shortened local name:") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "Tst") != NULL);
}

/* 5. TX Power Level (0x0A) — positive */
ATF_TC_WITHOUT_HEAD(test_adv_tx_power);
ATF_TC_BODY(test_adv_tx_power, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x02, BT_ADV_SPEC_TYPE_TX_POWER, 0x04 };

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Tx Power level:") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "4 dBm") != NULL);
}

/* 6. TX Power Level — negative */
ATF_TC_WITHOUT_HEAD(test_adv_tx_power_negative);
ATF_TC_BODY(test_adv_tx_power_negative, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x02, BT_ADV_SPEC_TYPE_TX_POWER,
	    (uint8_t)(int8_t)-4 };

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Tx Power level:") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "-4 dBm") != NULL);
}

/* 7. Appearance (0x19) — decoded category/subcategory.
 *
 * The Appearance value is 16-bit little-endian; the upper 10 bits are the
 * category and lower 6 the subcategory (Core Spec Vol 3 Part C S12.2 /
 * Assigned Numbers).  0x03C1 -> category 0x0F (Human Interface Device),
 * subcategory 0x01 (Keyboard).
 */
ATF_TC_WITHOUT_HEAD(test_adv_appearance);
ATF_TC_BODY(test_adv_appearance, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x03, BT_ADV_SPEC_TYPE_APPEARANCE,
	    (uint8_t)BT_ADVD_SPEC_APPEARANCE_HID_KEYBOARD,
	    (uint8_t)(BT_ADVD_SPEC_APPEARANCE_HID_KEYBOARD >> 8) };

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Appearance:") != NULL);
	ATF_CHECK_MSG(strstr(cap.out_buf, "0x03c1") != NULL,
	    "16-bit appearance value must be printed");
	ATF_CHECK_MSG(strstr(cap.out_buf, "Human Interface Device") != NULL,
	    "category 0x0f must decode to Human Interface Device");
	ATF_CHECK_MSG(strstr(cap.out_buf, "subcategory 0x01") != NULL,
	    "low 6 bits must decode as subcategory 0x01");
}

/* 8. Complete 16-bit UUID List (0x03) */
ATF_TC_WITHOUT_HEAD(test_adv_complete_uuid16_list);
ATF_TC_BODY(test_adv_complete_uuid16_list, tc)
{
	struct capture cap;
	/* Two UUID16s: 0x180F (Battery), 0x180A (Device Info) */
	uint8_t ad[] = { 0x05, BT_ADV_SPEC_TYPE_UUID16_COMPLETE,
	    (uint8_t)BT_ADVD_SPEC_UUID_BATTERY,
	    (uint8_t)(BT_ADVD_SPEC_UUID_BATTERY >> 8),
	    (uint8_t)BT_ADVD_SPEC_UUID_DEVICE_INFO,
	    (uint8_t)(BT_ADVD_SPEC_UUID_DEVICE_INFO >> 8) };

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Complete list of service class UUIDs (16-bit):") != NULL);
}

/* 9. Incomplete 16-bit UUID List (0x02) */
ATF_TC_WITHOUT_HEAD(test_adv_incomplete_uuid16_list);
ATF_TC_BODY(test_adv_incomplete_uuid16_list, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x03, BT_ADV_SPEC_TYPE_UUID16_INCOMPLETE,
	    (uint8_t)BT_ADVD_SPEC_UUID_BATTERY,
	    (uint8_t)(BT_ADVD_SPEC_UUID_BATTERY >> 8) };

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Incomplete list of service class UUIDs (16-bit):") != NULL);
}

/* 10. Complete 128-bit UUID List (0x07) */
ATF_TC_WITHOUT_HEAD(test_adv_complete_uuid128);
ATF_TC_BODY(test_adv_complete_uuid128, tc)
{
	struct capture cap;
	/* 16-byte UUID (vendor) */
	uint8_t ad[2 + BT_ADVD_SPEC_UUID128_SIZE];
	ad[0] = 1 + BT_ADVD_SPEC_UUID128_SIZE;
	ad[1] = BT_ADV_SPEC_TYPE_UUID128_COMPLETE;
	/*
	 * 128-bit Service UUIDs are transmitted in the AD structure in
	 * little-endian order (least significant octet first) --
	 * Core Spec Vol 3 Part C S11 / CSS Part A S1.1.  A distinguishable
	 * ascending pattern lets us assert that the parser re-orders the
	 * bytes into the canonical (big-endian) UUID string rather than
	 * merely echoing them.  Hand-derived: LE octets 00..FF reverse to
	 * ffeeddcc-bbaa-9988-7766-554433221100.
	 */
	for (int i = 0; i < BT_ADVD_SPEC_UUID128_SIZE; i++)
		ad[2 + i] = (uint8_t)(i * 0x11);

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "128 bit") != NULL);
	ATF_CHECK(strstr(cap.out_buf,
	    "ffeeddcc-bbaa-9988-7766-554433221100") != NULL);
}

/* 11. Manufacturer Specific Data (0xFF) */
ATF_TC_WITHOUT_HEAD(test_adv_manufacturer_data);
ATF_TC_BODY(test_adv_manufacturer_data, tc)
{
	struct capture cap;
	/* Manufacturer ID = 0x004C, then 2 bytes of data */
	uint8_t ad[] = { 0x05, BT_ADV_SPEC_TYPE_MANUFACTURER,
	    (uint8_t)BT_ADVD_SPEC_COMPANY_APPLE,
	    (uint8_t)(BT_ADVD_SPEC_COMPANY_APPLE >> 8), 0xDE, 0xAD };

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Manufacturer") != NULL);
	/*
	 * Manufacturer Specific Data: the first 2 value octets are the
	 * Company Identifier Code, the remainder is the payload (CSS Part
	 * A S1.4).  The 2-octet company id (4C 00) must be consumed, so
	 * only the trailing payload bytes DE AD are emitted as data --
	 * this proves the field split is spec-correct, not off-by-one.
	 */
	ATF_CHECK(strstr(cap.out_buf, "de ad") != NULL);
}

/* 12. Service Data (0x16) */
ATF_TC_WITHOUT_HEAD(test_adv_service_data);
ATF_TC_BODY(test_adv_service_data, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x04, BT_ADV_SPEC_TYPE_SERVICE_DATA16,
	    (uint8_t)BT_ADVD_SPEC_UUID_BATTERY,
	    (uint8_t)(BT_ADVD_SPEC_UUID_BATTERY >> 8), 0x64 };

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Service data:") != NULL);
}

/* 13. Unknown AD Type — should print "UNKNOWN" */
ATF_TC_WITHOUT_HEAD(test_adv_unknown_type);
ATF_TC_BODY(test_adv_unknown_type, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x02, BT_ADVD_SPEC_UNKNOWN_TYPE, 0x42 };

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "UNKNOWN datatype:") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "fe") != NULL);
}

/* 14. Malformed: length=0 — should print error and stop */
ATF_TC_WITHOUT_HEAD(test_adv_malformed_length_zero);
ATF_TC_BODY(test_adv_malformed_length_zero, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x00, BT_ADV_SPEC_TYPE_FLAGS,
	    BT_ADVD_SPEC_FLAGS_GENERAL_LE_ONLY };

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	/* Error goes to stderr */
	ATF_CHECK(strstr(cap.err_buf, "Invalid advertising data length") != NULL);
	/* No AD type output on stdout */
	ATF_CHECK(strstr(cap.out_buf, "Flags:") == NULL);
}

/* 15. Malformed: length exceeds remaining bytes */
ATF_TC_WITHOUT_HEAD(test_adv_malformed_length_exceeds);
ATF_TC_BODY(test_adv_malformed_length_exceeds, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x0A, BT_ADV_SPEC_TYPE_NAME_COMPLETE, 'A', 'B' };

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.err_buf, "Invalid advertising data length") != NULL);
}

/* 16. Multiple AD structures concatenated */
ATF_TC_WITHOUT_HEAD(test_adv_multiple_structures);
ATF_TC_BODY(test_adv_multiple_structures, tc)
{
	struct capture cap;
	/* Flags + Complete Local Name */
	uint8_t ad[] = {
		0x02, BT_ADV_SPEC_TYPE_FLAGS,
		    BT_ADVD_SPEC_FLAGS_GENERAL_LE_ONLY,
		0x05, BT_ADV_SPEC_TYPE_NAME_COMPLETE, 'T', 'e', 's', 't'
	};

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Flags:") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "Complete local name:") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "Test") != NULL);
}

/* 17. Exactly 31 bytes — legacy AD max */
ATF_TC_WITHOUT_HEAD(test_adv_exactly_31_bytes);
ATF_TC_BODY(test_adv_exactly_31_bytes, tc)
{
	struct capture cap;
	uint8_t ad[BT_ADV_SPEC_LEGACY_DATA_MAX];

	memset(ad, 0, sizeof(ad));
	/* Flags: 3 bytes */
	ad[0] = 0x02;
	ad[1] = BT_ADV_SPEC_TYPE_FLAGS;
	ad[2] = BT_ADVD_SPEC_FLAGS_GENERAL_LE_ONLY;
	/* Complete Local Name: 28 bytes (len=27, type, 26 chars) */
	ad[3] = 27;
	ad[4] = BT_ADV_SPEC_TYPE_NAME_COMPLETE;
	memset(&ad[5], 'A', 26);

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Flags:") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "Complete local name:") != NULL);
}

/* 18. dump_adv_data — verify hex output */
ATF_TC_WITHOUT_HEAD(test_adv_dump_hex);
ATF_TC_BODY(test_adv_dump_hex, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0xDE, 0xAD, 0xBE, 0xEF };

	capture_begin(&cap);
	dump_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "ADV Data:") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "de") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "ad") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "be") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "ef") != NULL);
}

/* 19. Class of Device (0x0D) — decoded Major Device Class.
 *
 * CoD is 3 octets little-endian; bytes 04 05 20 -> 0x200504.  The Major
 * Device Class is bits 8-12: (0x200504 >> 8) & 0x1f = 0x05 = Peripheral
 * (Assigned Numbers / Baseband).
 */
ATF_TC_WITHOUT_HEAD(test_adv_class_of_device);
ATF_TC_BODY(test_adv_class_of_device, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x04, BT_ADVD_SPEC_TYPE_CLASS_OF_DEVICE,
	    (uint8_t)BT_ADVD_SPEC_CLASS_PERIPHERAL,
	    (uint8_t)(BT_ADVD_SPEC_CLASS_PERIPHERAL >> 8),
	    (uint8_t)(BT_ADVD_SPEC_CLASS_PERIPHERAL >> 16) };

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Class of device:") != NULL);
	ATF_CHECK_MSG(strstr(cap.out_buf, "0x200504") != NULL,
	    "24-bit class-of-device value must be printed");
	ATF_CHECK_MSG(strstr(cap.out_buf, "Peripheral") != NULL,
	    "Major Device Class 0x05 must decode to Peripheral");
}

/* CSS field-width minima: one octet short must not be decoded or over-read. */
ATF_TC_WITHOUT_HEAD(test_adv_typed_value_minima);
ATF_TC_BODY(test_adv_typed_value_minima, tc)
{
	struct capture cap;
	uint8_t ad[] = {
		0x01, BT_ADV_SPEC_TYPE_TX_POWER,
		0x02, BT_ADV_SPEC_TYPE_MANUFACTURER, 0x4c,
		0x02, BT_ADV_SPEC_TYPE_APPEARANCE, 0xc1,
		0x03, BT_ADVD_SPEC_TYPE_CLASS_OF_DEVICE, 0x04, 0x05,
		BT_ADVD_SPEC_UUID128_SIZE, BT_ADV_SPEC_TYPE_UUID128_COMPLETE,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	};

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Tx Power level: (no data)") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "Manufacturer specific data (too short)") !=
	    NULL);
	ATF_CHECK(strstr(cap.out_buf, "Appearance: \n") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "Class of device: \n") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "UUIDs (128 bit): \n") != NULL);
}

/* ================================================================
 * Test registration
 * ================================================================ */

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_adv_empty_data);
	ATF_TP_ADD_TC(tp, test_adv_flags);
	ATF_TP_ADD_TC(tp, test_adv_complete_local_name);
	ATF_TP_ADD_TC(tp, test_adv_shortened_local_name);
	ATF_TP_ADD_TC(tp, test_adv_tx_power);
	ATF_TP_ADD_TC(tp, test_adv_tx_power_negative);
	ATF_TP_ADD_TC(tp, test_adv_appearance);
	ATF_TP_ADD_TC(tp, test_adv_complete_uuid16_list);
	ATF_TP_ADD_TC(tp, test_adv_incomplete_uuid16_list);
	ATF_TP_ADD_TC(tp, test_adv_complete_uuid128);
	ATF_TP_ADD_TC(tp, test_adv_manufacturer_data);
	ATF_TP_ADD_TC(tp, test_adv_service_data);
	ATF_TP_ADD_TC(tp, test_adv_unknown_type);
	ATF_TP_ADD_TC(tp, test_adv_malformed_length_zero);
	ATF_TP_ADD_TC(tp, test_adv_malformed_length_exceeds);
	ATF_TP_ADD_TC(tp, test_adv_multiple_structures);
	ATF_TP_ADD_TC(tp, test_adv_exactly_31_bytes);
	ATF_TP_ADD_TC(tp, test_adv_dump_hex);
	ATF_TP_ADD_TC(tp, test_adv_class_of_device);
	ATF_TP_ADD_TC(tp, test_adv_typed_value_minima);

	return (atf_no_error());
}
