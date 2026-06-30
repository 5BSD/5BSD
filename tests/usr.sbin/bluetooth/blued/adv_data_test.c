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

/* 2. Flags (0x01) */
ATF_TC_WITHOUT_HEAD(test_adv_flags);
ATF_TC_BODY(test_adv_flags, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x02, 0x01, 0x06 };  /* len=2, type=Flags, data=0x06 */

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Flags:") != NULL);
}

/* 3. Complete Local Name (0x09) */
ATF_TC_WITHOUT_HEAD(test_adv_complete_local_name);
ATF_TC_BODY(test_adv_complete_local_name, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x08, 0x09, 'T', 'e', 's', 't', 'D', 'e', 'v' };

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
	uint8_t ad[] = { 0x04, 0x08, 'T', 's', 't' };

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
	uint8_t ad[] = { 0x02, 0x0A, 0x04 };  /* +4 dBm */

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
	uint8_t ad[] = { 0x02, 0x0A, 0xFC };  /* -4 dBm (signed) */

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Tx Power level:") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "-4 dBm") != NULL);
}

/* 7. Appearance (0x19) */
ATF_TC_WITHOUT_HEAD(test_adv_appearance);
ATF_TC_BODY(test_adv_appearance, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x03, 0x19, 0xC1, 0x03 };  /* Appearance: 0x03C1 = keyboard */

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Appearance:") != NULL);
}

/* 8. Complete 16-bit UUID List (0x03) */
ATF_TC_WITHOUT_HEAD(test_adv_complete_uuid16_list);
ATF_TC_BODY(test_adv_complete_uuid16_list, tc)
{
	struct capture cap;
	/* Two UUID16s: 0x180F (Battery), 0x180A (Device Info) */
	uint8_t ad[] = { 0x05, 0x03, 0x0F, 0x18, 0x0A, 0x18 };

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
	uint8_t ad[] = { 0x03, 0x02, 0x0F, 0x18 };

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
	uint8_t ad[18];
	ad[0] = 17;	/* length: type(1) + uuid(16) */
	ad[1] = 0x07;	/* Complete 128-bit UUID list */
	/* Fill with a test UUID */
	memset(&ad[2], 0x42, 16);

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "128 bit") != NULL);
}

/* 11. Manufacturer Specific Data (0xFF) */
ATF_TC_WITHOUT_HEAD(test_adv_manufacturer_data);
ATF_TC_BODY(test_adv_manufacturer_data, tc)
{
	struct capture cap;
	/* Manufacturer ID = 0x004C (Apple), then 2 bytes of data */
	uint8_t ad[] = { 0x05, 0xFF, 0x4C, 0x00, 0xDE, 0xAD };

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Manufacturer") != NULL);
}

/* 12. Service Data (0x16) */
ATF_TC_WITHOUT_HEAD(test_adv_service_data);
ATF_TC_BODY(test_adv_service_data, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x04, 0x16, 0x0F, 0x18, 0x64 };  /* Battery Service + level */

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
	uint8_t ad[] = { 0x02, 0xFE, 0x42 };  /* type 0xFE = unknown */

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
	uint8_t ad[] = { 0x00, 0x01, 0x06 };

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
	uint8_t ad[] = { 0x0A, 0x09, 'A', 'B' };  /* length=10 but only 3 bytes remain */

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
		0x02, 0x01, 0x06,			/* Flags */
		0x05, 0x09, 'T', 'e', 's', 't'		/* Name */
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
	uint8_t ad[31];

	memset(ad, 0, sizeof(ad));
	/* Flags: 3 bytes */
	ad[0] = 0x02; ad[1] = 0x01; ad[2] = 0x06;
	/* Complete Local Name: 28 bytes (len=27, type, 26 chars) */
	ad[3] = 27; ad[4] = 0x09;
	memset(&ad[5], 'A', 26);

	capture_begin(&cap);
	print_adv_data(31, ad);
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

/* 19. Class of Device (0x0D) */
ATF_TC_WITHOUT_HEAD(test_adv_class_of_device);
ATF_TC_BODY(test_adv_class_of_device, tc)
{
	struct capture cap;
	uint8_t ad[] = { 0x04, 0x0D, 0x04, 0x05, 0x20 };  /* 3 bytes CoD */

	capture_begin(&cap);
	print_adv_data(sizeof(ad), ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Class of device:") != NULL);
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

	return (atf_no_error());
}
