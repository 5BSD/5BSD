/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Regression guard for the adv_name2str() out-of-bounds read fix in
 * usr.sbin/bluetooth/hccontrol/adv_data.c.
 *
 * The advertising Local Name field is raw, attacker-controlled AD bytes
 * and is NOT NUL terminated.  The old adv_name2str() used strlcpy(),
 * which scans the source to its NUL to compute a return value -- reading
 * past the end of the name buffer.  The fix copies exactly
 * min(datalen, size-1) bytes with memcpy() and terminates itself.
 *
 * This test feeds print_adv_data() a Complete Local Name whose bytes
 * fill an EXACT-SIZE heap allocation with no trailing NUL, so the old
 * strlcpy() over-read runs off the end of the allocation.  It must
 * return without crashing.  Most valuable under ASan, but also passes
 * in a normal build.
 *
 * This test uses the hccontrol link set (adv_data.c + hci_manufacturer2str
 * stub, -I hccontrol) exactly as adv_data_test.c does; that set does not
 * combine with the libble link set, so the ble.c guards live separately
 * in findings_regression_test.c.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include "hccontrol.h"
#include "spec_oracles.h"

/* adv_data.c references this hccontrol symbol; stub as in adv_data_test.c. */
char const *
hci_manufacturer2str(int id __unused)
{

	return ("TestManufacturer");
}

/* stdout/stderr capture so print_adv_data() output does not pollute the run. */
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

/*
 * Complete Local Name whose name bytes fill an exact-size heap
 * allocation with NO trailing NUL.  The old strlcpy() would scan past
 * the allocation; the fixed memcpy() copies exactly the field length.
 *
 * Core 6.3 Vol 3 Part C §11/Figure 11.1 makes AD data length-delimited:
 * one Length octet, one AD Type octet, then Length - 1 AD-data octets.
 * Assigned Numbers, Generic Access Profile Data Types assigns Complete
 * Local Name its generated value below.  No terminating NUL is specified.
 */
ATF_TC_WITHOUT_HEAD(test_adv_name_not_nul_terminated);
ATF_TC_BODY(test_adv_name_not_nul_terminated, tc)
{
	struct capture cap;
	/* 200 and 'A' are non-normative stress-vector choices. */
	const int namelen = 200;
	const int total = BT_CORE63_AD_PAYLOAD_OFFSET + namelen;
	uint8_t *ad;

	ad = malloc(total);			/* exact size: no slack, no NUL */
	ATF_REQUIRE(ad != NULL);
	ad[BT_CORE63_AD_LENGTH_OFFSET] =
	    (uint8_t)(BT_CORE63_AD_TYPE_SIZE + namelen);
	ad[BT_CORE63_AD_TYPE_OFFSET] =
	    BT_ASSIGNED_AD_TYPE_COMPLETE_LOCAL_NAME;
	memset(&ad[BT_CORE63_AD_PAYLOAD_OFFSET], 'A', namelen);
	ATF_REQUIRE(memchr(&ad[BT_CORE63_AD_PAYLOAD_OFFSET], '\0', namelen) ==
	    NULL);

	capture_begin(&cap);
	print_adv_data(total, ad);		/* must not over-read / crash */
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Complete local name:") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "AAAA") != NULL);

	free(ad);
}

/*
 * Shortened Local Name variant, also filling an exact-size
 * allocation with no NUL, exercising the same code path.
 * Core 6.3 Vol 3 Part C §11 supplies the same length-delimited framing;
 * Assigned Numbers supplies the generated Shortened Local Name AD type.
 */
ATF_TC_WITHOUT_HEAD(test_adv_shortname_not_nul_terminated);
ATF_TC_BODY(test_adv_shortname_not_nul_terminated, tc)
{
	struct capture cap;
	/* 32 and 'Z' are non-normative stress-vector choices. */
	const int namelen = 32;
	const int total = BT_CORE63_AD_PAYLOAD_OFFSET + namelen;
	uint8_t *ad;

	ad = malloc(total);
	ATF_REQUIRE(ad != NULL);
	ad[BT_CORE63_AD_LENGTH_OFFSET] =
	    (uint8_t)(BT_CORE63_AD_TYPE_SIZE + namelen);
	ad[BT_CORE63_AD_TYPE_OFFSET] =
	    BT_ASSIGNED_AD_TYPE_SHORTENED_LOCAL_NAME;
	memset(&ad[BT_CORE63_AD_PAYLOAD_OFFSET], 'Z', namelen);
	ATF_REQUIRE(memchr(&ad[BT_CORE63_AD_PAYLOAD_OFFSET], '\0', namelen) ==
	    NULL);

	capture_begin(&cap);
	print_adv_data(total, ad);
	capture_end(&cap);

	ATF_CHECK(strstr(cap.out_buf, "Shortened local name:") != NULL);
	ATF_CHECK(strstr(cap.out_buf, "ZZZZ") != NULL);

	free(ad);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_adv_name_not_nul_terminated);
	ATF_TP_ADD_TC(tp, test_adv_shortname_not_nul_terminated);

	return (atf_no_error());
}
