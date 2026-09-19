/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * HCI LE command parameter ENCODING boundary tests.
 *
 * These exercise the host-side parameter validation that blued performs
 * before a command reaches the controller, checked against the ranges in
 * Core Spec Vol 4 Part E Section 7.8:
 *
 *   - advertising interval (0.625ms units) min/max clamps (7.8.5)
 *   - extended advertising interval (3-byte, 7.8.53)
 *   - periodic advertising interval (1.25ms units, 7.8.61)
 *   - connection interval / latency / supervision-timeout (7.8.18)
 *   - data length (tx_octets 27..251, tx_time, 7.8.33 / 7.8.35)
 *   - RPA timeout (1..3600s, 7.8.45)
 *   - min encryption key size (7..16, 7.3.102)
 *   - extended create connection PHY-array bounds (7.8.66)
 *   - Create CIS / connectionless CTE / ECBFC channel-count bounds
 *
 * The encoders build a bt_devreq and hand it to bt_devreq()/the HCI
 * socket, so the emitted little-endian parameter bytes are not directly
 * observable from user space.  What *is* observable and deterministic is
 * the pre-I/O validation: an out-of-range parameter returns -1 with
 * errno == EINVAL *before* any socket I/O, while an in-range parameter
 * passes validation and only then fails at the (absent) hardware with a
 * different errno.  We drive every encoder with a valid non-HCI fd (see
 * test_fd()) and assert on that boundary behaviour.
 *
 * Link set (same as hci_offline_test.c): hci_util.c hci_adv.c hci_scan.c
 * hci_conn.c hci_privacy.c hci_misc.c hci_log.c.  No test_common.h.
 */

#include <atf-c.h>

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "hci_util.h"
#include "hci_internal.h"
#include "ble_util.h"
#include "blued_encryption_event.h"
#include "spec_oracles.h"
#include "spec_hci_event_bounds_oracles.h"

/* Stub globals required by the hci_*.c logging macros (_BLUED_LOG). */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

/*
 * A valid but non-HCI file descriptor.  Passing fd == -1 cannot distinguish a
 * host-side range rejection from a plain bad fd: bt_devreq() maps s < 0 to
 * EINVAL itself, the very errno our range checks use.  A real fd lets a valid
 * call proceed past the range check and fail later in getsockopt(SOL_HCI_RAW)
 * with ENOTSOCK, so ACCEPT() can assert errno != EINVAL meaningfully.
 */
static int
test_fd(void)
{
	static int fd = -1;

	if (fd < 0)
		fd = open("/dev/null", O_RDWR);
	return (fd);
}

/*
 * Helpers.  REJECT() asserts a call is rejected by host validation with
 * EINVAL before any I/O.  ACCEPT() asserts a call passes validation (it
 * still returns -1 because there is no controller behind fd -1, but the
 * failure is NOT the EINVAL of a range check).
 */
#define REJECT(call)	do {						\
	int _r;								\
	errno = 0;							\
	_r = (call);							\
	ATF_CHECK_EQ_MSG(_r, -1, "expected rejection from " #call);	\
	ATF_CHECK_EQ_MSG(EINVAL, errno,					\
	    "expected EINVAL from " #call ", got errno=%d", errno);	\
} while (0)

#define ACCEPT(call)	do {						\
	errno = 0;							\
	(void)(call);							\
	ATF_CHECK_MSG(errno != EINVAL,					\
	    "validation wrongly rejected " #call);			\
} while (0)

/* Core 6.3 Vol 4 Part E §7.7.8: exact v1/v2 event decoding for LE. */
ATF_TC_WITHOUT_HEAD(encryption_change_v1_v2_decode);
ATF_TC_BODY(encryption_change_v1_v2_decode, tc)
{
	struct blued_encryption_change event;
	uint8_t v1[3 + BT_CORE63_HCI_ENCRYPTION_CHANGE_V1_PARAM_SIZE] = {
		NG_HCI_EVENT_PKT,
		BT_CORE63_HCI_ENCRYPTION_CHANGE_V1_EVENT,
		BT_CORE63_HCI_ENCRYPTION_CHANGE_V1_PARAM_SIZE,
		BT_CORE63_HCI_ENCRYPTION_STATUS_SUCCESS, 0, 0,
		BT_CORE63_HCI_ENCRYPTION_LE_ON
	};
	uint8_t v2[3 + BT_CORE63_HCI_ENCRYPTION_CHANGE_V2_PARAM_SIZE] = {
		NG_HCI_EVENT_PKT,
		BT_CORE63_HCI_ENCRYPTION_CHANGE_V2_EVENT,
		BT_CORE63_HCI_ENCRYPTION_CHANGE_V2_PARAM_SIZE,
		BT_CORE63_HCI_ENCRYPTION_STATUS_SUCCESS, 0, 0,
		BT_CORE63_HCI_ENCRYPTION_LE_ON,
		BT_CORE63_SMP_MAX_KEY_SIZE + 1
	};

	/* Exact generated §7.7.8 lower and upper handle boundaries. */
	v1[4] = BT_CORE63_HCI_ENCRYPTION_HANDLE_MIN & 0xff;
	v1[5] = BT_CORE63_HCI_ENCRYPTION_HANDLE_MIN >> 8;
	ATF_REQUIRE_EQ(0, blued_parse_encryption_change(v1, sizeof(v1),
	    &event));
	ATF_CHECK_EQ(1, event.version);
	ATF_CHECK(blued_encryption_change_is_le_on(&event));

	v2[4] = BT_CORE63_HCI_ENCRYPTION_HANDLE_MAX & 0xff;
	v2[5] = BT_CORE63_HCI_ENCRYPTION_HANDLE_MAX >> 8;
	ATF_REQUIRE_EQ(0, blued_parse_encryption_change(v2, sizeof(v2),
	    &event));
	ATF_CHECK_EQ(2, event.version);
	ATF_CHECK_EQ(BT_CORE63_HCI_ENCRYPTION_HANDLE_MAX, event.handle);
	ATF_CHECK(blued_encryption_change_is_le_on(&event));

	/* The v2 key-size byte is deliberately 17: LE ignores this field. */
	v2[6] = BT_CORE63_HCI_ENCRYPTION_OFF;
	ATF_REQUIRE_EQ(0, blued_parse_encryption_change(v2, sizeof(v2),
	    &event));
	ATF_CHECK(!blued_encryption_change_is_le_on(&event));

	/* Unknown/out-of-range persisted metadata fails closed to 7, not 16. */
	ATF_CHECK_EQ(BT_CORE63_SMP_MIN_KEY_SIZE,
	    blued_encryption_change_effective_key_size(0));
	ATF_CHECK_EQ(BT_CORE63_SMP_MIN_KEY_SIZE,
	    blued_encryption_change_effective_key_size(
	    BT_CORE63_SMP_MIN_KEY_SIZE - 1));
	ATF_CHECK_EQ(BT_CORE63_SMP_MAX_KEY_SIZE,
	    blued_encryption_change_effective_key_size(
	    BT_CORE63_SMP_MAX_KEY_SIZE));
	ATF_CHECK_EQ(BT_CORE63_SMP_MIN_KEY_SIZE,
	    blued_encryption_change_effective_key_size(
	    BT_CORE63_SMP_MAX_KEY_SIZE + 1));
	v2[6] = BT_CORE63_HCI_ENCRYPTION_BREDR_AES_ON;
	ATF_REQUIRE_EQ(0, blued_parse_encryption_change(v2, sizeof(v2),
	    &event));
	ATF_CHECK(!blued_encryption_change_is_le_on(&event));
	v2[6] = BT_CORE63_HCI_ENCRYPTION_ENABLED_RESERVED_FIRST;
	ATF_REQUIRE_EQ(0, blued_parse_encryption_change(v2, sizeof(v2),
	    &event));
	ATF_CHECK(!blued_encryption_change_is_le_on(&event));

	/* First reserved handle and inconsistent/truncated packet lengths. */
	v2[4] = (BT_CORE63_HCI_ENCRYPTION_HANDLE_MAX + 1) & 0xff;
	v2[5] = (BT_CORE63_HCI_ENCRYPTION_HANDLE_MAX + 1) >> 8;
	ATF_CHECK_EQ(-1, blued_parse_encryption_change(v2, sizeof(v2),
	    &event));
	v2[4] = 0;
	v2[5] = 0;
	ATF_CHECK_EQ(-1, blued_parse_encryption_change(v2, sizeof(v2) - 1,
	    &event));
	v2[2]--;
	ATF_CHECK_EQ(-1, blued_parse_encryption_change(v2, sizeof(v2),
	    &event));
}

/* ================================================================
 * LE Set Advertising Parameters — 0.625ms units, 0x0020..0x4000
 * Core Spec Vol 4 Part E 7.8.5
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adv_params_interval_bounds);
ATF_TC_BODY(adv_params_interval_bounds, tc)
{
	/* interval_min below the 0x0020 floor */
	REJECT(hci_le_set_advertising_params(test_fd(),
	    BT_HE_SPEC_ADV_INTERVAL_MIN - 1, 0x0040,
	    BT_HE_SPEC_ADV_TYPE_CONNECTABLE, 0, 0));
	/* interval_max above the 0x4000 ceiling */
	REJECT(hci_le_set_advertising_params(test_fd(),
	    BT_HE_SPEC_ADV_INTERVAL_MIN, BT_HE_SPEC_ADV_INTERVAL_MAX + 1,
	    BT_HE_SPEC_ADV_TYPE_CONNECTABLE, 0, 0));
	/* min greater than max */
	REJECT(hci_le_set_advertising_params(test_fd(), 0x0100, 0x00FF, 0x00, 0, 0));

	/* Exact valid endpoints for a connectable (ADV_IND) set. */
	ACCEPT(hci_le_set_advertising_params(test_fd(),
	    BT_HE_SPEC_ADV_INTERVAL_MIN, BT_HE_SPEC_ADV_INTERVAL_MIN,
	    BT_HE_SPEC_ADV_TYPE_CONNECTABLE, 0, 0));
	ACCEPT(hci_le_set_advertising_params(test_fd(),
	    BT_HE_SPEC_ADV_INTERVAL_MIN, BT_HE_SPEC_ADV_INTERVAL_MAX,
	    BT_HE_SPEC_ADV_TYPE_CONNECTABLE, 0, 0));
}

ATF_TC_WITHOUT_HEAD(adv_params_nonconn_no_floor);
ATF_TC_BODY(adv_params_nonconn_no_floor, tc)
{
	/*
	 * Core Spec Vol 4 Part E §7.8.5 defines NO advertising-type dependent
	 * interval floor: non-connectable (0x03) and scannable (0x02) undirected
	 * advertising accept the full 0x0020-0x4000 range, exactly like
	 * connectable advertising.  (The old 0x00A0/100 ms minimum was a BT-4.0
	 * GAP recommendation, not an HCI constraint, and must not be enforced
	 * here.)  Only sub-0x0020 is rejected.
	 */
	ACCEPT(hci_le_set_advertising_params(test_fd(),
	    BT_HE_SPEC_ADV_INTERVAL_MIN, BT_HE_SPEC_ADV_INTERVAL_MIN,
	    BT_HE_SPEC_ADV_TYPE_NONCONNECTABLE, 0, 0));
	ACCEPT(hci_le_set_advertising_params(test_fd(),
	    BT_HE_SPEC_ADV_INTERVAL_MIN, BT_HE_SPEC_ADV_INTERVAL_MIN,
	    BT_HE_SPEC_ADV_TYPE_SCANNABLE, 0, 0));
	ACCEPT(hci_le_set_advertising_params(test_fd(),
	    BT_HE_SPEC_ADV_INTERVAL_MIN, BT_HE_SPEC_ADV_INTERVAL_MAX,
	    BT_HE_SPEC_ADV_TYPE_NONCONNECTABLE, 0, 0));
	REJECT(hci_le_set_advertising_params(test_fd(),
	    BT_HE_SPEC_ADV_INTERVAL_MIN - 1, 0x0040,
	    BT_HE_SPEC_ADV_TYPE_NONCONNECTABLE, 0, 0));
}

/* ================================================================
 * LE Set Extended Advertising Parameters — 3-byte interval,
 * 0x000020..0xFFFFFF.  Core Spec Vol 4 Part E 7.8.53
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ext_adv_params_interval_bounds);
ATF_TC_BODY(ext_adv_params_interval_bounds, tc)
{
	/* below floor */
	REJECT(hci_le_set_ext_adv_params(test_fd(), 0, 0,
	    BT_HE_SPEC_EXT_ADV_INTERVAL_MIN - 1, 0x000040, 0, 0));
	/* above ceiling */
	REJECT(hci_le_set_ext_adv_params(test_fd(), 0, 0,
	    BT_HE_SPEC_EXT_ADV_INTERVAL_MIN,
	    BT_HE_SPEC_EXT_ADV_INTERVAL_MAX + 1, 0, 0));
	/* min > max */
	REJECT(hci_le_set_ext_adv_params(test_fd(), 0, 0, 0x000100, 0x0000FF, 0, 0));

	/* Endpoints of the valid 3-byte range. */
	ACCEPT(hci_le_set_ext_adv_params(test_fd(), 0, 0,
	    BT_HE_SPEC_EXT_ADV_INTERVAL_MIN, BT_HE_SPEC_EXT_ADV_INTERVAL_MIN,
	    0, 0));
	ACCEPT(hci_le_set_ext_adv_params(test_fd(), 0, 0,
	    BT_HE_SPEC_EXT_ADV_INTERVAL_MIN, BT_HE_SPEC_EXT_ADV_INTERVAL_MAX,
	    0, 0));

	/* Same validation reached through the explicit-PHY wrapper. */
	REJECT(hci_le_set_ext_adv_params_phy(test_fd(), 0, 0,
	    BT_HE_SPEC_EXT_ADV_INTERVAL_MIN - 1, 0x000040,
	    0, 0, 0x01, 0x01));
	ACCEPT(hci_le_set_ext_adv_params_phy(test_fd(), 0, 0,
	    BT_HE_SPEC_EXT_ADV_INTERVAL_MIN, BT_HE_SPEC_EXT_ADV_INTERVAL_MAX,
	    0, 0, 0x03, 0x02));
}

/* ================================================================
 * LE Set Periodic Advertising Parameters — 1.25ms units, >= 0x0006
 * Core Spec Vol 4 Part E 7.8.61
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(periodic_adv_params_interval_bounds);
ATF_TC_BODY(periodic_adv_params_interval_bounds, tc)
{
	/* below the 0x0006 floor */
	REJECT(hci_le_set_periodic_adv_params(test_fd(), 0,
	    BT_HE_SPEC_PERIODIC_INTERVAL_MIN - 1, 0x0010, 0));
	/* max below floor */
	REJECT(hci_le_set_periodic_adv_params(test_fd(), 0,
	    BT_HE_SPEC_PERIODIC_INTERVAL_MIN,
	    BT_HE_SPEC_PERIODIC_INTERVAL_MIN - 1, 0));
	/* min > max */
	REJECT(hci_le_set_periodic_adv_params(test_fd(), 0, 0x0020, 0x0010, 0));

	/* Minimum legal interval and a normal span. */
	ACCEPT(hci_le_set_periodic_adv_params(test_fd(), 0,
	    BT_HE_SPEC_PERIODIC_INTERVAL_MIN,
	    BT_HE_SPEC_PERIODIC_INTERVAL_MIN, 0));
	ACCEPT(hci_le_set_periodic_adv_params(test_fd(), 0,
	    BT_HE_SPEC_PERIODIC_INTERVAL_MIN,
	    BT_HE_SPEC_PERIODIC_INTERVAL_MAX, 0));
}

/* ================================================================
 * LE Connection Update — interval 0x0006..0x0C80 (1.25ms),
 * latency <= 0x01F3, timeout 0x000A..0x0C80 (10ms), and the
 * timeout/latency relationship.  Core Spec Vol 4 Part E 7.8.18
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(conn_update_interval_bounds);
ATF_TC_BODY(conn_update_interval_bounds, tc)
{
	/* interval_min below 0x0006 */
	REJECT(hci_le_connection_update(test_fd(), 0x0040,
	    BT_HE_SPEC_CONN_INTERVAL_MIN - 1, 0x0028, 0, 0x0100));
	/* interval_max above 0x0C80 */
	REJECT(hci_le_connection_update(test_fd(), 0x0040, 0x0018,
	    BT_HE_SPEC_CONN_INTERVAL_MAX + 1, 0, 0x0100));
	/* min > max */
	REJECT(hci_le_connection_update(test_fd(), 0x0040, 0x0028, 0x0018, 0, 0x0100));

	/* A comfortably valid set (timeout*4 > interval_max*(1+latency)). */
	ACCEPT(hci_le_connection_update(test_fd(), 0x0040, 0x0018, 0x0028, 0, 0x0100));
}

ATF_TC_WITHOUT_HEAD(conn_update_latency_timeout_bounds);
ATF_TC_BODY(conn_update_latency_timeout_bounds, tc)
{
	/* latency above 0x01F3 */
	REJECT(hci_le_connection_update(test_fd(), 0x0040, 0x0018, 0x0028,
	    BT_HE_SPEC_CONN_LATENCY_MAX + 1,
	    BT_HE_SPEC_SUPERVISION_TIMEOUT_MAX));
	/* timeout below 0x000A */
	REJECT(hci_le_connection_update(test_fd(), 0x0040, 0x0018, 0x0028,
	    0, BT_HE_SPEC_SUPERVISION_TIMEOUT_MIN - 1));
	/* timeout above 0x0C80 */
	REJECT(hci_le_connection_update(test_fd(), 0x0040, 0x0018, 0x0028,
	    0, BT_HE_SPEC_SUPERVISION_TIMEOUT_MAX + 1));

	/*
	 * Timeout too short for the requested latency/interval:
	 * timeout*4 (40) <= interval_max*(1+latency) (0x0C80 = 3200).
	 * In-range individually, rejected by the relationship rule.
	 */
	REJECT(hci_le_connection_update(test_fd(), 0x0040,
	    BT_HE_SPEC_CONN_INTERVAL_MIN, BT_HE_SPEC_CONN_INTERVAL_MAX, 0,
	    BT_HE_SPEC_SUPERVISION_TIMEOUT_MIN));

	/* Maximum latency with a timeout that still satisfies the rule. */
	ACCEPT(hci_le_connection_update(test_fd(), 0x0040, 0x0018, 0x0018,
	    BT_HE_SPEC_CONN_LATENCY_MAX,
	    BT_HE_SPEC_SUPERVISION_TIMEOUT_MAX));
}

/* ================================================================
 * LE Set Data Length — tx_octets 0x001B..0x00FB, tx_time
 * 0x0148..0x4290.  Core Spec Vol 4 Part E 7.8.33 / 7.8.35
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(data_length_bounds);
ATF_TC_BODY(data_length_bounds, tc)
{
	/* tx_octets below 27 (0x001B) */
	REJECT(hci_le_set_data_length(test_fd(), 0x0040,
	    BT_HE_SPEC_DATA_OCTETS_MIN - 1, BT_HE_SPEC_DATA_TIME_MIN));
	/* tx_octets above 251 (0x00FB) */
	REJECT(hci_le_set_data_length(test_fd(), 0x0040,
	    BT_HE_SPEC_DATA_OCTETS_MAX + 1, BT_HE_SPEC_DATA_TIME_MIN));
	/* tx_time below floor */
	REJECT(hci_le_set_data_length(test_fd(), 0x0040,
	    BT_HE_SPEC_DATA_OCTETS_MIN, BT_HE_SPEC_DATA_TIME_MIN - 1));
	/* tx_time above ceiling */
	REJECT(hci_le_set_data_length(test_fd(), 0x0040,
	    BT_HE_SPEC_DATA_OCTETS_MIN, BT_HE_SPEC_DATA_TIME_MAX + 1));

	/* Both endpoints of the valid rectangle. */
	ACCEPT(hci_le_set_data_length(test_fd(), 0x0040,
	    BT_HE_SPEC_DATA_OCTETS_MIN, BT_HE_SPEC_DATA_TIME_MIN));
	ACCEPT(hci_le_set_data_length(test_fd(), 0x0040,
	    BT_HE_SPEC_DATA_OCTETS_MAX, BT_HE_SPEC_DATA_TIME_MAX));
}

ATF_TC_WITHOUT_HEAD(suggested_default_data_length_bounds);
ATF_TC_BODY(suggested_default_data_length_bounds, tc)
{
	REJECT(hci_le_write_suggested_default_data_length(test_fd(),
	    BT_HE_SPEC_DATA_OCTETS_MIN - 1, BT_HE_SPEC_DATA_TIME_MIN));
	REJECT(hci_le_write_suggested_default_data_length(test_fd(),
	    BT_HE_SPEC_DATA_OCTETS_MAX + 1, BT_HE_SPEC_DATA_TIME_MIN));
	REJECT(hci_le_write_suggested_default_data_length(test_fd(),
	    BT_HE_SPEC_DATA_OCTETS_MIN, BT_HE_SPEC_DATA_TIME_MIN - 1));
	REJECT(hci_le_write_suggested_default_data_length(test_fd(),
	    BT_HE_SPEC_DATA_OCTETS_MIN, BT_HE_SPEC_DATA_TIME_MAX + 1));

	ACCEPT(hci_le_write_suggested_default_data_length(test_fd(),
	    BT_HE_SPEC_DATA_OCTETS_MIN, BT_HE_SPEC_DATA_TIME_MIN));
	ACCEPT(hci_le_write_suggested_default_data_length(test_fd(),
	    BT_HE_SPEC_DATA_OCTETS_MAX, BT_HE_SPEC_DATA_TIME_MAX));
}

/* ================================================================
 * LE Set Resolvable Private Address Timeout — 1..0x0E10 (3600s)
 * Core Spec Vol 4 Part E 7.8.45
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(rpa_timeout_bounds);
ATF_TC_BODY(rpa_timeout_bounds, tc)
{
	/* zero is below the 1-second floor */
	REJECT(hci_le_set_rpa_timeout(test_fd(), BT_HE_SPEC_RPA_TIMEOUT_MIN - 1));
	/* above the 3600-second ceiling */
	REJECT(hci_le_set_rpa_timeout(test_fd(), BT_HE_SPEC_RPA_TIMEOUT_MAX + 1));

	ACCEPT(hci_le_set_rpa_timeout(test_fd(), BT_HE_SPEC_RPA_TIMEOUT_MIN));
	ACCEPT(hci_le_set_rpa_timeout(test_fd(), BT_HE_SPEC_RPA_TIMEOUT_MAX));
}

/* ================================================================
 * Set Minimum Encryption Key Size — 7..16 bytes
 * Core Spec Vol 4 Part E 7.3.102
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(min_enc_key_size_bounds);
ATF_TC_BODY(min_enc_key_size_bounds, tc)
{
	REJECT(hci_set_min_enc_key_size(test_fd(), BT_HE_SPEC_KEY_SIZE_MIN - 1));
	REJECT(hci_set_min_enc_key_size(test_fd(), BT_HE_SPEC_KEY_SIZE_MAX + 1));

	ACCEPT(hci_set_min_enc_key_size(test_fd(), BT_HE_SPEC_KEY_SIZE_MIN));
	ACCEPT(hci_set_min_enc_key_size(test_fd(), BT_HE_SPEC_KEY_SIZE_MAX));
}

/* ================================================================
 * PHY selection / extended create connection PHY-array shape.
 * The parameter array has exactly one 16-byte entry per selected PHY.
 * Core Spec Vol 4 Part E 7.8.66.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ext_create_connection_phy_bounds);
ATF_TC_BODY(ext_create_connection_phy_bounds, tc)
{
	uint8_t peer[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t phybuf[64];

	memset(phybuf, 0, sizeof(phybuf));

	/* Oversized, truncated, and extra records are all malformed. */
	REJECT(hci_le_ext_create_connection(test_fd(), 0, 0, 0, peer,
	    BT_HE_SPEC_PHY_ALL_BITS,
	    phybuf, 1000));
	REJECT(hci_le_ext_create_connection(test_fd(), 0, 0, 0, peer,
	    BT_HE_SPEC_PHY_1M_BIT, phybuf,
	    BT_HE_SPEC_EXT_CONN_PHY_RECORD_LEN - 1));
	REJECT(hci_le_ext_create_connection(test_fd(), 0, 0, 0, peer,
	    BT_HE_SPEC_PHY_1M_BIT, phybuf,
	    BT_HE_SPEC_EXT_CONN_PHY_RECORD_LEN * 2));

	/* A single-PHY (1M) params blob of exactly 16 bytes passes. */
	ACCEPT(hci_le_ext_create_connection(test_fd(), 0, 0, 0, peer,
	    BT_HE_SPEC_PHY_1M_BIT, phybuf,
	    BT_HE_SPEC_EXT_CONN_PHY_RECORD_LEN));
	/*
	 * Initiating_PHYs bits 0, 1, and 2 select 1M, 2M, and Coded,
	 * respectively (Core Vol 4 Part E 7.8.66).  Each selected PHY adds
	 * one 16-octet parameter record.  2M may accompany either PHY that
	 * can scan on the primary advertising channel.
	 */
	ACCEPT(hci_le_ext_create_connection(test_fd(), 0, 0, 0, peer,
	    BT_HE_SPEC_PHY_1M_BIT | BT_HE_SPEC_PHY_2M_BIT, phybuf,
	    BT_HE_SPEC_EXT_CONN_PHY_RECORD_LEN * 2));
	ACCEPT(hci_le_ext_create_connection(test_fd(), 0, 0, 0, peer,
	    BT_HE_SPEC_PHY_2M_BIT | BT_HE_SPEC_PHY_CODED_BIT, phybuf,
	    BT_HE_SPEC_EXT_CONN_PHY_RECORD_LEN * 2));
	ACCEPT(hci_le_ext_create_connection(test_fd(), 0, 0, 0, peer,
	    BT_HE_SPEC_PHY_ALL_BITS, phybuf,
	    BT_HE_SPEC_EXT_CONN_PHY_RECORD_LEN * 3));

	/* Null arrays, RFU PHY bits, and 2M-only selections are rejected. */
	REJECT(hci_le_ext_create_connection(test_fd(), 0, 0, 0, NULL,
	    BT_HE_SPEC_PHY_1M_BIT, phybuf, BT_HE_SPEC_EXT_CONN_PHY_RECORD_LEN));
	REJECT(hci_le_ext_create_connection(test_fd(), 0, 0, 0, peer,
	    BT_HE_SPEC_PHY_1M_BIT, NULL, BT_HE_SPEC_EXT_CONN_PHY_RECORD_LEN));
	REJECT(hci_le_ext_create_connection(test_fd(), 0, 0, 0, peer,
	    BT_HE_SPEC_PHY_FIRST_RFU_BIT,
	    phybuf, 0));
	REJECT(hci_le_ext_create_connection(test_fd(), 0, 0, 0, peer,
	    BT_HE_SPEC_PHY_2M_BIT, phybuf, BT_HE_SPEC_EXT_CONN_PHY_RECORD_LEN));
}

/* ================================================================
 * Create CIS channel-count bounds (1..31).
 * Core Spec Vol 4 Part E 7.8.99
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(create_cis_count_bounds);
ATF_TC_BODY(create_cis_count_bounds, tc)
{
	uint16_t cis[2] = { 0x0060, 0x0061 };
	uint16_t acl[2] = { 0x0040, 0x0041 };

	REJECT(hci_le_create_cis(test_fd(), 0, cis, acl));
	REJECT(hci_le_create_cis(test_fd(), BT_HE_SPEC_CIS_COUNT_MAX + 1,
	    cis, acl));

	ACCEPT(hci_le_create_cis(test_fd(), BT_HE_SPEC_CIS_COUNT_MIN, cis, acl));
}

/* ================================================================
 * Connectionless CTE Tx switching-pattern-length bound (<= 75).
 * Core Spec Vol 4 Part E 7.8.80
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(connless_cte_switching_len_bound);
ATF_TC_BODY(connless_cte_switching_len_bound, tc)
{
	uint8_t antenna[76];

	memset(antenna, 0, sizeof(antenna));

	/* switching_pattern_len > 75 must be rejected before any copy. */
	REJECT(hci_le_set_connless_cte_tx_params(test_fd(), 0, 0x14, 0, 1,
	    BT_HE_SPEC_CTE_SWITCH_PATTERN_MAX + 1,
	    antenna));

	ACCEPT(hci_le_set_connless_cte_tx_params(test_fd(), 0, 0x14, 0, 1, 2,
	    antenna));
}

/* ================================================================
 * ECBFC channel-count bounds (1..5).  Core Spec Vol 3 Part A 4.25
 * (ble_ecbfc_connect rejects out-of-range counts before any socket).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ecbfc_channel_count_bounds);
ATF_TC_BODY(ecbfc_channel_count_bounds, tc)
{
	uint8_t addr[6] = { 0, 0, 0, 0, 0, 0 };
	int fds[8];

	/* count below 1 */
	REJECT(ble_ecbfc_connect(NULL, addr, 0, 0x0027, 512,
	    BT_HE_SPEC_ECBFC_CHANNELS_MIN - 1, fds));
	/* count above 5 */
	REJECT(ble_ecbfc_connect(NULL, addr, 0, 0x0027, 512,
	    BT_HE_SPEC_ECBFC_CHANNELS_MAX + 1, fds));
	/* NULL fds vector */
	REJECT(ble_ecbfc_connect(NULL, addr, 0, 0x0027, 512,
	    BT_HE_SPEC_ECBFC_CHANNELS_MIN, NULL));
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, encryption_change_v1_v2_decode);
	ATF_TP_ADD_TC(tp, adv_params_interval_bounds);
	ATF_TP_ADD_TC(tp, adv_params_nonconn_no_floor);
	ATF_TP_ADD_TC(tp, ext_adv_params_interval_bounds);
	ATF_TP_ADD_TC(tp, periodic_adv_params_interval_bounds);
	ATF_TP_ADD_TC(tp, conn_update_interval_bounds);
	ATF_TP_ADD_TC(tp, conn_update_latency_timeout_bounds);
	ATF_TP_ADD_TC(tp, data_length_bounds);
	ATF_TP_ADD_TC(tp, suggested_default_data_length_bounds);
	ATF_TP_ADD_TC(tp, rpa_timeout_bounds);
	ATF_TP_ADD_TC(tp, min_enc_key_size_bounds);
	ATF_TP_ADD_TC(tp, ext_create_connection_phy_bounds);
	ATF_TP_ADD_TC(tp, create_cis_count_bounds);
	ATF_TP_ADD_TC(tp, connless_cte_switching_len_bound);
	ATF_TP_ADD_TC(tp, ecbfc_channel_count_bounds);

	return (atf_no_error());
}
