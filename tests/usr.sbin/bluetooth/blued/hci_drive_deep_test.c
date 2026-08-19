/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * HCI command-path DRIVE coverage (all seven hci_*.c files).
 *
 * The existing edge/encode suites pin every host-side range check, but leave
 * dozens of command wrappers entirely undriven, so their command-build body
 * and their "bt_devreq() failed" error arm never execute.  Every wrapper here
 * is driven with a real, non-HCI descriptor (open("/dev/null")): the call gets
 * past any range check, assembles the command, hands it to bt_devreq(), which
 * fails at getsockopt(SOL_HCI_RAW) with ENOTSOCK — exercising the command-build
 * path and the devreq-failure return without a controller.
 *
 * What this CANNOT reach (category B, integration-only): the post-I/O
 * "rp.status != 0x00" success/failure arms and the success-path output
 * extraction, both of which require bt_devreq() to return 0 with a controller
 * response.  Those are reported in the ledger, not faked here.
 *
 * Three levers beyond a bare drive:
 *   - a real BTSnoop capture is opened so hci_devreq_logged_locked()'s
 *     outgoing-command log block runs, including its plen>255 clamp;
 *   - blued_verbose is raised so the validation-failure LOG_HCI() branches
 *     (fprintf side) are taken;
 *   - blued_daemonized is raised in one case for the syslog side.
 *
 * This is implementation branch coverage, not a wire-conformance oracle:
 * Core-valid parameter samples reach command construction, but the fake fd
 * prevents observation of the constructed command.  Byte encoding is covered
 * by hci_encode_edge_test and the raw-command emulator suites.  The applicable
 * command references are listed on each group below.
 *
 * Link set: hci_drive_deep_test.c hci_util.c hci_adv.c hci_scan.c hci_conn.c
 * hci_privacy.c hci_misc.c hci_log.c   (+ libbluetooth, libcrypto).
 */

#include <sys/types.h>

#include <netgraph/bluetooth/include/ng_bluetooth.h>	/* BDADDR_LE_* */

#include <atf-c.h>

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "hci_util.h"
#include "hci_internal.h"
#include "hci_log.h"
#include "ble_util.h"

/* Stub globals required by the hci_*.c logging macros (_BLUED_LOG). */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

/* A valid but non-HCI descriptor: bt_devreq() fails past the range check. */
static int
test_fd(void)
{
	static int fd = -1;

	if (fd < 0)
		fd = open("/dev/null", O_RDWR);
	return (fd);
}

/*
 * DRIVE() asserts a wrapper ran to a definite -1 (there is no controller) and
 * that the failure was NOT a host-side EINVAL range rejection — i.e. it got
 * past validation into the command-build / devreq path.
 */
#define DRIVE(call)	do {						\
	int _r;								\
	errno = 0;							\
	_r = (call);							\
	ATF_CHECK_EQ_MSG(_r, -1, "expected -1 (no controller) from " #call);\
	ATF_CHECK_MSG(errno != EINVAL,					\
	    "unexpected EINVAL (range reject) from " #call);		\
} while (0)

/* ================================================================
 * hci_util.c: ioctl-backed lookups, disconnect, adapter open.
 * On /dev/null the ioctls fail (ENOTTY) and bt_devopen fails.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(util_ioctl_and_disconnect);
ATF_TC_BODY(util_ioctl_and_disconnect, tc)
{
	uint8_t bdaddr[6];
	uint8_t remote[6] = { 1, 2, 3, 4, 5, 6 };
	uint16_t handle = 0;

	/* SIOC_HCI_RAW ioctls on a non-HCI fd fail -> -1. */
	ATF_CHECK_EQ(hci_get_bdaddr(test_fd(), bdaddr), -1);
	ATF_CHECK_EQ(hci_get_con_handle(test_fd(), remote, 0x00, &handle), -1); /* H-L3 */
	ATF_CHECK_EQ(hci_node_init(test_fd()), -1);

	/* Disconnect: no range check, drives to the devreq-failure arm. */
	DRIVE(hci_disconnect(test_fd(), 0x0040, 0x13));

	/* Opening a device that does not exist returns -1. */
	ATF_CHECK(hci_open("ubt-nonexistent-xyz") < 0);
}

/* ================================================================
 * hci_misc.c: Core 6.3 Vol 4 Part E §§7.3.1-7.3.2, 7.3.79,
 * 7.3.93-7.3.94, 7.8.1, 7.8.3, 7.8.25-7.8.26, 7.8.96, 7.8.103,
 * and 7.8.116.  All were undriven by the edge suites.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(misc_command_drives);
ATF_TC_BODY(misc_command_drives, tc)
{
	uint8_t ltk[16], bcode[16];
	uint16_t seq, apto;
	uint32_t ts, off;
	uint32_t q0, q1, q2, q3, q4, q5, q6;
	uint64_t feats;

	memset(ltk, 0xAB, sizeof(ltk));
	memset(bcode, 0, sizeof(bcode));

	DRIVE(hci_reset(test_fd()));
	DRIVE(hci_write_le_host_support(test_fd(), 1, 0));
	DRIVE(hci_set_event_mask(test_fd(), 0x3FFFFFFFFFFFFFFFULL));
	DRIVE(hci_le_set_event_mask(test_fd(), 0x000000000000001FULL));
	DRIVE(hci_le_read_local_features(test_fd(), &feats));
	DRIVE(hci_le_ltk_request_reply(test_fd(), 0x0040, ltk));
	DRIVE(hci_le_ltk_request_neg_reply(test_fd(), 0x0040));
	DRIVE(hci_le_read_iso_tx_sync(test_fd(), 0x0040, &seq, &ts, &off));
	DRIVE(hci_le_read_iso_link_quality(test_fd(), 0x0040, &q0, &q1, &q2,
	    &q3, &q4, &q5, &q6));
	DRIVE(hci_le_read_auth_payload_timeout(test_fd(), 0x0040, &apto));
	DRIVE(hci_le_write_auth_payload_timeout(test_fd(), 0x0040, 0x0BB8));

	/* Create BIG: fixed 31-byte command, Command Status wrapper. */
	DRIVE(hci_le_create_big(test_fd(), 0, 0, 2, 10000, 100, 0x0064, 2,
	    0x02, 0, 0, 0, bcode));
}

/* ================================================================
 * hci_conn.c: Core 6.3 Vol 4 Part E §§7.8.9, 7.8.47, 7.8.117-7.8.121,
 * and 7.8.123-7.8.124.  ECBFC reconfiguration is a FreeBSD socket-API path.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(conn_command_drives);
ATF_TC_BODY(conn_command_drives, tc)
{
	uint8_t txphy, rxphy;
	int8_t cur, max;

	DRIVE(hci_le_read_phy(test_fd(), 0x0040, &txphy, &rxphy));
	DRIVE(hci_le_set_default_subrate(test_fd(), 1, 4, 0, 0, 0x0064));
	DRIVE(hci_le_subrate_request(test_fd(), 0x0040, 1, 4, 0, 0, 0x0064));
	DRIVE(hci_le_enhanced_read_tx_power_level(test_fd(), 0x0040, 0x01,
	    &cur, &max));
	DRIVE(hci_le_read_remote_tx_power_level(test_fd(), 0x0040, 0x01));
	DRIVE(hci_le_set_path_loss_reporting_params(test_fd(), 0x0040, 0x40,
	    0x04, 0x1E, 0x04, 0x000A));
	DRIVE(hci_le_set_path_loss_reporting_enable(test_fd(), 0x0040, 1));
	DRIVE(hci_le_set_tx_power_reporting_enable(test_fd(), 0x0040, 1, 1));
	DRIVE(hci_le_set_advertise_enable(test_fd(), true));
	DRIVE(hci_le_set_advertise_enable(test_fd(), false));

	/* ECBFC reconfig setsockopt on /dev/null fails -> -1. */
	DRIVE(ble_ecbfc_reconfig(test_fd(), 512, 512));
}

/* ================================================================
 * hci_conn.c FreeBSD socket-initiation paths: neither needs a controller to
 * fail deterministically (no adapter / connect to a null peer fails).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(conn_socket_paths);
ATF_TC_BODY(conn_socket_paths, tc)
{
	uint8_t local[6] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 };
	uint8_t peer[6] = { 1, 2, 3, 4, 5, 6 };

	/*
	 * l2cap_conn_param_update_req scans ubt0..7 via hci_open (all fail
	 * with no adapter), falls back to ubt0 (fails), returns -1.
	 */
	ATF_CHECK_EQ(l2cap_conn_param_update_req(local, peer, 0x00,
	    0x0018, 0x0028, 0, 0x0100), -1);

	/*
	 * ble_coc_connect: either PF_BLUETOOTH is unavailable (socket fails)
	 * or the connect() to the peer fails; both return -1 with a non-EINVAL
	 * errno after building the sockaddr.
	 */
	ATF_CHECK_EQ(ble_coc_connect(NULL, peer, BDADDR_LE_PUBLIC, 0x0027, 0), -1);
}

/* ================================================================
 * hci_scan.c: Core 6.3 Vol 4 Part E §§7.8.10 and 7.8.64 legacy and
 * extended scan setup paths.  On /dev/null the
 * first Set-Scan-Parameters devreq fails, so the parameter-build and
 * setup path run and the function returns via its early error arm.  The
 * scanning_phys variants exercise the 1M-only, 1M+Coded, and default
 * buffer-build branches.  hci_wait_encryption(timeout 0) covers entry
 * and the ETIMEDOUT exit.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(scan_setup_paths);
ATF_TC_BODY(scan_setup_paths, tc)
{
	struct ble_scan_result results[4];
	int n = 0;

	memset(results, 0, sizeof(results));

	ATF_CHECK_EQ(hci_le_scan(test_fd(), 0, results, 4, &n), -1);

	/* scanning_phys == 0 defaults to 0x01 (1M only). */
	ATF_CHECK_EQ(hci_le_ext_scan(test_fd(), 0, results, 4, &n, 0x00), -1);
	/* 1M PHY branch. */
	ATF_CHECK_EQ(hci_le_ext_scan(test_fd(), 0, results, 4, &n, 0x01), -1);
	/* 1M + Coded PHY branches both taken. */
	ATF_CHECK_EQ(hci_le_ext_scan(test_fd(), 0, results, 4, &n, 0x05), -1);

	/*
	 * timeout 1 lets the receive loop run one iteration: bt_devrecv on a
	 * non-socket fd fails with ENOTSOCK (not EAGAIN/EINTR), so the loop
	 * breaks and the function returns ETIMEDOUT.  Covers the recv-error
	 * branch and the non-retry break without a controller.
	 */
	errno = 0;
	ATF_CHECK_EQ(hci_wait_encryption(test_fd(), 0x0040, 1), -1);
	ATF_CHECK_EQ(errno, ETIMEDOUT);
}

/* ================================================================
 * FreeBSD BTSnoop/logging implementation coverage: with a capture open,
 * hci_devreq_logged_locked
 * runs its outgoing-command log block.  A maximum-size 255-octet Setup ISO
 * Data Path command drives the upper legal packet boundary;
 * hci_send_raw_cmd's own log_packet call is also exercised.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(devreq_logging_block);
ATF_TC_BODY(devreq_logging_block, tc)
{
	char path[64];
	uint8_t codec_id[5] = { 0, 0, 0, 0, 0 };
	uint8_t cfg[242];
	uint8_t raw[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	memset(cfg, 0x11, sizeof(cfg));
	snprintf(path, sizeof(path), "hci_drive_deep.%d.btsnoop", (int)getpid());
	hci_log_open(path);
	ATF_REQUIRE(hci_log_enabled());

	/* Small command: plen <= 255 log path, plen > 0 memcpy. */
	DRIVE(hci_le_set_advertise_enable(test_fd(), true));

	/* 13 fixed parameters + 242-byte configuration = 255 octets. */
	DRIVE(hci_le_setup_iso_data_path(test_fd(), 0x0040, 0x00, 0x00,
	    codec_id, 0, 242, cfg));

	/* hci_send_raw_cmd logs directly via hci_log_packet. */
	DRIVE(hci_send_raw_cmd(test_fd(), 0x2006, raw, sizeof(raw)));

	hci_log_close();
	(void)unlink(path);
}

/* ================================================================
 * Verbose validation-failure logging: Core parameter ranges come from Vol 4
 * Part E §§7.8.18 and 7.8.61; logging and name sanitization are FreeBSD
 * implementation contracts.  With blued_verbose raised, the
 * LOG_HCI() calls on the parameter-rejection arms take their fprintf
 * branch.  Only hci_le_connection_update and hci_le_set_periodic_adv_params
 * log before their EINVAL return.  Also drives the success-path LOG_HCI(2)
 * in hci_parse_ext_adv_report and the DEL (0x7F) control-char sanitiser
 * branch in hci_parse_ad_fields.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(verbose_logging_branches);
ATF_TC_BODY(verbose_logging_branches, tc)
{
	struct ble_scan_result sr;
	uint8_t rep[24];
	const uint8_t ad_del[] = { 0x03, 0x09, 'A', 0x7F };	/* DEL in name */

	blued_verbose = 2;

	/* conn update: three validation-failure LOG_HCI arms. */
	errno = 0;
	ATF_CHECK_EQ(hci_le_connection_update(test_fd(), 0x0040, 0x0005,
	    0x0028, 0, 0x0100), -1);			/* bad interval */
	ATF_CHECK_EQ(errno, EINVAL);
	errno = 0;
	ATF_CHECK_EQ(hci_le_connection_update(test_fd(), 0x0040, 0x0018,
	    0x0028, 0x01F4, 0x0C80), -1);		/* bad latency */
	ATF_CHECK_EQ(errno, EINVAL);
	errno = 0;
	ATF_CHECK_EQ(hci_le_connection_update(test_fd(), 0x0040, 0x0006,
	    0x0C80, 0, 0x000A), -1);			/* timeout too short */
	ATF_CHECK_EQ(errno, EINVAL);

	/* periodic adv params: validation-failure LOG_HCI arm. */
	errno = 0;
	ATF_CHECK_EQ(hci_le_set_periodic_adv_params(test_fd(), 0, 0x0005,
	    0x0010, 0), -1);
	ATF_CHECK_EQ(errno, EINVAL);

	/* Extended report parse success -> LOG_HCI(2) trace branch. */
	memset(rep, 0, sizeof(rep));
	rep[9] = 0x01;
	rep[23] = 0;					/* no AD data */
	memset(&sr, 0, sizeof(sr));
	ATF_CHECK_EQ(hci_parse_ext_adv_report(rep, sizeof(rep), &sr), 24);

	/* DEL (0x7F) in a name must be sanitised to '?' (c == 0x7F branch). */
	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = 0xFFFF;
	hci_parse_ad_fields(ad_del, sizeof(ad_del), &sr);
	ATF_CHECK(sr.has_name);
	ATF_CHECK_STREQ(sr.name, "A?");
}

/* ================================================================
 * Daemonized logging branch: with blued_daemonized set the LOG_HCI()
 * validation-failure arm takes its syslog() side instead of fprintf.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(daemonized_logging_branch);
ATF_TC_BODY(daemonized_logging_branch, tc)
{

	blued_verbose = 2;
	blued_daemonized = 1;

	errno = 0;
	ATF_CHECK_EQ(hci_le_connection_update(test_fd(), 0x0040, 0x0005,
	    0x0028, 0, 0x0100), -1);
	ATF_CHECK_EQ(errno, EINVAL);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, util_ioctl_and_disconnect);
	ATF_TP_ADD_TC(tp, misc_command_drives);
	ATF_TP_ADD_TC(tp, conn_command_drives);
	ATF_TP_ADD_TC(tp, conn_socket_paths);
	ATF_TP_ADD_TC(tp, scan_setup_paths);
	ATF_TP_ADD_TC(tp, devreq_logging_block);
	ATF_TP_ADD_TC(tp, verbose_logging_branches);
	ATF_TP_ADD_TC(tp, daemonized_logging_branch);

	return (atf_no_error());
}
