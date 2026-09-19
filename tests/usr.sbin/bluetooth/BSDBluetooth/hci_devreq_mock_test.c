/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * HCI command success/failure path coverage via a linker --wrap seam.
 *
 * The HCI command encoders in hci_{adv,conn,privacy,misc}.c reach the
 * controller through hci_devreq_logged() -> hci_devreq_logged_locked()
 * (hci_util.c) -> bt_devreq() (libbluetooth).  A plain socketpair cannot
 * exercise the post-I/O arms of these encoders because bt_devreq() bails
 * out at bt_devfilter()->getsockopt(SOL_HCI_RAW) on a non-HCI fd.
 *
 * Those arms — the "controller returned status != 0x00" rejection and the
 * "return 0" success tail (plus the return-parameter extraction the READ
 * commands perform) — are live, spec-relevant code: the normal completion
 * path of every command.  Here we interpose bt_devreq at link time
 * (-Wl,--wrap=bt_devreq) with a test-controlled controller response so the
 * encoder runs its validation, then reaches:
 *
 *     if (hci_devreq_logged(fd, &r, to) < 0)   return (-1);  // transport
 *     if (rp.status != 0x00) { errno = EIO;    return (-1); } // rejection
 *     ... extract rp.<field> ...
 *     return (0);                                             // success
 *
 * Every expected return-parameter layout below is hand-encoded from the
 * Bluetooth Core Specification Vol 4 Part E §7 (cited per command); the
 * assertions check the encoder's extraction against the spec byte layout,
 * never against captured implementation output.
 *
 * struct bt_devreq (verified in /usr/src/lib/libbluetooth/bluetooth.h):
 *     uint16_t opcode; uint8_t event; void *cparam; size_t clen;
 *     void *rparam; size_t rlen;
 * Real bt_devreq fills rparam with up to rlen bytes of the Command Complete
 * return parameters (status byte first) and returns 0; on error it returns
 * -1 with errno set.  __wrap_bt_devreq reproduces exactly that contract.
 */

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include "hci_util.h"
#include "hci_internal.h"
#include "ble_util.h"
#include "spec_extref_hci_le_event_mask.h"
#include "spec_extref_hci_status_codes.h"

/* Stub globals required by the hci_*.c logging macros. */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

/* Any non-negative fd works: __wrap_bt_devreq ignores it and BTSnoop
 * logging is inactive, so no real socket operation is performed. */
#define FD	3

/* ================================================================
 * The --wrap seam: a test-controlled stand-in for bt_devreq().
 * ================================================================ */
static struct {
	int		fail;		/* nonzero -> return -1, errno=fail_errno */
	int		fail_errno;
	int		call_count;
	int		fail_at;	/* one-shot transport failure at this call */
	uint8_t		payload[320];	/* return params, status byte first */
	size_t		payload_len;
	size_t		last_clen;	/* captured command-parameter length */
	uint16_t	last_opcode;	/* captured request opcode */
	uint8_t		last_cparam[64];/* captured command parameters */
	/*
	 * Real bt_devreq() shrinks r->rlen to the number of return-parameter
	 * octets the controller actually supplied.  Reproducing that
	 * unconditionally would change what every existing case here means, so
	 * it is opt-in: the cases that exercise the SHORT-REPLY arms set it.
	 */
	bool		shrink_rlen;
	/*
	 * Per-call capture of the command header so multi-command encoders
	 * (the §7.8.54 ext-adv-data fragment sequence) can be checked call
	 * by call: opcode, clen, the 4 fixed cparam octets (handle,
	 * operation, fragment-preference, data-length) and the first
	 * advertising-data octet.
	 */
#define W_SEQ_MAX	8
	struct {
		uint16_t	opcode;
		size_t		clen;
		uint8_t		hdr[4];
		uint8_t		first_octet;
	} seq[W_SEQ_MAX];
} W;

int __wrap_bt_devreq(int s, struct bt_devreq *r, time_t to);

int
__wrap_bt_devreq(int s, struct bt_devreq *r, time_t to)
{
	(void)s;
	(void)to;

	/* Capture the on-wire command framing for length assertions. */
	W.last_clen = r->clen;
	W.last_opcode = r->opcode;
	memset(W.last_cparam, 0, sizeof(W.last_cparam));
	if (r->cparam != NULL && r->clen > 0)
		memcpy(W.last_cparam, r->cparam,
		    r->clen < sizeof(W.last_cparam) ? r->clen :
		    sizeof(W.last_cparam));

	if (W.call_count < W_SEQ_MAX) {
		const uint8_t *cp = r->cparam;

		W.seq[W.call_count].opcode = r->opcode;
		W.seq[W.call_count].clen = r->clen;
		memset(W.seq[W.call_count].hdr, 0,
		    sizeof(W.seq[W.call_count].hdr));
		W.seq[W.call_count].first_octet = 0;
		if (cp != NULL && r->clen >= 4)
			memcpy(W.seq[W.call_count].hdr, cp, 4);
		if (cp != NULL && r->clen >= 5)
			W.seq[W.call_count].first_octet = cp[4];
	}

	W.call_count++;
	if (W.fail || (W.fail_at != 0 && W.call_count == W.fail_at)) {
		errno = W.fail_errno;
		return (-1);
	}
	/* Mirror bt_devreq's Command Complete contract: copy up to rlen
	 * bytes of return parameters into the caller-supplied rp buffer. */
	if (r->rparam != NULL && r->rlen > 0) {
		size_t n = W.payload_len < r->rlen ? W.payload_len : r->rlen;

		memset(r->rparam, 0, r->rlen);
		if (n > 0)
			memcpy(r->rparam, W.payload, n);
		if (W.shrink_rlen)
			r->rlen = n;
	}
	return (0);
}

/* Controller returns a Command Complete carrying return-parameter bytes. */
static void
mock_ok_bytes(const void *p, size_t n)
{
	W.fail = 0;
	W.call_count = 0;
	W.fail_at = 0;
	W.shrink_rlen = false;
	if (n > sizeof(W.payload))
		n = sizeof(W.payload);
	memcpy(W.payload, p, n);
	W.payload_len = n;
}

/* Controller accepts: status 0x00, no further return parameters. */
static void
mock_ok(void)
{
	uint8_t st = 0x00;

	mock_ok_bytes(&st, 1);
}

/*
 * Controller answers a Command Complete carrying ZERO return-parameter
 * octets, shrinking rlen the way libbluetooth's bt_devreq() does.  No
 * conformant controller does this -- Vol 4 Part E requires a Status octet --
 * but before the shared guard in hci_devreq_logged_locked() the pre-zeroed
 * buffer made it read as status 0x00, i.e. SUCCESS, in all 77 status-only
 * wrappers.
 */
static void
mock_ok_empty(void)
{
	W.fail = 0;
	W.call_count = 0;
	W.fail_at = 0;
	W.payload_len = 0;
	W.shrink_rlen = true;
}

/* Controller answers with a specific status octet and nothing else. */
static void
mock_status(uint8_t status)
{

	mock_ok_bytes(&status, 1);
}

/* Controller rejects with status 0x0C = Command Disallowed
 * (Core Spec Vol 1 Part F §1.3 error code table). */
static void
mock_status_bad(void)
{
	uint8_t st = 0x0C;

	mock_ok_bytes(&st, 1);
}

/* Transport failure: bt_devreq itself fails (e.g. recv error). */
static void
mock_xport_fail(int e)
{
	W.fail = 1;
	W.fail_errno = e;
	W.call_count = 0;
	W.fail_at = 0;
}

static void
mock_xport_fail_at(int ordinal, int e)
{

	mock_ok();
	W.fail_at = ordinal;
	W.fail_errno = e;
}

/*
 * Three-arm coverage for a status-only (ng_hci_status_rp) command.
 * The call expression is side-effect-idempotent (all I/O is mocked).
 */
#define CHECK_OK(call)		do {					\
	mock_ok();							\
	ATF_CHECK_EQ_MSG(0, (call), "success arm: expected 0");		\
} while (0)

#define CHECK_BAD(call)		do {					\
	mock_status_bad();						\
	errno = 0;							\
	ATF_CHECK_EQ_MSG(-1, (call), "status!=0 arm: expected -1");	\
	ATF_CHECK_EQ_MSG(EIO, errno, "status!=0 arm: expected EIO");	\
} while (0)

#define CHECK_XPORT(call)	do {					\
	mock_xport_fail(EIO);						\
	errno = 0;							\
	ATF_CHECK_EQ_MSG(-1, (call), "transport arm: expected -1");	\
	ATF_CHECK_EQ_MSG(EIO, errno, "transport arm: expected EIO");	\
} while (0)

#define CHECK_ALL(call)		do {					\
	CHECK_OK(call);							\
	CHECK_BAD(call);						\
	CHECK_XPORT(call);						\
} while (0)

/* ================================================================
 * hci_util.c — Read_BD_ADDR (Core Spec Vol 4 Part E §7.4.6)
 * RP: Status(1) | BD_ADDR(6)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_bd_addr);
ATF_TC_BODY(read_bd_addr, tc)
{
	uint8_t rp[7] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
	uint8_t bd[6];

	mock_ok_bytes(rp, sizeof(rp));
	memset(bd, 0, sizeof(bd));
	ATF_CHECK_EQ(0, hci_get_bdaddr(FD, bd));
	/* bdaddr_t is little-endian on the wire; the encoder copies the 6
	 * octets verbatim (Core Spec Vol 4 Part E §7.4.6). */
	ATF_CHECK_EQ(0x11, bd[0]);
	ATF_CHECK_EQ(0x66, bd[5]);

	/* Read_BD_ADDR reports failure as EIO (hci_util.c). */
	mock_status_bad();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_get_bdaddr(FD, bd));
	ATF_CHECK_EQ(EIO, errno);

	mock_xport_fail(EIO);
	ATF_CHECK_EQ(-1, hci_get_bdaddr(FD, bd));
}

/* ================================================================
 * hci_adv.c — legacy advertising
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adv_legacy);
ATF_TC_BODY(adv_legacy, tc)
{
	uint8_t data[8] = { 0x02, 0x01, 0x06 };

	/* §7.8.5 interval range 0x0020-0x4000, Min<=Max. */
	CHECK_ALL(hci_le_set_advertising_params(FD, 0x0020, 0x0040,
	    0x00, 0x00, 0x00));
	CHECK_ALL(hci_le_set_advertising_data(FD, data, 3));
	CHECK_ALL(hci_le_set_scan_response_data(FD, data, 3));
	CHECK_ALL(hci_le_set_advertise_enable(FD, true));
	CHECK_ALL(hci_le_set_advertise_enable(FD, false));
}

/* ================================================================
 * hci_adv.c — extended advertising (BT 5.0)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adv_extended);
ATF_TC_BODY(adv_extended, tc)
{
	uint8_t data[8] = { 0x02, 0x01, 0x06 };
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };

	/* §7.8.53 primary interval range 0x000020-0xFFFFFF. */
	CHECK_ALL(hci_le_set_ext_adv_params_phy(FD, 0, 0x0013,
	    0x000020, 0x000040, 0x00, 0x00, 0x01, 0x01));
	CHECK_ALL(hci_le_set_ext_adv_params(FD, 0, 0x0013,
	    0x000020, 0x000040, 0x00, 0x00));
	CHECK_ALL(hci_le_set_ext_adv_data(FD, 0, data, 3));
	CHECK_ALL(hci_le_set_ext_adv_enable(FD, 1, 0));
	CHECK_ALL(hci_le_remove_adv_set(FD, 0));
	CHECK_ALL(hci_le_set_adv_set_random_address(FD, 0, addr));
	CHECK_ALL(hci_le_set_ext_scan_response_data(FD, 0, data, 3));
	CHECK_ALL(hci_le_clear_adv_sets(FD));
}

/*
 * The LE Set Extended Advertising Data / Scan Response Data commands are sent
 * with a command-parameter length of exactly (4 fixed octets + data length),
 * NOT the full 251-octet struct (Core Spec Vol 4 Part E §7.8.54/§7.8.55: the
 * fixed header is Advertising_Handle, Operation, Fragment_Preference and
 * Advertising_Data_Length).  A wrong header size truncates or over-sends the
 * advertising data on the wire.  (Kills a `4 + len` -> `3 + len`/`sizeof(cp)`
 * clen encoding bug.)
 */
ATF_TC_WITHOUT_HEAD(ext_adv_data_clen);
ATF_TC_BODY(ext_adv_data_clen, tc)
{
	uint8_t data[8] = { 0x02, 0x01, 0x06, 0x04, 0x05 };

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_ext_adv_data(FD, 0, data, 5));
	ATF_CHECK_EQ_MSG(4 + 5, W.last_clen,
	    "Set Ext Adv Data clen must be 4 + data_len, got %zu", W.last_clen);

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_ext_adv_data(FD, 0, data, 0));
	ATF_CHECK_EQ_MSG(4 + 0, W.last_clen,
	    "Set Ext Adv Data (0 bytes) clen must be 4, got %zu", W.last_clen);

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_ext_scan_response_data(FD, 0, data, 5));
	ATF_CHECK_EQ_MSG(4 + 5, W.last_clen,
	    "Set Ext Scan Rsp Data clen must be 4 + data_len, got %zu",
	    W.last_clen);
}

/*
 * Finding H-M6: advertising data longer than one command fragment (251,
 * §7.8.54 Advertising_Data_Length) must be delivered as an ORDERED fragment
 * sequence — Operation 0x01 (first), 0x00 (intermediate), 0x02 (last) — on
 * the same opcode, each fragment carrying at most 251 octets, up to the
 * §7.8.57 Max_Advertising_Data_Length spec ceiling of 1650 total.  A total
 * of 251 or less stays a single Operation 0x03 (complete data) command.
 * The wrap seam records every call's fixed header, so the op codes, the
 * per-fragment lengths, the clen framing and the data offsets are all
 * pinned against the spec sequence.
 */
ATF_TC_WITHOUT_HEAD(ext_adv_data_fragmentation);
ATF_TC_BODY(ext_adv_data_fragmentation, tc)
{
	uint8_t data[1651];
	uint16_t off;
	int i;

	for (i = 0; i < (int)sizeof(data); i++)
		data[i] = (uint8_t)i;

	/* <= 251 total: exactly one command, Operation 0x03 (complete). */
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_ext_adv_data(FD, 0, data, 251));
	ATF_CHECK_EQ(1, W.call_count);
	ATF_CHECK_EQ(0x03, W.seq[0].hdr[1]);
	ATF_CHECK_EQ(251, W.seq[0].hdr[3]);
	ATF_CHECK_EQ(4 + 251, W.seq[0].clen);

	/* 252 = first fragmented length: 0x01 (251 octets) + 0x02 (1). */
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_ext_adv_data(FD, 0, data, 252));
	ATF_CHECK_EQ(2, W.call_count);
	ATF_CHECK_EQ(0x01, W.seq[0].hdr[1]);
	ATF_CHECK_EQ(251, W.seq[0].hdr[3]);
	ATF_CHECK_EQ(4 + 251, W.seq[0].clen);
	ATF_CHECK_EQ(data[0], W.seq[0].first_octet);
	ATF_CHECK_EQ(0x02, W.seq[1].hdr[1]);
	ATF_CHECK_EQ(1, W.seq[1].hdr[3]);
	ATF_CHECK_EQ(4 + 1, W.seq[1].clen);
	ATF_CHECK_EQ(data[251], W.seq[1].first_octet);
	ATF_CHECK_EQ(W.seq[0].opcode, W.seq[1].opcode);

	/*
	 * 1650 (spec maximum): 7 fragments — 0x01, five 0x00, 0x02; six of
	 * 251 octets and a final 144 (6 * 251 + 144 = 1650), each fragment
	 * starting at the right offset into the source data.
	 */
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_ext_adv_data(FD, 0, data, 1650));
	ATF_CHECK_EQ(7, W.call_count);
	off = 0;
	for (i = 0; i < 7; i++) {
		uint8_t want_op = (i == 0) ? 0x01 : (i == 6) ? 0x02 : 0x00;
		uint8_t want_len = (i == 6) ? 144 : 251;

		ATF_CHECK_EQ_MSG(want_op, W.seq[i].hdr[1],
		    "fragment %d: operation 0x%02x, want 0x%02x",
		    i, W.seq[i].hdr[1], want_op);
		ATF_CHECK_EQ_MSG(want_len, W.seq[i].hdr[3],
		    "fragment %d: data length %u, want %u",
		    i, W.seq[i].hdr[3], want_len);
		ATF_CHECK_EQ((size_t)(4 + want_len), W.seq[i].clen);
		ATF_CHECK_EQ(0, W.seq[i].hdr[0]);	/* adv handle */
		ATF_CHECK_EQ(data[off], W.seq[i].first_octet);
		ATF_CHECK_EQ(W.seq[0].opcode, W.seq[i].opcode);
		off += want_len;
	}
	ATF_CHECK_EQ(1650, off);

	/* 1651 exceeds the §7.8.57 ceiling: EINVAL before any I/O. */
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_ext_adv_data(FD, 0, data, 1651));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.call_count);

	/* Transport failure on the 2nd fragment aborts the sequence. */
	mock_xport_fail_at(2, EIO);
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_ext_adv_data(FD, 0, data, 1650));
	ATF_CHECK_EQ(EIO, errno);
	ATF_CHECK_EQ(2, W.call_count);

	/* Controller status != 0 on a fragment aborts with EIO. */
	mock_status_bad();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_ext_adv_data(FD, 0, data, 252));
	ATF_CHECK_EQ(EIO, errno);
	ATF_CHECK_EQ(1, W.call_count);
}

/* ================================================================
 * hci_adv.c — LE Read Maximum Advertising Data Length (§7.8.57)
 * RP: Status(1) | Max_Advertising_Data_Length(2 LE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_max_adv_data_length);
ATF_TC_BODY(read_max_adv_data_length, tc)
{
	uint8_t rp[3] = { 0x00, 0x00, 0x04 };	/* 0x0400 = 1024 */
	uint16_t max_len = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_max_adv_data_length(FD, &max_len));
	ATF_CHECK_EQ(0x0400, max_len);

	CHECK_BAD(hci_le_read_max_adv_data_length(FD, &max_len));
	CHECK_XPORT(hci_le_read_max_adv_data_length(FD, &max_len));

	/*
	 * NULL out-parameter must be rejected before the value is written
	 * (defensive API contract, matching the sibling read encoders).
	 * Without the guard the function dereferences NULL after the
	 * command completes -> latent crash.
	 */
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_read_max_adv_data_length(FD, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
}

/* ================================================================
 * hci_adv.c — LE Read Number of Supported Advertising Sets (§7.8.58)
 * RP: Status(1) | Num_Supported_Advertising_Sets(1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_num_supported_adv_sets);
ATF_TC_BODY(read_num_supported_adv_sets, tc)
{
	uint8_t rp[2] = { 0x00, 0x3F };		/* 63 sets */
	uint8_t nsets = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_num_supported_adv_sets(FD, &nsets));
	ATF_CHECK_EQ(0x3F, nsets);

	CHECK_BAD(hci_le_read_num_supported_adv_sets(FD, &nsets));
	CHECK_XPORT(hci_le_read_num_supported_adv_sets(FD, &nsets));

	/* NULL out-parameter must be rejected (see read_max_adv_data_length). */
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_read_num_supported_adv_sets(FD, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
}

/* ================================================================
 * hci_adv.c — periodic advertising (BT 5.0)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adv_periodic);
ATF_TC_BODY(adv_periodic, tc)
{
	uint8_t data[8] = { 0x02, 0x01, 0x06 };
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };

	/* §7.8.61 interval range 0x0006-0xFFFF, Min<=Max. */
	CHECK_ALL(hci_le_set_periodic_adv_params(FD, 0, 0x0006, 0x0006, 0));
	CHECK_ALL(hci_le_set_periodic_adv_data(FD, 0, data, 3));
	CHECK_ALL(hci_le_set_periodic_adv_enable(FD, 1, 0));
	CHECK_ALL(hci_le_periodic_adv_create_sync(FD, 0, 0, 0, addr, 0, 0x000A));
	CHECK_ALL(hci_le_periodic_adv_create_sync_cancel(FD));
	CHECK_ALL(hci_le_periodic_adv_terminate_sync(FD, 0x0001));
	CHECK_ALL(hci_le_add_dev_to_periodic_adv_list(FD, 0, addr, 0));
	CHECK_ALL(hci_le_remove_dev_from_periodic_adv_list(FD, 0, addr, 0));
	CHECK_ALL(hci_le_clear_periodic_adv_list(FD));
}

/* ================================================================
 * hci_adv.c — LE Read Periodic Advertiser List Size (§7.8.73)
 * RP: Status(1) | Periodic_Advertiser_List_Size(1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_periodic_adv_list_size);
ATF_TC_BODY(read_periodic_adv_list_size, tc)
{
	uint8_t rp[2] = { 0x00, 0x08 };
	uint8_t size = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_periodic_adv_list_size(FD, &size));
	ATF_CHECK_EQ(0x08, size);

	CHECK_BAD(hci_le_read_periodic_adv_list_size(FD, &size));
	CHECK_XPORT(hci_le_read_periodic_adv_list_size(FD, &size));
}

/* ================================================================
 * hci_adv.c — PAST (BT 5.1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adv_past);
ATF_TC_BODY(adv_past, tc)
{

	CHECK_ALL(hci_le_set_periodic_adv_receive_enable(FD, 0x0001, 1));
	CHECK_ALL(hci_le_periodic_adv_sync_transfer(FD, 0x0001, 0x1234, 0x0001));
	CHECK_ALL(hci_le_periodic_adv_set_info_transfer(FD, 0x0001, 0x1234, 0));
	CHECK_ALL(hci_le_set_past_params(FD, 0x0001, 0, 0, 0x000A, 0));
	CHECK_ALL(hci_le_set_default_past_params(FD, 0, 0, 0x000A, 0));
}

/* ================================================================
 * hci_adv.c — Direction Finding / CTE (BT 5.1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adv_cte);
ATF_TC_BODY(adv_cte, tc)
{
	uint8_t ant[2] = { 0, 1 };

	CHECK_ALL(hci_le_set_connless_cte_tx_params(FD, 0, 0x14, 0, 1, 2, ant));
	CHECK_ALL(hci_le_set_connless_cte_tx_enable(FD, 0, 1));
	CHECK_ALL(hci_le_set_connless_iq_sampling_enable(FD, 0x0001, 1, 1,
	    0, 2, ant));
	CHECK_ALL(hci_le_set_conn_cte_rx_params(FD, 0x0001, 1, 1, 2, ant));
	CHECK_ALL(hci_le_set_conn_cte_tx_params(FD, 0x0001, 0x01, 2, ant));
	CHECK_ALL(hci_le_conn_cte_req_enable(FD, 0x0001, 1, 0x000A, 0x14, 0));
	CHECK_ALL(hci_le_conn_cte_rsp_enable(FD, 0x0001, 1));
}

/* ================================================================
 * hci_adv.c — LE Read Antenna Information (§7.8.87)
 * RP: Status(1) | Supported_Switching_Sampling_Rates(1) |
 *     Num_Antennae(1) | Max_Switching_Pattern_Length(1) | Max_CTE_Length(1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_antenna_info);
ATF_TC_BODY(read_antenna_info, tc)
{
	uint8_t rp[5] = { 0x00, 0x03, 0x02, 0x4B, 0x14 };
	uint8_t rates = 0, nant = 0, maxpat = 0, maxcte = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_antenna_info(FD, &rates, &nant,
	    &maxpat, &maxcte));
	ATF_CHECK_EQ(0x03, rates);
	ATF_CHECK_EQ(0x02, nant);
	ATF_CHECK_EQ(0x4B, maxpat);	/* 75 */
	ATF_CHECK_EQ(0x14, maxcte);	/* 20 */

	CHECK_BAD(hci_le_read_antenna_info(FD, &rates, &nant, &maxpat, &maxcte));
	CHECK_XPORT(hci_le_read_antenna_info(FD, &rates, &nant, &maxpat,
	    &maxcte));
}

/* ================================================================
 * hci_conn.c — connection parameter / data length / host feature
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(conn_params);
ATF_TC_BODY(conn_params, tc)
{

	/*
	 * §7.8.18 conn update: interval 0x0006-0x0C80, latency <= 0x01F3,
	 * timeout 0x000A-0x0C80, and timeout*4 > interval_max*(1+latency).
	 * 0x000A*4 = 40 > 0x0006*1 = 6.
	 */
	CHECK_ALL(hci_le_connection_update(FD, 0x0040, 0x0006, 0x0006,
	    0, 0x000A));
	/* §7.8.33 tx_octets 0x001B-0x00FB, tx_time 0x0148-0x4290. */
	CHECK_ALL(hci_le_set_data_length(FD, 0x0040, 0x001B, 0x0148));
	CHECK_ALL(hci_le_write_suggested_default_data_length(FD, 0x001B,
	    0x0148));
	CHECK_ALL(hci_le_set_host_feature(FD, 32, 1));
	/*
	 * §7.8.13: Command Disallowed (0x0C, the CHECK_BAD status) means no
	 * create-connection was outstanding — the desired end state — and is
	 * deliberately treated as SUCCESS by hci_le_create_connection_cancel
	 * (a Connection Complete racing ahead of the cancel is benign).  So
	 * exercise the arms individually: 0x0C succeeds, a real controller
	 * error fails.
	 */
	CHECK_OK(hci_le_create_connection_cancel(FD));
	mock_status_bad();			/* 0x0C: benign, succeeds */
	ATF_CHECK_EQ(0, hci_le_create_connection_cancel(FD));
	{
		uint8_t st = 0x1F;		/* Unspecified Error */

		mock_ok_bytes(&st, 1);
		errno = 0;
		ATF_CHECK_EQ(-1, hci_le_create_connection_cancel(FD));
		ATF_CHECK_EQ(EIO, errno);
	}
	CHECK_XPORT(hci_le_create_connection_cancel(FD));
}

/* ================================================================
 * hci_conn.c — PHY
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(conn_phy);
ATF_TC_BODY(conn_phy, tc)
{

	CHECK_ALL(hci_le_set_default_phy(FD, 0x00, 0x07, 0x07));
	CHECK_ALL(hci_le_set_phy(FD, 0x0040, 0x00, 0x07, 0x07, 0x0000));
}

/* ================================================================
 * hci_conn.c — LE Read PHY (§7.8.47)
 * RP: Status(1) | Connection_Handle(2 LE) | TX_PHY(1) | RX_PHY(1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_phy);
ATF_TC_BODY(read_phy, tc)
{
	uint8_t rp[5] = { 0x00, 0x40, 0x00, 0x02, 0x01 };  /* tx=2M rx=1M */
	uint8_t tx = 0, rx = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_phy(FD, 0x0040, &tx, &rx));
	ATF_CHECK_EQ(0x02, tx);
	ATF_CHECK_EQ(0x01, rx);

	CHECK_BAD(hci_le_read_phy(FD, 0x0040, &tx, &rx));
	CHECK_XPORT(hci_le_read_phy(FD, 0x0040, &tx, &rx));
}

/* ================================================================
 * hci_conn.c — subrating (BT 5.3) & power control (BT 5.2)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(conn_subrate_power);
ATF_TC_BODY(conn_subrate_power, tc)
{

	CHECK_ALL(hci_le_set_default_subrate(FD, 1, 4, 0, 0, 0x000A));
	CHECK_ALL(hci_le_subrate_request(FD, 0x0040, 1, 4, 0, 0, 0x000A));
	CHECK_ALL(hci_le_read_remote_tx_power_level(FD, 0x0040, 0x01));
	CHECK_ALL(hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0x40, 0x04, 0x10, 0x04, 0x000A));
	CHECK_ALL(hci_le_set_path_loss_reporting_enable(FD, 0x0040, 1));
	CHECK_ALL(hci_le_set_tx_power_reporting_enable(FD, 0x0040, 1, 1));
}

/* ================================================================
 * hci_conn.c — LE Enhanced Read Transmit Power Level (§7.8.117)
 * RP: Status(1) | Connection_Handle(2) | PHY(1) |
 *     Current_TX_Power_Level(int8) | Max_TX_Power_Level(int8)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(enh_read_tx_power);
ATF_TC_BODY(enh_read_tx_power, tc)
{
	/* current = -20 dBm (0xEC), max = +10 dBm (0x0A) */
	uint8_t rp[6] = { 0x00, 0x40, 0x00, 0x01, 0xEC, 0x0A };
	int8_t cur = 0, max = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_enhanced_read_tx_power_level(FD, 0x0040,
	    0x01, &cur, &max));
	ATF_CHECK_EQ(-20, cur);
	ATF_CHECK_EQ(10, max);

	CHECK_BAD(hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x01,
	    &cur, &max));
	CHECK_XPORT(hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x01,
	    &cur, &max));
}

/* ================================================================
 * hci_conn.c — LE Extended Create Connection (§7.8.66)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ext_create_connection);
ATF_TC_BODY(ext_create_connection, tc)
{
	uint8_t peer[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t phy_params[16];		/* one PHY block, LE-encoded */

	memset(phy_params, 0, sizeof(phy_params));
	/* phys = 0x01 (1M) -> exactly one phy_params block. */
	CHECK_ALL(hci_le_ext_create_connection(FD, 0x00, 0x00, 0x00, peer,
	    0x01, phy_params, sizeof(phy_params)));
}

/* ================================================================
 * hci_privacy.c — resolving list, privacy, filter accept list
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(privacy);
ATF_TC_BODY(privacy, tc)
{
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t irk[16];

	memset(irk, 0xA5, sizeof(irk));
	/* Exercise the enabled side of the production HCI logging guard too.
	 * The command/result assertions below remain independent of logging. */
	atomic_store(&blued_verbose, 2);
	CHECK_ALL(hci_le_clear_resolving_list(FD));
	CHECK_ALL(hci_le_add_dev_resolving_list(FD, 0, addr, irk, irk));
	/* Core Spec Vol 4 Part E §7.8.39: removal uses the same three
	 * controller-result arms as the other resolving-list operations. */
	CHECK_ALL(hci_le_remove_dev_resolving_list(FD, 0, addr));
	CHECK_ALL(hci_le_set_addr_resolution_enable(FD, 1));
	CHECK_ALL(hci_le_set_privacy_mode(FD, 0, addr, 0));
	/* §7.8.45 RPA timeout range 1-0x0E10 s. */
	CHECK_ALL(hci_le_set_rpa_timeout(FD, 900));
	CHECK_ALL(hci_le_clear_filter_accept_list(FD));
	CHECK_ALL(hci_le_add_device_to_filter_accept_list(FD, 0, addr));
	CHECK_ALL(hci_le_remove_device_from_filter_accept_list(FD, 0, addr));

	/* Repeat the exact controller matrix with diagnostic output disabled. */
	atomic_store(&blued_verbose, 0);
	CHECK_ALL(hci_le_clear_resolving_list(FD));
	CHECK_ALL(hci_le_add_dev_resolving_list(FD, 0, addr, irk, irk));
	CHECK_ALL(hci_le_remove_dev_resolving_list(FD, 0, addr));
	CHECK_ALL(hci_le_set_addr_resolution_enable(FD, 1));
	CHECK_ALL(hci_le_set_privacy_mode(FD, 0, addr, 0));
	CHECK_ALL(hci_le_set_rpa_timeout(FD, 900));
	CHECK_ALL(hci_le_clear_filter_accept_list(FD));
	CHECK_ALL(hci_le_add_device_to_filter_accept_list(FD, 0, addr));
	CHECK_ALL(hci_le_remove_device_from_filter_accept_list(FD, 0, addr));
}

/* ================================================================
 * hci_misc.c — reset / masks / LTK / host support
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(misc_core);
ATF_TC_BODY(misc_core, tc)
{
	uint8_t ltk[16];

	memset(ltk, 0x5A, sizeof(ltk));
	CHECK_ALL(hci_reset(FD));
	CHECK_ALL(hci_write_le_host_support(FD, 1, 0));
	CHECK_ALL(hci_set_event_mask(FD, 0x00001FFFFFFFFFFFULL));
	CHECK_ALL(hci_le_set_event_mask(FD, 0x000000000000001FULL));
	CHECK_ALL(hci_le_ltk_request_reply(FD, 0x0040, ltk));
	CHECK_ALL(hci_le_ltk_request_neg_reply(FD, 0x0040));
	/* §7.3.102 Set Min Encryption Key Size: range 7-16. */
	CHECK_ALL(hci_set_min_enc_key_size(FD, 16));
	CHECK_ALL(hci_le_write_auth_payload_timeout(FD, 0x0040, 0x0BB8));

	/* §7.3.94: handle range 0x0000-0x0EFF, timeout range 1-0xFFFF. */
	W.call_count = 0;
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_write_auth_payload_timeout(FD, 0x0F00,
	    0x0BB8));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.call_count);
	W.call_count = 0;
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_write_auth_payload_timeout(FD, 0x0040, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.call_count);
}

/* ================================================================
 * hci_misc.c — LE Read Local Supported Features (§7.8.3)
 * RP: Status(1) | LE_Features(8 LE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_local_features);
ATF_TC_BODY(read_local_features, tc)
{
	/* features = 0x00000000DEADBEEF, little-endian on the wire. */
	uint8_t rp[9] = { 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00 };
	uint64_t feats = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_local_features(FD, &feats));
	ATF_CHECK_EQ(0x00000000DEADBEEFULL, feats);

	CHECK_BAD(hci_le_read_local_features(FD, &feats));
	CHECK_XPORT(hci_le_read_local_features(FD, &feats));
}

/* ================================================================
 * hci_misc.c — LE Read Buffer Size v2 (§7.8.2)
 * RP: Status(1) | LE_ACL_Data_Packet_Length(2) |
 *     Total_Num_LE_ACL_Data_Packets(1) | ISO_Data_Packet_Length(2) |
 *     Total_Num_ISO_Data_Packets(1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_buffer_size_v2);
ATF_TC_BODY(read_buffer_size_v2, tc)
{
	/* acl_len=0x00FB(251), acl_num=0x0A, iso_len=0x0200(512), iso_num=0x08 */
	uint8_t rp[7] = { 0x00, 0xFB, 0x00, 0x0A, 0x00, 0x02, 0x08 };
	uint16_t acl_len = 0, iso_len = 0;
	uint8_t acl_num = 0, iso_num = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_buffer_size_v2(FD, &acl_len, &acl_num,
	    &iso_len, &iso_num));
	ATF_CHECK_EQ(0x00FB, acl_len);
	ATF_CHECK_EQ(0x0A, acl_num);
	ATF_CHECK_EQ(0x0200, iso_len);
	ATF_CHECK_EQ(0x08, iso_num);

	CHECK_BAD(hci_le_read_buffer_size_v2(FD, &acl_len, &acl_num,
	    &iso_len, &iso_num));
	CHECK_XPORT(hci_le_read_buffer_size_v2(FD, &acl_len, &acl_num,
	    &iso_len, &iso_num));
}

/* ================================================================
 * hci_misc.c — LE Read ISO TX Sync (§7.8.96)
 * RP: Status(1) | Connection_Handle(2) | Packet_Sequence_Number(2) |
 *     TX_Time_Stamp(4) | Time_Offset(3 LE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_iso_tx_sync);
ATF_TC_BODY(read_iso_tx_sync, tc)
{
	uint8_t rp[12] = {
		0x00,			/* status */
		0x40, 0x00,		/* connection_handle */
		0x34, 0x12,		/* seq = 0x1234 */
		0xEF, 0xCD, 0xAB, 0x89,	/* ts = 0x89ABCDEF */
		0x01, 0x02, 0x03	/* offset = 0x030201 */
	};
	uint16_t seq = 0;
	uint32_t ts = 0, off = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_iso_tx_sync(FD, 0x0040, &seq, &ts, &off));
	ATF_CHECK_EQ(0x1234, seq);
	ATF_CHECK_EQ(0x89ABCDEF, ts);
	ATF_CHECK_EQ(0x00030201, off);

	CHECK_BAD(hci_le_read_iso_tx_sync(FD, 0x0040, &seq, &ts, &off));
	CHECK_XPORT(hci_le_read_iso_tx_sync(FD, 0x0040, &seq, &ts, &off));
}

/* ================================================================
 * hci_misc.c — LE Set CIG Parameters (§7.8.97)
 * RP: Status(1) | CIG_ID(1) | CIS_Count(1) | Connection_Handle[i](2 LE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(set_cig_params);
ATF_TC_BODY(set_cig_params, tc)
{
	uint8_t rp[5] = { 0x00, 0x05, 0x01, 0x60, 0x00 };  /* handle 0x0060 */
	uint8_t cis_params[9];
	uint8_t out_cig = 0, out_cnt = 0;
	uint16_t handles[1] = { 0 };

	memset(cis_params, 0, sizeof(cis_params));
	/* Per-record validation: PHY masks must be non-zero (§7.8.97). */
	cis_params[5] = 0x01;
	cis_params[6] = 0x01;
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_set_cig_params(FD, 0x05, 10000, 10000, 0,
	    0, 0, 10, 10, 1, cis_params, sizeof(cis_params),
	    &out_cig, &out_cnt, handles));
	ATF_CHECK_EQ(0x05, out_cig);
	ATF_CHECK_EQ(0x01, out_cnt);
	ATF_CHECK_EQ(0x0060, handles[0]);

	/* CIG params rejects with status byte at rpbuf[0]. */
	mock_status_bad();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_cig_params(FD, 0x05, 10000, 10000, 0,
	    0, 0, 10, 10, 1, cis_params, sizeof(cis_params),
	    &out_cig, &out_cnt, handles));
	ATF_CHECK_EQ(EIO, errno);

	mock_xport_fail(EIO);
	ATF_CHECK_EQ(-1, hci_le_set_cig_params(FD, 0x05, 10000, 10000, 0,
	    0, 0, 10, 10, 1, cis_params, sizeof(cis_params),
	    &out_cig, &out_cnt, handles));
}

/* ================================================================
 * hci_misc.c — ISO channel management (CIG/CIS/BIG)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(misc_iso);
ATF_TC_BODY(misc_iso, tc)
{
	uint16_t cis_h[1] = { 0x0100 };
	uint16_t acl_h[1] = { 0x0001 };
	uint8_t bcode[16];
	uint8_t bis[1] = { 1 };
	uint8_t codec_id[5] = { 0x03, 0, 0, 0, 0 };  /* transparent */

	memset(bcode, 0, sizeof(bcode));
	CHECK_ALL(hci_le_create_cis(FD, 1, cis_h, acl_h));
	CHECK_ALL(hci_le_remove_cig(FD, 0x05));
	CHECK_ALL(hci_le_accept_cis_request(FD, 0x0040));
	CHECK_ALL(hci_le_reject_cis_request(FD, 0x0040, 0x0D));
	CHECK_ALL(hci_le_create_big(FD, 0, 0, 1, 10000, 100, 10, 0, 0x01,
	    0, 0, 0, bcode));
	CHECK_ALL(hci_le_terminate_big(FD, 0, 0x16));
	CHECK_ALL(hci_le_big_create_sync(FD, 0, 0x0001, 0, bcode, 0,
	    0x0064, 1, bis));
	CHECK_ALL(hci_le_big_terminate_sync(FD, 0));
	CHECK_ALL(hci_le_setup_iso_data_path(FD, 0x0040, 0, 0, codec_id,
	    0, 0, NULL));
	CHECK_ALL(hci_le_remove_iso_data_path(FD, 0x0040, 0x01));
	CHECK_ALL(hci_le_request_peer_sca(FD, 0x0040));
}

/* ================================================================
 * hci_misc.c — LE Read ISO Link Quality (§7.8.116)
 * RP: Status(1) | Connection_Handle(2) | seven u32 counters (LE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_iso_link_quality);
ATF_TC_BODY(read_iso_link_quality, tc)
{
	uint8_t rp[31];
	uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0;
	int i;

	memset(rp, 0, sizeof(rp));
	rp[0] = 0x00;			/* status */
	rp[1] = 0x40; rp[2] = 0x00;	/* connection_handle */
	/* seven u32 counters 1..7, each little-endian at offset 3 + 4*i */
	for (i = 0; i < 7; i++)
		rp[3 + i * 4] = (uint8_t)(i + 1);

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_iso_link_quality(FD, 0x0040,
	    &a, &b, &c, &d, &e, &f, &g));
	ATF_CHECK_EQ(1, a);	/* tx_unacked */
	ATF_CHECK_EQ(2, b);	/* tx_flushed */
	ATF_CHECK_EQ(3, c);	/* tx_last_subevent */
	ATF_CHECK_EQ(4, d);	/* retransmitted */
	ATF_CHECK_EQ(5, e);	/* crc_error */
	ATF_CHECK_EQ(6, f);	/* rx_unreceived */
	ATF_CHECK_EQ(7, g);	/* duplicate */

	CHECK_BAD(hci_le_read_iso_link_quality(FD, 0x0040,
	    &a, &b, &c, &d, &e, &f, &g));
	CHECK_XPORT(hci_le_read_iso_link_quality(FD, 0x0040,
	    &a, &b, &c, &d, &e, &f, &g));
}

/* ================================================================
 * hci_misc.c — Read Authenticated Payload Timeout (§7.3.93)
 * RP: Status(1) | Connection_Handle(2) | Authenticated_Payload_Timeout(2)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_auth_payload_timeout);
ATF_TC_BODY(read_auth_payload_timeout, tc)
{
	uint8_t rp[5] = { 0x00, 0x40, 0x00, 0xB8, 0x0B };  /* 0x0BB8 = 3000 */
	uint16_t to = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_auth_payload_timeout(FD, 0x0040, &to));
	ATF_CHECK_EQ(0x0BB8, to);

	CHECK_BAD(hci_le_read_auth_payload_timeout(FD, 0x0040, &to));
	CHECK_XPORT(hci_le_read_auth_payload_timeout(FD, 0x0040, &to));

	/* §7.3.93: Connection_Handle is 12 bits meaningful, max 0x0EFF. */
	W.call_count = 0;
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_read_auth_payload_timeout(FD, 0x0F00, &to));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.call_count);
}

ATF_TC_WITHOUT_HEAD(scan_command_matrix);
ATF_TC_BODY(scan_command_matrix, tc)
{
	struct hci_scan_params p;
	struct ble_scan_result result;
	int nresults;

	hci_scan_params_default(&p);
	CHECK_ALL(hci_le_set_scan_params(FD, &p));
	CHECK_ALL(hci_le_set_scan_enable(FD, 1, 1));
	CHECK_ALL(hci_le_set_ext_scan_params(FD, &p, 0));

	/* Mesh scan selection covers legacy/extended enable and disable. */
	CHECK_ALL(hci_le_mesh_scan_set(FD, 0, false));
	CHECK_ALL(hci_le_mesh_scan_set(FD, LE_FEAT_EXT_ADVERTISING, false));
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_mesh_scan_set(FD, 0, true));
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_mesh_scan_set(FD,
	    LE_FEAT_EXT_ADVERTISING, true));
	mock_xport_fail(EIO);
	ATF_CHECK_EQ(-1, hci_le_mesh_scan_set(FD, 0, true));
	mock_xport_fail(EIO);
	ATF_CHECK_EQ(-1, hci_le_mesh_scan_set(FD,
	    LE_FEAT_EXT_ADVERTISING, true));

	/* Independent validation clauses. */
	p.active = 2;
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_scan_params(FD, &p));
	ATF_CHECK_EQ(EINVAL, errno);
	hci_scan_params_default(&p);
	p.window = 3;
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_scan_params(FD, &p));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(-1, hci_le_scan_ex(FD, 0, &p, &result, 1,
	    &nresults));
	ATF_CHECK_EQ(-1, hci_le_ext_scan_ex(FD, 0, &p, &result, 1,
	    &nresults, 1));
}

ATF_TC_WITHOUT_HEAD(adv_config_and_mesh_burst_matrix);
ATF_TC_BODY(adv_config_and_mesh_burst_matrix, tc)
{
	struct hci_adv_config cfg;
	uint8_t ad[31];
	int kind, ordinal;

	memset(ad, 0xa5, sizeof(ad));
	memset(&cfg, 0, sizeof(cfg));
	cfg.interval_min = 0x00a0;
	cfg.interval_max = 0x00a0;
	cfg.channel_map = 0x07;
	cfg.tx_power = 0x7f;
	cfg.primary_phy = 0x01;
	cfg.secondary_phy = 0x01;
	cfg.has_peer = true;

	/* Every normalized kind reaches both wire-encoding switch arms. */
	for (kind = HCI_ADV_CONN_UND; kind <= HCI_ADV_NONCONN_UND; kind++) {
		cfg.kind = kind;
		cfg.mode = HCI_ADV_MODE_LEGACY;
		mock_ok();
		ATF_CHECK_EQ(0, hci_adv_configure(FD, 0, &cfg));
		ATF_CHECK(!cfg.used_extended);

		cfg.mode = HCI_ADV_MODE_EXTENDED;
		mock_ok();
		ATF_CHECK_EQ(0, hci_adv_configure(FD,
		    LE_FEAT_EXT_ADVERTISING, &cfg));
		ATF_CHECK(cfg.used_extended);
	}

	/* AUTO and EXTENDED fall back when the feature bit is absent. */
	cfg.kind = HCI_ADV_CONN_UND;
	cfg.mode = HCI_ADV_MODE_AUTO;
	mock_ok();
	ATF_CHECK_EQ(0, hci_adv_configure(FD, 0, &cfg));
	ATF_CHECK(!cfg.used_extended);
	cfg.mode = HCI_ADV_MODE_EXTENDED;
	mock_ok();
	ATF_CHECK_EQ(0, hci_adv_configure(FD, 0, &cfg));
	ATF_CHECK(!cfg.used_extended);

	/* Configuration validation clauses are independent API contracts. */
	cfg.kind = HCI_ADV_CONN_DIR_HIGH;
	cfg.has_peer = false;
	ATF_CHECK_EQ(-1, hci_adv_configure(FD, 0, &cfg));
	cfg.kind = HCI_ADV_CONN_UND;
	cfg.has_peer = true;
	cfg.own_addr_type = 4;
	ATF_CHECK_EQ(-1, hci_adv_configure(FD, 0, &cfg));
	cfg.own_addr_type = 0;
	cfg.channel_map = 0;
	ATF_CHECK_EQ(-1, hci_adv_configure(FD, 0, &cfg));
	cfg.channel_map = 0x07;
	cfg.mode = HCI_ADV_MODE_EXTENDED;
	cfg.primary_phy = 2;
	ATF_CHECK_EQ(-1, hci_adv_configure(FD,
	    LE_FEAT_EXT_ADVERTISING, &cfg));
	cfg.primary_phy = 1;
	cfg.secondary_phy = 4;
	ATF_CHECK_EQ(-1, hci_adv_configure(FD,
	    LE_FEAT_EXT_ADVERTISING, &cfg));
	cfg.secondary_phy = 1;
	cfg.mode = HCI_ADV_MODE_LEGACY;
	cfg.interval_max = 0x10000;
	ATF_CHECK_EQ(-1, hci_adv_configure(FD, 0, &cfg));

	/* Data validation precedes controller I/O. */
	ATF_CHECK_EQ(-1, hci_le_set_advertising_data(FD, ad, 32));
	ATF_CHECK_EQ(-1, hci_le_set_advertising_data(FD, NULL, 1));
	ATF_CHECK_EQ(-1, hci_le_set_ext_adv_data(FD, 0, NULL, 1));
	ATF_CHECK_EQ(-1, hci_le_set_advertising_params_full(FD, 0x20, 0x20,
	    0, 0, 0, 0, 0, NULL));
	ATF_CHECK_EQ(-1, hci_le_set_ext_adv_params_full(FD, 0, 0, 0x20,
	    0x20, 0, 0, 1, 1, 0, 0x7f, 0, NULL));

	ATF_CHECK_EQ(-1, hci_mesh_adv_burst(FD, 0, 0x00, NULL, 1));
	ATF_CHECK_EQ(-1, hci_mesh_adv_burst(FD, 0, 0x00, ad, 0));
	ATF_CHECK_EQ(-1, hci_mesh_adv_burst(FD, 0, 0x00, ad, 32));
	for (ordinal = 1; ordinal <= 3; ordinal++) {
		mock_xport_fail_at(ordinal, EIO);
		ATF_CHECK_EQ(-1, hci_mesh_adv_burst(FD, 0, 0x00, ad, sizeof(ad)));
		mock_xport_fail_at(ordinal, EIO);
		/*
		 * The ext path issues a leading Set-Ext-Adv-Enable(disable)
		 * that is best-effort (finding 42: the set may not exist yet),
		 * so a failure of that first command is ignored and only
		 * ordinals >= 2 (params/data/enable) abort the burst.
		 */
		ATF_CHECK_EQ(ordinal == 1 ? 0 : -1, hci_mesh_adv_burst(FD,
		    LE_FEAT_EXT_ADVERTISING, 0x00, ad, sizeof(ad)));
	}
	mock_ok();
	ATF_CHECK_EQ(0, hci_mesh_adv_burst(FD, 0, 0x00, ad, sizeof(ad)));
	mock_ok();
	ATF_CHECK_EQ(0, hci_mesh_adv_burst(FD,
	    LE_FEAT_EXT_ADVERTISING, 0x00, ad, sizeof(ad)));
}


/* ================================================================
 * Controller capability query (Core Spec Vol 4 Part E §7.4.1, §7.4.2)
 *
 * Gates the fix for "no capability query at all": the daemon must be able to
 * read the §6.27 Supported_Commands bitmap and test the octet/bit pairs it
 * gates optional commands on, and status 0x01 must arrive at the caller as a
 * DISTINGUISHABLE "not supported" (Vol 1 Part F §2.1) rather than a generic
 * I/O error.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(capability_query);
ATF_TC_BODY(capability_query, tc)
{
	uint8_t rp[1 + HCI_SUPPORTED_COMMANDS_LEN];
	uint8_t cmds[HCI_SUPPORTED_COMMANDS_LEN];
	uint8_t ver = 0;
	uint16_t rev = 0, manuf = 0, sub = 0;
	uint8_t lmp = 0;

	/*
	 * A controller that implements LE Read Buffer Size v2 (octet 41 bit 5)
	 * and LE Set Host Feature (octet 44 bit 1) but NOT LE Request Peer SCA
	 * (octet 43 bit 2).  Octet/bit pairs are the §6.27 table's.
	 */
	memset(rp, 0, sizeof(rp));
	rp[0] = BT_EXTREF_HCI_SUCCESS;
	rp[1 + HCI_CMD_LE_READ_BUFFER_SIZE_V2_OCTET] =
	    (uint8_t)(1U << HCI_CMD_LE_READ_BUFFER_SIZE_V2_BIT);
	rp[1 + HCI_CMD_LE_SET_HOST_FEATURE_OCTET] =
	    (uint8_t)(1U << HCI_CMD_LE_SET_HOST_FEATURE_BIT);

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_read_local_supported_commands(FD, cmds));
	ATF_CHECK(hci_cmd_supported(cmds,
	    HCI_CMD_LE_READ_BUFFER_SIZE_V2_OCTET,
	    HCI_CMD_LE_READ_BUFFER_SIZE_V2_BIT));
	ATF_CHECK(hci_cmd_supported(cmds, HCI_CMD_LE_SET_HOST_FEATURE_OCTET,
	    HCI_CMD_LE_SET_HOST_FEATURE_BIT));
	ATF_CHECK(!hci_cmd_supported(cmds, HCI_CMD_LE_REQUEST_PEER_SCA_OCTET,
	    HCI_CMD_LE_REQUEST_PEER_SCA_BIT));
	/* Out-of-range indices answer false rather than reading off the end. */
	ATF_CHECK(!hci_cmd_supported(cmds, HCI_SUPPORTED_COMMANDS_LEN, 0));
	ATF_CHECK(!hci_cmd_supported(cmds, 0, 8));
	ATF_CHECK(!hci_cmd_supported(NULL, 0, 0));

	/*
	 * Vol 1 Part F §2.1: Unknown HCI Command is how a controller says the
	 * command "may have not been implemented".  It must not collapse to
	 * EIO, or a caller cannot degrade.
	 */
	mock_status(BT_EXTREF_HCI_ERR_UNKNOWN_HCI_COMMAND);
	errno = 0;
	ATF_CHECK_EQ(-1, hci_read_local_supported_commands(FD, cmds));
	ATF_CHECK_EQ(EOPNOTSUPP, errno);

	/* §7.4.1: Status(1) HCI_Version(1) HCI_Revision(2) LMP_Version(1)
	 * Manufacturer(2) LMP_Subversion(2), all little-endian. */
	{
		uint8_t vrp[9] = { 0x00, 0x0B, 0x34, 0x12, 0x0B, 0x0F, 0x00,
		    0x78, 0x56 };

		mock_ok_bytes(vrp, sizeof(vrp));
		ATF_CHECK_EQ(0, hci_read_local_version(FD, &ver, &rev, &lmp,
		    &manuf, &sub));
		ATF_CHECK_EQ(0x0B, ver);	/* 0x0B == Bluetooth 5.2 */
		ATF_CHECK_EQ(0x1234, rev);
		ATF_CHECK_EQ(0x0B, lmp);
		ATF_CHECK_EQ(0x000F, manuf);
		ATF_CHECK_EQ(0x5678, sub);
	}
	CHECK_BAD(hci_read_local_version(FD, NULL, NULL, NULL, NULL, NULL));
	CHECK_XPORT(hci_read_local_version(FD, NULL, NULL, NULL, NULL, NULL));
}

/*
 * LE Read Buffer Size v1 (§7.8.2, OCF 0x0002): the fallback for a controller
 * that does not implement v2.  RP: Status(1) HC_LE_ACL_Data_Packet_Length(2)
 * HC_Total_Num_LE_ACL_Data_Packets(1).
 */
ATF_TC_WITHOUT_HEAD(read_buffer_size_v1);
ATF_TC_BODY(read_buffer_size_v1, tc)
{
	uint8_t rp[4] = { 0x00, 0xFB, 0x00, 0x0A };
	uint16_t acl_len = 0;
	uint8_t acl_num = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_buffer_size_v1(FD, &acl_len, &acl_num));
	ATF_CHECK_EQ(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_BUFFER_SIZE), W.last_opcode);
	ATF_CHECK_EQ(0x00FB, acl_len);
	ATF_CHECK_EQ(0x0A, acl_num);

	CHECK_BAD(hci_le_read_buffer_size_v1(FD, &acl_len, &acl_num));
	CHECK_XPORT(hci_le_read_buffer_size_v1(FD, &acl_len, &acl_num));
}

/*
 * A Command Complete carrying NO return parameters must not read as success.
 *
 * Gates the shared guard in hci_devreq_logged_locked(): bt_devreq() pre-zeroes
 * the caller's buffer, so before the guard every status-only wrapper reported
 * SUCCESS for a command the controller never acknowledged.
 */
ATF_TC_WITHOUT_HEAD(empty_command_complete_fails);
ATF_TC_BODY(empty_command_complete_fails, tc)
{

	mock_ok_empty();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_event_mask(FD, 0));
	ATF_CHECK_EQ(EIO, errno);

	mock_ok_empty();
	ATF_CHECK_EQ(-1, hci_le_set_scan_enable(FD, 0x01, 0x00));

	/* A one-octet success status is still accepted. */
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_event_mask(FD, 0));
}

/*
 * LE Remote Connection Parameter Request Reply / Negative Reply
 * (Core Spec Vol 4 Part E §7.8.31, §7.8.32).
 *
 * Gates the answer half of the bit-5 fix: without these commands the peer's
 * Link Layer gets no response and, with the event masked, the procedure is
 * rejected on air with 0x1A (Vol 6 Part B §5.1.7.2).  The command octets are
 * asserted against the §7.8.31 field order, little-endian.
 */
ATF_TC_WITHOUT_HEAD(remote_conn_param_reply);
ATF_TC_BODY(remote_conn_param_reply, tc)
{
	uint8_t rp[3] = { 0x00, 0x40, 0x00 };	/* Status | Connection_Handle */

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_remote_conn_param_req_reply(FD, 0x0040,
	    0x0018, 0x0028, 0x0004, 0x0100));
	ATF_CHECK_EQ(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    BT_EXTREF_LE_OCF_REMOTE_CONN_PARAM_REQ_REPLY), W.last_opcode);
	/* handle(2) min(2) max(2) latency(2) timeout(2) min_ce(2) max_ce(2) */
	ATF_CHECK_EQ(14, W.last_clen);
	ATF_CHECK_EQ(0x40, W.last_cparam[0]);
	ATF_CHECK_EQ(0x00, W.last_cparam[1]);
	ATF_CHECK_EQ(0x18, W.last_cparam[2]);
	ATF_CHECK_EQ(0x00, W.last_cparam[3]);
	ATF_CHECK_EQ(0x28, W.last_cparam[4]);
	ATF_CHECK_EQ(0x00, W.last_cparam[5]);
	ATF_CHECK_EQ(0x04, W.last_cparam[6]);
	ATF_CHECK_EQ(0x00, W.last_cparam[7]);
	ATF_CHECK_EQ(0x00, W.last_cparam[8]);
	ATF_CHECK_EQ(0x01, W.last_cparam[9]);
	/* Min_CE_Length / Max_CE_Length: no preference. */
	ATF_CHECK_EQ(0x00, W.last_cparam[10]);
	ATF_CHECK_EQ(0x00, W.last_cparam[11]);
	ATF_CHECK_EQ(0x00, W.last_cparam[12]);
	ATF_CHECK_EQ(0x00, W.last_cparam[13]);

	/* Negative Reply: handle(2) reason(1), reason 0x3B per §5.1.7.2. */
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_remote_conn_param_req_neg_reply(FD, 0x0040,
	    BT_EXTREF_HCI_ERR_UNACCEPTABLE_CONNECTION_PARAMETERS));
	ATF_CHECK_EQ(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    BT_EXTREF_LE_OCF_REMOTE_CONN_PARAM_REQ_NEG_REPLY), W.last_opcode);
	ATF_CHECK_EQ(3, W.last_clen);
	ATF_CHECK_EQ(0x40, W.last_cparam[0]);
	ATF_CHECK_EQ(0x00, W.last_cparam[1]);
	ATF_CHECK_EQ(BT_EXTREF_HCI_ERR_UNACCEPTABLE_CONNECTION_PARAMETERS,
	    W.last_cparam[2]);

	/* Host-side validation: nothing reaches the controller. */
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(-1, hci_le_remote_conn_param_req_reply(FD, 0x0F00,
	    0x0018, 0x0028, 0x0004, 0x0100));
	ATF_CHECK_EQ(0, W.call_count);
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(-1, hci_le_remote_conn_param_req_neg_reply(FD, 0x0F00,
	    BT_EXTREF_HCI_ERR_UNACCEPTABLE_CONNECTION_PARAMETERS));
	ATF_CHECK_EQ(0, W.call_count);

	CHECK_BAD(hci_le_remote_conn_param_req_reply(FD, 0x0040, 0x0018,
	    0x0028, 0x0004, 0x0100));
	CHECK_XPORT(hci_le_remote_conn_param_req_neg_reply(FD, 0x0040,
	    BT_EXTREF_HCI_ERR_UNACCEPTABLE_CONNECTION_PARAMETERS));
}

/*
 * The acceptance policy for a peer's proposal (§7.7.65.6 values judged by the
 * §7.8.18 ranges the daemon applies to its OWN updates, including the
 * supervision-timeout inequality).
 */
ATF_TC_WITHOUT_HEAD(conn_param_req_policy);
ATF_TC_BODY(conn_param_req_policy, tc)
{

	/* 30-50 ms, latency 4, 2.56 s timeout: comfortably legal. */
	ATF_CHECK(hci_le_conn_param_req_acceptable(0x0018, 0x0028, 0x0004,
	    0x0100));
	/* Interval below 0x0006 / above 0x0C80. */
	ATF_CHECK(!hci_le_conn_param_req_acceptable(0x0005, 0x0028, 0x0000,
	    0x0100));
	ATF_CHECK(!hci_le_conn_param_req_acceptable(0x0018, 0x0C81, 0x0000,
	    0x0100));
	/* min > max. */
	ATF_CHECK(!hci_le_conn_param_req_acceptable(0x0028, 0x0018, 0x0000,
	    0x0100));
	/* Latency above 0x01F3. */
	ATF_CHECK(!hci_le_conn_param_req_acceptable(0x0018, 0x0028, 0x01F4,
	    0x0100));
	/* Timeout outside 0x000A..0x0C80. */
	ATF_CHECK(!hci_le_conn_param_req_acceptable(0x0018, 0x0028, 0x0000,
	    0x0009));
	/* Timeout too short for interval * (1 + latency). */
	ATF_CHECK(!hci_le_conn_param_req_acceptable(0x0018, 0x0028, 0x0004,
	    0x000A));
}

/*
 * LE Set Extended Advertising Enable with Max_Extended_Advertising_Events 0.
 *
 * §7.8.56 defines 0x00 as "No maximum number of advertising events", i.e.
 * advertise until the Host disables the set.  Rejecting it host-side made
 * Mesh Proxy advertising -- whose start path asks for exactly that -- fail
 * before reaching the air.
 */
ATF_TC_WITHOUT_HEAD(ext_adv_enable_burst_unbounded);
ATF_TC_BODY(ext_adv_enable_burst_unbounded, tc)
{

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_ext_adv_enable_burst(FD, 0x01, 0x00));
	ATF_CHECK_EQ(1, W.call_count);
	ATF_CHECK_EQ(6, W.last_clen);
	ATF_CHECK_EQ(0x01, W.last_cparam[0]);	/* Enable */
	ATF_CHECK_EQ(0x01, W.last_cparam[1]);	/* Num_Sets */
	ATF_CHECK_EQ(0x01, W.last_cparam[2]);	/* Advertising_Handle */
	ATF_CHECK_EQ(0x00, W.last_cparam[3]);	/* Duration lo */
	ATF_CHECK_EQ(0x00, W.last_cparam[4]);	/* Duration hi */
	ATF_CHECK_EQ(0x00, W.last_cparam[5]);	/* Max_Extended_Adv_Events */

	/* A bounded burst still works, and a bad handle is still refused. */
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_ext_adv_enable_burst(FD, 0x01, 0x01));
	ATF_CHECK_EQ(0x01, W.last_cparam[5]);
	mock_ok();
	ATF_CHECK_EQ(-1, hci_le_set_ext_adv_enable_burst(FD, 0xF0, 0x00));
	ATF_CHECK_EQ(0, W.call_count);
}

/*
 * LE Add Device To Resolving List: the two failures a caller filling the
 * controller's list must tell apart (§7.8.38 error table, Vol 1 Part F §2.7
 * and §2.18).  ENOSPC means the list is full and the loop should stop; EINVAL
 * means THIS entry was rejected and says nothing about the next peer.
 */
ATF_TC_WITHOUT_HEAD(resolving_list_add_status);
ATF_TC_BODY(resolving_list_add_status, tc)
{
	static const uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };
	static const uint8_t irk[16] = { 0 };

	mock_status(BT_EXTREF_HCI_ERR_MEMORY_CAPACITY_EXCEEDED);
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_add_dev_resolving_list(FD, 0x00, addr, irk,
	    irk));
	ATF_CHECK_EQ(ENOSPC, errno);

	mock_status(BT_EXTREF_HCI_ERR_INVALID_HCI_COMMAND_PARAMETERS);
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_add_dev_resolving_list(FD, 0x00, addr, irk,
	    irk));
	ATF_CHECK_EQ(EINVAL, errno);

	mock_status(BT_EXTREF_HCI_ERR_COMMAND_DISALLOWED);
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_add_dev_resolving_list(FD, 0x00, addr, irk,
	    irk));
	ATF_CHECK_EQ(EIO, errno);
}

/*
 * LE Set CIG Parameters RTN_C_To_P / RTN_P_To_C are a FULL octet.
 *
 * §7.8.97 gives both as "0xXX  Number of times every CIS Data PDU should be
 * retransmitted" with no reserved-values row -- unlike every other bounded
 * field of that command.  The 0x00-0x1E range belongs to §7.8.103 LE Create
 * BIG, and applying it here rejected legal values 0x1F to 0xFF.
 */
ATF_TC_WITHOUT_HEAD(set_cig_params_rtn_full_octet);
ATF_TC_BODY(set_cig_params_rtn_full_octet, tc)
{
	/* CIS_ID(1) Max_SDU_C_To_P(2) Max_SDU_P_To_C(2) PHY_C(1) PHY_P(1)
	 * RTN_C_To_P(1) RTN_P_To_C(1) */
	uint8_t cis[9] = { 0x00, 0x28, 0x00, 0x28, 0x00, 0x01, 0x01,
	    0x1F, 0xFF };
	uint8_t rp[5] = { 0x00, 0x00, 0x01, 0x40, 0x00 };
	uint16_t handles[1] = { 0 };
	uint8_t out_cig = 0, out_cnt = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_set_cig_params(FD, 0x00, 10000, 10000, 0x00,
	    0x00, 0x00, 10, 10, 1, cis, sizeof(cis), &out_cig, &out_cnt,
	    handles));
	ATF_CHECK_EQ(1, W.call_count);
	/* The RTN octets reach the controller unaltered. */
	ATF_CHECK_EQ(0x1F, W.last_cparam[15 + 7]);
	ATF_CHECK_EQ(0xFF, W.last_cparam[15 + 8]);

	/* The Create BIG bound is unchanged: RTN 0x1F is still refused there. */
	mock_ok();
	ATF_CHECK_EQ(-1, hci_le_create_big(FD, 0x00, 0x00, 1, 10000, 100,
	    10, 0x1F, 0x02, 0x00, 0x00, 0x00, NULL));
	ATF_CHECK_EQ(0, W.call_count);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, read_bd_addr);

	/* hci_adv.c */
	ATF_TP_ADD_TC(tp, adv_legacy);
	ATF_TP_ADD_TC(tp, adv_extended);
	ATF_TP_ADD_TC(tp, ext_adv_data_clen);
	ATF_TP_ADD_TC(tp, ext_adv_data_fragmentation);
	ATF_TP_ADD_TC(tp, read_max_adv_data_length);
	ATF_TP_ADD_TC(tp, read_num_supported_adv_sets);
	ATF_TP_ADD_TC(tp, adv_periodic);
	ATF_TP_ADD_TC(tp, read_periodic_adv_list_size);
	ATF_TP_ADD_TC(tp, adv_past);
	ATF_TP_ADD_TC(tp, adv_cte);
	ATF_TP_ADD_TC(tp, read_antenna_info);

	/* hci_conn.c */
	ATF_TP_ADD_TC(tp, conn_params);
	ATF_TP_ADD_TC(tp, conn_phy);
	ATF_TP_ADD_TC(tp, read_phy);
	ATF_TP_ADD_TC(tp, conn_subrate_power);
	ATF_TP_ADD_TC(tp, enh_read_tx_power);
	ATF_TP_ADD_TC(tp, ext_create_connection);

	/* hci_privacy.c */
	ATF_TP_ADD_TC(tp, privacy);

	/* hci_misc.c */
	ATF_TP_ADD_TC(tp, misc_core);
	ATF_TP_ADD_TC(tp, read_local_features);
	ATF_TP_ADD_TC(tp, read_buffer_size_v2);
	ATF_TP_ADD_TC(tp, read_iso_tx_sync);
	ATF_TP_ADD_TC(tp, set_cig_params);
	ATF_TP_ADD_TC(tp, misc_iso);
	ATF_TP_ADD_TC(tp, read_iso_link_quality);
	ATF_TP_ADD_TC(tp, read_auth_payload_timeout);
	ATF_TP_ADD_TC(tp, scan_command_matrix);
	ATF_TP_ADD_TC(tp, adv_config_and_mesh_burst_matrix);
	ATF_TP_ADD_TC(tp, ext_adv_enable_burst_unbounded);

	/* Controller capability query and status classification. */
	ATF_TP_ADD_TC(tp, capability_query);
	ATF_TP_ADD_TC(tp, read_buffer_size_v1);
	ATF_TP_ADD_TC(tp, empty_command_complete_fails);
	ATF_TP_ADD_TC(tp, resolving_list_add_status);

	/* Connection Parameters Request procedure (Vol 6 Part B §5.1.7.2). */
	ATF_TP_ADD_TC(tp, remote_conn_param_reply);
	ATF_TP_ADD_TC(tp, conn_param_req_policy);

	/* Isochronous parameter bounds. */
	ATF_TP_ADD_TC(tp, set_cig_params_rtn_full_octet);

	return (atf_no_error());
}
