/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * EXTERNAL REFERENCE ORACLE: ATT / GATT on-the-wire PDU scripts.
 *
 * Hand-transcribed, byte for byte, from the unit test suites of two
 * independent Bluetooth host stacks.  Nothing in this file was produced by
 * reading, running, or reasoning about blued, libble, or any other 5BSD
 * source: every octet below is a literal that already existed in a foreign
 * tree, and every array carries the file and line it was copied from.
 *
 * WHY THESE PARTICULAR SOURCES
 * ---------------------------
 * BlueZ's unit/test-gatt.c is not a home-grown test list.  Its cases are
 * named for the Bluetooth SIG's own GATT test specification identifiers
 * (TP/GAC/..., TP/GAD/..., TP/GAR/...), and each case is a literal script of
 * request and response PDUs that a conforming client or server must put on
 * the ATT channel.  That makes it, for our purposes, a third-party
 * transcription of the qualification suite rather than one team's opinion.
 *
 * Apache NimBLE's nimble/host/test/src/ tests were written from the same
 * specification by a different team with no shared lineage, so where the two
 * agree we have genuine corroboration and where they differ we have a
 * finding.
 *
 * SOURCES
 * -------
 *   [BLUEZ]  BlueZ, git.kernel.org/pub/scm/bluetooth/bluez.git, snapshot
 *            commit 92305dc06ab8a6d89af2dae1d725cc4d51462ad1.  Cited line
 *            numbers are lines of that snapshot.
 *   [NIMBLE] Apache NimBLE, github.com/apache/mynewt-nimble, snapshot commit
 *            1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845.
 *   [SPEC]   /usr/src/bluetooth-specs/Core_Specification_6_3.txt.
 *
 * BYTE ORDER
 * ----------
 * ATT is a little-endian protocol (Vol 3, Part F, Section 3.1: "All the
 * attribute protocol PDU fields ... shall be transmitted least significant
 * octet first").  Every array below is therefore in TRANSMISSION order --
 * index 0 is the first octet on the channel, which for a request is the
 * opcode.  No reordering of any kind has been applied.
 */

#ifndef TESTS_BLUETOOTH_SPEC_EXTREF_ATT_GATT_WIRE_H
#define TESTS_BLUETOOTH_SPEC_EXTREF_ATT_GATT_WIRE_H

#include <stdint.h>

/*
 * ================================================================
 * Exchange MTU -- SIG case TP/GAC/CL/BV-01-C and TP/GAC/SR/BV-01-C
 * [BLUEZ] unit/test-gatt.c:110-112 (MTU_EXCHANGE_CLIENT_PDUS),
 *         :2436-2441.
 *
 * The client's very first PDU is ATT_EXCHANGE_MTU_REQ carrying its own
 * receive MTU, and the server answers ATT_EXCHANGE_MTU_RSP carrying its.
 * BlueZ's client MTU here is 0x0200 = 512 ([SPEC] Vol 3, Part F, Section
 * 3.4.2.1 caps ATT_MTU at 517; 512 is BlueZ's configured value, not a
 * specification constant, so only the FRAMING of this pair is normative).
 * ================================================================
 */
static const uint8_t bt_extref_bluez_mtu_req[3] = {
	0x02, 0x00, 0x02,
};
static const uint8_t bt_extref_bluez_mtu_rsp[3] = {
	0x03, 0x00, 0x02,
};
#define BT_EXTREF_BLUEZ_MTU_VALUE	512

/*
 * ================================================================
 * Discover All Primary Services -- SIG case TP/GAD/CL/BV-01-C
 * [BLUEZ] unit/test-gatt.c:2449-2462.
 *
 * Procedure ([SPEC] Vol 3, Part G, Section 4.4.1): ATT_READ_BY_GROUP_TYPE_REQ
 * over 0x0001..0xFFFF with the Primary Service UUID 0x2800, repeated from the
 * last returned End Group Handle + 1, terminated by an ATT_ERROR_RSP with
 * Attribute Not Found (0x0A).
 *
 * The three requests are the load-bearing part: they are what OUR client must
 * emit given these responses.  Note that the second request starts at 0x0033,
 * i.e. 0x0032 + 1, where 0x0032 is the End Group Handle of the LAST group in
 * the first response -- not the last Attribute Handle, and not the request's
 * own end handle.
 * ================================================================
 */
static const uint8_t bt_extref_bluez_gad_bv01_req1[7] = {
	0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28,
};
static const uint8_t bt_extref_bluez_gad_bv01_rsp1[20] = {
	0x11, 0x06, 0x10, 0x00, 0x13, 0x00, 0x00, 0x18,
	0x20, 0x00, 0x29, 0x00, 0xb0, 0x68,
	0x30, 0x00, 0x32, 0x00, 0x19, 0x18,
};
static const uint8_t bt_extref_bluez_gad_bv01_req2[7] = {
	0x10, 0x33, 0x00, 0xff, 0xff, 0x00, 0x28,
};
static const uint8_t bt_extref_bluez_gad_bv01_rsp2[22] = {
	0x11, 0x14, 0x90, 0x00, 0x96, 0x00, 0xef, 0xcd,
	0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x85, 0x60,
	0x00, 0x00,
};
static const uint8_t bt_extref_bluez_gad_bv01_req3[7] = {
	0x10, 0x97, 0x00, 0xff, 0xff, 0x00, 0x28,
};
static const uint8_t bt_extref_bluez_gad_bv01_err[5] = {
	0x01, 0x10, 0x97, 0x00, 0x0a,
};

/*
 * ================================================================
 * Discover Primary Service by 16-bit UUID -- SIG case TP/GAD/CL/BV-02-C-1
 * [BLUEZ] unit/test-gatt.c:2487-2496.
 *
 * Procedure ([SPEC] Vol 3, Part G, Section 4.4.2): ATT_FIND_BY_TYPE_VALUE_REQ
 * with Attribute Type 0x2800 and the Attribute Value set to the service UUID,
 * little-endian.  The response is a list of Handles Information (found
 * handle, group end handle) pairs; the search resumes at the last group end
 * handle + 1 and terminates on 0x0A.
 * ================================================================
 */
static const uint8_t bt_extref_bluez_gad_bv02_16_req1[9] = {
	0x06, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28, 0x00, 0x18,
};
static const uint8_t bt_extref_bluez_gad_bv02_16_rsp1[5] = {
	0x07, 0x01, 0x00, 0x07, 0x00,
};
static const uint8_t bt_extref_bluez_gad_bv02_16_req2[9] = {
	0x06, 0x08, 0x00, 0xff, 0xff, 0x00, 0x28, 0x00, 0x18,
};
static const uint8_t bt_extref_bluez_gad_bv02_16_err[5] = {
	0x01, 0x06, 0x08, 0x00, 0x0a,
};

/*
 * TP/GAD/CL/BV-02-C-1-alternative, [BLUEZ] unit/test-gatt.c:2497-2504.
 * The same first request, answered with a group whose End Group Handle is
 * 0xFFFF.  BlueZ issues NO further request: the procedure is complete because
 * there is no handle above 0xFFFF ([SPEC] Vol 3, Part G, Section 4.4.2 --
 * "the procedure is complete when ... the End Group Handle is 0xFFFF").  A
 * client that computes 0xFFFF + 1 and wraps to 0x0000 loops forever, so this
 * script is the regression oracle for the wrap guard.
 */
static const uint8_t bt_extref_bluez_gad_bv02_alt_rsp[5] = {
	0x07, 0x01, 0x00, 0xFF, 0xFF,
};

/*
 * Discover Primary Service by 128-bit UUID -- SIG case TP/GAD/CL/BV-02-C-2
 * [BLUEZ] unit/test-gatt.c:2505-2518.
 *
 * The Attribute Value is the full 16-octet UUID, little-endian, so the
 * request is 7 + 16 = 23 octets.  Note the tail 0x0d 0x18 0x00 0x00 at
 * offsets 19..22: that is the 0x180D short alias expanded through the
 * Bluetooth Base UUID, transmitted least significant octet first.
 */
static const uint8_t bt_extref_bluez_gad_bv02_128_req1[23] = {
	0x06, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28, 0xfb,
	0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00,
	0x80, 0x00, 0x10, 0x00, 0x00, 0x0d,
	0x18, 0x00, 0x00,
};
static const uint8_t bt_extref_bluez_gad_bv02_128_rsp1[5] = {
	0x07, 0x10, 0x00, 0x17, 0x00,
};
static const uint8_t bt_extref_bluez_gad_bv02_128_req2[23] = {
	0x06, 0x18, 0x00, 0xff, 0xff, 0x00, 0x28, 0xfb,
	0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00,
	0x80, 0x00, 0x10, 0x00, 0x00, 0x0d,
	0x18, 0x00, 0x00,
};
static const uint8_t bt_extref_bluez_gad_bv02_128_err[5] = {
	0x01, 0x06, 0x18, 0x00, 0x0a,
};

/*
 * ================================================================
 * Find Included Services -- SIG case TP/GAD/CL/BV-03-C
 * [BLUEZ] unit/test-gatt.c:2576-2598.
 *
 * Procedure ([SPEC] Vol 3, Part G, Section 4.5.1): ATT_READ_BY_TYPE_REQ with
 * the Include declaration UUID 0x2802.  A record whose value is 6 octets
 * carries {included start, included end, 16-bit UUID}; a record whose value
 * is 4 octets carries only {included start, included end} and the client must
 * then issue an ATT_READ_REQ against the INCLUDED SERVICE'S START HANDLE to
 * fetch the 128-bit UUID from the primary service declaration itself.
 *
 * That second read is the part a naive implementation gets wrong: the handle
 * read is the included service's start handle (0x0020, 0x0030), not the
 * include declaration's own handle (0x0003, 0x0004).
 * ================================================================
 */
static const uint8_t bt_extref_bluez_gad_bv03_req1[7] = {
	0x08, 0x01, 0x00, 0xff, 0xff, 0x02, 0x28,
};
static const uint8_t bt_extref_bluez_gad_bv03_rsp1[10] = {
	0x09, 0x08, 0x02, 0x00, 0x10, 0x00, 0x1f, 0x00, 0x0f, 0x18,
};
static const uint8_t bt_extref_bluez_gad_bv03_req2[7] = {
	0x08, 0x03, 0x00, 0xff, 0xff, 0x02, 0x28,
};
static const uint8_t bt_extref_bluez_gad_bv03_rsp2[14] = {
	0x09, 0x06, 0x03, 0x00, 0x20, 0x00, 0x2f, 0x00,
	0x04, 0x00, 0x30, 0x00, 0x3f, 0x00,
};
static const uint8_t bt_extref_bluez_gad_bv03_read1[3] = {
	0x0a, 0x20, 0x00,
};
static const uint8_t bt_extref_bluez_gad_bv03_read1_rsp[17] = {
	0x0b, 0x00, 0x00, 0x3e, 0x39, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x23, 0x45, 0x67, 0x89,
	0xab, 0xcd, 0xef,
};
static const uint8_t bt_extref_bluez_gad_bv03_read2[3] = {
	0x0a, 0x30, 0x00,
};
static const uint8_t bt_extref_bluez_gad_bv03_read2_rsp[17] = {
	0x0b, 0x00, 0x00, 0x3b, 0x39, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x23, 0x45, 0x67, 0x89,
	0xab, 0xcd, 0xef,
};
static const uint8_t bt_extref_bluez_gad_bv03_req3[7] = {
	0x08, 0x05, 0x00, 0xff, 0xff, 0x02, 0x28,
};
static const uint8_t bt_extref_bluez_gad_bv03_rsp3[10] = {
	0x09, 0x08, 0x05, 0x00, 0x40, 0x00, 0x4f, 0x00, 0x0a, 0x18,
};
static const uint8_t bt_extref_bluez_gad_bv03_req4[7] = {
	0x08, 0x06, 0x00, 0xff, 0xff, 0x02, 0x28,
};
static const uint8_t bt_extref_bluez_gad_bv03_err[5] = {
	0x01, 0x08, 0x06, 0x00, 0x0a,
};

/*
 * ================================================================
 * Discover All Characteristics of a Service -- SIG case TP/GAD/CL/BV-04-C
 * [BLUEZ] unit/test-gatt.c:2621-2634.
 *
 * Procedure ([SPEC] Vol 3, Part G, Section 4.6.1): ATT_READ_BY_TYPE_REQ with
 * the Characteristic declaration UUID 0x2803, restricted to the service's
 * handle range (here 0x0010..0x0020).  A 5-octet record value is
 * {properties, value handle, 16-bit UUID}; a 19-octet record value is
 * {properties, value handle, 128-bit UUID}, i.e. record lengths 7 and 21
 * (0x15) including the 2-octet attribute handle.
 *
 * The request end handle stays pinned at the service's end handle across
 * continuations -- it is NOT widened to 0xFFFF.
 * ================================================================
 */
static const uint8_t bt_extref_bluez_gad_bv04_req1[7] = {
	0x08, 0x10, 0x00, 0x20, 0x00, 0x03, 0x28,
};
static const uint8_t bt_extref_bluez_gad_bv04_rsp1[9] = {
	0x09, 0x07, 0x11, 0x00, 0x02, 0x12, 0x00, 0x25, 0x2a,
};
static const uint8_t bt_extref_bluez_gad_bv04_req2[7] = {
	0x08, 0x12, 0x00, 0x20, 0x00, 0x03, 0x28,
};
static const uint8_t bt_extref_bluez_gad_bv04_rsp2[23] = {
	0x09, 0x15, 0x13, 0x00, 0x02, 0x14, 0x00, 0x85,
	0x00, 0xef, 0xcd, 0xab, 0x89, 0x67,
	0x45, 0x23, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00,
};
static const uint8_t bt_extref_bluez_gad_bv04_req3[7] = {
	0x08, 0x14, 0x00, 0x20, 0x00, 0x03, 0x28,
};
static const uint8_t bt_extref_bluez_gad_bv04_err[5] = {
	0x01, 0x08, 0x12, 0x00, 0x0a,
};

/*
 * ================================================================
 * Discover All Characteristic Descriptors -- SIG case TP/GAD/CL/BV-06-C
 * [BLUEZ] unit/test-gatt.c:2729-2736.
 *
 * Procedure ([SPEC] Vol 3, Part G, Section 4.7.1): ATT_FIND_INFORMATION_REQ
 * over the descriptor range.  Format 0x01 is {handle, 16-bit UUID} pairs.
 *
 * The termination rule here is the interesting one and there is no error
 * response in this script at all: the second response's last handle is
 * 0x0016, which EQUALS the requested end handle, so the procedure is complete
 * and BlueZ emits no third request ([SPEC] Vol 3, Part G, Section 4.7.1 --
 * "the procedure is complete when ... the Attribute Handle is equal to the
 * Ending Handle of the characteristic").  An implementation that always waits
 * for 0x0A emits a needless extra round trip; this script catches that.
 * ================================================================
 */
static const uint8_t bt_extref_bluez_gad_bv06_req1[5] = {
	0x04, 0x13, 0x00, 0x16, 0x00,
};
static const uint8_t bt_extref_bluez_gad_bv06_rsp1[10] = {
	0x05, 0x01, 0x13, 0x00, 0x02, 0x29, 0x14, 0x00, 0x03, 0x29,
};
static const uint8_t bt_extref_bluez_gad_bv06_req2[5] = {
	0x04, 0x15, 0x00, 0x16, 0x00,
};
static const uint8_t bt_extref_bluez_gad_bv06_rsp2[10] = {
	0x05, 0x01, 0x15, 0x00, 0x04, 0x29, 0x16, 0x00, 0x05, 0x29,
};

/*
 * ================================================================
 * Read Using Characteristic UUID -- SIG cases TP/GAR/CL/BV-03-C-1 and -2
 * [BLUEZ] unit/test-gatt.c:2842-2865.
 *
 * ATT_READ_BY_TYPE_REQ over 0x0001..0xFFFF.  The -1 variant uses the 16-bit
 * type 0x2A0D; the -2 variant uses a 128-bit type, and the type field is then
 * 16 octets transmitted least significant octet first, so the source's
 * ascending 0x00..0x0f UUID appears reversed on the wire.  This pair is the
 * oracle for "a Read By Type request is 7 octets for a 16-bit type and 21
 * octets for a 128-bit one, and the UUID is byte-reversed exactly once".
 * ================================================================
 */
static const uint8_t bt_extref_bluez_gar_bv03_16_req[7] = {
	0x08, 0x01, 0x00, 0xff, 0xff, 0x0d, 0x2a,
};
static const uint8_t bt_extref_bluez_gar_bv03_16_rsp[7] = {
	0x09, 0x05, 0x0a, 0x00, 0x01, 0x02, 0x03,
};
static const uint8_t bt_extref_bluez_gar_bv03_128_req[21] = {
	0x08, 0x01, 0x00, 0xff, 0xff, 0x0f, 0x0e, 0x0d,
	0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07,
	0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	0x00,
};

/*
 * ================================================================
 * ATT server error selection, observed as literal responses.
 *
 * These are the two cases where BlueZ's own SERVER, driven by the SIG script,
 * puts an error on the wire, and they pin a rule that is easy to get backwards.
 * ================================================================
 */

/*
 * TP/GAR/SR/BI-02-C/small -- [BLUEZ] unit/test-gatt.c:2830-2835.
 * ATT_READ_REQ for handle 0x0000.  Handle 0 is not a valid attribute handle
 * ([SPEC] Vol 3, Part F, Section 3.2.2: "The attribute handle value 0x0000 is
 * reserved").  Answer: Invalid Handle (0x01).
 */
static const uint8_t bt_extref_bluez_read_h0_req[3] = {
	0x0a, 0x00, 0x00,
};
static const uint8_t bt_extref_bluez_read_h0_err[5] = {
	0x01, 0x0a, 0x00, 0x00, 0x01,
};

/*
 * TP/GAR/SR/BI-02-C/large -- [BLUEZ] unit/test-gatt.c:2836-2841.
 * ATT_READ_REQ for handle 0xF00F, which does not exist in the database.
 * Answer: Invalid Handle (0x01), NOT Attribute Not Found (0x0A).
 *
 * This distinction is the whole point of transcribing it.  0x0A is the
 * terminator of the handle-RANGE procedures (Find Information, Find By Type
 * Value, Read By Type, Read By Group Type); a single-handle request against a
 * handle that is not allocated is Invalid Handle.  [SPEC] Vol 3, Part F,
 * Section 3.4.4.3 says of ATT_READ_REQ: "If the attribute handle is invalid
 * ... an ATT_ERROR_RSP PDU shall be sent ... with the Error Code parameter
 * set to Invalid Handle."
 *
 * CORROBORATION: NimBLE selects the same code from the same condition --
 * [NIMBLE] nimble/host/src/ble_att_svr.c, ble_att_svr_read_handle(), returns
 * BLE_ATT_ERR_INVALID_HANDLE when the handle lookup misses.
 */
static const uint8_t bt_extref_bluez_read_missing_req[3] = {
	0x0a, 0x0f, 0xf0,
};
static const uint8_t bt_extref_bluez_read_missing_err[5] = {
	0x01, 0x0a, 0x0f, 0xf0, 0x01,
};

/*
 * Client-side error propagation -- SIG cases TP/GAR/CL/BI-01-C through
 * BI-05-C, [BLUEZ] unit/test-gatt.c:2774-2811.  Every one of these is the
 * SAME ATT_READ_REQ (handle 0x0003) answered with a different Error Code, and
 * BlueZ asserts the client surfaces each distinctly.  The set is the
 * enumeration of the read-denial codes a client must not conflate:
 *
 *   BI-01-C  0x01  Invalid Handle              (request was handle 0x0000)
 *   BI-02-C  0x02  Read Not Permitted
 *   BI-03-C  0x08  Insufficient Authorization
 *   BI-04-C  0x05  Insufficient Authentication
 *   BI-05-C  0x0C  Insufficient Encryption Key Size
 */
static const uint8_t bt_extref_bluez_read_h3_req[3] = {
	0x0a, 0x03, 0x00,
};
static const uint8_t bt_extref_bluez_read_h3_err_read_not_permitted[5] = {
	0x01, 0x0a, 0x03, 0x00, 0x02,
};
static const uint8_t bt_extref_bluez_read_h3_err_authorization[5] = {
	0x01, 0x0a, 0x03, 0x00, 0x08,
};
static const uint8_t bt_extref_bluez_read_h3_err_authentication[5] = {
	0x01, 0x0a, 0x03, 0x00, 0x05,
};
static const uint8_t bt_extref_bluez_read_h3_err_key_size[5] = {
	0x01, 0x0a, 0x03, 0x00, 0x0c,
};
static const uint8_t bt_extref_bluez_read_h3_rsp[4] = {
	0x0b, 0x01, 0x02, 0x03,
};


/*
 * ================================================================
 * ATT SERVER BEHAVIOURAL RULES DERIVED FROM NIMBLE'S TESTS.
 *
 * These are not byte vectors; they are rules that NimBLE's unit tests assert
 * by construction, transcribed with the file and line that asserts them so
 * the derivation can be audited.  Each is expressed as a constant a test can
 * compare against, because a rule written only in a comment is a rule
 * nothing enforces.
 * ================================================================
 */

/*
 * An unknown REQUEST opcode is answered with Request Not Supported (0x06),
 * and the Attribute Handle In Error field is ZERO -- not the handle that
 * happened to follow the opcode in the malformed PDU.
 *
 * [NIMBLE] nimble/host/test/src/ble_att_svr_test.c:2101-2116,
 *   ble_att_svr_test_unsupported_req: sends opcode 0x3F followed by four
 *   octets and asserts verify_tx_err_rsp(0x3f, 0, REQ_NOT_SUPPORTED).  The
 *   0 is the handle field, checked explicitly.
 *
 * [SPEC] Vol 3, Part F, Section 3.4.1.1 and Table 3.4: "The attribute handle
 *   ... shall be set to 0x0000 if the request did not contain an attribute
 *   handle."  A server that echoes bytes 1..2 of an unknown opcode's payload
 *   is reporting a handle it never parsed.
 */
#define BT_EXTREF_NIMBLE_UNKNOWN_REQ_OPCODE		0x3f
#define BT_EXTREF_NIMBLE_UNKNOWN_REQ_ERROR		0x06
#define BT_EXTREF_NIMBLE_UNKNOWN_REQ_ERROR_HANDLE	0x0000

/*
 * An unknown COMMAND is silently discarded -- no Error Response, no response
 * of any kind.
 *
 * [NIMBLE] ble_att_svr_test.c:2118-2125: the same test then sets the opcode
 *   to 0x4F and asserts ble_hs_test_util_prev_tx_dequeue() == NULL.
 *
 * The two opcodes are both unallocated, and they sit on opposite sides of
 * bit 6, which [SPEC] Vol 3, Part F, Section 3.3.1 defines as the Command
 * Flag: 0x3F has it clear and is therefore a request, 0x4F has it set and is
 * therefore a command.  (They are not a single-bit pair -- 0x3F ^ 0x4F is
 * 0x70 -- so the flag is what the test varies, not the only bit that
 * differs.)  [SPEC]
 * Section 3.4.1.1: "No Error Response ... shall be sent in response to a
 * command."  Answering a command with an error is worse than useless: the
 * peer is not expecting a response and a malicious peer gets a free
 * amplification primitive.
 */
#define BT_EXTREF_NIMBLE_UNKNOWN_CMD_OPCODE		0x4f
#define BT_EXTREF_NIMBLE_ATT_COMMAND_FLAG		0x40

/*
 * Handle-range VALIDATION precedes the search for matching attributes.
 *
 * [NIMBLE] ble_att_svr_test.c:1145-1156, ble_att_svr_test_find_info:
 *   a Find Information Request with Starting Handle 0 is answered Invalid
 *   Handle (0x01) with the handle field 0; a request with Starting Handle
 *   101 and Ending Handle 100 is answered Invalid Handle with the handle
 *   field 101, i.e. the STARTING handle.
 * [NIMBLE] ble_att_svr_test.c:1158-1163: a well-formed range that simply
 *   contains no attributes is answered Attribute Not Found (0x0A), NOT
 *   Invalid Handle.
 *
 * That ordering is the substance.  Both faults are "there is nothing to
 * return", and a server that checks emptiness first answers 0x0A to a
 * malformed range -- which a client reasonably reads as "keep going, just
 * not here" rather than "your request was wrong".
 *
 * [SPEC] Vol 3, Part F, Section 3.4.3.1: "If the Starting Handle is greater
 * than the Ending Handle or the Starting Handle is 0x0000, an ATT_ERROR_RSP
 * PDU shall be sent with the Error Code parameter set to Invalid Handle."
 */
#define BT_EXTREF_NIMBLE_FIND_INFO_BAD_START		0x0000
#define BT_EXTREF_NIMBLE_FIND_INFO_INVERTED_START	101
#define BT_EXTREF_NIMBLE_FIND_INFO_INVERTED_END		100
#define BT_EXTREF_NIMBLE_FIND_INFO_EMPTY_START		200
#define BT_EXTREF_NIMBLE_FIND_INFO_EMPTY_END		300
#define BT_EXTREF_NIMBLE_ERR_INVALID_HANDLE		0x01
#define BT_EXTREF_NIMBLE_ERR_ATTR_NOT_FOUND		0x0a

/*
 * A single-handle read of a handle that does not exist is Invalid Handle
 * (0x01), for ATT_READ_REQ and for ATT_READ_BLOB_REQ alike.
 *
 * [NIMBLE] ble_att_svr_test.c:836-840 (ATT_READ_REQ, handle 0) and
 *   :924-928 (ATT_READ_BLOB_REQ, handle 0).
 * [BLUEZ]  unit/test-gatt.c:2830-2841, TP/GAR/SR/BI-02-C, for handle 0x0000
 *   and for the merely-absent handle 0xF00F.
 *
 * Two independent stacks, and BlueZ covers the case NimBLE does not: a
 * handle that is syntactically legal but unallocated.  Both answer 0x01.
 * The temptation is to answer 0x0A there, because "not found" is literally
 * what happened; 0x0A belongs to the range procedures and means "no more
 * matches above this point", which is a different statement entirely.
 */
#define BT_EXTREF_ATT_MISSING_SINGLE_HANDLE_ERROR	0x01

#endif /* TESTS_BLUETOOTH_SPEC_EXTREF_ATT_GATT_WIRE_H */
