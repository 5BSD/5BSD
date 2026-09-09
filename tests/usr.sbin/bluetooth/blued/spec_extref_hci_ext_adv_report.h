/*
 * EXTERNAL REFERENCE ORACLE: the HCI LE Extended Advertising Report event --
 * per-report layout, the field value tables, and what a host must do when one
 * report inside a multi-report event carries a reserved value.
 *
 * Hand-written.  Every value and every claim below is traceable to a named
 * external source; nothing here was derived from blued, and no value was
 * produced by running 5BSD code.
 *
 * WHY THIS HEADER EXISTS
 * ----------------------
 * This event is the single richest source of "reserved for future use" fields
 * in the whole HCI event set, and it is a BATCH: Num_Reports independent
 * reports share one event.  That combination creates a specific failure mode
 * that a single-report test never reaches:
 *
 *   a host that rejects the EVENT when it dislikes a REPORT loses every other
 *   report in the batch, including well-formed ones it had already parsed.
 *
 * Because each report's length is fully determined by its own Data_Length
 * field at a fixed offset, a bad report is always skippable.  There is
 * therefore no parsing reason to drop the batch; dropping it is a policy
 * choice, and the value tables below show that RFU values are not hypothetical
 * -- Primary_PHY 0x04 is ALREADY defined in this very specification revision.
 *
 * SPEC
 * ----
 * /usr/src/bluetooth-specs/Core_Specification_6_3.txt
 *
 *   Vol 4, Part E, Section 7.7.65.13 "LE Extended Advertising Report event",
 *   field tables at text lines 106160-106290.
 *
 *   Event_Type[i] bits 5-6, verbatim (text lines 106160-106166):
 *     "Data status:
 *        0b00 = Complete
 *        0b01 = Incomplete, more data to come
 *        0b10 = Incomplete, data truncated, no more to come
 *        0b11 = Reserved for future use"
 *     "All other bits    Reserved for future use"
 *
 *   Address_Type[i], verbatim (text lines 106167-106175):
 *     "0x00  Public Device Address
 *      0x01  Random Device Address
 *      0x02  Public Identity Address (corresponds to a resolved RPA)
 *      0x03  Random (static) Identity Address (corresponds to a resolved RPA)
 *      0xFF  No address provided (anonymous advertisement)
 *      All other values   Reserved for future use"
 *
 *   Primary_PHY[i], verbatim (text lines 106180-106191):
 *     "0x01  Advertiser PHY is LE 1M
 *      0x03  If the Advertising Coding Selection (Host Support) feature bit is
 *            set: Advertising PHY is LE Coded with S=8 data coding
 *            Otherwise: Advertiser PHY is LE Coded
 *      0x04  If the Advertising Coding Selection (Host Support) feature bit is
 *            set: Advertising PHY is LE Coded with S=2 data coding
 *            Otherwise: Reserved for future use
 *      All other values   Reserved for future use"
 *   -- 0x04 is the worked example of an RFU value that a real, shipping
 *   controller emits.  A host written against 5.2 that rejects it will drop
 *   reports from any 5.4+ controller using LE Coded S=2.
 *
 *   Advertising_SID[i], verbatim (text lines 106229-106233):
 *     "0x00 to 0x0F  Value of the Advertising SID subfield ...
 *      0xFF          No ADI field provided
 *      All other values   Reserved for future use"
 *
 *   TX_Power[i], verbatim (text lines 106236-106240):
 *     "0xXX  Range: -127 to +20   Units: dBm
 *      0x7F  Tx Power information not available"
 *   -- note this is the SAME range as RSSI.  There is no wider TX_Power range;
 *   a comment claiming TX_Power spans -127..+126 while RSSI is capped at +20
 *   is contradicted by this table.
 *
 *   RSSI[i], verbatim (text lines 106241-106245):
 *     "0xXX  Range: -127 to +20   Units: dBm
 *      0x7F  RSSI is not available"
 *
 *   Direct_Address_Type[i], verbatim (text lines 106256-106265):
 *     "0x00 ... 0x03 ...
 *      0xFE  Resolvable Private Address (Controller unable to resolve)
 *      All other values   Reserved for future use"
 *
 *   Data_Length[i], verbatim (text lines 106272-106275):
 *     "0 to 229  Length of the Data[i] field for each device which responded
 *      All other values   Reserved for future use"
 *
 *   Legacy PDU constraint, Section 7.7.65.13 Description (text line 106119):
 *     "If the Event_Type indicates a legacy PDU (bit 4 = 1), the Primary_PHY
 *      parameter shall indicate the LE 1M PHY and the Secondary_PHY parameter
 *      shall be set to 0x00."
 *   -- this is a requirement on the CONTROLLER.  Nothing obliges the Host to
 *   police it, and no reference does.
 *
 *   Vol 4, Part E, Section 7.7.65.2 "LE Advertising Report event": Num_Reports
 *   range 0x01 to 0x19 (text line 105134).
 *
 * REFERENCE IMPLEMENTATIONS -- BATCH SEMANTICS
 * --------------------------------------------
 * The question each reference answers: one report is unusable; what happens to
 * the others?
 *
 *   Apache NimBLE, snapshot commit 1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845:
 *     nimble/host/src/ble_hs_hci_evt.c:667-693 -- on an unrecognized legacy
 *     event type or a reserved data-status (0b11) it ADVANCES over the report
 *     and continues the loop:
 *         report = &report->data[report->data_len];
 *         continue;
 *     The remaining reports are still delivered.
 *
 *   Zephyr, snapshot commit 2665fcca3cced3aefb7202d6289991d8cc1dfcac:
 *     subsys/bluetooth/host/scan.c:1753-1763 and :881-884 -- stops the loop on
 *     a short/bad report, but reports already delivered STAND; it never
 *     retracts a prefix.  Zephyr performs no range validation on event_type,
 *     addr_type, RSSI, TX power, PHY or SID at all
 *     (create_ext_adv_info, scan.c:826-843, copies the raw values through).
 *
 *   BlueZ, snapshot commit 92305dc06ab8a6d89af2dae1d725cc4d51462ad1:
 *     monitor/packet.c:12605-12657 -- reserved primary/secondary PHY, reserved
 *     SID and reserved RSSI are rendered as "Reserved" and decoding CONTINUES.
 *     BlueZ userspace does not parse advertising reports on the data path at
 *     all; the Linux kernel does, and the daemon consumes mgmt Device Found.
 *
 * NO REFERENCE DISCARDS AN ALREADY-VALID REPORT BECAUSE A LATER REPORT IS BAD.
 * Two skip the bad report; one stops early but keeps the prefix.
 */
#ifndef TESTS_BLUETOOTH_SPEC_EXTREF_HCI_EXT_ADV_REPORT_H
#define TESTS_BLUETOOTH_SPEC_EXTREF_HCI_EXT_ADV_REPORT_H

#include <stdint.h>

/* Subevent codes, Vol 4 Part E 7.7.65.2 and 7.7.65.13. */
#define BT_EXTREF_LE_SUBEVENT_ADV_REPORT		0x02
#define BT_EXTREF_LE_SUBEVENT_EXT_ADV_REPORT		0x0d

/*
 * Num_Reports ranges.  Legacy: Vol 4 Part E 7.7.65.2, text line 105134.
 * Extended: Vol 4 Part E 7.7.65.13, text line 106221.
 */
#define BT_EXTREF_ADV_REPORT_NUM_REPORTS_MIN		0x01
#define BT_EXTREF_ADV_REPORT_NUM_REPORTS_MAX_LEGACY	0x19
#define BT_EXTREF_ADV_REPORT_NUM_REPORTS_MAX_EXTENDED	0x0a

/*
 * Fixed part of one extended report, in octets, preceding Data[i]:
 *   Event_Type(2) Address_Type(1) Address(6) Primary_PHY(1) Secondary_PHY(1)
 *   Advertising_SID(1) TX_Power(1) RSSI(1) Periodic_Advertising_Interval(2)
 *   Direct_Address_Type(1) Direct_Address(6) Data_Length(1)
 * Derived by adding the "Size:" column of the 7.7.65.13 field table
 * (text lines 106140-106275); Data_Length sits at the last fixed offset, so a
 * report's total length is always computable without interpreting any value.
 */
#define BT_EXTREF_EXT_ADV_REPORT_FIXED_LEN		24
#define BT_EXTREF_EXT_ADV_REPORT_DATA_LENGTH_OFFSET	23

/* Legacy report fixed part: Event_Type(1) Address_Type(1) Address(6)
 * Data_Length(1), then Data, then RSSI(1).  Vol 4 Part E 7.7.65.2. */
#define BT_EXTREF_ADV_REPORT_FIXED_LEN			9
#define BT_EXTREF_ADV_REPORT_DATA_LENGTH_OFFSET		8

/* Event_Type[i] data-status subfield, bits 5-6.  Text lines 106160-106166. */
#define BT_EXTREF_EXT_ADV_DATA_STATUS_SHIFT		5
#define BT_EXTREF_EXT_ADV_DATA_STATUS_MASK		0x03
#define BT_EXTREF_EXT_ADV_DATA_STATUS_COMPLETE		0x00
#define BT_EXTREF_EXT_ADV_DATA_STATUS_MORE		0x01
#define BT_EXTREF_EXT_ADV_DATA_STATUS_TRUNCATED		0x02
#define BT_EXTREF_EXT_ADV_DATA_STATUS_RESERVED		0x03

/* Event_Type[i] defined bits: 0-4 plus the 5-6 data-status subfield. */
#define BT_EXTREF_EXT_ADV_EVENT_TYPE_DEFINED_MASK	0x007f
#define BT_EXTREF_EXT_ADV_EVENT_TYPE_LEGACY_BIT		0x0010
#define BT_EXTREF_EXT_ADV_EVENT_TYPE_DIRECTED_BIT	0x0004

/* Address_Type[i].  Text lines 106167-106175. */
#define BT_EXTREF_ADV_ADDR_TYPE_PUBLIC			0x00
#define BT_EXTREF_ADV_ADDR_TYPE_RANDOM			0x01
#define BT_EXTREF_ADV_ADDR_TYPE_PUBLIC_IDENTITY		0x02
#define BT_EXTREF_ADV_ADDR_TYPE_RANDOM_IDENTITY		0x03
#define BT_EXTREF_ADV_ADDR_TYPE_ANONYMOUS		0xff

/* Direct_Address_Type[i] adds 0xFE.  Text lines 106256-106265. */
#define BT_EXTREF_ADV_DIRECT_ADDR_TYPE_UNRESOLVED	0xfe

/*
 * Primary_PHY[i] / Secondary_PHY[i].  Text lines 106180-106215.
 * 0x04 is DEFINED (LE Coded S=2 under Advertising Coding Selection), not
 * reserved -- see the note in the file header.
 */
#define BT_EXTREF_ADV_PHY_NONE				0x00	/* secondary only */
#define BT_EXTREF_ADV_PHY_1M				0x01
#define BT_EXTREF_ADV_PHY_2M				0x02	/* secondary only */
#define BT_EXTREF_ADV_PHY_CODED_S8			0x03
#define BT_EXTREF_ADV_PHY_CODED_S2			0x04

/* Advertising_SID[i].  Text lines 106229-106233. */
#define BT_EXTREF_ADV_SID_MAX				0x0f
#define BT_EXTREF_ADV_SID_NO_ADI			0xff

/*
 * TX_Power[i] AND RSSI[i] share one range and one "not available" value.
 * Text lines 106236-106245.  Both are int8 on the wire.
 */
#define BT_EXTREF_ADV_RSSI_MIN				(-127)
#define BT_EXTREF_ADV_RSSI_MAX				20
#define BT_EXTREF_ADV_RSSI_NOT_AVAILABLE		0x7f
#define BT_EXTREF_ADV_TX_POWER_MIN			(-127)
#define BT_EXTREF_ADV_TX_POWER_MAX			20
#define BT_EXTREF_ADV_TX_POWER_NOT_AVAILABLE		0x7f

/* Periodic_Advertising_Interval[i]: 0 = none, else >= 0x0006. */
#define BT_EXTREF_ADV_PERIODIC_INTERVAL_NONE		0x0000
#define BT_EXTREF_ADV_PERIODIC_INTERVAL_MIN		0x0006

/* Data_Length[i].  Text lines 106272-106275. */
#define BT_EXTREF_EXT_ADV_DATA_LENGTH_MAX		229
#define BT_EXTREF_ADV_DATA_LENGTH_MAX			31	/* legacy, 7.7.65.2 */

/*
 * Whether the legacy PHY tuple is a HOST-enforced check.  Section 7.7.65.13
 * (text line 106119) states it as a Controller requirement; 0 = the host does
 * not police it.  All three references: 0.
 */
#define BT_EXTREF_EXT_ADV_HOST_ENFORCES_LEGACY_PHY_TUPLE	0

/*
 * Batch disposition when one report in a multi-report event is unusable.
 */
enum bt_extref_adv_batch_policy {
	/* Skip the bad report, keep parsing the rest.  NimBLE. */
	BT_EXTREF_ADV_BATCH_SKIP_REPORT		= 0,
	/* Stop at the bad report, keep everything already delivered.  Zephyr. */
	BT_EXTREF_ADV_BATCH_STOP_KEEP_PREFIX	= 1,
	/* Discard the entire event including valid reports.  No reference. */
	BT_EXTREF_ADV_BATCH_DISCARD_EVENT	= 2
};

#define BT_EXTREF_ADV_BATCH_POLICY_NIMBLE	BT_EXTREF_ADV_BATCH_SKIP_REPORT
#define BT_EXTREF_ADV_BATCH_POLICY_ZEPHYR	BT_EXTREF_ADV_BATCH_STOP_KEEP_PREFIX
#define BT_EXTREF_ADV_BATCH_POLICY_BLUEZ	BT_EXTREF_ADV_BATCH_SKIP_REPORT

/*
 * 1 = at least one reference discards the whole event.  Recorded as 0 so a
 * test asserting "our policy matches some reference" fails loudly rather than
 * quietly finding a precedent that does not exist.
 */
#define BT_EXTREF_ADV_ANY_REFERENCE_DISCARDS_EVENT	0

/*
 * Whether each reference range-validates report fields at all (as opposed to
 * only bounds-checking lengths).  Zephyr does not; this is why a Zephyr host
 * cannot lose a batch to an RFU value.
 */
#define BT_EXTREF_ADV_RANGE_VALIDATES_ZEPHYR	0	/* scan.c:826-843 */
#define BT_EXTREF_ADV_RANGE_VALIDATES_NIMBLE	1	/* ble_hs_hci_evt.c:667-693 */
#define BT_EXTREF_ADV_RANGE_VALIDATES_BLUEZ	0	/* monitor/packet.c:12605-12657 */

#endif /* TESTS_BLUETOOTH_SPEC_EXTREF_HCI_EXT_ADV_REPORT_H */
