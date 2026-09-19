/*
 * EXTERNAL REFERENCE ORACLE: value ranges for LE Meta subevent fields whose
 * tables contain a SPECIAL value outside the ordinary range, or an explicit
 * "reserved for future use" row.
 *
 * Hand-written.  Every value and every claim below is traceable to a named
 * external source; nothing here was derived from blued, and no value was
 * produced by running 5BSD code.
 *
 * WHY THIS HEADER EXISTS
 * ----------------------
 * The recurring defect in this stack is not a missing check.  It is a check
 * written against the WRONG range: a field is validated against its ordinary
 * numeric range, the spec's out-of-band special value is not admitted, and the
 * decoder reports the whole event malformed.  The event is then discarded --
 * so a range error that looks cosmetic destroys a whole class of events.
 *
 * Every field below has the same shape: an ordinary range, PLUS at least one
 * value outside it that is legal and meaningful.  A validator that expresses
 * only the ordinary range is wrong for each one, and wrong in the direction
 * that loses data rather than accepting garbage.
 *
 * The companion trap: a field documented as having reserved values.  For those
 * the required behaviour is to IGNORE the value (or the field), never to
 * reject the event -- the whole point of an RFU row is that future controllers
 * will populate it while old hosts keep working.
 *
 * SPEC
 * ----
 * /usr/src/bluetooth-specs/Core_Specification_6_3.txt
 *
 *   Vol 4, Part E, Section 7.7.65.21 "LE Connectionless IQ Report event",
 *   Sync_Handle, verbatim (text lines 106983-106988):
 *     "Sync_Handle:   Size: 2 octets (12 bits meaningful)
 *       0xXXXX   Sync_Handle identifying the periodic advertising train.
 *                Range: 0x0000 to 0x0EFF
 *       0x0FFF   Receiver Test"
 *   -- 0x0FFF is NOT a handle and NOT reserved; it is the value the controller
 *   uses for IQ reports generated during HCI_LE_Receiver_Test.  A validator
 *   written as "handle <= 0x0EFF" discards every IQ report produced by a
 *   direction-finding receiver test.
 *
 *   Vol 4, Part E, Section 7.7.65.21, Channel_Index, verbatim
 *   (text lines 106990-106993):
 *     "0x00 to 0x27   The index of the channel on which the packet was
 *                     received.
 *      Note: 0x25 to 0x27 can be used only for packets generated during test
 *      modes."
 *
 *   Vol 4, Part E, Section 7.7.65.22 "LE Connection IQ Report event",
 *   Data_Channel_Index, verbatim (text lines 107160-107163):
 *     "0x00 to 0x24   The index of the data channel on which the Data Physical
 *                     Channel PDU was received."
 *   -- the two IQ reports have DIFFERENT channel ranges (0x27 vs 0x24),
 *   because only the connectionless one can carry test-mode channels.  Sharing
 *   one bound between them is wrong in one direction or the other.
 *
 *   Vol 4, Part E, Section 7.7.65.32 "LE Path Loss Threshold event",
 *   Zone_Entered, verbatim (text lines 108389-108395):
 *     "0x00   Entered low zone
 *      0x01   Entered middle zone
 *      0x02   Entered high zone
 *      All other values   Reserved for future use"
 *   and, from the Description (text lines 108359-108360), verbatim:
 *     "The Zone_Entered parameter indicates which zone was entered. If
 *      Current_Path_Loss is set to 0xFF then Zone_Entered shall be ignored."
 *   -- note the mandated verb for the 0xFF case is "ignored", not "rejected".
 *
 *   Vol 4, Part E, Section 7.7.65.33 "LE Transmit Power Reporting event",
 *   TX_Power_Level, verbatim (text lines 108510-108514):
 *     "0xXX   Transmit power level   Range: -127 to 20   Units: dBm
 *      0x7E   Remote device is not managing power levels on this PHY.
 *      0x7F   Transmit power level is not available"
 *
 *   Section 7.7.65.33, TX_Power_Level_Flag, verbatim (text lines 108515-108519):
 *     "Bit Number   Parameter Description
 *      0            Transmit power level is at minimum level
 *      1            Transmit power level is at maximum level
 *      All other bits   Reserved for future use"
 *
 *   Section 7.7.65.33, Delta, verbatim (text lines 108520-108525):
 *     "0xXX   Change in transmit power level (positive indicates increased
 *             power, negative indicates decreased power, zero indicates
 *             unchanged)   Units: dB
 *      0x7F   Change is not available or is out of range."
 *   and, from the Description (text line 108487), verbatim:
 *     "When this event is generated with Reason set to 0x02, Delta shall be set
 *      to zero. Delta shall be ignored if the TX_Power_Level parameter is set
 *      to 0x7E."
 *   -- so Delta IS constrained, contrary to any comment asserting that the
 *   section places no constraint on Delta for any Reason.
 *
 *   Section 7.7.65.33, Reason, verbatim (text lines 108494-108499):
 *     "0x00   Local transmit power changed
 *      0x01   Remote transmit power changed
 *      0x02   HCI_LE_Read_Remote_Transmit_Power_Level command completed
 *      All other values   Reserved for future use"
 *
 *   Vol 4, Part E, Section 7.7.65.15 "LE Periodic Advertising Report event",
 *   Data_Status, verbatim (text lines 106637-106644):
 *     "0x00   Data complete
 *      0x01   Data incomplete, more data to come
 *      0x02   Data incomplete, data truncated, no more to come
 *      0xFF   Failed to receive an AUX_SYNC_SUBEVENT_IND PDU
 *      All other values   Reserved for future use"
 *   -- 0xFF belongs to Periodic Advertising with Responses (5.4) and is
 *   therefore outside a 5.2 target, but it is recorded here because a
 *   validator written as "status <= 0x02" rejects it unconditionally, i.e. the
 *   host breaks against a newer controller rather than ignoring a value it
 *   does not need.
 *
 *   Section 7.7.65.15, TX_Power and RSSI (text lines 106591-106603): both
 *   "Range: -127 to +20" with 0x7F meaning not available.  The two fields have
 *   the SAME range; TX_Power is not wider than RSSI.
 *
 * REFERENCE IMPLEMENTATIONS
 * -------------------------
 *   Zephyr, snapshot commit 2665fcca3cced3aefb7202d6289991d8cc1dfcac:
 *     subsys/bluetooth/host/hci_core.c:3148-3153 (IQ reports) and :3160-3162
 *     (transmit power reporting) enforce a MINIMUM LENGTH and nothing else --
 *     no value-range validation on any of the fields above.
 *
 *   Apache NimBLE, snapshot commit 1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845:
 *     nimble/host/src/ble_hs_hci_evt.c:164 -- length check only, same as
 *     Zephyr.
 *
 *   BlueZ, snapshot commit 92305dc06ab8a6d89af2dae1d725cc4d51462ad1:
 *     monitor/packet.c renders unknown values as "Reserved" and continues
 *     decoding; it never treats an RFU value as a framing error.
 *
 * NO REFERENCE REJECTS AN EVENT FOR AN OUT-OF-RANGE OR RESERVED FIELD VALUE.
 * Validating these fields is defensible; the disposition on failure is where
 * this stack is alone.
 */
#ifndef TESTS_BLUETOOTH_SPEC_EXTREF_HCI_LE_META_RANGES_H
#define TESTS_BLUETOOTH_SPEC_EXTREF_HCI_LE_META_RANGES_H

#include <stdint.h>

/* Subevent codes referenced by this header, Vol 4 Part E 7.7.65.x. */
#define BT_EXTREF_LE_SUBEVENT_CONNECTIONLESS_IQ_REPORT	0x15
#define BT_EXTREF_LE_SUBEVENT_CONNECTION_IQ_REPORT	0x16
#define BT_EXTREF_LE_SUBEVENT_PER_ADV_REPORT		0x0f
#define BT_EXTREF_LE_SUBEVENT_PATH_LOSS_THRESHOLD	0x20
#define BT_EXTREF_LE_SUBEVENT_TX_POWER_REPORTING	0x21

/*
 * Ordinary connection/sync handle range, Vol 4 Part E (12 bits meaningful).
 */
#define BT_EXTREF_LE_HANDLE_MAX				0x0eff

/*
 * Section 7.7.65.21: the Connectionless IQ Report Sync_Handle admits ONE value
 * above the ordinary range.  A validator for this field is
 *   (h <= BT_EXTREF_LE_HANDLE_MAX || h == BT_EXTREF_IQ_SYNC_HANDLE_RECEIVER_TEST)
 * and anything narrower discards receiver-test IQ reports.
 */
#define BT_EXTREF_IQ_SYNC_HANDLE_RECEIVER_TEST		0x0fff

/*
 * The two IQ reports use DIFFERENT channel-index bounds.  7.7.65.21 vs
 * 7.7.65.22.
 */
#define BT_EXTREF_CONNECTIONLESS_IQ_CHANNEL_INDEX_MAX	0x27
#define BT_EXTREF_CONNECTION_IQ_CHANNEL_INDEX_MAX	0x24

/* Section 7.7.65.32, Zone_Entered. */
#define BT_EXTREF_PATH_LOSS_ZONE_LOW			0x00
#define BT_EXTREF_PATH_LOSS_ZONE_MIDDLE			0x01
#define BT_EXTREF_PATH_LOSS_ZONE_HIGH			0x02
#define BT_EXTREF_PATH_LOSS_ZONE_MAX_DEFINED		0x02
/* Current_Path_Loss == 0xFF: "Zone_Entered shall be ignored" (text 108359). */
#define BT_EXTREF_PATH_LOSS_CURRENT_UNAVAILABLE		0xff

/* Section 7.7.65.33, TX_Power_Level. */
#define BT_EXTREF_TX_POWER_LEVEL_MIN			(-127)
#define BT_EXTREF_TX_POWER_LEVEL_MAX			20
#define BT_EXTREF_TX_POWER_LEVEL_NOT_MANAGING		0x7e
#define BT_EXTREF_TX_POWER_LEVEL_NOT_AVAILABLE		0x7f

/*
 * Section 7.7.65.33, TX_Power_Level_Flag: bits 0 and 1 are defined, everything
 * else is RFU.  The mask names the DEFINED bits; the required behaviour for
 * the others is to ignore them, not to reject the event.
 */
#define BT_EXTREF_TX_POWER_FLAG_MIN_LEVEL		0x01
#define BT_EXTREF_TX_POWER_FLAG_MAX_LEVEL		0x02
#define BT_EXTREF_TX_POWER_FLAG_DEFINED_MASK		0x03

/* Section 7.7.65.33, Delta. */
#define BT_EXTREF_TX_POWER_DELTA_NOT_AVAILABLE		0x7f
/* "When this event is generated with Reason set to 0x02, Delta shall be set to
 * zero." (text line 108487) */
#define BT_EXTREF_TX_POWER_DELTA_ZERO_WHEN_REASON	0x02

/* Section 7.7.65.33, Reason. */
#define BT_EXTREF_TX_POWER_REASON_LOCAL_CHANGED		0x00
#define BT_EXTREF_TX_POWER_REASON_REMOTE_CHANGED	0x01
#define BT_EXTREF_TX_POWER_REASON_READ_COMPLETED	0x02
#define BT_EXTREF_TX_POWER_REASON_MAX_DEFINED		0x02

/* Section 7.7.65.15, Periodic Advertising Report Data_Status. */
#define BT_EXTREF_PER_ADV_DATA_STATUS_COMPLETE		0x00
#define BT_EXTREF_PER_ADV_DATA_STATUS_MORE		0x01
#define BT_EXTREF_PER_ADV_DATA_STATUS_TRUNCATED		0x02
#define BT_EXTREF_PER_ADV_DATA_STATUS_AUX_FAILED	0xff	/* 5.4 PAwR */

/*
 * Section 7.7.65.15: TX_Power and RSSI share one range and one sentinel.
 * Stated as separate names so a test can assert the EQUALITY rather than
 * assume it.
 */
#define BT_EXTREF_PER_ADV_TX_POWER_MIN			(-127)
#define BT_EXTREF_PER_ADV_TX_POWER_MAX			20
#define BT_EXTREF_PER_ADV_TX_POWER_NOT_AVAILABLE	0x7f
#define BT_EXTREF_PER_ADV_RSSI_MIN			(-127)
#define BT_EXTREF_PER_ADV_RSSI_MAX			20
#define BT_EXTREF_PER_ADV_RSSI_NOT_AVAILABLE		0x7f

/*
 * The required disposition when a field carries a reserved or unrecognized
 * value.  0 = ignore the value / the field and keep the event; 1 = reject the
 * event.  The spec's RFU rows and all three references say 0.
 */
#define BT_EXTREF_LE_META_RFU_REJECTS_EVENT		0

/* Whether each reference range-validates these fields at all. */
#define BT_EXTREF_LE_META_RANGE_VALIDATES_ZEPHYR	0	/* hci_core.c:3148-3162 */
#define BT_EXTREF_LE_META_RANGE_VALIDATES_NIMBLE	0	/* ble_hs_hci_evt.c:164 */
#define BT_EXTREF_LE_META_RANGE_VALIDATES_BLUEZ		0	/* monitor/packet.c */

#endif /* TESTS_BLUETOOTH_SPEC_EXTREF_HCI_LE_META_RANGES_H */
