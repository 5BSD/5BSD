/*
 * EXTERNAL REFERENCE ORACLE: the LE Extended Advertising Report event -- its
 * field layout, its sentinel values, and the reassembly contract its Data
 * Status field defines.
 *
 * Hand-transcribed from the named external sources below.  Every constant and
 * every quoted sentence is traceable to one of them; nothing here was derived
 * from blued and no value was produced by running 5BSD code.
 *
 * WHY THIS HEADER EXISTS
 * ----------------------
 * The extended advertising report is where a Bluetooth 5 host most often
 * silently loses data.  Three things conspire:
 *
 *   1. The controller is PERMITTED to split one advertisement across several
 *      HCI events, and the split point is not an AD-structure boundary.  A
 *      host that AD-parses each report independently parses fragments of an
 *      AD structure as if they were whole ones.
 *   2. The correct behaviour is not "skip the fragments" -- it is to
 *      CONCATENATE them and parse the join.  A host that recognises
 *      fragmentation and then declines to parse anything ends up reporting a
 *      MAC address with no name, no UUIDs and no manufacturer data, which
 *      looks like a device that advertises nothing rather than like a bug.
 *   3. There is a third status, "truncated", meaning the controller tried and
 *      failed.  It is not an error to suppress silently and not a complete
 *      report to accept; the application has to be able to tell.
 *
 * SOURCES
 * -------
 * SPEC: /usr/src/bluetooth-specs/Core_Specification_6_3.txt
 *   Vol 4 Part E Section 7.7.65.13 (LE Extended Advertising Report event),
 *     text lines 106026-106300
 *   Vol 4 Part E Section 7.7.65.2 (LE Advertising Report event, legacy),
 *     text lines 105120-105200
 *   Vol 6 Part B Section 4.4.3.5 (scanning state, report and duplicate
 *     rules), text lines 138900-138950
 *   Vol 4 Part E Sections 7.8.10 and 7.8.64 (Set Scan Parameters, legacy and
 *     extended), text lines 112590-112730 and 117800-117900
 */

#ifndef SPEC_EXTREF_GAP_EXT_ADV_REPORT_H
#define SPEC_EXTREF_GAP_EXT_ADV_REPORT_H

#include <stdint.h>

/*
 * =========================================================================
 * Event_Type bit assignments, Section 7.7.65.13, text lines 106196-106210.
 *
 * Bits 0-4 are properties; bits 5-6 are the two-bit Data Status field.  Bits
 * 7-15 are reserved for future use, so a report whose Event_Type has any bit
 * above 6 set is malformed.
 * =========================================================================
 */
#define SPEC_EXT_ADV_EVT_CONNECTABLE		0x0001	/* bit 0 */
#define SPEC_EXT_ADV_EVT_SCANNABLE		0x0002	/* bit 1 */
#define SPEC_EXT_ADV_EVT_DIRECTED		0x0004	/* bit 2 */
#define SPEC_EXT_ADV_EVT_SCAN_RESPONSE		0x0008	/* bit 3 */
#define SPEC_EXT_ADV_EVT_LEGACY_PDU		0x0010	/* bit 4 */
#define SPEC_EXT_ADV_EVT_DATA_STATUS_SHIFT	5
#define SPEC_EXT_ADV_EVT_DATA_STATUS_MASK	0x0060	/* bits 5-6 */
#define SPEC_EXT_ADV_EVT_DEFINED_MASK		0x007F

/*
 * =========================================================================
 * Data Status.
 *
 * Section 7.7.65.13, text lines 106203-106209:
 *   0b00  Complete
 *   0b01  Incomplete, more data to come
 *   0b10  Incomplete, data truncated, no more to come
 *   0b11  Reserved for future use
 *
 * Section 7.7.65.13, text lines 106057-106063, verbatim -- the reassembly
 * contract, and the key to what must be used as the reassembly key:
 *   "The Controller may split the data from a single advertisement or scan
 *    response (whether one PDU or several) into several reports. If so, each
 *    report except the last shall have an Event_Type with a data status field
 *    of 'incomplete, more data to come', while the last shall have the value
 *    'complete'; the Address_Type, Address, Advertising_SID, Primary_PHY, and
 *    Secondary_PHY fields shall be the same in all the reports."
 *
 * Note what that sentence does NOT include: bit 3, the scan-response bit.
 * The invariant fields are the five listed, and the SCAN_RESPONSE bit is not
 * one of them.  Section 7.7.65.13, text lines 106065-106067, verbatim:
 *   "When a scan response is received, bits 0 to 2 and 4 of the event type
 *    shall indicate the properties of the original advertising event and the
 *    Advertising_SID field should be set to the value in the original
 *    scannable advertisement."
 * -- so a scan response carries the SAME Advertising_SID as the advertisement
 * it answers.  A reassembly key of (address type, address, SID) alone will
 * therefore match a scan response against an outstanding advertisement chain.
 * The scan-response bit must be part of the key, or the two streams must be
 * tracked separately, and Vol 6 Part B requires exactly that separation
 * anyway (see the duplicate-filtering quote below).
 *
 * Section 7.7.65.13, text lines 106069-106071, verbatim -- what truncated
 * actually means:
 *   "An Event_Type with a data status field of 'incomplete, data truncated'
 *    shall indicate that the Controller attempted to receive an AUX_CHAIN_IND
 *    PDU but was not successful or received it but was unable to store the
 *    data."
 * =========================================================================
 */
#define SPEC_EXT_ADV_DATA_STATUS_COMPLETE	0x00
#define SPEC_EXT_ADV_DATA_STATUS_INCOMPLETE	0x01	/* more to come */
#define SPEC_EXT_ADV_DATA_STATUS_TRUNCATED	0x02	/* no more coming */
#define SPEC_EXT_ADV_DATA_STATUS_RFU		0x03

#define SPEC_EXT_ADV_DATA_STATUS(evt_type)				\
	(((evt_type) & SPEC_EXT_ADV_EVT_DATA_STATUS_MASK) >>		\
	 SPEC_EXT_ADV_EVT_DATA_STATUS_SHIFT)

/*
 * =========================================================================
 * Table 7.1: legacy PDU types encoded as extended Event_Type values.
 *
 * Section 7.7.65.13, text lines 106074-106081.  When bit 4 (legacy PDU) is
 * set, Event_Type takes exactly one of these six values and no other.
 * =========================================================================
 */
#define SPEC_EXT_ADV_LEGACY_EVT_ADV_NONCONN_IND		0x0010
#define SPEC_EXT_ADV_LEGACY_EVT_ADV_SCAN_IND		0x0012
#define SPEC_EXT_ADV_LEGACY_EVT_ADV_IND			0x0013
#define SPEC_EXT_ADV_LEGACY_EVT_ADV_DIRECT_IND		0x0015
#define SPEC_EXT_ADV_LEGACY_EVT_SCAN_RSP_TO_ADV_SCAN_IND	0x001A
#define SPEC_EXT_ADV_LEGACY_EVT_SCAN_RSP_TO_ADV_IND	0x001B

static const uint16_t bt_extref_gap_ext_report_legacy_evt[6] = {
	SPEC_EXT_ADV_LEGACY_EVT_ADV_NONCONN_IND,
	SPEC_EXT_ADV_LEGACY_EVT_ADV_SCAN_IND,
	SPEC_EXT_ADV_LEGACY_EVT_ADV_IND,
	SPEC_EXT_ADV_LEGACY_EVT_ADV_DIRECT_IND,
	SPEC_EXT_ADV_LEGACY_EVT_SCAN_RSP_TO_ADV_SCAN_IND,
	SPEC_EXT_ADV_LEGACY_EVT_SCAN_RSP_TO_ADV_IND,
};

/*
 * Section 7.7.65.13, text lines 106083-106086, verbatim:
 *   "If the Event_Type indicates a legacy PDU (bit 4 = 1), the Primary_PHY
 *    parameter shall indicate the LE 1M PHY and the Secondary_PHY parameter
 *    shall be set to 0x00."
 *
 * And text lines 106096-106098, verbatim:
 *   "These parameters shall be ignored for undirected advertising event types
 *    (bit 2 = 0)."  [Direct_Address_Type and Direct_Address]
 */

/*
 * =========================================================================
 * Field ranges and sentinels.
 *
 * Num_Reports, Section 7.7.65.13, text lines 106215-106219:
 *   "0x01 to 0x0A  Number of separate reports in the event"
 *   "All other values  Reserved for future use"
 * Legacy Num_Reports, Section 7.7.65.2, text lines 105126-105128: 0x01 to 0x19.
 *
 * RSSI, text lines 106259-106264 (and 105191-105196 for legacy):
 *   "0xXX  Range: -127 to +20  Units: dBm"
 *   "0x7F  RSSI is not available"
 *
 * TX_Power, text lines 106251-106257:
 *   "0xXX  Range: -127 to +20  Units: dBm"
 *   "0x7F  Tx Power information not available"
 * -- note that TX_Power is capped at +20 dBm exactly as RSSI is.  There is no
 * wider "-127 to +126" range for TX power anywhere in this section; values
 * 0x15 through 0x7E are reserved, not merely improbable.
 *
 * Periodic_Advertising_Interval, text lines 106266-106272:
 *   "0x0000  No periodic advertising"
 *   "0x0006 to 0xFFFF  Range 7.5 ms to 81,918.75 s, Time = N x 1.25 ms"
 * -- values 0x0001 to 0x0005 are not legal.
 *
 * Data_Length, text lines 106292-106294: "0 to 229".
 * Legacy Data_Length, Section 7.7.65.2, text lines 105172-105174: "0x00 to 0x1F".
 *
 * Advertising_SID, text lines 106236-106238, verbatim:
 *   "Value of the Advertising SID subfield in the ADI field of the PDU or,
 *    for scan responses, in the ADI field of the original scannable
 *    advertisement"
 * =========================================================================
 */
#define SPEC_EXT_ADV_NUM_REPORTS_MIN		0x01
#define SPEC_EXT_ADV_NUM_REPORTS_MAX		0x0A
#define SPEC_LEGACY_ADV_NUM_REPORTS_MIN		0x01
#define SPEC_LEGACY_ADV_NUM_REPORTS_MAX		0x19

#define SPEC_ADV_RSSI_MIN_DBM			(-127)
#define SPEC_ADV_RSSI_MAX_DBM			20
#define SPEC_ADV_RSSI_NOT_AVAILABLE		0x7F

#define SPEC_ADV_TX_POWER_MIN_DBM		(-127)
#define SPEC_ADV_TX_POWER_MAX_DBM		20
#define SPEC_ADV_TX_POWER_NOT_AVAILABLE		0x7F

#define SPEC_PERIODIC_ADV_INTERVAL_NONE		0x0000
#define SPEC_PERIODIC_ADV_INTERVAL_MIN		0x0006

#define SPEC_EXT_ADV_DATA_LENGTH_MAX		229
#define SPEC_LEGACY_ADV_DATA_LENGTH_MAX		0x1F	/* 31 */

/*
 * The controller's minimum storage obligation, Vol 6 Part B Section 4.4.3.5,
 * text lines 138919-138922, verbatim:
 *   "the Controller must be able to store and report to the Host at least 251
 *    octets of data from a single advertisement or scan response (irrespective
 *    of the number of PDUs used to transmit the data) if the Controller
 *    supports LE extended advertising and 31 octets otherwise."
 *
 * 251 > 229, so an advertisement at the controller's guaranteed capacity
 * CANNOT fit in one report.  Fragmentation is not an exotic case a host may
 * hope not to meet; it is arithmetically unavoidable above 229 octets.  A
 * host without reassembly has a hard ceiling of 229 octets of advertising
 * data it can ever observe, against a 1650-octet host-side maximum it may
 * itself transmit.
 */
#define SPEC_EXT_ADV_CONTROLLER_MIN_STORAGE	251

/*
 * =========================================================================
 * Duplicate filtering, Vol 6 Part B Section 4.4.3.5.
 *
 * Text lines 138927-138934, verbatim:
 *   "Where a received ADV_EXT_IND PDU contains an ADI field, a duplicate
 *    advertising report is an advertising report for the same device address
 *    where the previous report that contained an ADI value with the same
 *    Advertising SID also had the same Advertising DID. For this purpose, all
 *    anonymous advertising is treated as being from a single device different
 *    to all non-anonymous devices."
 *   "Where the ADV_EXT_IND PDU does not contain an ADI field or a legacy PDU
 *    was received, a duplicate advertising report is an advertising report for
 *    the same device address while the Link Layer stays in the Scanning state."
 *
 * Text lines 138937-138939, verbatim -- the rule that makes name resolution
 * from a scan response work at all:
 *   "Advertising data reports and scan data reports shall be processed
 *    separately when determining duplicate advertising reports; i.e., an
 *    advertising data report shall not be treated as a duplicate of a scan
 *    response report or vice versa."
 *
 * Text lines 138943-138946, verbatim:
 *   "In either case the actual data may change; advertising data or scan
 *    response data is not considered significant when determining duplicate
 *    advertising reports. However, if not all the subordinate set of an
 *    advertisement or scan response was received (i.e., an incomplete report),
 *    a subsequent report that contains more of the data should not be"
 *    [treated as a duplicate]
 *
 * Text line 138924, verbatim -- duplicate filtering is advisory:
 *   "The Host may request that duplicate advertising reports are filtered and
 *    so not sent. The Controller may nevertheless send a duplicate of any
 *    report."
 * -- a host may not rely on Filter_Duplicates for correctness, only for load.
 * =========================================================================
 */

/*
 * Filter_Duplicates values, Section 7.8.64 (LE Set Extended Scan Enable):
 *   0x00 Duplicate filtering disabled
 *   0x01 Duplicate filtering enabled
 *   0x02 Duplicate filtering enabled, reset each scan period
 * Error condition, text lines 117994-117996, verbatim:
 *   "Filter_Duplicates is set to 0x02 and either Period or Duration is set to
 *    0."  -> Invalid HCI Command Parameters (0x12)
 * -- so 0x02 is only legal alongside a non-zero Period AND Duration.
 *
 * Section 7.8.11 (legacy LE Set Scan Enable), text lines 112724-112725,
 * verbatim: "If LE_Scan_Enable is set to 0x00 then Filter_Duplicates shall be
 * ignored."
 */
#define SPEC_SCAN_FILTER_DUP_DISABLED		0x00
#define SPEC_SCAN_FILTER_DUP_ENABLED		0x01
#define SPEC_SCAN_FILTER_DUP_RESET_EACH_PERIOD	0x02

/*
 * =========================================================================
 * Scan interval and window.
 *
 * LEGACY, Section 7.8.10, text lines 112639-112653:
 *   LE_Scan_Interval and LE_Scan_Window: Range 0x0004 to 0x4000,
 *   Time = N x 0.625 ms, i.e. 2.5 ms to 10.24 s.  Default 0x0010.
 *
 * EXTENDED, Section 7.8.64, text lines 117878-117890:
 *   Scan_Interval[i] and Scan_Window[i]: Range 0x0004 to 0xFFFF,
 *   Time = N x 0.625 ms, i.e. 2.5 ms to 40.959375 s.
 *
 * The two commands have DIFFERENT upper bounds.  Applying the legacy 0x4000
 * cap to the extended command rejects a range of legal values -- exactly the
 * band a low-duty-cycle background scanner wants.
 *
 * Section 7.8.10, text lines 112601-112606, verbatim:
 *   "The LE_Scan_Window parameter shall always be set to a value smaller or
 *    equal to the value set for the LE_Scan_Interval parameter. If they are
 *    set to the same value scanning should be run continuously."
 * -- window == interval is explicitly legal, not an off-by-one to reject.
 *
 * Duration, Section 7.8.64, text lines 118036-118041:
 *   0x0000 = "Scan continuously until explicitly disable"
 *   0x0001 to 0xFFFF = Range 10 ms to 655.35 s, Time = N x 10 ms
 * =========================================================================
 */
#define SPEC_SCAN_INTERVAL_LEGACY_MIN		0x0004
#define SPEC_SCAN_INTERVAL_LEGACY_MAX		0x4000
#define SPEC_SCAN_INTERVAL_LEGACY_DEFAULT	0x0010
#define SPEC_SCAN_INTERVAL_EXT_MIN		0x0004
#define SPEC_SCAN_INTERVAL_EXT_MAX		0xFFFF
#define SPEC_SCAN_DURATION_CONTINUOUS		0x0000

/*
 * Scanning_PHYs bit field, Section 7.8.64, text lines 117862-117866:
 *   Bit 0 = LE 1M PHY, Bit 2 = LE Coded PHY, all other bits reserved.
 * (Bit 1 would be the LE 2M PHY, on which no advertising is transmitted on
 * the primary advertising physical channel, so it is not offered here.)
 */
#define SPEC_SCAN_PHY_1M			0x01
#define SPEC_SCAN_PHY_CODED			0x04
#define SPEC_SCAN_PHY_DEFINED_MASK		0x05

/*
 * Primary_PHY in a report, Section 7.7.65.13, text lines 106192-106203:
 *   0x01 = LE 1M
 *   0x03 = LE Coded (S=8 when the Advertising Coding Selection host-support
 *          feature bit is set; plain "LE Coded" otherwise)
 *   0x04 = LE Coded S=2, ONLY when Advertising Coding Selection host support
 *          is set; reserved for future use otherwise.
 * Advertising Coding Selection is a Bluetooth 6.0 feature.  Against a 5.2
 * target a Primary_PHY of 0x04 is a reserved value, not an S=2 report.
 * Secondary_PHY additionally permits 0x00 ("No packets on the secondary
 * advertising physical channel") and 0x02 (LE 2M).
 */
#define SPEC_ADV_PHY_1M				0x01
#define SPEC_ADV_PHY_2M				0x02
#define SPEC_ADV_PHY_CODED			0x03
#define SPEC_ADV_SECONDARY_PHY_NONE		0x00

#endif /* SPEC_EXTREF_GAP_EXT_ADV_REPORT_H */
