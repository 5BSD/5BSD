/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * EXTERNAL REFERENCE ORACLE: HID over GATT characteristic inventory, the
 * per-Report-Type characteristic property matrix, and the enumerated values
 * of the control-point-like characteristics.
 *
 * Hand-written.  Every value below is traceable to a named external source.
 * Nothing here was derived from blued, and no value was produced by running
 * 5BSD code.  This header includes no blued header and compiles standalone.
 *
 * SOURCES
 * -------
 *   [AN]    /usr/src/bluetooth-specs/Assigned_Numbers.html
 *           Bluetooth SIG Assigned Numbers, GATT Services / Characteristics /
 *           Descriptors tables.
 *   [HIDS]  /usr/src/bluetooth-specs/HIDS_v1.1.txt
 *           HID Service Specification v1.1 (in-tree text; title page line 26
 *           records "v1.1 ... 2026-04-21 Adopted by the Bluetooth SIG Board
 *           of Directors").
 *   [HOGP]  /usr/src/bluetooth-specs/HOGP_v1.1.txt
 *           HID Over GATT Profile v1.1 (in-tree text; title page line 5
 *           records "Version: v1.1", line 6 "Version Date: 2025-08-05").
 *
 * NOTE ON VERSION NUMBERING.  Several comments and test headers in this tree
 * cite "HOGP 1.1.1".  No such version exists; the SIG adopted 1.0, 1.1 and
 * 1.2.  The section numbers those comments use match the in-tree HOGP v1.1
 * text, so the intended citation is v1.1.  This header cites v1.1 only.
 */

#ifndef TESTS_BLUETOOTH_SPEC_EXTREF_HOGP_CHARACTERISTICS_H
#define TESTS_BLUETOOTH_SPEC_EXTREF_HOGP_CHARACTERISTICS_H

#include <stdint.h>

/*
 * 1. UUIDs.  [AN], GATT Services and GATT Characteristics and Object Types
 *    tables; the descriptor UUIDs come from the GATT Descriptors table.
 *    Transcribed row by row; each value appears in [AN] in the same row as
 *    the quoted name.
 */
#define BT_EXTREF_UUID_HID_SERVICE		0x1812	/* "Human Interface Device" */
#define BT_EXTREF_UUID_BATTERY_SERVICE		0x180F	/* "Battery" */
#define BT_EXTREF_UUID_DEVICE_INFORMATION	0x180A	/* "Device Information" */
#define BT_EXTREF_UUID_SCAN_PARAMETERS		0x1813	/* "Scan Parameters" */

#define BT_EXTREF_UUID_BOOT_KB_INPUT_REPORT	0x2A22	/* "Boot Keyboard Input Report" */
#define BT_EXTREF_UUID_BOOT_KB_OUTPUT_REPORT	0x2A32	/* "Boot Keyboard Output Report" */
#define BT_EXTREF_UUID_BOOT_MOUSE_INPUT_REPORT	0x2A33	/* "Boot Mouse Input Report" */
#define BT_EXTREF_UUID_HID_INFORMATION		0x2A4A	/* "HID Information" */
#define BT_EXTREF_UUID_REPORT_MAP		0x2A4B	/* "Report Map" */
#define BT_EXTREF_UUID_HID_CONTROL_POINT	0x2A4C	/* "HID Control Point" */
#define BT_EXTREF_UUID_REPORT			0x2A4D	/* "Report" */
#define BT_EXTREF_UUID_PROTOCOL_MODE		0x2A4E	/* "Protocol Mode" */
#define BT_EXTREF_UUID_PNP_ID			0x2A50	/* "PnP ID" */
#define BT_EXTREF_UUID_BATTERY_LEVEL		0x2A19	/* "Battery Level" */

#define BT_EXTREF_UUID_CCCD			0x2902	/* "Client Characteristic Configuration" */
#define BT_EXTREF_UUID_EXTERNAL_REPORT_REF	0x2907	/* "External Report Reference" */
#define BT_EXTREF_UUID_REPORT_REFERENCE		0x2908	/* "Report Reference" */

/*
 * 2. Protocol Mode characteristic value.  [HIDS] Section 2.4.1.1, Table 2.2
 *    (text lines 656-669), verbatim:
 *      0x00  Boot Protocol Mode    "A HID Service shall only enter Boot
 *                                   Protocol Mode after this value has been
 *                                   written."
 *      0x01  Report Protocol Mode  "Default Protocol Mode of all HID Devices."
 *      0x02 - 0xFF                 "Reserved for Future Use."
 *
 *    [HIDS] Section 2.4.1.1, line 672: "The Protocol Mode characteristic
 *    value shall be reset to the default value following connection
 *    establishment."  The default is therefore 0x01 on every fresh
 *    connection, with no read required to know it.
 *
 *    [HIDS] Section 2.4.1, lines 652-654: the value "can be read using either
 *    the GATT Read Characteristic Value or Read Using Characteristic UUID
 *    sub-procedures and is written using the GATT Write Without Response
 *    sub-procedure."  Write Without Response is the only write procedure
 *    named for this characteristic.
 */
#define BT_EXTREF_PROTOCOL_MODE_BOOT		0x00
#define BT_EXTREF_PROTOCOL_MODE_REPORT		0x01
#define BT_EXTREF_PROTOCOL_MODE_DEFAULT		BT_EXTREF_PROTOCOL_MODE_REPORT
#define BT_EXTREF_PROTOCOL_MODE_RFU_FIRST	0x02

/*
 * 3. HID Control Point characteristic value.  [HIDS] Section 2.11.2,
 *    Table 2.17 (text lines 1153-1160):
 *      0x00  Suspend       "Informs HID Device that HID Host is entering the
 *                          Suspend State"
 *      0x01  Exit Suspend
 *    [HIDS] Section 2.11.1, lines 1149-1151: "The GATT Write Without Response
 *    sub-procedure is used to write to the HID Control Point characteristic."
 */
#define BT_EXTREF_HID_CTRL_SUSPEND		0x00
#define BT_EXTREF_HID_CTRL_EXIT_SUSPEND		0x01

/*
 * 4. Report Reference characteristic descriptor.  [HIDS] Section 2.5.3.2,
 *    Table 2.6 / Table 2.7 (text around lines 820-847).  Two octets, in this
 *    order: Report ID (1 octet) then Report Type (1 octet).
 *
 *    Report Type values, [HIDS] Table 2.7 (text lines 832-834):
 *      0x01 Input Report, 0x02 Output Report, 0x03 Feature Report.
 *    0x00 is not an assigned Report Type; it is not a legal value in a
 *    Report Reference descriptor.
 *
 *    [HIDS] lines 842-847, verbatim:
 *      "Report ID shall be nonzero in a Report Reference characteristic
 *       descriptor where there is more than one instance of the Report
 *       characteristic for any given Report Type."
 *      "HID Devices shall have a Report Reference characteristic descriptor
 *       in each Report characteristic definition for Report Protocol Mode."
 *    Note the scope of the uniqueness rule: it is stated per HID Service.
 *    See BT_EXTREF_HOGP_REPORT_ID_UNIQUE_ACROSS_INSTANCES below.
 */
#define BT_EXTREF_REPORT_REF_LEN		2
#define BT_EXTREF_REPORT_REF_OFF_REPORT_ID	0
#define BT_EXTREF_REPORT_REF_OFF_REPORT_TYPE	1

#define BT_EXTREF_REPORT_TYPE_INPUT		0x01
#define BT_EXTREF_REPORT_TYPE_OUTPUT		0x02
#define BT_EXTREF_REPORT_TYPE_FEATURE		0x03

/*
 * 5. External Report Reference characteristic descriptor.  [HIDS]
 *    Section 2.6.3.1, Table 2.9 (text lines 895-905): a single field,
 *    "Characteristic UUID", 2 octets, "Characteristic UUID for externally
 *    referenced characteristic".  Table 2.8 gives its permissions as
 *    "Read only, No Authentication, No Authorization".
 *
 *    [HOGP] Section 4.6.1.1, line 1036, verbatim: "The Report Host shall
 *    discover all External Report Reference characteristic descriptors for
 *    each Report Map characteristic."
 *
 *    [HOGP] Section 4.9 (text lines 1141-1145), verbatim: an alternative to
 *    a Report characteristic is "An external service characteristic whose
 *    UUID is supplied via an External Report Reference characteristic
 *    descriptor within the Report Map characteristic definition, and whose
 *    characteristic value contains a Report Reference characteristic
 *    descriptor within the external service characteristic definition. All
 *    External Report Reference characteristic descriptors shall contain
 *    unique values within a HID Service definition."
 */
#define BT_EXTREF_EXTERNAL_REPORT_REF_LEN	2

/*
 * 6. HID Information characteristic value.  [HIDS] Section 2.10.2,
 *    Table 2.16 (text lines 1090-1123).  Four octets:
 *      bcdHID       2 octets (little-endian uint16)
 *      bCountryCode 1 octet
 *      Flags        1 octet
 *    Flags bits, verbatim from Table 2.16 lines 1100-1121:
 *      Bit 0 RemoteWake - "Boolean value indicating whether HID Device is
 *            capable of sending a wake-signal to a HID Host."
 *      Bit 1 NormallyConnectable - "Boolean value indicating whether HID
 *            Device will be advertising when bonded but not connected."
 *      Bit 2 SCI Supported
 *      Bit 3 SCI Low Power mode supported
 */
#define BT_EXTREF_HID_INFO_LEN			4
#define BT_EXTREF_HID_INFO_OFF_BCDHID		0
#define BT_EXTREF_HID_INFO_OFF_COUNTRY		2
#define BT_EXTREF_HID_INFO_OFF_FLAGS		3

#define BT_EXTREF_HID_INFO_FLAG_REMOTE_WAKE		0x01
#define BT_EXTREF_HID_INFO_FLAG_NORMALLY_CONNECTABLE	0x02
#define BT_EXTREF_HID_INFO_FLAG_SCI_SUPPORTED		0x04
#define BT_EXTREF_HID_INFO_FLAG_SCI_LOW_POWER		0x08

/*
 * 7. Report Map characteristic.  [HIDS] Section 2.6, line 855, verbatim:
 *    "Only a single instance of this characteristic shall exist as part of a
 *    HID Service."
 *    [HIDS] Section 2.6.1, lines 858-862, verbatim: "The GATT Read
 *    Characteristic Value or Read Long Characteristic Values sub-procedures
 *    are used to read the Report Map characteristic value." and "The length
 *    of the Report Map characteristic value is limited to 512 octets."
 */
#define BT_EXTREF_REPORT_MAP_MAX_OCTETS		512
#define BT_EXTREF_REPORT_MAP_PER_SERVICE	1

/*
 * 8. Characteristic property matrix.
 *
 *    [HIDS] Section 2.5, Table 2.4 (text lines 707-717) for the Report
 *    characteristic, keyed by Report Type; and Table 2.11 (line 950) and
 *    Table 2.13 (line 991) for the boot characteristics.  [HIDS] line 719,
 *    verbatim: "Requirements marked with 'M' are mandatory, 'O' are optional
 *    and 'E' are excluded (not permitted)."
 *
 *    'E' is the load-bearing column here: an implementation must never use a
 *    procedure the matrix excludes.  In particular Write Without Response is
 *    EXCLUDED for Input Reports and for Feature Reports, and Notify is
 *    EXCLUDED for Output Reports and Feature Reports.
 */
enum bt_extref_prop_req {
	BT_EXTREF_PROP_MANDATORY = 0,	/* 'M' */
	BT_EXTREF_PROP_OPTIONAL = 1,	/* 'O' */
	BT_EXTREF_PROP_EXCLUDED = 2	/* 'E' -- not permitted */
};

struct bt_extref_hid_char_props {
	const char	*characteristic;
	uint16_t	 uuid16;
	uint8_t		 report_type;	/* 0 when not a Report characteristic */
	uint8_t		 read;
	uint8_t		 write;		/* GATT Write Characteristic Value */
	uint8_t		 write_no_rsp;	/* GATT Write Without Response */
	uint8_t		 notify;
	const char	*source;
};

static const struct bt_extref_hid_char_props bt_extref_hid_char_props[] = {
	{ "Report (Input Report)", BT_EXTREF_UUID_REPORT,
	  BT_EXTREF_REPORT_TYPE_INPUT,
	  BT_EXTREF_PROP_MANDATORY, BT_EXTREF_PROP_OPTIONAL,
	  BT_EXTREF_PROP_EXCLUDED, BT_EXTREF_PROP_MANDATORY,
	  "HIDS v1.1 Table 2.4" },
	{ "Report (Output Report)", BT_EXTREF_UUID_REPORT,
	  BT_EXTREF_REPORT_TYPE_OUTPUT,
	  BT_EXTREF_PROP_MANDATORY, BT_EXTREF_PROP_MANDATORY,
	  BT_EXTREF_PROP_MANDATORY, BT_EXTREF_PROP_EXCLUDED,
	  "HIDS v1.1 Table 2.4" },
	{ "Report (Feature Report)", BT_EXTREF_UUID_REPORT,
	  BT_EXTREF_REPORT_TYPE_FEATURE,
	  BT_EXTREF_PROP_MANDATORY, BT_EXTREF_PROP_MANDATORY,
	  BT_EXTREF_PROP_EXCLUDED, BT_EXTREF_PROP_EXCLUDED,
	  "HIDS v1.1 Table 2.4" },
	{ "Boot Keyboard Input Report", BT_EXTREF_UUID_BOOT_KB_INPUT_REPORT,
	  BT_EXTREF_REPORT_TYPE_INPUT,
	  BT_EXTREF_PROP_MANDATORY, BT_EXTREF_PROP_OPTIONAL,
	  BT_EXTREF_PROP_EXCLUDED, BT_EXTREF_PROP_MANDATORY,
	  "HIDS v1.1 Table 2.11" },
	{ "Boot Keyboard Output Report", BT_EXTREF_UUID_BOOT_KB_OUTPUT_REPORT,
	  BT_EXTREF_REPORT_TYPE_OUTPUT,
	  BT_EXTREF_PROP_MANDATORY, BT_EXTREF_PROP_MANDATORY,
	  BT_EXTREF_PROP_MANDATORY, BT_EXTREF_PROP_EXCLUDED,
	  "HIDS v1.1 Table 2.13" },
};

/*
 * 9. CCCD existence rules.  [HIDS] Section 2.5.1, lines 774-776, verbatim:
 *    "No Client Characteristic Configuration descriptor shall exist for a
 *     Report characteristic containing Output Report data or Feature Report
 *     data."
 *    and Section 2.5.3.1, lines 798-800: "A Client Characteristic
 *    Configuration descriptor shall be included in each Report characteristic
 *    definition where the data contained in the Report characteristic value
 *    refers to an Input Report."
 */
#define BT_EXTREF_CCCD_REQUIRED_FOR_INPUT_REPORT	1
#define BT_EXTREF_CCCD_FORBIDDEN_FOR_OUTPUT_REPORT	1
#define BT_EXTREF_CCCD_FORBIDDEN_FOR_FEATURE_REPORT	1

#endif /* TESTS_BLUETOOTH_SPEC_EXTREF_HOGP_CHARACTERISTICS_H */
