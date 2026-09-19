/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * EXTERNAL REFERENCE ORACLE: the normative HID-Host rules of the HID Over
 * GATT Profile, reduced to machine-checkable predicates, each carried with
 * the verbatim sentence it was reduced from and the text line number it was
 * read at.
 *
 * Hand-written.  Nothing here was derived from blued, and no value was
 * produced by running 5BSD code.  This header includes no blued header and
 * compiles standalone.
 *
 * WHY THIS HEADER EXISTS
 * ----------------------
 * HOGP splits the host into two mutually exclusive roles -- Boot Host and
 * Report Host -- and almost every "what should the host do" question has a
 * DIFFERENT answer per role.  A single code path that writes Report Protocol
 * Mode and then writes Boot Protocol Mode on the same connection is not a
 * host that supports both; it is a host that violates the concurrency rule
 * in both directions.  Pinning the role split as data makes that testable.
 *
 * SOURCE
 * ------
 *   [HOGP]  /usr/src/bluetooth-specs/HOGP_v1.1.txt
 *           HID Over GATT Profile, in-tree text.  Title page line 5
 *           "Version: v1.1", line 6 "Version Date: 2025-08-05".
 *   [HIDS]  /usr/src/bluetooth-specs/HIDS_v1.1.txt
 *           HID Service Specification, in-tree text.  Line 26 records
 *           "v1.1 ... 2026-04-21 Adopted by the Bluetooth SIG Board of
 *           Directors".
 *
 * Line numbers are 1-based into those .txt files as they stand in tree.
 */

#ifndef TESTS_BLUETOOTH_SPEC_EXTREF_HOGP_HOST_RULES_H
#define TESTS_BLUETOOTH_SPEC_EXTREF_HOGP_HOST_RULES_H

#include <stdint.h>

/* The two host roles of [HOGP] Section 2. */
#define BT_EXTREF_HOGP_ROLE_BOOT_HOST	0
#define BT_EXTREF_HOGP_ROLE_REPORT_HOST	1

/*
 * A single normative rule, reduced to (role, applies, requirement level).
 * `level' uses the specification's own modal verbs so a test can tell a
 * "shall" it must satisfy from a "may" it is free to ignore.
 */
enum bt_extref_req_level {
	BT_EXTREF_REQ_SHALL = 0,
	BT_EXTREF_REQ_SHALL_NOT = 1,
	BT_EXTREF_REQ_SHOULD = 2,
	BT_EXTREF_REQ_MAY = 3,
	BT_EXTREF_REQ_NO_REQUIREMENT = 4
};

struct bt_extref_hogp_rule {
	const char	*id;		/* stable local tag */
	int8_t		 role;		/* BT_EXTREF_HOGP_ROLE_*, -1 = both */
	uint8_t		 level;		/* enum bt_extref_req_level */
	const char	*section;	/* [HOGP] or [HIDS] section number */
	int		 line;		/* text line in the cited .txt */
	const char	*text;		/* verbatim */
};

static const struct bt_extref_hogp_rule bt_extref_hogp_rules[] = {

/* --- Role exclusivity.  [HOGP] Section 2. ------------------------------- */
{ "ROLE-EXCL-BOOT", BT_EXTREF_HOGP_ROLE_BOOT_HOST,
  BT_EXTREF_REQ_SHALL_NOT, "HOGP 2", 575,
  "A Boot Host shall not concurrently be a Report Host." },
{ "ROLE-EXCL-REPORT", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL_NOT, "HOGP 2", 577,
  "A Report Host shall not concurrently be a Boot Host." },
{ "ROLE-SCANCLIENT", BT_EXTREF_HOGP_ROLE_BOOT_HOST,
  BT_EXTREF_REQ_SHALL_NOT, "HOGP 2", 566,
  "The Boot Host shall not support the Scan Client role of the Scan "
  "Parameters Profile." },
{ "ROLE-SCANPARAM", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP 4", 886,
  "The Report Host shall support the "
  "functionality defined in the Scan Parameters Profile [6]." },

/* --- Protocol Mode.  [HOGP] Section 4.11, text lines 1183-1189. --------- */
{ "PROTOMODE-BOOT-WRITE", BT_EXTREF_HOGP_ROLE_BOOT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP heading \"Protocol Mode behavior\"", 1187,
  "The Boot Host shall write to the Protocol Mode characteristic for each "
  "HID Service on the GATT Server and set the characteristic value to the "
  "defined value for Boot Protocol Mode following connection establishment." },
{ "PROTOMODE-REPORT-NOREQ", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_NO_REQUIREMENT, "HOGP heading \"Protocol Mode behavior\"", 1189,
  "There are no requirements on a Report Host to use the Protocol Mode "
  "characteristic." },
{ "PROTOMODE-DISCOVER", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_MAY, "HOGP 4.6.1.5", 1057,
  "The Report Host may discover the Protocol Mode characteristic for each "
  "HID Service on the GATT server." },
{ "PROTOMODE-DEFAULT-RESET", -1,
  BT_EXTREF_REQ_SHALL, "HIDS 2.4.1.1", 672,
  "The Protocol Mode characteristic value shall be reset to the default "
  "value following connection establishment." },
{ "PROTOMODE-ENTER-BOOT", -1,
  BT_EXTREF_REQ_SHALL, "HIDS 2.4.1.1 Table 2.2", 662,
  "A HID Service shall only enter Boot Protocol Mode after this value has "
  "been written." },

/* --- Boot vs report notification cross-talk.  [HOGP] Section 4.12-4.14. - */
{ "BOOTKB-NTF-ENABLE", BT_EXTREF_HOGP_ROLE_BOOT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP heading \"Boot Keyboard Input Report behavior\"", 1196,
  "If the Boot Host supports the Boot Keyboard Input Report characteristic, "
  "then it shall enable notifications of the Boot Keyboard Input Report "
  "characteristic using the Client Characteristic Configuration descriptor." },
{ "BOOTKB-NTF-IGNORE", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP heading \"Boot Keyboard Input Report behavior\"", 1199,
  "The Report Host shall ignore notifications of the Boot Keyboard Input "
  "Report characteristic." },
{ "BOOTMS-NTF-ENABLE", BT_EXTREF_HOGP_ROLE_BOOT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP heading \"Boot Mouse Input Report behavior\"", 1211,
  "If the Boot Host supports the Boot Mouse Input Report characteristic, "
  "then it shall enable notifications of the Boot Mouse Input Report "
  "characteristic using the Client Characteristic Configuration descriptor." },
{ "BOOTMS-NTF-IGNORE", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP heading \"Boot Mouse Input Report behavior\"", 1214,
  "The Report Host shall ignore notifications of the Boot Mouse Input "
  "Report characteristic." },
{ "REPORT-NTF-IGNORE-BOOTHOST", BT_EXTREF_HOGP_ROLE_BOOT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP heading \"Report behavior\" (line 1107)", 1115,
  "The Boot Host shall ignore notifications of the Report characteristic." },

/* --- Boot Host CCCD discovery.  [HOGP] Sections 4.4.1.2 / 4.4.1.4. ------ */
{ "BOOTKB-CCCD-DISC", BT_EXTREF_HOGP_ROLE_BOOT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP 4.4.1.2", 936,
  "The Boot Host shall discover the associated Client Characteristic "
  "Configuration Descriptor of all Boot Keyboard Input Report "
  "characteristics using the GATT Discover All Characteristic Descriptors "
  "sub-procedure." },
{ "BOOTMS-CCCD-DISC", BT_EXTREF_HOGP_ROLE_BOOT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP 4.4.1.4", 948,
  "The Boot Host shall discover the associated Client Characteristic "
  "Configuration Descriptor of all Boot Mouse Input Report characteristics "
  "using the GATT Discover All Characteristic Descriptors sub-procedure." },

/* --- Report Host discovery duties.  [HOGP] Sections 4.5 / 4.6. ---------- */
{ "DISC-ALL-HID-SERVICES", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP 4.5.1", 996,
  "The Report Host shall perform primary service discovery to discover all "
  "HID Services." },
{ "DISC-MTU-FIRST", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP 4.4.3.1", 992,
  "If the Report Host supports an ATT_MTU larger than the default ATT_MTU, "
  "then the Report Host shall use the GATT Exchange MTU sub-procedure prior "
  "to performing service discovery." },
{ "DISC-ALL-REPORT-MAPS", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP 4.6.1.1", 1034,
  "The Report Host shall discover all Report Map characteristics." },
{ "DISC-ALL-EXT-REPORT-REF", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP 4.6.1.1", 1036,
  "The Report Host shall discover all External Report Reference "
  "characteristic descriptors for each Report Map characteristic." },
{ "DISC-ALL-REPORTS", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP 4.6.1.2", 1040,
  "The Report Host shall discover all Report characteristics." },
{ "DISC-REPORT-CCCD", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP 4.6.1.2", 1042,
  "The Report Host shall discover the associated Client Characteristic "
  "Configuration Descriptor of all Report characteristics." },
{ "DISC-REPORT-REF", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP 4.6.1.2", 1045,
  "The Report Host shall discover the associated Report Reference "
  "characteristic descriptor of all Report characteristics." },
{ "DISC-HID-CONTROL-POINT", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP 4.6.1.3", 1049,
  "The Report Host shall discover all HID Control Point characteristics, if "
  "the Report Host supports Suspend mode, to allow the Report Host to send "
  "control commands to HID Devices whenever the Report Host enters a low "
  "power Suspend Mode." },
{ "DISC-HID-INFORMATION", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP 4.6.1.4", 1054,
  "The Report Host shall discover all HID Information characteristics." },
{ "DISC-DIS", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP 4.5.2", 999,
  "The Report Host shall perform primary service discovery to discover the "
  "Device Information Service." },
{ "DISC-BAS-INCLUDED", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP 4.5.3", 1004,
  "The Report Host shall perform relationship discovery to find included "
  "services to discover all Battery Services with characteristics described "
  "within a HID Service Report Map characteristic value." },
{ "DISC-TOLERATE-EXTRA", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP 4.6", 1018,
  "As required by GATT, the Report Host must be tolerant of additional "
  "optional characteristics of services used with this profile and used "
  "outside of this profile." },

/* --- Notification enablement.  [HOGP] Section 4.9 area. ----------------- */
{ "NTF-ENABLE-INPUT-ONLY", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP heading \"Report behavior\" (line 1107)", 1111,
  "The Report Host shall enable notifications, via the Client "
  "Characteristic Configuration descriptor, of the Report characteristic "
  "for all instances of the Report characteristic where the Report Type as "
  "defined in the Report Reference characteristic descriptor refers to an "
  "Input Report." },

/* --- Report ID handling on the data path.  [HOGP] Section 4.9. --------- */
{ "REPORTID-PREPEND-INBOUND", -1,
  BT_EXTREF_REQ_SHALL, "HOGP 4.8.1 Translation layer", 1147,
  "For data transferred from the HID Device to the Report Host, the Report "
  "ID is prepended to data received by the Report Host (usually either a "
  "notification of a Report characteristic value, or as a read response of "
  "a Report characteristic value, for HID Service data) before being passed "
  "to a USB HID Class driver." },
{ "REPORTID-STRIP-OUTBOUND", -1,
  BT_EXTREF_REQ_SHALL, "HOGP 4.8.1 Translation layer", 1151,
  "For data transferred to the HID Device from the Report Host, the Report "
  "ID is removed from data received from a USB HID Class driver before "
  "being transmitted to the HID Device (usually a write command to a Report "
  "characteristic value or as a write request to a Report characteristic "
  "value for HID Service data)." },

/* --- Multiple service instances.  [HOGP] Section 2, lines 596-608. ------
 *
 * Note what is and is not prohibited.  Multiple HID Service instances are
 * EXPLICITLY PERMITTED and are the sanctioned way to describe a composite
 * device; it is Device Information, Scan Parameters and HID ISO that are
 * limited to one.  A host that cannot keep two HID Service instances apart
 * is not "handling an illegal device", it is failing a supported topology.
 */
{ "MULTI-DIS-FORBIDDEN", -1,
  BT_EXTREF_REQ_SHALL_NOT, "HOGP 2", 596,
  "Multiple service instances shall not be supported for the following "
  "services: Device Information Service. Scan Parameters Service. "
  "HID ISO Service." },
{ "MULTI-HID-PERMITTED", -1,
  BT_EXTREF_REQ_MAY, "HOGP 2", 603,
  "Multiple service instances of the HID Service may be supported to allow "
  "implementers to define composite HID Devices whose combined functions "
  "require more than 512 octets of data to describe." },
{ "MULTI-BAS-PERMITTED", -1,
  BT_EXTREF_REQ_MAY, "HOGP 2", 606,
  "Multiple service instances of the Battery Service may be supported." },
{ "MULTI-REPORTID-UNIQUE-ISO-ONLY", -1,
  BT_EXTREF_REQ_SHALL, "HOGP 3.1.6", 693,
  "When a HID Device supporting the HID ISO feature has more than one "
  "instance of the HID Service [3], all Report IDs shall be unique within "
  "each Report Type within the HID Device." },
{ "MULTI-REPORTID-UNIQUE-PER-SERVICE", -1,
  BT_EXTREF_REQ_SHALL, "HIDS 2.5.3.2", 844,
  "Report ID shall be nonzero in a Report Reference characteristic "
  "descriptor where there is more than one instance of the Report "
  "characteristic for any given Report Type." },

/* --- Suspend / HID Information flags.  [HOGP] Section 4.8. -------------- */
{ "SUSPEND-REMOTEWAKE", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP heading \"HID Information behavior\"", 1165,
  "When a system enters a low-power Suspend Mode, the RemoteWake flag shall "
  "be used to determine whether the Report Host includes the HID Device in "
  "the set of devices that can wake it up." },
{ "RESUME-NORMALLYCONNECTABLE", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP heading \"HID Information behavior\"", 1172,
  "When a Report Host is exiting a low power Suspend Mode, the "
  "NormallyConnectable flag shall be used to determine whether the Report "
  "Host can connect to the HID Device before any user interaction occurs on "
  "the HID device." },

/* --- PnP ID.  [HOGP] Section 4.16. ------------------------------------- */
{ "PNPID-READ-ON-CONNECT", BT_EXTREF_HOGP_ROLE_REPORT_HOST,
  BT_EXTREF_REQ_SHALL, "HOGP heading \"PnP ID behavior\"", 1224,
  "The PnP ID characteristic value shall be read by the Report Host upon "
  "initial connection establishment and may be cached afterwards." },

/* --- Security.  [HOGP] Section 7, text lines 2066-2089. ----------------- */
{ "SEC-HOST-BOND", -1,
  BT_EXTREF_REQ_SHALL, "HOGP 7", 2083,
  "The HID Host, which must be a Central as per Section 2.4, shall perform "
  "the Bonding procedure with the HID Device, as defined in [2] Volume 3, "
  "Part C, Section 9.4.4." },
{ "SEC-ENCRYPT-EARLY", -1,
  BT_EXTREF_REQ_SHOULD, "HOGP 7", 2086,
  "The HID Host should encrypt the link as early as possible after "
  "reconnection." },
{ "SEC-KEY-REFRESH-ONLY-ON-REQUEST", -1,
  BT_EXTREF_REQ_SHALL, "HOGP 7", 2088,
  "The HID Host shall only initiate an encryption key refresh on receipt of "
  "a Peripheral Security Request, as defined in [2] Volume 3, Part H, "
  "Section 2.4.6, from the HID Device." },
{ "SEC-CHARS-ENCRYPTED", -1,
  BT_EXTREF_REQ_SHALL, "HOGP 7", 2073,
  "HID Service characteristics shall require an encrypted link for reading, "
  "writing, and notification." },

/* --- Information sharing between the two host roles.  [HOGP] 4.17. ------ */
{ "HOSTS-SHARE-BONDING", -1,
  BT_EXTREF_REQ_SHALL, "HOGP heading \"Information sharing between HID Hosts\"", 1243,
  "The Boot Host and Report Host shall share bonding information and "
  "information regarding \xc2\xabService changed\xc2\xbb indications." },
};

#define BT_EXTREF_HOGP_NRULES \
	(sizeof(bt_extref_hogp_rules) / sizeof(bt_extref_hogp_rules[0]))

/*
 * Reconnection behaviour keyed on NormallyConnectable.
 * [HOGP] Appendix A, Table A.1 "HID Host and HID Device Connection Behavior"
 * (text lines 2147-2178).  Transcribed verbatim.
 *
 * The load-bearing point for a host: in BOTH rows the DEVICE advertises and
 * the HOST scans.  There is no row in which the host performs a bare
 * connection attempt on a timer; the host's obligation is to be scanning
 * when the device chooses to advertise.  With NormallyConnectable FALSE --
 * "Most common configuration" -- the device advertises for only 5 s after it
 * has data, so a host that is not scanning during that window loses the
 * keystroke that triggered it.
 */
struct bt_extref_hogp_reconnect_row {
	uint8_t		 normally_connectable;
	const char	*device_behaviour;
	const char	*host_behaviour;
	const char	*comment;
};

static const struct bt_extref_hogp_reconnect_row
bt_extref_hogp_reconnect[] = {
	{ 0,
	  "if data to transmit: high duty-cycle advertising for 5 s; "
	  "if idle: radio off",
	  "low duty-cycle scanning",
	  "Most common configuration" },
	{ 1,
	  "if data to transmit: high duty-cycle advertising for 5 s; "
	  "if idle: low duty-cycle advertising",
	  "if data to transmit: high duty-cycle scanning for 5 s; "
	  "if idle: low duty-cycle scanning",
	  "In this case, it is preferred to keep the LE HID connection active "
	  "always." },
};

#define BT_EXTREF_HOGP_NRECONNECT \
	(sizeof(bt_extref_hogp_reconnect) / \
	 sizeof(bt_extref_hogp_reconnect[0]))

#endif /* TESTS_BLUETOOTH_SPEC_EXTREF_HOGP_HOST_RULES_H */
