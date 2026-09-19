/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Implementations of the known GATT profile fixtures and their golden data
 * vectors.  See profile_fixtures.h for the model.
 *
 * Handle assignment: attdb_init() resets next_handle to 0x0001, and every
 * attdb_add_* call consumes handles sequentially:
 *   attdb_add_service        -> 1 attribute
 *   attdb_add_characteristic -> 2 attributes (declaration + value)
 *   attdb_add_cccd           -> 1 attribute
 *   attdb_add_descriptor     -> 1 attribute
 * Each builder below starts from a fresh attdb_init(), so the handles cited
 * in the golden vectors are exact and stable.
 *
 * Response byte layout follows att_server_dispatch.c:
 *   READ_RSP (0x0B):            opcode, value...
 *   READ_BY_TYPE_RSP (0x09):    opcode, attr_len, (handle, value)...
 *   WRITE_RSP (0x13):           opcode
 *   ERROR_RSP (0x01):           opcode, req_opcode, handle_lo, handle_hi, code
 *   Handle Value Notify (0x1B): opcode, handle_lo, handle_hi, value...
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "att.h"
#include "att_server.h"
#include "gatt.h"

#include "profile_fixtures.h"
#include "spec_profile_data_oracles.h"

/* SIG 16-bit UUIDs used across the fixtures. */
/*
 * ORACLE: every expected response below is hand-encoded from the Bluetooth
 * Core Specification PDU definitions, NOT captured from att_server_handle().
 * The attribute-database layout (order, handles) is defined by these fixtures,
 * so handle values are ours; the PDU structure, field order, and error codes
 * are the spec's.  Reference layouts (Core Spec Vol 3 Part F unless noted):
 *
 *   Error Response          (0x01) §3.4.1.1:
 *       opcode | Request Opcode In Error(1) | Attribute Handle(2, LE) | Error Code(1)
 *   Read By Type Response   (0x09) §3.4.4.2:
 *       opcode | Length(1) | { Attribute Handle(2, LE) | Attribute Value } ...
 *       Length = size of each Attribute Data record (2 + value length)
 *   Read Response           (0x0B) §3.4.4.4:  opcode | Attribute Value
 *   Write Response          (0x13) §3.4.5.2:  opcode  (no parameters)
 *   Handle Value Notification (0x1B) §3.4.7.1:
 *       opcode | Attribute Handle(2, LE) | Attribute Value
 *   Read By Group Type Rsp  (0x11) §3.4.4.10 and
 *   Find Information Rsp     (0x05) §3.4.3.2  are used to script the client
 *       discovery round-trip in profile_data_test.c.
 *
 *   Error Codes (§3.4.1.1, Table 3.4):
 *       0x02 Read Not Permitted, 0x13 Value Not Allowed.
 *
 * Characteristic Declaration value (the bytes returned for a 0x2803 read) is
 * Properties(1) | Value Handle(2, LE) | Characteristic UUID(2/16, LE),
 * Core Spec Vol 3 Part G §3.3.1.
 */

/* ================================================================
 * GAP (0x1800)
 * ================================================================ */

static struct att_attr	gap_attrs[8];
static uint8_t		gap_vals[256];

/* Realistic values. */
static const char	gap_device_name[] = "5BSD-blued";	/* 10 bytes */
static const uint8_t	gap_appearance[] = { 0x80, 0x00 };	/* 0x0080 Generic Computer, LE */

static void
gap_build(struct att_db *db)
{

	attdb_init(db, gap_attrs, 8, gap_vals, sizeof(gap_vals));

	/* handle 0x0001: Primary Service 0x1800 */
	attdb_add_service(db, BT_PROFILE_SPEC_UUID_GAP_SERVICE);
	/* 0x0002 decl, 0x0003 value: Device Name (read) */
	attdb_add_characteristic(db, BT_PROFILE_SPEC_UUID_DEVICE_NAME, BT_PROFILE_SPEC_PROP_READ,
	    ATT_PERM_READ, gap_device_name, sizeof(gap_device_name) - 1);
	/* 0x0004 decl, 0x0005 value: Appearance (read) */
	attdb_add_characteristic(db, BT_PROFILE_SPEC_UUID_APPEARANCE, BT_PROFILE_SPEC_PROP_READ,
	    ATT_PERM_READ, gap_appearance, sizeof(gap_appearance));
}

/*
 * Read Request (0x0A) handle 0x0003 -> Read Response (0x0B).
 * Vol 3 Part F §3.4.4.4: opcode | Attribute Value.
 * Device Name value is a UTF-8 string (Vol 3 Part C §12.1 / Part G §12.1).
 */
static const uint8_t gap_req_name[] = { BT_PROFILE_SPEC_ATT_READ_REQ, 0x03, 0x00 };
static const uint8_t gap_rsp_name[] = {
	BT_PROFILE_SPEC_ATT_READ_RSP,
	'5', 'B', 'S', 'D', '-', 'b', 'l', 'u', 'e', 'd'
};

/*
 * Read Request 0x0005 -> Read Response (0x0B), Vol 3 Part F §3.4.4.4.
 * Appearance is a 16-bit value, little-endian (Vol 3 Part C §12.2):
 * 0x0080 = Generic Computer -> 0x80 0x00.
 */
static const uint8_t gap_req_appear[] = { BT_PROFILE_SPEC_ATT_READ_REQ, 0x05, 0x00 };
static const uint8_t gap_rsp_appear[] = { BT_PROFILE_SPEC_ATT_READ_RSP, 0x80, 0x00 };

/*
 * Read By Type Request (0x08), Device Name UUID 0x2A00 -> Read By Type
 * Response (0x09), Vol 3 Part F §3.4.4.2: opcode | Length | {handle | value}.
 * Length = 2 + 10 = 0x0C; one record, handle 0x0003 + name.
 */
static const uint8_t gap_req_rbt_name[] = {
	BT_PROFILE_SPEC_ATT_READ_BY_TYPE_REQ, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x2A
};
static const uint8_t gap_rsp_rbt_name[] = {
	BT_PROFILE_SPEC_ATT_READ_BY_TYPE_RSP, 0x0C,		/* Length = 2 + 10 */
	0x03, 0x00,				/* handle 0x0003 */
	'5', 'B', 'S', 'D', '-', 'b', 'l', 'u', 'e', 'd'
};

/*
 * Read By Type Request for Characteristic Declaration UUID 0x2803 ->
 * Read By Type Response (0x09), Vol 3 Part F §3.4.4.2.  Each record's value
 * is a Characteristic Declaration: Properties(1) | Value Handle(2, LE) |
 * UUID(2, LE), Vol 3 Part G §3.3.1.  Length = 2 + 5 = 0x07; two records.
 */
static const uint8_t gap_req_rbt_decl[] = {
	BT_PROFILE_SPEC_ATT_READ_BY_TYPE_REQ, 0x01, 0x00, 0xFF, 0xFF, 0x03, 0x28
};
static const uint8_t gap_rsp_rbt_decl[] = {
	BT_PROFILE_SPEC_ATT_READ_BY_TYPE_RSP, 0x07,		/* Length = 2 + 5 */
	0x02, 0x00, 0x02, 0x03, 0x00, 0x00, 0x2A, /* decl 0x0002: props R, vh 0x0003, 0x2A00 */
	0x04, 0x00, 0x02, 0x05, 0x00, 0x01, 0x2A  /* decl 0x0004: props R, vh 0x0005, 0x2A01 */
};

static const struct golden_op gap_ops[] = {
	{ "READ Device Name (0x0003)", gap_req_name, sizeof(gap_req_name),
	  gap_rsp_name, sizeof(gap_rsp_name) },
	{ "READ Appearance (0x0005)", gap_req_appear, sizeof(gap_req_appear),
	  gap_rsp_appear, sizeof(gap_rsp_appear) },
	{ "READ_BY_TYPE Device Name", gap_req_rbt_name, sizeof(gap_req_rbt_name),
	  gap_rsp_rbt_name, sizeof(gap_rsp_rbt_name) },
	{ "READ_BY_TYPE char declarations", gap_req_rbt_decl,
	  sizeof(gap_req_rbt_decl), gap_rsp_rbt_decl, sizeof(gap_rsp_rbt_decl) },
};

static const struct profile_fixture gap_fixture = {
	.name = "GAP", .service_uuid = BT_PROFILE_SPEC_UUID_GAP_SERVICE, .build = gap_build,
	.ops = gap_ops, .nops = sizeof(gap_ops) / sizeof(gap_ops[0]),
	.has_notify = false,
};

/* ================================================================
 * GATT (0x1801): Service Changed (indicate) + CCCD + Database Hash
 * ================================================================ */

static struct att_attr	gatt_attrs[8];
static uint8_t		gatt_vals[256];

/* Service Changed initial affected range 0x0001-0xFFFF. */
static const uint8_t	gatt_sc_value[] = { 0x01, 0x00, 0xFF, 0xFF };

static void
gatt_build(struct att_db *db)
{
	static const uint8_t zero_hash[16] = { 0 };
	uint8_t hash[16];
	int i;

	attdb_init(db, gatt_attrs, 8, gatt_vals, sizeof(gatt_vals));

	/* handle 0x0001: Primary Service 0x1801 */
	attdb_add_service(db, BT_PROFILE_SPEC_UUID_GATT_SERVICE);
	/*
	 * 0x0002 decl, 0x0003 value: Service Changed (indicate only,
	 * no read/write permission per Core Spec Vol 3 Part G Section 7.1).
	 */
	attdb_add_characteristic(db, BT_PROFILE_SPEC_UUID_SERVICE_CHANGED, BT_PROFILE_SPEC_PROP_INDICATE,
	    0, gatt_sc_value, sizeof(gatt_sc_value));
	/* 0x0004: Client Characteristic Configuration descriptor */
	attdb_add_cccd(db);
	/* 0x0005 decl, 0x0006 value: Database Hash (read) */
	attdb_add_characteristic(db, BT_PROFILE_SPEC_UUID_DATABASE_HASH, BT_PROFILE_SPEC_PROP_READ,
	    ATT_PERM_READ, zero_hash, sizeof(zero_hash));

	/* Fill in the real Database Hash (AES-CMAC over the DB). */
	attdb_compute_db_hash(db, hash);
	for (i = 0; i < db->count; i++) {
		if (db->attrs[i].uuid16 == BT_PROFILE_SPEC_UUID_DATABASE_HASH &&
		    db->attrs[i].is_char_value && db->attrs[i].value_len == 16) {
			memcpy(db->attrs[i].value, hash, 16);
			break;
		}
	}
}

/*
 * Read Request Service Changed value 0x0003.  The characteristic has neither
 * Read property nor read permission (indicate-only, Vol 3 Part G §7.1), so
 * the server must return Error Response (0x01), Vol 3 Part F §3.4.1.1:
 * opcode | ReqOp(0x0A) | Handle(0x0003, LE) | Read Not Permitted (0x02).
 */
static const uint8_t gatt_req_read_sc[] = { BT_PROFILE_SPEC_ATT_READ_REQ, 0x03, 0x00 };
static const uint8_t gatt_rsp_read_sc[] = {
	BT_PROFILE_SPEC_ATT_ERROR_RSP, BT_PROFILE_SPEC_ATT_READ_REQ, 0x03, 0x00, BT_PROFILE_SPEC_ERR_READ_NOT_PERMITTED
};

/*
 * Write Request CCCD 0x0004 = 0x0002 enabling indications.  Parent Service
 * Changed has the Indicate property, so this is a valid configuration
 * (Vol 3 Part G §3.3.3.3) -> Write Response (0x13), Vol 3 Part F §3.4.5.2.
 */
static const uint8_t gatt_req_cccd_ind[] = {
	BT_PROFILE_SPEC_ATT_WRITE_REQ, 0x04, 0x00, 0x02, 0x00
};
static const uint8_t gatt_rsp_cccd_ind[] = { BT_PROFILE_SPEC_ATT_WRITE_RSP };

/*
 * Write Request CCCD 0x0004 = 0x0001 enabling notifications.  Vol 3 Part G
 * §3.3.3.3 Table 3.11 mandates that the Notification bit "shall only be set if
 * the characteristic's properties have the notify bit set"; Service Changed is
 * indicate-only, so the server shall reject the write.  ORACLE NOTE: the Core
 * Spec mandates the rejection but names no single ATT error for it, so this is
 * a defensible-within-latitude choice: Value Not Allowed (0x13, Vol 3 Part F
 * §3.4.1.1 Table 3.4 — "attribute parameter value was not allowed"), the
 * out-of-range-for-the-service code.  (0xFD "CCCD Improperly Configured"
 * applies to a notify/indicate operation, not to the CCCD write itself.)  If
 * a future spec revision names a specific code, THIS expectation changes to
 * match the spec, not the implementation.
 */
static const uint8_t gatt_req_cccd_ntf[] = {
	BT_PROFILE_SPEC_ATT_WRITE_REQ, 0x04, 0x00, 0x01, 0x00
};
static const uint8_t gatt_rsp_cccd_ntf[] = {
	BT_PROFILE_SPEC_ATT_ERROR_RSP, BT_PROFILE_SPEC_ATT_WRITE_REQ, 0x04, 0x00, BT_PROFILE_SPEC_ERR_VALUE_NOT_ALLOWED
};

/*
 * Read Request CCCD 0x0004 on a fresh connection -> Read Response (0x0B),
 * Vol 3 Part F §3.4.4.4.  An unconfigured CCCD reads as the 2-octet value
 * 0x0000 (Vol 3 Part G §3.3.3.3).
 */
static const uint8_t gatt_req_read_cccd[] = { BT_PROFILE_SPEC_ATT_READ_REQ, 0x04, 0x00 };
static const uint8_t gatt_rsp_read_cccd[] = { BT_PROFILE_SPEC_ATT_READ_RSP, 0x00, 0x00 };

static const struct golden_op gatt_ops[] = {
	{ "READ Service Changed rejected", gatt_req_read_sc,
	  sizeof(gatt_req_read_sc), gatt_rsp_read_sc, sizeof(gatt_rsp_read_sc) },
	{ "WRITE CCCD indicate accepted", gatt_req_cccd_ind,
	  sizeof(gatt_req_cccd_ind), gatt_rsp_cccd_ind, sizeof(gatt_rsp_cccd_ind) },
	{ "WRITE CCCD notify rejected", gatt_req_cccd_ntf,
	  sizeof(gatt_req_cccd_ntf), gatt_rsp_cccd_ntf, sizeof(gatt_rsp_cccd_ntf) },
	{ "READ CCCD unconfigured", gatt_req_read_cccd,
	  sizeof(gatt_req_read_cccd), gatt_rsp_read_cccd, sizeof(gatt_rsp_read_cccd) },
};

static const struct profile_fixture gatt_fixture = {
	.name = "GATT", .service_uuid = BT_PROFILE_SPEC_UUID_GATT_SERVICE, .build = gatt_build,
	.ops = gatt_ops, .nops = sizeof(gatt_ops) / sizeof(gatt_ops[0]),
	.has_notify = false,
};

/* ================================================================
 * Device Information (0x180A): Manufacturer, Model, Firmware (all read)
 * ================================================================ */

static struct att_attr	dis_attrs[8];
static uint8_t		dis_vals[256];

static const char	dis_manufacturer[] = "FreeBSD";	/* 7 bytes */
static const char	dis_model[] = "blued";		/* 5 bytes */
static const char	dis_firmware[] = "1.0.0";	/* 5 bytes */

static void
dis_build(struct att_db *db)
{

	attdb_init(db, dis_attrs, 8, dis_vals, sizeof(dis_vals));

	/* 0x0001: Primary Service 0x180A */
	attdb_add_service(db, BT_PROFILE_SPEC_UUID_DIS_SERVICE);
	/* 0x0002 decl, 0x0003 value: Manufacturer Name (read) */
	attdb_add_characteristic(db, BT_PROFILE_SPEC_UUID_MANUFACTURER, BT_PROFILE_SPEC_PROP_READ,
	    ATT_PERM_READ, dis_manufacturer, sizeof(dis_manufacturer) - 1);
	/* 0x0004 decl, 0x0005 value: Model Number (read) */
	attdb_add_characteristic(db, BT_PROFILE_SPEC_UUID_MODEL_NUMBER, BT_PROFILE_SPEC_PROP_READ,
	    ATT_PERM_READ, dis_model, sizeof(dis_model) - 1);
	/* 0x0006 decl, 0x0007 value: Firmware Revision (read) */
	attdb_add_characteristic(db, BT_PROFILE_SPEC_UUID_FIRMWARE_REV, BT_PROFILE_SPEC_PROP_READ,
	    ATT_PERM_READ, dis_firmware, sizeof(dis_firmware) - 1);
}

/*
 * Read Request handles 0x0003 / 0x0005 / 0x0007 -> Read Response (0x0B),
 * Vol 3 Part F §3.4.4.4: opcode | Attribute Value.  Manufacturer Name (0x2A29),
 * Model Number (0x2A24) and Firmware Revision (0x2A26) are UTF-8 strings
 * (Device Information Service 1.1).
 */
static const uint8_t dis_req_manuf[] = { BT_PROFILE_SPEC_ATT_READ_REQ, 0x03, 0x00 };
static const uint8_t dis_rsp_manuf[] = {
	BT_PROFILE_SPEC_ATT_READ_RSP, 'F', 'r', 'e', 'e', 'B', 'S', 'D'
};
static const uint8_t dis_req_model[] = { BT_PROFILE_SPEC_ATT_READ_REQ, 0x05, 0x00 };
static const uint8_t dis_rsp_model[] = {
	BT_PROFILE_SPEC_ATT_READ_RSP, 'b', 'l', 'u', 'e', 'd'
};
static const uint8_t dis_req_fw[] = { BT_PROFILE_SPEC_ATT_READ_REQ, 0x07, 0x00 };
static const uint8_t dis_rsp_fw[] = {
	BT_PROFILE_SPEC_ATT_READ_RSP, '1', '.', '0', '.', '0'
};

static const struct golden_op dis_ops[] = {
	{ "READ Manufacturer Name (0x0003)", dis_req_manuf, sizeof(dis_req_manuf),
	  dis_rsp_manuf, sizeof(dis_rsp_manuf) },
	{ "READ Model Number (0x0005)", dis_req_model, sizeof(dis_req_model),
	  dis_rsp_model, sizeof(dis_rsp_model) },
	{ "READ Firmware Revision (0x0007)", dis_req_fw, sizeof(dis_req_fw),
	  dis_rsp_fw, sizeof(dis_rsp_fw) },
};

static const struct profile_fixture dis_fixture = {
	.name = "DIS", .service_uuid = BT_PROFILE_SPEC_UUID_DIS_SERVICE, .build = dis_build,
	.ops = dis_ops, .nops = sizeof(dis_ops) / sizeof(dis_ops[0]),
	.has_notify = false,
};

/* ================================================================
 * Battery (0x180F): Battery Level (read + notify) + CCCD
 * ================================================================ */

static struct att_attr	batt_attrs[8];
static uint8_t		batt_vals[128];

static const uint8_t	batt_level[] = { 0x64 };		/* 100% */

static void
battery_build(struct att_db *db)
{

	attdb_init(db, batt_attrs, 8, batt_vals, sizeof(batt_vals));

	/* 0x0001: Primary Service 0x180F */
	attdb_add_service(db, BT_PROFILE_SPEC_UUID_BATTERY_SERVICE);
	/* 0x0002 decl, 0x0003 value: Battery Level (read + notify) */
	attdb_add_characteristic(db, BT_PROFILE_SPEC_UUID_BATTERY_LEVEL,
	    BT_PROFILE_SPEC_PROP_READ | BT_PROFILE_SPEC_PROP_NOTIFY, ATT_PERM_READ,
	    batt_level, sizeof(batt_level));
	/* 0x0004: CCCD */
	attdb_add_cccd(db);
}

/*
 * Read Request Battery Level 0x0003 -> Read Response (0x0B),
 * Vol 3 Part F §3.4.4.4.  Battery Level is a uint8 percentage 0-100
 * (Battery Service 1.0 §3.1); 0x64 = 100%.
 */
static const uint8_t batt_req_level[] = { BT_PROFILE_SPEC_ATT_READ_REQ, 0x03, 0x00 };
static const uint8_t batt_rsp_level[] = { BT_PROFILE_SPEC_ATT_READ_RSP, 0x64 };

/*
 * Write Request CCCD 0x0004 = 0x0001 enabling notifications.  Parent Battery
 * Level has the Notify property, valid configuration (Vol 3 Part G §3.3.3.3)
 * -> Write Response (0x13), Vol 3 Part F §3.4.5.2.
 */
static const uint8_t batt_req_cccd[] = {
	BT_PROFILE_SPEC_ATT_WRITE_REQ, 0x04, 0x00, 0x01, 0x00
};
static const uint8_t batt_rsp_cccd[] = { BT_PROFILE_SPEC_ATT_WRITE_RSP };

/*
 * Read Request CCCD 0x0004 (fresh) -> Read Response (0x0B) 2-octet 0x0000
 * (unconfigured), Vol 3 Part F §3.4.4.4 / Vol 3 Part G §3.3.3.3.
 */
static const uint8_t batt_req_read_cccd[] = { BT_PROFILE_SPEC_ATT_READ_REQ, 0x04, 0x00 };
static const uint8_t batt_rsp_read_cccd[] = { BT_PROFILE_SPEC_ATT_READ_RSP, 0x00, 0x00 };

/*
 * Read By Type Request Battery Level UUID 0x2A19 -> Read By Type Response
 * (0x09), Vol 3 Part F §3.4.4.2.  Length = 2 + 1 = 0x03; handle 0x0003 + level.
 */
static const uint8_t batt_req_rbt[] = {
	BT_PROFILE_SPEC_ATT_READ_BY_TYPE_REQ, 0x01, 0x00, 0xFF, 0xFF, 0x19, 0x2A
};
static const uint8_t batt_rsp_rbt[] = {
	BT_PROFILE_SPEC_ATT_READ_BY_TYPE_RSP, 0x03,		/* Length = 2 + 1 */
	0x03, 0x00, 0x64
};

static const struct golden_op battery_ops[] = {
	{ "READ Battery Level (0x0003)", batt_req_level, sizeof(batt_req_level),
	  batt_rsp_level, sizeof(batt_rsp_level) },
	{ "WRITE CCCD notify accepted", batt_req_cccd, sizeof(batt_req_cccd),
	  batt_rsp_cccd, sizeof(batt_rsp_cccd) },
	{ "READ CCCD unconfigured", batt_req_read_cccd, sizeof(batt_req_read_cccd),
	  batt_rsp_read_cccd, sizeof(batt_rsp_read_cccd) },
	{ "READ_BY_TYPE Battery Level", batt_req_rbt, sizeof(batt_req_rbt),
	  batt_rsp_rbt, sizeof(batt_rsp_rbt) },
};

/*
 * Handle Value Notification of Battery Level 0x0003 = 90% (0x5A).
 * Vol 3 Part F §3.4.7.1: opcode(0x1B) | Attribute Handle(2, LE) | Value.
 */
static const uint8_t	batt_notify_value[] = { 0x5A };
static const uint8_t	batt_notify_pdu[] = {
	BT_PROFILE_SPEC_ATT_HANDLE_NOTIFY, 0x03, 0x00, 0x5A
};

static const struct profile_fixture battery_fixture = {
	.name = "Battery", .service_uuid = BT_PROFILE_SPEC_UUID_BATTERY_SERVICE,
	.build = battery_build,
	.ops = battery_ops, .nops = sizeof(battery_ops) / sizeof(battery_ops[0]),
	.has_notify = true, .notify_handle = 0x0003,
	.notify_value = batt_notify_value, .notify_len = sizeof(batt_notify_value),
	.notify_pdu = batt_notify_pdu, .notify_pdu_len = sizeof(batt_notify_pdu),
};

/* ================================================================
 * Heart Rate (0x180D): HR Measurement (notify) + CCCD, Body Sensor Location
 * ================================================================ */

static struct att_attr	hr_attrs[8];
static uint8_t		hr_vals[128];

/* HR Measurement: flags=0x00 (uint8 BPM), value 72 BPM. */
static const uint8_t	hr_measurement[] = { 0x00, 0x48 };
/* Body Sensor Location: 0x01 = Chest. */
static const uint8_t	hr_body_sensor[] = { 0x01 };

static void
heart_rate_build(struct att_db *db)
{

	attdb_init(db, hr_attrs, 8, hr_vals, sizeof(hr_vals));

	/* 0x0001: Primary Service 0x180D */
	attdb_add_service(db, BT_PROFILE_SPEC_UUID_HEART_RATE_SERVICE);
	/*
	 * 0x0002 decl, 0x0003 value: Heart Rate Measurement (notify only,
	 * not readable).
	 */
	attdb_add_characteristic(db, BT_PROFILE_SPEC_UUID_HR_MEASUREMENT, BT_PROFILE_SPEC_PROP_NOTIFY,
	    0, hr_measurement, sizeof(hr_measurement));
	/* 0x0004: CCCD */
	attdb_add_cccd(db);
	/* 0x0005 decl, 0x0006 value: Body Sensor Location (read) */
	attdb_add_characteristic(db, BT_PROFILE_SPEC_UUID_BODY_SENSOR_LOC, BT_PROFILE_SPEC_PROP_READ,
	    ATT_PERM_READ, hr_body_sensor, sizeof(hr_body_sensor));
}

/*
 * Read Request Body Sensor Location 0x0006 -> Read Response (0x0B),
 * Vol 3 Part F §3.4.4.4.  Body Sensor Location is a uint8 enumeration
 * (Heart Rate Service 1.0 §3.2); 0x01 = Chest.
 */
static const uint8_t hr_req_bsl[] = { BT_PROFILE_SPEC_ATT_READ_REQ, 0x06, 0x00 };
static const uint8_t hr_rsp_bsl[] = { BT_PROFILE_SPEC_ATT_READ_RSP, 0x01 };

/*
 * Write Request CCCD 0x0004 = 0x0001 enabling notifications.  Parent Heart
 * Rate Measurement has the Notify property (Vol 3 Part G §3.3.3.3) ->
 * Write Response (0x13), Vol 3 Part F §3.4.5.2.
 */
static const uint8_t hr_req_cccd[] = {
	BT_PROFILE_SPEC_ATT_WRITE_REQ, 0x04, 0x00, 0x01, 0x00
};
static const uint8_t hr_rsp_cccd[] = { BT_PROFILE_SPEC_ATT_WRITE_RSP };

/*
 * Read Request HR Measurement 0x0003.  The characteristic is notify-only with
 * no read permission (Heart Rate Service 1.0 §3.1), so the server must return
 * Error Response (0x01), Vol 3 Part F §3.4.1.1: opcode | ReqOp(0x0A) |
 * Handle(0x0003, LE) | Read Not Permitted (0x02).
 */
static const uint8_t hr_req_read_meas[] = { BT_PROFILE_SPEC_ATT_READ_REQ, 0x03, 0x00 };
static const uint8_t hr_rsp_read_meas[] = {
	BT_PROFILE_SPEC_ATT_ERROR_RSP, BT_PROFILE_SPEC_ATT_READ_REQ, 0x03, 0x00, BT_PROFILE_SPEC_ERR_READ_NOT_PERMITTED
};

static const struct golden_op heart_rate_ops[] = {
	{ "READ Body Sensor Location (0x0006)", hr_req_bsl, sizeof(hr_req_bsl),
	  hr_rsp_bsl, sizeof(hr_rsp_bsl) },
	{ "WRITE CCCD notify accepted", hr_req_cccd, sizeof(hr_req_cccd),
	  hr_rsp_cccd, sizeof(hr_rsp_cccd) },
	{ "READ HR Measurement rejected", hr_req_read_meas,
	  sizeof(hr_req_read_meas), hr_rsp_read_meas, sizeof(hr_rsp_read_meas) },
};

/*
 * Handle Value Notification of HR Measurement 0x0003.  Vol 3 Part F §3.4.7.1:
 * opcode(0x1B) | Handle(2, LE) | Value.  Value = Flags(0x00: uint8 BPM format,
 * Heart Rate Service 1.0 §3.1) followed by 72 BPM (0x48).
 */
static const uint8_t	hr_notify_value[] = { 0x00, 0x48 };
static const uint8_t	hr_notify_pdu[] = {
	BT_PROFILE_SPEC_ATT_HANDLE_NOTIFY, 0x03, 0x00, 0x00, 0x48
};

static const struct profile_fixture heart_rate_fixture = {
	.name = "HeartRate", .service_uuid = BT_PROFILE_SPEC_UUID_HEART_RATE_SERVICE,
	.build = heart_rate_build,
	.ops = heart_rate_ops,
	.nops = sizeof(heart_rate_ops) / sizeof(heart_rate_ops[0]),
	.has_notify = true, .notify_handle = 0x0003,
	.notify_value = hr_notify_value, .notify_len = sizeof(hr_notify_value),
	.notify_pdu = hr_notify_pdu, .notify_pdu_len = sizeof(hr_notify_pdu),
};

/* ================================================================
 * HID over GATT / HOGP (0x1812)
 * ================================================================ */

static struct att_attr	hid_attrs[16];
static uint8_t		hid_vals[512];

/*
 * HID Information: bcdHID = 0x0111, bCountryCode = 0x00,
 * Flags = 0x02 (NormallyConnectable).
 */
static const uint8_t	hid_information[] = { 0x11, 0x01, 0x00, 0x02 };

/*
 * A small but valid HID Report Map: a standard boot keyboard descriptor.
 * (Usage Page Generic Desktop / Keyboard, 8-bit modifier + reserved byte +
 * six key array bytes.)
 */
static const uint8_t	hid_report_map[] = {
	0x05, 0x01,		/* Usage Page (Generic Desktop) */
	0x09, 0x06,		/* Usage (Keyboard) */
	0xA1, 0x01,		/* Collection (Application) */
	0x05, 0x07,		/*   Usage Page (Keyboard/Keypad) */
	0x19, 0xE0,		/*   Usage Minimum (0xE0) */
	0x29, 0xE7,		/*   Usage Maximum (0xE7) */
	0x15, 0x00,		/*   Logical Minimum (0) */
	0x25, 0x01,		/*   Logical Maximum (1) */
	0x75, 0x01,		/*   Report Size (1) */
	0x95, 0x08,		/*   Report Count (8) */
	0x81, 0x02,		/*   Input (Data,Var,Abs) -- modifier byte */
	0x95, 0x01,		/*   Report Count (1) */
	0x75, 0x08,		/*   Report Size (8) */
	0x81, 0x01,		/*   Input (Const) -- reserved byte */
	0x95, 0x06,		/*   Report Count (6) */
	0x75, 0x08,		/*   Report Size (8) */
	0x15, 0x00,		/*   Logical Minimum (0) */
	0x25, 0x65,		/*   Logical Maximum (101) */
	0x05, 0x07,		/*   Usage Page (Keyboard/Keypad) */
	0x19, 0x00,		/*   Usage Minimum (0) */
	0x29, 0x65,		/*   Usage Maximum (101) */
	0x81, 0x00,		/*   Input (Data,Array) -- key array */
	0xC0			/* End Collection */
};

/* Input Report: 8-byte boot keyboard report, initially idle. */
static const uint8_t	hid_report[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Report Reference descriptor: Report ID 1, Report Type 1 (Input). */
static const uint8_t	hid_report_ref[] = { 0x01, 0x01 };

/* Protocol Mode: 0x01 = Report Protocol Mode. */
static const uint8_t	hid_protocol_mode[] = { 0x01 };

static void
hogp_build(struct att_db *db)
{

	attdb_init(db, hid_attrs, 16, hid_vals, sizeof(hid_vals));

	/* 0x0001: Primary Service 0x1812 */
	attdb_add_service(db, BT_PROFILE_SPEC_UUID_HID_SERVICE);
	/* 0x0002 decl, 0x0003 value: HID Information (read) */
	attdb_add_characteristic(db, BT_PROFILE_SPEC_UUID_HID_INFORMATION, BT_PROFILE_SPEC_PROP_READ,
	    ATT_PERM_READ, hid_information, sizeof(hid_information));
	/* 0x0004 decl, 0x0005 value: Report Map (read) */
	attdb_add_characteristic(db, BT_PROFILE_SPEC_UUID_REPORT_MAP, BT_PROFILE_SPEC_PROP_READ,
	    ATT_PERM_READ, hid_report_map, sizeof(hid_report_map));
	/* 0x0006 decl, 0x0007 value: Report (read + notify) */
	attdb_add_characteristic(db, BT_PROFILE_SPEC_UUID_REPORT,
	    BT_PROFILE_SPEC_PROP_READ | BT_PROFILE_SPEC_PROP_NOTIFY, ATT_PERM_READ,
	    hid_report, sizeof(hid_report));
	/* 0x0008: CCCD for the Report */
	attdb_add_cccd(db);
	/* 0x0009: Report Reference descriptor (read) */
	attdb_add_descriptor(db, BT_PROFILE_SPEC_UUID_REPORT_REFERENCE, ATT_PERM_READ,
	    hid_report_ref, sizeof(hid_report_ref));
	/* 0x000A decl, 0x000B value: Protocol Mode (read + write-no-response) */
	attdb_add_characteristic(db, BT_PROFILE_SPEC_UUID_PROTOCOL_MODE,
	    BT_PROFILE_SPEC_PROP_READ | BT_PROFILE_SPEC_PROP_WRITE_NO_RSP,
	    ATT_PERM_READ | ATT_PERM_WRITE,
	    hid_protocol_mode, sizeof(hid_protocol_mode));
}

/*
 * Read Request HID Information 0x0003 -> Read Response (0x0B),
 * Vol 3 Part F §3.4.4.4.  Value = bcdHID(2, LE 0x0111) | bCountryCode(0x00) |
 * Flags(0x02 NormallyConnectable), HID Service 1.0 §5.
 */
static const uint8_t hid_req_info[] = { BT_PROFILE_SPEC_ATT_READ_REQ, 0x03, 0x00 };
static const uint8_t hid_rsp_info[] = {
	BT_PROFILE_SPEC_ATT_READ_RSP, 0x11, 0x01, 0x00, 0x02
};

/*
 * Read Request Report Map 0x0005 -> Read Response (0x0B), Vol 3 Part F
 * §3.4.4.4.  Value = the USB HID report descriptor bytes verbatim (HID
 * Service 1.0 §2.6); it fits within MTU-1 so no truncation applies.
 */
static const uint8_t hid_req_map[] = { BT_PROFILE_SPEC_ATT_READ_REQ, 0x05, 0x00 };
static const uint8_t hid_rsp_map[] = {
	BT_PROFILE_SPEC_ATT_READ_RSP,
	0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07,
	0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01,
	0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01,
	0x75, 0x08, 0x81, 0x01, 0x95, 0x06, 0x75, 0x08,
	0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00,
	0x29, 0x65, 0x81, 0x00, 0xC0
};

/*
 * Read Request Report Reference descriptor 0x0009 -> Read Response (0x0B),
 * Vol 3 Part F §3.4.4.4.  Value = Report ID(0x01) | Report Type(0x01 Input),
 * HID Service 1.0 §2.5.
 */
static const uint8_t hid_req_ref[] = { BT_PROFILE_SPEC_ATT_READ_REQ, 0x09, 0x00 };
static const uint8_t hid_rsp_ref[] = { BT_PROFILE_SPEC_ATT_READ_RSP, 0x01, 0x01 };

/*
 * Read Request Protocol Mode 0x000B -> Read Response (0x0B),
 * Vol 3 Part F §3.4.4.4.  Value = uint8 mode, 0x01 = Report Protocol Mode
 * (HID Service 1.0 §2.4).
 */
static const uint8_t hid_req_proto[] = { BT_PROFILE_SPEC_ATT_READ_REQ, 0x0B, 0x00 };
static const uint8_t hid_rsp_proto[] = { BT_PROFILE_SPEC_ATT_READ_RSP, 0x01 };

/*
 * Write Request Report CCCD 0x0008 = 0x0001 enabling notifications.  Parent
 * Report characteristic has the Notify property (Vol 3 Part G §3.3.3.3) ->
 * Write Response (0x13), Vol 3 Part F §3.4.5.2.
 */
static const uint8_t hid_req_cccd[] = {
	BT_PROFILE_SPEC_ATT_WRITE_REQ, 0x08, 0x00, 0x01, 0x00
};
static const uint8_t hid_rsp_cccd[] = { BT_PROFILE_SPEC_ATT_WRITE_RSP };

/*
 * Read By Type Request Report Reference UUID 0x2908 -> Read By Type Response
 * (0x09), Vol 3 Part F §3.4.4.2.  Length = 2 + 2 = 0x04; handle 0x0009 + value.
 */
static const uint8_t hid_req_rbt_ref[] = {
	BT_PROFILE_SPEC_ATT_READ_BY_TYPE_REQ, 0x01, 0x00, 0xFF, 0xFF, 0x08, 0x29
};
static const uint8_t hid_rsp_rbt_ref[] = {
	BT_PROFILE_SPEC_ATT_READ_BY_TYPE_RSP, 0x04,		/* Length = 2 + 2 */
	0x09, 0x00, 0x01, 0x01
};

static const struct golden_op hogp_ops[] = {
	{ "READ HID Information (0x0003)", hid_req_info, sizeof(hid_req_info),
	  hid_rsp_info, sizeof(hid_rsp_info) },
	{ "READ Report Map (0x0005)", hid_req_map, sizeof(hid_req_map),
	  hid_rsp_map, sizeof(hid_rsp_map) },
	{ "READ Report Reference (0x0009)", hid_req_ref, sizeof(hid_req_ref),
	  hid_rsp_ref, sizeof(hid_rsp_ref) },
	{ "READ Protocol Mode (0x000B)", hid_req_proto, sizeof(hid_req_proto),
	  hid_rsp_proto, sizeof(hid_rsp_proto) },
	{ "WRITE Report CCCD notify accepted", hid_req_cccd, sizeof(hid_req_cccd),
	  hid_rsp_cccd, sizeof(hid_rsp_cccd) },
	{ "READ_BY_TYPE Report Reference", hid_req_rbt_ref, sizeof(hid_req_rbt_ref),
	  hid_rsp_rbt_ref, sizeof(hid_rsp_rbt_ref) },
};

/*
 * Handle Value Notification of the input Report 0x0007 (a key press).
 * Vol 3 Part F §3.4.7.1: opcode(0x1B) | Handle(2, LE) | Value.  Value is an
 * 8-octet boot-keyboard input report (modifier | reserved | six keycodes,
 * per the Report Map above); byte 2 = 0x04 = USB HID keycode for 'a'.
 */
static const uint8_t	hid_notify_value[] = {
	0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00	/* 'a' keycode */
};
static const uint8_t	hid_notify_pdu[] = {
	BT_PROFILE_SPEC_ATT_HANDLE_NOTIFY, 0x07, 0x00,
	0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const struct profile_fixture hogp_fixture = {
	.name = "HOGP", .service_uuid = BT_PROFILE_SPEC_UUID_HID_SERVICE, .build = hogp_build,
	.ops = hogp_ops, .nops = sizeof(hogp_ops) / sizeof(hogp_ops[0]),
	.has_notify = true, .notify_handle = 0x0007,
	.notify_value = hid_notify_value, .notify_len = sizeof(hid_notify_value),
	.notify_pdu = hid_notify_pdu, .notify_pdu_len = sizeof(hid_notify_pdu),
};

/* ================================================================
 * Accessors
 * ================================================================ */

const struct profile_fixture *
profile_fixture_gap(void)
{

	return (&gap_fixture);
}

const struct profile_fixture *
profile_fixture_gatt(void)
{

	return (&gatt_fixture);
}

const struct profile_fixture *
profile_fixture_dis(void)
{

	return (&dis_fixture);
}

const struct profile_fixture *
profile_fixture_battery(void)
{

	return (&battery_fixture);
}

const struct profile_fixture *
profile_fixture_heart_rate(void)
{

	return (&heart_rate_fixture);
}

const struct profile_fixture *
profile_fixture_hogp(void)
{

	return (&hogp_fixture);
}

static const struct profile_fixture *const all_fixtures[] = {
	&gap_fixture,
	&gatt_fixture,
	&dis_fixture,
	&battery_fixture,
	&heart_rate_fixture,
	&hogp_fixture,
};

const struct profile_fixture *const *
profile_fixtures_all(size_t *count)
{

	if (count != NULL)
		*count = sizeof(all_fixtures) / sizeof(all_fixtures[0]);
	return (all_fixtures);
}
