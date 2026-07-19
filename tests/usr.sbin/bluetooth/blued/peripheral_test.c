/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF integration tests for peripheral GATT server.
 *
 * Builds a full peripheral GATT database (GAP + DIS + custom service
 * with CCCD) and exercises the ATT server via socketpair mock.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "hci_log.h"
#include "hci_util.h"
#include "spec_oracles.h"

#include "test_common.h"

/*
 * This integration suite predates the independent oracle catalog and uses
 * the production-style ATT spelling throughout.  Remap those spellings only
 * in this test translation unit, after all production headers are parsed, so
 * every request and expected response below comes from spec_oracles.h rather
 * than att.h.  The separately compiled server retains its production values.
 */
#undef ATT_OP_ERROR_RSP
#define ATT_OP_ERROR_RSP	PERIPH_ATT_OP_ERROR_RSP
#undef ATT_OP_MTU_REQ
#define ATT_OP_MTU_REQ		PERIPH_ATT_OP_MTU_REQ
#undef ATT_OP_MTU_RSP
#define ATT_OP_MTU_RSP		PERIPH_ATT_OP_MTU_RSP
#undef ATT_OP_FIND_INFO_REQ
#define ATT_OP_FIND_INFO_REQ	PERIPH_ATT_OP_FIND_INFO_REQ
#undef ATT_OP_FIND_INFO_RSP
#define ATT_OP_FIND_INFO_RSP	PERIPH_ATT_OP_FIND_INFO_RSP
#undef ATT_OP_FIND_BY_TYPE_VALUE_REQ
#define ATT_OP_FIND_BY_TYPE_VALUE_REQ PERIPH_ATT_OP_FIND_BY_TYPE_VALUE_REQ
#undef ATT_OP_FIND_BY_TYPE_VALUE_RSP
#define ATT_OP_FIND_BY_TYPE_VALUE_RSP PERIPH_ATT_OP_FIND_BY_TYPE_VALUE_RSP
#undef ATT_OP_READ_BY_TYPE_REQ
#define ATT_OP_READ_BY_TYPE_REQ	PERIPH_ATT_OP_READ_BY_TYPE_REQ
#undef ATT_OP_READ_BY_TYPE_RSP
#define ATT_OP_READ_BY_TYPE_RSP	PERIPH_ATT_OP_READ_BY_TYPE_RSP
#undef ATT_OP_READ_REQ
#define ATT_OP_READ_REQ		PERIPH_ATT_OP_READ_REQ
#undef ATT_OP_READ_RSP
#define ATT_OP_READ_RSP		PERIPH_ATT_OP_READ_RSP
#undef ATT_OP_READ_BLOB_REQ
#define ATT_OP_READ_BLOB_REQ	PERIPH_ATT_OP_READ_BLOB_REQ
#undef ATT_OP_READ_BY_GROUP_TYPE_REQ
#define ATT_OP_READ_BY_GROUP_TYPE_REQ PERIPH_ATT_OP_READ_BY_GROUP_TYPE_REQ
#undef ATT_OP_READ_BY_GROUP_TYPE_RSP
#define ATT_OP_READ_BY_GROUP_TYPE_RSP PERIPH_ATT_OP_READ_BY_GROUP_TYPE_RSP
#undef ATT_OP_WRITE_REQ
#define ATT_OP_WRITE_REQ	PERIPH_ATT_OP_WRITE_REQ
#undef ATT_OP_WRITE_RSP
#define ATT_OP_WRITE_RSP	PERIPH_ATT_OP_WRITE_RSP
#undef ATT_OP_PREPARE_WRITE_REQ
#define ATT_OP_PREPARE_WRITE_REQ PERIPH_ATT_OP_PREPARE_WRITE_REQ
#undef ATT_OP_PREPARE_WRITE_RSP
#define ATT_OP_PREPARE_WRITE_RSP PERIPH_ATT_OP_PREPARE_WRITE_RSP
#undef ATT_OP_EXECUTE_WRITE_REQ
#define ATT_OP_EXECUTE_WRITE_REQ PERIPH_ATT_OP_EXECUTE_WRITE_REQ
#undef ATT_OP_EXECUTE_WRITE_RSP
#define ATT_OP_EXECUTE_WRITE_RSP PERIPH_ATT_OP_EXECUTE_WRITE_RSP
#undef ATT_OP_HANDLE_IND
#define ATT_OP_HANDLE_IND	PERIPH_ATT_OP_HANDLE_IND

#undef ATT_ERR_INVALID_HANDLE
#define ATT_ERR_INVALID_HANDLE	PERIPH_ATT_ERR_INVALID_HANDLE
#undef ATT_ERR_READ_NOT_PERMITTED
#define ATT_ERR_READ_NOT_PERMITTED PERIPH_ATT_ERR_READ_NOT_PERMITTED
#undef ATT_ERR_WRITE_NOT_PERMITTED
#define ATT_ERR_WRITE_NOT_PERMITTED PERIPH_ATT_ERR_WRITE_NOT_PERMITTED
#undef ATT_ERR_INVALID_PDU
#define ATT_ERR_INVALID_PDU	PERIPH_ATT_ERR_INVALID_PDU
#undef ATT_ERR_PREPARE_QUEUE_FULL
#define ATT_ERR_PREPARE_QUEUE_FULL PERIPH_ATT_ERR_PREPARE_QUEUE_FULL
#undef ATT_ERR_ATTR_NOT_LONG
#define ATT_ERR_ATTR_NOT_LONG	PERIPH_ATT_ERR_ATTR_NOT_LONG
#undef ATT_ERR_REQ_NOT_SUPPORTED
#define ATT_ERR_REQ_NOT_SUPPORTED PERIPH_ATT_ERR_REQ_NOT_SUPPORTED
#undef ATT_ERR_UNSUPPORTED_GROUP_TYPE
#define ATT_ERR_UNSUPPORTED_GROUP_TYPE PERIPH_ATT_ERR_UNSUPPORTED_GROUP_TYPE
#undef ATT_ERR_DATABASE_OUT_OF_SYNC
#define ATT_ERR_DATABASE_OUT_OF_SYNC PERIPH_ATT_ERR_DATABASE_OUT_OF_SYNC

#undef ATT_DEFAULT_MTU
#define ATT_DEFAULT_MTU		BT_CORE63_ATT_DEFAULT_MTU
#undef GATT_UUID_PRIMARY_SERVICE
#define GATT_UUID_PRIMARY_SERVICE BT_ASSIGNED_UUID_PRIMARY_SERVICE
#undef GATT_UUID_CCCD
#define GATT_UUID_CCCD		BT_ASSIGNED_UUID_CCCD
#undef GATT_CCCD_NOTIFY
#define GATT_CCCD_NOTIFY	BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED
#undef GATT_CCCD_INDICATE
#define GATT_CCCD_INDICATE	BT_CORE63_GATT_CCCD_INDICATIONS_ENABLED
#undef GATT_PROP_READ
#define GATT_PROP_READ		PERIPH_GATT_PROP_READ

#define PERIPH_ENUM(name, value) PERIPH_##name = value,
enum {
	BT_CORE63_ATT_ORACLES(PERIPH_ENUM)
	BT_CORE63_ATT_ERROR_ORACLES(PERIPH_ENUM)
	BT_CORE63_GATT_PROPERTY_ORACLES(PERIPH_ENUM)
};
#undef PERIPH_ENUM

/* ================================================================
 * GATT UUIDs
 * ================================================================ */

#define UUID_GAP_SERVICE	BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE
#define UUID_DEVICE_NAME	BT_ASSIGNED_UUID_DEVICE_NAME
#define UUID_APPEARANCE		BT_ASSIGNED_UUID_APPEARANCE
#define UUID_GATT_SERVICE	BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE
#define UUID_DIS_SERVICE	BT_ASSIGNED_UUID_DEVICE_INFORMATION_SERVICE
#define UUID_MANUFACTURER	BT_ASSIGNED_UUID_MANUFACTURER_NAME_STRING
#define UUID_MODEL_NUMBER	BT_ASSIGNED_UUID_MODEL_NUMBER_STRING
#define UUID_FIRMWARE_REV	BT_ASSIGNED_UUID_FIRMWARE_REVISION_STRING
#define UUID_CUSTOM_SERVICE	0xFFE0
#define UUID_CUSTOM_CHAR	0xFFE1
#define UUID_DATABASE_HASH	BT_ASSIGNED_UUID_DATABASE_HASH
#define UUID_CLIENT_SUPP_FEAT	BT_ASSIGNED_UUID_CLIENT_SUPPORTED_FEATURES
#define UUID_SERVER_SUPP_FEAT	BT_ASSIGNED_UUID_SERVER_SUPPORTED_FEATURES
#define UUID_CENTRAL_ADDR_RES	BT_ASSIGNED_UUID_CENTRAL_ADDRESS_RESOLUTION

#define PERIPHERAL_NAME		"5BSD-blued"

/* ================================================================
 * Test fixture: build a full peripheral GATT DB
 * ================================================================ */

#define PERIPH_MAX_ATTRS	64
#define PERIPH_VAL_SIZE		2048

static struct att_db db;
static struct att_attr attrs[PERIPH_MAX_ATTRS];
static uint8_t val_buf[PERIPH_VAL_SIZE];

static void
build_peripheral_db(void)
{
	static const uint8_t appearance[] = { 0x00, 0x00 };

	attdb_init(&db, attrs, PERIPH_MAX_ATTRS, val_buf, PERIPH_VAL_SIZE);

	/* GAP Service */
	attdb_add_service(&db, UUID_GAP_SERVICE);
	attdb_add_characteristic(&db, UUID_DEVICE_NAME,
	    PERIPH_GATT_PROP_READ, ATT_PERM_READ,
	    PERIPHERAL_NAME, sizeof(PERIPHERAL_NAME) - 1);
	attdb_add_characteristic(&db, UUID_APPEARANCE,
	    PERIPH_GATT_PROP_READ, ATT_PERM_READ,
	    appearance, sizeof(appearance));

	/* GATT Service with Service Changed */
	attdb_add_service(&db, UUID_GATT_SERVICE);
	attdb_add_characteristic(&db, BT_ASSIGNED_UUID_SERVICE_CHANGED,
	    PERIPH_GATT_PROP_INDICATE, 0,
	    "\x01\x00\xFF\xFF", 4);
	attdb_add_cccd(&db);

	/* Client Supported Features */
	attdb_add_characteristic(&db, UUID_CLIENT_SUPP_FEAT,
	    PERIPH_GATT_PROP_READ | PERIPH_GATT_PROP_WRITE,
	    ATT_PERM_READ | ATT_PERM_WRITE,
	    "\x00", 1);

	/* Server Supported Features */
	{
		static const uint8_t ssf[] = { 0x01 };
		attdb_add_characteristic(&db, UUID_SERVER_SUPP_FEAT,
		    PERIPH_GATT_PROP_READ, ATT_PERM_READ,
		    ssf, sizeof(ssf));
	}

	/* Database Hash (placeholder, computed below) */
	attdb_add_characteristic(&db, UUID_DATABASE_HASH,
	    PERIPH_GATT_PROP_READ, ATT_PERM_READ,
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00", 16);

	/* Device Information Service */
	attdb_add_service(&db, UUID_DIS_SERVICE);
	attdb_add_characteristic(&db, UUID_MANUFACTURER,
	    PERIPH_GATT_PROP_READ, ATT_PERM_READ, "FreeBSD", 7);
	attdb_add_characteristic(&db, UUID_MODEL_NUMBER,
	    PERIPH_GATT_PROP_READ, ATT_PERM_READ, "blued", 5);
	attdb_add_characteristic(&db, UUID_FIRMWARE_REV,
	    PERIPH_GATT_PROP_READ, ATT_PERM_READ, "1.0", 3);

	/* Custom service with read/write/notify + CCCD */
	attdb_add_service(&db, UUID_CUSTOM_SERVICE);
	attdb_add_characteristic(&db, UUID_CUSTOM_CHAR,
	    PERIPH_GATT_PROP_READ | PERIPH_GATT_PROP_WRITE |
	    PERIPH_GATT_PROP_NOTIFY,
	    ATT_PERM_READ | ATT_PERM_WRITE,
	    "\x00", 1);
	attdb_add_cccd(&db);

	/* Compute and set Database Hash */
	{
		uint8_t db_hash[16];

		attdb_compute_db_hash(&db, db_hash);
		for (int i = 0; i < db.count; i++) {
			if (db.attrs[i].uuid16 == UUID_DATABASE_HASH &&
			    db.attrs[i].value_len == 16) {
				memcpy(db.attrs[i].value, db_hash, 16);
				break;
			}
		}
	}
}

/*
 * Create a socketpair-backed att_conn for server-side testing.
 * The server att_conn is in *ac; *peer_fd is the client side.
 */
static void
mock_pair(struct att_conn *ac, int *peer_fd)
{
	int fds[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	memset(ac, 0, sizeof(*ac));
	ac->fd = fds[0];
	ac->bearer_fd = -1;
	ac->mtu = BT_CORE63_ATT_DEFAULT_MTU;
	ac->buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
	*peer_fd = fds[1];
}

static void
mock_cleanup(struct att_conn *ac, int peer_fd)
{

	free(ac->buf);
	close(ac->fd);
	close(peer_fd);
}

/*
 * Send request to peer, server reads and handles, read response.
 */
static ssize_t
server_request(int peer_fd, struct att_conn *ac,
    const void *req, size_t reqlen, void *rsp, size_t rsplen)
{
	ssize_t nr;

	ATF_REQUIRE(send(peer_fd, req, reqlen, 0) == (ssize_t)reqlen);

	/* Server reads from its fd */
	{
		uint8_t sbuf[ATT_PDU_BUF_SIZE];
		nr = recv(ac->fd, sbuf, ac->mtu, 0);
		ATF_REQUIRE(nr > 0);
		att_server_handle(ac, &db, sbuf, (size_t)nr, -1, 0);
	}

	/* Read response from peer */
	nr = recv(peer_fd, rsp, rsplen, 0);
	return (nr);
}

/* ================================================================
 * Tests
 * ================================================================ */

/*
 * Test 1: MTU Exchange
 */
ATF_TC(mtu_exchange);
ATF_TC_HEAD(mtu_exchange, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MTU exchange: server responds with ATT_DEFAULT_MTU");
}
ATF_TC_BODY(mtu_exchange, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	/* ATT_OP_MTU_REQ with client_mtu=256 */
	{
		uint8_t req[] = { ATT_OP_MTU_REQ, 0x00, 0x01 }; /* 256 */
		nr = server_request(peer_fd, &ac, req, sizeof(req),
		    rsp, sizeof(rsp));
	}

	ATF_REQUIRE(nr >= 3);
	ATF_CHECK_EQ(rsp[0], ATT_OP_MTU_RSP);
	{
		uint16_t server_mtu = rsp[1] | (rsp[2] << 8);
		ATF_CHECK(server_mtu >= ATT_DEFAULT_MTU);
	}

	mock_cleanup(&ac, peer_fd);
}

/*
 * Test 2: Service Discovery (Read By Group Type)
 */
ATF_TC(service_discovery);
ATF_TC_HEAD(service_discovery, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Discover all primary services via Read By Group Type");
}
ATF_TC_BODY(service_discovery, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;
	int nservices = 0;
	uint16_t start = 0x0001;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	/*
	 * Walk through all services using Read By Group Type.
	 * UUID 0x2800 = Primary Service.
	 */
	while (start <= 0xFFFF) {
		uint8_t req[7];

		req[0] = ATT_OP_READ_BY_GROUP_TYPE_REQ;
		req[1] = start & 0xFF;
		req[2] = start >> 8;
		req[3] = 0xFF;
		req[4] = 0xFF;
		put_le16(req + 5, BT_ASSIGNED_UUID_PRIMARY_SERVICE);

		nr = server_request(peer_fd, &ac, req, sizeof(req),
		    rsp, sizeof(rsp));
		ATF_REQUIRE(nr > 0);

		if (rsp[0] == ATT_OP_ERROR_RSP)
			break;

		ATF_REQUIRE_EQ(rsp[0], ATT_OP_READ_BY_GROUP_TYPE_RSP);
		{
			uint8_t entry_len = rsp[1];
			int nentries = ((int)nr - 2) / entry_len;

			nservices += nentries;

			/* Advance past last entry */
			uint8_t *last = &rsp[2 + (nentries - 1) * entry_len];
			uint16_t end_handle = last[2] | (last[3] << 8);
			if (end_handle == 0xFFFF)
				break;
			start = end_handle + 1;
		}
	}

	/* GAP, GATT, DIS, Custom = 4 services */
	ATF_CHECK_EQ(nservices, 4);

	mock_cleanup(&ac, peer_fd);
}

/*
 * Test 3: Characteristic Discovery (Read By Type for a service)
 */
ATF_TC(characteristic_discovery);
ATF_TC_HEAD(characteristic_discovery, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Discover characteristics in GAP service via Read By Type");
}
ATF_TC_BODY(characteristic_discovery, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;
	int nchars = 0;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	/*
	 * Find GAP service range first.  GAP is the first service
	 * so start_handle=0x0001.  Get the end group handle.
	 */
	uint16_t gap_start = 0x0001, gap_end;
	{
		uint8_t req[7] = {
			ATT_OP_READ_BY_GROUP_TYPE_REQ,
			0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28
		};
		nr = server_request(peer_fd, &ac, req, sizeof(req),
		    rsp, sizeof(rsp));
		ATF_REQUIRE(nr > 2);
		ATF_REQUIRE_EQ(rsp[0], ATT_OP_READ_BY_GROUP_TYPE_RSP);
		/* First entry: start_handle(2) + end_handle(2) + uuid(2) */
		gap_end = rsp[4] | (rsp[5] << 8);
	}

	/*
	 * Now discover characteristics within GAP range.
	 * UUID 0x2803 = Characteristic Declaration.
	 */
	{
		uint16_t s = gap_start;

		while (s <= gap_end) {
			uint8_t req[7];

			req[0] = ATT_OP_READ_BY_TYPE_REQ;
			req[1] = s & 0xFF;
			req[2] = s >> 8;
			req[3] = gap_end & 0xFF;
			req[4] = gap_end >> 8;
			put_le16(req + 5, BT_ASSIGNED_UUID_CHARACTERISTIC);

			nr = server_request(peer_fd, &ac, req, sizeof(req),
			    rsp, sizeof(rsp));
			ATF_REQUIRE(nr > 0);

			if (rsp[0] == ATT_OP_ERROR_RSP)
				break;

			ATF_REQUIRE_EQ(rsp[0], ATT_OP_READ_BY_TYPE_RSP);
			{
				uint8_t entry_len = rsp[1];
				int n = ((int)nr - 2) / entry_len;

				nchars += n;

				uint8_t *last = &rsp[2 + (n - 1) * entry_len];
				uint16_t handle = last[0] | (last[1] << 8);
				if (handle >= gap_end)
					break;
				s = handle + 1;
			}
		}
	}

	/* GAP has Device Name + Appearance = 2 characteristics */
	ATF_CHECK_EQ(nchars, 2);

	mock_cleanup(&ac, peer_fd);
}

/*
 * Test 4: Find Information (Descriptor Discovery)
 */
ATF_TC(descriptor_discovery);
ATF_TC_HEAD(descriptor_discovery, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Discover descriptors via Find Information Request");
}
ATF_TC_BODY(descriptor_discovery, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;
	bool found_cccd = false;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	/*
	 * Scan the full handle range for CCCDs (0x2902).
	 */
	{
		uint16_t s = 0x0001;

		while (s <= 0xFFFF) {
			uint8_t req[5];

			req[0] = ATT_OP_FIND_INFO_REQ;
			req[1] = s & 0xFF;
			req[2] = s >> 8;
			req[3] = 0xFF;
			req[4] = 0xFF;

			nr = server_request(peer_fd, &ac, req, sizeof(req),
			    rsp, sizeof(rsp));
			ATF_REQUIRE(nr > 0);

			if (rsp[0] == ATT_OP_ERROR_RSP)
				break;

			ATF_REQUIRE_EQ(rsp[0], ATT_OP_FIND_INFO_RSP);

			uint8_t format = rsp[1];
			int entry_len = (format == 0x01) ? 4 : 18;
			int n = ((int)nr - 2) / entry_len;
			uint16_t last_handle = 0;

			for (int i = 0; i < n; i++) {
				uint8_t *e = &rsp[2 + i * entry_len];

				last_handle = e[0] | (e[1] << 8);
				if (format == 0x01) {
					uint16_t uuid = e[2] | (e[3] << 8);
					if (uuid == GATT_UUID_CCCD)
						found_cccd = true;
				}
			}

			if (last_handle >= 0xFFFF)
				break;
			s = last_handle + 1;
		}
	}

	ATF_CHECK(found_cccd);

	mock_cleanup(&ac, peer_fd);
}

/*
 * Test 5: Read Device Name
 */
ATF_TC(read_device_name);
ATF_TC_HEAD(read_device_name, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Read GAP Device Name characteristic value");
}
ATF_TC_BODY(read_device_name, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;
	uint16_t name_handle = 0;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	/* Find the Device Name value handle via Read By Type */
	{
		uint8_t req[7];

		req[0] = ATT_OP_READ_BY_TYPE_REQ;
		put_le16(req + 1, 0x0001);
		put_le16(req + 3, 0xffff);
		put_le16(req + 5, UUID_DEVICE_NAME);
		nr = server_request(peer_fd, &ac, req, sizeof(req),
		    rsp, sizeof(rsp));
		ATF_REQUIRE(nr > 2);
		ATF_REQUIRE_EQ(rsp[0], ATT_OP_READ_BY_TYPE_RSP);

		/* Response includes handle + value; extract value directly */
		uint8_t entry_len = rsp[1];
		uint16_t vlen = entry_len - 2;

		ATF_CHECK(vlen == sizeof(PERIPHERAL_NAME) - 1);
		ATF_CHECK(memcmp(&rsp[4], PERIPHERAL_NAME,
		    sizeof(PERIPHERAL_NAME) - 1) == 0);

		name_handle = rsp[2] | (rsp[3] << 8);
	}

	/* Also test direct Read Request */
	{
		uint8_t req[3] = {
			ATT_OP_READ_REQ,
			name_handle & 0xFF,
			name_handle >> 8
		};
		nr = server_request(peer_fd, &ac, req, sizeof(req),
		    rsp, sizeof(rsp));
		ATF_REQUIRE(nr > 1);
		ATF_REQUIRE_EQ(rsp[0], ATT_OP_READ_RSP);
		ATF_CHECK(memcmp(&rsp[1], PERIPHERAL_NAME,
		    sizeof(PERIPHERAL_NAME) - 1) == 0);
	}

	mock_cleanup(&ac, peer_fd);
}

/*
 * Test 6: CCCD Write enables notifications
 */
ATF_TC(cccd_write);
ATF_TC_HEAD(cccd_write, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Writing 0x0001 to CCCD enables notifications");
}
ATF_TC_BODY(cccd_write, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;
	uint16_t cccd_handle = 0;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	/*
	 * Find the custom service's CCCD handle.
	 * The custom service CCCD is the last CCCD in the database.
	 */
	for (int i = 0; i < db.count; i++) {
		if (attrs[i].uuid16 == GATT_UUID_CCCD)
			cccd_handle = attrs[i].handle;
	}
	ATF_REQUIRE(cccd_handle != 0);

	/* Write 0x0001 (enable notifications) */
	{
		uint8_t req[5];

		req[0] = ATT_OP_WRITE_REQ;
		put_le16(req + 1, cccd_handle);
		put_le16(req + 3, GATT_CCCD_NOTIFY);
		nr = server_request(peer_fd, &ac, req, sizeof(req),
		    rsp, sizeof(rsp));
		ATF_REQUIRE(nr >= 1);
		ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);
	}

	/* Read it back to verify */
	{
		uint8_t req[3] = {
			ATT_OP_READ_REQ,
			cccd_handle & 0xFF,
			cccd_handle >> 8
		};
		nr = server_request(peer_fd, &ac, req, sizeof(req),
		    rsp, sizeof(rsp));
		ATF_REQUIRE(nr >= 3);
		ATF_CHECK_EQ(rsp[0], ATT_OP_READ_RSP);
		ATF_CHECK_EQ(rsp[1], 0x01);
		ATF_CHECK_EQ(rsp[2], 0x00);
	}

	mock_cleanup(&ac, peer_fd);
}

/*
 * Test 7: Database Hash read
 */
ATF_TC(database_hash_exposed);
ATF_TC_HEAD(database_hash_exposed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Read the exposed 16-octet Database Hash characteristic");
}
ATF_TC_BODY(database_hash_exposed, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	/* Read by type for Database Hash UUID 0x2B2A */
	{
		uint8_t req[7];

		req[0] = ATT_OP_READ_BY_TYPE_REQ;
		put_le16(req + 1, 0x0001);
		put_le16(req + 3, 0xffff);
		put_le16(req + 5, UUID_DATABASE_HASH);
		nr = server_request(peer_fd, &ac, req, sizeof(req),
		    rsp, sizeof(rsp));
		ATF_REQUIRE(nr > 2);
		ATF_REQUIRE_EQ(rsp[0], ATT_OP_READ_BY_TYPE_RSP);

		/* entry_len should be 2 (handle) + 16 (hash) = 18 */
		uint8_t entry_len = rsp[1];
		ATF_CHECK_EQ(entry_len, 18);

		/*
		 * Core Part G §7.3.1 specifies a 16-octet AES-CMAC but does
		 * not reserve the all-zero result.  Exact CMAC correctness is
		 * covered by the Appendix B KAT in att_server_edge_test; this
		 * integration case verifies only characteristic exposure/length.
		 */
	}

	mock_cleanup(&ac, peer_fd);
}

/*
 * Test 8: Service Changed indication
 *
 * Build a DB with Service Changed + CCCD, enable indications
 * via the CCCD, then call att_send_indication() directly on the
 * Service Changed value handle with a handle range payload.
 * Verify the peer receives an ATT_OP_HANDLE_IND PDU.
 */
ATF_TC(service_changed_indication);
ATF_TC_HEAD(service_changed_indication, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Service Changed: indication PDU sent when CCCD enabled");
}
ATF_TC_BODY(service_changed_indication, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;
	uint16_t sc_handle = 0;
	uint16_t cccd_handle = 0;
	int i;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);
	ac.ind_timer = 0;

	/*
	 * Find Service Changed (UUID 0x2A05) value handle and
	 * its following CCCD (UUID 0x2902) handle.
	 */
	for (i = 0; i < db.count; i++) {
		if (db.attrs[i].uuid16 == BT_ASSIGNED_UUID_SERVICE_CHANGED &&
		    db.attrs[i].is_char_value) {
			sc_handle = db.attrs[i].handle;
			if (i + 1 < db.count &&
			    db.attrs[i + 1].uuid16 == GATT_UUID_CCCD)
				cccd_handle = db.attrs[i + 1].handle;
			break;
		}
	}
	ATF_REQUIRE_MSG(sc_handle != 0,
	    "Service Changed value handle not found in DB");
	ATF_REQUIRE_MSG(cccd_handle != 0,
	    "Service Changed CCCD handle not found in DB");

	/*
	 * Enable indications on the CCCD by writing 0x0002.
	 */
	{
		uint8_t req[5];

		req[0] = ATT_OP_WRITE_REQ;
		put_le16(req + 1, cccd_handle);
		put_le16(req + 3, GATT_CCCD_INDICATE);
		nr = server_request(peer_fd, &ac, req, sizeof(req),
		    rsp, sizeof(rsp));
		ATF_REQUIRE(nr >= 1);
		ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);
	}

	/*
	 * Send a Service Changed indication with range 0x0001-0xFFFF.
	 */
	{
		uint8_t val[4];
		int ret;

		val[0] = 0x01; val[1] = 0x00;	/* start = 0x0001 */
		val[2] = 0xFF; val[3] = 0xFF;	/* end   = 0xFFFF */
		ret = att_send_indication(&ac, sc_handle, val, sizeof(val));
		ATF_CHECK_EQ_MSG(ret, 0,
		    "att_send_indication failed: %d", errno);
	}

	/*
	 * Read the indication PDU from the peer side.
	 * Format: opcode(0x1D) + handle(2) + value(4)
	 */
	nr = recv(peer_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(nr >= 7);
	ATF_CHECK_EQ_MSG(rsp[0], ATT_OP_HANDLE_IND,
	    "expected indication opcode 0x1D, got 0x%02x", rsp[0]);

	/* Verify handle matches Service Changed */
	{
		uint16_t h = rsp[1] | (rsp[2] << 8);
		ATF_CHECK_EQ_MSG(h, sc_handle,
		    "indication handle %04x != expected %04x",
		    h, sc_handle);
	}

	/* Verify handle range payload */
	ATF_CHECK_EQ(rsp[3], 0x01);	/* start low */
	ATF_CHECK_EQ(rsp[4], 0x00);	/* start high */
	ATF_CHECK_EQ(rsp[5], 0xFF);	/* end low */
	ATF_CHECK_EQ(rsp[6], 0xFF);	/* end high */

	mock_cleanup(&ac, peer_fd);
}

/*
 * Test 9: Service Changed characteristic is not readable
 *
 * Verify that a Read By Type for UUID 0x2A05 (Service Changed)
 * returns READ_NOT_PERMITTED.  Core Spec Vol 3 Part G §7.1 Table 7.3
 * specifies the value as Not Readable and Not Writable.
 */
ATF_TC(service_changed_not_readable);
ATF_TC_HEAD(service_changed_not_readable, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Service Changed (0x2A05) is indicate-only, not readable");
}
ATF_TC_BODY(service_changed_not_readable, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	/* Read By Type for UUID 0x2A05 (Service Changed) */
	{
		uint8_t req[7];

		req[0] = ATT_OP_READ_BY_TYPE_REQ;
		put_le16(req + 1, 0x0001);
		put_le16(req + 3, 0xffff);
		put_le16(req + 5, BT_ASSIGNED_UUID_SERVICE_CHANGED);
		nr = server_request(peer_fd, &ac, req, sizeof(req),
		    rsp, sizeof(rsp));
	}

	ATF_REQUIRE(nr > 0);

	/*
	 * Must return an error -- Service Changed has no read permission.
	 */
	ATF_CHECK_EQ_MSG(rsp[0], ATT_OP_ERROR_RSP,
	    "expected Error Response (0x01), got 0x%02x", rsp[0]);
	if (rsp[0] == ATT_OP_ERROR_RSP && nr >= 5)
		ATF_CHECK_EQ(rsp[4], ATT_ERR_READ_NOT_PERMITTED);

	mock_cleanup(&ac, peer_fd);
}

/*
 * Test 10: Database Hash changes when the database structure changes
 *
 * Build the peripheral DB, compute its hash, then modify the DB
 * (add a new service) and recompute.  Verify only the relational property
 * that the hashes differ.  Service Changed scheduling is not exercised here.
 */
ATF_TC(database_hash_changes_on_structure_mutation);
ATF_TC_HEAD(database_hash_changes_on_structure_mutation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Database Hash changes when service structure is modified");
}
ATF_TC_BODY(database_hash_changes_on_structure_mutation, tc)
{
	uint8_t hash_before[16], hash_after[16];

	build_peripheral_db();

	/* Compute initial hash */
	attdb_compute_db_hash(&db, hash_before);

	/* Modify the database — add a new service */
	attdb_add_service(&db, 0xFFF0);
	attdb_add_characteristic(&db, 0xFFF1,
	    GATT_PROP_READ, ATT_PERM_READ, "\x00", 1);

	/* Recompute hash */
	attdb_compute_db_hash(&db, hash_after);

	/* Part G §7.3.1 includes service declarations in the hash input. */
	ATF_CHECK_MSG(memcmp(hash_before, hash_after, 16) != 0,
	    "db_hash should change after adding a service");
}

/* ================================================================
 * ATT Server error path tests — verify correct error responses
 * ================================================================ */

/* Read invalid handle returns INVALID_HANDLE */
ATF_TC_WITHOUT_HEAD(read_invalid_handle);
ATF_TC_BODY(read_invalid_handle, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t req[3], rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	req[0] = ATT_OP_READ_REQ;
	put_le16(req + 1, 0xFFFF);  /* nonexistent handle */
	nr = server_request(peer_fd, &ac, req, 3, rsp, sizeof(rsp));

	ATF_REQUIRE(nr >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_HANDLE);

	mock_cleanup(&ac, peer_fd);
}

/* Read handle 0 (zero is invalid per spec) */
ATF_TC_WITHOUT_HEAD(read_handle_zero);
ATF_TC_BODY(read_handle_zero, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t req[3], rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	req[0] = ATT_OP_READ_REQ;
	put_le16(req + 1, 0x0000);
	nr = server_request(peer_fd, &ac, req, 3, rsp, sizeof(rsp));

	ATF_REQUIRE(nr >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_HANDLE);

	mock_cleanup(&ac, peer_fd);
}

/* Read with truncated PDU returns INVALID_PDU */
ATF_TC_WITHOUT_HEAD(read_truncated_pdu);
ATF_TC_BODY(read_truncated_pdu, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t req[2], rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	req[0] = ATT_OP_READ_REQ;
	req[1] = 0x01;  /* only 2 bytes, need 3 */
	nr = server_request(peer_fd, &ac, req, 2, rsp, sizeof(rsp));

	ATF_REQUIRE(nr >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_PDU);

	mock_cleanup(&ac, peer_fd);
}

/* Read Blob with non-zero offset on short attribute */
ATF_TC_WITHOUT_HEAD(read_blob_not_long);
ATF_TC_BODY(read_blob_not_long, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t req[5], rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;
	uint16_t name_handle;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	/* Find Device Name handle (short value, fits in MTU-1) */
	name_handle = 0;
	for (int i = 0; i < db.count; i++) {
		if (db.attrs[i].uuid16 == UUID_DEVICE_NAME &&
		    db.attrs[i].is_char_value) {
			name_handle = db.attrs[i].handle;
			break;
		}
	}
	ATF_REQUIRE(name_handle != 0);

	req[0] = ATT_OP_READ_BLOB_REQ;
	put_le16(req + 1, name_handle);
	put_le16(req + 3, 1);  /* offset > 0 on short attr */
	nr = server_request(peer_fd, &ac, req, 5, rsp, sizeof(rsp));

	ATF_REQUIRE(nr >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_LONG);

	mock_cleanup(&ac, peer_fd);
}

/* Write to read-only attribute */
ATF_TC_WITHOUT_HEAD(write_readonly);
ATF_TC_BODY(write_readonly, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t req[10], rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;
	uint16_t name_handle;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	name_handle = 0;
	for (int i = 0; i < db.count; i++) {
		if (db.attrs[i].uuid16 == UUID_DEVICE_NAME &&
		    db.attrs[i].is_char_value) {
			name_handle = db.attrs[i].handle;
			break;
		}
	}
	ATF_REQUIRE(name_handle != 0);

	req[0] = ATT_OP_WRITE_REQ;
	put_le16(req + 1, name_handle);
	req[3] = 0x41;  /* 'A' */
	nr = server_request(peer_fd, &ac, req, 4, rsp, sizeof(rsp));

	ATF_REQUIRE(nr >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_WRITE_NOT_PERMITTED);

	mock_cleanup(&ac, peer_fd);
}

/* Find Information with invalid handle range (start > end) */
ATF_TC_WITHOUT_HEAD(find_info_invalid_range);
ATF_TC_BODY(find_info_invalid_range, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t req[5], rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	req[0] = ATT_OP_FIND_INFO_REQ;
	put_le16(req + 1, 0x0010);  /* start */
	put_le16(req + 3, 0x0001);  /* end < start */
	nr = server_request(peer_fd, &ac, req, 5, rsp, sizeof(rsp));

	ATF_REQUIRE(nr >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_HANDLE);

	mock_cleanup(&ac, peer_fd);
}

/* Read By Group Type with non-grouping UUID */
ATF_TC_WITHOUT_HEAD(read_by_group_nonsvc_uuid);
ATF_TC_BODY(read_by_group_nonsvc_uuid, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t req[7], rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	req[0] = ATT_OP_READ_BY_GROUP_TYPE_REQ;
	put_le16(req + 1, 0x0001);
	put_le16(req + 3, 0xFFFF);
	put_le16(req + 5, UUID_DEVICE_NAME);
	nr = server_request(peer_fd, &ac, req, 7, rsp, sizeof(rsp));

	ATF_REQUIRE(nr >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_UNSUPPORTED_GROUP_TYPE);

	mock_cleanup(&ac, peer_fd);
}

/* Unknown ATT opcode returns REQUEST_NOT_SUPPORTED */
ATF_TC_WITHOUT_HEAD(unknown_opcode);
ATF_TC_BODY(unknown_opcode, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t req[3], rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	req[0] = BT_CORE63_ATT_RESERVED_REQUEST_OPCODE;
	req[1] = 0x00;
	req[2] = 0x00;
	nr = server_request(peer_fd, &ac, req, 3, rsp, sizeof(rsp));

	ATF_REQUIRE(nr >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_REQ_NOT_SUPPORTED);

	mock_cleanup(&ac, peer_fd);
}

/* Prepare Write queue overflow */
ATF_TC_WITHOUT_HEAD(prepare_write_queue_full);
ATF_TC_BODY(prepare_write_queue_full, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t req[10], rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;
	uint16_t custom_handle;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	/* Find writable custom char handle */
	custom_handle = 0;
	for (int i = 0; i < db.count; i++) {
		if (db.attrs[i].uuid16 == UUID_CUSTOM_CHAR &&
		    db.attrs[i].is_char_value) {
			custom_handle = db.attrs[i].handle;
			break;
		}
	}
	ATF_REQUIRE(custom_handle != 0);

	/* Fill the prepare queue (ATT_PREPARE_QUEUE_MAX = 16) */
	for (int q = 0; q < ATT_PREPARE_QUEUE_MAX; q++) {
		req[0] = ATT_OP_PREPARE_WRITE_REQ;
		put_le16(req + 1, custom_handle);
		put_le16(req + 3, 0);  /* offset */
		req[5] = (uint8_t)q;  /* 1 byte value */
		nr = server_request(peer_fd, &ac, req, 6, rsp, sizeof(rsp));
		ATF_REQUIRE(nr > 0);
		ATF_CHECK_EQ(rsp[0], ATT_OP_PREPARE_WRITE_RSP);
	}

	/* 17th prepare should fail with queue full */
	req[0] = ATT_OP_PREPARE_WRITE_REQ;
	put_le16(req + 1, custom_handle);
	put_le16(req + 3, 0);
	req[5] = 0xFF;
	nr = server_request(peer_fd, &ac, req, 6, rsp, sizeof(rsp));

	ATF_REQUIRE(nr >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_PREPARE_QUEUE_FULL);

	/* Cancel the queued writes */
	req[0] = ATT_OP_EXECUTE_WRITE_REQ;
	req[1] = BT_CORE63_ATT_EXECUTE_CANCEL;
	nr = server_request(peer_fd, &ac, req, 2, rsp, sizeof(rsp));
	ATF_CHECK_EQ(rsp[0], ATT_OP_EXECUTE_WRITE_RSP);

	mock_cleanup(&ac, peer_fd);
}

/* Robust Caching: write CSF bit, mutate DB, verify out-of-sync */
ATF_TC_WITHOUT_HEAD(robust_caching_out_of_sync);
ATF_TC_BODY(robust_caching_out_of_sync, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t req[10], rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;
	uint16_t csf_handle, hash_handle;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	/* Find Client Supported Features handle */
	csf_handle = 0;
	hash_handle = 0;
	for (int i = 0; i < db.count; i++) {
		if (db.attrs[i].uuid16 == UUID_CLIENT_SUPP_FEAT &&
		    db.attrs[i].is_char_value)
			csf_handle = db.attrs[i].handle;
		if (db.attrs[i].uuid16 == UUID_DATABASE_HASH &&
		    db.attrs[i].is_char_value)
			hash_handle = db.attrs[i].handle;
	}
	ATF_REQUIRE(csf_handle != 0);
	ATF_REQUIRE(hash_handle != 0);

	/* Step 1: Write Robust Caching bit to CSF */
	req[0] = ATT_OP_WRITE_REQ;
	put_le16(req + 1, csf_handle);
	req[3] = BT_CORE63_GATT_CSF_ROBUST_CACHING;
	nr = server_request(peer_fd, &ac, req, 4, rsp, sizeof(rsp));
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);
	ATF_CHECK(ac.robust_caching);
	/*
	 * Per Vol 3 Part G Sec 2.5.2.1 a CSF (Robust Caching) write does NOT by
	 * itself make the client change-aware — initial awareness is derived at
	 * connect time from the bonded Database Hash compare.  A CSF write only
	 * enables robust caching; it does not change awareness.
	 */

	/* Step 2: Simulate DB change — mark client as change-unaware */
	ac.change_aware = false;

	/*
	 * Step 3: a GATED request while change-unaware must get
	 * DATABASE_OUT_OF_SYNC.  Find Information is a discovery procedure and is
	 * NOT gated (Vol 3 Part G Table 3.43 / Sec 2.5.2.1), so drive Read-By-Type
	 * of a non-discovery type (Device Name 0x2A00) over a PARTIAL range.
	 */
	req[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(req + 1, 0x0001);
	put_le16(req + 3, 0x0005);
	put_le16(req + 5, UUID_DEVICE_NAME);
	nr = server_request(peer_fd, &ac, req, 7, rsp, sizeof(rsp));

	ATF_REQUIRE(nr >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_DATABASE_OUT_OF_SYNC);

	/* Step 4: Read Database Hash — should succeed and make us aware */
	req[0] = ATT_OP_READ_REQ;
	put_le16(req + 1, hash_handle);
	nr = server_request(peer_fd, &ac, req, 3, rsp, sizeof(rsp));
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_RSP);
	ATF_CHECK(ac.change_aware);  /* reading hash restores awareness */

	/* Step 5: Find Information should now succeed */
	req[0] = ATT_OP_FIND_INFO_REQ;
	put_le16(req + 1, 0x0001);
	put_le16(req + 3, 0xFFFF);
	nr = server_request(peer_fd, &ac, req, 5, rsp, sizeof(rsp));
	ATF_CHECK_EQ(rsp[0], ATT_OP_FIND_INFO_RSP);

	mock_cleanup(&ac, peer_fd);
}

/* Robust Caching: exempted opcodes pass even when change-unaware */
ATF_TC_WITHOUT_HEAD(robust_caching_exemptions);
ATF_TC_BODY(robust_caching_exemptions, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t req[10], rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr __unused;
	uint16_t hash_handle;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	/* Set up change-unaware state */
	ac.robust_caching = true;
	ac.change_aware = false;

	/* MTU exchange — should be exempted */
	req[0] = ATT_OP_MTU_REQ;
	put_le16(req + 1, 100);
	nr = server_request(peer_fd, &ac, req, 3, rsp, sizeof(rsp));
	ATF_CHECK_EQ(rsp[0], ATT_OP_MTU_RSP);

	/* Read request — exempted (for DB Hash read) */
	hash_handle = 0;
	for (int i = 0; i < db.count; i++) {
		if (db.attrs[i].uuid16 == UUID_DATABASE_HASH &&
		    db.attrs[i].is_char_value) {
			hash_handle = db.attrs[i].handle;
			break;
		}
	}
	ATF_REQUIRE(hash_handle != 0);

	req[0] = ATT_OP_READ_REQ;
	put_le16(req + 1, hash_handle);
	nr = server_request(peer_fd, &ac, req, 3, rsp, sizeof(rsp));
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_RSP);

	mock_cleanup(&ac, peer_fd);
}

/* CCCD write with invalid value (RFU bits set) gets masked */
ATF_TC_WITHOUT_HEAD(cccd_rfu_bits_masked);
ATF_TC_BODY(cccd_rfu_bits_masked, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t req[5], rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr __unused;
	uint16_t cccd_handle;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	/* Find the LAST CCCD handle (custom service, parent has NOTIFY) */
	cccd_handle = 0;
	for (int i = 0; i < db.count; i++) {
		if (db.attrs[i].uuid16 == GATT_UUID_CCCD)
			cccd_handle = db.attrs[i].handle;
	}
	ATF_REQUIRE(cccd_handle != 0);

	/* Write with RFU bits set: 0xFF01 — only bit 0 should be kept */
	req[0] = ATT_OP_WRITE_REQ;
	put_le16(req + 1, cccd_handle);
	put_le16(req + 3, 0xFF01);
	nr = server_request(peer_fd, &ac, req, 5, rsp, sizeof(rsp));
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);

	/*
	 * Read back.  Per Core Spec Vol 3 Part G Section 3.3.3.3
	 * Table 3.11, only bit 0 (Notification) and bit 1 (Indication)
	 * are defined; "all other bits" are Reserved for Future Use.
	 * The written value 0xFF01 has bit 0 set (Notification) with the
	 * RFU bits 2-15 set.  The parent (custom) characteristic has the
	 * Notify property, so the Notification bit is honoured and every
	 * RFU bit (mask 0xFFFC) must read back as 0 -> exactly 0x0001.
	 */
	req[0] = ATT_OP_READ_REQ;
	put_le16(req + 1, cccd_handle);
	nr = server_request(peer_fd, &ac, req, 3, rsp, sizeof(rsp));
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_RSP);
	ATF_CHECK_EQ(get_le16(rsp + 1), 0x0001);  /* Vol 3 Part G 3.3.3.3 */

	mock_cleanup(&ac, peer_fd);
}

/* Read By Type with handle range start=0 */
ATF_TC_WITHOUT_HEAD(read_by_type_zero_start);
ATF_TC_BODY(read_by_type_zero_start, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t req[7], rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	req[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(req + 1, 0x0000);  /* invalid start */
	put_le16(req + 3, 0xFFFF);
	put_le16(req + 5, BT_ASSIGNED_UUID_CHARACTERISTIC);
	nr = server_request(peer_fd, &ac, req, 7, rsp, sizeof(rsp));

	ATF_REQUIRE(nr >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_HANDLE);

	mock_cleanup(&ac, peer_fd);
}

/* Write to custom characteristic and read back */
ATF_TC_WITHOUT_HEAD(write_read_roundtrip);
ATF_TC_BODY(write_read_roundtrip, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t req[10], rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;
	uint16_t custom_handle;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	custom_handle = 0;
	for (int i = 0; i < db.count; i++) {
		if (db.attrs[i].uuid16 == UUID_CUSTOM_CHAR &&
		    db.attrs[i].is_char_value) {
			custom_handle = db.attrs[i].handle;
			break;
		}
	}
	ATF_REQUIRE(custom_handle != 0);

	/* Write 0x42 */
	req[0] = ATT_OP_WRITE_REQ;
	put_le16(req + 1, custom_handle);
	req[3] = 0x42;
	nr = server_request(peer_fd, &ac, req, 4, rsp, sizeof(rsp));
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);

	/* Read back */
	req[0] = ATT_OP_READ_REQ;
	put_le16(req + 1, custom_handle);
	nr = server_request(peer_fd, &ac, req, 3, rsp, sizeof(rsp));
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_RSP);
	ATF_CHECK_EQ(nr, 2);
	ATF_CHECK_EQ(rsp[1], 0x42);

	mock_cleanup(&ac, peer_fd);
}

/* Find By Type Value — find primary service by UUID */
ATF_TC_WITHOUT_HEAD(find_by_type_value);
ATF_TC_BODY(find_by_type_value, tc)
{
	struct att_conn ac;
	int peer_fd;
	uint8_t req[9], rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;

	build_peripheral_db();
	mock_pair(&ac, &peer_fd);

	req[0] = ATT_OP_FIND_BY_TYPE_VALUE_REQ;
	put_le16(req + 1, 0x0001);  /* start */
	put_le16(req + 3, 0xFFFF);  /* end */
	put_le16(req + 5, GATT_UUID_PRIMARY_SERVICE);  /* attr type */
	put_le16(req + 7, UUID_GAP_SERVICE);  /* value: GAP service UUID */

	nr = server_request(peer_fd, &ac, req, 9, rsp, sizeof(rsp));
	ATF_REQUIRE(nr > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_FIND_BY_TYPE_VALUE_RSP);
	/* Response contains [found_handle(2), group_end(2)] */
	ATF_CHECK(nr >= 5);

	mock_cleanup(&ac, peer_fd);
}

/*
 * P11: GAP service must expose the Central Address Resolution
 * characteristic (UUID 0x2AA6) with value 0x01.
 *
 * Core Spec Vol 3 Part C §12.4: a GAP peripheral that also operates as a
 * Central and supports LL Privacy (address resolution) shall include the
 * Central Address Resolution characteristic in its GAP service; the value
 * 0x01 means address resolution is supported.  The characteristic is
 * read-only.  This mirrors the GAP portion built by
 * peripheral_build_gattdb() (blued_peripheral.c) and exercises it through
 * the real ATT server: a Read Request must return 0x01, and a Write
 * Request must be rejected as Write Not Permitted.
 */
ATF_TC(gap_central_address_resolution);
ATF_TC_HEAD(gap_central_address_resolution, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "GAP exposes Central Address Resolution (0x2AA6) = 0x01, read-only");
}
ATF_TC_BODY(gap_central_address_resolution, tc)
{
	static const uint8_t appearance[] = { 0x00, 0x00 };
	struct att_db ldb;
	struct att_attr lattrs[PERIPH_MAX_ATTRS];
	uint8_t lval[PERIPH_VAL_SIZE];
	struct att_conn ac;
	int peer_fd;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	uint16_t car_handle = 0;
	ssize_t nr;
	int i;

	/* GAP service exactly as peripheral_build_gattdb() constructs it. */
	attdb_init(&ldb, lattrs, PERIPH_MAX_ATTRS, lval, PERIPH_VAL_SIZE);
	attdb_add_service(&ldb, UUID_GAP_SERVICE);
	attdb_add_characteristic(&ldb, UUID_DEVICE_NAME,
	    GATT_PROP_READ, ATT_PERM_READ,
	    PERIPHERAL_NAME, sizeof(PERIPHERAL_NAME) - 1);
	attdb_add_characteristic(&ldb, UUID_APPEARANCE,
	    GATT_PROP_READ, ATT_PERM_READ,
	    appearance, sizeof(appearance));
	attdb_add_characteristic(&ldb, UUID_CENTRAL_ADDR_RES,
	    GATT_PROP_READ, ATT_PERM_READ,
	    "\x01", 1);

	/* Locate the Central Address Resolution value handle. */
	for (i = 0; i < ldb.count; i++) {
		if (ldb.attrs[i].uuid16 == UUID_CENTRAL_ADDR_RES &&
		    ldb.attrs[i].is_char_value) {
			car_handle = ldb.attrs[i].handle;
			break;
		}
	}
	ATF_REQUIRE_MSG(car_handle != 0,
	    "Central Address Resolution characteristic (0x2AA6) missing from "
	    "GAP service");

	mock_pair(&ac, &peer_fd);

	/* Read Request -> value must be a single octet 0x01. */
	{
		uint8_t req[3];

		req[0] = ATT_OP_READ_REQ;
		put_le16(req + 1, car_handle);
		ATF_REQUIRE(send(peer_fd, req, sizeof(req),
		    0) == (ssize_t)sizeof(req));
		{
			uint8_t sbuf[ATT_PDU_BUF_SIZE];
			nr = recv(ac.fd, sbuf, ac.mtu, 0);
			ATF_REQUIRE(nr > 0);
			att_server_handle(&ac, &ldb, sbuf, (size_t)nr, -1, 0);
		}
		nr = recv(peer_fd, rsp, sizeof(rsp), 0);
		ATF_REQUIRE_EQ(nr, 2);
		ATF_CHECK_EQ(rsp[0], ATT_OP_READ_RSP);
		ATF_CHECK_EQ_MSG(rsp[1], 0x01,
		    "Central Address Resolution value must be 0x01 "
		    "(address resolution supported)");
	}

	/* Write Request -> read-only, must be rejected. */
	{
		uint8_t req[4];

		req[0] = ATT_OP_WRITE_REQ;
		put_le16(req + 1, car_handle);
		req[3] = 0x00;
		ATF_REQUIRE(send(peer_fd, req, sizeof(req),
		    0) == (ssize_t)sizeof(req));
		{
			uint8_t sbuf[ATT_PDU_BUF_SIZE];
			nr = recv(ac.fd, sbuf, ac.mtu, 0);
			ATF_REQUIRE(nr > 0);
			att_server_handle(&ac, &ldb, sbuf, (size_t)nr, -1, 0);
		}
		nr = recv(peer_fd, rsp, sizeof(rsp), 0);
		ATF_REQUIRE_EQ(nr, 5);
		ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
		ATF_CHECK_EQ_MSG(rsp[4], ATT_ERR_WRITE_NOT_PERMITTED,
		    "Central Address Resolution is read-only");
	}

	mock_cleanup(&ac, peer_fd);
}

/* ================================================================
 * Test registration
 * ================================================================ */

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, mtu_exchange);
	ATF_TP_ADD_TC(tp, service_discovery);
	ATF_TP_ADD_TC(tp, characteristic_discovery);
	ATF_TP_ADD_TC(tp, descriptor_discovery);
	ATF_TP_ADD_TC(tp, read_device_name);
	ATF_TP_ADD_TC(tp, cccd_write);
	ATF_TP_ADD_TC(tp, database_hash_exposed);
	ATF_TP_ADD_TC(tp, service_changed_indication);
	ATF_TP_ADD_TC(tp, service_changed_not_readable);
	ATF_TP_ADD_TC(tp, database_hash_changes_on_structure_mutation);

	/* ATT server error paths */
	ATF_TP_ADD_TC(tp, read_invalid_handle);
	ATF_TP_ADD_TC(tp, read_handle_zero);
	ATF_TP_ADD_TC(tp, read_truncated_pdu);
	ATF_TP_ADD_TC(tp, read_blob_not_long);
	ATF_TP_ADD_TC(tp, write_readonly);
	ATF_TP_ADD_TC(tp, find_info_invalid_range);
	ATF_TP_ADD_TC(tp, read_by_group_nonsvc_uuid);
	ATF_TP_ADD_TC(tp, unknown_opcode);
	ATF_TP_ADD_TC(tp, prepare_write_queue_full);
	ATF_TP_ADD_TC(tp, read_by_type_zero_start);
	ATF_TP_ADD_TC(tp, write_read_roundtrip);
	ATF_TP_ADD_TC(tp, find_by_type_value);

	/* Robust Caching */
	ATF_TP_ADD_TC(tp, robust_caching_out_of_sync);
	ATF_TP_ADD_TC(tp, robust_caching_exemptions);

	/* CCCD validation */
	ATF_TP_ADD_TC(tp, cccd_rfu_bits_masked);
	ATF_TP_ADD_TC(tp, gap_central_address_resolution);

	return (atf_no_error());
}
