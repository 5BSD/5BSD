/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF unit tests for GATT discovery and robust caching.
 *
 * Uses socketpair(AF_UNIX, SOCK_SEQPACKET, 0) to mock L2CAP ATT
 * channels so no real Bluetooth hardware is needed.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <signal.h>

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
#include "gatt.h"
#include "hci_log.h"
#include "hci_util.h"

#include "test_common.h"
#include "spec_oracles.h"

#define GTEST_ENUM(name, value) GTEST_##name = value,
enum {
	BT_CORE63_ATT_ORACLES(GTEST_ENUM)
	BT_CORE63_ATT_ERROR_ORACLES(GTEST_ENUM)
	BT_CORE63_GATT_PROPERTY_ORACLES(GTEST_ENUM)
};
#undef GTEST_ENUM

enum {
	GTEST_HANDLE_MIN = 0x0001,
	GTEST_HANDLE_MAX = 0xffff,
	GTEST_FIXTURE_VENDOR_SERVICE = 0xffe0,
	GTEST_FIXTURE_VENDOR_CHARACTERISTIC = 0xffe1,
	GTEST_FIXTURE_VENDOR_SERVICE_2 = 0xfff0,
	GTEST_FIXTURE_VENDOR_CHARACTERISTIC_2 = 0xfff1,
	GTEST_FIXTURE_VENDOR_DESCRIPTOR = 0xff01,
	GTEST_FIXTURE_NONHASH_DESCRIPTOR = 0x2906,
};

/* ================================================================
 * Mock helper: create a socketpair-backed att_conn
 * ================================================================ */

static void
att_mock_pair(struct att_conn *ac, int *peer_fd)
{
	int fds[2];

	/* Ignore SIGPIPE — fork-based tests may write to closed peers */
	signal(SIGPIPE, SIG_IGN);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	memset(ac, 0, sizeof(*ac));
	ac->fd = fds[0];
	ac->mtu = BT_CORE63_ATT_DEFAULT_MTU;
	ac->buf = malloc(ATT_MAX_MTU);
	ac->bearer_fd = -1;
	ATF_REQUIRE(ac->buf != NULL);
	*peer_fd = fds[1];
}

static void
att_mock_cleanup(struct att_conn *ac, int peer_fd)
{

	free(ac->buf);
	ac->buf = NULL;
	if (ac->fd >= 0)
		close(ac->fd);
	if (peer_fd >= 0)
		close(peer_fd);
}

/* Suppress unused warning — kept for symmetry with att_test.c */
static void (*att_mock_cleanup_ref)(struct att_conn *, int)
    __unused = att_mock_cleanup;

/* ================================================================
 * Helper: build a standard test database with known structure.
 *
 * GAP Service (BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE):
 *   handle 1: Primary Service Decl (BT_ASSIGNED_UUID_PRIMARY_SERVICE), value=BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE
 *   handle 2: Char Decl (BT_ASSIGNED_UUID_CHARACTERISTIC), props=READ
 *   handle 3: Device Name (BT_ASSIGNED_UUID_DEVICE_NAME), value="Test"
 *
 * Custom Service (GTEST_FIXTURE_VENDOR_SERVICE):
 *   handle 4: Primary Service Decl (BT_ASSIGNED_UUID_PRIMARY_SERVICE), value=GTEST_FIXTURE_VENDOR_SERVICE
 *   handle 5: Char Decl (BT_ASSIGNED_UUID_CHARACTERISTIC), props=READ|WRITE|NOTIFY
 *   handle 6: Custom Char (GTEST_FIXTURE_VENDOR_CHARACTERISTIC), value=0xAA 0xBB 0xCC 0xDD
 *   handle 7: CCCD (BT_ASSIGNED_UUID_CCCD), value=0x0000
 * ================================================================ */

#define TEST_DB_MAX_ATTRS	32
#define TEST_DB_VAL_SIZE	512

static void
build_test_db(struct att_db *db, struct att_attr *attrs, uint8_t *val_buf)
{

	attdb_init(db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);

	/* GAP Service */
	attdb_add_service(db, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
	attdb_add_characteristic(db, BT_ASSIGNED_UUID_DEVICE_NAME,
	    GTEST_GATT_PROP_READ, ATT_PERM_READ, "Test", 4);

	/* Custom Service */
	attdb_add_service(db, GTEST_FIXTURE_VENDOR_SERVICE);
	attdb_add_characteristic(db, GTEST_FIXTURE_VENDOR_CHARACTERISTIC,
	    GTEST_GATT_PROP_READ | GTEST_GATT_PROP_WRITE |
	    GTEST_GATT_PROP_NOTIFY,
	    ATT_PERM_READ | ATT_PERM_WRITE,
	    "\xAA\xBB\xCC\xDD", 4);
	attdb_add_cccd(db);
}

/* ================================================================
 * GATT DISCOVERY TESTS
 * ================================================================ */

/*
 * 1. test_gatt_discover_primary_services
 *
 * Fork a child mock server that responds to Read By Group Type
 * (opcode 0x10) with UUID BT_ASSIGNED_UUID_PRIMARY_SERVICE, returning 3 primary services.
 */
ATF_TC_WITHOUT_HEAD(test_gatt_discover_primary_services);
ATF_TC_BODY(test_gatt_discover_primary_services, tc)
{
	struct att_conn ac;
	int peer;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: mock server */
		uint8_t req[32];
		ssize_t n;
		int round;

		close(ac.fd);

		/*
		 * First request: return 3 services in one response.
		 * entry_len=6 (start(2)+end(2)+uuid16(2))
		 * Format: [opcode(0x11)] [entry_len(6)]
		 *         [svc1: 0x0001-0x0003, UUID=BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE]
		 *         [svc2: 0x0004-0x0007, UUID=GTEST_FIXTURE_VENDOR_SERVICE]
		 *         [svc3: 0x0008-0x000A, UUID=BT_ASSIGNED_UUID_BATTERY_SERVICE]
		 */
		for (round = 0; round < 2; round++) {
			n = recv(peer, req, sizeof(req), 0);
			if (n < 7 || req[0] != GTEST_ATT_OP_READ_BY_GROUP_TYPE_REQ) {
				close(peer);
				_exit(1);
			}
			/* Verify UUID = BT_ASSIGNED_UUID_PRIMARY_SERVICE (primary service) */
			if (get_le16(req + 5) != BT_ASSIGNED_UUID_PRIMARY_SERVICE) {
				close(peer);
				_exit(2);
			}

			if (round == 0) {
				uint8_t rsp[1 + 1 + 3 * 6];
				rsp[0] = GTEST_ATT_OP_READ_BY_GROUP_TYPE_RSP;
				rsp[1] = 6; /* entry_len */
				/* Service 1: 0x0001-0x0003, UUID BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE */
				put_le16(rsp + 2, 0x0001);
				put_le16(rsp + 4, 0x0003);
				put_le16(rsp + 6, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
				/* Service 2: 0x0004-0x0007, UUID GTEST_FIXTURE_VENDOR_SERVICE */
				put_le16(rsp + 8, 0x0004);
				put_le16(rsp + 10, 0x0007);
				put_le16(rsp + 12, GTEST_FIXTURE_VENDOR_SERVICE);
				/* Service 3: 0x0008-0x000A, UUID BT_ASSIGNED_UUID_BATTERY_SERVICE */
				put_le16(rsp + 14, 0x0008);
				put_le16(rsp + 16, 0x000A);
				put_le16(rsp + 18, BT_ASSIGNED_UUID_BATTERY_SERVICE);
				send(peer, rsp, sizeof(rsp), 0);
			} else {
				/*
				 * Second request: return Attribute Not Found
				 * error to signal end of discovery.
				 */
				uint8_t err[5];
				err[0] = GTEST_ATT_OP_ERROR_RSP;
				err[1] = GTEST_ATT_OP_READ_BY_GROUP_TYPE_REQ;
				put_le16(err + 2, get_le16(req + 1));
				err[4] = GTEST_ATT_ERR_ATTR_NOT_FOUND;
				send(peer, err, sizeof(err), 0);
			}
		}

		close(peer);
		_exit(0);
	}

	/* Parent: client side */
	close(peer);
	struct gatt_service svcs[GATT_MAX_SERVICES];
	int nsvcs = 0;
	int ret = gatt_discover_primary_services(&ac, svcs,
	    GATT_MAX_SERVICES, &nsvcs);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(nsvcs, 3);

	ATF_CHECK_EQ(svcs[0].start_handle, 0x0001);
	ATF_CHECK_EQ(svcs[0].end_handle, 0x0003);
	ATF_CHECK_EQ(svcs[0].uuid16, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);

	ATF_CHECK_EQ(svcs[1].start_handle, 0x0004);
	ATF_CHECK_EQ(svcs[1].end_handle, 0x0007);
	ATF_CHECK_EQ(svcs[1].uuid16, GTEST_FIXTURE_VENDOR_SERVICE);

	ATF_CHECK_EQ(svcs[2].start_handle, 0x0008);
	ATF_CHECK_EQ(svcs[2].end_handle, 0x000A);
	ATF_CHECK_EQ(svcs[2].uuid16, BT_ASSIGNED_UUID_BATTERY_SERVICE);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
}

/*
 * 2. test_gatt_discover_characteristics
 *
 * Discover characteristics within a service handle range.
 * Mock server responds to Read By Type (0x08) with UUID BT_ASSIGNED_UUID_CHARACTERISTIC.
 */
ATF_TC_WITHOUT_HEAD(test_gatt_discover_characteristics);
ATF_TC_BODY(test_gatt_discover_characteristics, tc)
{
	struct att_conn ac;
	int peer;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		uint8_t req[32];
		ssize_t n;
		int round;

		close(ac.fd);

		for (round = 0; round < 2; round++) {
			n = recv(peer, req, sizeof(req), 0);
			if (n < 7 || req[0] != GTEST_ATT_OP_READ_BY_TYPE_REQ) {
				close(peer);
				_exit(1);
			}
			/* Verify UUID = BT_ASSIGNED_UUID_CHARACTERISTIC (characteristic) */
			if (get_le16(req + 5) != BT_ASSIGNED_UUID_CHARACTERISTIC) {
				close(peer);
				_exit(2);
			}

			if (round == 0) {
				/*
				 * Response: 2 characteristics.
				 * entry_len=7: decl_handle(2) + props(1) +
				 *              value_handle(2) + uuid16(2)
				 */
				uint8_t rsp[1 + 1 + 2 * 7];
				rsp[0] = GTEST_ATT_OP_READ_BY_TYPE_RSP;
				rsp[1] = 7; /* entry_len */
				/* Char 1: decl=0x0002, props=READ,
				 * val=0x0003, UUID=BT_ASSIGNED_UUID_DEVICE_NAME */
				put_le16(rsp + 2, 0x0002);
				rsp[4] = GTEST_GATT_PROP_READ;
				put_le16(rsp + 5, 0x0003);
				put_le16(rsp + 7, BT_ASSIGNED_UUID_DEVICE_NAME);
				/* Char 2: decl=0x0005, props=RWN,
				 * val=0x0006, UUID=GTEST_FIXTURE_VENDOR_CHARACTERISTIC */
				put_le16(rsp + 9, 0x0005);
				rsp[11] = GTEST_GATT_PROP_READ | GTEST_GATT_PROP_WRITE |
				    GTEST_GATT_PROP_NOTIFY;
				put_le16(rsp + 12, 0x0006);
				put_le16(rsp + 14, GTEST_FIXTURE_VENDOR_CHARACTERISTIC);
				send(peer, rsp, sizeof(rsp), 0);
			} else {
				uint8_t err[5];
				err[0] = GTEST_ATT_OP_ERROR_RSP;
				err[1] = GTEST_ATT_OP_READ_BY_TYPE_REQ;
				put_le16(err + 2, get_le16(req + 1));
				err[4] = GTEST_ATT_ERR_ATTR_NOT_FOUND;
				send(peer, err, sizeof(err), 0);
			}
		}

		close(peer);
		_exit(0);
	}

	close(peer);
	struct gatt_char chars[GATT_MAX_CHARS];
	int nchars = 0;
	int ret = gatt_discover_characteristics(&ac, 0x0001, 0x0007,
	    chars, GATT_MAX_CHARS, &nchars);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(nchars, 2);

	ATF_CHECK_EQ(chars[0].decl_handle, 0x0002);
	ATF_CHECK_EQ(chars[0].properties, GTEST_GATT_PROP_READ);
	ATF_CHECK_EQ(chars[0].value_handle, 0x0003);
	ATF_CHECK_EQ(chars[0].uuid16, BT_ASSIGNED_UUID_DEVICE_NAME);

	ATF_CHECK_EQ(chars[1].decl_handle, 0x0005);
	ATF_CHECK_EQ(chars[1].properties,
	    GTEST_GATT_PROP_READ | GTEST_GATT_PROP_WRITE | GTEST_GATT_PROP_NOTIFY);
	ATF_CHECK_EQ(chars[1].value_handle, 0x0006);
	ATF_CHECK_EQ(chars[1].uuid16, GTEST_FIXTURE_VENDOR_CHARACTERISTIC);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
}

/*
 * 3. test_gatt_discover_descriptors
 *
 * Discover descriptors within a characteristic handle range.
 * Mock server responds to Find Information (0x04) with
 * descriptor handle/UUID pairs.
 */
ATF_TC_WITHOUT_HEAD(test_gatt_discover_descriptors);
ATF_TC_BODY(test_gatt_discover_descriptors, tc)
{
	struct att_conn ac;
	int peer;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		uint8_t req[32];
		ssize_t n;
		int round;

		close(ac.fd);

		for (round = 0; round < 2; round++) {
			n = recv(peer, req, sizeof(req), 0);
			if (n < 5 || req[0] != GTEST_ATT_OP_FIND_INFO_REQ) {
				close(peer);
				_exit(1);
			}

			if (round == 0) {
				/*
				 * Response: format=1 (16-bit UUID),
				 * 2 descriptors.
				 * entry_len=4: handle(2) + uuid16(2)
				 */
				uint8_t rsp[1 + 1 + 2 * 4];
				rsp[0] = GTEST_ATT_OP_FIND_INFO_RSP;
				rsp[1] = 1; /* format: 16-bit UUID */
				/* Descriptor 1: handle=0x0007,
				 * UUID=BT_ASSIGNED_UUID_CCCD (CCCD) */
				put_le16(rsp + 2, 0x0007);
				put_le16(rsp + 4, BT_ASSIGNED_UUID_CCCD);
				/* Descriptor 2: handle=0x0008,
				 * UUID=BT_ASSIGNED_UUID_CHARACTERISTIC_USER_DESCRIPTION (Char User Desc) */
				put_le16(rsp + 6, 0x0008);
				put_le16(rsp + 8, BT_ASSIGNED_UUID_CHARACTERISTIC_USER_DESCRIPTION);
				send(peer, rsp, sizeof(rsp), 0);
			} else {
				uint8_t err[5];
				err[0] = GTEST_ATT_OP_ERROR_RSP;
				err[1] = GTEST_ATT_OP_FIND_INFO_REQ;
				put_le16(err + 2, get_le16(req + 1));
				err[4] = GTEST_ATT_ERR_ATTR_NOT_FOUND;
				send(peer, err, sizeof(err), 0);
			}
		}

		close(peer);
		_exit(0);
	}

	close(peer);
	struct gatt_desc descs[GATT_MAX_DESCS];
	int ndescs = 0;
	int ret = gatt_discover_descriptors(&ac, 0x0007, 0x000A,
	    descs, GATT_MAX_DESCS, &ndescs);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(ndescs, 2);

	ATF_CHECK_EQ(descs[0].handle, 0x0007);
	ATF_CHECK_EQ(descs[0].uuid16, BT_ASSIGNED_UUID_CCCD);

	ATF_CHECK_EQ(descs[1].handle, 0x0008);
	ATF_CHECK_EQ(descs[1].uuid16, BT_ASSIGNED_UUID_CHARACTERISTIC_USER_DESCRIPTION);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
}

/*
 * 4. test_gatt_discover_primary_by_uuid
 *
 * Uses Find By Type Value (opcode 0x06) with UUID BT_ASSIGNED_UUID_PRIMARY_SERVICE.
 * Mock server returns handle pairs for a single matching service
 * out of 3 on the server.
 */
ATF_TC_WITHOUT_HEAD(test_gatt_discover_primary_by_uuid);
ATF_TC_BODY(test_gatt_discover_primary_by_uuid, tc)
{
	struct att_conn ac;
	int peer;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		uint8_t req[32];
		ssize_t n;
		int round;

		close(ac.fd);

		for (round = 0; round < 2; round++) {
			n = recv(peer, req, sizeof(req), 0);
			if (n < 7 ||
			    req[0] != GTEST_ATT_OP_FIND_BY_TYPE_VALUE_REQ) {
				close(peer);
				_exit(1);
			}
			/* Verify type UUID = BT_ASSIGNED_UUID_PRIMARY_SERVICE */
			if (get_le16(req + 5) != BT_ASSIGNED_UUID_PRIMARY_SERVICE) {
				close(peer);
				_exit(2);
			}
			/* Verify value = GTEST_FIXTURE_VENDOR_SERVICE (LE) */
			if (n < 9 || get_le16(req + 7) != GTEST_FIXTURE_VENDOR_SERVICE) {
				close(peer);
				_exit(3);
			}

			if (round == 0) {
				/*
				 * Response: 1 matching service.
				 * Each entry: found_handle(2) +
				 *             group_end_handle(2)
				 */
				uint8_t rsp[1 + 4];
				rsp[0] = GTEST_ATT_OP_FIND_BY_TYPE_VALUE_RSP;
				put_le16(rsp + 1, 0x0004); /* start */
				put_le16(rsp + 3, 0x0007); /* end */
				send(peer, rsp, sizeof(rsp), 0);
			} else {
				uint8_t err[5];
				err[0] = GTEST_ATT_OP_ERROR_RSP;
				err[1] = GTEST_ATT_OP_FIND_BY_TYPE_VALUE_REQ;
				put_le16(err + 2, get_le16(req + 1));
				err[4] = GTEST_ATT_ERR_ATTR_NOT_FOUND;
				send(peer, err, sizeof(err), 0);
			}
		}

		close(peer);
		_exit(0);
	}

	close(peer);
	struct gatt_service svcs[GATT_MAX_SERVICES];
	int nsvcs = 0;
	int ret = gatt_discover_primary_service_by_uuid(&ac, GTEST_FIXTURE_VENDOR_SERVICE,
	    svcs, GATT_MAX_SERVICES, &nsvcs);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(nsvcs, 1);
	ATF_CHECK_EQ(svcs[0].start_handle, 0x0004);
	ATF_CHECK_EQ(svcs[0].end_handle, 0x0007);
	ATF_CHECK_EQ(svcs[0].uuid16, GTEST_FIXTURE_VENDOR_SERVICE);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
}

/*
 * 5. test_gatt_discover_primary_by_uuid128
 *
 * Same as above but with a 128-bit UUID.
 */
ATF_TC_WITHOUT_HEAD(test_gatt_discover_primary_by_uuid128);
ATF_TC_BODY(test_gatt_discover_primary_by_uuid128, tc)
{
	struct att_conn ac;
	int peer;
	/* Custom 128-bit UUID (vendor-specific) in LE wire order */
	static const uint8_t custom_uuid[16] = {
		0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80,
		0x00, 0x10, 0x00, 0x00, 0x01, 0xAB, 0xCD, 0xEF
	};

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		uint8_t req[64];
		ssize_t n;
		int round;

		close(ac.fd);

		for (round = 0; round < 2; round++) {
			n = recv(peer, req, sizeof(req), 0);
			if (n < 7 ||
			    req[0] != GTEST_ATT_OP_FIND_BY_TYPE_VALUE_REQ) {
				close(peer);
				_exit(1);
			}
			/* Verify type UUID = BT_ASSIGNED_UUID_PRIMARY_SERVICE */
			if (get_le16(req + 5) != BT_ASSIGNED_UUID_PRIMARY_SERVICE) {
				close(peer);
				_exit(2);
			}
			/* Verify 128-bit UUID value */
			if (n < 23 ||
			    memcmp(req + 7, custom_uuid, 16) != 0) {
				close(peer);
				_exit(3);
			}

			if (round == 0) {
				uint8_t rsp[1 + 4];
				rsp[0] = GTEST_ATT_OP_FIND_BY_TYPE_VALUE_RSP;
				put_le16(rsp + 1, 0x0010);
				put_le16(rsp + 3, 0x0015);
				send(peer, rsp, sizeof(rsp), 0);
			} else {
				uint8_t err[5];
				err[0] = GTEST_ATT_OP_ERROR_RSP;
				err[1] = GTEST_ATT_OP_FIND_BY_TYPE_VALUE_REQ;
				put_le16(err + 2, get_le16(req + 1));
				err[4] = GTEST_ATT_ERR_ATTR_NOT_FOUND;
				send(peer, err, sizeof(err), 0);
			}
		}

		close(peer);
		_exit(0);
	}

	close(peer);
	struct gatt_service svcs[GATT_MAX_SERVICES];
	int nsvcs = 0;
	int ret = gatt_discover_primary_service_by_uuid128(&ac, custom_uuid,
	    svcs, GATT_MAX_SERVICES, &nsvcs);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(nsvcs, 1);
	ATF_CHECK_EQ(svcs[0].start_handle, 0x0010);
	ATF_CHECK_EQ(svcs[0].end_handle, 0x0015);
	ATF_CHECK_EQ(svcs[0].uuid16, 0);
	ATF_CHECK_EQ(memcmp(svcs[0].uuid128, custom_uuid, 16), 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
}

/*
 * 6. test_gatt_discover_secondary_services (FreeBSD extension)
 *
 * Uses Read By Group Type with the Secondary Service declaration.  Core 6.3
 * Vol 3 Part G §3.1 explicitly defines no discovery procedure for secondary
 * services, so this is implementation-contract coverage, not a normative
 * GATT discovery procedure.
 */
ATF_TC_WITHOUT_HEAD(test_gatt_discover_secondary_services);
ATF_TC_BODY(test_gatt_discover_secondary_services, tc)
{
	struct att_conn ac;
	int peer;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		uint8_t req[32];
		ssize_t n;
		int round;

		close(ac.fd);

		for (round = 0; round < 2; round++) {
			n = recv(peer, req, sizeof(req), 0);
			if (n < 7 ||
			    req[0] != GTEST_ATT_OP_READ_BY_GROUP_TYPE_REQ) {
				close(peer);
				_exit(1);
			}
			/* Verify UUID = BT_ASSIGNED_UUID_SECONDARY_SERVICE (secondary service) */
			if (get_le16(req + 5) != BT_ASSIGNED_UUID_SECONDARY_SERVICE) {
				close(peer);
				_exit(2);
			}

			if (round == 0) {
				/* 1 secondary service */
				uint8_t rsp[1 + 1 + 6];
				rsp[0] = GTEST_ATT_OP_READ_BY_GROUP_TYPE_RSP;
				rsp[1] = 6; /* entry_len */
				put_le16(rsp + 2, 0x0020);
				put_le16(rsp + 4, 0x0025);
				put_le16(rsp + 6, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);
				send(peer, rsp, sizeof(rsp), 0);
			} else {
				uint8_t err[5];
				err[0] = GTEST_ATT_OP_ERROR_RSP;
				err[1] = GTEST_ATT_OP_READ_BY_GROUP_TYPE_REQ;
				put_le16(err + 2, get_le16(req + 1));
				err[4] = GTEST_ATT_ERR_ATTR_NOT_FOUND;
				send(peer, err, sizeof(err), 0);
			}
		}

		close(peer);
		_exit(0);
	}

	close(peer);
	struct gatt_service svcs[GATT_MAX_SERVICES];
	int nsvcs = 0;
	int ret = gatt_discover_secondary_services(&ac, svcs,
	    GATT_MAX_SERVICES, &nsvcs);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(nsvcs, 1);
	ATF_CHECK_EQ(svcs[0].start_handle, 0x0020);
	ATF_CHECK_EQ(svcs[0].end_handle, 0x0025);
	ATF_CHECK_EQ(svcs[0].uuid16, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
}

/*
 * 7. test_gatt_discover_includes
 *
 * Uses Read By Type (opcode 0x08) with UUID BT_ASSIGNED_UUID_INCLUDE.
 * Tests both cases:
 *   - 8-byte entry with inline 16-bit UUID
 *   - 6-byte entry requiring separate Read for 128-bit UUID
 */
ATF_TC_WITHOUT_HEAD(test_gatt_discover_includes);
ATF_TC_BODY(test_gatt_discover_includes, tc)
{
	struct att_conn ac;
	int peer;
	/* 128-bit UUID expected from separate Read */
	static const uint8_t inc128_uuid[16] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
	};

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		uint8_t req[32];
		ssize_t n;
		int phase = 0;

		close(ac.fd);

		/*
		 * Phase 0: Read By Type for includes, return one
		 *          8-byte entry (with inline 16-bit UUID).
		 * Phase 1: Read By Type continues, return one
		 *          6-byte entry (no inline UUID).
		 * Phase 2: Read request for the 128-bit UUID
		 *          of the included service.
		 * Phase 3: Read By Type continues, return
		 *          GTEST_ATT_ERR_ATTR_NOT_FOUND.
		 */
		while (phase < 4) {
			n = recv(peer, req, sizeof(req), 0);
			if (n < 1) {
				close(peer);
				_exit(10);
			}

			if (phase == 0) {
				if (req[0] != GTEST_ATT_OP_READ_BY_TYPE_REQ ||
				    n < 7) {
					close(peer);
					_exit(1);
				}
				if (get_le16(req + 5) != BT_ASSIGNED_UUID_INCLUDE) {
					close(peer);
					_exit(2);
				}
				/*
				 * entry_len=8: handle(2) + start(2) +
				 * end(2) + uuid16(2)
				 */
				uint8_t rsp[1 + 1 + 8];
				rsp[0] = GTEST_ATT_OP_READ_BY_TYPE_RSP;
				rsp[1] = 8;
				put_le16(rsp + 2, 0x0004); /* incl handle */
				put_le16(rsp + 4, 0x0020); /* start */
				put_le16(rsp + 6, 0x0025); /* end */
				put_le16(rsp + 8, BT_ASSIGNED_UUID_DEVICE_INFORMATION_SERVICE); /* uuid16 */
				send(peer, rsp, sizeof(rsp), 0);
				phase = 1;
			} else if (phase == 1) {
				if (req[0] != GTEST_ATT_OP_READ_BY_TYPE_REQ ||
				    n < 7) {
					close(peer);
					_exit(3);
				}
				/*
				 * entry_len=6: handle(2) + start(2) +
				 * end(2), no UUID
				 */
				uint8_t rsp[1 + 1 + 6];
				rsp[0] = GTEST_ATT_OP_READ_BY_TYPE_RSP;
				rsp[1] = 6;
				put_le16(rsp + 2, 0x0006); /* incl handle */
				put_le16(rsp + 4, 0x0030); /* start */
				put_le16(rsp + 6, 0x0035); /* end */
				send(peer, rsp, sizeof(rsp), 0);
				phase = 2;
			} else if (phase == 2) {
				/*
				 * Expect an ATT Read Request for
				 * handle 0x0030 (the start handle of
				 * the included service) to resolve
				 * its 128-bit UUID.
				 */
				if (req[0] != GTEST_ATT_OP_READ_REQ || n < 3) {
					close(peer);
					_exit(4);
				}
				if (get_le16(req + 1) != 0x0030) {
					close(peer);
					_exit(5);
				}
				/* Reply with 16 bytes (128-bit UUID) */
				uint8_t rsp[1 + 16];
				rsp[0] = GTEST_ATT_OP_READ_RSP;
				memcpy(rsp + 1, inc128_uuid, 16);
				send(peer, rsp, sizeof(rsp), 0);
				phase = 3;
			} else {
				/* Phase 3: continuation Read By Type */
				if (req[0] != GTEST_ATT_OP_READ_BY_TYPE_REQ) {
					close(peer);
					_exit(6);
				}
				uint8_t err[5];
				err[0] = GTEST_ATT_OP_ERROR_RSP;
				err[1] = GTEST_ATT_OP_READ_BY_TYPE_REQ;
				put_le16(err + 2, get_le16(req + 1));
				err[4] = GTEST_ATT_ERR_ATTR_NOT_FOUND;
				send(peer, err, sizeof(err), 0);
				phase = 4;
			}
		}

		close(peer);
		_exit(0);
	}

	close(peer);
	struct gatt_include includes[GATT_MAX_INCLUDES];
	int ninc = 0;
	int ret = gatt_discover_includes(&ac, 0x0001, 0x000A,
	    includes, GATT_MAX_INCLUDES, &ninc);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(ninc, 2);

	/* First include: 16-bit UUID inline */
	ATF_CHECK_EQ(includes[0].handle, 0x0004);
	ATF_CHECK_EQ(includes[0].start_handle, 0x0020);
	ATF_CHECK_EQ(includes[0].end_handle, 0x0025);
	ATF_CHECK_EQ(includes[0].uuid16, BT_ASSIGNED_UUID_DEVICE_INFORMATION_SERVICE);
	ATF_CHECK(includes[0].has_uuid);

	/* Second include: 128-bit UUID from separate Read */
	ATF_CHECK_EQ(includes[1].handle, 0x0006);
	ATF_CHECK_EQ(includes[1].start_handle, 0x0030);
	ATF_CHECK_EQ(includes[1].end_handle, 0x0035);
	ATF_CHECK_EQ(includes[1].uuid16, 0);
	ATF_CHECK(includes[1].has_uuid);
	ATF_CHECK_EQ(memcmp(includes[1].uuid128, inc128_uuid, 16), 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
}

/* ================================================================
 * GATT ROBUST CACHING TESTS
 * ================================================================ */

/*
 * 8. test_gatt_db_hash_repeatability
 *
 * Build a test database and verify repeatability.  Core §7.3.1 does not
 * reserve the all-zero CMAC output, so zero is not a valid rejection oracle.
 */
ATF_TC_WITHOUT_HEAD(test_gatt_db_hash_repeatability);
ATF_TC_BODY(test_gatt_db_hash_repeatability, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t hash1[16], hash2[16];

	build_test_db(&db, attrs, val_buf);

	memset(hash1, 0, sizeof(hash1));
	memset(hash2, 0, sizeof(hash2));

	attdb_compute_db_hash(&db, hash1);

	/* Same DB produces same hash (deterministic) */
	attdb_compute_db_hash(&db, hash2);
	ATF_CHECK_EQ(memcmp(hash1, hash2, 16), 0);
}

/*
 * 9. test_gatt_db_hash_changes_on_modification
 *
 * Add an attribute to the DB, recompute hash, verify it changed.
 */
ATF_TC_WITHOUT_HEAD(test_gatt_db_hash_changes_on_modification);
ATF_TC_BODY(test_gatt_db_hash_changes_on_modification, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t hash_before[16], hash_after[16];

	build_test_db(&db, attrs, val_buf);
	attdb_compute_db_hash(&db, hash_before);

	/* Add another service to modify the DB */
	attdb_add_service(&db, BT_ASSIGNED_UUID_BATTERY_SERVICE);
	attdb_add_characteristic(&db, BT_ASSIGNED_UUID_BATTERY_LEVEL,
	    GTEST_GATT_PROP_READ | GTEST_GATT_PROP_NOTIFY,
	    ATT_PERM_READ, "\x64", 1);

	attdb_compute_db_hash(&db, hash_after);

	/* Hash must differ after modification */
	ATF_CHECK(memcmp(hash_before, hash_after, 16) != 0);
}

/*
 * 10. test_gatt_db_hash_excludes_char_values
 *
 * Build two databases identical in structure but with different
 * characteristic values.  Per Core Spec Vol 3 Part G Section 7.3.1,
 * characteristic values are excluded from the hash, so both
 * databases must produce the same hash.
 */
ATF_TC_WITHOUT_HEAD(test_gatt_db_hash_excludes_char_values);
ATF_TC_BODY(test_gatt_db_hash_excludes_char_values, tc)
{
	struct att_db db1, db2;
	struct att_attr attrs1[TEST_DB_MAX_ATTRS], attrs2[TEST_DB_MAX_ATTRS];
	uint8_t val1[TEST_DB_VAL_SIZE], val2[TEST_DB_VAL_SIZE];
	uint8_t hash1[16], hash2[16];

	/* DB1: characteristic value = "AAAA" */
	attdb_init(&db1, attrs1, TEST_DB_MAX_ATTRS, val1, TEST_DB_VAL_SIZE);
	attdb_add_service(&db1, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
	attdb_add_characteristic(&db1, BT_ASSIGNED_UUID_DEVICE_NAME,
	    GTEST_GATT_PROP_READ, ATT_PERM_READ, "AAAA", 4);

	/* DB2: same structure, different value = "ZZZZ" */
	attdb_init(&db2, attrs2, TEST_DB_MAX_ATTRS, val2, TEST_DB_VAL_SIZE);
	attdb_add_service(&db2, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
	attdb_add_characteristic(&db2, BT_ASSIGNED_UUID_DEVICE_NAME,
	    GTEST_GATT_PROP_READ, ATT_PERM_READ, "ZZZZ", 4);

	attdb_compute_db_hash(&db1, hash1);
	attdb_compute_db_hash(&db2, hash2);

	/* Hashes must be equal since char values are excluded */
	ATF_CHECK_EQ(memcmp(hash1, hash2, 16), 0);
}

/*
 * 10b. test_gatt_read_database_hash
 *
 * Mock a peer that serves UUID BT_ASSIGNED_UUID_DATABASE_HASH (Database Hash) with a known
 * 16-byte hash value.  Verify gatt_read_database_hash() returns the
 * correct hash.
 */
ATF_TC_WITHOUT_HEAD(test_gatt_read_database_hash);
ATF_TC_BODY(test_gatt_read_database_hash, tc)
{
	struct att_conn ac;
	int peer;
	static const uint8_t expected_hash[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
	};

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		uint8_t req[32];
		ssize_t n;

		close(ac.fd);

		/* Expect Read By Type Request with UUID BT_ASSIGNED_UUID_DATABASE_HASH */
		n = recv(peer, req, sizeof(req), 0);
		if (n < 7 || req[0] != GTEST_ATT_OP_READ_BY_TYPE_REQ) {
			close(peer);
			_exit(1);
		}
		/* Verify UUID = BT_ASSIGNED_UUID_DATABASE_HASH (Database Hash) */
		if (get_le16(req + 5) != BT_ASSIGNED_UUID_DATABASE_HASH) {
			close(peer);
			_exit(2);
		}

		/*
		 * Respond with Read By Type Response:
		 * [opcode(0x09)] [attr_data_len=18] [handle(2) + hash(16)]
		 * Total: 1 + 1 + 18 = 20 bytes
		 */
		uint8_t rsp[1 + 1 + 2 + 16];
		rsp[0] = GTEST_ATT_OP_READ_BY_TYPE_RSP;
		rsp[1] = 18;			/* attr_data_len: 2+16 */
		put_le16(rsp + 2, 0x0010);	/* handle of the hash char */
		memcpy(rsp + 4, expected_hash, 16);
		send(peer, rsp, sizeof(rsp), 0);

		close(peer);
		_exit(0);
	}

	close(peer);
	uint8_t hash[16];
	memset(hash, 0, sizeof(hash));
	int ret = gatt_read_database_hash(&ac, hash);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(memcmp(hash, expected_hash, 16), 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
}

/*
 * 10c. test_gatt_read_database_hash_not_found
 *
 * Mock a peer that does NOT serve UUID BT_ASSIGNED_UUID_DATABASE_HASH (returns Attribute Not
 * Found error).  Verify gatt_read_database_hash() returns -1.
 */
ATF_TC_WITHOUT_HEAD(test_gatt_read_database_hash_not_found);
ATF_TC_BODY(test_gatt_read_database_hash_not_found, tc)
{
	struct att_conn ac;
	int peer;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		uint8_t req[32];
		ssize_t n;

		close(ac.fd);

		n = recv(peer, req, sizeof(req), 0);
		if (n < 7 || req[0] != GTEST_ATT_OP_READ_BY_TYPE_REQ) {
			close(peer);
			_exit(1);
		}

		/* Return Attribute Not Found */
		uint8_t err[5];
		err[0] = GTEST_ATT_OP_ERROR_RSP;
		err[1] = GTEST_ATT_OP_READ_BY_TYPE_REQ;
		put_le16(err + 2, get_le16(req + 1));
		err[4] = GTEST_ATT_ERR_ATTR_NOT_FOUND;
		send(peer, err, sizeof(err), 0);

		close(peer);
		_exit(0);
	}

	close(peer);
	uint8_t hash[16];
	memset(hash, 0xFF, sizeof(hash));
	int ret = gatt_read_database_hash(&ac, hash);

	/* Should fail since characteristic not found */
	ATF_CHECK(ret != 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
}

/* ================================================================
 * EDGE CASE TESTS
 * ================================================================ */

/*
 * 11. test_gatt_discover_empty
 *
 * Discover services on a server that returns GTEST_ATT_ERR_ATTR_NOT_FOUND
 * immediately.  Verify count=0, return=0.
 */
ATF_TC_WITHOUT_HEAD(test_gatt_discover_empty);
ATF_TC_BODY(test_gatt_discover_empty, tc)
{
	struct att_conn ac;
	int peer;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		uint8_t req[32];
		ssize_t n;

		close(ac.fd);

		n = recv(peer, req, sizeof(req), 0);
		if (n < 7 || req[0] != GTEST_ATT_OP_READ_BY_GROUP_TYPE_REQ) {
			close(peer);
			_exit(1);
		}

		/* Immediately return Attribute Not Found */
		uint8_t err[5];
		err[0] = GTEST_ATT_OP_ERROR_RSP;
		err[1] = GTEST_ATT_OP_READ_BY_GROUP_TYPE_REQ;
		put_le16(err + 2, get_le16(req + 1));
		err[4] = GTEST_ATT_ERR_ATTR_NOT_FOUND;
		send(peer, err, sizeof(err), 0);

		close(peer);
		_exit(0);
	}

	close(peer);
	struct gatt_service svcs[GATT_MAX_SERVICES];
	int nsvcs = -1;
	int ret = gatt_discover_primary_services(&ac, svcs,
	    GATT_MAX_SERVICES, &nsvcs);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(nsvcs, 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
}

/*
 * 12. test_gatt_discover_services_truncated
 *
 * Server returns a single ATT response that fills the MTU
 * (one service entry), then GTEST_ATT_ERR_ATTR_NOT_FOUND on the next
 * request.  Verify partial results are returned correctly.
 */
ATF_TC_WITHOUT_HEAD(test_gatt_discover_services_truncated);
ATF_TC_BODY(test_gatt_discover_services_truncated, tc)
{
	struct att_conn ac;
	int peer;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		uint8_t req[32];
		ssize_t n;
		int round;

		close(ac.fd);

		for (round = 0; round < 2; round++) {
			n = recv(peer, req, sizeof(req), 0);
			if (n < 7 ||
			    req[0] != GTEST_ATT_OP_READ_BY_GROUP_TYPE_REQ) {
				close(peer);
				_exit(1);
			}

			if (round == 0) {
				/*
				 * Return exactly 1 service entry
				 * (fits in MTU=23: opcode(1) + entry_len(1)
				 * + entry(6) = 8 bytes).
				 */
				uint8_t rsp[1 + 1 + 6];
				rsp[0] = GTEST_ATT_OP_READ_BY_GROUP_TYPE_RSP;
				rsp[1] = 6;
				put_le16(rsp + 2, 0x0001);
				put_le16(rsp + 4, 0x0005);
				put_le16(rsp + 6, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
				send(peer, rsp, sizeof(rsp), 0);
			} else {
				uint8_t err[5];
				err[0] = GTEST_ATT_OP_ERROR_RSP;
				err[1] = GTEST_ATT_OP_READ_BY_GROUP_TYPE_REQ;
				put_le16(err + 2, get_le16(req + 1));
				err[4] = GTEST_ATT_ERR_ATTR_NOT_FOUND;
				send(peer, err, sizeof(err), 0);
			}
		}

		close(peer);
		_exit(0);
	}

	close(peer);
	struct gatt_service svcs[GATT_MAX_SERVICES];
	int nsvcs = 0;
	int ret = gatt_discover_primary_services(&ac, svcs,
	    GATT_MAX_SERVICES, &nsvcs);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(nsvcs, 1);
	ATF_CHECK_EQ(svcs[0].start_handle, 0x0001);
	ATF_CHECK_EQ(svcs[0].end_handle, 0x0005);
	ATF_CHECK_EQ(svcs[0].uuid16, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
}

/* ================================================================
 * BLE 5.1 DATABASE HASH — SPEC CONFORMANCE TESTS
 * ================================================================ */

/*
 * test_db_hash_spec_types_only: verify that only the 10 spec-mandated
 * attribute types are included in the database hash computation.
 *
 * Core Spec Vol 3 Part G Section 7.3.1 mandates exactly:
 *   With value:  BT_ASSIGNED_UUID_PRIMARY_SERVICE, BT_ASSIGNED_UUID_SECONDARY_SERVICE, BT_ASSIGNED_UUID_INCLUDE, BT_ASSIGNED_UUID_CHARACTERISTIC, BT_ASSIGNED_UUID_CHARACTERISTIC_EXTENDED_PROPERTIES
 *   Handle+type: BT_ASSIGNED_UUID_CHARACTERISTIC_USER_DESCRIPTION, BT_ASSIGNED_UUID_CCCD, 0x2903, 0x2904, 0x2905
 *
 * Build two databases identical except one has an extra attribute
 * with a non-spec UUID (e.g., BT_ASSIGNED_UUID_DEVICE_NAME Device Name).  Since BT_ASSIGNED_UUID_DEVICE_NAME is
 * excluded from the hash, both hashes must be identical.
 *
 * Note: the characteristic value for BT_ASSIGNED_UUID_DEVICE_NAME is already excluded because
 * is_char_value=true.  The declaration handle for BT_ASSIGNED_UUID_DEVICE_NAME has UUID BT_ASSIGNED_UUID_CHARACTERISTIC
 * which IS included.  So the hash differs only if we add an extra
 * *declaration* with a new UUID.  This test adds a descriptor with
 * UUID GTEST_FIXTURE_NONHASH_DESCRIPTOR (not in the spec list) and verifies it is excluded.
 */
ATF_TC_WITHOUT_HEAD(test_db_hash_spec_types_only);
ATF_TC_BODY(test_db_hash_spec_types_only, tc)
{
	struct att_db db1, db2;
	struct att_attr a1[TEST_DB_MAX_ATTRS], a2[TEST_DB_MAX_ATTRS];
	uint8_t v1[TEST_DB_VAL_SIZE], v2[TEST_DB_VAL_SIZE];
	uint8_t hash1[16], hash2[16];

	/* DB1: standard test database */
	build_test_db(&db1, a1, v1);

	/* DB2: same structure plus an extra descriptor with non-spec UUID */
	build_test_db(&db2, a2, v2);
	attdb_add_descriptor(&db2, GTEST_FIXTURE_NONHASH_DESCRIPTOR, ATT_PERM_READ, "\x00", 1);

	attdb_compute_db_hash(&db1, hash1);
	attdb_compute_db_hash(&db2, hash2);

	/* GTEST_FIXTURE_NONHASH_DESCRIPTOR is not in the 10 spec-mandated types, so hashes must match */
	ATF_CHECK_EQ_MSG(memcmp(hash1, hash2, 16), 0,
	    "hash should not change when adding non-spec-mandated descriptor");
}

/*
 * test_db_hash_includes_declarations_for_128bit_uuid: declarations whose
 * values contain 128-bit UUIDs remain hash-relevant because their Attribute
 * Types are Primary Service and Characteristic (Part G §7.3.1).
 */
ATF_TC_WITHOUT_HEAD(test_db_hash_includes_declarations_for_128bit_uuid);
ATF_TC_BODY(test_db_hash_includes_declarations_for_128bit_uuid, tc)
{
	struct att_db db1, db2;
	struct att_attr a1[TEST_DB_MAX_ATTRS], a2[TEST_DB_MAX_ATTRS];
	uint8_t v1[TEST_DB_VAL_SIZE], v2[TEST_DB_VAL_SIZE];
	uint8_t hash1[16], hash2[16];
	static const uint8_t vendor_uuid[16] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
	};

	/* DB1: standard test database */
	build_test_db(&db1, a1, v1);

	/* DB2: same plus a 128-bit UUID service */
	build_test_db(&db2, a2, v2);
	attdb_add_service128(&db2, vendor_uuid);
	attdb_add_characteristic128(&db2, vendor_uuid,
	    GTEST_GATT_PROP_READ, ATT_PERM_READ, "\x00", 1);

	attdb_compute_db_hash(&db1, hash1);
	attdb_compute_db_hash(&db2, hash2);

	/* Both added declaration Attribute Types are in the §7.3.1 set. */
	ATF_CHECK_MSG(memcmp(hash1, hash2, 16) != 0,
	    "hash should differ because service declaration BT_ASSIGNED_UUID_PRIMARY_SERVICE is included");
}

/*
 * test_db_hash_excludes_vendor_16bit: verify that vendor-specific
 * 16-bit UUIDs (not in the 10 spec-mandated types) are excluded.
 */
ATF_TC_WITHOUT_HEAD(test_db_hash_excludes_vendor_16bit);
ATF_TC_BODY(test_db_hash_excludes_vendor_16bit, tc)
{
	struct att_db db1, db2;
	struct att_attr a1[TEST_DB_MAX_ATTRS], a2[TEST_DB_MAX_ATTRS];
	uint8_t v1[TEST_DB_VAL_SIZE], v2[TEST_DB_VAL_SIZE];
	uint8_t hash1[16], hash2[16];

	/* DB1: standard test database */
	build_test_db(&db1, a1, v1);

	/* DB2: same plus a descriptor with vendor 16-bit UUID */
	build_test_db(&db2, a2, v2);
	attdb_add_descriptor(&db2, GTEST_FIXTURE_VENDOR_DESCRIPTOR, ATT_PERM_READ, "\x42", 1);

	attdb_compute_db_hash(&db1, hash1);
	attdb_compute_db_hash(&db2, hash2);

	/* GTEST_FIXTURE_VENDOR_DESCRIPTOR is a vendor UUID, not in the 10 spec types */
	ATF_CHECK_EQ_MSG(memcmp(hash1, hash2, 16), 0,
	    "hash should not change when adding vendor 16-bit descriptor");
}

/*
 * test_db_hash_deterministic: verify same DB produces same hash.
 * (Supplementary to existing test_gatt_db_hash_computation.)
 */
ATF_TC_WITHOUT_HEAD(test_db_hash_deterministic);
ATF_TC_BODY(test_db_hash_deterministic, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t h1[16], h2[16], h3[16];

	build_test_db(&db, attrs, val_buf);

	attdb_compute_db_hash(&db, h1);
	attdb_compute_db_hash(&db, h2);
	attdb_compute_db_hash(&db, h3);

	ATF_CHECK_EQ(memcmp(h1, h2, 16), 0);
	ATF_CHECK_EQ(memcmp(h2, h3, 16), 0);
}

/*
 * test_db_hash_changes_on_add: verify hash changes when a service is added.
 */
ATF_TC_WITHOUT_HEAD(test_db_hash_changes_on_add);
ATF_TC_BODY(test_db_hash_changes_on_add, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t hash_before[16], hash_after[16];

	build_test_db(&db, attrs, val_buf);
	attdb_compute_db_hash(&db, hash_before);

	/* Add a new service */
	attdb_add_service(&db, BT_ASSIGNED_UUID_BATTERY_SERVICE);
	attdb_add_characteristic(&db, BT_ASSIGNED_UUID_BATTERY_LEVEL,
	    GTEST_GATT_PROP_READ | GTEST_GATT_PROP_NOTIFY,
	    ATT_PERM_READ, "\x64", 1);

	attdb_compute_db_hash(&db, hash_after);

	ATF_CHECK_MSG(memcmp(hash_before, hash_after, 16) != 0,
	    "hash must change when a service is added");
}

/*
 * test_db_hash_changes_on_remove: verify hash changes when a service
 * is removed.
 */
ATF_TC_WITHOUT_HEAD(test_db_hash_changes_on_remove);
ATF_TC_BODY(test_db_hash_changes_on_remove, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t hash_original[16], hash_added[16], hash_removed[16];
	uint16_t svc_handle;

	build_test_db(&db, attrs, val_buf);
	attdb_compute_db_hash(&db, hash_original);

	/* Add a service */
	svc_handle = attdb_add_service(&db, GTEST_FIXTURE_VENDOR_SERVICE_2);
	ATF_REQUIRE(svc_handle != 0);
	attdb_add_characteristic(&db, GTEST_FIXTURE_VENDOR_CHARACTERISTIC_2,
	    GTEST_GATT_PROP_READ, ATT_PERM_READ, "\x00", 1);

	attdb_compute_db_hash(&db, hash_added);
	ATF_CHECK(memcmp(hash_original, hash_added, 16) != 0);

	/* Remove the service */
	int ret = attdb_remove_service(&db, svc_handle);
	ATF_CHECK_EQ(ret, 0);

	attdb_compute_db_hash(&db, hash_removed);

	/* After removal, hash should return to the original */
	ATF_CHECK_EQ_MSG(memcmp(hash_original, hash_removed, 16), 0,
	    "hash should return to original after removing added service");
}

/*
 * test_db_hash_appendix_b_kat: exact known-answer test for the GATT
 * Database Hash.
 *
 * Core Spec Vol 3 Part G Appendix B ("Example Database Hash") publishes a
 * complete worked example: a fixed 22-attribute GATT database (handles
 * 0x0001..0x0016), the resulting concatenation m (blocks M0..M6), and the
 * resulting AES-CMAC (all-zero key) hash.  This test reconstructs that
 * exact database attribute-for-attribute and asserts attdb_compute_db_hash
 * reproduces the spec's published hash byte-for-byte.  This is the
 * strongest possible oracle for §7.3.1: unlike the "non-zero /
 * deterministic / changes-on-modify" property tests, it pins the hash to a
 * value hand-derivable from the spec, so a spec-wrong concatenation (field
 * order, endianness, which types/values are included, the value-handle
 * subfield) is caught.
 *
 * Handle assignment is sequential from attdb_init (next_handle starts at
 * 0x0001); each add_* below is annotated with the handle(s) it consumes so
 * the layout matches Table B.1 exactly.  Characteristic values are
 * irrelevant to the hash (is_char_value) so a 1-byte placeholder is used.
 * The Secondary Service declaration (BT_ASSIGNED_UUID_SECONDARY_SERVICE) is emitted with the generic
 * attdb_add_descriptor since it is just handle+type(BT_ASSIGNED_UUID_SECONDARY_SERVICE)+value(UUID).
 *
 * Spec m (Table B.1) and result:
 *   Database Hash = F1 CA 2D 48 EC F5 8B AC 8A 88 30 BB B9 FB A9 90 (MSB..LSB)
 */
ATF_TC_WITHOUT_HEAD(test_db_hash_appendix_b_kat);
ATF_TC_BODY(test_db_hash_appendix_b_kat, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t hash[16];
	uint8_t sec_svc[2];
	/* Core Spec Vol 3 Part G Appendix B, MSB..LSB == hash[0]..hash[15]. */
	static const uint8_t spec_hash[16] = {
		BT_CORE63_GATT_DATABASE_HASH_KAT_BYTES
	};

	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);

	/* 0x0001 Primary Service: GAP (BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE) */
	attdb_add_service(&db, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
	/* 0x0002/0x0003 Characteristic (Read|Write) Device Name (BT_ASSIGNED_UUID_DEVICE_NAME) */
	attdb_add_characteristic(&db, BT_ASSIGNED_UUID_DEVICE_NAME,
	    GTEST_GATT_PROP_READ | GTEST_GATT_PROP_WRITE, ATT_PERM_READ, "\x00", 1);
	/* 0x0004/0x0005 Characteristic (Read) Appearance (BT_ASSIGNED_UUID_APPEARANCE) */
	attdb_add_characteristic(&db, BT_ASSIGNED_UUID_APPEARANCE,
	    GTEST_GATT_PROP_READ, ATT_PERM_READ, "\x00", 1);
	/* 0x0006 Primary Service: GATT (BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE) */
	attdb_add_service(&db, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);
	/* 0x0007/0x0008 Characteristic (Indicate) Service Changed (BT_ASSIGNED_UUID_SERVICE_CHANGED) */
	attdb_add_characteristic(&db, BT_ASSIGNED_UUID_SERVICE_CHANGED,
	    GTEST_GATT_PROP_INDICATE, ATT_PERM_READ, "\x00", 1);
	/* 0x0009 CCCD (BT_ASSIGNED_UUID_CCCD) — value excluded from hash */
	attdb_add_cccd(&db);
	/* 0x000A/0x000B Characteristic (Read|Write) Client Supp. Feat (BT_ASSIGNED_UUID_CLIENT_SUPPORTED_FEATURES) */
	attdb_add_characteristic(&db, BT_ASSIGNED_UUID_CLIENT_SUPPORTED_FEATURES,
	    GTEST_GATT_PROP_READ | GTEST_GATT_PROP_WRITE, ATT_PERM_READ, "\x00", 1);
	/* 0x000C/0x000D Characteristic (Read) Database Hash (BT_ASSIGNED_UUID_DATABASE_HASH) */
	attdb_add_characteristic(&db, BT_ASSIGNED_UUID_DATABASE_HASH,
	    GTEST_GATT_PROP_READ, ATT_PERM_READ, "\x00", 1);
	/* 0x000E Primary Service: Glucose (BT_ASSIGNED_UUID_GLUCOSE_SERVICE) */
	attdb_add_service(&db, BT_ASSIGNED_UUID_GLUCOSE_SERVICE);
	/* 0x000F Included Service: Battery (0x0014..0x0016, BT_ASSIGNED_UUID_BATTERY_SERVICE) */
	attdb_add_include(&db, 0x000E, 0x0014, 0x0016, BT_ASSIGNED_UUID_BATTERY_SERVICE);
	/* 0x0010/0x0011 Characteristic (Read|Indicate|ExtProps=0xA2) Glucose
	 * Measurement (BT_ASSIGNED_UUID_GLUCOSE_MEASUREMENT) */
	attdb_add_characteristic(&db, BT_ASSIGNED_UUID_GLUCOSE_MEASUREMENT,
	    GTEST_GATT_PROP_READ | GTEST_GATT_PROP_INDICATE | 0x80, ATT_PERM_READ,
	    "\x00", 1);
	/* 0x0012 CCCD (BT_ASSIGNED_UUID_CCCD) */
	attdb_add_cccd(&db);
	/* 0x0013 Characteristic Extended Properties (BT_ASSIGNED_UUID_CHARACTERISTIC_EXTENDED_PROPERTIES) value 0x0000 */
	attdb_add_descriptor(&db, BT_ASSIGNED_UUID_CHARACTERISTIC_EXTENDED_PROPERTIES, ATT_PERM_READ, "\x00\x00", 2);
	/* 0x0014 Secondary Service: Battery (BT_ASSIGNED_UUID_SECONDARY_SERVICE) value BT_ASSIGNED_UUID_BATTERY_SERVICE */
	put_le16(sec_svc, BT_ASSIGNED_UUID_BATTERY_SERVICE);
	attdb_add_descriptor(&db, BT_ASSIGNED_UUID_SECONDARY_SERVICE, ATT_PERM_READ, sec_svc, 2);
	/* 0x0015/0x0016 Characteristic (Read) Battery Level (BT_ASSIGNED_UUID_BATTERY_LEVEL) */
	attdb_add_characteristic(&db, BT_ASSIGNED_UUID_BATTERY_LEVEL,
	    GTEST_GATT_PROP_READ, ATT_PERM_READ, "\x00", 1);

	attdb_compute_db_hash(&db, hash);

	ATF_CHECK_EQ_MSG(memcmp(hash, spec_hash, 16), 0,
	    "database hash must equal Core Spec Vol 3 Part G Appendix B value");
}

/*
 * Build a database that includes a Database Hash characteristic (BT_ASSIGNED_UUID_DATABASE_HASH)
 * so Robust Caching gating and the change-aware transition can be driven.
 *
 *   handle 1: GATT Primary Service Decl (BT_ASSIGNED_UUID_PRIMARY_SERVICE), value=BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE
 *   handle 2: Char Decl (BT_ASSIGNED_UUID_CHARACTERISTIC), props=READ
 *   handle 3: Database Hash value (BT_ASSIGNED_UUID_DATABASE_HASH), 16 octets
 *   handle 4: GAP Primary Service Decl (BT_ASSIGNED_UUID_PRIMARY_SERVICE), value=BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE
 *   handle 5: Char Decl (BT_ASSIGNED_UUID_CHARACTERISTIC), props=READ
 *   handle 6: Device Name value (BT_ASSIGNED_UUID_DEVICE_NAME), value="Test"
 */
static void
build_rc_hash_db(struct att_db *db, struct att_attr *attrs, uint8_t *val_buf,
    uint16_t *hash_handle, uint16_t *name_handle)
{
	uint16_t h;

	attdb_init(db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);

	attdb_add_service(db, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);
	h = attdb_add_characteristic(db, BT_ASSIGNED_UUID_DATABASE_HASH, GTEST_GATT_PROP_READ, ATT_PERM_READ,
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00", 16);
	if (hash_handle != NULL)
		*hash_handle = h;

	attdb_add_service(db, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
	h = attdb_add_characteristic(db, BT_ASSIGNED_UUID_DEVICE_NAME, GTEST_GATT_PROP_READ, ATT_PERM_READ,
	    "Test", 4);
	if (name_handle != NULL)
		*name_handle = h;
}

/*
 * test_change_aware_client: verify GTEST_ATT_ERR_DATABASE_OUT_OF_SYNC for
 * change-unaware clients on a gated operation.
 *
 * Core Spec Vol 3 Part G §2.5.2.1: a change-unaware Robust Caching client
 * that requests an operation at a specific Attribute Handle (here a plain
 * ATT_READ_REQ of a value handle) is rejected once with Database Out Of Sync
 * (0x12); the very next request transitions it to change-aware (Fig 2.7) and
 * is processed normally.
 */
ATF_TC_WITHOUT_HEAD(test_change_aware_client);
ATF_TC_BODY(test_change_aware_client, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	uint16_t name_handle = 0;
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_rc_hash_db(&db, attrs, val_buf, NULL, &name_handle);

	/* Set robust caching bit and mark client as change-unaware */
	ac.robust_caching = true;
	ac.change_aware = false;

	/* Read of a value handle -- gated -> DATABASE_OUT_OF_SYNC. */
	{
		uint8_t req[3];
		req[0] = GTEST_ATT_OP_READ_REQ;
		put_le16(req + 1, name_handle);

		att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
		n = recv(peer, rsp, sizeof(rsp), 0);
		ATF_REQUIRE(n >= 5);
		ATF_CHECK_EQ(rsp[0], GTEST_ATT_OP_ERROR_RSP);
		ATF_CHECK_EQ(rsp[4], GTEST_ATT_ERR_DATABASE_OUT_OF_SYNC);
	}

	/*
	 * Fig 2.7: the Database Out Of Sync error is sent only once per bearer;
	 * the next request auto-transitions the still-unaware client to
	 * change-aware and is processed normally (a READ_RSP, not a 2nd error).
	 */
	{
		uint8_t req[3];
		req[0] = GTEST_ATT_OP_READ_REQ;
		put_le16(req + 1, name_handle);

		att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
		n = recv(peer, rsp, sizeof(rsp), 0);
		ATF_REQUIRE(n >= 1);
		ATF_CHECK_EQ(rsp[0], GTEST_ATT_OP_READ_RSP);
		ATF_CHECK(ac.change_aware);
	}

	att_mock_cleanup(&ac, peer);
}

/*
 * test_rc_read_by_type_hash_transitions: Core Spec Vol 3 Part G §7.3 mandates
 * that a client read the Database Hash using an ATT_READ_BY_TYPE_REQ.  Such a
 * request over the full handle range 0x0001-0xFFFF must be ALLOWED for a
 * change-unaware Robust Caching client (§2.5.2.1: the range is 0x0001-0xFFFF),
 * and reading the hash this way must transition the client to change-aware
 * (§7.3.1) -- not only the plain ATT_READ_REQ path.
 */
ATF_TC_WITHOUT_HEAD(test_rc_read_by_type_hash_transitions);
ATF_TC_BODY(test_rc_read_by_type_hash_transitions, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	uint8_t req[7];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_rc_hash_db(&db, attrs, val_buf, NULL, NULL);

	ac.robust_caching = true;
	ac.change_aware = false;

	/* Read-Using-UUID(BT_ASSIGNED_UUID_DATABASE_HASH) over 0x0001-0xFFFF. */
	req[0] = GTEST_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(req + 1, 0x0001);
	put_le16(req + 3, 0xFFFF);
	put_le16(req + 5, BT_ASSIGNED_UUID_DATABASE_HASH);

	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 2);
	/* Allowed (not 0x12) and answered with a Read By Type Response. */
	ATF_CHECK_EQ(rsp[0], GTEST_ATT_OP_READ_BY_TYPE_RSP);
	/* Reading the hash via Read-By-Type made the client change-aware. */
	ATF_CHECK_MSG(ac.change_aware,
	    "reading the Database Hash via Read-By-Type must set change_aware");

	att_mock_cleanup(&ac, peer);
}

/*
 * test_rc_discovery_not_out_of_sync: Table 3.43 (Vol 3 Part F §3.4.9) and
 * §3.4.4.9 do not permit Database Out Of Sync (0x12) for Find Information
 * (0x04), Find By Type Value (0x06) or Read By Group Type (0x10).  A
 * change-unaware Robust Caching client issuing any of these must be answered
 * normally, never with 0x12.
 */
ATF_TC_WITHOUT_HEAD(test_rc_discovery_not_out_of_sync);
ATF_TC_BODY(test_rc_discovery_not_out_of_sync, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_rc_hash_db(&db, attrs, val_buf, NULL, NULL);

	/* Find Information (0x04) over the full range. */
	{
		uint8_t req[5];
		ac.robust_caching = true;
		ac.change_aware = false;
		ac.out_of_sync_sent = false;
		req[0] = GTEST_ATT_OP_FIND_INFO_REQ;
		put_le16(req + 1, 0x0001);
		put_le16(req + 3, 0xFFFF);
		att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
		n = recv(peer, rsp, sizeof(rsp), 0);
		ATF_REQUIRE(n >= 1);
		ATF_CHECK_MSG(!(n == 5 && rsp[0] == GTEST_ATT_OP_ERROR_RSP &&
		    rsp[4] == GTEST_ATT_ERR_DATABASE_OUT_OF_SYNC),
		    "Find Information must not be Database-Out-Of-Sync rejected");
		ATF_CHECK_EQ(rsp[0], GTEST_ATT_OP_FIND_INFO_RSP);
	}

	/* Read By Group Type (0x10) of Primary Service over the full range. */
	{
		uint8_t req[7];
		ac.change_aware = false;
		ac.out_of_sync_sent = false;
		req[0] = GTEST_ATT_OP_READ_BY_GROUP_TYPE_REQ;
		put_le16(req + 1, 0x0001);
		put_le16(req + 3, 0xFFFF);
		put_le16(req + 5, BT_ASSIGNED_UUID_PRIMARY_SERVICE);
		att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
		n = recv(peer, rsp, sizeof(rsp), 0);
		ATF_REQUIRE(n >= 1);
		ATF_CHECK_MSG(!(n == 5 && rsp[0] == GTEST_ATT_OP_ERROR_RSP &&
		    rsp[4] == GTEST_ATT_ERR_DATABASE_OUT_OF_SYNC),
		    "Read By Group Type must not be Database-Out-Of-Sync rejected");
		ATF_CHECK_EQ(rsp[0], GTEST_ATT_OP_READ_BY_GROUP_TYPE_RSP);
	}

	/* Find By Type Value (0x06) for Primary Service = BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE. */
	{
		uint8_t req[9];
		ac.change_aware = false;
		ac.out_of_sync_sent = false;
		req[0] = GTEST_ATT_OP_FIND_BY_TYPE_VALUE_REQ;
		put_le16(req + 1, 0x0001);
		put_le16(req + 3, 0xFFFF);
		put_le16(req + 5, BT_ASSIGNED_UUID_PRIMARY_SERVICE);
		put_le16(req + 7, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);
		att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
		n = recv(peer, rsp, sizeof(rsp), 0);
		ATF_REQUIRE(n >= 1);
		ATF_CHECK_MSG(!(n == 5 && rsp[0] == GTEST_ATT_OP_ERROR_RSP &&
		    rsp[4] == GTEST_ATT_ERR_DATABASE_OUT_OF_SYNC),
		    "Find By Type Value must not be Database-Out-Of-Sync rejected");
		ATF_CHECK_EQ(rsp[0], GTEST_ATT_OP_FIND_BY_TYPE_VALUE_RSP);
	}

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * SERVICE CHANGED FLOW TESTS
 * ================================================================ */

/*
 * Verify the database-hash mutation prerequisite after adding a service.
 * This relational test does not send or validate a Service Changed indication.
 */
ATF_TC_WITHOUT_HEAD(test_service_changed_on_add);
ATF_TC_BODY(test_service_changed_on_add, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t hash_before[16], hash_after[16];

	build_test_db(&db, attrs, val_buf);
	attdb_compute_db_hash(&db, hash_before);

	/* Add a service */
	attdb_add_service(&db, BT_ASSIGNED_UUID_BATTERY_SERVICE);
	attdb_add_characteristic(&db, BT_ASSIGNED_UUID_BATTERY_LEVEL,
	    GTEST_GATT_PROP_READ, ATT_PERM_READ, "\x64", 1);

	attdb_compute_db_hash(&db, hash_after);

	/* §7.3.1 structural mutation changes the hash. */
	ATF_CHECK(memcmp(hash_before, hash_after, 16) != 0);
}

/*
 * Verify the database-hash mutation prerequisite after removing a service.
 * This relational test does not send or validate a Service Changed indication.
 */
ATF_TC_WITHOUT_HEAD(test_service_changed_on_remove);
ATF_TC_BODY(test_service_changed_on_remove, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t hash_before[16], hash_after[16];
	uint16_t svc_handle;

	build_test_db(&db, attrs, val_buf);

	/* Add then remove a service */
	svc_handle = attdb_add_service(&db, GTEST_FIXTURE_VENDOR_SERVICE_2);
	ATF_REQUIRE(svc_handle != 0);
	attdb_add_characteristic(&db, GTEST_FIXTURE_VENDOR_CHARACTERISTIC_2,
	    GTEST_GATT_PROP_READ, ATT_PERM_READ, "\x00", 1);

	attdb_compute_db_hash(&db, hash_before);

	int ret = attdb_remove_service(&db, svc_handle);
	ATF_CHECK_EQ(ret, 0);

	attdb_compute_db_hash(&db, hash_after);

	/* Hash must change when a service is removed */
	ATF_CHECK(memcmp(hash_before, hash_after, 16) != 0);
}

/*
 * Verify the low-level indication wire layout using the four-octet Service
 * Changed value format.  The fake value handle and direct send helper mean
 * this does not test CCCD gating or full Service Changed procedure behavior.
 */
ATF_TC_WITHOUT_HEAD(test_service_changed_handle_range);
ATF_TC_BODY(test_service_changed_handle_range, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	uint16_t sc_handle;

	att_mock_pair(&ac, &peer);
	ac.ind_pending = false;
	ac.ind_timer = 0;

	/*
	 * Use a fake Service Changed handle. The att_send_indication
	 * function doesn't check the database -- it just sends the PDU.
	 */
	sc_handle = 0x0005;

	/* Send indication with range 0x0010-0x0020 */
	{
		uint8_t val[4];
		put_le16(val, 0x0010);     /* start handle */
		put_le16(val + 2, 0x0020); /* end handle */
		int ret = att_send_indication(&ac, sc_handle, val, sizeof(val));
		ATF_CHECK_EQ(ret, 0);
	}

	/* Read indication PDU from peer */
	n = recv(peer, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 7);
	ATF_CHECK_EQ(rsp[0], GTEST_ATT_OP_HANDLE_IND);
	ATF_CHECK_EQ(get_le16(rsp + 1), sc_handle);

	/* Verify handle range payload */
	ATF_CHECK_EQ(get_le16(rsp + 3), 0x0010); /* start */
	ATF_CHECK_EQ(get_le16(rsp + 5), 0x0020); /* end */

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * ATF TEST PLAN
 * ================================================================ */

ATF_TP_ADD_TCS(tp)
{

	/* GATT discovery */
	ATF_TP_ADD_TC(tp, test_gatt_discover_primary_services);
	ATF_TP_ADD_TC(tp, test_gatt_discover_characteristics);
	ATF_TP_ADD_TC(tp, test_gatt_discover_descriptors);
	ATF_TP_ADD_TC(tp, test_gatt_discover_primary_by_uuid);
	ATF_TP_ADD_TC(tp, test_gatt_discover_primary_by_uuid128);
	ATF_TP_ADD_TC(tp, test_gatt_discover_secondary_services);
	ATF_TP_ADD_TC(tp, test_gatt_discover_includes);

	/* GATT robust caching */
	ATF_TP_ADD_TC(tp, test_gatt_db_hash_repeatability);
	ATF_TP_ADD_TC(tp, test_gatt_db_hash_changes_on_modification);
	ATF_TP_ADD_TC(tp, test_gatt_db_hash_excludes_char_values);
	ATF_TP_ADD_TC(tp, test_gatt_read_database_hash);
	ATF_TP_ADD_TC(tp, test_gatt_read_database_hash_not_found);

	/* Edge cases */
	ATF_TP_ADD_TC(tp, test_gatt_discover_empty);
	ATF_TP_ADD_TC(tp, test_gatt_discover_services_truncated);

	/* BLE 5.1: Database Hash spec conformance */
	ATF_TP_ADD_TC(tp, test_db_hash_spec_types_only);
	ATF_TP_ADD_TC(tp, test_db_hash_includes_declarations_for_128bit_uuid);
	ATF_TP_ADD_TC(tp, test_db_hash_excludes_vendor_16bit);
	ATF_TP_ADD_TC(tp, test_db_hash_deterministic);
	ATF_TP_ADD_TC(tp, test_db_hash_changes_on_add);
	ATF_TP_ADD_TC(tp, test_db_hash_changes_on_remove);
	ATF_TP_ADD_TC(tp, test_db_hash_appendix_b_kat);
	ATF_TP_ADD_TC(tp, test_change_aware_client);
	ATF_TP_ADD_TC(tp, test_rc_read_by_type_hash_transitions);
	ATF_TP_ADD_TC(tp, test_rc_discovery_not_out_of_sync);

	/* Service Changed flow */
	ATF_TP_ADD_TC(tp, test_service_changed_on_add);
	ATF_TP_ADD_TC(tp, test_service_changed_on_remove);
	ATF_TP_ADD_TC(tp, test_service_changed_handle_range);

	return (atf_no_error());
}
