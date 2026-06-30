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
	ac->mtu = ATT_DEFAULT_MTU;
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
 * GAP Service (0x1800):
 *   handle 1: Primary Service Decl (0x2800), value=0x1800
 *   handle 2: Char Decl (0x2803), props=READ
 *   handle 3: Device Name (0x2A00), value="Test"
 *
 * Custom Service (0xFFE0):
 *   handle 4: Primary Service Decl (0x2800), value=0xFFE0
 *   handle 5: Char Decl (0x2803), props=READ|WRITE|NOTIFY
 *   handle 6: Custom Char (0xFFE1), value=0xAA 0xBB 0xCC 0xDD
 *   handle 7: CCCD (0x2902), value=0x0000
 * ================================================================ */

#define TEST_DB_MAX_ATTRS	32
#define TEST_DB_VAL_SIZE	512

static void
build_test_db(struct att_db *db, struct att_attr *attrs, uint8_t *val_buf)
{

	attdb_init(db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);

	/* GAP Service */
	attdb_add_service(db, 0x1800);
	attdb_add_characteristic(db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ, "Test", 4);

	/* Custom Service */
	attdb_add_service(db, 0xFFE0);
	attdb_add_characteristic(db, 0xFFE1,
	    GATT_PROP_READ | GATT_PROP_WRITE | GATT_PROP_NOTIFY,
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
 * (opcode 0x10) with UUID 0x2800, returning 3 primary services.
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
		 *         [svc1: 0x0001-0x0003, UUID=0x1800]
		 *         [svc2: 0x0004-0x0007, UUID=0xFFE0]
		 *         [svc3: 0x0008-0x000A, UUID=0x180F]
		 */
		for (round = 0; round < 2; round++) {
			n = recv(peer, req, sizeof(req), 0);
			if (n < 7 || req[0] != ATT_OP_READ_BY_GROUP_TYPE_REQ) {
				close(peer);
				_exit(1);
			}
			/* Verify UUID = 0x2800 (primary service) */
			if (get_le16(req + 5) != GATT_UUID_PRIMARY_SERVICE) {
				close(peer);
				_exit(2);
			}

			if (round == 0) {
				uint8_t rsp[1 + 1 + 3 * 6];
				rsp[0] = ATT_OP_READ_BY_GROUP_TYPE_RSP;
				rsp[1] = 6; /* entry_len */
				/* Service 1: 0x0001-0x0003, UUID 0x1800 */
				put_le16(rsp + 2, 0x0001);
				put_le16(rsp + 4, 0x0003);
				put_le16(rsp + 6, 0x1800);
				/* Service 2: 0x0004-0x0007, UUID 0xFFE0 */
				put_le16(rsp + 8, 0x0004);
				put_le16(rsp + 10, 0x0007);
				put_le16(rsp + 12, 0xFFE0);
				/* Service 3: 0x0008-0x000A, UUID 0x180F */
				put_le16(rsp + 14, 0x0008);
				put_le16(rsp + 16, 0x000A);
				put_le16(rsp + 18, 0x180F);
				send(peer, rsp, sizeof(rsp), 0);
			} else {
				/*
				 * Second request: return Attribute Not Found
				 * error to signal end of discovery.
				 */
				uint8_t err[5];
				err[0] = ATT_OP_ERROR_RSP;
				err[1] = ATT_OP_READ_BY_GROUP_TYPE_REQ;
				put_le16(err + 2, get_le16(req + 1));
				err[4] = ATT_ERR_ATTR_NOT_FOUND;
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
	ATF_CHECK_EQ(svcs[0].uuid16, 0x1800);

	ATF_CHECK_EQ(svcs[1].start_handle, 0x0004);
	ATF_CHECK_EQ(svcs[1].end_handle, 0x0007);
	ATF_CHECK_EQ(svcs[1].uuid16, 0xFFE0);

	ATF_CHECK_EQ(svcs[2].start_handle, 0x0008);
	ATF_CHECK_EQ(svcs[2].end_handle, 0x000A);
	ATF_CHECK_EQ(svcs[2].uuid16, 0x180F);

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
 * Mock server responds to Read By Type (0x08) with UUID 0x2803.
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
			if (n < 7 || req[0] != ATT_OP_READ_BY_TYPE_REQ) {
				close(peer);
				_exit(1);
			}
			/* Verify UUID = 0x2803 (characteristic) */
			if (get_le16(req + 5) != GATT_UUID_CHARACTERISTIC) {
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
				rsp[0] = ATT_OP_READ_BY_TYPE_RSP;
				rsp[1] = 7; /* entry_len */
				/* Char 1: decl=0x0002, props=READ,
				 * val=0x0003, UUID=0x2A00 */
				put_le16(rsp + 2, 0x0002);
				rsp[4] = GATT_PROP_READ;
				put_le16(rsp + 5, 0x0003);
				put_le16(rsp + 7, 0x2A00);
				/* Char 2: decl=0x0005, props=RWN,
				 * val=0x0006, UUID=0xFFE1 */
				put_le16(rsp + 9, 0x0005);
				rsp[11] = GATT_PROP_READ | GATT_PROP_WRITE |
				    GATT_PROP_NOTIFY;
				put_le16(rsp + 12, 0x0006);
				put_le16(rsp + 14, 0xFFE1);
				send(peer, rsp, sizeof(rsp), 0);
			} else {
				uint8_t err[5];
				err[0] = ATT_OP_ERROR_RSP;
				err[1] = ATT_OP_READ_BY_TYPE_REQ;
				put_le16(err + 2, get_le16(req + 1));
				err[4] = ATT_ERR_ATTR_NOT_FOUND;
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
	ATF_CHECK_EQ(chars[0].properties, GATT_PROP_READ);
	ATF_CHECK_EQ(chars[0].value_handle, 0x0003);
	ATF_CHECK_EQ(chars[0].uuid16, 0x2A00);

	ATF_CHECK_EQ(chars[1].decl_handle, 0x0005);
	ATF_CHECK_EQ(chars[1].properties,
	    GATT_PROP_READ | GATT_PROP_WRITE | GATT_PROP_NOTIFY);
	ATF_CHECK_EQ(chars[1].value_handle, 0x0006);
	ATF_CHECK_EQ(chars[1].uuid16, 0xFFE1);

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
			if (n < 5 || req[0] != ATT_OP_FIND_INFO_REQ) {
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
				rsp[0] = ATT_OP_FIND_INFO_RSP;
				rsp[1] = 1; /* format: 16-bit UUID */
				/* Descriptor 1: handle=0x0007,
				 * UUID=0x2902 (CCCD) */
				put_le16(rsp + 2, 0x0007);
				put_le16(rsp + 4, 0x2902);
				/* Descriptor 2: handle=0x0008,
				 * UUID=0x2901 (Char User Desc) */
				put_le16(rsp + 6, 0x0008);
				put_le16(rsp + 8, 0x2901);
				send(peer, rsp, sizeof(rsp), 0);
			} else {
				uint8_t err[5];
				err[0] = ATT_OP_ERROR_RSP;
				err[1] = ATT_OP_FIND_INFO_REQ;
				put_le16(err + 2, get_le16(req + 1));
				err[4] = ATT_ERR_ATTR_NOT_FOUND;
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
	ATF_CHECK_EQ(descs[0].uuid16, 0x2902);

	ATF_CHECK_EQ(descs[1].handle, 0x0008);
	ATF_CHECK_EQ(descs[1].uuid16, 0x2901);

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
 * Uses Find By Type Value (opcode 0x06) with UUID 0x2800.
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
			    req[0] != ATT_OP_FIND_BY_TYPE_VALUE_REQ) {
				close(peer);
				_exit(1);
			}
			/* Verify type UUID = 0x2800 */
			if (get_le16(req + 5) != GATT_UUID_PRIMARY_SERVICE) {
				close(peer);
				_exit(2);
			}
			/* Verify value = 0xFFE0 (LE) */
			if (n < 9 || get_le16(req + 7) != 0xFFE0) {
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
				rsp[0] = ATT_OP_FIND_BY_TYPE_VALUE_RSP;
				put_le16(rsp + 1, 0x0004); /* start */
				put_le16(rsp + 3, 0x0007); /* end */
				send(peer, rsp, sizeof(rsp), 0);
			} else {
				uint8_t err[5];
				err[0] = ATT_OP_ERROR_RSP;
				err[1] = ATT_OP_FIND_BY_TYPE_VALUE_REQ;
				put_le16(err + 2, get_le16(req + 1));
				err[4] = ATT_ERR_ATTR_NOT_FOUND;
				send(peer, err, sizeof(err), 0);
			}
		}

		close(peer);
		_exit(0);
	}

	close(peer);
	struct gatt_service svcs[GATT_MAX_SERVICES];
	int nsvcs = 0;
	int ret = gatt_discover_primary_service_by_uuid(&ac, 0xFFE0,
	    svcs, GATT_MAX_SERVICES, &nsvcs);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(nsvcs, 1);
	ATF_CHECK_EQ(svcs[0].start_handle, 0x0004);
	ATF_CHECK_EQ(svcs[0].end_handle, 0x0007);
	ATF_CHECK_EQ(svcs[0].uuid16, 0xFFE0);

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
			    req[0] != ATT_OP_FIND_BY_TYPE_VALUE_REQ) {
				close(peer);
				_exit(1);
			}
			/* Verify type UUID = 0x2800 */
			if (get_le16(req + 5) != GATT_UUID_PRIMARY_SERVICE) {
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
				rsp[0] = ATT_OP_FIND_BY_TYPE_VALUE_RSP;
				put_le16(rsp + 1, 0x0010);
				put_le16(rsp + 3, 0x0015);
				send(peer, rsp, sizeof(rsp), 0);
			} else {
				uint8_t err[5];
				err[0] = ATT_OP_ERROR_RSP;
				err[1] = ATT_OP_FIND_BY_TYPE_VALUE_REQ;
				put_le16(err + 2, get_le16(req + 1));
				err[4] = ATT_ERR_ATTR_NOT_FOUND;
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
 * 6. test_gatt_discover_secondary_services
 *
 * Uses Read By Group Type (opcode 0x10) with UUID 0x2801.
 * Mock server returns secondary service declarations.
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
			    req[0] != ATT_OP_READ_BY_GROUP_TYPE_REQ) {
				close(peer);
				_exit(1);
			}
			/* Verify UUID = 0x2801 (secondary service) */
			if (get_le16(req + 5) != GATT_UUID_SECONDARY_SERVICE) {
				close(peer);
				_exit(2);
			}

			if (round == 0) {
				/* 1 secondary service */
				uint8_t rsp[1 + 1 + 6];
				rsp[0] = ATT_OP_READ_BY_GROUP_TYPE_RSP;
				rsp[1] = 6; /* entry_len */
				put_le16(rsp + 2, 0x0020);
				put_le16(rsp + 4, 0x0025);
				put_le16(rsp + 6, 0x1801);
				send(peer, rsp, sizeof(rsp), 0);
			} else {
				uint8_t err[5];
				err[0] = ATT_OP_ERROR_RSP;
				err[1] = ATT_OP_READ_BY_GROUP_TYPE_REQ;
				put_le16(err + 2, get_le16(req + 1));
				err[4] = ATT_ERR_ATTR_NOT_FOUND;
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
	ATF_CHECK_EQ(svcs[0].uuid16, 0x1801);

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
 * Uses Read By Type (opcode 0x08) with UUID 0x2802.
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
		 *          ATT_ERR_ATTR_NOT_FOUND.
		 */
		while (phase < 4) {
			n = recv(peer, req, sizeof(req), 0);
			if (n < 1) {
				close(peer);
				_exit(10);
			}

			if (phase == 0) {
				if (req[0] != ATT_OP_READ_BY_TYPE_REQ ||
				    n < 7) {
					close(peer);
					_exit(1);
				}
				if (get_le16(req + 5) != GATT_UUID_INCLUDE) {
					close(peer);
					_exit(2);
				}
				/*
				 * entry_len=8: handle(2) + start(2) +
				 * end(2) + uuid16(2)
				 */
				uint8_t rsp[1 + 1 + 8];
				rsp[0] = ATT_OP_READ_BY_TYPE_RSP;
				rsp[1] = 8;
				put_le16(rsp + 2, 0x0004); /* incl handle */
				put_le16(rsp + 4, 0x0020); /* start */
				put_le16(rsp + 6, 0x0025); /* end */
				put_le16(rsp + 8, 0x180A); /* uuid16 */
				send(peer, rsp, sizeof(rsp), 0);
				phase = 1;
			} else if (phase == 1) {
				if (req[0] != ATT_OP_READ_BY_TYPE_REQ ||
				    n < 7) {
					close(peer);
					_exit(3);
				}
				/*
				 * entry_len=6: handle(2) + start(2) +
				 * end(2), no UUID
				 */
				uint8_t rsp[1 + 1 + 6];
				rsp[0] = ATT_OP_READ_BY_TYPE_RSP;
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
				if (req[0] != ATT_OP_READ_REQ || n < 3) {
					close(peer);
					_exit(4);
				}
				if (get_le16(req + 1) != 0x0030) {
					close(peer);
					_exit(5);
				}
				/* Reply with 16 bytes (128-bit UUID) */
				uint8_t rsp[1 + 16];
				rsp[0] = ATT_OP_READ_RSP;
				memcpy(rsp + 1, inc128_uuid, 16);
				send(peer, rsp, sizeof(rsp), 0);
				phase = 3;
			} else {
				/* Phase 3: continuation Read By Type */
				if (req[0] != ATT_OP_READ_BY_TYPE_REQ) {
					close(peer);
					_exit(6);
				}
				uint8_t err[5];
				err[0] = ATT_OP_ERROR_RSP;
				err[1] = ATT_OP_READ_BY_TYPE_REQ;
				put_le16(err + 2, get_le16(req + 1));
				err[4] = ATT_ERR_ATTR_NOT_FOUND;
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
	ATF_CHECK_EQ(includes[0].uuid16, 0x180A);
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
 * 8. test_gatt_db_hash_computation
 *
 * Build a test database, call attdb_compute_db_hash, verify the hash
 * is non-zero and deterministic.
 */
ATF_TC_WITHOUT_HEAD(test_gatt_db_hash_computation);
ATF_TC_BODY(test_gatt_db_hash_computation, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t hash1[16], hash2[16];
	uint8_t zero[16];

	build_test_db(&db, attrs, val_buf);

	memset(zero, 0, sizeof(zero));
	memset(hash1, 0, sizeof(hash1));
	memset(hash2, 0, sizeof(hash2));

	attdb_compute_db_hash(&db, hash1);

	/* Hash must be non-zero */
	ATF_CHECK(memcmp(hash1, zero, 16) != 0);

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
	attdb_add_service(&db, 0x180F);
	attdb_add_characteristic(&db, 0x2A19,
	    GATT_PROP_READ | GATT_PROP_NOTIFY,
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
	attdb_add_service(&db1, 0x1800);
	attdb_add_characteristic(&db1, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ, "AAAA", 4);

	/* DB2: same structure, different value = "ZZZZ" */
	attdb_init(&db2, attrs2, TEST_DB_MAX_ATTRS, val2, TEST_DB_VAL_SIZE);
	attdb_add_service(&db2, 0x1800);
	attdb_add_characteristic(&db2, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ, "ZZZZ", 4);

	attdb_compute_db_hash(&db1, hash1);
	attdb_compute_db_hash(&db2, hash2);

	/* Hashes must be equal since char values are excluded */
	ATF_CHECK_EQ(memcmp(hash1, hash2, 16), 0);
}

/*
 * 10b. test_gatt_read_database_hash
 *
 * Mock a peer that serves UUID 0x2B2A (Database Hash) with a known
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

		/* Expect Read By Type Request with UUID 0x2B2A */
		n = recv(peer, req, sizeof(req), 0);
		if (n < 7 || req[0] != ATT_OP_READ_BY_TYPE_REQ) {
			close(peer);
			_exit(1);
		}
		/* Verify UUID = 0x2B2A (Database Hash) */
		if (get_le16(req + 5) != GATT_UUID_DATABASE_HASH) {
			close(peer);
			_exit(2);
		}

		/*
		 * Respond with Read By Type Response:
		 * [opcode(0x09)] [attr_data_len=18] [handle(2) + hash(16)]
		 * Total: 1 + 1 + 18 = 20 bytes
		 */
		uint8_t rsp[1 + 1 + 2 + 16];
		rsp[0] = ATT_OP_READ_BY_TYPE_RSP;
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
 * Mock a peer that does NOT serve UUID 0x2B2A (returns Attribute Not
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
		if (n < 7 || req[0] != ATT_OP_READ_BY_TYPE_REQ) {
			close(peer);
			_exit(1);
		}

		/* Return Attribute Not Found */
		uint8_t err[5];
		err[0] = ATT_OP_ERROR_RSP;
		err[1] = ATT_OP_READ_BY_TYPE_REQ;
		put_le16(err + 2, get_le16(req + 1));
		err[4] = ATT_ERR_ATTR_NOT_FOUND;
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
 * Discover services on a server that returns ATT_ERR_ATTR_NOT_FOUND
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
		if (n < 7 || req[0] != ATT_OP_READ_BY_GROUP_TYPE_REQ) {
			close(peer);
			_exit(1);
		}

		/* Immediately return Attribute Not Found */
		uint8_t err[5];
		err[0] = ATT_OP_ERROR_RSP;
		err[1] = ATT_OP_READ_BY_GROUP_TYPE_REQ;
		put_le16(err + 2, get_le16(req + 1));
		err[4] = ATT_ERR_ATTR_NOT_FOUND;
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
 * (one service entry), then ATT_ERR_ATTR_NOT_FOUND on the next
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
			    req[0] != ATT_OP_READ_BY_GROUP_TYPE_REQ) {
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
				rsp[0] = ATT_OP_READ_BY_GROUP_TYPE_RSP;
				rsp[1] = 6;
				put_le16(rsp + 2, 0x0001);
				put_le16(rsp + 4, 0x0005);
				put_le16(rsp + 6, 0x1800);
				send(peer, rsp, sizeof(rsp), 0);
			} else {
				uint8_t err[5];
				err[0] = ATT_OP_ERROR_RSP;
				err[1] = ATT_OP_READ_BY_GROUP_TYPE_REQ;
				put_le16(err + 2, get_le16(req + 1));
				err[4] = ATT_ERR_ATTR_NOT_FOUND;
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
	ATF_CHECK_EQ(svcs[0].uuid16, 0x1800);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
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
	ATF_TP_ADD_TC(tp, test_gatt_db_hash_computation);
	ATF_TP_ADD_TC(tp, test_gatt_db_hash_changes_on_modification);
	ATF_TP_ADD_TC(tp, test_gatt_db_hash_excludes_char_values);
	ATF_TP_ADD_TC(tp, test_gatt_read_database_hash);
	ATF_TP_ADD_TC(tp, test_gatt_read_database_hash_not_found);

	/* Edge cases */
	ATF_TP_ADD_TC(tp, test_gatt_discover_empty);
	ATF_TP_ADD_TC(tp, test_gatt_discover_services_truncated);

	return (atf_no_error());
}
