/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for the ATT server PDU dispatcher.
 *
 * att_server_handle() is the entry point that every ATT request from a
 * remote peer (an untrusted GATT client) flows into.  It is the largest
 * attack surface in the peripheral role: it parses attribute handles,
 * ranges, UUIDs and value blobs straight off the wire.  This harness
 * feeds arbitrary bytes as one ATT PDU against a small, fixed GATT
 * database and lets ASan catch any out-of-bounds read/write.
 *
 * Build/run: see fuzz/Makefile and fuzz/README.md.
 *
 * Reference: Core Spec Vol 3 Part F (ATT), Part G (GATT).
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <fcntl.h>
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

#define TEST_DB_MAX_ATTRS	32
#define TEST_DB_VAL_SIZE	512

static int		 devnull_fd = -1;
static uint8_t		*conn_buf;

/*
 * Rebuild the database each iteration so write requests that mutate
 * attribute values cannot make the corpus non-deterministic.  Backing
 * storage is static: attdb_init() copies nothing it does not own.
 */
static void
build_db(struct att_db *db)
{
	static struct att_attr attrs[TEST_DB_MAX_ATTRS];
	static uint8_t val_buf[TEST_DB_VAL_SIZE];

	attdb_init(db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);

	/* GAP service (0x1800) with Device Name */
	attdb_add_service(db, 0x1800);
	attdb_add_characteristic(db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ, "fuzz", 4);

	/* Custom service (0xFFE0): readable/writable/notifiable char + CCCD */
	attdb_add_service(db, 0xFFE0);
	attdb_add_characteristic(db, 0xFFE1,
	    GATT_PROP_READ | GATT_PROP_WRITE | GATT_PROP_NOTIFY,
	    ATT_PERM_READ | ATT_PERM_WRITE,
	    "\xAA\xBB\xCC\xDD", 4);
	attdb_add_cccd(db);
}

int
LLVMFuzzerInitialize(int *argc __unused, char ***argv __unused)
{

	devnull_fd = open("/dev/null", O_WRONLY);
	if (devnull_fd < 0)
		abort();
	conn_buf = malloc(ATT_MAX_MTU);
	if (conn_buf == NULL)
		abort();
	return (0);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct att_conn ac;
	struct att_db db;

	if (size == 0)
		return (0);

	build_db(&db);

	memset(&ac, 0, sizeof(ac));
	ac.fd = devnull_fd;		/* responses go to the bit bucket */
	ac.bearer_fd = -1;		/* unenhanced ATT bearer */
	ac.mtu = ATT_DEFAULT_MTU;	/* negotiable via ATT_OP_MTU_REQ */
	ac.buf = conn_buf;

	att_server_handle(&ac, &db, data, size, -1, 0);

	return (0);
}
