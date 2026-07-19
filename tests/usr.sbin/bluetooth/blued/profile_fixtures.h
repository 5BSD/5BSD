/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_PROFILE_FIXTURES_H_
#define _BLUED_PROFILE_FIXTURES_H_

/*
 * Reusable library of known GATT profile fixtures and golden data vectors.
 *
 * Each fixture pairs a builder that populates a real struct att_db (via the
 * attdb_* API from att_server.c) with a table of "golden operations": each
 * operation is an input ATT PDU and the exact response PDU the server must
 * emit, plus an optional notification vector (an emitted Handle Value
 * Notification PDU).
 *
 * The same fixtures are intended to double as scripted controller payloads
 * for a future HCI controller emulator, so the byte vectors are kept as
 * plain static const arrays with ATT opcode / handle citations.
 *
 * Core Spec Vol 3 Part F (ATT), Part G (GATT), and the referenced SIG
 * service specifications (GAP 0x1800, GATT 0x1801, DIS 0x180A,
 * Battery 0x180F, Heart Rate 0x180D, HID over GATT 0x1812).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "att_server.h"		/* struct att_db, struct att_attr */

/*
 * A single known-answer operation: feed req[0..req_len) to
 * att_server_handle() and expect exactly rsp[0..rsp_len) back.
 */
struct golden_op {
	const char	*desc;		/* human-readable description */
	const uint8_t	*req;		/* input ATT request PDU */
	size_t		 req_len;
	const uint8_t	*rsp;		/* exact expected response PDU */
	size_t		 rsp_len;
};

/*
 * A profile fixture: a service builder plus its golden operations and an
 * optional notification demonstration.
 */
struct profile_fixture {
	const char	*name;		/* e.g. "GAP" */
	uint16_t	 service_uuid;	/* primary service UUID (0x1800 ...) */

	/*
	 * Populate *db with this profile's attribute database.  The builder
	 * owns its own value/attr storage (file-static in profile_fixtures.c),
	 * so callers only supply the struct att_db to initialise.
	 */
	void		(*build)(struct att_db *db);

	const struct golden_op	*ops;	/* golden operation table */
	size_t			 nops;

	/*
	 * Optional Handle Value Notification demonstration.  When has_notify
	 * is true, calling att_send_notification(ac, notify_handle,
	 * notify_value, notify_len) must emit exactly notify_pdu[0..len).
	 */
	bool		 has_notify;
	uint16_t	 notify_handle;
	const uint8_t	*notify_value;
	uint16_t	 notify_len;
	const uint8_t	*notify_pdu;
	size_t		 notify_pdu_len;
};

/* Per-profile accessors. */
const struct profile_fixture	*profile_fixture_gap(void);
const struct profile_fixture	*profile_fixture_gatt(void);
const struct profile_fixture	*profile_fixture_dis(void);
const struct profile_fixture	*profile_fixture_battery(void);
const struct profile_fixture	*profile_fixture_heart_rate(void);
const struct profile_fixture	*profile_fixture_hogp(void);

/* All profiles as an array (for iterating every fixture). */
const struct profile_fixture	*const *profile_fixtures_all(size_t *count);

#endif /* _BLUED_PROFILE_FIXTURES_H_ */
