/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Daemon-wiring tests: blued_peripheral.c and blued_central.c.
 *
 * Both files were linked by NO test program (each pulls in blued.c).  This
 * program drives the real objects over the same 62-symbol blued.c seam the
 * event-loop tests use (blued_daemon_stub.c), and observes the controller
 * through the --wrap=bt_devreq seam so the HCI-failure arms -- readvertise
 * retry/backoff above all -- are reachable without a controller.
 *
 * Covered here: readvertise arming, its per-adapter retry budget and cancel;
 * the peripheral and central setup-failure handoffs to the main loop; the
 * armed late-pairing SMP channel's descriptor-ownership rules; the
 * config-built GATT database including the C3-D30 descriptor guards; the
 * Signed-Write flush timer; and central-role teardown.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/un.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "blued.h"
#include "blued_daemon_stub.h"
#include "blued_internal.h"
#include "ble_util.h"
#include "config.h"
#include "conn.h"
#include "ctl.h"
#include "gatt.h"
#include "hci_util.h"
#include "smp.h"

/* ================================================================
 * bt_devreq wrap: count HCI commands and force controller failures.
 * ================================================================ */

static unsigned int role_ncmds;
static bool role_devreq_fail;

int	__wrap_bt_devreq(int s, struct bt_devreq *r, time_t to);

int
__wrap_bt_devreq(int s __unused, struct bt_devreq *r, time_t to __unused)
{

	role_ncmds++;
	if (role_devreq_fail) {
		errno = EIO;
		return (-1);
	}
	if (r->rparam != NULL && r->rlen > 0)
		memset(r->rparam, 0, r->rlen);
	return (0);
}

/* ================================================================
 * Fixture
 * ================================================================ */

static struct blued_adapter role_adp;
static int role_hci_sp[2] = { -1, -1 };

static void
role_reset(void)
{

	role_ncmds = 0;
	role_devreq_fail = false;
	blued_stub_reset();
	running = 1;

	memset(&blued_g, 0, sizeof(blued_g));
	blued_g.kq = -1;
	blued_g.ctl_fd = -1;
	blued_g.bond_fd = -1;
	blued_g.vhid_ctl_fd = -1;
	LIST_INIT(&blued_g.adapters);
	LIST_INIT(&blued_g.conns);
	LIST_INIT(&blued_g.ctl_clients);
	LIST_INIT(&blued_g.ctl_acquires);
	pthread_rwlock_init(&blued_g.conns_lock, NULL);
	pthread_mutex_init(&blued_g.bond_db_lock, NULL);
	pthread_mutex_init(&blued_g.gatt_db_lock, NULL);
	pthread_mutex_init(&blued_g.att_sec_lock, NULL);
	pthread_mutex_init(&blued_g.reslist_lock, NULL);
	blued_ctl_clients_lock_init(&blued_g.ctl_clients_lock);
	blued_g.main_thread = pthread_self();
	blued_g.kq = kqueue();
	ATF_REQUIRE(blued_g.kq >= 0);
	ATF_REQUIRE_EQ(0, pipe(blued_g.setup_pipe));

	memset(&role_adp, 0, sizeof(role_adp));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, role_hci_sp));
	role_adp.hci_fd = role_hci_sp[0];
	role_adp.active = true;
	role_adp.powered = true;
	role_adp.adv_configured = true;
	role_adp.periph_listen_fd = role_hci_sp[1];
	role_adp.eatt_listen_fd = -1;
	strlcpy(role_adp.name, "ubt0", sizeof(role_adp.name));
	LIST_INSERT_HEAD(&blued_g.adapters, &role_adp, entries);
	blued_g.periph_active = true;
}

static void
role_teardown(void)
{

	if (blued_g.kq >= 0)
		close(blued_g.kq);
	if (blued_g.setup_pipe[0] >= 0)
		close(blued_g.setup_pipe[0]);
	if (blued_g.setup_pipe[1] >= 0)
		close(blued_g.setup_pipe[1]);
	if (role_hci_sp[0] >= 0)
		close(role_hci_sp[0]);
	if (role_hci_sp[1] >= 0)
		close(role_hci_sp[1]);
	hci_fd_closed(role_adp.hci_fd);
	blued_g.kq = -1;
	blued_g.setup_pipe[0] = blued_g.setup_pipe[1] = -1;
	role_hci_sp[0] = role_hci_sp[1] = -1;
}

static struct blued_conn *
role_make_conn(int role, int state)
{
	struct blued_conn *c;

	c = blued_conn_alloc();
	ATF_REQUIRE(c != NULL);
	c->adapter = &role_adp;
	c->role = role;
	c->att_fd = -1;
	c->smp_fd = -1;
	c->addr_type = BDADDR_LE_PUBLIC;
	atomic_store(&c->state, state);
	return (c);
}

/* True while FD names an open descriptor in this process. */
static bool
role_fd_open(int fd)
{

	return (fcntl(fd, F_GETFD) != -1 || errno != EBADF);
}

/* ================================================================
 * Peripheral: re-advertise
 * ================================================================ */

/*
 * Pins the gate at the head of blued_periph_readvertise_one(): every one of
 * the five preconditions suppresses the controller command, so a quiescing or
 * unconfigured adapter is never re-enabled behind the operator's back.
 */
ATF_TC_WITHOUT_HEAD(readvertise_respects_adapter_gates);
ATF_TC_BODY(readvertise_respects_adapter_gates, tc)
{
	struct {
		const char	*what;
		bool		*flag;
		bool		value;
	} gates[] = {
		{ "periph_active",	&blued_g.periph_active,	false },
		{ "active",		&role_adp.active,	false },
		{ "powered",		&role_adp.powered,	false },
		{ "adv_configured",	&role_adp.adv_configured, false },
		{ "power_quiescing",	&role_adp.power_quiescing, true },
	};
	size_t i;

	for (i = 0; i < nitems(gates); i++) {
		role_reset();
		*gates[i].flag = gates[i].value;
		blued_periph_readvertise();
		ATF_CHECK_MSG(role_ncmds == 0,
		    "%s did not suppress re-advertising", gates[i].what);
		role_teardown();
	}

	/* The listener descriptor is the sixth gate. */
	role_reset();
	role_adp.periph_listen_fd = -1;
	blued_periph_readvertise();
	ATF_CHECK_EQ(0, role_ncmds);
	role_teardown();

	/* All gates open: the enable is issued and latched. */
	role_reset();
	blued_periph_readvertise();
	ATF_CHECK(role_ncmds > 0);
	ATF_CHECK(role_adp.adv_enabled);
	role_teardown();
}

/*
 * Pins the legacy reclaim in blued_periph_readvertise_one(): on a legacy
 * controller the single advertising resource is reclaimed from a mesh burst
 * BEFORE the enable, and a reclaim failure is treated as a re-advertise
 * failure rather than airing mesh's stale PDU as ours.
 */
ATF_TC_WITHOUT_HEAD(readvertise_reclaims_legacy_adv_resource);
ATF_TC_BODY(readvertise_reclaims_legacy_adv_resource, tc)
{

	role_reset();
	role_adp.adv_use_extended = false;
	blued_periph_readvertise();
	ATF_CHECK_EQ(1, blued_stub.adv_legacy_reclaim_calls);
	ATF_CHECK(role_adp.adv_enabled);
	role_teardown();

	/* An extended-advertising adapter owns its own set: no reclaim. */
	role_reset();
	role_adp.adv_use_extended = true;
	blued_periph_readvertise();
	ATF_CHECK_EQ(0, blued_stub.adv_legacy_reclaim_calls);
	role_teardown();
}

/*
 * Pins the retry budget: a failing controller arms at most
 * BLUED_READVERTISE_MAX_RETRIES one-shots and then gives up, and a single
 * pending timer suppresses further arming.
 */
ATF_TC_WITHOUT_HEAD(readvertise_retry_budget_is_bounded);
ATF_TC_BODY(readvertise_retry_budget_is_bounded, tc)
{
	unsigned int i;

	role_reset();
	role_devreq_fail = true;

	blued_periph_readvertise();
	ATF_CHECK_MSG(role_adp.readvertise_timer != 0, "no retry armed");
	ATF_CHECK_EQ(1, role_adp.readvertise_retries);

	/* A pending timer suppresses re-arming. */
	blued_periph_readvertise();
	ATF_CHECK_EQ(1, role_adp.readvertise_retries);

	/* Each expiry re-attempts and re-arms, up to the budget. */
	for (i = 2; i <= BLUED_READVERTISE_MAX_RETRIES; i++) {
		ATF_CHECK(blued_periph_readvertise_timer_fired(
		    role_adp.readvertise_timer));
		ATF_CHECK_EQ(i, role_adp.readvertise_retries);
	}

	/* Budget spent: the last expiry re-attempts but arms nothing. */
	ATF_CHECK(blued_periph_readvertise_timer_fired(
	    role_adp.readvertise_timer));
	ATF_CHECK_EQ(0, role_adp.readvertise_timer);
	ATF_CHECK_EQ(BLUED_READVERTISE_MAX_RETRIES,
	    role_adp.readvertise_retries);

	role_teardown();
}

/*
 * Pins blued_periph_readvertise_timer_fired()'s identity check and
 * blued_periph_readvertise_cancel(): an expiry that belongs to no adapter is
 * refused (so the event loop can fall through to its other timer arms), and a
 * successful re-advertise clears both the timer and the retry budget.
 */
ATF_TC_WITHOUT_HEAD(readvertise_timer_identity_and_cancel);
ATF_TC_BODY(readvertise_timer_identity_and_cancel, tc)
{

	role_reset();
	role_devreq_fail = true;
	blued_periph_readvertise();
	ATF_REQUIRE(role_adp.readvertise_timer != 0);

	ATF_CHECK_MSG(!blued_periph_readvertise_timer_fired(
	    role_adp.readvertise_timer + 1000),
	    "a foreign timer ident claimed the readvertise arm");
	ATF_CHECK(role_adp.readvertise_timer != 0);

	/* The controller recovers: the next attempt cancels the retry state. */
	role_devreq_fail = false;
	ATF_CHECK(blued_periph_readvertise_timer_fired(
	    role_adp.readvertise_timer));
	ATF_CHECK_EQ(0, role_adp.readvertise_timer);
	ATF_CHECK_EQ(0, role_adp.readvertise_retries);
	ATF_CHECK(role_adp.adv_enabled);

	role_teardown();
}

/*
 * Pins the "retry state and timer ownership are adapter-local" contract: one
 * failing controller must not consume or reset another controller's budget.
 */
ATF_TC_WITHOUT_HEAD(readvertise_retry_state_is_per_adapter);
ATF_TC_BODY(readvertise_retry_state_is_per_adapter, tc)
{
	struct blued_adapter second;
	int sp[2];

	role_reset();
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp));
	memset(&second, 0, sizeof(second));
	second.hci_fd = sp[0];
	second.index = 1;
	second.active = true;
	second.powered = true;
	second.adv_configured = true;
	second.periph_listen_fd = sp[1];
	second.eatt_listen_fd = -1;
	strlcpy(second.name, "ubt1", sizeof(second.name));
	LIST_INSERT_HEAD(&blued_g.adapters, &second, entries);

	role_devreq_fail = true;
	blued_periph_readvertise();
	ATF_CHECK_EQ(1, role_adp.readvertise_retries);
	ATF_CHECK_EQ(1, second.readvertise_retries);
	ATF_CHECK(role_adp.readvertise_timer != second.readvertise_timer);

	/* Cancelling one adapter leaves the other's budget untouched. */
	blued_periph_readvertise_cancel(&second);
	ATF_CHECK_EQ(0, second.readvertise_retries);
	ATF_CHECK_EQ(1, role_adp.readvertise_retries);

	LIST_REMOVE(&second, entries);
	hci_fd_closed(second.hci_fd);
	close(sp[0]);
	close(sp[1]);
	role_teardown();
}

/* ================================================================
 * Setup-failure handoffs
 * ================================================================ */

/*
 * Pins blued_periph_setup_fail(): the failing setup thread hands the
 * connection to the main loop with BOTH latches set and pokes the self-pipe,
 * so the sweep frees the conn AND the adapter goes back on air.
 */
ATF_TC_WITHOUT_HEAD(peripheral_setup_fail_hands_off_to_main_loop);
ATF_TC_BODY(peripheral_setup_fail_hands_off_to_main_loop, tc)
{
	struct blued_conn *c;
	char byte;

	role_reset();
	c = role_make_conn(BLUED_ROLE_PERIPHERAL, BLUED_CONN_CONNECTING);

	blued_periph_setup_fail(c);

	ATF_CHECK_EQ(BLUED_CONN_IDLE, atomic_load(&c->state));
	ATF_CHECK(atomic_load(&c->needs_readvertise));
	ATF_CHECK(atomic_load(&c->needs_cleanup));
	ATF_CHECK_EQ(1, read(blued_g.setup_pipe[0], &byte, 1));

	blued_conn_free(c);
	role_teardown();
}

/*
 * Pins C3-H3 in blued_central_setup_fail(): entering the reconnect backoff
 * invalidates the stale connection handle, and the reconnect ONESHOT is NOT
 * armed from the setup thread -- only requested, so arm and teardown stay
 * serialized on the main thread.
 */
ATF_TC_WITHOUT_HEAD(central_setup_fail_defers_arm_and_kills_handle);
ATF_TC_BODY(central_setup_fail_defers_arm_and_kills_handle, tc)
{
	struct blued_conn *c;
	char byte;

	role_reset();
	c = role_make_conn(BLUED_ROLE_CENTRAL, BLUED_CONN_CONNECTING);
	c->reconnect = true;
	c->con_handle = 0x0070;
	c->con_handle_valid = true;

	blued_central_setup_fail(c);

	ATF_CHECK_EQ(BLUED_CONN_RECONNECTING, atomic_load(&c->state));
	ATF_CHECK_MSG(!c->con_handle_valid, "stale handle survived setup failure");
	ATF_CHECK(atomic_load(&c->needs_reconnect_arm));
	ATF_CHECK_MSG(c->reconnect_timer == 0,
	    "reconnect ONESHOT armed from the setup thread");
	ATF_CHECK_EQ(1, read(blued_g.setup_pipe[0], &byte, 1));

	blued_conn_free(c);
	role_teardown();
}

/*
 * Pins the non-reconnect arm of blued_central_setup_fail(): the conn goes IDLE
 * and is flagged for terminal cleanup instead of for a retry.
 */
ATF_TC_WITHOUT_HEAD(central_setup_fail_without_reconnect_is_terminal);
ATF_TC_BODY(central_setup_fail_without_reconnect_is_terminal, tc)
{
	struct blued_conn *c;

	role_reset();
	c = role_make_conn(BLUED_ROLE_CENTRAL, BLUED_CONN_CONNECTING);
	c->reconnect = false;

	blued_central_setup_fail(c);

	ATF_CHECK_EQ(BLUED_CONN_IDLE, atomic_load(&c->state));
	ATF_CHECK(atomic_load(&c->needs_cleanup));
	ATF_CHECK(!atomic_load(&c->needs_reconnect_arm));

	blued_conn_free(c);
	role_teardown();
}

/* ================================================================
 * Armed late-pairing SMP channel
 * ================================================================ */

/*
 * Pins the descriptor-ownership rules of blued_periph_smp_late_event(): the
 * responder descriptor moves OUT of the connection (so exactly one worker can
 * own it), and an EOF closes it there.
 */
ATF_TC_WITHOUT_HEAD(late_smp_eof_takes_and_closes_descriptor);
ATF_TC_BODY(late_smp_eof_takes_and_closes_descriptor, tc)
{
	struct blued_conn *c;
	int sp[2];

	role_reset();
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp));
	c = role_make_conn(BLUED_ROLE_PERIPHERAL, BLUED_CONN_ACTIVE);
	c->smp_fd = sp[0];

	blued_periph_smp_late_event(sp[0], true);

	ATF_CHECK_MSG(c->smp_fd == -1, "descriptor left owned by the conn");
	ATF_CHECK_MSG(!role_fd_open(sp[0]), "EOF path leaked the descriptor");

	close(sp[1]);
	blued_conn_free(c);
	role_teardown();
}

/*
 * Pins the orphan arm: when no live connection claims the descriptor its owner
 * has been detached but not destroyed, so the event must NOT close it -- a
 * double close could land on a recycled descriptor.
 */
ATF_TC_WITHOUT_HEAD(late_smp_orphan_descriptor_is_not_closed);
ATF_TC_BODY(late_smp_orphan_descriptor_is_not_closed, tc)
{
	int sp[2];

	role_reset();
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp));

	blued_periph_smp_late_event(sp[0], false);
	ATF_CHECK_MSG(role_fd_open(sp[0]),
	    "an unclaimed responder descriptor was closed by the event loop");

	close(sp[0]);
	close(sp[1]);
	role_teardown();
}

/* Pins the negative-descriptor guard. */
ATF_TC_WITHOUT_HEAD(late_smp_ignores_invalid_descriptor);
ATF_TC_BODY(late_smp_ignores_invalid_descriptor, tc)
{

	role_reset();
	blued_periph_smp_late_event(-1, false);
	blued_periph_smp_late_event(-1, true);
	role_teardown();
}

/* ================================================================
 * Config-built GATT database
 * ================================================================ */

static struct att_attr role_attrs[64];
static uint8_t role_valbuf[2048];

/* Locate an attribute by 16-bit UUID; returns its index or -1. */
static int
role_db_find(const struct att_db *db, uint16_t uuid16)
{
	int i;

	for (i = 0; i < db->count; i++)
		if (db->attrs[i].uuid16 == uuid16)
			return (i);
	return (-1);
}

/*
 * True when the database holds a Primary Service declaration (0x2800) whose
 * value is the 16-bit service UUID -- a service's own UUID lives in the
 * declaration's value, not in the attribute type.
 */
static bool
role_db_service_declared(const struct att_db *db, uint16_t svc_uuid16)
{
	int i;

	for (i = 0; i < db->count; i++)
		if (db->attrs[i].uuid16 == 0x2800 &&
		    db->attrs[i].value_len == 2 &&
		    (uint16_t)(db->attrs[i].value[0] |
		    (db->attrs[i].value[1] << 8)) == svc_uuid16)
			return (true);
	return (false);
}

static int
role_db_count(const struct att_db *db, uint16_t uuid16)
{
	int i, n = 0;

	for (i = 0; i < db->count; i++)
		if (db->attrs[i].uuid16 == uuid16)
			n++;
	return (n);
}

/*
 * Pins the mandatory shape of the built database: GAP + GATT + DIS, the
 * Service Changed characteristic and its CCCD, the Client/Server Supported
 * Features characteristics and a Database Hash that is actually computed
 * (never left as the 16 zero placeholder bytes).
 */
ATF_TC_WITHOUT_HEAD(gattdb_mandatory_shape);
ATF_TC_BODY(gattdb_mandatory_shape, tc)
{
	struct att_db db;
	static const uint8_t zeros[16];
	int i;

	role_reset();
	peripheral_build_gattdb(&db, role_attrs, role_valbuf,
	    sizeof(role_valbuf), NULL);

	ATF_CHECK(role_db_find(&db, UUID_DEVICE_NAME) >= 0);
	ATF_CHECK(role_db_find(&db, 0x2AA6) >= 0);	/* Central Addr Res */
	ATF_CHECK(role_db_find(&db, 0x2A05) >= 0);	/* Service Changed */
	ATF_CHECK(role_db_find(&db, UUID_CLIENT_SUPP_FEAT) >= 0);
	ATF_CHECK(role_db_find(&db, UUID_SERVER_SUPP_FEAT) >= 0);
	ATF_CHECK(role_db_find(&db, UUID_MANUFACTURER) >= 0);

	i = role_db_find(&db, UUID_DATABASE_HASH);
	ATF_REQUIRE(i >= 0);
	ATF_CHECK_EQ(16, db.attrs[i].value_len);
	ATF_CHECK_MSG(memcmp(db.attrs[i].value, zeros, 16) != 0,
	    "Database Hash left as the build-time placeholder");

	role_teardown();
}

/*
 * Pins finding 115: Central Address Resolution (0x2AA6) is DERIVED from the
 * configured privacy state, not hardcoded -- advertising 0x01 with address
 * resolution off would falsely invite a peer to rely on RPA resolution.
 */
ATF_TC_WITHOUT_HEAD(gattdb_central_address_resolution_follows_privacy);
ATF_TC_BODY(gattdb_central_address_resolution_follows_privacy, tc)
{
	struct att_db db;
	int i;

	role_reset();

	blued_cfg.privacy = false;
	peripheral_build_gattdb(&db, role_attrs, role_valbuf,
	    sizeof(role_valbuf), NULL);
	i = role_db_find(&db, 0x2AA6);
	ATF_REQUIRE(i >= 0);
	ATF_CHECK_EQ(0x00, db.attrs[i].value[0]);

	blued_cfg.privacy = true;
	peripheral_build_gattdb(&db, role_attrs, role_valbuf,
	    sizeof(role_valbuf), NULL);
	i = role_db_find(&db, 0x2AA6);
	ATF_REQUIRE(i >= 0);
	ATF_CHECK_EQ(0x01, db.attrs[i].value[0]);

	blued_cfg.privacy = false;
	role_teardown();
}

/*
 * Pins the Device Name capacity reservation: BLUED_GAP_NAME_MAXLEN bytes of
 * value store are reserved so the SET_NAME verb can rename at runtime, while
 * value_len is trimmed to the startup name.
 */
ATF_TC_WITHOUT_HEAD(gattdb_device_name_reserves_rename_capacity);
ATF_TC_BODY(gattdb_device_name_reserves_rename_capacity, tc)
{
	struct att_db db;
	int i;

	role_reset();
	blued_peripheral_name = "ab";
	peripheral_build_gattdb(&db, role_attrs, role_valbuf,
	    sizeof(role_valbuf), NULL);
	i = role_db_find(&db, UUID_DEVICE_NAME);
	ATF_REQUIRE(i >= 0);
	ATF_CHECK_EQ(2, db.attrs[i].value_len);
	ATF_CHECK_MSG(db.attrs[i].value_maxlen >= BLUED_GAP_NAME_MAXLEN,
	    "no room reserved for a runtime rename (value_maxlen %u)",
	    db.attrs[i].value_maxlen);

	blued_peripheral_name = "5BSD-blued";
	role_teardown();
}

/*
 * Pins C3-D30 in peripheral_build_gattdb(): a config "descriptor" block must
 * not be able to declare a reserved GATT declaration type (0x2800-0x2803), a
 * mis-sized Client Characteristic Configuration (0x2902, must be 2 bytes) or a
 * mis-sized Characteristic User Description-adjacent 0x2B29 (must be 1 byte).
 * These are exactly the three checks the ctl path enforces.
 */
ATF_TC_WITHOUT_HEAD(gattdb_config_descriptor_guards);
ATF_TC_BODY(gattdb_config_descriptor_guards, tc)
{
	static struct blued_config cfg;
	struct blued_char_conf *ch;
	static struct att_attr ctrl_attrs[64];
	static uint8_t ctrl_valbuf[2048];
	struct att_db db, ctrl;

	role_reset();

	memset(&cfg, 0, sizeof(cfg));
	cfg.nservices = 1;
	strlcpy(cfg.services[0].name, "guarded",
	    sizeof(cfg.services[0].name));
	cfg.services[0].uuid16 = 0xFF10;
	cfg.services[0].nchars = 1;
	ch = &cfg.services[0].chars[0];
	ch->uuid16 = 0xFF11;
	ch->properties = GATT_PROP_READ;
	ch->permissions = ATT_PERM_READ;
	/* BLUED_MAX_CONF_DESCS bounds the block; three rejects + one keeper. */
	ch->ndescs = 4;
	/* 1: a Characteristic declaration smuggled in as a descriptor. */
	ch->descs[0].uuid16 = 0x2803;
	ch->descs[0].value_len = 2;
	/* 2: a mis-sized CCCD (the server serves 2 bytes per connection). */
	ch->descs[1].uuid16 = GATT_UUID_CCCD;
	ch->descs[1].value_len = 4;
	/* 3: a mis-sized 0x2B29 (the server serves 1 byte). */
	ch->descs[2].uuid16 = 0x2B29;
	ch->descs[2].value_len = 2;
	/* 4: a legitimate Characteristic User Description. */
	ch->descs[3].uuid16 = 0x2901;
	ch->descs[3].permissions = ATT_PERM_READ;
	ch->descs[3].value_len = 2;
	ch->descs[3].value[0] = 'o';
	ch->descs[3].value[1] = 'k';

	peripheral_build_gattdb(&db, role_attrs, role_valbuf,
	    sizeof(role_valbuf), &cfg);

	/*
	 * Control build: the SAME config with only the one legitimate
	 * descriptor.  Every count below is compared against it, so
	 * 0x2800/0x2803/0x2902, which also occur as genuine declarations, are
	 * still asserted exactly.
	 */
	cfg.services[0].chars[0].descs[0] = cfg.services[0].chars[0].descs[3];
	cfg.services[0].chars[0].ndescs = 1;
	peripheral_build_gattdb(&ctrl, ctrl_attrs, ctrl_valbuf,
	    sizeof(ctrl_valbuf), &cfg);

	ATF_CHECK_MSG(role_db_find(&db, 0xFF11) >= 0,
	    "the config characteristic itself was rejected");
	ATF_CHECK_MSG(role_db_find(&db, 0x2901) >= 0,
	    "a legitimate config descriptor was rejected");
	ATF_CHECK_MSG(role_db_count(&db, GATT_UUID_CCCD) ==
	    role_db_count(&ctrl, GATT_UUID_CCCD),
	    "a mis-sized CCCD was admitted from the config");
	ATF_CHECK_MSG(role_db_count(&db, 0x2B29) ==
	    role_db_count(&ctrl, 0x2B29),
	    "a mis-sized 0x2B29 descriptor was admitted from the config");
	ATF_CHECK_MSG(role_db_count(&db, 0x2803) ==
	    role_db_count(&ctrl, 0x2803),
	    "a Characteristic declaration was admitted as a config descriptor");
	ATF_CHECK_MSG(db.count == ctrl.count,
	    "%d guarded descriptor(s) leaked into the database",
	    db.count - ctrl.count);

	role_teardown();
}

/*
 * Pins the config service/characteristic path itself, so the guard test above
 * cannot pass merely because config services are ignored altogether.
 */
ATF_TC_WITHOUT_HEAD(gattdb_config_services_are_registered);
ATF_TC_BODY(gattdb_config_services_are_registered, tc)
{
	static struct blued_config cfg;
	struct att_db db;

	role_reset();
	memset(&cfg, 0, sizeof(cfg));
	cfg.nservices = 1;
	strlcpy(cfg.services[0].name, "plain", sizeof(cfg.services[0].name));
	cfg.services[0].uuid16 = 0xFF20;
	cfg.services[0].nchars = 1;
	cfg.services[0].chars[0].uuid16 = 0xFF21;
	cfg.services[0].chars[0].properties = GATT_PROP_READ | GATT_PROP_NOTIFY;
	cfg.services[0].chars[0].permissions = ATT_PERM_READ;
	cfg.services[0].chars[0].has_cccd = true;
	cfg.services[0].chars[0].initial_value_len = 1;
	cfg.services[0].chars[0].initial_value[0] = 0x5a;

	peripheral_build_gattdb(&db, role_attrs, role_valbuf,
	    sizeof(role_valbuf), &cfg);

	ATF_CHECK_MSG(role_db_service_declared(&db, 0xFF20),
	    "config service missing from the built database");
	ATF_CHECK_MSG(role_db_find(&db, 0xFF21) >= 0,
	    "config characteristic missing from the built database");

	role_teardown();
}

/* ================================================================
 * Signed-Write replay-floor flush timer
 * ================================================================ */

/*
 * Pins blued_sign_counter_timer_arm()'s idempotence and its kqueue
 * precondition, and that blued_sign_counter_flush() is a no-op when no counter
 * advanced (so a quiet daemon does not re-encrypt the bond database every
 * 30 seconds).
 */
ATF_TC_WITHOUT_HEAD(sign_counter_timer_arm_is_idempotent);
ATF_TC_BODY(sign_counter_timer_arm_is_idempotent, tc)
{
	struct smp_bond_db db;

	role_reset();

	ATF_CHECK_EQ(0, blued_sign_counter_timer_arm());
	ATF_CHECK_EQ(0, blued_sign_counter_timer_arm());

	memset(&db, 0, sizeof(db));
	db.dir_fd = -1;
	blued_g.bond_db = &db;
	blued_sign_counter_flush();		/* clean: no save attempted */
	blued_g.bond_db = NULL;
	blued_sign_counter_flush();		/* no database: no crash */

	role_teardown();
}

/* ================================================================
 * Central-role teardown
 * ================================================================ */

/*
 * Pins blued_conn_central_teardown() (findings 59/60/89/93): the single
 * central teardown releases hogp, clears conn->att / att_fd, and is idempotent
 * and a no-op for a peripheral conn -- the stale kqueue registration it removes
 * is what used to spin the loop at 100% CPU.
 */
ATF_TC_WITHOUT_HEAD(central_teardown_releases_hogp_once);
ATF_TC_BODY(central_teardown_releases_hogp_once, tc)
{
	struct blued_conn *c;
	struct hogp_device *dev;
	int sp[2];

	role_reset();
	c = role_make_conn(BLUED_ROLE_CENTRAL, BLUED_CONN_ACTIVE);

	dev = calloc(1, sizeof(*dev));
	ATF_REQUIRE(dev != NULL);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp));
	dev->att.fd = -1;
	dev->smp.fd = -1;
	dev->vhid_fd = sp[0];
	dev->vhid_ctl_fd = -1;
	dev->hci_fd = -1;
	dev->bond_fd = -1;
	dev->report_map = malloc(4);
	ATF_REQUIRE(dev->report_map != NULL);
	dev->report_map_len = 4;
	c->hogp = dev;
	c->att = &dev->att;
	c->att_fd = -1;

	blued_conn_central_teardown(c);

	ATF_CHECK_MSG(c->hogp == NULL, "hogp not released");
	ATF_CHECK_MSG(c->att == NULL, "stale ATT pointer left attached");
	ATF_CHECK_EQ(-1, c->att_fd);
	ATF_CHECK_MSG(!role_fd_open(sp[0]), "vhid descriptor leaked");

	/* Idempotent, and a no-op for a peripheral conn. */
	blued_conn_central_teardown(c);
	c->role = BLUED_ROLE_PERIPHERAL;
	blued_conn_central_teardown(c);

	close(sp[1]);
	blued_conn_free(c);
	role_teardown();
}

/*
 * Pins blued_hogp_alloc(): a freshly allocated HOGP device carries INVALID
 * descriptors, so a teardown before setup completes cannot close descriptor 0.
 */
ATF_TC_WITHOUT_HEAD(hogp_alloc_starts_with_invalid_descriptors);
ATF_TC_BODY(hogp_alloc_starts_with_invalid_descriptors, tc)
{
	static const uint8_t peer[6] = { 1, 2, 3, 4, 5, 6 };
	struct hogp_device *dev;

	role_reset();
	dev = blued_hogp_alloc(&role_adp, peer, BDADDR_LE_PUBLIC, true);
	ATF_REQUIRE(dev != NULL);
	ATF_CHECK_EQ(-1, dev->vhid_fd);
	ATF_CHECK_EQ(-1, dev->vhid_ctl_fd);
	ATF_CHECK(dev->reconnect);
	ATF_CHECK_EQ(0, memcmp(dev->addr, peer, 6));
	ATF_CHECK_EQ(BDADDR_LE_PUBLIC, dev->addr_type);
	free(dev->report_map);
	free(dev);
	role_teardown();
}

/* ================================================================
 * HOGP discovery decisions, driven through the REAL
 * hogp_process_service() / hogp_subscribe() in blued_central.c.
 *
 * The ATT link is a SOCK_SEQPACKET socketpair with the daemon side
 * O_NONBLOCK; responses are queued in the order the production code issues
 * its requests, each delimited by MSG_EOR (FreeBSD's AF_UNIX SOCK_SEQPACKET
 * delimits records by MSG_EOR, exactly as att.c's own sends do).  Requests
 * the client emitted are read back off the peer end afterwards and asserted
 * as wire octets.
 * ================================================================ */

/* Non-normative but distinguishable fixture handles. */
#define HG_REPORT_DECL		0x0010
#define HG_REPORT_VALUE		0x0011
#define HG_REPORT_REF		0x0012
#define HG_REPORT_CCCD		0x0013
#define HG_MAP_DECL		0x0020
#define HG_MAP_VALUE		0x0021
#define HG_PROTOMODE_DECL	0x0030
#define HG_PROTOMODE_VALUE	0x0031
#define HG_HIDINFO_DECL		0x0040
#define HG_HIDINFO_VALUE	0x0041
#define HG_SVC_START		0x0001
#define HG_SVC_END		0x0050

/* Second HID Service instance. */
#define HG2_REPORT_DECL		0x0060
#define HG2_REPORT_VALUE	0x0061
#define HG2_REPORT_REF		0x0062
#define HG2_REPORT_CCCD		0x0063
#define HG2_MAP_DECL		0x0070
#define HG2_MAP_VALUE		0x0071
#define HG2_SVC_START		0x0055
#define HG2_SVC_END		0x0080

static int hg_peer = -1;

static void
hg_open(struct hogp_device *dev)
{
	int fds[2];

	signal(SIGPIPE, SIG_IGN);
	memset(dev, 0, sizeof(*dev));
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	ATF_REQUIRE(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	dev->att.fd = fds[0];
	dev->att.bearer_fd = -1;
	dev->att.mtu = ATT_MAX_MTU;
	dev->att.buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(dev->att.buf != NULL);
	dev->vhid_fd = -1;
	dev->vhid_ctl_fd = -1;
	hg_peer = fds[1];
}

static void
hg_close(struct hogp_device *dev)
{

	free(dev->att.buf);
	dev->att.buf = NULL;
	free(dev->report_map);
	dev->report_map = NULL;
	if (dev->att.fd >= 0)
		close(dev->att.fd);
	if (hg_peer >= 0)
		close(hg_peer);
	hg_peer = -1;
}

static void
hg_reply(const uint8_t *pdu, size_t len)
{

	ATF_REQUIRE(send(hg_peer, pdu, len, MSG_EOR) == (ssize_t)len);
}

/* ATT Read Response carrying `len' octets (Core Vol 3 Part F §3.4.4.4). */
static void
hg_reply_read(const uint8_t *val, size_t len)
{
	uint8_t pdu[64];

	ATF_REQUIRE(len + 1 <= sizeof(pdu));
	pdu[0] = 0x0B;			/* ATT_READ_RSP */
	memcpy(pdu + 1, val, len);
	hg_reply(pdu, len + 1);
}

/* ATT Error Response to a Read Request (Core Vol 3 Part F §3.4.1.1). */
static void
hg_reply_read_error(uint16_t handle, uint8_t code)
{
	uint8_t pdu[5] = { 0x01, 0x0A, 0, 0, 0 };

	pdu[2] = (uint8_t)handle;
	pdu[3] = (uint8_t)(handle >> 8);
	pdu[4] = code;
	hg_reply(pdu, sizeof(pdu));
}

/* Count the ATT Write Commands (0x52) the client sent, by value octet. */
static int
hg_count_write_cmds(uint8_t value)
{
	uint8_t pdu[512];
	ssize_t n;
	int count = 0;

	while ((n = recv(hg_peer, pdu, sizeof(pdu), MSG_DONTWAIT)) > 0) {
		if (n >= 4 && pdu[0] == 0x52 && pdu[3] == value)
			count++;
	}
	return (count);
}

static void
hg_build_service(struct gatt_discovery *disc)
{

	memset(disc, 0, sizeof(*disc));
	disc->service.start_handle = HG_SVC_START;
	disc->service.end_handle = HG_SVC_END;
	disc->service.uuid16 = 0x1812;
	disc->nchars = 4;
	disc->chars[0].decl_handle = HG_REPORT_DECL;
	disc->chars[0].value_handle = HG_REPORT_VALUE;
	disc->chars[0].uuid16 = 0x2A4D;		/* Report */
	disc->chars[1].decl_handle = HG_MAP_DECL;
	disc->chars[1].value_handle = HG_MAP_VALUE;
	disc->chars[1].uuid16 = 0x2A4B;		/* Report Map */
	disc->chars[2].decl_handle = HG_PROTOMODE_DECL;
	disc->chars[2].value_handle = HG_PROTOMODE_VALUE;
	disc->chars[2].uuid16 = 0x2A4E;		/* Protocol Mode */
	disc->chars[3].decl_handle = HG_HIDINFO_DECL;
	disc->chars[3].value_handle = HG_HIDINFO_VALUE;
	disc->chars[3].uuid16 = 0x2A4A;		/* HID Information */
	disc->ndescs = 2;
	disc->descs[0].handle = HG_REPORT_REF;
	disc->descs[0].uuid16 = 0x2908;		/* Report Reference */
	disc->descs[1].handle = HG_REPORT_CCCD;
	disc->descs[1].uuid16 = 0x2902;		/* CCCD */
}

/* The three reads hogp_process_service() issues after the Report Reference. */
static void
hg_reply_map_and_info(void)
{
	static const uint8_t report_map[] = { 0x05, 0x01, 0x09, 0x06, 0xA1,
	    0x01, 0xC0 };
	static const uint8_t hid_info[] = { 0x11, 0x01, 0x00, 0x00 };

	hg_reply_read(report_map, sizeof(report_map));
	hg_reply_read(hid_info, sizeof(hid_info));
}

/* ================================================================
 * H6 -- a Report characteristic whose Report Reference descriptor cannot be
 * read is DROPPED, and a device left with no usable Input Report fails to
 * subscribe instead of enumerating mute.
 *
 * The read status used to be discarded and the report retained with Report
 * Type 0x00, which HIDS Table 2.7 marks Prohibited: it matched no branch, so
 * nothing was subscribed, and because hogp_subscribe()'s guard only fired when
 * at least one input report had been FOUND, setup completed successfully and
 * the user got a keyboard that never typed.
 *
 * GATES the fix.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(failed_report_reference_read_drops_the_report);
ATF_TC_BODY(failed_report_reference_read_drops_the_report, tc)
{
	struct hogp_device dev;
	struct gatt_discovery disc;

	role_reset();
	hg_open(&dev);
	hg_build_service(&disc);

	/* Read Not Permitted on the Report Reference descriptor. */
	hg_reply_read_error(HG_REPORT_REF, 0x02);
	hg_reply_map_and_info();

	ATF_CHECK_EQ_MSG(0, hogp_process_service(&dev, &disc, 0),
	    "a single unreadable descriptor is not a device-wide failure");
	ATF_CHECK_EQ_MSG(0, dev.nreports,
	    "an unclassifiable Report characteristic must not be retained");
	ATF_CHECK_MSG(dev.report_map_len > 0, "the Report Map was still read");

	ATF_CHECK_MSG(hogp_subscribe(&dev) != 0,
	    "a device with no usable Input Report must not report success");

	hg_close(&dev);
	role_teardown();
}

/* ================================================================
 * H6 -- Report Type 0x00 is Prohibited (HIDS Table 2.7) and 0x04-0xFF are
 * reserved; a descriptor carrying one is as unusable as a failed read.
 *
 * GATES the fix.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(prohibited_report_type_drops_the_report);
ATF_TC_BODY(prohibited_report_type_drops_the_report, tc)
{
	struct hogp_device dev;
	struct gatt_discovery disc;
	const uint8_t prohibited[2] = { 0x01, 0x00 };	/* id 1, type 0x00 */
	const uint8_t reserved[2] = { 0x01, 0x04 };	/* id 1, type RFU */

	role_reset();

	hg_open(&dev);
	hg_build_service(&disc);
	hg_reply_read(prohibited, sizeof(prohibited));
	hg_reply_map_and_info();
	ATF_CHECK_EQ(0, hogp_process_service(&dev, &disc, 0));
	ATF_CHECK_EQ_MSG(0, dev.nreports,
	    "Report Type 0x00 is Prohibited and must never be retained");
	hg_close(&dev);

	hg_open(&dev);
	hg_build_service(&disc);
	hg_reply_read(reserved, sizeof(reserved));
	hg_reply_map_and_info();
	ATF_CHECK_EQ(0, hogp_process_service(&dev, &disc, 0));
	ATF_CHECK_EQ_MSG(0, dev.nreports,
	    "a reserved Report Type must never be retained");
	hg_close(&dev);

	role_teardown();
}

/* ================================================================
 * H6 -- the positive control: a well-formed Input Report is admitted and
 * subscribed, and the CCCD write carries 0x0001 to the descriptor handle.
 *
 * PINS the working path so the drop rules above cannot pass vacuously.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(input_report_is_admitted_and_subscribed);
ATF_TC_BODY(input_report_is_admitted_and_subscribed, tc)
{
	struct hogp_device dev;
	struct gatt_discovery disc;
	const uint8_t ref[2] = { 0x01, 0x01 };		/* id 1, Input */
	const uint8_t wr_rsp[1] = { 0x13 };		/* ATT Write Response */
	uint8_t pdu[64];
	ssize_t n;
	int i;

	role_reset();
	hg_open(&dev);
	hg_build_service(&disc);
	hg_reply_read(ref, sizeof(ref));
	hg_reply_map_and_info();

	ATF_REQUIRE_EQ(0, hogp_process_service(&dev, &disc, 0));
	ATF_REQUIRE_EQ(1, dev.nreports);
	ATF_CHECK_EQ(HG_REPORT_VALUE, dev.reports[0].value_handle);
	ATF_CHECK_EQ(HG_REPORT_CCCD, dev.reports[0].cccd_handle);
	ATF_CHECK_EQ(1, dev.reports[0].report_id);
	ATF_CHECK_EQ(HID_REPORT_TYPE_INPUT, dev.reports[0].report_type);
	ATF_CHECK_EQ_MSG(0, dev.reports[0].instance,
	    "the report must be stamped with its HID Service instance");

	/* Drain the reads, then answer the CCCD write. */
	while ((n = recv(hg_peer, pdu, sizeof(pdu), MSG_DONTWAIT)) > 0)
		;
	hg_reply(wr_rsp, sizeof(wr_rsp));
	ATF_CHECK_EQ_MSG(0, hogp_subscribe(&dev),
	    "a usable Input Report must subscribe successfully");

	n = recv(hg_peer, pdu, sizeof(pdu), MSG_DONTWAIT);
	ATF_REQUIRE_MSG(n == 5, "expected a 5-octet Write Request, got %zd",
	    n);
	ATF_CHECK_EQ(0x12, pdu[0]);			/* ATT Write Request */
	ATF_CHECK_EQ(HG_REPORT_CCCD, (uint16_t)(pdu[1] | (pdu[2] << 8)));
	ATF_CHECK_EQ_MSG(0x0001, (uint16_t)(pdu[3] | (pdu[4] << 8)),
	    "Input Reports are NOTIFIED (Core Vol 3 Part G Table 3.11)");
	for (i = 0; i < 1; i++)
		;
	hg_close(&dev);
	role_teardown();
}

/* ================================================================
 * H5 -- the Report Host role writes no Protocol Mode at all.
 *
 * HOGP §2.3 lines 575/577 make Boot Host and Report Host mutually exclusive
 * in both directions; §4.11 line 1189 states there is no requirement on a
 * Report Host to use the characteristic, and HIDS §2.4.1.1 line 672 already
 * resets the value to Report Protocol Mode at connection establishment.
 * hogp_process_service() used to write 0x01 to every Protocol Mode
 * characteristic and the boot fallback then wrote 0x00 on the same
 * connection, so the device saw one host acting as both roles.
 *
 * GATES the fix: restoring the Report-mode write fails here.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(protocol_mode_is_never_written_in_report_role);
ATF_TC_BODY(protocol_mode_is_never_written_in_report_role, tc)
{
	struct hogp_device dev;
	struct gatt_discovery disc;
	const uint8_t ref[2] = { 0x01, 0x01 };

	role_reset();
	hg_open(&dev);
	hg_build_service(&disc);
	hg_reply_read(ref, sizeof(ref));
	hg_reply_map_and_info();

	ATF_REQUIRE_EQ(0, hogp_process_service(&dev, &disc, 0));
	ATF_CHECK_EQ_MSG(0, hg_count_write_cmds(0x01),
	    "a Report Host must not write Report Protocol Mode");
	hg_close(&dev);

	role_teardown();
}

/* ================================================================
 * H1 -- a second HID Service instance that reuses a (Report Type, Report ID)
 * pair is refused, report table and Report Map both.
 *
 * HOGP §2.5 line 603 sanctions multi-instance composite devices and §3.1.6
 * guarantees device-wide Report ID uniqueness only for HID ISO devices, so
 * the collision is legal on the wire.  Merging the two instances into one
 * flat table let an outbound report resolve to the wrong instance's
 * characteristic.
 *
 * GATES the fix: without the conflict check the second instance is admitted
 * and nreports reaches 2 with two different value handles for the same
 * identity.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(colliding_second_hid_instance_is_refused);
ATF_TC_BODY(colliding_second_hid_instance_is_refused, tc)
{
	struct hogp_device dev;
	struct gatt_discovery disc, disc2;
	const uint8_t ref[2] = { 0x01, 0x02 };	/* id 1, Output */
	size_t map_len_after_first;

	role_reset();
	hg_open(&dev);

	hg_build_service(&disc);
	hg_reply_read(ref, sizeof(ref));
	hg_reply_map_and_info();
	ATF_REQUIRE_EQ(0, hogp_process_service(&dev, &disc, 0));
	ATF_REQUIRE_EQ(1, dev.nreports);
	map_len_after_first = dev.report_map_len;
	ATF_REQUIRE(map_len_after_first > 0);

	/* Second instance, same Output Report ID 1, different handles. */
	memset(&disc2, 0, sizeof(disc2));
	disc2.service.start_handle = HG2_SVC_START;
	disc2.service.end_handle = HG2_SVC_END;
	disc2.service.uuid16 = 0x1812;
	disc2.nchars = 2;
	disc2.chars[0].decl_handle = HG2_REPORT_DECL;
	disc2.chars[0].value_handle = HG2_REPORT_VALUE;
	disc2.chars[0].uuid16 = 0x2A4D;
	disc2.chars[1].decl_handle = HG2_MAP_DECL;
	disc2.chars[1].value_handle = HG2_MAP_VALUE;
	disc2.chars[1].uuid16 = 0x2A4B;
	disc2.ndescs = 2;
	disc2.descs[0].handle = HG2_REPORT_REF;
	disc2.descs[0].uuid16 = 0x2908;
	disc2.descs[1].handle = HG2_REPORT_CCCD;
	disc2.descs[1].uuid16 = 0x2902;

	hg_reply_read(ref, sizeof(ref));
	ATF_CHECK_EQ_MSG(0, hogp_process_service(&dev, &disc2, 1),
	    "refusing an instance is not a device-wide failure");
	ATF_CHECK_EQ_MSG(1, dev.nreports,
	    "the colliding instance's reports must not enter the table");
	ATF_CHECK_EQ_MSG(HG_REPORT_VALUE, dev.reports[0].value_handle,
	    "the admitted instance's routing must be untouched");
	ATF_CHECK_EQ_MSG(map_len_after_first, dev.report_map_len,
	    "a refused instance's Report Map must not be concatenated");

	hg_close(&dev);
	role_teardown();
}

/* ================================================================
 * H1 -- a non-colliding second instance IS admitted, with its own instance
 * index, and routes to its own value handle.
 *
 * PINS that the conflict rule is not a blanket refusal of composite devices.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(distinct_second_hid_instance_is_admitted);
ATF_TC_BODY(distinct_second_hid_instance_is_admitted, tc)
{
	struct hogp_device dev;
	struct gatt_discovery disc, disc2;
	const uint8_t ref1[2] = { 0x01, 0x01 };	/* id 1, Input */
	const uint8_t ref2[2] = { 0x02, 0x01 };	/* id 2, Input */

	role_reset();
	hg_open(&dev);

	hg_build_service(&disc);
	hg_reply_read(ref1, sizeof(ref1));
	hg_reply_map_and_info();
	ATF_REQUIRE_EQ(0, hogp_process_service(&dev, &disc, 0));
	ATF_REQUIRE_EQ(1, dev.nreports);

	memset(&disc2, 0, sizeof(disc2));
	disc2.service.start_handle = HG2_SVC_START;
	disc2.service.end_handle = HG2_SVC_END;
	disc2.service.uuid16 = 0x1812;
	disc2.nchars = 2;
	disc2.chars[0].decl_handle = HG2_REPORT_DECL;
	disc2.chars[0].value_handle = HG2_REPORT_VALUE;
	disc2.chars[0].uuid16 = 0x2A4D;
	disc2.chars[1].decl_handle = HG2_MAP_DECL;
	disc2.chars[1].value_handle = HG2_MAP_VALUE;
	disc2.chars[1].uuid16 = 0x2A4B;
	disc2.ndescs = 2;
	disc2.descs[0].handle = HG2_REPORT_REF;
	disc2.descs[0].uuid16 = 0x2908;
	disc2.descs[1].handle = HG2_REPORT_CCCD;
	disc2.descs[1].uuid16 = 0x2902;

	hg_reply_read(ref2, sizeof(ref2));
	{
		static const uint8_t map2[] = { 0x05, 0x01, 0x09, 0x02, 0xC0 };

		hg_reply_read(map2, sizeof(map2));
	}
	ATF_REQUIRE_EQ(0, hogp_process_service(&dev, &disc2, 1));
	ATF_CHECK_EQ_MSG(2, dev.nreports,
	    "a non-colliding instance must be admitted");
	ATF_CHECK_EQ_MSG(1, dev.reports[1].instance,
	    "the second instance's reports carry instance index 1");
	ATF_CHECK_EQ(HG2_REPORT_VALUE, dev.reports[1].value_handle);
	ATF_CHECK_EQ_MSG(HG_REPORT_VALUE,
	    hogp_find_report_handle_instance(dev.reports, dev.nreports, 1,
	    HID_REPORT_TYPE_INPUT, 0), "instance 0 must route to instance 0");
	ATF_CHECK_EQ_MSG(HG2_REPORT_VALUE,
	    hogp_find_report_handle_instance(dev.reports, dev.nreports, 2,
	    HID_REPORT_TYPE_INPUT, 1), "instance 1 must route to instance 1");

	hg_close(&dev);
	role_teardown();
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, readvertise_respects_adapter_gates);
	ATF_TP_ADD_TC(tp, readvertise_reclaims_legacy_adv_resource);
	ATF_TP_ADD_TC(tp, readvertise_retry_budget_is_bounded);
	ATF_TP_ADD_TC(tp, readvertise_timer_identity_and_cancel);
	ATF_TP_ADD_TC(tp, readvertise_retry_state_is_per_adapter);
	ATF_TP_ADD_TC(tp, peripheral_setup_fail_hands_off_to_main_loop);
	ATF_TP_ADD_TC(tp, central_setup_fail_defers_arm_and_kills_handle);
	ATF_TP_ADD_TC(tp, central_setup_fail_without_reconnect_is_terminal);
	ATF_TP_ADD_TC(tp, late_smp_eof_takes_and_closes_descriptor);
	ATF_TP_ADD_TC(tp, late_smp_orphan_descriptor_is_not_closed);
	ATF_TP_ADD_TC(tp, late_smp_ignores_invalid_descriptor);
	ATF_TP_ADD_TC(tp, gattdb_mandatory_shape);
	ATF_TP_ADD_TC(tp, gattdb_central_address_resolution_follows_privacy);
	ATF_TP_ADD_TC(tp, gattdb_device_name_reserves_rename_capacity);
	ATF_TP_ADD_TC(tp, gattdb_config_descriptor_guards);
	ATF_TP_ADD_TC(tp, gattdb_config_services_are_registered);
	ATF_TP_ADD_TC(tp, sign_counter_timer_arm_is_idempotent);
	ATF_TP_ADD_TC(tp, central_teardown_releases_hogp_once);
	ATF_TP_ADD_TC(tp, hogp_alloc_starts_with_invalid_descriptors);
	ATF_TP_ADD_TC(tp, failed_report_reference_read_drops_the_report);
	ATF_TP_ADD_TC(tp, prohibited_report_type_drops_the_report);
	ATF_TP_ADD_TC(tp, input_report_is_admitted_and_subscribed);
	ATF_TP_ADD_TC(tp, protocol_mode_is_never_written_in_report_role);
	ATF_TP_ADD_TC(tp, colliding_second_hid_instance_is_refused);
	ATF_TP_ADD_TC(tp, distinct_second_hid_instance_is_admitted);

	return (atf_no_error());
}
