/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Daemon-wiring test harness: the blued.c seam.
 *
 * blued_event.c, blued_peripheral.c and blued_central.c hold the event loop,
 * the connection lifecycle, the role setup threads and the defer ring.  Until
 * now no test program linked ANY of them, because every one of the three pulls
 * in blued.c -- the 5700-line daemon main() translation unit, which opens
 * controllers, daemonises, enters Capsicum and installs signal handlers.
 *
 * Measurement (nm(1) over the production objects): with EVERY other production
 * translation unit linked, the three role/event files plus their transitive
 * dependencies reference exactly 62 symbols that only blued.c defines --
 * 28 objects (the kqueue udata tags, blued_g, blued_cfg, the timer-id counter,
 * the local IRK, ...) and 34 functions (adapter power/privacy/discoverable,
 * the resolving-list and accept-list shadows, the RPA rotation retry, the SMP
 * user-interaction callbacks, ...).  Everything else resolves inside the
 * production object set or against libc/libcrypto/libucl/libbluetooth.
 *
 * 62 is a small, mechanical stub surface, so this harness takes the "link the
 * real file" route (a) rather than extracting seams: the tests drive the REAL
 * blued_event.c/blued_peripheral.c/blued_central.c objects, and only this file
 * stands in for blued.c.
 *
 * Every stub is observable: it records its calls in a counter or a snapshot so
 * a test can assert on the daemon-side effect a production path requested.
 * blued_stub_reset() clears the record between cases.
 */

#include <sys/types.h>
#include <sys/event.h>

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include "att.h"
#include "att_server.h"
#include "blued.h"
#include "blued_internal.h"
#include "blued_persist.h"
#include "blued_daemon_stub.h"
#include "config.h"
#include "conn.h"
#include "smp.h"

/* ---- blued.c objects ------------------------------------------------- */

struct blued_ctx blued_g;
struct blued_config blued_cfg;
atomic_int blued_verbose;
int blued_daemonized;
atomic_bool blued_shutting_down;
const char *blued_peripheral_name = "5BSD-blued";
volatile sig_atomic_t running = 1;
_Atomic uintptr_t blued_next_timer_id = 1000;
uintptr_t blued_rpa_retry_timer;
int blued_reconnect_max_delay = 60;
uint8_t blued_local_irk[16];
bool blued_has_local_irk;
atomic_bool blued_pairable = true;
struct att_db periph_gatt_db;

const int _blued_kq_acquire_tag;
const int _blued_kq_ctl_accept_retry_tag;
const int _blued_kq_ctl_tag;
const int _blued_kq_idle_timeout_tag;
const int _blued_kq_ind_timeout_tag;
const int _blued_kq_mesh_legacy_stop_tag;
const int _blued_kq_readvertise_tag;
const int _blued_kq_rpa_retry_tag;
const int _blued_kq_rpa_timer_tag;
const int _blued_kq_setup_pipe_tag;
const int _blued_kq_signctr_flush_tag;
const int _blued_kq_smp_tag;
const int _blued_kq_supervisor_tag;
const int _blued_kq_plane_listen_tag;
const int _blued_kq_reclaim_timer_tag;
const int _blued_kq_vhid_output_tag;

/* ---- observation record ---------------------------------------------- */

struct blued_stub_record blued_stub;

void
blued_stub_reset(void)
{

	memset(&blued_stub, 0, sizeof(blued_stub));
	blued_stub.rotate_rpa_rc = 0;
	blued_stub.rpa_retry_arm_rc = 0;
	blued_stub.discoverable_timer_match = 0;
}

/* ---- blued.c functions ----------------------------------------------- */

int
blued_adapter_rotate_rpa(struct blued_adapter *adp, const uint8_t rpa[6])
{

	if (blued_stub.rotate_rpa_calls < BLUED_STUB_MAX_ROTATE) {
		blued_stub.rotate_rpa_adapters[blued_stub.rotate_rpa_calls] =
		    adp;
		memcpy(blued_stub.rotate_rpa_addrs[blued_stub.rotate_rpa_calls],
		    rpa, 6);
	}
	blued_stub.rotate_rpa_calls++;
	return (blued_stub.rotate_rpa_rc);
}

int
blued_rpa_retry_arm(void)
{

	blued_stub.rpa_retry_arm_calls++;
	return (blued_stub.rpa_retry_arm_rc);
}

void
blued_rpa_retry_cancel(void)
{

	blued_stub.rpa_retry_cancel_calls++;
	blued_rpa_retry_timer = 0;
}

bool
blued_discoverable_timer_fired(uintptr_t timer_id)
{

	blued_stub.discoverable_timer_calls++;
	blued_stub.discoverable_timer_last = timer_id;
	return (blued_stub.discoverable_timer_match != 0 &&
	    timer_id == blued_stub.discoverable_timer_match);
}

void
blued_reload_config(void)
{

	blued_stub.reload_config_calls++;
}

int
blued_adapter_set_power(struct blued_adapter *adp __unused, bool on)
{

	blued_stub.set_power_calls++;
	blued_stub.set_power_last_on = on;
	return (0);
}

int
blued_adapter_set_privacy(struct blued_adapter *adp __unused, bool on)
{

	blued_stub.set_privacy_calls++;
	blued_stub.set_privacy_last_on = on;
	return (0);
}

int
blued_adapter_set_discoverable(struct blued_adapter *adp __unused,
    bool enable, bool limited __unused, unsigned int timeout_sec __unused)
{

	blued_stub.set_discoverable_calls++;
	blued_stub.set_discoverable_last_on = enable;
	return (0);
}

int
blued_adv_legacy_reclaim(struct blued_adapter *adp __unused,
    const uint8_t *adv_data __unused, uint8_t adv_len __unused,
    const uint8_t *scan_rsp __unused, uint8_t scan_rsp_len __unused)
{

	blued_stub.adv_legacy_reclaim_calls++;
	return (0);
}

int
blued_adv_set_privacy_prepare(struct blued_adapter *adp __unused,
    uint8_t handle __unused)
{

	return (0);
}

void
blued_primary_adv_cache(struct blued_adapter *adp __unused,
    bool scan_rsp __unused, const uint8_t *data __unused,
    uint8_t len __unused)
{
}

int
blued_ext_adv_set_track(struct blued_adapter *adp __unused,
    uint8_t handle __unused, uint16_t props __unused,
    uint32_t min_int __unused, uint32_t max_int __unused,
    uint8_t chan __unused, uint8_t own_addr __unused,
    uint8_t peer_type __unused, uint8_t filter __unused,
    uint8_t phy1 __unused, int8_t txpower __unused, uint8_t phy2 __unused,
    const uint8_t *peer __unused)
{

	return (0);
}

void
blued_ext_adv_set_enabled(struct blued_adapter *adp __unused,
    uint8_t handle __unused, bool on __unused)
{
}

void
blued_ext_adv_set_untrack(struct blued_adapter *adp __unused,
    uint8_t handle __unused)
{
}

bool
blued_ext_adv_set_used(const struct blued_adapter *adp __unused,
    uint8_t handle __unused)
{

	return (false);
}

void
blued_reslist_quiesce_begin(struct blued_adapter *adp __unused,
    struct blued_reslist_quiesce *q)
{

	if (q != NULL)
		memset(q, 0, sizeof(*q));
	blued_stub.reslist_quiesce_begin_calls++;
}

void
blued_reslist_quiesce_end(struct blued_adapter *adp __unused,
    struct blued_reslist_quiesce *q __unused)
{

	blued_stub.reslist_quiesce_end_calls++;
}

void
blued_reslist_restore_resolution(int hci_fd __unused,
    struct blued_adapter *adp __unused)
{
}

void
blued_reslist_sync_add(int hci_fd __unused, const struct smp_bond *bond __unused)
{

	blued_stub.reslist_sync_add_calls++;
}

void
blued_reslist_sync_remove(int hci_fd __unused, const uint8_t addr[6] __unused,
    uint8_t addr_type __unused)
{

	blued_stub.reslist_sync_remove_calls++;
}

void
blued_runtime_resolv_record(const uint8_t addr[6] __unused,
    uint8_t addr_type __unused, const uint8_t irk[16] __unused)
{
}

void
blued_runtime_resolv_forget(const uint8_t addr[6] __unused,
    uint8_t addr_type __unused)
{
}

void
blued_runtime_resolv_clear(void)
{
}

int
blued_acceptlist_record(const uint8_t addr[6] __unused,
    uint8_t addr_type __unused)
{

	return (1);
}

int
blued_acceptlist_forget(const uint8_t addr[6] __unused,
    uint8_t addr_type __unused)
{

	return (1);
}

void
blued_acceptlist_clear_all(void)
{
}

uint32_t
blued_acceptlist_snapshot(struct blued_persist_accept_entry *out __unused,
    uint32_t max __unused)
{

	return (0);
}

bool
blued_persist_gattcache_reuse(const uint8_t addr[6] __unused,
    uint8_t addr_type __unused, const uint8_t fresh_hash[16] __unused)
{

	return (false);
}

int
blued_set_device_name(const char *name __unused)
{

	return (0);
}

int
blued_set_rpa_timeout(int timeout_sec __unused)
{

	return (0);
}

int
blued_socket_broker_take(void)
{

	return (-1);
}

int
passkey_display(uint32_t *passkey __unused, bool display __unused,
    void *arg __unused)
{

	blued_stub.passkey_display_calls++;
	return (-1);
}

int
numcmp_confirm(uint32_t value __unused, void *arg __unused)
{

	blued_stub.numcmp_confirm_calls++;
	return (-1);
}

void
blued_keypress_notify(uint8_t type __unused, void *arg __unused)
{

	blued_stub.keypress_notify_calls++;
}
