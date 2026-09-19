/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * hci_emulator.h - transport-agnostic userspace HCI controller emulator.
 *
 * A "btdev" analogue for the FreeBSD/5BSD BLE stack: a controller state
 * machine that consumes typed HCI command packets and emits spec-correct
 * typed HCI event packets.  It has NO dependency on the kernel, netgraph,
 * or the blued daemon so it is unit-testable in isolation (the controller
 * emulator core is deliberately kept independent of any transport).  A
 * netgraph drv-hook transport can be layered on top later; the core speaks the
 * exact byte format seen on the controller-facing "drv" hook, that
 * transport is a straight pipe.
 *
 * Wire format (see sys/netgraph/bluetooth/hci/ng_hci_main.c
 * ng_hci_drv_rcvdata()): every packet is prefixed with a 1-byte
 * packet-type indicator.
 *   command = NG_HCI_CMD_PKT(0x01) | opcode(2,LE) | param_len(1) | params
 *   event   = NG_HCI_EVENT_PKT(0x04) | event_code(1) | param_len(1) | params
 *
 * The oracle for every byte emitted is the Bluetooth Core Spec Vol 4
 * Part E (HCI), NOT the daemon's behavior.  Struct layouts come from
 * sys/netgraph/bluetooth/include/ng_hci.h so the emulator is byte
 * compatible with the stack.
 */

#ifndef _HCI_EMULATOR_H_
#define _HCI_EMULATOR_H_

#include <stddef.h>
#include <stdint.h>

struct hci_emu;

/*
 * Output callback: invoked once for every emitted typed event packet
 * (0x04 | code | len | params).  pkt/len are owned by the emulator and
 * valid only for the duration of the call.
 */
typedef void (*hci_emu_out_fn)(void *ctx, const uint8_t *pkt, size_t len);

/*
 * Reusable controller capability profiles.  The default emulator is
 * feature-complete; tests that need an older or narrower controller can apply
 * one of these profiles and assert that feature reporting and command support
 * move together.
 */
enum hci_emu_profile {
	HCI_EMU_PROFILE_LEGACY = 0,
	HCI_EMU_PROFILE_EXT_ADV,
	HCI_EMU_PROFILE_PERIODIC,
	HCI_EMU_PROFILE_ISO,
	HCI_EMU_PROFILE_POWER_CONTROL,
	HCI_EMU_PROFILE_FULL
};

/* Lifecycle. */
struct hci_emu	*hci_emu_new(void);
void		 hci_emu_free(struct hci_emu *emu);
void		 hci_emu_set_output(struct hci_emu *emu, hci_emu_out_fn fn,
		     void *ctx);

/*
 * Feed one typed command/ACL packet.  Drives the matching command
 * handler and emits the resulting event(s) via the output callback.
 */
void		 hci_emu_input(struct hci_emu *emu, const uint8_t *pkt,
		     size_t len);

/*
 * Increment 2: two-controller linking.  Join two emulators as a simulated
 * "air": while A advertises (connectable) and B scans, B emits an LE
 * Advertising Report carrying A's address/adv-data; an LE_Create_Connection
 * from one to the other establishes a connection on both; ACL data fed to
 * one side is delivered out the peer's output callback.  The link is a
 * physical property and is symmetric.  Passing NULL unlinks.
 */
void		 hci_emu_link(struct hci_emu *a, struct hci_emu *b);

/* Observe the connection table (so tests can confirm setup/teardown). */
int		 hci_emu_get_conn_count(const struct hci_emu *emu);
int		 hci_emu_get_conn_handle(const struct hci_emu *emu, int idx,
		     uint16_t *handle_out);

/*
 * Increment 4: observe the ISO (CIS/BIS) stream table.  hci_emu_get_iso_path_open
 * returns a bitmask (0x01 = Host->Controller input path open, 0x02 =
 * Controller->Host output path open) for the given stream handle, or -1 if no
 * such stream exists.  See Vol 4 Part E §7.8.97-.109 / §7.7.65.25-.30.
 */
int		 hci_emu_get_iso_count(const struct hci_emu *emu);
int		 hci_emu_get_iso_handle(const struct hci_emu *emu, int idx,
		     uint16_t *handle_out);
int		 hci_emu_get_iso_path_open(const struct hci_emu *emu,
		     uint16_t handle);

/* -----------------------------------------------------------------
 * Deterministic-state setters (so tests can pin controller identity).
 * ----------------------------------------------------------------- */
void	hci_emu_set_bd_addr(struct hci_emu *emu, const uint8_t bd_addr[6]);
void	hci_emu_set_local_version(struct hci_emu *emu, uint8_t hci_version,
	    uint16_t hci_revision, uint8_t lmp_version, uint16_t manufacturer,
	    uint16_t lmp_subversion);
void	hci_emu_set_buffer_size(struct hci_emu *emu, uint16_t acl_size,
	    uint8_t sco_size, uint16_t num_acl, uint16_t num_sco);
void	hci_emu_set_le_buffer_size(struct hci_emu *emu, uint16_t le_acl_len,
	    uint8_t le_acl_num, uint16_t iso_len, uint8_t iso_num);
void	hci_emu_set_lmp_features(struct hci_emu *emu, const uint8_t feats[8]);
void	hci_emu_set_le_features(struct hci_emu *emu, const uint8_t feats[8]);
void	hci_emu_set_supported_commands(struct hci_emu *emu,
	    const uint8_t cmds[64]);
void	hci_emu_set_num_adv_sets(struct hci_emu *emu, uint8_t n);
int	hci_emu_apply_profile(struct hci_emu *emu, enum hci_emu_profile profile);

/* -----------------------------------------------------------------
 * State getters (so tests can observe the effect of Set_* commands).
 * ----------------------------------------------------------------- */
int		hci_emu_get_adv_enable(const struct hci_emu *emu);
int		hci_emu_get_scan_enable(const struct hci_emu *emu);
int		hci_emu_get_periodic_adv_enable(const struct hci_emu *emu);
int		hci_emu_get_addr_resolution_enable(const struct hci_emu *emu);
void		hci_emu_get_random_addr(const struct hci_emu *emu,
		    uint8_t out[6]);
int		hci_emu_get_resolving_list_count(const struct hci_emu *emu);
uint64_t	hci_emu_get_event_mask(const struct hci_emu *emu);
uint64_t	hci_emu_get_le_event_mask(const struct hci_emu *emu);

/* -----------------------------------------------------------------
 * Asynchronous event injection (build the typed event and emit it).
 * ----------------------------------------------------------------- */

/* LE Meta (0x3E) / LE Connection Complete (0x01), Vol 4 Part E §7.7.65.1. */
void	hci_emu_inject_le_connection_complete(struct hci_emu *emu,
	    uint8_t status, uint16_t handle, uint8_t role,
	    uint8_t peer_addr_type, const uint8_t peer_addr[6],
	    uint16_t conn_interval, uint16_t conn_latency,
	    uint16_t supervision_timeout, uint8_t central_clock_accuracy);

/* LE Meta (0x3E) / LE Advertising Report (0x02), Vol 4 Part E §7.7.65.2. */
void	hci_emu_inject_le_adv_report(struct hci_emu *emu, uint8_t evt_type,
	    uint8_t addr_type, const uint8_t addr[6], const uint8_t *ad,
	    uint8_t adlen, int8_t rssi);

/* LE periodic-advertising observer events (Core 5.0, §7.7.65.14-.16). */
void	hci_emu_inject_periodic_sync_established(struct hci_emu *emu,
	    uint8_t status, uint16_t sync_handle, uint8_t sid, uint8_t addr_type,
	    const uint8_t addr[6], uint8_t phy, uint16_t interval);
void	hci_emu_inject_periodic_adv_report(struct hci_emu *emu,
	    uint16_t sync_handle, int8_t tx_power, int8_t rssi, uint8_t cte_type,
	    uint8_t data_status, const uint8_t *data, uint8_t data_len);
void	hci_emu_inject_periodic_sync_lost(struct hci_emu *emu,
	    uint16_t sync_handle);

/* Disconnection Complete (0x05), Vol 4 Part E §7.7.5. */
void	hci_emu_inject_disconnection_complete(struct hci_emu *emu,
	    uint16_t handle, uint8_t reason);

/* Generic: build 0x04 | evt_code | plen | params and emit. */
void	hci_emu_inject_event(struct hci_emu *emu, uint8_t evt_code,
	    const uint8_t *params, uint8_t plen);

/* -----------------------------------------------------------------
 * Fault injection (btdev-hook analogue).  Force a given command opcode
 * to complete with a chosen error status.  hci_emu_clear_forced_status()
 * (or force_status with opcode 0x0000) removes the override(s).
 * ----------------------------------------------------------------- */
void	hci_emu_force_status(struct hci_emu *emu, uint16_t opcode,
	    uint8_t status);
void	hci_emu_clear_forced_status(struct hci_emu *emu);

/* -----------------------------------------------------------------
 * Increment 3: virtual clock + deterministic timer queue.
 *
 * hci_emu_set_clock() pins the controller's notion of "now" (absolute
 * nanoseconds) without firing anything.  hci_emu_advance() moves the
 * clock forward by dt and fires every timer whose deadline is reached,
 * in deadline order, with NO dependence on wall-clock time.  This is the
 * seam that drives the connection supervision timeout (and future
 * SMP/L2CAP timeouts).
 * ----------------------------------------------------------------- */
void		hci_emu_set_clock(struct hci_emu *emu, uint64_t ns);
void		hci_emu_advance(struct hci_emu *emu, uint64_t ns);
uint64_t	hci_emu_get_clock(const struct hci_emu *emu);

/* -----------------------------------------------------------------
 * Increment 3: LE encryption / LTK path (Vol 4 Part E §7.8.24-.26,
 * §7.7.8, §7.7.65.5).
 * ----------------------------------------------------------------- */

/*
 * Settable outcome for the success (LTK-reply) path: 0x00 (default)
 * yields Encryption_Change status success with encryption enabled; any
 * nonzero value yields that error status with encryption disabled.  The
 * negative-reply path always fails with PIN or Key Missing (0x06)
 * regardless of this setting.
 */
void	hci_emu_set_encryption_outcome(struct hci_emu *emu, uint8_t status);

/* Observe per-connection encryption state (1 = encrypted, 0 = not). */
int	hci_emu_get_conn_encrypted(const struct hci_emu *emu, uint16_t handle);

/* Encryption Change (event 0x08), Vol 4 Part E §7.7.8. */
void	hci_emu_inject_encryption_change(struct hci_emu *emu, uint16_t handle,
	    uint8_t status, uint8_t enabled);

/* -----------------------------------------------------------------
 * Increment 3: LE Power Control (Core 5.2), Vol 4 Part E §7.8.117-.121,
 * §7.7.65.32-.33.  A per-connection tx-power level and current path loss
 * are modeled; a test sets them and they drive the reporting events.
 * ----------------------------------------------------------------- */
void	hci_emu_set_conn_tx_power(struct hci_emu *emu, uint16_t handle,
	    int8_t tx_power);
void	hci_emu_set_conn_path_loss(struct hci_emu *emu, uint16_t handle,
	    uint8_t path_loss);

/* LE Transmit Power Reporting (LE Meta 0x3E / subevent 0x21), §7.7.65.33. */
void	hci_emu_inject_tx_power_report(struct hci_emu *emu, uint8_t status,
	    uint16_t handle, uint8_t reason, uint8_t phy, int8_t tx_power_level,
	    uint8_t tx_power_level_flag, int8_t delta);

/* LE Path Loss Threshold (LE Meta 0x3E / subevent 0x20), §7.7.65.32. */
void	hci_emu_inject_path_loss_threshold(struct hci_emu *emu, uint16_t handle,
	    uint8_t current_path_loss, uint8_t zone_entered);

#endif /* _HCI_EMULATOR_H_ */
