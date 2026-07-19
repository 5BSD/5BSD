/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for blued's HOGP (HID-over-GATT) host-side report
 * handling in blued_central.c.
 *
 * NOTE ON THE TARGET.  blued does NOT contain a HID Report *Descriptor*
 * item parser: the Report Map characteristic (UUID 0x2A4B) is read into an
 * opaque buffer and written verbatim to the kernel vhid device, which is
 * what actually parses the descriptor items (out of scope here -- it is the
 * kernel).  The host-side parsing that blued itself performs over data
 * derived from a paired HID device is:
 *   1. Report Reference classification (report_id / report_type per report).
 *   2. Output-report routing: given a raw report, decide whether a leading
 *      Report ID byte is present, strip it, match the Report ID to an
 *      Output Report characteristic and forward the payload via ATT Write
 *      Command.
 * (2) is hogp_handle_vhid_output() -- the exact production routine the
 * sibling ATF test hogp_report_map_test.c models with a local copy.  This
 * harness links the REAL function and drives it, so a bug in the real
 * routing / ID-strip / ATT PDU construction (not a copy) is caught.
 *
 * Fuzz layout:
 *   byte[0]              = number of classified reports N (clamped)
 *   next N*4 bytes       = per report: value_handle (2 LE), report_id (1),
 *                          report_type (1)  -- the attacker's Report
 *                          Reference descriptors
 *   remaining bytes      = the raw report the kernel vhid device delivers,
 *                          preloaded onto dev->vhid_fd
 *
 * dev->att.fd is one end of a non-blocking socketpair so att_write_cmd()
 * runs for real (its output is discarded); dev->vhid_fd is the read end of
 * a second socketpair preloaded with the report bytes.  ASan/UBSan are the
 * oracle.  The rest of blued_central.c's daemon surface is satisfied with
 * link-only stubs (never executed on this path).
 *
 * Reference: HOGP v1.0 3.3.3; Core Spec Vol 3 Part F (ATT).
 */

#include "blued_internal.h"

#include <sys/socket.h>

#include <fcntl.h>

/* ================================================================
 * Daemon globals referenced (only) by unused code in blued_central.c.
 * ================================================================ */
struct blued_ctx		blued_g;
struct blued_config		blued_cfg;
struct pidfh			*blued_pfh;
struct att_db			periph_gatt_db;
struct att_attr			periph_gatt_attrs[64];
atomic_int			blued_verbose = 0;
atomic_bool			blued_shutting_down = 0;
int				blued_daemonized = 0;
int				blued_reconnect_max_delay = 60;
_Atomic uintptr_t		blued_next_timer_id = 1;
const int			_blued_kq_vhid_output_tag = 0;
volatile sig_atomic_t		running = 1;

/* ================================================================
 * Link-only stubs: referenced by blued_central.c functions we never
 * call from this harness.  They must link but never execute here.
 * ================================================================ */
int
hci_get_con_handle(int hci_fd __unused, const uint8_t *remote_addr __unused,
    uint16_t *con_handle __unused)
{
	return (-1);
}

int
hci_le_connection_update(int hci_fd __unused, uint16_t handle __unused,
    uint16_t min __unused, uint16_t max __unused, uint16_t lat __unused,
    uint16_t tmo __unused)
{
	return (-1);
}

int
hci_le_enhanced_read_tx_power_level(int hci_fd __unused,
    uint16_t con_handle __unused, uint8_t phy __unused,
    int8_t *cur __unused, int8_t *max __unused)
{
	return (-1);
}

int
hci_le_read_phy(int hci_fd __unused, uint16_t con_handle __unused,
    uint8_t *tx __unused, uint8_t *rx __unused)
{
	return (-1);
}

int
hci_le_set_data_length(int hci_fd __unused, uint16_t con_handle __unused,
    uint16_t tx_octets __unused, uint16_t tx_time __unused)
{
	return (-1);
}

int
hci_le_set_phy(int hci_fd __unused, uint16_t con_handle __unused,
    uint8_t all_phys __unused, uint8_t tx_phys __unused,
    uint8_t rx_phys __unused, uint16_t opts __unused)
{
	return (-1);
}

int
hci_wait_encryption(int hci_fd __unused, uint16_t con_handle __unused,
    int timeout_sec __unused)
{
	return (-1);
}

int
smp_bond_db_load(struct smp_bond_db *db __unused, int fd __unused)
{
	return (-1);
}

int
smp_bond_db_save(struct smp_bond_db *db __unused)
{
	return (-1);
}

int
smp_bond_db_commit_bond(struct smp_bond_db *db __unused,
    struct smp_bond *bond __unused, const struct smp_bond *old __unused)
{
	return (-1);
}

void
smp_close(struct smp_conn *sc __unused)
{
}

int
smp_encrypt_with_ltk(struct smp_conn *sc __unused,
    const struct smp_bond *bond __unused)
{
	return (-1);
}

struct smp_bond *
smp_find_bond(struct smp_bond_db *db __unused, const uint8_t *addr __unused,
    uint8_t addr_type __unused)
{
	return (NULL);
}

int
smp_open(struct smp_conn *sc __unused, const uint8_t *addr __unused,
    uint8_t addr_type __unused, const uint8_t *local_addr __unused,
    uint8_t local_addr_type __unused, int hci_fd __unused,
    uint16_t con_handle __unused, struct smp_bond_db *db __unused)
{
	return (-1);
}

int
smp_pair(struct smp_conn *sc __unused)
{
	return (-1);
}

int
ble_coc_connect(const uint8_t *local_addr __unused,
    const uint8_t *addr __unused, uint8_t addr_type __unused,
    uint16_t psm __unused, uint16_t mtu __unused)
{
	return (-1);
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
	return (-1);
}

int
numcmp_confirm(uint32_t value __unused, void *arg __unused)
{
	return (-1);
}

void
blued_keypress_notify(uint8_t type __unused, void *arg __unused)
{
}

bool
blued_oob_take(const uint8_t *addr __unused,
    struct smp_oob_legacy *lg __unused, bool *has_lg,
    struct smp_oob_sc *scd __unused, bool *has_sc)
{
	if (has_lg != NULL)
		*has_lg = false;
	if (has_sc != NULL)
		*has_sc = false;
	return (false);
}

void
blued_ctl_notify_value(struct blued_conn *conn __unused, uint16_t handle __unused,
    const uint8_t *value __unused, uint16_t len __unused,
    uint16_t bearer_mtu __unused)
{
}

bool
att_conn_apply_encryption(struct att_conn *ac __unused,
    bool has_key_material __unused, bool mitm __unused,
    uint8_t bond_key_size __unused, uint8_t link_key_size __unused)
{
	return (false);
}

uint8_t
blued_ctl_effective_io_cap(uint8_t static_default)
{
	return (static_default);
}

bool
blued_persist_gattcache_reuse(const uint8_t addr[6] __unused,
    uint8_t addr_type __unused, const uint8_t fresh_hash[16] __unused)
{
	return (false);
}

void
blued_reslist_sync_add(int hci_fd __unused, const struct smp_bond *bond __unused)
{
}

void
blued_reslist_sync_remove(int hci_fd __unused, const uint8_t addr[6] __unused,
    uint8_t addr_type __unused)
{
}

/* ================================================================
 * Harness
 * ================================================================ */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int init;
	struct hogp_device *dev;
	int att_fds[2], vhid_fds[2];
	size_t pos;
	int i;

	if (!init) {
		signal(SIGPIPE, SIG_IGN);
		init = 1;
	}

	if (size > 4096)
		size = 4096;
	if (size < 1)
		return (0);

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, att_fds) != 0)
		return (0);
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, vhid_fds) != 0) {
		close(att_fds[0]);
		close(att_fds[1]);
		return (0);
	}
	(void)fcntl(att_fds[0], F_SETFL, O_NONBLOCK);
	(void)fcntl(att_fds[1], F_SETFL, O_NONBLOCK);
	(void)fcntl(vhid_fds[0], F_SETFL, O_NONBLOCK);
	(void)fcntl(vhid_fds[1], F_SETFL, O_NONBLOCK);

	dev = calloc(1, sizeof(*dev));
	if (dev == NULL)
		abort();

	dev->att.fd = att_fds[0];
	dev->att.mtu = 247;
	dev->vhid_fd = vhid_fds[0];
	dev->vhid_ctl_fd = -1;
	dev->hci_fd = -1;

	/* Report table: attacker-supplied Report Reference classifications. */
	pos = 0;
	dev->nreports = data[pos++] % (HOGP_MAX_REPORTS + 1);
	for (i = 0; i < dev->nreports; i++) {
		struct hogp_report *r = &dev->reports[i];

		if (pos + 4 > size) {
			dev->nreports = i;
			break;
		}
		r->value_handle = (uint16_t)data[pos] |
		    ((uint16_t)data[pos + 1] << 8);
		r->report_id = data[pos + 2];
		r->report_type = data[pos + 3];
		pos += 4;
	}

	/* Remaining bytes are the raw vhid report the kernel delivers. */
	if (pos < size)
		(void)send(vhid_fds[1], data + pos, size - pos, MSG_DONTWAIT);

	hogp_handle_vhid_output(dev);

	free(dev);
	close(att_fds[0]);
	close(att_fds[1]);
	close(vhid_fds[0]);
	close(vhid_fds[1]);
	return (0);
}
