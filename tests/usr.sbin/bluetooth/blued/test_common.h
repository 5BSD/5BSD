/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_TEST_COMMON_H_
#define _BLUED_TEST_COMMON_H_

/*
 * Common stub definitions shared across blued ATF test programs.
 *
 * Each test binary is a separate executable, so it is safe to define
 * (not just declare) globals and functions here -- only one copy of
 * each symbol will exist per binary.
 *
 * Only stubs that are identical in 3+ test files belong here.
 * File-specific stubs remain in their respective test files.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "ble_util.h"
#include "hci_log.h"

/* ================================================================
 * ble_util.h globals
 * ================================================================ */
/*
 * Globals — declared extern in ble_util.h / blued.h.
 * Tests that include blued.h will have the extern visible already;
 * for others, provide an extern declaration to satisfy -Wmissing-variable-declarations.
 */
#ifndef _BLUED_H_
extern atomic_bool blued_shutting_down;
#endif
atomic_int blued_verbose;
int blued_daemonized;
atomic_bool blued_shutting_down;

/* ================================================================
 * hci_log.c stubs -- no-op implementations for test builds
 * ================================================================ */
bool
hci_log_enabled(void)
{

	return (false);
}

void
hci_log_l2cap(uint16_t con_handle __unused, uint16_t cid __unused,
    const uint8_t *data __unused, uint16_t len __unused,
    bool incoming __unused)
{
}

void
hci_log_packet(uint8_t type __unused, const uint8_t *data __unused,
    uint16_t len __unused, bool incoming __unused)
{
}

/* ================================================================
 * ble_coc_connect stub -- returns -1 (no CoC support in tests)
 *
 * Define TEST_CUSTOM_BLE_COC_CONNECT before including this header
 * to provide your own ble_coc_connect implementation.
 * ================================================================ */
#ifndef TEST_CUSTOM_BLE_COC_CONNECT
/* Prototype — not in any header, declared ad-hoc in att.c */
int	ble_coc_connect(const uint8_t *, uint8_t, uint16_t, uint16_t);

int
ble_coc_connect(const uint8_t *addr __unused, uint8_t addr_type __unused,
    uint16_t psm __unused, uint16_t mtu __unused)
{

	return (-1);
}
#endif

/* ================================================================
 * ctl.h stubs -- no ctl socket in tests
 * ================================================================ */
#include "ctl.h"
#include "smp.h"

/* smp_verify_signature stub -- only for tests not linking real smp.c.
 * Define TEST_LINKS_SMP before including this header to suppress. */
#ifndef TEST_LINKS_SMP
bool
smp_verify_signature(const uint8_t csrk[16] __unused,
    const uint8_t *msg __unused, size_t msg_len __unused,
    const uint8_t mac[8] __unused, uint32_t counter __unused)
{
	return (false);
}
#endif

/*
 * ctl notify stubs -- only for tests that do NOT link the real ctl.c.
 * Define TEST_LINKS_CTL before including this header to suppress.
 */
#ifndef TEST_LINKS_CTL
void
blued_ctl_notify_value(const bdaddr_t *addr __unused, uint16_t handle __unused,
    const uint8_t *value __unused, uint16_t len __unused)
{
}

void
blued_ctl_notify_write(int owner_fd __unused, uint16_t handle __unused,
    const uint8_t *value __unused, uint16_t len __unused)
{
}
#endif

#endif /* _BLUED_TEST_COMMON_H_ */
