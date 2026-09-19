/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Observation surface of the blued.c stub seam (blued_daemon_stub.c).
 * See that file for why the daemon-wiring harness stubs blued.c and links
 * every other production translation unit for real.
 */

#ifndef _BLUED_DAEMON_STUB_H_
#define _BLUED_DAEMON_STUB_H_

#include <stdbool.h>
#include <stdint.h>

#define	BLUED_STUB_MAX_ROTATE	8

struct blued_adapter;

struct blued_stub_record {
	unsigned int	rotate_rpa_calls;
	struct blued_adapter *rotate_rpa_adapters[BLUED_STUB_MAX_ROTATE];
	uint8_t		rotate_rpa_addrs[BLUED_STUB_MAX_ROTATE][6];
	int		rotate_rpa_rc;

	unsigned int	rpa_retry_arm_calls;
	int		rpa_retry_arm_rc;
	unsigned int	rpa_retry_cancel_calls;

	unsigned int	discoverable_timer_calls;
	uintptr_t	discoverable_timer_last;
	uintptr_t	discoverable_timer_match;

	unsigned int	reload_config_calls;

	unsigned int	set_power_calls;
	bool		set_power_last_on;
	unsigned int	set_privacy_calls;
	bool		set_privacy_last_on;
	unsigned int	set_discoverable_calls;
	bool		set_discoverable_last_on;
	unsigned int	adv_legacy_reclaim_calls;

	unsigned int	reslist_quiesce_begin_calls;
	unsigned int	reslist_quiesce_end_calls;
	unsigned int	reslist_sync_add_calls;
	unsigned int	reslist_sync_remove_calls;

	unsigned int	passkey_display_calls;
	unsigned int	numcmp_confirm_calls;
	unsigned int	keypress_notify_calls;
};

extern struct blued_stub_record blued_stub;

void	blued_stub_reset(void);

#endif /* _BLUED_DAEMON_STUB_H_ */
