/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for blued's LE Meta event decoder
 * (blued_parse_le_meta_event() in blued_le_meta.h).
 *
 * blued enables the BT 5.2 LE Power Control and LE Isochronous (ISO)
 * meta-events in its LE event mask, so a controller delivers them over the
 * raw HCI socket.  blued_handle_hci_event() (blued_event.c) hands each
 * HCI_LE_Meta packet to this pure decoder, which overlays the wire bytes
 * onto a caller struct and validates the spec-defined lengths.  The bytes
 * are fully controller-controlled: a malicious or buggy controller is the
 * attacker here.  The decoder does manual fixed-offset reads (p[15], p[22],
 * ... p[27]) and, for the BIG subevents, a num_bis-driven length check --
 * classic over-read territory -- so ASan/UBSan are the oracle.
 *
 * The decoder expects the raw HCI event framing:
 *   pkt[0]=packet type, pkt[1]=event code (0x3E), pkt[2]=param len,
 *   pkt[3]=subevent, pkt[4..]=subevent parameters.
 *
 * To keep coverage flowing regardless of how the fuzzer sets pkt[1], the
 * input is decoded twice: once verbatim, and once through a copy whose
 * pkt[1] is forced to NG_HCI_EVENT_LE so the subevent switch is always
 * reached.  Both copies are exact-size heap allocations so any read past
 * the declared length trips ASan.
 *
 * Reference: Core Spec Vol 4 Part E 7.7.65.25-.33.
 */

#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "blued_le_meta.h"

static void
decode_once(const uint8_t *data, size_t size)
{
	struct blued_le_meta_report rep;
	uint8_t *copy;

	copy = malloc(size == 0 ? 1 : size);
	if (copy == NULL)
		abort();
	if (size != 0)
		memcpy(copy, data, size);

	(void)blued_parse_le_meta_event(copy, size, &rep);

	free(copy);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t *forced;

	if (size > 4096)
		size = 4096;

	/* As delivered on the wire (fuzzer controls the event code). */
	decode_once(data, size);

	/*
	 * Same bytes but with the event code pinned to HCI_LE_Meta, so the
	 * subevent switch (the interesting, over-read-prone arms) is always
	 * exercised even before the fuzzer learns byte 1 must be 0x3E.
	 */
	if (size >= 2) {
		forced = malloc(size);
		if (forced == NULL)
			abort();
		memcpy(forced, data, size);
		forced[1] = NG_HCI_EVENT_LE;
		decode_once(forced, size);
		free(forced);
	}

	return (0);
}
