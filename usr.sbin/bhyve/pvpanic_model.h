/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Pure, allocation-free model of the QEMU pvpanic event register ABI and the
 * host reaction policy.  Kept header-only so both the bhyve device model
 * (pvpanic.c) and the rootless ATF model test can share the exact same
 * decode/encode logic.
 */

#ifndef _PVPANIC_MODEL_H_
#define	_PVPANIC_MODEL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * QEMU pvpanic event bits.  The guest reads the single-byte event register to
 * learn which events the host understands, then writes back the bit(s) for the
 * event that just occurred.  These values are ABI: they must match QEMU's
 * hw/misc/pvpanic.h so a stock guest driver (Linux's pvpanic) interoperates.
 */
#define	PVPANIC_PANICKED	0x01	/* guest has panicked */
#define	PVPANIC_CRASHLOADED	0x02	/* guest is loading/running a crashkernel */
#define	PVPANIC_SUPPORTED_EVENTS	(PVPANIC_PANICKED | PVPANIC_CRASHLOADED)

/* Host reaction policy selectable by the operator. */
enum pvpanic_action {
	PVPANIC_ACT_NONE = 0,	/* log only; do not change VM lifecycle */
	PVPANIC_ACT_POWEROFF,	/* stop the VM */
	PVPANIC_ACT_RESET,	/* reset the VM */
	PVPANIC_ACT_HALT,	/* halt the VM */
};

/*
 * A read of the event register returns the bitmap of events the host
 * understands.  This value is constant for the lifetime of the device.
 */
static inline uint8_t
pvpanic_supported_events(void)
{

	return (PVPANIC_SUPPORTED_EVENTS);
}

/*
 * Decode a guest write to the event register.  Per the QEMU ABI, unknown bits
 * are ignored: only recognised event bits are returned.  A return of 0 means
 * the write carried nothing the host acts on and must be dropped silently.
 */
static inline uint8_t
pvpanic_decode_event(uint8_t written)
{

	return (written & PVPANIC_SUPPORTED_EVENTS);
}

/*
 * A PANICKED event means the guest is dead and would otherwise hang; that is
 * the only event that may drive a VM lifecycle change.  A CRASHLOADED event
 * means a crashkernel is (about to be) running, so the VM must be left alone
 * to capture the dump.  Returns true if the given (already decoded) event set
 * authorises the configured lifecycle action.
 */
static inline bool
pvpanic_event_is_fatal(uint8_t events)
{

	return ((events & PVPANIC_PANICKED) != 0);
}

/*
 * Parse an operator-supplied action string ("none"/"log", "poweroff",
 * "reset", "halt").  Returns false on an unrecognised value and leaves *out
 * untouched.
 */
static inline bool
pvpanic_parse_action(const char *s, enum pvpanic_action *out)
{
	enum pvpanic_action act;

	if (s == NULL || out == NULL)
		return (false);
	if (strcmp(s, "none") == 0 || strcmp(s, "log") == 0)
		act = PVPANIC_ACT_NONE;
	else if (strcmp(s, "poweroff") == 0)
		act = PVPANIC_ACT_POWEROFF;
	else if (strcmp(s, "reset") == 0)
		act = PVPANIC_ACT_RESET;
	else if (strcmp(s, "halt") == 0)
		act = PVPANIC_ACT_HALT;
	else
		return (false);
	*out = act;
	return (true);
}

/*
 * Snapshot codec for the device's checkpointable configuration byte.  The
 * pvpanic event register is otherwise stateless (write-only trigger, constant
 * read), so the only state worth serialising is whether the device is enabled
 * and which host action is armed.  Layout: bit7 = enabled, bits2:0 = action.
 */
static inline uint8_t
pvpanic_config_encode(bool enabled, enum pvpanic_action action)
{

	return ((uint8_t)((enabled ? 0x80u : 0u) | ((uint8_t)action & 0x07u)));
}

static inline bool
pvpanic_config_decode(uint8_t byte, bool *enabled, enum pvpanic_action *action)
{
	uint8_t raw;

	/*
	 * Reject any byte with bits set outside the defined layout (bit7 =
	 * enabled, bits2:0 = action).  A restored image carrying reserved bits
	 * is not one we wrote, so treat it as corrupt rather than silently
	 * masking it away.
	 */
	if ((byte & ~(uint8_t)0x87u) != 0)
		return (false);
	raw = (uint8_t)(byte & 0x07u);
	if (raw > (uint8_t)PVPANIC_ACT_HALT)
		return (false);
	if (enabled != NULL)
		*enabled = (byte & 0x80u) != 0;
	if (action != NULL)
		*action = (enum pvpanic_action)raw;
	return (true);
}

#endif /* _PVPANIC_MODEL_H_ */
