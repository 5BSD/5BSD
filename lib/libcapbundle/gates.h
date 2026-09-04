/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * System gate name-to-bitmask table.
 *
 * Shared between config.c and manifest.c to avoid duplication.
 * The bitmask values match SYS_GATE_* in mac_capability_system_proto.h.
 */

#ifndef GATES_H
#define GATES_H

#include <dev/mac_capability/mac_capability_system_proto.h>

struct gate_entry {
	const char	*name;
	uint32_t	 gate;
};

static const struct gate_entry gate_names[] = {
	{ "kldload",	SYS_GATE_KLDLOAD },
	{ "kldunload",	SYS_GATE_KLDUNLOAD },
	{ "reboot",	SYS_GATE_REBOOT },
	{ "swapon",	SYS_GATE_SWAPON },
	{ "swapoff",	SYS_GATE_SWAPOFF },
	{ "sysctl",	SYS_GATE_SYSCTL },
	{ "kenv",	SYS_GATE_KENV },
	{ "acct",	SYS_GATE_ACCT },
	{ "audit",	SYS_GATE_AUDIT },
	{ "kenv_read",	SYS_GATE_KENV_READ },
};

#endif /* GATES_H */
