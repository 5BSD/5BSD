/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * System gate name-to-bitmask table.
 *
 * Shared between config.c and manifest.c to avoid duplication.
 * The bitmask values match SYS_GATE_* in cap_rt_system_proto.h.
 */

#ifndef GATES_H
#define GATES_H

#include <stdint.h>

struct gate_entry {
	const char	*name;
	uint32_t	 gate;
};

static const struct gate_entry gate_names[] = {
	{ "kldload",	0x0001 },
	{ "kldunload",	0x0002 },
	{ "kldstat",	0x0004 },
	{ "reboot",	0x0008 },
	{ "swapon",	0x0010 },
	{ "swapoff",	0x0020 },
	{ "sysctl",	0x0040 },
	{ "kenv",	0x0080 },
	{ "acct",	0x0100 },
	{ "audit",	0x0200 },
	{ "kenv_read",	0x0400 },
};

#endif /* GATES_H */
