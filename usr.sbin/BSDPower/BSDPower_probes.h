/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * USDT probe shims for BSDPower(8): dtrace(1)-generated macros under
 * -DWITH_DTRACE, argument-consuming no-ops otherwise.
 */
#ifndef BSDPOWER_PROBES_H
#define BSDPOWER_PROBES_H

#include <sys/cdefs.h>

#ifdef WITH_DTRACE
#include "BSDPower_provider.h"
#define	BSDPOWER_PROBE_REQUEST(client, opcode, status) \
	BSDPOWER_REQUEST(__DECONST(char *, client), opcode, status)
#define	BSDPOWER_PROBE_SUSPEND(client, state) \
	BSDPOWER_SUSPEND(__DECONST(char *, client), state)
#else
#define	BSDPOWER_PROBE_REQUEST(client, opcode, status) \
	do { (void)(client); (void)(opcode); (void)(status); } while (0)
#define	BSDPOWER_PROBE_SUSPEND(client, state) \
	do { (void)(client); (void)(state); } while (0)
#endif

#endif /* BSDPOWER_PROBES_H */
