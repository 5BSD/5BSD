/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * USDT probe shims for BSDTime(8).  Under -DWITH_DTRACE (MK_DTRACE builds) these
 * expand to the dtrace(1)-generated provider macros; otherwise they compile to
 * argument-consuming no-ops, so BSDTime builds identically with and without
 * DTrace.  Mirrors the BSDExtension/BSDLog provider convention.
 */
#ifndef BSDTIME_PROBES_H
#define BSDTIME_PROBES_H

#include <sys/cdefs.h>

#ifdef WITH_DTRACE
#include "BSDTime_provider.h"
#define	BSDTIME_PROBE_REQUEST(client, opcode, status) \
	BSDTIME_REQUEST(__DECONST(char *, client), opcode, status)
#define	BSDTIME_PROBE_CLOCK_SET(client, sec, nsec) \
	BSDTIME_CLOCK_SET(__DECONST(char *, client), sec, nsec)
#define	BSDTIME_PROBE_CLOCK_ADJUST(client, nsec) \
	BSDTIME_CLOCK_ADJUST(__DECONST(char *, client), nsec)
#else
#define	BSDTIME_PROBE_REQUEST(client, opcode, status) \
	do { (void)(client); (void)(opcode); (void)(status); } while (0)
#define	BSDTIME_PROBE_CLOCK_SET(client, sec, nsec) \
	do { (void)(client); (void)(sec); (void)(nsec); } while (0)
#define	BSDTIME_PROBE_CLOCK_ADJUST(client, nsec) \
	do { (void)(client); (void)(nsec); } while (0)
#endif

#endif /* BSDTIME_PROBES_H */
