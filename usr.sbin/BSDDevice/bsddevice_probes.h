/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Thin, optional wrappers over the bsddevice USDT provider.  With MK_DTRACE
 * the daemon is built -DWITH_DTRACE and these expand to the dtrace(1)-generated
 * probe macros (bsddevice_provider.h, produced from bsddevice_provider.d in
 * the object directory); without it they compile to argument-consuming no-ops so
 * the daemon and its ATF harness build cleanly with DTrace disabled.
 */
#ifndef _BSDDEVICE_PROBES_H_
#define _BSDDEVICE_PROBES_H_

#ifdef WITH_DTRACE
#include "bsddevice_provider.h"
#define	BSDDEVICE_PROBE_OPEN(label, device, granted, error) \
	BSDDEVICE_OPEN(__DECONST(char *, label), \
	    __DECONST(char *, device), granted, error)
#define	BSDDEVICE_PROBE_LIST(label, cursor, count, error) \
	BSDDEVICE_LIST(__DECONST(char *, label), cursor, count, error)
#else
#define	BSDDEVICE_PROBE_OPEN(label, device, granted, error) \
	do { (void)(label); (void)(device); (void)(granted); \
	    (void)(error); } while (0)
#define	BSDDEVICE_PROBE_LIST(label, cursor, count, error) \
	do { (void)(label); (void)(cursor); (void)(count); \
	    (void)(error); } while (0)
#endif

#endif /* !_BSDDEVICE_PROBES_H_ */
