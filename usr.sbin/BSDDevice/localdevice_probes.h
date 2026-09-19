/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Thin, optional wrappers over the localdevice USDT provider.  With MK_DTRACE
 * the daemon is built -DWITH_DTRACE and these expand to the dtrace(1)-generated
 * probe macros (localdevice_provider.h, produced from localdevice_provider.d in
 * the object directory); without it they compile to argument-consuming no-ops so
 * the daemon and its ATF harness build cleanly with DTrace disabled.
 */
#ifndef _LOCALDEVICE_PROBES_H_
#define _LOCALDEVICE_PROBES_H_

#ifdef WITH_DTRACE
#include "localdevice_provider.h"
#define	LOCALDEVICE_PROBE_OPEN(label, device, granted, error) \
	LOCALDEVICE_OPEN(__DECONST(char *, label), \
	    __DECONST(char *, device), granted, error)
#define	LOCALDEVICE_PROBE_LIST(label, cursor, count, error) \
	LOCALDEVICE_LIST(__DECONST(char *, label), cursor, count, error)
#else
#define	LOCALDEVICE_PROBE_OPEN(label, device, granted, error) \
	do { (void)(label); (void)(device); (void)(granted); \
	    (void)(error); } while (0)
#define	LOCALDEVICE_PROBE_LIST(label, cursor, count, error) \
	do { (void)(label); (void)(cursor); (void)(count); \
	    (void)(error); } while (0)
#endif

#endif /* !_LOCALDEVICE_PROBES_H_ */
