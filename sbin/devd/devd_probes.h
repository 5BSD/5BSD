/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef DEVD_PROBES_H
#define DEVD_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
/*
 * The userland DTRACE_PROBE macros in <sys/sdt.h> declare the __dtrace_*
 * stub with default linkage.  In C++ that mangles the symbol name, so
 * dtrace(1) -G finds no probe sites.  Pre-declaring the stub with C
 * linkage forces the block-scope redeclaration in the macro to refer to
 * this (unmangled) entity.
 */
#ifdef __cplusplus
extern "C" {
#endif
extern void __dtrace_devd___action(unsigned long, unsigned long);
#ifdef __cplusplus
}
#endif
#else
#define DTRACE_PROBE2(p,n,a,b) do { if (0){(void)(a);(void)(b);} } while (0)
#define DTRACE_PROBE3(p,n,a,b,c) do { if (0){(void)(a);(void)(b);(void)(c);} } while (0)
#endif

#define	DEVD_PROBE_ACTION(event,cmd) \
	DTRACE_PROBE2(devd, action, event, cmd)

#endif /* DEVD_PROBES_H */
