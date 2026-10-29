/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Allocation-failure injection for tests.  failalloc.c defines the
 * linker wrappers (-Wl,--wrap=malloc and so on, see tests/Makefile), so
 * the library is linked exactly as built: only allocations made from
 * the statically linked objects pass through the countdown; shared
 * libraries (libucl, ATF) are not affected.
 */

#ifndef _FAILALLOC_H_
#define	_FAILALLOC_H_

/* <0: never fail; otherwise the allocation after this many fails. */
extern long failalloc_countdown;
/* Number of injected failures since the last reset. */
extern long failalloc_failures;

#endif /* !_FAILALLOC_H_ */
