/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probe for libutil's setusercontext() credential transition.
 *
 * Provider: logincap
 *
 * Usage:
 *   dtrace -n 'logincap*:::setusercontext'
 */

#ifndef LOGINCAP_PROBES_H
#define LOGINCAP_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#ifdef WITH_DTRACE_STATIC_ANCHOR
/* Pull separate provider metadata only when this object is selected. */
extern const unsigned char __bsd_dof_anchor_logincap_provider
    __attribute__((visibility("hidden")));
static const void * const logincap_dtrace_anchor __attribute__((used, retain)) =
    &__bsd_dof_anchor_logincap_provider;
#endif
#else
#define	DTRACE_PROBE4(provider, name, arg1, arg2, arg3, arg4) \
	do { if (0) { (void)(arg1); (void)(arg2); (void)(arg3); \
	    (void)(arg4); } } while (0)
#endif

#define	LOGINCAP_PROBE_SETUSERCONTEXT(user, uid, flags, error)	\
	DTRACE_PROBE4(logincap, setusercontext, user, uid, flags, error)

#endif /* LOGINCAP_PROBES_H */
