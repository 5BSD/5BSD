/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * In-process probe tap for blued.
 *
 * This is the third backend selected by the BLUED_PROBE_* macros in
 * blued_probes.h.  When blued (or a unit test that links its objects) is
 * compiled with -DWITH_PROBE_TAP, every BLUED_PROBE_x(...) invocation
 * appends a record to a fixed in-process ring buffer instead of firing a
 * DTrace USDT probe (WITH_DTRACE) or expanding to nothing (default).
 *
 * The tap exists purely so ATF tests can observe protocol steps -- SMP
 * pairing phases, GATT discovery iterations, ATT errors, robust-caching
 * transitions -- and assert on the exact records and their order.
 *
 * Threading: the ring buffer is a plain static array with no locking.
 * blued's protocol paths (and every test that drives them) are
 * single-threaded, so no synchronisation is required.  Do NOT enable
 * -DWITH_PROBE_TAP in a multi-threaded build; it is a test aid, not a
 * production tracing facility (production uses WITH_DTRACE).
 */

#ifndef BLUED_PROBE_TAP_H
#define BLUED_PROBE_TAP_H

#include <stddef.h>
#include <stdint.h>

/* Maximum number of integer (uint64) arguments captured per record. */
#define	PROBE_TAP_MAX_ARGS	5
/* Bytes reserved for a copy of a probe's string argument (incl. NUL). */
#define	PROBE_TAP_STR_MAX	48
/* Number of records the ring buffer holds before wrapping. */
#define	PROBE_TAP_RING_SIZE	1024

/*
 * One captured probe firing.
 *
 * name   -- stable string literal identifying the probe, e.g.
 *           "smp:method:select" or "att:error".
 * nargs  -- number of valid entries in args[].
 * args   -- integer arguments, widened to uint64_t at the call site.
 * str    -- copy of the probe's (single) string argument, NUL-terminated;
 *           empty ("") and has_str == 0 when the probe carries no string.
 */
struct probe_rec {
	const char	*name;
	unsigned	 nargs;
	uint64_t	 args[PROBE_TAP_MAX_ARGS];
	char		 str[PROBE_TAP_STR_MAX];
	int		 has_str;
};

/* Accessors (see blued_probe_tap.c). */
void			 probe_tap_reset(void);
size_t			 probe_tap_count(void);
const struct probe_rec	*probe_tap_get(size_t i);
size_t			 probe_tap_find(const char *name, size_t from);

/*
 * Recording helpers, one per argument arity.  str may be NULL for probes
 * with no string argument.  The BLUED_PROBE_* macros (blued_probes.h,
 * WITH_PROBE_TAP branch) widen their integer arguments to uint64_t and
 * dispatch to the matching helper.
 */
void	probe_tap_rec0(const char *name, const char *str);
void	probe_tap_rec1(const char *name, const char *str, uint64_t a0);
void	probe_tap_rec2(const char *name, const char *str, uint64_t a0,
	    uint64_t a1);
void	probe_tap_rec3(const char *name, const char *str, uint64_t a0,
	    uint64_t a1, uint64_t a2);
void	probe_tap_rec4(const char *name, const char *str, uint64_t a0,
	    uint64_t a1, uint64_t a2, uint64_t a3);

#endif /* BLUED_PROBE_TAP_H */
