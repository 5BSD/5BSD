/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * USDT call sites for usdt-link.py: plain probes, an is-enabled probe, a
 * probe in a static function, a probe whose name has "__" (a '-' in D), and
 * a probe in tail position (compiled at -O2, a jmp rather than a call).
 * Never executed.
 */
#include "usdt-link.h"

static __attribute__((noinline)) void
ul_static(int x)
{
	ULINK_ONE(x);
	ULINK_ZERO();
}

void
ul_main(int x, char *s)
{
	ULINK_ZERO();
	if (ULINK_TWO_ENABLED())
		ULINK_TWO(x, s);
	ul_static(x);
	ULINK_FIVE(x, 2L, s, 3, 4UL);
	ULINK_DASH_NAME(x);
}

void
ul_tail(int x)
{
	ULINK_ONE(x);
}
