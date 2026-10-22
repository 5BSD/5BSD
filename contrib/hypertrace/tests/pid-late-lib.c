/* SPDX-License-Identifier: BSD-2-Clause */
/* Library loaded at run time by pid-late-target; carries USDT DOF. */
#include "pid-late.h"

int
ht_late(int x)
{
	HTLATE_FIRE(x, "late");
	return (x * 7);
}
