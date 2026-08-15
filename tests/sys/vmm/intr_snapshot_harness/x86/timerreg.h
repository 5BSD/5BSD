/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Userspace harness shadow of <x86/timerreg.h>.  The real header hides its
 * contents behind _KERNEL, so mirror the port definitions here and pull the
 * 8253 mode/command bits from the tree's unguarded i8253 register header.
 */
#ifndef _KMOCK_X86_TIMERREG_H_
#define	_KMOCK_X86_TIMERREG_H_

#include "../../../../../sys/dev/ic/i8253reg.h"

#define	IO_TIMER1	0x40		/* 8253 Timer #1 */
#define	TIMER_CNTR0	(IO_TIMER1 + TIMER_REG_CNTR0)
#define	TIMER_CNTR1	(IO_TIMER1 + TIMER_REG_CNTR1)
#define	TIMER_CNTR2	(IO_TIMER1 + TIMER_REG_CNTR2)
#define	TIMER_MODE	(IO_TIMER1 + TIMER_REG_MODE)

#endif /* !_KMOCK_X86_TIMERREG_H_ */
