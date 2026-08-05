/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _LOGCMP_WAKEUP_H_
#define _LOGCMP_WAKEUP_H_

#include <stdbool.h>

#define	LOGCMP_WAKE_CONSUMER	0
#define	LOGCMP_WAKE_PRODUCER	1

int	logcmp_wakeup_create(int [2]);
int	logcmp_wakeup_validate_consumer(int);
int	logcmp_wakeup_signal(int, bool);
int	logcmp_wakeup_drain(int);

#endif
