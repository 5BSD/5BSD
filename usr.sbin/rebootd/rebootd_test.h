/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _REBOOTD_TEST_H_
#define	_REBOOTD_TEST_H_

#include <stdbool.h>
#include <stdatomic.h>

struct rebootd_backend;

int rebootd_test_serve(int, const char *, bool, _Atomic bool *,
    const struct rebootd_backend *);
int rebootd_test_scheduler_tick(int, int, unsigned *, unsigned *, bool *);

#endif /* !_REBOOTD_TEST_H_ */
