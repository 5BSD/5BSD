/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _TRACECMP_TEST_H_
#define	_TRACECMP_TEST_H_

#include <stdbool.h>

int tracecmp_test_serve(int, int, bool, int, const char *);
int tracecmp_test_prepare_worker_fd(int);

#endif
