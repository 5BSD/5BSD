/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _KLDMGRD_TEST_H_
#define	_KLDMGRD_TEST_H_

#include <stdbool.h>

struct kldmgrd_backend;

int kldmgrd_test_serve(int, const char *, bool,
    const struct kldmgrd_backend *);
int kldmgrd_test_prepare_worker_fd(int);

#endif /* !_KLDMGRD_TEST_H_ */
