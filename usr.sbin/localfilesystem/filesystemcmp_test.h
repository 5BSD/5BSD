/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _FILESYSTEMCMP_TEST_H_
#define	_FILESYSTEMCMP_TEST_H_

#include <stdbool.h>

struct filesystem_store;

int filesystemcmp_test_serve(int, struct filesystem_store *, const char *);
int filesystemcmp_test_harden_resource_fd(int, bool);

#endif
