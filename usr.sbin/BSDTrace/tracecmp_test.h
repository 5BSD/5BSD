/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _TRACECMP_TEST_H_
#define	_TRACECMP_TEST_H_

#include <stdbool.h>

#include <libservice.h>	/* service_rights_t */

int tracecmp_test_serve(int, int, bool, int, const char *, service_rights_t);
int tracecmp_test_prepare_worker_fd(int);
int tracecmp_test_open_consumer(int);

#endif
