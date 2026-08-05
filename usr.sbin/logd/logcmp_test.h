/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _LOGCMP_TEST_H_
#define	_LOGCMP_TEST_H_

#include <stdint.h>

#include "session.h"

int logcmp_test_serve(int, const char *, uint32_t, int);
int logcmp_test_trusted_submit(const struct logcmp_record *, logcmp_sink_fn,
    void *);

#endif
