/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NETWORKCMP_TEST_H_
#define	_NETWORKCMP_TEST_H_

#include <libcasper.h>

struct networkcmp_policy;

int networkcmp_test_serve(int, cap_channel_t *,
    const struct networkcmp_policy *, const char *);
int networkcmp_test_serve_blocked_resolver(int, cap_channel_t *,
    const struct networkcmp_policy *, const char *, int, int);
int networkcmp_test_serve_blocked_resolver_timeout(int, cap_channel_t *,
    const struct networkcmp_policy *, const char *, int, int, uint32_t);

#endif
