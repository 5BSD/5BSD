/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NETWORKCMP_TEST_H_
#define	_NETWORKCMP_TEST_H_

#include <stdbool.h>

#include <libcasper.h>

struct networkcmp_policy;
struct networkcmp_endpoint;

/*
 * Test-only accessor for the static endpoint_is_internal() SSRF guard.  This
 * lets the pure destination-constraint regression exercise the classifier
 * directly without standing up a provider channel.
 */
bool networkcmp_test_endpoint_is_internal(const struct networkcmp_endpoint *);

int networkcmp_test_serve(int, cap_channel_t *,
    const struct networkcmp_policy *, const char *);
int networkcmp_test_serve_blocked_resolver(int, cap_channel_t *,
    const struct networkcmp_policy *, const char *, int, int);
int networkcmp_test_serve_blocked_resolver_timeout(int, cap_channel_t *,
    const struct networkcmp_policy *, const char *, int, int, uint32_t);

#endif
