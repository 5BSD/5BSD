/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LOCALSYSCTL_TEST_H_
#define _LOCALSYSCTL_TEST_H_

#include "config.h"

/*
 * Test-only entrypoint.  Runs the real per-label serve path (the GET/SET/
 * OIDFMT/DESCR/NEXT/HELLO dispatch) on a caller-owned channel descriptor with a
 * caller-supplied client label and policy, so the per-label read/write gating
 * can be driven over the plane without serviced or a config-directory overlay.
 */
int sysctlcmp_test_serve(int, const char *, const struct sysctlcmp_config *);

#endif /* !_LOCALSYSCTL_TEST_H_ */
