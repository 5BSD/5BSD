/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LOCALCRYPTO_TEST_H_
#define _LOCALCRYPTO_TEST_H_

/*
 * Test-only entrypoint.  Runs the real owner-scoped serve path on a caller-owned
 * channel descriptor with a caller-supplied owner label, so the crown-jewel
 * named-key isolation property can be driven over the plane without serviced.
 */
int localcrypto_test_serve(int, const char *);

/*
 * Test-only entrypoint.  Runs the real capability-lifecycle reclaim handler for
 * the given retired owner label against the shared kernel keystore, so the
 * owner-scoped, idempotent reclaim can be driven without serviced pushing the
 * retirement.  Returns 0 on a completed reclaim, -1/errno on a bad label or a
 * control-device open failure.
 */
int localcrypto_test_reclaim(const char *);

#endif
