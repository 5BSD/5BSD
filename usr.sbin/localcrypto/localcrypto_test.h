/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LOCALCRYPTO_TEST_H_
#define _LOCALCRYPTO_TEST_H_

/*
 * Test-only entrypoint.  Runs the real owner-scoped serve path on a caller-owned
 * channel descriptor with a caller-supplied owner label, so the crown-jewel
 * named-key isolation property can be driven over the plane without serviced.
 */
int localcrypto_test_serve(int, const char *);

#endif
