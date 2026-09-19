/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BSDCRYPTO_TEST_H_
#define _BSDCRYPTO_TEST_H_

/*
 * Test-only entrypoint.  Runs the real owner-scoped serve path on a caller-owned
 * channel descriptor with a caller-supplied owner label, so the crown-jewel
 * named-key isolation property can be driven over the plane without switchboard.
 */
int bsdcrypto_test_serve(int, const char *);
void bsdcrypto_test_bundle_of(const char *, char *, size_t);

#endif
