/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BSDDEVICE_TEST_H_
#define _BSDDEVICE_TEST_H_

#include <devicecmp_protocol.h>

#include "policy.h"

/*
 * Test-only entrypoints.  bsddevice_test_set_config() installs a policy in
 * place of the switchboard-delivered Config/ overlay; bsddevice_test_serve()
 * runs the real per-label serve path on a caller-owned channel descriptor with
 * a caller-supplied client label, so the default-deny + Capsicum-narrowing
 * isolation properties can be driven over the plane without switchboard.
 */
void	bsddevice_test_set_config(const struct devicecmp_config *);
int	bsddevice_test_serve(int, const char *);

#endif /* !_BSDDEVICE_TEST_H_ */
