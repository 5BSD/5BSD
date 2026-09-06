/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LOCALDEVICE_TEST_H_
#define _LOCALDEVICE_TEST_H_

#include <devicecmp_protocol.h>

#include "policy.h"

/*
 * Test-only entrypoints.  localdevice_test_set_config() installs a policy in
 * place of the serviced-delivered Config/ overlay; localdevice_test_serve()
 * runs the real per-label serve path on a caller-owned channel descriptor with
 * a caller-supplied client label, so the default-deny + Capsicum-narrowing
 * isolation properties can be driven over the plane without serviced.
 */
void	localdevice_test_set_config(const struct devicecmp_config *);
int	localdevice_test_serve(int, const char *);

#endif /* !_LOCALDEVICE_TEST_H_ */
