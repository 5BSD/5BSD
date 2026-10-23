/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_MIGRATION_VSOCK_OWNER_H_
#define _BHYVE_MIGRATION_VSOCK_OWNER_H_

#include <sys/types.h>

#include <stddef.h>

#include "migration_vsock_relay.h"

/* Start before bhyve creates device or vCPU threads. */
int migration_vsock_owner_start(pid_t *);
/* Transfer paused source descriptors without starting any reads. */
int migration_vsock_owner_prepare(int,
    const struct migration_vsock_relay_endpoint *, size_t);
/* Confirm the owner's copies are closed before source rollback. */
int migration_vsock_owner_cancel(void);
/* After RELEASE, start forwarding and relinquish the control socket. */
int migration_vsock_owner_activate(void);
/* Close an idle owner during ordinary VM teardown. */
void migration_vsock_owner_detach(void);

#endif
