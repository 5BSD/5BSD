/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_MIGRATION_VSOCK_RELAY_H_
#define _BHYVE_MIGRATION_VSOCK_RELAY_H_

#include <stddef.h>
#include <stdint.h>

struct migration_vsock_relay_endpoint {
	int fd;
	uint32_t type;	/* VSOCK_MIGRATION_TYPE_* */
};

/*
 * Run one side of a symmetric, bounded relay over a connected stream.  The
 * caller owns all descriptors and keeps them open until this function exits.
 * Endpoints are paired by their index in the previously accepted state table.
 */
int migration_vsock_relay_run(int,
    const struct migration_vsock_relay_endpoint *, size_t);

#endif
