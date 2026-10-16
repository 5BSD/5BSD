/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_MIGRATION_VSOCK_BUNDLE_H_
#define _BHYVE_MIGRATION_VSOCK_BUNDLE_H_

#include <stddef.h>
#include <stdint.h>

#define MIGRATION_VSOCK_BUNDLE_NAME 40U
#define MIGRATION_VSOCK_BUNDLE_MAX_DEVICES 256U
#define MIGRATION_VSOCK_BUNDLE_MAX_ENDPOINTS 256U
#define MIGRATION_VSOCK_BUNDLE_MAX_WIRE (512U * 1024U * 1024U)

/* Table bytes are owned by the caller, or point into a decoded wire image. */
struct migration_vsock_bundle_item {
	char name[MIGRATION_VSOCK_BUNDLE_NAME];
	const uint8_t *table;
	size_t table_len;
	uint32_t endpoint_count;
};

int migration_vsock_bundle_size(
    const struct migration_vsock_bundle_item *, uint32_t, size_t *);
int migration_vsock_bundle_encode(
    const struct migration_vsock_bundle_item *, uint32_t, uint8_t *, size_t);
int migration_vsock_bundle_decode(const uint8_t *, size_t,
    struct migration_vsock_bundle_item *, uint32_t, uint32_t *, uint32_t *);

#endif
