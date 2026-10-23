/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <corvink@FreeBSD.org>
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <vmmapi.h>

#include "config.h"

struct tpm_device;
struct vm_snapshot_meta;

int tpm_device_create(struct tpm_device **new_dev, struct vmctx *vm_ctx,
    nvlist_t *nvl);
void tpm_device_destroy(struct tpm_device *dev);

int init_tpm(struct vmctx *ctx);
bool tpm_device_present(void);
int tpm_device_state_begin_read(void);
int tpm_device_state_begin_write(void);
int tpm_device_state_end(void);
int tpm_device_state_end_if_active(void);
int tpm_device_state_get_blob(uint32_t type, uint8_t **blob,
    size_t *length, uint32_t *flags);
int tpm_device_state_set_blob(uint32_t type, const uint8_t *blob,
    size_t length, uint32_t flags);
int tpm_device_state_local_sizes(size_t *intf_size, size_t *ppi_size);
int tpm_device_state_get_local(uint8_t *intf, size_t intf_size,
    uint8_t *ppi, size_t ppi_size);
int tpm_device_state_validate_local(const uint8_t *intf, size_t intf_size,
    const uint8_t *ppi, size_t ppi_size);
int tpm_device_state_set_local(const uint8_t *intf, size_t intf_size,
    const uint8_t *ppi, size_t ppi_size);
#ifdef BHYVE_SNAPSHOT
#define TPM_SNAPSHOT_NAME "tpm"
#define TPM_MIGRATION_IDENTITY_SIZE 64U
#define TPM_MIGRATION_COMPAT_SCHEMA 3U
int tpm_device_migration_check(void);
int tpm_device_migration_identity(uint8_t
    identity[TPM_MIGRATION_IDENTITY_SIZE]);
int tpm_device_snapshot(struct vm_snapshot_meta *meta);
#endif
