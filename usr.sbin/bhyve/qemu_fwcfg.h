/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#pragma once

#include <stdbool.h>

#include <vmmapi.h>

#define QEMU_FWCFG_MAX_ARCHS 0x2
#define QEMU_FWCFG_MAX_ENTRIES 0x4000
#define QEMU_FWCFG_MAX_NAME 56

#define QEMU_FWCFG_FILE_TABLE_LOADER "etc/table-loader"

struct qemu_fwcfg_item {
	uint32_t size;
	uint8_t *data;
};

int qemu_fwcfg_add_file(const char *name,
    const uint32_t size, void *const data);
int qemu_fwcfg_init(struct vmctx *const ctx);
int qemu_fwcfg_parse_cmdline_arg(const char *opt);
bool qemu_fwcfg_enabled(void);

#ifdef BHYVE_SNAPSHOT
struct pci_snapshot_compat;
struct vm_snapshot_meta;

int qemu_fwcfg_snapshot(struct vm_snapshot_meta *meta);
int qemu_fwcfg_snapshot_compat(struct pci_snapshot_compat *compat);
int qemu_fwcfg_snapshot_compat_record(const void *record, size_t record_size,
    struct pci_snapshot_compat *compat);
int qemu_fwcfg_migration_identity(uint32_t *identity);
#endif
