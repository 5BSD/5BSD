/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
#ifndef BLUED_DISCOVERY_H
#define BLUED_DISCOVERY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct blued_adapter;
struct blued_ctl_client;
struct ctl_scan_params;
struct ble_scan_result;

/* All discovery ownership changes run on the daemon's event-loop thread. */
int blued_discovery_start(struct blued_ctl_client *,
    const struct ctl_scan_params *);
void blued_discovery_cancel(int fd, bool reply);
void blued_discovery_abort(void);
bool blued_discovery_timer(uintptr_t);
void blued_discovery_report(struct blued_adapter *, const uint8_t *, size_t);
void blued_discovery_adapter_gone(struct blued_adapter *);
bool blued_discovery_busy(void);
/* Caller holds reslist_lock, including across pause, mutation and resume. */
bool blued_discovery_quiesce(struct blued_adapter *, bool resume);

/* Reply routing checks the client's generation before sending. */
void blued_ctl_scan_event(int, uint64_t, uint32_t,
    const struct blued_adapter *, const struct ble_scan_result *);
void blued_ctl_scan_done(int, uint64_t, uint32_t, uint16_t);

#endif
