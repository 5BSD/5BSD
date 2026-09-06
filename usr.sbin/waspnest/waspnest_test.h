/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Test-only interface (VMD_TESTING builds only) onto vmd(8)'s otherwise-private
 * accept-loop statics: the label->window ownership registry, its FNV hash,
 * request validation, backlog clamping, and the per-client request handler.
 * These wrap the production functions verbatim so unit and provider tests can
 * drive them deterministically; they exist only when vmd.c is compiled with
 * -DVMD_TESTING.
 */

#ifndef VMD_TEST_H
#define VMD_TEST_H

#include <stdbool.h>
#include <stdint.h>

#include "vmd_proto.h"

/* Zero the file-scope window-ownership registry (clean slate per test). */
void		vmd_test_registry_reset(void);

/* FNV-1a home-slot hash over a label. */
uint32_t	vmd_test_label_hash(const char *label);

/* Resolve (assigning on first contact) a label's exclusively-owned window. */
bool		vmd_test_resolve_window(const char *label, uint32_t *base_out);

/* Wire-request validation (op/_reserved/port-index bounds). */
bool		vmd_test_valid_request(const struct vmd_request *rq);

/* listen(2) backlog clamp (0 -> default, >SOMAXCONN -> SOMAXCONN). */
int		vmd_test_clamp_backlog(uint32_t backlog);

/* Serve one client on a provider channel built from fd, in this process. */
int		vmd_test_worker(int fd, const char *label, uint32_t window_base);

/*
 * Capability-cleanup reclaim of one label's window (the SVC_OP_RECLAIM_LABEL
 * push path).  Returns true iff a slot was freed; owner-scoped and idempotent.
 */
bool		vmd_test_reclaim(const char *label);

#endif /* VMD_TEST_H */
