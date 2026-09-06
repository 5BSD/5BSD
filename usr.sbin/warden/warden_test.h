/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _WARDEN_TEST_H_
#define _WARDEN_TEST_H_

#include <stdbool.h>
#include <stddef.h>

struct warden_request;

/*
 * Test-only entrypoints exposing warden(8)'s pure decision logic and its
 * per-client channel worker.  Compiled into warden.c only under -DWARDEN_TESTING
 * (see the guarded block in warden.c); the shipped daemon never defines them.
 */

/* Injective jail-name derivation: SHA-256(label) -> "wj_"<hex>. */
bool	warden_test_jail_name(const char *label, char *out, size_t outsz);

/* Request field/opcode/flag validation. */
bool	warden_test_valid_request(const struct warden_request *rq);

/* Strict decimal "desc" descriptor parsing (the strtol-validation fix). */
bool	warden_test_parse_desc(const char *desc, int *out_fd);

/* Serve one client on an already-connected provider channel fd. */
int	warden_test_worker(int fd, const char *client);

/*
 * Capability-cleanup reclaim (docs/capability-lifecycle-cleanup.md).
 *
 * warden_test_reclaim() drives the owner-scoped reclaim primitive for one label
 * (destroy that label's persistent jail); returns true iff a jail was removed.
 */
bool	warden_test_reclaim(const char *label);

#endif /* _WARDEN_TEST_H_ */
