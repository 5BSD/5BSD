/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BSDNAMESPACE_TEST_H_
#define _BSDNAMESPACE_TEST_H_

#include <stdbool.h>
#include <stddef.h>

struct bsdnamespace_request;

/*
 * Test-only entrypoints exposing bsdnamespace(8)'s pure decision logic and its
 * per-client channel worker.  Compiled into bsdnamespace.c only under -DBSDNAMESPACE_TESTING
 * (see the guarded block in bsdnamespace.c); the shipped daemon never defines them.
 */

/* Injective jail-name derivation: SHA-256(label) -> "wj_"<hex>. */
bool	bsdnamespace_test_jail_name(const char *label, char *out, size_t outsz);

/* Request field/opcode/flag validation. */
bool	bsdnamespace_test_valid_request(const struct bsdnamespace_request *rq);

/* Serve one client on an already-connected provider channel fd. */
int	bsdnamespace_test_worker(int fd, const char *client);

/* Install a held SYS_GATE_JAIL token before running the worker (mint stand-in). */
void	bsdnamespace_test_set_jail_token(int fd);

#endif /* _BSDNAMESPACE_TEST_H_ */
