/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BHYVE_MIGRATION_TLS_H_
#define _BHYVE_MIGRATION_TLS_H_
#include "migration_session.h"
#include "migration_credentials.h"

struct migration_tls {
	struct ssl_ctx_st *context;
	struct ssl_st *ssl;
	int fd, original_flags, timeout_ms;
	uint8_t local_certificate_sha256[32];
	uint8_t peer_certificate_sha256[32];
};
/* Borrows all descriptors; does not connect/listen or load path-based files.
 * No transport is published until TLS 1.3 mutual verification and peer pin
 * checks complete. Each handshake/transfer has a monotonic deadline. */
int migration_tls_init(struct migration_tls *, struct migration_transport *,
    int, bool, const struct migration_tls_credentials *, int);
void migration_tls_cleanup(struct migration_tls *);
#endif
