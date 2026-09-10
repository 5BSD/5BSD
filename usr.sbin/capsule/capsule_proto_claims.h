/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Internal interface between capsule_proto.c and
 * capsule_proto_claims.c.  Not for external use.
 */

#ifndef CAPSULE_PROTO_CLAIMS_H
#define CAPSULE_PROTO_CLAIMS_H

#include <stdint.h>

struct ort_net_claim;
struct ort_vsock_claim;

/* Auto-claim helpers (called from mint handlers in capsule_proto.c). */
int	auto_claim_net(const struct ort_net_claim *nc, int *errp);
int	auto_claim_vsock(const struct ort_vsock_claim *vc, int *errp);
int	auto_claim_system(uint32_t gates, int *errp);
void	release_auto_claim_net(const struct ort_net_claim *nc);
void	release_auto_claim_vsock(const struct ort_vsock_claim *vc);
void	release_auto_claim_system(uint32_t gates);

/* Explicit claim/release handlers (called from dispatch switch). */
void	handle_claim_net(const void *payload, uint32_t len,
	    uint64_t reply_token);
void	handle_claim_system(const void *payload, uint32_t len,
	    uint64_t reply_token);
void	handle_claim_vsock(const void *payload, uint32_t len,
	    uint64_t reply_token);
void	handle_release_net(const void *payload, uint32_t len,
	    uint64_t reply_token);
void	handle_release_system(const void *payload, uint32_t len,
	    uint64_t reply_token);
void	handle_release_vsock(const void *payload, uint32_t len,
	    uint64_t reply_token);

/* Sweep all dynamic claims (called on switchboard exit). */
void	sweep_dynamic_claims(void);

/* Reply helper (defined in capsule_proto.c, used by claim handlers). */
int	proto_reply(int status, uint64_t reply_token, int *fds, int nfds);

#endif /* CAPSULE_PROTO_CLAIMS_H */
