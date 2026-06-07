/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Internal interface between oracle_proto.c and
 * oracle_proto_claims.c.  Not for external use.
 */

#ifndef ORACLE_PROTO_CLAIMS_H
#define ORACLE_PROTO_CLAIMS_H

#include <stdint.h>

struct oracled_net_claim;
struct oracled_jail_claim;

/* Auto-claim helpers (called from mint handlers in oracle_proto.c). */
int	auto_claim_path(const char *path, int *errp);
int	auto_claim_net(const struct oracled_net_claim *nc, int *errp);
int	auto_claim_jail(const struct oracled_jail_claim *jc, int *errp);
int	auto_claim_system(uint32_t gates, int *errp);

/* Explicit claim/release handlers (called from dispatch switch). */
void	handle_claim_path(const void *payload, uint32_t len,
	    uint64_t reply_token);
void	handle_claim_net(const void *payload, uint32_t len,
	    uint64_t reply_token);
void	handle_claim_jail(const void *payload, uint32_t len,
	    uint64_t reply_token);
void	handle_claim_system(const void *payload, uint32_t len,
	    uint64_t reply_token);
void	handle_release_path(const void *payload, uint32_t len,
	    uint64_t reply_token);
void	handle_release_net(const void *payload, uint32_t len,
	    uint64_t reply_token);
void	handle_release_jail(const void *payload, uint32_t len,
	    uint64_t reply_token);
void	handle_release_system(const void *payload, uint32_t len,
	    uint64_t reply_token);

/* Sweep all dynamic claims (called on serviced exit). */
void	sweep_dynamic_claims(void);

/* Reply helper (defined in oracle_proto.c, used by claim handlers). */
int	proto_reply(int status, uint64_t reply_token, int *fds, int nfds);

#endif /* ORACLE_PROTO_CLAIMS_H */
