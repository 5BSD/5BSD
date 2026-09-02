/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Claim validation helpers.  Used by authority_proto.c (runtime minting)
 * to check whether a requested resource is covered by the authority's
 * claimed set.
 *
 * These operate on the global od.cfg and are intentionally kept as
 * static functions in a header so both translation units can use
 * them without cross-module linkage.
 */

#ifndef CLAIM_CHECK_H
#define CLAIM_CHECK_H

#include <sys/socket.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <dev/mac_capability/mac_capability_isolation_proto.h>

#include "authorityd.h"
#include "config.h"
#include "gates.h"

static inline bool
claim_net_addr_is_wildcard(const uint8_t addr[16])
{
	static const uint8_t zero_addr[16];

	return (memcmp(addr, zero_addr, sizeof(zero_addr)) == 0);
}

static inline uint8_t
claim_net_effective_prefix(int domain, uint8_t prefix)
{

	if (domain == AF_INET || domain == 0) {
		if (prefix == 0)
			return (128);
		if (prefix <= 32)
			return ((uint8_t)(96 + prefix));
		return (128);
	}
	return (prefix == 0 ? 128 : (prefix > 128 ? 128 : prefix));
}

static inline bool
claim_net_addr_prefix_match(const uint8_t a[16], const uint8_t b[16],
    uint8_t prefix)
{
	uint8_t full_bytes, rem_bits, mask;

	if (prefix >= 128)
		return (memcmp(a, b, 16) == 0);

	full_bytes = prefix / 8;
	rem_bits = prefix % 8;
	if (memcmp(a, b, full_bytes) != 0)
		return (false);
	if (rem_bits == 0)
		return (true);
	mask = (uint8_t)(0xff << (8 - rem_bits));
	return ((a[full_bytes] & mask) == (b[full_bytes] & mask));
}

static inline bool
claim_net_entry_covers(const struct ort_net_claim *claim,
    const struct ort_net_claim *req)
{

	if ((claim->direction & req->direction) != req->direction)
		return (false);
	if (claim->domain != 0 &&
	    (req->domain == 0 || claim->domain != req->domain))
		return (false);
	if (claim->protocol != 0 &&
	    (req->protocol == 0 || claim->protocol != req->protocol))
		return (false);
	if (claim->port_min > req->port_min ||
	    claim->port_max < req->port_max)
		return (false);
	if (claim_net_addr_is_wildcard(claim->addr))
		return (true);
	if (claim_net_addr_is_wildcard(req->addr))
		return (false);
	if (claim_net_effective_prefix(claim->domain, claim->prefix) >
	    claim_net_effective_prefix(req->domain, req->prefix))
		return (false);
	if (!claim_net_addr_prefix_match(claim->addr, req->addr,
	    claim_net_effective_prefix(claim->domain, claim->prefix)))
		return (false);
	return (true);
}

static inline bool
claim_net_covered(const struct authorityd_config *cfg,
    const struct ort_net_claim *req)
{
	unsigned i;

	for (i = 0; i < cfg->nclaim_net; i++) {
		if (claim_net_entry_covers(&cfg->claim_net[i], req))
			return (true);
	}
	return (false);
}

static inline int
claim_gate_name_to_bit(const char *name)
{
	unsigned int i;

	for (i = 0; i < sizeof(gate_names) / sizeof(gate_names[0]); i++) {
		if (strcmp(gate_names[i].name, name) == 0)
			return ((int)gate_names[i].gate);
	}
	return (0);
}

static inline bool
claim_system_covered(const struct authorityd_config *cfg, const char *gate_name)
{
	int bit;

	bit = claim_gate_name_to_bit(gate_name);
	if (bit == 0)
		return (false);
	return ((cfg->claim_system & (uint32_t)bit) != 0);
}

#endif /* CLAIM_CHECK_H */
