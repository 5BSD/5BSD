/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared request validation helpers.  Used by oracle_proto.c
 * (mint handlers) and oracle_proto_claims.c (claim/release
 * handlers) to avoid triplicating field validation logic.
 *
 * These are static inline so both translation units can use
 * them without cross-module linkage, mirroring claim_check.h.
 */

#ifndef REQ_VALIDATE_H
#define REQ_VALIDATE_H

#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <oraclert.h>			/* ORT_NET_DIR_ANY */
#include <dev/mac_capability/mac_capability_isolation_proto.h>	/* FI_JAIL_ALL */

#include "oracled_svc_proto.h"

/*
 * Validate an oracle_path_req payload.  Returns true if the request
 * is well-formed, false otherwise.  On failure, *errp is set to the
 * appropriate errno (EINVAL or ENAMETOOLONG).
 */
static inline bool
validate_path_req(const void *payload, uint32_t len,
    const struct oracle_path_req **reqp, int *errp)
{
	const struct oracle_path_req *req;

	if (len < sizeof(*req)) {
		*errp = EINVAL;
		return (false);
	}
	req = payload;

	if (strnlen(req->path, PATH_MAX) >= PATH_MAX) {
		*errp = ENAMETOOLONG;
		return (false);
	}
	if (req->path[0] != '/') {
		*errp = EINVAL;
		return (false);
	}

	*reqp = req;
	return (true);
}

/*
 * Validate an oracle_net_req and populate an ort_net_claim.
 * Returns true on success, false on validation failure with
 * *errp set.
 */
static inline bool
validate_net_req(const void *payload, uint32_t len,
    struct ort_net_claim *nc, int *errp)
{
	const struct oracle_net_req *req;

	if (len < sizeof(*req)) {
		*errp = EINVAL;
		return (false);
	}
	req = payload;

	if (req->direction == 0 || (req->direction & ~ORT_NET_DIR_ANY) != 0 ||
	    (req->domain != 0 && req->domain != AF_INET &&
	    req->domain != AF_INET6) ||
	    (req->protocol != 0 && req->protocol != IPPROTO_TCP &&
	    req->protocol != IPPROTO_UDP) ||
	    req->prefix > 128 ||
	    (req->domain == AF_INET && req->prefix > 32) ||
	    req->port_min > req->port_max) {
		*errp = EINVAL;
		return (false);
	}

	memset(nc, 0, sizeof(*nc));
	nc->domain = req->domain;
	nc->protocol = req->protocol;
	nc->port_min = req->port_min;
	nc->port_max = req->port_max;
	nc->direction = req->direction;
	nc->prefix = req->prefix;
	memcpy(nc->addr, req->addr, sizeof(nc->addr));
	return (true);
}

/*
 * Validate an oracle_jail_req and populate an oracled_jail_claim.
 * Returns true on success, false on validation failure with
 * *errp set.
 */
static inline bool
validate_jail_req(const void *payload, uint32_t len,
    struct oracled_jail_claim *jc, int *errp)
{
	const struct oracle_jail_req *req;

	if (len < sizeof(*req)) {
		*errp = EINVAL;
		return (false);
	}
	req = payload;

	if (req->jid < 0 || req->actions == 0 ||
	    (req->actions & ~FI_JAIL_ALL) != 0) {
		*errp = EINVAL;
		return (false);
	}
	if (memchr(req->name, '\0', sizeof(req->name)) == NULL) {
		*errp = ENAMETOOLONG;
		return (false);
	}
	if (req->jid == 0 && req->name[0] == '\0') {
		*errp = EINVAL;
		return (false);
	}

	memset(jc, 0, sizeof(*jc));
	jc->jid = req->jid;
	jc->actions = req->actions;
	strlcpy(jc->name, req->name, sizeof(jc->name));
	return (true);
}

#endif /* REQ_VALIDATE_H */
