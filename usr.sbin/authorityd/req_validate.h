/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared request validation helpers.  Used by authority_proto.c
 * (mint handlers) and authority_proto_claims.c (claim/release
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
#include <ctype.h>
#include <stdint.h>
#include <string.h>

#include <authorityrt.h>
#include <dev/mac_capability/mac_capability_isolation_proto.h>	/* FI_JAIL_ALL */

#include "authorityd_svc_proto.h"
#include "config.h"

static inline bool
validate_kmod_req(const void *payload, uint32_t len,
    const struct authority_kmod_req **reqp, int *errp)
{
	const struct authority_kmod_req *req;
	size_t i, n;

	if (len != sizeof(*req)) {
		*errp = EINVAL;
		return (false);
	}
	req = payload;
	n = strnlen(req->name, sizeof(req->name));
	if (req->_pad != 0 || n == 0 || n == sizeof(req->name)) {
		*errp = EINVAL;
		return (false);
	}
	for (i = 0; i < n; i++) {
		if (isalnum((unsigned char)req->name[i]) ||
		    req->name[i] == '_' || req->name[i] == '-' ||
		    req->name[i] == '.')
			continue;
		*errp = EINVAL;
		return (false);
	}
	*reqp = req;
	return (true);
}

static inline bool
validate_service_req(const void *payload, uint32_t len,
    const struct authority_service_req **reqp, int *errp)
{
	const struct authority_service_req *req;

	if (len != sizeof(*req)) {
		*errp = EINVAL;
		return (false);
	}
	req = payload;
	if (req->_pad != 0 ||
	    memchr(req->name, '\0', sizeof(req->name)) == NULL ||
	    (strcmp(req->name, "mount") != 0 &&
	    strcmp(req->name, "node") != 0 &&
	    strcmp(req->name, "accounting") != 0 &&
	    strcmp(req->name, "identity") != 0)) {
		*errp = EINVAL;
		return (false);
	}
	*reqp = req;
	return (true);
}

/*
 * Validate an authority_path_req payload.  Returns true if the request
 * is well-formed, false otherwise.  On failure, *errp is set to the
 * appropriate errno (EINVAL or ENAMETOOLONG).
 */
static inline bool
validate_path_req(const void *payload, uint32_t len,
    const struct authority_path_req **reqp, int *errp)
{
	const struct authority_path_req *req;

	if (len != sizeof(*req)) {
		*errp = EINVAL;
		return (false);
	}
	req = payload;

	if (req->_pad != 0) {
		*errp = EINVAL;
		return (false);
	}
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
 * Validate an authority_net_req and populate an ort_net_claim.
 * Returns true on success, false on validation failure with
 * *errp set.
 */
static inline bool
validate_net_req(const void *payload, uint32_t len,
    struct ort_net_claim *nc, int *errp)
{
	const struct authority_net_req *req;

	if (len != sizeof(*req)) {
		*errp = EINVAL;
		return (false);
	}
	req = payload;

	if (req->_pad != 0 || req->_reserved[0] != 0 ||
	    req->_reserved[1] != 0 || req->direction == 0 ||
	    (req->direction & ~ORT_NET_DIR_ANY) != 0 ||
	    (req->domain != 0 && req->domain != AF_INET &&
	    req->domain != AF_INET6 && req->domain != AF_BLUETOOTH) ||
	    (req->protocol != 0 && req->protocol != IPPROTO_TCP &&
	    req->protocol != IPPROTO_UDP &&
	    req->protocol != ORT_BTPROTO_HCI &&
	    req->protocol != ORT_BTPROTO_L2CAP &&
	    req->protocol != ORT_BTPROTO_RFCOMM &&
	    req->protocol != ORT_BTPROTO_SCO &&
	    req->protocol != ORT_BTPROTO_ISO) ||
	    (req->domain == AF_BLUETOOTH &&
	    (req->protocol == IPPROTO_TCP || req->protocol == IPPROTO_UDP)) ||
	    (req->domain != 0 && req->domain != AF_BLUETOOTH &&
	    req->protocol != 0 && req->protocol != IPPROTO_TCP &&
	    req->protocol != IPPROTO_UDP) ||
	    req->prefix > 128 ||
	    (req->domain == AF_INET && req->prefix > 32) ||
	    (req->domain == AF_BLUETOOTH && req->prefix != 0 &&
	    req->prefix != 48) ||
	    (req->domain == 0 && (req->prefix != 0 ||
	    memcmp(req->addr, (const uint8_t[16]){ 0 }, 16) != 0)) ||
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
 * Validate an authority_jail_req and populate an authorityd_jail_claim.
 * Returns true on success, false on validation failure with
 * *errp set.
 */
static inline bool
validate_jail_req(const void *payload, uint32_t len,
    struct authorityd_jail_claim *jc, int *errp)
{
	const struct authority_jail_req *req;

	if (len != sizeof(*req)) {
		*errp = EINVAL;
		return (false);
	}
	req = payload;

	if (req->_pad != 0 || req->jid < 0 || req->actions == 0 ||
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

static inline bool
validate_vsock_req(const void *payload, uint32_t len,
    struct ort_vsock_claim *vc, int *errp)
{
	const struct authority_vsock_req *req;

	if (len != sizeof(*req)) {
		*errp = EINVAL;
		return (false);
	}
	req = payload;
	if (req->_pad != 0 ||
	    memcmp(req->_reserved, (const uint8_t[7]){ 0 }, 7) != 0 ||
	    req->port_min > req->port_max || req->direction == 0 ||
	    (req->direction & ~ORT_NET_DIR_ANY) != 0) {
		*errp = EINVAL;
		return (false);
	}
	vc->cid = req->cid;
	vc->port_min = req->port_min;
	vc->port_max = req->port_max;
	vc->direction = req->direction;
	return (true);
}

#endif /* REQ_VALIDATE_H */
