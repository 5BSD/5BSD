/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Dynamic claim/release handlers for the authority channel protocol.
 *
 * Split from authority_proto.c.  Contains auto-claim helpers (called
 * from mint handlers), explicit CLAIM/RELEASE handlers (dispatched
 * from authority_proto.c), find/remove array helpers, and the
 * sweep-on-serviced-exit logic.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <dev/mac_capability/mac_capability_isolation_proto.h>
#include <dev/mac_capability/mac_capability_system_proto.h>

#include <errno.h>
#include <string.h>
#include <syslog.h>

#include "authorityd.h"
#include "authorityd_svc_proto.h"
#include "mac_capability_priv.h"
#include "probes.h"
#include "authority_proto_claims.h"
#include "req_validate.h"

/* --- Find helpers --- */

static int
find_path_claim(const char *path)
{
	unsigned i;

	for (i = 0; i < od.cfg.nclaim_paths; i++) {
		if (strcmp(od.cfg.claim_paths[i], path) == 0)
			return ((int)i);
	}
	return (-1);
}

static int
find_net_claim(const struct ort_net_claim *nc)
{
	unsigned i;

	for (i = 0; i < od.cfg.nclaim_net; i++) {
		const struct ort_net_claim *c = &od.cfg.claim_net[i];

		if (c->domain == nc->domain &&
		    c->protocol == nc->protocol &&
		    c->port_min == nc->port_min &&
		    c->port_max == nc->port_max &&
		    c->direction == nc->direction &&
		    c->prefix == nc->prefix &&
		    memcmp(c->addr, nc->addr, sizeof(c->addr)) == 0)
			return ((int)i);
	}
	return (-1);
}

static int
find_jail_claim(const struct authorityd_jail_claim *jc)
{
	unsigned i;

	for (i = 0; i < od.cfg.nclaim_jail; i++) {
		const struct authorityd_jail_claim *c = &od.cfg.claim_jail[i];

		if (c->jid == jc->jid && c->actions == jc->actions &&
		    strcmp(c->name, jc->name) == 0)
			return ((int)i);
	}
	return (-1);
}

static int
find_vsock_claim(const struct ort_vsock_claim *vc)
{
	unsigned i;
	for (i = 0; i < od.cfg.nclaim_vsock; i++) {
		const struct ort_vsock_claim *c = &od.cfg.claim_vsock[i];
		if (c->cid == vc->cid && c->port_min == vc->port_min &&
		    c->port_max == vc->port_max && c->direction == vc->direction)
			return ((int)i);
	}
	return (-1);
}

/*
 * --- Remove helpers ---
 *
 * Each claim type stores data, source, and refcount in parallel
 * arrays.  Removal shifts all three with memmove and decrements
 * the count.  The bodies are identical across types.
 */
#define	DEFINE_REMOVE_CLAIM(type, data_arr, src_arr, ref_arr, count)	\
static void								\
remove_##type##_claim(unsigned idx)					\
{									\
	unsigned n;							\
									\
	n = od.cfg.count - 1;						\
	if (idx < n) {							\
		memmove(&od.cfg.data_arr[idx],				\
		    &od.cfg.data_arr[idx + 1],				\
		    (n - idx) * sizeof(od.cfg.data_arr[0]));		\
		memmove(&od.cfg.src_arr[idx],				\
		    &od.cfg.src_arr[idx + 1],				\
		    (n - idx) * sizeof(od.cfg.src_arr[0]));		\
		memmove(&od.cfg.ref_arr[idx],				\
		    &od.cfg.ref_arr[idx + 1],				\
		    (n - idx) * sizeof(od.cfg.ref_arr[0]));		\
	}								\
	od.cfg.count = n;						\
}

DEFINE_REMOVE_CLAIM(path, claim_paths, claim_path_source,
    claim_path_refcount, nclaim_paths)
DEFINE_REMOVE_CLAIM(net, claim_net, claim_net_source,
    claim_net_refcount, nclaim_net)
DEFINE_REMOVE_CLAIM(jail, claim_jail, claim_jail_source,
    claim_jail_refcount, nclaim_jail)
DEFINE_REMOVE_CLAIM(vsock, claim_vsock, claim_vsock_source,
    claim_vsock_refcount, nclaim_vsock)

/* --- Auto-claim helpers --- */

int
auto_claim_path(const char *path, int *errp)
{
	int idx;

	idx = find_path_claim(path);
	if (idx >= 0) {
		if (od.cfg.claim_path_source[idx] == CLAIM_SOURCE_SERVICE)
			od.cfg.claim_path_refcount[idx]++;
		return (0);
	}

	if (od.cfg.nclaim_paths >= AUTHORITYD_MAX_PATH_CLAIMS) {
		*errp = ENOSPC;
		return (-1);
	}
	if (mac_capability_claim_path(path) != 0) {
		*errp = EIO;
		return (-1);
	}

	idx = (int)od.cfg.nclaim_paths;
	strlcpy(od.cfg.claim_paths[idx], path, PATH_MAX);
	od.cfg.claim_path_source[idx] = CLAIM_SOURCE_SERVICE;
	od.cfg.claim_path_refcount[idx] = 1;
	od.cfg.nclaim_paths++;

	syslog(LOG_INFO, "authority_proto: auto-claimed %s", path);
	AUTHORITYD_PROBE_DYN_CLAIM_PATH(path, 0);
	return (0);
}

int
auto_claim_net(const struct ort_net_claim *nc, int *errp)
{
	int idx;

	idx = find_net_claim(nc);
	if (idx >= 0) {
		if (od.cfg.claim_net_source[idx] == CLAIM_SOURCE_SERVICE)
			od.cfg.claim_net_refcount[idx]++;
		return (0);
	}

	if (od.cfg.nclaim_net >= AUTHORITYD_MAX_NET_CLAIMS) {
		*errp = ENOSPC;
		return (-1);
	}
	if (mac_capability_claim_net(nc) != 0) {
		*errp = EIO;
		return (-1);
	}

	idx = (int)od.cfg.nclaim_net;
	od.cfg.claim_net[idx] = *nc;
	od.cfg.claim_net_source[idx] = CLAIM_SOURCE_SERVICE;
	od.cfg.claim_net_refcount[idx] = 1;
	od.cfg.nclaim_net++;

	syslog(LOG_INFO, "authority_proto: auto-claimed net %u-%u/%d",
	    nc->port_min, nc->port_max, nc->protocol);
	AUTHORITYD_PROBE_DYN_CLAIM_NET(nc->port_min, nc->port_max,
	    nc->protocol, 0);
	return (0);
}

int
auto_claim_jail(const struct authorityd_jail_claim *jc, int *errp)
{
	int idx;

	idx = find_jail_claim(jc);
	if (idx >= 0) {
		if (od.cfg.claim_jail_source[idx] == CLAIM_SOURCE_SERVICE)
			od.cfg.claim_jail_refcount[idx]++;
		return (0);
	}

	if (od.cfg.nclaim_jail >= AUTHORITYD_MAX_JAIL_CLAIMS) {
		*errp = ENOSPC;
		return (-1);
	}
	if (mac_capability_claim_jail(jc) != 0) {
		*errp = EIO;
		return (-1);
	}

	idx = (int)od.cfg.nclaim_jail;
	od.cfg.claim_jail[idx] = *jc;
	od.cfg.claim_jail_source[idx] = CLAIM_SOURCE_SERVICE;
	od.cfg.claim_jail_refcount[idx] = 1;
	od.cfg.nclaim_jail++;

	syslog(LOG_INFO, "authority_proto: auto-claimed jail %s", jc->name);
	AUTHORITYD_PROBE_DYN_CLAIM_JAIL(jc->name, jc->actions, 0);
	return (0);
}

int
auto_claim_vsock(const struct ort_vsock_claim *vc, int *errp)
{
	int idx = find_vsock_claim(vc);
	if (idx >= 0) {
		if (od.cfg.claim_vsock_source[idx] == CLAIM_SOURCE_SERVICE)
			od.cfg.claim_vsock_refcount[idx]++;
		return (0);
	}
	if (od.cfg.nclaim_vsock >= AUTHORITYD_MAX_VSOCK_CLAIMS) {
		*errp = ENOSPC;
		return (-1);
	}
	if (mac_capability_claim_vsock(vc) != 0) {
		*errp = EIO;
		return (-1);
	}
	idx = (int)od.cfg.nclaim_vsock++;
	od.cfg.claim_vsock[idx] = *vc;
	od.cfg.claim_vsock_source[idx] = CLAIM_SOURCE_SERVICE;
	od.cfg.claim_vsock_refcount[idx] = 1;
	AUTHORITYD_PROBE_DYN_CLAIM_VSOCK(vc->cid, vc->port_min, vc->port_max, 0);
	return (0);
}

int
auto_claim_system(uint32_t gates, int *errp)
{
	uint32_t new_bits;
	unsigned bit;

	new_bits = gates & ~od.cfg.claim_system;
	if (new_bits != 0) {
		if (mac_capability_claim_system_gate_bits(new_bits) != 0) {
			*errp = EIO;
			return (-1);
		}
		od.cfg.claim_system |= new_bits;
		od.cfg.claim_system_service |= new_bits;
	}

	for (bit = 0; bit < AUTHORITYD_SYSTEM_GATE_NBITS; bit++) {
		if (!(gates & (1U << bit)))
			continue;
		if (od.cfg.claim_system_policy & (1U << bit))
			continue;
		od.cfg.claim_system_refcount[bit]++;
	}

	if (new_bits != 0) {
		syslog(LOG_INFO,
		    "authority_proto: auto-claimed system gates 0x%x",
		    new_bits);
		AUTHORITYD_PROBE_DYN_CLAIM_SYSTEM(gates, 0);
	}
	return (0);
}

void
release_auto_claim_path(const char *path)
{
	uint32_t new_refcount;
	int idx;

	idx = find_path_claim(path);
	if (idx < 0 ||
	    od.cfg.claim_path_source[idx] != CLAIM_SOURCE_SERVICE ||
	    od.cfg.claim_path_refcount[idx] == 0)
		return;

	od.cfg.claim_path_refcount[idx]--;
	new_refcount = od.cfg.claim_path_refcount[idx];
	if (new_refcount == 0) {
		mac_capability_release_path(path);
		remove_path_claim((unsigned)idx);
	}
	AUTHORITYD_PROBE_DYN_RELEASE_PATH(path, new_refcount, 0);
}

void
release_auto_claim_net(const struct ort_net_claim *nc)
{
	uint32_t new_refcount;
	int idx;

	idx = find_net_claim(nc);
	if (idx < 0 ||
	    od.cfg.claim_net_source[idx] != CLAIM_SOURCE_SERVICE ||
	    od.cfg.claim_net_refcount[idx] == 0)
		return;

	od.cfg.claim_net_refcount[idx]--;
	new_refcount = od.cfg.claim_net_refcount[idx];
	if (new_refcount == 0) {
		mac_capability_release_net(&od.cfg.claim_net[idx]);
		remove_net_claim((unsigned)idx);
	}
	AUTHORITYD_PROBE_DYN_RELEASE_NET(nc->port_min, nc->port_max,
	    nc->protocol, new_refcount, 0);
}

void
release_auto_claim_jail(const struct authorityd_jail_claim *jc)
{
	uint32_t new_refcount;
	int idx;

	idx = find_jail_claim(jc);
	if (idx < 0 ||
	    od.cfg.claim_jail_source[idx] != CLAIM_SOURCE_SERVICE ||
	    od.cfg.claim_jail_refcount[idx] == 0)
		return;

	od.cfg.claim_jail_refcount[idx]--;
	new_refcount = od.cfg.claim_jail_refcount[idx];
	if (new_refcount == 0) {
		mac_capability_release_jail(&od.cfg.claim_jail[idx]);
		remove_jail_claim((unsigned)idx);
	}
	AUTHORITYD_PROBE_DYN_RELEASE_JAIL(jc->name, jc->actions, new_refcount, 0);
}

void
release_auto_claim_vsock(const struct ort_vsock_claim *vc)
{
	uint32_t new_refcount;
	int idx = find_vsock_claim(vc);
	if (idx < 0 || od.cfg.claim_vsock_source[idx] != CLAIM_SOURCE_SERVICE ||
	    od.cfg.claim_vsock_refcount[idx] == 0)
		return;
	new_refcount = --od.cfg.claim_vsock_refcount[idx];
	if (new_refcount == 0) {
		(void)mac_capability_release_vsock(&od.cfg.claim_vsock[idx]);
		remove_vsock_claim((unsigned)idx);
	}
	AUTHORITYD_PROBE_DYN_RELEASE_VSOCK(vc->cid, vc->port_min, vc->port_max,
	    new_refcount, 0);
}

void
release_auto_claim_system(uint32_t gates)
{
	uint32_t release_bits;
	unsigned bit;

	release_bits = 0;
	for (bit = 0; bit < AUTHORITYD_SYSTEM_GATE_NBITS; bit++) {
		if (!(gates & (1U << bit)))
			continue;
		if (od.cfg.claim_system_policy & (1U << bit))
			continue;
		if (!(od.cfg.claim_system_service & (1U << bit)))
			continue;
		if (od.cfg.claim_system_refcount[bit] == 0)
			continue;
		od.cfg.claim_system_refcount[bit]--;
		if (od.cfg.claim_system_refcount[bit] == 0)
			release_bits |= (1U << bit);
	}

	if (release_bits != 0) {
		mac_capability_release_system_gates(release_bits);
		od.cfg.claim_system &= ~release_bits;
		od.cfg.claim_system_service &= ~release_bits;
	}
	AUTHORITYD_PROBE_DYN_RELEASE_SYSTEM(gates, release_bits, 0);
}

/* --- Explicit claim handlers --- */

void
handle_claim_path(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct authority_path_req *req;
	int err;

	if (!validate_path_req(payload, len, &req, &err)) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	if (auto_claim_path(req->path, &err) != 0) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}
	proto_reply(0, reply_token, NULL, 0);
}

void
handle_claim_net(const void *payload, uint32_t len, uint64_t reply_token)
{
	struct ort_net_claim nc;
	int err;

	if (!validate_net_req(payload, len, &nc, &err)) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	if (auto_claim_net(&nc, &err) != 0) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}
	proto_reply(0, reply_token, NULL, 0);
}

void
handle_claim_jail(const void *payload, uint32_t len, uint64_t reply_token)
{
	struct authorityd_jail_claim jc;
	int err;

	if (!validate_jail_req(payload, len, &jc, &err)) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	if (auto_claim_jail(&jc, &err) != 0) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}
	proto_reply(0, reply_token, NULL, 0);
}

void
handle_claim_system(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct authority_system_req *req;
	int err;

	if (len != sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;

	if (req->gates == 0 || (req->gates & ~SYS_GATE_ALL) != 0) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}

	if (auto_claim_system(req->gates, &err) != 0) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}
	proto_reply(0, reply_token, NULL, 0);
}

void
handle_claim_vsock(const void *payload, uint32_t len, uint64_t reply_token)
{
	struct ort_vsock_claim vc;
	int err;
	if (!validate_vsock_req(payload, len, &vc, &err) ||
	    auto_claim_vsock(&vc, &err) != 0) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}
	proto_reply(0, reply_token, NULL, 0);
}

/* --- Release handlers --- */

void
handle_release_path(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct authority_path_req *req;
	int err, idx;

	if (!validate_path_req(payload, len, &req, &err)) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	idx = find_path_claim(req->path);
	if (idx < 0) {
		AUTHORITYD_PROBE_DYN_RELEASE_PATH(req->path, 0, ENOENT);
		proto_reply(ENOENT, reply_token, NULL, 0);
		return;
	}

	if (od.cfg.claim_path_source[idx] != CLAIM_SOURCE_SERVICE) {
		syslog(LOG_NOTICE,
		    "authority_proto: release_path denied (manifest): %s",
		    req->path);
		AUTHORITYD_PROBE_DYN_RELEASE_PATH(req->path, 0, EPERM);
		proto_reply(EPERM, reply_token, NULL, 0);
		return;
	}

	if (od.cfg.claim_path_refcount[idx] == 0) {
		syslog(LOG_WARNING,
		    "authority_proto: release_path %s refcount already 0",
		    req->path);
		AUTHORITYD_PROBE_DYN_RELEASE_PATH(req->path, 0, EINVAL);
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	od.cfg.claim_path_refcount[idx]--;
	{
		uint32_t new_refcount = od.cfg.claim_path_refcount[idx];

		if (new_refcount == 0) {
			mac_capability_release_path(req->path);
			syslog(LOG_INFO,
			    "authority_proto: released dynamic claim %s",
			    req->path);
			remove_path_claim((unsigned)idx);
		} else {
			syslog(LOG_DEBUG,
			    "authority_proto: release_path %s refcount=%u",
			    req->path, new_refcount);
		}

		AUTHORITYD_PROBE_DYN_RELEASE_PATH(req->path, new_refcount, 0);
	}
	proto_reply(0, reply_token, NULL, 0);
}

void
handle_release_net(const void *payload, uint32_t len, uint64_t reply_token)
{
	struct ort_net_claim nc;
	int err, idx;

	if (!validate_net_req(payload, len, &nc, &err)) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	idx = find_net_claim(&nc);
	if (idx < 0) {
		AUTHORITYD_PROBE_DYN_RELEASE_NET(nc.port_min, nc.port_max,
		    nc.protocol, 0, ENOENT);
		proto_reply(ENOENT, reply_token, NULL, 0);
		return;
	}

	if (od.cfg.claim_net_source[idx] != CLAIM_SOURCE_SERVICE) {
		AUTHORITYD_PROBE_DYN_RELEASE_NET(nc.port_min, nc.port_max,
		    nc.protocol, 0, EPERM);
		proto_reply(EPERM, reply_token, NULL, 0);
		return;
	}

	if (od.cfg.claim_net_refcount[idx] == 0) {
		syslog(LOG_WARNING,
		    "authority_proto: release_net refcount already 0");
		AUTHORITYD_PROBE_DYN_RELEASE_NET(nc.port_min, nc.port_max,
		    nc.protocol, 0, EINVAL);
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	od.cfg.claim_net_refcount[idx]--;
	{
		uint32_t new_refcount = od.cfg.claim_net_refcount[idx];

		if (new_refcount == 0) {
			mac_capability_release_net(&od.cfg.claim_net[idx]);
			syslog(LOG_INFO,
			    "authority_proto: released dynamic net claim %u-%u/%d",
			    nc.port_min, nc.port_max, nc.protocol);
			remove_net_claim((unsigned)idx);
		}

		AUTHORITYD_PROBE_DYN_RELEASE_NET(nc.port_min, nc.port_max,
		    nc.protocol, new_refcount, 0);
	}
	proto_reply(0, reply_token, NULL, 0);
}

void
handle_release_jail(const void *payload, uint32_t len, uint64_t reply_token)
{
	struct authorityd_jail_claim jc;
	int err, idx;

	if (!validate_jail_req(payload, len, &jc, &err)) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	idx = find_jail_claim(&jc);
	if (idx < 0) {
		AUTHORITYD_PROBE_DYN_RELEASE_JAIL(jc.name, jc.actions, 0, ENOENT);
		proto_reply(ENOENT, reply_token, NULL, 0);
		return;
	}

	if (od.cfg.claim_jail_source[idx] != CLAIM_SOURCE_SERVICE) {
		AUTHORITYD_PROBE_DYN_RELEASE_JAIL(jc.name, jc.actions, 0, EPERM);
		proto_reply(EPERM, reply_token, NULL, 0);
		return;
	}

	if (od.cfg.claim_jail_refcount[idx] == 0) {
		syslog(LOG_WARNING,
		    "authority_proto: release_jail %s refcount already 0",
		    jc.name);
		AUTHORITYD_PROBE_DYN_RELEASE_JAIL(jc.name, jc.actions, 0,
		    EINVAL);
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	od.cfg.claim_jail_refcount[idx]--;
	{
		uint32_t new_refcount = od.cfg.claim_jail_refcount[idx];

		if (new_refcount == 0) {
			mac_capability_release_jail(&od.cfg.claim_jail[idx]);
			syslog(LOG_INFO,
			    "authority_proto: released dynamic jail claim %s",
			    jc.name);
			remove_jail_claim((unsigned)idx);
		}

		AUTHORITYD_PROBE_DYN_RELEASE_JAIL(jc.name, jc.actions,
		    new_refcount, 0);
	}
	proto_reply(0, reply_token, NULL, 0);
}

void
handle_release_system(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct authority_system_req *req;
	uint32_t release_bits;
	unsigned bit;

	if (len != sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;

	if (req->gates == 0 || (req->gates & ~SYS_GATE_ALL) != 0) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}

	if (req->gates & od.cfg.claim_system_policy) {
		syslog(LOG_NOTICE,
		    "authority_proto: release_system denied (manifest): 0x%x",
		    req->gates);
		AUTHORITYD_PROBE_DYN_RELEASE_SYSTEM(req->gates, 0, EPERM);
		proto_reply(EPERM, reply_token, NULL, 0);
		return;
	}

	if ((req->gates & od.cfg.claim_system_service) != req->gates) {
		AUTHORITYD_PROBE_DYN_RELEASE_SYSTEM(req->gates, 0, ENOENT);
		proto_reply(ENOENT, reply_token, NULL, 0);
		return;
	}

	release_bits = 0;
	for (bit = 0; bit < AUTHORITYD_SYSTEM_GATE_NBITS; bit++) {
		if (!(req->gates & (1U << bit)))
			continue;
		if (od.cfg.claim_system_refcount[bit] == 0)
			continue;
		od.cfg.claim_system_refcount[bit]--;
		if (od.cfg.claim_system_refcount[bit] == 0)
			release_bits |= (1U << bit);
	}

	if (release_bits != 0) {
		mac_capability_release_system_gates(release_bits);
		od.cfg.claim_system &= ~release_bits;
		od.cfg.claim_system_service &= ~release_bits;
		syslog(LOG_INFO,
		    "authority_proto: released dynamic system gates 0x%x",
		    release_bits);
	}

	AUTHORITYD_PROBE_DYN_RELEASE_SYSTEM(req->gates, release_bits, 0);
	proto_reply(0, reply_token, NULL, 0);
}

void
handle_release_vsock(const void *payload, uint32_t len, uint64_t reply_token)
{
	struct ort_vsock_claim vc;
	int err, idx;
	if (!validate_vsock_req(payload, len, &vc, &err)) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}
	idx = find_vsock_claim(&vc);
	if (idx < 0) {
		AUTHORITYD_PROBE_DYN_RELEASE_VSOCK(vc.cid, vc.port_min, vc.port_max,
		    0, ENOENT);
		proto_reply(ENOENT, reply_token, NULL, 0);
		return;
	}
	if (od.cfg.claim_vsock_source[idx] != CLAIM_SOURCE_SERVICE) {
		AUTHORITYD_PROBE_DYN_RELEASE_VSOCK(vc.cid, vc.port_min, vc.port_max,
		    od.cfg.claim_vsock_refcount[idx], EPERM);
		proto_reply(EPERM, reply_token, NULL, 0);
		return;
	}
	release_auto_claim_vsock(&vc);
	proto_reply(0, reply_token, NULL, 0);
}

/* --- Sweep --- */

void
sweep_dynamic_claims(void)
{
	unsigned i;
	uint32_t release_gates;

	for (i = od.cfg.nclaim_paths; i > 0; i--) {
		if (od.cfg.claim_path_source[i - 1] == CLAIM_SOURCE_SERVICE) {
			mac_capability_release_path(od.cfg.claim_paths[i - 1]);
			syslog(LOG_INFO,
			    "authority_proto: sweep released path %s",
			    od.cfg.claim_paths[i - 1]);
			remove_path_claim(i - 1);
		}
	}

	for (i = od.cfg.nclaim_net; i > 0; i--) {
		if (od.cfg.claim_net_source[i - 1] == CLAIM_SOURCE_SERVICE) {
			mac_capability_release_net(&od.cfg.claim_net[i - 1]);
			syslog(LOG_INFO,
			    "authority_proto: sweep released net claim");
			remove_net_claim(i - 1);
		}
	}

	for (i = od.cfg.nclaim_jail; i > 0; i--) {
		if (od.cfg.claim_jail_source[i - 1] == CLAIM_SOURCE_SERVICE) {
			mac_capability_release_jail(&od.cfg.claim_jail[i - 1]);
			syslog(LOG_INFO,
			    "authority_proto: sweep released jail %s",
			    od.cfg.claim_jail[i - 1].name);
			remove_jail_claim(i - 1);
		}
	}
	for (i = od.cfg.nclaim_vsock; i > 0; i--) {
		if (od.cfg.claim_vsock_source[i - 1] == CLAIM_SOURCE_SERVICE) {
			(void)mac_capability_release_vsock(&od.cfg.claim_vsock[i - 1]);
			remove_vsock_claim(i - 1);
		}
	}

	release_gates = 0;
	for (i = 0; i < AUTHORITYD_SYSTEM_GATE_NBITS; i++) {
		if (od.cfg.claim_system_refcount[i] > 0 &&
		    !(od.cfg.claim_system_policy & (1U << i))) {
			release_gates |= (1U << i);
			od.cfg.claim_system_refcount[i] = 0;
		}
	}
	if (release_gates != 0) {
		mac_capability_release_system_gates(release_gates);
		od.cfg.claim_system &= ~release_gates;
		od.cfg.claim_system_service &= ~release_gates;
		syslog(LOG_INFO,
		    "authority_proto: sweep released system gates 0x%x",
		    release_gates);
	}
}
