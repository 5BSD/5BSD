/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * MAC_CAPABILITY reload orchestration for authorityd.
 *
 * Handles reconciling old and new claim sets during a
 * configuration reload: acquire new claims, release stale ones,
 * and build an effective config reflecting kernel ground truth.
 */

#include <sys/param.h>

#include <dev/mac_capability/mac_capability_system_proto.h>

#include <string.h>
#include <syslog.h>

#include "authorityd.h"
#include "authorityd_svc_proto.h"
#include "probes.h"
#include "mac_capability_priv.h"

/* --- Static helpers for set membership --- */

static bool
net_claim_eq(const struct ort_net_claim *a,
    const struct ort_net_claim *b)
{

	return (a->domain == b->domain &&
	    a->protocol == b->protocol &&
	    a->port_min == b->port_min &&
	    a->port_max == b->port_max &&
	    a->direction == b->direction &&
	    a->prefix == b->prefix &&
	    memcmp(a->addr, b->addr, sizeof(a->addr)) == 0);
}

static bool
net_claim_in(const struct ort_net_claim *needle,
    const struct ort_net_claim *haystack, unsigned nhaystack)
{
	unsigned i;

	for (i = 0; i < nhaystack; i++) {
		if (net_claim_eq(needle, &haystack[i]))
			return (true);
	}
	return (false);
}

static bool
jail_claim_eq(const struct authorityd_jail_claim *a,
    const struct authorityd_jail_claim *b)
{

	return (a->jid == b->jid && a->actions == b->actions &&
	    strcmp(a->name, b->name) == 0);
}

static bool
jail_claim_in(const struct authorityd_jail_claim *needle,
    const struct authorityd_jail_claim *haystack, unsigned nhaystack)
{
	unsigned i;

	for (i = 0; i < nhaystack; i++) {
		if (jail_claim_eq(needle, &haystack[i]))
			return (true);
	}
	return (false);
}

static bool
path_in(const char *path, const char paths[][PATH_MAX], unsigned npaths)
{
	unsigned i;

	for (i = 0; i < npaths; i++) {
		if (strcmp(path, paths[i]) == 0)
			return (true);
	}
	return (false);
}

/*
 * Reload resource claims and build an effective config reflecting
 * what the kernel actually holds.  Acquire new claims first, then
 * release old claims no longer needed.
 *
 * The effective config (written to *effective) reflects ground truth:
 * - Claims that were successfully acquired are included
 * - Claims that failed to acquire are excluded (old claim kept if it
 *   existed, otherwise not present)
 * - Claims that failed to release remain in the effective config
 *
 * The caller should use the effective config to update od.cfg so
 * status reports match kernel state.
 *
 * Integrity flags are a one-way latch and not modified here.
 */
int
mac_capability_reload_claims(const struct authorityd_config *newcfg)
{
	const struct authorityd_config *oldcfg;
	unsigned i;
	unsigned nacquire, nrelease;
	int acquired, released, failed;
	bool path_ok[AUTHORITYD_MAX_PATH_CLAIMS];
	bool net_ok[AUTHORITYD_MAX_NET_CLAIMS];
	bool jail_ok[AUTHORITYD_MAX_JAIL_CLAIMS];
	uint32_t gates_acquired, gates_released;

	oldcfg = &od.cfg;
	acquired = released = failed = 0;
	gates_acquired = 0;
	gates_released = 0;

	if (mac_capability_isolation_fd == -1 && mac_capability_system_fd == -1) {
		syslog(LOG_WARNING, "reload: mac_capability not available, "
		    "skipping claims update");
		return (0);
	}

	/* Pre-compute acquire/release counts for the start probe. */
	nacquire = nrelease = 0;
	for (i = 0; i < newcfg->nclaim_paths; i++) {
		if (!path_in(newcfg->claim_paths[i],
		    oldcfg->claim_paths, oldcfg->nclaim_paths))
			nacquire++;
	}
	for (i = 0; i < newcfg->nclaim_net; i++) {
		if (!net_claim_in(&newcfg->claim_net[i],
		    oldcfg->claim_net, oldcfg->nclaim_net))
			nacquire++;
	}
	for (i = 0; i < newcfg->nclaim_jail; i++) {
		if (!jail_claim_in(&newcfg->claim_jail[i],
		    oldcfg->claim_jail, oldcfg->nclaim_jail))
			nacquire++;
	}
	if (newcfg->claim_system != oldcfg->claim_system &&
	    (newcfg->claim_system & ~oldcfg->claim_system) != 0)
		nacquire++;
	for (i = 0; i < oldcfg->nclaim_paths; i++) {
		if (!path_in(oldcfg->claim_paths[i],
		    newcfg->claim_paths, newcfg->nclaim_paths))
			nrelease++;
	}
	for (i = 0; i < oldcfg->nclaim_net; i++) {
		if (!net_claim_in(&oldcfg->claim_net[i],
		    newcfg->claim_net, newcfg->nclaim_net))
			nrelease++;
	}
	for (i = 0; i < oldcfg->nclaim_jail; i++) {
		if (!jail_claim_in(&oldcfg->claim_jail[i],
		    newcfg->claim_jail, newcfg->nclaim_jail))
			nrelease++;
	}
	if (newcfg->claim_system != oldcfg->claim_system &&
	    (oldcfg->claim_system & ~newcfg->claim_system) != 0)
		nrelease++;
	AUTHORITYD_PROBE_RELOAD_CLAIMS_START(nacquire, nrelease);

	/* Track which new claims succeed. */
	for (i = 0; i < newcfg->nclaim_paths; i++)
		path_ok[i] = true;
	for (i = 0; i < newcfg->nclaim_net; i++)
		net_ok[i] = true;
	for (i = 0; i < newcfg->nclaim_jail; i++)
		jail_ok[i] = true;

	/*
	 * Phase 1: Acquire new path claims.
	 */
	for (i = 0; i < newcfg->nclaim_paths; i++) {
		if (!path_in(newcfg->claim_paths[i],
		    oldcfg->claim_paths, oldcfg->nclaim_paths)) {
			if (mac_capability_claim_path(newcfg->claim_paths[i]) == 0) {
				acquired++;
			} else {
				path_ok[i] = false;
				failed++;
			}
		}
	}

	/*
	 * Phase 2: Acquire new network claims.
	 */
	for (i = 0; i < newcfg->nclaim_net; i++) {
		if (!net_claim_in(&newcfg->claim_net[i],
		    oldcfg->claim_net, oldcfg->nclaim_net)) {
			if (mac_capability_claim_net(&newcfg->claim_net[i]) == 0) {
				acquired++;
			} else {
				net_ok[i] = false;
				failed++;
			}
		}
	}

	/*
	 * Phase 3: Acquire new jail claims.
	 */
	for (i = 0; i < newcfg->nclaim_jail; i++) {
		if (!jail_claim_in(&newcfg->claim_jail[i],
		    oldcfg->claim_jail, oldcfg->nclaim_jail)) {
			if (mac_capability_claim_jail(&newcfg->claim_jail[i]) == 0) {
				acquired++;
			} else {
				jail_ok[i] = false;
				failed++;
			}
		}
	}

	/*
	 * Phase 4: Acquire new system gates.
	 */
	if (newcfg->claim_system != oldcfg->claim_system) {
		uint32_t new_gates;

		new_gates = newcfg->claim_system & ~oldcfg->claim_system;
		if (new_gates != 0 && mac_capability_system_fd != -1) {
			struct sys_request req;

			memset(&req, 0, sizeof(req));
			req.op = SYS_OP_CLAIM;
			req.gates = new_gates;
			if (mac_capability_do_call(mac_capability_system_fd, &req,
			    sizeof(req), NULL, 0) == -1) {
				syslog(LOG_WARNING,
				    "reload: claim new gates 0x%x: %m",
				    new_gates);
				failed++;
			} else {
				syslog(LOG_INFO,
				    "reload: claimed new gates 0x%x",
				    new_gates);
				gates_acquired = new_gates;
				acquired++;
			}
		}
	}

	/*
	 * Phase 5: Release old path claims no longer in config.
	 */
	for (i = 0; i < oldcfg->nclaim_paths; i++) {
		if (!path_in(oldcfg->claim_paths[i],
		    newcfg->claim_paths, newcfg->nclaim_paths)) {
			if (mac_capability_release_path(oldcfg->claim_paths[i]) == 0)
				released++;
			else
				failed++;
		}
	}

	/*
	 * Phase 6: Release old network claims no longer in config.
	 */
	for (i = 0; i < oldcfg->nclaim_net; i++) {
		if (!net_claim_in(&oldcfg->claim_net[i],
		    newcfg->claim_net, newcfg->nclaim_net)) {
			if (mac_capability_release_net(&oldcfg->claim_net[i]) == 0)
				released++;
			else
				failed++;
		}
	}

	/*
	 * Phase 7: Release old jail claims no longer in config.
	 */
	for (i = 0; i < oldcfg->nclaim_jail; i++) {
		if (!jail_claim_in(&oldcfg->claim_jail[i],
		    newcfg->claim_jail, newcfg->nclaim_jail)) {
			if (mac_capability_release_jail(&oldcfg->claim_jail[i]) == 0)
				released++;
			else
				failed++;
		}
	}

	/*
	 * Phase 8: Release old system gates no longer in config.
	 */
	if (newcfg->claim_system != oldcfg->claim_system) {
		uint32_t old_gates;

		old_gates = oldcfg->claim_system & ~newcfg->claim_system;
		if (old_gates != 0) {
			if (mac_capability_release_system_gates(old_gates) == 0) {
				gates_released = old_gates;
				released++;
			} else {
				failed++;
			}
		}
	}

	/*
	 * Phase 9: Build effective config — only include claims that
	 * are actually held by the kernel.  This is written back to
	 * the newcfg struct (which the caller passes to
	 * config_apply_claims).
	 *
	 * Dynamic claims (CLAIM_SOURCE_SERVICE) from the old config
	 * are carried forward — they persist across reloads.  If a
	 * previously-dynamic claim now appears in the manifest, it is
	 * upgraded to CLAIM_SOURCE_POLICY (immortal).
	 */
	{
		struct authorityd_config *eff;
		unsigned n;

		/*
		 * Cast away const — the caller owns this struct and
		 * expects us to adjust it to reflect ground truth.
		 */
		eff = __DECONST(struct authorityd_config *, newcfg);

		/* Paths: keep successful policy claims. */
		n = 0;
		for (i = 0; i < newcfg->nclaim_paths; i++) {
			if (path_ok[i]) {
				if (n != i)
					strlcpy(eff->claim_paths[n],
					    newcfg->claim_paths[i], PATH_MAX);
				eff->claim_path_source[n] = CLAIM_SOURCE_POLICY;
				eff->claim_path_refcount[n] = 0;
				n++;
			} else {
				syslog(LOG_WARNING, "reload: dropping failed "
				    "claim %s from effective config",
				    newcfg->claim_paths[i]);
			}
		}
		/*
		 * Carry forward dynamic claims from the old config.
		 * Skip entries already covered by the new manifest.
		 */
#define	CARRY_FORWARD(arr, src, rc, nold, in_fn, max)	do {	\
	for (i = 0; i < (nold); i++) {				\
		if (oldcfg->src[i] != CLAIM_SOURCE_SERVICE)	\
			continue;				\
		if (in_fn(&oldcfg->arr[i], eff->arr, n))	\
			continue;				\
		if (n >= (max)) {				\
			syslog(LOG_WARNING,			\
			    "reload: dynamic claim table full, "	\
			    "dropping orphaned claims");		\
			break;					\
		}						\
		eff->arr[n] = oldcfg->arr[i];			\
		eff->src[n] = CLAIM_SOURCE_SERVICE;		\
		eff->rc[n] = oldcfg->rc[i];			\
		n++;						\
	}							\
} while (0)

		/* Paths: path_in has a different signature, keep inline. */
		for (i = 0; i < oldcfg->nclaim_paths; i++) {
			if (oldcfg->claim_path_source[i] !=
			    CLAIM_SOURCE_SERVICE)
				continue;
			if (path_in(oldcfg->claim_paths[i],
			    eff->claim_paths, n))
				continue;
			if (n >= AUTHORITYD_MAX_PATH_CLAIMS) {
				syslog(LOG_WARNING,
				    "reload: path claim table full, "
				    "dropping orphaned dynamic claims");
				break;
			}
			strlcpy(eff->claim_paths[n],
			    oldcfg->claim_paths[i], PATH_MAX);
			eff->claim_path_source[n] = CLAIM_SOURCE_SERVICE;
			eff->claim_path_refcount[n] =
			    oldcfg->claim_path_refcount[i];
			n++;
		}
		eff->nclaim_paths = n;

		/* Network: keep successful policy claims. */
		n = 0;
		for (i = 0; i < newcfg->nclaim_net; i++) {
			if (net_ok[i]) {
				if (n != i)
					eff->claim_net[n] = newcfg->claim_net[i];
				eff->claim_net_source[n] = CLAIM_SOURCE_POLICY;
				eff->claim_net_refcount[n] = 0;
				n++;
			} else {
				syslog(LOG_WARNING, "reload: dropping failed "
				    "net claim from effective config");
			}
		}
		CARRY_FORWARD(claim_net, claim_net_source,
		    claim_net_refcount, oldcfg->nclaim_net,
		    net_claim_in, AUTHORITYD_MAX_NET_CLAIMS);
		eff->nclaim_net = n;

		/* Jails: keep successful policy claims. */
		n = 0;
		for (i = 0; i < newcfg->nclaim_jail; i++) {
			if (jail_ok[i]) {
				if (n != i)
					eff->claim_jail[n] =
					    newcfg->claim_jail[i];
				eff->claim_jail_source[n] = CLAIM_SOURCE_POLICY;
				eff->claim_jail_refcount[n] = 0;
				n++;
			} else {
				syslog(LOG_WARNING, "reload: dropping failed "
				    "jail claim from effective config");
			}
		}
		CARRY_FORWARD(claim_jail, claim_jail_source,
		    claim_jail_refcount, oldcfg->nclaim_jail,
		    jail_claim_in, AUTHORITYD_MAX_JAIL_CLAIMS);
		eff->nclaim_jail = n;

		/* VSOCK currently has service-manifest dynamic claims only. */
		n = 0;
		for (i = 0; i < oldcfg->nclaim_vsock &&
		    n < AUTHORITYD_MAX_VSOCK_CLAIMS; i++) {
			if (oldcfg->claim_vsock_source[i] != CLAIM_SOURCE_SERVICE)
				continue;
			eff->claim_vsock[n] = oldcfg->claim_vsock[i];
			eff->claim_vsock_source[n] = CLAIM_SOURCE_SERVICE;
			eff->claim_vsock_refcount[n] =
			    oldcfg->claim_vsock_refcount[i];
			n++;
		}
		eff->nclaim_vsock = n;

#undef CARRY_FORWARD

		/* System gates: add only what was acquired, remove only
		 * what was released.  Preserve dynamic refcounts for
		 * service-owned gates that remain service-owned. */
		eff->claim_system = oldcfg->claim_system;
		eff->claim_system |= gates_acquired;
		eff->claim_system &= ~gates_released;
		eff->claim_system_policy = newcfg->claim_system_policy;
		eff->claim_system_service = oldcfg->claim_system_service;
		eff->claim_system_service &= ~gates_released;
		eff->claim_system_service &= ~eff->claim_system_policy;
		memcpy(eff->claim_system_refcount,
		    oldcfg->claim_system_refcount,
		    sizeof(eff->claim_system_refcount));
		for (i = 0; i < AUTHORITYD_SYSTEM_GATE_NBITS; i++) {
			if ((gates_released | eff->claim_system_policy) &
			    (1U << i))
				eff->claim_system_refcount[i] = 0;
		}
	}

	syslog(LOG_INFO, "reload: claims %d acquired, %d released, %d failed",
	    acquired, released, failed);
	AUTHORITYD_PROBE_RELOAD_CLAIMS_DONE(acquired, released, failed);
	return (failed > 0 ? -1 : 0);
}
