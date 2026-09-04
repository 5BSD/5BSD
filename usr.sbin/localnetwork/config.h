/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _NETWORKCMP_CONFIG_H_
#define	_NETWORKCMP_CONFIG_H_

#include <stdbool.h>
#include <stddef.h>

#include "policy.h"

/*
 * Per-client (per-LABEL) network policy configuration (N1).  Like the sibling
 * providers (bsdnotify's clients{}, traced's allow-list, tzfsd's open_paths),
 * the provider owns its own policy table, keyed by the unforgeable serviced
 * manifest label; serviced itself stays policy-free and identity.rights is
 * consulted only for the SERVICE_RIGHTS_ADMIN bypass.
 *
 * The table is loaded once at startup, pre-capability-mode, from the unit's
 * Config directory ($CAPABILITY_UNIT_DIR/Config/localnetwork.conf):
 *
 *	default {
 *		resolve = true; connect = true; udp = true;
 *		inet4 = true; inet6 = true; internal = false;
 *	}
 *	clients {
 *		"some.label" { connect = false; }
 *	}
 *
 * `default` applies to any label without a clients{} entry.  A clients{} entry
 * names only the dimensions it overrides; unnamed dimensions inherit from
 * default.  The entry schema is closed (an unknown key is malformed), but the
 * FILE-level failure direction is FAIL-SOFT: a missing or malformed file
 * leaves the compiled-in default policy (today's non-admin grant: outbound
 * allowed, internal ranges denied) in force, because a bad config file must
 * not brick the network provider everything else depends on.
 */

#define	NETWORKCMP_CONFIG_NAME		"localnetwork.conf"
#define	NETWORKCMP_CONFIG_LABEL_MAX	63	/* service_identity label - NUL */
#define	NETWORKCMP_CONFIG_CLIENT_MAX	256
#define	NETWORKCMP_CONFIG_FILE_MAX	(64 * 1024)

struct networkcmp_config_client {
	char				label[NETWORKCMP_CONFIG_LABEL_MAX + 1];
	struct networkcmp_policy	policy;
};

struct networkcmp_config {
	/* Applies to any label without a clients{} entry. */
	struct networkcmp_policy	default_policy;
	struct networkcmp_config_client	clients[NETWORKCMP_CONFIG_CLIENT_MAX];
	size_t				nclients;
};

/*
 * The compiled-in configuration: no per-label entries, and a default policy
 * equal to the historical non-admin grant (resolve/connect/udp over v4+v6
 * permitted, internal destinations denied).
 */
void	networkcmp_config_defaults(struct networkcmp_config *);

/*
 * Parse a configuration text into *config.  Strict: on any schema violation
 * (unknown key, wrong type, invalid or duplicate label, too many entries) the
 * whole text is rejected, -1 is returned, and *config is reset to the
 * compiled-in defaults so a partial parse can never leak through.
 */
int	networkcmp_config_parse(const char *, struct networkcmp_config *);

/*
 * Load the configuration from a file, with the same open-time hardening as the
 * sibling providers (O_NOFOLLOW, regular file, trusted owner, not group/other
 * writable, size cap).  Fail-soft: a missing file is not an error (returns 0
 * with defaults); any other failure returns -1 with *config holding the
 * compiled-in defaults, and the caller logs and continues.
 */
int	networkcmp_config_load(struct networkcmp_config *, const char *);

/*
 * The policy for a label: its clients{} entry if listed, else the default.
 * *listed (optional) reports which.  Never returns NULL for a valid config.
 */
const struct networkcmp_policy *networkcmp_config_lookup(
	    const struct networkcmp_config *, const char *, bool *listed);

/*
 * Resolve the immutable session policy: SERVICE_RIGHTS_ADMIN bypasses the
 * table and receives the full policy (including internal reach); every other
 * session receives its label's config policy.  *source (optional) names the
 * decision origin: "admin", "label", or "default".
 */
int	networkcmp_config_session_policy(const struct networkcmp_config *,
	    const char *label, service_rights_t rights,
	    struct networkcmp_policy *, const char **source);

#endif
