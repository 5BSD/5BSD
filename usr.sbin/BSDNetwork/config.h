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
 * providers (bsdnotify's clients{}, traced's allow-list, bsdfilesystem's open_paths),
 * the provider owns its own policy table, keyed by the unforgeable switchboard
 * manifest label; switchboard itself stays policy-free and identity.rights is
 * consulted only for the SERVICE_RIGHTS_ADMIN bypass.
 *
 * The table is required at startup and is read through the delivered Config
 * directory descriptor, including for launches already in capability mode:
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
 * default. Unknown/duplicate/NUL-aliased keys, external includes and invalid
 * types reject the entire input. Production startup refuses unavailable or
 * rejected policy; it cannot silently restore outbound grants.
 */

#define	NETWORKCMP_CONFIG_NAME		"bsdnetwork.conf"
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
 * whole text is rejected, -1 is returned, and *config is cleared so normal
 * sessions receive no grants. Callers must handle the error before serving.
 */
int	networkcmp_config_parse(const char *, struct networkcmp_config *);

/*
 * Load the configuration from a file, with the same open-time hardening as the
 * sibling providers (O_NOFOLLOW, regular file, trusted owner, not group/other
 * writable, size cap). This optional-path API accepts an absent file as an
 * explicit request for defaults. Every other failure clears *config and
 * returns -1. Production startup uses the required delivered-fd path instead.
 */
int	networkcmp_config_load(struct networkcmp_config *, const char *);

/*
 * As networkcmp_config_load(), but from an already-open descriptor (which it
 * takes ownership of and closes). Reads from offset zero, rejects observed
 * length/metadata changes, and applies a fully validated candidate. Used with
 * service_config_open(3) so the
 * config is read via the switchboard-delivered Config directory descriptor,
 * needing no path lookup under capability mode.
 */
int	networkcmp_config_load_fd(struct networkcmp_config *, int fd);

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
