/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Resource-ownership identity for launched units and their client sessions.
 *
 * Ownership is keyed on the stable bundle label: the /Capabilities/Data layout
 * stores each capability's runtime data under a per-label container, so the
 * path is the ownership record and cleanup is structural, reaped by the
 * per-provider reconcile (docs/capability-container-model.md).  Nothing here
 * consults a store or gates launch; it only derives the flat owner key and the
 * 16-byte id switchboard hands to a unit and to each client connection.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "switchboard.h"
#include "switchboard_svc_proto.h"
#include "installation_trace.h"

/*
 * Derive a stable, flat resource-ownership identity from the label alone.  The
 * owner key must be a single path component -- providers name a per-owner
 * container by it -- so it cannot carry the '/' a bundle label has
 * (system.Filesystem/tzfsd).  Both the 16-byte id and the "cap.<hex>" owner
 * key are a deterministic function of the label, so they are stable across
 * boots and a label-keyed reconcile can recompute them.
 */
static void
svc_identity_from_label(const char *label,
    uint8_t id[SVC_IDENTITY_ID_SIZE], char *owner, size_t owner_size)
{
	uint64_t h1 = 1469598103934665603ULL, h2 = 1099511628211ULL;
	const unsigned char *p;

	for (p = (const unsigned char *)label; *p != '\0'; p++) {
		h1 = (h1 ^ *p) * 1099511628211ULL;
		h2 = (h2 + *p) * 1099511628211ULL;
	}
	memcpy(id, &h1, 8);
	memcpy((uint8_t *)id + 8, &h2, 8);
	if (!svc_identity_id_nonzero(id))
		id[0] = 1;			/* never all-zero */
	if (owner != NULL && owner_size > 0) {
		char hex[33];

		svc_identity_id_format(id, hex);
		(void)snprintf(owner, owner_size, "cap.%s", hex);
	}
}

int
svc_lifecycle_identity(struct svc_runtime *svc)
{
	svc_identity_from_label(svc->manifest.label, svc->installation,
	    svc->resource_owner, sizeof(svc->resource_owner));
	svc_trace_identity("start", svc->manifest.label, svc->installation, 0);
	return (0);
}

int
svc_lifecycle_client(struct svc_runtime *svc, struct svc_runtime *provider,
    struct svc_new_client_msg *msg)
{
	const char *label = svc != NULL ? svc->manifest.label : msg->client_label;

	(void)provider;
	svc_identity_from_label(label, msg->generation, msg->resource_owner,
	    sizeof(msg->resource_owner));
	svc_trace_identity("session", label, msg->generation, 0);
	return (0);
}
