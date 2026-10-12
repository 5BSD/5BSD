/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Resource-ownership identity for launched units and their client sessions.
 *
 * Two identities are stamped on each client connection.  The flat
 * "cap.<hex>" resource owner is a stable per-scope, per-label key providers use to name
 * their own per-owner resources (jails, keys, windows).  The container
 * "<bundle>/<unit>" is the connecting unit's place in the /Capabilities/Data
 * layout: a storage provider roots the unit's durable data at
 * Data/<bundle>/<unit>/ and the per-provider reconcile reaps it by comparing
 * the top-level bundle against the installed set (docs/capability-container-
 * model.md).  Nothing here consults a store or gates launch.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libcapbundle.h>

#include "switchboard.h"
#include "scope_storage.h"
#include "switchboard_svc_proto.h"
#include "identity_trace.h"

/*
 * Derive a stable, flat resource-ownership identity from the label alone.  The
 * owner key must be a single path component -- providers name a per-owner
 * container by it -- so it cannot carry the '/' a bundle label has
 * (system.Filesystem/bsdfilesystem).  Both the 16-byte id and the "cap.<hex>" owner
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

static void
svc_identity_scoped(const char *label, uid_t owner_uid,
    uint8_t id[SVC_IDENTITY_ID_SIZE], char *owner, size_t owner_size)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	char hex[33];
	if (owner_uid == (uid_t)-1) {
		svc_identity_from_label(label, id, owner, owner_size);
		return;
	}
	sb_personal_digest("resource", owner_uid, label, digest);
	memcpy(id, digest, SVC_IDENTITY_ID_SIZE);
	if (!svc_identity_id_nonzero(id)) id[0] = 1;
	svc_identity_id_format(id, hex);
	(void)snprintf(owner, owner_size, "cap.%s", hex);
}

/*
 * Derive the container path "<bundle>/<unit>" for a connecting client: the
 * installed bundle it belongs to (the top-level container the reconcile keys
 * on) and the unit within it.  Empty when the client has no bundle -- a user
 * session or an adopted rc unit -- which then holds no container storage.  For GLOBAL units the
 * bundle component is the install directory's basename with the ".cap" suffix
 * removed, exactly the form the reconcile reads back from System/ and Apps/;
 * the unit component is the leaf of the unit's label. Personal components
 * are broker-generated scoped digests so separate users cannot alias storage.
 */
static void
svc_container_from_client(struct svc_runtime *svc, char *out, size_t outsz)
{
	struct capbundle *b;
	const char *bname, *leaf;
	char bundle[64], unit_key[25];
	unsigned char digest[SHA256_DIGEST_LENGTH];
	size_t len;

	out[0] = '\0';
	if (svc == NULL || svc->bundle_idx == (unsigned)-1)
		return;
	b = bundle_registry_get(svc->bundle_idx);
	if (b == NULL || (bname = capbundle_name(b)) == NULL || bname[0] == '\0')
		return;
	if (svc->owner_uid != (uid_t)-1) {
		if (!sb_personal_storage_key("bundle", svc->owner_uid,
		    capbundle_id(b), bundle, sizeof(bundle)))
			return;
	} else
		(void)strlcpy(bundle, bname, sizeof(bundle));
	len = strlen(bundle);
	if (len > 4 && strcmp(bundle + len - 4, ".cap") == 0)
		bundle[len - 4] = '\0';			/* Foo.cap -> Foo */
	leaf = strrchr(svc->manifest.label, '/');
	leaf = leaf != NULL ? leaf + 1 : svc->manifest.label;
	if (svc->owner_uid != (uid_t)-1) {
		/* A full label may not fit after the scoped bundle key. Never
		 * truncate it: different unit names must not alias by prefix. */
		sb_personal_digest("unit", svc->owner_uid, leaf, digest);
		for (unsigned i = 0; i < 12; i++)
			(void)snprintf(unit_key + i * 2, 3, "%02x", digest[i]);
		leaf = unit_key;
	}
	if (bundle[0] == '\0' || leaf[0] == '\0' || strchr(bundle, '/') != NULL)
		return;					/* malformed: no container */
	if (snprintf(out, outsz, "%s/%s", bundle, leaf) >= (int)outsz)
		out[0] = '\0';
}

/*
 * The group containers the connecting client's bundle declares membership in
 * (Bundle.ucl `groups`), for the storage provider to authorize a
 * Data/Shared/<group>/ claim.  Empty slots are "".
 */
static void
svc_groups_from_client(struct svc_runtime *svc, char (*out)[64], unsigned n)
{
	struct capbundle *b;
	unsigned i, count;

	for (i = 0; i < n; i++)
		out[i][0] = '\0';
	if (svc == NULL || svc->bundle_idx == (unsigned)-1)
		return;
	b = bundle_registry_get(svc->bundle_idx);
	if (b == NULL)
		return;
	count = capbundle_ngroups(b);
	for (i = 0; i < count && i < n; i++) {
		if (svc->owner_uid != (uid_t)-1) {
			if (!sb_personal_storage_key("group", svc->owner_uid,
			    capbundle_group(b, i), out[i], 64)) out[i][0] = '\0';
		} else
			(void)strlcpy(out[i], capbundle_group(b, i), 64);
	}
}

int
svc_lifecycle_identity(struct svc_runtime *svc)
{
	svc_identity_scoped(svc->manifest.label, svc->owner_uid, svc->installation,
	    svc->resource_owner, sizeof(svc->resource_owner));
	svc_trace_identity("start", svc->manifest.label, svc->installation, 0);
	return (0);
}

int
svc_lifecycle_client(struct svc_runtime *svc, struct svc_runtime *provider,
    struct svc_new_client_msg *msg, uid_t sender_uid)
{
	const char *label = svc != NULL ? svc->manifest.label : msg->client_label;

	(void)provider;
	svc_identity_scoped(label, svc != NULL ? svc->owner_uid : sender_uid,
	    msg->generation, msg->resource_owner,
	    sizeof(msg->resource_owner));
	svc_container_from_client(svc, msg->container, sizeof(msg->container));
	svc_groups_from_client(svc, msg->groups, SVC_GROUPS_MAX);
	svc_trace_identity("session", label, msg->generation, 0);
	return (0);
}
