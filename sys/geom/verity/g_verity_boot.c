/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/linker.h>
#include <sys/malloc.h>
#include <crypto/sha2/sha256.h>
#include <geom/verity/g_verity_transition.h>
#include <geom/verity/g_verity_provider.h>
#include <geom/verity/g_verity_verify.h>

/*
 * Decode exactly one loader descriptor before preload memory is reclaimed.
 * Caller must establish the authenticated loader/generation trust chain first.
 * A module type string is NOT proof of authenticity. This does not open storage,
 * construct a provider, or admit a root mount. No caller output changes on error.
 */
static int
verity_preload_copy(const char *wanted, void *output, size_t length)
{
	caddr_t module, selected, type;
	void *address;

	selected = NULL;
	module = NULL;
	while ((module = preload_search_next_name(module)) != NULL) {
		type = preload_search_info(module, MODINFO_TYPE);
		if (type == NULL || strcmp(type, wanted) != 0)
			continue;
		if (selected != NULL)
			return (EEXIST);
		selected = module;
	}
	if (selected == NULL)
		return (ENOENT);
	if (preload_fetch_size(selected) != length)
		return (EINVAL);
	address = preload_fetch_addr(selected);
	if (address == NULL || (uintptr_t)address > (uintptr_t)-1 - length)
		return (EINVAL);
	memcpy(output, address, length);
	return (0);
}

int
g_verity_preload_decode(struct g_verity_root *root)
{
	unsigned char wire[G_VERITY_ROOT_BYTES];
	int error;

	if (root == NULL)
		return (EINVAL);
	error = verity_preload_copy(G_VERITY_ROOT_TYPE, wire, sizeof(wire));
	if (error != 0)
		return (error);
	return (g_verity_root_decode(wire, sizeof(wire), root));
}

/*
 * Boot-only pair consistency, not release authentication or root admission.
 * Fixed scratch allocation avoids large nested kernel stack frames. No storage
 * is opened; publish caller outputs only after both snapshots and their binding
 * have been validated. Caller establishes the authenticated loader trust chain.
 */
int
g_verity_preload_transition(struct g_verity_transition *transition,
    struct g_verity_root *root)
{
	struct scratch {
		unsigned char plan_wire[G_VERITY_TRANSITION_BYTES];
		unsigned char root_wire[G_VERITY_ROOT_BYTES];
		struct g_verity_transition plan;
		struct g_verity_root root;
	} *scratch;
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256_CTX context;
	size_t per_worker;
	int error;

	if (transition == NULL || root == NULL)
		return (EINVAL);
	scratch = malloc(sizeof(*scratch), M_TEMP, M_WAITOK);
	error = verity_preload_copy(G_VERITY_TRANSITION_TYPE,
	    scratch->plan_wire, sizeof(scratch->plan_wire));
	if (error != 0)
		goto out;
	error = verity_preload_copy(G_VERITY_ROOT_TYPE,
	    scratch->root_wire, sizeof(scratch->root_wire));
	if (error != 0)
		goto out;
	error = g_verity_transition_decode(scratch->plan_wire,
	    sizeof(scratch->plan_wire), &scratch->plan);
	if (error != 0)
		goto out;
	error = g_verity_root_decode(scratch->root_wire,
	    sizeof(scratch->root_wire), &scratch->root);
	if (error != 0)
		goto out;
	SHA256_Init(&context);
	SHA256_Update(&context, scratch->root_wire, sizeof(scratch->root_wire));
	SHA256_Final(digest, &context);
	if (memcmp(digest, scratch->plan.descriptor_sha256, sizeof(digest)) != 0) {
		error = EAUTH;
		goto out;
	}
	error = g_verity_provider_resources(&scratch->root, scratch->plan.workers,
	    scratch->plan.cache_blocks, scratch->plan.window_bytes,
	    scratch->plan.buffer_bytes, &per_worker);
	if (error != 0)
		goto out;
	*transition = scratch->plan;
	*root = scratch->root;
out:
	free(scratch, M_TEMP);
	return (error);
}
