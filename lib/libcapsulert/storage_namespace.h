/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef STORAGE_NAMESPACE_H
#define STORAGE_NAMESPACE_H
#include <sys/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define STORAGE_NAMESPACE_GROUPS_MAX 4
#define STORAGE_NAMESPACE_PATH_MAX 256
#define STORAGE_NAMESPACE_SELECTION_MAX (1 + 2 * (2 + STORAGE_NAMESPACE_GROUPS_MAX))
#define STORAGE_NAMESPACE_SHARED_DIR "Shared"
#define STORAGE_NAMESPACE_STAGING_PREFIX "del-"
enum storage_namespace_kind { STORAGE_NAMESPACE_DURABLE, STORAGE_NAMESPACE_BOOT,
    STORAGE_NAMESPACE_LEASE };
struct storage_namespace_entry {
	enum storage_namespace_kind kind;
	char name[STORAGE_NAMESPACE_PATH_MAX];
};
struct storage_namespace_selection {
	size_t count;
	struct storage_namespace_entry entries[STORAGE_NAMESPACE_SELECTION_MAX];
};
/* Boot generation spelling is shared by the provider and manager. */
int storage_namespace_boot_name(char *, size_t);
bool storage_namespace_component_valid(const char *, size_t);
bool storage_namespace_claim_valid(const char *);
bool storage_namespace_version_name(const char *);
bool storage_namespace_owner(const char *, char *, size_t);
bool storage_namespace_container_valid(const char *);
bool storage_namespace_container(const char *, uint32_t, char *, size_t);
bool storage_namespace_scope(const char *, const char (*)[64], uint8_t,
    const char *, uint32_t, char *, size_t);
/* Fixed-width observed identity fields. Failure clears the entire output.
 * Results are relative names, not roots, object identities or access grants. */
int storage_namespace_select(const char [64], const char [64],
    const char [STORAGE_NAMESPACE_GROUPS_MAX][64], struct storage_namespace_selection *);
#endif
