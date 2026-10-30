/* SPDX-License-Identifier: BSD-2-Clause */
/* Shared logical namespace selection. Names alone confer no storage authority. */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/sysctl.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "storage_namespace.h"
#include "bsdfilesystem_proto.h"

int
storage_namespace_boot_name(char *out, size_t capacity)
{
	struct timeval boot;
	size_t size = sizeof(boot);
	int length;

	if (out == NULL || capacity == 0)
		return (errno = EINVAL, -1);
	out[0] = '\0';
	if (sysctlbyname("kern.boottime", &boot, &size, NULL, 0) == -1)
		return (-1);
	if (size != sizeof(boot) || boot.tv_sec < 0 || boot.tv_usec < 0 ||
	    boot.tv_usec >= 1000000)
		return (errno = EINVAL, -1);
	length = snprintf(out, capacity, "boot-%016jx-%08lx",
	    (uintmax_t)boot.tv_sec, (unsigned long)boot.tv_usec);
	if (length < 0 || (size_t)length >= capacity) {
		out[0] = '\0';
		return (errno = ENAMETOOLONG, -1);
	}
	return (0);
}

bool
storage_namespace_component_valid(const char *name, size_t capacity)
{
	size_t i, len;

	/*
	 * A claim or namespace component is a positive charset, not merely
	 * "no slash": ZFS gives a leading '@', '#' or '%' a meaning of its own
	 * (a snapshot, a bookmark, a receive placeholder -- of the PARENT, one
	 * level above the claim), and a leading '.' or '-' is a hazard to
	 * every tool that later names the dataset.  Everything else that ZFS
	 * accepts in a component is fine.
	 */
	if (name == NULL || capacity == 0)
		return (false);
	len = strnlen(name, capacity);
	if (len == 0 || len >= capacity)
		return (false);
	if (name[0] == '.' || name[0] == '-' || name[0] == '@' ||
	    name[0] == '#' || name[0] == '%')
		return (false);
	for (i = 0; i < len; i++) {
		char c = name[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		    c == '-' || c == ':'))
			return (false);
	}
	return (true);
}

bool
storage_namespace_version_name(const char *s)
{
	size_t i;

	if (s == NULL || s[0] != 'v')
		return (false);
	for (i = 1; s[i] != '\0'; i++)
		if (!isxdigit((unsigned char)s[i]))
			return (false);
	return (i >= 17);	/* 'v' + at least 16 hex digits */
}

/* Transaction staging names and version identifiers cannot name claims or groups. */
bool
storage_namespace_claim_valid(const char *name)
{
	if (!storage_namespace_component_valid(name, BSDFILESYSTEM_NAME_MAX))
		return (false);

	if (strncmp(name, STORAGE_NAMESPACE_STAGING_PREFIX,
	    sizeof(STORAGE_NAMESPACE_STAGING_PREFIX) - 1) == 0)
		return (false);
	if (storage_namespace_version_name(name))
		return (false);
	return (storage_namespace_component_valid(name, BSDFILESYSTEM_NAME_MAX));
}

bool
storage_namespace_owner(const char *client, char *out, size_t outsz)
{
	if (!storage_namespace_component_valid(client, BSDFILESYSTEM_NAME_MAX))
		return (false);
	if ((size_t)snprintf(out, outsz, "%s", client) >= outsz)
		return (false);
	return (true);
}

bool
storage_namespace_container_valid(const char *c)
{
	const char *slash;
	char comp[BSDFILESYSTEM_NAME_MAX];
	size_t n;

	if (c == NULL || (slash = strchr(c, '/')) == NULL || slash == c ||
	    slash[1] == '\0' || strchr(slash + 1, '/') != NULL)
		return (false);
	n = (size_t)(slash - c);
	if (n >= sizeof(comp))
		return (false);
	memcpy(comp, c, n);
	comp[n] = '\0';
	if (!storage_namespace_component_valid(comp, sizeof(comp)) ||
	    !storage_namespace_component_valid(slash + 1, BSDFILESYSTEM_NAME_MAX))
		return (false);
	/*
	 * Reserved: a bundle named "Shared" would alias Data/Shared/ -- the
	 * GROUP container root -- so its unit-scope claims would land in group
	 * containers with no membership check and be reaped by the group
	 * reconcile; a unit named "shared" would alias its bundle's SHARED
	 * scope.  Neither may exist as a container.
	 */
	if (strcasecmp(comp, STORAGE_NAMESPACE_SHARED_DIR) == 0 || strcasecmp(slash + 1, "shared") == 0)
		return (false);
	return (true);
}

bool
storage_namespace_container(const char *container, uint32_t lifetime, char *out, size_t outsz)
{
	const char *sub = lifetime == BSDFILESYSTEM_CACHE ? "cache" : "persistent";

	if ((lifetime != BSDFILESYSTEM_PERSISTENT && lifetime != BSDFILESYSTEM_CACHE) ||
	    !storage_namespace_container_valid(container))
		return (false);
	return ((size_t)snprintf(out, outsz, "%s/%s", container, sub) < outsz);
}

/* Relative durable layout: bundle/unit, bundle/shared, or Shared/declared-group.
 * Dataset roots come from authenticated policy, not these logical names. */
bool
storage_namespace_scope(const char *container, const char (*groups)[64], uint8_t scope,
    const char *group, uint32_t lifetime, char *out, size_t outsz)
{
	const char *sub = lifetime == BSDFILESYSTEM_CACHE ? "cache" : "persistent";
	const char *slash;
	size_t blen;
	unsigned i;

	if ((lifetime != BSDFILESYSTEM_PERSISTENT && lifetime != BSDFILESYSTEM_CACHE) ||
	    !storage_namespace_container_valid(container))
		return (false);
	switch (scope) {
	case BSDFILESYSTEM_SCOPE_UNIT:
		return (storage_namespace_container(container, lifetime, out, outsz));
	case BSDFILESYSTEM_SCOPE_SHARED:
		slash = strchr(container, '/');
		blen = (size_t)(slash - container);
		return ((size_t)snprintf(out, outsz, "%.*s/shared/%s", (int)blen,
		    container, sub) < outsz);
	case BSDFILESYSTEM_SCOPE_GROUP:
		if (group == NULL || group[0] == '\0' || groups == NULL ||
		    !storage_namespace_claim_valid(group))
			return (false);
		for (i = 0; i < STORAGE_NAMESPACE_GROUPS_MAX; i++)
			if (strnlen(groups[i], 64) < 64 && groups[i][0] != '\0' && strcmp(groups[i], group) == 0)
				break;
		if (i == STORAGE_NAMESPACE_GROUPS_MAX)
			return (false);			/* not a member */
		return ((size_t)snprintf(out, outsz, "Shared/%s/%s", group, sub) <
		    outsz);
	default:
		return (false);
	}
}

static int
selection_add(struct storage_namespace_selection *selection,
    enum storage_namespace_kind kind, const char *name)
{
	struct storage_namespace_entry *entry;

	for (size_t i = 0; i < selection->count; i++)
		if (selection->entries[i].kind == kind &&
		    strcmp(selection->entries[i].name, name) == 0)
			return (0);
	if (selection->count == STORAGE_NAMESPACE_SELECTION_MAX ||
	    strlen(name) >= sizeof(entry->name))
		return (errno = EOVERFLOW, -1);
	entry = &selection->entries[selection->count++];
	entry->kind = kind;
	strlcpy(entry->name, name, sizeof(entry->name));
	return (0);
}

int
storage_namespace_select(const char owner[64], const char container[64],
    const char groups[STORAGE_NAMESPACE_GROUPS_MAX][64],
    struct storage_namespace_selection *result)
{
	struct storage_namespace_selection selected = {0};
	char name[STORAGE_NAMESPACE_PATH_MAX];

	if (result == NULL)
		return (errno = EINVAL, -1);
	memset(result, 0, sizeof(*result));
	if (owner == NULL || container == NULL || groups == NULL ||
	    strnlen(owner, 64) == 64 || strnlen(container, 64) == 64 ||
	    !storage_namespace_owner(owner, name, sizeof(name)) ||
	    (container[0] != '\0' && !storage_namespace_container_valid(container)))
		return (errno = EINVAL, -1);
	for (size_t i = 0; i < STORAGE_NAMESPACE_GROUPS_MAX; i++)
		if (strnlen(groups[i], 64) == 64 ||
		    (groups[i][0] != '\0' && !storage_namespace_claim_valid(groups[i])))
			return (errno = EINVAL, -1);
	if (selection_add(&selected, STORAGE_NAMESPACE_BOOT, name) == -1)
		return (-1);
	if (container[0] != '\0') {
		for (uint32_t lifetime = BSDFILESYSTEM_PERSISTENT;
		    lifetime <= BSDFILESYSTEM_CACHE; lifetime++) {
			for (uint8_t scope = BSDFILESYSTEM_SCOPE_UNIT;
			    scope <= BSDFILESYSTEM_SCOPE_SHARED; scope++) {
				if (!storage_namespace_scope(container, groups, scope, "",
				    lifetime, name, sizeof(name)))
					return (errno = EINVAL, -1);
				if (selection_add(&selected, STORAGE_NAMESPACE_DURABLE, name) == -1)
					return (-1);
			}
			for (size_t i = 0; i < STORAGE_NAMESPACE_GROUPS_MAX; i++) {
				if (groups[i][0] == '\0')
					continue;
				if (!storage_namespace_scope(container, groups, BSDFILESYSTEM_SCOPE_GROUP,
				    groups[i], lifetime, name, sizeof(name)))
					return (errno = EINVAL, -1);
				if (selection_add(&selected, STORAGE_NAMESPACE_DURABLE, name) == -1)
					return (-1);
			}
		}
	}
	*result = selected;
	return (0);
}
