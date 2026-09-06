/*- SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include "cryptodesc.h"

static int
named_identifier(const char *value, size_t maxlen)
{
	size_t i, length;

	if (value == NULL)
		return (0);
	length = strnlen(value, maxlen);
	if (length == 0 || length == maxlen)
		return (0);
	for (i = 0; i < length; i++) {
		if (!((value[i] >= 'a' && value[i] <= 'z') ||
		    (value[i] >= 'A' && value[i] <= 'Z') ||
		    (value[i] >= '0' && value[i] <= '9') ||
		    value[i] == '.' || value[i] == '_' || value[i] == '-'))
			return (0);
	}
	return (1);
}

int
cryptodesc_mint(int control_fd, const struct session2_op *session,
    uint32_t rights, int *descriptor_fd)
{
	struct cryptodesc_create create;

	if (control_fd < 0 || session == NULL || descriptor_fd == NULL ||
	    rights == 0 || (rights & ~CRYPTODESC_RIGHT_ALL) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(&create, 0, sizeof(create));
	create.session = *session;
	create.cd_rights = rights;
	create.cd_fd = -1;
	if (ioctl(control_fd, CIOCGCRYPTODESC, &create) == -1)
		return (-1);
	if (create.cd_fd < 0) {
		errno = EPROTO;
		return (-1);
	}
	*descriptor_fd = create.cd_fd;
	return (0);
}

int
cryptodesc_mint_generated(int control_fd, const struct session2_op *session,
    uint32_t rights, uint32_t ttl, int *descriptor_fd)
{
	struct cryptodesc_generate create;

	if (control_fd < 0 || session == NULL || descriptor_fd == NULL ||
	    rights == 0 || (rights & ~CRYPTODESC_RIGHT_ALL) != 0 ||
	    session->key != NULL || session->mackey != NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(&create, 0, sizeof(create));
	create.session = *session;
	create.cd_rights = rights;
	create.cd_ttl = ttl;
	create.cd_fd = -1;
	if (ioctl(control_fd, CIOCGCRYPTODESCGENERATE, &create) == -1)
		return (-1);
	if (create.cd_fd < 0) {
		errno = EPROTO;
		return (-1);
	}
	*descriptor_fd = create.cd_fd;
	return (0);
}

int
cryptodesc_mint_key(int control_fd, uint32_t type, uint32_t rights,
    uint32_t ttl, uint8_t public_key[CRYPTODESC_ED25519_PUBLIC_SIZE],
    int *descriptor_fd)
{
	struct cryptodesc_key_create create;

	if (control_fd < 0 || public_key == NULL || descriptor_fd == NULL ||
	    rights == 0 || (rights & ~CRYPTODESC_RIGHT_ALL) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(&create, 0, sizeof(create));
	create.cd_type = type;
	create.cd_rights = rights;
	create.cd_ttl = ttl;
	create.cd_fd = -1;
	if (ioctl(control_fd, CIOCGCRYPTOKEYDESC, &create) == -1)
		return (-1);
	if (create.cd_fd < 0) {
		errno = EPROTO;
		return (-1);
	}
	memcpy(public_key, create.cd_public, sizeof(create.cd_public));
	*descriptor_fd = create.cd_fd;
	return (0);
}

int
cryptodesc_named_create(int control_fd, const char *name, const char *owner,
    const struct session2_op *session, uint32_t rights, uint64_t *generation)
{
	struct cryptodesc_named_create create;

	if (control_fd < 0 || session == NULL || generation == NULL ||
	    !named_identifier(name, CRYPTODESC_KEY_NAME_MAX) ||
	    !named_identifier(owner, CRYPTODESC_KEY_OWNER_MAX) || rights == 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(&create, 0, sizeof(create));
	strlcpy(create.cd_name, name, sizeof(create.cd_name));
	strlcpy(create.cd_owner, owner, sizeof(create.cd_owner));
	create.cd_session = *session;
	create.cd_rights = rights;
	if (ioctl(control_fd, CIOCGCRYPTONAMEDKEY, &create) == -1)
		return (-1);
	*generation = create.cd_generation;
	return (0);
}

int
cryptodesc_named_lease(int control_fd, const char *name, const char *owner,
    uint32_t rights, uint32_t ttl, uint64_t *generation, int *descriptor_fd)
{
	struct cryptodesc_named_lease lease;

	if (control_fd < 0 || generation == NULL || descriptor_fd == NULL ||
	    !named_identifier(name, CRYPTODESC_KEY_NAME_MAX) ||
	    !named_identifier(owner, CRYPTODESC_KEY_OWNER_MAX) || rights == 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(&lease, 0, sizeof(lease));
	strlcpy(lease.cd_name, name, sizeof(lease.cd_name));
	strlcpy(lease.cd_owner, owner, sizeof(lease.cd_owner));
	lease.cd_rights = rights;
	lease.cd_ttl = ttl;
	lease.cd_fd = -1;
	if (ioctl(control_fd, CIOCGCRYPTONAMEDLEASE, &lease) == -1)
		return (-1);
	if (lease.cd_fd < 0) {
		errno = EPROTO;
		return (-1);
	}
	*generation = lease.cd_generation;
	*descriptor_fd = lease.cd_fd;
	return (0);
}

static int
cryptodesc_named_control(int control_fd, const char *name, const char *owner,
    uint64_t *generation, u_long command)
{
	struct cryptodesc_named_control control;

	if (control_fd < 0 || generation == NULL ||
	    !named_identifier(name, CRYPTODESC_KEY_NAME_MAX) ||
	    !named_identifier(owner, CRYPTODESC_KEY_OWNER_MAX)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&control, 0, sizeof(control));
	strlcpy(control.cd_name, name, sizeof(control.cd_name));
	strlcpy(control.cd_owner, owner, sizeof(control.cd_owner));
	if (ioctl(control_fd, command, &control) == -1)
		return (-1);
	*generation = control.cd_generation;
	return (0);
}

int
cryptodesc_named_rotate(int control_fd, const char *name, const char *owner,
    uint64_t *generation)
{

	return (cryptodesc_named_control(control_fd, name, owner, generation,
	    CIOCCRYPTONAMEDROTATE));
}

int
cryptodesc_named_delete(int control_fd, const char *name, const char *owner,
    uint64_t *generation)
{

	return (cryptodesc_named_control(control_fd, name, owner, generation,
	    CIOCCRYPTONAMEDDELETE));
}

int
cryptodesc_named_stat(int control_fd, const char *name, const char *owner,
    struct cryptodesc_named_stat *stat)
{

	if (control_fd < 0 || stat == NULL ||
	    !named_identifier(name, CRYPTODESC_KEY_NAME_MAX) ||
	    !named_identifier(owner, CRYPTODESC_KEY_OWNER_MAX)) {
		errno = EINVAL;
		return (-1);
	}
	memset(stat, 0, sizeof(*stat));
	strlcpy(stat->cd_name, name, sizeof(stat->cd_name));
	strlcpy(stat->cd_owner, owner, sizeof(stat->cd_owner));
	return (ioctl(control_fd, CIOCGCRYPTONAMEDSTAT, stat));
}

/*
 * Owner-scoped enumeration of named keys.  Issues one CIOCGCRYPTONAMEDLIST for
 * the owner at the given cursor and copies out up to max entries; the number
 * populated is returned through count and the resume cursor (zero at the end
 * of the walk) through next_cursor.  A caller pages by re-issuing with the
 * returned next_cursor until it is zero.  No key material is returned.
 */
int
cryptodesc_named_list(int control_fd, const char *owner, uint32_t cursor,
    struct cryptodesc_named_list_entry *entries, uint32_t max, uint32_t *count,
    uint32_t *next_cursor)
{
	struct cryptodesc_named_list list;
	uint32_t copied;

	if (control_fd < 0 || entries == NULL || max == 0 || count == NULL ||
	    next_cursor == NULL || !named_identifier(owner, CRYPTODESC_KEY_OWNER_MAX)) {
		errno = EINVAL;
		return (-1);
	}
	*count = 0;
	*next_cursor = 0;
	memset(&list, 0, sizeof(list));
	strlcpy(list.cd_owner, owner, sizeof(list.cd_owner));
	list.cd_cursor = cursor;
	if (ioctl(control_fd, CIOCGCRYPTONAMEDLIST, &list) == -1)
		return (-1);
	copied = list.cd_count;
	if (copied > CRYPTODESC_NAMED_LIST_MAX)
		copied = CRYPTODESC_NAMED_LIST_MAX;
	if (copied > max)
		copied = max;
	memset(entries, 0, (size_t)max * sizeof(*entries));
	memcpy(entries, list.cd_entries, (size_t)copied * sizeof(*entries));
	*count = copied;
	*next_cursor = list.cd_next_cursor;
	return (0);
}

int
cryptodesc_restrict(int descriptor_fd, uint32_t rights)
{
	struct cryptodesc_restrict attenuation;

	if (descriptor_fd < 0 || (rights & ~CRYPTODESC_RIGHT_ALL) != 0) {
		errno = EINVAL;
		return (-1);
	}
	attenuation.cd_rights = rights;
	return (ioctl(descriptor_fd, CIOCSCRYPTODESCRIGHTS, &attenuation));
}

int
cryptodesc_revoke(int descriptor_fd)
{
	struct cryptodesc_revoke revoke;

	if (descriptor_fd < 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(&revoke, 0, sizeof(revoke));
	return (ioctl(descriptor_fd, CIOCCRYPTODESCREVOKE, &revoke));
}

int
cryptodesc_get_info(int descriptor_fd, struct cryptodesc_info *info)
{

	if (descriptor_fd < 0 || info == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(info, 0, sizeof(*info));
	info->cd_size = sizeof(*info);
	return (ioctl(descriptor_fd, CIOCGCRYPTODESCINFO, info));
}
