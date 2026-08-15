/*- SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include "cryptodesc.h"

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
