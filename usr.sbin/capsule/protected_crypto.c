/* SPDX-License-Identifier: BSD-2-Clause */
/* Original PID 1 supplies only the recipient selected by boot policy. */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/cryptodesc.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "protected_crypto.h"

static bool prepared;
static char retained_recipient[CAPSULE_BOOT_STORAGE_LABEL_MAX];

int
protected_crypto_prepare(const struct capsule_config *cfg)
{

	if (cfg == NULL)
		return (errno = EINVAL, -1);
	if (getpid() != 1)
		return (errno = EPERM, -1);
	if (prepared)
		return (strcmp(retained_recipient, cfg->crypto_recipient) == 0 ?
		    0 : (errno = EPERM, -1));
	strlcpy(retained_recipient, cfg->crypto_recipient, sizeof(retained_recipient));
	prepared = true;
	return (0);
}

int
protected_crypto_open(const char *recipient)
{
	const cap_ioctl_t commands[] = {
	    CIOCGCRYPTOCONTROLINFO, CIOCGCRYPTOCONTROL
	};
	struct cryptoctl_info info;
	cap_rights_t rights;
	int fd, saved;

	if (getpid() != 1)
		return (errno = EPERM, -1);
	if (recipient == NULL)
		return (errno = EINVAL, -1);
	if (!prepared || retained_recipient[0] == '\0' ||
	    strcmp(recipient, retained_recipient) != 0)
		return (errno = ENOENT, -1);
	/* This is the kernel control endpoint, not an executable-derived grant. */
	fd = open("/dev/crypto", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1)
		return (-1);
	memset(&info, 0, sizeof(info));
	if (ioctl(fd, CIOCGCRYPTOCONTROLINFO, &info) == -1)
		goto fail;
	if (info.version != CRYPTOCTL_INFO_VERSION ||
	    info.scope != CRYPTOCTL_SCOPE_SUPERVISOR ||
	    (info.rights & CRYPTOCTL_DERIVE) == 0 || info.reserved != 0 ||
	    info.owner[0] != '\0') {
		errno = EPROTO;
		goto fail;
	}
	cap_rights_init(&rights, CAP_IOCTL);
	if (cap_ioctls_limit(fd, commands, nitems(commands)) == -1 ||
	    cap_rights_limit(fd, &rights) == -1)
		goto fail;
	return (fd);
fail:
	saved = errno;
	close(fd);
	return (errno = saved, -1);
}
