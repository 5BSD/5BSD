/* SPDX-License-Identifier: BSD-2-Clause */
/* Boot policy scopes the short-lived rc application; logins issue no grants. */
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <libcapbundle.h>
#include "switchboard.h"
#include "authority.h"

static bool loaded;
static struct svc_authority_scope boot_scope;
static struct svc_domain boot_domain;
static bool boot_valid;
static void load_boot_policy(void);

static int
open_trusted(const char *path)
{
	struct stat st;
	int fd, saved;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_VERIFY);
	if (fd < 0)
		return (-1);
	if (fstat(fd, &st) == -1) {
		saved = errno;
		close(fd);
		return (errno = saved, -1);
	}
	if (!S_ISREG(st.st_mode) || st.st_uid != 0 ||
	    (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
		close(fd);
		return (errno = EPERM, -1);
	}
	return (fd);
}
void
svc_authority_policy_init(void)
{
	if (loaded)
		return;
	loaded = true;
	load_boot_policy();
}

/* Image policy for the short-lived rc principal, never a UID-based grant. */
static void
load_boot_policy(void)
{
	int fd;

	fd = open_trusted("/Capabilities/Config/switchboard/boot-authority.ucl");
	if (fd < 0)
		return;
	boot_valid = svc_authority_parse_boot(fd, &boot_domain, &boot_scope) == 0;
	close(fd);
	if (!boot_valid)
		syslog(LOG_ERR, "invalid boot authority policy: rc receives no protected grants");
}

int
svc_authority_boot_policy(struct svc_domain *domain,
    const struct svc_authority_scope **scope)
{
	if (!loaded || !boot_valid)
		return (errno = EACCES, -1);
	*domain = boot_domain;
	*scope = &boot_scope;
	return (0);
}
