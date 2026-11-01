/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Image policy for software authority: the short-lived rc application and the
 * lasting grants of adopted rc.d services.  Logins issue no grants.
 */
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
#include "rc_adopt.h"

#define BOOT_AUTHORITY_POLICY "/Capabilities/Config/switchboard/boot-authority.ucl"
#define SERVICE_AUTHORITY_POLICY "/Capabilities/Config/switchboard/service-authority.ucl"
#define ROOT_QUERY_POLICY "/Capabilities/Config/switchboard/root-query.ucl"
#define ROOT_LOAD_POLICY "/Capabilities/Config/switchboard/root-load.ucl"

static bool loaded;
static struct svc_authority_scope boot_scope;
static struct svc_domain boot_domain;
static bool boot_valid;
static struct svc_service_authority services[SVC_SERVICE_AUTHORITY_MAX];
static unsigned nservices;
static struct svc_authority_scope root_query_scope;
static struct svc_authority_scope root_load_scope;
static void load_boot_policy(void);
static void load_service_policy(void);
static void load_root_query_policy(void);
static void load_root_load_policy(void);

static int
open_trusted(const char *path)
{
	struct stat st;
	int fd, saved;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_VERIFY);
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
	load_service_policy();
	load_root_query_policy();
	load_root_load_policy();
}

/* Image policy for the short-lived rc principal, never a UID-based grant. */
static void
load_boot_policy(void)
{
	int fd;

	fd = open_trusted(BOOT_AUTHORITY_POLICY);
	if (fd < 0)
		return;
	boot_valid = svc_authority_parse_boot(fd, &boot_domain, &boot_scope) == 0;
	close(fd);
	if (!boot_valid)
		syslog(LOG_ERR, "invalid boot authority policy: rc receives no protected grants");
}

/*
 * Lasting grants for adopted rc.d services.  An absent file grants nothing;
 * an invalid file grants nothing and is logged.  A grant names a unit that
 * rc_adopt.conf must also adopt: both files live in the protected
 * configuration tree, and neither alone confers authority.
 */
static void
load_service_policy(void)
{
	unsigned count, i;
	int fd;

	fd = open_trusted(SERVICE_AUTHORITY_POLICY);
	if (fd < 0) {
		if (errno != ENOENT)
			syslog(LOG_ERR, "service authority policy unavailable: %m; "
			    "adopted services receive no lasting grants");
		return;
	}
	if (svc_authority_parse_services(fd, services, SVC_SERVICE_AUTHORITY_MAX,
	    &count) == -1) {
		syslog(LOG_ERR, "invalid service authority policy: adopted "
		    "services receive no lasting grants");
		count = 0;
	}
	close(fd);
	nservices = count;
	for (i = 0; i < nservices; i++)
		syslog(LOG_INFO, "service authority: %s may reach %u endpoint(s)%s",
		    services[i].label, services[i].scope.count,
		    rc_adopt_is_allowed(services[i].label) ? "" :
		    " (not adopted; inactive)");
}

/*
 * Read-only endpoints for UID 0 sessions without software authority.  An absent
 * file grants nothing; an invalid file grants nothing and is logged.
 */
static void
load_root_query_policy(void)
{
	unsigned i;
	int fd;

	fd = open_trusted(ROOT_QUERY_POLICY);
	if (fd < 0) {
		if (errno != ENOENT)
			syslog(LOG_ERR, "root query policy unavailable: %m; "
			    "root sessions reach no read-only endpoints");
		return;
	}
	if (svc_authority_parse_root_query(fd, &root_query_scope) == -1) {
		syslog(LOG_ERR, "invalid root query policy: root sessions "
		    "reach no read-only endpoints");
		memset(&root_query_scope, 0, sizeof(root_query_scope));
	}
	close(fd);
	if (root_query_scope.count != 0)
		svc_authority_set_root_query(&root_query_scope);
	for (i = 0; i < root_query_scope.count; i++)
		syslog(LOG_INFO, "root query: UID 0 sessions may reach %s",
		    root_query_scope.endpoints[i]);
}

/*
 * Endpoints that act (BSDExtension's RootLoad) for UID 0 sessions without
 * software authority.  Same format and admission as root-query.ucl, separate
 * file so they can be withdrawn without losing the read-only view.  An absent
 * or invalid file grants nothing.
 */
static void
load_root_load_policy(void)
{
	unsigned i;
	int fd;

	fd = open_trusted(ROOT_LOAD_POLICY);
	if (fd < 0) {
		if (errno != ENOENT)
			syslog(LOG_ERR, "root load policy unavailable: %m; "
			    "root sessions reach no load endpoints");
		return;
	}
	if (svc_authority_parse_root_query(fd, &root_load_scope) == -1) {
		syslog(LOG_ERR, "invalid root load policy: root sessions "
		    "reach no load endpoints");
		memset(&root_load_scope, 0, sizeof(root_load_scope));
	}
	close(fd);
	if (root_load_scope.count != 0)
		svc_authority_set_root_load(&root_load_scope);
	for (i = 0; i < root_load_scope.count; i++)
		syslog(LOG_INFO, "root load: UID 0 sessions may reach %s",
		    root_load_scope.endpoints[i]);
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

const struct svc_service_authority *
svc_authority_service_policy(const char *label)
{
	unsigned i;

	if (!loaded || label == NULL || !rc_adopt_is_allowed(label))
		return (NULL);
	for (i = 0; i < nservices; i++)
		if (strcmp(services[i].label, label) == 0)
			return (&services[i]);
	return (NULL);
}
