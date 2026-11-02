/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_AUTHORITY_H
#define SWITCHBOARD_AUTHORITY_H

#include <sys/cap_authority.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define SVC_AUTHORITY_SCOPE_MAX 16
struct svc_authority_scope {
	unsigned count;
	char endpoints[SVC_AUTHORITY_SCOPE_MAX][64];
};

/*
 * A lasting grant for one adopted rc.d service (service-authority.ucl).  It is
 * issued to the unit's start command, held by the daemon it starts for as long
 * as that launch lasts, survives exec only into the listed images, reaches only
 * the listed endpoints, and carries no attributes or administrative rights.
 */
#define SVC_SERVICE_AUTHORITY_MAX 8
#define SVC_SERVICE_IMAGES_MAX CAP_AUTH_EXEC_MAX
#define SVC_SERVICE_IMAGE_MAX 128
struct svc_service_authority {
	char label[64];
	struct svc_authority_scope scope;
	unsigned nimages;
	char images[SVC_SERVICE_IMAGES_MAX][SVC_SERVICE_IMAGE_MAX];
};
struct svc_domain;
struct svc_runtime;
struct channel_message;
struct channel_sender;

/* The broker alone owns the issuer. Returned grants are one-use objects. */
int svc_authority_issue(uid_t, struct svc_domain *,
    const struct svc_runtime *, int *);
int svc_authority_applications_sync(void);
int svc_authority_constrain_application(const struct svc_runtime *, int);
int svc_authority_resolve(const struct channel_message *, struct svc_domain *,
    struct svc_runtime **);
uid_t svc_authority_personal_uid(const struct svc_domain *, const struct channel_sender *);
const char *svc_authority_label(const struct svc_domain *);
int svc_authority_bind(const struct svc_domain *, int);
int svc_authority_bind_invocation(const struct svc_domain *, int);
void svc_authority_revoke_unit(const struct svc_runtime *);
void svc_authority_collect(void);
void svc_authority_teardown(void);
void svc_authority_policy_init(void);
int svc_authority_parse_boot(int, struct svc_domain *, struct svc_authority_scope *);
int svc_authority_boot_policy(struct svc_domain *, const struct svc_authority_scope **);
int svc_authority_issue_boot(struct svc_runtime *, int *);
int svc_authority_parse_services(int, struct svc_service_authority *, unsigned,
    unsigned *);
const struct svc_service_authority *svc_authority_service_policy(const char *);
/*
 * Open a service-authority.ucl image for pinning: a regular, root-owned,
 * executable file not writable by group or others, not a symbolic link.
 * Returns the descriptor, or -1 with errno (EPERM for an unacceptable file).
 */
int svc_authority_open_image(const char *);
int svc_authority_issue_service(struct svc_runtime *, int *);
bool svc_authority_permits(const struct svc_domain *, const char *);
/*
 * root-query.ucl: read-only endpoints a UID 0 session without software
 * authority may resolve (the kernel-stamped sender's effective UID is 0 and it
 * is not jailed).  It grants no attributes and no administrative rights.
 */
int svc_authority_parse_root_query(int, struct svc_authority_scope *);
/* Install the loaded policy (authority_policy.c); NULL grants nothing. */
void svc_authority_set_root_query(const struct svc_authority_scope *);
bool svc_authority_root_query(const struct svc_domain *,
    const struct channel_sender *, const char *);
/*
 * root-load.ucl: endpoints that act for the same callers (UID 0, not jailed,
 * no software authority), kept apart from the read-only list.  Parsed with
 * svc_authority_parse_root_query() (same format); NULL grants nothing.
 */
void svc_authority_set_root_load(const struct svc_authority_scope *);
bool svc_authority_root_load(const struct svc_domain *,
    const struct channel_sender *, const char *);

/*
 * Whether a lookup may resolve name through root-query.ucl: the caller holds no
 * software authority (a grant has its own scope and never widens through
 * here), the kernel-stamped sender has effective UID 0 outside any jail, the
 * name is listed, and it is not a control-plane name.
 */
static inline bool
svc_authority_root_query_admits(const struct svc_authority_scope *scope,
    bool authorized, bool stamped, uint32_t uid, int32_t prison_id,
    const char *name)
{
	const char *dot;
	unsigned i;

	if (scope == NULL || name == NULL || authorized || !stamped ||
	    uid != 0 || prison_id != 0)
		return (false);
	dot = strrchr(name, '.');
	if (dot != NULL && strcmp(dot + 1, "Control") == 0)
		return (false);
	for (i = 0; i < scope->count; i++)
		if (strcmp(scope->endpoints[i], name) == 0)
			return (true);
	return (false);
}
#endif
