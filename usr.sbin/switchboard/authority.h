/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_AUTHORITY_H
#define SWITCHBOARD_AUTHORITY_H

#include <sys/cap_authority.h>

#define SVC_AUTHORITY_SCOPE_MAX 16
struct svc_authority_scope {
	unsigned count;
	char endpoints[SVC_AUTHORITY_SCOPE_MAX][64];
};
struct svc_domain;
struct svc_runtime;
struct channel_message;

/* The broker alone owns the issuer. Returned grants are one-use objects. */
int svc_authority_issue(uid_t, struct svc_domain *,
    const struct svc_runtime *, int *);
int svc_authority_applications_sync(void);
int svc_authority_constrain_application(const struct svc_runtime *, int);
int svc_authority_resolve(const struct channel_message *, struct svc_domain *,
    struct svc_runtime **);
const char *svc_authority_label(const struct svc_domain *);
int svc_authority_bind(const struct svc_domain *, int);
void svc_authority_revoke_unit(const struct svc_runtime *);
void svc_authority_collect(void);
void svc_authority_teardown(void);
void svc_authority_policy_init(void);
int svc_authority_parse_boot(int, struct svc_domain *, struct svc_authority_scope *);
int svc_authority_boot_policy(struct svc_domain *, const struct svc_authority_scope **);
int svc_authority_issue_boot(struct svc_runtime *, int *);
bool svc_authority_permits(const struct svc_domain *, const char *);
#endif
