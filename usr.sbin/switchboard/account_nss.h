/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_ACCOUNT_NSS_H
#define SWITCHBOARD_ACCOUNT_NSS_H
#include <sys/types.h>
#include <stddef.h>
struct service_account_identity {
	uid_t uid;
	gid_t gid;
	const char *home;
	const char *shell;
};
/* Configure once before serving requests. Copies helper and duplicates diag.
 * With no configuration, normal installations use libc NSS directly.
 * Once configured, failed helper calls never fall back to in-process NSS. */
int account_nss_isolate(const char *helper, int diagnostic, int timeout_ms);
int account_nss_uid(uid_t, char *, size_t);
/* Returned user strings last until the next user-name lookup; single-threaded
 * manager use only, like the libc interfaces these wrappers replace. */
int account_nss_user(const char *, struct service_account_identity *);
int account_nss_group(const char *, gid_t *);
int account_nss_groups(const char *, gid_t, gid_t *, int *);
#endif
