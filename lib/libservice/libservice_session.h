/* SPDX-License-Identifier: BSD-2-Clause */
/* Process-held discovery and attribution; authentication remains provider-owned. */
#ifndef _LIBSERVICE_SESSION_H_
#define _LIBSERVICE_SESSION_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/cap_process.h>
#include <sys/cap_authority.h>

#define SERVICE_LOOKUP_ENV "SERVICE_LOOKUP_FD"

__BEGIN_DECLS
/* Return an owned close-on-exec descriptor from process state. */
int service_ambient_lookup_fd(void);
/* Install a held reference; the caller still owns fd. */
int service_install_ambient_lookup(int fd);
int service_clear_ambient_lookup(void);
/* Install a genuine, one-use issued grant, independently of discovery. */
int service_authority_install(int token_fd);
int service_authority_clear(void);
int service_authority_info(struct cap_authority_info *);
int service_process_info(struct mac_cap_process_info *info);
int service_origin_export(void);
int service_origin_set(int token_fd);
/* The caller retains the descriptor; rehomes only inherited membership. */
int service_session_join_fd(int coalition_fd);
__END_DECLS

#endif
