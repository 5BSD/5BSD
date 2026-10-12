/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _EXTENSIONCMP_H_
#define _EXTENSIONCMP_H_

/* The system.SystemExtension client (formerly part of libservice). */
#include <libservice.h>

__BEGIN_DECLS
/*
 * Ensure a named kernel extension (module) is loaded.  bsdextension is a socket-free
 * provider (system.SystemExtension): libservice opens it by name and asks it to
 * load the module.  A SYSTEM-domain caller only; the discovery domain layer
 * makes the name unresolvable for user services, so this fails closed for them.
 * `module` is a single, safe filename component.  Returns 0 on success
 * (including already-loaded); -1 with errno on failure.
 */
int	service_ensure_extension(struct service_context *, const char *module);

/*
 * Query whether a named kernel extension is loaded (SYSEXT_OP_STAT), without
 * attempting a load.  Routed/validated exactly like service_ensure_extension: a
 * SYSTEM-domain caller only, a denied name fails EPERM.  On a completed query
 * returns 0 with *loadedp set to 1 (loaded) or 0 (not); -1 with errno otherwise.
 */
int	service_extension_stat(struct service_context *, const char *module,
	    int *loadedp);

/*
 * Enumerate the module names bsdextension's allow-list permits (SYSEXT_OP_LIST), so a
 * consumer can discover what it may service_ensure_extension(3) without probing
 * names blindly.  Routed exactly like the other extension calls: a SYSTEM-domain
 * caller only.  The allow-list is global (not per-label), so every caller sees
 * the same set; the reply reveals only which names may load, never any loaded/
 * not-loaded state.  Up to `max` names are written into `names` (each a
 * SERVICE_EXTENSION_NAME_MAX-byte NUL-terminated buffer) and their number is
 * stored in *countp.  This operation returns EOVERFLOW if the policy
 * exceeds SERVICE_EXTENSION_LIST_MAX entries; use extension_info with next=1
 * for bounded enumeration of larger policies.  A smaller `max` that cannot
 * hold a successful reply fails EMSGSIZE (never silent truncation).
 */
#define	SERVICE_EXTENSION_NAME_MAX	64	/* == bsdextension SYSEXT_NAME_MAX */
#define	SERVICE_EXTENSION_LIST_MAX	32	/* == bsdextension SYSEXT_LIST_MAX */
int	service_extension_list(struct service_context *,
	    char (*names)[SERVICE_EXTENSION_NAME_MAX], size_t max,
	    size_t *countp);

/* Typed operations on a borrowed SystemExtension session.  These work for
 * ambient login clients as well as supervised services.  They neither close
 * the session nor change the caller's authority; malformed replies poison
 * the session with EPROTO.  Calls have a 30-second timeout. */
int	service_session_extension_load(struct service_session *, const char *);
/* Reload only the broker's configured policy file; requires ADMIN rights.
 * Existing admitted loads can finish; future requests see the new policy. */
int	service_session_extension_reload(struct service_session *);
int	service_session_extension_stat(struct service_session *, const char *,
	    int *);
int	service_session_extension_list(struct service_session *,
	    char (*)[SERVICE_EXTENSION_NAME_MAX], size_t, size_t *);

/* ADMIN-only durable overrides. ENABLE/DISABLE affect future restoration;
 * LOAD remains the immediate idempotent operation. RESET removes an override. */
enum service_extension_action {
    SERVICE_EXTENSION_ALLOW, SERVICE_EXTENSION_DENY, SERVICE_EXTENSION_RESET,
    SERVICE_EXTENSION_ENABLE, SERVICE_EXTENSION_DISABLE, SERVICE_EXTENSION_RESTORE
};
struct service_extension_info {
    char name[SERVICE_EXTENSION_NAME_MAX];
    int allowed, enabled, loaded, overridden, ready;
};
int service_session_extension_manage(struct service_session *,
    enum service_extension_action, const char *);
/* next=1: first policy entry lexically after name; ENOENT ends enumeration.
 * Each entry is coherent; enumeration is not a snapshot across transactions. */
int service_session_extension_info(struct service_session *, const char *, int,
    struct service_extension_info *);

__END_DECLS

#endif
