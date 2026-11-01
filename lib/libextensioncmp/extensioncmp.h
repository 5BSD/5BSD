/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _EXTENSIONCMP_H_
#define _EXTENSIONCMP_H_

/* The system.SystemExtension client (bsd.extension.v1). */
#include <sys/types.h>
#include <stdint.h>
#include <libservice.h>

__BEGIN_DECLS
/*
 * Ensure a named kernel extension (module) is loaded.  bsdextension is a socket-free
 * provider (system.SystemExtension): this library opens it by name and asks it to
 * load the module.  A SYSTEM-domain caller only; the discovery domain layer
 * makes the name unresolvable for user services, so this fails closed for them.
 * `module` is a single, safe filename component.  Returns 0 on success
 * (including already-loaded); -1 with errno on failure.
 */
int	service_ensure_extension(struct service_context *, const char *module);

/*
 * Query whether a named kernel extension is loaded (Stat), without
 * attempting a load.  Routed/validated exactly like service_ensure_extension: a
 * SYSTEM-domain caller only, a denied name fails EPERM.  On a completed query
 * returns 0 with *loadedp set to 1 (loaded) or 0 (not); -1 with errno otherwise.
 */
int	service_extension_stat(struct service_context *, const char *module,
	    int *loadedp);

/*
 * Enumerate the module names bsdextension's allow-list permits (List), so a
 * consumer can discover what it may service_ensure_extension(3) without probing
 * names blindly.  Routed exactly like the other extension calls: a SYSTEM-domain
 * caller only.  The allow-list is global (not per-label), so every caller sees
 * the same set; the reply reveals only which names may load, never any loaded/
 * not-loaded state.  Up to `max` names are written into `names` (each a
 * SERVICE_EXTENSION_NAME_MAX-byte NUL-terminated buffer) and their number is
 * stored in *countp.  This operation returns EOVERFLOW if the policy
 * exceeds SERVICE_EXTENSION_LIST_MAX entries; use extensioncmp_info with next=1
 * for bounded enumeration of larger policies.  A smaller `max` that cannot
 * hold a successful reply fails EMSGSIZE (never silent truncation).
 */
#define	SERVICE_EXTENSION_NAME_MAX	64	/* == bsdextension SYSEXT_NAME_MAX */
#define	SERVICE_EXTENSION_LIST_MAX	32	/* == bsdextension SYSEXT_LIST_MAX */
int	service_extension_list(struct service_context *,
	    char (*names)[SERVICE_EXTENSION_NAME_MAX], size_t max,
	    size_t *countp);

/*
 * An explicit SystemExtension session, for operators (sysextctl(8)) and other
 * clients that need their own connection rather than the process-wide one.
 * extensioncmp_session_open() opens system.SystemExtension by name;
 * extensioncmp_session_create() adopts a held channel (consumed only on
 * success).  The typed operations below neither close the session nor change
 * the caller's authority; a transport failure or malformed reply makes the
 * session fail every later call (open a new one).  Calls have a 30-second
 * timeout, shortened by an active service_budget_begin(3).
 * Explicit sessions belong to their creating process. After fork/pdfork,
 * operations return ECHILD without touching the inherited session lock;
 * close releases only the child's wrapper.
 */
struct extensioncmp_session;
int	extensioncmp_session_open(struct extensioncmp_session **);
int	extensioncmp_session_create(int fd, struct extensioncmp_session **);
void	extensioncmp_session_close(struct extensioncmp_session *);

int	extensioncmp_load(struct extensioncmp_session *, const char *);
/* Reload only the broker's configured policy file; requires ADMIN rights.
 * Existing admitted loads can finish; future requests see the new policy. */
int	extensioncmp_reload(struct extensioncmp_session *);
int	extensioncmp_stat(struct extensioncmp_session *, const char *, int *);
int	extensioncmp_list(struct extensioncmp_session *,
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
int	extensioncmp_manage(struct extensioncmp_session *,
	    enum service_extension_action, const char *);
/* next=1: first policy entry lexically after name; ENOENT ends enumeration.
 * Each entry is coherent; enumeration is not a snapshot across transactions. */
int	extensioncmp_info(struct extensioncmp_session *, const char *, int,
	    struct service_extension_info *);

/*
 * The read-only view, system.SystemExtension.Status (SystemExtensionStatus).
 * switchboard resolves it for UID 0 sessions that hold no software authority
 * (root login shells; /Capabilities/Config/switchboard/root-query.ucl), not for
 * other users.  A status session answers extensioncmp_info() and
 * extensioncmp_decision(); every other operation fails EPERM without sending
 * anything, and the protocol itself has no method that loads a module or
 * changes policy.  extensioncmp_session_create_status() adopts a held channel.
 */
int	extensioncmp_session_open_status(struct extensioncmp_session **);
int	extensioncmp_session_create_status(int fd, struct extensioncmp_session **);
/* 1 for a status session, else 0. */
int	extensioncmp_session_read_only(const struct extensioncmp_session *);

/*
 * The broker's recent load decisions (Ensure and Restore), oldest first: the
 * first retained decision with a sequence above `after` (0 starts); ENOENT
 * ends.  The broker keeps the most recent 64 since it started.  EOPNOTSUPP on
 * a session that is not a status session.  result is SYSEXT_DECISION_* from
 * <sysext_proto.h>: 1 loaded, 2 already present, 3 not permitted, 4 client
 * limited to hardware drivers, 5 administrator deny override, 6 load failed
 * (error holds the errno); root loads add 7 not a base package file,
 * 8 checksum mismatch, 9 no regular file in /boot/kernel, 10 unloaded, 11 not
 * loaded by a root load, 12 root loads not configured, 13 package database
 * unavailable, 14 file changed during the load.  operation is 1 (Ensure),
 * 10 (Restore), 14 (root Load) or 15 (root Unload).
 */
struct service_extension_decision {
    uint64_t sequence;
    time_t time;
    char name[SERVICE_EXTENSION_NAME_MAX];
    char client[64];
    int operation, result, error;
};
int	extensioncmp_decision(struct extensioncmp_session *, uint64_t after,
	    struct service_extension_decision *);

/*
 * The root-load endpoint, system.SystemExtension.RootLoad
 * (SystemExtensionRootLoad).  switchboard resolves it for UID 0 sessions outside
 * a jail that hold no software authority (root login shells;
 * /Capabilities/Config/switchboard/root-load.ucl).  extensioncmp_root_load()
 * asks the broker to load /boot/kernel/NAME.ko, which it does only for a file
 * the package database records in a 5BSD base package with a matching
 * checksum; extensioncmp_root_unload() removes only a module a root load
 * loaded.  Both return 0 when the broker decided (outcome->result is
 * SYSEXT_DECISION_*, outcome->error the errno of a failed load or unload),
 * -1 with errno otherwise (EINVAL: bad name; EOPNOTSUPP: not a root-load
 * session).  Every other operation fails EPERM on such a session.
 */
struct service_extension_root_outcome {
    int result, error;
};
int	extensioncmp_session_open_rootload(struct extensioncmp_session **);
int	extensioncmp_session_create_rootload(int fd,
	    struct extensioncmp_session **);
int	extensioncmp_root_load(struct extensioncmp_session *, const char *,
	    struct service_extension_root_outcome *);
int	extensioncmp_root_unload(struct extensioncmp_session *, const char *,
	    struct service_extension_root_outcome *);

__END_DECLS

#endif
