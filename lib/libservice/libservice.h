/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libservice — client library for services managed by switchboard(8).
 *
 * Provides a clean API for services to communicate with switchboard
 * over their inherited pair fd.  Services link against libservice
 * without exposing the common mac_capability transport ioctls.
 *
 * Applications normally use a typed service library.  Global providers use a
 * service_provider; local/global discovery policy remains inside the typed
 * library rather than becoming an application choice.
 */

#ifndef _LIBSERVICE_H_
#define	_LIBSERVICE_H_

#include <sys/types.h>

#include <limits.h>	/* PATH_MAX for struct service_namespace_info */
#include <stdbool.h>
#include <stdint.h>

/* Supervisor-owned location of the selected unit's immutable bundle files. */
#define	SERVICE_UNIT_DIR_ENV	"CAPABILITY_UNIT_DIR"

/*
 * Descriptor for the unit's bundle Config/ directory, delivered by switchboard so
 * a capability-mode program can openat(2) its config files without a path
 * lookup (which cap_enter(2) forbids).  service_config_open(3) uses it.
 */
#define	SERVICE_CONFIG_FD_ENV	"CAPABILITY_CONFIG_FD"
#define	SERVICE_DIR_FDS_ENV	"CAPABILITY_DIR_FDS"

/*
 * Public process-protection flags used by service_provider_protect() and
 * service_worker_protect().  Keep kernel protocol details behind libservice
 * so service programs do not need mac_capability headers.
 */
#define	SERVICE_PROTECT_PTRACE		0x0001
#define	SERVICE_PROTECT_SIGNAL		0x0002
#define	SERVICE_PROTECT_VISIBLE		0x0004
#define	SERVICE_PROTECT_WAIT		0x0008
#define	SERVICE_PROTECT_SIGKILL		0x0010
#define	SERVICE_PROTECT_SIGCONT		0x0020
#define	SERVICE_PROTECT_SCHED		0x0040
#define	SERVICE_PROTECT_CORE		0x0080
#define	SERVICE_PROTECT_KTRACE		0x0100
#define	SERVICE_PROTECT_NOPRIVS		0x0200
#define	SERVICE_PROTECT_NOFORK		0x0400
#define	SERVICE_PROTECT_NOIPC		0x0800
#define	SERVICE_PROTECT_NOFDRECV	0x1000
#define	SERVICE_PROTECT_NOEXEC		0x2000
#define	SERVICE_PROTECT_NOSOCK		0x4000

#define	SERVICE_PROTECT_EXTERNAL	(SERVICE_PROTECT_PTRACE | \
	 SERVICE_PROTECT_SIGNAL | SERVICE_PROTECT_VISIBLE | \
	 SERVICE_PROTECT_WAIT | SERVICE_PROTECT_SIGKILL | \
	 SERVICE_PROTECT_SIGCONT | SERVICE_PROTECT_SCHED | \
	 SERVICE_PROTECT_CORE | SERVICE_PROTECT_KTRACE)
#define	SERVICE_PROTECT_RESTRICT	(SERVICE_PROTECT_NOPRIVS | \
	 SERVICE_PROTECT_NOFORK | SERVICE_PROTECT_NOIPC | \
	 SERVICE_PROTECT_NOFDRECV | SERVICE_PROTECT_NOEXEC | \
	 SERVICE_PROTECT_NOSOCK)
#define	SERVICE_PROTECT_ALL		(SERVICE_PROTECT_EXTERNAL | \
	 SERVICE_PROTECT_RESTRICT)

struct service_listener;
struct service_session;
struct service_context;
struct service_provider;
typedef int (*service_activation_handler)(const char *name, void *context);

/*
 * A capability's rights (docs/capability-authority-model.md).  A service-defined
 * bitmask of the operations the holder of a granted session may perform; bit
 * meanings are per-service (Capsicum-shaped).  Attenuation is monotone: a child
 * capability may only clear bits, never set them.  SERVICE_RIGHTS_ALL is the
 * unattenuated grant a legacy lookup (one that carries no explicit rights) still
 * receives, so a service that ignores rights behaves exactly as before.
 */
typedef uint64_t service_rights_t;
#define	SERVICE_RIGHTS_NONE	((service_rights_t)0)
#define	SERVICE_RIGHTS_ALL	(~(service_rights_t)0)
/*
 * The one cross-service well-known right: administrative access, which bypasses
 * a service's per-object policy (the capability replacement for the old
 * "root may do anything" bypass).  switchboard grants it only to an admin login
 * session's grants.  Per-service rights use the low bits; this reserves the top.
 */
#define	SERVICE_RIGHTS_ADMIN	((service_rights_t)1 << 63)

/* A held capability permits an operation iff it holds every needed right. */
static __inline bool
service_rights_allow(service_rights_t held, service_rights_t needed)
{
	return ((held & needed) == needed);
}

/* Attenuate: keep only the intersection; the result can never exceed `held`. */
static __inline service_rights_t
service_rights_attenuate(service_rights_t held, service_rights_t keep)
{
	return (held & keep);
}

/*
 * Revocation epoch (docs/capability-authority-model.md §11.3).  A service keeps
 * a generation per object; a capability records the epoch it was minted at, and
 * bumping the object's epoch invalidates every capability of the prior epoch at
 * once.  Selective revocation is composed on top with a caretaker.
 */
typedef uint64_t service_epoch_t;

/* A capability minted at `minted` is live iff the object is still at that epoch. */
static __inline bool
service_epoch_live(service_epoch_t minted, service_epoch_t current)
{
	return (minted == current);
}

/*
 * Client / sender ABI as stamped by the kernel on the channel message that
 * carried the request (mac_capability_cred_trailer.abi).  Values mirror
 * SV_ABI_* from <sys/sysent.h>.  UNKNOWN is reported for kernel-originated
 * messages and by a kernel that predates the stamp.  Information for the
 * provider only: ABI never gates reach, only anointments do
 * (docs/ipc-anointments-design.md).
 */
#define	SERVICE_GROUPS_MAX		4	/* group containers per bundle (Bundle.ucl groups) */
#define	SERVICE_CLIENT_ABI_UNKNOWN	0
#define	SERVICE_CLIENT_ABI_LINUX	3
#define	SERVICE_CLIENT_ABI_NATIVE	9

struct service_identity {
	size_t	size;
	char	service_name[256];		/* the object this session names */
	char	client_label[64];		/* persistent identity (bundle label) */
	char	resource_owner[64];
	uint8_t installation[16];
	service_rights_t rights;		/* rights granted to this session */
	uint64_t client_nonce;			/* running instance: kernel per-exec nonce */
	uint8_t	client_abi;			/* SERVICE_CLIENT_ABI_* */
	uint8_t	reserved8[7];
	char	container[64];			/* installed bundle for per-bundle
						 * container storage; "" if none
						 * (docs/capability-container-model.md) */
	uint64_t reserved[1];
	/*
	 * Group containers the client's bundle declares membership in
	 * (Bundle.ucl `groups`); "" slots are empty.  `size` must be exactly
	 * sizeof(struct service_identity) (the accept contract); growing the
	 * struct is a library ABI change (SHLIB_MAJOR 7).
	 */
	char	groups[SERVICE_GROUPS_MAX][64];
};
_Static_assert(sizeof(struct service_identity) == 760,
    "service_identity size is part of the accept() contract");

/*
 * Metadata stamped or carried by a mac_capability channel message.  Attached
 * descriptors are returned separately in attachment-slot order.
 */
struct service_message_metadata {
	size_t		size;
	size_t		payload_length;
	uint64_t	sender_badge;
	uint64_t	sender_nonce;
	uint32_t	sender_uid;
	uint32_t	sender_gid;
	int32_t		sender_prison;
	uint8_t		sender_abi;	/* SERVICE_CLIENT_ABI_* */
	uint8_t		reserved8[3];
	uint32_t	reserved[2];
};
_Static_assert(sizeof(struct service_message_metadata) == 56,
    "service_message_metadata size is part of the call contract");

__BEGIN_DECLS

/*
 * Acquire the process-wide switchboard context.  Initialization is idempotent,
 * thread-safe, and shared by every typed service library in the process.
 * The first terminal bootstrap error is returned consistently to all callers.
 * Releasing the last logical reference does not invalidate active sessions or
 * listeners.
 */
int	service_acquire(struct service_context **);
void	service_release(struct service_context *);
int	service_authorize_capabilities(struct service_context *);
int	service_enter_capability_mode(struct service_context *);
/*
 * Finalize an ambient-authority provider that cannot enter capability mode (its
 * authority is a held system capability, not the capsicum sandbox — e.g. the
 * kldload broker).  Alternative to service_enter_capability_mode; every other
 * provider must sandbox.  service_ready() then succeeds without capability mode.
 */
int	service_enter_ambient(struct service_context *);
int	service_ready(struct service_context *);

/*
 * Request that switchboard stop this provider after `seconds` of no new client
 * demand; a subsequent lookup relaunches it on demand.  Call again after
 * handling a client to re-arm, or with 0 to cancel.
 */
int	service_idle_shutdown(struct service_context *, unsigned seconds);

/*
 * A provider owns global-name exposure and makes the capability-mode security
 * transition explicit.  service_provider_ready() never enters capability
 * mode; callers must seal the process first.
 */
int	service_provider_create(struct service_provider **);
void	service_provider_destroy(struct service_provider *);
int	service_provider_authorize_capabilities(struct service_provider *);
int	service_provider_worker_channel(struct service_provider *,
	    int *provider_fd, int *worker_fd);
int	service_provider_protect(struct service_provider *, uint32_t flags);
int	service_provider_expose(struct service_provider *, const char *name,
	    struct service_listener **);
/*
 * Like service_provider_expose(), but declares that sessions delivered for
 * this name may be forwarded: the consumer receives a transfer-unlimited
 * endpoint it can re-send (attenuating per hop) instead of the default
 * non-transferable one.  This is the provider's own protocol contract.
 */
int	service_provider_expose_sendable(struct service_provider *,
	    const char *name, struct service_listener **);
int	service_provider_expose_lazy(struct service_provider *, const char *name,
	    service_activation_handler, void *, struct service_listener **);
int	service_provider_enter_capability_mode(struct service_provider *);
/* Ambient-authority alternative to enter_capability_mode (see above). */
int	service_provider_enter_ambient(struct service_provider *);
int	service_provider_ready(struct service_provider *);

/*
 * Open one of the unit's bundle Config/ files read-only, returning its
 * descriptor in *fdp.  Prefers the switchboard-delivered Config directory
 * descriptor (SERVICE_CONFIG_FD_ENV) via openat(2) -- capability-mode safe and
 * usable after cap_enter(2) -- and falls back to <CAPABILITY_UNIT_DIR>/Config/
 * by path for a legacy/pre-capmode launch.  O_NOFOLLOW, no directory escape.
 */
int	service_config_open(const char *name, int *fdp);

/*
 * Return the descriptor for a switchboard-delivered resource directory declared in
 * the unit's manifest (directories = [...]).  `path` is the absolute directory
 * the manifest declared (e.g. "/dev"); *fdp receives its inherited, ambient
 * read-only directory descriptor, advertised in SERVICE_DIR_FDS_ENV.  A
 * born-in-capmode daemon uses it as the openat(2) base for the nodes it needs,
 * never naming a global path.  Returns -1 / ENOENT when the path was not
 * delivered.  The descriptor is borrowed (do not close); the daemon may
 * cap_rights_limit(2) a dup of nodes it opens beneath it.
 */
int	service_resource_dir(const char *path, int *fdp);

int	service_provider_quiescing(struct service_provider *);
int	service_provider_quiesce_complete(struct service_provider *, int status);

/*
 * Monitor the supervising switchboard connection.  The borrowed event fd becomes
 * readable once the connection is permanently lost.  status returns zero
 * while the dispatcher is healthy and otherwise returns -1 with the terminal
 * transport error in errno.  It never consumes the event indication.
 */
int	service_supervisor_fd(struct service_context *);
int	service_supervisor_status(struct service_context *);

/*
 * Return the immutable switchboard manifest label for this process.
 * The returned pointer remains owned by libservice.
 */
const char *service_label(struct service_context *);

/*
 * Open an owned, type-checked descriptor declared by the manifest.  Named
 * capability services use their interface name as the type.  Mount-only
 * storage uses type "directory"; advanced storage uses "zfshandle".  Unlike
 * access tokens, these descriptors are not activated.  The caller must close
 * the returned close-on-exec descriptor.
 */
int	service_storage_open(struct service_context *, const char *name,
	    int *dirfdp);
/*
 * As service_storage_open(3), but bound the persistent claim's refquota to
 * `quota` bytes (0 = tzfsd's configured default; a value below the daemon's
 * floor is rejected with EINVAL).  service_storage_open is this with quota=0.
 */
int	service_storage_open_quota(struct service_context *, const char *name,
	    uint64_t quota, int *dirfdp);
/*
 * Reclaim (destroy) a persistent storage claim previously granted under `name`,
 * freeing its pool space; symmetric with service_storage_open(3).  The claim is
 * resolved under the caller's own label-scoped namespace, so a caller can never
 * name another's.  Returns 0, or -1 with errno (ENOENT if the claim is absent).
 */
int	service_storage_destroy(struct service_context *, const char *name);

/*
 * Container scopes (docs/capability-container-model.md "Storage and
 * delivery").  service_storage_open(3) claims live in the unit's PRIVATE
 * container Data/<bundle>/<unit>/persistent/<name>.  The bundle-SHARED variant
 * claims Data/<bundle>/shared/persistent/<name>, reachable by every unit of the
 * bundle and reaped with the bundle.  The GROUP variant claims
 * Data/Shared/<group>/persistent/<name>, a cross-bundle group container the
 * unit's bundle must declare membership in (Bundle.ucl `groups`; switchboard
 * stamps the membership on the connection, tzfsd enforces it: EPERM
 * otherwise); it is reaped only when no installed bundle claims the group.
 * `group` is a single safe component.  The destroy variants are symmetric.
 */
/*
 * The unit's CACHE sub-container Data/<bundle>/<unit>/cache/<name>: regenerable
 * data, claimed and reaped exactly like persistent storage (it is part of the
 * unit's container) but kept apart so an operator or a future policy can drop
 * it without touching durable state.  Same rights and delivery as
 * service_storage_open(3).
 */
int	service_storage_open_cache(struct service_context *, const char *name,
	    int *dirfdp);
int	service_storage_destroy_cache(struct service_context *,
	    const char *name);
int	service_storage_open_shared(struct service_context *, const char *name,
	    int *dirfdp);
/*
 * A READ-ONLY view of a bundle-shared store: the same claim as
 * service_storage_open_shared(3) (created if absent, shared with the bundle's
 * writers, reaped with the bundle) but the delivered directory carries
 * read-only Capsicum rights, so every descriptor derived under it can look up,
 * read, stat and map, never write, create, unlink or change attributes
 * (ENOTCAPABLE).  Several units may hold the same store at once, read-only
 * and read-write alike: it is mounted once and shared.  The SHARED ENVIRONMENT
 * is the conventional such store, SERVICE_STORAGE_ENV ("env"): one unit of the
 * bundle writes it through service_storage_open_shared(ctx, "env"), every
 * other unit reads it through service_storage_open_env(3).
 */
#define	SERVICE_STORAGE_ENV	"env"
/*
 * Bound on one storage request to system.Filesystem.  The provider answers
 * a claim in well under a second; a request that gets no reply at all means
 * the worker serving this connection died (its provider was relaunched), and
 * the session is then treated as dead and reopened on the next claim.
 */
#define	SERVICE_STORAGE_CALL_TIMEOUT_MS	10000
int	service_storage_open_shared_readonly(struct service_context *,
	    const char *name, int *dirfdp);
int	service_storage_open_env(struct service_context *, int *dirfdp);
int	service_storage_open_group(struct service_context *, const char *group,
	    const char *name, int *dirfdp);
int	service_storage_destroy_shared(struct service_context *,
	    const char *name);
int	service_storage_destroy_group(struct service_context *,
	    const char *group, const char *name);
/*
 * One enumerated storage claim: its opaque key plus cheap usage accounting
 * (bytes referenced, and the refquota ceiling in bytes; refquota 0 == none).
 * name[] is sized to match tzfsd's TZFSD_NAME_MAX so a claim key round-trips
 * without truncation.
 */
struct service_storage_claim {
	char		name[64];
	uint64_t	used;
	uint64_t	refquota;
};
/*
 * Enumerate the caller's OWN persistent/cache storage claims (those granted via
 * service_storage_open(3)), so a consumer that has forgotten a claim's name can
 * still find it to service_storage_destroy(3) it.  tzfsd scopes the walk to the
 * caller's own label-derived namespace, so this can only ever return the
 * caller's claims and never another label's.  Up to `max` entries are written to
 * `claims` and their number stored in *countp.  Enumeration is paged: pass
 * *cursorp == 0 for the first page; on return *cursorp is nonzero when more
 * claims remain (re-issue with that value) and 0 when the last page was
 * returned.  A buffer of SERVICE_STORAGE_LIST_MAX entries always holds a whole
 * page; a smaller `max` that cannot hold the returned page fails EMSGSIZE
 * (never a silent truncation).  Returns 0, or -1 with errno.
 */
#define	SERVICE_STORAGE_LIST_MAX	32	/* claims per page (== provider) */
int	service_storage_list(struct service_context *,
	    struct service_storage_claim *claims, size_t max, size_t *countp,
	    uint32_t *cursorp);
/*
 * Open this service's writable, label-scoped configuration area (the well-known
 * "config" claim under its per-service home) and return its mounted directory
 * root.  A place for configuration files outside the shared UNIX directories,
 * scoped so a service only ever reaches its own.  Thin wrapper over
 * service_storage_open(3).  Returns 0 with *dirfdp set, or -1 with errno.
 */
int	service_open_config(struct service_context *, int *dirfdp);

/*
 * Open an existing filesystem path via tzfsd's per-label policy (default-deny)
 * and return a Capsicum-rights-limited, close-on-exec descriptor.  Lets a
 * sandboxed service reach a device node, shared directory, or config file it
 * cannot open by path itself, with nothing declared in the manifest.  `rights`
 * is a SERVICE_OPEN_* mask; `is_dir` requires a directory.  Returns 0 with *fdp
 * set, or -1 with errno (EACCES if the label is not granted the path).
 */
#define	SERVICE_OPEN_READ	0x1u	/* CAP_READ */
#define	SERVICE_OPEN_WRITE	0x2u	/* CAP_WRITE */
#define	SERVICE_OPEN_EXEC	0x4u	/* CAP_FEXECVE */
#define	SERVICE_OPEN_LOOKUP	0x8u	/* CAP_LOOKUP (directories, for openat) */
#define	SERVICE_OPEN_IOCTL	0x10u	/* CAP_IOCTL + CAP_EVENT (device nodes) */
int	service_open_isolated(struct service_context *, const char *path,
	    unsigned rights, int is_dir, int *fdp);

int	service_capability_open(struct service_context *, const char *name,
	    const char *type, int *fd);

/*
 * Ensure a named kernel extension (module) is loaded.  sysextd is a socket-free
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
 * Enumerate the module names sysextd's allow-list permits (SYSEXT_OP_LIST), so a
 * consumer can discover what it may service_ensure_extension(3) without probing
 * names blindly.  Routed exactly like the other extension calls: a SYSTEM-domain
 * caller only.  The allow-list is global (not per-label), so every caller sees
 * the same set; the reply reveals only which names may load, never any loaded/
 * not-loaded state.  Up to `max` names are written into `names` (each a
 * SERVICE_EXTENSION_NAME_MAX-byte NUL-terminated buffer) and their number is
 * stored in *countp.  A buffer of SERVICE_EXTENSION_LIST_MAX entries always holds
 * the whole list; a smaller `max` that cannot hold it fails EMSGSIZE (never a
 * silent truncation).  Returns 0, or -1 with errno.
 */
#define	SERVICE_EXTENSION_NAME_MAX	64	/* == sysextd SYSEXT_NAME_MAX */
#define	SERVICE_EXTENSION_LIST_MAX	32	/* == sysextd SYSEXT_LIST_MAX */
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

/*
 * Confine this process to a jail via warden (system.Namespace).  Consumer self-
 * service: libservice resolves warden by name, has it create a jail rooted at
 * `path` (scoped by this process's channel label), and jail_attach_jd(2)s the
 * process to the returned descriptor — whose root credential authorizes the
 * attach, so a non-root caller may confine itself.  hostname/ip4_addr may be
 * NULL.  switchboard is not involved.
 *
 * `flags` is 0 for a persistent jail (reused by label across restarts) or
 * SERVICE_NS_EPHEMERAL for a jail whose lifetime is bound to this process (torn
 * down when the process exits).  Returns 0, or -1 with errno.
 */
#define	SERVICE_NS_EPHEMERAL	0x1u	/* jail lifetime bound to the caller */
#define	SERVICE_NS_VNET		0x2u	/* jail gets its own vnet (needs VIMAGE) */
int	service_enter_namespace(struct service_context *, const char *path,
	    const char *hostname, const char *ip4_addr, unsigned flags);
/*
 * As service_enter_namespace(3) but with an IPv6 address (ip6_addr; "" or NULL =
 * none) and the full SERVICE_NS_* flag set, including SERVICE_NS_VNET for a
 * jail with its own virtual network stack.  service_enter_namespace is this with
 * ip6_addr="".  Returns 0, or -1 with errno.
 */
int	service_enter_namespace_ex(struct service_context *, const char *path,
	    const char *hostname, const char *ip4_addr, const char *ip6_addr,
	    unsigned flags);
/*
 * Destroy the caller's namespace (jail), scoped to the caller's own label so it
 * can never name another's.  Returns 0, or -1 with errno (ENOENT if none).
 */
int	service_destroy_namespace(struct service_context *);

/*
 * The caller's namespace (jail) as reported by service_namespace_info(3).  A
 * label owns at most one jail: present==1 with the fields filled, or present==0.
 * An address field is empty ("") when the jail has no address of that family.
 *
 * `flags` carries the SERVICE_NS_* bits describing the jail, so a consumer that
 * lists after a restart can pass them straight back to service_enter_namespace_ex
 * to reconstruct a matching request: SERVICE_NS_VNET when the jail has its own
 * virtual network stack, SERVICE_NS_EPHEMERAL when this process's own connection
 * is anchoring the jail's lifetime (a persistent jail reused across a restart
 * reports it clear).
 */
struct service_namespace_info {
	int		present;	/* 1 = the caller has a jail, 0 = none */
	int		jid;		/* jail id when present */
	unsigned	flags;		/* SERVICE_NS_* describing the jail */
	char		path[PATH_MAX];	/* jail root path */
	char		hostname[64];	/* host.hostname */
	char		ip4_addr[64];	/* ip4.addr (empty if none) */
	char		ip6_addr[64];	/* ip6.addr (empty if none) */
};
/*
 * Report the caller's namespace (jail) into *out.  present==0 (no jail) is still
 * a success (returns 0).  Owner-scoped.  Returns -1 with errno on real failure.
 */
int	service_namespace_info(struct service_context *,
	    struct service_namespace_info *out);

/*
 * Obtain a host-local vsock (VM socket) listener from vmd (system.VM).  Consumer
 * self-service: libservice resolves vmd by name (pulling it up on demand) and
 * has it bind a listening AF_VSOCK socket on the caller's behalf — a capability-
 * mode process cannot bind a vsock address itself.  `port` is an index within
 * the caller's own label-scoped window (0 .. VMD_PORTS_PER_LABEL-1), so it can
 * never name another Component's port; `backlog` is the listen backlog (0 =
 * default).  On success fdp receives the close-on-exec listening descriptor to
 * accept(2) on, and cidp/portp (when non-NULL) the concrete host-local CID and
 * port bound.  Returns 0, or -1 with errno.
 */
int	service_vsock_listen(struct service_context *, unsigned port,
	    unsigned backlog, unsigned *cidp, unsigned *portp, int *fdp);

/*
 * Dial a peer's advertised vsock (cid,port) via vmd (system.VM) and return the
 * connected AF_VSOCK socket — a capability-mode process cannot connect a vsock
 * address itself.  `port` is the concrete port the peer advertised from its own
 * service_vsock_listen reply (not a window index); `cid` is the target CID and
 * must not be VMADDR_CID_ANY (0xffffffff).  On success *fdp receives the close-
 * on-exec connected descriptor.  Returns 0, or -1 with errno.
 */
int	service_vsock_connect(struct service_context *, unsigned cid,
	    unsigned port, int *fdp);

/*
 * Report the caller's OWN vsock port window from vmd (VMD_OP_VSOCK_LIST), so a
 * Component can discover the concrete port range it may service_vsock_listen(3)
 * within (and the base to advertise) without guessing.  Data-only: no descriptor.
 * The answer is derived entirely from the caller's unforgeable channel label, so
 * it can only ever be the caller's own window and never another Component's.  On
 * success stores (when non-NULL) the host-local CID in *cidp, the first concrete
 * port of the window in *port_basep, and the window width (VMD_PORTS_PER_LABEL)
 * in *port_countp; a window index i passed to service_vsock_listen(3) maps to
 * concrete port (*port_basep + i).  Returns 0, or -1 with errno.
 */
int	service_vsock_list(struct service_context *, unsigned *cidp,
	    unsigned *port_basep, unsigned *port_countp);

/*
 * Return the manager-owned socket-activation listener (Phase 4) delivered under
 * the given logical name, or -1 with errno ENOENT if the process has none by
 * that name (EINVAL for a malformed name).  switchboard binds, listen(2)s, and
 * holds the socket, so it survives this provider's restarts with its backlog
 * intact; the returned descriptor is owned by libservice for the life of the
 * process — accept(2)/recv on it, but do not close it.
 */
int	service_activation_socket(const char *name);

/*
 * Activate every isolation token delivered in the bootstrap descriptor.
 * switchboard only delivers tokens; policy activation is deliberately an
 * explicit service decision.  The function consumes the token descriptors.
 * Because kernel authorization is a descriptor lease, the library retains
 * private close-on-exec references until process exit.
 */
int	service_worker_protect(uint32_t flags);

/*
 * Drop every descriptor authority retained internally by libservice.
 * A freshly forked component worker calls this after
 * service_worker_protect() and before cap_enter().  Application-owned
 * session, ring, and bearer
 * descriptors are not affected.
 */
void	service_worker_drop_inherited_authority(void);

/*
 * Channel/descriptor hardening: apply the capability-plane triple
 * (cap_xfer_limit, cap_clofork_limit, cap_cloexec_limit) that every daemon
 * reinvented as harden_{factory,worker,transfer}_*.  Default (flags 0) is the
 * "held for good" channel: XFER_NONE + CLOFORK_LOCKED.  cloexec is always
 * locked.  Returns 0, or -1 with errno.
 *   SERVICE_HARDEN_XFER_ONCE     -- descriptor will be delegated exactly once
 *   SERVICE_HARDEN_CLOFORK_ONCE  -- descriptor survives exactly one more fork
 */
#define	SERVICE_HARDEN_XFER_ONCE	0x1u
#define	SERVICE_HARDEN_CLOFORK_ONCE	0x2u
int	service_harden_fd(int fd, unsigned flags);

/*
 * Enter capability mode in a freshly forked worker: the standard sequence
 * service_worker_protect(protect_flags) -> service_worker_drop_inherited_
 * authority() -> capmode preflight (tz/NLS/errno warm) -> cap_enter().  The
 * worker-side mirror of service_provider_enter_capability_mode(3) that six
 * daemons hand-rolled (and which skipped the preflight).  No-op cap_enter if
 * the process is already in capability mode.  Returns 0, or -1 with errno.
 */
int	service_worker_enter_capability_mode(uint32_t protect_flags);

/*
 * True if the process is already in capability mode (cap_getmode(2) != 0).
 * The one guard a daemon needs before deciding to init Casper: a born-in-
 * capability-mode daemon cannot fork a Casper zygote (that must happen before
 * cap_enter(2)), so it must take its capmode-native path instead.  Treats a
 * cap_getmode failure as "in capmode" (fail-safe: skip the pre-capmode work).
 */
bool	service_in_capability_mode(void);

/*
 * Set a stable ps(1) title from the unit switchboard launched this daemon as
 * (CAPABILITY_UNIT_DIR basename, minus a trailing ".unit"), so a born-in-
 * capability-mode daemon -- exec'd through /libexec/ld-elf.so.1 -- shows its
 * own name in ps rather than "ld-elf.so.1 -f N ...".  Falls back to
 * getprogname().  A daemon wanting a bespoke title calls setproctitle(3)
 * directly instead of this.
 */
void	service_set_proctitle(void);

/*
 * Every exposed global name has an independent listener and accept queue.
 * service_listener_close() consumes the listener and withdraws that name.
 */
int	service_listener_close(struct service_listener *listener);
int	service_listener_fd(const struct service_listener *listener);
int	service_listener_accept(struct service_listener *,
	    struct service_identity *, int *session_fd);

/*
 * Connect to a global service.  The returned session descriptor is owned by
 * the caller.  switchboard supplies authenticated provider and client
 * identities when it creates the direct channel.
 */
int	service_connect(struct service_context *, const char *name,
	    int *session_fd);
int	service_helper_open(struct service_context *, const char *name,
	    int *session_fd);


/*
 * Client-side connect.  service_connect_ambient() resolves a name over the
 * §21 ambient lookup channel a login session inherits (SERVICE_LOOKUP_FD),
 * for a program run from a shell that has no switchboard bootstrap context.
 * service_open() is the context-agnostic front door: it uses the bootstrap
 * dispatch channel when switchboard launched the caller, and falls back to the
 * ambient channel otherwise -- consumer client_open() paths call it so they
 * work both as a switchboard-launched service and as a standalone CLI.
 */
int	service_connect_ambient(const char *name, int *session_fd);
int	service_open(const char *name, int *session_fd);

/*
 * Which session channel a mint request asks switchboard to create (§6).  The
 * numeric values are the wire domain values SVC_OP_MINT_DOMAIN carries, with
 * USER == 0 so a zero-initialized request defaults to the scoped channel.
 */
enum service_mint_kind {
	SERVICE_MINT_USER = 0,		/* per-uid scoped channel */
	SERVICE_MINT_SYSTEM = 1,	/* full-discovery admin channel */
};

/*
 * The principal->bundle admin decision lives in libcapbundle
 * (capbundle_principal_is_admin, docs/capability-authority-model.md P1), which
 * can read the UCL policy; login/su call it there.
 */

/*
 * Mint a session lookup channel (§6/§21/§22) over a borrowed SYSTEM-domain
 * lookup channel (syschan).  `kind` selects the minted channel's scope:
 * SERVICE_MINT_USER binds a per-uid scoped channel; SERVICE_MINT_SYSTEM binds a
 * full-discovery admin channel (for a root/wheel session) and uid is ignored.
 * On success *out_fd is a new, caller-owned ambient descriptor: it survives fork
 * and exec and is usable in capability mode, ready to be installed as a session
 * leader's inherited lookup channel.  Fails with EPERM if syschan is not a
 * SYSTEM-domain channel (domains only ever narrow), or — for a SERVICE_MINT_SYSTEM
 * request — if switchboard refuses the privilege for the requesting channel.
 */
int	service_mint_session_domain(int syschan, enum service_mint_kind kind,
	    uid_t uid, int *out_fd);

/*
 * Thin backward-compatible wrapper: mint a per-uid USER-domain channel.
 * Equivalent to service_mint_session_domain(syschan, SERVICE_MINT_USER, ...).
 */
int	service_mint_user_domain(int syschan, uid_t uid, int *out_fd);

/*
 * Like service_mint_session_domain() but delivers a transferable descriptor for
 * a caller that must forward it over one more SCM_RIGHTS hop before installing
 * it (sshd's monitor -> session child).  See the implementation for the
 * CAP_XFER contract.  Ordinary login/su sessions must NOT use this.
 */
int	service_mint_session_domain_resend(int syschan, enum service_mint_kind kind,
	    uid_t uid, int *out_fd);

/*
 * Mint this session's lookup channel through the auth-agent (system.auth),
 * reached over the caller's ambient SYSTEM lookup channel.  Unlike
 * service_mint_session_domain(), the caller does NOT decide SYSTEM vs USER and
 * holds no mint authority: the agent resolves the principal and applies policy.
 * A login program (login/su/sshd) uses this as the primary path and falls back
 * to service_mint_session_domain() when the agent is unreachable.  Returns 0
 * with *out_fd set on success; -1 (with errno) otherwise.
 *
 * `flags` is 0 for a session leaf that installs the channel directly (login,
 * su): the delivered descriptor arrives non-transferable.  Pass
 * SERVICE_MINT_AGENT_FORWARDABLE when the caller must forward the descriptor
 * over one more SCM_RIGHTS hop before it is installed (sshd's monitor -> session
 * child): the descriptor then arrives transferable and the caller must
 * re-attenuate it (cap_xfer_limit CAP_XFER_ONCE) before the single forward.
 */
#define	SERVICE_MINT_AGENT_FORWARDABLE	0x1u
/*
 * Bound of one lookup RPC to switchboard (a parked lookup -- the provider is
 * launched but has not checked in yet -- times out and may be retried), and
 * the whole-exchange budget the login programs give
 * service_mint_session_via_agent(): long enough for a console autologin or
 * an early ssh session to outlast the agent's own start-up (its identity
 * databases arrive through system.Filesystem) on a slow boot, short enough
 * that a broken agent costs one bounded wait per login, never a hang.
 */
#define	SERVICE_LOOKUP_TIMEOUT_MS	2000U
#define	SERVICE_MINT_SESSION_TIMEOUT_MS	10000U
int	service_mint_session_via_agent(int lookup_chan, uid_t uid,
	    uint32_t flags, unsigned timeout_ms, int *out_fd);
/*
 * Authenticated session mint for a non-admin caller: like
 * service_mint_session_via_agent(), but the caller proves the TARGET uid's
 * `password` (as su collected it through PAM) instead of holding
 * SERVICE_RIGHTS_ADMIN.  Used by su from an ordinary session, whose channel
 * carries no admin bit.  `flags` accepts SERVICE_MINT_AGENT_FORWARDABLE.  The
 * password buffer is zeroed before return.
 */
int	service_mint_session_authenticated(int lookup_chan, uid_t uid,
	    const char *password, uint32_t flags, unsigned timeout_ms,
	    int *out_fd);

/*
 * Mint a session lookup channel over the provider's OWN bootstrap channel to
 * switchboard (not a borrowed syschan).  Delivered transferable (RESEND) so the
 * caller can forward it over one more hop.  The auth-agent path; see
 * docs/auth-agent-design.md.
 */
int	service_context_mint_domain(struct service_context *context,
	    enum service_mint_kind kind, uid_t uid, int *out_fd);

/*
 * Anointments (docs/ipc-anointments-design.md).  A mint may carry the set of
 * anointment names the minted session holds; switchboard matches that set
 * against each endpoint's per-endpoint `requires` at lookup time, after the
 * existing domain check.  Names are NUL-terminated reverse-domain strings of
 * at most SERVICE_ANOINT_NAME_MAX - 1 characters; at most SERVICE_ANOINT_MAX
 * per mint (both equal the switchboard wire bounds SVC_ANOINT_*).
 *
 * `all` marks a session that holds every anointment (the principal policy's
 * `*`); `names`/`n` are then ignored.  `admin_rights` makes connections
 * resolved from the session carry SVC_RIGHTS_ADMIN.  The non-anointed
 * functions above are equivalent to n = 0, all = admin_rights =
 * (kind == SERVICE_MINT_SYSTEM), which preserves their historical meaning.
 */
#define	SERVICE_ANOINT_NAME_MAX	64
#define	SERVICE_ANOINT_MAX	32

int	service_context_mint_domain_anointed(struct service_context *context,
	    enum service_mint_kind kind, uid_t uid,
	    const char (*names)[SERVICE_ANOINT_NAME_MAX], unsigned n,
	    bool all, bool admin_rights, int *out_fd);

/* Raw-fd equivalent over a borrowed SYSTEM-domain lookup channel. */
int	service_mint_session_domain_anointed(int syschan,
	    enum service_mint_kind kind, uid_t uid,
	    const char (*names)[SERVICE_ANOINT_NAME_MAX], unsigned n,
	    bool all, bool admin_rights, int *out_fd);

/*
 * Elevate: obtain a session lookup channel that holds the caller's current
 * anointment set plus `name` (docs/ipc-anointments-design.md "Elevation").
 * system.auth is resolved over the caller's ambient lookup channel
 * (service_ambient_lookup_fd()); the agent takes the caller's uid and session
 * from the kernel-stamped sender, never from the payload, checks the
 * principal's `may_elevate` policy, authenticates `password` against the
 * caller's own account, and mints session-set-plus-one.  On success *out_fd is
 * the minted channel (install it with service_install_ambient_lookup() before
 * exec).  The password buffer passed in is NOT modified; the request copy is
 * zeroed before return.  Returns 0 on success, -1 with errno: EINVAL (bad or
 * over-long argument), ENOENT (no ambient channel or no agent), EPERM (name
 * not in the caller's may_elevate), EACCES (authentication failed), EBADMSG
 * (malformed reply), ETIMEDOUT.
 */
int	service_elevate(const char *name, const char *password,
	    unsigned timeout_ms, int *out_fd);

#define	SERVICE_CLIENT_TIMEOUT_INFINITE	UINT32_MAX

struct service_message {
	size_t		size;
	const void	*data;
	size_t		length;
	const int	*fds;
	size_t		nfds;
};

struct service_reply {
	size_t		size;
	void		*data;
	size_t		capacity;
	size_t		length;
	int		*fds;
	size_t		fd_capacity;
	size_t		nfds;
	struct service_message_metadata metadata;
};

struct service_call_options {
	size_t		size;
	uint32_t	timeout_ms;
	uint32_t	flags;
	uint64_t	reserved[2];
};

#define	SERVICE_CALL_OPTIONS_INITIALIZER {			\
	.size = sizeof(struct service_call_options),		\
	.timeout_ms = SERVICE_CLIENT_TIMEOUT_INFINITE,		\
	.flags = 0,						\
	.reserved = { 0, 0 }					\
}

int	service_session_create(int fd, struct service_session **session);
int	service_session_fail(struct service_session *session, int error);
void	service_session_close(struct service_session *session);
/* True once a session has failed terminally (provider gone, protocol error). */
bool	service_session_is_dead(const struct service_session *session);
int	service_session_call(struct service_session *,
	    const struct service_message *, struct service_reply *,
	    const struct service_call_options *);
int	service_session_receive_event(struct service_session *,
	    struct service_reply *, const struct service_call_options *);

__END_DECLS

#endif /* !_LIBSERVICE_H_ */
