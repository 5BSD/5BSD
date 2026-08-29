/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libservice — client library for services managed by serviced(8).
 *
 * Provides a clean API for services to communicate with serviced
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

#include <stdint.h>

/* Supervisor-owned location of the selected unit's immutable bundle files. */
#define	SERVICE_UNIT_DIR_ENV	"CAPABILITY_UNIT_DIR"

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
struct service_component_bootstrap;
typedef int (*service_activation_handler)(const char *name, void *context);

enum service_component_member_type {
	SERVICE_COMPONENT_MEMBER_PROCDESC = 1,
	SERVICE_COMPONENT_MEMBER_COALITION = 2
};

struct service_identity {
	size_t	size;
	char	service_name[256];
	char	client_label[64];
	uint64_t reserved[4];
};

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
	uint32_t	reserved[3];
};

__BEGIN_DECLS

/*
 * Acquire the process-wide serviced context.  Initialization is idempotent,
 * thread-safe, and shared by every typed service library in the process.
 * The first terminal bootstrap error is returned consistently to all callers.
 * Releasing the last logical reference does not invalidate active sessions or
 * listeners.
 */
int	service_acquire(struct service_context **);
void	service_release(struct service_context *);
int	service_authorize_capabilities(struct service_context *);
int	service_enter_capability_mode(struct service_context *);
int	service_ready(struct service_context *);

/*
 * Request that serviced stop this provider after `seconds` of no new client
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
int	service_provider_expose_lazy(struct service_provider *, const char *name,
	    service_activation_handler, void *, struct service_listener **);
int	service_provider_enter_capability_mode(struct service_provider *);
int	service_provider_ready(struct service_provider *);
int	service_provider_quiescing(struct service_provider *);
int	service_provider_quiesce_complete(struct service_provider *, int status);

/*
 * Monitor the supervising serviced connection.  The borrowed event fd becomes
 * readable once the connection is permanently lost.  status returns zero
 * while the dispatcher is healthy and otherwise returns -1 with the terminal
 * transport error in errno.  It never consumes the event indication.
 */
int	service_supervisor_fd(struct service_context *);
int	service_supervisor_status(struct service_context *);

/*
 * Return the immutable serviced manifest label for this process.
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
int	service_capability_open(struct service_context *, const char *name,
	    const char *type, int *fd);

/*
 * Return the manager-owned socket-activation listener (Phase 4) delivered under
 * the given logical name, or -1 with errno ENOENT if the process has none by
 * that name (EINVAL for a malformed name).  serviced binds, listen(2)s, and
 * holds the socket, so it survives this provider's restarts with its backlog
 * intact; the returned descriptor is owned by libservice for the life of the
 * process — accept(2)/recv on it, but do not close it.
 */
int	service_activation_socket(const char *name);

int	service_local_component_open(struct service_context *,
	    const char *interface, const char *version, int *session_fd);

/*
 * Provider-side local-component bootstrap.  The opaque object owns every
 * received descriptor until its attachment slot is explicitly taken.
 * complete() and fail() consume the object on both success and failure.
 */
int	service_component_accept(int fd,
	    struct service_component_bootstrap **);
const char *service_component_name(
	    const struct service_component_bootstrap *);
const char *service_component_interface(
	    const struct service_component_bootstrap *);
const char *service_component_interface_version(
	    const struct service_component_bootstrap *);
const char *service_component_client_label(
	    const struct service_component_bootstrap *);
uint64_t service_component_instance_id(
	    const struct service_component_bootstrap *);
size_t	service_component_resource_count(
	    const struct service_component_bootstrap *);
int	service_component_take_resource(
	    struct service_component_bootstrap *, size_t slot);
int	service_component_complete(struct service_component_bootstrap *,
	    enum service_component_member_type, int member_fd);
int	service_component_fail(struct service_component_bootstrap *, int error);
void	service_component_abort(struct service_component_bootstrap *);

/*
 * Activate every isolation token delivered in the bootstrap descriptor.
 * serviced only delivers tokens; policy activation is deliberately an
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
 * Every exposed global name has an independent listener and accept queue.
 * service_listener_close() consumes the listener and withdraws that name.
 */
int	service_listener_close(struct service_listener *listener);
int	service_listener_fd(const struct service_listener *listener);
int	service_listener_accept(struct service_listener *,
	    struct service_identity *, int *session_fd);

/*
 * Connect to a global service.  The returned session descriptor is owned by
 * the caller.  serviced supplies authenticated provider and client
 * identities when it creates the direct channel.
 */
int	service_connect(struct service_context *, const char *name,
	    int *session_fd);
int	service_helper_open(struct service_context *, const char *name,
	    int *session_fd);

/*
 * Which session channel a mint request asks serviced to create (§6).  The
 * numeric values are the wire domain values SVC_OP_MINT_DOMAIN carries, with
 * USER == 0 so a zero-initialized request defaults to the scoped channel.
 */
enum service_mint_kind {
	SERVICE_MINT_USER = 0,		/* per-uid scoped channel */
	SERVICE_MINT_SYSTEM = 1,	/* full-discovery admin channel */
};

/*
 * Mint a session lookup channel (§6/§21/§22) over a borrowed SYSTEM-domain
 * lookup channel (syschan).  `kind` selects the minted channel's scope:
 * SERVICE_MINT_USER binds a per-uid scoped channel; SERVICE_MINT_SYSTEM binds a
 * full-discovery admin channel (for a root/wheel session) and uid is ignored.
 * On success *out_fd is a new, caller-owned ambient descriptor: it survives fork
 * and exec and is usable in capability mode, ready to be installed as a session
 * leader's inherited lookup channel.  Fails with EPERM if syschan is not a
 * SYSTEM-domain channel (domains only ever narrow), or — for a SERVICE_MINT_SYSTEM
 * request — if serviced refuses the privilege for the requesting channel.
 */
int	service_mint_session_domain(int syschan, enum service_mint_kind kind,
	    uid_t uid, int *out_fd);

/*
 * Thin backward-compatible wrapper: mint a per-uid USER-domain channel.
 * Equivalent to service_mint_session_domain(syschan, SERVICE_MINT_USER, ...).
 */
int	service_mint_user_domain(int syschan, uid_t uid, int *out_fd);

/*
 * Socket-authenticated session provisioning (§21/§22, item 4).  Ask serviced,
 * over its getpeereid(3)-authenticated control socket, to mint this session's
 * ambient lookup channel for `uid`, returning the caller-owned endpoint in
 * *out_fd.  Unlike service_mint_session_domain(), this needs no inherited
 * SYSTEM channel — it is the path for a login that cannot inherit one (an ssh
 * network session).  serviced chooses the scope from the TARGET uid (SYSTEM/
 * admin for root or a wheel member, USER otherwise) and permits ONLY a root
 * peer (EPERM otherwise).  On success *out_fd is ambient (survives fork/exec);
 * the caller installs it and closes its own copy.  Best-effort and bounded: any
 * failure returns -1 (errno set) and the caller must proceed with no channel.
 */
int	service_provision_session(uid_t uid, int *out_fd);

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
int	service_session_call(struct service_session *,
	    const struct service_message *, struct service_reply *,
	    const struct service_call_options *);
int	service_session_receive_event(struct service_session *,
	    struct service_reply *, const struct service_call_options *);

__END_DECLS

#endif /* !_LIBSERVICE_H_ */
