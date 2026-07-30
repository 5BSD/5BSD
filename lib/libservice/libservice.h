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
 * Typical usage:
 *
 *   service_init();
 *   service_authorize_capabilities();
 *   service_protect(SERVICE_PROTECT_EXTERNAL);
 *   service_register("org.5bsd.myservice");
 *   service_ready();
 *
 *   for (;;) {
 *       int client = service_accept();
 *       // handle client on the returned fd
 *   }
 *
 * Or for a client connecting to another service:
 *
 *   service_init();
 *   int peer = service_lookup("org.5bsd.myservice");
 *   // talk to peer
 */

#ifndef _LIBSERVICE_H_
#define	_LIBSERVICE_H_

#include <sys/types.h>

#include <stdint.h>

#include "component_session.h"

/*
 * Public service_protect() flags.  Keep kernel protocol details behind
 * libservice so service programs do not need mac_capability headers.
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

__BEGIN_DECLS

/*
 * Initialize the library from serviced's versioned bootstrap descriptor.
 * The descriptor is validated, mapped read-only, and closed before return.
 * Must be called exactly once before any other function.
 */
int	service_init(void);

/*
 * Return the channel fd to serviced.  Useful for kqueue registration.
 * Returns -1 if not initialized.
 */
int	service_channel_fd(void);

/*
 * Return the immutable serviced manifest label for this process.
 * The returned pointer remains owned by libservice.
 */
const char *service_label(void);

/*
 * Return a borrowed descriptor for a manifest-declared capability service.
 * Current names are "mount", "node", "accounting", and "identity".
 * These descriptors are ready for service-specific ioctls; unlike access
 * tokens, they are not activated.  The descriptor remains owned by libservice.
 */
int	service_capability_fd(const char *name);

/*
 * Return the borrowed channel for a manifest-declared component session.
 * The name is the key used under the manifest's components object.
 */
int	service_component_fd(const char *name);

/*
 * Provider-side component bootstrap helpers.  The receive helper validates
 * the versioned frame and copies its NUL-terminated JSON options.  A
 * successful reply must attach one procdesc or coalition membership fd;
 * an error reply attaches no descriptor.
 */
int	service_component_recv_bootstrap(int fd,
	    struct component_session_bootstrap *bootstrap, char *options,
	    size_t options_size);
int	service_component_send_reply(int fd, uint64_t instance_id, int status,
	    uint32_t member_type, int member_fd);

/*
 * Activate every isolation token delivered in the bootstrap descriptor.
 * serviced only delivers tokens; policy activation is deliberately an
 * explicit service decision.  The function consumes the token descriptors.
 * Because kernel authorization is a descriptor lease, the library retains
 * private close-on-exec references until process exit.
 */
int	service_authorize_capabilities(void);

/*
 * Apply mac_capability_capprotect shielding to this service process.
 * The service must have received a capprotect instance from serviced.
 * Use SERVICE_PROTECT_* flags.  A flags value of 0 requests all current
 * capprotect protections; explicit flags are preferable for stable policy.
 */
int	service_protect(uint32_t flags);

/*
 * Drop every descriptor authority retained internally by libservice.
 * A freshly forked component worker calls this after service_protect() and
 * before cap_enter().  Application-owned session, ring, and bearer
 * descriptors are not affected.
 */
void	service_drop_inherited_authority(void);

/*
 * Enter Capsicum capability mode, then send the compatibility readiness
 * advisory.  serviced promotes dependents from the independently observed
 * and verified NOTE_CAPMODE process-descriptor event.
 * Returns 0 on success, -1 on failure.
 */
int	service_ready(void);

/*
 * Register a reverse-domain name with serviced.
 * After registration, clients can connect via service_lookup().
 * Returns 0 on success, -1 on failure (sets errno).
 */
int	service_register(const char *name);

/*
 * Deregister a previously registered name.
 * Returns 0 on success, -1 on failure (sets errno).
 */
int	service_unregister(const char *name);

/*
 * Connect to a named service.
 * Returns a file descriptor for the connection, or -1 on failure.
 * The returned fd is a bidirectional pair endpoint.
 */
int	service_lookup(const char *name);

/*
 * Accept a new client connection.
 * Blocks until a client connects via service_lookup() to one of
 * this service's registered names.
 * Returns a file descriptor for the client, or -1 on failure.
 * Also fills client_label (if non-NULL) with the connecting
 * service's label (up to labelsz bytes).
 */
int	service_accept(char *client_label, size_t labelsz);

/*
 * Send a message on a pair fd.  Convenience wrapper.
 * Returns 0 on success, -1 on failure.
 */
int	service_send(int fd, const void *data, size_t len);

/*
 * Send a message with zero or more attached descriptors.
 * The descriptors are borrowed for the duration of the call.
 */
int	service_send_fds(int fd, const void *data, size_t len,
	    const int *fds, size_t nfds);

/*
 * Receive a message from a pair fd.  Convenience wrapper.
 * Returns bytes received on success, -1 on failure.
 * If peer_fd is non-NULL and the message carries an attached fd,
 * it is stored there (-1 if no fd attached).
 */
ssize_t	service_recv(int fd, void *buf, size_t bufsz, int *peer_fd);

/*
 * Receive a message and zero or more attached descriptors.
 * On entry, *nfds is the capacity of fds[].  On success it is the number
 * received.  The caller owns all returned descriptors.
 */
ssize_t	service_recv_fds(int fd, void *buf, size_t bufsz, int *fds,
	    size_t *nfds);

__END_DECLS

#endif /* !_LIBSERVICE_H_ */
