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
 * Initialize the library.  Reads ORACLED_CHANNEL_FD from environment.
 * Must be called before any other function.
 * Returns 0 on success, -1 on failure (pair fd not set).
 */
int	service_init(void);

/*
 * Return the channel fd to serviced.  Useful for kqueue registration.
 * Returns -1 if not initialized.
 */
int	service_channel_fd(void);

/*
 * Return a borrowed descriptor for a manifest-declared capability service.
 * Current names are "mount", "node", "accounting", and "identity".
 * These descriptors are ready for service-specific ioctls; unlike access
 * tokens, they are not activated.  The descriptor remains owned by libservice.
 */
int	service_capability_fd(const char *name);

/*
 * Activate every isolation token listed in ORACLED_TOKEN_FDS for the
 * calling process.  serviced only delivers tokens; policy activation is
 * deliberately an explicit service decision.  The function consumes the
 * token descriptors and removes ORACLED_TOKEN_FDS after validation.  Because
 * kernel authorization is a descriptor lease, the library retains private
 * close-on-exec references until process exit; callers must not close or
 * otherwise use the descriptor numbers from the removed environment value.
 */
int	service_authorize_capabilities(void);

/*
 * Apply mac_capability_capprotect shielding to this service process.
 * The service must have inherited ORACLED_CAPPROTECT_FD from serviced.
 * Use SERVICE_PROTECT_* flags.  A flags value of 0 requests all current
 * capprotect protections; explicit flags are preferable for stable policy.
 */
int	service_protect(uint32_t flags);

/*
 * Report readiness to serviced.  Dependents waiting on this
 * service's provides[] will not start until ready is sent.
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
 * Receive a message from a pair fd.  Convenience wrapper.
 * Returns bytes received on success, -1 on failure.
 * If peer_fd is non-NULL and the message carries an attached fd,
 * it is stored there (-1 if no fd attached).
 */
ssize_t	service_recv(int fd, void *buf, size_t bufsz, int *peer_fd);

__END_DECLS

#endif /* !_LIBSERVICE_H_ */
