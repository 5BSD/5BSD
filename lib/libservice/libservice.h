/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libservice — client library for services managed by serviced(8).
 *
 * Provides a clean API for services to communicate with serviced
 * over their inherited pair fd.  Services link against libservice
 * and never need to know about cap_rt ioctls.
 *
 * Typical usage:
 *
 *   service_init();
 *   service_ready();
 *   service_register("org.freebsd.myservice");
 *
 *   for (;;) {
 *       int client = service_accept();
 *       // handle client on the returned fd
 *   }
 *
 * Or for a client connecting to another service:
 *
 *   service_init();
 *   int peer = service_lookup("org.freebsd.myservice");
 *   // talk to peer
 */

#ifndef _LIBSERVICE_H_
#define	_LIBSERVICE_H_

#include <sys/types.h>

__BEGIN_DECLS

/*
 * Initialize the library.  Reads ORACLED_PAIR_FD from environment.
 * Must be called before any other function.
 * Returns 0 on success, -1 on failure (pair fd not set).
 */
int	service_init(void);

/*
 * Return the pair fd to serviced.  Useful for kqueue registration.
 * Returns -1 if not initialized.
 */
int	service_pair_fd(void);

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
