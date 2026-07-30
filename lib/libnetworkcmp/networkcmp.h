/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _NETWORKCMP_H_
#define	_NETWORKCMP_H_

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

#include "networkcmp_protocol.h"

struct addrinfo;
struct networkcmp_client;
struct networkcmp_io;

struct networkcmp_preferences {
	uint32_t	tx_ring_size;	/* zero selects provider default */
	uint32_t	rx_ring_size;	/* zero selects provider default */
	uint32_t	max_datagram;	/* zero selects provider default */
	uint32_t	reserved;
};

__BEGIN_DECLS

#define	NETWORKCMP_ENV	"NETWORKCMP"

/*
 * NULL selects the serviced-owned environment selector, then the conventional
 * "network" key.  The returned close-on-exec fd belongs to the caller.
 * Typed operations are synchronous and serialized within the library.
 */
int	networkcmp_open(const char *component);
int	networkcmp_client_open(const char *component,
	    const struct networkcmp_preferences *preferences,
	    struct networkcmp_client **client);
int	networkcmp_client_fd(const struct networkcmp_client *client);
const struct networkcmp_hello_reply *
	networkcmp_client_limits(const struct networkcmp_client *client);
void	networkcmp_client_close(struct networkcmp_client *client);
int	networkcmp_hello(int fd, struct networkcmp_hello_reply *reply);
int	networkcmp_negotiate(int fd,
	    const struct networkcmp_preferences *preferences,
	    struct networkcmp_hello_reply *reply);
int	networkcmp_socket(int fd, uint32_t family, uint32_t type,
	    uint32_t protocol, uint32_t flags,
	    struct networkcmp_handle *socket);
int	networkcmp_bind(int fd, struct networkcmp_handle socket,
	    const struct networkcmp_endpoint *endpoint);
int	networkcmp_connect(int fd, struct networkcmp_handle socket,
	    const struct networkcmp_endpoint *endpoint);
int	networkcmp_listen(int fd, struct networkcmp_handle socket,
	    uint32_t backlog);
int	networkcmp_accept(int fd, struct networkcmp_handle socket,
	    struct networkcmp_handle *accepted);
int	networkcmp_setopt(int fd, struct networkcmp_handle socket,
	    uint32_t level, uint32_t option, const void *value,
	    size_t value_length);
int	networkcmp_shutdown(int fd, struct networkcmp_handle socket,
	    uint32_t how);
int	networkcmp_close_socket(int fd, struct networkcmp_handle socket);
int	networkcmp_resolve(int fd, const char *host, const char *service,
	    uint32_t family, uint32_t socket_type, uint32_t flags,
	    struct networkcmp_resolve_result *results, size_t *nresults,
	    char *canonname, size_t canonname_size, uint32_t *ttl_seconds);
int	networkcmp_getaddrinfo(int fd, const char *host, const char *service,
	    const struct addrinfo *hints, struct addrinfo **result);
/* Release only lists returned by networkcmp_getaddrinfo(). */
void	networkcmp_freeaddrinfo(struct addrinfo *result);

/*
 * Attach one TX and one RX ring to a socket using the values accepted during
 * client negotiation.  Stream calls preserve bytes; datagram calls preserve
 * records.  Calls are nonblocking and return EAGAIN for ring backpressure.
 */
int	networkcmp_attach_io(struct networkcmp_client *client,
	    struct networkcmp_handle socket, uint32_t socket_type,
	    struct networkcmp_io **io);
ssize_t	networkcmp_write(struct networkcmp_io *io, const void *buffer,
	    size_t length);
ssize_t	networkcmp_read(struct networkcmp_io *io, void *buffer,
	    size_t capacity);
int	networkcmp_send_datagram(struct networkcmp_io *io,
	    const void *buffer, size_t length);
ssize_t	networkcmp_recv_datagram(struct networkcmp_io *io, void *buffer,
	    size_t capacity);
int	networkcmp_event_fd(const struct networkcmp_io *io);
void	networkcmp_io_close(struct networkcmp_io *io);

/* Provider and advanced-client framing primitives. */
int	networkcmp_validate_message(const struct networkcmp_msg *msg,
	    size_t received);
int	networkcmp_validate_fds(const struct networkcmp_msg *msg, size_t nfds);
int	networkcmp_send_message(int fd, const void *message, size_t length,
	    const int *fds, size_t nfds);
ssize_t	networkcmp_receive_message(int fd, void *message, size_t capacity,
	    int *fds, size_t *nfds);

__END_DECLS

#endif /* !_NETWORKCMP_H_ */
