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

int	networkcmp_client_open(const struct networkcmp_preferences *preferences,
	    struct networkcmp_client **client);
const struct networkcmp_hello_reply *
	networkcmp_client_limits(const struct networkcmp_client *client);
void	networkcmp_client_close(struct networkcmp_client *client);
int	networkcmp_hello(struct networkcmp_client *,
	    struct networkcmp_hello_reply *reply);
int	networkcmp_negotiate(struct networkcmp_client *,
	    const struct networkcmp_preferences *preferences,
	    struct networkcmp_hello_reply *reply);
int	networkcmp_socket(struct networkcmp_client *, uint32_t family,
	    uint32_t type,
	    uint32_t protocol, uint32_t flags,
	    struct networkcmp_handle *socket);
int	networkcmp_bind(struct networkcmp_client *,
	    struct networkcmp_handle socket,
	    const struct networkcmp_endpoint *endpoint);
int	networkcmp_connect(struct networkcmp_client *,
	    struct networkcmp_handle socket,
	    const struct networkcmp_endpoint *endpoint);
int	networkcmp_connect_status(struct networkcmp_client *,
	    struct networkcmp_handle socket);
int	networkcmp_listen(struct networkcmp_client *,
	    struct networkcmp_handle socket,
	    uint32_t backlog);
int	networkcmp_accept(struct networkcmp_client *,
	    struct networkcmp_handle socket,
	    struct networkcmp_handle *accepted);
int	networkcmp_setopt(struct networkcmp_client *,
	    struct networkcmp_handle socket,
	    uint32_t level, uint32_t option, const void *value,
	    size_t value_length);
int	networkcmp_shutdown(struct networkcmp_client *,
	    struct networkcmp_handle socket,
	    uint32_t how);
int	networkcmp_close_socket(struct networkcmp_client *,
	    struct networkcmp_handle socket);
ssize_t	networkcmp_send_inline(struct networkcmp_client *,
	    struct networkcmp_handle socket,
	    const void *buffer, size_t length);
ssize_t	networkcmp_recv_inline(struct networkcmp_client *,
	    struct networkcmp_handle socket,
	    void *buffer, size_t capacity, uint32_t timeout_ms,
	    uint32_t *flags);
int	networkcmp_resolve(struct networkcmp_client *, const char *host,
	    const char *service,
	    uint32_t family, uint32_t socket_type, uint32_t flags,
	    struct networkcmp_resolve_result *results, size_t *nresults,
	    char *canonname, size_t canonname_size, uint32_t *ttl_seconds);
int	networkcmp_getaddrinfo(struct networkcmp_client *, const char *host,
	    const char *service,
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
void	networkcmp_io_close(struct networkcmp_io *io);

/* Provider and advanced-client framing primitives. */
int	networkcmp_validate_message(const struct networkcmp_msg *msg,
	    size_t received, enum networkcmp_message_role role);
int	networkcmp_message_init(struct networkcmp_msg *msg, uint16_t opcode,
	    uint32_t flags);
int	networkcmp_message_init_reply(struct networkcmp_msg *reply,
	    const struct networkcmp_msg *request, int status);
int	networkcmp_validate_fds(const struct networkcmp_msg *msg, size_t nfds,
	    enum networkcmp_message_role role);
__END_DECLS

#endif /* !_NETWORKCMP_H_ */
