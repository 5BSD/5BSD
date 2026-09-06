/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _NETWORKCMP_H_
#define	_NETWORKCMP_H_

#include <sys/types.h>
#include <sys/socket.h>

#include <stddef.h>
#include <stdint.h>

#include "networkcmp_protocol.h"

struct addrinfo;
struct networkcmp_client;

/*
 * The network broker returns real, rights-limited, connected socket
 * descriptors.  A CONNECT or UDP call hands back a descriptor received via
 * SCM_RIGHTS; the caller owns all subsequent I/O (read/write/recv/send,
 * shutdown, get/setsockopt, and O_NONBLOCK through fcntl) on that descriptor.
 * The descriptor cannot bind, listen, accept, reconnect, or be re-sent.  The
 * broker never proxies application data.
 */

__BEGIN_DECLS

int	networkcmp_client_open(struct networkcmp_client **client);
const struct networkcmp_hello_reply *
	networkcmp_client_limits(const struct networkcmp_client *client);
void	networkcmp_client_close(struct networkcmp_client *client);
int	networkcmp_hello(struct networkcmp_client *,
	    struct networkcmp_hello_reply *reply);
/*
 * Policy-check and open a connected TCP socket to the destination address,
 * returning the connected descriptor in *out_fd on success.
 */
int	networkcmp_connect(struct networkcmp_client *,
	    const struct sockaddr *address, socklen_t address_length,
	    int *out_fd);
/*
 * As networkcmp_connect(), but bound the TCP handshake by timeout_ms: if the
 * connect does not complete within the deadline the broker fails the request
 * with ETIMEDOUT and delivers no descriptor.  timeout_ms == 0 is identical to
 * networkcmp_connect() (fully-blocking connect with the kernel default).
 */
int	networkcmp_connect_ex(struct networkcmp_client *,
	    const struct sockaddr *address, socklen_t address_length,
	    uint32_t timeout_ms, int *out_fd);
/*
 * Policy-check and open a connected UDP socket bound to the peer address,
 * returning the connected descriptor in *out_fd on success.  The datagram
 * socket accepts only send/recv to that peer.
 */
int	networkcmp_udp(struct networkcmp_client *,
	    const struct sockaddr *peer, socklen_t peer_length, int *out_fd);
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

__END_DECLS

#endif /* !_NETWORKCMP_H_ */
