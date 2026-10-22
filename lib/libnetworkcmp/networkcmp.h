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

/* bsd.network.v1 Network wire major (networkcmp.fidl). */
#define	NETWORKCMP_WIRE_VERSION	1

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
int	networkcmp_client_open_admin(struct networkcmp_client **client);
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
 * Bind+listen a TCP socket on an OS-assigned loopback port and return the
 * narrowed listening descriptor in *out_fd; the concrete port bound is stored in
 * *port_out (for the caller to advertise).  The caller accept(2)s on the fd
 * itself (capability-mode legal); accepted connections inherit its rights.
 * backlog 0 selects SOMAXCONN.  Requires the label's `listen` policy.
 */
int	networkcmp_listen(struct networkcmp_client *, uint16_t backlog,
	    uint16_t *port_out, int *out_fd);
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

/*
 * system.Network.PF (NETWORKCMP_PF_INTERFACE; the caller's software identity
 * must hold system.network.pf.read): one short session that returns, in
 * *out_fd, a pf(4) descriptor reporting the state table of the caller's own
 * vnet.  The descriptor carries exactly CAP_READ, CAP_FSTAT and CAP_IOCTL,
 * admits only DIOCGETSTATES (struct pfioc_states of struct pfsync_state,
 * <net/pfvar.h>), no fcntls, and cannot be transferred again; the library
 * refuses anything else with EPROTO.  Independent of the process client:
 * each call opens and closes its own session.  Returns 0, or -1 with errno
 * (ENOENT when the endpoint is not resolvable for this identity, the
 * provider's errno for a refused or failed open).
 */
int	networkcmp_pf_open(int *out_fd);

__END_DECLS

#endif /* !_NETWORKCMP_H_ */
