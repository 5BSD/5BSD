/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BHYVE_MIGRATION_CHANNEL_H_
#define _BHYVE_MIGRATION_CHANNEL_H_
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include "migration_credentials.h"
#include "migration_session.h"
#ifndef NO_OPENSSL
#include "migration_tls.h"
#endif
struct migration_channel {
	struct migration_transport_fd plain;
	bool secure;
#ifndef NO_OPENSSL
	struct migration_tls tls;
#endif
};

/*
 * Every migration transport must be authenticated and encrypted with mutual
 * TLS: the stream carries guest memory and CPU state, and its CRC is a framing
 * check, not authentication.  Plaintext is accepted only when the operator
 * explicitly opted in (plaintext_unix) and the descriptor is a local AF_UNIX
 * stream socket, so both endpoints are on this host.
 */
static inline int
migration_channel_policy(int fd, bool have_credentials, bool plaintext_unix)
{
	struct sockaddr_storage ss;
	socklen_t len;
	int type;

	if (have_credentials)
		return (0);
	if (!plaintext_unix)
		return (EACCES);
	len = sizeof(ss);
	memset(&ss, 0, sizeof(ss));
	if (getsockname(fd, (struct sockaddr *)&ss, &len) != 0)
		return (errno == ENOTSOCK ? EPROTONOSUPPORT : errno);
	if (ss.ss_family != AF_UNIX)
		return (EPROTONOSUPPORT);
	len = sizeof(type);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) != 0)
		return (errno);
	if (type != SOCK_STREAM)
		return (EPROTONOSUPPORT);
	return (0);
}
static inline int
migration_channel_init(struct migration_channel *channel,
    struct migration_transport *transport, int fd, bool server,
    const struct migration_tls_credentials *credentials, int timeout_ms)
{
	if (channel == NULL || transport == NULL) return (EINVAL);
	memset(channel, 0, sizeof(*channel));
	memset(transport, 0, sizeof(*transport));
	if (credentials == NULL) {
		migration_transport_fd_init(transport, &channel->plain, fd, timeout_ms);
		return (0);
	}
#ifdef NO_OPENSSL
	(void)server;
	return (EOPNOTSUPP);
#else
	int error = migration_tls_init(&channel->tls, transport, fd, server,
	    credentials, timeout_ms);
	channel->secure = error == 0;
	return (error);
#endif
}
static inline void
migration_channel_cleanup(struct migration_channel *channel)
{
#ifndef NO_OPENSSL
	if (channel->secure) migration_tls_cleanup(&channel->tls);
#endif
	channel->secure = false;
}

/* Export only authenticated identities, ordered identically on both hosts. */
static inline int
migration_channel_binding(const struct migration_channel *channel, bool source,
    uint8_t source_certificate[32], uint8_t destination_certificate[32])
{
	if (channel == NULL || source_certificate == NULL ||
	    destination_certificate == NULL) return (EINVAL);
	if (!channel->secure) return (EACCES);
#ifdef NO_OPENSSL
	(void)source;
	return (EOPNOTSUPP);
#else
	memcpy(source_certificate, source ? channel->tls.local_certificate_sha256 :
	    channel->tls.peer_certificate_sha256, 32);
	memcpy(destination_certificate, source ? channel->tls.peer_certificate_sha256 :
	    channel->tls.local_certificate_sha256, 32);
	return (0);
#endif
}
#endif
