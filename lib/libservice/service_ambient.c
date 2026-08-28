/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Ambient lookup-channel helpers (§21).
 *
 * A process reaches serviced through an inherited "ask serviced" lookup
 * channel, exactly the way it inherits standard I/O: the descriptor is ambient
 * (survives every fork via CAP_CLOFORK_UNLOCKED, survives exec by not being
 * close-on-exec) and its number is advertised in SERVICE_LOOKUP_ENV so a child
 * can find it after execve(2).  serviced installs a SYSTEM-scoped channel
 * before running /etc/rc; the login path (login, su) narrows it to a
 * per-uid user-domain channel and re-advertises that instead.
 *
 * These helpers are best-effort discovery, never authority.  Every caller
 * treats a -1 return as "no ambient channel" and proceeds exactly as it would
 * without one; a broken ambient carry must never fail a boot or a login.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libservice.h"
#include "serviced_svc_proto.h"
#include "service_bootstrap.h"

/*
 * Bound for the ambient HELLO handshake.  The probe must never block a login or
 * an su indefinitely, so it gives up after this many milliseconds and treats a
 * silent channel as "not the lookup channel".  A genuine lookup channel (or a
 * unit control channel answering ENOTSUP) replies far inside this window; the
 * timeout only guards a wedged or half-open peer.  Same order as the other
 * bounded serviced RPCs (component_request's 2s bootstrap deadline).
 */
#define	AMBIENT_HELLO_TIMEOUT_MS	2000U

/*
 * Behavioral handshake (§11a D1): a MAC_CAPABILITY_GETINFO check proves the fd
 * is an open mac_capability channel, but it does NOT prove it is THE ambient
 * lookup channel — a service's unit control channel sits at the same fd 3
 * (SVC_CHANNEL_FD == SERVICE_LOOKUP_FIXED_FD) and answers GETINFO identically,
 * and all anonymous channels share one generic name/badge, so neither
 * discriminates.  So after the cheap GETINFO gate we send SVC_OP_AMBIENT_HELLO
 * and accept the fd only if serviced's lookup-channel handler answers with the
 * magic ack inside a bounded timeout.  A unit control channel returns ENOTSUP
 * (its dispatcher has no case for this op); a wedged peer times out; either way
 * the fd is rejected.
 *
 * Strictly non-fatal and bounded: every failure path returns false and the
 * caller degrades to "no ambient channel".  fd is borrowed — service_session_*
 * takes ownership of the descriptor it is handed, so we probe over a private
 * duplicate and never disturb the caller's fd.
 */
static bool
ambient_fd_speaks_hello(int fd)
{
	struct svc_ambient_hello_req req;
	struct svc_ambient_hello_reply reply_data;
	struct service_message message = {
		.size = sizeof(message),
		.data = &req,
		.length = sizeof(req),
	};
	struct service_reply reply = {
		.size = sizeof(reply),
		.data = &reply_data,
		.capacity = sizeof(reply_data),
	};
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_session *session;
	int dupfd, saved;
	bool ok;

	dupfd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (dupfd == -1)
		return (false);
	if (service_session_create(dupfd, &session) == -1) {
		(void)close(dupfd);
		return (false);
	}

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_AMBIENT_HELLO;
	memset(&reply_data, 0, sizeof(reply_data));
	options.timeout_ms = AMBIENT_HELLO_TIMEOUT_MS;

	ok = false;
	if (service_session_call(session, &message, &reply, &options) == 0 &&
	    reply.length == sizeof(reply_data) && reply_data.status == 0 &&
	    reply_data.magic == SVC_AMBIENT_HELLO_MAGIC)
		ok = true;

	saved = errno;
	service_session_close(session);
	errno = saved;
	return (ok);
}

/*
 * A candidate ambient fd must be an open mac_capability channel (cheap GETINFO
 * gate) AND prove it is the lookup channel by answering the HELLO handshake.
 * Rejecting on either count keeps a stale, spoofed, or wrong-kind fd (a unit
 * control channel, a pipe) from being handed back as the ambient channel.
 */
static bool
ambient_fd_is_channel(int fd)
{
	struct mac_capability_info_args info;

	memset(&info, 0, sizeof(info));
	if (ioctl(fd, MAC_CAPABILITY_GETINFO, &info) != 0)
		return (false);
	return (ambient_fd_speaks_hello(fd));
}

int
service_ambient_lookup_fd(void)
{
	const char *value;
	char *end;
	long fd;

	/*
	 * Preferred source: the fd number advertised in SERVICE_LOOKUP_ENV.
	 * This covers the login->shell hop and every process serviced or a
	 * login shell launched directly, all of which inherit and re-advertise
	 * the variable.
	 */
	value = getenv(SERVICE_LOOKUP_ENV);
	if (value != NULL && value[0] != '\0') {
		errno = 0;
		fd = strtol(value, &end, 10);
		if (errno == 0 && end != value && *end == '\0' &&
		    fd >= 0 && fd <= INT_MAX &&
		    ambient_fd_is_channel((int)fd))
			return ((int)fd);
	}

	/*
	 * Fallback source: the getty-path carry.  authority-init cannot pass the
	 * environment variable across its hand-built getty environment, so it
	 * pins the channel at the fixed descriptor number instead.  Probe that
	 * number and accept it only if it is a live mac_capability channel; a
	 * stale or unrelated fd 3 is rejected and the caller degrades to "no
	 * ambient channel".  The env source above always wins.
	 */
	if (ambient_fd_is_channel(SERVICE_LOOKUP_FIXED_FD))
		return (SERVICE_LOOKUP_FIXED_FD);

	errno = ENOENT;
	return (-1);
}

int
service_install_ambient_lookup(int fd)
{
	char buf[16];

	if (fd < 0) {
		errno = EBADF;
		return (-1);
	}
	/*
	 * Make the descriptor ambient: survive every fork and survive exec so a
	 * session leader and everything it launches inherits it (§21.1).  Leave
	 * it at its own number and advertise that number in the environment.
	 */
	if (cap_clofork_limit(fd, CAP_CLOFORK_UNLOCKED) == -1)
		return (-1);
	if (fcntl(fd, F_SETFD, 0) == -1)
		return (-1);
	if (snprintf(buf, sizeof(buf), "%d", fd) >= (int)sizeof(buf)) {
		errno = ERANGE;
		return (-1);
	}
	if (setenv(SERVICE_LOOKUP_ENV, buf, 1) == -1)
		return (-1);
	return (0);
}
