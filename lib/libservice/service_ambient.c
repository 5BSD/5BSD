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
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <channel.h>

#include "libservice.h"
#include "serviced_svc_proto.h"
#include "service_bootstrap.h"
#include "ambient_lookup.h"

/*
 * Bound for the ambient HELLO handshake.  The probe must never block a login or
 * an su indefinitely, so it gives up after this many milliseconds and treats a
 * silent channel as "not the lookup channel".  A genuine lookup channel (or a
 * unit control channel answering ENOTSUP) replies far inside this window; the
 * timeout only guards a wedged or half-open peer.  Same order as the other
 * bounded serviced RPCs.
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
	 * Fallback source: the getty-path carry.  capsule cannot pass the
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

/*
 * Per-process private lookup channel (docs/capability-ambient-lookup-per-process.md
 * P2).  The inherited SERVICE_LOOKUP_FD is ONE shared endpoint whose single
 * kernel receive queue races: a sibling process can pump the queue and discard
 * a reply meant for another, hanging the other until timeout.  To escape it a
 * process creates its OWN connected channel pair, hands serviced one end via
 * SVC_OP_REGISTER_LOOKUP over the shared channel (a one-way send — no reply is
 * awaited there, so the racy shared receive is never touched), and thereafter
 * does every lookup on its private end, whose queue only it holds.
 *
 * Everything here is best-effort and memoized once per process: if the create
 * syscall is missing, the send fails, or no ACK arrives before the bounded
 * timeout, the process falls back to the inherited shared channel exactly as
 * before.  A broken registration must never break discovery or boot.
 */
#define	AMBIENT_REG_TIMEOUT_MS	2000U

/*
 * Registration state, memoized per process:
 *   AMBIENT_PENDING   not yet resolved (or no reachable channel yet — retry)
 *   AMBIENT_PRIVATE   registered: use ambient_priv_fd, our own endpoint
 *   AMBIENT_FALLBACK  registration is not going to work here (old kernel, or a
 *                     send/ACK failure): use the inherited shared channel, and
 *                     — crucially — re-resolve it LIVE on every call, exactly as
 *                     the pre-P2 code did, so we never memoize a transient
 *                     "serviced not up yet" into a permanent -1.
 */
enum ambient_state {
	AMBIENT_PENDING = 0,
	AMBIENT_PRIVATE,
	AMBIENT_FALLBACK,
};

static pthread_mutex_t ambient_priv_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t ambient_atfork_once = PTHREAD_ONCE_INIT;
static enum ambient_state ambient_priv_state;	/* AMBIENT_PENDING == 0 */
static int ambient_priv_fd = -1;		/* our private endpoint when PRIVATE */

/*
 * A forked child must not keep the parent's private endpoint — sharing it would
 * re-create the very cross-process race we escaped.  Drop it and re-arm so the
 * child registers its OWN channel on next ambient use.  The private endpoint is
 * close-on-exec, so the exec case re-registers automatically (fresh memory);
 * this handles fork-without-exec.
 */
static void
ambient_atfork_child(void)
{

	if (ambient_priv_state == AMBIENT_PRIVATE && ambient_priv_fd >= 0)
		(void)close(ambient_priv_fd);
	ambient_priv_fd = -1;
	ambient_priv_state = AMBIENT_PENDING;
	(void)pthread_mutex_init(&ambient_priv_lock, NULL);
}

static void
ambient_atfork_setup(void)
{

	(void)pthread_atfork(NULL, NULL, ambient_atfork_child);
}

/*
 * Reply handler for the one-way registration send.  We never dispatch the
 * shared channel's inbound side, so serviced's (absent) reply is never routed
 * here; it exists only to satisfy channel_send_request()'s non-NULL contract.
 * Should a stray reply ever be delivered, release it without touching any
 * caller state.
 */
static void
ambient_reg_reply_ignore(struct channel_request *request,
    struct channel_message *message, int error, void *context)
{

	(void)error;
	(void)context;
	if (message != NULL)
		channel_message_free(message);
	channel_request_release(request);
}

/*
 * Send SVC_OP_REGISTER_LOOKUP carrying `peer_fd` over the inherited shared
 * lookup channel, one-way: we drive only the OUTBOUND side to completion and
 * never receive on the shared channel (the ACK comes on the private endpoint),
 * so we cannot hit the shared receive-queue race.  Returns true once the
 * fd-bearing message has been flushed to the kernel.
 */
static bool
ambient_reg_send(int shared_fd, int peer_fd)
{
	struct svc_register_lookup_req reqmsg;
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	struct channel_outgoing out;
	struct channel *channel;
	struct channel_request *request;
	int dupfd, waited, ready, wants;
	bool ok;

	dupfd = fcntl(shared_fd, F_DUPFD_CLOEXEC, 0);
	if (dupfd == -1)
		return (false);
	if (channel_create(dupfd, &options, &channel) == -1) {
		(void)close(dupfd);
		return (false);
	}

	memset(&reqmsg, 0, sizeof(reqmsg));
	reqmsg.op = SVC_OP_REGISTER_LOOKUP;
	reqmsg.flags = 0;
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = &reqmsg;
	out.length = sizeof(reqmsg);
	out.fds = &peer_fd;
	out.nfds = 1;

	ok = false;
	request = NULL;
	if (channel_send_request(channel, &out, ambient_reg_reply_ignore, NULL,
	    &request) == 0) {
		/*
		 * Usually the fd-bearing message goes out inline; drive a bounded
		 * flush loop only for the rare queued case.  We NEVER dispatch the
		 * inbound side, so no reply is ever read on the shared channel.
		 */
		ok = true;
		waited = 0;
		while ((wants = channel_wants_write(channel)) == 1 &&
		    waited < (int)AMBIENT_REG_TIMEOUT_MS) {
			ready = channel_wait(channel, 1, 200);
			if (ready < 0) {
				ok = false;
				break;
			}
			waited += 200;
			if (channel_flush(channel) == -1) {
				ok = false;
				break;
			}
		}
		if (channel_wants_write(channel) == 1)
			ok = false;
	}

	channel_destroy(channel);
	return (ok);
}

/*
 * Receive and validate serviced's ACK on the private endpoint.  serviced pushes
 * it as an unsolicited event on the channel it adopted, so only this process
 * (the sole holder of `private_fd`) can read it — no shared queue, no race.
 * Bounded so a silent serviced cannot stall the caller.  private_fd is borrowed.
 */
static bool
ambient_reg_recv_ack(int private_fd)
{
	struct svc_register_lookup_ack ack;
	struct service_reply reply = {
		.size = sizeof(reply),
		.data = &ack,
		.capacity = sizeof(ack),
	};
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_session *session;
	int dupfd;
	bool ok;

	dupfd = fcntl(private_fd, F_DUPFD_CLOEXEC, 0);
	if (dupfd == -1)
		return (false);
	if (service_session_create(dupfd, &session) == -1) {
		(void)close(dupfd);
		return (false);
	}

	memset(&ack, 0, sizeof(ack));
	options.timeout_ms = AMBIENT_REG_TIMEOUT_MS;
	ok = false;
	if (service_session_receive_event(session, &reply, &options) == 0 &&
	    reply.length == sizeof(ack) && ack.op == SVC_OP_REGISTER_LOOKUP &&
	    ack.status == 0 && ack.magic == SVC_REGISTER_LOOKUP_MAGIC)
		ok = true;

	service_session_close(session);
	return (ok);
}

/*
 * The effective ambient lookup fd for this process: its private lookup channel
 * once registration has succeeded, otherwise the inherited shared channel.
 * Registration is attempted once, lazily, and memoized (including the fail-soft
 * fallback, so a failed attempt is never retried).  The returned fd is BORROWED
 * — callers dup it — and is -1 when the process has no ambient channel at all.
 */
int
service_ambient_lookup_channel(void) __no_lock_analysis
{
	int shared, pair[2], create_errno, result;
	bool send_ok, ack_ok;

	(void)pthread_once(&ambient_atfork_once, ambient_atfork_setup);

	if (pthread_mutex_lock(&ambient_priv_lock) != 0) {
		/* Cannot memoize; degrade to the inherited shared channel. */
		return (service_ambient_lookup_fd());
	}
	if (ambient_priv_state == AMBIENT_PRIVATE) {
		result = ambient_priv_fd;
		(void)pthread_mutex_unlock(&ambient_priv_lock);
		return (result);
	}
	if (ambient_priv_state == AMBIENT_FALLBACK) {
		/*
		 * Registration is known not to work here; resolve the inherited
		 * shared channel LIVE (never memoize its value) so a channel that
		 * only becomes reachable later is still found — exactly the pre-P2
		 * behavior.
		 */
		(void)pthread_mutex_unlock(&ambient_priv_lock);
		return (service_ambient_lookup_fd());
	}

	/* AMBIENT_PENDING: find the inherited shared channel we register over. */
	shared = service_ambient_lookup_fd();
	if (shared < 0) {
		/*
		 * No reachable ambient channel yet.  Stay PENDING (do NOT memoize)
		 * so a later call retries once serviced/login has installed one —
		 * matching the pre-P2 re-probe-every-call behavior.
		 */
		(void)pthread_mutex_unlock(&ambient_priv_lock);
		return (-1);
	}

	pair[0] = -1;
	pair[1] = -1;
	create_errno = 0;
	if (mac_capability_channel_create(pair) == -1)
		create_errno = errno != 0 ? errno : ENOSYS;

	send_ok = false;
	ack_ok = false;
	if (create_errno == 0) {
		send_ok = ambient_reg_send(shared, pair[1]);
		if (send_ok)
			ack_ok = ambient_reg_recv_ack(pair[0]);
	}

	if (service_ambient_reg_decide(create_errno, send_ok, ack_ok) ==
	    SERVICE_AMBIENT_USE_PRIVATE) {
		/*
		 * Keep our end (pair[0]) as the private lookup fd; close the peer
		 * (serviced holds its own duplicate).  Close-on-exec so an exec'd
		 * child re-registers instead of inheriting a shared endpoint.
		 */
		(void)fcntl(pair[0], F_SETFD, FD_CLOEXEC);
		if (pair[1] >= 0)
			(void)close(pair[1]);
		ambient_priv_fd = pair[0];
		ambient_priv_state = AMBIENT_PRIVATE;
		result = ambient_priv_fd;
	} else {
		/* Fail-soft: discard the pair, use the inherited shared channel. */
		if (pair[0] >= 0)
			(void)close(pair[0]);
		if (pair[1] >= 0)
			(void)close(pair[1]);
		ambient_priv_state = AMBIENT_FALLBACK;
		result = shared;
	}
	(void)pthread_mutex_unlock(&ambient_priv_lock);
	return (result);
}
