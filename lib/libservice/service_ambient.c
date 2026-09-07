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
#include "service_ambient_probes.h"

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
 * Backoff between raw SENDMSG/RECVMSG retries while serviced drains a transient
 * queue-pressure burst (a concurrent boot storm registers many lookup channels
 * at once).  20ms keeps the bounded wait responsive without busy-spinning.
 */
#define	AMBIENT_REG_BACKOFF_US	20000U
/*
 * Reply-token stamped on the one-way REGISTER send.  Must be non-zero so the
 * kernel/libchannel dispatch routes it to serviced's lookup-channel REQUEST
 * handler; a zero token is delivered as an unsolicited EVENT and discarded.
 */
#define	AMBIENT_REG_TOKEN	1ULL

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
 * Send SVC_OP_REGISTER_LOOKUP carrying `peer_fd` over the inherited shared
 * lookup channel, one-way: only the OUTBOUND side is driven, and the ACK is
 * awaited on the PRIVATE endpoint (ambient_reg_recv_ack), never on the shared
 * channel, so the shared receive-queue race is never touched.
 *
 * Deliberately a RAW MAC_CAPABILITY_SENDMSG on a private duplicate rather than a
 * libchannel channel object.  Wrapping the shared fd in a channel would churn
 * low-numbered descriptors — an extra dup, a kqueue — and set O_NONBLOCK on the
 * shared file description (dups share it).  Those transient descriptors recycle
 * their fd numbers across the registration endpoints and then COLLIDE with the
 * fallback lookup's own channel/kqueue descriptors, yielding a use-after-close
 * (a SENDMSG on an fd another teardown just closed -> EBADF) that fails the
 * fallback under a concurrent boot storm.  A bare ioctl on a duplicate that we
 * close immediately leaves the caller's fd table exactly as it was.  The kernel
 * returns EAGAIN/ENOBUFS on transient TX-queue pressure even for a blocking
 * descriptor, so a bounded backoff drains a registration burst without ever
 * mutating the shared fd's status flags.
 */
static bool
ambient_reg_send(int shared_fd, int peer_fd)
{
	struct svc_register_lookup_req reqmsg;
	struct mac_capability_sendmsg_args send;
	int dupfd, waited;
	bool ok;

	dupfd = fcntl(shared_fd, F_DUPFD_CLOEXEC, 0);
	if (dupfd == -1)
		return (false);

	memset(&reqmsg, 0, sizeof(reqmsg));
	reqmsg.op = SVC_OP_REGISTER_LOOKUP;
	reqmsg.flags = 0;
	memset(&send, 0, sizeof(send));
	send.payload = &reqmsg;
	send.payload_len = sizeof(reqmsg);
	send.fds = &peer_fd;
	send.nfds = 1;
	/*
	 * A NON-ZERO token routes this as a REQUEST to serviced's lookup-channel
	 * request handler; token 0 would be delivered to the (absent) event
	 * handler and silently discarded.  serviced never replies on the shared
	 * channel for a register (it ACKs on the adopted private endpoint), so
	 * the token is never echoed and any non-zero value serves — it only
	 * selects the request dispatch path.
	 */
	send.reply_token = AMBIENT_REG_TOKEN;

	ok = false;
	waited = 0;
	for (;;) {
		if (ioctl(dupfd, MAC_CAPABILITY_SENDMSG, &send) == 0) {
			ok = true;
			break;
		}
		if ((errno != EAGAIN && errno != ENOBUFS) ||
		    waited >= (int)AMBIENT_REG_TIMEOUT_MS)
			break;
		(void)usleep(AMBIENT_REG_BACKOFF_US);
		waited += (int)(AMBIENT_REG_BACKOFF_US / 1000U);
	}

	(void)close(dupfd);
	return (ok);
}

/*
 * Receive and validate serviced's ACK on the private endpoint.  serviced pushes
 * it as an unsolicited event on the channel it adopted, so only this process
 * (the sole holder of `private_fd`) can read it — no shared queue, no race.
 *
 * Also a RAW MAC_CAPABILITY_RECVMSG rather than a channel object, for the same
 * fd-hygiene reason as ambient_reg_send.  The endpoint is ours alone, so setting
 * O_NONBLOCK on it is isolated (it shares no file description with the shared
 * channel) and lets us bound the wait with a backoff; a blocking descriptor
 * could otherwise stall on a silent serviced.  private_fd is borrowed.
 */
static bool
ambient_reg_recv_ack(int private_fd)
{
	struct svc_register_lookup_ack ack;
	struct mac_capability_recvmsg_args recv;
	int flags, waited;
	bool ok;

	flags = fcntl(private_fd, F_GETFL);
	if (flags != -1)
		(void)fcntl(private_fd, F_SETFL, flags | O_NONBLOCK);

	ok = false;
	waited = 0;
	for (;;) {
		memset(&ack, 0, sizeof(ack));
		memset(&recv, 0, sizeof(recv));
		recv.payload = &ack;
		recv.payload_len = sizeof(ack);
		recv.fds = NULL;
		recv.nfds = 0;
		if (ioctl(private_fd, MAC_CAPABILITY_RECVMSG, &recv) == 0) {
			if (recv.payload_len == sizeof(ack) &&
			    ack.op == SVC_OP_REGISTER_LOOKUP &&
			    ack.status == 0 &&
			    ack.magic == SVC_REGISTER_LOOKUP_MAGIC)
				ok = true;
			break;
		}
		if (errno != EAGAIN || waited >= (int)AMBIENT_REG_TIMEOUT_MS)
			break;
		(void)usleep(AMBIENT_REG_BACKOFF_US);
		waited += (int)(AMBIENT_REG_BACKOFF_US / 1000U);
	}

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
	pair[0] = -1;
	pair[1] = -1;
	create_errno = 0;
	if (mac_capability_channel_create(pair) == -1)
		create_errno = errno != 0 ? errno : ENOSYS;
	SERVICE_AMBIENT_PROBE_REG_CREATE(create_errno);

	send_ok = false;
	ack_ok = false;
	if (create_errno == 0) {
		send_ok = ambient_reg_send(shared, pair[1]);
		SERVICE_AMBIENT_PROBE_REG_SEND(send_ok ? 1 : 0);
		if (send_ok) {
			ack_ok = ambient_reg_recv_ack(pair[0]);
			SERVICE_AMBIENT_PROBE_REG_ACK(ack_ok ? 1 : 0);
		}
	}

	if (service_ambient_reg_decide(create_errno, send_ok, ack_ok) ==
	    SERVICE_AMBIENT_USE_PRIVATE) {
		SERVICE_AMBIENT_PROBE_REG_RESULT(1, create_errno,
		    send_ok ? 1 : 0, ack_ok ? 1 : 0);
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
		SERVICE_AMBIENT_PROBE_REG_RESULT(0, create_errno,
		    send_ok ? 1 : 0, ack_ok ? 1 : 0);
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
