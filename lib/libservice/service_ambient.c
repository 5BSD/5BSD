/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Process-held discovery helpers. The kernel holds the inherited channel;
 * working descriptors and private per-handle reply queues are temporary.
 * Approved software has separate protected authority, not another route.
 * Registration failure never falls back to a shared receive queue.
 */

#include <sys/types.h>
#include <sys/cap_process.h>
#include <sys/cap_authority.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>

#include <dev/mac_capability/mac_capability_coalition_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <capability.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "libservice.h"
#include "libservice_session.h"
#include "service_ambient_probes.h"
#include "service_bootstrap.h"
#include "service_private.h"
#include "switchboard_svc_proto.h"

/* Probe the feature before using the new syscall on an older kernel. */
static int
process_context(int op, int fd, uid_t uid, void *data)
{
	static _Atomic int available;
	int value = 0;
	size_t len = sizeof(value);
	if (atomic_load(&available) == 0) {
		if (sysctlbyname("kern.features.cap_process", &value, &len,
			NULL, 0) < 0 ||
		    value != 1) {
			errno = ENOSYS;
			return (-1);
		}
		atomic_store(&available, 1);
	}
	return (syscall(SYS_cap_process, op, fd, uid, data));
}

int
service_authority_install(int fd)
{
	return (process_context(CAP_AUTH_INSTALL, fd, 0, NULL));
}
int
service_authority_clear(void)
{
	return (process_context(CAP_AUTH_CLEAR, -1, 0, NULL));
}
int
service_authority_info(struct cap_authority_info *info)
{
	return (process_context(CAP_AUTH_INFO, -1, 0, info));
}

int
service_process_info(struct mac_cap_process_info *info)
{
	return (process_context(MAC_CAP_PROCESS_INFO, -1, 0, info));
}

int
service_origin_export(void)
{
	return (process_context(MAC_CAP_PROCESS_ORIGIN_EXPORT, -1, 0, NULL));
}

int
service_origin_set(int token_fd)
{
	return (process_context(MAC_CAP_PROCESS_ORIGIN_SET, token_fd, 0, NULL));
}

/* An OWNED close-on-exec descriptor; caller must close it. */
static int
process_lookup_fd(void)
{
	return (process_context(MAC_CAP_PROCESS_GET, -1, 0, NULL));
}

int
service_get_ambient_lookup(void)
{
	return (process_lookup_fd());
}

int
service_clear_ambient_lookup(void)
{
	return (process_context(MAC_CAP_PROCESS_CLEAR, -1, 0, NULL));
}

int
service_install_ambient_lookup(int fd)
{
	if (fd < 0) {
		errno = EBADF;
		return (-1);
	}
	/* The kernel slot, not this temporary descriptor, is inherited on exec.
	 */
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
		return (-1);
	/* Discovery is a route; the separate authority context identifies software. */
	return (process_context(MAC_CAP_PROCESS_SET, fd, 0, NULL));
}

int
service_session_join_fd(int fd)
{
	struct coalition_req_hdr request = { .op = COALITION_OP_JOIN_REHOME };
	struct coalition_reply response;
	size_t length = sizeof(response), nfds = 0;

	if (capability_kernel_call(fd, &request, sizeof(request), NULL, 0,
	    &response, &length, NULL, &nfds) == -1)
		return (-1);
	if (length != sizeof(response) || nfds != 0 ||
	    response.status < 0 || response.status > ELAST)
		return (errno = EBADMSG, -1);
	return (response.status == 0 ? 0 : (errno = response.status, -1));
}

/*
 * Each owned lookup handle has its own reply queue. The kernel-held channel
 * is used only for one-way registration, never to receive lookup replies.
 * Failed registration is retryable and never falls back to a shared queue.
 *
 * No step is bounded by a clock: a lookup ends with switchboard's answer,
 * with ECONNRESET when the switchboard holding the private channel exits, or
 * with EINTR when a signal whose handler was not installed with SA_RESTART
 * arrives (service_runtime(3)).
 */

/*
 * Reply-token stamped on the one-way REGISTER send.  Must be non-zero so the
 * kernel/libchannel dispatch routes it to switchboard's lookup-channel REQUEST
 * handler; a zero token is delivered as an unsolicited EVENT and discarded.
 */
#define AMBIENT_REG_TOKEN 1ULL

static void
close_owned_fd(void *arg)
{
	int *fd = arg;

	if (*fd >= 0) {
		(void)close(*fd);
		*fd = -1;
	}
}

/*
 * Wait until a channel can take another message (its peer's receive queue has
 * room).  kevent(2) answers a signal with EINTR whatever the handler's
 * SA_RESTART, so this wait does too.  It is a cancellation point.
 */
__hidden int
service_channel_wait_writable(int fd)
{
	struct kevent event;
	int error, kq, n;

	kq = kqueue();
	if (kq == -1)
		return (-1);
	EV_SET(&event, fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0, 0, NULL);
	pthread_cleanup_push(close_owned_fd, &kq);
	n = kevent(kq, &event, 1, &event, 1, NULL);
	error = errno;
	pthread_cleanup_pop(1);
	if (n == -1) {
		errno = error;
		return (-1);
	}
	if (n == 1 && (event.flags & EV_ERROR) != 0) {
		errno = (int)event.data;
		return (-1);
	}
	return (0);
}

/*
 * Send one message on a channel, waiting for room in its peer's queue.
 * A raw ioctl: the caller's descriptor flags are left alone.
 */
__hidden int
service_channel_send_wait(int fd, struct mac_capability_sendmsg_args *send)
{

	for (;;) {
		if (ioctl(fd, MAC_CAPABILITY_SENDMSG, send) == 0)
			return (0);
		if (errno != EAGAIN && errno != ENOBUFS)
			return (-1);
		if (service_channel_wait_writable(fd) == -1)
			return (-1);
	}
}

/*
 * Receive one message on a channel, waiting for it with no time limit
 * (MAC_CAPABILITY_RECV_F_WAIT).  The kernel sleeps interruptibly: a signal
 * whose handler was installed with SA_RESTART restarts the receive, any
 * other gives EINTR, as read(2) on a pipe does.  Like read(2) it is a
 * cancellation point.  A peer that closed gives ECONNRESET.
 */
__hidden int
service_channel_recv_wait(int fd, struct mac_capability_recvmsg_args *recv)
{

	recv->flags = MAC_CAPABILITY_RECV_F_WAIT;
	recv->_reserved[0] = MAC_CAPABILITY_RECV_WAIT_FOREVER;
	if (ioctl(fd, MAC_CAPABILITY_RECVMSG, recv) == -1) {
		/*
		 * A cancellation request interrupts the sleep (SIGCANCEL has
		 * no SA_RESTART): act on it here, as read(2) would, rather
		 * than report EINTR.
		 */
		if (errno == EINTR)
			pthread_testcancel();
		return (-1);
	}
	if (recv->payload_len == 0 && recv->nfds == 0) {
		errno = ECONNRESET;
		return (-1);
	}
	return (0);
}

/*
 * Send SVC_OP_REGISTER_LOOKUP carrying `peer_fd` over the inherited shared
 * lookup channel, one-way: only the OUTBOUND side is driven, and the ACK is
 * awaited on the PRIVATE endpoint (ambient_reg_recv_ack), never on the shared
 * channel, so the shared receive-queue race is never touched.
 *
 * A raw ioctl leaves the status flags of the shared file description alone.
 * A full queue (switchboard restarting, or a burst of registrations) is
 * waited out.
 */
static bool
ambient_reg_send(int shared_fd, int peer_fd)
{
	struct svc_register_lookup_req reqmsg;
	struct mac_capability_sendmsg_args send;

	memset(&reqmsg, 0, sizeof(reqmsg));
	reqmsg.op = SVC_OP_REGISTER_LOOKUP;
	reqmsg.flags = 0;
	memset(&send, 0, sizeof(send));
	send.payload = &reqmsg;
	send.payload_len = sizeof(reqmsg);
	send.fds = &peer_fd;
	send.nfds = 1;
	/*
	 * A NON-ZERO token routes this as a REQUEST to switchboard's
	 * lookup-channel request handler; token 0 would be delivered to the
	 * (absent) event handler and silently discarded.  switchboard never
	 * replies on the shared channel for a register (it ACKs on the adopted
	 * private endpoint), so the token is never echoed and any non-zero
	 * value serves — it only selects the request dispatch path.
	 */
	send.reply_token = AMBIENT_REG_TOKEN;

	return (service_channel_send_wait(shared_fd, &send) == 0);
}

/*
 * Receive and validate switchboard's ACK on the private endpoint.  switchboard
 * pushes it as an unsolicited event on the channel it adopted, so only this
 * process (the sole holder of `private_fd`) can read it — no shared queue, no
 * race.  A raw MAC_CAPABILITY_RECVMSG, for the same fd-hygiene reason as
 * ambient_reg_send.  It waits with no limit: a refused registration closes the
 * other end (ECONNRESET), and so does the exit of the switchboard that adopted
 * it.  private_fd is borrowed.
 */
static bool
ambient_reg_recv_ack(int private_fd)
{
	struct svc_register_lookup_ack ack;
	struct mac_capability_recvmsg_args recv;

	memset(&recv, 0, sizeof(recv));
	recv.payload = &ack;
	recv.payload_len = sizeof(ack);
	if (service_channel_recv_wait(private_fd, &recv) == -1)
		return (false);
	if (recv.payload_len != sizeof(ack) || recv.nfds != 0 ||
	    ack.op != SVC_OP_REGISTER_LOOKUP) {
		errno = EBADMSG;
		return (false);
	}
	/* A refused registration carries switchboard's errno. */
	if (ack.status != 0) {
		errno = ack.status > 0 && ack.status <= ELAST ?
		    (int)ack.status : EBADMSG;
		return (false);
	}
	if (ack.magic != SVC_REGISTER_LOOKUP_MAGIC) {
		errno = EBADMSG;
		return (false);
	}
	return (true);
}

/*
 * Each owned handle gets a separate reply queue. Sharing a cached endpoint
 * between independent service_session objects also races within one process:
 * one session may consume and discard another session's reply token.
 * The kernel context is the only persistent reference; no hidden descriptors
 * or atfork cache state need to survive closefrom(), exec, or uid changes.
 */
struct ambient_reg_owned {
	int	shared, pair[2];
};

static void
ambient_reg_cleanup(void *arg)
{
	struct ambient_reg_owned *owned = arg;

	close_owned_fd(&owned->shared);
	close_owned_fd(&owned->pair[0]);
	close_owned_fd(&owned->pair[1]);
}

int
service_ambient_lookup_channel(void)
{
	struct ambient_reg_owned owned;
	int error, private_fd;
	bool sent, acknowledged;

	owned.shared = process_lookup_fd();
	if (owned.shared == -1)
		return (-1);
	if (mac_capability_channel_create(owned.pair) == -1) {
		error = errno;
		(void)close(owned.shared);
		errno = error;
		return (-1);
	}
	/* The waits below are cancellation points. */
	pthread_cleanup_push(ambient_reg_cleanup, &owned);
	/*
	 * Only the queued registration may hold the other end once it is
	 * sent: a child forked meanwhile must not keep it open, or a refusal
	 * or a switchboard exit would never close the peer.
	 */
	if (fcntl(owned.pair[0], F_SETFD, FD_CLOEXEC) == -1 ||
	    fcntl(owned.pair[1], F_SETFD, FD_CLOEXEC | FD_CLOFORK) == -1)
		sent = false;
	else
		sent = ambient_reg_send(owned.shared, owned.pair[1]);
	pthread_cleanup_pop(0);
	/*
	 * The queued registration holds its own reference: drop ours now, so a
	 * refusal or a switchboard exit closes the other end and ends the wait
	 * for the ACK.
	 */
	error = errno;
	close_owned_fd(&owned.pair[1]);
	close_owned_fd(&owned.shared);
	if (sent) {
		pthread_cleanup_push(close_owned_fd, &owned.pair[0]);
		acknowledged = ambient_reg_recv_ack(owned.pair[0]);
		pthread_cleanup_pop(0);
		error = errno;
	} else
		acknowledged = false;
	private_fd = owned.pair[0];
	SERVICE_AMBIENT_PROBE_REG_RESULT(acknowledged ? 1 : 0, 0, sent ? 1 : 0,
	    acknowledged ? 1 : 0);
	if (!acknowledged) {
		(void)close(private_fd);
		errno = error != 0 ? error : EIO;
		return (-1);
	}
	return (private_fd);
}

int
service_ambient_lookup_fd(void)
{
	return (service_ambient_lookup_channel());
}
