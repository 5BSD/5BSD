/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Process-held discovery helpers. The kernel holds the inherited channel;
 * working descriptors and private per-handle reply queues are temporary.
 * Approved software has separate protected authority, not another route.
 * Registration failure never falls back to a shared receive queue, and stale
 * environment variables never restore a cleared context.
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
 */
#define AMBIENT_REG_TIMEOUT_MS 2000U
/*
 * Backoff between raw SENDMSG/RECVMSG retries while switchboard drains a
 * transient queue-pressure burst (a concurrent boot storm registers many lookup
 * channels at once).  20ms keeps the bounded wait responsive without
 * busy-spinning.
 */
#define AMBIENT_REG_BACKOFF_US 20000U
/*
 * Reply-token stamped on the one-way REGISTER send.  Must be non-zero so the
 * kernel/libchannel dispatch routes it to switchboard's lookup-channel REQUEST
 * handler; a zero token is delivered as an unsolicited EVENT and discarded.
 */
#define AMBIENT_REG_TOKEN 1ULL

/*
 * Send SVC_OP_REGISTER_LOOKUP carrying `peer_fd` over the inherited shared
 * lookup channel, one-way: only the OUTBOUND side is driven, and the ACK is
 * awaited on the PRIVATE endpoint (ambient_reg_recv_ack), never on the shared
 * channel, so the shared receive-queue race is never touched.
 *
 * A raw ioctl on a temporary duplicate avoids changing status flags on the
 * shared file description. Transient queue pressure receives bounded backoff.
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
	 * A NON-ZERO token routes this as a REQUEST to switchboard's
	 * lookup-channel request handler; token 0 would be delivered to the
	 * (absent) event handler and silently discarded.  switchboard never
	 * replies on the shared channel for a register (it ACKs on the adopted
	 * private endpoint), so the token is never echoed and any non-zero
	 * value serves — it only selects the request dispatch path.
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
 * Receive and validate switchboard's ACK on the private endpoint.  switchboard
 * pushes it as an unsolicited event on the channel it adopted, so only this
 * process (the sole holder of `private_fd`) can read it — no shared queue, no
 * race.
 *
 * Also a RAW MAC_CAPABILITY_RECVMSG rather than a channel object, for the same
 * fd-hygiene reason as ambient_reg_send.  The endpoint is ours alone, so
 * setting O_NONBLOCK on it is isolated (it shares no file description with the
 * shared channel) and lets us bound the wait with kqueue; a blocking
 * descriptor could otherwise stall on a silent switchboard.  private_fd is
 * borrowed.
 */
static bool
ambient_reg_recv_ack(int private_fd)
{
	struct svc_register_lookup_ack ack;
	struct mac_capability_recvmsg_args recv;
	struct kevent event;
	struct timespec timeout, start, now;
	int flags, kq, result;
	int64_t remaining;
	bool ok;

	flags = fcntl(private_fd, F_GETFL);
	if (flags == -1 || fcntl(private_fd, F_SETFL, flags | O_NONBLOCK) == -1)
		return (false);
	kq = kqueue();
	if (kq == -1)
		return (false);
	EV_SET(&event, private_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &event, 1, NULL, 0, NULL) == -1) {
		(void)close(kq);
		return (false);
	}
	ok = false;
	(void)clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		memset(&recv, 0, sizeof(recv));
		recv.payload = &ack;
		recv.payload_len = sizeof(ack);
		if (ioctl(private_fd, MAC_CAPABILITY_RECVMSG, &recv) == 0) {
			ok = recv.payload_len == sizeof(ack) &&
			    ack.op == SVC_OP_REGISTER_LOOKUP &&
			    ack.status == 0 &&
			    ack.magic == SVC_REGISTER_LOOKUP_MAGIC;
			break;
		}
		if (errno != EAGAIN)
			break;
		(void)clock_gettime(CLOCK_MONOTONIC, &now);
		remaining = (int64_t)AMBIENT_REG_TIMEOUT_MS * 1000000 -
		    ((int64_t)(now.tv_sec - start.tv_sec) * 1000000000 +
			now.tv_nsec - start.tv_nsec);
		if (remaining <= 0) {
			errno = ETIMEDOUT;
			break;
		}
		timeout.tv_sec = remaining / 1000000000;
		timeout.tv_nsec = remaining % 1000000000;
		result = kevent(kq, NULL, 0, &event, 1, &timeout);
		if (result < 0 && errno != EINTR)
			break;
	}
	(void)close(kq);
	return (ok);
}

/*
 * Each owned handle gets a separate reply queue. Sharing a cached endpoint
 * between independent service_session objects also races within one process:
 * one session may consume and discard another session's reply token.
 * The kernel context is the only persistent reference; no hidden descriptors
 * or atfork cache state need to survive closefrom(), exec, or uid changes.
 */
int
service_ambient_lookup_channel(void)
{
	int shared, pair[2], error;
	bool sent, acknowledged;

	shared = process_lookup_fd();
	if (shared == -1)
		return (-1);
	if (mac_capability_channel_create(pair) == -1) {
		error = errno;
		(void)close(shared);
		errno = error;
		return (-1);
	}
	sent = ambient_reg_send(shared, pair[1]);
	acknowledged = sent && ambient_reg_recv_ack(pair[0]);
	error = errno;
	(void)close(pair[1]);
	(void)close(shared);
	SERVICE_AMBIENT_PROBE_REG_RESULT(acknowledged ? 1 : 0, 0, sent ? 1 : 0,
	    acknowledged ? 1 : 0);
	if (!acknowledged) {
		(void)close(pair[0]);
		errno = error != 0 ? error : EIO;
		return (-1);
	}
	if (fcntl(pair[0], F_SETFD, FD_CLOEXEC) == -1) {
		error = errno;
		(void)close(pair[0]);
		errno = error;
		return (-1);
	}
	return (pair[0]);
}

int
service_ambient_lookup_fd(void)
{
	return (service_ambient_lookup_channel());
}
