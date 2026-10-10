/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "channel.h"
#include "channel_probes.h"

_Static_assert(sizeof(struct channel_fd_spec) ==
    sizeof(struct mac_capability_fd_spec) &&
    CHANNEL_FD_LOCK_INHERIT == MAC_CAPABILITY_FD_SPEC_LOCK_INHERIT &&
    CHANNEL_FD_TYPE_SOCKET == MAC_CAPABILITY_FD_TYPE_SOCKET &&
    CHANNEL_FD_TYPE_CHANNEL == MAC_CAPABILITY_FD_TYPE_CHANNEL &&
    CHANNEL_FD_RIGHT_READ == MAC_CAPABILITY_FD_RIGHT_READ &&
    CHANNEL_FD_RIGHT_WRITE == MAC_CAPABILITY_FD_RIGHT_WRITE,
    "descriptor specs are passed to the kernel unchanged");
_Static_assert(sizeof(struct channel_fd_info) ==
    sizeof(struct mac_capability_fd_info),
    "descriptor info is received from the kernel unchanged");

#define	CHANNEL_DISPATCH_BATCH	64

struct channel_request {
	struct channel_request	*next;
	struct channel		*channel;
	channel_reply_handler	 handler;
	void			*context;
	uint64_t		 token;
	int			 status;
	bool			 pending;
	bool			 callback_active;
	bool			 free_pending;
};

struct channel_queue_entry {
	struct channel_queue_entry *next;
	struct channel_request	*request;
	void			*data;
	size_t			 length;
	int			*fds;
	size_t			 nfds;
	uint64_t		 token;
	uint32_t		 flags;		/* CHANNEL_SEND_* */
	struct channel_fd_spec	*specs;		/* NULL or nfds entries */
};

struct channel {
	int receive_version;
	int			 send_version;	/* 0 unknown, 2, or 1 (no V2) */
	int			 fd;
	int			 kqueue_fd;	/* lazy kqueue for channel_wait */
	pid_t			 owner;
	int			 error;
	enum channel_role	 role;
	size_t			 max_pending_requests;
	size_t			 max_queued_messages;
	size_t			 max_queued_bytes;
	size_t			 max_queued_fds;
	size_t			 npending;
	size_t			 nqueued;
	size_t			 queued_bytes;
	size_t			 queued_fds;
	struct channel_request	*requests;
	struct channel_queue_entry *out_head;
	struct channel_queue_entry *out_tail;
	channel_request_handler	 request_handler;
	void			*request_context;
	channel_event_handler	 event_handler;
	void			*event_context;
	unsigned		 dispatch_depth;
	bool			 destroy_pending;
	bool			 owner_released;
	unsigned		 references;
	struct channel_message	*rx_spare;	/* unused receive block */
	bool			 write_filter;	/* EVFILT_WRITE registered */
	bool			 rx_drained;	/* kernel reported an empty queue */
	bool			 rx_wait_unsupported; /* kernel lacks RECV_F_WAIT */
	struct channel_message	*rx_prefetched;	/* received by channel_wait */
	size_t			 rx_hint;	/* last received payload length */
};

struct channel_message {
	struct channel_process_identity process;
	struct cap_authority_stamp authority;
	struct channel		*channel;
	pid_t			 owner;
	enum channel_message_kind kind;
	struct channel_sender	 sender;
	void			*data;
	size_t			 length;
	int			*fds;
	size_t			 nfds;
	uint64_t		 token;
	bool			 responded;
	size_t			 capacity;	/* payload bytes in this block */
	bool			 has_fd_info;	/* fd_info filled by the kernel */
	int			 inline_fds[MAC_CAPABILITY_MAX_FDS];
	struct channel_fd_info	 fd_info[MAC_CAPABILITY_MAX_FDS];
	/* payload storage follows, CHANNEL_RX_ALIGN-aligned */
};

/*
 * Receive blocks hold the message, its descriptor slots and its payload in
 * one allocation sized from the previous message on the channel, never the
 * 14 KiB maximum.  The kernel leaves a message queued with EMSGSIZE when a
 * block is too small, so the block grows before dequeue and allocation
 * failure never loses a message.  The unused block is kept across EAGAIN.
 */
#define	CHANNEL_RX_MIN		512
#define	CHANNEL_RX_ALIGN	16
#define	CHANNEL_RX_HEADER	\
	((sizeof(struct channel_message) + CHANNEL_RX_ALIGN - 1) & \
	~(size_t)(CHANNEL_RX_ALIGN - 1))

/*
 * Ownership checks run on every operation.  getpid(2) is a system call, so
 * cache the pid in a page marked INHERIT_ZERO: a fork child sees zero and
 * re-reads its own pid (the arc4random(3) technique).  A vfork(2) child shares
 * the page and must only exec or _exit, as for any library.
 */
static struct channel_message *channel_message_receive_wait(struct channel *,
    int);

static pid_t *channel_pid_cache;

static pid_t
channel_self_pid_slow(void)
{
	pid_t *page, *expected;

	page = __atomic_load_n(&channel_pid_cache, __ATOMIC_ACQUIRE);
	if (page == NULL) {
		page = mmap(NULL, (size_t)getpagesize(), PROT_READ | PROT_WRITE,
		    MAP_ANON | MAP_PRIVATE, -1, 0);
		if (page == MAP_FAILED)
			return (getpid());
		if (minherit(page, (size_t)getpagesize(), INHERIT_ZERO) == -1) {
			(void)munmap(page, (size_t)getpagesize());
			return (getpid());
		}
		expected = NULL;
		if (!__atomic_compare_exchange_n(&channel_pid_cache, &expected,
		    page, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
			(void)munmap(page, (size_t)getpagesize());
			page = expected;
		}
	}
	*page = getpid();
	return (*page);
}

static inline pid_t
channel_self_pid(void)
{
	pid_t *page;

	page = __atomic_load_n(&channel_pid_cache, __ATOMIC_ACQUIRE);
	if (page != NULL && *page != 0)
		return (*page);
	return (channel_self_pid_slow());
}

static void
channel_retain(struct channel *channel)
{

	channel->references++;
}

static void
channel_release(struct channel *channel)
{

	if (--channel->references == 0) {
		free(channel->rx_spare);
		free(channel);
	}
}

static bool
channel_owned(const struct channel *channel)
{

	if (channel == NULL) {
		errno = EINVAL;
		return (false);
	}
	if (channel->owner != channel_self_pid()) {
		errno = ECHILD;
		return (false);
	}
	return (true);
}

static bool
channel_terminal_error(int error)
{

	return (error == EBADF || error == ECONNRESET || error == ENOTCONN ||
	    error == ENXIO || error == EPIPE);
}

static void
channel_outgoing_free(struct channel_queue_entry *out)
{
	int error;
	size_t i;

	if (out == NULL)
		return;
	error = errno;
	for (i = 0; i < out->nfds; i++)
		if (out->fds[i] >= 0)
			(void)close(out->fds[i]);
	free(out->fds);
	free(out->specs);
	free(out->data);
	free(out);
	errno = error;
}

static struct channel_request *
channel_request_find(struct channel *channel, uint64_t token,
    struct channel_request ***linkp)
{
	struct channel_request **link;

	for (link = &channel->requests; *link != NULL;
	    link = &(*link)->next) {
		if ((*link)->token == token) {
			if (linkp != NULL)
				*linkp = link;
			return (*link);
		}
	}
	return (NULL);
}

static uint64_t
channel_new_token(struct channel *channel)
{
	uint64_t token;

	do {
		arc4random_buf(&token, sizeof(token));
	} while (token == 0 || channel_request_find(channel, token, NULL) !=
	    NULL);
	return (token);
}

static void
channel_request_complete(struct channel_request *request,
    struct channel_message *message, int error)
{
	channel_reply_handler handler;
	void *context;

	request->pending = false;
	request->status = error;
	handler = request->handler;
	context = request->context;
	request->callback_active = true;
	LIBCHANNEL_PROBE_COMPLETE(request->token, error);
	if (handler != NULL)
		handler(request, message, error, context);
	request->callback_active = false;
	if (request->free_pending)
		free(request);
}

static void
channel_fail_requests(struct channel *channel, int error)
{
	struct channel_request *request;

	while ((request = channel->requests) != NULL) {
		channel->requests = request->next;
		request->next = NULL;
		channel->npending--;
		channel_request_complete(request, NULL, error);
	}
}

static void
channel_mark_dead(struct channel *channel, int error)
{
	struct channel_queue_entry *out;

	if (channel->error != 0)
		return;
	channel->error = error != 0 ? error : ECONNRESET;
	LIBCHANNEL_PROBE_PEER_DEATH(channel->error, channel->npending);
	while ((out = channel->out_head) != NULL) {
		channel->out_head = out->next;
		channel_outgoing_free(out);
	}
	channel->out_tail = NULL;
	channel->nqueued = channel->queued_bytes = channel->queued_fds = 0;
	/*
	 * Completion callbacks may request channel destruction.  Keep the
	 * object alive until the public operation which detected death unwinds.
	 */
	channel->dispatch_depth++;
	channel_fail_requests(channel, channel->error);
	channel->dispatch_depth--;
}

/*
 * Userland equivalent of the kernel's per-descriptor expectation check,
 * used only on kernels without MAC_CAPABILITY_SENDMSG_V2.  On success *fdp
 * is the descriptor to send: the caller's, or a narrowed duplicate.
 */
static int
channel_compat_prepare(int fd, const struct channel_fd_spec *spec, bool lock,
    int *fdp)
{
	struct mac_capability_info_args info;
	cap_rights_t actual, needed;
	struct stat st;
	int copy, type;

	*fdp = fd;
	if (spec->type > CHANNEL_FD_TYPE_CHANNEL ||
	    (spec->rights & ~(CHANNEL_FD_RIGHT_READ |
	    CHANNEL_FD_RIGHT_WRITE)) != 0 ||
	    (spec->flags & ~CHANNEL_FD_LOCK_INHERIT) != 0 ||
	    spec->reserved != 0 ||
	    (spec->type == CHANNEL_FD_TYPE_CHANNEL && spec->rights != 0))
		return (EOPNOTSUPP);
	if (spec->type == CHANNEL_FD_TYPE_SOCKET) {
		if (fstat(fd, &st) != 0)
			return (errno);
		if (!S_ISSOCK(st.st_mode))
			return (EFTYPE);
	} else if (spec->type == CHANNEL_FD_TYPE_CHANNEL) {
		memset(&info, 0, sizeof(info));
		if (ioctl(fd, MAC_CAPABILITY_GETINFO, &info) != 0)
			return (errno == ENOTTY ? EFTYPE : errno);
		if (strncmp(info.name, "channel", sizeof(info.name)) != 0)
			return (EFTYPE);
	}
	type = spec->type;
	if (spec->rights != 0) {
		if (cap_rights_get(fd, &actual) != 0)
			return (errno);
		cap_rights_init(&needed);
		if (type == CHANNEL_FD_TYPE_SOCKET)
			cap_rights_set(&needed, CAP_FSTAT);
		if (spec->rights & CHANNEL_FD_RIGHT_READ)
			cap_rights_set(&needed, CAP_READ);
		if (spec->rights & CHANNEL_FD_RIGHT_WRITE)
			cap_rights_set(&needed, CAP_WRITE);
		if (!cap_rights_contains(&actual, &needed))
			return (ENOTCAPABLE);
	}
	if ((spec->flags & CHANNEL_FD_LOCK_INHERIT) != 0)
		lock = true;
	if (spec->rights == 0 && !lock)
		return (0);
	/* Narrow or lock a private duplicate, never the caller's descriptor. */
	copy = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (copy == -1)
		return (errno);
	if ((spec->rights != 0 && cap_rights_limit(copy, &needed) != 0) ||
	    (lock &&
	    (cap_clofork_limit(copy, CAP_CLOFORK_LOCKED) != 0 ||
	    cap_cloexec_limit(copy, CAP_CLOEXEC_LOCKED) != 0))) {
		int error = errno;

		(void)close(copy);
		return (error);
	}
	*fdp = copy;
	return (0);
}

/* Check expectations without sending (queue slow path only). */
static int
channel_check_specs(const int *fds, size_t nfds,
    const struct channel_fd_spec *specs)
{
	size_t i;
	int error, fd;

	for (i = 0; i < nfds; i++) {
		error = channel_compat_prepare(fds[i], &specs[i], false, &fd);
		if (fd != fds[i])
			(void)close(fd);
		if (error != 0) {
			errno = error;
			return (-1);
		}
	}
	return (0);
}

static int
channel_send_compat(struct channel *channel, const void *data, size_t length,
    const int *fds, size_t nfds, uint64_t token,
    const struct channel_fd_spec *specs, uint32_t flags)
{
	struct mac_capability_sendmsg_args send;
	int sent[MAC_CAPABILITY_MAX_FDS];
	struct channel_fd_spec none;
	const struct channel_fd_spec *spec;
	size_t i, prepared;
	int error;

	memset(&none, 0, sizeof(none));
	error = 0;
	for (prepared = 0; prepared < nfds; prepared++) {
		spec = specs != NULL ? &specs[prepared] : &none;
		error = channel_compat_prepare(fds[prepared], spec,
		    (flags & CHANNEL_SEND_LOCK_INHERIT) != 0, &sent[prepared]);
		if (error != 0)
			break;
	}
	if (error == 0) {
		memset(&send, 0, sizeof(send));
		send.payload = data;
		send.payload_len = (uint32_t)length;
		send.fds = sent;
		send.nfds = (uint32_t)nfds;
		send.reply_token = token;
		if (ioctl(channel->fd, MAC_CAPABILITY_SENDMSG, &send) != 0)
			error = errno;
	}
	for (i = 0; i < prepared; i++)
		if (sent[i] != fds[i])
			(void)close(sent[i]);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	if (flags & CHANNEL_SEND_MOVE)
		for (i = 0; i < nfds; i++)
			(void)close(fds[i]);
	return (0);
}

/*
 * One system call for the message and all of its descriptors.  With
 * CHANNEL_SEND_MOVE the descriptors are closed once the kernel accepts the
 * message; on failure they are untouched.
 */
static int
channel_send_now(struct channel *channel, const void *data, size_t length,
    const int *fds, size_t nfds, uint64_t token,
    const struct channel_fd_spec *specs, uint32_t flags)
{
	struct mac_capability_sendmsg_v2_args send2;
	struct mac_capability_sendmsg_args send;
	int error;

	memset(&send, 0, sizeof(send));
	send.payload = data;
	send.payload_len = (uint32_t)length;
	send.fds = fds;
	send.nfds = (uint32_t)nfds;
	send.reply_token = token;
	if (nfds == 0 || (specs == NULL && flags == 0)) {
		error = ioctl(channel->fd, MAC_CAPABILITY_SENDMSG, &send) == 0 ?
		    0 : errno;
	} else if (channel->send_version != 1) {
		memset(&send2, 0, sizeof(send2));
		send2.message = send;
		if (flags & CHANNEL_SEND_MOVE)
			send2.message.flags |= MAC_CAPABILITY_SEND_F_MOVE;
		if (flags & CHANNEL_SEND_LOCK_INHERIT)
			send2.message.flags |=
			    MAC_CAPABILITY_SEND_F_LOCK_INHERIT;
		send2.fd_specs = (const struct mac_capability_fd_spec *)specs;
		error = ioctl(channel->fd, MAC_CAPABILITY_SENDMSG_V2, &send2) ==
		    0 ? 0 : errno;
		if (error == ENOTTY && channel->send_version == 0) {
			channel->send_version = 1;
			return (channel_send_now(channel, data, length, fds,
			    nfds, token, specs, flags));
		}
		if (error != ENOTTY)
			channel->send_version = 2;
	} else {
		error = channel_send_compat(channel, data, length, fds, nfds,
		    token, specs, flags) == 0 ? 0 : errno;
	}
	LIBCHANNEL_PROBE_SEND(token, length, nfds, error);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

static int
channel_queue(struct channel *channel, const void *data, size_t length,
    const int *fds, size_t nfds, uint64_t token,
    struct channel_request *request, const struct channel_fd_spec *specs,
    uint32_t flags)
{
	struct channel_queue_entry *out;
	size_t i;

	if (channel->nqueued >= channel->max_queued_messages ||
	    length > channel->max_queued_bytes - channel->queued_bytes ||
	    nfds > channel->max_queued_fds - channel->queued_fds) {
		errno = ENOBUFS;
		return (-1);
	}
	out = calloc(1, sizeof(*out));
	if (out == NULL)
		return (-1);
	out->data = malloc(length);
	if (out->data == NULL)
		goto fail;
	memcpy(out->data, data, length);
	out->length = length;
	out->token = token;
	out->request = request;
	out->flags = flags & ~CHANNEL_SEND_MOVE;
	if (nfds != 0 && specs != NULL) {
		out->specs = malloc(nfds * sizeof(*out->specs));
		if (out->specs == NULL)
			goto fail;
		memcpy(out->specs, specs, nfds * sizeof(*out->specs));
	}
	if (nfds != 0) {
		out->fds = malloc(nfds * sizeof(*out->fds));
		if (out->fds == NULL)
			goto fail;
		for (i = 0; i < nfds; i++)
			out->fds[i] = -1;
	}
	if (nfds != 0 && (flags & CHANNEL_SEND_MOVE) != 0) {
		/* Adopt the caller's descriptors: no system calls. */
		memcpy(out->fds, fds, nfds * sizeof(*out->fds));
		out->nfds = nfds;
	} else if (nfds != 0) {
		for (i = 0; i < nfds; i++) {
			out->fds[i] = fcntl(fds[i], F_DUPFD_CLOEXEC, 0);
			if (out->fds[i] == -1)
				goto fail;
			out->nfds++;
			if (cap_clofork_limit(out->fds[i],
			    CAP_CLOFORK_LOCKED) == -1 ||
			    cap_cloexec_limit(out->fds[i],
			    CAP_CLOEXEC_LOCKED) == -1)
				goto fail;
		}
	}
	if (channel->out_tail == NULL)
		channel->out_head = out;
	else
		channel->out_tail->next = out;
	channel->out_tail = out;
	channel->nqueued++;
	channel->queued_bytes += length;
	channel->queued_fds += nfds;
	LIBCHANNEL_PROBE_QUEUE(token, length, nfds, channel->nqueued);
	return (0);
fail:
	channel_outgoing_free(out);
	return (-1);
}

static int
channel_send_or_queue(struct channel *channel, const void *data,
    size_t length, const int *fds, size_t nfds, uint64_t token,
    struct channel_request *request, const struct channel_fd_spec *specs,
    uint32_t flags)
{

	if (channel->error != 0) {
		errno = channel->error;
		return (-1);
	}
	if (channel->out_head == NULL) {
		if (channel_send_now(channel, data, length, fds, nfds, token,
		    specs, flags) == 0)
			return (0);
		if (channel->error != 0)
			return (-1);
		/* EAGAIN follows the descriptor checks, so they passed. */
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			return (-1);
	} else if (specs != NULL && nfds != 0 &&
	    channel_check_specs(fds, nfds, specs) != 0) {
		/* Behind queued messages: report a bad descriptor now. */
		return (-1);
	}
	return (channel_queue(channel, data, length, fds, nfds, token,
	    request, specs, flags));
}

/*
 * A descriptor limited by cap_ioctls_limit(2) to the older commands would
 * fail the newer ones with ENOTCAPABLE, which a send cannot tell apart from
 * a descriptor expectation failure; decide once, here.
 */
static void
channel_ioctl_allowlist(int fd, struct channel *channel)
{
	cap_ioctl_t *cmds;
	ssize_t count, i;
	bool send2, recv4;

	count = cap_ioctls_get(fd, NULL, 0);
	if (count < 0 || count == CAP_IOCTLS_ALL)
		return;
	send2 = recv4 = false;
	cmds = count > 0 ? calloc((size_t)count, sizeof(*cmds)) : NULL;
	if (cmds != NULL && cap_ioctls_get(fd, cmds, (size_t)count) == count)
		for (i = 0; i < count; i++) {
			if (cmds[i] == MAC_CAPABILITY_SENDMSG_V2)
				send2 = true;
			else if (cmds[i] == MAC_CAPABILITY_RECVMSG_V4)
				recv4 = true;
		}
	free(cmds);
	if (!send2)
		channel->send_version = 1;
	if (!recv4)
		channel->receive_version = 3;
}

int
channel_create(int fd, const struct channel_options *options,
    struct channel **channelp)
{
	struct mac_capability_info_args info;
	struct channel *channel;
	int flags, owned;

	if (fd < 0 || options == NULL || channelp == NULL ||
	    options->size < sizeof(*options) ||
	    (options->role != CHANNEL_ROLE_CLIENT &&
	    options->role != CHANNEL_ROLE_PROVIDER) ||
	    options->max_pending_requests == 0 ||
	    options->max_queued_messages == 0 ||
	    options->max_queued_bytes == 0) {
		errno = EINVAL;
		return (-1);
	}
	*channelp = NULL;
	memset(&info, 0, sizeof(info));
	if (ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == -1)
		return (-1);
	if ((info.features & (MAC_CAPABILITY_INFO_F_SENDMSG |
	    MAC_CAPABILITY_INFO_F_RECVMSG | MAC_CAPABILITY_INFO_F_KQUEUE)) !=
	    (MAC_CAPABILITY_INFO_F_SENDMSG | MAC_CAPABILITY_INFO_F_RECVMSG |
	    MAC_CAPABILITY_INFO_F_KQUEUE)) {
		errno = EPROTONOSUPPORT;
		return (-1);
	}
	channel = calloc(1, sizeof(*channel));
	if (channel == NULL)
		return (-1);
	channel_ioctl_allowlist(fd, channel);
	/*
	 * Configure a private duplicate so any failure leaves the caller's
	 * descriptor untouched, as required by the ownership contract.
	 */
	owned = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (owned == -1) {
		free(channel);
		return (-1);
	}
	if (cap_clofork_limit(owned, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(owned, CAP_CLOEXEC_LOCKED) == -1) {
		(void)close(owned);
		free(channel);
		return (-1);
	}
	flags = fcntl(owned, F_GETFL);
	if (flags == -1 ||
	    fcntl(owned, F_SETFL, flags | O_NONBLOCK) == -1) {
		(void)close(owned);
		free(channel);
		return (-1);
	}
	(void)close(fd);
	channel->fd = owned;
	channel->kqueue_fd = -1;
	channel->owner = channel_self_pid();
	channel->role = options->role;
	channel->max_pending_requests = options->max_pending_requests;
	channel->max_queued_messages = options->max_queued_messages;
	channel->max_queued_bytes = options->max_queued_bytes;
	channel->max_queued_fds = options->max_queued_fds;
	channel->references = 1;
	*channelp = channel;
	LIBCHANNEL_PROBE_CREATE(owned, options->role, 0);
	return (0);
}

static void
channel_destroy_now(struct channel *channel)
{
	struct channel_queue_entry *out;

	channel_mark_dead(channel, ECANCELED);
	while ((out = channel->out_head) != NULL) {
		channel->out_head = out->next;
		channel_outgoing_free(out);
	}
	if (channel->fd >= 0)
		(void)close(channel->fd);
	channel->fd = -1;
	if (channel->kqueue_fd >= 0)
		(void)close(channel->kqueue_fd);
	channel->kqueue_fd = -1;
	free(channel->rx_spare);
	channel->rx_spare = NULL;
	if (channel->rx_prefetched != NULL) {
		struct channel_message *m = channel->rx_prefetched;

		channel->rx_prefetched = NULL;
		channel_message_free(m);
	}
	/*
	 * A callback-owned message still references the channel.  When abandon
	 * is used during dispatch, defer the owner's release until dispatch
	 * unwinds so freeing that message cannot invalidate the active stack.
	 */
	if (channel->dispatch_depth == 0 && !channel->owner_released) {
		channel->owner_released = true;
		channel_release(channel);
	}
}

void
channel_destroy(struct channel *channel)
{

	if (channel == NULL)
		return;
	if (channel->owner != channel_self_pid()) {
		channel_abandon(channel);
		return;
	}
	if (channel->dispatch_depth != 0) {
		channel->destroy_pending = true;
		channel_mark_dead(channel, ECANCELED);
		return;
	}
	channel_destroy_now(channel);
}

void
channel_abandon(struct channel *channel)
{
	struct channel_queue_entry *out;
	struct channel_request *request;
	bool inherited;

	if (channel == NULL)
		return;
	inherited = channel->owner != channel_self_pid();
	while ((out = channel->out_head) != NULL) {
		channel->out_head = out->next;
		if (inherited) {
			free(out->fds);
			free(out->data);
			free(out);
		} else
			channel_outgoing_free(out);
	}
	channel->out_tail = NULL;
	while ((request = channel->requests) != NULL) {
		channel->requests = request->next;
		free(request);
	}
	channel->npending = channel->nqueued = 0;
	channel->queued_bytes = channel->queued_fds = 0;
	channel->error = ECANCELED;
	channel->destroy_pending = true;
	if (channel->fd >= 0 && !inherited)
		(void)close(channel->fd);
	channel->fd = -1;
	/* The kqueue is process-local and never inherited; always close it. */
	if (channel->kqueue_fd >= 0)
		(void)close(channel->kqueue_fd);
	channel->kqueue_fd = -1;
	if (!channel->owner_released) {
		channel->owner_released = true;
		channel_release(channel);
	}
}

int
channel_fd(const struct channel *channel)
{

	if (!channel_owned(channel))
		return (-1);
	if (channel->destroy_pending) {
		errno = EINVAL;
		return (-1);
	}
	return (channel->fd);
}

/*
 * Wait for the channel to become ready via kqueue.  Capability channels are
 * kqueue-only (poll(2)/select(2) are unsupported by the kernel), so this is
 * the sole readiness primitive.  A lazily-created kqueue is cached on the
 * channel with a persistent EVFILT_READ registration; EVFILT_WRITE is toggled
 * per call to match want_write.  timeout_ms < 0 blocks indefinitely, 0 polls
 * once.  Returns a CHANNEL_WAIT_READ|CHANNEL_WAIT_WRITE bitmask of ready
 * filters (0 on timeout), or -1 with errno set on error.  A dead/EOF channel
 * reports CHANNEL_WAIT_READ ready so the caller's dispatch observes the error.
 */
int
channel_wait(struct channel *channel, int want_write, int timeout_ms)
{
	struct kevent chg, out[2];
	struct timespec ts, *tsp;
	int n, i, nchg, ready;

	if (!channel_owned(channel) || channel->destroy_pending ||
	    channel->fd < 0) {
		errno = EBADF;
		return (-1);
	}
	/*
	 * Read-only waits receive in the same system call: the kernel waits
	 * for a message and returns it, and channel_dispatch() handles it
	 * first.  Kernels without RECV_F_WAIT use kqueue below.
	 */
	if (!want_write && !channel->rx_wait_unsupported) {
		if (channel->rx_prefetched != NULL)
			return (CHANNEL_WAIT_READ);
		for (;;) {
			struct channel_message *m;

			m = channel_message_receive_wait(channel,
			    timeout_ms < 0 ? -1 : timeout_ms);
			if (m != NULL) {
				channel->rx_prefetched = m;
				return (CHANNEL_WAIT_READ);
			}
			if (errno == EINTR)
				continue;
			if (errno == ETIMEDOUT || errno == EAGAIN)
				return (0);
			if (errno == EINVAL) {
				channel->rx_wait_unsupported = true;
				break;
			}
			/* Dead or failing: channel_dispatch() reports it. */
			return (CHANNEL_WAIT_READ);
		}
	}
	if (channel->kqueue_fd < 0) {
		channel->kqueue_fd = kqueue();
		if (channel->kqueue_fd < 0)
			return (-1);
		(void)cap_cloexec_limit(channel->kqueue_fd, CAP_CLOEXEC_LOCKED);
		EV_SET(&chg, channel->fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
		if (kevent(channel->kqueue_fd, &chg, 1, NULL, 0, NULL) == -1) {
			(void)close(channel->kqueue_fd);
			channel->kqueue_fd = -1;
			return (-1);
		}
		channel->write_filter = false;
	}
	/*
	 * Change the write filter only when want_write changes, and in the
	 * same kevent(2) call that waits.  A failed change (EV_DELETE of an
	 * absent filter, EV_ADD on a receive-only channel) is benign; it is
	 * reported as an EV_ERROR event, which must not end the wait.
	 */
	nchg = 0;
	if ((want_write != 0) != channel->write_filter) {
		EV_SET(&chg, channel->fd, EVFILT_WRITE,
		    want_write ? EV_ADD : EV_DELETE, 0, 0, NULL);
		channel->write_filter = want_write != 0;
		nchg = 1;
	}

	if (timeout_ms < 0) {
		tsp = NULL;
	} else {
		ts.tv_sec = timeout_ms / 1000;
		ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
		tsp = &ts;
	}
	for (;;) {
		n = kevent(channel->kqueue_fd, nchg ? &chg : NULL, nchg, out, 2,
		    tsp);
		nchg = 0;
		if (n == -1 && errno == EINTR)
			continue;
		if (n == -1)
			return (-1);
		ready = 0;
		for (i = 0; i < n; i++) {
			if (out[i].flags & EV_ERROR)
				continue;
			if (out[i].filter == EVFILT_READ)
				ready |= CHANNEL_WAIT_READ;
			else if (out[i].filter == EVFILT_WRITE)
				ready |= CHANNEL_WAIT_WRITE;
		}
		/* Only a change error was returned: wait again. */
		if (n > 0 && ready == 0)
			continue;
		return (ready);
	}
}

int
channel_error(const struct channel *channel)
{

	if (!channel_owned(channel))
		return (-1);
	if (channel->error != 0) {
		errno = channel->error;
		return (-1);
	}
	return (0);
}

int
channel_wants_write(const struct channel *channel)
{

	if (!channel_owned(channel))
		return (-1);
	if (channel->destroy_pending) {
		errno = EINVAL;
		return (-1);
	}
	return (channel->out_head != NULL);
}

/*
 * Read the size-versioned outgoing options.  Callers built before
 * libchannel 2 pass CHANNEL_OUTGOING_SIZE_V1 and get neither.
 */
static int
channel_outgoing_options(const struct channel_outgoing *outgoing,
    const struct channel_fd_spec **specsp, uint32_t *flagsp)
{
	if (outgoing == NULL || (outgoing->size != CHANNEL_OUTGOING_SIZE_V1 &&
	    outgoing->size < sizeof(*outgoing))) {
		errno = EINVAL;
		return (-1);
	}
	*specsp = NULL;
	*flagsp = 0;
	if (outgoing->size >= sizeof(*outgoing)) {
		*specsp = outgoing->fd_specs;
		*flagsp = outgoing->flags;
	}
	if ((*flagsp & ~(CHANNEL_SEND_MOVE | CHANNEL_SEND_LOCK_INHERIT)) != 0) {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

int
channel_send_request(struct channel *channel,
    const struct channel_outgoing *outgoing, channel_reply_handler handler,
    void *context, struct channel_request **requestp)
{
	struct channel_request *request;
	struct channel_request **link;
	const void *data;
	const int *fds;
	const struct channel_fd_spec *specs;
	uint32_t flags;
	size_t length, nfds;
	int error;

	if (channel_outgoing_options(outgoing, &specs, &flags) != 0)
		return (-1);
	data = outgoing->data;
	length = outgoing->length;
	fds = outgoing->fds;
	nfds = outgoing->nfds;
	if (!channel_owned(channel))
		return (-1);
	if (data == NULL || length == 0 ||
	    length > MAC_CAPABILITY_MAX_MSG || nfds > MAC_CAPABILITY_MAX_FDS ||
	    (nfds != 0 && fds == NULL) || handler == NULL ||
	    requestp == NULL || channel->destroy_pending ||
	    channel->role != CHANNEL_ROLE_CLIENT) {
		errno = EINVAL;
		return (-1);
	}
	*requestp = NULL;
	if (channel->npending >= channel->max_pending_requests) {
		errno = ENOBUFS;
		return (-1);
	}
	request = calloc(1, sizeof(*request));
	if (request == NULL)
		return (-1);
	request->channel = channel;
	request->handler = handler;
	request->context = context;
	request->token = channel_new_token(channel);
	request->status = EINPROGRESS;
	request->pending = true;
	request->next = channel->requests;
	channel->requests = request;
	channel->npending++;
	if (channel_send_or_queue(channel, data, length, fds, nfds,
	    request->token, request, specs, flags) == -1) {
		error = errno;
		for (link = &channel->requests; *link != NULL;
		    link = &(*link)->next)
			if (*link == request) {
				*link = request->next;
				break;
			}
		channel->npending--;
		free(request);
		if (channel_terminal_error(error))
			channel_mark_dead(channel, error);
		if (channel->destroy_pending && channel->dispatch_depth == 0)
			channel_destroy_now(channel);
		errno = error;
		return (-1);
	}
	*requestp = request;
	return (0);
}

int
channel_send_event(struct channel *channel,
    const struct channel_outgoing *outgoing)
{
	const void *data;
	const int *fds;
	const struct channel_fd_spec *specs;
	uint32_t flags;
	size_t length, nfds;

	if (channel_outgoing_options(outgoing, &specs, &flags) != 0)
		return (-1);
	data = outgoing->data;
	length = outgoing->length;
	fds = outgoing->fds;
	nfds = outgoing->nfds;
	if (!channel_owned(channel))
		return (-1);
	if (data == NULL || length == 0 ||
	    length > MAC_CAPABILITY_MAX_MSG || nfds > MAC_CAPABILITY_MAX_FDS ||
	    (nfds != 0 && fds == NULL) || channel->destroy_pending) {
		errno = EINVAL;
		return (-1);
	}
	if (channel_send_or_queue(channel, data, length, fds, nfds, 0,
	    NULL, specs, flags) == -1) {
		int error;

		error = errno;
		if (channel_terminal_error(error))
			channel_mark_dead(channel, error);
		if (channel->destroy_pending && channel->dispatch_depth == 0)
			channel_destroy_now(channel);
		errno = error;
		return (-1);
	}
	return (0);
}

int
channel_set_request_handler(struct channel *channel,
    channel_request_handler handler, void *context)
{

	if (!channel_owned(channel))
		return (-1);
	if (channel->destroy_pending || channel->role == CHANNEL_ROLE_CLIENT) {
		errno = EINVAL;
		return (-1);
	}
	channel->request_handler = handler;
	channel->request_context = context;
	return (0);
}

int
channel_set_event_handler(struct channel *channel,
    channel_event_handler handler, void *context)
{

	if (!channel_owned(channel))
		return (-1);
	if (channel->destroy_pending) {
		errno = EINVAL;
		return (-1);
	}
	channel->event_handler = handler;
	channel->event_context = context;
	return (0);
}

int
channel_flush(struct channel *channel)
{
	struct channel_queue_entry *out;
	int error;

	if (!channel_owned(channel))
		return (-1);
	if (channel->destroy_pending) {
		errno = EINVAL;
		return (-1);
	}
	while ((out = channel->out_head) != NULL) {
		/* The queue owns its descriptors: the kernel closes them. */
		if (channel_send_now(channel, out->data, out->length, out->fds,
		    out->nfds, out->token, out->specs,
		    out->flags | CHANNEL_SEND_MOVE) == -1) {
			error = errno;
			if (error == EAGAIN || error == EWOULDBLOCK)
				return (0);
			if (channel_terminal_error(error))
				channel_mark_dead(channel, error);
			if (channel->destroy_pending &&
			    channel->dispatch_depth == 0)
				channel_destroy_now(channel);
			errno = error;
			return (-1);
		}
		channel->out_head = out->next;
		if (channel->out_head == NULL)
			channel->out_tail = NULL;
		channel->nqueued--;
		channel->queued_bytes -= out->length;
		channel->queued_fds -= out->nfds;
		out->nfds = 0;
		channel_outgoing_free(out);
	}
	return (0);
}

/* Payload capacity for the next receive block: the last length, rounded. */
static size_t
channel_rx_capacity(size_t length)
{

	if (length < CHANNEL_RX_MIN)
		length = CHANNEL_RX_MIN;
	length = (length + CHANNEL_RX_ALIGN - 1) &
	    ~(size_t)(CHANNEL_RX_ALIGN - 1);
	return (length > MAC_CAPABILITY_MAX_MSG ? MAC_CAPABILITY_MAX_MSG :
	    length);
}

/* Make channel->rx_spare hold at least capacity payload bytes. */
static int
channel_rx_reserve(struct channel *channel, size_t capacity)
{
	struct channel_message *block;

	if (channel->rx_spare != NULL && channel->rx_spare->capacity >= capacity)
		return (0);
	block = malloc(CHANNEL_RX_HEADER + capacity);
	if (block == NULL)
		return (-1);
	free(channel->rx_spare);
	block->capacity = capacity;
	channel->rx_spare = block;
	return (0);
}

/*
 * Receive one message.  wait_ms < -1 never waits; otherwise the kernel waits
 * up to wait_ms milliseconds (-1: forever) inside the same call.
 */
static struct channel_message *
channel_message_receive_wait(struct channel *channel, int wait_ms)
{
	struct mac_capability_recvmsg_args receive;
	struct mac_capability_recvmsg_v4_args described;
	struct mac_capability_recvmsg_v3_args current;
	struct mac_capability_recvmsg_v2_args extended;
	struct channel_process_identity process;
	struct cap_authority_stamp authority;
	struct channel_message *message;
	void *data;
	int error;
	size_t i;

	if (channel_rx_reserve(channel, channel_rx_capacity(channel->rx_hint))
	    == -1)
		return (NULL);
retry:
	message = channel->rx_spare;
	data = (char *)message + CHANNEL_RX_HEADER;
	/* The kernel installs descriptors only into slots it reports. */
	for (i = 0; i < MAC_CAPABILITY_MAX_FDS; i++)
		message->inline_fds[i] = -1;
	memset(&process, 0, sizeof(process));
	memset(&authority, 0, sizeof(authority));
	memset(&receive, 0, sizeof(receive));
	receive.payload = data;
	receive.payload_len = message->capacity;
	receive.fds = message->inline_fds;
	receive.nfds = MAC_CAPABILITY_MAX_FDS;
	if (wait_ms >= -1) {
		receive.flags = MAC_CAPABILITY_RECV_F_WAIT;
		receive._reserved[0] = wait_ms < 0 ?
		    MAC_CAPABILITY_RECV_WAIT_FOREVER : (uint32_t)wait_ms;
	}
	error = 0;
	message->has_fd_info = false;
	if (channel->receive_version == 0 || channel->receive_version == 4) {
		memset(&described, 0, sizeof(described));
		described.v3.message = receive;
		described.fd_info = (struct mac_capability_fd_info *)
		    message->fd_info;
		if (ioctl(channel->fd, MAC_CAPABILITY_RECVMSG_V4,
		    &described) == 0) {
			channel->receive_version = 4;
			message->has_fd_info = true;
			receive = described.v3.message;
			process.identity = described.v3.process.identity;
			process.responsible_identity =
			    described.v3.process.responsible_identity;
			process.pid = described.v3.process.pid;
			process.responsible_pid =
			    described.v3.process.responsible_pid;
			authority = described.v3.authority;
		} else if (errno == ENOTTY || errno == ENOTCAPABLE) {
			channel->receive_version = 3;
		} else {
			error = errno;
		}
	}
	if (error == 0 && channel->receive_version == 3 &&
	    !message->has_fd_info) {
		memset(&current, 0, sizeof(current));
		current.message = receive;
		if (ioctl(channel->fd, MAC_CAPABILITY_RECVMSG_V3, &current) == 0) {
			receive = current.message;
			process.identity = current.process.identity;
			process.responsible_identity = current.process.responsible_identity;
			process.pid = current.process.pid;
			process.responsible_pid = current.process.responsible_pid;
			authority = current.authority;
		} else if (errno == ENOTTY || errno == ENOTCAPABLE) {
			channel->receive_version = 2;
		} else {
			error = errno;
		}
	}
	if (error == 0 && channel->receive_version == 2) {
		memset(&extended, 0, sizeof(extended));
		extended.message = receive;
		if (ioctl(channel->fd, MAC_CAPABILITY_RECVMSG_V2, &extended) == 0) {
			receive = extended.message;
			process.identity = extended.process.identity;
			process.responsible_identity = extended.process.responsible_identity;
			process.pid = extended.process.pid;
			process.responsible_pid = extended.process.responsible_pid;
		} else if (errno == ENOTTY || errno == ENOTCAPABLE) {
			/* Compatibility never fabricates missing sender attribution. */
			channel->receive_version = -1;
		} else {
			error = errno;
		}
	}
	if (error == 0 && channel->receive_version == -1 &&
	    ioctl(channel->fd, MAC_CAPABILITY_RECVMSG, &receive) == -1)
		error = errno;
	if (error == EMSGSIZE && message->capacity < MAC_CAPABILITY_MAX_MSG) {
		/*
		 * Still queued.  The ioctl does not copy out the required size
		 * on failure, so grow to the maximum and receive it; the next
		 * block is sized from this message.
		 */
		if (channel_rx_reserve(channel, MAC_CAPABILITY_MAX_MSG) == -1)
			return (NULL);
		goto retry;
	}
	if (error != 0) {
		errno = error;
		return (NULL);
	}
	channel->rx_spare = NULL;
	channel->rx_hint = receive.payload_len;
	/* Kernels that report queue state let dispatch skip an EAGAIN receive. */
	channel->rx_drained = (receive.flags & MAC_CAPABILITY_RECV_F_STATUS) &&
	    (receive.flags & MAC_CAPABILITY_RECV_F_EMPTY);
	message->process = process;
	message->authority = authority;
	message->channel = channel;
	message->owner = channel_self_pid();
	message->kind = 0;
	message->responded = false;
	channel_retain(channel);
	message->data = data;
	message->length = receive.payload_len;
	message->fds = message->inline_fds;
	message->nfds = receive.nfds;
	message->token = receive.reply_token;
	memset(&message->sender, 0, sizeof(message->sender));
	message->sender.badge = receive.badge;
	message->sender.uid = receive.trailer.uid;
	message->sender.gid = receive.trailer.gid;
	message->sender.prison_id = receive.trailer.prison_id;
	message->sender.nonce = receive.trailer.nonce;
	message->sender.abi = receive.trailer.abi;
	return (message);
}

static struct channel_message *
channel_message_receive(struct channel *channel)
{

	return (channel_message_receive_wait(channel, -2));
}

int
channel_dispatch(struct channel *channel)
{
	struct channel_message *message;
	struct channel_request *request, **link;
	int error, dispatched;

	if (!channel_owned(channel))
		return (-1);
	if (channel->destroy_pending) {
		errno = EINVAL;
		return (-1);
	}
	channel->dispatch_depth++;
	error = 0;
	dispatched = 0;
	while (dispatched < CHANNEL_DISPATCH_BATCH) {
		if (channel->rx_prefetched != NULL) {
			message = channel->rx_prefetched;
			channel->rx_prefetched = NULL;
		} else
			message = channel_message_receive(channel);
		if (message == NULL) {
			error = errno;
			if (error == EAGAIN || error == EWOULDBLOCK) {
				error = 0;
				break;
			}
			if (channel_terminal_error(error))
				channel_mark_dead(channel, error);
			break;
		}
		dispatched++;
		if (message->token == 0) {
			message->kind = CHANNEL_MESSAGE_EVENT;
			LIBCHANNEL_PROBE_RECEIVE(message->kind, message->token,
			    message->length, message->nfds);
			if (channel->event_handler != NULL) {
				channel->event_handler(channel, message,
				    channel->event_context);
				message = NULL;
			} else
				LIBCHANNEL_PROBE_DISCARD(message->token,
				    message->nfds, 1);
		} else if ((request = channel_request_find(channel,
		    message->token, &link)) != NULL) {
			message->kind = CHANNEL_MESSAGE_REPLY;
			LIBCHANNEL_PROBE_RECEIVE(message->kind, message->token,
			    message->length, message->nfds);
			*link = request->next;
			request->next = NULL;
			channel->npending--;
			channel_request_complete(request, message, 0);
			message = NULL;
		} else if (channel->role == CHANNEL_ROLE_PROVIDER) {
			message->kind = CHANNEL_MESSAGE_REQUEST;
			LIBCHANNEL_PROBE_RECEIVE(message->kind, message->token,
			    message->length, message->nfds);
			if (channel->request_handler != NULL) {
				channel->request_handler(channel, message,
				    channel->request_context);
				message = NULL;
			} else
				LIBCHANNEL_PROBE_DISCARD(message->token,
				    message->nfds, 2);
		} else
			LIBCHANNEL_PROBE_DISCARD(message->token, message->nfds,
			    3);
		if (message != NULL)
			channel_message_free(message);
		if (channel->destroy_pending || channel->rx_drained)
			break;
	}
	channel->dispatch_depth--;
	if (channel->destroy_pending && channel->dispatch_depth == 0) {
		channel_destroy_now(channel);
		if (error != 0)
			errno = error;
		return (error == 0 ? dispatched : -1);
	}
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (dispatched);
}

int
channel_send_reply(struct channel_message *request,
    const struct channel_outgoing *outgoing)
{
	struct channel *channel;
	const void *data;
	const int *fds;
	const struct channel_fd_spec *specs;
	uint32_t flags;
	size_t length, nfds;

	if (request == NULL || request->channel == NULL ||
	    request->kind != CHANNEL_MESSAGE_REQUEST || request->token == 0 ||
	    request->responded || request->channel->destroy_pending) {
		errno = EINVAL;
		return (-1);
	}
	if (!channel_owned(request->channel))
		return (-1);
	if (channel_outgoing_options(outgoing, &specs, &flags) != 0)
		return (-1);
	data = outgoing->data;
	length = outgoing->length;
	fds = outgoing->fds;
	nfds = outgoing->nfds;
	if (data == NULL || length == 0 || length > MAC_CAPABILITY_MAX_MSG ||
	    nfds > MAC_CAPABILITY_MAX_FDS || (nfds != 0 && fds == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	channel = request->channel;
	if (channel_send_or_queue(channel, data, length, fds, nfds,
	    request->token, NULL, specs, flags) == -1) {
		int error;

		error = errno;
		if (channel_terminal_error(error))
			channel_mark_dead(channel, error);
		if (channel->destroy_pending && channel->dispatch_depth == 0)
			channel_destroy_now(channel);
		errno = error;
		return (-1);
	}
	request->responded = true;
	return (0);
}

enum channel_message_kind
channel_message_kind(const struct channel_message *message)
{

	return (message == NULL ? 0 : message->kind);
}

const void *
channel_message_data(const struct channel_message *message)
{

	return (message == NULL ? NULL : message->data);
}

size_t
channel_message_length(const struct channel_message *message)
{

	return (message == NULL ? 0 : message->length);
}

uint64_t
channel_message_token(const struct channel_message *message)
{

	return (message == NULL ? 0 : message->token);
}

const struct channel_sender *
channel_message_sender(const struct channel_message *message)
{

	return (message == NULL ? NULL : &message->sender);
}

const struct channel_process_identity *
channel_message_process(const struct channel_message *message)
{
	if (message == NULL || message->process.identity == 0)
		return (NULL);
	return (&message->process);
}

const struct cap_authority_stamp *
channel_message_authority(const struct channel_message *message)
{
	if (message == NULL || !message->authority.valid ||
	    message->authority.issuer == 0 || message->authority.identity == 0)
		return (NULL);
	return (&message->authority);
}

size_t
channel_message_fd_count(const struct channel_message *message)
{

	return (message == NULL ? 0 : message->nfds);
}

int
channel_message_borrow_fd(const struct channel_message *message, size_t slot)
{

	if (message == NULL || slot >= message->nfds ||
	    message->fds[slot] < 0) {
		errno = EINVAL;
		return (-1);
	}
	if (message->owner != channel_self_pid()) {
		errno = ECHILD;
		return (-1);
	}
	return (message->fds[slot]);
}

int
channel_message_take_fd(struct channel_message *message, size_t slot)
{
	int fd;

	if (message == NULL || slot >= message->nfds ||
	    message->fds[slot] < 0) {
		errno = EINVAL;
		return (-1);
	}
	if (message->owner != channel_self_pid()) {
		errno = ECHILD;
		return (-1);
	}
	fd = message->fds[slot];
	message->fds[slot] = -1;
	return (fd);
}

int
channel_message_fd_info(const struct channel_message *message, size_t slot,
    struct channel_fd_info *info)
{

	if (message == NULL || info == NULL || slot >= message->nfds) {
		errno = EINVAL;
		return (-1);
	}
	if (!message->has_fd_info) {
		errno = ENOTSUP;
		return (-1);
	}
	*info = message->fd_info[slot];
	return (0);
}

void
channel_message_free(struct channel_message *message)
{
	struct channel *channel;
	size_t i;

	if (message == NULL)
		return;
	channel = message->channel;
	if (message->owner == channel_self_pid()) {
		for (i = 0; i < message->nfds; i++)
			if (message->fds[i] >= 0)
				(void)close(message->fds[i]);
	}
	free(message);		/* descriptors and payload are inline */
	channel_release(channel);
}

int
channel_request_cancel(struct channel_request *request)
{
	struct channel *channel;
	struct channel_queue_entry **out_link, *out, *out_previous;
	struct channel_request **link;

	if (request == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (!channel_owned(request->channel))
		return (-1);
	if (!request->pending || request->channel == NULL) {
		errno = EALREADY;
		return (-1);
	}
	channel = request->channel;
	out_previous = NULL;
	for (out_link = &channel->out_head; (out = *out_link) != NULL;
	    out_previous = out, out_link = &out->next) {
		if (out->request != request)
			continue;
		*out_link = out->next;
		if (channel->out_tail == out)
			channel->out_tail = out_previous;
		channel->nqueued--;
		channel->queued_bytes -= out->length;
		channel->queued_fds -= out->nfds;
		channel_outgoing_free(out);
		break;
	}
	for (link = &channel->requests; *link != NULL;
	    link = &(*link)->next)
		if (*link == request) {
			*link = request->next;
			request->next = NULL;
			channel->npending--;
			break;
		}
	channel_request_complete(request, NULL, ECANCELED);
	return (0);
}

int
channel_request_status(const struct channel_request *request)
{

	if (request == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (!channel_owned(request->channel))
		return (-1);
	if (request->pending)
		return (EINPROGRESS);
	return (request->status);
}

void
channel_request_release(struct channel_request *request)
{

	if (request == NULL)
		return;
	if (request->channel != NULL &&
	    request->channel->owner != channel_self_pid())
		return;
	if (request->pending) {
		request->free_pending = true;
		return;
	}
	if (request->callback_active) {
		request->free_pending = true;
		return;
	}
	free(request);
}
