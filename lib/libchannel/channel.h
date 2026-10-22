/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _CHANNEL_H_
#define _CHANNEL_H_

#include <sys/cdefs.h>
#include <sys/types.h>

#include <stddef.h>
#include <sys/cap_authority.h>
#include <stdint.h>

struct channel;
struct channel_message;

/* Kernel-stamped process attribution, independent of authorization. */
struct channel_process_identity {
	uint64_t identity;
	uint64_t responsible_identity;
	int32_t pid;
	int32_t responsible_pid;
};

struct channel_request;

enum channel_role {
	CHANNEL_ROLE_CLIENT = 1,
	CHANNEL_ROLE_PROVIDER = 2
};

enum channel_message_kind {
	CHANNEL_MESSAGE_REQUEST = 1,
	CHANNEL_MESSAGE_REPLY = 2,
	CHANNEL_MESSAGE_EVENT = 3
};

struct channel_options {
	size_t		 size;
	enum channel_role role;
	size_t		 max_pending_requests;
	size_t		 max_queued_messages;
	size_t		 max_queued_bytes;
	size_t		 max_queued_fds;
};

#define	CHANNEL_OPTIONS_INITIALIZER(_role) {		\
	.size = sizeof(struct channel_options),		\
	.role = (_role),				\
	.max_pending_requests = 256,			\
	.max_queued_messages = 256,			\
	.max_queued_bytes = 1024 * 1024,			\
	.max_queued_fds = 256				\
}

/*
 * Sender ABI, stamped by the kernel from the sending process's sysentvec
 * alongside uid/gid/prison/nonce.  Values mirror SV_ABI_* (<sys/sysent.h>);
 * CHANNEL_ABI_UNKNOWN is reported for kernel-originated messages and by
 * kernels that predate the stamp.  Informational only; never a gate.
 */
#define	CHANNEL_ABI_UNKNOWN	0
#define	CHANNEL_ABI_LINUX	3
#define	CHANNEL_ABI_NATIVE	9

struct channel_sender {
	uint64_t	badge;
	uint64_t	nonce;
	uint32_t	uid;
	uint32_t	gid;
	int32_t		prison_id;
	uint8_t		abi;		/* CHANNEL_ABI_* */
};
_Static_assert(sizeof(struct channel_sender) == 32,
    "channel_sender layout is shared with consumers; abi fits in tail padding");

/*
 * Optional expectation for one attached descriptor.  The kernel checks the
 * type and rights of every descriptor before accepting the message and
 * narrows only the delivered copy to the requested rights.  Without kernel
 * support the library performs the same checks itself.
 */
#define	CHANNEL_FD_TYPE_ANY	0
#define	CHANNEL_FD_TYPE_SOCKET	1
#define	CHANNEL_FD_TYPE_CHANNEL	2	/* a channel endpoint */
#define	CHANNEL_FD_TYPE_OTHER	3	/* channel_message_fd_info() only */
#define	CHANNEL_FD_RIGHT_READ	0x00000001
#define	CHANNEL_FD_RIGHT_WRITE	0x00000002
#define	CHANNEL_FD_RIGHT_FSTAT	0x00000004	/* fd_info only */
#define	CHANNEL_FD_RIGHTS_ALL	0x40000000	/* fd_info: unrestricted */
#define	CHANNEL_FD_RIGHTS_EXACT	0x80000000	/* fd_info: no other rights */
#define	CHANNEL_FD_LOCK_INHERIT	0x00000001	/* spec flag, see below */

struct channel_fd_spec {
	uint32_t	type;		/* CHANNEL_FD_TYPE_* */
	uint32_t	rights;		/* CHANNEL_FD_RIGHT_READ|WRITE, 0: keep */
	uint32_t	flags;		/* CHANNEL_FD_LOCK_INHERIT */
	uint32_t	reserved;	/* must be 0 */
};

struct channel_fd_info {
	uint32_t	type;		/* CHANNEL_FD_TYPE_* */
	uint32_t	rights;		/* CHANNEL_FD_RIGHT* */
};

/*
 * Outgoing flags.  CHANNEL_SEND_MOVE transfers ownership of the attached
 * descriptors: once the message is accepted (sent or queued) they are
 * closed for the caller; on failure they remain the caller's.
 * CHANNEL_FD_LOCK_INHERIT (per descriptor) delivers it with close-on-exec
 * and close-on-fork locked.  All descriptors, however many, are handled in
 * the one send system call.
 */
#define	CHANNEL_SEND_MOVE		0x00000001
/* CHANNEL_FD_LOCK_INHERIT for every attached descriptor. */
#define	CHANNEL_SEND_LOCK_INHERIT	0x00000002

struct channel_outgoing {
	size_t		size;
	const void	*data;
	size_t		length;
	const int	*fds;
	size_t		nfds;
	/* Read only when size covers them (libchannel 2). */
	const struct channel_fd_spec *fd_specs;	/* NULL or nfds entries */
	uint32_t	flags;			/* CHANNEL_SEND_* */
};
/* Callers built before fd_specs and flags existed pass this size. */
#define	CHANNEL_OUTGOING_SIZE_V1	offsetof(struct channel_outgoing, fd_specs)

#define	CHANNEL_OUTGOING_INITIALIZER(_data, _length) {	\
	.size = sizeof(struct channel_outgoing),		\
	.data = (_data),					\
	.length = (_length),				\
	.fds = NULL,					\
	.nfds = 0,					\
	.fd_specs = NULL,				\
	.flags = 0					\
}

typedef void (*channel_reply_handler)(struct channel_request *,
	    struct channel_message *, int, void *);
typedef void (*channel_request_handler)(struct channel *,
	    struct channel_message *, void *);
typedef void (*channel_event_handler)(struct channel *,
	    struct channel_message *, void *);

/*
 * Consumes the descriptor on success.  The channel owns a private
 * close-on-fork/exec duplicate, whose number is returned by channel_fd();
 * the input descriptor remains owned by the caller on failure.
 */
__BEGIN_DECLS

int	channel_create(int, const struct channel_options *, struct channel **);
void	channel_destroy(struct channel *);
void	channel_abandon(struct channel *);
int	channel_fd(const struct channel *);
int	channel_error(const struct channel *);
int	channel_wants_write(const struct channel *);

/*
 * Readiness wait (kqueue-only; channels do not support poll(2)/select(2)).
 * Returns a bitmask of the ready filters, 0 on timeout, or -1 on error.
 */
#define	CHANNEL_WAIT_READ	0x1
#define	CHANNEL_WAIT_WRITE	0x2
int	channel_wait(struct channel *, int /*want_write*/, int /*timeout_ms*/);

int	channel_send_request(struct channel *, const struct channel_outgoing *,
	    channel_reply_handler, void *, struct channel_request **);
int	channel_send_event(struct channel *, const struct channel_outgoing *);
int	channel_set_request_handler(struct channel *,
	    channel_request_handler, void *);
int	channel_set_event_handler(struct channel *, channel_event_handler,
	    void *);
int	channel_dispatch(struct channel *);
int	channel_flush(struct channel *);

int	channel_send_reply(struct channel_message *,
	    const struct channel_outgoing *);

/*
 * Send-path statistics.  Set size before calling.  The sent_* counters are
 * cumulative over the channel's lifetime: sent_direct counts messages the
 * kernel accepted from the caller's memory, sent_queued those queued behind
 * backpressure and sent_flushed the queued ones since accepted by
 * channel_flush().  The remaining fields are current gauges.
 */
struct channel_stats {
	size_t		size;
	uint64_t	sent_direct;
	uint64_t	sent_queued;
	uint64_t	sent_flushed;
	uint64_t	pending_requests;
	uint64_t	queued_messages;
	uint64_t	queued_bytes;
	uint64_t	queued_fds;
};
#define	CHANNEL_STATS_INITIALIZER	{ .size = sizeof(struct channel_stats) }
int	channel_get_stats(const struct channel *, struct channel_stats *);

/*
 * Encode into the send buffer.  channel_outgoing_reserve() yields a buffer
 * with room for max_length payload bytes and nfds descriptors; the caller
 * writes the payload at channel_outgoing_buffer_data() and commits it with
 * its actual length (1..max_length) and up to nfds descriptors, after which
 * the buffer is no longer the caller's.  When nothing is queued ahead and the
 * kernel accepts the message it is sent from the buffer; otherwise the
 * buffer itself becomes the queue entry.  A failed commit leaves the
 * buffer, its payload and the caller's descriptors as they were; the caller
 * commits again or aborts.  Descriptors, expectations, flags and the
 * request or reply semantics are those of the channel_send_* functions.
 */
struct channel_outgoing_buffer;
int	channel_outgoing_reserve(struct channel *, size_t /*max_length*/,
	    size_t /*nfds*/, struct channel_outgoing_buffer **);
void	*channel_outgoing_buffer_data(struct channel_outgoing_buffer *);
size_t	channel_outgoing_buffer_capacity(
	    const struct channel_outgoing_buffer *);
int	channel_outgoing_commit_event(struct channel_outgoing_buffer *,
	    size_t /*length*/, const int * /*fds*/, size_t /*nfds*/,
	    const struct channel_fd_spec *, uint32_t /*CHANNEL_SEND_* */);
int	channel_outgoing_commit_request(struct channel_outgoing_buffer *,
	    size_t /*length*/, const int * /*fds*/, size_t /*nfds*/,
	    const struct channel_fd_spec *, uint32_t /*CHANNEL_SEND_* */,
	    channel_reply_handler, void *, struct channel_request **);
int	channel_outgoing_commit_reply(struct channel_outgoing_buffer *,
	    struct channel_message * /*request*/, size_t /*length*/,
	    const int * /*fds*/, size_t /*nfds*/,
	    const struct channel_fd_spec *, uint32_t /*CHANNEL_SEND_* */);
void	channel_outgoing_abort(struct channel_outgoing_buffer *);

enum channel_message_kind
	channel_message_kind(const struct channel_message *);
const void *channel_message_data(const struct channel_message *);
size_t	channel_message_length(const struct channel_message *);
uint64_t channel_message_token(const struct channel_message *);
const struct channel_sender *
	channel_message_sender(const struct channel_message *);
/* NULL when the kernel or descriptor rights provide only legacy metadata. */
const struct channel_process_identity *
	channel_message_process(const struct channel_message *);
/* NULL unless the kernel stamped a currently valid issued authority. */
const struct cap_authority_stamp *
	channel_message_authority(const struct channel_message *);
size_t	channel_message_fd_count(const struct channel_message *);
int	channel_message_borrow_fd(const struct channel_message *, size_t);
int	channel_message_take_fd(struct channel_message *, size_t);
/* Kernel-reported type and rights of an attached descriptor; -1 (ENOTSUP)
 * when the kernel does not report them. */
int	channel_message_fd_info(const struct channel_message *, size_t,
	    struct channel_fd_info *);
void	channel_message_free(struct channel_message *);

/*
 * Synchronous call (channel_call.c).  channel_call_request() is
 * channel_send_request() whose reply, on kernels with
 * MAC_CAPABILITY_CHANNEL_CALL, is received in the same system call: when
 * nothing is queued ahead the calling thread sleeps in the kernel for the
 * message carrying the request's token, events and other replies stay
 * queued for channel_dispatch(), and the handler runs with the reply (or
 * ETIMEDOUT after timeout_ms milliseconds; -1 waits without limit) before
 * this returns, so *request may already have been handed to it.  When the
 * kernel lacks the command, output is queued, or the kernel refuses the
 * request with EAGAIN, the request is sent or queued as usual and completes
 * from channel_dispatch(); the timeout then does not apply.
 * channel_request_status() tells the two apart.  A late reply to a timed-out
 * call is discarded, with its descriptors closed, on either path.
 *
 * channel_call() wraps it for callers without an event loop: it runs the
 * wait/dispatch loop when needed, applying timeout_ms to the whole call,
 * and returns the reply, a CHANNEL_MESSAGE_REPLY the caller frees.  Other
 * messages received meanwhile reach the installed handlers as from
 * channel_dispatch().  Fails with ETIMEDOUT (the request stays sent) or the
 * terminal channel error.
 */
int	channel_call_request(struct channel *, const struct channel_outgoing *,
	    channel_reply_handler, void *, struct channel_request **,
	    int /*timeout_ms*/);
int	channel_call(struct channel *, const struct channel_outgoing *,
	    struct channel_message **, int /*timeout_ms*/);

/*
 * Create a fresh, self-owned pair of two connected mac_capability channel
 * endpoints (no service connection, no authority — the socketpair(2)
 * equivalent).  fds[0] and fds[1] are the two ends; a message sent on
 * either is delivered to the other, kernel-stamped with the sender's
 * cred nonce.  Works inside cap_enter().  Returns 0 on success, or -1
 * with errno (ENOSYS when the kernel lacks the syscall — fail soft).
 */
int	mac_capability_channel_create(int fds[2]);

int	channel_request_cancel(struct channel_request *);
int	channel_request_status(const struct channel_request *);
void	channel_request_release(struct channel_request *);

__END_DECLS

#endif /* _CHANNEL_H_ */
