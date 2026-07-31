/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _CHANNEL_H_
#define _CHANNEL_H_

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

struct channel;
struct channel_message;
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

struct channel_sender {
	uint64_t	badge;
	uint64_t	nonce;
	uint32_t	uid;
	uint32_t	gid;
	int32_t		prison_id;
};

struct channel_outgoing {
	size_t		size;
	const void	*data;
	size_t		length;
	const int	*fds;
	size_t		nfds;
};

#define	CHANNEL_OUTGOING_INITIALIZER(_data, _length) {	\
	.size = sizeof(struct channel_outgoing),		\
	.data = (_data),					\
	.length = (_length),				\
	.fds = NULL,					\
	.nfds = 0					\
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
int	channel_create(int, const struct channel_options *, struct channel **);
void	channel_destroy(struct channel *);
void	channel_abandon(struct channel *);
int	channel_fd(const struct channel *);
int	channel_error(const struct channel *);
int	channel_wants_write(const struct channel *);

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

enum channel_message_kind
	channel_message_kind(const struct channel_message *);
const void *channel_message_data(const struct channel_message *);
size_t	channel_message_length(const struct channel_message *);
uint64_t channel_message_token(const struct channel_message *);
const struct channel_sender *
	channel_message_sender(const struct channel_message *);
size_t	channel_message_fd_count(const struct channel_message *);
int	channel_message_borrow_fd(const struct channel_message *, size_t);
int	channel_message_take_fd(struct channel_message *, size_t);
void	channel_message_free(struct channel_message *);

int	channel_request_cancel(struct channel_request *);
int	channel_request_status(const struct channel_request *);
void	channel_request_release(struct channel_request *);

#endif /* _CHANNEL_H_ */
