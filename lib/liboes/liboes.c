/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * liboes - Userspace library for Endpoint Security Capabilities
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "liboes.h"

/*
 * Client structure
 */
struct oes_client {
	int		ec_fd;		/* File descriptor */
	bool		ec_owned;	/* We own the fd (close on destroy) */
	uint32_t	ec_mode;	/* Current mode */

	/*
	 * Batch read buffer: kernel packs multiple NOTIFY events per read().
	 * Union ensures the buffer is aligned for oes_message_t access.
	 */
	union {
		oes_message_t	_align;
		uint8_t		_raw[OES_MSG_MAX_SIZE];
	}		ec_buf;
	size_t		ec_buflen;	/* Valid bytes in ec_buf */
	size_t		ec_bufoff;	/* Current read offset into ec_buf */
};

static int
oes_client_get_fd(oes_client_t *client)
{
	if (client == NULL) {
		errno = EINVAL;
		return (-1);
	}
	return (client->ec_fd);
}

/*
 * oes_client_create - Create a new OES client
 */
oes_client_t *
oes_client_create(void)
{
	oes_client_t *client;
	int fd;

	fd = open(OES_DEVICE_PATH, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return (NULL);

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		close(fd);
		return (NULL);
	}

	client->ec_fd = fd;
	client->ec_owned = true;
	client->ec_mode = OES_MODE_NOTIFY;

	return (client);
}

/*
 * oes_client_create_from_fd - Create client from existing fd
 */
oes_client_t *
oes_client_create_from_fd(int fd)
{
	oes_client_t *client;

	if (fd < 0) {
		errno = EBADF;
		return (NULL);
	}

	client = calloc(1, sizeof(*client));
	if (client == NULL)
		return (NULL);

	client->ec_fd = fd;
	client->ec_owned = false;
	client->ec_mode = OES_MODE_NOTIFY;

	return (client);
}

/*
 * oes_client_destroy - Destroy a client
 */
void
oes_client_destroy(oes_client_t *client)
{

	if (client == NULL)
		return;

	if (client->ec_owned && client->ec_fd >= 0)
		close(client->ec_fd);

	free(client);
}

/*
 * oes_client_fd - Get the underlying file descriptor
 */
int
oes_client_fd(oes_client_t *client)
{

	return (oes_client_get_fd(client));
}

/*
 * oes_set_mode - Set client operating mode
 */
int
oes_set_mode(oes_client_t *client, uint32_t mode,
    uint32_t timeout_ms, uint32_t queue_size)
{
	struct oes_mode_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);

	memset(&args, 0, sizeof(args));
	args.ema_mode = mode;
	args.ema_timeout_ms = timeout_ms;
	args.ema_queue_size = queue_size;

	if (ioctl(fd, OES_IOC_SET_MODE, &args) < 0)
		return (-1);

	client->ec_mode = mode;
	return (0);
}

/*
 * oes_get_mode - Get current client mode and configuration
 */
int
oes_get_mode(oes_client_t *client, uint32_t *mode,
    uint32_t *timeout_ms, uint32_t *queue_size)
{
	struct oes_mode_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);

	memset(&args, 0, sizeof(args));
	if (ioctl(fd, OES_IOC_GET_MODE, &args) < 0)
		return (-1);

	if (mode != NULL)
		*mode = args.ema_mode;
	if (timeout_ms != NULL)
		*timeout_ms = args.ema_timeout_ms;
	if (queue_size != NULL)
		*queue_size = args.ema_queue_size;

	return (0);
}

/*
 * oes_set_timeout - Set AUTH timeout independently of mode
 */
int
oes_set_timeout(oes_client_t *client, uint32_t timeout_ms)
{
	struct oes_timeout_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);

	memset(&args, 0, sizeof(args));
	args.eta_timeout_ms = timeout_ms;

	return (ioctl(fd, OES_IOC_SET_TIMEOUT, &args));
}

/*
 * oes_get_timeout - Get current AUTH timeout
 */
int
oes_get_timeout(oes_client_t *client, uint32_t *timeout_ms)
{
	struct oes_timeout_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);

	memset(&args, 0, sizeof(args));
	if (ioctl(fd, OES_IOC_GET_TIMEOUT, &args) < 0)
		return (-1);

	if (timeout_ms != NULL)
		*timeout_ms = args.eta_timeout_ms;

	return (0);
}

/*
 * oes_set_timeout_action - Set default action when AUTH times out
 */
int
oes_set_timeout_action(oes_client_t *client, oes_auth_result_t action)
{
	struct oes_timeout_action_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);

	memset(&args, 0, sizeof(args));
	args.eta_action = action;

	if (ioctl(fd, OES_IOC_SET_TIMEOUT_ACTION, &args) < 0)
		return (-1);

	return (0);
}

/*
 * oes_get_timeout_action - Get default action when AUTH times out
 */
int
oes_get_timeout_action(oes_client_t *client, oes_auth_result_t *action)
{
	struct oes_timeout_action_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);

	memset(&args, 0, sizeof(args));
	if (ioctl(fd, OES_IOC_GET_TIMEOUT_ACTION, &args) < 0)
		return (-1);

	if (action != NULL)
		*action = (oes_auth_result_t)args.eta_action;

	return (0);
}

/*
 * oes_cache_add - Add or update a decision cache entry
 */
int
oes_cache_add(oes_client_t *client, const oes_cache_entry_t *entry)
{
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);
	return (ioctl(fd, OES_IOC_CACHE_ADD, entry));
}

/*
 * oes_cache_remove - Remove decision cache entries matching key
 */
int
oes_cache_remove(oes_client_t *client, const oes_cache_key_t *key)
{
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);
	return (ioctl(fd, OES_IOC_CACHE_REMOVE, key));
}

/*
 * oes_cache_clear - Clear the decision cache for this client
 */
int
oes_cache_clear(oes_client_t *client)
{
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);
	return (ioctl(fd, OES_IOC_CACHE_CLEAR, NULL));
}

/*
 * oes_subscribe - Subscribe to event types
 */
int
oes_subscribe(oes_client_t *client, const oes_event_type_t *events,
    size_t count, uint32_t flags)
{
	struct oes_subscribe_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);

	memset(&args, 0, sizeof(args));
	args.esa_events = events;
	args.esa_count = count;
	args.esa_flags = flags;

	return (ioctl(fd, OES_IOC_SUBSCRIBE, &args));
}

/*
 * oes_subscribe_bitmap - Subscribe using bitmaps directly
 *
 * This uses the bitmap ioctl for efficient bulk subscription.
 * Bit positions correspond to (event_type & 0x0FFF).
 */
int
oes_subscribe_bitmap(oes_client_t *client, uint64_t auth_bitmap,
    uint64_t notify_bitmap, uint32_t flags)
{
	struct oes_subscribe_bitmap_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);

	memset(&args, 0, sizeof(args));
	args.esba_auth = auth_bitmap;
	args.esba_notify = notify_bitmap;
	args.esba_flags = flags;

	return (ioctl(fd, OES_IOC_SUBSCRIBE_BITMAP, &args));
}

/*
 * oes_subscribe_bitmap_ex - Subscribe using 128-bit bitmaps
 *
 * Extended version supporting events with bit positions >= 64.
 */
int
oes_subscribe_bitmap_ex(oes_client_t *client, const uint64_t auth_bitmap[2],
    const uint64_t notify_bitmap[2], uint32_t flags)
{
	struct oes_subscribe_bitmap_ex_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);
	if (auth_bitmap == NULL || notify_bitmap == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&args, 0, sizeof(args));
	args.esba_auth[0] = auth_bitmap[0];
	args.esba_auth[1] = auth_bitmap[1];
	args.esba_notify[0] = notify_bitmap[0];
	args.esba_notify[1] = notify_bitmap[1];
	args.esba_flags = flags;

	return (ioctl(fd, OES_IOC_SUBSCRIBE_BITMAP_EX, &args));
}

/*
 * oes_subscribe_all - Subscribe to all events of a type
 *
 * Uses the extended bitmap ioctl for a single atomic operation.
 */
int
oes_subscribe_all(oes_client_t *client, bool auth, bool notify)
{
	const uint64_t all_auth[2] = {
		OES_AUTH_EVENT_MASK_LO, OES_AUTH_EVENT_MASK_HI
	};
	const uint64_t all_notify[2] = {
		OES_NOTIFY_EVENT_MASK_LO, OES_NOTIFY_EVENT_MASK_HI
	};

	return (oes_subscribe_bitmap_ex(client,
	    auth ? all_auth : (const uint64_t[2]){0, 0},
	    notify ? all_notify : (const uint64_t[2]){0, 0},
	    OES_SUB_REPLACE));
}

/*
 * oes_mute_self - Mute events from the current process
 */
int
oes_mute_self(oes_client_t *client)
{
	struct oes_mute_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);

	memset(&args, 0, sizeof(args));
	args.emu_flags = OES_MUTE_SELF;

	return (ioctl(fd, OES_IOC_MUTE_PROCESS, &args));
}

/*
 * oes_mute_process - Mute events from a specific process
 */
int
oes_mute_process(oes_client_t *client, const oes_proc_token_t *token)
{
	struct oes_mute_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);
	if (token == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&args, 0, sizeof(args));
	args.emu_token = *token;
	args.emu_flags = 0;

	return (ioctl(fd, OES_IOC_MUTE_PROCESS, &args));
}

/*
 * oes_unmute_process - Unmute a previously muted process
 */
int
oes_unmute_process(oes_client_t *client, const oes_proc_token_t *token)
{
	struct oes_mute_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);
	if (token == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&args, 0, sizeof(args));
	args.emu_token = *token;

	return (ioctl(fd, OES_IOC_UNMUTE_PROCESS, &args));
}

/*
 * oes_mute_path - Mute events by path
 */
int
oes_mute_path(oes_client_t *client, const char *path, uint32_t type)
{
	struct oes_mute_path_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);

	memset(&args, 0, sizeof(args));
	if (path != NULL)
		strlcpy(args.emp_path, path, sizeof(args.emp_path));
	args.emp_type = type;
	args.emp_flags = 0;

	return (ioctl(fd, OES_IOC_MUTE_PATH, &args));
}

/*
 * oes_unmute_path - Unmute events by path
 */
int
oes_unmute_path(oes_client_t *client, const char *path, uint32_t type)
{
	struct oes_mute_path_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);

	memset(&args, 0, sizeof(args));
	if (path != NULL)
		strlcpy(args.emp_path, path, sizeof(args.emp_path));
	args.emp_type = type;
	args.emp_flags = 0;

	return (ioctl(fd, OES_IOC_UNMUTE_PATH, &args));
}

/*
 * oes_mute_target_path - Mute events by target path
 */
int
oes_mute_target_path(oes_client_t *client, const char *path, uint32_t type)
{
	struct oes_mute_path_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);

	memset(&args, 0, sizeof(args));
	if (path != NULL)
		strlcpy(args.emp_path, path, sizeof(args.emp_path));
	args.emp_type = type;
	args.emp_flags = OES_MUTE_PATH_FLAG_TARGET;

	return (ioctl(fd, OES_IOC_MUTE_PATH, &args));
}

/*
 * oes_unmute_target_path - Unmute events by target path
 */
int
oes_unmute_target_path(oes_client_t *client, const char *path, uint32_t type)
{
	struct oes_mute_path_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);

	memset(&args, 0, sizeof(args));
	if (path != NULL)
		strlcpy(args.emp_path, path, sizeof(args.emp_path));
	args.emp_type = type;
	args.emp_flags = OES_MUTE_PATH_FLAG_TARGET;

	return (ioctl(fd, OES_IOC_UNMUTE_PATH, &args));
}

/*
 * oes_set_mute_invert - Enable/disable mute inversion for a type
 */
int
oes_set_mute_invert(oes_client_t *client, uint32_t type, bool invert)
{
	struct oes_mute_invert_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);

	memset(&args, 0, sizeof(args));
	args.emi_type = type;
	args.emi_invert = invert ? 1 : 0;

	return (ioctl(fd, OES_IOC_SET_MUTE_INVERT, &args));
}

/*
 * oes_get_mute_invert - Query mute inversion for a type
 */
int
oes_get_mute_invert(oes_client_t *client, uint32_t type, bool *invert)
{
	struct oes_mute_invert_args args;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);
	if (invert == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&args, 0, sizeof(args));
	args.emi_type = type;
	if (ioctl(fd, OES_IOC_GET_MUTE_INVERT, &args) < 0)
		return (-1);

	*invert = (args.emi_invert != 0);
	return (0);
}

/*
 * Refill the internal batch buffer from the kernel.
 * The kernel packs multiple NOTIFY events per read().
 */
static int
oes_refill(oes_client_t *client, bool blocking)
{
	struct pollfd pfd;
	ssize_t n;

	if (!blocking) {
		int ret;

		pfd.fd = client->ec_fd;
		pfd.events = POLLIN;
		pfd.revents = 0;

		ret = poll(&pfd, 1, 0);
		if (ret < 0)
			return (-1);
		if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
			errno = ENXIO;
			return (-1);
		}
		if (ret == 0 || !(pfd.revents & POLLIN)) {
			errno = EAGAIN;
			return (-1);
		}
	}

	n = read(client->ec_fd, client->ec_buf._raw, sizeof(client->ec_buf));
	if (n < 0)
		return (-1);

	if ((size_t)n < sizeof(oes_message_t)) {
		errno = EIO;
		return (-1);
	}

	client->ec_buflen = (size_t)n;
	client->ec_bufoff = 0;
	return (0);
}

/*
 * oes_read_event - Read one event from the batched buffer.
 *
 * Returns a pointer to the next event in the internal buffer.
 * The kernel packs multiple NOTIFY events per read() syscall;
 * this function drains them one at a time, refilling only when
 * the buffer is exhausted.
 *
 * The returned pointer is valid until the next oes_read_event() call.
 */
int
oes_read_event(oes_client_t *client, const oes_message_t **msgp,
    bool blocking)
{
	const oes_message_t *msg;

	if (client == NULL || msgp == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/* Advance past previous message if we have one buffered */
	if (client->ec_bufoff < client->ec_buflen) {
		msg = (const oes_message_t *)(void *)
		    (client->ec_buf._raw + client->ec_bufoff);
		if (msg->em_size < sizeof(oes_message_t) ||
		    msg->em_size > client->ec_buflen - client->ec_bufoff) {
			client->ec_buflen = 0;
			client->ec_bufoff = 0;
			errno = EIO;
			return (-1);
		}
		if (!oes_message_is_compatible(msg)) {
			client->ec_buflen = 0;
			client->ec_bufoff = 0;
			errno = EPROTO;
			return (-1);
		}
		client->ec_bufoff += msg->em_size;
	}

	/* Check if more messages remain in the batch */
	if (client->ec_bufoff + sizeof(oes_message_t) <= client->ec_buflen) {
		msg = (const oes_message_t *)(void *)
		    (client->ec_buf._raw + client->ec_bufoff);
		if (msg->em_size >= sizeof(oes_message_t) &&
		    client->ec_bufoff + msg->em_size <= client->ec_buflen) {
			*msgp = msg;
			return (0);
		}
	}

	/* Buffer empty or corrupt - refill from kernel */
	if (oes_refill(client, blocking) < 0)
		return (-1);

	msg = &client->ec_buf._align;
	if (msg->em_size < sizeof(oes_message_t) ||
	    msg->em_size > client->ec_buflen) {
		errno = EIO;
		return (-1);
	}
	if (!oes_message_is_compatible(msg)) {
		client->ec_buflen = 0;
		client->ec_bufoff = 0;
		errno = EPROTO;
		return (-1);
	}

	*msgp = msg;
	return (0);
}

/*
 * oes_respond - Respond to an AUTH event
 */
int
oes_respond(oes_client_t *client, uint64_t msg_id, oes_auth_result_t result)
{
	oes_response_t resp;
	ssize_t n;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);

	memset(&resp, 0, sizeof(resp));
	resp.er_id = msg_id;
	resp.er_result = result;

	n = write(fd, &resp, sizeof(resp));
	if (n < 0)
		return (-1);

	if (n != sizeof(resp)) {
		errno = EIO;
		return (-1);
	}

	return (0);
}

/*
 * oes_respond_flags - Respond to an AUTH event with flag restrictions
 */
int
oes_respond_flags(oes_client_t *client, uint64_t msg_id,
    oes_auth_result_t result, uint32_t allowed_flags, uint32_t denied_flags)
{
	oes_response_flags_t resp;
	ssize_t n;
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);
	if (result != OES_AUTH_ALLOW && result != OES_AUTH_DENY) {
		errno = EINVAL;
		return (-1);
	}

	memset(&resp, 0, sizeof(resp));
	resp.erf_id = msg_id;
	resp.erf_result = result;
	resp.erf_allowed_flags = allowed_flags;
	resp.erf_denied_flags = denied_flags;

	n = write(fd, &resp, sizeof(resp));
	if (n < 0)
		return (-1);
	if (n != sizeof(resp)) {
		errno = EIO;
		return (-1);
	}

	return (0);
}

/*
 * oes_dispatch - Event dispatch loop
 */
int
oes_dispatch(oes_client_t *client, oes_handler_t handler, void *context)
{
	const oes_message_t *msg;

	if (handler == NULL) {
		errno = EINVAL;
		return (-1);
	}

	for (;;) {
		if (oes_read_event(client, &msg, true) < 0)
			return (-1);

		if (!handler(client, msg, context))
			return (0);
	}
}

/*
 * oes_get_stats - Get client statistics
 */
int
oes_get_stats(oes_client_t *client, struct oes_stats *stats)
{
	int fd;

	fd = oes_client_get_fd(client);
	if (fd < 0)
		return (-1);
	return (ioctl(fd, OES_IOC_GET_STATS, stats));
}

/*
 * oes_event_name - Get human-readable event name
 */
const char *
oes_event_name(oes_event_type_t event)
{
/* Skip the common "OES_EVENT_" prefix, leaving e.g. "AUTH_EXEC". */
#define OES_EVENT_NAME_CASE(name, value) \
	case name: return (&(#name)[sizeof("OES_EVENT_") - 1]);
	switch (event) {
	OES_AUTH_EVENT_LIST(OES_EVENT_NAME_CASE)
	OES_NOTIFY_EVENT_LIST(OES_EVENT_NAME_CASE)
	default:
		return "UNKNOWN";
	}
#undef OES_EVENT_NAME_CASE
}
