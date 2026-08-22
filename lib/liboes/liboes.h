/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * liboes - Userspace library for Endpoint Security Capabilities
 */

#ifndef _LIBOES_H_
#define _LIBOES_H_

#include <sys/types.h>
#include <stdbool.h>

/* Include kernel definitions */
#include <security/oes/oes.h>

__BEGIN_DECLS

/*
 * Client handle (opaque)
 */
typedef struct oes_client oes_client_t;

/*
 * Event handler callback
 *
 * Called for each event received. For AUTH events, must call
 * oes_respond() before returning (or event times out).
 *
 * Return false to stop the event loop.
 */
typedef bool (*oes_handler_t)(oes_client_t *client, const oes_message_t *msg,
    void *context);

/*
 * Client creation and destruction
 */

/*
 * oes_client_create - Create a new OES client
 *
 * Opens /dev/oes and returns a client handle.
 * Requires appropriate privileges.
 *
 * Returns NULL on error, sets errno.
 */
oes_client_t *oes_client_create(void);

/*
 * Create a client scoped to the calling process and its descendants.
 *
 * The root process is visible for NOTIFY events; descendants are visible for
 * AUTH and NOTIFY events.  Processes outside the subtree are never delivered.
 * On FreeBSD this still requires permission to open /dev/oes.
 */
oes_client_t *oes_client_create_descendants(void);

/*
 * oes_client_create_from_fd - Create client from existing fd
 *
 * Used when receiving a restricted fd from a system daemon.
 * The fd is NOT closed when client is destroyed.
 *
 * Returns NULL on error, sets errno.
 */
oes_client_t *oes_client_create_from_fd(int fd);

/*
 * oes_client_destroy - Destroy a client
 *
 * Closes the underlying fd (unless created with _from_fd).
 * Any pending AUTH events get default response.
 */
void oes_client_destroy(oes_client_t *client);

/*
 * oes_client_fd - Get the underlying file descriptor
 *
 * Useful for poll()/kevent() integration.
 */
int oes_client_fd(oes_client_t *client);

/* Select/query visibility.  Scope can only be narrowed before configuration. */
int oes_set_descendants_scope(oes_client_t *client);
int oes_get_scope(oes_client_t *client, uint32_t *scope);

/*
 * Configuration
 */

/*
 * oes_set_mode - Set client operating mode
 *
 * mode: OES_MODE_NOTIFY, OES_MODE_AUTH, or OES_MODE_PASSIVE
 * default_deadline_ms: default AUTH deadline in milliseconds (0 = current)
 * queue_size: Max queued events (0 = keep current)
 *
 * Returns 0 on success, -1 on error (sets errno).
 */
int oes_set_mode(oes_client_t *client, uint32_t mode,
    uint32_t default_deadline_ms, uint32_t queue_size);

/*
 * oes_get_mode - Get current client mode and configuration
 *
 * mode: OUT, current operating mode (may be NULL)
 * default_deadline_ms: OUT, current default AUTH deadline (may be NULL)
 * queue_size: OUT, current max queued events (may be NULL)
 *
 * Returns 0 on success, -1 on error (sets errno).
 */
int oes_get_mode(oes_client_t *client, uint32_t *mode,
    uint32_t *default_deadline_ms, uint32_t *queue_size);

/* Per-AUTH-event deadline controls (milliseconds). */
int oes_set_deadline_max(oes_client_t *client, oes_event_type_t event,
    uint32_t milliseconds);
int oes_get_deadline_max(oes_client_t *client, oes_event_type_t event,
    uint32_t *milliseconds);
int oes_set_deadline_min(oes_client_t *client, oes_event_type_t event,
    uint32_t milliseconds);
int oes_get_deadline_min(oes_client_t *client, oes_event_type_t event,
    uint32_t *milliseconds);

/*
 * Set/query behavior when an AUTH deadline is missed or delivery is dropped.
 */
int oes_set_deadline_miss_mode(oes_client_t *client,
    oes_deadline_miss_mode_t mode);
int oes_get_deadline_miss_mode(oes_client_t *client,
    oes_deadline_miss_mode_t *mode);

/*
 * oes_cache_add - Add or update a decision cache entry
 */
int oes_cache_add(oes_client_t *client, const oes_cache_entry_t *entry);

/*
 * oes_cache_remove - Remove decision cache entries matching key
 */
int oes_cache_remove(oes_client_t *client, const oes_cache_key_t *key);

/*
 * oes_cache_clear - Clear the decision cache for this client
 */
int oes_cache_clear(oes_client_t *client);

/*
 * oes_subscribe - Subscribe to event types
 *
 * events: Array of event types to subscribe to
 * count: Number of events in array
 * flags: OES_SUB_ADD or OES_SUB_REPLACE
 *
 * Returns 0 on success, -1 on error.
 */
int oes_subscribe(oes_client_t *client, const oes_event_type_t *events,
    size_t count, uint32_t flags);

/* Remove selected subscriptions, or remove every subscription. */
int oes_unsubscribe(oes_client_t *client, const oes_event_type_t *events,
    size_t count);
int oes_unsubscribe_all(oes_client_t *client);

/* Retrieve the current 128-bit AUTH and NOTIFY subscription sets. */
int oes_get_subscriptions(oes_client_t *client, uint64_t auth_bitmap[2],
    uint64_t notify_bitmap[2]);

/*
 * oes_subscribe_bitmap - Subscribe using bitmaps directly
 *
 * Efficient bulk subscription using event bitmaps.
 * Bit positions correspond to (event_type & 0x0FFF).
 * Each bitmap contains bits 0-127.
 *
 * Returns 0 on success, -1 on error (sets errno).
 */
int oes_subscribe_bitmap(oes_client_t *client, const uint64_t auth_bitmap[2],
    const uint64_t notify_bitmap[2], uint32_t flags);

/*
 * oes_subscribe_all - Subscribe to all events of a type
 *
 * auth: Subscribe to all AUTH events
 * notify: Subscribe to all NOTIFY events
 */
int oes_subscribe_all(oes_client_t *client, bool auth, bool notify);

/*
 * oes_mute_self - Mute events from the current process
 *
 * Prevents recursion when this process triggers events.
 */
int oes_mute_self(oes_client_t *client);

/*
 * oes_mute_process - Mute events from a specific process
 */
int oes_mute_process(oes_client_t *client, const oes_proc_token_t *token);

/*
 * oes_unmute_process - Unmute a previously muted process
 */
int oes_unmute_process(oes_client_t *client, const oes_proc_token_t *token);

/*
 * oes_mute_path - Mute events whose primary object matches a path
 *
 * type: OES_MUTE_PATH_LITERAL or OES_MUTE_PATH_PREFIX
 * This is target-object muting, not executable/source-process muting.
 */
int oes_mute_path(oes_client_t *client, const char *path, uint32_t type);

/*
 * oes_unmute_path - Unmute events by path
 */
int oes_unmute_path(oes_client_t *client, const char *path, uint32_t type);

/*
 * oes_mute_target_path - Mute events by secondary/destination path
 */
int oes_mute_target_path(oes_client_t *client, const char *path,
    uint32_t type);

/*
 * oes_unmute_target_path - Unmute events by target path
 */
int oes_unmute_target_path(oes_client_t *client, const char *path,
    uint32_t type);

/* Clear process/path mute lists, including defaults applied at mode setup. */
int oes_unmute_all_processes(oes_client_t *client);
int oes_unmute_all_paths(oes_client_t *client);
int oes_unmute_all_target_paths(oes_client_t *client);

/*
 * oes_set_mute_invert - Enable/disable mute inversion for a type
 */
int oes_set_mute_invert(oes_client_t *client, uint32_t type, bool invert);

/*
 * oes_get_mute_invert - Query mute inversion for a type
 */
int oes_get_mute_invert(oes_client_t *client, uint32_t type, bool *invert);

/*
 * Event handling
 */

/*
 * oes_read_event - Read one event (blocking or non-blocking)
 *
 * On success, *msgp points to the event inside the client's internal
 * buffer.  The pointer is valid until the next oes_read_event() call.
 * Copy any data you need before calling oes_read_event() again.
 *
 * The kernel batches multiple NOTIFY events per read() syscall.
 * This function drains them one at a time transparently.
 *
 * Returns 0 on success, -1 on error.
 * EAGAIN if non-blocking and no events available.
 */
int oes_read_event(oes_client_t *client, const oes_message_t **msgp,
    bool blocking);

/* Copy a message when it must outlive the next read on this client. */
oes_message_t *oes_message_copy(const oes_message_t *msg);
void oes_message_free(oes_message_t *msg);

/*
 * oes_respond - Respond to an AUTH event
 *
 * msg_id: Message ID from oes_message_t.em_id
 * result: OES_AUTH_ALLOW or OES_AUTH_DENY
 *
 * Returns 0 on success, -1 on error.
 */
int oes_respond(oes_client_t *client, uint64_t msg_id,
    oes_auth_result_t result);

/*
 * oes_respond_flags - Respond with event-specific flag restrictions.
 *
 * For AUTH_OPEN, AUTH_MMAP, and AUTH_MPROTECT, allowed_flags restricts an
 * otherwise allowed request and denied_flags explicitly denies matching
 * requested flags.  A zero value for either field leaves that restriction
 * unset.  Other AUTH events ignore the flag fields.
 */
int oes_respond_flags(oes_client_t *client, uint64_t msg_id,
    oes_auth_result_t result, uint32_t allowed_flags,
    uint32_t denied_flags);

/*
 * oes_respond_allow - Shorthand for oes_respond(..., OES_AUTH_ALLOW)
 */
static inline int
oes_respond_allow(oes_client_t *client, const oes_message_t *msg)
{
	return (oes_respond(client, msg->em_id, OES_AUTH_ALLOW));
}

/*
 * oes_respond_deny - Shorthand for oes_respond(..., OES_AUTH_DENY)
 */
static inline int
oes_respond_deny(oes_client_t *client, const oes_message_t *msg)
{
	return (oes_respond(client, msg->em_id, OES_AUTH_DENY));
}

/*
 * oes_process_path - Get the cached executable path from process info
 *
 * Check OES_PROC_META_PATH_UNAVAILABLE and OES_PROC_META_PATH_TRUNCATED.
 */
static inline const char *
oes_process_path(const oes_message_t *msg, const oes_process_t *proc)
{
	return (oes_msg_string(msg, proc->ep_path_off));
}

/*
 * oes_file_path - Get file path from file info
 */
static inline const char *
oes_file_path(const oes_message_t *msg, const oes_file_t *file)
{
	return (oes_msg_string(msg, file->ef_path_off));
}

/*
 * oes_dispatch - Event dispatch loop
 *
 * Reads events and calls handler for each one.
 * Returns when handler returns false or on error.
 *
 * Returns 0 if handler stopped, -1 on error.
 */
int oes_dispatch(oes_client_t *client, oes_handler_t handler, void *context);

/*
 * Statistics
 */

/*
 * oes_get_stats - Get client statistics
 */
int oes_get_stats(oes_client_t *client, struct oes_stats *stats);

/*
 * Utility functions
 */

/*
 * oes_event_name - Get human-readable event name
 */
const char *oes_event_name(oes_event_type_t event);

/*
 * oes_is_auth_event - Check if event requires AUTH response
 */
static inline bool
oes_is_auth_event(const oes_message_t *msg)
{
	return msg->em_action == OES_ACTION_AUTH;
}

__END_DECLS

#endif /* !_LIBOES_H_ */
