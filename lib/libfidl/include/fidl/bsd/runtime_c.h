/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef FIDL_BSD_RUNTIME_C_H
#define FIDL_BSD_RUNTIME_C_H
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct fidl_bsd_empty {
	unsigned char unused;
};
#define FIDL_BSD_ABI_VERSION 1
uint32_t fidl_bsd_runtime_abi_version(void);
/* Sized options allow callers to set application resource limits explicitly. */
struct fidl_bsd_options {
	uint32_t size;
	uint32_t reserved;
	uint64_t max_pending_requests;
	uint64_t max_queued_messages;
	uint64_t max_queued_bytes;
	uint64_t max_queued_fds;
};
#define FIDL_BSD_OPTIONS_INITIALIZER \
	{ sizeof(struct fidl_bsd_options), 0, 256, 256, 1024 * 1024, 256 }
struct fidl_bsd_connection;
struct fidl_bsd_request;
enum fidl_bsd_role { FIDL_BSD_CLIENT = 1, FIDL_BSD_SERVER = 2 };
/* Takes the channel fd on success; leaves it owned by the caller on failure. */
int fidl_bsd_connection_create(int, enum fidl_bsd_role,
    struct fidl_bsd_connection **);
int fidl_bsd_connection_create_with_options(int, enum fidl_bsd_role,
    const struct fidl_bsd_options *, struct fidl_bsd_connection **);
/* Returns ENOENT until an epitaph is received; the protocol status is signed.
 */
int fidl_bsd_connection_peer_epitaph(const struct fidl_bsd_connection *,
    int32_t *);
/* Single dispatch thread. Do not destroy from a callback; close is permitted.
 */
void fidl_bsd_connection_destroy(struct fidl_bsd_connection *);
void fidl_bsd_connection_close(struct fidl_bsd_connection *, int);
int fidl_bsd_connection_poll(struct fidl_bsd_connection *, int);
int fidl_bsd_connection_dispatch(struct fidl_bsd_connection *);
int fidl_bsd_connection_fd(const struct fidl_bsd_connection *);
int fidl_bsd_connection_wants_write(const struct fidl_bsd_connection *);
int fidl_bsd_connection_error(const struct fidl_bsd_connection *);
int fidl_bsd_connection_cancel(struct fidl_bsd_connection *, uint32_t);
int fidl_bsd_connection_shutdown(struct fidl_bsd_connection *, int32_t);
/*
 * C connections deliver sent descriptors with close-on-exec and close-on-fork
 * locked.  A provider that sets each delivered descriptor's own inheritance
 * state (for example service_harden_fd(3) CLOFORK_ONCE) asks for that state
 * to be kept instead.
 */
void fidl_bsd_connection_preserve_sent_inheritance(struct fidl_bsd_connection *);
/*
 * One synchronous two-way call.  issue(context) makes exactly one generated
 * client call on the connection and returns its result.  When no other call
 * is outstanding and no output is queued, the request and its reply travel
 * in one system call (channel_call_request(3), kernels with
 * MAC_CAPABILITY_CHANNEL_CALL) and the call's callback has run, with its
 * reply or an error, when issue() returns; otherwise the call is sent as
 * usual and the connection is polled until it completes.  Returns issue()'s
 * error, else the completion's: 0 with a reply, ETIMEDOUT after timeout_ms
 * milliseconds (only this call is cancelled; the connection stays open), or a
 * transport error, which closes the connection.  EINVAL when issue() made no
 * call.  The callback must not destroy the connection.  Replaces
 * fidl_bsd_sync_deadline() plus fidl_bsd_sync_wait_txid() for one call.
 */
int fidl_bsd_connection_call(struct fidl_bsd_connection *, uint32_t,
    int (*)(void *), void *);
/*
 * Provider reactor helper: one kevent(2) wait over a listener and up to 256
 * server connections, then one bounded dispatch (and flush) per ready slot.
 * A slot's error is set when its connection failed; the caller destroys it.
 * *listener_ready is set when the listener (if >= 0) is readable.
 */
struct fidl_bsd_connection_slot {
	struct fidl_bsd_connection *connection;
	int error;
};
int fidl_bsd_connections_wait(int, struct fidl_bsd_connection_slot *, size_t,
    int, int, int *);
/* All status returns are errno values, except fd (descriptor or -1). */
void fidl_bsd_request_retain(struct fidl_bsd_request *);
void fidl_bsd_request_release(struct fidl_bsd_request *);
/* Take a received descriptor during its callback; strings are always borrowed.
 */
int fidl_bsd_take_fd(int *);
/*
 * Outgoing descriptor fields.  A non-negative value is borrowed: the call
 * sends a private duplicate and the caller keeps the descriptor and its
 * rights.  FIDL_BSD_FD_ABSENT (-1) is an absent optional descriptor.
 * fidl_bsd_fd_owned(fd) marks a descriptor the call takes instead: it is
 * moved into the message without a duplicate and the caller must not use or
 * close it afterwards, whether the call succeeds or fails.  A call that
 * fails before returning (an argument, connection or immediate send error)
 * closes it first; a message that was accepted (sent or queued) owns it and
 * the runtime closes it after delivery or when the queued send fails later.
 * Values below -1 are only produced by fidl_bsd_fd_owned(); received
 * descriptor fields are plain descriptors or -1.
 */
#define FIDL_BSD_FD_ABSENT (-1)
static inline int
fidl_bsd_fd_owned(int fd)
{
	return fd < 0 || fd > INT_MAX - 2 ? FIDL_BSD_FD_ABSENT : -2 - fd;
}
/* Borrowed original native message; kernel stamps remain available to C
 * callers. */
struct channel_message;
const struct channel_message *fidl_bsd_request_native(
    const struct fidl_bsd_request *);
#ifdef __cplusplus
}
#endif
#endif
