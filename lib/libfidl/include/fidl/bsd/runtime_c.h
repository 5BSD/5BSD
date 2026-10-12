/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef FIDL_BSD_RUNTIME_C_H
#define FIDL_BSD_RUNTIME_C_H
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
/* Borrowed original native message; kernel stamps remain available to C
 * callers. */
struct channel_message;
const struct channel_message *fidl_bsd_request_native(
    const struct fidl_bsd_request *);
#ifdef __cplusplus
}
#endif
#endif
