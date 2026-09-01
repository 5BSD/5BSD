/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * blued control socket — Unix domain socket for runtime management.
 *
 * Core control socket setup (bind/listen/accept), command dispatcher,
 * common send helpers, and commands that don't fit into the GATT or
 * connection-management groups.
 *
 * GATT commands are in ctl_gatt.c; connection commands in ctl_conn.c.
 * Shared declarations live in ctl_internal.h.
 */

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <err.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "adv_builder.h"
#include "att.h"
#include "att_server.h"
#include "blued.h"
#include "blued_devmgr.h"
#include "blued_internal.h"
#include "ble_util.h"
#include "blued_probes.h"
#include "config.h"
#include "conn.h"
#include "ctl.h"
#include "ctl_internal.h"
#include "hci_internal.h"
#include "hci_util.h"
#include "ipc_proto.h"
#include "iso.h"
#include "smp.h"

/* Peripheral GATT database — defined in blued.c */
extern struct att_db periph_gatt_db;

/*
 * Initialize ctl_clients_lock as a RECURSIVE mutex (lock-reacquisition class,
 * findings 30/88).
 *
 * The ctl event loop holds ctl_clients_lock across the whole verb dispatch
 * (blued_ctl_dispatch), but several handlers reach helpers that legitimately
 * need the same lock again — DISCONNECT -> blued_conn_disconnect ->
 * blued_ctl_broadcast_conn_event / ctl_gatt_conn_gone / ctl_acquire_conn_gone;
 * STATUS -> ctl_status_snapshot; POWER-off -> blued_adapter_set_power ->
 * blued_adapter_controller_invalidated -> blued_conn_disconnect -> (same).
 * With FreeBSD's default (ERRORCHECK) mutex the inner re-lock returns EDEADLK
 * (silently ignored) and, worse, the inner *unlock* releases the mutex early,
 * shredding the dispatch critical section that serialises client txq writes
 * against the GATT worker threads.  A recursive mutex makes the nested
 * acquire/release a no-op depth change, so the outermost holder keeps the lock
 * for the entire critical section regardless of how the call graph re-enters.
 * All other exclusion contracts are unchanged: it is still a normal mutex to
 * every other thread.
 */
void
blued_ctl_clients_lock_init(pthread_mutex_t *m)
{
	pthread_mutexattr_t attr;

	if (pthread_mutexattr_init(&attr) != 0) {
		/* Fall back to a default mutex rather than run uninitialised. */
		(void)pthread_mutex_init(m, NULL);
		return;
	}
	(void)pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	(void)pthread_mutex_init(m, &attr);
	(void)pthread_mutexattr_destroy(&attr);
}

static char	*ctl_sock_path;		/* saved for cleanup unlink */

/* Privilege-tier predicate, defined below but used by the bond export/import
 * handlers that appear before it. */
static bool	ctl_client_privileged(const struct blued_ctl_client *client);

/*
 * Remove a dead Unix-domain listener without stealing the pathname from a
 * live daemon.  unlink(2) unconditionally would let a second invocation make
 * the first daemon unreachable while both continue controlling the adapter.
 */
static int
ctl_unlink_stale_socket(const char *path)
{
	struct sockaddr_un sun;
	struct stat before, after;
	int fd, saved;

	if (lstat(path, &before) != 0)
		return (errno == ENOENT ? 0 : -1);
	if (!S_ISSOCK(before.st_mode) || before.st_uid != geteuid()) {
		errno = EPERM;
		return (-1);
	}

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return (-1);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == 0) {
		(void)close(fd);
		errno = EADDRINUSE;
		return (-1);
	}
	saved = errno;
	(void)close(fd);
	if (saved == ENOENT)
		return (0);
	if (saved != ECONNREFUSED) {
		errno = EADDRINUSE;
		return (-1);
	}

	/* Refuse to unlink if the pathname changed during the probe. */
	if (lstat(path, &after) != 0)
		return (errno == ENOENT ? 0 : -1);
	if (before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
	    !S_ISSOCK(after.st_mode) || after.st_uid != geteuid()) {
		errno = EAGAIN;
		return (-1);
	}
	return (unlink(path));
}

/*
 * Runtime pairing agent (the common pairing-agent model).  A privileged
 * push-events client registers itself as THE pairing agent with REGISTER_AGENT
 * <io_cap>; while registered, pairing prompts (passkey display/entry, numeric
 * comparison) route to that client alone and its declared IO capability
 * overrides the static config for the association-model selection (Core Spec
 * Vol 3 Part H §2.3.5.1).  Cleared on UNREGISTER_AGENT or on disconnect so a
 * departed agent never strands a pairing.  Lock-free: the fd/cap pair is set
 * under the ctl dispatch (which holds ctl_clients_lock) and read from the SMP
 * setup thread; atomics keep each field coherent and -1 means "no agent".
 */
static atomic_int ctl_agent_fd = -1;
static _Atomic uint64_t ctl_client_generation = 1;
static atomic_int ctl_agent_io_cap = SMP_IO_KEYBOARD_DISPLAY;
static int ctl_security_passkey_result(uint8_t, const bdaddr_t *, uint8_t,
    uint32_t);
static int ctl_security_numcmp_result(uint8_t, const bdaddr_t *, uint8_t,
    bool);
static int ctl_security_register_agent_result(struct blued_ctl_client *,
    uint8_t);
static void ctl_security_unregister_agent_result(struct blued_ctl_client *);
static struct blued_adapter *ctl_typed_adapter(uint16_t, uint32_t, bool *);
static struct blued_adapter *ctl_typed_adapter_any(uint16_t, uint32_t, bool *);
static int ctl_security_oob_generate_result(uint8_t [16], uint8_t [16],
    uint8_t [32]);
static int ctl_security_oob_inject_result(const bdaddr_t *, bool,
    const uint8_t [16], const uint8_t [16]);
static void ctl_security_oob_clear_result(const bdaddr_t *, bool);
static int ctl_security_resolv_result(struct blued_adapter *, uint16_t,
    const bdaddr_t *, uint8_t, const uint8_t [16], bool);


/*
 * Effective pairing IO capability: the registered agent's declared capability
 * overrides the static default; with no agent the static config is used
 * unchanged (no behaviour change).  Consulted by the central and peripheral
 * pairing setup paths when populating smp_conn.io_capability.
 */
uint8_t
blued_ctl_effective_io_cap(uint8_t static_default)
{

	if (atomic_load(&ctl_agent_fd) >= 0)
		return ((uint8_t)atomic_load(&ctl_agent_io_cap));
	return (static_default);
}

/* Clear the pairing agent if fd was the registered agent (on disconnect). */
static void
ctl_agent_client_gone(int fd)
{

	if (atomic_load(&ctl_agent_fd) == fd)
		atomic_store(&ctl_agent_fd, -1);
}

static void
ctl_tx_watch(struct blued_ctl_client *client, bool enable)
{
	struct kevent kev;

	if (!client->kq_registered || client->tx_write_enabled == enable)
		return;
	EV_SET(&kev, client->fd, EVFILT_WRITE,
	    enable ? EV_ADD | EV_ENABLE : EV_DELETE, 0, 0, client);
	if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) == 0)
		client->tx_write_enabled = enable;
}

void
blued_ctl_client_fini(struct blued_ctl_client *client)
{
	struct blued_ctl_tx *tx;

	while ((tx = STAILQ_FIRST(&client->txq)) != NULL) {
		STAILQ_REMOVE_HEAD(&client->txq, entries);
		if (tx->passed_fd >= 0)
			close(tx->passed_fd);
		free(tx->data);
		free(tx);
	}
	client->tx_queued = 0;
	client->tx_write_enabled = false;
}

int
blued_ctl_flush(struct blued_ctl_client *client)
{
	struct blued_ctl_tx *tx;
	ssize_t n;

	while ((tx = STAILQ_FIRST(&client->txq)) != NULL) {
		do {
			if (tx->passed_fd >= 0) {
				struct msghdr msg;
				struct iovec iov;
				struct cmsghdr *cmsg;
				char cbuf[CMSG_SPACE(sizeof(int))];

				memset(&msg, 0, sizeof(msg));
				iov.iov_base = tx->data + tx->off;
				iov.iov_len = tx->len - tx->off;
				msg.msg_iov = &iov;
				msg.msg_iovlen = 1;
				memset(cbuf, 0, sizeof(cbuf));
				msg.msg_control = cbuf;
				msg.msg_controllen = sizeof(cbuf);
				cmsg = CMSG_FIRSTHDR(&msg);
				cmsg->cmsg_level = SOL_SOCKET;
				cmsg->cmsg_type = SCM_RIGHTS;
				cmsg->cmsg_len = CMSG_LEN(sizeof(int));
				memcpy(CMSG_DATA(cmsg), &tx->passed_fd,
				    sizeof(tx->passed_fd));
				n = sendmsg(client->fd, &msg, MSG_NOSIGNAL);
			} else {
				n = send(client->fd, tx->data + tx->off,
				    tx->len - tx->off, MSG_NOSIGNAL);
			}
		} while (n < 0 && errno == EINTR);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				ctl_tx_watch(client, true);
				return (0);
			}
			client->tx_error = true;
			return (-1);
		}
		if (n == 0) {
			client->tx_error = true;
			errno = EPIPE;
			return (-1);
		}
		if (tx->passed_fd >= 0) {
			close(tx->passed_fd);
			tx->passed_fd = -1;
		}
		tx->off += (size_t)n;
		client->tx_queued -= (size_t)n;
		if (tx->off != tx->len) {
			ctl_tx_watch(client, true);
			return (0);
		}
		STAILQ_REMOVE_HEAD(&client->txq, entries);
		free(tx->data);
		free(tx);
	}
	ctl_tx_watch(client, false);
	return (0);
}

bool
ctl_tx_has_room(const struct blued_ctl_client *client, size_t need)
{

	if (client == NULL || client->tx_error || need > BLUED_CTL_TX_MAX)
		return (false);
	return (client->tx_queued <= BLUED_CTL_TX_MAX - need);
}

/* Queue one complete frame and opportunistically flush it. */
int
ctl_send_frame(struct blued_ctl_client *client, uint16_t type, uint16_t arg,
    const void *payload, size_t plen)
{
	struct blued_ctl_tx *tx;
	size_t flen;

	if (client == NULL || client->tx_error)
		return (-1);
	/* Unit-created clients may not have passed through blued_ctl_accept(). */
	if (client->txq.stqh_last == NULL)
		STAILQ_INIT(&client->txq);
	if (plen > IPC_MAX_PAYLOAD)
		plen = IPC_MAX_PAYLOAD;
	flen = IPC_HDR_SIZE + plen;
	if (!ctl_tx_has_room(client, flen)) {
		client->tx_error = true;
		errno = ENOBUFS;
		(void)shutdown(client->fd, SHUT_RDWR);
		return (-1);
	}
	tx = calloc(1, sizeof(*tx));
	if (tx == NULL)
		return (-1);
	tx->data = malloc(flen);
	if (tx->data == NULL) {
		free(tx);
		return (-1);
	}
	tx->len = flen;
	tx->passed_fd = -1;
	ipc_hdr_encode(tx->data, (uint32_t)plen, type, arg);
	if (plen != 0)
		memcpy(tx->data + IPC_HDR_SIZE, payload, plen);
	STAILQ_INSERT_TAIL(&client->txq, tx, entries);
	client->tx_queued += flen;
	return (blued_ctl_flush(client));
}

/* Queue one descriptor handout in-order with the surrounding frames. */
static int
ctl_queue_fd(struct blued_ctl_client *client, int fd)
{
	struct blued_ctl_tx *tx;

	if (!ctl_tx_has_room(client, 1)) {
		errno = ENOBUFS;
		return (-1);
	}
	if (client->txq.stqh_last == NULL)
		STAILQ_INIT(&client->txq);
	tx = calloc(1, sizeof(*tx));
	if (tx == NULL)
		return (-1);
	tx->data = calloc(1, 1);
	if (tx->data == NULL) {
		free(tx);
		return (-1);
	}
	tx->len = 1;
	tx->passed_fd = fd;
	STAILQ_INSERT_TAIL(&client->txq, tx, entries);
	client->tx_queued++;
	(void)blued_ctl_flush(client);
	return (0);
}

/*
 * Duplicate fd_to_send and capability-limit the copy for handout to a client,
 * returning the ready descriptor (caller owns it) or -1.  This is the fallible
 * part of an fd handout, separated so a caller can perform it BEFORE committing
 * to a success reply (finding 121).
 */
static int
ctl_dup_capped_fd(int fd_to_send, bool allow_reconfigure)
{
	int dup_fd;
	cap_rights_t rights;

	dup_fd = fcntl(fd_to_send, F_DUPFD_CLOEXEC, 0);
	if (dup_fd < 0)
		return (-1);

	if (allow_reconfigure)
		cap_rights_init(&rights, CAP_SEND, CAP_RECV, CAP_EVENT,
		    CAP_SETSOCKOPT);
	else
		cap_rights_init(&rights, CAP_SEND, CAP_RECV, CAP_EVENT);
	(void)cap_rights_limit(dup_fd, &rights);

	/* Restrict transfer/inheritance properties */
	(void)cap_xfer_limit(dup_fd, CAP_XFER_ONCE);
	(void)cap_cloexec_limit(dup_fd, CAP_CLOEXEC_LOCKED);
	(void)cap_clofork_limit(dup_fd, CAP_CLOFORK_LOCKED);
	return (dup_fd);
}

static int
ctl_send_fd_with_rights(struct blued_ctl_client *client, int fd_to_send,
    bool allow_reconfigure)
{
	int dup_fd;

	if (client == NULL) {
		errno = ENOTCONN;
		return (-1);
	}
	dup_fd = ctl_dup_capped_fd(fd_to_send, allow_reconfigure);
	if (dup_fd < 0)
		return (-1);

	if (ctl_queue_fd(client, dup_fd) < 0) {
		close(dup_fd);
		return (-1);
	}
	return (0);
}

int
ctl_send_fd_to_client(struct blued_ctl_client *client, int fd_to_send)
{

	return (ctl_send_fd_with_rights(client, fd_to_send, false));
}

int
ctl_send_ecbfc_fd_to_client(struct blued_ctl_client *client, int fd_to_send)
{

	/* libble's public ECBFC reconfiguration API needs this one right only. */
	return (ctl_send_fd_with_rights(client, fd_to_send, true));
}

/*
 * Encode a security event body (finding 28).  Wire layout (server->client):
 *   [event_code u16 LE][adapter_index u8][addr_type u8][addr[6]][payload...]
 * addr_type is the IPC-domain encoding (0 public / 1 random); adapter_index
 * identifies the controller.  Both let the client echo the exact
 * (adapter, addr, addr_type) tuple back in a passkey/numcmp reply so a
 * random-address peer under LE privacy can be answered.
 */
static void
ctl_send_security_event(struct blued_ctl_client *client, uint16_t event,
    uint8_t adapter_index, uint8_t addr_type_ipc, const bdaddr_t *addr,
    uint32_t value)
{
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_SECURITY_PASSKEY_EVENT_SIZE];
	uint8_t *body = payload + IPC_OP_PREFIX_SIZE;
	size_t payload_len;

	memset(payload, 0, sizeof(payload));
	ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
	ipc_put_le16(body, event);
	body[2] = adapter_index;
	body[3] = addr_type_ipc;
	memcpy(body + 4, addr, sizeof(*addr));
	if (event == IPC_SECURITY_EV_PASSKEY_INPUT)
		payload_len = IPC_OP_PREFIX_SIZE + IPC_SECURITY_INPUT_EVENT_SIZE;
	else if (event == IPC_SECURITY_EV_KEYPRESS) {
		body[10] = (uint8_t)value;
		payload_len = IPC_OP_PREFIX_SIZE + IPC_SECURITY_KEYPRESS_EVENT_SIZE;
	} else {
		ipc_put_le32(body + 10, value);
		payload_len = IPC_OP_PREFIX_SIZE + IPC_SECURITY_PASSKEY_EVENT_SIZE;
	}
	ctl_send_frame(client, IPC_T_OP_EVENT, IPC_OP_DOMAIN_SECURITY, payload,
	    payload_len);
}

static void
ctl_broadcast_security_event(uint16_t event, const bdaddr_t *addr,
    uint32_t value)
{
	struct blued_ctl_client *client;
	int agent_fd;
	uint8_t adapter_index = 0, addr_type_internal = BDADDR_LE_PUBLIC;
	uint8_t addr_type_ipc = 0;

	/*
	 * Recover the adapter and LE address type of the live connection this
	 * pairing prompt is for.  Derived before taking ctl_clients_lock to
	 * avoid nesting it under conns_lock.  A missing connection (non-daemon
	 * fallback, or a null peer) leaves the public/adapter-0 defaults.
	 */
	if (blued_conn_addr_context(addr, &adapter_index, &addr_type_internal))
		(void)ctl_addr_type_to_ipc(addr_type_internal, &addr_type_ipc);

	agent_fd = atomic_load(&ctl_agent_fd);
	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	if (agent_fd >= 0) {
		LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
			if (client->fd == agent_fd && client->wants_events) {
				ctl_send_security_event(client, event,
				    adapter_index, addr_type_ipc, addr, value);
				pthread_mutex_unlock(&blued_g.ctl_clients_lock);
				return;
			}
		}
	}
	LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
		if (client->wants_events && client->peer_known &&
		    client->peer_uid == 0)
			ctl_send_security_event(client, event, adapter_index,
			    addr_type_ipc, addr, value);
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

void
blued_ctl_passkey_display(const bdaddr_t *addr, uint32_t passkey)
{
	ctl_broadcast_security_event(IPC_SECURITY_EV_PASSKEY_DISPLAY, addr,
	    passkey);
}

void
blued_ctl_passkey_input(const bdaddr_t *addr)
{
	ctl_broadcast_security_event(IPC_SECURITY_EV_PASSKEY_INPUT, addr, 0);
}

void
blued_ctl_numcmp_request(const bdaddr_t *addr, uint32_t value)
{
	ctl_broadcast_security_event(IPC_SECURITY_EV_NUMCMP, addr, value);
}

void
blued_ctl_keypress(const bdaddr_t *addr, uint8_t type)
{
	ctl_broadcast_security_event(IPC_SECURITY_EV_KEYPRESS, addr, type);
}

/*
 * Send a file descriptor to a control client via SCM_RIGHTS.
 * The fd is dup'd and capability-limited before sending.
 */
void
blued_ctl_send_fd(int client_fd, uint64_t client_gen, int fd_to_send)
{
	struct blued_ctl_client *client;

	/*
	 * Finding 87: this runs on the main thread from iso_on_cis_established,
	 * which does not hold ctl_clients_lock, yet it mutates a client's txq
	 * (STAILQ_INSERT_TAIL + flush inside ctl_send_fd_to_client).  A GATT
	 * worker may be appending frames to the same client's txq under the
	 * lock at the same moment (ctl_gatt_job_send / blued_ctl_notify_value),
	 * so this writer must take the lock too or the STAILQ corrupts.
	 * (Recursive: harmless if a caller already holds it.)
	 */
	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	client = NULL;
	LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
		/*
		 * C3-M9: match BOTH fd and generation.  Matching the raw fd
		 * alone would deliver the descriptor to whatever client now
		 * holds that fd number if the original requester disconnected
		 * and its fd was reassigned.  A zero generation from a caller
		 * that has no generation to assert never matches a live client.
		 */
		if (client->fd == client_fd &&
		    client->generation == client_gen)
			break;
	}
	(void)ctl_send_fd_to_client(client, fd_to_send);
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

/*
 * Set ATT socket I/O timeouts for control socket commands.
 * Prevents a slow or unresponsive remote device from blocking
 * the main event loop indefinitely.  Returns the previous timeout
 * so the caller can restore it.
 */
/*
 * ATT I/O timeout for control socket commands (DISCOVER, READ, WRITE,
 * HOGP_READ, HOGP_WRITE).  These commands block the main event loop
 * while waiting for the BLE device to respond.  A malicious or slow
 * device can stall event processing for up to this duration.
 *
 * Kept short (2s) to minimize the DoS window.  A proper fix would
 * dispatch these to worker threads, but ATT is a sequential protocol
 * on a single socket: the kqueue event loop and a worker thread cannot
 * both recv() from the same fd without stealing each other's data.
 * Moving to async ATT would require splitting request/response I/O
 * from the notification path, which is a larger refactor.
 */
void
ctl_set_att_timeout(int att_fd, struct timeval *old_tv)
{
	struct timeval tv = { .tv_sec = CTL_ATT_TIMEOUT_SEC, .tv_usec = 0 };
	socklen_t len = sizeof(*old_tv);

	if (getsockopt(att_fd, SOL_SOCKET, SO_RCVTIMEO, old_tv, &len) < 0)
		memset(old_tv, 0, sizeof(*old_tv));
	(void)setsockopt(att_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(att_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

void
ctl_restore_att_timeout(int att_fd, const struct timeval *old_tv)
{

	(void)setsockopt(att_fd, SOL_SOCKET, SO_RCVTIMEO, old_tv,
	    sizeof(*old_tv));
	(void)setsockopt(att_fd, SOL_SOCKET, SO_SNDTIMEO, old_tv,
	    sizeof(*old_tv));
}











/*
 * Rate-limit blocking ATT commands (DISCOVER, READ, WRITE, HOGP_READ, HOGP_WRITE).
 * Allow at most 4 blocking commands per 10-second window per client.
 * Returns true if the command should be allowed, false if rate-limited.
 */
#define CTL_BLOCKING_LIMIT	4
#define CTL_BLOCKING_WINDOW	10

/*
 * Finding C-M1: the operator SCAN verb runs synchronously on the main event
 * loop and is exempt from the privilege gate on a 0660 socket, so any local
 * user could freeze the loop with repeated multi-second scans.  Wire up the
 * per-client blocking-command rate limiter (previously dead) to bound how
 * often a client can trigger such a blocking command.  Returns true when the
 * command is admitted, false when the client is over budget for the window.
 * Runs on the main thread (per-client counters need no lock).
 */
static bool
ctl_blocking_rate_ok(struct blued_ctl_client *client)
{
	/*
	 * C3-L: measure the window on CLOCK_MONOTONIC.  With wall-clock
	 * time(NULL) an NTP step (or manual clock set) backwards could park the
	 * window far in the future and suppress every SCAN, or a forward jump
	 * could reset the budget early — a monotonic source is immune.
	 */
	struct timespec ts;
	time_t now;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts.tv_sec;

	if (client == NULL)
		return (true);
	if (client->blocking_window == 0 ||
	    now - client->blocking_window >= CTL_BLOCKING_WINDOW) {
		client->blocking_window = now;
		client->blocking_count = 0;
	}
	if (client->blocking_count >= CTL_BLOCKING_LIMIT)
		return (false);
	client->blocking_count++;
	return (true);
}






/* Route a value to any AcquireNotify fd for (addr, handle); defined below. */
static void ctl_acquire_route_notify(const struct blued_conn *conn,
	    uint16_t handle, const uint8_t *value, uint16_t len);

/*
 * Send a notification event to all subscribed ctl clients.
 * Called from blued.c when an ATT notification/indication arrives
 * on a central connection.
 */
void
blued_ctl_notify_value(struct blued_conn *conn, uint16_t handle,
    const uint8_t *value, uint16_t len, uint16_t bearer_mtu)
{
	struct blued_ctl_client *client;
	const bdaddr_t any = { { 0, 0, 0, 0, 0, 0 } };
	const bdaddr_t *addr;

	if (conn == NULL || conn->adapter == NULL ||
	    (len != 0 && value == NULL) || bearer_mtu < ATT_DEFAULT_MTU ||
	    len > (uint16_t)(bearer_mtu - 3) ||
	    len > IPC_MAX_PAYLOAD - IPC_OP_PREFIX_SIZE -
	    IPC_GATT_NOTIFY_EVENT_SIZE)
		return;
	addr = &conn->dst;

	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
		int j;

		for (j = 0; j < client->nsubs; j++) {
			bool is_wild = memcmp(&client->subs[j].addr, &any,
			    sizeof(any)) == 0;

			/*
			 * A wildcard subscription (all-zero address) matches any
			 * connection; when it also carries handle 0 it is a
			 * "monitor all connections" registration and matches any
			 * notification handle (finding 31).  A wildcard with a
			 * concrete handle still matches only that handle.
			 */
			if ((is_wild ||
			    memcmp(&client->subs[j].addr, addr,
			    sizeof(*addr)) == 0) &&
			    (client->subs[j].handle == handle ||
			    (is_wild && client->subs[j].handle == 0)) &&
			    (is_wild ||
			    (client->subs[j].addr_type == conn->addr_type &&
			    client->subs[j].adapter_index == conn->adapter->index))) {
				if (client->wants_events) {
					uint8_t *evt, *body;
					size_t evtlen;

					evtlen = IPC_OP_PREFIX_SIZE +
					    IPC_GATT_NOTIFY_EVENT_SIZE + len;
					evt = malloc(evtlen);
					if (evt == NULL)
						break;
					body = evt + IPC_OP_PREFIX_SIZE;

					ipc_op_prefix_encode(evt, 0, IPC_ERR_NONE, 0);
					ipc_put_le16(body, IPC_GATT_EV_NOTIFY);
					(void)ctl_addr_type_to_ipc(conn->addr_type,
					    &body[2]);
					memcpy(body + 3, addr, sizeof(*addr));
					ipc_put_le16(body + 9, handle);
					ipc_put_le16(body + 11, len);
					body[13] = (uint8_t)conn->adapter->index;
					ipc_put_le16(body + 14, bearer_mtu);
					if (len != 0)
						memcpy(body + IPC_GATT_NOTIFY_EVENT_SIZE,
						    value, len);
					ctl_send_frame(client, IPC_T_OP_EVENT,
					    IPC_OP_DOMAIN_GATT, evt,
					    evtlen);
					free(evt);
				}
				break;
			}
		}
	}
	/*
	 * AcquireNotify data path: deliver the raw value to any acquired fd for
	 * this (peer, characteristic) as one datagram, in addition to the EVENT
	 * NOTIFY push above.  Main-thread-only registry, same as this routine.
	 */
	ctl_acquire_route_notify(conn, handle, value, len);
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

/*
 * Send a write event to the ctl client that owns an attribute.
 * Called from att_server.c handle_write when owner_fd >= 0.
 */
void
blued_ctl_notify_write(int owner_fd, uint16_t handle,
    const uint8_t *value, uint16_t len)
{
	struct blued_ctl_client *client;

	if ((len != 0 && value == NULL) || len > ATT_PDU_BUF_SIZE)
		return;

	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
		if (client->fd == owner_fd)
			break;
	}
	/*
	 * Deliver only to a known client that opted into push-events; an owner
	 * fd with no client record has nothing to frame to.
	 */
	if (client != NULL) {
		if (client->wants_events) {
			uint8_t payload[IPC_OP_PREFIX_SIZE +
			    IPC_GATT_VALUE_EVENT_SIZE + ATT_PDU_BUF_SIZE];
			uint8_t *body = payload + IPC_OP_PREFIX_SIZE;

			ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
			ipc_put_le16(body, IPC_GATT_EV_WRITE);
			ipc_put_le16(body + 2, handle);
			ipc_put_le16(body + 4, len);
			if (len != 0)
				memcpy(body + IPC_GATT_VALUE_EVENT_SIZE, value, len);
			ctl_send_frame(client, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT,
			    payload, IPC_OP_PREFIX_SIZE + IPC_GATT_VALUE_EVENT_SIZE +
			    len);
		}
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

/*
 * Ask the owning app to supply a dynamic characteristic's value for a peer
 * read (EVENT READ <handle> <offset>).  Called from the ATT server when a
 * dynamic read is deferred; the app answers with READ_REPLY / READ_REJECT.
 */
void
blued_ctl_notify_read(int owner_fd, uint16_t handle, uint16_t offset)
{
	struct blued_ctl_client *client;

	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
		if (client->fd == owner_fd)
			break;
	}
	if (client != NULL) {
		if (client->wants_events) {
			uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_GATT_READ_EVENT_SIZE];
			uint8_t *body = payload + IPC_OP_PREFIX_SIZE;

			ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
			ipc_put_le16(body, IPC_GATT_EV_READ);
			ipc_put_le16(body + 2, handle);
			ipc_put_le16(body + 4, offset);
			ctl_send_frame(client, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT,
			    payload, sizeof(payload));
		}
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

/*
 * Ask the owning app to authorize a peer's read/write of an authorize-gated
 * characteristic (EVENT AUTHORIZE <handle> <read|write> <addr>).  The peer
 * address is resolved from the connection that owns the ATT bearer; the app
 * answers with AUTHORIZE_REPLY.
 */
void
blued_ctl_notify_authorize(int owner_fd, uint16_t handle, bool is_write,
    const struct att_conn *ac)
{
	struct blued_ctl_client *client;
	struct blued_conn *conn;
	bdaddr_t peer = { { 0, 0, 0, 0, 0, 0 } };
	uint8_t addr_type = 0;

	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (conn->att == ac) {
			peer = conn->dst;
			(void)ctl_addr_type_to_ipc(conn->addr_type, &addr_type);
			break;
		}
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);

	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
		if (client->fd == owner_fd)
			break;
	}
	if (client != NULL) {
		if (client->wants_events) {
			uint8_t payload[IPC_OP_PREFIX_SIZE +
			    IPC_GATT_AUTHORIZE_EVENT_SIZE];
			uint8_t *body = payload + IPC_OP_PREFIX_SIZE;

			ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
			ipc_put_le16(body, IPC_GATT_EV_AUTHORIZE);
			body[2] = addr_type;
			memcpy(body + 3, &peer, sizeof(peer));
			ipc_put_le16(body + 9, handle);
			body[11] = is_write ? 1 : 0;
			ctl_send_frame(client, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT,
			    payload, sizeof(payload));
		}
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

/* Broadcast a connection-lifecycle event to every event subscriber. */
void
blued_ctl_broadcast_conn_event(const bdaddr_t *addr, int role,
    uint8_t addr_type, uint8_t adapter_index, uint16_t handle, uint16_t mtu,
    bool up, uint8_t reason)
{
	struct blued_ctl_client *client;
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_GAP_CONNECTED_EVENT_SIZE];
	size_t payload_len;

	ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE,
	    up ? IPC_GAP_EV_CONNECTED : IPC_GAP_EV_DISCONNECTED);
	if (!ctl_addr_type_to_ipc(addr_type,
	    &payload[IPC_OP_PREFIX_SIZE + 2]))
		return;
	memcpy(payload + IPC_OP_PREFIX_SIZE + 3, addr, 6);
	if (up) {
		payload[IPC_OP_PREFIX_SIZE + 9] =
		    role == BLUED_ROLE_PERIPHERAL ? 1 : 0;
		ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 10, handle);
		ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 12, mtu);
		payload[IPC_OP_PREFIX_SIZE + 14] = adapter_index;
		payload_len = IPC_OP_PREFIX_SIZE + IPC_GAP_CONNECTED_EVENT_SIZE;
	} else {
		ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 9, reason);
		payload[IPC_OP_PREFIX_SIZE + 11] = adapter_index;
		payload_len = IPC_OP_PREFIX_SIZE + IPC_GAP_DISCONNECTED_EVENT_SIZE;
	}

	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
		if (client->wants_events)
			ctl_send_frame(client, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP,
			    payload, payload_len);
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

static void
ctl_broadcast_iso_event(struct blued_adapter *adp, uint16_t event,
    const bdaddr_t *addr,
    uint8_t addr_type, uint16_t cis_handle, uint8_t cig_id, uint8_t cis_id,
    uint16_t mtu)
{
	struct blued_ctl_client *client;
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_ISO_EVENT_SIZE];
	uint8_t *body = payload + IPC_OP_PREFIX_SIZE;

	memset(payload, 0, sizeof(payload));
	ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
	ipc_put_le16(body, event);
	if (!ctl_addr_type_to_ipc(addr_type, &body[2]))
		return;
	memcpy(body + 3, addr, sizeof(*addr));
	ipc_put_le16(body + 9, cis_handle);
	if (event == IPC_ISO_EV_CIS_REQUEST) {
		body[11] = cig_id;
		body[12] = cis_id;
	} else
		ipc_put_le16(body + 11, mtu);
	body[13] = (uint8_t)adp->index;
	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
		if (client->wants_events)
			ctl_send_frame(client, IPC_T_OP_EVENT, IPC_OP_DOMAIN_ISO,
			    payload, sizeof(payload));
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

void
blued_ctl_iso_cis_request(struct blued_adapter *adp, const bdaddr_t *addr,
    uint8_t addr_type,
    uint16_t cis_handle, uint8_t cig_id, uint8_t cis_id)
{
	ctl_broadcast_iso_event(adp, IPC_ISO_EV_CIS_REQUEST, addr, addr_type,
	    cis_handle, cig_id, cis_id, 0);
}

void
blued_ctl_iso_established(struct blued_adapter *adp, const bdaddr_t *addr,
    uint8_t addr_type,
    uint16_t cis_handle, uint16_t mtu)
{
	ctl_broadcast_iso_event(adp, IPC_ISO_EV_ESTABLISHED, addr, addr_type,
	    cis_handle, 0, 0, mtu);
}

/*
 * Finding 116: report a CIS establishment failure so a client that issued
 * ISO_CIS_CREATE (or subscribed to establishment) stops waiting.  The failure
 * status is carried in the event's u16 field in place of the MTU.
 */
void
blued_ctl_iso_failed(struct blued_adapter *adp, const bdaddr_t *addr,
    uint8_t addr_type, uint16_t cis_handle, uint8_t status)
{
	ctl_broadcast_iso_event(adp, IPC_ISO_EV_FAILED, addr, addr_type,
	    cis_handle, 0, 0, status);
}

/* ================================================================
 * Mesh bearer (broker step C).
 *
 * blued is a DUMB mesh pipe: it validates the AD type and moves bytes; it
 * NEVER parses mesh PDU internals (all mesh crypto/relay stays in the mesh
 * daemon).  This block implements the three privileged operations (subscribe /
 * unsubscribe / send), the mesh-subscriber-only push path, the receive-side
 * AD-type demux (the leak filter), and the always-on-scanner refcount.  See
 * ipc_proto.h for the frozen wire contract.
 * ================================================================ */

/*
 * Number of live MESH_ADV subscribers.  Mutated only on the main event-loop
 * thread (operation dispatch and client-disconnect cleanup), so a plain int with
 * no extra lock is race-free.  Drives the always-on mesh scanner: 0->1 turns
 * the passive scan on across all adapters, 1->0 turns it off.
 */
static int mesh_subscribers;

/* Apply (enable/disable) the always-on mesh passive scan on every adapter. */
static int
mesh_scan_apply(bool on)
{
	struct blued_adapter *adp;
	int error;

	error = 0;
	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (!adp->active)
			continue;
		if (adp->mesh_scan_active == on)
			continue;
		if (hci_le_mesh_scan_set(adp->hci_fd, adp->le_features, on) == 0)
			adp->mesh_scan_active = on;
		else
			error = -1;
	}
	return (error);
}

/* First subscriber turns the mesh scanner on. */
static int
mesh_scan_ref(void)
{

	if (mesh_subscribers == 0 && mesh_scan_apply(true) < 0) {
		(void)mesh_scan_apply(false);
		return (-1);
	}
	mesh_subscribers++;
	return (0);
}

/* Last subscriber turns the mesh scanner off. */
static void
mesh_scan_unref(void)
{

	if (mesh_subscribers > 0 && --mesh_subscribers == 0)
		mesh_scan_apply(false);
}

/*
 * Re-assert the mesh scanner after an unrelated client SCAN burst reprogrammed
 * and disabled the controller scanner.  The per-adapter
 * mesh_scan_active flag is still set from the subscription, but the controller
 * scan was turned off by the burst, so re-enable it unconditionally here.
 */
/*
 * Re-assert the mesh scanner after a controller reset / power cycle cleared
 * adp->mesh_scan_active while the host still has subscribers.  Unlike
 * blued_mesh_scan_resume(), this does NOT require the per-adapter flag to be
 * set -- mesh_scan_apply() enables adapters whose flag is currently false and
 * re-sets it.
 */
void
blued_mesh_scan_reassert(void)
{

	if (mesh_subscribers > 0)
		(void)mesh_scan_apply(true);
}

void
blued_mesh_scan_resume(void)
{
	struct blued_adapter *adp;

	if (mesh_subscribers == 0)
		return;
	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (!adp->active || !adp->mesh_scan_active)
			continue;
		(void)hci_le_mesh_scan_set(adp->hci_fd, adp->le_features, true);
	}
}

/*
 * Deliver EVENT MESH_ADV <adtype> <pdu-hex> to mesh subscribers only.  A
 * client that is not a mesh subscriber receives nothing, so its request/
 * response stream never desyncs.  Runs under ctl_clients_lock (safe against
 * concurrent accept/close); called from the RX demux on the main thread.
 */
void
blued_ctl_broadcast_mesh_adv(uint8_t adtype, const uint8_t *pdu, size_t len)
{
	struct blued_ctl_client *client;
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_MESH_ADV_EVENT_HDR_SIZE +
	    MESH_ADV_PDU_MAX];
	uint8_t *body = payload + IPC_OP_PREFIX_SIZE;

	if (len > MESH_ADV_PDU_MAX)
		return;
	ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
	ipc_put_le16(body, IPC_MESH_EV_ADV);
	body[2] = adtype;
	body[3] = (uint8_t)len;
	memcpy(body + IPC_MESH_ADV_EVENT_HDR_SIZE, pdu, len);

	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
		if (client->mesh_sub)
			ctl_send_frame(client, IPC_T_OP_EVENT, IPC_OP_DOMAIN_MESH,
			    payload, IPC_OP_PREFIX_SIZE +
			    IPC_MESH_ADV_EVENT_HDR_SIZE + len);
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

/*
 * Receive-side leak filter: walk the AD structures of a received advertising
 * report and forward ONLY mesh AD fields (0x29/0x2A/0x2B) as EVENT MESH_ADV;
 * every other AD structure (device name, flags, manufacturer data, ...) is
 * dropped and never reaches any client.  A malformed AD length terminates the
 * walk without over-reading.  Core Spec CSS Part A §1: AD = [len][type][data],
 * len covers type+data.
 */
void
blued_mesh_demux_report(const uint8_t *ad, size_t adlen)
{
	size_t i = 0;

	if (ad == NULL)
		return;
	while (i < adlen) {
		uint8_t fieldlen = ad[i];
		uint8_t adtype;

		if (fieldlen == 0)
			break;			/* end of AD data / padding */
		if (i + 1 + (size_t)fieldlen > adlen)
			break;			/* truncated field: stop, no over-read */
		adtype = ad[i + 1];
		if (blued_mesh_adtype_valid(adtype))
			blued_ctl_broadcast_mesh_adv(adtype, &ad[i + 2],
			    (size_t)fieldlen - 1);
		i += 1 + (size_t)fieldlen;
	}
}

/*
 * Bounded burst FIFO for outbound mesh adv PDUs (broker step C §1.4).  A mesh
 * flooding bearer emits many small PDUs; the FIFO bounds how many may be
 * pending so a burst can never overrun memory.  Each MESH_ADV_SEND enqueues a
 * fully-framed AD structure; mesh_adv_drain() transmits in order.  On a
 * controller error the drain stops and leaves the backlog queued (a later
 * send retries it); when the FIFO is full, MESH_ADV_SEND returns IPC_ERR_BUSY
 * and the mesh daemon drops the PDU (spec-legal for the adv bearer).
 */
#define MESH_ADV_QUEUE_DEPTH	16
#define MESH_ADV_AD_MAX		31	/* one legacy AD structure */

struct mesh_adv_frame {
	struct blued_adapter	*adp;
	uint8_t			ad[MESH_ADV_AD_MAX];
	uint8_t			adlen;
};

static struct mesh_adv_frame	mesh_adv_q[MESH_ADV_QUEUE_DEPTH];
static int			mesh_adv_q_head;
static int			mesh_adv_q_count;
/*
 * The adapter whose extended-adv mesh PDU is currently on air with a bounded
 * copy count while we wait for its Advertising Set Terminated before airing the
 * next queued PDU (NULL when idle).  Without this one-at-a-time pacing a
 * back-to-back burst of distinct PDUs would reprogram the single mesh adv set
 * before any but the last aired (breaking PB-ADV segmentation and relay bursts).
 *
 * This is scoped to the owning adapter -- not a process-global flag -- because
 * Advertising Set Terminated events are delivered per adapter: with two or more
 * extended-advertising adapters running mesh, a Terminated event on a NON-owning
 * adapter must not dequeue/re-air the frame belonging to the owner.
 */
static struct blued_adapter	*mesh_adv_inflight_adp;

/* Enqueue a framed AD; returns -1 if the FIFO is full. */
static int
mesh_adv_enqueue(struct blued_adapter *adp, const uint8_t *ad, uint8_t adlen)
{
	int slot;

	if (mesh_adv_q_count >= MESH_ADV_QUEUE_DEPTH)
		return (-1);
	slot = (mesh_adv_q_head + mesh_adv_q_count) % MESH_ADV_QUEUE_DEPTH;
	mesh_adv_q[slot].adp = adp;
	memcpy(mesh_adv_q[slot].ad, ad, adlen);
	mesh_adv_q[slot].adlen = adlen;
	mesh_adv_q_count++;
	return (0);
}

/*
 * Transmit queued mesh adv frames.  On an extended-advertising controller each
 * PDU is aired with a bounded copy count and we STOP after starting it, waiting
 * for its Advertising Set Terminated (blued_mesh_adv_set_terminated) before
 * airing the next -- so every queued PDU gets on-air time instead of being
 * clobbered by the next reprogram.  On a legacy controller there is no
 * per-set auto-terminate, so we advance synchronously as before.
 */
static void
mesh_adv_drain(void)
{
	while (mesh_adv_q_count > 0) {
		struct mesh_adv_frame *f = &mesh_adv_q[mesh_adv_q_head];
		bool ext = (f->adp->le_features & LE_FEAT_EXT_ADVERTISING) != 0;

		if (ext && mesh_adv_inflight_adp != NULL)
			return;		/* wait for the in-flight PDU to terminate */
		if (hci_mesh_adv_burst(f->adp->hci_fd, f->adp->le_features,
		    f->ad, f->adlen) < 0)
			break;		/* leave backlog queued; a later send retries */
		if (ext) {
			/* Aired with a bounded copy count; Advertising Set
			 * Terminated for this adapter will dequeue this frame
			 * and air the next. */
			mesh_adv_inflight_adp = f->adp;
			return;
		}
		mesh_adv_q_head = (mesh_adv_q_head + 1) % MESH_ADV_QUEUE_DEPTH;
		mesh_adv_q_count--;
	}
}

/*
 * Advertising Set Terminated fired on ADP for the mesh adv set: the in-flight
 * PDU finished its bounded airing.  Only act if ADP actually owns the in-flight
 * frame -- a Terminated on a different adapter must not dequeue/re-air this
 * adapter's frame (that would double-burst a live set and skip queued PDUs).
 * Dequeue the owner's frame and air the next queued PDU.
 */
static void
blued_mesh_adv_set_terminated(struct blued_adapter *adp)
{

	if (mesh_adv_inflight_adp == NULL || adp != mesh_adv_inflight_adp)
		return;
	mesh_adv_inflight_adp = NULL;
	if (mesh_adv_q_count > 0) {
		mesh_adv_q_head = (mesh_adv_q_head + 1) % MESH_ADV_QUEUE_DEPTH;
		mesh_adv_q_count--;
	}
	mesh_adv_drain();
}

/*
 * Recover the mesh adv FIFO after a controller reset / power cycle.  A reset
 * that lands while an extended-adv mesh PDU is in flight destroys the adv set,
 * so its Advertising Set Terminated event will never arrive and the in-flight
 * owner would stay stuck set -- wedging the drain (and thus all mesh TX)
 * forever.  Clear the in-flight owner and re-air any queued PDU on the fresh
 * controller.  This is the global recovery entry point (called from
 * blued_adapter_controller_invalidated() when a controller goes away).
 *
 * RESIDUAL: this function takes no adapter argument, so it cannot tell which
 * controller was invalidated.  If a second extended-adv adapter is invalidated
 * while THIS adapter legitimately has a frame in flight, clearing the owner and
 * re-draining can re-air that still-live adapter's head frame one burst early
 * (a harmless extra enable-burst / spurious Terminated -- the Terminated path
 * above is now scoped and absorbs the stray event).  Fully disambiguating would
 * require threading the invalidated adapter in from blued.c; deferred to keep
 * this change scoped to the ctl.c dequeue fix.
 */
void
blued_mesh_adv_reset(void)
{

	mesh_adv_inflight_adp = NULL;
	mesh_adv_drain();
}

static void
ctl_process_typed_mesh(struct blued_ctl_client *client, const uint8_t *payload,
    size_t plen)
{
	struct blued_adapter *adp = NULL;
	uint8_t ad[MESH_ADV_AD_MAX];
	uint16_t opcode;
	uint8_t adtype, adapter, pdulen;

	if (plen < IPC_MESH_REQ_SIZE) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_MESH, IPC_ERR_PROTO,
		    "mesh request too short");
		return;
	}
	opcode = ipc_get_le16(payload);
	if (!client->wants_mesh) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_MESH, IPC_ERR_PERM,
		    "mesh-bearer not negotiated");
		return;
	}
	if (!ctl_client_privileged(client)) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_MESH, IPC_ERR_PERM,
		    "mesh operation requires privilege");
		return;
	}
	if (opcode == IPC_MESH_SUBSCRIBE || opcode == IPC_MESH_UNSUBSCRIBE) {
		if (plen != IPC_MESH_REQ_SIZE) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_MESH, IPC_ERR_PROTO,
			    "invalid mesh subscription request");
			return;
		}
		if (opcode == IPC_MESH_SUBSCRIBE && !client->mesh_sub) {
			if (mesh_scan_ref() < 0) {
				ctl_send_op_error(client, IPC_OP_DOMAIN_MESH,
				    IPC_ERR_IO, "mesh scan enable failed");
				return;
			}
			client->mesh_sub = true;
		} else if (opcode == IPC_MESH_UNSUBSCRIBE && client->mesh_sub) {
			client->mesh_sub = false;
			mesh_scan_unref();
		}
		ctl_send_op_ack(client, IPC_OP_DOMAIN_MESH);
		return;
	}
	if (opcode != IPC_MESH_ADV_SEND || plen < IPC_MESH_ADV_REQ_HDR_SIZE) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_MESH, IPC_ERR_UNKNOWN_CMD,
		    "invalid mesh operation");
		return;
	}
	adtype = payload[2];
	adapter = payload[3];
	pdulen = payload[4];
	if (payload[5] != 0 || pdulen == 0 || pdulen > MESH_ADV_PDU_MAX ||
	    plen != IPC_MESH_ADV_REQ_HDR_SIZE + pdulen ||
	    !blued_mesh_adtype_valid(adtype)) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_MESH, IPC_ERR_INVAL,
		    "invalid mesh advertising request");
		return;
	}
	if (adapter == IPC_MESH_ADAPTER_DEFAULT) {
		LIST_FOREACH(adp, &blued_g.adapters, entries)
			if (adp->active)
				break;
	} else {
		LIST_FOREACH(adp, &blued_g.adapters, entries)
			if (adp->active && adp->index == adapter)
				break;
	}
	if (adp == NULL) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_MESH, IPC_ERR_NOT_FOUND,
		    "no active adapter");
		return;
	}
	ad[0] = (uint8_t)(pdulen + 1);
	ad[1] = adtype;
	memcpy(ad + 2, payload + IPC_MESH_ADV_REQ_HDR_SIZE, pdulen);
	mesh_adv_drain();
	if (mesh_adv_enqueue(adp, ad, (uint8_t)(pdulen + 2)) < 0) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_MESH, IPC_ERR_BUSY,
		    "mesh advertising queue full");
		return;
	}
	mesh_adv_drain();
	ctl_send_op_ack(client, IPC_OP_DOMAIN_MESH);
}




/*
 * Release a departing client's mesh subscription so an orphaned subscriber
 * can never leave the scanner stuck-on (implicit MESH_ADV_UNSUBSCRIBE on
 * disconnect).
 */
void
blued_ctl_client_mesh_gone(struct blued_ctl_client *client)
{

	if (client != NULL && client->mesh_sub) {
		client->mesh_sub = false;
		mesh_scan_unref();
	}
}











/*
 * OOB pairing-data store (deliverable: the OOB engine was wired but had zero
 * exposure).  Peer OOB data supplied by OOB_INJECT is held here keyed by peer
 * identity address and consumed by the central pairing setup (blued_oob_take),
 * mirroring NimBLE ble_sm_inject_io.  A single pending local SC-OOB random
 * (from OOB_GENERATE) is merged into whatever SC entry a pairing consumes.
 */
#define BLUED_OOB_MAX	8
struct blued_oob_pending {
	bdaddr_t	addr;
	bool		valid;
	bool		has_legacy;
	uint8_t		tk[16];
	bool		has_sc;
	uint8_t		sc_confirm[16];
	uint8_t		sc_random[16];
};
static struct blued_oob_pending blued_oob_tbl[BLUED_OOB_MAX];
static bool blued_oob_local_valid;
static uint8_t blued_oob_local_random[16];
static pthread_mutex_t blued_oob_lock = PTHREAD_MUTEX_INITIALIZER;

static struct blued_oob_pending *
blued_oob_find(const uint8_t *addr, bool alloc)
{
	int i, free_i = -1;

	for (i = 0; i < BLUED_OOB_MAX; i++) {
		if (blued_oob_tbl[i].valid &&
		    memcmp(&blued_oob_tbl[i].addr, addr, 6) == 0)
			return (&blued_oob_tbl[i]);
		if (!blued_oob_tbl[i].valid && free_i < 0)
			free_i = i;
	}
	if (alloc && free_i >= 0) {
		memset(&blued_oob_tbl[free_i], 0, sizeof(blued_oob_tbl[free_i]));
		memcpy(&blued_oob_tbl[free_i].addr, addr, 6);
		blued_oob_tbl[free_i].valid = true;
		return (&blued_oob_tbl[free_i]);
	}
	return (NULL);
}

/*
 * Consume the pending OOB data for a peer into caller-owned storage, filling
 * *lg / *scd and the has_* flags.  Clears the peer entry and any one-shot local
 * SC-OOB random (also detaching the SC-OOB ephemeral).  Returns true if any OOB
 * data was found.  Called from the pairing setup path just before smp_pair().
 */
bool
blued_oob_take(const uint8_t *addr, struct smp_oob_legacy *lg, bool *has_lg,
    struct smp_oob_sc *scd, bool *has_sc)
{
	struct blued_oob_pending *e;
	bool found = false;

	*has_lg = false;
	*has_sc = false;
	memset(scd, 0, sizeof(*scd));
	pthread_mutex_lock(&blued_oob_lock);
	e = blued_oob_find(addr, false);
	if (e != NULL) {
		if (e->has_legacy) {
			memcpy(lg->tk, e->tk, 16);
			*has_lg = true;
			found = true;
		}
		if (e->has_sc) {
			/* We received the peer's OOB {confirm,random}. */
			memcpy(scd->confirm, e->sc_confirm, 16);
			memcpy(scd->random, e->sc_random, 16);
			scd->have_peer = true;
		}
		e->valid = false;
	}
	/*
	 * Local OOB is independent of whether we received the peer's OOB
	 * (Core Vol 3 Part H Table 2.7 allows one-sided OOB in either
	 * direction).  Populate local_random whenever we generated/shared it,
	 * even with no peer entry, so the DHKey check can supply our ra/rb when
	 * the peer's OOB flag says the peer used it.
	 */
	if (blued_oob_local_valid) {
		memcpy(scd->local_random, blued_oob_local_random, 16);
		scd->have_local = true;
	}
	/* SC OOB is in play if we have peer OOB and/or local OOB. */
	if (scd->have_peer || scd->have_local) {
		*has_sc = true;
		found = true;
	}
	if (*has_sc && blued_oob_local_valid) {
		/*
		 * C1-H2: consume the published one-shot local OOB random here,
		 * but do NOT clear the SC-OOB ephemeral yet.  smp_pair_sc()
		 * calls smp_sc_gen_ephemeral() AFTER this take; clearing the
		 * ephemeral now (NULLing the hook) would make it mint a fresh
		 * random keypair, so the wire PKa would no longer match the pkx
		 * that was published to the peer over OOB — the peer's
		 * Ca = f4(PKax,PKax,ra,0) check then fails and every SC-OOB
		 * pairing is rejected with Confirm Value Failed.  The ephemeral
		 * is cleared post-pairing instead (blued_central_start_pairing).
		 */
		blued_oob_local_valid = false;
		explicit_bzero(blued_oob_local_random,
		    sizeof(blued_oob_local_random));
	}
	pthread_mutex_unlock(&blued_oob_lock);
	return (found);
}







#define CTL_ADV_SET_MAX 16
struct ctl_adv_set {
	bool used, configured, enabled;
	uint8_t handle;
	int owner_fd;
	struct blued_adapter *adapter;
};
static struct ctl_adv_set ctl_adv_sets[CTL_ADV_SET_MAX];

static struct ctl_adv_set *
ctl_adv_set_owned(int client_fd, unsigned handle)
{
	int i;

	for (i = 0; i < CTL_ADV_SET_MAX; i++)
		if (ctl_adv_sets[i].used && ctl_adv_sets[i].handle == handle &&
		    ctl_adv_sets[i].owner_fd == client_fd)
			return (&ctl_adv_sets[i]);
	return (NULL);
}





static void
ctl_adv_set_release(struct ctl_adv_set *set)
{

	if (set->configured) {
		if (set->enabled)
			(void)hci_le_set_ext_adv_enable(set->adapter->hci_fd, 0,
			    set->handle);
		(void)hci_le_remove_adv_set(set->adapter->hci_fd, set->handle);
	}
	if (set->adapter != NULL)
		blued_ext_adv_set_untrack(set->adapter, set->handle);
	memset(set, 0, sizeof(*set));
}

/*
 * C3-L: the controller stopped an advertising set (LE Advertising Set
 * Terminated, subevent 0x12).  Clear the ctl-registry `enabled` flag for the
 * matching adapter+handle so the operator adv-set view (and any re-enable
 * bookkeeping) does not keep believing a controller-stopped set is still
 * advertising.  Runs on the main event-loop thread, same as the ctl verbs, so
 * ctl_adv_sets needs no additional lock.
 */
void
blued_ctl_adv_set_terminated(struct blued_adapter *adp, uint8_t handle)
{

	if (adp == NULL)
		return;
	if (handle == MESH_ADV_HANDLE) {
		/* Pace the mesh adv FIFO: air the next queued PDU. */
		blued_mesh_adv_set_terminated(adp);
		return;
	}
	for (size_t i = 0; i < nitems(ctl_adv_sets); i++)
		if (ctl_adv_sets[i].used && ctl_adv_sets[i].adapter == adp &&
		    ctl_adv_sets[i].handle == handle)
			ctl_adv_sets[i].enabled = false;
}

/* HCI Reset removes every controller advertising set and its payloads. */
void
blued_ctl_adapter_reset(struct blued_adapter *adp)
{

	if (adp == NULL)
		return;
	for (size_t i = 0; i < nitems(ctl_adv_sets); i++)
		if (ctl_adv_sets[i].used && ctl_adv_sets[i].adapter == adp)
			memset(&ctl_adv_sets[i], 0, sizeof(ctl_adv_sets[i]));
}



















/*
 * Program an assembled AD payload into the addressed adapter, choosing the
 * extended vs legacy Set (Scan Response|Advertising) Data command against the
 * controller's LE_FEAT_EXT_ADVERTISING (Core Spec Vol 4 Part E §7.8.7 legacy /
 * §7.8.54 extended).  Returns 0 on success, -1 on controller error.
 */
static int
ctl_adv_program(struct blued_adapter *adp, bool scan_rsp, const uint8_t *data,
    uint8_t len)
{
	int error;

	if (adp->disc_saved_valid) {
		blued_primary_adv_cache(adp, scan_rsp, data, len);
		return (0);
	}

	if (adp->adv_configured ? adp->adv_use_extended :
	    (adp->le_features & LE_FEAT_EXT_ADVERTISING) != 0) {
		if (scan_rsp)
			error = hci_le_set_ext_scan_response_data(adp->hci_fd,
			    0x00, data, len);
		else
			error = hci_le_set_ext_adv_data(adp->hci_fd, 0x00, data, len);
	} else if (scan_rsp) {
		error = hci_le_set_scan_response_data(adp->hci_fd, data, len);
	} else {
		error = hci_le_set_advertising_data(adp->hci_fd, data, len);
	}
	if (error == 0)
		blued_primary_adv_cache(adp, scan_rsp, data, len);
	return (error);
}






















/*
 * Per-characteristic data-path acquire (the common GATT-characteristic
 * AcquireNotify / AcquireWrite pattern; Core Spec Vol 3 Part G notify/write).  These operations hand a
 * privileged fd-passing client one end of a SEQPACKET socketpair and keep the
 * other in the daemon: a NOTIFY acquire copies each notification/indication
 * value for the characteristic to the client as one datagram; a WRITE acquire
 * turns each datagram the client sends into an ATT Write-Without-Response PDU
 * to the characteristic.  The daemon end is pumped by the main kqueue loop, so
 * a high-rate GATT data path bypasses the per-notification IPC event stream.
 *
 * Locking (finding 58): the registry (blued_g.ctl_acquires) is NOT main-thread
 * only — ctl_acquire_route_notify() iterates it and send()s from
 * blued_ctl_notify_value(), which a GATT worker thread reaches via
 * hogp_unsolicited() when a notification arrives mid-operation.  The registry is
 * therefore serialised by ctl_clients_lock: every list mutation (insert /
 * teardown) and every traversal (route_notify, find, the fd pump, conn_gone,
 * client_gone) runs with that lock held.  ctl_clients_lock is a recursive mutex
 * (see blued_ctl_clients_lock_init), so a helper may take it even when a caller
 * on the same thread already holds it across dispatch.
 */

/* Registry lookup for the single acquire on a (peer, characteristic, dir). */
static struct ctl_acquire *
ctl_acquire_find(uint8_t adapter_index, const bdaddr_t *addr,
    uint8_t addr_type, uint16_t handle, uint8_t dir)
{
	struct ctl_acquire *acq;

	LIST_FOREACH(acq, &blued_g.ctl_acquires, entries) {
		if (acq->dir == dir && acq->handle == handle &&
		    acq->adapter_index == adapter_index &&
		    acq->addr_type == addr_type &&
		    memcmp(&acq->addr, addr, sizeof(*addr)) == 0)
			return (acq);
	}
	return (NULL);
}

/*
 * Tear one acquire down on every path (unsubscribe/close, peer disconnect,
 * client close): deregister the daemon fd from kqueue, close it, unlink from
 * the registry and free.  Idempotent per record; leaves the client's own fd
 * (already capability-scoped and owned outright) untouched.
 */
static void
ctl_acquire_teardown(struct ctl_acquire *acq)
{
	struct kevent kev;

	if (acq->daemon_fd >= 0) {
		EV_SET(&kev, acq->daemon_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
		close(acq->daemon_fd);
		acq->daemon_fd = -1;
	}
	LIST_REMOVE(acq, entries);
	free(acq);
}

/*
 * Create the socketpair, hand one capability-scoped end to the client and keep
 * the non-blocking daemon end registered in the kqueue loop.  On any failure
 * the caller's correlated error reply has already been (or must be) emitted; this
 * returns 0 on success, -1 otherwise.
 */
static int
ctl_acquire_create(struct blued_ctl_client *client, const bdaddr_t *addr,
    uint8_t adapter_index, uint8_t addr_type, uint16_t handle, uint8_t dir,
    uint16_t mtu, uint16_t typed_opcode)
{
	struct ctl_acquire *acq;
	struct kevent kev;
	int sv[2];
	size_t handout_len;

	handout_len = IPC_HDR_SIZE + IPC_OP_PREFIX_SIZE +
	    IPC_GATT_ACQUIRE_REPLY_SIZE + 1;
	if (!ctl_tx_has_room(client, handout_len)) {
		errno = ENOBUFS;
		return (-1);
	}

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) {
		return (-1);
	}

	acq = calloc(1, sizeof(*acq));
	if (acq == NULL) {
		close(sv[0]);
		close(sv[1]);
		return (-1);
	}

	/*
	 * The daemon end is non-blocking so notification routing and the write
	 * pump never stall the single-threaded event loop; a slow client that
	 * stops draining causes bounded drops (EAGAIN), not head-of-line block.
	 */
	(void)fcntl(sv[0], F_SETFL, O_NONBLOCK);

	memcpy(&acq->addr, addr, sizeof(*addr));
	acq->adapter_index = adapter_index;
	acq->addr_type = addr_type;
	acq->handle = handle;
	acq->dir = dir;
	acq->mtu = mtu;
	acq->daemon_fd = sv[0];
	acq->client = client;

	EV_SET(&kev, sv[0], EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0,
	    BLUED_KQ_ACQUIRE);
	if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0) {
		close(sv[0]);
		close(sv[1]);
		free(acq);
		return (-1);
	}
	LIST_INSERT_HEAD(&blued_g.ctl_acquires, acq, entries);

	/*
	 * Header line carries the negotiated MTU (the common AcquireNotify/AcquireWrite
	 * return fd + MTU), then the SCM_RIGHTS handout, then END.  send_fd dup'd
	 * and capability-limited its own copy, so the daemon drops the original
	 * client end and never touches the data path from that descriptor again.
	 */
	{
		uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_GATT_ACQUIRE_REPLY_SIZE];
		int dup_fd;

		/*
		 * Finding 121: do the fallible descriptor dup/capability-limit
		 * BEFORE sending the success OP_REPLY.  Previously the reply was
		 * sent first and a failed SCM_RIGHTS handout then returned -1,
		 * which the dispatcher turned into a SECOND (error) reply for
		 * the same request id — the client saw success-then-error and
		 * never got the promised fd.  Now a dup failure is reported as
		 * the single OP_ERROR (no reply sent yet); txq room for both
		 * frames was reserved above, so the ordered reply+fd queueing
		 * below cannot fail for space.
		 */
		dup_fd = ctl_dup_capped_fd(sv[1], false);
		if (dup_fd < 0) {
			ctl_acquire_teardown(acq);
			close(sv[1]);
			return (-1);
		}
		ipc_op_prefix_encode(reply, client->active_request_id,
		    IPC_ERR_NONE, 0);
		ipc_put_le16(reply + IPC_OP_PREFIX_SIZE, typed_opcode);
		ipc_put_le16(reply + IPC_OP_PREFIX_SIZE + 2, mtu);
		if (ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT,
		    reply, sizeof(reply)) < 0) {
			close(dup_fd);
			ctl_acquire_teardown(acq);
			close(sv[1]);
			return (-1);
		}
		if (ctl_queue_fd(client, dup_fd) < 0) {
			/*
			 * Success reply already delivered; do NOT emit a
			 * contradictory second reply.  Drop the fd and shut the
			 * client down so it does not block awaiting an fd that
			 * will never arrive, and report success to the caller so
			 * the dispatcher stays silent.
			 */
			close(dup_fd);
			(void)shutdown(client->fd, SHUT_RDWR);
			ctl_acquire_teardown(acq);
			close(sv[1]);
			return (0);
		}
	}
	close(sv[1]);
	return (0);
}

static int
ctl_acquire_chan_result(struct blued_ctl_client *client,
    uint8_t adapter_index, const bdaddr_t *addr, uint8_t addr_type,
    uint16_t handle, uint8_t dir, uint16_t typed_opcode)
{
	struct blued_conn *conn;

	if (client == NULL || addr == NULL || handle == 0 || typed_opcode == 0 ||
	    (dir != CTL_ACQ_NOTIFY && dir != CTL_ACQ_WRITE))
		return (IPC_ERR_INVAL);
	if (!client->wants_fdpass || !ctl_client_privileged(client) ||
	    cap_sandboxed())
		return (IPC_ERR_PERM);
	conn = blued_conn_by_peer_cmd(blued_adapter_by_index_powered(adapter_index),
	    addr, addr_type);
	if (conn == NULL || conn->att == NULL)
		return (IPC_ERR_NOT_CONN);
	if (ctl_acquire_find(adapter_index, addr, addr_type, handle, dir) != NULL)
		return (IPC_ERR_BUSY);
	if (ctl_acquire_create(client, addr, adapter_index, addr_type, handle,
	    dir, conn->att->mtu, typed_opcode) != 0)
		return (IPC_ERR_IO);
	return (IPC_ERR_NONE);
}

/*
 * Route a notification/indication value to a NOTIFY acquire's fd (one datagram
 * per value).  Called from blued_ctl_notify_value under ctl_clients_lock.  A
 * full send buffer (slow client) drops the value rather than blocking the loop.
 */
static void
ctl_acquire_route_notify(const struct blued_conn *conn, uint16_t handle,
    const uint8_t *value, uint16_t len)
{
	struct ctl_acquire *acq;

	LIST_FOREACH(acq, &blued_g.ctl_acquires, entries) {
		if (acq->dir != CTL_ACQ_NOTIFY || acq->handle != handle ||
		    acq->adapter_index != conn->adapter->index ||
		    acq->addr_type != conn->addr_type ||
		    memcmp(&acq->addr, &conn->dst, sizeof(conn->dst)) != 0)
			continue;
		(void)send(acq->daemon_fd, value, len, MSG_DONTWAIT | MSG_EOR);
	}
}

/*
 * Drain the daemon end of an acquire fd that became readable.  For a WRITE
 * acquire each datagram becomes one ATT Write-Without-Response to the char,
 * bounded to the negotiated MTU (payload <= mtu-3, Core Spec Vol 3 Part F
 * §3.2.9) so a client can never provoke an oversized ATT PDU.  A zero-length
 * read / EV_EOF means the client closed its end: tear the acquire down.
 */
void
ctl_acquire_dispatch(struct kevent *ev)
{
	struct ctl_acquire *acq, *found = NULL;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t nr;

	/*
	 * Finding 58: serialise registry access against a GATT worker's
	 * ctl_acquire_route_notify().  Recursive lock, so nesting under a
	 * dispatch that already holds it is safe.
	 */
	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(acq, &blued_g.ctl_acquires, entries) {
		if (acq->daemon_fd == (int)ev->ident) {
			found = acq;
			break;
		}
	}
	if (found == NULL) {
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		return;
	}

	if (ev->flags & EV_EOF) {
		ctl_acquire_teardown(found);
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		return;
	}

	nr = recv(found->daemon_fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (nr == 0) {
		/* Peer end closed with no pending data: client-close teardown. */
		ctl_acquire_teardown(found);
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		return;
	}
	if (nr < 0) {
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		return;
	}

	if (found->dir == CTL_ACQ_WRITE) {
		struct blued_conn *conn;
		size_t dlen = (size_t)nr;
		uint16_t cap;

		conn = blued_conn_by_peer(
		    blued_adapter_by_index_powered(found->adapter_index), &found->addr,
		    found->addr_type);
		/* Bound to the ATT payload budget (mtu-3); never over-send. */
		cap = (found->mtu > 3) ? (uint16_t)(found->mtu - 3) : 0;
		if (conn != NULL && conn->att != NULL && cap != 0) {
			if (dlen > cap)
				dlen = cap;
			(void)att_write_cmd(conn->att, found->handle, buf,
			    dlen);
		}
	}
	/*
	 * A NOTIFY acquire's client end is receive-only from the daemon's point
	 * of view; any bytes it writes are drained above and discarded.
	 */
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

/* Release every acquire owned by a departing control client. */
void
ctl_acquire_client_gone(struct blued_ctl_client *client)
{
	struct ctl_acquire *acq, *tmp;

	/* Registry serialisation (finding 58); recursive, caller already holds. */
	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH_SAFE(acq, &blued_g.ctl_acquires, entries, tmp) {
		if (acq->client == client)
			ctl_acquire_teardown(acq);
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

/* Release every acquire bound to a peer that has disconnected. */
void
ctl_acquire_conn_gone(const struct blued_conn *conn)
{
	struct ctl_acquire *acq, *tmp;

	/* Registry serialisation (finding 58); recursive, may already be held. */
	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH_SAFE(acq, &blued_g.ctl_acquires, entries, tmp) {
		if (acq->adapter_index == conn->adapter->index &&
		    acq->addr_type == conn->addr_type &&
		    memcmp(&acq->addr, &conn->dst, sizeof(conn->dst)) == 0)
			ctl_acquire_teardown(acq);
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}







/*
 * Privilege tiers (finding: trust model).
 *
 * Read-only / query commands are available to any local user.  Commands that
 * mutate state — pairing, bond/config mutation, adapter control, GATT-DB
 * edits — require a privileged peer (uid 0).  The tier is enforced using the
 * peer credentials obtained via getpeereid() at accept time; a peer whose
 * credentials could not be determined is not privileged.
 */
static bool
ctl_client_privileged(const struct blued_ctl_client *client)
{

	if (!client->peer_known)
		return (false);
	return (client->peer_uid == 0);
}

/*
 * Handle a HELLO handshake frame from a framed client: negotiate protocol
 * version and features, reply with a HELLO frame (or a clean IPC_ERR_PROTO
 * error frame on version mismatch).
 */
static void
ctl_process_hello(struct blued_ctl_client *client, uint16_t cli_ver,
    const uint8_t *payload, size_t plen)
{
	uint8_t reply[IPC_HELLO_FEATURES_SIZE];
	uint32_t accepted, requested;

	if (cli_ver != IPC_PROTO_VERSION ||
	    plen != IPC_HELLO_FEATURES_SIZE) {
		static const char m[] = "protocol version mismatch";

		ctl_send_frame(client, IPC_T_ERROR, IPC_ERR_PROTO,
		    m, sizeof(m) - 1);
		client->handshaked = false;
		return;
	}
	requested = ipc_get_le32(payload);
	accepted = requested & IPC_FEATURE_ALL;
	if ((requested & IPC_FEATURE_MESH) != 0)
		accepted |= IPC_FEATURE_EVENTS;
	if ((accepted & IPC_FEATURE_EVENTS) != 0)
		client->wants_events = true;
	if ((accepted & IPC_FEATURE_FDPASS) != 0) {
		/*
 * Record the opt-in so the capability-broker operations (ACQUIRE_COC,
		 * ACQUIRE_ISO) know this client can receive a connected data-path
		 * fd over SCM_RIGHTS.  Without this capability the daemon does not
		 * hand out a socket.
		 */
		client->wants_fdpass = true;
	}
	if ((accepted & IPC_FEATURE_MESH) != 0) {
		/*
		 * Mesh bearer clients require asynchronous MESH_ADV events, so the
		 * events capability is accepted automatically.
		 */
		client->wants_mesh = true;
	}
	client->handshaked = true;
	ipc_put_le32(reply, accepted);
	ctl_send_frame(client, IPC_T_HELLO, IPC_PROTO_VERSION,
	    reply, sizeof(reply));
}

static void
ctl_send_status_reply(struct blued_ctl_client *client)
{
	uint16_t adapters, connections, clients, flags;
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_STATUS_REPLY_SIZE];

	ctl_status_snapshot(&adapters, &connections, &clients, &flags);
	ipc_op_prefix_encode(payload, client->active_request_id, IPC_ERR_NONE, 0);
	ipc_status_reply_encode(payload + IPC_OP_PREFIX_SIZE, adapters,
	    connections, clients, flags);
	ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_CTL, payload,
	    sizeof(payload));
}

static void
ctl_send_adapter_caps_reply(struct blued_ctl_client *client,
	    uint16_t index)
{
	struct blued_adapter *adp;
	uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_ADAPTER_CAPS_REPLY_SIZE];
	uint8_t addr[6];

	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (!adp->active || adp->index != (int)index)
			continue;
		memcpy(addr, &adp->addr, sizeof(addr));
		ipc_op_prefix_encode(reply, client->active_request_id,
		    IPC_ERR_NONE, 0);
		ipc_adapter_caps_reply_encode(reply + IPC_OP_PREFIX_SIZE,
		    (uint16_t)adp->index,
		    adp->name, addr, 0, adp->powered ? 1 : 0,
		    adp->le_features);
		ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_CTL,
		    reply, sizeof(reply));
		return;
	}
	ctl_send_op_error(client, IPC_OP_DOMAIN_CTL, IPC_ERR_NOT_FOUND,
	    "adapter not found");
}

static void
ctl_send_ctl_ack(struct blued_ctl_client *client, uint16_t opcode,
    uint16_t flags, uint32_t value)
{
	uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_CTL_REPLY_SIZE];

	ipc_op_prefix_encode(reply, client->active_request_id,
	    IPC_ERR_NONE, 0);
	ipc_ctl_reply_encode(reply + IPC_OP_PREFIX_SIZE, opcode, flags, value);
	ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_CTL, reply,
	    sizeof(reply));
}

void
ctl_send_op_error(struct blued_ctl_client *client, uint16_t domain,
    uint16_t code, const char *msg)
{
	uint8_t reply[IPC_OP_PREFIX_SIZE + 128];
	size_t len;

	len = strlen(msg);
	if (len > sizeof(reply) - IPC_OP_PREFIX_SIZE)
		len = sizeof(reply) - IPC_OP_PREFIX_SIZE;
	ipc_op_prefix_encode(reply, client->active_request_id, code, 0);
	memcpy(reply + IPC_OP_PREFIX_SIZE, msg, len);
	ctl_send_frame(client, IPC_T_OP_REPLY, domain, reply,
	    IPC_OP_PREFIX_SIZE + len);
}

static void
ctl_send_ctl_error(struct blued_ctl_client *client, uint16_t code,
    const char *msg)
{

	ctl_send_op_error(client, IPC_OP_DOMAIN_CTL, code, msg);
}

void
ctl_send_op_ack(struct blued_ctl_client *client, uint16_t domain)
{
	uint8_t reply[IPC_OP_PREFIX_SIZE];

	ipc_op_prefix_encode(reply, client->active_request_id, IPC_ERR_NONE, 0);
	ctl_send_frame(client, IPC_T_OP_REPLY, domain, reply, sizeof(reply));
}

static void
ctl_send_typed_scan_result(const struct blued_adapter *adp,
    const struct ble_scan_result *result, void *arg)
{
	struct blued_ctl_client *client = arg;
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_GAP_SCAN_RESULT_EVENT_SIZE];
	uint8_t *event = payload + IPC_OP_PREFIX_SIZE;
	size_t name_len;
	int count;

	ipc_op_prefix_encode(payload, client->active_request_id, IPC_ERR_NONE, 0);
	memset(event, 0, IPC_GAP_SCAN_RESULT_EVENT_SIZE);
	ipc_put_le16(event, IPC_GAP_EV_SCAN_RESULT);
	ipc_put_le16(event + 2, (uint16_t)adp->index);
	if (!ctl_addr_type_to_ipc(result->addr_type, &event[4]))
		return;
	memcpy(event + 5, result->addr, 6);
	event[11] = (uint8_t)result->rssi;
	ipc_put_le16(event + 12, result->mfr_id);
	count = result->num_svc_uuids;
	if (count < 0)
		count = 0;
	if (count > 8)
		count = 8;
	event[14] = (uint8_t)count;
	for (int i = 0; i < count; i++)
		ipc_put_le16(event + 16 + i * 2, result->svc_uuids[i]);
	name_len = result->has_name ? strnlen(result->name, 32) : 0;
	event[15] = (uint8_t)name_len;
	memcpy(event + 32, result->name, name_len);
	ctl_send_frame(client, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, payload,
	    sizeof(payload));
}

static void
ctl_process_typed_gap(struct blued_ctl_client *client, const uint8_t *payload,
    size_t plen)
{
	bdaddr_t addr;
	uint8_t addr_type, adapter_index;
	uint16_t opcode, flags;
	int error;

	if (plen < IPC_GAP_REQ_SIZE) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_GAP, IPC_ERR_PROTO,
		    "typed GAP payload has wrong size");
		return;
	}
	opcode = ipc_get_le16(payload);
	if (opcode != IPC_GAP_SCAN && opcode != IPC_GAP_GET_CONNECTIONS &&
	    !ctl_client_privileged(client)) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_GAP, IPC_ERR_PERM,
		    "permission denied");
		return;
	}
	if (opcode == IPC_GAP_SCAN) {
		struct ctl_scan_params params;

		flags = ipc_get_le16(payload + 2);
		if (plen != IPC_GAP_SCAN_REQ_SIZE ||
		    (flags & ~(IPC_GAP_SCAN_F_PASSIVE |
		    IPC_GAP_SCAN_F_ACCEPT_LIST | IPC_GAP_SCAN_F_NO_DEDUP)) != 0 ||
		    payload[11] != 0 || memchr(payload + 12, '\0', 32) == NULL) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP, IPC_ERR_PROTO,
			    "SCAN payload has wrong size or flags");
			return;
		}
		/*
		 * Finding C-M1: bound the frequency of this event-loop-blocking
		 * SCAN (the previously-dead per-client rate limiter), and cap the
		 * per-request synchronous duration below.
		 */
		if (!ctl_blocking_rate_ok(client)) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP,
			    IPC_ERR_BUSY, "scan rate limit exceeded");
			return;
		}
		memset(&params, 0, sizeof(params));
		params.passive = (flags & IPC_GAP_SCAN_F_PASSIVE) != 0;
		params.accept_list = (flags & IPC_GAP_SCAN_F_ACCEPT_LIST) != 0;
		params.no_dedup = (flags & IPC_GAP_SCAN_F_NO_DEDUP) != 0;
		params.interval = ipc_get_le16(payload + 4);
		params.window = ipc_get_le16(payload + 6);
		params.uuid16 = ipc_get_le16(payload + 8);
		params.rssi_min = (int8_t)payload[10];
		memcpy(params.name_sub, payload + 12, sizeof(params.name_sub));
		error = ctl_scan_result(&params, NULL, ctl_send_typed_scan_result,
		    client, 3);
		if (error != IPC_ERR_NONE) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP,
			    (uint16_t)error, error == IPC_ERR_NOT_FOUND ?
			    "no active adapter" : "invalid scan parameters");
			return;
		}
		ctl_send_op_ack(client, IPC_OP_DOMAIN_GAP);
		return;
	}
	if (opcode == IPC_GAP_CONNECT_NAME) {
		uint8_t reply[IPC_OP_PREFIX_SIZE +
		    IPC_GAP_CONNECT_NAME_REPLY_SIZE];
		struct blued_adapter *adapter;
		uint8_t resolved_type;
		bdaddr_t resolved;

		flags = ipc_get_le16(payload + 2);
		adapter_index = (uint8_t)((flags & IPC_OP_ADAPTER_MASK) >>
		    IPC_OP_ADAPTER_SHIFT);
		adapter = blued_adapter_by_index_powered(adapter_index);
		if (plen != IPC_GAP_CONNECT_NAME_REQ_SIZE ||
		    (flags & IPC_OP_FLAGS_RESERVED_MASK) != 0 || adapter == NULL ||
		    !adapter->active ||
		    memchr(payload + 4, '\0', 32) == NULL || payload[4] == '\0') {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP, IPC_ERR_PROTO,
			    "CONNECT_NAME payload is invalid");
			return;
		}
		error = ctl_connect_name_result((const char *)payload + 4, adapter,
		    &resolved, &resolved_type);
		if (error != IPC_ERR_NONE) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP,
			    (uint16_t)error, error == IPC_ERR_NOT_FOUND ?
			    "named device not found" : "connect by name failed");
			return;
		}
		ipc_op_prefix_encode(reply, client->active_request_id,
		    IPC_ERR_NONE, 0);
		(void)ctl_addr_type_to_ipc(resolved_type,
		    &reply[IPC_OP_PREFIX_SIZE]);
		memcpy(reply + IPC_OP_PREFIX_SIZE + 1, &resolved, sizeof(resolved));
		ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_GAP, reply,
		    sizeof(reply));
		return;
	}
	ipc_gap_req_decode(payload, &opcode, &flags, &addr_type,
	    (uint8_t *)&addr, &adapter_index);
	if (!ctl_addr_type_from_ipc(addr_type, &addr_type) ||
	    adapter_index >= BLUED_MAX_ADAPTERS) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_GAP, IPC_ERR_INVAL,
		    "invalid typed GAP request");
		return;
	}
	switch (opcode) {
	case IPC_GAP_GET_CONNECTIONS: {
		uint8_t reply[IPC_OP_PREFIX_SIZE +
		    IPC_GAP_CONNECTION_REPLY_HDR_SIZE +
		    IPC_GAP_CONNECTION_MAX * IPC_GAP_CONNECTION_RECORD_SIZE];
		uint8_t *body = reply + IPC_OP_PREFIX_SIZE;
		struct blued_conn *conn;
		uint16_t count = 0;

		if (flags != 0 || plen != IPC_GAP_CONNECTION_REQ_SIZE ||
			addr_type != BDADDR_LE_PUBLIC || adapter_index != 0 ||
		    memcmp(&addr, &(bdaddr_t){{0}}, sizeof(addr)) != 0) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP, IPC_ERR_PROTO,
			    "invalid connection snapshot request");
			return;
		}
		memset(reply, 0, sizeof(reply));
		ipc_op_prefix_encode(reply, client->active_request_id, 0, 0);
		ipc_put_le16(body, opcode);
		pthread_rwlock_rdlock(&blued_g.conns_lock);
		LIST_FOREACH(conn, &blued_g.conns, entries) {
			struct smp_bond *bond = NULL;
			uint8_t *record;
			uint8_t tx_phy = 0, rx_phy = 0;
			int hci_fd;

			if (count == IPC_GAP_CONNECTION_MAX)
				break;
			record = body + IPC_GAP_CONNECTION_REPLY_HDR_SIZE +
			    count * IPC_GAP_CONNECTION_RECORD_SIZE;
			(void)ctl_addr_type_to_ipc(conn->addr_type, &record[0]);
			memcpy(record + 1, &conn->dst, sizeof(conn->dst));
			record[7] = (uint8_t)atomic_load(&conn->state);
			record[8] = conn->role == BLUED_ROLE_PERIPHERAL ? 1 : 0;
			if (conn->att != NULL && conn->att->encrypted)
				record[9] |= IPC_GAP_CONN_F_ENCRYPTED;
			if (conn->att != NULL && conn->att->authenticated)
				record[9] |= IPC_GAP_CONN_F_AUTHENTICATED;
			record[10] = conn->att != NULL ? conn->att->enc_key_size : 0;
			hci_fd = conn->adapter != NULL ? conn->adapter->hci_fd : -1;
			if (conn->con_handle_valid && hci_fd >= 0 &&
			    hci_le_read_phy(hci_fd, conn->con_handle, &tx_phy,
			    &rx_phy) == 0) {
				record[9] |= IPC_GAP_CONN_F_PHY_VALID;
				record[11] = tx_phy;
			record[12] = rx_phy;
			}
			record[13] = conn->adapter != NULL ?
			    (uint8_t)conn->adapter->index : 0;
			ipc_put_le16(record + 14, conn->con_handle);
			ipc_put_le16(record + 16, conn->att != NULL ?
			    conn->att->mtu : 0);
			ipc_put_le16(record + 18, conn->conn_interval);
			ipc_put_le16(record + 20, conn->conn_latency);
			ipc_put_le16(record + 22, conn->supervision_timeout);
			pthread_mutex_lock(&blued_g.bond_db_lock);
			if (blued_g.bond_db != NULL)
				bond = smp_find_bond(blued_g.bond_db,
				    (const uint8_t *)&conn->dst, conn->addr_type);
			if (bond != NULL && bond->has_name)
				strlcpy((char *)record + 24, bond->name, 64);
			pthread_mutex_unlock(&blued_g.bond_db_lock);
			count++;
		}
		pthread_rwlock_unlock(&blued_g.conns_lock);
		ipc_put_le16(body + 2, count);
		ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_GAP, reply,
		    IPC_OP_PREFIX_SIZE + IPC_GAP_CONNECTION_REPLY_HDR_SIZE +
		    count * IPC_GAP_CONNECTION_RECORD_SIZE);
		return;
	}
	case IPC_GAP_DISCONNECT:
		if (flags != 0 || plen != IPC_GAP_REQ_SIZE) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP, IPC_ERR_PROTO,
			    "DISCONNECT payload has wrong size");
			return;
		}
		error = ctl_disconnect_result(adapter_index, &addr, addr_type);
		if (error != IPC_ERR_NONE) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP,
			    (uint16_t)error, error == IPC_ERR_BUSY ?
			    "connection still setting up" : "device not found");
			return;
		}
		ctl_send_op_ack(client, IPC_OP_DOMAIN_GAP);
		break;
	case IPC_GAP_SET_PHY:
		if (flags != 0 || plen != IPC_GAP_PHY_REQ_SIZE) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP, IPC_ERR_PROTO,
			    "SET_PHY payload has wrong size");
			return;
		}
		error = ctl_set_phy_result(adapter_index, &addr, addr_type,
		    payload[12], payload[13]);
		if (error != IPC_ERR_NONE) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP,
			    (uint16_t)error, "set PHY failed");
			return;
		}
		ctl_send_op_ack(client, IPC_OP_DOMAIN_GAP);
		break;
	case IPC_GAP_SET_DATA_LEN:
		if (flags != 0 || plen != IPC_GAP_DATA_LEN_REQ_SIZE) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP, IPC_ERR_PROTO,
			    "SET_DATA_LEN payload has wrong size");
			return;
		}
		error = ctl_set_data_len_result(adapter_index, &addr, addr_type,
		    ipc_get_le16(payload + 12), ipc_get_le16(payload + 14));
		if (error != IPC_ERR_NONE) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP,
			    (uint16_t)error, "set data length failed");
			return;
		}
		ctl_send_op_ack(client, IPC_OP_DOMAIN_GAP);
		break;
	case IPC_GAP_PATH_LOSS:
		if (flags != 0 || plen != IPC_GAP_PATH_LOSS_REQ_SIZE ||
		    payload[18] > 1 || payload[19] != 0) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP, IPC_ERR_PROTO,
			    "PATH_LOSS payload has wrong size");
			return;
		}
		error = ctl_path_loss_result(adapter_index, &addr, addr_type,
		    payload[12], payload[13],
		    payload[14], payload[15], ipc_get_le16(payload + 16),
		    payload[18] != 0);
		if (error != IPC_ERR_NONE) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP,
			    (uint16_t)error, "path loss configuration failed");
			return;
		}
		ctl_send_op_ack(client, IPC_OP_DOMAIN_GAP);
		break;
	case IPC_GAP_CONN_UPDATE:
		if (flags != 0 || plen != IPC_GAP_CONN_UPDATE_REQ_SIZE) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP, IPC_ERR_PROTO,
			    "CONN_UPDATE payload has wrong size");
			return;
		}
		error = ctl_connparams_update_result(adapter_index, &addr, addr_type,
		    ipc_get_le16(payload + 12), ipc_get_le16(payload + 14),
		    ipc_get_le16(payload + 16), ipc_get_le16(payload + 18));
		if (error != IPC_ERR_NONE) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP,
			    (uint16_t)error, "connection update failed");
			return;
		}
		ctl_send_op_ack(client, IPC_OP_DOMAIN_GAP);
		break;
	case IPC_GAP_CONNECT: {
		struct ctl_connect_params params;

		if (plen != IPC_GAP_CONNECT_REQ_SIZE ||
		    (flags & ~(IPC_GAP_F_CONN_PARAMS | IPC_GAP_F_PHY)) != 0) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP, IPC_ERR_PROTO,
			    "CONNECT payload has wrong size or flags");
			return;
		}
		memset(&params, 0, sizeof(params));
		params.has_conn_params = (flags & IPC_GAP_F_CONN_PARAMS) != 0;
		params.has_phy = (flags & IPC_GAP_F_PHY) != 0;
		params.interval_min = ipc_get_le16(payload + 12);
		params.interval_max = ipc_get_le16(payload + 14);
		params.latency = ipc_get_le16(payload + 16);
		params.timeout = ipc_get_le16(payload + 18);
		params.tx_phys = payload[20];
		params.rx_phys = payload[21];
		error = ctl_connect_result(&addr, addr_type,
		    blued_adapter_by_index_powered(adapter_index), &params);
		if (error != IPC_ERR_NONE) {
			ctl_send_op_error(client, IPC_OP_DOMAIN_GAP,
			    (uint16_t)error, "connect request failed");
			return;
		}
		ctl_send_op_ack(client, IPC_OP_DOMAIN_GAP);
		break;
	}
	default:
		ctl_send_op_error(client, IPC_OP_DOMAIN_GAP,
		    IPC_ERR_UNKNOWN_CMD, "unknown typed GAP opcode");
		break;
	}
}

struct ctl_gatt_job {
	struct blued_conn *conn;
	int client_fd;
	uint64_t client_generation;
	uint32_t request_id;
	uint16_t opcode;
	uint8_t adapter_index;
	uint8_t addr_type;
	uint16_t handle;
	uint16_t route_handle;	/* value handle guarded by CCCD cleanup */
	bdaddr_t addr;
	uint16_t value_len;
	uint8_t value[ATT_PDU_BUF_SIZE];
	STAILQ_ENTRY(ctl_gatt_job) entries;
};

/* Internal worker operation: best-effort disable of a departed owner's CCCD. */
#define CTL_GATT_CCCD_CLEANUP	UINT16_MAX

#define CTL_GATT_WORKERS	4
#define CTL_GATT_QUEUE_MAX	64
/* At most every subscription owned by every admitted control client. */
#define CTL_GATT_CLEANUP_MAX	(BLUED_MAX_CTL * CTL_MAX_SUBSCRIPTIONS)

static STAILQ_HEAD(, ctl_gatt_job) ctl_gatt_jobs =
    STAILQ_HEAD_INITIALIZER(ctl_gatt_jobs);
static pthread_mutex_t ctl_gatt_jobs_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ctl_gatt_jobs_cond = PTHREAD_COND_INITIALIZER;
static pthread_t ctl_gatt_workers[CTL_GATT_WORKERS];
static size_t ctl_gatt_jobs_count;
static struct ctl_gatt_job *ctl_gatt_cleanup_jobs[CTL_GATT_CLEANUP_MAX];
static size_t ctl_gatt_cleanup_count;
static size_t ctl_gatt_workers_count;
static bool ctl_gatt_jobs_stopping;
static struct blued_conn *ctl_gatt_active_conns[CTL_GATT_WORKERS];
static size_t ctl_gatt_active_count;

/*
 * Finding 91: make each att_ops_active 0<->1 transition atomic with its
 * EV_DISABLE/EV_ENABLE side effect.  Without this a worker that decrements
 * 1->0 can be preempted before it re-enables the ATT read filter while main
 * admits a new job (0->1) and disables it; the worker then resumes and
 * re-enables the filter during the new job, leaving a level-triggered readable
 * event the handler refuses (att_ops_active != 0) — the event loop spins until
 * the worker drains the fd.  Serialising the {count change + kevent} pair under
 * one lock keeps the filter state consistent with the count.
 */
static pthread_mutex_t ctl_att_ops_lock = PTHREAD_MUTEX_INITIALIZER;

/* Admit an ATT operation on conn: bump att_ops_active, disable the read filter
 * on the 0->1 edge, as one atomic step. */
static void
ctl_att_ops_enter(struct blued_conn *conn)
{

	pthread_mutex_lock(&ctl_att_ops_lock);
	if (atomic_fetch_add_explicit(&conn->att_ops_active, 1,
	    memory_order_acq_rel) == 0)
		blued_conn_set_att_events(conn, false);
	pthread_mutex_unlock(&ctl_att_ops_lock);
}

/* Retire an ATT operation on conn: drop att_ops_active, re-enable the read
 * filter on the 1->0 edge, as one atomic step.  Returns true on that edge. */
static bool
ctl_att_ops_leave(struct blued_conn *conn)
{
	bool last;

	pthread_mutex_lock(&ctl_att_ops_lock);
	/*
	 * seq_cst: this decrement is the worker's store side of the
	 * store-buffering handshake with blued_conn_disconnect (which stores
	 * disconnect_pending then loads att_ops_active).  ctl_att_ops_lock does
	 * not serialize it against the main thread's lock-free att_ops_active
	 * load, so the ordering must come from a single total order.
	 */
	last = atomic_fetch_sub_explicit(&conn->att_ops_active, 1,
	    memory_order_seq_cst) == 1;
	if (last)
		blued_conn_set_att_events(conn, true);
	pthread_mutex_unlock(&ctl_att_ops_lock);
	return (last);
}

/*
 * Finding H-H1: expose the ATT-ops in-flight guard to non-GATT worker paths
 * (the central pairing worker in blued_central.c).  Bumping att_ops_active
 * makes blued_conn_disconnect and the APTO cleanup sweep defer teardown until
 * the worker exits, exactly as they already do for a GATT worker — so a remote
 * link drop during smp_pair() cannot free conn->hogp (dev->smp/dev->att) under
 * the worker.  _end mirrors the re-signal ctl_gatt_job_run performs so a
 * disconnect that arrived while the worker ran is finalized on the main thread
 * once the last ATT op retires.
 */
void
blued_conn_att_ops_begin(struct blued_conn *conn)
{

	ctl_att_ops_enter(conn);
}

void
blued_conn_att_ops_end(struct blued_conn *conn)
{

	(void)ctl_att_ops_leave(conn);
	/* seq_cst load side of the SB handshake (see ctl_att_ops_leave). */
	if (atomic_load_explicit(&conn->disconnect_pending,
	    memory_order_seq_cst) && atomic_load_explicit(
	    &conn->att_ops_active, memory_order_seq_cst) == 0)
		(void)write(blued_g.setup_pipe[1], "d", 1);
}

static bool
ctl_subscription_equal(const struct ctl_subscription *a,
    const struct ctl_subscription *b)
{

	return (memcmp(&a->addr, &b->addr, sizeof(a->addr)) == 0 &&
	    a->handle == b->handle && a->addr_type == b->addr_type &&
	    a->adapter_index == b->adapter_index);
}

/*
 * Cleanup jobs remain registered while queued and while a worker is inside
 * ATT I/O.  This both coalesces repeated owner churn and gives teardown work
 * a bound independent of a stalled peer or worker pool.
 */
static bool
ctl_gatt_cleanup_equal(const struct ctl_gatt_job *a,
    const struct ctl_gatt_job *b)
{

	return (a->adapter_index == b->adapter_index &&
	    a->addr_type == b->addr_type && a->handle == b->handle &&
	    a->route_handle == b->route_handle &&
	    memcmp(&a->addr, &b->addr, sizeof(a->addr)) == 0);
}

static void
ctl_gatt_cleanup_unregister(struct ctl_gatt_job *job)
{
	size_t i;

	pthread_mutex_lock(&ctl_gatt_jobs_lock);
	for (i = 0; i < ctl_gatt_cleanup_count; i++) {
		if (ctl_gatt_cleanup_jobs[i] != job)
			continue;
		ctl_gatt_cleanup_count--;
		ctl_gatt_cleanup_jobs[i] =
		    ctl_gatt_cleanup_jobs[ctl_gatt_cleanup_count];
		ctl_gatt_cleanup_jobs[ctl_gatt_cleanup_count] = NULL;
		break;
	}
	pthread_mutex_unlock(&ctl_gatt_jobs_lock);
}

static bool
ctl_gatt_cleanup_still_needed(const struct ctl_gatt_job *job)
{
	struct blued_ctl_client *client;
	bool needed;
	int i;

	needed = true;
	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
		for (i = 0; i < client->nsubs; i++) {
			if (memcmp(&client->subs[i].addr, &job->addr,
			    sizeof(job->addr)) != 0 ||
			    client->subs[i].handle != job->route_handle ||
			    client->subs[i].addr_type != job->addr_type ||
			    client->subs[i].adapter_index != job->adapter_index)
				continue;
			needed = false;
			break;
		}
		if (!needed)
			break;
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
	return (needed);
}

/* Resolve 0xff to the sole live connection matching address and type. */
static int
ctl_gatt_resolve_conn(uint8_t requested_adapter, const bdaddr_t *addr,
    uint8_t addr_type, struct blued_conn **result, uint8_t *actual_adapter)
{
	struct blued_conn *conn, *found;
	int i;

	*result = NULL;
	*actual_adapter = requested_adapter;
	if (requested_adapter != UINT8_MAX) {
		conn = blued_conn_by_peer_cmd(
		    blued_adapter_by_index_powered(requested_adapter),
		    addr, addr_type);
		/*
		 * Finding H-M7: the central setup thread publishes conn->att
		 * before the connection reaches ACTIVE.  Admitting a GATT job on
		 * an att!=NULL but still-CONNECTING conn races the setup thread.
		 * Require ACTIVE as well (mirrors ctl_gatt.c:1053).
		 */
		if (conn == NULL || conn->att == NULL ||
		    atomic_load_explicit(&conn->state, memory_order_acquire) !=
		    BLUED_CONN_ACTIVE)
			return (IPC_ERR_NOT_CONN);
		*result = conn;
		return (IPC_ERR_NONE);
	}

	found = NULL;
	for (i = 0; i < BLUED_MAX_ADAPTERS; i++) {
		conn = blued_conn_by_peer_cmd(blued_adapter_by_index_powered(i), addr,
		    addr_type);
		if (conn == NULL || conn->att == NULL ||
		    atomic_load_explicit(&conn->state, memory_order_acquire) !=
		    BLUED_CONN_ACTIVE)	/* Finding H-M7 */
			continue;
		if (found != NULL)
			return (IPC_ERR_BUSY);
		found = conn;
		*actual_adapter = (uint8_t)i;
	}
	if (found == NULL)
		return (IPC_ERR_NOT_CONN);
	*result = found;
	return (IPC_ERR_NONE);
}

static struct blued_ctl_client *
ctl_gatt_job_client(const struct ctl_gatt_job *job)
{
	struct blued_ctl_client *client;

	LIST_FOREACH(client, &blued_g.ctl_clients, entries)
		if (client->fd == job->client_fd &&
		    client->generation == job->client_generation)
			return (client);
	return (NULL);
}

static void
ctl_gatt_job_send(const struct ctl_gatt_job *job, const uint8_t *payload,
    size_t payload_len, uint16_t type)
{
	struct blued_ctl_client *client;

	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	client = ctl_gatt_job_client(job);
	if (client != NULL)
		ctl_send_frame(client, type, IPC_OP_DOMAIN_GATT, payload,
		    payload_len);
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

static void
ctl_gatt_job_discovery(const struct gatt_service *service,
    const struct gatt_char *characteristic, void *arg)
{
	struct ctl_gatt_job *job = arg;
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_GATT_DISCOVERY_EVENT_SIZE];
	uint8_t *body = payload + IPC_OP_PREFIX_SIZE;

	ipc_op_prefix_encode(payload, job->request_id, IPC_ERR_NONE, 0);
	memset(body, 0, IPC_GATT_DISCOVERY_EVENT_SIZE);
	if (service != NULL) {
		ipc_put_le16(body, IPC_GATT_EV_SERVICE);
		ipc_put_le16(body + 2, service->uuid16);
		memcpy(body + 4, service->uuid128, 16);
		ipc_put_le16(body + 20, service->start_handle);
		ipc_put_le16(body + 22, service->end_handle);
	} else if (characteristic != NULL) {
		ipc_put_le16(body, IPC_GATT_EV_CHARACTERISTIC);
		ipc_put_le16(body + 2, characteristic->uuid16);
		memcpy(body + 4, characteristic->uuid128, 16);
		ipc_put_le16(body + 20, characteristic->value_handle);
		body[22] = characteristic->properties;
	}
	ctl_gatt_job_send(job, payload, sizeof(payload), IPC_T_OP_EVENT);
}

static void *
ctl_gatt_job_run(void *arg)
{
	struct ctl_gatt_job *job = arg;
	uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_GATT_READ_REPLY_SIZE +
	    ATT_PDU_BUF_SIZE];
	size_t outlen = 0;
	int error;

	switch (job->opcode) {
	case CTL_GATT_CCCD_CLEANUP:
		if (!ctl_gatt_cleanup_still_needed(job))
			error = IPC_ERR_NONE;
		else
			error = ctl_gatt_write_result(job->conn,
			    job->adapter_index,
			    &job->addr, job->addr_type, job->handle, job->value,
			    job->value_len, false);
		break;
	case IPC_GATT_DISCOVER:
		error = ctl_gatt_discover_result(job->conn, job->adapter_index,
		    &job->addr, job->addr_type,
		    ctl_gatt_job_discovery, job);
		break;
	case IPC_GATT_READ:
		error = ctl_gatt_read_result(job->conn, job->adapter_index,
		    &job->addr, job->addr_type, job->handle,
		    reply + IPC_OP_PREFIX_SIZE + IPC_GATT_READ_REPLY_SIZE,
		    ATT_PDU_BUF_SIZE, &outlen);
		break;
	case IPC_GATT_SUBSCRIBE:
	case IPC_GATT_UNSUBSCRIBE: {
		error = ctl_gatt_subscribe_result(job->conn, job->client_fd,
		    job->client_generation, job->adapter_index,
		    &job->addr, job->addr_type, job->handle,
		    job->opcode == IPC_GATT_SUBSCRIBE);
		break;
	}
	default:
		error = ctl_gatt_write_result(job->conn, job->adapter_index,
		    &job->addr, job->addr_type, job->handle,
		    job->value, job->value_len,
		    job->opcode == IPC_GATT_WRITE_CMD);
		break;
	}

	if (job->opcode == CTL_GATT_CCCD_CLEANUP) {
		/* Client teardown is best-effort and has no reply recipient. */
	} else if (error == IPC_ERR_NONE && job->opcode == IPC_GATT_DISCOVER) {
		ipc_op_prefix_encode(reply, job->request_id, IPC_ERR_NONE, 0);
		ipc_put_le16(reply + IPC_OP_PREFIX_SIZE, IPC_GATT_DISCOVER);
		reply[IPC_OP_PREFIX_SIZE + 2] = job->adapter_index;
		reply[IPC_OP_PREFIX_SIZE + 3] = 0;
		ipc_put_le16(reply + IPC_OP_PREFIX_SIZE + 4,
		    job->conn->att->mtu);
		ctl_gatt_job_send(job, reply,
		    IPC_OP_PREFIX_SIZE + IPC_GATT_DISCOVER_REPLY_SIZE,
		    IPC_T_OP_REPLY);
	} else if (error == IPC_ERR_NONE && job->opcode == IPC_GATT_READ) {
		ipc_op_prefix_encode(reply, job->request_id, IPC_ERR_NONE, 0);
		ipc_put_le16(reply + IPC_OP_PREFIX_SIZE, IPC_GATT_READ);
		ipc_put_le16(reply + IPC_OP_PREFIX_SIZE + 2, job->handle);
		ipc_put_le16(reply + IPC_OP_PREFIX_SIZE + 4, (uint16_t)outlen);
		ctl_gatt_job_send(job, reply,
		    IPC_OP_PREFIX_SIZE + IPC_GATT_READ_REPLY_SIZE + outlen,
		    IPC_T_OP_REPLY);
	} else {
		const char *message = error == IPC_ERR_NONE ? NULL :
		    "GATT operation failed";
		size_t len = message == NULL ? 0 : strlen(message);

		ipc_op_prefix_encode(reply, job->request_id,
		    error == IPC_ERR_NONE ? IPC_ERR_NONE : (uint16_t)error, 0);
		if (len != 0)
			memcpy(reply + IPC_OP_PREFIX_SIZE, message, len);
		ctl_gatt_job_send(job, reply, IPC_OP_PREFIX_SIZE + len,
		    IPC_T_OP_REPLY);
	}

	(void)ctl_att_ops_leave(job->conn);
	/* seq_cst load side of the SB handshake (see ctl_att_ops_leave). */
	if (atomic_load_explicit(&job->conn->disconnect_pending,
	    memory_order_seq_cst) && atomic_load_explicit(
	    &job->conn->att_ops_active, memory_order_seq_cst) == 0)
		(void)write(blued_g.setup_pipe[1], "d", 1);
	if (job->opcode == CTL_GATT_CCCD_CLEANUP)
		ctl_gatt_cleanup_unregister(job);
	blued_conn_unref(job->conn);
	explicit_bzero(job, sizeof(*job));
	free(job);
	return (NULL);
}

static void
ctl_gatt_job_cancel(struct ctl_gatt_job *job)
{
	if (job->opcode == CTL_GATT_CCCD_CLEANUP)
		ctl_gatt_cleanup_unregister(job);

	(void)ctl_att_ops_leave(job->conn);
	blued_conn_unref(job->conn);
	explicit_bzero(job, sizeof(*job));
	free(job);
}

static void *
ctl_gatt_worker(void *arg __unused)
{
	struct ctl_gatt_job *job, *candidate;
	struct blued_conn *conn;
	bool active;
	size_t i;

	for (;;) {
		pthread_mutex_lock(&ctl_gatt_jobs_lock);
		for (;;) {
			job = NULL;
			STAILQ_FOREACH(candidate, &ctl_gatt_jobs, entries) {
				active = false;
				for (i = 0; i < ctl_gatt_active_count; i++)
					if (ctl_gatt_active_conns[i] == candidate->conn) {
						active = true;
						break;
					}
				if (!active) {
					job = candidate;
					break;
				}
			}
			if (job != NULL)
				break;
			if (STAILQ_EMPTY(&ctl_gatt_jobs) &&
			    ctl_gatt_jobs_stopping) {
				pthread_mutex_unlock(&ctl_gatt_jobs_lock);
				return (NULL);
			}
			pthread_cond_wait(&ctl_gatt_jobs_cond,
			    &ctl_gatt_jobs_lock);
		}
		STAILQ_REMOVE(&ctl_gatt_jobs, job, ctl_gatt_job, entries);
		ctl_gatt_jobs_count--;
		conn = job->conn;
		blued_conn_ref(conn);
		ctl_gatt_active_conns[ctl_gatt_active_count++] = conn;
		pthread_mutex_unlock(&ctl_gatt_jobs_lock);
		(void)ctl_gatt_job_run(job);
		pthread_mutex_lock(&ctl_gatt_jobs_lock);
		for (i = 0; i < ctl_gatt_active_count; i++)
			if (ctl_gatt_active_conns[i] == conn) {
				ctl_gatt_active_count--;
				ctl_gatt_active_conns[i] =
				    ctl_gatt_active_conns[ctl_gatt_active_count];
				break;
			}
		pthread_cond_broadcast(&ctl_gatt_jobs_cond);
		pthread_mutex_unlock(&ctl_gatt_jobs_lock);
		blued_conn_unref(conn);
	}
}

static int
ctl_gatt_workers_start(void)
{
	size_t i;

	pthread_mutex_lock(&ctl_gatt_jobs_lock);
	if (ctl_gatt_workers_count != 0) {
		pthread_mutex_unlock(&ctl_gatt_jobs_lock);
		return (0);
	}
	ctl_gatt_jobs_stopping = false;
	ctl_gatt_active_count = 0;
	pthread_mutex_unlock(&ctl_gatt_jobs_lock);

	for (i = 0; i < CTL_GATT_WORKERS; i++) {
		if (pthread_create(&ctl_gatt_workers[i], NULL,
		    ctl_gatt_worker, NULL) != 0)
			break;
		ctl_gatt_workers_count++;
	}
	if (ctl_gatt_workers_count != CTL_GATT_WORKERS) {
		pthread_mutex_lock(&ctl_gatt_jobs_lock);
		ctl_gatt_jobs_stopping = true;
		pthread_cond_broadcast(&ctl_gatt_jobs_cond);
		pthread_mutex_unlock(&ctl_gatt_jobs_lock);
		while (ctl_gatt_workers_count != 0)
			pthread_join(ctl_gatt_workers[--ctl_gatt_workers_count],
			    NULL);
		return (-1);
	}
	return (0);
}

static void
ctl_gatt_workers_stop(void)
{
	struct ctl_gatt_job *job;

	pthread_mutex_lock(&ctl_gatt_jobs_lock);
	ctl_gatt_jobs_stopping = true;
	while ((job = STAILQ_FIRST(&ctl_gatt_jobs)) != NULL) {
		STAILQ_REMOVE_HEAD(&ctl_gatt_jobs, entries);
		ctl_gatt_jobs_count--;
		pthread_mutex_unlock(&ctl_gatt_jobs_lock);
		ctl_gatt_job_cancel(job);
		pthread_mutex_lock(&ctl_gatt_jobs_lock);
	}
	pthread_cond_broadcast(&ctl_gatt_jobs_cond);
	pthread_mutex_unlock(&ctl_gatt_jobs_lock);
	while (ctl_gatt_workers_count != 0)
		pthread_join(ctl_gatt_workers[--ctl_gatt_workers_count], NULL);
}

/*
 * Public entry so shutdown can quiesce the GATT worker pool BEFORE it frees
 * per-connection hogp/att state (finding 93).  A worker mid-job dereferences
 * conn->att == &hogp->att, which the conn refcount does not cover; joining the
 * workers here guarantees no worker is touching a hogp when it is freed.
 */
void
blued_ctl_gatt_workers_stop(void)
{

	ctl_gatt_workers_stop();
}

static void
ctl_gatt_jobs_cancel_client(int client_fd)
{
	struct ctl_gatt_job *job, *tmp;
	STAILQ_HEAD(, ctl_gatt_job) canceled = STAILQ_HEAD_INITIALIZER(canceled);

	pthread_mutex_lock(&ctl_gatt_jobs_lock);
	STAILQ_FOREACH_SAFE(job, &ctl_gatt_jobs, entries, tmp) {
		if (job->opcode == CTL_GATT_CCCD_CLEANUP ||
		    job->client_fd != client_fd)
			continue;
		STAILQ_REMOVE(&ctl_gatt_jobs, job, ctl_gatt_job, entries);
		ctl_gatt_jobs_count--;
		STAILQ_INSERT_TAIL(&canceled, job, entries);
	}
	pthread_mutex_unlock(&ctl_gatt_jobs_lock);
	while ((job = STAILQ_FIRST(&canceled)) != NULL) {
		STAILQ_REMOVE_HEAD(&canceled, entries);
		ctl_gatt_job_cancel(job);
	}
}

static int
ctl_gatt_job_start(struct blued_ctl_client *client, uint16_t opcode,
    uint8_t adapter_index, const bdaddr_t *addr, uint8_t addr_type,
    uint16_t handle, uint16_t route_handle, const uint8_t *value,
    uint16_t value_len)
{
	struct ctl_gatt_job *job;
	struct blued_conn *conn;
	uint8_t actual_adapter;
	bool duplicate;
	size_t i;
	int error;

	error = ctl_gatt_resolve_conn(adapter_index, addr, addr_type, &conn,
	    &actual_adapter);
	if (error != IPC_ERR_NONE)
		return (error);
	job = calloc(1, sizeof(*job));
	if (job == NULL)
		return (IPC_ERR_NOMEM);
	job->conn = conn;
	job->client_fd = client->fd;
	job->client_generation = client->generation;
	job->request_id = client->active_request_id;
	job->opcode = opcode;
	job->adapter_index = actual_adapter;
	job->addr_type = addr_type;
	job->handle = handle;
	job->route_handle = route_handle;
	job->addr = *addr;
	job->value_len = value_len;
	if (value_len != 0)
		memcpy(job->value, value, value_len);
	blued_conn_ref(conn);
	ctl_att_ops_enter(conn);
	pthread_mutex_lock(&ctl_gatt_jobs_lock);
	duplicate = false;
	if (opcode == CTL_GATT_CCCD_CLEANUP) {
		for (i = 0; i < ctl_gatt_cleanup_count; i++) {
			if (ctl_gatt_cleanup_equal(ctl_gatt_cleanup_jobs[i], job)) {
				duplicate = true;
				break;
			}
		}
	}
	if (ctl_gatt_jobs_stopping ||
	    (ctl_gatt_jobs_count >= CTL_GATT_QUEUE_MAX &&
	    opcode != CTL_GATT_CCCD_CLEANUP) ||
	    (opcode == CTL_GATT_CCCD_CLEANUP && !duplicate &&
	    ctl_gatt_cleanup_count >= CTL_GATT_CLEANUP_MAX)) {
		pthread_mutex_unlock(&ctl_gatt_jobs_lock);
		(void)ctl_att_ops_leave(conn);
		blued_conn_unref(conn);
		free(job);
		return (IPC_ERR_BUSY);
	}
	if (duplicate) {
		pthread_mutex_unlock(&ctl_gatt_jobs_lock);
		(void)ctl_att_ops_leave(conn);
		blued_conn_unref(conn);
		free(job);
		return (IPC_ERR_NONE);
	}
	if (opcode == CTL_GATT_CCCD_CLEANUP)
		ctl_gatt_cleanup_jobs[ctl_gatt_cleanup_count++] = job;
	STAILQ_INSERT_TAIL(&ctl_gatt_jobs, job, entries);
	ctl_gatt_jobs_count++;
	pthread_cond_signal(&ctl_gatt_jobs_cond);
	pthread_mutex_unlock(&ctl_gatt_jobs_lock);
	return (IPC_ERR_NONE);
}

void
ctl_gatt_client_gone(struct blued_ctl_client *client)
{
	struct ctl_subscription cleanup[CTL_MAX_SUBSCRIPTIONS];
	struct blued_ctl_client *other;
	uint8_t zero[2] = { 0, 0 };
	bool shared;
	int error, i, j, ncleanup;

	if (client == NULL)
		return;

	/*
	 * Snapshot ownership while it is stable, but never hold the client-list
	 * lock over connection lookup, allocation, or blocking ATT traffic.
	 * The departing client has already been unlinked, so every matching entry
	 * found here is an independent owner that must keep the peer CCCD enabled.
	 */
	ncleanup = 0;
	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	for (i = 0; i < client->nsubs; i++) {
		shared = false;
		LIST_FOREACH(other, &blued_g.ctl_clients, entries) {
			for (j = 0; j < other->nsubs; j++) {
				if (!ctl_subscription_equal(&client->subs[i],
				    &other->subs[j]))
					continue;
				shared = true;
				break;
			}
			if (shared)
				break;
		}
		if (!shared && client->subs[i].cccd_handle != 0)
			cleanup[ncleanup++] = client->subs[i];
	}
	client->nsubs = 0;
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);

	/*
	 * Queue cleanup behind any already-running transaction on this connection.
	 * ctl_gatt_job_start takes a connection reference, so a simultaneous link
	 * teardown is safe; a peer that is already gone simply yields NOT_CONN.
	 */
	for (i = 0; i < ncleanup; i++) {
		error = ctl_gatt_job_start(client, CTL_GATT_CCCD_CLEANUP,
		    cleanup[i].adapter_index, &cleanup[i].addr,
		    cleanup[i].addr_type, cleanup[i].cccd_handle,
		    cleanup[i].handle, zero, sizeof(zero));
		if (error == IPC_ERR_NONE)
			continue;

		/*
		 * The ownership snapshot has now been removed from the client, so
		 * silently dropping a cleanup job would leave an enabled peer CCCD
		 * with no local owner.  Cleanup admission is deliberately bounded;
		 * when that bound (or allocation) prevents admission, terminate the
		 * affected link instead.  ctl_disconnect_result suppresses automatic
		 * reconnect, and an outstanding ATT job defers the physical teardown
		 * through disconnect_pending until its connection reference is safe.
		 * An already-vanished peer needs no further cleanup.
		 */
		(void)ctl_disconnect_result(cleanup[i].adapter_index,
		    &cleanup[i].addr, cleanup[i].addr_type);
	}
}

/*
 * Register or remove a wildcard "monitor all connections" subscription
 * (all-zero address, handle 0) (finding 31).  Unlike a real GATT subscribe it
 * performs no ATT/CCCD operation: it records a passive route so
 * blued_ctl_notify_value mirrors every notification to the monitoring client.
 */
static int
ctl_gatt_wildcard_subscribe(struct blued_ctl_client *client, bool subscribe)
{
	static const bdaddr_t any = { { 0, 0, 0, 0, 0, 0 } };
	int i;

	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	for (i = 0; i < client->nsubs; i++)
		if (client->subs[i].handle == 0 &&
		    memcmp(&client->subs[i].addr, &any, sizeof(any)) == 0)
			break;
	if (subscribe) {
		if (i < client->nsubs) {
			pthread_mutex_unlock(&blued_g.ctl_clients_lock);
			return (IPC_ERR_NONE);	/* already monitoring */
		}
		if (client->nsubs >= CTL_MAX_SUBSCRIPTIONS) {
			pthread_mutex_unlock(&blued_g.ctl_clients_lock);
			return (IPC_ERR_BUSY);
		}
		memset(&client->subs[client->nsubs], 0,
		    sizeof(client->subs[client->nsubs]));
		client->nsubs++;
	} else {
		if (i == client->nsubs) {
			pthread_mutex_unlock(&blued_g.ctl_clients_lock);
			return (IPC_ERR_NOT_FOUND);
		}
		if (i + 1 < client->nsubs)
			memmove(&client->subs[i], &client->subs[i + 1],
			    (client->nsubs - i - 1) *
			    sizeof(client->subs[0]));
		client->nsubs--;
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
	return (IPC_ERR_NONE);
}

static void
ctl_process_typed_gatt(struct blued_ctl_client *client, const uint8_t *payload,
    size_t plen)
{
	uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_GATT_READ_REPLY_SIZE +
	    ATT_PDU_BUF_SIZE];
	static const bdaddr_t zero_addr = { { 0, 0, 0, 0, 0, 0 } };
	bdaddr_t addr;
	uint16_t opcode, flags, handle, value_len;
	uint8_t addr_type, adapter_index;
	bool wildcard;
	int error;

	if (plen < IPC_GATT_REQ_SIZE) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_GATT, IPC_ERR_PROTO,
		    "typed GATT payload is too short");
		return;
	}
	opcode = ipc_get_le16(payload);
	if (opcode != IPC_GATT_DISCOVER && opcode != IPC_GATT_READ &&
	    opcode != IPC_GATT_SUBSCRIBE && opcode != IPC_GATT_UNSUBSCRIBE &&
	    !ctl_client_privileged(client)) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_GATT, IPC_ERR_PERM,
		    "permission denied");
		return;
	}
	flags = ipc_get_le16(payload + 2);
	addr_type = payload[4];
	memcpy(&addr, payload + 5, sizeof(addr));
	adapter_index = payload[11];
	handle = ipc_get_le16(payload + 12);
	/*
	 * A (UN)SUBSCRIBE with an all-zero address and handle 0 is the wildcard
	 * "monitor all connections" registration (finding 31); handle 0 is
	 * otherwise rejected for these opcodes.
	 */
	wildcard = handle == 0 && (opcode == IPC_GATT_SUBSCRIBE ||
	    opcode == IPC_GATT_UNSUBSCRIBE) &&
	    memcmp(&addr, &zero_addr, sizeof(addr)) == 0;
	if (flags != 0 || !ctl_addr_type_from_ipc(addr_type, &addr_type) ||
	    (adapter_index != UINT8_MAX && adapter_index >= BLUED_MAX_ADAPTERS) ||
	    (handle == 0 && opcode != IPC_GATT_DISCOVER &&
	    opcode != IPC_GATT_ADD_SERVICE && !wildcard)) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_GATT, IPC_ERR_INVAL,
		    "invalid typed GATT request");
		return;
	}
	switch (opcode) {
	case IPC_GATT_DISCOVER:
		if (plen != IPC_GATT_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		error = ctl_gatt_job_start(client, opcode, adapter_index, &addr,
		    addr_type, 0, 0, NULL, 0);
		if (error == IPC_ERR_NONE)
			return;
		break;
	case IPC_GATT_READ:
		if (plen != IPC_GATT_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		error = ctl_gatt_job_start(client, opcode, adapter_index, &addr,
		    addr_type, handle, handle, NULL, 0);
		if (error == IPC_ERR_NONE)
			return;
		break;
	case IPC_GATT_WRITE:
	case IPC_GATT_WRITE_CMD:
	case IPC_GATT_READ_REPLY:
	case IPC_GATT_SET_VALUE:
	case IPC_GATT_NOTIFY:
	case IPC_GATT_INDICATE:
		if (plen < IPC_GATT_VALUE_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		value_len = ipc_get_le16(payload + 14);
		if (value_len > ATT_PDU_BUF_SIZE ||
		    plen != IPC_GATT_VALUE_REQ_SIZE + value_len) {
			error = IPC_ERR_PROTO;
			break;
		}
		if (opcode == IPC_GATT_READ_REPLY)
			error = ctl_gatt_read_reply_result(client->fd, handle,
			    payload + IPC_GATT_VALUE_REQ_SIZE, value_len);
		else if (opcode == IPC_GATT_SET_VALUE) {
			pthread_mutex_lock(&blued_g.gatt_db_lock);
			error = ctl_gatt_set_value_result(client->fd, handle,
			    payload + IPC_GATT_VALUE_REQ_SIZE, value_len);
			pthread_mutex_unlock(&blued_g.gatt_db_lock);
		} else if (opcode == IPC_GATT_NOTIFY ||
		    opcode == IPC_GATT_INDICATE)
			error = ctl_gatt_notify_result(handle,
			    payload + IPC_GATT_VALUE_REQ_SIZE, value_len,
			    opcode == IPC_GATT_INDICATE, NULL);
		else
			error = ctl_gatt_job_start(client, opcode, adapter_index,
			    &addr, addr_type, handle, handle,
			    payload + IPC_GATT_VALUE_REQ_SIZE, value_len);
		if (error == IPC_ERR_NONE) {
			if (opcode == IPC_GATT_WRITE ||
			    opcode == IPC_GATT_WRITE_CMD)
				return;
			ctl_send_op_ack(client, IPC_OP_DOMAIN_GATT);
			return;
		}
		break;
	case IPC_GATT_REMOVE_SERVICE:
		if (plen != IPC_GATT_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		pthread_mutex_lock(&blued_g.gatt_db_lock);
		error = ctl_gatt_remove_service_result(client->fd, handle);
		pthread_mutex_unlock(&blued_g.gatt_db_lock);
		if (error == IPC_ERR_NONE) {
			ctl_send_op_ack(client, IPC_OP_DOMAIN_GATT);
			return;
		}
		break;
	case IPC_GATT_ADD_SERVICE:
	case IPC_GATT_ADD_CHARACTERISTIC:
	case IPC_GATT_ADD_INCLUDE:
	case IPC_GATT_ADD_DESCRIPTOR: {
		uint16_t result_handle = 0;

		if (opcode == IPC_GATT_ADD_SERVICE) {
			if (plen != IPC_GATT_ADD_SERVICE_REQ_SIZE) {
				error = IPC_ERR_PROTO;
				break;
			}
			pthread_mutex_lock(&blued_g.gatt_db_lock);
			error = ctl_gatt_add_service_result(client->fd,
			    ipc_get_le16(payload + 14), payload + 16,
			    &result_handle);
			pthread_mutex_unlock(&blued_g.gatt_db_lock);
		} else if (opcode == IPC_GATT_ADD_CHARACTERISTIC) {
			if (plen < IPC_GATT_ADD_CHAR_REQ_SIZE ||
			    (value_len = ipc_get_le16(payload + 36)) >
			    ATT_PDU_BUF_SIZE || plen != IPC_GATT_ADD_CHAR_REQ_SIZE +
			    value_len || payload[35] != 0) {
				error = IPC_ERR_PROTO;
				break;
			}
			pthread_mutex_lock(&blued_g.gatt_db_lock);
			error = ctl_gatt_add_char_result(client->fd, handle,
			    ipc_get_le16(payload + 14), payload + 16, payload[32],
			    payload[33], payload[34],
			    payload + IPC_GATT_ADD_CHAR_REQ_SIZE, value_len,
			    &result_handle);
			pthread_mutex_unlock(&blued_g.gatt_db_lock);
		} else if (opcode == IPC_GATT_ADD_INCLUDE) {
			if (plen != IPC_GATT_ADD_INCLUDE_REQ_SIZE) {
				error = IPC_ERR_PROTO;
				break;
			}
			pthread_mutex_lock(&blued_g.gatt_db_lock);
			error = ctl_gatt_add_include_result(client->fd, handle,
			    ipc_get_le16(payload + 14), ipc_get_le16(payload + 16),
			    ipc_get_le16(payload + 18), &result_handle);
			pthread_mutex_unlock(&blued_g.gatt_db_lock);
		} else {
			if (plen < IPC_GATT_ADD_DESC_REQ_SIZE || payload[33] != 0 ||
			    (value_len = ipc_get_le16(payload + 34)) >
			    ATT_PDU_BUF_SIZE || plen != IPC_GATT_ADD_DESC_REQ_SIZE +
			    value_len) {
				error = IPC_ERR_PROTO;
				break;
			}
			pthread_mutex_lock(&blued_g.gatt_db_lock);
			error = ctl_gatt_add_desc_result(client->fd, handle,
			    ipc_get_le16(payload + 14), payload + 16, payload[32],
			    payload + IPC_GATT_ADD_DESC_REQ_SIZE, value_len,
			    &result_handle);
			pthread_mutex_unlock(&blued_g.gatt_db_lock);
		}
		if (error != IPC_ERR_NONE)
			break;
		ipc_op_prefix_encode(reply, client->active_request_id,
		    IPC_ERR_NONE, 0);
		ipc_put_le16(reply + IPC_OP_PREFIX_SIZE, opcode);
		ipc_put_le16(reply + IPC_OP_PREFIX_SIZE + 2, result_handle);
		ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, reply,
		    IPC_OP_PREFIX_SIZE + IPC_GATT_HANDLE_REPLY_SIZE);
		return;
	}
	case IPC_GATT_READ_REJECT:
	case IPC_GATT_AUTHORIZE_REPLY:
		if (plen != IPC_GATT_DECISION_REQ_SIZE ||
		    (opcode == IPC_GATT_AUTHORIZE_REPLY && payload[14] > 1) ||
		    (opcode == IPC_GATT_READ_REJECT && payload[14] == 0)) {
			error = IPC_ERR_PROTO;
			break;
		}
		if (opcode == IPC_GATT_READ_REJECT)
			error = ctl_gatt_read_reject_result(client->fd, handle,
			    payload[14]);
		else
			error = ctl_gatt_authorize_reply_result(client->fd, handle,
			    payload[14] != 0);
		if (error == IPC_ERR_NONE) {
			ctl_send_op_ack(client, IPC_OP_DOMAIN_GATT);
			return;
		}
		break;
	case IPC_GATT_SUBSCRIBE:
	case IPC_GATT_UNSUBSCRIBE:
		if (plen != IPC_GATT_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		if (wildcard) {
			error = ctl_gatt_wildcard_subscribe(client,
			    opcode == IPC_GATT_SUBSCRIBE);
			if (error == IPC_ERR_NONE) {
				ctl_send_op_ack(client, IPC_OP_DOMAIN_GATT);
				return;
			}
			break;
		}
		error = ctl_gatt_job_start(client, opcode, adapter_index, &addr,
		    addr_type, handle, handle, NULL, 0);
		if (error == IPC_ERR_NONE)
			return;
		break;
	case IPC_GATT_ACQUIRE_NOTIFY:
	case IPC_GATT_ACQUIRE_WRITE:
		if (plen != IPC_GATT_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		error = ctl_acquire_chan_result(client, adapter_index, &addr,
		    addr_type, handle,
		    opcode == IPC_GATT_ACQUIRE_NOTIFY ? CTL_ACQ_NOTIFY :
		    CTL_ACQ_WRITE, opcode);
		if (error == IPC_ERR_NONE)
			return;
		break;
	default:
		error = IPC_ERR_UNKNOWN_CMD;
		break;
	}
	ctl_send_op_error(client, IPC_OP_DOMAIN_GATT, (uint16_t)error,
	    error == IPC_ERR_NOT_CONN ? "device not connected" :
	    error == IPC_ERR_NOT_FOUND ? "subscription not found" :
	    error == IPC_ERR_IO ? "GATT operation failed" :
	    error == IPC_ERR_BUSY ? "too many subscriptions" :
	    "invalid typed GATT request");
}

static struct blued_conn *
ctl_security_conn(uint8_t adapter_index, const bdaddr_t *addr,
    uint8_t addr_type)
{

	/* Operator command path: accept a unique address-only match so a peer
	 * connected with a random/RPA address is reachable without the CLI
	 * having to restate the address type. */
	return (blued_conn_by_peer_cmd(
	    blued_adapter_by_index_powered(adapter_index), addr, addr_type));
}

static int
ctl_security_passkey_result(uint8_t adapter_index, const bdaddr_t *addr,
    uint8_t addr_type, uint32_t passkey)
{
	struct blued_conn *conn;

	if (passkey > 999999)
		return (IPC_ERR_INVAL);
	conn = ctl_security_conn(adapter_index, addr, addr_type);
	if (conn == NULL)
		return (IPC_ERR_NOT_FOUND);
	pthread_mutex_lock(&conn->pairing_lock);
	if (conn->passkey_reply_status != 0) {
		pthread_mutex_unlock(&conn->pairing_lock);
		return (IPC_ERR_NOT_FOUND);
	}
	conn->passkey_reply = passkey;
	conn->passkey_reply_status = 1;
	pthread_cond_broadcast(&conn->pairing_cond);
	pthread_mutex_unlock(&conn->pairing_lock);
	return (IPC_ERR_NONE);
}

static int
ctl_security_numcmp_result(uint8_t adapter_index, const bdaddr_t *addr,
    uint8_t addr_type, bool confirm)
{
	struct blued_conn *conn;

	conn = ctl_security_conn(adapter_index, addr, addr_type);
	if (conn == NULL)
		return (IPC_ERR_NOT_FOUND);
	pthread_mutex_lock(&conn->pairing_lock);
	if (conn->numcmp_reply_status != 0) {
		pthread_mutex_unlock(&conn->pairing_lock);
		return (IPC_ERR_NOT_FOUND);
	}
	conn->numcmp_reply = confirm;
	conn->numcmp_reply_status = 1;
	pthread_cond_broadcast(&conn->pairing_cond);
	pthread_mutex_unlock(&conn->pairing_lock);
	return (IPC_ERR_NONE);
}

static int
ctl_security_register_agent_result(struct blued_ctl_client *client,
    uint8_t io_cap)
{

	if (client == NULL || !client->wants_events || io_cap > 4)
		return (IPC_ERR_PERM);
	atomic_store(&ctl_agent_io_cap, io_cap);
	atomic_store(&ctl_agent_fd, client->fd);
	return (IPC_ERR_NONE);
}

static void
ctl_security_unregister_agent_result(struct blued_ctl_client *client)
{

	if (client != NULL && atomic_load(&ctl_agent_fd) == client->fd)
		atomic_store(&ctl_agent_fd, -1);
}

static int
ctl_security_unbond_result(const bdaddr_t *addr, uint8_t addr_type)
{
	struct blued_adapter *adp;
	struct smp_bond *bond;
	struct smp_bond removed;
	char addr_str[18];
	int idx, remain;

	pthread_mutex_lock(&blued_g.bond_db_lock);
	if (blued_g.bond_db == NULL) {
		pthread_mutex_unlock(&blued_g.bond_db_lock);
		return (IPC_ERR_NOT_FOUND);
	}
	bond = smp_find_bond(blued_g.bond_db, (const uint8_t *)addr, addr_type);
	if (bond == NULL) {
		pthread_mutex_unlock(&blued_g.bond_db_lock);
		return (IPC_ERR_NOT_FOUND);
	}
	removed = *bond;
	idx = (int)(bond - blued_g.bond_db->bonds);
	remain = blued_g.bond_db->count - idx - 1;
	if (remain > 0)
		memmove(bond, bond + 1, (size_t)remain * sizeof(*bond));
	blued_g.bond_db->count--;
	{
		int save_rc = smp_bond_db_save(blued_g.bond_db);
		if (save_rc != 0) {
			if (save_rc == -1) {
		if (remain > 0)
			memmove(bond + 1, bond, (size_t)remain * sizeof(*bond));
		*bond = removed;
		blued_g.bond_db->count++;
			}
		pthread_mutex_unlock(&blued_g.bond_db_lock);
		return (IPC_ERR_IO);
		}
	}
	pthread_mutex_unlock(&blued_g.bond_db_lock);
	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (!adp->active)
			continue;
		hci_le_remove_device_from_filter_accept_list(adp->hci_fd,
		    addr_type == BDADDR_LE_RANDOM ? 1 : 0, removed.addr);
		blued_reslist_sync_remove(adp->hci_fd, removed.addr,
		    removed.addr_type);
	}
	bt_ntoa(addr, addr_str);
	BLUED_LOG_SECURITY("bond removed addr=%s", addr_str);
	BLUED_PROBE_BOND_REMOVE(addr_str);
	return (IPC_ERR_NONE);
}

static int
ctl_security_rekey_result(uint8_t adapter_index, const bdaddr_t *addr,
    uint8_t addr_type)
{
	struct blued_conn *conn;
	bool bonded = false;

	conn = ctl_security_conn(adapter_index, addr, addr_type);
	if (conn == NULL)
		return (IPC_ERR_NOT_CONN);
	pthread_mutex_lock(&blued_g.bond_db_lock);
	if (blued_g.bond_db != NULL)
		bonded = smp_find_bond(blued_g.bond_db,
		    (const uint8_t *)&conn->dst, conn->addr_type) != NULL;
	pthread_mutex_unlock(&blued_g.bond_db_lock);
	if (!bonded)
		return (IPC_ERR_NOT_FOUND);
	if (conn->role != BLUED_ROLE_CENTRAL || conn->hogp == NULL)
		return (IPC_ERR_PERM);
	/*
	 * Finding 33: never run the blocking pairing on the dispatch thread;
	 * hand it to a detached worker.  The reply now means "rekey accepted"
	 * (the exchange proceeds asynchronously and can be answered by a
	 * concurrent passkey/numcmp reply).
	 */
	return (blued_central_start_pairing_async(conn) < 0 ?
	    IPC_ERR_IO : IPC_ERR_NONE);
}

static int
ctl_security_oob_generate_result(uint8_t confirm[16], uint8_t random[16],
    uint8_t pkx[32])
{

	if (smp_sc_oob_generate_local(confirm, random, pkx) < 0)
		return (IPC_ERR_IO);
	pthread_mutex_lock(&blued_oob_lock);
	memcpy(blued_oob_local_random, random, 16);
	blued_oob_local_valid = true;
	pthread_mutex_unlock(&blued_oob_lock);
	return (IPC_ERR_NONE);
}

static int
ctl_security_oob_inject_result(const bdaddr_t *addr, bool sc,
    const uint8_t first[16], const uint8_t second[16])
{
	struct blued_oob_pending *entry;

	pthread_mutex_lock(&blued_oob_lock);
	entry = blued_oob_find((const uint8_t *)addr, true);
	if (entry != NULL) {
		if (sc) {
			memcpy(entry->sc_confirm, first, 16);
			memcpy(entry->sc_random, second, 16);
			entry->has_sc = true;
		} else {
			memcpy(entry->tk, first, 16);
			entry->has_legacy = true;
		}
	}
	pthread_mutex_unlock(&blued_oob_lock);
	return (entry != NULL ? IPC_ERR_NONE : IPC_ERR_BUSY);
}

static void
ctl_security_oob_clear_result(const bdaddr_t *addr, bool all)
{
	int i;

	pthread_mutex_lock(&blued_oob_lock);
	for (i = 0; i < BLUED_OOB_MAX; i++) {
		if (!blued_oob_tbl[i].valid)
			continue;
		if (!all && memcmp(&blued_oob_tbl[i].addr, addr, 6) != 0)
			continue;
		explicit_bzero(&blued_oob_tbl[i], sizeof(blued_oob_tbl[i]));
	}
	if (all) {
		blued_oob_local_valid = false;
		explicit_bzero(blued_oob_local_random,
		    sizeof(blued_oob_local_random));
		smp_sc_oob_clear_local();
	}
	pthread_mutex_unlock(&blued_oob_lock);
}

static int
ctl_security_resolv_result(struct blued_adapter *adp, uint16_t opcode,
    const bdaddr_t *addr, uint8_t addr_type,
    const uint8_t supplied_irk[16], bool have_irk)
{
	static const uint8_t zero_irk[16];
	struct smp_bond *bond;
	uint8_t irk[16], hci_type;
	bool bad;
	/*
	 * Finding H-M5: the Peer_Identity_Address programmed into the resolving
	 * list must be the peer's true identity address, not an observed RPA the
	 * operator may have supplied.  These track the identity address actually
	 * programmed; they are overridden from the resolved bond below.
	 */
	const uint8_t *pid = (const uint8_t *)addr;
	uint8_t pid_buf[6];		/* C3-M8: stable copy of a bond's addr */
	uint8_t pid_type = addr_type;
	/*
	 * Finding 138: only a client-*supplied* IRK (a non-bond runtime entry)
	 * is persisted; an IRK derived from a bond is already covered by the
	 * bond database and rebuilt from it at init.
	 */
	bool client_supplied_irk = have_irk;
	int error = IPC_ERR_NONE;

	if (adp == NULL)
		adp = ctl_typed_adapter(0, 0, &bad);
	else
		bad = false;
	if (bad || adp == NULL)
		return (IPC_ERR_NOT_FOUND);
	if (opcode == IPC_SECURITY_RESOLV_CLEAR) {
		struct blued_reslist_quiesce q;

		/* Serialize shadow + controller mutation (finding 92). */
		pthread_mutex_lock(&blued_g.reslist_lock);
		/* Finding H-H7: quiesce adv/scan around the disallowed-while-
		 * active mutation (Core Spec Vol 4 Part E §7.8.38/§7.8.45). */
		blued_reslist_quiesce_begin(adp, &q);
		hci_le_set_addr_resolution_enable(adp->hci_fd, 0);
		if (hci_le_clear_resolving_list(adp->hci_fd) < 0)
			error = IPC_ERR_IO;
		else {
			memset(&adp->reslist, 0, sizeof(adp->reslist));
			/* Drop persisted runtime entries too (finding 138). */
			blued_runtime_resolv_clear();
		}
		/* Finding H-H5: gate resolution on shadow non-empty, not just
		 * local privacy. */
		blued_reslist_restore_resolution(adp->hci_fd, adp);
		blued_reslist_quiesce_end(adp, &q);
		pthread_mutex_unlock(&blued_g.reslist_lock);
		return (error);
	}
	if (opcode == IPC_SECURITY_RESOLV_ADD && !have_irk) {
		bond = NULL;
		pthread_mutex_lock(&blued_g.bond_db_lock);
		if (blued_g.bond_db != NULL)
			bond = smp_find_bond(blued_g.bond_db,
			    (const uint8_t *)addr, addr_type);
		if (bond != NULL && bond->has_irk) {
			memcpy(irk, bond->irk, sizeof(irk));
			have_irk = true;
			/*
			 * Finding H-M5: the operator may have supplied an
			 * observed RPA that smp_find_bond resolved to this bond.
			 * Program the bond's identity address as
			 * Peer_Identity_Address, not the RPA.
			 */
			/*
			 * C3-M8: bond->addr points into the bond DB array,
			 * which an unbond can memmove once we drop
			 * bond_db_lock below.  Copy the identity address into a
			 * stack buffer under the lock (as irk is copied above)
			 * and use that for the later HCI resolving-list
			 * add/remove, so we never dereference a shifted DB slot.
			 */
			memcpy(pid_buf, bond->addr, sizeof(pid_buf));
			pid = pid_buf;
			pid_type = bond->addr_type;
		}
		pthread_mutex_unlock(&blued_g.bond_db_lock);
		if (!have_irk)
			return (IPC_ERR_NOT_FOUND);
	} else if (have_irk)
		memcpy(irk, supplied_irk, sizeof(irk));
	hci_type = pid_type == BDADDR_LE_RANDOM ? 0x01 : 0x00;
	/* Serialize shadow + controller mutation against setup threads (92). */
	pthread_mutex_lock(&blued_g.reslist_lock);
	/* Finding H-H7: quiesce adv/scan around the disallowed-while-active
	 * resolving-list mutation (Core Spec Vol 4 Part E §7.8.38/§7.8.39). */
	{
	struct blued_reslist_quiesce q;

	blued_reslist_quiesce_begin(adp, &q);
	hci_le_set_addr_resolution_enable(adp->hci_fd, 0);
	if (opcode == IPC_SECURITY_RESOLV_ADD) {
		if (hci_le_add_dev_resolving_list(adp->hci_fd, hci_type,
		    pid, irk, blued_has_local_irk ?
		    blued_local_irk : zero_irk) < 0)
			error = IPC_ERR_IO;
		else if (hci_le_set_privacy_mode(adp->hci_fd, hci_type,
		    pid, blued_cfg.privacy_mode) < 0) {
			/*
			 * Finding 122: the entry is in the controller resolving
			 * list but Set Privacy Mode was rejected — do not report
			 * full success.  Roll the entry back so the host shadow
			 * and the controller stay consistent and the operator
			 * sees the failure.
			 */
			(void)hci_le_remove_dev_resolving_list(adp->hci_fd,
			    hci_type, pid);
			error = IPC_ERR_IO;
		} else {
			(void)blued_reslist_add(&adp->reslist, pid, pid_type);
			/*
			 * Persist a non-bond runtime entry with its supplied
			 * IRK so it survives a restart (finding 138).
			 */
			if (client_supplied_irk)
				blued_runtime_resolv_record(pid, pid_type, irk);
		}
	} else if (hci_le_remove_dev_resolving_list(adp->hci_fd, hci_type,
	    pid) < 0)
		error = IPC_ERR_IO;
	else {
		(void)blued_reslist_remove(&adp->reslist, pid, pid_type);
		blued_runtime_resolv_forget(pid, pid_type);
	}
	/* Finding H-H5: resolution on whenever the shadow is non-empty. */
	blued_reslist_restore_resolution(adp->hci_fd, adp);
	blued_reslist_quiesce_end(adp, &q);
	}
	pthread_mutex_unlock(&blued_g.reslist_lock);
	return (error);
}

/*
 * Filter Accept List operator surface (finding 135).  ADD/REMOVE program the
 * (addr_type, addr) on every powered adapter; CLEAR removes only the persisted
 * runtime entries (never the bond-derived ones, so it does not issue a
 * controller-wide clear).  The persisted shadow is updated on success so the
 * entries survive a restart.
 */
static int
ctl_security_acceptlist_result(uint16_t opcode, const bdaddr_t *addr,
    uint8_t addr_type)
{
	struct blued_adapter *adp;
	uint8_t at = addr_type == BDADDR_LE_RANDOM ? 0x01 : 0x00;
	int error = IPC_ERR_NONE;
	bool any = false;

	if (opcode == IPC_SECURITY_ACCEPT_CLEAR) {
		struct blued_persist_accept_entry snap[IPC_SECURITY_ACCEPT_MAX];
		uint32_t n, i;

		n = blued_acceptlist_snapshot(snap, nitems(snap));
		LIST_FOREACH(adp, &blued_g.adapters, entries) {
			if (!adp->active)
				continue;
			any = true;
			for (i = 0; i < n; i++) {
				uint8_t eat = snap[i].addr_type ==
				    BDADDR_LE_RANDOM ? 0x01 : 0x00;

				(void)hci_le_remove_device_from_filter_accept_list(
				    adp->hci_fd, eat, snap[i].addr);
			}
		}
		if (!any)
			return (IPC_ERR_NOT_FOUND);
		blued_acceptlist_clear_all();
		return (IPC_ERR_NONE);
	}

	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (!adp->active)
			continue;
		any = true;
		if (opcode == IPC_SECURITY_ACCEPT_ADD) {
			if (hci_le_add_device_to_filter_accept_list(adp->hci_fd,
			    at, (const uint8_t *)addr) != 0)
				error = IPC_ERR_IO;
		} else if (hci_le_remove_device_from_filter_accept_list(
		    adp->hci_fd, at, (const uint8_t *)addr) != 0)
			error = IPC_ERR_IO;
	}
	if (!any)
		return (IPC_ERR_NOT_FOUND);
	if (error == IPC_ERR_NONE) {
		if (opcode == IPC_SECURITY_ACCEPT_ADD)
			(void)blued_acceptlist_record((const uint8_t *)addr,
			    addr_type);
		else
			(void)blued_acceptlist_forget((const uint8_t *)addr,
			    addr_type);
	}
	return (error);
}

static void
ctl_process_typed_security(struct blued_ctl_client *client,
    const uint8_t *payload, size_t plen)
{
	bdaddr_t addr;
	uint16_t opcode, flags;
	uint8_t addr_type, adapter_index;
	int error;

	if (plen < IPC_SECURITY_REQ_SIZE) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_SECURITY, IPC_ERR_PROTO,
		    "typed security payload is too short");
		return;
	}
	opcode = ipc_get_le16(payload);
	if (opcode != IPC_SECURITY_GET_POLICY &&
	    opcode != IPC_SECURITY_GET_INFO &&
	    opcode != IPC_SECURITY_BOND_LIST &&
	    opcode != IPC_SECURITY_RESOLV_LIST &&
	    opcode != IPC_SECURITY_ACCEPT_LIST &&
	    !ctl_client_privileged(client)) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_SECURITY, IPC_ERR_PERM,
		    "permission denied");
		return;
	}
	flags = ipc_get_le16(payload + 2);
	addr_type = payload[4];
	memcpy(&addr, payload + 5, sizeof(addr));
	adapter_index = payload[11];
	if (flags != 0 || !ctl_addr_type_from_ipc(addr_type, &addr_type) ||
	    adapter_index >= BLUED_MAX_ADAPTERS) {
		error = IPC_ERR_INVAL;
		goto out;
	}
	switch (opcode) {
	case IPC_SECURITY_PAIR: {
		struct blued_conn *conn;

		if (plen != IPC_SECURITY_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		conn = ctl_security_conn(adapter_index, &addr, addr_type);
		if (conn == NULL) {
			error = IPC_ERR_NOT_CONN;
			break;
		}
		/*
		 * Actually initiate SMP pairing rather than reporting a bare
		 * "connection exists" success (finding 37).  An already-encrypted
		 * link is reported as success (nothing to do).  Only a Central can
		 * initiate pairing over an existing link; a Peripheral would have
		 * to send a Security Request, which this path does not model, so
		 * it returns a clear IPC_ERR_PERM instead of a false success.
		 */
		if (conn->att != NULL && conn->att->encrypted) {
			error = IPC_ERR_NONE;
			break;
		}
		if (conn->role != BLUED_ROLE_CENTRAL || conn->hogp == NULL) {
			error = IPC_ERR_PERM;
			break;
		}
		/* Finding 33: run pairing off the dispatch thread. */
		error = blued_central_start_pairing_async(conn) < 0 ?
		    IPC_ERR_IO : IPC_ERR_NONE;
		break;
	}
	case IPC_SECURITY_PASSKEY_REPLY:
		if (plen != IPC_SECURITY_PASSKEY_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		error = ctl_security_passkey_result(adapter_index, &addr, addr_type,
		    ipc_get_le32(payload + 12));
		break;
	case IPC_SECURITY_NUMCMP_REPLY:
		if (plen != IPC_SECURITY_DECISION_REQ_SIZE || payload[12] > 1) {
			error = IPC_ERR_PROTO;
			break;
		}
		error = ctl_security_numcmp_result(adapter_index, &addr, addr_type,
		    payload[12] != 0);
		break;
	case IPC_SECURITY_REGISTER_AGENT:
		if (plen != IPC_SECURITY_AGENT_REQ_SIZE || payload[12] > 4) {
			error = IPC_ERR_PROTO;
			break;
		}
		error = ctl_security_register_agent_result(client, payload[12]);
		break;
	case IPC_SECURITY_UNREGISTER_AGENT:
		if (plen != IPC_SECURITY_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		ctl_security_unregister_agent_result(client);
		error = IPC_ERR_NONE;
		break;
	case IPC_SECURITY_UNBOND:
		if (plen != IPC_SECURITY_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		error = ctl_security_unbond_result(&addr, addr_type);
		break;
	case IPC_SECURITY_REKEY:
		if (plen != IPC_SECURITY_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		error = ctl_security_rekey_result(adapter_index, &addr, addr_type);
		break;
	case IPC_SECURITY_SET_POLICY: {
		uint16_t mask;

		if (plen != IPC_SECURITY_POLICY_REQ_SIZE ||
		    (mask = ipc_get_le16(payload + 12)) == 0 ||
		    (mask & ~IPC_SECURITY_POLICY_F_ALL) != 0 ||
		    ipc_get_le16(payload + 22) != 0 ||
		    ((mask & IPC_SECURITY_POLICY_F_MITM) != 0 && payload[14] > 1) ||
		    ((mask & IPC_SECURITY_POLICY_F_BONDING) != 0 && payload[15] > 1) ||
		    ((mask & IPC_SECURITY_POLICY_F_SC) != 0 && payload[16] > 2) ||
		    ((mask & IPC_SECURITY_POLICY_F_KEYPRESS) != 0 && payload[17] > 1) ||
		    ((mask & IPC_SECURITY_POLICY_F_IO_CAP) != 0 && payload[18] > 4) ||
		    ((mask & IPC_SECURITY_POLICY_F_MIN_SEC) != 0 && payload[19] > 3) ||
		    ((mask & IPC_SECURITY_POLICY_F_KEY_SIZE) != 0 &&
		    (payload[20] < 7 || payload[20] > 16)) ||
		    ((mask & IPC_SECURITY_POLICY_F_KEY_DIST) != 0 &&
		    (payload[21] & ~0x07u) != 0)) {
			error = IPC_ERR_INVAL;
			break;
		}
		if ((mask & IPC_SECURITY_POLICY_F_MITM) != 0)
			blued_cfg.mitm = payload[14] != 0;
		if ((mask & IPC_SECURITY_POLICY_F_BONDING) != 0)
			blued_cfg.bondable = payload[15] != 0;
		if ((mask & IPC_SECURITY_POLICY_F_SC) != 0) {
			blued_cfg.sc_mode = payload[16];
		}
		if ((mask & IPC_SECURITY_POLICY_F_KEYPRESS) != 0)
			blued_cfg.keypress = payload[17] != 0;
		if ((mask & IPC_SECURITY_POLICY_F_IO_CAP) != 0)
			blued_cfg.io_capability = payload[18];
		if ((mask & IPC_SECURITY_POLICY_F_MIN_SEC) != 0)
			blued_cfg.min_pairing_security = payload[19];
		if ((mask & IPC_SECURITY_POLICY_F_KEY_SIZE) != 0)
			blued_cfg.min_key_size = payload[20];
		if ((mask & IPC_SECURITY_POLICY_F_KEY_DIST) != 0)
			blued_cfg.key_dist = payload[21];
		error = IPC_ERR_NONE;
		break;
	}
	case IPC_SECURITY_GET_POLICY: {
		uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_SECURITY_POLICY_REPLY_SIZE];
		uint8_t *body = reply + IPC_OP_PREFIX_SIZE;

		if (plen != IPC_SECURITY_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		memset(reply, 0, sizeof(reply));
		ipc_op_prefix_encode(reply, client->active_request_id, 0, 0);
		ipc_put_le16(body, opcode);
		body[2] = blued_cfg.mitm ? 1 : 0;
		body[3] = blued_cfg.bondable ? 1 : 0;
		body[4] = blued_cfg.sc_mode;
		body[5] = blued_cfg.keypress ? 1 : 0;
		body[6] = blued_cfg.io_capability;
		body[7] = blued_cfg.min_pairing_security;
		body[8] = (uint8_t)blued_cfg.min_key_size;
		body[9] = blued_cfg.key_dist;
		ipc_put_le16(body + 10, (uint16_t)blued_cfg.rpa_timeout);
		ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_SECURITY,
		    reply, sizeof(reply));
		return;
	}
	case IPC_SECURITY_GET_INFO: {
		struct blued_conn *conn;
		struct smp_bond *bond = NULL;
		uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_SECURITY_INFO_REPLY_SIZE];
		uint8_t *body = reply + IPC_OP_PREFIX_SIZE;
		bool encrypted, authenticated;
		uint8_t key_size, level, info_flags = 0;

		if (plen != IPC_SECURITY_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		conn = ctl_security_conn(adapter_index, &addr, addr_type);
		if (conn == NULL) {
			error = IPC_ERR_NOT_CONN;
			break;
		}
		encrypted = conn->att != NULL && conn->att->encrypted != 0;
		authenticated = conn->att != NULL &&
		    conn->att->authenticated != 0;
		key_size = conn->att != NULL ? conn->att->enc_key_size : 0;
		pthread_mutex_lock(&blued_g.bond_db_lock);
		if (blued_g.bond_db != NULL)
			bond = smp_find_bond(blued_g.bond_db,
			    (const uint8_t *)&conn->dst, conn->addr_type);
		if (bond != NULL && key_size == 0)
			key_size = bond->key_size;
		if (encrypted)
			info_flags |= IPC_SECURITY_INFO_F_ENCRYPTED;
		if (authenticated)
			info_flags |= IPC_SECURITY_INFO_F_AUTHENTICATED;
		if (bond != NULL && bond->is_sc)
			info_flags |= IPC_SECURITY_INFO_F_SC;
		if (bond != NULL)
			info_flags |= IPC_SECURITY_INFO_F_BONDED;
		pthread_mutex_unlock(&blued_g.bond_db_lock);
		level = !encrypted ? 1 : !authenticated ? 2 :
		    (info_flags & IPC_SECURITY_INFO_F_SC) != 0 ? 4 : 3;
		memset(reply, 0, sizeof(reply));
		ipc_op_prefix_encode(reply, client->active_request_id, 0, 0);
		ipc_put_le16(body, opcode);
		(void)ctl_addr_type_to_ipc(conn->addr_type, &body[2]);
		memcpy(body + 3, &conn->dst, sizeof(conn->dst));
		body[9] = key_size;
		body[10] = level;
		body[11] = info_flags;
		ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_SECURITY,
		    reply, sizeof(reply));
		return;
	}
	case IPC_SECURITY_OOB_GENERATE: {
		uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_SECURITY_OOB_REPLY_SIZE];
		uint8_t *body = reply + IPC_OP_PREFIX_SIZE;

		if (plen != IPC_SECURITY_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		memset(reply, 0, sizeof(reply));
		error = ctl_security_oob_generate_result(body + 2, body + 18,
		    body + 34);
		if (error != IPC_ERR_NONE)
			break;
		ipc_op_prefix_encode(reply, client->active_request_id, 0, 0);
		ipc_put_le16(body, opcode);
		ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_SECURITY,
		    reply, sizeof(reply));
		return;
	}
	case IPC_SECURITY_OOB_INJECT_SC:
		if (plen != IPC_SECURITY_OOB_SC_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		error = ctl_security_oob_inject_result(&addr, true, payload + 12,
		    payload + 28);
		break;
	case IPC_SECURITY_OOB_INJECT_LEGACY:
		if (plen != IPC_SECURITY_OOB_LEGACY_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		error = ctl_security_oob_inject_result(&addr, false, payload + 12,
		    NULL);
		break;
	case IPC_SECURITY_OOB_CLEAR:
		if (plen != IPC_SECURITY_OOB_CLEAR_REQ_SIZE ||
		    (payload[12] & ~IPC_SECURITY_OOB_CLEAR_F_ALL) != 0) {
			error = IPC_ERR_PROTO;
			break;
		}
		ctl_security_oob_clear_result(&addr,
		    (payload[12] & IPC_SECURITY_OOB_CLEAR_F_ALL) != 0);
		error = IPC_ERR_NONE;
		break;
	case IPC_SECURITY_RESOLV_ADD:
	case IPC_SECURITY_RESOLV_REMOVE:
	case IPC_SECURITY_RESOLV_CLEAR:
		if (plen != IPC_SECURITY_RESOLV_REQ_SIZE ||
		    (payload[12] & ~IPC_SECURITY_RESOLV_F_IRK) != 0 ||
		    payload[13] != 0 || payload[14] != 0 || payload[15] != 0 ||
		    (opcode != IPC_SECURITY_RESOLV_ADD && payload[12] != 0)) {
			error = IPC_ERR_PROTO;
			break;
		}
		error = ctl_security_resolv_result(
		    blued_adapter_by_index_powered(adapter_index), opcode, &addr, addr_type,
		    payload + 16,
		    (payload[12] & IPC_SECURITY_RESOLV_F_IRK) != 0);
		break;
	case IPC_SECURITY_ACCEPT_ADD:
	case IPC_SECURITY_ACCEPT_REMOVE:
	case IPC_SECURITY_ACCEPT_CLEAR:
		if (plen != IPC_SECURITY_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		pthread_mutex_lock(&blued_g.reslist_lock);
		error = ctl_security_acceptlist_result(opcode, &addr, addr_type);
		pthread_mutex_unlock(&blued_g.reslist_lock);
		break;
	case IPC_SECURITY_ACCEPT_LIST: {
		uint8_t reply[IPC_OP_PREFIX_SIZE +
		    IPC_SECURITY_ACCEPT_REPLY_HDR_SIZE + IPC_SECURITY_ACCEPT_MAX *
		    IPC_SECURITY_ACCEPT_RECORD_SIZE];
		uint8_t *body = reply + IPC_OP_PREFIX_SIZE;
		struct blued_persist_accept_entry snap[IPC_SECURITY_ACCEPT_MAX];
		uint32_t count, i;

		if (plen != IPC_SECURITY_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		memset(reply, 0, sizeof(reply));
		ipc_op_prefix_encode(reply, client->active_request_id, 0, 0);
		ipc_put_le16(body, opcode);
		pthread_mutex_lock(&blued_g.reslist_lock);
		count = blued_acceptlist_snapshot(snap, nitems(snap));
		pthread_mutex_unlock(&blued_g.reslist_lock);
		for (i = 0; i < count; i++) {
			uint8_t *record = body +
			    IPC_SECURITY_ACCEPT_REPLY_HDR_SIZE + i *
			    IPC_SECURITY_ACCEPT_RECORD_SIZE;

			record[0] = snap[i].addr_type == BDADDR_LE_RANDOM ? 1 : 0;
			memcpy(record + 1, snap[i].addr, 6);
		}
		ipc_put_le16(body + 2, (uint16_t)count);
		ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_SECURITY,
		    reply, IPC_OP_PREFIX_SIZE + IPC_SECURITY_ACCEPT_REPLY_HDR_SIZE +
		    count * IPC_SECURITY_ACCEPT_RECORD_SIZE);
		return;
	}
	case IPC_SECURITY_BOND_LIST: {
		uint8_t reply[IPC_OP_PREFIX_SIZE +
		    IPC_SECURITY_BOND_REPLY_HDR_SIZE + SMP_MAX_BONDS *
		    IPC_SECURITY_BOND_RECORD_SIZE];
		uint8_t *body = reply + IPC_OP_PREFIX_SIZE;
		uint16_t count = 0;

		if (plen != IPC_SECURITY_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		memset(reply, 0, sizeof(reply));
		ipc_op_prefix_encode(reply, client->active_request_id, 0, 0);
		ipc_put_le16(body, opcode);
		pthread_mutex_lock(&blued_g.bond_db_lock);
		if (blued_g.bond_db != NULL) {
			for (int i = 0; i < blued_g.bond_db->count; i++) {
				struct smp_bond *bond = &blued_g.bond_db->bonds[i];
				uint8_t *record = body +
				    IPC_SECURITY_BOND_REPLY_HDR_SIZE + count *
				    IPC_SECURITY_BOND_RECORD_SIZE;

				record[0] = bond->addr_type == BDADDR_LE_RANDOM ? 1 : 0;
				memcpy(record + 1, bond->addr, sizeof(bond->addr));
				if (bond->has_ltk) record[7] |= IPC_SECURITY_BOND_F_LTK;
				if (bond->has_irk) record[7] |= IPC_SECURITY_BOND_F_IRK;
				if (bond->has_csrk) record[7] |= IPC_SECURITY_BOND_F_CSRK;
				if (bond->is_sc) record[7] |= IPC_SECURITY_BOND_F_SC;
				if (bond->has_link_key)
					record[7] |= IPC_SECURITY_BOND_F_LINK_KEY;
				if (bond->is_mitm) record[7] |= IPC_SECURITY_BOND_F_MITM;
				if (bond->has_name)
					strlcpy((char *)record + 8, bond->name, 64);
				count++;
			}
		}
		pthread_mutex_unlock(&blued_g.bond_db_lock);
		ipc_put_le16(body + 2, count);
		ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_SECURITY,
		    reply, IPC_OP_PREFIX_SIZE + IPC_SECURITY_BOND_REPLY_HDR_SIZE +
		    count * IPC_SECURITY_BOND_RECORD_SIZE);
		return;
	}
	case IPC_SECURITY_RESOLV_LIST: {
		struct blued_adapter *list_adp;
		uint8_t reply[IPC_OP_PREFIX_SIZE +
		    IPC_SECURITY_RESOLV_REPLY_HDR_SIZE + SMP_MAX_BONDS *
		    IPC_SECURITY_RESOLV_RECORD_SIZE];
		uint8_t *body = reply + IPC_OP_PREFIX_SIZE;
		uint16_t count = 0;

		if (plen != IPC_SECURITY_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		list_adp = blued_adapter_by_index_powered(adapter_index);
		if (list_adp == NULL) {
			error = IPC_ERR_NOT_FOUND;
			break;
		}
		memset(reply, 0, sizeof(reply));
		ipc_op_prefix_encode(reply, client->active_request_id, 0, 0);
		ipc_put_le16(body, opcode);
		pthread_mutex_lock(&blued_g.bond_db_lock);
		/* Read the shadow under its lock; a setup thread may be
		 * mutating it concurrently (finding 92). */
		pthread_mutex_lock(&blued_g.reslist_lock);
		if (blued_g.bond_db != NULL) {
			for (int i = 0; i < blued_g.bond_db->count; i++) {
				struct smp_bond *bond = &blued_g.bond_db->bonds[i];
				uint8_t *record;

				if (!bond->has_irk)
					continue;
				record = body + IPC_SECURITY_RESOLV_REPLY_HDR_SIZE +
				    count * IPC_SECURITY_RESOLV_RECORD_SIZE;
				record[0] = bond->addr_type == BDADDR_LE_RANDOM ? 1 : 0;
				memcpy(record + 1, bond->addr, sizeof(bond->addr));
				if (blued_reslist_contains(&list_adp->reslist, bond->addr,
				    bond->addr_type))
					record[7] = IPC_SECURITY_RESOLV_F_IN_LIST;
				count++;
			}
		}
		pthread_mutex_unlock(&blued_g.reslist_lock);
		pthread_mutex_unlock(&blued_g.bond_db_lock);
		ipc_put_le16(body + 2, count);
		ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_SECURITY,
		    reply, IPC_OP_PREFIX_SIZE + IPC_SECURITY_RESOLV_REPLY_HDR_SIZE +
		    count * IPC_SECURITY_RESOLV_RECORD_SIZE);
		return;
	}
	case IPC_SECURITY_BOND_EXPORT: {
		uint8_t reply[IPC_OP_PREFIX_SIZE +
		    IPC_SECURITY_BOND_EXPORT_REPLY_HDR_SIZE + SMP_BOND_REC_LEN];
		uint8_t *body = reply + IPC_OP_PREFIX_SIZE;
		struct smp_bond *bond;
		size_t record_len;

		if (plen != IPC_SECURITY_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		pthread_mutex_lock(&blued_g.bond_db_lock);
		bond = blued_g.bond_db == NULL ? NULL : smp_find_bond(
		    blued_g.bond_db, (const uint8_t *)&addr, addr_type);
		if (bond == NULL) {
			pthread_mutex_unlock(&blued_g.bond_db_lock);
			error = IPC_ERR_NOT_FOUND;
			break;
		}
		memset(reply, 0, sizeof(reply));
		record_len = smp_bond_export_record(bond,
		    body + IPC_SECURITY_BOND_EXPORT_REPLY_HDR_SIZE,
		    SMP_BOND_REC_LEN);
		pthread_mutex_unlock(&blued_g.bond_db_lock);
		if (record_len == 0) {
			error = IPC_ERR_IO;
			break;
		}
		ipc_op_prefix_encode(reply, client->active_request_id, 0, 0);
		ipc_put_le16(body, opcode);
		ipc_put_le16(body + 2, (uint16_t)record_len);
		ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_SECURITY,
		    reply, IPC_OP_PREFIX_SIZE +
		    IPC_SECURITY_BOND_EXPORT_REPLY_HDR_SIZE + record_len);
		explicit_bzero(reply, sizeof(reply));
		return;
	}
	case IPC_SECURITY_BOND_IMPORT: {
		struct smp_bond bond;
		struct blued_adapter *adp;
		uint16_t record_len;
		int rc;

		record_len = plen >= IPC_SECURITY_BOND_IMPORT_REQ_HDR_SIZE ?
		    ipc_get_le16(payload + 12) : 0;
		if (plen < IPC_SECURITY_BOND_IMPORT_REQ_HDR_SIZE ||
		    ipc_get_le16(payload + 14) != 0 || record_len == 0 ||
		    plen != IPC_SECURITY_BOND_IMPORT_REQ_HDR_SIZE + record_len ||
		    smp_bond_import_record(payload +
		    IPC_SECURITY_BOND_IMPORT_REQ_HDR_SIZE, record_len, &bond) != 0) {
			error = IPC_ERR_INVAL;
			break;
		}
		pthread_mutex_lock(&blued_g.bond_db_lock);
		rc = blued_g.bond_db == NULL ? -1 :
		    smp_bond_db_import(blued_g.bond_db, &bond);
		pthread_mutex_unlock(&blued_g.bond_db_lock);
		if (rc < 0) {
			explicit_bzero(&bond, sizeof(bond));
			error = rc == -2 ? IPC_ERR_IO : IPC_ERR_BUSY;
			break;
		}
		if (bond.has_irk) {
			LIST_FOREACH(adp, &blued_g.adapters, entries)
				if (adp->active)
					blued_reslist_sync_add(adp->hci_fd, &bond);
		}
		explicit_bzero(&bond, sizeof(bond));
		error = IPC_ERR_NONE;
		break;
	}
	default:
		error = IPC_ERR_UNKNOWN_CMD;
		break;
	}
out:
	if (error == IPC_ERR_NONE)
		ctl_send_op_ack(client, IPC_OP_DOMAIN_SECURITY);
	else
		ctl_send_op_error(client, IPC_OP_DOMAIN_SECURITY, error,
		    error == IPC_ERR_NOT_CONN ? "device not connected" :
		    error == IPC_ERR_NOT_FOUND ? "security state not found" :
		    error == IPC_ERR_BUSY ? "security operation busy" :
		    error == IPC_ERR_IO ? "security operation failed" :
		    "invalid security request");
}

static void
ctl_process_typed_adv(struct blued_ctl_client *client, const uint8_t *payload,
    size_t plen)
{
	struct blued_adapter *adp;
	struct ctl_adv_set *set;
	struct hci_adv_config cfg;
	uint16_t opcode, flags;
	uint8_t handle;
	bool bad;
	int error = IPC_ERR_NONE;

	if (!ctl_client_privileged(client)) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_ADV, IPC_ERR_PERM,
		    "permission denied");
		return;
	}
	if (plen < 4) {
		error = IPC_ERR_PROTO;
		goto out;
	}
	opcode = ipc_get_le16(payload);
	flags = ipc_get_le16(payload + 2);
	if (flags != 0) {
		error = IPC_ERR_INVAL;
		goto out;
	}
	adp = ctl_typed_adapter(0, 0, &bad);
	if (adp == NULL || !adp->powered || adp->power_quiescing) {
		error = IPC_ERR_NOT_FOUND;
		goto out;
	}
	switch (opcode) {
	case IPC_ADV_SET_PARAMS:
		if (plen != IPC_ADV_PARAMS_REQ_SIZE || payload[4] > 2 ||
		    payload[5] > 4 || payload[6] == 0 || payload[6] > 7 ||
		    payload[7] > 3 || payload[8] == 0 || payload[8] > 3 ||
		    payload[8] == 2 || payload[9] == 0 || payload[9] > 3 ||
		    payload[11] > 1 || payload[12] > 1 || payload[19] != 0 ||
		    ipc_get_le32(payload + 20) >
		    ipc_get_le32(payload + 24)) {
			error = IPC_ERR_INVAL;
			break;
		}
		if (adp == NULL) {
			error = IPC_ERR_NOT_FOUND;
			break;
		}
		if (!blued_g.periph_active) {
			error = IPC_ERR_PERM;
			break;
		}
		memset(&cfg, 0, sizeof(cfg));
		cfg.mode = payload[4];
		cfg.kind = payload[5];
		cfg.channel_map = payload[6];
		cfg.own_addr_type = payload[7];
		cfg.primary_phy = payload[8];
		cfg.secondary_phy = payload[9];
		cfg.tx_power = (int8_t)payload[10];
		cfg.has_peer = payload[11] != 0;
		cfg.peer_addr_type = payload[12];
		memcpy(cfg.peer_addr, payload + 13, sizeof(cfg.peer_addr));
		cfg.interval_min = ipc_get_le32(payload + 20);
		cfg.interval_max = ipc_get_le32(payload + 24);
		if (adp->adv_config == NULL &&
		    (adp->adv_config = malloc(sizeof(*adp->adv_config))) == NULL)
			error = IPC_ERR_NOMEM;
		else {
			/*
			 * Set Advertising Parameters is Command Disallowed
			 * (§7.8.5 / §7.8.53) while the set is enabled -- the
			 * default peripheral state.  Quiesce the primary set
			 * around the reconfigure, then restore it, so the verb
			 * is not inert in the normal running state.
			 */
			bool was_enabled = adp->adv_enabled;

			if (was_enabled)
				(void)(adp->adv_use_extended ?
				    hci_le_set_ext_adv_enable(adp->hci_fd, 0,
				    0x00) :
				    hci_le_set_advertise_enable(adp->hci_fd,
				    false));
			if (hci_adv_configure(adp->hci_fd, adp->le_features,
			    &cfg) < 0) {
				error = IPC_ERR_INVAL;
			} else {
				adp->adv_configured = true;
				adp->adv_use_extended = cfg.used_extended;
				*adp->adv_config = cfg;
			}
			if (was_enabled) {
				int renable;

				renable = adp->adv_use_extended ?
				    hci_le_set_ext_adv_enable(adp->hci_fd, 1,
				    0x00) :
				    hci_le_set_advertise_enable(adp->hci_fd,
				    true);
				if (renable < 0) {
					/*
					 * Re-enable failed (e.g. a legacy->ext
					 * switch before ext adv data is
					 * programmed -> Command Disallowed /
					 * Invalid Params): the controller is now
					 * silent, so reconcile the cached state
					 * instead of leaving adv_enabled stale-
					 * true, and surface the failure.  Do not
					 * clobber an earlier configure error.
					 */
					adp->adv_enabled = false;
					if (error == IPC_ERR_NONE)
						error = IPC_ERR_IO;
				}
			}
		}
		break;
	case IPC_ADV_SET_NAME:
		if (plen <= IPC_ADV_NAME_REQ_HDR_SIZE ||
		    plen > IPC_ADV_NAME_REQ_HDR_SIZE + BLUED_GAP_NAME_MAXLEN) {
			error = IPC_ERR_INVAL;
			break;
		}
		for (size_t i = IPC_ADV_NAME_REQ_HDR_SIZE; i < plen; i++)
			if (payload[i] < 0x20 || payload[i] == 0x7f) {
				error = IPC_ERR_INVAL;
				goto out;
			}
		{
			char name[BLUED_GAP_NAME_MAXLEN + 1];

			memcpy(name, payload + IPC_ADV_NAME_REQ_HDR_SIZE,
			    plen - IPC_ADV_NAME_REQ_HDR_SIZE);
			name[plen - IPC_ADV_NAME_REQ_HDR_SIZE] = '\0';
			error = blued_set_device_name(name) < 0 ? IPC_ERR_IO :
			    IPC_ERR_NONE;
		}
		break;
	case IPC_ADV_SET_DATA:
	case IPC_ADV_SET_SCAN_RESPONSE: {
		uint16_t len;

		if (plen < IPC_ADV_DATA_REQ_HDR_SIZE ||
		    (len = ipc_get_le16(payload + 4)) > 31 ||
		    ipc_get_le16(payload + 6) != 0 ||
		    plen != IPC_ADV_DATA_REQ_HDR_SIZE + len) {
			error = IPC_ERR_PROTO;
			break;
		}
		if (adp == NULL) {
			error = IPC_ERR_NOT_FOUND;
			break;
		}
		error = ctl_adv_program(adp,
		    opcode == IPC_ADV_SET_SCAN_RESPONSE,
		    payload + IPC_ADV_DATA_REQ_HDR_SIZE, (uint8_t)len) < 0 ?
		    IPC_ERR_IO : IPC_ERR_NONE;
		if (error == IPC_ERR_NONE)
			BLUED_PROBE_GAP_ADV_DATA(len);
		break;
	}
	case IPC_ADV_SET_CREATE: {
		uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_ADV_SET_CREATE_REPLY_SIZE];
		int slot, candidate, i;

		if (plen != IPC_ADV_SET_CREATE_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		if (adp == NULL ||
		    (adp->le_features & LE_FEAT_EXT_ADVERTISING) == 0) {
			error = IPC_ERR_NOT_FOUND;
			break;
		}
		for (slot = 0; slot < CTL_ADV_SET_MAX && ctl_adv_sets[slot].used;
		    slot++)
			;
		if (slot == CTL_ADV_SET_MAX) {
			error = IPC_ERR_BUSY;
			break;
		}
		for (candidate = 1; candidate <= 0xef; candidate++) {
			/*
			 * Finding H-M3: the mesh bearer's advertising set
			 * (MESH_ADV_HANDLE, programmed in hci_adv.c) is not
			 * tracked in ext_adv_sets[]/ctl_adv_sets[], so exclude it
			 * explicitly or a client could be handed handle 0x02 and
			 * collide with the mesh set.
			 */
			if (candidate == MESH_ADV_HANDLE)
				continue;
			if (blued_ext_adv_set_used(adp, (uint8_t)candidate))
				continue;
			for (i = 0; i < CTL_ADV_SET_MAX; i++)
				if (ctl_adv_sets[i].used &&
				    ctl_adv_sets[i].handle == candidate)
					break;
			if (i == CTL_ADV_SET_MAX)
				break;
		}
		memset(&ctl_adv_sets[slot], 0, sizeof(ctl_adv_sets[slot]));
		ctl_adv_sets[slot].used = true;
		ctl_adv_sets[slot].handle = (uint8_t)candidate;
		ctl_adv_sets[slot].owner_fd = client->fd;
		ctl_adv_sets[slot].adapter = adp;
		memset(reply, 0, sizeof(reply));
		ipc_op_prefix_encode(reply, client->active_request_id, 0, 0);
		ipc_put_le16(reply + IPC_OP_PREFIX_SIZE, opcode);
		reply[IPC_OP_PREFIX_SIZE + 2] = (uint8_t)candidate;
		ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_ADV, reply,
		    sizeof(reply));
		return;
	}
	case IPC_ADV_SET_HANDLE_PARAMS:
		if (plen != IPC_ADV_SET_PARAMS_REQ_SIZE || payload[7] != 0 ||
		    ipc_get_le16(payload + 10) != 0 ||
		    ipc_get_le32(payload + 12) < 0x20 ||
		    ipc_get_le32(payload + 16) > 0xffffff ||
		    ipc_get_le32(payload + 12) > ipc_get_le32(payload + 16)) {
			error = IPC_ERR_INVAL;
			break;
		}
		handle = payload[4];
		set = ctl_adv_set_owned(client->fd, handle);
		if (set == NULL) {
			error = IPC_ERR_NOT_FOUND;
			break;
		}
		if (hci_le_set_ext_adv_params_phy(set->adapter->hci_fd, handle,
		    ipc_get_le16(payload + 8), ipc_get_le32(payload + 12),
		    ipc_get_le32(payload + 16),
		    set->adapter->privacy ? 0x03 : 0x00, 0,
		    payload[5], payload[6]) < 0)
			error = IPC_ERR_IO;
		else if (blued_adv_set_privacy_prepare(set->adapter, handle) < 0) {
			(void)hci_le_remove_adv_set(set->adapter->hci_fd, handle);
			error = IPC_ERR_IO;
		}
		else if (blued_ext_adv_set_track(set->adapter, handle,
		    ipc_get_le16(payload + 8), ipc_get_le32(payload + 12),
		    ipc_get_le32(payload + 16),
		    set->adapter->privacy ? 0x03 : 0x00, 0,
		    payload[5], payload[6],
		    0x07, 0x7f, 0, NULL) < 0) {
			(void)hci_le_remove_adv_set(set->adapter->hci_fd, handle);
			error = IPC_ERR_BUSY;
		} else
			set->configured = true;
		break;
	case IPC_ADV_SET_HANDLE_DATA: {
		uint8_t len;

		if (plen < IPC_ADV_SET_DATA_REQ_HDR_SIZE || payload[6] != 0 ||
		    payload[7] != 0 ||
		    plen != IPC_ADV_SET_DATA_REQ_HDR_SIZE + (len = payload[5])) {
			error = IPC_ERR_PROTO;
			break;
		}
		set = ctl_adv_set_owned(client->fd, payload[4]);
		if (set == NULL || !set->configured) {
			error = IPC_ERR_NOT_FOUND;
			break;
		}
		error = hci_le_set_ext_adv_data(set->adapter->hci_fd,
		    set->handle, payload + IPC_ADV_SET_DATA_REQ_HDR_SIZE, len) < 0 ?
		    IPC_ERR_IO : IPC_ERR_NONE;
		break;
	}
	case IPC_ADV_SET_HANDLE_ENABLE:
		if (plen != IPC_ADV_SET_STATE_REQ_SIZE || payload[5] > 1 ||
		    ipc_get_le16(payload + 6) != 0) {
			error = IPC_ERR_PROTO;
			break;
		}
		set = ctl_adv_set_owned(client->fd, payload[4]);
		if (set == NULL || !set->configured) {
			error = IPC_ERR_NOT_FOUND;
			break;
		}
		error = hci_le_set_ext_adv_enable(set->adapter->hci_fd,
		    payload[5], set->handle) < 0 ? IPC_ERR_IO : IPC_ERR_NONE;
		if (error == IPC_ERR_NONE)
			blued_ext_adv_set_enabled(set->adapter, set->handle,
			    payload[5] != 0);
		if (error == IPC_ERR_NONE)
			set->enabled = payload[5] != 0;
		break;
	case IPC_ADV_SET_HANDLE_REMOVE:
		if (plen != IPC_ADV_SET_STATE_REQ_SIZE || payload[5] != 0 ||
		    ipc_get_le16(payload + 6) != 0) {
			error = IPC_ERR_PROTO;
			break;
		}
		set = ctl_adv_set_owned(client->fd, payload[4]);
		if (set == NULL) {
			error = IPC_ERR_NOT_FOUND;
			break;
		}
		ctl_adv_set_release(set);
		break;
	default:
		error = IPC_ERR_UNKNOWN_CMD;
		break;
	}
out:
	if (error == IPC_ERR_NONE)
		ctl_send_op_ack(client, IPC_OP_DOMAIN_ADV);
	else
		ctl_send_op_error(client, IPC_OP_DOMAIN_ADV, error,
		    error == IPC_ERR_NOT_FOUND ? "advertising resource not found" :
		    error == IPC_ERR_BUSY ? "advertising resources exhausted" :
		    error == IPC_ERR_PERM ? "peripheral mode not active" :
		    error == IPC_ERR_IO ? "advertising operation failed" :
		    "invalid advertising request");
}

static void
ctl_process_typed_periodic(struct blued_ctl_client *client,
    const uint8_t *payload, size_t plen)
{
	struct blued_adapter *adp;
	struct blued_conn *conn;
	struct ctl_adv_set *set;
	bdaddr_t addr;
	uint16_t opcode, flags, con_handle;
	uint8_t addr_type, adapter_index;
	int error = IPC_ERR_NONE;

	if (!ctl_client_privileged(client)) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_PERIODIC, IPC_ERR_PERM,
		    "permission denied");
		return;
	}
	if (plen < 4) {
		error = IPC_ERR_PROTO;
		goto out;
	}
	opcode = ipc_get_le16(payload);
	flags = ipc_get_le16(payload + 2);
	adapter_index = (uint8_t)(flags >> IPC_OP_ADAPTER_SHIFT);
	if ((flags & IPC_OP_FLAGS_RESERVED_MASK) != 0 ||
	    adapter_index >= BLUED_MAX_ADAPTERS) {
		error = IPC_ERR_INVAL;
		goto out;
	}
	adp = blued_adapter_by_index_powered(adapter_index);
	if (adp == NULL || (adp->le_features & LE_FEAT_PERIODIC_ADV) == 0) {
		error = IPC_ERR_NOT_FOUND;
		goto out;
	}
	switch (opcode) {
	case IPC_PERIODIC_ADV_PARAMS:
		if (plen != IPC_PERIODIC_PARAMS_REQ_SIZE ||
		    ipc_get_le16(payload + 4) < 6 ||
		    ipc_get_le16(payload + 4) > ipc_get_le16(payload + 6) ||
		    ipc_get_le16(payload + 10) != 0) {
			error = IPC_ERR_INVAL;
			break;
		}
		error = hci_le_set_periodic_adv_params(adp->hci_fd, 0,
		    ipc_get_le16(payload + 4), ipc_get_le16(payload + 6),
		    ipc_get_le16(payload + 8)) < 0 ? IPC_ERR_IO : IPC_ERR_NONE;
		if (error == IPC_ERR_NONE)
			BLUED_PROBE_PER_ADV_PARAMS(ipc_get_le16(payload + 4),
			    ipc_get_le16(payload + 6));
		break;
	case IPC_PERIODIC_ADV_DATA: {
		uint16_t len;

		if (plen < IPC_PERIODIC_DATA_REQ_HDR_SIZE ||
		    (len = ipc_get_le16(payload + 4)) > 252 ||
		    ipc_get_le16(payload + 6) != 0 ||
		    plen != IPC_PERIODIC_DATA_REQ_HDR_SIZE + len) {
			error = IPC_ERR_PROTO;
			break;
		}
		error = hci_le_set_periodic_adv_data(adp->hci_fd, 0,
		    payload + IPC_PERIODIC_DATA_REQ_HDR_SIZE, (uint8_t)len) < 0 ?
		    IPC_ERR_IO : IPC_ERR_NONE;
		break;
	}
	case IPC_PERIODIC_ADV_ENABLE:
		if (plen != IPC_PERIODIC_STATE_REQ_SIZE || payload[4] > 1 ||
		    payload[5] != 0 || ipc_get_le16(payload + 6) != 0) {
			error = IPC_ERR_PROTO;
			break;
		}
		error = hci_le_set_periodic_adv_enable(adp->hci_fd, payload[4], 0) < 0 ?
		    IPC_ERR_IO : IPC_ERR_NONE;
		if (error == IPC_ERR_NONE)
			adp->periodic_adv_enabled = payload[4] != 0;
		break;
	case IPC_PERIODIC_SYNC_CREATE:
		if (plen != IPC_PERIODIC_SYNC_CREATE_REQ_SIZE || payload[4] > 1 ||
		    payload[11] > 0x0f || ipc_get_le16(payload + 14) < 0x000a ||
		    ipc_get_le16(payload + 14) > 0x4000) {
			error = IPC_ERR_INVAL;
			break;
		}
		memcpy(&addr, payload + 5, sizeof(addr));
		error = hci_le_periodic_adv_create_sync(adp->hci_fd, 0,
		    payload[11], payload[4], (const uint8_t *)&addr,
		    ipc_get_le16(payload + 12), ipc_get_le16(payload + 14)) < 0 ?
		    IPC_ERR_IO : IPC_ERR_NONE;
		if (error == IPC_ERR_NONE)
			adp->periodic_sync_pending = true;
		break;
	case IPC_PERIODIC_SYNC_CANCEL:
		if (plen != IPC_PERIODIC_SIMPLE_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		error = hci_le_periodic_adv_create_sync_cancel(adp->hci_fd) < 0 ?
		    IPC_ERR_IO : IPC_ERR_NONE;
		if (error == IPC_ERR_NONE)
			adp->periodic_sync_pending = false;
		break;
	case IPC_PERIODIC_SYNC_TERMINATE:
		if (plen != IPC_PERIODIC_STATE_REQ_SIZE ||
		    ipc_get_le16(payload + 4) > 0x0eff ||
		    ipc_get_le16(payload + 6) != 0) {
			error = IPC_ERR_INVAL;
			break;
		}
		error = hci_le_periodic_adv_terminate_sync(adp->hci_fd,
		    ipc_get_le16(payload + 4)) < 0 ? IPC_ERR_IO : IPC_ERR_NONE;
		if (error == IPC_ERR_NONE)
			adp->periodic_syncs[ipc_get_le16(payload + 4) / 8] &=
			    (uint8_t)~(1U << (ipc_get_le16(payload + 4) % 8));
		break;
	case IPC_PERIODIC_LIST_ADD:
	case IPC_PERIODIC_LIST_REMOVE:
		if (plen != IPC_PERIODIC_PEER_REQ_SIZE || payload[4] > 1 ||
		    payload[11] > 0x0f) {
			error = IPC_ERR_INVAL;
			break;
		}
		error = (opcode == IPC_PERIODIC_LIST_ADD ?
		    hci_le_add_dev_to_periodic_adv_list(adp->hci_fd, payload[4],
		    payload + 5, payload[11]) :
		    hci_le_remove_dev_from_periodic_adv_list(adp->hci_fd,
		    payload[4], payload + 5, payload[11])) < 0 ?
		    IPC_ERR_IO : IPC_ERR_NONE;
		break;
	case IPC_PERIODIC_LIST_CLEAR:
		if (plen != IPC_PERIODIC_SIMPLE_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		error = hci_le_clear_periodic_adv_list(adp->hci_fd) < 0 ?
		    IPC_ERR_IO : IPC_ERR_NONE;
		break;
	case IPC_PERIODIC_LIST_SIZE: {
		uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_PERIODIC_SIZE_REPLY_SIZE];
		uint8_t count;

		if (plen != IPC_PERIODIC_SIMPLE_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		if (hci_le_read_periodic_adv_list_size(adp->hci_fd, &count) < 0) {
			error = IPC_ERR_IO;
			break;
		}
		memset(reply, 0, sizeof(reply));
		ipc_op_prefix_encode(reply, client->active_request_id, 0, 0);
		ipc_put_le16(reply + IPC_OP_PREFIX_SIZE, opcode);
		reply[IPC_OP_PREFIX_SIZE + 2] = count;
		ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_PERIODIC,
		    reply, sizeof(reply));
		return;
	}
	case IPC_PERIODIC_PAST_TRANSFER:
	case IPC_PERIODIC_PAST_SET_INFO:
	case IPC_PERIODIC_PAST_PARAMS:
		if ((adp->le_features & (opcode == IPC_PERIODIC_PAST_TRANSFER ||
		    opcode == IPC_PERIODIC_PAST_SET_INFO ? LE_FEAT_PAST_SENDER :
		    LE_FEAT_PAST_RECIPIENT)) == 0) {
			error = IPC_ERR_NOT_FOUND;
			break;
		}
		if ((opcode == IPC_PERIODIC_PAST_PARAMS &&
		    plen != IPC_PERIODIC_PAST_PARAMS_REQ_SIZE) ||
		    (opcode != IPC_PERIODIC_PAST_PARAMS &&
		    plen != IPC_PERIODIC_PAST_TRANSFER_REQ_SIZE) ||
		    payload[4] > 1 || payload[11] != 0) {
			error = IPC_ERR_PROTO;
			break;
		}
		memcpy(&addr, payload + 5, sizeof(addr));
		addr_type = payload[4] == 0 ? BDADDR_LE_PUBLIC : BDADDR_LE_RANDOM;
		conn = blued_conn_by_peer(adp, &addr, addr_type);
		if (conn == NULL || !conn->con_handle_valid) {
			error = IPC_ERR_NOT_CONN;
			break;
		}
		con_handle = conn->con_handle;
		if (opcode == IPC_PERIODIC_PAST_TRANSFER) {
			if (ipc_get_le16(payload + 14) > 0x0eff)
				error = IPC_ERR_INVAL;
			else
				error = hci_le_periodic_adv_sync_transfer(adp->hci_fd,
				    con_handle, ipc_get_le16(payload + 12),
				    ipc_get_le16(payload + 14)) < 0 ? IPC_ERR_IO :
				    IPC_ERR_NONE;
		} else if (opcode == IPC_PERIODIC_PAST_SET_INFO) {
			set = payload[14] == 0 ? NULL :
			    ctl_adv_set_owned(client->fd, payload[14]);
			if (payload[15] != 0 || payload[14] > 0xef ||
			    (payload[14] != 0 && set == NULL))
				error = IPC_ERR_NOT_FOUND;
			else
				error = hci_le_periodic_adv_set_info_transfer(
				    adp->hci_fd, con_handle,
				    ipc_get_le16(payload + 12), payload[14]) < 0 ?
				    IPC_ERR_IO : IPC_ERR_NONE;
		} else if (payload[12] > 3 ||
		    ipc_get_le16(payload + 14) > 0x01f3 ||
		    ipc_get_le16(payload + 16) < 0x000a ||
		    ipc_get_le16(payload + 16) > 0x4000 ||
		    ipc_get_le16(payload + 18) != 0)
			error = IPC_ERR_INVAL;
		else
			error = hci_le_set_past_params(adp->hci_fd, con_handle,
			    payload[12], ipc_get_le16(payload + 14),
			    ipc_get_le16(payload + 16), payload[13]) < 0 ?
			    IPC_ERR_IO : IPC_ERR_NONE;
		break;
	case IPC_PERIODIC_PAST_RECEIVE:
		if ((adp->le_features & LE_FEAT_PAST_RECIPIENT) == 0 ||
		    plen != IPC_PERIODIC_STATE_REQ_SIZE ||
		    ipc_get_le16(payload + 4) > 0x0eff || payload[6] > 1 ||
		    payload[7] != 0) {
			error = IPC_ERR_INVAL;
			break;
		}
		error = hci_le_set_periodic_adv_receive_enable(adp->hci_fd,
		    ipc_get_le16(payload + 4), payload[6]) < 0 ? IPC_ERR_IO :
		    IPC_ERR_NONE;
		break;
	case IPC_PERIODIC_PAST_DEFAULT_PARAMS:
		if ((adp->le_features & LE_FEAT_PAST_RECIPIENT) == 0 ||
		    plen != IPC_PERIODIC_PAST_DEFAULT_REQ_SIZE || payload[4] > 3 ||
		    ipc_get_le16(payload + 6) > 0x01f3 ||
		    ipc_get_le16(payload + 8) < 0x000a ||
		    ipc_get_le16(payload + 8) > 0x4000 ||
		    ipc_get_le16(payload + 10) != 0) {
			error = IPC_ERR_INVAL;
			break;
		}
		error = hci_le_set_default_past_params(adp->hci_fd, payload[4],
		    ipc_get_le16(payload + 6), ipc_get_le16(payload + 8),
		    payload[5]) < 0 ? IPC_ERR_IO : IPC_ERR_NONE;
		break;
	default:
		error = IPC_ERR_UNKNOWN_CMD;
		break;
	}
out:
	if (error == IPC_ERR_NONE)
		ctl_send_op_ack(client, IPC_OP_DOMAIN_PERIODIC);
	else
		ctl_send_op_error(client, IPC_OP_DOMAIN_PERIODIC, error,
		    error == IPC_ERR_NOT_CONN ? "peer not connected" :
		    error == IPC_ERR_NOT_FOUND ? "periodic feature unavailable" :
		    error == IPC_ERR_IO ? "periodic operation failed" :
		    "invalid periodic request");
}

static void
ctl_process_typed_l2cap(struct blued_ctl_client *client,
    const uint8_t *payload, size_t plen)
{
	struct blued_conn *conn;
	bdaddr_t addr;
	uint16_t opcode, flags;
	uint8_t addr_type, count, adapter_index;
	int error = IPC_ERR_NONE;

	if (!ctl_client_privileged(client)) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_L2CAP, IPC_ERR_PERM,
		    "permission denied");
		return;
	}
	if (plen != IPC_L2CAP_REQ_SIZE) {
		error = IPC_ERR_PROTO;
		goto out;
	}
	opcode = ipc_get_le16(payload);
	flags = ipc_get_le16(payload + 2);
	addr_type = payload[4];
	memcpy(&addr, payload + 5, sizeof(addr));
	count = payload[11];
	adapter_index = payload[16];
	if (flags != 0 || !ctl_addr_type_from_ipc(addr_type, &addr_type) ||
	    adapter_index >= BLUED_MAX_ADAPTERS ||
	    ipc_get_le16(payload + 14) != 0) {
		error = IPC_ERR_INVAL;
		goto out;
	}
	switch (opcode) {
	case IPC_L2CAP_ACQUIRE_COC: {
		uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_L2CAP_ACQUIRE_REPLY_SIZE];
		struct blued_adapter *adp;
		size_t handout_len;
		int fds[5], opened;

		if (!client->wants_fdpass) {
			error = IPC_ERR_PERM;
			break;
		}
		if (cap_sandboxed()) {
			error = IPC_ERR_PERM;
			break;
		}
		if (count < 1 || count > 5 || ipc_get_le16(payload + 12) == 0) {
			error = IPC_ERR_INVAL;
			break;
		}
		handout_len = IPC_HDR_SIZE + sizeof(reply) + count;
		if (!ctl_tx_has_room(client, handout_len)) {
			error = IPC_ERR_IO;
			break;
		}
		adp = blued_adapter_by_index_powered(adapter_index);
		if (adp == NULL || !adp->active) {
			error = IPC_ERR_NOT_FOUND;
			break;
		}
		opened = ble_ecbfc_connect((const uint8_t *)&adp->addr,
		    (const uint8_t *)&addr, addr_type,
		    ipc_get_le16(payload + 12), 0, count, fds);
		if (opened <= 0) {
			error = IPC_ERR_IO;
			break;
		}
		memset(reply, 0, sizeof(reply));
		ipc_op_prefix_encode(reply, client->active_request_id, 0, 0);
		ipc_put_le16(reply + IPC_OP_PREFIX_SIZE, opcode);
		reply[IPC_OP_PREFIX_SIZE + 2] = (uint8_t)opened;
		for (int i = 0; i < opened; i++) {
			uint16_t omtu = 0;
			socklen_t olen = sizeof(omtu);

			(void)getsockopt(fds[i], SOL_L2CAP, SO_L2CAP_OMTU,
			    &omtu, &olen);
			ipc_put_le16(reply + IPC_OP_PREFIX_SIZE + 4 + i * 2,
			    omtu);
		}
		if (ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_L2CAP,
		    reply, sizeof(reply)) < 0) {
			error = IPC_ERR_IO;
			for (int i = 0; i < opened; i++)
				close(fds[i]);
			break;
		}
		for (int i = 0; i < opened; i++) {
			if (ctl_send_ecbfc_fd_to_client(client, fds[i]) < 0)
				error = IPC_ERR_IO;
			close(fds[i]);
		}
		return;
	}
	case IPC_L2CAP_EATT_OPEN:
		if (count < 1 || count > ATT_MAX_EATT_BEARERS ||
		    ipc_get_le32(payload + 12) != 0) {
			error = IPC_ERR_INVAL;
			break;
		}
		if (cap_sandboxed()) {
			error = IPC_ERR_PERM;
			break;
		}
		conn = blued_conn_by_peer(blued_adapter_by_index_powered(adapter_index),
		    &addr, addr_type);
		if (conn == NULL || conn->att == NULL) {
			error = IPC_ERR_NOT_CONN;
			break;
		}
		if (!conn->att->encrypted) {
			error = IPC_ERR_PERM;
			break;
		}
		if (conn->att->eatt_count != 0) {
			error = IPC_ERR_BUSY;
			break;
		}
		if (atomic_load_explicit(&conn->att_ops_active,
		    memory_order_acquire) != 0) {
			error = IPC_ERR_BUSY;
			break;
		}
		error = att_open_eatt(conn->att,
		    (const uint8_t *)&conn->adapter->addr, (const uint8_t *)&addr,
		    addr_type,
		    count) <= 0 ? IPC_ERR_IO : IPC_ERR_NONE;
		if (error == IPC_ERR_NONE) {
			int i;

			for (i = 0; i < conn->att->eatt_count; i++) {
				if (blued_conn_register_bearer(conn,
				    conn->att->eatt[i].fd) < 0)
					break;
			}
			if (i != conn->att->eatt_count) {
				while (i-- > 0)
					blued_conn_unregister_bearer(
					    conn->att->eatt[i].fd);
				att_close_eatt(conn->att);
				error = IPC_ERR_IO;
			}
		}
		break;
	case IPC_L2CAP_EATT_CLOSE:
		if (count != 0 || ipc_get_le32(payload + 12) != 0) {
			error = IPC_ERR_INVAL;
			break;
		}
		conn = blued_conn_by_peer(blued_adapter_by_index_powered(adapter_index),
		    &addr, addr_type);
		if (conn == NULL || conn->att == NULL) {
			error = IPC_ERR_NOT_CONN;
			break;
		}
		for (int i = 0; i < conn->att->eatt_count; i++)
			blued_conn_unregister_bearer(conn->att->eatt[i].fd);
		att_close_eatt(conn->att);
		break;
	default:
		error = IPC_ERR_UNKNOWN_CMD;
		break;
	}
out:
	if (error == IPC_ERR_NONE)
		ctl_send_op_ack(client, IPC_OP_DOMAIN_L2CAP);
	else
		ctl_send_op_error(client, IPC_OP_DOMAIN_L2CAP, error,
		    error == IPC_ERR_NOT_CONN ? "device not connected" :
		    error == IPC_ERR_BUSY ? "EATT already open" :
		    error == IPC_ERR_IO ? "L2CAP operation failed" :
		    error == IPC_ERR_PERM ? "L2CAP operation not permitted" :
		    "invalid L2CAP request");
}

static struct blued_adapter *
ctl_typed_adapter_any(uint16_t flags, uint32_t arg1, bool *bad)
{
	struct blued_adapter *adp;

	*bad = false;
	if ((flags & IPC_CTL_F_ADAPTER) == 0) {
		LIST_FOREACH(adp, &blued_g.adapters, entries)
			if (adp->active)
				return (adp);
		return (NULL);
	}
	if (arg1 > INT_MAX) {
		*bad = true;
		return (NULL);
	}
	LIST_FOREACH(adp, &blued_g.adapters, entries)
		if (adp->active && adp->index == (int)arg1)
			return (adp);
	return (NULL);
}

static struct blued_adapter *
ctl_typed_adapter(uint16_t flags, uint32_t arg1, bool *bad)
{
	struct blued_adapter *adp;

	if ((flags & IPC_CTL_F_ADAPTER) == 0) {
		*bad = false;
		LIST_FOREACH(adp, &blued_g.adapters, entries)
			if (adp->active && adp->powered &&
			    !adp->power_quiescing)
				return (adp);
		return (NULL);
	}
	adp = ctl_typed_adapter_any(flags, arg1, bad);
	return (adp != NULL && adp->powered && !adp->power_quiescing ?
	    adp : NULL);
}

static void
ctl_process_typed_ctl(struct blued_ctl_client *client, const uint8_t *payload,
    size_t plen)
{
	struct blued_adapter *adp;
	uint16_t opcode, flags, err;
	uint32_t arg0, arg1;
	bool on, bad;

	if (plen != IPC_CTL_REQ_SIZE) {
		ctl_send_ctl_error(client, IPC_ERR_PROTO,
		    "typed control payload has wrong size");
		return;
	}
	ipc_ctl_req_decode(payload, &opcode, &flags, &arg0, &arg1);
	if ((flags & ~(IPC_CTL_F_BOOL | IPC_CTL_F_ADAPTER |
	    IPC_CTL_F_LIMITED)) != 0) {
		ctl_send_ctl_error(client, IPC_ERR_INVAL,
		    "unknown typed control flag");
		return;
	}
	if (opcode == IPC_CTL_STATUS) {
		if (flags != 0 || arg0 != 0 || arg1 != 0) {
			ctl_send_ctl_error(client, IPC_ERR_INVAL,
			    "invalid STATUS request");
			return;
		}
		ctl_send_status_reply(client);
		return;
	}
	if (opcode == IPC_CTL_ADAPTER_CAPS) {
		if (flags != 0 || arg0 > UINT16_MAX || arg1 != 0) {
			ctl_send_ctl_error(client, IPC_ERR_INVAL,
			    "invalid ADAPTER_CAPS request");
			return;
		}
		ctl_send_adapter_caps_reply(client, (uint16_t)arg0);
		return;
	}
	if (!ctl_client_privileged(client)) {
		ctl_send_ctl_error(client, IPC_ERR_PERM, "permission denied");
		return;
	}
	/*
	 * SET_MTU and the staged GATT database transaction are daemon-global;
	 * they remain usable before an adapter is powered.  Only operations that
	 * actually issue controller commands require a live powered adapter here.
	 */
	if (opcode != IPC_CTL_POWER && opcode != IPC_CTL_SET_MTU &&
	    opcode != IPC_CTL_GATT_BEGIN && opcode != IPC_CTL_GATT_COMMIT &&
	    opcode != IPC_CTL_GATT_ROLLBACK) {
		adp = ctl_typed_adapter(flags, arg1, &bad);
		if (adp == NULL || !adp->powered || adp->power_quiescing) {
			ctl_send_ctl_error(client, IPC_ERR_NOT_FOUND,
			    "adapter is powered off");
			return;
		}
	}
	switch (opcode) {
	case IPC_CTL_POWER:
		if ((flags & IPC_CTL_F_BOOL) == 0 ||
		    (flags & IPC_CTL_F_LIMITED) != 0 ||
		    ((flags & IPC_CTL_F_ADAPTER) == 0 && arg1 != 0) ||
		    arg0 > 1) {
			ctl_send_ctl_error(client, IPC_ERR_INVAL,
			    "invalid POWER request");
			return;
		}
		on = (arg0 != 0);
		adp = ctl_typed_adapter_any(flags, arg1, &bad);
		if (bad) {
			ctl_send_ctl_error(client, IPC_ERR_INVAL,
			    "invalid adapter");
			return;
		}
		if (adp == NULL) {
			ctl_send_ctl_error(client, IPC_ERR_NOT_FOUND,
			    "no active adapter");
			return;
		}
		if (blued_adapter_set_power(adp, on) < 0) {
			ctl_send_ctl_error(client, IPC_ERR_IO,
			    "power operation failed");
			return;
		}
		ctl_send_ctl_ack(client, opcode, flags, adp->powered ? 1 : 0);
		break;
	case IPC_CTL_PRIVACY: {
		struct blued_adapter *changed[BLUED_MAX_ADAPTERS];
		struct blued_adapter *iter;
		bool old_privacy;
		size_t nchanged;

		if ((flags & IPC_CTL_F_BOOL) == 0 ||
		    (flags & IPC_CTL_F_LIMITED) != 0 ||
		    ((flags & IPC_CTL_F_ADAPTER) == 0 && arg1 != 0) ||
		    arg0 > 1) {
			ctl_send_ctl_error(client, IPC_ERR_INVAL,
			    "invalid PRIVACY request");
			return;
		}
		on = (arg0 != 0);
		adp = ctl_typed_adapter(flags, arg1, &bad);
		if (bad || adp == NULL) {
			ctl_send_ctl_error(client, bad ? IPC_ERR_INVAL :
			    IPC_ERR_NOT_FOUND, bad ? "invalid adapter" :
			    "no active adapter");
			return;
		}
		/*
		 * Privacy is daemon-global: scanning, advertising and the initiating
		 * L2CAP policy must not disagree by controller.  Program every active
		 * adapter first, rolling earlier adapters back if any controller fails;
		 * publish configuration and initiator policy only after full success.
		 */
		old_privacy = blued_cfg.privacy;
		nchanged = 0;
		LIST_FOREACH(iter, &blued_g.adapters, entries) {
			if (!iter->active)
				continue;
			if (!iter->powered || iter->power_quiescing) {
				ctl_send_ctl_error(client, IPC_ERR_NOT_FOUND,
				    "adapter is powered off");
				return;
			}
			if (blued_adapter_set_privacy(iter, on) < 0) {
				while (nchanged != 0)
					(void)blued_adapter_set_privacy(
					    changed[--nchanged], old_privacy);
				ctl_send_ctl_error(client, IPC_ERR_IO,
				    "privacy operation failed");
				return;
			}
			changed[nchanged++] = iter;
		}
		blued_cfg.privacy = on;
		hci_l2cap_set_own_address_type(on ? 0x03 : 0x00);
		for (size_t i = 0; i < nchanged; i++)
			changed[i]->privacy = on;
		ctl_send_ctl_ack(client, opcode, flags, on ? 1 : 0);
		break;
	}
	case IPC_CTL_SET_MTU:
		if (flags != 0 || arg1 != 0 ||
		    arg0 < ATT_DEFAULT_MTU || arg0 > ATT_PDU_BUF_SIZE) {
			ctl_send_ctl_error(client, IPC_ERR_INVAL,
			    "mtu out of range");
			return;
		}
		blued_g.att_preferred_mtu = (uint16_t)arg0;
		ctl_send_ctl_ack(client, opcode, flags, arg0);
		break;
	case IPC_CTL_GATT_BEGIN:
		if (flags != 0 || arg0 != 0 || arg1 != 0) {
			ctl_send_ctl_error(client, IPC_ERR_INVAL,
			    "invalid GATT_BEGIN request");
			return;
		}
		pthread_mutex_lock(&blued_g.gatt_db_lock);
		err = (uint16_t)ctl_gatt_begin_result(client->fd);
		pthread_mutex_unlock(&blued_g.gatt_db_lock);
		if (err != 0) {
			ctl_send_ctl_error(client, err,
			    "GATT_BEGIN failed");
			return;
		}
		ctl_send_ctl_ack(client, opcode, flags, 0);
		break;
	case IPC_CTL_GATT_COMMIT:
		if (flags != 0 || arg0 != 0 || arg1 != 0) {
			ctl_send_ctl_error(client, IPC_ERR_INVAL,
			    "invalid GATT_COMMIT request");
			return;
		}
		pthread_mutex_lock(&blued_g.gatt_db_lock);
		err = (uint16_t)ctl_gatt_commit_result(client->fd);
		pthread_mutex_unlock(&blued_g.gatt_db_lock);
		if (err != 0) {
			ctl_send_ctl_error(client, err,
			    "GATT_COMMIT failed");
			return;
		}
		ctl_send_ctl_ack(client, opcode, flags, 0);
		break;
	case IPC_CTL_GATT_ROLLBACK:
		if (flags != 0 || arg0 != 0 || arg1 != 0) {
			ctl_send_ctl_error(client, IPC_ERR_INVAL,
			    "invalid GATT_ROLLBACK request");
			return;
		}
		pthread_mutex_lock(&blued_g.gatt_db_lock);
		err = (uint16_t)ctl_gatt_rollback_result(client->fd);
		pthread_mutex_unlock(&blued_g.gatt_db_lock);
		if (err != 0) {
			ctl_send_ctl_error(client, err,
			    "GATT_ROLLBACK failed");
			return;
		}
		ctl_send_ctl_ack(client, opcode, flags, 0);
		break;
	case IPC_CTL_ADVERTISE:
		if ((flags & IPC_CTL_F_BOOL) == 0 ||
		    (flags & (IPC_CTL_F_ADAPTER | IPC_CTL_F_LIMITED)) != 0 ||
		    arg0 > 1 || arg1 != 0) {
			ctl_send_ctl_error(client, IPC_ERR_INVAL,
			    "ADVERTISE requires only boolean flag");
			return;
		}
		on = (arg0 != 0);
		adp = ctl_typed_adapter(0, 0, &bad);
		if (adp == NULL) {
			ctl_send_ctl_error(client, IPC_ERR_NOT_FOUND,
			    "no active adapter");
			return;
		}
		if (!blued_g.periph_active) {
			ctl_send_ctl_error(client, IPC_ERR_PERM,
			    "peripheral mode not active");
			return;
		}
		if (adp->disc_saved_valid) {
			adp->disc_saved_enabled = on;
			ctl_send_ctl_ack(client, opcode, flags, on ? 1 : 0);
			break;
		}
		if (adp->adv_configured ? adp->adv_use_extended :
		    (adp->le_features & LE_FEAT_EXT_ADVERTISING) != 0) {
			if (hci_le_set_ext_adv_enable(adp->hci_fd,
			    on ? 1 : 0, 0x00) < 0) {
				ctl_send_ctl_error(client, IPC_ERR_IO,
				    "advertising operation failed");
				return;
			}
		} else if (hci_le_set_advertise_enable(adp->hci_fd,
		    on) < 0) {
			ctl_send_ctl_error(client, IPC_ERR_IO,
			    "advertising operation failed");
			return;
		}
			BLUED_PROBE_GAP_ADV_ENABLE(on ? 1 : 0, 0);
			adp->adv_enabled = on;
			if (!on) {
				adp->rpa_restore_legacy = false;
				adp->rpa_restore_primary = false;
			}
		ctl_send_ctl_ack(client, opcode, flags, on ? 1 : 0);
		break;
	case IPC_CTL_DISCOVERABLE:
		if ((flags & IPC_CTL_F_BOOL) == 0 ||
		    (flags & ~(IPC_CTL_F_BOOL | IPC_CTL_F_LIMITED)) != 0 ||
		    arg0 > 1 || arg1 > 3600 ||
		    ((flags & IPC_CTL_F_LIMITED) != 0 && arg0 == 0)) {
			ctl_send_ctl_error(client, IPC_ERR_INVAL,
			    "invalid DISCOVERABLE request");
			return;
		}
		on = (arg0 != 0);
		adp = ctl_typed_adapter(0, 0, &bad);
		if (adp == NULL) {
			ctl_send_ctl_error(client, IPC_ERR_NOT_FOUND,
			    "no active adapter");
			return;
		}
		if (on && !blued_g.periph_active) {
			ctl_send_ctl_error(client, IPC_ERR_PERM,
			    "peripheral mode not active");
			return;
		}
		if (blued_adapter_set_discoverable(adp, on,
		    (flags & IPC_CTL_F_LIMITED) != 0,
		    (unsigned int)arg1) < 0) {
			ctl_send_ctl_error(client, IPC_ERR_IO,
			    "discoverable operation failed");
			return;
		}
		ctl_send_ctl_ack(client, opcode, flags,
		    adp->discoverable ? 1 : 0);
		break;
	case IPC_CTL_PAIRABLE:
		if ((flags & IPC_CTL_F_BOOL) == 0 ||
		    (flags & (IPC_CTL_F_ADAPTER | IPC_CTL_F_LIMITED)) != 0 ||
		    arg0 > 1 || arg1 != 0) {
			ctl_send_ctl_error(client, IPC_ERR_INVAL,
			    "PAIRABLE requires only boolean flag");
			return;
		}
		atomic_store(&blued_pairable, arg0 != 0);
		ctl_send_ctl_ack(client, opcode, flags,
		    atomic_load(&blued_pairable) ? 1 : 0);
		break;
	case IPC_CTL_RPA_TIMEOUT:
		if (arg0 < 1 || arg0 > 3600 ||
		    (flags & (IPC_CTL_F_BOOL | IPC_CTL_F_LIMITED)) != 0 ||
		    ((flags & IPC_CTL_F_ADAPTER) == 0 && arg1 != 0)) {
			ctl_send_ctl_error(client, IPC_ERR_INVAL,
			    "invalid RPA_TIMEOUT request");
			return;
		}
		adp = ctl_typed_adapter(flags, arg1, &bad);
		if (bad) {
			ctl_send_ctl_error(client, IPC_ERR_INVAL,
			    "invalid adapter");
			return;
		}
		if (adp == NULL) {
			ctl_send_ctl_error(client, IPC_ERR_NOT_FOUND,
			    "no active adapter");
			return;
		}
		if (blued_set_rpa_timeout((int)arg0) < 0) {
			ctl_send_ctl_error(client, IPC_ERR_IO,
			    "set RPA timeout failed");
			return;
		}
		ctl_send_ctl_ack(client, opcode, flags, arg0);
		break;
	default:
		ctl_send_ctl_error(client, IPC_ERR_UNKNOWN_CMD,
		    "unknown typed control opcode");
		break;
	}
}

/*
 * Process one complete framed message from a client.
 */
static void
ctl_process_frame(struct blued_ctl_client *client, uint16_t type,
    uint16_t arg, const uint8_t *payload, size_t plen)
{

	switch (type) {
	case IPC_T_HELLO:
		ctl_process_hello(client, arg, payload, plen);
		break;
	case IPC_T_OP_REQ: {
		uint32_t request_id;
		uint16_t status, flags;

		/*
		 * The HELLO handshake is the only defense against struct-layout
		 * skew (ipc_proto.h): a client that never handshaked, or whose
		 * version was rejected (ctl_process_hello leaves handshaked
		 * false), must not have its operation frames dispatched
		 * (finding 35).
		 */
		if (!client->handshaked) {
			ctl_send_frame(client, IPC_T_ERROR, IPC_ERR_PROTO,
			    "handshake required",
			    sizeof("handshake required") - 1);
			break;
		}
		if (plen < IPC_OP_PREFIX_SIZE) {
			ctl_send_frame(client, IPC_T_ERROR, IPC_ERR_PROTO,
			    "operation prefix missing",
			    sizeof("operation prefix missing") - 1);
			break;
		}
		ipc_op_prefix_decode(payload, &request_id, &status, &flags);
		if (request_id == 0 || status != 0 ||
		    flags != 0) {
			ctl_send_frame(client, IPC_T_ERROR, IPC_ERR_PROTO,
			    "invalid operation envelope",
			    sizeof("invalid operation envelope") - 1);
			break;
		}
		client->active_request_id = request_id;
		if (arg == IPC_OP_DOMAIN_CTL)
			ctl_process_typed_ctl(client, payload + IPC_OP_PREFIX_SIZE,
			    plen - IPC_OP_PREFIX_SIZE);
		else if (arg == IPC_OP_DOMAIN_GAP)
			ctl_process_typed_gap(client, payload + IPC_OP_PREFIX_SIZE,
			    plen - IPC_OP_PREFIX_SIZE);
		else if (arg == IPC_OP_DOMAIN_GATT)
			ctl_process_typed_gatt(client, payload + IPC_OP_PREFIX_SIZE,
			    plen - IPC_OP_PREFIX_SIZE);
		else if (arg == IPC_OP_DOMAIN_SECURITY)
			ctl_process_typed_security(client,
			    payload + IPC_OP_PREFIX_SIZE,
			    plen - IPC_OP_PREFIX_SIZE);
		else if (arg == IPC_OP_DOMAIN_ADV)
			ctl_process_typed_adv(client, payload + IPC_OP_PREFIX_SIZE,
			    plen - IPC_OP_PREFIX_SIZE);
		else if (arg == IPC_OP_DOMAIN_PERIODIC)
			ctl_process_typed_periodic(client,
			    payload + IPC_OP_PREFIX_SIZE,
			    plen - IPC_OP_PREFIX_SIZE);
		else if (arg == IPC_OP_DOMAIN_L2CAP)
			ctl_process_typed_l2cap(client,
			    payload + IPC_OP_PREFIX_SIZE,
			    plen - IPC_OP_PREFIX_SIZE);
		else if (arg == IPC_OP_DOMAIN_ISO)
			ctl_iso_process_typed(client, payload + IPC_OP_PREFIX_SIZE,
			    plen - IPC_OP_PREFIX_SIZE);
		else if (arg == IPC_OP_DOMAIN_MESH)
			ctl_process_typed_mesh(client,
			    payload + IPC_OP_PREFIX_SIZE,
			    plen - IPC_OP_PREFIX_SIZE);
		else
			ctl_send_op_error(client, arg, IPC_ERR_UNKNOWN_CMD,
			    "unknown operation domain");
		client->active_request_id = 0;
		break;
	}
	default:
		ctl_send_frame(client, IPC_T_ERROR, IPC_ERR_PROTO,
		    "unsupported frame type",
		    sizeof("unsupported frame type") - 1);
		break;
	}
}

/*
 * Framed dispatch path: read bytes, decode as many complete length-prefixed
 * frames as are available, and process each one.
 */
static int
ctl_dispatch_framed(struct blued_ctl_client *client)
{
	ssize_t n;
	size_t avail;

	avail = sizeof(client->rxbuf) - client->rxlen;
	if (avail == 0) {
		/* Header claimed more than fits: desynced, drop and error. */
		static const char m[] = "frame too large";

		client->rxlen = 0;
		ctl_send_frame(client, IPC_T_ERROR, IPC_ERR_PROTO,
		    m, sizeof(m) - 1);
		return (0);
	}

	n = recv(client->fd, client->rxbuf + client->rxlen, avail, 0);
	if (n == 0)
		return (-1);
	if (n < 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return (0);
		return (-1);
	}
	client->rxlen += (size_t)n;

	for (;;) {
		uint32_t plen;
		uint16_t type, arg;

		if (client->rxlen < IPC_HDR_SIZE)
			break;
		ipc_hdr_decode(client->rxbuf, &plen, &type, &arg);
		if (plen > IPC_MAX_PAYLOAD) {
			static const char m[] = "frame too large";

			client->rxlen = 0;
			ctl_send_frame(client, IPC_T_ERROR, IPC_ERR_PROTO,
			    m, sizeof(m) - 1);
			break;
		}
		if (client->rxlen < IPC_HDR_SIZE + plen)
			break;	/* wait for the rest of the frame */

		ctl_process_frame(client, type, arg,
		    client->rxbuf + IPC_HDR_SIZE, plen);

		{
			size_t consumed = IPC_HDR_SIZE + plen;
			size_t remain = client->rxlen - consumed;

			if (remain > 0)
				memmove(client->rxbuf,
				    client->rxbuf + consumed, remain);
			client->rxlen = remain;
		}
	}
	return (0);
}

/*
 * Dispatch a control command from a client.
 *
 * The daemon speaks the length-prefixed binary protocol only (see
 * ipc_proto.h): a client upgrades a fresh connection with a HELLO frame and
 * then exchanges CMD/REPLY/EVENT frames.  A peer that sends bytes which do not
 * form valid frames is rejected with an IPC_ERR_PROTO frame and its buffer is
 * reset (see ctl_dispatch_framed()).
 */
int
blued_ctl_dispatch(struct blued_ctl_client *client)
{

	return (ctl_dispatch_framed(client));
}

/*
 * Initialize the control socket.
 * Creates a Unix domain stream socket, binds, listens, and registers
 * with the global kqueue.  Must be called before cap_enter().
 */
int
blued_ctl_init(const char *path)
{
	struct sockaddr_un sun;
	struct kevent kev;
	int fd;

	fd = socket(AF_UNIX,
	    SOCK_STREAM | SOCK_CLOEXEC | SOCK_CLOFORK | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return (-1);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlen(path) >= sizeof(sun.sun_path)) {
		warnx("control socket path too long");
		close(fd);
		return (-1);
	}
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

	/* Remove only a proven-dead socket; never displace a live daemon. */
	if (ctl_unlink_stale_socket(path) != 0) {
		close(fd);
		return (-1);
	}

	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		close(fd);
		return (-1);
	}

	/*
	 * Restrict the control socket to owner + group (0660).
	 * The expected group is "wheel" (default) or a dedicated
	 * "bluetooth" group if the admin has configured one.
	 * bluedctl and other management tools must run as root
	 * or be in the matching group to connect.
	 */
	if (chmod(path, 0660) < 0) {
		close(fd);
		(void)unlink(path);
		return (-1);
	}

	if (listen(fd, BLUED_MAX_CTL) < 0) {
		close(fd);
		(void)unlink(path);
		return (-1);
	}

	/* Register with kqueue — use sentinel so blued_handle_readable()
	 * can identify the control socket listener */
	blued_g.ctl_fd = fd;
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0,
	    BLUED_KQ_CTL_LISTEN);
	if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0) {
		close(fd);
		(void)unlink(path);
		blued_g.ctl_fd = -1;
		return (-1);
	}
	if (ctl_gatt_workers_start() < 0) {
		close(fd);
		(void)unlink(path);
		blued_g.ctl_fd = -1;
		return (-1);
	}

	/* Save path for cleanup */
	ctl_sock_path = strdup(path);
	if (ctl_sock_path == NULL) {
		/*
		 * Do not leave an active listener whose pathname cannot be removed
		 * during normal shutdown.  This is after worker startup, so undo the
		 * complete control-plane setup before reporting ENOMEM.
		 */
		ctl_gatt_workers_stop();
		close(fd);
		blued_g.ctl_fd = -1;
		(void)unlink(path);
		errno = ENOMEM;
		return (-1);
	}

	LOG_HCI(1, "control socket: %s", path);
	return (0);
}

/*
 * Reset owner_fd for all GATT attributes owned by a disconnected client.
 * Called when a ctl client disconnects so that stale fds are not retained.
 */
void
blued_ctl_reset_owner(int client_fd)
{
	struct att_db *db = &periph_gatt_db;
	int i;

	ctl_gatt_jobs_cancel_client(client_fd);

	/* C3-M9: drop any pending ISO CIS fd handout aimed at this client. */
	blued_iso_client_gone(client_fd);

	for (i = 0; i < CTL_ADV_SET_MAX; i++)
		if (ctl_adv_sets[i].used && ctl_adv_sets[i].owner_fd == client_fd)
			ctl_adv_set_release(&ctl_adv_sets[i]);

	/*
	 * A departed client cannot answer prompts nor finish a staged GATT
	 * application: drop its agent registration (so pairings fall back to
	 * static config rather than stalling) and roll back any open GATT
	 * transaction it owns (freeing the scratch DB, live DB untouched).
	 */
	ctl_agent_client_gone(client_fd);

	pthread_mutex_lock(&blued_g.gatt_db_lock);
	for (i = 0; i < db->count; i++) {
		if (db->attrs[i].owner_fd == client_fd)
			db->attrs[i].owner_fd = -1;
	}
	ctl_gatt_txn_client_gone(client_fd);
	pthread_mutex_unlock(&blued_g.gatt_db_lock);

	/*
	 * Fail any access still deferred on this client's characteristics: with
	 * the authorizing/serving app gone the peer would otherwise wait out the
	 * full transaction timeout.  Answer now and release the bearer.
	 */
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	{
		struct blued_conn *conn;

		LIST_FOREACH(conn, &blued_g.conns, entries) {
			struct att_conn *ac = conn->att;

			if (conn->role != BLUED_ROLE_PERIPHERAL || ac == NULL)
				continue;
			if (!att_server_pending_active(ac) ||
			    att_server_pending_owner(ac) != client_fd)
				continue;
			if (att_server_pending_is_read(ac))
				att_server_reject_read(ac,
				    ATT_ERR_UNLIKELY_ERROR);
			else
				att_server_complete_authorize(ac,
				    conn->gatt_db, false);
		}
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
}

/*
 * Finding C-m1: re-enable the control-socket listener after the fd-exhaustion
 * backoff timer (BLUED_KQ_CTL_ACCEPT_RETRY) fires.  The one-shot timer is
 * already consumed; just re-arm the read filter.
 */
void
blued_ctl_accept_retry_enable(void)
{
	struct kevent kev;

	if (blued_g.kq < 0 || blued_g.ctl_fd < 0)
		return;
	EV_SET(&kev, blued_g.ctl_fd, EVFILT_READ, EV_ENABLE, 0, 0,
	    BLUED_KQ_CTL_LISTEN);
	(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
}

/*
 * Accept a new control client connection.
 */
void
blued_ctl_accept(void)
{
	struct blued_ctl_client *client;
	struct kevent kev;
	int fd, nclients;
	uid_t peer_uid = 0;
	gid_t peer_gid = 0;
	bool peer_known = false;

	fd = accept4(blued_g.ctl_fd, NULL, NULL,
	    SOCK_CLOEXEC | SOCK_CLOFORK | SOCK_NONBLOCK);
	if (fd < 0) {
		/*
		 * Finding C-m1: the listener is level-triggered, so on fd
		 * exhaustion (EMFILE/ENFILE) accept4 keeps failing and the event
		 * loop re-enters here at 100% CPU.  Disable the listener's read
		 * filter and arm a one-shot timer to re-enable it, giving fds a
		 * chance to be released first.
		 */
		if (errno == EMFILE || errno == ENFILE) {
			struct kevent retry_events[2];
			/*
			 * C3-M2: the retry timer must NOT use ctl_fd as its
			 * EVFILT_TIMER ident.  Connection/idle/reconnect timers
			 * are keyed by blued_next_timer_id (from 1), which lives
			 * in the same small-integer space as fds; a timer whose
			 * ident equals ctl_fd would collide with a connection
			 * timer on (ident, EVFILT_TIMER), so EV_ADD would modify
			 * the existing knote — clobbering a conn's disconnect
			 * timer or having the retry timer overwritten.  Draw a
			 * dedicated ident from blued_next_timer_id (allocated
			 * once) so it can never alias another timer.
			 */
			static uintptr_t accept_retry_timer_id;

			if (accept_retry_timer_id == 0)
				accept_retry_timer_id = blued_next_timer_id++;
			EV_SET(&retry_events[0], blued_g.ctl_fd, EVFILT_READ,
			    EV_DISABLE,
			    0, 0, BLUED_KQ_CTL_LISTEN);
			EV_SET(&retry_events[1], accept_retry_timer_id,
			    EVFILT_TIMER,
			    EV_ADD | EV_ONESHOT, NOTE_SECONDS, 1,
			    BLUED_KQ_CTL_ACCEPT_RETRY);
			(void)kevent(blued_g.kq, retry_events,
			    nitems(retry_events), NULL, 0, NULL);
		}
		return;
	}

	/*
	 * Record the peer's credentials for per-command privilege tiers.
	 * This MUST happen before the fd is capability-limited below, since
	 * getpeereid() is implemented via getsockopt(LOCAL_PEERCRED) and the
	 * capability restriction strips CAP_GETSOCKOPT from the accepted fd.
	 */
	{
		uid_t uid;
		gid_t gid;

		if (getpeereid(fd, &uid, &gid) == 0) {
			peer_uid = uid;
			peer_gid = gid;
			peer_known = true;
		}
	}

	/* Capability-limit accepted client fd to send/recv/event only */
	{
		cap_rights_t rights;

		cap_rights_init(&rights, CAP_RECV, CAP_SEND, CAP_EVENT);
		(void)cap_rights_limit(fd, &rights);
		(void)cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED);
		(void)cap_clofork_limit(fd, CAP_CLOFORK_LOCKED);
		(void)cap_xfer_limit(fd, CAP_XFER_ONCE);
	}

	/* Enforce maximum control client count to prevent fd exhaustion */
	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	nclients = 0;
	LIST_FOREACH(client, &blued_g.ctl_clients, entries)
		nclients++;
	if (nclients >= BLUED_MAX_CTL) {
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		LOG_HCI(1, "control socket: max clients (%d) reached, "
		    "rejecting", BLUED_MAX_CTL);
		close(fd);
		return;
	}

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		close(fd);
		return;
	}
	client->fd = fd;
	client->generation = atomic_fetch_add(&ctl_client_generation, 1);
	STAILQ_INIT(&client->txq);
	client->peer_uid = peer_uid;
	client->peer_gid = peer_gid;
	client->peer_known = peer_known;

	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);

	/* Register for read events */
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, client);
	if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0) {
		pthread_mutex_lock(&blued_g.ctl_clients_lock);
		LIST_REMOVE(client, entries);
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		close(fd);
		blued_ctl_client_fini(client);
		free(client);
	} else
		client->kq_registered = true;
}

/*
 * Clean up the control socket and all connected clients.
 */
void
blued_ctl_cleanup(void)
{
	struct blued_ctl_client *client, *tmp;

	/* Workers can reference clients while sending terminal replies. */
	ctl_gatt_workers_stop();

	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH_SAFE(client, &blued_g.ctl_clients, entries, tmp) {
		close(client->fd);
		LIST_REMOVE(client, entries);
		blued_ctl_client_fini(client);
		free(client);
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);

	if (blued_g.ctl_fd >= 0) {
		close(blued_g.ctl_fd);
		blued_g.ctl_fd = -1;
	}

	if (ctl_sock_path != NULL) {
		(void)unlink(ctl_sock_path);
		free(ctl_sock_path);
		ctl_sock_path = NULL;
	}
}
