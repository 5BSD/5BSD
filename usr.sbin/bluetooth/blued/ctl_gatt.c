/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * blued control socket — GATT-related commands.
 *
 * Commands handled here:
 *   SERVICES, DISCOVER, READ, WRITE, WRITE_CMD, SUBSCRIBE,
 *   UNSUBSCRIBE, ADD_SERVICE, ADD_INCLUDE, ADD_CHAR, ADD_DESC,
 *   REMOVE_SERVICE, NOTIFY, INDICATE
 */

#include <sys/capsicum.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "blued.h"
#include "blued_internal.h"
#include "blued_probes.h"
#include "config.h"
#include "conn.h"
#include "ctl.h"
#include "ctl_internal.h"
#include "gatt.h"
#include "hci_util.h"
#include "ipc_proto.h"
#include "smp.h"

/* Peripheral GATT database — defined in blued.c */
extern struct att_db periph_gatt_db;

struct ctl_attdb_mark {
	int		count;
	uint16_t	next_handle;
	size_t		val_used;
};

static void
ctl_attdb_mark(struct att_db *db, struct ctl_attdb_mark *mark)
{

	mark->count = db->count;
	mark->next_handle = db->next_handle;
	mark->val_used = db->val_used;
}

static void
ctl_attdb_rollback(struct att_db *db, const struct ctl_attdb_mark *mark)
{

	db->count = mark->count;
	db->next_handle = mark->next_handle;
	db->val_used = mark->val_used;
}


/*
 * Attempt SMP pairing and encryption elevation for a connection
 * that returned ATT_ERR_INSUFF_AUTHEN or ATT_ERR_INSUFF_ENCRYPTION.
 * Returns true if pairing and encryption succeeded, false otherwise.
 *
 * Modeled after the auth retry path in blued_conn_setup_central()
 * (blued.c).
 *
 * Note: smp_open() creates a PF_BLUETOOTH socket internally, which
 * requires socket(2).  This call is blocked inside a Capsicum
 * sandbox (after cap_enter()).  If the daemon is sandboxed, we
 * return false immediately rather than attempting a syscall that
 * would fail with ECAPMODE.  Security elevation in this case
 * requires restarting the daemon or pre-establishing the bond
 * before entering the sandbox.
 */
static bool
ctl_elevate_security(struct blued_conn *conn)
{
	struct smp_conn sc;
	int ret;

	if (conn->adapter == NULL)
		return (false);

	/*
	 * smp_open() calls socket(PF_BLUETOOTH, ...) which is not
	 * permitted inside Capsicum capability mode.
	 */
	if (cap_sandboxed()) {
		errno = ENOTCAPABLE;
		return (false);
	}

	memset(&sc, 0, sizeof(sc));
	sc.fd = -1;

	pthread_mutex_lock(&blued_g.bond_db_lock);
	ret = smp_open(&sc, (const uint8_t *)&conn->dst,
	    conn->addr_type, (const uint8_t *)&conn->adapter->addr, 0,
	    conn->adapter->hci_fd, conn->con_handle,
	    blued_g.bond_db);
	pthread_mutex_unlock(&blued_g.bond_db_lock);
	if (ret < 0)
		return (false);

	ret = smp_pair(&sc);
	if (ret < 0) {
		smp_close(&sc);
		return (false);
	}

	/*
	 * C3-H1: smp_pair() already waits for and consumes the HCI Encryption
	 * Change event internally (smp_sc.c / smp.c hci_wait_encryption) and only
	 * returns >= 0 once encryption is confirmed for this connection.  A
	 * second hci_wait_encryption() here would block on an already-consumed
	 * one-shot event and always time out, turning every successful elevation
	 * into a reported failure.  Encryption is confirmed above, so proceed
	 * directly to committing the ATT security state.
	 */

	/*
	 * Finding 95: serialise these security-state writes against the HCI
	 * Encryption-Change / Key-Refresh handlers on the event loop, which
	 * write the same fields under only a conns_lock read lock.
	 */
	{
		struct smp_bond *pb;
		bool mitm = false;

		pthread_mutex_lock(&blued_g.bond_db_lock);
		pb = smp_find_bond(blued_g.bond_db,
		    (const uint8_t *)&conn->dst, conn->addr_type);
		if (pb != NULL && pb->is_mitm)
			mitm = true;
		pthread_mutex_unlock(&blued_g.bond_db_lock);

		pthread_mutex_lock(&blued_g.att_sec_lock);
		conn->att->encrypted = true;
		conn->att->enc_key_size = 16;
		if (mitm)
			conn->att->authenticated = true;
		pthread_mutex_unlock(&blued_g.att_sec_lock);
	}
	smp_close(&sc);
	return (true);
}

/*
 * Check whether an ATT error code indicates that security
 * elevation (pairing) should be attempted.
 */
static bool
ctl_att_needs_security(int err)
{

	return (err == ATT_ERR_INSUFF_AUTHEN ||
	    err == ATT_ERR_INSUFF_ENCRYPTION ||
	    err == ATT_ERR_INSUFF_ENC_KEY_SIZE);
}

int
ctl_gatt_read_result(struct blued_conn *job_conn, uint8_t adapter_index,
    const bdaddr_t *addr,
    uint8_t addr_type, uint16_t handle, uint8_t *value, size_t value_size,
    size_t *value_len)
{
	struct blued_conn *conn;
	struct timeval old_tv;
	int ret;

	(void)adapter_index;
	(void)addr_type;
	if (addr == NULL || handle == 0 || value == NULL || value_len == NULL)
		return (IPC_ERR_INVAL);
	/* Finding 90: operate on the admitted, ref'd conn, not an address re-lookup. */
	conn = job_conn;
	if (conn == NULL || conn->att == NULL)
		return (IPC_ERR_NOT_CONN);
	ctl_set_att_timeout(conn->att->fd, &old_tv);
	/*
	 * C2-L5: the SO_RCVTIMEO installed by ctl_set_att_timeout is reset every
	 * iteration by att.c's per-request deadline loop, so on its own the ctl
	 * 2 s cap is dead — the op would run to the 30 s ATT ceiling.  Install
	 * the tighter bound through the mechanism att.c actually honours
	 * (att_conn_set_op_timeout / ac->op_timeout_ms) so a stalled peer fails
	 * the ctl op in CTL_ATT_TIMEOUT_SEC, then clear it before restore so the
	 * notification/peripheral paths sharing this att_conn keep blocking
	 * semantics.
	 */
	att_conn_set_op_timeout(conn->att, CTL_ATT_TIMEOUT_SEC * 1000);
	*value_len = 0;
	ret = att_read(conn->att, handle, value, value_size, value_len);
	if (ret != 0 && ctl_att_needs_security(ret) &&
	    ctl_elevate_security(conn)) {
		*value_len = 0;
		ret = att_read(conn->att, handle, value, value_size, value_len);
	}
	/*
	 * C2-M8: an ATT Read Response carries at most ATT_MTU-1 value octets, so
	 * a value that exactly fills MTU-1 may have more bytes the client never
	 * sees.  Continue with ATT Read Blob (Read Long, Core Spec Vol 3 Part G
	 * §4.8.3) at successive offsets to assemble the full value for the ctl
	 * client, mirroring the pattern blued_central uses for the Report Map.
	 */
	if (ret == 0) {
		size_t total = *value_len;
		uint16_t mtu = conn->att->mtu;

		while (total == (size_t)(mtu - 1) && total < value_size &&
		    total <= UINT16_MAX) {
			size_t blen = 0;

			if (att_read_blob(conn->att, handle, (uint16_t)total,
			    value + total, value_size - total, &blen) != 0)
				break;
			if (blen == 0)
				break;
			total += blen;
		}
		*value_len = total;
	}
	att_conn_set_op_timeout(conn->att, 0);
	ctl_restore_att_timeout(conn->att->fd, &old_tv);
	return (ret == 0 ? IPC_ERR_NONE : IPC_ERR_IO);
}

int
ctl_gatt_write_result(struct blued_conn *job_conn, uint8_t adapter_index,
    const bdaddr_t *addr,
    uint8_t addr_type, uint16_t handle, const uint8_t *value,
    size_t value_len, bool command)
{
	struct blued_conn *conn;
	struct timeval old_tv;
	int ret;

	(void)adapter_index;
	(void)addr_type;
	if (addr == NULL || handle == 0 || (value == NULL && value_len != 0) ||
	    value_len > ATT_MAX_ATTR_VALUE_LEN /* A-F6: max attr value is 512 */)
		return (IPC_ERR_INVAL);
	/* Finding 90: operate on the admitted, ref'd conn. */
	conn = job_conn;
	if (conn == NULL || conn->att == NULL)
		return (IPC_ERR_NOT_CONN);
	if (command)
		return (att_write_cmd(conn->att, handle, value, value_len) == 0 ?
		    IPC_ERR_NONE : IPC_ERR_IO);
	ctl_set_att_timeout(conn->att->fd, &old_tv);
	/* C2-L5: honour the ctl op timeout through att.c's op_timeout_ms (the
	 * SO_RCVTIMEO alone is reset each iteration by att.c's deadline loop). */
	att_conn_set_op_timeout(conn->att, CTL_ATT_TIMEOUT_SEC * 1000);
	ret = att_write_req(conn->att, handle, value, value_len);
	if (ret != 0 && ctl_att_needs_security(ret) &&
	    ctl_elevate_security(conn))
		ret = att_write_req(conn->att, handle, value, value_len);
	att_conn_set_op_timeout(conn->att, 0);
	ctl_restore_att_timeout(conn->att->fd, &old_tv);
	return (ret == 0 ? IPC_ERR_NONE : IPC_ERR_IO);
}

static struct blued_ctl_client *
ctl_subscription_client(int fd, uint64_t generation)
{
	struct blued_ctl_client *client;

	LIST_FOREACH(client, &blued_g.ctl_clients, entries)
		if (client->fd == fd && client->generation == generation)
			return (client);
	return (NULL);
}

static bool
ctl_subscription_matches(const struct ctl_subscription *sub,
    const bdaddr_t *addr, uint8_t addr_type, uint8_t adapter_index,
    uint16_t handle)
{

	return (memcmp(&sub->addr, addr, sizeof(*addr)) == 0 &&
	    sub->handle == handle && sub->addr_type == addr_type &&
	    sub->adapter_index == adapter_index);
}

static int
ctl_subscription_find(const struct blued_ctl_client *client,
    const bdaddr_t *addr, uint8_t addr_type, uint8_t adapter_index,
    uint16_t handle)
{
	int i;

	for (i = 0; i < client->nsubs; i++)
		if (ctl_subscription_matches(&client->subs[i], addr, addr_type,
		    adapter_index, handle))
			break;
	return (i);
}

static void
ctl_subscription_remove(struct blued_ctl_client *client, int i)
{

	if (i + 1 < client->nsubs)
		memmove(&client->subs[i], &client->subs[i + 1],
		    (client->nsubs - i - 1) * sizeof(client->subs[0]));
	client->nsubs--;
}

void
ctl_gatt_conn_gone(const struct blued_conn *conn)
{
	struct blued_ctl_client *client;
	int i;

	if (conn == NULL || conn->adapter == NULL)
		return;
	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
		for (i = 0; i < client->nsubs;) {
			if (memcmp(&client->subs[i].addr, &conn->dst,
			    sizeof(conn->dst)) != 0 ||
			    client->subs[i].addr_type != conn->addr_type ||
			    client->subs[i].adapter_index != conn->adapter->index) {
				i++;
				continue;
			}
			if (i + 1 < client->nsubs)
				memmove(&client->subs[i], &client->subs[i + 1],
				    (client->nsubs - i - 1) *
				    sizeof(client->subs[0]));
			client->nsubs--;
		}
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

static int
ctl_gatt_service_for_handle(struct att_conn *att, uint16_t handle,
    struct gatt_service *service)
{
	struct gatt_service services[GATT_MAX_SERVICES];
	uint16_t start;
	int i, nservices, ret;

	start = 0x0001;
	for (;;) {
		nservices = 0;
		ret = gatt_discover_primary_services_range(att, start, 0xffff,
		    services, GATT_MAX_SERVICES, &nservices);
		if (ret != 0)
			return (ret);
		for (i = 0; i < nservices; i++) {
			if (handle >= services[i].start_handle &&
			    handle <= services[i].end_handle) {
				*service = services[i];
				return (0);
			}
		}
		if (nservices < GATT_MAX_SERVICES || nservices == 0 ||
		    services[nservices - 1].end_handle == 0xffff)
			break;
		start = services[nservices - 1].end_handle + 1;
	}
	errno = ENOENT;
	return (-1);
}

int
ctl_gatt_subscribe_result(struct blued_conn *job_conn, int client_fd,
    uint64_t client_generation,
    uint8_t adapter_index, const bdaddr_t *addr, uint8_t addr_type,
    uint16_t handle, bool subscribe)
{
	struct gatt_service service;
	struct gatt_char chars[GATT_MAX_CHARS];
	struct gatt_char next_char;
	struct gatt_desc descs[GATT_MAX_DESCS];
	struct blued_conn *conn;
	struct blued_ctl_client *client, *other;
	struct timeval old_tv;
	uint16_t cccd_handle, cccd_value, desc_end;
	uint8_t properties;
	bool shared, shared_pending, staged, route_live;
	uint16_t char_start;
	int i, j, nchars, ndescs, nnext, ret, local_error;

	if (addr == NULL || handle == 0)
		return (IPC_ERR_INVAL);
	staged = false;
	/* Snapshot local subscription state without holding this lock over ATT. */
	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	client = ctl_subscription_client(client_fd, client_generation);
	if (client == NULL) {
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		return (IPC_ERR_NOT_FOUND);
	}
	/* Finding 90: operate on the admitted, ref'd conn, not a re-lookup. */
	conn = job_conn;
	if (conn == NULL || conn->att == NULL) {
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		return (IPC_ERR_NOT_CONN);
	}

	for (i = 0; i < client->nsubs; i++) {
		if (memcmp(&client->subs[i].addr, addr, sizeof(*addr)) != 0 ||
		    client->subs[i].handle != handle ||
		    client->subs[i].addr_type != addr_type ||
		    client->subs[i].adapter_index != adapter_index)
			continue;
		if (subscribe) {
			if (client->subs[i].pending) {
				pthread_mutex_unlock(&blued_g.ctl_clients_lock);
				return (IPC_ERR_BUSY);
			}
			pthread_mutex_unlock(&blued_g.ctl_clients_lock);
			return (IPC_ERR_NONE);
		}
		/* Cancel an in-flight enable; its owner will undo any successful write. */
		if (client->subs[i].pending) {
			if (i + 1 < client->nsubs)
				memmove(&client->subs[i], &client->subs[i + 1],
				    (client->nsubs - i - 1) * sizeof(client->subs[0]));
			client->nsubs--;
			pthread_mutex_unlock(&blued_g.ctl_clients_lock);
			return (IPC_ERR_NONE);
		}
		break;
	}
	if (!subscribe && i == client->nsubs) {
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		return (IPC_ERR_NOT_FOUND);
	}
	if (subscribe && client->nsubs >= CTL_MAX_SUBSCRIPTIONS) {
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		return (IPC_ERR_BUSY);
	}

	/*
	 * A control subscription is also a GATT subscription.  The first local
	 * route is staged before CCCD enable so a value sent immediately after
	 * the server processes that write has an exact recipient.
	 * Multiple control clients share the one peer CCCD, so only the first
	 * subscriber enables it and only the last subscriber disables it.
	 */
	shared = false;
	shared_pending = false;
	LIST_FOREACH(other, &blued_g.ctl_clients, entries) {
		for (j = 0; j < other->nsubs; j++) {
			if (other == client && j == i)
				continue;
			if (memcmp(&other->subs[j].addr, addr, sizeof(*addr)) == 0 &&
			    other->subs[j].handle == handle &&
			    other->subs[j].addr_type == addr_type &&
			    other->subs[j].adapter_index == adapter_index) {
				if (other->subs[j].pending)
					shared_pending = true;
				else
					shared = true;
				break;
			}
		}
		if (shared)
			break;
	}
	if (subscribe && shared_pending) {
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		return (IPC_ERR_BUSY);
	}

	if (shared) {
		if (subscribe) {
			/* Copy the CCCD metadata from an existing owner. */
			for (j = 0; j < other->nsubs; j++)
				if (memcmp(&other->subs[j].addr, addr,
				    sizeof(*addr)) == 0 &&
				    other->subs[j].handle == handle &&
				    other->subs[j].addr_type == addr_type &&
				    other->subs[j].adapter_index == adapter_index)
					break;
			memcpy(&client->subs[client->nsubs].addr, addr,
			    sizeof(*addr));
			client->subs[client->nsubs].handle = handle;
			client->subs[client->nsubs].cccd_handle =
			    other->subs[j].cccd_handle;
			client->subs[client->nsubs].cccd_value =
			    other->subs[j].cccd_value;
			client->subs[client->nsubs].addr_type = addr_type;
			client->subs[client->nsubs].adapter_index = adapter_index;
			client->subs[client->nsubs].pending = false;
			client->nsubs++;
		} else {
			if (i + 1 < client->nsubs)
				memmove(&client->subs[i], &client->subs[i + 1],
				    (client->nsubs - i - 1) *
				    sizeof(client->subs[0]));
			client->nsubs--;
		}
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		return (IPC_ERR_NONE);
	}

	if (!subscribe) {
		uint8_t value[2] = { 0, 0 };

		cccd_handle = client->subs[i].cccd_handle;
		cccd_value = client->subs[i].cccd_value;
		/*
		 * C2-M11: this is the last-owner unsubscribe (the shared path
		 * above did not fire), so we are about to write CCCD=0.  Mark the
		 * subscription pending-removal BEFORE dropping the lock.  Left
		 * non-pending, a concurrent subscriber for the same characteristic
		 * would scan this still-present sub, conclude the peer CCCD is
		 * already enabled ("shared"), and add its route WITHOUT rewriting
		 * the CCCD — then our CCCD=0 write lands and the new subscriber
		 * silently never receives notifications.  Marked pending, that
		 * concurrent subscriber instead observes shared_pending and backs
		 * off with BUSY, symmetric with the subscribe staging path.
		 */
		client->subs[i].pending = true;
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		ctl_set_att_timeout(conn->att->fd, &old_tv);
		ret = att_write_req(conn->att, cccd_handle, value, sizeof(value));
		if (ret != 0 && cccd_handle != 0 &&
		    ctl_att_needs_security(ret) &&
		    ctl_elevate_security(conn))
			ret = att_write_req(conn->att, cccd_handle, value,
			    sizeof(value));
		ctl_restore_att_timeout(conn->att->fd, &old_tv);
		if (ret != 0) {
			/*
			 * C2-M11: the disable failed, so the subscription stays
			 * active — clear the pending-removal mark we set above
			 * rather than leaving the sub wedged pending forever
			 * (which would make it un-removable and block resubscribe).
			 */
			pthread_mutex_lock(&blued_g.ctl_clients_lock);
			client = ctl_subscription_client(client_fd,
			    client_generation);
			if (client != NULL) {
				i = ctl_subscription_find(client, addr, addr_type,
				    adapter_index, handle);
				if (i != client->nsubs)
					client->subs[i].pending = false;
			}
			pthread_mutex_unlock(&blued_g.ctl_clients_lock);
			return (IPC_ERR_IO);
		}
	} else {
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		/* Locate the characteristic's descriptor range and its CCCD. */
		cccd_handle = 0;
		cccd_value = 0;
		properties = 0;
		ctl_set_att_timeout(conn->att->fd, &old_tv);
		ret = ctl_gatt_service_for_handle(conn->att, handle, &service);
		char_start = ret == 0 ? service.start_handle : 0;
		while (ret == 0 && cccd_handle == 0) {
			nchars = 0;
			ret = gatt_discover_characteristics(conn->att,
			    char_start, service.end_handle, chars,
			    GATT_MAX_CHARS, &nchars);
			if (ret != 0)
				break;
			for (j = 0; j < nchars; j++) {
				if (chars[j].value_handle != handle)
					continue;
				properties = chars[j].properties;
				if (j + 1 < nchars) {
					desc_end = chars[j + 1].decl_handle - 1;
				} else {
					nnext = 0;
					ret = gatt_discover_characteristics(conn->att,
					    chars[j].decl_handle + 1,
					    service.end_handle, &next_char, 1, &nnext);
					/*
					 * A swallowed discovery error must not fall
					 * back to service.end_handle: that over-wide
					 * range can latch a later characteristic's
					 * CCCD onto this subscription (finding 66).
					 */
					if (ret != 0)
						break;
					desc_end = nnext == 1 ? next_char.decl_handle - 1 :
					    service.end_handle;
				}
				if (handle == UINT16_MAX || handle + 1 > desc_end)
					break;
				ndescs = 0;
				ret = gatt_discover_descriptors(conn->att, handle + 1,
				    desc_end, descs, GATT_MAX_DESCS, &ndescs);
				if (ret != 0)
					break;
				for (int k = 0; k < ndescs; k++)
					if (descs[k].uuid16 == GATT_UUID_CCCD) {
						cccd_handle = descs[k].handle;
						break;
				}
				break;
			}
			if (cccd_handle != 0 || nchars < GATT_MAX_CHARS ||
			    nchars == 0 || chars[nchars - 1].decl_handle == 0xffff)
				break;
			char_start = chars[nchars - 1].decl_handle + 1;
		}
		if (ret == 0 && cccd_handle != 0) {
			uint8_t value[2];

			if ((properties & GATT_PROP_NOTIFY) != 0)
				cccd_value = GATT_CCCD_NOTIFY;
			else if ((properties & GATT_PROP_INDICATE) != 0)
				cccd_value = GATT_CCCD_INDICATE;
			else
				ret = ATT_ERR_WRITE_NOT_PERMITTED;
			/*
			 * Publish the exact route before the Write Request.  A pending route
			 * receives values but cannot be used as established shared ownership.
			 * Recheck client capacity/lifetime and sharing after discovery.
			 */
			local_error = IPC_ERR_NONE;
			if (ret == 0) {
				pthread_mutex_lock(&blued_g.ctl_clients_lock);
				client = ctl_subscription_client(client_fd,
				    client_generation);
				if (client == NULL) {
					local_error = IPC_ERR_NOT_FOUND;
				} else {
					i = ctl_subscription_find(client, addr, addr_type,
					    adapter_index, handle);
					if (i != client->nsubs) {
						local_error = client->subs[i].pending ?
						    IPC_ERR_BUSY : IPC_ERR_NONE;
					} else if (client->nsubs >= CTL_MAX_SUBSCRIPTIONS) {
						local_error = IPC_ERR_BUSY;
					} else {
						shared = false;
						shared_pending = false;
						LIST_FOREACH(other, &blued_g.ctl_clients,
						    entries) {
							for (j = 0; j < other->nsubs; j++) {
								if (!ctl_subscription_matches(
								    &other->subs[j], addr, addr_type,
								    adapter_index, handle))
									continue;
								if (other->subs[j].pending)
									shared_pending = true;
								else
									shared = true;
								break;
							}
							if (shared || shared_pending)
								break;
						}
						if (shared_pending) {
							local_error = IPC_ERR_BUSY;
						} else {
							struct ctl_subscription *sub =
							    &client->subs[client->nsubs++];

							memset(sub, 0, sizeof(*sub));
							sub->addr = *addr;
							sub->handle = handle;
							sub->cccd_handle = cccd_handle;
							sub->cccd_value = cccd_value;
							sub->addr_type = addr_type;
							sub->adapter_index = adapter_index;
							sub->pending = !shared;
							staged = !shared;
						}
					}
				}
				pthread_mutex_unlock(&blued_g.ctl_clients_lock);
			}
			if (ret == 0 && local_error != IPC_ERR_NONE) {
				ctl_restore_att_timeout(conn->att->fd, &old_tv);
				return (local_error);
			}
			if (ret == 0 && !staged) {
				ctl_restore_att_timeout(conn->att->fd, &old_tv);
				return (IPC_ERR_NONE);
			}
			put_le16(value, cccd_value);
			if (ret == 0)
				ret = att_write_req(conn->att, cccd_handle, value,
				    sizeof(value));
		}
		if (ret != 0 && cccd_handle != 0 &&
		    ctl_att_needs_security(ret) &&
		    ctl_elevate_security(conn)) {
			uint8_t value[2];

			put_le16(value, cccd_value);
			ret = att_write_req(conn->att, cccd_handle, value,
			    sizeof(value));
		}
		ctl_restore_att_timeout(conn->att->fd, &old_tv);
		if (ret != 0) {
			/* Roll back only this operation's still-pending reservation. */
			if (staged) {
				pthread_mutex_lock(&blued_g.ctl_clients_lock);
				client = ctl_subscription_client(client_fd,
				    client_generation);
				if (client != NULL) {
					i = ctl_subscription_find(client, addr, addr_type,
					    adapter_index, handle);
					if (i != client->nsubs && client->subs[i].pending)
						ctl_subscription_remove(client, i);
				}
				pthread_mutex_unlock(&blued_g.ctl_clients_lock);
			}
			return (IPC_ERR_IO);
		}
		if (cccd_handle == 0)
			return (IPC_ERR_NOT_FOUND);
	}

	if (subscribe && staged) {
		/*
		 * Commit only if the same client still owns the staged route.  Client
		 * exit or a concurrent unsubscribe may remove it during ATT I/O; never
		 * resurrect such a route after the Write Response.  If no active owner
		 * remains, roll the just-enabled remote CCCD back as well.
		 */
		pthread_mutex_lock(&blued_g.ctl_clients_lock);
		client = ctl_subscription_client(client_fd, client_generation);
		route_live = false;
		if (client != NULL) {
			i = ctl_subscription_find(client, addr, addr_type, adapter_index,
			    handle);
			if (i != client->nsubs) {
				client->subs[i].pending = false;
				route_live = true;
			}
		}
		if (!route_live) {
			LIST_FOREACH(other, &blued_g.ctl_clients, entries) {
				for (j = 0; j < other->nsubs; j++) {
					if (other->subs[j].pending ||
					    !ctl_subscription_matches(&other->subs[j], addr,
					    addr_type, adapter_index, handle))
						continue;
					route_live = true;
					break;
				}
				if (route_live)
					break;
			}
		}
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		if (!route_live) {
			uint8_t value[2] = { 0, 0 };

			ctl_set_att_timeout(conn->att->fd, &old_tv);
			(void)att_write_req(conn->att, cccd_handle, value, sizeof(value));
			ctl_restore_att_timeout(conn->att->fd, &old_tv);
			return (IPC_ERR_NOT_FOUND);
		}
		return (IPC_ERR_NONE);
	}

	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	client = ctl_subscription_client(client_fd, client_generation);
	if (client == NULL) {
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		if (subscribe) {
			uint8_t value[2] = { 0, 0 };

			ctl_set_att_timeout(conn->att->fd, &old_tv);
			(void)att_write_req(conn->att, cccd_handle, value,
			    sizeof(value));
			ctl_restore_att_timeout(conn->att->fd, &old_tv);
		}
		return (IPC_ERR_NOT_FOUND);
	}
	for (i = 0; i < client->nsubs; i++)
		if (memcmp(&client->subs[i].addr, addr, sizeof(*addr)) == 0 &&
		    client->subs[i].handle == handle &&
		    client->subs[i].addr_type == addr_type &&
		    client->subs[i].adapter_index == adapter_index)
			break;
	if (!subscribe) {
		if (i == client->nsubs) {
			pthread_mutex_unlock(&blued_g.ctl_clients_lock);
			return (IPC_ERR_NOT_FOUND);
		}
		if (i + 1 < client->nsubs)
			memmove(&client->subs[i], &client->subs[i + 1],
			    (client->nsubs - i - 1) * sizeof(client->subs[0]));
		client->nsubs--;
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		return (IPC_ERR_NONE);
	}
	if (i != client->nsubs) {
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		return (IPC_ERR_NONE);
	}
	if (client->nsubs >= CTL_MAX_SUBSCRIPTIONS) {
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		{
			uint8_t value[2] = { 0, 0 };

			ctl_set_att_timeout(conn->att->fd, &old_tv);
			(void)att_write_req(conn->att, cccd_handle, value,
			    sizeof(value));
			ctl_restore_att_timeout(conn->att->fd, &old_tv);
		}
		return (IPC_ERR_BUSY);
	}
	memcpy(&client->subs[client->nsubs].addr, addr, sizeof(*addr));
	client->subs[client->nsubs].handle = handle;
	client->subs[client->nsubs].cccd_handle = cccd_handle;
	client->subs[client->nsubs].cccd_value = cccd_value;
	client->subs[client->nsubs].addr_type = addr_type;
	client->subs[client->nsubs].adapter_index = adapter_index;
	client->nsubs++;
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
	return (IPC_ERR_NONE);
}

int
ctl_gatt_discover_result(struct blued_conn *job_conn, uint8_t adapter_index,
    const bdaddr_t *addr,
    uint8_t addr_type, ctl_gatt_discover_cb cb, void *arg)
{
	struct gatt_service services[GATT_MAX_SERVICES];
	struct blued_conn *conn;
	struct timeval old_tv;
	uint16_t service_start;
	int nservices, ret;

	(void)adapter_index;
	(void)addr_type;
	if (addr == NULL || cb == NULL)
		return (IPC_ERR_INVAL);
	/* Finding 90: operate on the admitted, ref'd conn. */
	conn = job_conn;
	if (conn == NULL || conn->att == NULL)
		return (IPC_ERR_NOT_CONN);
	ctl_set_att_timeout(conn->att->fd, &old_tv);
	service_start = 0x0001;
	nservices = 0;
	ret = gatt_discover_primary_services_range(conn->att, service_start,
	    0xffff, services, GATT_MAX_SERVICES, &nservices);
	if (ret != 0 && ctl_att_needs_security(ret) &&
	    ctl_elevate_security(conn)) {
		nservices = 0;
		ret = gatt_discover_primary_services_range(conn->att,
		    service_start, 0xffff, services, GATT_MAX_SERVICES,
		    &nservices);
	}
	while (ret == 0) {
		for (int i = 0; i < nservices; i++) {
			struct gatt_char chars[GATT_MAX_CHARS];
			uint16_t char_start;
			int nchars;

			cb(&services[i], NULL, arg);
			char_start = services[i].start_handle;
			for (;;) {
				nchars = 0;
				ret = gatt_discover_characteristics(conn->att,
				    char_start, services[i].end_handle, chars,
				    GATT_MAX_CHARS, &nchars);
				if (ret != 0)
					break;
				for (int j = 0; j < nchars; j++)
					cb(NULL, &chars[j], arg);
				if (nchars < GATT_MAX_CHARS || nchars == 0 ||
				    chars[nchars - 1].decl_handle == 0xffff)
					break;
				char_start = chars[nchars - 1].decl_handle + 1;
			}
			if (ret != 0)
				break;
		}
		if (ret != 0 || nservices < GATT_MAX_SERVICES ||
		    nservices == 0 ||
		    services[nservices - 1].end_handle == 0xffff)
			break;
		service_start = services[nservices - 1].end_handle + 1;
		nservices = 0;
		ret = gatt_discover_primary_services_range(conn->att,
		    service_start, 0xffff, services, GATT_MAX_SERVICES,
		    &nservices);
	}
	ctl_restore_att_timeout(conn->att->fd, &old_tv);
	return (ret == 0 ? IPC_ERR_NONE : IPC_ERR_IO);
}

static struct att_attr *
ctl_find_parent_service(struct att_db *db, uint16_t handle)
{
	struct att_attr *svc = NULL;
	int i;

	for (i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];

		if (a->handle > handle)
			break;
		if (a->uuid16 == GATT_UUID_PRIMARY_SERVICE ||
		    a->uuid16 == GATT_UUID_SECONDARY_SERVICE)
			svc = a;
	}
	return (svc);
}

static bool
ctl_service_append_ok(struct att_db *db, uint16_t service_handle)
{
	bool seen_service = false;
	int i;

	for (i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];

		if (a->handle == service_handle) {
			seen_service = true;
			continue;
		}
		if (!seen_service)
			continue;
		if (a->uuid16 == GATT_UUID_PRIMARY_SERVICE ||
		    a->uuid16 == GATT_UUID_SECONDARY_SERVICE)
			return (false);
	}
	return (seen_service);
}

static bool
ctl_service_derived_end(struct att_db *db, uint16_t service_handle,
    uint16_t *out)
{
	bool seen_service = false;
	uint16_t end = 0;
	int i;

	for (i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];

		if (a->handle == service_handle &&
		    (a->uuid16 == GATT_UUID_PRIMARY_SERVICE ||
		    a->uuid16 == GATT_UUID_SECONDARY_SERVICE)) {
			seen_service = true;
			end = a->handle;
			continue;
		}
		if (!seen_service)
			continue;
		if (a->uuid16 == GATT_UUID_PRIMARY_SERVICE ||
		    a->uuid16 == GATT_UUID_SECONDARY_SERVICE)
			break;
		end = a->handle;
	}
	if (!seen_service)
		return (false);
	*out = end;
	return (true);
}

static bool
ctl_include_append_ok(struct att_db *db, uint16_t service_handle)
{
	bool seen_service = false;
	int i;

	for (i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];

		if (a->handle == service_handle) {
			seen_service = true;
			continue;
		}
		if (!seen_service)
			continue;
		if (a->uuid16 == GATT_UUID_CHARACTERISTIC ||
		    a->uuid16 == GATT_UUID_PRIMARY_SERVICE ||
		    a->uuid16 == GATT_UUID_SECONDARY_SERVICE)
			return (false);
	}
	return (seen_service);
}

static bool
ctl_descriptor_append_ok(struct att_db *db, uint16_t handle)
{
	bool seen_owner = false;
	int i;

	for (i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];

		if (a->handle == handle) {
			seen_owner = true;
			continue;
		}
		if (!seen_owner)
			continue;
		if (a->uuid16 == GATT_UUID_CHARACTERISTIC ||
		    a->uuid16 == GATT_UUID_PRIMARY_SERVICE ||
		    a->uuid16 == GATT_UUID_SECONDARY_SERVICE)
			return (false);
	}
	return (seen_owner);
}

static bool
ctl_char_metadata(struct att_db *db, uint16_t value_handle, uint8_t *props,
    uint16_t *cccd_handle)
{
	bool found = false;
	int i;

	*props = 0;
	*cccd_handle = 0;

	for (i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];

		if (a->uuid16 != GATT_UUID_CHARACTERISTIC ||
		    a->value == NULL ||
		    (a->value_len != 5 && a->value_len != 19))
			continue;
		if (get_le16(a->value + 1) != value_handle)
			continue;
		*props = a->value[0];
		found = true;
		break;
	}
	if (!found)
		return (false);

	for (i++; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];

		if (a->uuid16 == GATT_UUID_CHARACTERISTIC ||
		    a->uuid16 == GATT_UUID_PRIMARY_SERVICE ||
		    a->uuid16 == GATT_UUID_SECONDARY_SERVICE)
			break;
		if (a->uuid16 == GATT_UUID_CCCD) {
			*cccd_handle = a->handle;
			break;
		}
	}
	return (true);
}

static bool
ctl_cccd_enabled(struct att_conn *ac, uint16_t cccd_handle, uint16_t bit)
{
	int i;

	for (i = 0; i < ac->cccd_count; i++) {
		if (ac->cccds[i].handle == cccd_handle &&
		    (ac->cccds[i].value & bit) != 0)
			return (true);
	}
	return (false);
}

/*
 * Helper: recompute the GATT Database Hash after a live DB change
 * and send Service Changed indication to all connected peripheral
 * clients that have enabled indications.
 */
static void
ctl_recompute_hash_and_notify(uint16_t start, uint16_t end)
{
	struct att_db *db = &periph_gatt_db;
	uint8_t db_hash[16];
	struct blued_conn *conn;

	/* Recompute DB hash */
	attdb_compute_db_hash(db, db_hash);
	for (int i = 0; i < db->count; i++) {
		if (db->attrs[i].uuid16 == 0x2B2A /* UUID_DATABASE_HASH */ &&
		    db->attrs[i].value_len == 16) {
			memcpy(db->attrs[i].value, db_hash, 16);
			break;
		}
	}

	/*
	 * Mark all connected clients with Robust Caching as
	 * change-unaware.  They will receive ATT_ERR_DATABASE_OUT_OF_SYNC
	 * (0x12) on subsequent requests until they read the new DB hash.
	 * Core Spec Vol 3 Part G Section 2.5.2.1.
	 */
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (conn->att != NULL && conn->att->robust_caching) {
			/*
			 * The database changed: the client is change-unaware
			 * again, and the once-per-bearer Out Of Sync error may
			 * be sent afresh (Vol 3 Part G §2.5.2.1).
			 */
			conn->att->change_aware = false;
			conn->att->out_of_sync_sent = false;
		}
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);

	/*
	 * Send Service Changed indication to all connected peripheral
	 * clients.  Walk the connection list and notify each that has
	 * an ATT connection and is in peripheral role.
	 */
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (conn->role != BLUED_ROLE_PERIPHERAL)
			continue;
		if (conn->att == NULL)
			continue;
		if (atomic_load(&conn->state) != BLUED_CONN_ACTIVE)
			continue;

		/* Build the affected handle range [start, end] */
		{
			uint8_t val[4];
			uint16_t sc_handle = 0;
			uint16_t cccd_handle = 0;
			bool ind_enabled = false;

			/* Find Service Changed characteristic */
			for (int i = 0; i < db->count; i++) {
				if (db->attrs[i].uuid16 == 0x2A05 &&
				    db->attrs[i].is_char_value) {
					sc_handle = db->attrs[i].handle;
					if (i + 1 < db->count &&
					    db->attrs[i + 1].uuid16 ==
					    GATT_UUID_CCCD)
						cccd_handle =
						    db->attrs[i + 1].handle;
					break;
				}
			}
			if (sc_handle == 0 || cccd_handle == 0)
				continue;

			/* Check if indications enabled */
			for (int j = 0; j < conn->att->cccd_count; j++) {
				if (conn->att->cccds[j].handle ==
				    cccd_handle &&
				    (conn->att->cccds[j].value &
				    GATT_CCCD_INDICATE) != 0) {
					ind_enabled = true;
					break;
				}
			}
			if (!ind_enabled)
				continue;

			put_le16(val, start);
			put_le16(val + 2, end);
			if (att_send_indication(conn->att, sc_handle,
			    val, sizeof(val)) == 0)
				blued_ind_arm_timeout(conn);
		}
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);

	/* Finding 137: persist the runtime-added local GATT server DB. */
	ctl_gatt_persist_runtime();
}

/*
 * Finding 137: base attribute count captured immediately after the peripheral
 * build (built-in + config services).  Attributes at index >= this mark were
 * added at runtime (add-service and friends) and are the ones serialized;
 * built-in/config attributes are rebuilt from scratch each boot.  Note that
 * runtime service/characteristic *declaration* attributes keep owner_fd == -1
 * (only char-value attrs carry the owner), so the high-water mark -- not
 * owner_fd -- is what distinguishes a runtime attribute here.
 */
static int	ctl_gatt_base_count;

void
ctl_gatt_set_base_count(void)
{

	ctl_gatt_base_count = periph_gatt_db.count;
}

/*
 * Finding 137: serialize the runtime-added attributes (index >= base count) of
 * the live periph_gatt_db to the gattsrv persist artifact.  Called under
 * gatt_db_lock after each structural change / value update.
 */
void
ctl_gatt_persist_runtime(void)
{
	static struct blued_persist_gatt_srv_attr
	    rows[BLUED_PERSIST_MAX_GATTSRV_ATTRS];
	struct att_db *db = &periph_gatt_db;
	uint32_t n = 0;

	if (blued_g.persist_dirfd < 0)
		return;
	for (int i = ctl_gatt_base_count; i < db->count &&
	    n < BLUED_PERSIST_MAX_GATTSRV_ATTRS; i++) {
		const struct att_attr *a = &db->attrs[i];
		struct blued_persist_gatt_srv_attr *r;
		uint16_t vlen;

		r = &rows[n++];
		memset(r, 0, sizeof(*r));
		r->handle = a->handle;
		r->uuid16 = a->uuid16;
		memcpy(r->uuid128, a->uuid128, sizeof(r->uuid128));
		r->perms = a->perms;
		r->flags = a->flags;
		r->is_char_value = a->is_char_value ? 1 : 0;
		r->value_maxlen = a->value_maxlen;
		r->end_group_handle = a->end_group_handle;
		vlen = a->value_len;
		if (vlen > BLUED_PERSIST_GATTSRV_VALLEN)
			vlen = BLUED_PERSIST_GATTSRV_VALLEN;
		r->value_len = vlen;
		if (vlen > 0 && a->value != NULL)
			memcpy(r->value, a->value, vlen);
	}
	(void)blued_persist_gattsrv_save(blued_g.persist_dirfd, rows, n);
}

/*
 * Finding 137: replay the persisted runtime GATT server attributes into
 * periph_gatt_db after the peripheral build.  Restored attributes keep their
 * original handles and carry the CTL_GATT_OWNER_PERSISTED sentinel so they are
 * re-serialized on subsequent saves but served as static attributes (no live
 * app backing).  The DB hash is recomputed to include them.
 */
void
ctl_gatt_load_persisted_services(int dirfd)
{
	static struct blued_persist_gatt_srv_attr
	    rows[BLUED_PERSIST_MAX_GATTSRV_ATTRS];
	struct att_db *db = &periph_gatt_db;
	uint32_t nrows = 0, i;
	bool added = false;

	if (dirfd < 0)
		return;
	if (blued_persist_gattsrv_load(dirfd, rows, &nrows) != 0 || nrows == 0)
		return;
	pthread_mutex_lock(&blued_g.gatt_db_lock);
	for (i = 0; i < nrows; i++) {
		const struct blued_persist_gatt_srv_attr *r = &rows[i];
		struct att_attr *a;
		uint16_t vlen = r->value_len;

		if (db->count >= db->max)
			break;
		if (vlen > BLUED_PERSIST_GATTSRV_VALLEN)
			vlen = BLUED_PERSIST_GATTSRV_VALLEN;
		if ((size_t)vlen > db->val_size - db->val_used)
			break;		/* out of value backing store */
		a = &db->attrs[db->count];
		memset(a, 0, sizeof(*a));
		a->handle = r->handle;
		a->uuid16 = r->uuid16;
		memcpy(a->uuid128, r->uuid128, sizeof(a->uuid128));
		a->perms = r->perms;
		a->flags = r->flags;
		a->is_char_value = r->is_char_value != 0;
		a->owner_fd = CTL_GATT_OWNER_PERSISTED;
		a->value_len = vlen;
		a->value_maxlen = r->value_maxlen;
		a->end_group_handle = r->end_group_handle;
		if (vlen > 0) {
			a->value = db->val_store + db->val_used;
			memcpy(a->value, r->value, vlen);
			db->val_used += vlen;
		}
		db->count++;
		if (r->handle >= db->next_handle)
			db->next_handle = (uint16_t)(r->handle + 1);
		added = true;
	}
	if (added) {
		uint8_t db_hash[16];

		attdb_compute_db_hash(db, db_hash);
		for (int j = 0; j < db->count; j++) {
			if (db->attrs[j].uuid16 == 0x2B2A &&
			    db->attrs[j].value_len == 16) {
				memcpy(db->attrs[j].value, db_hash, 16);
				break;
			}
		}
	}
	pthread_mutex_unlock(&blued_g.gatt_db_lock);
}

/*
 * Atomic GATT-application registration (the common atomic GATT-application registration).
 *
 * A single global staged build at a time, owned by one client.  The scratch DB
 * is seeded from the live DB at GATT_BEGIN so staged services/characteristics
 * append with correct handle numbering, then swapped back wholesale at
 * GATT_COMMIT so peers observe the whole application appear together with one
 * DB-hash recompute.  All GATT-DB verbs run under gatt_db_lock, which therefore
 * also serialises this transaction state.
 */
static struct gatt_txn {
	bool		active;
	int		owner_fd;
	struct att_db	db;		/* scratch, isolated from the live DB */
	struct att_attr	*attrs;		/* scratch attribute storage */
	uint8_t		*val;		/* scratch value storage */
} gatt_txn;

/* Discard the scratch DB and clear the transaction (live DB untouched). */
static void
ctl_gatt_txn_free(void)
{

	free(gatt_txn.attrs);
	free(gatt_txn.val);
	gatt_txn.attrs = NULL;
	gatt_txn.val = NULL;
	gatt_txn.active = false;
	gatt_txn.owner_fd = -1;
	memset(&gatt_txn.db, 0, sizeof(gatt_txn.db));
}

/*
 * Select the DB a mutating GATT verb should operate on for this client, and
 * report whether that DB is the staged scratch.  Returns the scratch DB when
 * the client owns the open transaction, the live DB when no transaction is
 * open, or NULL when another client holds the transaction (the verb is
 * refused rather than mutating a DB the owner is about to commit).
 */
static struct att_db *
ctl_gatt_target_db(int client_fd, bool *staged)
{

	if (gatt_txn.active) {
		if (gatt_txn.owner_fd == client_fd) {
			*staged = true;
			return (&gatt_txn.db);
		}
		*staged = false;
		return (NULL);
	}
	*staged = false;
	return (&periph_gatt_db);
}

void
ctl_gatt_txn_client_gone(int client_fd)
{

	if (gatt_txn.active && gatt_txn.owner_fd == client_fd)
		ctl_gatt_txn_free();
}


int
ctl_gatt_begin_result(int client_fd)
{
	struct att_db *live = &periph_gatt_db;

	if (gatt_txn.active)
		return (IPC_ERR_BUSY);

	gatt_txn.attrs = calloc((size_t)live->max, sizeof(struct att_attr));
	gatt_txn.val = malloc(live->val_size);
	if (gatt_txn.attrs == NULL || gatt_txn.val == NULL) {
		ctl_gatt_txn_free();
		return (IPC_ERR_NOMEM);
	}
	attdb_init(&gatt_txn.db, gatt_txn.attrs, live->max, gatt_txn.val,
	    live->val_size);
	if (attdb_copy(&gatt_txn.db, live) < 0) {
		ctl_gatt_txn_free();
		return (IPC_ERR_TOOBIG);
	}
	gatt_txn.active = true;
	gatt_txn.owner_fd = client_fd;
	return (0);
}


static bool
ctl_gatt_attr_equal(const struct att_attr *a, const struct att_attr *b)
{

	if (a->handle != b->handle || a->uuid16 != b->uuid16 ||
	    a->perms != b->perms || a->flags != b->flags ||
	    a->is_char_value != b->is_char_value ||
	    a->value_len != b->value_len ||
	    a->value_maxlen != b->value_maxlen ||
	    a->end_group_handle != b->end_group_handle ||
	    memcmp(a->uuid128, b->uuid128, sizeof(a->uuid128)) != 0)
		return (false);
	if (a->value_len == 0)
		return (true);
	if (a->value == NULL || b->value == NULL)
		return (a->value == b->value);
	return (memcmp(a->value, b->value, a->value_len) == 0);
}

static uint16_t
ctl_gatt_changed_start(const struct att_db *live, const struct att_db *staged)
{
	uint16_t a_handle, b_handle;
	int count, i;

	count = live->count < staged->count ? live->count : staged->count;
	for (i = 0; i < count; i++) {
		if (ctl_gatt_attr_equal(&live->attrs[i], &staged->attrs[i]))
			continue;
		a_handle = live->attrs[i].handle;
		b_handle = staged->attrs[i].handle;
		return (a_handle < b_handle ? a_handle : b_handle);
	}
	if (live->count > staged->count)
		return (live->attrs[i].handle);
	if (staged->count > live->count)
		return (staged->attrs[i].handle);
	return (0);
}

int
ctl_gatt_commit_result(int client_fd)
{
	uint16_t start;

	if (!gatt_txn.active || gatt_txn.owner_fd != client_fd)
		return (IPC_ERR_NOT_FOUND);

	start = ctl_gatt_changed_start(&periph_gatt_db, &gatt_txn.db);
	if (attdb_copy(&periph_gatt_db, &gatt_txn.db) < 0) {
		ctl_gatt_txn_free();
		return (IPC_ERR_TOOBIG);
	}
	ctl_gatt_txn_free();
	if (start != 0)
		ctl_recompute_hash_and_notify(start, 0xFFFF);
	return (0);
}


int
ctl_gatt_rollback_result(int client_fd)
{

	if (!gatt_txn.active || gatt_txn.owner_fd != client_fd)
		return (IPC_ERR_NOT_FOUND);
	ctl_gatt_txn_free();
	return (0);
}

int
ctl_gatt_set_value_result(int client_fd, uint16_t handle,
    const uint8_t *value, uint16_t value_len)
{
	struct att_attr *attr;
	struct att_db *db;
	bool staged;

	if (handle == 0 || (value == NULL && value_len != 0) ||
	    value_len > ATT_MAX_ATTR_VALUE_LEN /* A-F6: max attr value is 512 */)
		return (IPC_ERR_INVAL);
	/*
	 * C2-L3: when this client owns an active staged txn, apply the value to
	 * the staged scratch DB, not the live periph_gatt_db.  Writing the live
	 * DB mid-txn makes the new value visible to peers immediately and is
	 * then reverted by the COMMIT attdb_copy() (which overwrites live with
	 * the staged snapshot) — so the SET_VALUE would silently vanish.  The
	 * staged path also skips the hash recompute / Service Changed, which
	 * COMMIT emits atomically for the whole batch.
	 */
	db = ctl_gatt_target_db(client_fd, &staged);
	if (db == NULL)
		return (IPC_ERR_BUSY);
	attr = attdb_find_by_handle(db, handle);
	if (attr == NULL)
		return (IPC_ERR_NOT_FOUND);
	if (attr->owner_fd >= 0 && attr->owner_fd != client_fd)
		return (IPC_ERR_PERM);
	if (attr->value == NULL || value_len > attr->value_maxlen)
		return (IPC_ERR_TOOBIG);
	if (value_len != 0)
		memcpy(attr->value, value, value_len);
	attr->value_len = value_len;
	if (staged)
		return (IPC_ERR_NONE);
	/*
	 * A-F6: the Characteristic Extended Properties descriptor (0x2900) value
	 * is covered by the GATT Database Hash (Core Spec Vol 3 Part G §7.3.1).
	 * Mutating it in place without recomputing the hash would leave
	 * change-aware clients with a stale hash, so recompute and signal
	 * Service Changed for its handle.
	 */
	/*
	 * C2-L4: the DB-hash value-inclusion set is 0x2800/0x2801/0x2802/0x2803/
	 * 0x2900 (see attdb_compute_db_hash in att_server_hash.c) — a SET_VALUE
	 * on ANY of these declaration / extended-properties attributes changes
	 * the hash, not only 0x2900.  These declarations are unowned
	 * (owner_fd == -1) so a client can mutate them here; recompute the hash
	 * and signal Service Changed for each so change-aware clients don't keep
	 * a stale hash (Core Spec Vol 3 Part G §7.3.1).
	 */
	switch (attr->uuid16) {
	case 0x2800:
	case 0x2801:
	case 0x2802:
	case 0x2803:
	case 0x2900:
		ctl_recompute_hash_and_notify(handle, handle);
		break;
	}
	return (IPC_ERR_NONE);
}

int
ctl_gatt_remove_service_result(int client_fd, uint16_t handle)
{
	struct att_db *db;
	bool staged;

	if (handle == 0)
		return (IPC_ERR_INVAL);
	db = ctl_gatt_target_db(client_fd, &staged);
	if (db == NULL)
		return (IPC_ERR_BUSY);
	if (attdb_remove_service(db, handle) != 0) {
		/*
		 * C2-M9: a benign per-verb error must NOT tear down an active
		 * staged txn.  Freeing it here would make every subsequent verb
		 * fall through to the LIVE periph_gatt_db (ctl_gatt_target_db
		 * returns the live DB once the txn is inactive), applying changes
		 * one-by-one with mid-apply hash recompute + Service Changed —
		 * exactly what the BEGIN/COMMIT batching exists to prevent.  The
		 * staged DB is unchanged on this error path, so leave the txn
		 * staged for the client to continue or ABORT/COMMIT.
		 */
		return (IPC_ERR_NOT_FOUND);
	}
	BLUED_PROBE_GATT_SVC_REMOVE(handle);
	if (!staged)
		ctl_recompute_hash_and_notify(handle, 0xFFFF);
	return (IPC_ERR_NONE);
}

int
ctl_gatt_add_service_result(int client_fd, uint16_t uuid16,
    const uint8_t uuid128[16], uint16_t *handle_out)
{
	struct att_db *db;
	bool staged;
	uint16_t handle;
	int error = IPC_ERR_NONE;

	if (handle_out == NULL || (uuid16 == 0 && uuid128 == NULL) ||
	    (uuid16 >= 0x2800 && uuid16 <= 0x2803) || uuid16 == 0x1800 ||
	    uuid16 == 0x1801)
		return (IPC_ERR_INVAL);
	db = ctl_gatt_target_db(client_fd, &staged);
	if (db == NULL)
		return (IPC_ERR_BUSY);
	handle = uuid16 != 0 ? attdb_add_service(db, uuid16) :
	    attdb_add_service128(db, uuid128);
	if (handle == 0)
		error = IPC_ERR_TOOBIG;
	else {
		if (!staged)
			ctl_recompute_hash_and_notify(handle, 0xFFFF);
		BLUED_PROBE_GATT_SVC_ADD(handle, uuid16);
		*handle_out = handle;
	}
	/*
	 * C2-M9: do NOT free an active staged txn on a per-verb error.  Each
	 * failure path above either mutated nothing or rolled back via the
	 * attdb mark, so the staged DB stays consistent; tearing the txn down
	 * would make later verbs mutate the LIVE periph_gatt_db directly,
	 * defeating the atomic BEGIN/COMMIT application.  Leave it staged for
	 * the client to continue or ABORT/COMMIT.
	 */
	return (error);
}

int
ctl_gatt_add_char_result(int client_fd, uint16_t service_handle,
    uint16_t uuid16, const uint8_t uuid128[16], uint8_t properties,
    uint8_t permissions, uint8_t flags, const uint8_t *value,
    uint16_t value_len, uint16_t *handle_out)
{
	struct ctl_attdb_mark mark;
	struct att_attr *attr;
	struct att_db *db;
	bool staged;
	uint16_t handle;
	int error = IPC_ERR_NONE;

	if (service_handle == 0 || handle_out == NULL ||
	    (uuid16 == 0 && uuid128 == NULL) ||
	    (value == NULL && value_len != 0) || value_len > ATT_MAX_ATTR_VALUE_LEN /* A-F6: max attr value is 512 */ ||
	    (permissions & ~0x3fu) != 0 ||
	    (flags & ~(ATT_ATTR_F_DYNAMIC | ATT_ATTR_F_AUTHORIZE)) != 0)
		return (IPC_ERR_INVAL);
	db = ctl_gatt_target_db(client_fd, &staged);
	if (db == NULL)
		return (IPC_ERR_BUSY);
	attr = attdb_find_by_handle(db, service_handle);
	if (attr == NULL || (attr->uuid16 != GATT_UUID_PRIMARY_SERVICE &&
	    attr->uuid16 != GATT_UUID_SECONDARY_SERVICE) ||
	    !ctl_service_append_ok(db, service_handle)) {
		error = IPC_ERR_NOT_FOUND;
		goto out;
	}
	ctl_attdb_mark(db, &mark);
	handle = uuid16 != 0 ? attdb_add_characteristic(db, uuid16, properties,
	    permissions, value_len != 0 ? value : NULL, value_len) :
	    attdb_add_characteristic128(db, uuid128, properties, permissions,
	    value_len != 0 ? value : NULL, value_len);
	if (handle == 0) {
		ctl_attdb_rollback(db, &mark);
		error = IPC_ERR_TOOBIG;
		goto out;
	}
	attr = attdb_find_by_handle(db, handle);
	if (attr != NULL) {
		attr->owner_fd = client_fd;
		attr->flags = flags;
	}
	if ((properties & (GATT_PROP_NOTIFY | GATT_PROP_INDICATE)) != 0 &&
	    attdb_add_cccd(db) == 0) {
		ctl_attdb_rollback(db, &mark);
		error = IPC_ERR_TOOBIG;
		goto out;
	}
	attr = attdb_find_by_handle(db, service_handle);
	if (attr != NULL)
		attr->end_group_handle = db->next_handle - 1;
	if (!staged)
		ctl_recompute_hash_and_notify(handle, 0xFFFF);
	*handle_out = handle;
out:
	/*
	 * C2-M9: do NOT free an active staged txn on a per-verb error.  Each
	 * failure path above either mutated nothing or rolled back via the
	 * attdb mark, so the staged DB stays consistent; tearing the txn down
	 * would make later verbs mutate the LIVE periph_gatt_db directly,
	 * defeating the atomic BEGIN/COMMIT application.  Leave it staged for
	 * the client to continue or ABORT/COMMIT.
	 */
	return (error);
}

int
ctl_gatt_add_include_result(int client_fd, uint16_t service_handle,
    uint16_t included_start, uint16_t included_end, uint16_t uuid16,
    uint16_t *handle_out)
{
	struct ctl_attdb_mark mark;
	struct att_attr *service, *included;
	struct att_db *db;
	bool staged;
	uint16_t derived_end, included_uuid16 = 0, handle;
	int error = IPC_ERR_NONE;

	if (service_handle == 0 || included_start == 0 ||
	    included_end < included_start || handle_out == NULL)
		return (IPC_ERR_INVAL);
	db = ctl_gatt_target_db(client_fd, &staged);
	if (db == NULL)
		return (IPC_ERR_BUSY);
	service = attdb_find_by_handle(db, service_handle);
	included = attdb_find_by_handle(db, included_start);
	if (service == NULL || included == NULL || service_handle == included_start ||
	    (service->uuid16 != GATT_UUID_PRIMARY_SERVICE &&
	    service->uuid16 != GATT_UUID_SECONDARY_SERVICE) ||
	    (included->uuid16 != GATT_UUID_PRIMARY_SERVICE &&
	    included->uuid16 != GATT_UUID_SECONDARY_SERVICE) ||
	    !ctl_include_append_ok(db, service_handle) ||
	    !ctl_service_derived_end(db, included_start, &derived_end)) {
		error = IPC_ERR_NOT_FOUND;
		goto out;
	}
	if (included_end != derived_end) {
		error = IPC_ERR_INVAL;
		goto out;
	}
	if (included->value_len == 2) {
		included_uuid16 = (uint16_t)included->value[0] |
		    ((uint16_t)included->value[1] << 8);
		if (uuid16 == 0)
			uuid16 = included_uuid16;
		else if (uuid16 != included_uuid16) {
			error = IPC_ERR_INVAL;
			goto out;
		}
	} else if (uuid16 != 0) {
		error = IPC_ERR_INVAL;
		goto out;
	}
	ctl_attdb_mark(db, &mark);
	handle = attdb_add_include(db, service_handle, included_start,
	    included_end, uuid16);
	if (handle == 0) {
		ctl_attdb_rollback(db, &mark);
		error = IPC_ERR_TOOBIG;
		goto out;
	}
	service = attdb_find_by_handle(db, service_handle);
	if (service != NULL)
		service->end_group_handle = db->next_handle - 1;
	if (!staged)
		ctl_recompute_hash_and_notify(handle, 0xFFFF);
	*handle_out = handle;
out:
	/*
	 * C2-M9: do NOT free an active staged txn on a per-verb error.  Each
	 * failure path above either mutated nothing or rolled back via the
	 * attdb mark, so the staged DB stays consistent; tearing the txn down
	 * would make later verbs mutate the LIVE periph_gatt_db directly,
	 * defeating the atomic BEGIN/COMMIT application.  Leave it staged for
	 * the client to continue or ABORT/COMMIT.
	 */
	return (error);
}

int
ctl_gatt_add_desc_result(int client_fd, uint16_t char_handle,
    uint16_t uuid16, const uint8_t uuid128[16], uint8_t permissions,
    const uint8_t *value, uint16_t value_len, uint16_t *handle_out)
{
	struct att_attr *attr;
	struct att_db *db;
	bool staged;
	uint16_t handle;
	int error = IPC_ERR_NONE;

	if (char_handle == 0 || handle_out == NULL ||
	    (uuid16 == 0 && uuid128 == NULL) ||
	    (value == NULL && value_len != 0) || value_len > ATT_MAX_ATTR_VALUE_LEN /* A-F6: max attr value is 512 */ ||
	    (permissions & ~0x3fu) != 0)
		return (IPC_ERR_INVAL);
	db = ctl_gatt_target_db(client_fd, &staged);
	if (db == NULL)
		return (IPC_ERR_BUSY);
	attr = attdb_find_by_handle(db, char_handle);
	if (attr == NULL || !attr->is_char_value ||
	    !ctl_descriptor_append_ok(db, char_handle)) {
		error = IPC_ERR_NOT_FOUND;
		goto out;
	}
	handle = uuid16 != 0 ? attdb_add_descriptor(db, uuid16, permissions,
	    value_len != 0 ? value : NULL, value_len) :
	    attdb_add_descriptor128(db, uuid128, permissions,
	    value_len != 0 ? value : NULL, value_len);
	if (handle == 0) {
		error = IPC_ERR_TOOBIG;
		goto out;
	}
	attr = ctl_find_parent_service(db, char_handle);
	if (attr != NULL)
		attr->end_group_handle = db->next_handle - 1;
	if (!staged)
		ctl_recompute_hash_and_notify(handle, 0xFFFF);
	*handle_out = handle;
out:
	/*
	 * C2-M9: do NOT free an active staged txn on a per-verb error.  Each
	 * failure path above either mutated nothing or rolled back via the
	 * attdb mark, so the staged DB stays consistent; tearing the txn down
	 * would make later verbs mutate the LIVE periph_gatt_db directly,
	 * defeating the atomic BEGIN/COMMIT application.  Leave it staged for
	 * the client to continue or ABORT/COMMIT.
	 */
	return (error);
}















int
ctl_gatt_notify_result(uint16_t handle, const uint8_t *value,
    uint16_t value_len, bool indicate, int *sent_out)
{
	struct att_attr *val_attr;
	uint16_t cccd_handle;
	uint8_t props;
	uint8_t sec_perms = 0;
	int sent = 0;

	if (handle == 0 || (value == NULL && value_len != 0) ||
	    value_len > ATT_MAX_ATTR_VALUE_LEN /* A-F6: max attr value is 512 */)
		return (IPC_ERR_INVAL);
	pthread_mutex_lock(&blued_g.gatt_db_lock);
	if (!ctl_char_metadata(&periph_gatt_db, handle, &props, &cccd_handle)) {
		pthread_mutex_unlock(&blued_g.gatt_db_lock);
		return (IPC_ERR_NOT_FOUND);
	}
	if ((props & (indicate ? GATT_PROP_INDICATE : GATT_PROP_NOTIFY)) == 0 ||
	    cccd_handle == 0) {
		pthread_mutex_unlock(&blued_g.gatt_db_lock);
		return (IPC_ERR_INVAL);
	}
	/*
	 * A-F2: capture the characteristic value's security requirement so
	 * delivery can be gated on the link meeting the parent characteristic's
	 * encryption/authentication level (Core Spec Vol 3 Part G §10.3.1.1).
	 */
	val_attr = attdb_find_by_handle(&periph_gatt_db, handle);
	if (val_attr != NULL)
		sec_perms = val_attr->perms;
	pthread_mutex_unlock(&blued_g.gatt_db_lock);

	pthread_rwlock_rdlock(&blued_g.conns_lock);
	{
		struct blued_conn *conn;

		LIST_FOREACH(conn, &blued_g.conns, entries) {
			struct att_conn *ac = conn->att;
			int ret;

			if (conn->role != BLUED_ROLE_PERIPHERAL || ac == NULL ||
			    atomic_load(&conn->state) != BLUED_CONN_ACTIVE ||
			    !ctl_cccd_enabled(ac, cccd_handle, indicate ?
			    GATT_CCCD_INDICATE : GATT_CCCD_NOTIFY))
				continue;
			/*
			 * A-F2: never deliver over a link that does not meet the
			 * characteristic's security requirement, even if the CCCD
			 * subscription bit is set.
			 */
			if (att_check_security_perms_read(sec_perms, ac) != 0)
				continue;
			if (indicate) {
				ret = att_send_indication(ac, handle, value, value_len);
				if (ret == 0) {
					blued_ind_arm_timeout(conn);
					sent++;
				}
			} else if (att_send_notification(ac, handle, value,
			    value_len) == 0) {
				sent++;
			}
		}
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
	if (sent_out != NULL)
		*sent_out = sent;
	return (IPC_ERR_NONE);
}





/*
 * Locate the peripheral connection whose ATT bearer has an access deferred on
 * `handle` for the replying client.  Caller holds conns_lock.  want_read
 * selects a dynamic-read pending; otherwise an authorization pending.
 */
static struct blued_conn *
ctl_find_pending_conn(int client_fd, uint16_t handle, bool want_read)
{
	struct blued_conn *conn;

	LIST_FOREACH(conn, &blued_g.conns, entries) {
		struct att_conn *ac = conn->att;

		if (conn->role != BLUED_ROLE_PERIPHERAL || ac == NULL)
			continue;
		if (!att_server_pending_active(ac))
			continue;
		if (att_server_pending_handle(ac) != handle ||
		    att_server_pending_owner(ac) != client_fd)
			continue;
		if (want_read != att_server_pending_is_read(ac))
			continue;
		return (conn);
	}
	return (NULL);
}

int
ctl_gatt_read_reply_result(int client_fd, uint16_t handle,
    const uint8_t *value, uint16_t value_len)
{
	struct blued_conn *conn;

	if (handle == 0 || value_len > ATT_MAX_ATTR_VALUE_LEN /* A-F6: max attr value is 512 */ ||
	    (value == NULL && value_len != 0))
		return (IPC_ERR_INVAL);
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	conn = ctl_find_pending_conn(client_fd, handle, true);
	if (conn != NULL)
		att_server_complete_read(conn->att, value, value_len);
	pthread_rwlock_unlock(&blued_g.conns_lock);
	return (conn != NULL ? IPC_ERR_NONE : IPC_ERR_NOT_FOUND);
}

int
ctl_gatt_read_reject_result(int client_fd, uint16_t handle, uint8_t att_error)
{
	struct blued_conn *conn;

	if (handle == 0 || att_error == 0)
		return (IPC_ERR_INVAL);
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	conn = ctl_find_pending_conn(client_fd, handle, true);
	if (conn != NULL)
		att_server_reject_read(conn->att, att_error);
	pthread_rwlock_unlock(&blued_g.conns_lock);
	return (conn != NULL ? IPC_ERR_NONE : IPC_ERR_NOT_FOUND);
}

int
ctl_gatt_authorize_reply_result(int client_fd, uint16_t handle, bool allow)
{
	struct blued_conn *conn;

	if (handle == 0)
		return (IPC_ERR_INVAL);
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	conn = ctl_find_pending_conn(client_fd, handle, false);
	if (conn != NULL) {
		pthread_mutex_lock(&blued_g.gatt_db_lock);
		att_server_complete_authorize(conn->att, conn->gatt_db, allow);
		pthread_mutex_unlock(&blued_g.gatt_db_lock);
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
	return (conn != NULL ? IPC_ERR_NONE : IPC_ERR_NOT_FOUND);
}
