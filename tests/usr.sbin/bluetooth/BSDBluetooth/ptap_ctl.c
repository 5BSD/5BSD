/* White-box build of ctl.c for defensive registry/worker coverage. */
#include "ctl.c"

int ptap_ctl_internal_completion(void);
int ptap_ctl_cleanup_bound(void);
int ptap_ctl_client_queue_isolation(void);
extern int ctl_test_disconnect_calls;
int ptap_plane_stalled(void);
int ptap_plane_attach(void);

static void
ptap_plane_reply(struct channel_request *request __unused,
    struct channel_message *message, int error, void *argument)
{
	int *fd = argument;
	const struct blued_plane_msg *reply;

	if (error == 0 && message != NULL &&
	    channel_message_length(message) == sizeof(*reply)) {
		reply = channel_message_data(message);
		if (reply->status == 0 && channel_message_fd_count(message) == 1)
			*fd = channel_message_take_fd(message, 0);
	}
	if (message != NULL)
		channel_message_free(message);
}

int
ptap_plane_attach(void)
{
	struct service_identity id = { .size = sizeof(id), .rights = 0 };
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	struct blued_plane_msg input = { .magic = BLUED_PLANE_MAGIC,
	    .opcode = BLUED_PLANE_OP_ATTACH };
	struct channel_outgoing out = CHANNEL_OUTGOING_INITIALIZER(&input, sizeof(input));
	struct channel_request *request;
	struct channel *client;
	struct kevent events[8];
	struct timespec timeout = { .tv_nsec = 100000000 };
	struct blued_ctl_client *adopted;
	int sv[2], i, n, turn, received = -1, result = 0;

	blued_g.kq = kqueue();
	blued_ctl_plane_batch_begin();
	strlcpy(id.container, "org.5bsd.Test/gui", sizeof(id.container));
	if (blued_g.kq < 0 || mac_capability_channel_create(sv) != 0)
		return (1);
	if (channel_create(sv[0], &options, &client) != 0 || plane_start(sv[1], &id) != 0)
		return (2);
	if (channel_send_request(client, &out, ptap_plane_reply, &received, &request) != 0)
		return (3);
	for (turn = 0; turn < 10 && received < 0; turn++) {
		if (channel_flush(client) != 0)
			return (4);
		n = kevent(blued_g.kq, NULL, 0, events, 8, &timeout);
		blued_ctl_plane_batch_begin();
		for (i = 0; i < n; i++)
			(void)blued_ctl_plane_event(&events[i]);
		(void)channel_dispatch(client);
	}
	adopted = LIST_FIRST(&blued_g.ctl_clients);
	if (received < 0 || adopted == NULL)
		result = 5;
	else if (adopted->peer_uid != (uid_t)-1)
		result = 6;
	if (received >= 0)
		close(received);
	channel_destroy(client);
	blued_ctl_cleanup();
	close(blued_g.kq);
	blued_g.kq = -1;
	return (result);
}

/* Real channels: admission must not wait for a silent client. */
int
ptap_plane_stalled(void)
{
	struct service_identity id = { .size = sizeof(id) };
	struct kevent ev;
	struct timespec start, end;
	int peers[BLUED_MAX_CTL], sv[2], i, rc = 0;

	blued_g.kq = kqueue();
	if (blued_g.kq < 0)
		return (1);
	blued_ctl_plane_batch_begin();
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < BLUED_MAX_CTL; i++) {
		if (mac_capability_channel_create(sv) != 0)
			return (2);
		peers[i] = sv[0];
		if (plane_start(sv[1], &id) != 0)
			return (3);
	}
	clock_gettime(CLOCK_MONOTONIC, &end);
	if ((end.tv_sec - start.tv_sec) * 1000000000LL +
	    end.tv_nsec - start.tv_nsec > 1000000000LL)
		rc = 4;
	if (mac_capability_channel_create(sv) != 0)
		return (5);
	if (plane_start(sv[1], &id) != -1 || errno != EBUSY)
		rc = 6;
	close(sv[0]);
	for (i = 0; i < BLUED_MAX_CTL; i++) {
		EV_SET(&ev, plane_pending[i].timer, EVFILT_TIMER, 0,
		    0, 0, &plane_pending[i]);
		if (!blued_ctl_plane_event(&ev) || plane_pending[i].channel != NULL ||
		    !plane_pending[i].retired || !blued_ctl_plane_event(&ev))
			rc = 7;
		close(peers[i]);
	}
	blued_ctl_plane_batch_begin();
	if (mac_capability_channel_create(sv) != 0)
		return (8);
	if (plane_start(sv[1], &id) != 0)
		rc = 9;
	close(sv[0]);
	blued_ctl_cleanup();
	close(blued_g.kq);
	blued_g.kq = -1;
	return (rc);
}

int
ptap_ctl_client_queue_isolation(void)
{
	struct blued_adapter adp = { .index = 2, .active = true, .powered = true };
	struct blued_ctl_client clients[2] = {
	    { .fd = 80, .generation = 10 }, { .fd = 81, .generation = 11 }
	};
	struct att_conn att = { .fd = -1, .mtu = 23 };
	struct blued_conn *conn;
	bdaddr_t peer;
	int result = -1;

	if (!bt_aton("11:22:33:44:55:66", &peer))
		return (-1);
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	conn = blued_conn_alloc();
	if (conn == NULL) {
		LIST_REMOVE(&adp, entries);
		return (-1);
	}
	conn->adapter = &adp;
	conn->dst = peer;
	conn->addr_type = BDADDR_LE_PUBLIC;
	conn->att = &att;
	conn->att_fd = -1;
	blued_conn_set_state(conn, BLUED_CONN_ACTIVE);

	/* Deliberately leave workers stopped to make queue admission deterministic. */
	for (int owner = 0; owner != 2; owner++) {
		for (int i = 0; i != CTL_GATT_CLIENT_QUEUE_MAX; i++) {
			if (ctl_gatt_job_start(&clients[owner], IPC_GATT_READ, 2,
			    &peer, BDADDR_LE_PUBLIC, 0x25, 0, NULL, 0) != IPC_ERR_NONE)
				goto out;
		}
		if (ctl_gatt_job_start(&clients[owner], IPC_GATT_READ, 2,
		    &peer, BDADDR_LE_PUBLIC, 0x25, 0, NULL, 0) != IPC_ERR_BUSY)
			goto out;
	}
	if (ctl_gatt_jobs_count != 2 * CTL_GATT_CLIENT_QUEUE_MAX)
		goto out;
	ctl_gatt_jobs_cancel_client(clients[0].fd);
	if (ctl_gatt_jobs_count != CTL_GATT_CLIENT_QUEUE_MAX ||
	    atomic_load(&conn->att_ops_active) != CTL_GATT_CLIENT_QUEUE_MAX)
		goto out;
	/* Admission recovers after cancellation; the second owner's work survives. */
	if (ctl_gatt_job_start(&clients[0], IPC_GATT_READ, 2, &peer,
	    BDADDR_LE_PUBLIC, 0x25, 0, NULL, 0) != IPC_ERR_NONE)
		goto out;
	result = 0;
out:
	ctl_gatt_workers_stop();
	if (ctl_gatt_jobs_count != 0 || atomic_load(&conn->att_ops_active) != 0)
		result = -1;
	conn->att = NULL;
	blued_conn_free(conn);
	LIST_REMOVE(&adp, entries);
	return (result);
}

int
ptap_ctl_cleanup_bound(void)
{
	struct blued_ctl_client client;
	struct blued_adapter adp;
	struct blued_conn *conn, *random_alias;
	struct att_conn att;
	bdaddr_t peer;
	int batch, disconnects, i, ordinal, result;

	memset(&client, 0, sizeof(client));
	memset(&adp, 0, sizeof(adp));
	memset(&att, 0, sizeof(att));
	if (!bt_aton("11:22:33:44:55:66", &peer))
		return (-1);
	adp.index = 2;
	adp.active = true;
	adp.powered = true;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	att.fd = -1;
	att.mtu = 23;
	conn = blued_conn_alloc();
	if (conn == NULL) {
		LIST_REMOVE(&adp, entries);
		return (-1);
	}
	conn->adapter = &adp;
	conn->dst = peer;
	conn->addr_type = BDADDR_LE_PUBLIC;
	conn->att = &att;
	conn->att_fd = -1;
	blued_conn_set_state(conn, BLUED_CONN_ACTIVE);
	conn->reconnect = true;
	/* Same address bytes in the other identity domain must never alias. */
	random_alias = blued_conn_alloc();
	if (random_alias == NULL) {
		conn->att = NULL;
		blued_conn_free(conn);
		LIST_REMOVE(&adp, entries);
		return (-1);
	}
	random_alias->adapter = &adp;
	random_alias->dst = peer;
	random_alias->addr_type = BDADDR_LE_RANDOM;
	random_alias->att = &att;
	random_alias->att_fd = -1;
	blued_conn_set_state(random_alias, BLUED_CONN_ACTIVE);
	random_alias->reconnect = true;
	client.fd = 80;
	client.generation = 1;
	result = -1;

	/* No workers: repeated full-client churn must coalesce to sixteen jobs. */
	for (batch = 0; batch < 1000; batch++) {
		for (i = 0; i < CTL_MAX_SUBSCRIPTIONS; i++) {
			client.subs[i] = (struct ctl_subscription){
			    .addr = peer, .handle = (uint16_t)(0x0100 + i * 2),
			    .cccd_handle = (uint16_t)(0x0101 + i * 2),
			    .cccd_value = GATT_CCCD_NOTIFY,
			    .addr_type = BDADDR_LE_PUBLIC,
			    .adapter_index = 2 };
		}
		client.nsubs = CTL_MAX_SUBSCRIPTIONS;
		ctl_gatt_client_gone(&client);
	}
	if (ctl_gatt_jobs_count != CTL_MAX_SUBSCRIPTIONS ||
	    ctl_gatt_cleanup_count != CTL_MAX_SUBSCRIPTIONS ||
	    atomic_load(&conn->att_ops_active) != CTL_MAX_SUBSCRIPTIONS)
		goto out;

	/* Fill the fixed registry, then force distinct cleanup overflow. */
	for (batch = 1; batch < BLUED_MAX_CTL; batch++) {
		for (i = 0; i < CTL_MAX_SUBSCRIPTIONS; i++) {
			ordinal = batch * CTL_MAX_SUBSCRIPTIONS + i;
			client.subs[i] = (struct ctl_subscription){
			    .addr = peer,
			    .handle = (uint16_t)(0x0100 + ordinal * 2),
			    .cccd_handle = (uint16_t)(0x0101 + ordinal * 2),
			    .cccd_value = GATT_CCCD_NOTIFY,
			    .addr_type = BDADDR_LE_PUBLIC,
			    .adapter_index = 2 };
		}
		client.nsubs = CTL_MAX_SUBSCRIPTIONS;
		ctl_gatt_client_gone(&client);
	}
	if (ctl_gatt_cleanup_count != CTL_GATT_CLEANUP_MAX ||
	    ctl_gatt_jobs_count != CTL_GATT_CLEANUP_MAX)
		goto out;
	disconnects = ctl_test_disconnect_calls;
	for (i = 0; i < CTL_MAX_SUBSCRIPTIONS; i++) {
		ordinal = CTL_GATT_CLEANUP_MAX + i;
		client.subs[i] = (struct ctl_subscription){
		    .addr = peer, .handle = (uint16_t)(0x0100 + ordinal * 2),
		    .cccd_handle = (uint16_t)(0x0101 + ordinal * 2),
		    .cccd_value = GATT_CCCD_NOTIFY,
		    .addr_type = BDADDR_LE_PUBLIC,
		    .adapter_index = 2 };
	}
	client.nsubs = CTL_MAX_SUBSCRIPTIONS;
	ctl_gatt_client_gone(&client);
	if (ctl_gatt_cleanup_count != CTL_GATT_CLEANUP_MAX ||
	    ctl_gatt_jobs_count != CTL_GATT_CLEANUP_MAX ||
	    atomic_load(&conn->att_ops_active) != CTL_GATT_CLEANUP_MAX ||
	    ctl_test_disconnect_calls == disconnects || conn->reconnect ||
	    !random_alias->reconnect)
		goto out;
	result = 0;
out:
	ctl_gatt_workers_stop();
	if (ctl_gatt_cleanup_count != 0 || ctl_gatt_jobs_count != 0 ||
	    atomic_load(&conn->att_ops_active) != 0)
		result = -1;
	conn->att = NULL;
	blued_conn_free(conn);
	random_alias->att = NULL;
	blued_conn_free(random_alias);
	LIST_REMOVE(&adp, entries);
	return (result);
}

int
ptap_ctl_internal_completion(void)
{
	struct ctl_acquire *acq;
	struct ctl_gatt_job *job1, *job2;
	struct blued_conn *conn;
	struct blued_adapter adp;
	struct blued_ctl_client owner, other;
	struct kevent ev;
	bdaddr_t addr;
	bool bad;
	int sv[2];
	char byte = 'x';

	memset(&addr, 0x5a, sizeof(addr));
	acq = calloc(1, sizeof(*acq));
	if (acq == NULL)
		return (-1);
	acq->addr = addr;
	acq->adapter_index = 2;
	acq->addr_type = 1;
	acq->handle = 0x1234;
	acq->dir = CTL_ACQ_NOTIFY;
	acq->daemon_fd = -1;
	LIST_INSERT_HEAD(&blued_g.ctl_acquires, acq, entries);
	(void)ctl_acquire_find(1, &addr, 1, 0x1234, CTL_ACQ_NOTIFY);
	if (ctl_acquire_find(2, &addr, 1, 0x1234, CTL_ACQ_NOTIFY) != acq)
		return (-1);
	ctl_acquire_teardown(acq);

	/* Dispatch covers absent descriptors, EOF teardown, peer-close teardown,
	 * and a WRITE datagram whose connection disappeared. */
	memset(&ev, 0, sizeof(ev));
	ev.ident = INT_MAX;
	ctl_acquire_dispatch(&ev);
	memset(&owner, 0, sizeof(owner));
	memset(&other, 0, sizeof(other));
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0)
		return (-1);
	acq = calloc(1, sizeof(*acq));
	if (acq == NULL)
		return (-1);
	acq->daemon_fd = sv[0]; acq->client = &owner;
	LIST_INSERT_HEAD(&blued_g.ctl_acquires, acq, entries);
	ev.ident = sv[0]; ev.flags = EV_EOF;
	ctl_acquire_dispatch(&ev);
	close(sv[1]);

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0)
		return (-1);
	acq = calloc(1, sizeof(*acq));
	if (acq == NULL)
		return (-1);
	acq->daemon_fd = sv[0]; acq->client = &owner;
	LIST_INSERT_HEAD(&blued_g.ctl_acquires, acq, entries);
	close(sv[1]);
	ev.ident = sv[0]; ev.flags = 0;
	ctl_acquire_dispatch(&ev);

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0)
		return (-1);
	acq = calloc(1, sizeof(*acq));
	if (acq == NULL)
		return (-1);
	acq->daemon_fd = sv[0]; acq->client = &owner;
	acq->dir = CTL_ACQ_WRITE; acq->mtu = 23;
	acq->addr = addr; acq->adapter_index = 9; acq->handle = 1;
	LIST_INSERT_HEAD(&blued_g.ctl_acquires, acq, entries);
	(void)send(sv[1], &byte, 1, 0);
	ev.ident = sv[0]; ev.flags = 0;
	ctl_acquire_dispatch(&ev);
	/* Non-owner is skipped, owner removes the remaining record. */
	ctl_acquire_client_gone(&other);
	ctl_acquire_client_gone(&owner);
	close(sv[1]);

	/* Cover both implicit-active and explicit-index adapter selection. */
	memset(&adp, 0, sizeof(adp));
	adp.active = true;
	adp.index = 7;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	(void)ctl_typed_adapter(0, 0, &bad);
	(void)ctl_typed_adapter(IPC_CTL_F_ADAPTER, 7, &bad);
	(void)ctl_typed_adapter(IPC_CTL_F_ADAPTER, 8, &bad);
	LIST_REMOVE(&adp, entries);

	/* Notification routing skips a mismatch, then sends on an exact match;
	 * connection teardown removes the record. */
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0)
		return (-1);
	acq = calloc(1, sizeof(*acq));
	if (acq == NULL)
		return (-1);
	acq->daemon_fd = sv[0]; acq->dir = CTL_ACQ_NOTIFY;
	acq->adapter_index = adp.index; acq->addr_type = 1;
	acq->handle = 0x44; acq->addr = addr;
	LIST_INSERT_HEAD(&blued_g.ctl_acquires, acq, entries);
	/* Use a temporary stack view only for the routing predicates. */
	{
		struct blued_conn view;
		memset(&view, 0, sizeof(view));
		view.adapter = &adp; view.addr_type = 1; view.dst = addr;
		ctl_acquire_route_notify(&view, 0x45, (uint8_t *)&byte, 1);
		ctl_acquire_route_notify(&view, 0x44, (uint8_t *)&byte, 1);
		ctl_acquire_conn_gone(&view);
	}
	close(sv[1]);

	/* Cancel one queued GATT operation by owner, then let worker shutdown
	 * drain the other.  Both paths restore the connection busy flag/ref. */
	conn = blued_conn_alloc();
	job1 = calloc(1, sizeof(*job1));
	job2 = calloc(1, sizeof(*job2));
	if (conn == NULL || job1 == NULL || job2 == NULL) {
		free(job1); free(job2);
		if (conn != NULL)
			blued_conn_free(conn);
		return (-1);
	}
	conn->att_fd = -1;
	job1->conn = conn; job1->client_fd = 10;
	job2->conn = conn; job2->client_fd = 11;
	blued_conn_ref(conn);
	blued_conn_ref(conn);
	ctl_gatt_jobs_stopping = false;
	STAILQ_INSERT_TAIL(&ctl_gatt_jobs, job1, entries);
	STAILQ_INSERT_TAIL(&ctl_gatt_jobs, job2, entries);
	ctl_gatt_jobs_count = 2;
	ctl_gatt_jobs_cancel_client(10);
	ctl_gatt_workers_stop();
	blued_conn_free(conn);

	/* Frame-envelope validation sits before all typed-domain dispatch.  Drive
	 * each reject path directly so malformed peers cannot hide behind a
	 * higher-level request builder. */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return (-1);
	memset(&owner, 0, sizeof(owner));
	owner.fd = sv[0];
	ctl_process_frame(&owner, 0xffff, 0, NULL, 0);
	ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_CTL, NULL, 0);
	{
		uint8_t envelope[IPC_OP_PREFIX_SIZE + 4] = { 0 };

		/* request ID zero, nonzero request status, and nonzero flags each
		 * violate the operation envelope before a domain is selected. */
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_CTL,
		    envelope, IPC_OP_PREFIX_SIZE);
		ipc_op_prefix_encode(envelope, 7, IPC_ERR_IO, 0);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_CTL,
		    envelope, IPC_OP_PREFIX_SIZE);
		ipc_op_prefix_encode(envelope, 8, IPC_ERR_NONE, 1);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_CTL,
		    envelope, IPC_OP_PREFIX_SIZE);
		ipc_op_prefix_encode(envelope, 9, IPC_ERR_NONE, 0);
		ctl_process_frame(&owner, IPC_T_OP_REQ, 0x7fff, envelope,
		    sizeof(envelope));

		/* HELLO has an independently checked feature-vector length. */
		ctl_process_frame(&owner, IPC_T_HELLO, 0,
		    envelope, 0);

		/* ISO was the one framed domain not represented by the generic
		 * dispatcher matrix.  Its error paths are entirely local: exercise
		 * privilege, adapter, header/flag and every verb-family validator
		 * without opening a controller socket. */
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    sizeof(envelope));
		owner.peer_known = true;
		owner.peer_uid = 0;
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    sizeof(envelope));
		memset(&adp, 0, sizeof(adp));
		adp.active = true;
		adp.index = 0;
		adp.hci_fd = -1;
		LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    IPC_OP_PREFIX_SIZE);
		memset(envelope + IPC_OP_PREFIX_SIZE, 0, 2);
		ipc_put_le16(envelope + IPC_OP_PREFIX_SIZE, 0xffff);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    sizeof(envelope));
		ipc_put_le16(envelope + IPC_OP_PREFIX_SIZE, IPC_ISO_CIG_CREATE);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    sizeof(envelope));
		ipc_put_le16(envelope + IPC_OP_PREFIX_SIZE, IPC_ISO_CIS_CREATE);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    sizeof(envelope));
		ipc_put_le16(envelope + IPC_OP_PREFIX_SIZE, IPC_ISO_CIS_TEARDOWN);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    sizeof(envelope));
		ipc_put_le16(envelope + IPC_OP_PREFIX_SIZE, IPC_ISO_CIG_REMOVE);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    sizeof(envelope));
		ipc_put_le16(envelope + IPC_OP_PREFIX_SIZE, IPC_ISO_CIS_ACCEPT);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    sizeof(envelope));
		ipc_put_le16(envelope + IPC_OP_PREFIX_SIZE, IPC_ISO_CIS_REJECT);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    sizeof(envelope));
		ipc_put_le16(envelope + IPC_OP_PREFIX_SIZE, IPC_ISO_BIG_TERMINATE);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    sizeof(envelope));
		ipc_put_le16(envelope + IPC_OP_PREFIX_SIZE,
		    IPC_ISO_BIG_SYNC_TERMINATE);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    sizeof(envelope));
		ipc_put_le16(envelope + IPC_OP_PREFIX_SIZE, IPC_ISO_BIG_CREATE);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    sizeof(envelope));
		ipc_put_le16(envelope + IPC_OP_PREFIX_SIZE, IPC_ISO_BIG_SYNC_CREATE);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    sizeof(envelope));
		ipc_put_le16(envelope + IPC_OP_PREFIX_SIZE, IPC_ISO_ACQUIRE);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    sizeof(envelope));
		ipc_put_le16(envelope + IPC_OP_PREFIX_SIZE, IPC_ISO_BIS_ACQUIRE);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    sizeof(envelope));
		ipc_put_le16(envelope + IPC_OP_PREFIX_SIZE,
		    IPC_ISO_CONNECT_ACQUIRE);
		ctl_process_frame(&owner, IPC_T_OP_REQ, IPC_OP_DOMAIN_ISO, envelope,
		    sizeof(envelope));
		LIST_REMOVE(&adp, entries);
	}
	close(sv[0]);
	close(sv[1]);
	return (0);
}
