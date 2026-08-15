/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "virtio_fs_backend.h"
#include "virtio_fs_backend_client.h"
#include "virtio_fs_backend_io.h"
#include "virtio_fs_connection.h"
#include "virtio_fs_queue.h"
#include "virtio_state_range.h"

struct virtio_fs_connection {
	struct virtio_fs_backend_client *client;
	struct virtio_fs_queue *queue;
	virtio_fs_queue_complete_cb complete;
	void *complete_arg;
	virtio_fs_connection_notify_cb notify;
	void *notify_arg;
	uint8_t *receive_buffer;
	uint8_t *notification_payload;
	uint32_t normal_capacity;
	uint32_t priority_capacity;
	uint32_t maximum_message;
	uint32_t required_features;
	struct virtio_fs_backend_session session;
	struct virtio_fs_backend_header control_header;
	struct virtio_fs_session checkpoint_fuse_session;
	uint8_t *control_payload;
	uint8_t *checkpoint_backend_state;
	size_t control_payload_len;
	size_t checkpoint_backend_state_len;
	size_t notification_payload_len;
	uint64_t next_control_id;
	int control_error;
	bool checkpoint_fuse_session_valid;
	bool control_active;
	bool control_done;
	bool control_pending_send;
	bool notifications_fenced;
	bool session_valid;
	/*
	 * Completion callbacks run synchronously while queue destruction drains
	 * retained guest requests.  They may inspect this public object, but no
	 * callback may restart a backend or mutate checkpoint state once teardown
	 * has begun.
	 */
	bool destroying;
	int fd;
	int error;
};

static bool
virtio_fs_connection_state_overlaps(
    const struct virtio_fs_connection *connection, const void *buffer,
    size_t length)
{

	if (buffer == NULL)
		return (false);
	return (virtio_state_ranges_overlap(buffer, length, connection,
	    sizeof(*connection)) ||
	    virtio_state_ranges_overlap(buffer, length,
	    connection->receive_buffer, connection->maximum_message) ||
	    virtio_state_ranges_overlap(buffer, length,
	    connection->control_payload, connection->control_payload_len) ||
	    virtio_state_ranges_overlap(buffer, length,
	    connection->checkpoint_backend_state,
	    connection->checkpoint_backend_state_len) ||
	    virtio_state_ranges_overlap(buffer, length,
	    connection->notification_payload,
	    connection->notification_payload_len));
}

static int
virtio_fs_connection_fail(struct virtio_fs_connection *connection, int error)
{
	size_t completed;
	int queue_error;

	if (error == 0)
		error = EIO;
	if (connection->queue != NULL) {
		queue_error = virtio_fs_queue_fail(connection->queue, &completed);
		/*
		 * Preserve the transport/protocol error as the connection's
		 * terminal cause.  Completion-scatter failure is secondary and
		 * is observable through a zero-length completion.
		 */
		(void)queue_error;
	}
	if (connection->fd >= 0) {
		(void)close(connection->fd);
		connection->fd = -1;
	}
	connection->error = error;
	return (error);
}

static int
virtio_fs_connection_activate(struct virtio_fs_connection *connection)
{
	struct virtio_fs_backend_session session;
	int error, fd;

	error = virtio_fs_backend_client_take_active(connection->client,
	    &session, &fd);
	if (error != 0)
		return (error);
	if ((session.features & connection->required_features) !=
	    connection->required_features) {
		(void)close(fd);
		return (ENOTSUP);
	}
	connection->receive_buffer = malloc(session.maximum_message);
	if (connection->receive_buffer == NULL) {
		(void)close(fd);
		return (ENOMEM);
	}
	error = virtio_fs_queue_create(&session, connection->normal_capacity,
	    connection->priority_capacity, connection->complete,
	    connection->complete_arg, &connection->queue);
	if (error != 0) {
		free(connection->receive_buffer);
		connection->receive_buffer = NULL;
		(void)close(fd);
		return (error);
	}
	connection->maximum_message = session.maximum_message;
	connection->session = session;
	connection->session_valid = true;
	connection->fd = fd;
	return (0);
}

static int
virtio_fs_connection_alloc(uint32_t normal_capacity,
    uint32_t priority_capacity, uint32_t required_features,
    virtio_fs_queue_complete_cb complete, void *complete_arg,
    struct virtio_fs_connection **result)
{
	struct virtio_fs_connection *connection;

	if (result == NULL || complete == NULL || normal_capacity == 0 ||
	    priority_capacity == 0 ||
	    (required_features & ~VIRTIO_FS_BACKEND_F_ALL) != 0)
		return (EINVAL);
	*result = NULL;
	connection = calloc(1, sizeof(*connection));
	if (connection == NULL)
		return (ENOMEM);
	connection->fd = -1;
	connection->complete = complete;
	connection->complete_arg = complete_arg;
	connection->normal_capacity = normal_capacity;
	connection->priority_capacity = priority_capacity;
	connection->required_features = required_features;
	connection->next_control_id = 1;
	*result = connection;
	return (0);
}

int
virtio_fs_connection_connect(const char *path, uid_t expected_uid,
    gid_t expected_gid, const struct virtio_fs_backend_hello *offer,
    uint32_t normal_capacity, uint32_t priority_capacity,
    virtio_fs_queue_complete_cb complete, void *complete_arg,
    struct virtio_fs_connection **result)
{

	return (virtio_fs_connection_connect_required(path, expected_uid,
	    expected_gid, offer, normal_capacity, priority_capacity, 0,
	    complete, complete_arg, result));
}

int
virtio_fs_connection_connect_required(const char *path, uid_t expected_uid,
    gid_t expected_gid, const struct virtio_fs_backend_hello *offer,
    uint32_t normal_capacity, uint32_t priority_capacity,
    uint32_t required_features, virtio_fs_queue_complete_cb complete,
    void *complete_arg, struct virtio_fs_connection **result)
{
	struct virtio_fs_connection *connection;
	int error;

	if (offer == NULL ||
	    (required_features & ~offer->features) != 0)
		return (EINVAL);
	error = virtio_fs_connection_alloc(normal_capacity, priority_capacity,
	    required_features, complete, complete_arg, &connection);
	if (error != 0)
		return (error);
	error = virtio_fs_backend_client_connect(path, expected_uid,
	    expected_gid, offer, &connection->client);
	if (error != 0) {
		free(connection);
		return (error);
	}
	*result = connection;
	return (0);
}

int
virtio_fs_connection_adopt(int fd, uid_t expected_uid, gid_t expected_gid,
    const struct virtio_fs_backend_hello *offer, uint32_t normal_capacity,
    uint32_t priority_capacity, virtio_fs_queue_complete_cb complete,
    void *complete_arg, struct virtio_fs_connection **result)
{

	return (virtio_fs_connection_adopt_required(fd, expected_uid,
	    expected_gid, offer, normal_capacity, priority_capacity, 0,
	    complete, complete_arg, result));
}

int
virtio_fs_connection_adopt_required(int fd, uid_t expected_uid,
    gid_t expected_gid, const struct virtio_fs_backend_hello *offer,
    uint32_t normal_capacity, uint32_t priority_capacity,
    uint32_t required_features, virtio_fs_queue_complete_cb complete,
    void *complete_arg, struct virtio_fs_connection **result)
{
	struct virtio_fs_connection *connection;
	int error;

	if (offer == NULL ||
	    (required_features & ~offer->features) != 0)
		return (EINVAL);
	error = virtio_fs_connection_alloc(normal_capacity, priority_capacity,
	    required_features, complete, complete_arg, &connection);
	if (error != 0)
		return (error);
	error = virtio_fs_backend_client_adopt(fd, expected_uid, expected_gid,
	    offer, &connection->client);
	if (error != 0) {
		free(connection);
		return (error);
	}
	*result = connection;
	return (0);
}

void
virtio_fs_connection_destroy(struct virtio_fs_connection *connection)
{
	struct virtio_fs_queue *queue;

	if (connection == NULL)
		return;
	if (connection->destroying)
		return;
	connection->destroying = true;
	/*
	 * queue_destroy() fails every retained request and invokes the caller's
	 * completion callback.  That callback is allowed to query connection
	 * pressure for tracing, so withdraw the queue from the public connection
	 * view before its storage can be reclaimed.  A teardown completion then
	 * observes zero pending/outgoing work rather than following a dangling
	 * queue pointer.
	 */
	queue = connection->queue;
	connection->queue = NULL;
	virtio_fs_queue_destroy(queue);
	virtio_fs_backend_client_destroy(connection->client);
	if (connection->fd >= 0)
		(void)close(connection->fd);
	free(connection->checkpoint_backend_state);
	free(connection->control_payload);
	free(connection->notification_payload);
	free(connection->receive_buffer);
	free(connection);
}

int
virtio_fs_connection_set_reset_complete(
    struct virtio_fs_connection *connection,
    virtio_fs_queue_reset_complete_cb reset_complete,
    void *reset_complete_arg)
{

	if (connection == NULL)
		return (EINVAL);
	if (connection->destroying)
		return (ECANCELED);
	if (connection->queue == NULL)
		return (ENOTCONN);
	return (virtio_fs_queue_set_reset_complete(connection->queue,
	    reset_complete, reset_complete_arg));
}

int
virtio_fs_connection_set_discard(struct virtio_fs_connection *connection,
    virtio_fs_queue_discard_cb discard, void *discard_arg)
{

	if (connection == NULL)
		return (EINVAL);
	if (connection->destroying)
		return (ECANCELED);
	if (connection->queue == NULL)
		return (ENOTCONN);
	return (virtio_fs_queue_set_discard(connection->queue, discard,
	    discard_arg));
}

static int
virtio_fs_connection_deliver_notification(
    struct virtio_fs_connection *connection)
{
	int error;

	if (connection->notification_payload == NULL)
		return (0);
	if (connection->notify == NULL)
		return (ENOTSUP);
	error = connection->notify(connection->notify_arg,
	    connection->notification_payload, connection->notification_payload_len);
	if (error == EAGAIN || error == EWOULDBLOCK)
		return (EAGAIN);
	if (error != 0)
		return (error);
	free(connection->notification_payload);
	connection->notification_payload = NULL;
	connection->notification_payload_len = 0;
	return (0);
}

int
virtio_fs_connection_set_notification(struct virtio_fs_connection *connection,
    virtio_fs_connection_notify_cb notify, void *notify_arg)
{
	int error;

	if (connection == NULL || notify == NULL)
		return (EINVAL);
	if (connection->destroying)
		return (ECANCELED);
	if (connection->queue == NULL || !connection->session_valid)
		return (ENOTCONN);
	if ((connection->session.features & VIRTIO_FS_BACKEND_F_NOTIFICATION) == 0)
		return (ENOTSUP);
	if (connection->notify != NULL)
		return (EALREADY);
	connection->notify = notify;
	connection->notify_arg = notify_arg;
	error = virtio_fs_connection_deliver_notification(connection);
	if (error != 0 && error != EAGAIN) {
		connection->notify = NULL;
		connection->notify_arg = NULL;
	}
	return (error);
}

int
virtio_fs_connection_retry_notification(struct virtio_fs_connection *connection)
{
	int error;

	if (connection == NULL)
		return (EINVAL);
	if (connection->destroying)
		return (ECANCELED);
	if (connection->error != 0)
		return (connection->error);
	error = virtio_fs_connection_deliver_notification(connection);
	if (error != 0 && error != EAGAIN)
		return (virtio_fs_connection_fail(connection, error));
	return (error);
}

int
virtio_fs_connection_fd(const struct virtio_fs_connection *connection)
{

	if (connection == NULL)
		return (-1);
	if (connection->destroying)
		return (-1);
	if (connection->fd >= 0)
		return (connection->fd);
	return (virtio_fs_backend_client_fd(connection->client));
}

uint32_t
virtio_fs_connection_events(struct virtio_fs_connection *connection)
{
	uint32_t events;

	if (connection == NULL || connection->destroying || connection->error != 0)
		return (0);
	if (connection->queue == NULL) {
		events = virtio_fs_backend_client_events(connection->client);
		return (((events & VIRTIO_FS_BACKEND_CLIENT_READ) != 0 ?
		    VIRTIO_FS_CONNECTION_READ : 0) |
		    ((events & VIRTIO_FS_BACKEND_CLIENT_WRITE) != 0 ?
		    VIRTIO_FS_CONNECTION_WRITE : 0));
	}
	events = VIRTIO_FS_CONNECTION_READ;
	if (connection->control_pending_send ||
	    virtio_fs_queue_outgoing(connection->queue) != 0)
		events |= VIRTIO_FS_CONNECTION_WRITE;
	return (events);
}

static int
virtio_fs_connection_finish_control(struct virtio_fs_connection *connection,
    const struct virtio_fs_backend_header *header, const void *payload,
    size_t payload_len)
{
	uint8_t *state;
	int error;

	if (!connection->control_active || connection->control_done ||
	    header->request_id != connection->session.pending_control_id)
		return (EPROTO);
	state = NULL;
	if (header->type == VIRTIO_FS_BACKEND_QUIESCE_REPLY &&
	    header->status == 0 && payload_len != 0) {
		state = malloc(payload_len);
		if (state == NULL)
			return (ENOMEM);
		memcpy(state, payload, payload_len);
	}
	error = virtio_fs_backend_finish_control(&connection->session, header);
	/*
	 * A nonzero backend status is an ordinary control-operation refusal:
	 * finish_control() has already restored the phase from QUIESCING or
	 * THAWING and the caller may retry.  All other errors describe a broken
	 * control protocol or an inconsistent local state.  Do not mark those as
	 * a completed control operation, since doing so would leave admission
	 * fenced in an intermediate phase.  Propagate them so progress() tears
	 * down the connection and drains its ownership.
	 */
	if (error != 0 && error != EIO) {
		free(state);
		return (error);
	}
	if (error == 0 &&
	    header->type == VIRTIO_FS_BACKEND_QUIESCE_REPLY) {
		free(connection->checkpoint_backend_state);
		connection->checkpoint_backend_state = state;
		connection->checkpoint_backend_state_len = payload_len;
		state = NULL;
	} else if (error == 0 &&
	    header->type == VIRTIO_FS_BACKEND_THAW_REPLY) {
		free(connection->checkpoint_backend_state);
		connection->checkpoint_backend_state = NULL;
		connection->checkpoint_backend_state_len = 0;
		connection->checkpoint_fuse_session_valid = false;
		connection->notifications_fenced = false;
		virtio_fs_queue_resume(connection->queue);
	} else if (header->type == VIRTIO_FS_BACKEND_QUIESCE_REPLY) {
		connection->checkpoint_fuse_session_valid = false;
		connection->notifications_fenced = false;
		virtio_fs_queue_resume(connection->queue);
	}
	free(state);
	connection->control_error = error;
	connection->control_done = true;
	return (0);
}

static int
virtio_fs_connection_receive_notification(
    struct virtio_fs_connection *connection,
    const struct virtio_fs_backend_header *header, const void *payload,
    size_t payload_len)
{
	uint8_t *copy;
	int error;

	if ((connection->session.features & VIRTIO_FS_BACKEND_F_NOTIFICATION) == 0 ||
	    header->incarnation != connection->session.incarnation ||
	    payload_len == 0 || payload_len > connection->maximum_message ||
	    connection->notification_payload != NULL ||
	    connection->notifications_fenced)
		return (EPROTO);
	copy = malloc(payload_len);
	if (copy == NULL)
		return (ENOMEM);
	memcpy(copy, payload, payload_len);
	connection->notification_payload = copy;
	connection->notification_payload_len = payload_len;
	error = virtio_fs_connection_deliver_notification(connection);
	if (error == EAGAIN)
		return (0);
	return (error);
}

int
virtio_fs_connection_progress(struct virtio_fs_connection *connection,
    bool readable, bool writable)
{
	struct virtio_fs_backend_header header;
	size_t payload_len;
	int error;

	if (connection == NULL)
		return (EINVAL);
	if (connection->destroying)
		return (ECANCELED);
	if (connection->error != 0)
		return (connection->error);
	if (connection->queue == NULL) {
		error = virtio_fs_backend_client_progress(connection->client,
		    readable, writable);
		if (error != 0 && error != EAGAIN)
			return (virtio_fs_connection_fail(connection, error));
		if (virtio_fs_backend_client_active(connection->client)) {
			error = virtio_fs_connection_activate(connection);
			if (error != 0)
				return (virtio_fs_connection_fail(connection,
				    error));
		}
		return (error);
	}
	if (writable && connection->control_pending_send) {
		error = virtio_fs_backend_send_frame(connection->fd,
		    &connection->control_header, connection->control_payload);
		if (error != 0 && error != EAGAIN && error != EWOULDBLOCK)
			return (virtio_fs_connection_fail(connection, error));
		if (error == 0) {
			connection->control_pending_send = false;
			free(connection->control_payload);
			connection->control_payload = NULL;
			connection->control_payload_len = 0;
		}
	}
	if (writable && virtio_fs_queue_outgoing(connection->queue) != 0) {
		error = virtio_fs_queue_flush_one(connection->queue,
		    connection->fd);
		if (error != 0 && error != EAGAIN && error != EWOULDBLOCK)
			return (virtio_fs_connection_fail(connection, error));
	}
	if (!readable)
		return (0);
	error = virtio_fs_backend_receive_frame(connection->fd, &header,
	    connection->receive_buffer, connection->maximum_message,
	    &payload_len);
	if (error == EAGAIN || error == EWOULDBLOCK)
		return (EAGAIN);
	if (error != 0)
		return (virtio_fs_connection_fail(connection, error));
	if (header.type == VIRTIO_FS_BACKEND_NOTIFICATION)
		error = virtio_fs_connection_receive_notification(connection,
		    &header, connection->receive_buffer, payload_len);
	else if ((header.request_id & VIRTIO_FS_BACKEND_CONTROL_ID_BIT) != 0)
		error = virtio_fs_connection_finish_control(connection, &header,
		    connection->receive_buffer, payload_len);
	else
		error = virtio_fs_queue_receive(connection->queue, &header,
		    connection->receive_buffer, payload_len);
	if (error != 0)
		return (virtio_fs_connection_fail(connection, error));
	return (0);
}

bool
virtio_fs_connection_active(
    const struct virtio_fs_connection *connection)
{

	return (connection != NULL && !connection->destroying &&
	    connection->queue != NULL &&
	    connection->error == 0);
}

int
virtio_fs_connection_error(
    const struct virtio_fs_connection *connection)
{

	return (connection == NULL ? EINVAL :
	    (connection->destroying ? ECANCELED : connection->error));
}

int
virtio_fs_connection_submit(struct virtio_fs_connection *connection,
    enum virtio_fs_queue_class queue_class, const struct iovec *iov,
    size_t iov_count, size_t readable_count, size_t writable_count,
    bool ordered, uintptr_t guest_cookie)
{

	return (virtio_fs_connection_submit_on(connection, 0, queue_class,
	    iov, iov_count, readable_count, writable_count, ordered,
	    guest_cookie));
}

int
virtio_fs_connection_submit_on(struct virtio_fs_connection *connection,
    uint32_t queue_id, enum virtio_fs_queue_class queue_class,
    const struct iovec *iov, size_t iov_count, size_t readable_count,
    size_t writable_count, bool ordered, uintptr_t guest_cookie)
{

	if (connection == NULL)
		return (EINVAL);
	if (connection->destroying)
		return (ECANCELED);
	if (connection->error != 0)
		return (connection->error);
	if (connection->queue == NULL)
		return (ENOTCONN);
	return (virtio_fs_queue_submit_on(connection->queue, queue_id,
	    queue_class, iov, iov_count, readable_count, writable_count,
	    ordered, guest_cookie));
}

int
virtio_fs_connection_reset_queue(struct virtio_fs_connection *connection,
    uint32_t queue_id, size_t *discarded)
{

	if (connection == NULL || discarded == NULL)
		return (EINVAL);
	if (connection->destroying)
		return (ECANCELED);
	if (connection->error != 0)
		return (connection->error);
	if (connection->queue == NULL) {
		*discarded = 0;
		return (0);
	}
	return (virtio_fs_queue_reset_one(connection->queue, queue_id,
	    discarded));
}

int
virtio_fs_connection_reset(struct virtio_fs_connection *connection,
    size_t *discarded)
{

	if (connection == NULL || discarded == NULL)
		return (EINVAL);
	if (connection->destroying)
		return (ECANCELED);
	if (connection->error != 0)
		return (connection->error);
	if (connection->queue == NULL) {
		*discarded = 0;
		return (0);
	}
	return (virtio_fs_queue_reset(connection->queue, discarded));
}

uint32_t
virtio_fs_connection_pending(struct virtio_fs_connection *connection)
{

	if (connection == NULL || connection->destroying ||
	    connection->queue == NULL)
		return (0);
	return (virtio_fs_queue_pending(connection->queue));
}

uint32_t
virtio_fs_connection_outgoing(struct virtio_fs_connection *connection)
{

	if (connection == NULL || connection->destroying ||
	    connection->queue == NULL)
		return (0);
	return (virtio_fs_queue_outgoing(connection->queue));
}

int
virtio_fs_connection_checkpoint_contract(
    const struct virtio_fs_connection *connection,
    struct virtio_fs_backend_session *backend_session)
{

	if (connection == NULL || backend_session == NULL)
		return (EINVAL);
	if (connection->destroying)
		return (ECANCELED);
	if (connection->error != 0)
		return (connection->error);
	if (connection->queue == NULL || !connection->session_valid)
		return (ENOTCONN);
	if (connection->notification_payload != NULL)
		return (EBUSY);
	if ((connection->session.features &
	    (VIRTIO_FS_BACKEND_F_FREEZE |
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER)) !=
	    (VIRTIO_FS_BACKEND_F_FREEZE |
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER))
		return (ENOTSUP);
	*backend_session = connection->session;
	backend_session->phase = VIRTIO_FS_BACKEND_QUIESCED;
	backend_session->pending_control_id = 0;
	return (0);
}

int
virtio_fs_connection_pause(struct virtio_fs_connection *connection,
    struct virtio_fs_session *fuse_session,
    struct virtio_fs_backend_session *backend_session)
{
	int error;

	if (connection == NULL || fuse_session == NULL ||
	    backend_session == NULL)
		return (EINVAL);
	if (connection->destroying)
		return (ECANCELED);
	if (connection->error != 0)
		return (connection->error);
	if (connection->queue == NULL || !connection->session_valid)
		return (ENOTCONN);
	if ((connection->session.features &
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER) == 0)
		return (ENOTSUP);
	if (connection->notification_payload != NULL)
		return (EBUSY);
	error = virtio_fs_queue_pause(connection->queue, fuse_session);
	if (error == EINPROGRESS) {
		/*
		 * This synchronous compatibility API does not transfer drain
		 * ownership to its caller.  Preserve its transactional contract;
		 * begin_quiesce() is the event-driven interface.
		 */
		virtio_fs_queue_resume(connection->queue);
		return (EBUSY);
	}
	if (error != 0)
		return (error);
	connection->notifications_fenced = true;
	*backend_session = connection->session;
	return (0);
}

void
virtio_fs_connection_resume(struct virtio_fs_connection *connection)
{

	if (connection == NULL || connection->destroying ||
	    connection->queue == NULL)
		return;
	connection->notifications_fenced = false;
	virtio_fs_queue_resume(connection->queue);
}

int
virtio_fs_connection_restore_session(struct virtio_fs_connection *connection,
    const struct virtio_fs_session *session)
{

	if (connection == NULL)
		return (ENOTCONN);
	if (connection->destroying)
		return (ECANCELED);
	if (connection->queue == NULL)
		return (ENOTCONN);
	return (virtio_fs_queue_restore_session(connection->queue, session));
}

static int
virtio_fs_connection_next_control_id(struct virtio_fs_connection *connection,
    uint64_t *request_id)
{

	if (connection->next_control_id == 0 ||
	    connection->next_control_id > VIRTIO_FS_BACKEND_REQUEST_ID_MAX)
		return (EOVERFLOW);
	*request_id = VIRTIO_FS_BACKEND_CONTROL_ID_BIT |
	    connection->next_control_id++;
	return (0);
}

static void
virtio_fs_connection_control_prepare(struct virtio_fs_connection *connection)
{

	free(connection->control_payload);
	connection->control_payload = NULL;
	connection->control_payload_len = 0;
	connection->control_error = EINPROGRESS;
	connection->control_active = true;
	connection->control_done = false;
	connection->control_pending_send = true;
}

int
virtio_fs_connection_begin_quiesce(struct virtio_fs_connection *connection)
{
	struct virtio_fs_session fuse_session;
	uint64_t request_id;
	int error;

	if (connection == NULL)
		return (EINVAL);
	if (connection->destroying)
		return (ECANCELED);
	if (connection->error != 0)
		return (connection->error);
	if (connection->queue == NULL || !connection->session_valid)
		return (ENOTCONN);
	if ((connection->session.features &
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER) == 0)
		return (ENOTSUP);
	if (connection->notification_payload != NULL)
		return (EBUSY);
	if (connection->control_active && !connection->control_done)
		return (EBUSY);
	error = virtio_fs_queue_pause(connection->queue, &fuse_session);
	if (error == EINPROGRESS)
		return (EINPROGRESS);
	if (error != 0)
		return (error);
	connection->notifications_fenced = true;
	error = virtio_fs_connection_next_control_id(connection, &request_id);
	if (error == 0)
		error = virtio_fs_backend_start_control(&connection->session,
		    VIRTIO_FS_BACKEND_QUIESCE, request_id);
	if (error != 0) {
		connection->notifications_fenced = false;
		virtio_fs_queue_resume(connection->queue);
		return (error);
	}
	virtio_fs_connection_control_prepare(connection);
	connection->checkpoint_fuse_session = fuse_session;
	connection->checkpoint_fuse_session_valid = true;
	connection->control_header = (struct virtio_fs_backend_header) {
		.version = VIRTIO_FS_BACKEND_VERSION,
		.type = VIRTIO_FS_BACKEND_QUIESCE,
		.request_id = request_id,
		.incarnation = connection->session.incarnation,
	};
	return (0);
}

int
virtio_fs_connection_begin_thaw(struct virtio_fs_connection *connection,
    const void *state, size_t state_len)
{
	uint8_t *payload;
	uint64_t request_id;
	int error;

	if (connection == NULL || (state == NULL && state_len != 0))
		return (EINVAL);
	if (connection->destroying)
		return (ECANCELED);
	if (connection->error != 0)
		return (connection->error);
	if (connection->queue == NULL || !connection->session_valid)
		return (ENOTCONN);
	if ((connection->session.features &
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER) == 0)
		return (ENOTSUP);
	if (state_len > connection->maximum_message)
		return (EMSGSIZE);
	if (connection->control_active && !connection->control_done)
		return (EBUSY);
	payload = NULL;
	if (state_len != 0) {
		payload = malloc(state_len);
		if (payload == NULL)
			return (ENOMEM);
		memcpy(payload, state, state_len);
	}
	error = virtio_fs_connection_next_control_id(connection, &request_id);
	if (error == 0)
		error = virtio_fs_backend_start_control(&connection->session,
		    VIRTIO_FS_BACKEND_THAW, request_id);
	if (error != 0) {
		free(payload);
		return (error);
	}
	virtio_fs_connection_control_prepare(connection);
	connection->control_payload = payload;
	connection->control_payload_len = state_len;
	connection->control_header = (struct virtio_fs_backend_header) {
		.version = VIRTIO_FS_BACKEND_VERSION,
		.type = VIRTIO_FS_BACKEND_THAW,
		.payload_len = (uint32_t)state_len,
		.request_id = request_id,
		.incarnation = connection->session.incarnation,
	};
	return (0);
}

int
virtio_fs_connection_begin_thaw_saved(
    struct virtio_fs_connection *connection)
{

	if (connection == NULL)
		return (EINVAL);
	if (connection->destroying)
		return (ECANCELED);
	if (!connection->checkpoint_fuse_session_valid ||
	    connection->session.phase != VIRTIO_FS_BACKEND_QUIESCED)
		return (EBUSY);
	return (virtio_fs_connection_begin_thaw(connection,
	    connection->checkpoint_backend_state,
	    connection->checkpoint_backend_state_len));
}

int
virtio_fs_connection_control_status(
    const struct virtio_fs_connection *connection)
{

	if (connection == NULL)
		return (EINVAL);
	if (connection->destroying)
		return (ECANCELED);
	if (connection->error != 0)
		return (connection->error);
	if (!connection->control_active)
		return (ENOENT);
	return (connection->control_done ? connection->control_error :
	    EINPROGRESS);
}

size_t
virtio_fs_connection_checkpoint_size(
    const struct virtio_fs_connection *connection)
{

	if (connection == NULL || connection->destroying || connection->error != 0 ||
	    !connection->control_done || connection->control_error != 0 ||
	    connection->session.phase != VIRTIO_FS_BACKEND_QUIESCED ||
	    !connection->checkpoint_fuse_session_valid)
		return (0);
	return (connection->checkpoint_backend_state_len);
}

int
virtio_fs_connection_checkpoint_copy(
    const struct virtio_fs_connection *connection,
    struct virtio_fs_session *fuse_session,
    struct virtio_fs_backend_session *backend_session, void *state,
    size_t state_capacity, size_t *state_len)
{
	size_t required;

	if (connection == NULL || fuse_session == NULL ||
	    backend_session == NULL || state_len == NULL ||
	    (state == NULL && state_capacity != 0))
		return (EINVAL);
	if (connection->destroying)
		return (ECANCELED);
	if (connection->error != 0)
		return (connection->error);
	if (!connection->control_done)
		return (EINPROGRESS);
	if (connection->control_error != 0)
		return (connection->control_error);
	if (connection->session.phase != VIRTIO_FS_BACKEND_QUIESCED ||
	    !connection->checkpoint_fuse_session_valid)
		return (EBUSY);
	required = connection->checkpoint_backend_state_len;
	/*
	 * This is a multi-output transaction.  Reject every overlap with the
	 * immutable source graph and every overlap between outputs before
	 * publishing even the required length.
	 */
	if (virtio_fs_connection_state_overlaps(connection, fuse_session,
	    sizeof(*fuse_session)) ||
	    virtio_fs_connection_state_overlaps(connection, backend_session,
	    sizeof(*backend_session)) ||
	    virtio_fs_connection_state_overlaps(connection, state,
	    state_capacity) ||
	    virtio_fs_connection_state_overlaps(connection, state_len,
	    sizeof(*state_len)) ||
	    virtio_state_ranges_overlap(fuse_session, sizeof(*fuse_session),
	    backend_session, sizeof(*backend_session)) ||
	    virtio_state_ranges_overlap(fuse_session, sizeof(*fuse_session),
	    state, state_capacity) ||
	    virtio_state_ranges_overlap(fuse_session, sizeof(*fuse_session),
	    state_len, sizeof(*state_len)) ||
	    virtio_state_ranges_overlap(backend_session,
	    sizeof(*backend_session), state, state_capacity) ||
	    virtio_state_ranges_overlap(backend_session,
	    sizeof(*backend_session), state_len, sizeof(*state_len)) ||
	    virtio_state_ranges_overlap(state, state_capacity, state_len,
	    sizeof(*state_len)))
		return (EINVAL);
	*state_len = required;
	if (state_capacity < required)
		return (EMSGSIZE);
	if (required != 0)
		memcpy(state, connection->checkpoint_backend_state, required);
	*fuse_session = connection->checkpoint_fuse_session;
	*backend_session = connection->session;
	return (0);
}

int
virtio_fs_connection_abort_control(struct virtio_fs_connection *connection,
    int error)
{

	if (connection == NULL || error == 0)
		return (EINVAL);
	if (connection->destroying)
		return (ECANCELED);
	if (!connection->control_active || connection->control_done)
		return (ENOENT);
	return (virtio_fs_connection_fail(connection, error));
}
