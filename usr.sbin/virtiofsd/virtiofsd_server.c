/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "virtio_fs_backend.h"
#include "virtio_fs_outbox.h"
#include "virtiofsd_fuse.h"
#include "virtiofsd_server.h"
#include "virtiofsd_session.h"

#define	VIRTIOFSD_SERVER_PRIORITY	16U
#define	VIRTIOFSD_JOB_NONE		UINT32_MAX

enum virtiofsd_job_state {
	VIRTIOFSD_JOB_FREE = 0,
	VIRTIOFSD_JOB_QUEUED,
	VIRTIOFSD_JOB_RUNNING,
};

struct virtiofsd_job {
	struct virtio_fs_backend_header header;
	uint8_t *payload;
	uint32_t next;
	enum virtiofsd_job_state state;
	bool canceled;
};

struct virtiofsd_server {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_t *workers;
	struct virtiofsd_job *jobs;
	struct virtiofsd_session *session;
	struct virtio_fs_outbox *outbox;
	struct virtio_fs_backend_header quiesce;
	struct virtio_fs_backend_header shutdown;
	uint32_t maximum_message;
	uint32_t maximum_inflight;
	uint32_t maximum_pending_bytes;
	uint32_t negotiated_message;
	uint32_t negotiated_inflight;
	uint32_t job_head;
	uint32_t job_tail;
	uint32_t job_count;
	unsigned int worker_count;
	uint64_t incarnation;
	int wakeup[2];
	int error;
	enum virtio_fs_backend_phase phase;
	bool stopping;
	bool quiesce_pending;
	bool shutdown_pending;
};

static void
server_wakeup(struct virtiofsd_server *server)
{
	uint8_t byte;
	ssize_t result;

	byte = 1;
	do {
		result = write(server->wakeup[1], &byte, sizeof(byte));
	} while (result < 0 && errno == EINTR);
	/* A full pipe is already readable and therefore needs no new byte. */
}

static int
server_enqueue_locked(struct virtiofsd_server *server, bool priority,
    const struct virtio_fs_backend_header *header, const void *payload)
{
	int error;

	error = virtio_fs_outbox_enqueue(server->outbox, priority, header,
	    payload);
	if (error != 0 && server->error == 0)
		server->error = error;
	server_wakeup(server);
	return (error);
}

static int
server_quiesce_complete_locked(struct virtiofsd_server *server)
{
	struct virtio_fs_backend_header reply;
	uint8_t *state;
	size_t state_len, written;
	int error;

	if (!server->quiesce_pending || server->job_count != 0)
		return (0);
	reply = (struct virtio_fs_backend_header) {
		.version = VIRTIO_FS_BACKEND_VERSION,
		.type = VIRTIO_FS_BACKEND_QUIESCE_REPLY,
		.request_id = server->quiesce.request_id,
		.incarnation = server->incarnation,
	};
	state = NULL;
	state_len = 0;
	written = 0;
	error = virtiofsd_session_checkpoint_size(server->session, &state_len);
	if (error == 0 && state_len > server->negotiated_message)
		error = EMSGSIZE;
	if (error == 0) {
		state = malloc(state_len);
		if (state == NULL)
			error = ENOMEM;
	}
	if (error == 0)
		error = virtiofsd_session_checkpoint_write(server->session, state,
		    state_len, &written);
	if (error == 0 && written != state_len)
		error = EPROTO;
	if (error != 0)
		reply.status = -error;
	else
		reply.payload_len = (uint32_t)state_len;
	/*
	 * This is a barrier reply.  Keep it behind already completed request
	 * responses in the normal lane; the priority lane is for cancellation
	 * and other controls that are permitted to overtake data work.
	 */
	error = server_enqueue_locked(server, false, &reply,
	    reply.status == 0 ? state : NULL);
	free(state);
	if (error == 0) {
		server->quiesce_pending = false;
		server->phase = reply.status == 0 ?
		    VIRTIO_FS_BACKEND_QUIESCED : VIRTIO_FS_BACKEND_ACTIVE;
	}
	return (error);
}

static int
server_shutdown_complete_locked(struct virtiofsd_server *server)
{
	struct virtio_fs_backend_header reply;
	int error;

	if (!server->shutdown_pending || server->job_count != 0)
		return (0);
	reply = (struct virtio_fs_backend_header) {
		.version = VIRTIO_FS_BACKEND_VERSION,
		.type = VIRTIO_FS_BACKEND_SHUTDOWN_REPLY,
		.request_id = server->shutdown.request_id,
		.incarnation = server->incarnation,
	};
	error = server_enqueue_locked(server, false, &reply, NULL);
	if (error == 0) {
		server->shutdown_pending = false;
		server->phase = VIRTIO_FS_BACKEND_CLOSED;
	}
	return (error);
}

static uint32_t
server_find_job_locked(struct virtiofsd_server *server, uint64_t request_id)
{
	uint32_t i;

	for (i = 0; i < server->maximum_inflight; i++)
		if (server->jobs[i].state != VIRTIOFSD_JOB_FREE &&
		    server->jobs[i].header.request_id == request_id)
			return (i);
	return (VIRTIOFSD_JOB_NONE);
}

static void
server_job_free_locked(struct virtiofsd_server *server, uint32_t index)
{
	struct virtiofsd_job *job;

	job = &server->jobs[index];
	free(job->payload);
	memset(job, 0, sizeof(*job));
	job->next = VIRTIOFSD_JOB_NONE;
	server->job_count--;
	(void)server_quiesce_complete_locked(server);
	(void)server_shutdown_complete_locked(server);
}

static bool
server_job_unlink_locked(struct virtiofsd_server *server, uint32_t index)
{
	uint32_t current, previous;

	previous = VIRTIOFSD_JOB_NONE;
	for (current = server->job_head; current != VIRTIOFSD_JOB_NONE;
	    current = server->jobs[current].next) {
		if (current != index) {
			previous = current;
			continue;
		}
		if (previous == VIRTIOFSD_JOB_NONE)
			server->job_head = server->jobs[current].next;
		else
			server->jobs[previous].next =
			    server->jobs[current].next;
		if (server->job_tail == current)
			server->job_tail = previous;
		server->jobs[current].next = VIRTIOFSD_JOB_NONE;
		return (true);
	}
	return (false);
}

static void *
server_worker(void *argument)
{
	struct virtio_fs_backend_header reply;
	struct virtiofsd_server *server;
	struct virtiofsd_job *job;
	uint8_t *response;
	uint32_t index;
	size_t written;
	int cleanup_error, error;
	bool canceled, expected_reply, reply_required;

	server = argument;
	response = malloc(server->maximum_message);
	if (response == NULL) {
		pthread_mutex_lock(&server->mutex);
		if (server->error == 0)
			server->error = ENOMEM;
		server->stopping = true;
		pthread_cond_broadcast(&server->cond);
		server_wakeup(server);
		pthread_mutex_unlock(&server->mutex);
		return (NULL);
	}
	for (;;) {
		pthread_mutex_lock(&server->mutex);
		while (server->job_head == VIRTIOFSD_JOB_NONE &&
		    !server->stopping)
			pthread_cond_wait(&server->cond, &server->mutex);
		if (server->stopping) {
			pthread_mutex_unlock(&server->mutex);
			break;
		}
		index = server->job_head;
		job = &server->jobs[index];
		server->job_head = job->next;
		if (server->job_head == VIRTIOFSD_JOB_NONE)
			server->job_tail = VIRTIOFSD_JOB_NONE;
		job->next = VIRTIOFSD_JOB_NONE;
		job->state = VIRTIOFSD_JOB_RUNNING;
		pthread_mutex_unlock(&server->mutex);

		written = 0;
		reply_required = true;
		error = virtiofsd_session_execute(server->session, job->payload,
		    job->header.payload_len, response,
		    server->negotiated_message, &written, &reply_required);
		expected_reply = (job->header.flags &
		    VIRTIO_FS_BACKEND_MSG_F_NOREPLY) == 0;
		reply = (struct virtio_fs_backend_header) {
			.version = VIRTIO_FS_BACKEND_VERSION,
			.type = VIRTIO_FS_BACKEND_RESPONSE,
			.payload_len = error == 0 && reply_required ?
			    (uint32_t)written : 0,
			.request_id = job->header.request_id,
			.incarnation = server->incarnation,
			.status = error == 0 ? 0 : -EIO,
		};

		cleanup_error = 0;
		pthread_mutex_lock(&server->mutex);
		canceled = job->canceled;
		if (reply_required != expected_reply) {
			if (server->error == 0)
				server->error = EPROTO;
			server->stopping = true;
			pthread_cond_broadcast(&server->cond);
			server_wakeup(server);
		} else if (!canceled && reply_required &&
		    server->error == 0)
			(void)server_enqueue_locked(server, false, &reply,
			    reply.payload_len == 0 ? NULL : response);
		pthread_mutex_unlock(&server->mutex);

		if (canceled && error == 0 && reply_required)
			cleanup_error = virtiofsd_session_discard_result(
			    server->session, job->payload,
			    job->header.payload_len, response, written);

		pthread_mutex_lock(&server->mutex);
		if (cleanup_error != 0) {
			if (server->error == 0)
				server->error = cleanup_error;
			server->stopping = true;
			pthread_cond_broadcast(&server->cond);
			server_wakeup(server);
		}
		server_job_free_locked(server, index);
		pthread_mutex_unlock(&server->mutex);
	}
	free(response);
	return (NULL);
}

int
virtiofsd_server_create(struct virtiofsd_session *session,
    uint32_t maximum_message, uint32_t maximum_inflight,
    uint32_t maximum_pending_bytes, unsigned int worker_count,
    struct virtiofsd_server **result)
{
	struct virtiofsd_server *server;
	unsigned int i;
	int error;

	if (session == NULL || maximum_message == 0 ||
	    maximum_message > VIRTIO_FS_BACKEND_MAX_FRAME ||
	    maximum_inflight == 0 ||
	    maximum_inflight > VIRTIO_FS_BACKEND_MAX_INFLIGHT ||
	    maximum_message > maximum_pending_bytes / 2U ||
	    maximum_pending_bytes > VIRTIO_FS_BACKEND_MAX_PENDING_BYTES ||
	    worker_count == 0 || worker_count > maximum_inflight ||
	    result == NULL)
		return (EINVAL);
	*result = NULL;
	server = calloc(1, sizeof(*server));
	if (server == NULL)
		return (ENOMEM);
	server->jobs = calloc(maximum_inflight, sizeof(*server->jobs));
	server->workers = calloc(worker_count, sizeof(*server->workers));
	if (server->jobs == NULL || server->workers == NULL) {
		free(server->workers);
		free(server->jobs);
		free(server);
		return (ENOMEM);
	}
	server->wakeup[0] = -1;
	server->wakeup[1] = -1;
	error = pthread_mutex_init(&server->mutex, NULL);
	if (error != 0)
		goto fail;
	error = pthread_cond_init(&server->cond, NULL);
	if (error != 0) {
		(void)pthread_mutex_destroy(&server->mutex);
		goto fail;
	}
	if (pipe2(server->wakeup, O_CLOEXEC | O_NONBLOCK) != 0) {
		error = errno;
		(void)pthread_cond_destroy(&server->cond);
		(void)pthread_mutex_destroy(&server->mutex);
		goto fail;
	}
	server->session = session;
	server->maximum_message = maximum_message;
	server->maximum_inflight = maximum_inflight;
	server->maximum_pending_bytes = maximum_pending_bytes;
	server->worker_count = worker_count;
	server->phase = VIRTIO_FS_BACKEND_NEGOTIATING;
	server->job_head = VIRTIOFSD_JOB_NONE;
	server->job_tail = VIRTIOFSD_JOB_NONE;
	for (i = 0; i < maximum_inflight; i++)
		server->jobs[i].next = VIRTIOFSD_JOB_NONE;
	for (i = 0; i < worker_count; i++) {
		error = pthread_create(&server->workers[i], NULL,
		    server_worker, server);
		if (error != 0) {
			pthread_mutex_lock(&server->mutex);
			server->stopping = true;
			pthread_cond_broadcast(&server->cond);
			pthread_mutex_unlock(&server->mutex);
			while (i != 0)
				(void)pthread_join(server->workers[--i], NULL);
			(void)close(server->wakeup[0]);
			(void)close(server->wakeup[1]);
			(void)pthread_cond_destroy(&server->cond);
			(void)pthread_mutex_destroy(&server->mutex);
			goto fail;
		}
	}
	*result = server;
	return (0);
fail:
	free(server->workers);
	free(server->jobs);
	free(server);
	return (error);
}

void
virtiofsd_server_destroy(struct virtiofsd_server *server)
{
	uint32_t i;
	unsigned int worker;

	if (server == NULL)
		return;
	pthread_mutex_lock(&server->mutex);
	server->stopping = true;
	pthread_cond_broadcast(&server->cond);
	pthread_mutex_unlock(&server->mutex);
	for (worker = 0; worker < server->worker_count; worker++)
		(void)pthread_join(server->workers[worker], NULL);
	for (i = 0; i < server->maximum_inflight; i++)
		free(server->jobs[i].payload);
	virtio_fs_outbox_destroy(server->outbox);
	(void)close(server->wakeup[0]);
	(void)close(server->wakeup[1]);
	(void)pthread_cond_destroy(&server->cond);
	(void)pthread_mutex_destroy(&server->mutex);
	free(server->workers);
	free(server->jobs);
	free(server);
}

static int
server_hello_locked(struct virtiofsd_server *server,
    const struct virtio_fs_backend_header *header, const void *payload,
    size_t payload_len)
{
	struct virtio_fs_backend_hello offer, selection;
	struct virtio_fs_backend_header reply;
	uint8_t wire[VIRTIO_FS_BACKEND_HELLO_SIZE];
	uint32_t inflight_by_bytes, maximum_message;
	int error;

	if (server->phase != VIRTIO_FS_BACKEND_NEGOTIATING)
		return (EPROTO);
	error = virtio_fs_backend_hello_decode(payload, payload_len, &offer);
	if (error != 0)
		return (error);
	maximum_message = MIN(offer.maximum_message, server->maximum_message);
	maximum_message = MIN(maximum_message,
	    offer.maximum_pending_bytes / 2U);
	if (maximum_message < VIRTIOFSD_FUSE_IN_HEADER_SIZE)
		return (EMSGSIZE);
	selection = (struct virtio_fs_backend_hello) {
		.minimum_version = VIRTIO_FS_BACKEND_VERSION,
		.maximum_version = VIRTIO_FS_BACKEND_VERSION,
		.features = offer.features &
		    (VIRTIO_FS_BACKEND_F_CANCEL |
		    VIRTIO_FS_BACKEND_F_FREEZE |
		    VIRTIO_FS_BACKEND_F_STATE_TRANSFER),
		.maximum_message = maximum_message,
		.maximum_inflight = MIN(offer.maximum_inflight,
		    server->maximum_inflight),
		.maximum_pending_bytes = MIN(offer.maximum_pending_bytes,
		    server->maximum_pending_bytes),
	};
	if (maximum_message > selection.maximum_pending_bytes / 2U)
		return (EMSGSIZE);
	/*
	 * The outbox reserves one maximum-sized frame for priority control
	 * traffic.  Never negotiate more simultaneous requests than the
	 * remaining byte budget can hold at maximum response size.
	 */
	inflight_by_bytes =
	    (selection.maximum_pending_bytes - maximum_message) /
	    maximum_message;
	selection.maximum_inflight = MIN(selection.maximum_inflight,
	    inflight_by_bytes);
	if (selection.maximum_inflight == 0)
		return (EMSGSIZE);
	error = virtio_fs_backend_hello_encode(&selection, wire);
	if (error != 0)
		return (error);
	error = virtio_fs_outbox_create(selection.maximum_inflight + 1U,
	    VIRTIOFSD_SERVER_PRIORITY, selection.maximum_message,
	    selection.maximum_pending_bytes, &server->outbox);
	if (error != 0)
		return (error);
	server->negotiated_message = selection.maximum_message;
	server->negotiated_inflight = selection.maximum_inflight;
	reply = (struct virtio_fs_backend_header) {
		.version = VIRTIO_FS_BACKEND_VERSION,
		.type = VIRTIO_FS_BACKEND_HELLO_REPLY,
		.payload_len = sizeof(wire),
		.request_id = header->request_id,
		.incarnation = 0,
	};
	error = server_enqueue_locked(server, true, &reply, wire);
	if (error == 0)
		server->phase = VIRTIO_FS_BACKEND_ACTIVE;
	return (error);
}

static int
server_request_locked(struct virtiofsd_server *server,
    const struct virtio_fs_backend_header *header, const void *payload)
{
	struct virtiofsd_job *job;
	uint32_t index;
	bool expects_reply, marked_noreply;
	int error;

	if (server->phase != VIRTIO_FS_BACKEND_ACTIVE ||
	    header->incarnation == 0 ||
	    header->payload_len == 0 ||
	    header->payload_len > server->negotiated_message ||
	    server->job_count >= server->negotiated_inflight)
		return (server->job_count >= server->negotiated_inflight ?
		    ENOBUFS : EPROTO);
	if (server->incarnation == 0)
		server->incarnation = header->incarnation;
	else if (header->incarnation != server->incarnation)
		return (ESTALE);
	error = virtiofsd_session_request_expects_reply(server->session,
	    payload, header->payload_len, &expects_reply);
	if (error != 0)
		return (EPROTO);
	marked_noreply = (header->flags &
	    VIRTIO_FS_BACKEND_MSG_F_NOREPLY) != 0;
	if (expects_reply == marked_noreply)
		return (EPROTO);
	if (server_find_job_locked(server, header->request_id) !=
	    VIRTIOFSD_JOB_NONE)
		return (EEXIST);
	for (index = 0; index < server->maximum_inflight; index++)
		if (server->jobs[index].state == VIRTIOFSD_JOB_FREE)
			break;
	if (index == server->maximum_inflight)
		return (ENOBUFS);
	job = &server->jobs[index];
	job->payload = malloc(header->payload_len);
	if (job->payload == NULL)
		return (ENOMEM);
	memcpy(job->payload, payload, header->payload_len);
	job->header = *header;
	job->next = VIRTIOFSD_JOB_NONE;
	job->state = VIRTIOFSD_JOB_QUEUED;
	if (server->job_tail == VIRTIOFSD_JOB_NONE)
		server->job_head = index;
	else
		server->jobs[server->job_tail].next = index;
	server->job_tail = index;
	server->job_count++;
	pthread_cond_signal(&server->cond);
	return (0);
}

static int
server_cancel_locked(struct virtiofsd_server *server,
    const struct virtio_fs_backend_header *header)
{
	struct virtio_fs_backend_header reply;
	uint32_t index;
	int error;

	if (server->phase != VIRTIO_FS_BACKEND_ACTIVE ||
	    server->incarnation == 0 ||
	    header->incarnation != server->incarnation)
		return (EPROTO);
	reply = (struct virtio_fs_backend_header) {
		.version = VIRTIO_FS_BACKEND_VERSION,
		.type = VIRTIO_FS_BACKEND_CANCEL_REPLY,
		.request_id = header->request_id,
		.incarnation = server->incarnation,
	};
	error = server_enqueue_locked(server, true, &reply, NULL);
	if (error != 0)
		return (error);
	index = server_find_job_locked(server, header->request_id);
	if (index == VIRTIOFSD_JOB_NONE)
		return (0);
	if (server->jobs[index].state == VIRTIOFSD_JOB_QUEUED) {
		if (!server_job_unlink_locked(server, index))
			return (EPROTO);
		server_job_free_locked(server, index);
	} else {
		server->jobs[index].canceled = true;
	}
	return (0);
}

static int
server_control_locked(struct virtiofsd_server *server,
    const struct virtio_fs_backend_header *header, const void *payload,
    size_t payload_len)
{
	struct virtio_fs_backend_header reply;

	if (header->incarnation != server->incarnation)
		return (EPROTO);
	reply = (struct virtio_fs_backend_header) {
		.version = VIRTIO_FS_BACKEND_VERSION,
		.request_id = header->request_id,
		.incarnation = server->incarnation,
	};
	switch (header->type) {
	case VIRTIO_FS_BACKEND_QUIESCE:
		if (server->phase != VIRTIO_FS_BACKEND_ACTIVE ||
		    payload_len != 0 || server->quiesce_pending)
			return (EPROTO);
		server->phase = VIRTIO_FS_BACKEND_QUIESCING;
		server->quiesce = *header;
		server->quiesce_pending = true;
		return (server_quiesce_complete_locked(server));
	case VIRTIO_FS_BACKEND_THAW:
		if (server->phase != VIRTIO_FS_BACKEND_QUIESCED)
			return (EPROTO);
		reply.type = VIRTIO_FS_BACKEND_THAW_REPLY;
		reply.status = -virtiofsd_session_restore(server->session,
		    payload, payload_len);
		if (server_enqueue_locked(server, true, &reply, NULL) == 0) {
			if (reply.status == 0)
				server->phase = VIRTIO_FS_BACKEND_ACTIVE;
			return (0);
		}
		return (server->error);
	case VIRTIO_FS_BACKEND_SHUTDOWN:
		if ((server->phase != VIRTIO_FS_BACKEND_ACTIVE &&
		    server->phase != VIRTIO_FS_BACKEND_QUIESCED) ||
		    payload_len != 0 || server->quiesce_pending ||
		    server->shutdown_pending)
			return (EPROTO);
		server->phase = VIRTIO_FS_BACKEND_QUIESCING;
		server->shutdown = *header;
		server->shutdown_pending = true;
		return (server_shutdown_complete_locked(server));
	default:
		return (EPROTO);
	}
}

int
virtiofsd_server_handle(struct virtiofsd_server *server,
    const struct virtio_fs_backend_header *header, const void *payload,
    size_t payload_len)
{
	uint8_t wire[VIRTIO_FS_BACKEND_HEADER_SIZE];
	int error;

	if (server == NULL || header == NULL ||
	    (payload == NULL && payload_len != 0) ||
	    header->payload_len != payload_len)
		return (EINVAL);
	if (virtio_fs_backend_header_encode(header, wire) != 0)
		return (EPROTO);
	pthread_mutex_lock(&server->mutex);
	if (server->error != 0) {
		error = server->error;
		goto out;
	}
	switch (header->type) {
	case VIRTIO_FS_BACKEND_HELLO:
		error = server_hello_locked(server, header, payload,
		    payload_len);
		break;
	case VIRTIO_FS_BACKEND_REQUEST:
		error = server_request_locked(server, header, payload);
		break;
	case VIRTIO_FS_BACKEND_CANCEL:
		error = server_cancel_locked(server, header);
		break;
	case VIRTIO_FS_BACKEND_QUIESCE:
	case VIRTIO_FS_BACKEND_THAW:
	case VIRTIO_FS_BACKEND_SHUTDOWN:
		error = server_control_locked(server, header, payload,
		    payload_len);
		break;
	default:
		error = EPROTO;
		break;
	}
	if (error != 0 && server->error == 0)
		server->error = error;
out:
	pthread_mutex_unlock(&server->mutex);
	return (error);
}

int
virtiofsd_server_flush_one(struct virtiofsd_server *server, int fd)
{
	struct virtio_fs_backend_header sent;
	int error;

	if (server == NULL || fd < 0)
		return (EINVAL);
	pthread_mutex_lock(&server->mutex);
	if (server->outbox == NULL) {
		error = ENOENT;
	} else {
		error = virtio_fs_outbox_flush_one(server->outbox, fd, &sent);
		if (error != 0 && error != EAGAIN && error != EWOULDBLOCK &&
		    error != ENOENT && server->error == 0)
			server->error = error;
	}
	pthread_mutex_unlock(&server->mutex);
	return (error);
}

int
virtiofsd_server_wakeup_fd(const struct virtiofsd_server *server)
{

	return (server == NULL ? -1 : server->wakeup[0]);
}

void
virtiofsd_server_drain_wakeup(struct virtiofsd_server *server)
{
	uint8_t buffer[64];
	ssize_t result;

	if (server == NULL)
		return;
	do {
		result = read(server->wakeup[0], buffer, sizeof(buffer));
	} while (result > 0 || (result < 0 && errno == EINTR));
}

bool
virtiofsd_server_wants_write(struct virtiofsd_server *server)
{
	bool wants;

	if (server == NULL)
		return (false);
	pthread_mutex_lock(&server->mutex);
	wants = server->outbox != NULL &&
	    (virtio_fs_outbox_count(server->outbox, true) != 0 ||
	    virtio_fs_outbox_count(server->outbox, false) != 0);
	pthread_mutex_unlock(&server->mutex);
	return (wants);
}

bool
virtiofsd_server_closed(struct virtiofsd_server *server)
{
	bool closed;

	if (server == NULL)
		return (true);
	pthread_mutex_lock(&server->mutex);
	closed = server->phase == VIRTIO_FS_BACKEND_CLOSED;
	pthread_mutex_unlock(&server->mutex);
	return (closed);
}

int
virtiofsd_server_error(struct virtiofsd_server *server)
{
	int error;

	if (server == NULL)
		return (EINVAL);
	pthread_mutex_lock(&server->mutex);
	error = server->error;
	pthread_mutex_unlock(&server->mutex);
	return (error);
}
