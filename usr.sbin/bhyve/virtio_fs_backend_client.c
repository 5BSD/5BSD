/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "virtio_fs_backend.h"
#include "virtio_fs_backend_client.h"
#include "virtio_fs_backend_io.h"

enum virtio_fs_backend_client_phase {
	VFS_CLIENT_CONNECTING = 0,
	VFS_CLIENT_HELLO_SEND,
	VFS_CLIENT_HELLO_RECEIVE,
	VFS_CLIENT_ACTIVE,
	VFS_CLIENT_FAILED,
	VFS_CLIENT_TRANSFERRED,
};

struct virtio_fs_backend_client {
	struct virtio_fs_backend_session session;
	struct virtio_fs_backend_hello offer;
	uid_t expected_uid;
	gid_t expected_gid;
	int fd;
	int error;
	enum virtio_fs_backend_client_phase phase;
	bool hello_started;
};

static int
virtio_fs_backend_client_offer_validate(
    const struct virtio_fs_backend_hello *offer)
{
	uint8_t wire[VIRTIO_FS_BACKEND_HELLO_SIZE];

	if (offer == NULL)
		return (EINVAL);
	return (virtio_fs_backend_hello_encode(offer, wire));
}

static int
virtio_fs_backend_client_fail(struct virtio_fs_backend_client *client,
    int error)
{

	if (error == 0)
		error = EIO;
	if (client->fd >= 0) {
		(void)close(client->fd);
		client->fd = -1;
	}
	if (client->session.phase != VIRTIO_FS_BACKEND_DISCONNECTED)
		virtio_fs_backend_disconnect(&client->session);
	client->phase = VFS_CLIENT_FAILED;
	client->error = error;
	return (error);
}

static int
virtio_fs_backend_client_create(int fd, bool connecting, uid_t expected_uid,
    gid_t expected_gid, const struct virtio_fs_backend_hello *offer,
    struct virtio_fs_backend_client **result)
{
	struct virtio_fs_backend_client *client;
	int error;

	if (result == NULL || fd < 0)
		return (EINVAL);
	*result = NULL;
	error = virtio_fs_backend_client_offer_validate(offer);
	if (error != 0)
		return (error);
	client = calloc(1, sizeof(*client));
	if (client == NULL)
		return (ENOMEM);
	error = fcntl(fd, F_GETFD);
	if (error < 0) {
		error = errno;
		goto fail;
	}
	if ((error & FD_CLOEXEC) == 0 &&
	    fcntl(fd, F_SETFD, error | FD_CLOEXEC) < 0) {
		error = errno;
		goto fail;
	}
	virtio_fs_backend_session_init(&client->session);
	client->offer = *offer;
	client->expected_uid = expected_uid;
	client->expected_gid = expected_gid;
	client->fd = fd;
	client->phase = connecting ? VFS_CLIENT_CONNECTING :
	    VFS_CLIENT_HELLO_SEND;
	*result = client;
	return (0);

fail:
	free(client);
	return (error);
}

int
virtio_fs_backend_client_connect(const char *path, uid_t expected_uid,
    gid_t expected_gid, const struct virtio_fs_backend_hello *offer,
    struct virtio_fs_backend_client **result)
{
	bool connecting;
	int error, fd;

	if (result == NULL)
		return (EINVAL);
	*result = NULL;
	error = virtio_fs_backend_client_offer_validate(offer);
	if (error != 0)
		return (error);
	error = virtio_fs_backend_connect_start(path, expected_uid,
	    expected_gid, &fd, &connecting);
	if (error != 0)
		return (error);
	error = virtio_fs_backend_client_create(fd, connecting, expected_uid,
	    expected_gid, offer, result);
	if (error != 0)
		(void)close(fd);
	return (error);
}

int
virtio_fs_backend_client_adopt(int fd, uid_t expected_uid,
    gid_t expected_gid, const struct virtio_fs_backend_hello *offer,
    struct virtio_fs_backend_client **result)
{
	int error;

	if (result == NULL)
		return (EINVAL);
	*result = NULL;
	error = virtio_fs_backend_client_offer_validate(offer);
	if (error != 0)
		return (error);
	error = virtio_fs_backend_authenticate(fd, expected_uid, expected_gid);
	if (error != 0)
		return (error);
	return (virtio_fs_backend_client_create(fd, false, expected_uid,
	    expected_gid, offer, result));
}

void
virtio_fs_backend_client_destroy(struct virtio_fs_backend_client *client)
{

	if (client == NULL)
		return;
	if (client->fd >= 0)
		(void)close(client->fd);
	free(client);
}

int
virtio_fs_backend_client_fd(
    const struct virtio_fs_backend_client *client)
{

	if (client == NULL)
		return (-1);
	return (client->fd);
}

uint32_t
virtio_fs_backend_client_events(
    const struct virtio_fs_backend_client *client)
{

	if (client == NULL)
		return (0);
	switch (client->phase) {
	case VFS_CLIENT_CONNECTING:
	case VFS_CLIENT_HELLO_SEND:
		return (VIRTIO_FS_BACKEND_CLIENT_WRITE);
	case VFS_CLIENT_HELLO_RECEIVE:
		return (VIRTIO_FS_BACKEND_CLIENT_READ);
	default:
		return (0);
	}
}

int
virtio_fs_backend_client_progress(struct virtio_fs_backend_client *client,
    bool readable, bool writable)
{
	struct virtio_fs_backend_header header;
	struct virtio_fs_backend_hello selection;
	uint8_t hello[VIRTIO_FS_BACKEND_HELLO_SIZE];
	uint8_t payload[VIRTIO_FS_BACKEND_HELLO_SIZE];
	size_t payload_len;
	int error;

	if (client == NULL)
		return (EINVAL);
	if (client->phase == VFS_CLIENT_FAILED)
		return (client->error);
	if (client->phase == VFS_CLIENT_ACTIVE)
		return (EALREADY);
	if (client->phase == VFS_CLIENT_TRANSFERRED)
		return (ENXIO);

	if (client->phase == VFS_CLIENT_CONNECTING) {
		if (!writable)
			return (EAGAIN);
		error = virtio_fs_backend_connect_finish(client->fd,
		    client->expected_uid, client->expected_gid);
		if (error != 0)
			return (virtio_fs_backend_client_fail(client, error));
		client->phase = VFS_CLIENT_HELLO_SEND;
	}
	if (client->phase == VFS_CLIENT_HELLO_SEND) {
		if (!writable)
			return (EAGAIN);
		if (!client->hello_started) {
			error = virtio_fs_backend_start_hello(&client->session, 1,
			    &client->offer);
			if (error != 0)
				return (virtio_fs_backend_client_fail(client,
				    error));
			client->hello_started = true;
		}
		header = (struct virtio_fs_backend_header) {
			.version = VIRTIO_FS_BACKEND_VERSION,
			.type = VIRTIO_FS_BACKEND_HELLO,
			.payload_len = VIRTIO_FS_BACKEND_HELLO_SIZE,
			.request_id = 1,
		};
		error = virtio_fs_backend_hello_encode(&client->offer, hello);
		if (error != 0)
			return (virtio_fs_backend_client_fail(client, error));
		error = virtio_fs_backend_send_frame(client->fd, &header,
		    hello);
		if (error == EAGAIN || error == EWOULDBLOCK)
			return (EAGAIN);
		if (error != 0)
			return (virtio_fs_backend_client_fail(client, error));
		client->phase = VFS_CLIENT_HELLO_RECEIVE;
	}
	if (client->phase != VFS_CLIENT_HELLO_RECEIVE || !readable)
		return (EAGAIN);

	error = virtio_fs_backend_receive_frame(client->fd, &header, payload,
	    sizeof(payload), &payload_len);
	if (error == EAGAIN || error == EWOULDBLOCK)
		return (EAGAIN);
	if (error != 0)
		return (virtio_fs_backend_client_fail(client, error));
	if (header.status == 0) {
		error = virtio_fs_backend_hello_decode(payload, payload_len,
		    &selection);
		if (error != 0)
			return (virtio_fs_backend_client_fail(client, error));
	} else if (payload_len != 0) {
		return (virtio_fs_backend_client_fail(client, EPROTO));
	}
	error = virtio_fs_backend_finish_hello(&client->session, &header,
	    header.status == 0 ? &selection : NULL);
	if (error != 0)
		return (virtio_fs_backend_client_fail(client, error));
	client->phase = VFS_CLIENT_ACTIVE;
	return (0);
}

bool
virtio_fs_backend_client_active(
    const struct virtio_fs_backend_client *client)
{

	return (client != NULL && client->phase == VFS_CLIENT_ACTIVE);
}

int
virtio_fs_backend_client_error(
    const struct virtio_fs_backend_client *client)
{

	if (client == NULL)
		return (EINVAL);
	return (client->phase == VFS_CLIENT_FAILED ? client->error : 0);
}

int
virtio_fs_backend_client_take_active(
    struct virtio_fs_backend_client *client,
    struct virtio_fs_backend_session *session, int *fd)
{

	if (client == NULL || session == NULL || fd == NULL)
		return (EINVAL);
	if (client->phase != VFS_CLIENT_ACTIVE)
		return (EBUSY);
	*session = client->session;
	*fd = client->fd;
	client->fd = -1;
	client->phase = VFS_CLIENT_TRANSFERRED;
	return (0);
}
