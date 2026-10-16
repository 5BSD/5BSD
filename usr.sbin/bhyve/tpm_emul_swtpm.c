/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Hans Rosenfeld
 * Author: Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/endian.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc_np.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "config.h"
#include "tpm_device.h"
#include "tpm_emul.h"
#include "tpm_swtpm_control.h"

struct tpm_swtpm {
	int fd;
	int ctrl_fd;
	bool migration_key;
};

struct tpm_resp_hdr {
	uint16_t tag;
	uint32_t len;
	uint32_t errcode;
} __packed;

static int
tpm_swtpm_send_all(int fd, const void *buffer, size_t size)
{
	const uint8_t *p = buffer;
	ssize_t n;

	while (size != 0) {
		n = send(fd, p, size, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return (errno);
		}
		if (n == 0)
			return (ECONNRESET);
		p += n;
		size -= n;
	}
	return (0);
}

static int
tpm_swtpm_recv_all(int fd, void *buffer, size_t size)
{
	uint8_t *p = buffer;
	ssize_t n;

	while (size != 0) {
		n = recv(fd, p, size, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return (errno);
		}
		if (n == 0)
			return (ECONNRESET);
		p += n;
		size -= n;
	}
	return (0);
}

static int
tpm_swtpm_connect(const char *path, int *fd)
{
	struct sockaddr_un addr;
	int connected, error;

	if (path == NULL || fd == NULL)
		return (EINVAL);
	connected = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (connected < 0)
		return (errno);
	bzero(&addr, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (strlcpy(addr.sun_path, path, sizeof(addr.sun_path)) >=
	    sizeof(addr.sun_path)) {
		close(connected);
		return (ENAMETOOLONG);
	}
	if (connect(connected, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		error = errno;
		close(connected);
		return (error);
	}
	*fd = connected;
	return (0);
}

static int
tpm_swtpm_init(void **sc, nvlist_t *nvl)
{
	struct tpm_swtpm *tpm;
	const char *path, *ctrl_path;
	struct timeval timeout;
	uint32_t caps, config_flags;
	int error;

	tpm = calloc(1, sizeof (struct tpm_swtpm));
	if (tpm == NULL) {
		warnx("%s: failed to allocate tpm_swtpm", __func__);
		return (ENOMEM);
	}
	tpm->fd = -1;
	tpm->ctrl_fd = -1;

	path = get_config_value_node(nvl, "path");
	if (path == NULL) {
		warnx("%s: no socket path specified", __func__);
		free(tpm);
		return (EINVAL);
	}

	error = tpm_swtpm_connect(path, &tpm->fd);
	if (error != 0) {
		warnx("%s: unable to connect to tpm socket \"%s\"", __func__,
		    path);
		free(tpm);
		return (error);
	}
	ctrl_path = get_config_value_node(nvl, "ctrl_path");
	if (ctrl_path != NULL) {
		error = tpm_swtpm_connect(ctrl_path, &tpm->ctrl_fd);
		timeout = (struct timeval){ .tv_sec = 30 };
		if (error == 0 && (setsockopt(tpm->ctrl_fd, SOL_SOCKET,
		    SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
		    setsockopt(tpm->ctrl_fd, SOL_SOCKET, SO_SNDTIMEO,
		    &timeout, sizeof(timeout)) != 0))
			error = errno;
		if (error == 0)
			error = tpm_swtpm_control_capabilities(tpm->ctrl_fd,
			    &caps);
		if (error == 0 && (caps & (SWTPM_CONTROL_CAP_INIT |
		    SWTPM_CONTROL_CAP_GET_STATEBLOB |
		    SWTPM_CONTROL_CAP_SET_STATEBLOB |
		    SWTPM_CONTROL_CAP_STOP |
		    SWTPM_CONTROL_CAP_LOCK_STORAGE)) !=
		    (SWTPM_CONTROL_CAP_INIT |
		    SWTPM_CONTROL_CAP_GET_STATEBLOB |
		    SWTPM_CONTROL_CAP_SET_STATEBLOB |
		    SWTPM_CONTROL_CAP_STOP |
		    SWTPM_CONTROL_CAP_LOCK_STORAGE))
			error = EOPNOTSUPP;
		if (error == 0 &&
		    (caps & SWTPM_CONTROL_CAP_GET_CONFIG) != 0) {
			error = tpm_swtpm_control_get_config(tpm->ctrl_fd,
			    &config_flags);
			if (error == 0)
				tpm->migration_key =
				    (config_flags &
				    SWTPM_CONTROL_CONFIG_MIGRATION_KEY) != 0;
		}
		if (error != 0) {
			warnx("%s: unusable swtpm control socket \"%s\"",
			    __func__, ctrl_path);
			if (tpm->ctrl_fd >= 0)
				close(tpm->ctrl_fd);
			close(tpm->fd);
			free(tpm);
			return (error);
		}
	}

	*sc = tpm;

	return (0);
}

static int
tpm_swtpm_execute_cmd(void *sc, void *cmd, uint32_t cmd_size, void *rsp,
    uint32_t rsp_size)
{
	struct tpm_swtpm *tpm;
	uint32_t response_size;
	int error;

	if (rsp_size < (ssize_t)sizeof(struct tpm_resp_hdr)) {
		warn("%s: rsp_size of %u is too small", __func__, rsp_size);
		return (EINVAL);
	}

	tpm = sc;

	/*
	 * A partial send or recv leaves the SOCK_STREAM connection desynced
	 * mid-message.  Tear the fd down on any transport error so a later
	 * command cannot read a stale/aborted message's bytes as its own
	 * response; subsequent commands then fail closed on the dead fd
	 * rather than acting on leftover data.
	 */
	error = tpm_swtpm_send_all(tpm->fd, cmd, cmd_size);
	if (error != 0)
		goto fail;
	error = tpm_swtpm_recv_all(tpm->fd, rsp,
	    sizeof(struct tpm_resp_hdr));
	if (error != 0)
		goto fail;
	response_size = be32dec((uint8_t *)rsp +
	    offsetof(struct tpm_resp_hdr, len));
	if (response_size < sizeof(struct tpm_resp_hdr) ||
	    response_size > rsp_size) {
		error = EMSGSIZE;
		goto fail;
	}
	error = tpm_swtpm_recv_all(tpm->fd,
	    (uint8_t *)rsp + sizeof(struct tpm_resp_hdr),
	    response_size - sizeof(struct tpm_resp_hdr));
	if (error != 0)
		goto fail;
	memset((uint8_t *)rsp + response_size, 0, rsp_size - response_size);

	return (0);

fail:
	if (tpm->fd >= 0) {
		(void)close(tpm->fd);
		tpm->fd = -1;
	}
	return (error);
}

static void
tpm_swtpm_deinit(void *sc)
{
	struct tpm_swtpm *tpm;

	tpm = sc;
	if (tpm == NULL)
		return;

	if (tpm->fd >= 0)
		close(tpm->fd);
	if (tpm->ctrl_fd >= 0)
		close(tpm->ctrl_fd);

	free(tpm);
}

static int
tpm_swtpm_state_result(struct tpm_swtpm *tpm, int error)
{

	/* A failed transfer may have left a partial reply on the stream. */
	if (error != 0 && tpm->ctrl_fd >= 0) {
		(void)close(tpm->ctrl_fd);
		tpm->ctrl_fd = -1;
	}
	return (error);
}

static int
tpm_swtpm_state_stop(void *sc)
{
	struct tpm_swtpm *tpm = sc;

	return (tpm->ctrl_fd < 0 ? EOPNOTSUPP :
	    tpm_swtpm_state_result(tpm,
	    tpm_swtpm_control_stop(tpm->ctrl_fd)));
}

static bool
tpm_swtpm_state_available(void *sc)
{
	struct tpm_swtpm *tpm = sc;

	return (tpm != NULL && tpm->fd >= 0 && tpm->ctrl_fd >= 0 &&
	    tpm->migration_key);
}

static int
tpm_swtpm_state_init(void *sc)
{
	struct tpm_swtpm *tpm = sc;

	return (tpm->ctrl_fd < 0 ? EOPNOTSUPP :
	    tpm_swtpm_state_result(tpm,
	    tpm_swtpm_control_init(tpm->ctrl_fd, 0)));
}

static int
tpm_swtpm_state_lock(void *sc)
{
	struct tpm_swtpm *tpm = sc;

	return (tpm->ctrl_fd < 0 ? EOPNOTSUPP :
	    tpm_swtpm_state_result(tpm,
	    tpm_swtpm_control_lock_storage(tpm->ctrl_fd, 0)));
}

static int
tpm_swtpm_state_get_blob(void *sc, uint32_t type, uint8_t **blob,
    size_t *length, uint32_t *flags)
{
	struct tpm_swtpm *tpm = sc;

	return (tpm->ctrl_fd < 0 ? EOPNOTSUPP :
	    tpm_swtpm_state_result(tpm,
	    tpm_swtpm_control_get_blob(tpm->ctrl_fd, type, blob, length,
	    flags)));
}

static int
tpm_swtpm_state_set_blob(void *sc, uint32_t type, const uint8_t *blob,
    size_t length, uint32_t flags)
{
	struct tpm_swtpm *tpm = sc;

	return (tpm->ctrl_fd < 0 ? EOPNOTSUPP :
	    tpm_swtpm_state_result(tpm,
	    tpm_swtpm_control_set_blob(tpm->ctrl_fd, type, blob, length,
	    flags)));
}

static const struct tpm_emul tpm_emul_swtpm = {
	.name = "swtpm",
	.init = tpm_swtpm_init,
	.deinit = tpm_swtpm_deinit,
	.execute_cmd = tpm_swtpm_execute_cmd,
	.state_available = tpm_swtpm_state_available,
	.state_stop = tpm_swtpm_state_stop,
	.state_init = tpm_swtpm_state_init,
	.state_lock = tpm_swtpm_state_lock,
	.state_get_blob = tpm_swtpm_state_get_blob,
	.state_set_blob = tpm_swtpm_state_set_blob,
};
TPM_EMUL_SET(tpm_emul_swtpm);
