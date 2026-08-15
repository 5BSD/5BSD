/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Hans Rosenfeld
 * Author: Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
 */

#include <sys/types.h>
#include <sys/socket.h>
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

struct tpm_swtpm {
	int fd;
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
tpm_swtpm_init(void **sc, nvlist_t *nvl)
{
	struct tpm_swtpm *tpm;
	const char *path;
	struct sockaddr_un tpm_addr;

	tpm = calloc(1, sizeof (struct tpm_swtpm));
	if (tpm == NULL) {
		warnx("%s: failed to allocate tpm_swtpm", __func__);
		return (ENOMEM);
	}
	tpm->fd = -1;

	path = get_config_value_node(nvl, "path");
	if (path == NULL) {
		warnx("%s: no socket path specified", __func__);
		free(tpm);
		return (EINVAL);
	}

	tpm->fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (tpm->fd < 0) {
		warnx("%s: unable to open tpm socket", __func__);
		free(tpm);
		return (ENOENT);
	}

	bzero(&tpm_addr, sizeof (tpm_addr));
	tpm_addr.sun_family = AF_UNIX;
	if (strlcpy(tpm_addr.sun_path, path, sizeof(tpm_addr.sun_path)) >=
	    sizeof(tpm_addr.sun_path)) {
		warnx("%s: TPM socket path is too long", __func__);
		close(tpm->fd);
		free(tpm);
		return (ENAMETOOLONG);
	}

	if (connect(tpm->fd, (struct sockaddr *)&tpm_addr, sizeof (tpm_addr)) ==
	    -1) {
		warnx("%s: unable to connect to tpm socket \"%s\"", __func__,
		    path);
		close(tpm->fd);
		free(tpm);
		return (ENOENT);
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

	free(tpm);
}

static const struct tpm_emul tpm_emul_swtpm = {
	.name = "swtpm",
	.init = tpm_swtpm_init,
	.deinit = tpm_swtpm_deinit,
	.execute_cmd = tpm_swtpm_execute_cmd,
};
TPM_EMUL_SET(tpm_emul_swtpm);
