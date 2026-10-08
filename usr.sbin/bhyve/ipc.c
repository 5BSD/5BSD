/*
 * Copyright (c) 2016 Flavius Anton
 * Copyright (c) 2016 Mihai Tiganus
 * Copyright (c) 2016-2019 Mihai Carabas
 * Copyright (c) 2017-2019 Darius Mihai
 * Copyright (c) 2017-2019 Elena Mihailescu
 * Copyright (c) 2018-2019 Sergiu Weisz
 * Copyright (c) 2025 Bojan Novković <bnovkov@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */


#include "ipc.h"

#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/types.h>
#include <sys/linker_set.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif
#include <sys/cpuset.h>
#include <sys/ioctl.h>

#include <machine/vmm.h>
#include <machine/vmm_snapshot.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <pthread_np.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <vmmapi.h>

#include "bhyverun.h"
#include "debug.h"

/* One stalled controller must not monopolize the IPC command thread. */
#define	IPC_CLIENT_TIMEOUT_SEC	30

#define IPC_COMMAND_FOREACH(pvar, set) SET_FOREACH(pvar, set)

SET_DECLARE(ipc_cmd_set, struct ipc_command);

static struct ipc_thread_ctx {
	struct vmctx *vmctx;
	int sockfd;
} thr_ctx;

static nvlist_t *
ipc_get_vm_pid(struct vmctx *ctx __unused, const nvlist_t *nvl __unused)
{
	nvlist_t *reply;

	reply = nvlist_create(0);
	nvlist_add_number(reply, "pid", getpid());
	return (reply);
}
IPC_COMMAND(get_vm_pid, ipc_get_vm_pid);

static nvlist_t *
handle_message(struct vmctx *ctx, const char *cmd, nvlist_t *nvl)
{
	struct ipc_command **ipc_cmd;

	IPC_COMMAND_FOREACH(ipc_cmd, ipc_cmd_set)
	{
		if (strcmp(cmd, (*ipc_cmd)->name) == 0)
			return ((*ipc_cmd)->handler(ctx, nvl));
	}

	return (NULL);
}

/*
 * Listen for commands from bhyvectl.
 */
static void *
ipc_thread(void *param)
{
	int fd, on;
	nvlist_t *nvl, *reply;
	const char *cmdname;
	struct ipc_thread_ctx *ctx;

	pthread_set_name_np(pthread_self(), "IPC thread");
	ctx = (struct ipc_thread_ctx *)param;
	for (;;) {
		fd = accept4(ctx->sockfd, NULL, NULL, SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			EPRINTLN("%s: accept failed: %s", __func__,
			    strerror(errno));
			break;
		}
		/*
		 * A client that disconnects before reading its reply must not
		 * kill bhyve with SIGPIPE.
		 */
		on = 1;
		(void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));

		nvl = nvlist_recv(fd, 0);
		if (nvl == NULL) {
			EPRINTLN("%s: nvlist_recv() failed: %s", __func__,
			    strerror(errno));
			close(fd);
			continue;
		}

		/* nvlist_get_string() aborts on a missing or mistyped key. */
		if (!nvlist_exists_string(nvl, "cmd")) {
			reply = nvlist_create(0);
			nvlist_add_string(reply, "error",
			    "missing command name");
		} else {
			cmdname = nvlist_get_string(nvl, "cmd");
			reply = handle_message(ctx->vmctx, cmdname, nvl);
			if (reply == NULL) {
				reply = nvlist_create(0);
				nvlist_add_stringf(reply, "error",
				    "command '%s' not found", cmdname);
			} else if (nvlist_exists_string(reply, "error")) {
				EPRINTLN("IPC command '%s' failed: %s", cmdname,
				    nvlist_get_string(reply, "error"));
			}
		}
		/* The handler should set the error message if need be. */
		(void)nvlist_send(fd, reply);

		nvlist_destroy(nvl);
		nvlist_destroy(reply);
		close(fd);
	}

	return (NULL);
}

/*
 * Create the listening socket for IPC with bhyvectl.
 */
int
init_ipc_thread(struct vmctx *ctx, const char *bhyve_run_dir)
{
	struct sockaddr_un addr;
	struct timeval receive_timeout;
	pthread_t ipc_pthread;
	int socket_fd;
	int err, ret;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif

	memset(&addr, 0, sizeof(addr));

	socket_fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (socket_fd < 0) {
		EPRINTLN("Socket creation failed: %s", strerror(errno));
		err = -1;
		goto fail;
	}

	addr.sun_family = AF_UNIX;

	if (bhyve_run_dir == NULL)
		bhyve_run_dir = BHYVE_RUN_DIR;
	ret = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s",
	    bhyve_run_dir, vm_get_name(ctx));
	if (ret < 0 || (size_t)ret >= sizeof(addr.sun_path)) {
		EPRINTLN("IPC socket path is too long");
		addr.sun_path[0] = '\0';
		err = ENAMETOOLONG;
		goto fail;
	}

	addr.sun_len = SUN_LEN(&addr);
	unlink(addr.sun_path);

	if (bind(socket_fd, (struct sockaddr *)&addr, addr.sun_len) != 0) {
		EPRINTLN("Failed to bind socket \"%s\": %s\n",
		    addr.sun_path, strerror(errno));
		err = -1;
		goto fail;
	}
	/*
	 * Control operations can replace guest state; keep the endpoint
	 * private.  Use lchmod() so that if the run directory is writable by
	 * an unprivileged user who races a symlink into our path between
	 * bind() and here, we retarget the symlink itself rather than handing
	 * that user an arbitrary-file chmod primitive.
	 */
	if (lchmod(addr.sun_path, S_IRUSR | S_IWUSR) != 0) {
		EPRINTLN("Failed to restrict IPC socket \"%s\": %s\n",
		    addr.sun_path, strerror(errno));
		err = errno;
		goto fail;
	}
	/* Accepted Unix sockets inherit this deadline for nvlist_recv(). */
	receive_timeout = (struct timeval) {
		.tv_sec = IPC_CLIENT_TIMEOUT_SEC,
		.tv_usec = 0,
	};
	if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout,
	    sizeof(receive_timeout)) != 0) {
		EPRINTLN("Failed to set IPC client timeout: %s\n",
		    strerror(errno));
		err = errno;
		goto fail;
	}

	if (listen(socket_fd, 10) < 0) {
		EPRINTLN("ipc socket listen: %s\n", strerror(errno));
		err = errno;
		goto fail;
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_ACCEPT, CAP_READ, CAP_RECV, CAP_WRITE,
	    CAP_SEND, CAP_GETSOCKOPT, CAP_SETSOCKOPT);

	if (caph_rights_limit(socket_fd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif
	memset(&thr_ctx, 0, sizeof(thr_ctx));
	thr_ctx.vmctx = ctx;
	thr_ctx.sockfd = socket_fd;

	err = pthread_create(&ipc_pthread, NULL, ipc_thread,
		&thr_ctx);
	if (err != 0)
		goto fail;

	return (0);
fail:
	if (socket_fd >= 0)
		close(socket_fd);
	if (addr.sun_path[0] != '\0')
		unlink(addr.sun_path);

	return (err);
}
