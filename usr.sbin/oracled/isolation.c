/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Claim /dev/cap_rt via the cap_rt_isolation service so that only
 * processes sharing oracled's nonce can open the device directly.
 */

#include <sys/ioctl.h>

#include <dev/cap_rt/cap_rt_ioctl.h>
#include <dev/cap_rt/cap_rt_isolation_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"

/*
 * Connect to the "isolation" cap_rt service and claim /dev/cap_rt.
 *
 * On success, sets isolation_fd to the service instance fd.
 * The claim persists as long as isolation_fd is open.
 */
int
isolate_cap_rt_device(void)
{
	struct cap_rt_connect_args conn;
	struct cap_rt_call_args call;
	struct fi_request req;
	struct fi_reply reply;
	int dev_fd, iso_fd;

	if (cap_rt_fd < 0)
		return (-1);

	/* Connect to the isolation service. */
	memset(&conn, 0, sizeof(conn));
	strlcpy(conn.name, "isolation", sizeof(conn.name));
	if (ioctl(cap_rt_fd, CAP_RT_CONNECT, &conn) == -1) {
		syslog(LOG_ERR, "cap_rt connect isolation: %m");
		return (-1);
	}
	iso_fd = conn.fd;

	/*
	 * Open /dev/cap_rt a second time to pass as the claim target.
	 * The isolation service identifies the vnode from this fd.
	 */
	dev_fd = open("/dev/cap_rt", O_RDONLY | O_CLOEXEC);
	if (dev_fd == -1) {
		syslog(LOG_ERR, "open /dev/cap_rt for isolation claim: %m");
		close(iso_fd);
		return (-1);
	}

	/* FI_OP_CLAIM with the device fd attached. */
	memset(&req, 0, sizeof(req));
	req.op = FI_OP_CLAIM;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.req_fds = &dev_fd;
	call.req_nfds = 1;
	call.reply = &reply;
	call.reply_len = sizeof(reply);

	if (ioctl(iso_fd, CAP_RT_CALL, &call) == -1) {
		syslog(LOG_ERR, "cap_rt isolation claim /dev/cap_rt: %m");
		close(dev_fd);
		close(iso_fd);
		return (-1);
	}

	close(dev_fd);
	isolation_fd = iso_fd;
	syslog(LOG_INFO, "claimed /dev/cap_rt via isolation");
	return (0);
}
