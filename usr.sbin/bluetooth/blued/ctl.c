/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * blued control socket — Unix domain socket for runtime management.
 *
 * Commands are newline-terminated text:
 *   ADAPTERS   — list active adapters
 *   LIST       — list connected devices
 *   SCAN       — start LE scan, stream results
 *   CONNECT <addr> [public|random] — initiate connection
 *   DISCONNECT <addr> — disconnect device
 *   STATUS     — daemon status summary
 */

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blued.h"
#include "ble_util.h"
#include "blued_probes.h"
#include "conn.h"
#include "ctl.h"
#include "hci_util.h"
#include "smp.h"

#define CTL_MAXLINE	256

static char	*ctl_sock_path;		/* saved for cleanup unlink */

/*
 * Send a text response to a control client.
 */
static void
blued_ctl_respond(int client_fd, const char *fmt, ...)
{
	va_list ap;
	char buf[1024];
	int len;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (len > 0) {
		if (len >= (int)sizeof(buf))
			len = (int)sizeof(buf) - 1;
		(void)send(client_fd, buf, (size_t)len, MSG_NOSIGNAL);
	}
}

/*
 * Send a file descriptor to a control client via SCM_RIGHTS.
 * The fd is dup'd and capability-limited before sending.
 */
void
blued_ctl_send_fd(int client_fd, int fd_to_send)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(sizeof(int))];
	char byte;
	int dup_fd;

	dup_fd = fcntl(fd_to_send, F_DUPFD_CLOEXEC, 0);
	if (dup_fd < 0)
		return;

	/* Capability-limit the sent fd */
	{
		cap_rights_t rights;

		cap_rights_init(&rights, CAP_SEND, CAP_RECV, CAP_EVENT);
		(void)cap_rights_limit(dup_fd, &rights);
	}

	/* Restrict transfer/inheritance properties */
	(void)cap_xfer_limit(dup_fd, CAP_XFER_ONCE);
	(void)cap_cloexec_limit(dup_fd, CAP_CLOEXEC_LOCKED);
	(void)cap_clofork_limit(dup_fd, CAP_CLOFORK_LOCKED);
	if (cap_ambient_limit(dup_fd) < 0) {
		close(dup_fd);
		blued_ctl_respond(client_fd, "ERROR fd hardening failed\n");
		return;
	}

	memset(&msg, 0, sizeof(msg));
	byte = '\0';
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	memset(cbuf, 0, sizeof(cbuf));
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &dup_fd, sizeof(int));

	if (sendmsg(client_fd, &msg, 0) < 0) {
		close(dup_fd);
		blued_ctl_respond(client_fd, "ERROR fd transfer failed\n");
		return;
	}

	close(dup_fd);
}

/*
 * Handle the ADAPTERS command.
 */
static void
ctl_cmd_adapters(int client_fd)
{
	struct blued_adapter *adp;
	char addr_str[18];

	blued_ctl_respond(client_fd, "ADAPTERS\n");
	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (!adp->active)
			continue;
		bt_ntoa(&adp->addr, addr_str);
		blued_ctl_respond(client_fd, "%s %s\n",
		    adp->name, addr_str);
	}
	blued_ctl_respond(client_fd, "END\n");
}

/*
 * Handle the LIST command — list connected devices.
 */
static void
ctl_cmd_list(int client_fd)
{
	struct blued_conn *conn;
	char addr_str[18];

	blued_ctl_respond(client_fd, "LIST\n");
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		bt_ntoa(&conn->dst, addr_str);
		blued_ctl_respond(client_fd, "%s state=%d handle=%04x\n",
		    addr_str, conn->state, conn->con_handle);
	}
	blued_ctl_respond(client_fd, "END\n");
}

/*
 * Handle the SCAN command — start LE scan on first adapter.
 */
static void
ctl_cmd_scan(int client_fd)
{
	struct blued_adapter *adp;
	struct ble_scan_result results[BLE_MAX_SCAN_RESULTS];
	int nresults, i;
	char addr_str[18];

	adp = LIST_FIRST(&blued_g.adapters);
	if (adp == NULL || !adp->active) {
		blued_ctl_respond(client_fd, "ERROR no active adapter\n");
		return;
	}

	blued_ctl_respond(client_fd, "SCANNING\n");

	nresults = 0;
	if (adp->le_features & LE_FEAT_EXT_ADVERTISING) {
		if (hci_le_ext_scan(adp->hci_fd, 5, results,
		    BLE_MAX_SCAN_RESULTS, &nresults) != 0)
			nresults = 0;
	}
	if (nresults == 0) {
		if (hci_le_scan(adp->hci_fd, 5, results,
		    BLE_MAX_SCAN_RESULTS, &nresults) < 0) {
			blued_ctl_respond(client_fd, "ERROR scan failed\n");
			return;
		}
	}

	for (i = 0; i < nresults; i++) {
		bt_ntoa((bdaddr_t *)results[i].addr, addr_str);
		blued_ctl_respond(client_fd, "DEVICE %s %s rssi=%d %s\n",
		    addr_str,
		    results[i].addr_type == BDADDR_LE_RANDOM ?
		    "random" : "public",
		    results[i].rssi,
		    results[i].has_name ? results[i].name : "(unknown)");
	}
	blued_ctl_respond(client_fd, "END\n");
}

/*
 * Handle the STATUS command.
 */
static void
ctl_cmd_status(int client_fd)
{
	struct blued_adapter *adp;
	struct blued_conn *conn;
	int nadp, nconn;

	nadp = 0;
	LIST_FOREACH(adp, &blued_g.adapters, entries)
		if (adp->active)
			nadp++;

	nconn = 0;
	LIST_FOREACH(conn, &blued_g.conns, entries)
		nconn++;

	blued_ctl_respond(client_fd,
	    "STATUS adapters=%d connections=%d\n", nadp, nconn);
}

/*
 * Handle the CONNECT command.
 * Syntax: CONNECT <addr> [public|random]
 */
static void
ctl_cmd_connect(int client_fd, const char *args)
{
	struct blued_adapter *adp;
	bdaddr_t addr;
	char addr_str[18];
	char buf[64];
	uint8_t addr_type;

	while (*args == ' ')
		args++;
	strlcpy(buf, args, sizeof(buf));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' ||
		    buf[len - 1] == '\r' || buf[len - 1] == ' '))
			buf[--len] = '\0';
	}

	/* Parse address and optional type */
	addr_type = BDADDR_LE_PUBLIC;
	{
		char *sp = strchr(buf, ' ');
		if (sp != NULL) {
			*sp = '\0';
			sp++;
			while (*sp == ' ')
				sp++;
			if (strcmp(sp, "random") == 0)
				addr_type = BDADDR_LE_RANDOM;
		}
	}

	strlcpy(addr_str, buf, sizeof(addr_str));
	if (!bt_aton(addr_str, &addr)) {
		blued_ctl_respond(client_fd, "ERROR invalid address\n");
		return;
	}

	/* Check not already connected */
	if (blued_conn_by_addr(&addr) != NULL) {
		blued_ctl_respond(client_fd, "ERROR already connected\n");
		return;
	}

	/* Find first active adapter */
	adp = LIST_FIRST(&blued_g.adapters);
	while (adp != NULL && !adp->active)
		adp = LIST_NEXT(adp, entries);
	if (adp == NULL) {
		blued_ctl_respond(client_fd, "ERROR no active adapter\n");
		return;
	}

	/*
	 * TODO: allocate a hogp_device with HCI fd, bond_db, local_addr,
	 * ATT pool, and vhid_ctl_fd.  Without these, the central setup
	 * thread cannot function (conn->hogp == NULL causes immediate
	 * failure).  Until this is implemented, reject the command.
	 */
	blued_ctl_respond(client_fd,
	    "ERROR dynamic connect not yet implemented\n");
	(void)adp;
	(void)addr_type;
}

/*
 * Handle the DISCONNECT command.
 */
static void
ctl_cmd_disconnect(int client_fd, const char *args)
{
	struct blued_conn *conn;
	bdaddr_t addr;
	char addr_str[18];

	while (*args == ' ')
		args++;
	strlcpy(addr_str, args, sizeof(addr_str));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(addr_str);
		while (len > 0 && (addr_str[len - 1] == '\n' ||
		    addr_str[len - 1] == '\r' ||
		    addr_str[len - 1] == ' '))
			addr_str[--len] = '\0';
	}

	if (!bt_aton(addr_str, &addr)) {
		blued_ctl_respond(client_fd, "ERROR invalid address\n");
		return;
	}

	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (memcmp(&conn->dst, &addr, sizeof(addr)) == 0) {
			/*
			 * Refuse to disconnect a conn whose setup thread
			 * is still running — closing the fd under it would
			 * cause use-after-free / double-close.
			 */
			if (conn->state == BLUED_CONN_CONNECTING) {
				blued_ctl_respond(client_fd,
				    "ERROR connection still setting up\n");
				return;
			}
			/* Close the ATT fd — the event loop will detect
			 * the disconnect and clean up */
			if (conn->att_fd >= 0) {
				close(conn->att_fd);
				conn->att_fd = -1;
			}
			conn->state = BLUED_CONN_IDLE;
			blued_ctl_respond(client_fd, "OK disconnected\n");
			return;
		}
	}
	blued_ctl_respond(client_fd, "ERROR device not found\n");
}

/*
 * Process a single complete command line from a control client.
 */
static void
blued_ctl_process(int client_fd, char *line)
{
	char *nl;

	/* Strip trailing \r */
	nl = strchr(line, '\r');
	if (nl != NULL)
		*nl = '\0';

	BLUED_PROBE_CTL_CMD(line);

	if (strcmp(line, "ADAPTERS") == 0) {
		ctl_cmd_adapters(client_fd);
	} else if (strcmp(line, "LIST") == 0) {
		ctl_cmd_list(client_fd);
	} else if (strcmp(line, "SCAN") == 0) {
		ctl_cmd_scan(client_fd);
	} else if (strcmp(line, "STATUS") == 0) {
		ctl_cmd_status(client_fd);
	} else if (strncmp(line, "CONNECT ", 8) == 0) {
		ctl_cmd_connect(client_fd, line + 8);
	} else if (strncmp(line, "DISCONNECT ", 11) == 0) {
		ctl_cmd_disconnect(client_fd, line + 11);
	} else {
		blued_ctl_respond(client_fd, "ERROR unknown command\n");
	}
}

/*
 * Dispatch a control command from a client.
 * Appends received data to the per-client buffer and processes
 * complete newline-terminated lines.
 */
int
blued_ctl_dispatch(struct blued_ctl_client *client)
{
	ssize_t n;
	char *nl;
	size_t avail;

	avail = sizeof(client->buf) - client->buflen - 1;
	if (avail == 0) {
		/* Buffer full with no newline — discard and reset */
		client->buflen = 0;
		blued_ctl_respond(client->fd, "ERROR line too long\n");
		return (0);
	}

	n = recv(client->fd, client->buf + client->buflen, avail, 0);
	if (n == 0)
		return (-1);	/* Client disconnected */
	if (n < 0) {
		if (errno == EINTR)
			return (0);
		return (-1);	/* Error — caller removes client */
	}
	client->buflen += (size_t)n;
	client->buf[client->buflen] = '\0';

	/* Process all complete lines */
	while ((nl = strchr(client->buf, '\n')) != NULL) {
		*nl = '\0';
		blued_ctl_process(client->fd, client->buf);

		/* Shift remainder */
		{
			size_t consumed = (size_t)(nl - client->buf) + 1;
			size_t remain = client->buflen - consumed;

			if (remain > 0)
				memmove(client->buf, nl + 1, remain);
			client->buflen = remain;
			client->buf[client->buflen] = '\0';
		}
	}

	return (0);
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

	/* Remove stale socket */
	(void)unlink(path);

	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		close(fd);
		return (-1);
	}

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

	/* Save path for cleanup */
	ctl_sock_path = strdup(path);

	LOG_HCI(1, "control socket: %s", path);
	return (0);
}

/*
 * Accept a new control client connection.
 */
void
blued_ctl_accept(void)
{
	struct blued_ctl_client *client;
	struct kevent kev;
	int fd;

	fd = accept4(blued_g.ctl_fd, NULL, NULL,
	    SOCK_CLOEXEC | SOCK_CLOFORK | SOCK_NONBLOCK);
	if (fd < 0)
		return;

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		close(fd);
		return;
	}
	client->fd = fd;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);

	/* Register for read events */
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, client);
	if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0) {
		LIST_REMOVE(client, entries);
		close(fd);
		free(client);
	}
}

/*
 * Clean up the control socket and all connected clients.
 */
void
blued_ctl_cleanup(void)
{
	struct blued_ctl_client *client, *tmp;

	LIST_FOREACH_SAFE(client, &blued_g.ctl_clients, entries, tmp) {
		close(client->fd);
		LIST_REMOVE(client, entries);
		free(client);
	}

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
