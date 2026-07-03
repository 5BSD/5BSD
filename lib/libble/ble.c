/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libble — BLE client library implementation.
 *
 * Communicates with blued(8) over its Unix domain control socket
 * using a newline-terminated text protocol.  Async events from the
 * daemon (EVENT NOTIFY, EVENT PASSKEY_*, EVENT NUMCMP_*) are
 * dispatched to registered callbacks when ble_process() is called.
 */

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include "ble.h"

#define DEFAULT_SOCK	"/var/run/blued.sock"
#define RECV_BUF	4096
#define SEND_BUF	512
#define MAX_LINE	4096

struct ble_ctx {
	int		fd;
	char		linebuf[MAX_LINE];
	size_t		linelen;
	int		line_overflow;

	/* Persistent callbacks */
	ble_notify_cb		notify_cb;
	void			*notify_arg;
	ble_write_req_cb	write_cb;
	void			*write_arg;
	ble_passkey_display_cb	passkey_display_cb;
	void			*passkey_display_arg;
	ble_passkey_input_cb	passkey_input_cb;
	void			*passkey_input_arg;
	ble_numcmp_cb		numcmp_cb;
	void			*numcmp_arg;

	/* One-shot callbacks for pending operations */
	ble_scan_cb		scan_cb;
	void			*scan_arg;
	ble_connect_cb		connect_cb;
	void			*connect_arg;
	ble_read_cb		read_cb;
	void			*read_arg;
	ble_addr_t		read_addr;
	ble_discover_cb		discover_cb;
	void			*discover_arg;
	ble_addr_t		discover_addr;
	ble_service_t		discover_svcs[16];
	int			discover_nsvc;
	ble_characteristic_t	discover_chars[64];
	int			discover_nchar;

	/* Pending handle return for add_service / add_char */
	uint16_t		*pending_handle;

	/* Raw command callback (one-shot, cleared on terminal) */
	ble_line_cb		line_cb;
	void			*line_arg;
	bool			line_streaming;

	/* Unsolicited line callback (persistent, for async events) */
	ble_line_cb		unsolicited_cb;
	void			*unsolicited_arg;
};

static int
ctl_send(int fd, const char *fmt, ...)
{
	va_list ap;
	char buf[SEND_BUF];
	int len;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (len < 0 || (size_t)len >= sizeof(buf))
		return (-1);

	/* Append newline */
	if (len > 0 && buf[len - 1] != '\n') {
		if ((size_t)len + 1 >= sizeof(buf))
			return (-1);
		buf[len++] = '\n';
		buf[len] = '\0';
	}

	if (send(fd, buf, (size_t)len, 0) < 0)
		return (-1);
	return (0);
}

static void
parse_hex(const char *hex, uint8_t *out, uint16_t *outlen, uint16_t maxlen)
{
	size_t i, hlen;

	hlen = strlen(hex);
	if (hlen > (size_t)maxlen * 2)
		hlen = (size_t)maxlen * 2;
	*outlen = 0;
	for (i = 0; i + 1 < hlen && *outlen < maxlen; i += 2) {
		unsigned int byte;
		if (sscanf(hex + i, "%2x", &byte) != 1)
			break;
		out[(*outlen)++] = (uint8_t)byte;
	}
}

static void
parse_addr(const char *str, ble_addr_t *addr)
{
	bdaddr_t ba;

	memset(addr, 0, sizeof(*addr));
	if (bt_aton(str, &ba))
		memcpy(addr->addr, &ba, 6);
}

static void
bytes_to_hex(const uint8_t *data, uint16_t len, char *hexbuf, size_t bufsz)
{
	uint16_t i;

	if (bufsz == 0)
		return;
	for (i = 0; i < len && (size_t)(i * 2 + 2) < bufsz; i++)
		snprintf(hexbuf + i * 2, 3, "%02X", data[i]);
	hexbuf[i * 2] = '\0';
}

const char *
ble_addr_str(const ble_addr_t *addr, char buf[18])
{
	bdaddr_t ba;

	memcpy(&ba, addr->addr, 6);
	bt_ntoa(&ba, buf);
	return (buf);
}

/*
 * Terminal detection — single source of truth for protocol framing.
 * Returns 1 for success terminals (OK, END, STATUS), -1 for error
 * terminals (ERROR), 0 for non-terminal lines.
 */
static int
ble_is_terminal(const char *line)
{

	if (strncmp(line, "OK", 2) == 0 &&
	    (line[2] == '\0' || line[2] == ' '))
		return (1);
	if (strncmp(line, "ERROR", 5) == 0 &&
	    (line[5] == '\0' || line[5] == ' '))
		return (-1);
	if (strcmp(line, "END") == 0)
		return (1);
	if (strncmp(line, "STATUS ", 7) == 0)
		return (1);
	return (0);
}

/*
 * Process a single line from the daemon.
 *
 * If a raw line callback is registered (via ble_command()), it fires
 * first for every line.  The typed dispatch below then runs for its
 * internal state management.
 */
static void
ble_dispatch_line(ble_ctx_t *ctx, const char *line)
{
	int term;

	term = ble_is_terminal(line);

	/* Raw command callback — fires for every line when active */
	if (ctx->line_cb != NULL) {
		ctx->line_cb(line, term != 0, term, ctx->line_arg);
		if (term != 0 && !ctx->line_streaming) {
			ctx->line_cb = NULL;
			ctx->line_arg = NULL;
		}
		return;	/* raw mode: skip typed dispatch */
	}

	/* Unsolicited line callback — fires when no command is pending */
	if (ctx->unsolicited_cb != NULL) {
		ctx->unsolicited_cb(line, term != 0, term,
		    ctx->unsolicited_arg);
		/* Don't return — fall through to typed dispatch */
	}

	/* EVENT NOTIFY <addr> 0x<handle> <hex> */
	if (strncmp(line, "EVENT NOTIFY ", 13) == 0 && ctx->notify_cb) {
		char astr[18];
		unsigned int h;
		char hexval[1024];
		ble_addr_t addr;
		uint8_t val[512];
		uint16_t vlen;

		hexval[0] = '\0';
		if (sscanf(line + 13, "%17s 0x%x %1023s", astr, &h, hexval) >= 2) {
			parse_addr(astr, &addr);
			parse_hex(hexval, val, &vlen, sizeof(val));
			ctx->notify_cb(&addr, (uint16_t)h, val, vlen,
			    ctx->notify_arg);
		}
		return;
	}

	/* EVENT WRITE 0x<handle> <hex> */
	if (strncmp(line, "EVENT WRITE ", 12) == 0 && ctx->write_cb) {
		unsigned int h;
		char hexval[1024];
		uint8_t val[512];
		uint16_t vlen;

		hexval[0] = '\0';
		if (sscanf(line + 12, "0x%x %1023s", &h, hexval) >= 1) {
			parse_hex(hexval, val, &vlen, sizeof(val));
			ctx->write_cb((uint16_t)h, val, vlen, ctx->write_arg);
		}
		return;
	}

	/* EVENT PASSKEY_DISPLAY <addr> <passkey> */
	if (strncmp(line, "EVENT PASSKEY_DISPLAY ", 21) == 0 &&
	    ctx->passkey_display_cb) {
		char astr[18];
		unsigned int pk;
		ble_addr_t addr;

		if (sscanf(line + 21, "%17s %u", astr, &pk) == 2) {
			parse_addr(astr, &addr);
			ctx->passkey_display_cb(&addr, pk,
			    ctx->passkey_display_arg);
		}
		return;
	}

	/* EVENT PASSKEY_INPUT <addr> */
	if (strncmp(line, "EVENT PASSKEY_INPUT ", 19) == 0 &&
	    ctx->passkey_input_cb) {
		char astr[18];
		ble_addr_t addr;

		if (sscanf(line + 19, "%17s", astr) == 1) {
			parse_addr(astr, &addr);
			ctx->passkey_input_cb(&addr, ctx->passkey_input_arg);
		}
		return;
	}

	/* EVENT NUMCMP_REQUEST <addr> <value> */
	if (strncmp(line, "EVENT NUMCMP_REQUEST ", 20) == 0 &&
	    ctx->numcmp_cb) {
		char astr[18];
		unsigned int val;
		ble_addr_t addr;

		if (sscanf(line + 20, "%17s %u", astr, &val) == 2) {
			parse_addr(astr, &addr);
			ctx->numcmp_cb(&addr, val, ctx->numcmp_arg);
		}
		return;
	}

	/* DEVICE lines from SCAN */
	if (strncmp(line, "DEVICE ", 7) == 0 && ctx->scan_cb) {
		ble_scan_result_t r;
		char astr[18], type[16];
		int rssi;
		const char *p;

		memset(&r, 0, sizeof(r));
		r.mfr_id = 0xFFFF;

		/*
		 * Parse: DEVICE [adapter] addr type rssi=N name=... mfr=0xN svcs=...
		 * Use strstr for name= since names can contain spaces.
		 */
		p = strchr(line + 7, ']');
		if (p == NULL)
			return;
		p++;
		while (*p == ' ')
			p++;

		if (sscanf(p, "%17s %15s rssi=%d", astr, type, &rssi) < 3)
			return;

		parse_addr(astr, &r.addr);
		if (strcmp(type, "random") == 0)
			r.addr.addr_type = 1;
		r.rssi = (int8_t)rssi;

		/* Extract name= field (may contain spaces, ends at mfr=) */
		{
			const char *ns, *ne;

			ns = strstr(p, "name=");
			if (ns != NULL) {
				ns += 5;
				ne = strstr(ns, " mfr=");
				if (ne == NULL)
					ne = ns + strlen(ns);
				{
					size_t nlen = (size_t)(ne - ns);
					if (nlen >= sizeof(r.name))
						nlen = sizeof(r.name) - 1;
					memcpy(r.name, ns, nlen);
					r.name[nlen] = '\0';
				}
			}
		}

		/* Extract mfr= */
		{
			const char *ms = strstr(p, "mfr=0x");
			if (ms != NULL) {
				unsigned int m;
				if (sscanf(ms + 4, "0x%x", &m) == 1)
					r.mfr_id = (uint16_t)m;
			}
		}

		ctx->scan_cb(&r, ctx->scan_arg);
		return;
	}

	/* OK CONNECT — connection success */
	if (strncmp(line, "OK CONNECT ", 11) == 0 && ctx->connect_cb) {
		char astr[18];
		ble_addr_t addr;

		if (sscanf(line + 11, "%17s", astr) == 1) {
			parse_addr(astr, &addr);
			ctx->connect_cb(&addr, 0, ctx->connect_arg);
		}
		ctx->connect_cb = NULL;
		return;
	}

	/* OK READ */
	if (strncmp(line, "OK READ ", 8) == 0 && ctx->read_cb) {
		unsigned int h;
		char hexval[1024];
		uint8_t val[512];
		uint16_t vlen;

		hexval[0] = '\0';
		if (sscanf(line + 8, "0x%x len=%*u value=%1023s", &h, hexval) >= 1) {
			parse_hex(hexval, val, &vlen, sizeof(val));
			ctx->read_cb(&ctx->read_addr, (uint16_t)h, val, vlen,
			    0, ctx->read_arg);
		}
		ctx->read_cb = NULL;
		return;
	}

	/* DISCOVER header — "DISCOVER <addr>" */
	if (strncmp(line, "DISCOVER ", 9) == 0 && ctx->discover_cb) {
		char astr[18];

		if (sscanf(line + 9, "%17s", astr) == 1)
			parse_addr(astr, &ctx->discover_addr);
		ctx->discover_nsvc = 0;
		ctx->discover_nchar = 0;
		return;
	}

	/* DISCOVER service line — "  service uuid=0xNNNN handles=..." */
	if (strncmp(line, "  service ", 10) == 0 && ctx->discover_cb) {
		unsigned int u, sh, eh;

		if (ctx->discover_nsvc < 16) {
			ble_service_t *s =
			    &ctx->discover_svcs[ctx->discover_nsvc];
			memset(s, 0, sizeof(*s));
			if (sscanf(line, "  service uuid=0x%x handles=0x%x-0x%x",
			    &u, &sh, &eh) == 3) {
				s->uuid.uuid16 = (uint16_t)u;
				s->start_handle = (uint16_t)sh;
				s->end_handle = (uint16_t)eh;
			} else if (sscanf(line,
			    "  service uuid=128bit handles=0x%x-0x%x",
			    &sh, &eh) == 2) {
				s->start_handle = (uint16_t)sh;
				s->end_handle = (uint16_t)eh;
			}
			ctx->discover_nsvc++;
		}
		return;
	}

	/* DISCOVER char line — "    char uuid=0xNNNN handle=0xNNNN props=..." */
	if (strncmp(line, "    char ", 9) == 0 && ctx->discover_cb) {
		unsigned int u, h;
		char props_str[128];

		if (ctx->discover_nchar < 64) {
			ble_characteristic_t *c =
			    &ctx->discover_chars[ctx->discover_nchar];
			memset(c, 0, sizeof(*c));
			props_str[0] = '\0';
			if (sscanf(line,
			    "    char uuid=0x%x handle=0x%x props=%127s",
			    &u, &h, props_str) >= 2) {
				c->uuid.uuid16 = (uint16_t)u;
				c->handle = (uint16_t)h;
				/* Parse pipe-separated properties */
				{
					char ptmp[128], *pp, *tok;
					strlcpy(ptmp, props_str, sizeof(ptmp));
					pp = ptmp;
					while ((tok = strsep(&pp, "|,")) != NULL) {
						if (strcmp(tok, "read") == 0)
							c->properties |= BLE_PROP_READ;
						else if (strcmp(tok, "write_no_rsp") == 0)
							c->properties |= BLE_PROP_WRITE_NO_RSP;
						else if (strcmp(tok, "write") == 0)
							c->properties |= BLE_PROP_WRITE;
						else if (strcmp(tok, "notify") == 0)
							c->properties |= BLE_PROP_NOTIFY;
						else if (strcmp(tok, "indicate") == 0)
							c->properties |= BLE_PROP_INDICATE;
						else if (strcmp(tok, "broadcast") == 0)
							c->properties |= BLE_PROP_BROADCAST;
						else if (strcmp(tok, "auth_signed") == 0)
							c->properties |= BLE_PROP_AUTH_SIGNED_WRITE;
					}
				}
			} else if (sscanf(line,
			    "    char uuid=128bit handle=0x%x props=%127s",
			    &h, props_str) >= 1) {
				c->handle = (uint16_t)h;
			}
			ctx->discover_nchar++;
		}
		return;
	}

	/* OK ADD_SERVICE — return handle */
	if (strncmp(line, "OK ADD_SERVICE ", 15) == 0 &&
	    ctx->pending_handle != NULL) {
		unsigned int h;

		if (sscanf(line + 15, "handle=0x%x", &h) == 1)
			*ctx->pending_handle = (uint16_t)h;
		ctx->pending_handle = NULL;
		return;
	}

	/* OK ADD_CHAR — return handle */
	if (strncmp(line, "OK ADD_CHAR ", 12) == 0 &&
	    ctx->pending_handle != NULL) {
		unsigned int h;

		if (sscanf(line + 12, "handle=0x%x", &h) == 1)
			*ctx->pending_handle = (uint16_t)h;
		ctx->pending_handle = NULL;
		return;
	}

	/* ERROR lines — dispatch error to pending callback */
	if (strncmp(line, "ERROR", 5) == 0) {
		if (ctx->connect_cb) {
			ble_addr_t addr;
			memset(&addr, 0, sizeof(addr));
			ctx->connect_cb(&addr, -1, ctx->connect_arg);
			ctx->connect_cb = NULL;
		}
		if (ctx->read_cb) {
			ble_addr_t addr;
			memset(&addr, 0, sizeof(addr));
			ctx->read_cb(&addr, 0, NULL, 0, -1, ctx->read_arg);
			ctx->read_cb = NULL;
		}
		if (ctx->discover_cb) {
			ctx->discover_cb(&ctx->discover_addr,
			    NULL, 0, NULL, 0, ctx->discover_arg);
			ctx->discover_cb = NULL;
		}
		ctx->pending_handle = NULL;
		return;
	}

	/* END — deliver accumulated discover results, clear one-shots */
	if (strcmp(line, "END") == 0) {
		if (ctx->discover_cb) {
			ctx->discover_cb(&ctx->discover_addr,
			    ctx->discover_svcs, ctx->discover_nsvc,
			    ctx->discover_chars, ctx->discover_nchar,
			    ctx->discover_arg);
			ctx->discover_cb = NULL;
		}
		ctx->scan_cb = NULL;
		return;
	}
}

ble_ctx_t *
ble_open(const char *sock_path)
{
	struct sockaddr_un sun;
	ble_ctx_t *ctx;
	int fd;

	if (sock_path == NULL)
		sock_path = DEFAULT_SOCK;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return (NULL);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, sock_path, sizeof(sun.sun_path));

	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		close(fd);
		return (NULL);
	}

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		close(fd);
		return (NULL);
	}
	ctx->fd = fd;
	return (ctx);
}

ble_ctx_t *
ble_open_fd(int fd)
{
	ble_ctx_t *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return (NULL);
	ctx->fd = fd;
	return (ctx);
}

void
ble_close(ble_ctx_t *ctx)
{

	if (ctx == NULL)
		return;
	if (ctx->fd >= 0)
		close(ctx->fd);
	free(ctx);
}

int
ble_fd(ble_ctx_t *ctx)
{

	return (ctx->fd);
}

int
ble_process(ble_ctx_t *ctx)
{
	char buf[RECV_BUF];
	ssize_t n;

	n = recv(ctx->fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return (0);
		return (-1);
	}
	if (n == 0)
		return (-1);
	buf[n] = '\0';

	for (ssize_t i = 0; i < n; i++) {
		if (buf[i] == '\n') {
			if (ctx->line_overflow) {
				ctx->line_overflow = 0;
				ctx->linelen = 0;
				continue;
			}
			ctx->linebuf[ctx->linelen] = '\0';
			ble_dispatch_line(ctx, ctx->linebuf);
			ctx->linelen = 0;
		} else {
			if (ctx->linelen < sizeof(ctx->linebuf) - 1)
				ctx->linebuf[ctx->linelen++] = buf[i];
			else
				ctx->line_overflow = 1;
		}
	}

	return (0);
}

/*
 * Raw command interface
 */

int
ble_command(ble_ctx_t *ctx, const char *cmd, ble_line_cb cb,
    void *arg, int flags)
{

	/*
	 * Raw mode overrides typed dispatch.  Clear any pending typed
	 * callbacks to prevent stale state from leaking across modes.
	 */
	ctx->scan_cb = NULL;
	ctx->connect_cb = NULL;
	ctx->read_cb = NULL;
	ctx->discover_cb = NULL;
	ctx->pending_handle = NULL;

	ctx->line_cb = cb;
	ctx->line_arg = arg;
	ctx->line_streaming = (flags & BLE_CMD_STREAMING) != 0;
	return (ctl_send(ctx->fd, "%s", cmd));
}

void
ble_on_line(ble_ctx_t *ctx, ble_line_cb cb, void *arg)
{

	ctx->unsolicited_cb = cb;
	ctx->unsolicited_arg = arg;
}

/*
 * Central mode
 */

int
ble_scan(ble_ctx_t *ctx, ble_scan_cb cb, void *arg)
{

	if (ctx->scan_cb != NULL)
		return (-1);	/* scan already in progress */
	ctx->scan_cb = cb;
	ctx->scan_arg = arg;
	return (ctl_send(ctx->fd, "SCAN"));
}

int
ble_connect(ble_ctx_t *ctx, const ble_addr_t *addr,
    ble_connect_cb cb, void *arg)
{
	char astr[18];

	if (ctx->connect_cb != NULL)
		return (-1);	/* connect already in progress */
	ble_addr_str(addr, astr);
	ctx->connect_cb = cb;
	ctx->connect_arg = arg;
	return (ctl_send(ctx->fd, "CONNECT %s %s", astr,
	    addr->addr_type ? "random" : "public"));
}

int
ble_connect_name(ble_ctx_t *ctx, const char *name,
    ble_connect_cb cb, void *arg)
{
	const char *p;

	if (name == NULL || *name == '\0')
		return (-1);
	for (p = name; *p != '\0'; p++) {
		if (*p == '\n' || *p == '\r' || (unsigned char)*p < 0x20)
			return (-1);
	}

	if (ctx->connect_cb != NULL)
		return (-1);
	ctx->connect_cb = cb;
	ctx->connect_arg = arg;
	return (ctl_send(ctx->fd, "CONNECT_NAME %s", name));
}

int
ble_disconnect(ble_ctx_t *ctx, const ble_addr_t *addr)
{
	char astr[18];

	ble_addr_str(addr, astr);
	return (ctl_send(ctx->fd, "DISCONNECT %s", astr));
}

int
ble_discover(ble_ctx_t *ctx, const ble_addr_t *addr,
    ble_discover_cb cb, void *arg)
{
	char astr[18];

	if (ctx->discover_cb != NULL)
		return (-1);	/* discover already in progress */
	ble_addr_str(addr, astr);
	ctx->discover_cb = cb;
	ctx->discover_arg = arg;
	return (ctl_send(ctx->fd, "DISCOVER %s", astr));
}

int
ble_read(ble_ctx_t *ctx, const ble_addr_t *addr,
    uint16_t handle, ble_read_cb cb, void *arg)
{
	char astr[18];

	if (ctx->read_cb != NULL)
		return (-1);	/* read already in progress */
	ble_addr_str(addr, astr);
	ctx->read_cb = cb;
	ctx->read_arg = arg;
	ctx->read_addr = *addr;
	return (ctl_send(ctx->fd, "READ %s 0x%04X", astr, handle));
}

int
ble_write(ble_ctx_t *ctx, const ble_addr_t *addr,
    uint16_t handle, const uint8_t *value, uint16_t len)
{
	char astr[18];
	char hexbuf[1024];

	if (len * 2 >= sizeof(hexbuf))
		return (-1);

	ble_addr_str(addr, astr);
	bytes_to_hex(value, len, hexbuf, sizeof(hexbuf));

	return (ctl_send(ctx->fd, "WRITE %s 0x%04X %s", astr, handle, hexbuf));
}

int
ble_subscribe(ble_ctx_t *ctx, const ble_addr_t *addr,
    uint16_t handle, ble_notify_cb cb, void *arg)
{
	char astr[18];

	ble_addr_str(addr, astr);
	ctx->notify_cb = cb;
	ctx->notify_arg = arg;
	return (ctl_send(ctx->fd, "SUBSCRIBE %s 0x%04X", astr, handle));
}

int
ble_unsubscribe(ble_ctx_t *ctx, const ble_addr_t *addr,
    uint16_t handle)
{
	char astr[18];

	ble_addr_str(addr, astr);
	return (ctl_send(ctx->fd, "UNSUBSCRIBE %s 0x%04X", astr, handle));
}

/*
 * Peripheral mode
 */

int
ble_add_service(ble_ctx_t *ctx, const ble_uuid_t *uuid,
    uint16_t *out_handle)
{

	if (out_handle != NULL) {
		*out_handle = 0;
		ctx->pending_handle = out_handle;
	}
	if (uuid->uuid16 != 0)
		return (ctl_send(ctx->fd, "ADD_SERVICE 0x%04X", uuid->uuid16));
	ctx->pending_handle = NULL;
	return (-1);
}

int
ble_add_characteristic(ble_ctx_t *ctx, uint16_t svc_handle,
    const ble_uuid_t *uuid, uint8_t props, uint8_t perms,
    const uint8_t *value, uint16_t len, uint16_t *out_handle)
{

	if (uuid->uuid16 == 0)
		return (-1);	/* 128-bit UUID not yet supported */

	if (out_handle != NULL) {
		*out_handle = 0;
		ctx->pending_handle = out_handle;
	}

	if (value != NULL && len > 0) {
		char hexbuf[512];

		if (len * 2 >= sizeof(hexbuf)) {
			ctx->pending_handle = NULL;
			return (-1);
		}
		bytes_to_hex(value, len, hexbuf, sizeof(hexbuf));
		return (ctl_send(ctx->fd,
		    "ADD_CHAR 0x%04X 0x%04X %d %d %s",
		    svc_handle, uuid->uuid16, props, perms, hexbuf));
	}

	return (ctl_send(ctx->fd,
	    "ADD_CHAR 0x%04X 0x%04X %d %d",
	    svc_handle, uuid->uuid16, props, perms));
}

int
ble_set_value(ble_ctx_t *ctx, uint16_t handle,
    const uint8_t *value, uint16_t len)
{
	char hexbuf[1024];

	if (len * 2 >= sizeof(hexbuf))
		return (-1);
	bytes_to_hex(value, len, hexbuf, sizeof(hexbuf));

	return (ctl_send(ctx->fd, "SET_VALUE 0x%04X %s", handle, hexbuf));
}

int
ble_remove_service(ble_ctx_t *ctx, uint16_t handle)
{

	return (ctl_send(ctx->fd, "REMOVE_SERVICE 0x%04X", handle));
}

void
ble_on_write(ble_ctx_t *ctx, ble_write_req_cb cb, void *arg)
{

	ctx->write_cb = cb;
	ctx->write_arg = arg;
}

/*
 * Pairing
 */

int
ble_passkey_reply(ble_ctx_t *ctx, const ble_addr_t *addr,
    uint32_t passkey)
{
	char astr[18];

	ble_addr_str(addr, astr);
	return (ctl_send(ctx->fd, "PASSKEY_REPLY %s %u", astr, passkey));
}

int
ble_numcmp_reply(ble_ctx_t *ctx, const ble_addr_t *addr, bool accept)
{
	char astr[18];

	ble_addr_str(addr, astr);
	return (ctl_send(ctx->fd, "NUMCMP_REPLY %s %s", astr,
	    accept ? "yes" : "no"));
}

void
ble_on_passkey_display(ble_ctx_t *ctx, ble_passkey_display_cb cb, void *arg)
{

	ctx->passkey_display_cb = cb;
	ctx->passkey_display_arg = arg;
}

void
ble_on_passkey_input(ble_ctx_t *ctx, ble_passkey_input_cb cb, void *arg)
{

	ctx->passkey_input_cb = cb;
	ctx->passkey_input_arg = arg;
}

void
ble_on_numcmp(ble_ctx_t *ctx, ble_numcmp_cb cb, void *arg)
{

	ctx->numcmp_cb = cb;
	ctx->numcmp_arg = arg;
}

/*
 * Convenience — client-side profile helpers.
 *
 * These chain generic GATT operations (DISCOVER + READ/SUBSCRIBE)
 * to provide higher-level profile access without daemon-side
 * profile knowledge.
 */

/*
 * Internal callback for ble_read_battery(): invoked when DISCOVER
 * completes, searches for Battery Level, issues READ.
 */
static void
battery_discover_done(const ble_addr_t *addr,
    const ble_service_t *svcs, int nsvc,
    const ble_characteristic_t *chars, int nchar, void *arg)
{
	ble_ctx_t *ctx = arg;
	ble_read_cb cb;
	void *cb_arg;
	int i;

	(void)svcs;
	(void)nsvc;

	/* Save and clear the stashed callback so ble_read() accepts it */
	cb = ctx->read_cb;
	cb_arg = ctx->read_arg;
	ctx->read_cb = NULL;

	for (i = 0; i < nchar; i++) {
		if (chars[i].uuid.uuid16 == BLE_CHR_BATTERY_LEVEL) {
			ble_read(ctx, addr, chars[i].handle, cb, cb_arg);
			return;
		}
	}

	/* Not found — report error */
	if (cb != NULL)
		cb(addr, 0, NULL, 0, -1, cb_arg);
}

int
ble_read_battery(ble_ctx_t *ctx, const ble_addr_t *addr,
    ble_read_cb cb, void *arg)
{

	if (ctx->read_cb != NULL || ctx->discover_cb != NULL)
		return (-1);

	/* Stash the user's read callback for battery_discover_done */
	ctx->read_cb = cb;
	ctx->read_arg = arg;
	ctx->read_addr = *addr;

	/* Start discovery — battery_discover_done chains the READ */
	return (ble_discover(ctx, addr, battery_discover_done, ctx));
}
