/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * bluedctl — command-line client for the blued(8) BLE daemon.
 *
 * Uses libble to connect to blued's Unix domain control socket.
 * Supports one-shot mode (single command) and interactive mode (-i).
 */

#include <sys/capsicum.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <ble.h>

#define SEND_BUF_SIZE		512

static volatile sig_atomic_t got_sigint;
static bool json_mode;			/* -j: machine-readable output */
static bool interactive_session;	/* true while interactive_mode() runs */

static void
sigint_handler(int sig __unused)
{

	got_sigint = 1;
}

/*
 * Exit-status taxonomy.  A distinct code per error class lets scripts react
 * without scraping text.  Mirrors the daemon's IPC_ERR_* taxonomy as surfaced
 * by libble's ble_errno().
 */
#define EX_OK		0
#define EX_ERR		1	/* generic / daemon error */
#define EX_USAGE	2	/* bad arguments (never reaches the daemon) */
#define EX_NOTCONN	3	/* device not connected / not found */
#define EX_PERM		4	/* permission denied (privilege tier) */
#define EX_BUSY		5	/* rate limited / in progress */
#define EX_TIMEOUT	6	/* no response */

static int
map_exit_code(int ble_err)
{

	switch (ble_err) {
	case BLE_ERR_NONE:	return (EX_OK);
	case BLE_ERR_PERM:	return (EX_PERM);
	case BLE_ERR_BUSY:	return (EX_BUSY);
	case BLE_ERR_TIMEOUT:	return (EX_TIMEOUT);
	case BLE_ERR_NOTCONN:
	case BLE_ERR_NOTFOUND:	return (EX_NOTCONN);
	case BLE_ERR_INVAL:	return (EX_USAGE);
	default:		return (EX_ERR);
	}
}

/*
 * Map an error class to a one-line actionable hint printed to stderr, so a
 * bare "ERROR permission denied" becomes something the user can act on.
 */
static void
print_error_hint(int ble_err)
{

	switch (ble_err) {
	case BLE_ERR_PERM:
		fprintf(stderr,
		    "hint: this command mutates state and requires root; "
		    "run as root or via the bluetooth group.\n");
		break;
	case BLE_ERR_NOTCONN:
		fprintf(stderr,
		    "hint: connect first (bluedctl connect <addr>), then "
		    "retry; use 'bluedctl list' to see connections.\n");
		break;
	case BLE_ERR_BUSY:
		fprintf(stderr,
		    "hint: an operation is in progress or you are rate "
		    "limited; wait a moment and retry.\n");
		break;
	case BLE_ERR_TIMEOUT:
		fprintf(stderr,
		    "hint: the device did not respond in time; ensure it is "
		    "in range and awake.\n");
		break;
	default:
		break;
	}
}

/* Rough validity check for an "XX:XX:XX:XX:XX:XX" address argument. */
static bool
looks_like_addr(const char *s)
{
	unsigned int b[6];

	return (sscanf(s, "%x:%x:%x:%x:%x:%x",
	    &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6);
}

/* Print a string as a JSON-escaped value (no surrounding quotes). */
static void
json_escape(const char *s)
{

	for (; *s != '\0'; s++) {
		switch (*s) {
		case '"':	fputs("\\\"", stdout); break;
		case '\\':	fputs("\\\\", stdout); break;
		case '\n':	fputs("\\n", stdout); break;
		case '\r':	fputs("\\r", stdout); break;
		case '\t':	fputs("\\t", stdout); break;
		default:
			if ((unsigned char)*s < 0x20)
				printf("\\u%04x", (unsigned char)*s);
			else
				putchar(*s);
		}
	}
}

/*
 * Harden a single fd: prevent transfer via SCM_RIGHTS, lock
 * close-on-exec and close-on-fork, and strip ambient authority.
 */
static void
ctl_harden_fd(int fd)
{

	(void)cap_xfer_limit(fd, CAP_XFER_NONE);
	(void)cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED);
	(void)cap_clofork_limit(fd, CAP_CLOFORK_LOCKED);
}

/*
 * Enter Capsicum sandbox after all file descriptors are acquired.
 */
static bool ctl_sandbox_enabled = true;

static void
ctl_sandbox(int fd)
{
	cap_rights_t rights;

	if (!ctl_sandbox_enabled)
		return;

	cap_rights_init(&rights, CAP_SEND, CAP_RECV, CAP_EVENT);
	if (cap_rights_limit(fd, &rights) < 0 && errno != ENOSYS)
		warn("cap_rights_limit socket");
	ctl_harden_fd(fd);

	cap_rights_init(&rights, CAP_READ, CAP_EVENT);
	if (cap_rights_limit(STDIN_FILENO, &rights) < 0 && errno != ENOSYS)
		warn("cap_rights_limit stdin");
	ctl_harden_fd(STDIN_FILENO);

	cap_rights_init(&rights, CAP_WRITE, CAP_EVENT);
	if (cap_rights_limit(STDOUT_FILENO, &rights) < 0 && errno != ENOSYS)
		warn("cap_rights_limit stdout");
	ctl_harden_fd(STDOUT_FILENO);
	if (cap_rights_limit(STDERR_FILENO, &rights) < 0 && errno != ENOSYS)
		warn("cap_rights_limit stderr");
	ctl_harden_fd(STDERR_FILENO);

	if (cap_enter() < 0 && errno != ENOSYS)
		warn("cap_enter");
}

/*
 * Join argv[start..argc) into buf, space-separated, without ever writing past
 * buf[bufsz-1].
 *
 * snprintf() returns the length it *would* have written had the buffer been big
 * enough, not the length it actually wrote.  A naive running offset (off += w)
 * therefore walks past the end of the buffer once the accumulated content
 * exceeds bufsz; on the next iteration "bufsz - off" underflows to a huge
 * size_t and "buf + off" points past the buffer, so snprintf performs an
 * unbounded out-of-bounds write — a stack smash reachable from argv and from
 * interactive input (finding K1).
 *
 * Guard every step: if a segment would not fit, clamp the offset, keep buf
 * NUL-terminated, and fail rather than truncate a security-relevant command.
 *
 * Returns 0 on success (buf holds the joined, NUL-terminated string) or -1 if
 * the result does not fit (buf is left safely NUL-terminated and truncated;
 * off never exceeds bufsz - 1).
 */
static int
join_args(char *buf, size_t bufsz, int argc, char **argv, int start)
{
	size_t off = 0;
	int a;

	if (bufsz == 0)
		return (-1);
	buf[0] = '\0';
	for (a = start; a < argc; a++) {
		int w = snprintf(buf + off, bufsz - off, "%s%s",
		    a > start ? " " : "", argv[a]);

		if (w < 0) {
			buf[bufsz - 1] = '\0';
			return (-1);
		}
		if ((size_t)w >= bufsz - off) {
			/* Doesn't fit — clamp to the last byte and stop. */
			buf[bufsz - 1] = '\0';
			return (-1);
		}
		off += (size_t)w;
	}
	return (0);
}

static void
print_result_line(const char *line)
{

	if (json_mode) {
		fputs("{\"line\":\"", stdout);
		json_escape(line);
		fputs("\"}\n", stdout);
	} else
		printf("%s\n", line);
}

static int
parse_u32(const char *text, uint32_t min, uint32_t max, uint32_t *out)
{
	char *end;
	unsigned long value;

	errno = 0;
	value = strtoul(text, &end, 0);
	if (errno != 0 || text[0] == '\0' || *end != '\0' ||
	    value < min || value > max)
		return (-1);
	*out = (uint32_t)value;
	return (0);
}

static int
parse_switch(const char *text, bool *out)
{

	if (strcasecmp(text, "on") == 0 || strcasecmp(text, "yes") == 0) {
		*out = true;
		return (0);
	}
	if (strcasecmp(text, "off") == 0 || strcasecmp(text, "no") == 0) {
		*out = false;
		return (0);
	}
	return (-1);
}

static int
parse_hex_value(const char *text, uint8_t *out, size_t capacity,
    uint16_t *length)
{
	size_t n;

	n = strlen(text);
	if ((n & 1) != 0 || n / 2 > capacity)
		return (-1);
	for (size_t i = 0; i < n / 2; i++) {
		char byte[3] = { text[i * 2], text[i * 2 + 1], '\0' };
		char *end;
		unsigned long value;

		errno = 0;
		value = strtoul(byte, &end, 16);
		if (errno != 0 || *end != '\0')
			return (-1);
		out[i] = (uint8_t)value;
	}
	*length = (uint16_t)(n / 2);
	return (0);
}

static int
parse_uuid16(const char *text, ble_uuid_t *uuid)
{
	uint32_t value;

	if (parse_u32(text, 1, UINT16_MAX, &value) != 0)
		return (-1);
	memset(uuid, 0, sizeof(*uuid));
	uuid->uuid16 = (uint16_t)value;
	return (0);
}

static int
parse_name_mask(const char *text, const char *const *names,
    const uint8_t *bits, size_t count, uint8_t *out)
{
	char copy[128], *cursor, *token;
	uint8_t mask = 0;

	if (strlcpy(copy, text, sizeof(copy)) >= sizeof(copy))
		return (-1);
	cursor = copy;
	while ((token = strsep(&cursor, ",")) != NULL) {
		bool found = false;

		for (size_t i = 0; i < count; i++) {
			if (strcmp(token, names[i]) == 0) {
				mask |= bits[i];
				found = true;
				break;
			}
		}
		if (!found)
			return (-1);
	}
	*out = mask;
	return (0);
}

static int
wait_typed_handle(ble_ctx_t *ctx, uint16_t *handle)
{
	struct pollfd pfd = { .fd = ble_fd(ctx), .events = POLLIN };

	while (*handle == 0 && !got_sigint) {
		if (poll(&pfd, 1, 5000) <= 0 ||
		    ((pfd.revents & POLLIN) != 0 && ble_process(ctx) < 0) ||
		    (pfd.revents & (POLLERR | POLLHUP)) != 0)
			return (-1);
		if (ble_errno(ctx) != BLE_ERR_NONE)
			return (-1);
	}
	return (*handle != 0 ? 0 : -1);
}

struct typed_wait {
	bool done;
	int status;
};

static int
wait_typed_result(ble_ctx_t *ctx, struct typed_wait *wait)
{
	struct pollfd pfd = { .fd = ble_fd(ctx), .events = POLLIN };

	while (!wait->done && !got_sigint) {
		if (poll(&pfd, 1, 5000) <= 0) {
			warnx("operation timed out");
			return (-1);
		}
		if ((pfd.revents & POLLIN) != 0 && ble_process(ctx) < 0)
			return (-1);
		if ((pfd.revents & (POLLERR | POLLHUP)) != 0)
			return (-1);
	}
	return (wait->done ? wait->status : -1);
}

static void
typed_connect_cb(const ble_addr_t *addr __unused, int error, void *arg)
{
	struct typed_wait *wait = arg;

	wait->status = error;
	wait->done = true;
}

static void
typed_discover_cb(const ble_addr_t *addr, const ble_service_t *services,
    int service_count, const ble_characteristic_t *characteristics,
    int characteristic_count, void *arg)
{
	struct typed_wait *wait = arg;
	char peer[18], line[192];

	ble_addr_str(addr, peer);
	for (int i = 0; i < service_count; i++) {
		snprintf(line, sizeof(line),
		    "%s service start=0x%04x end=0x%04x uuid=0x%04x", peer,
		    services[i].start_handle, services[i].end_handle,
		    services[i].uuid.uuid16);
		print_result_line(line);
	}
	for (int i = 0; i < characteristic_count; i++) {
		snprintf(line, sizeof(line),
		    "%s characteristic handle=0x%04x props=0x%02x uuid=0x%04x",
		    peer, characteristics[i].handle, characteristics[i].properties,
		    characteristics[i].uuid.uuid16);
		print_result_line(line);
	}
	wait->status = 0;
	wait->done = true;
}

static void
typed_read_cb(const ble_addr_t *addr, uint16_t handle, const uint8_t *value,
    uint16_t length, int error, void *arg)
{
	struct typed_wait *wait = arg;
	char peer[18];

	if (error == 0) {
		ble_addr_str(addr, peer);
		printf("%s handle=0x%04x value=", peer, handle);
		for (uint16_t i = 0; i < length; i++)
			printf("%02x", value[i]);
		putchar('\n');
	}
	wait->status = error;
	wait->done = true;
}

static void
typed_scan_cb(const ble_scan_result_t *result, void *arg __unused)
{
	char addr[18];

	ble_addr_str(&result->addr, addr);
	if (json_mode) {
		printf("{\"addr\":\"%s\",\"rssi\":%d,\"name\":\"", addr,
		    result->rssi);
		json_escape(result->name);
		printf("\"}\n");
	} else {
		printf("%s rssi=%d name=%s\n", addr, result->rssi, result->name);
	}
	fflush(stdout);
}

/* Structured read-only commands; returns 0 when argv names another command. */
static int
handle_structured_query(ble_ctx_t *ctx, int argc, char **argv)
{
	ble_connection_info_t conns[32];
	ble_resolv_entry_t entries[BLE_MAX_BONDS];
	ble_bond_t bonds[BLE_MAX_BONDS];
	ble_adapter_caps_t caps;
	ble_status_t status;
	ble_addr_t filter;
	char line[256], addr[18];
	bool have_filter = false;
	int count;

	if (strcmp(argv[0], "status") == 0 && argc == 1) {
		if (ble_status(ctx, &status) < 0)
			goto error;
		snprintf(line, sizeof(line),
		    "adapters=%u connections=%u clients=%u peripheral_active=%u",
		    status.adapters, status.connections, status.clients,
		    status.peripheral_active);
		print_result_line(line);
		return (1);
	}
	if ((strcmp(argv[0], "adapters") == 0 && argc == 1) ||
	    (strcmp(argv[0], "adapter-caps") == 0 && argc <= 2)) {
		if (ble_status(ctx, &status) < 0)
			goto error;
		int first = 0;
		int last = status.adapters;

		if (argc == 2) {
			char *end;
			long index = strtol(argv[1], &end, 0);

			if (*argv[1] == '\0' || *end != '\0' || index < 0 ||
			    index >= status.adapters) {
				warnx("invalid adapter index: %s", argv[1]);
				return (-1);
			}
			first = (int)index;
			last = first + 1;
		}
		for (int i = first; i < last; i++) {
			if (ble_adapter_caps(ctx, i, &caps) < 0)
				goto error;
			ble_addr_str(&caps.addr, addr);
			snprintf(line, sizeof(line),
			    "index=%d name=%s addr=%s powered=%u le_features=%#jx",
			    caps.index, caps.name, addr, caps.powered,
			    (uintmax_t)caps.le_features);
			print_result_line(line);
		}
		return (1);
	}

	if ((strcmp(argv[0], "list") == 0 || strcmp(argv[0], "conninfo") == 0 ||
	    strcmp(argv[0], "connparams") == 0 || strcmp(argv[0], "phy") == 0) &&
	    (argc == 1 || (argc == 2 && strcmp(argv[0], "phy") != 0))) {
		if (argc == 2) {
			if (ble_addr_parse(argv[1], 0, &filter) != 0) {
				warnx("invalid address: %s", argv[1]);
				return (-1);
			}
			have_filter = true;
		}
		count = ble_connections(ctx, conns, 32);
		if (count < 0)
			goto error;
		for (int i = 0; i < count; i++) {
			if (have_filter && memcmp(filter.addr, conns[i].addr.addr, 6) != 0)
				continue;
			ble_addr_str(&conns[i].addr, addr);
			if (strcmp(argv[0], "phy") == 0)
				snprintf(line, sizeof(line), "%s %s", addr,
				    conns[i].phy_valid ? (conns[i].tx_phy == conns[i].rx_phy ?
				    conns[i].tx_phy == 2 ? "tx=2M rx=2M" :
				    conns[i].tx_phy == 3 ? "tx=Coded rx=Coded" :
				    "tx=1M rx=1M" : "phy=asymmetric") : "phy=unknown");
			else if (strcmp(argv[0], "connparams") == 0)
				snprintf(line, sizeof(line),
				    "%s interval=%u.%02ums latency=%u timeout=%ums", addr,
				    conns[i].interval * 125 / 100,
				    conns[i].interval * 125 % 100, conns[i].latency,
				    conns[i].supervision_timeout * 10);
			else
				snprintf(line, sizeof(line),
				    "%s state=%u handle=%04x role=%s mtu=%u encrypted=%u "
				    "authenticated=%u key_size=%u name=%s", addr,
				    conns[i].state, conns[i].handle,
				    conns[i].role ? "peripheral" : "central", conns[i].mtu,
				    conns[i].encrypted, conns[i].authenticated,
				    conns[i].key_size, conns[i].name);
			print_result_line(line);
		}
		return (1);
	}
	if (strcmp(argv[0], "bonds") == 0 && argc == 1) {
		count = ble_bond_list(ctx, bonds, BLE_MAX_BONDS);
		if (count < 0)
			goto error;
		for (int i = 0; i < count; i++) {
			ble_addr_str(&bonds[i].addr, addr);
			snprintf(line, sizeof(line),
			    "%s %s ltk=%u irk=%u sc=%u lk=%u csrk=%u name=%s", addr,
			    bonds[i].addr.addr_type ? "random" : "public",
			    bonds[i].has_ltk, bonds[i].has_irk, bonds[i].is_sc,
			    bonds[i].has_link_key, bonds[i].has_csrk, bonds[i].name);
			print_result_line(line);
		}
		return (1);
	}
	if (strcmp(argv[0], "resolv") == 0 && argc == 2 &&
	    strcmp(argv[1], "list") == 0) {
		count = ble_resolv_entries(ctx, entries, BLE_MAX_BONDS);
		if (count < 0)
			goto error;
		for (int i = 0; i < count; i++) {
			ble_addr_str(&entries[i].addr, addr);
			snprintf(line, sizeof(line), "%s type=%s in_list=%u", addr,
			    entries[i].addr.addr_type ? "random" : "public",
			    entries[i].in_controller);
			print_result_line(line);
		}
		return (1);
	}
	return (0);
error:
	warnx("%s", ble_strerror(ctx));
	print_error_hint(ble_errno(ctx));
	return (-1);
}

static void mon_notify_cb(const ble_addr_t *, uint16_t, const uint8_t *,
    uint16_t, void *);

/*
 * Finding 34: fire-and-forget operations (write/disconnect/pair/unbond/rekey/
 * advertise/...) register a correlated request but return before its OP_REPLY
 * arrives, so a one-shot process would exit 0 even when the daemon rejected the
 * operation.  Pump ble_process() until every pending operation has resolved,
 * then report the last error the reply carried.  No-op when nothing is pending
 * (e.g. commands that already used a synchronous libble call).
 */
static int
drain_pending(ble_ctx_t *ctx)
{
	struct pollfd pfd = { .fd = ble_fd(ctx), .events = POLLIN };

	while (ble_pending_count(ctx) > 0 && !got_sigint) {
		if (poll(&pfd, 1, 5000) <= 0) {
			warnx("operation timed out");
			return (-1);
		}
		if ((pfd.revents & POLLIN) != 0 && ble_process(ctx) < 0)
			return (-1);
		if ((pfd.revents & (POLLERR | POLLHUP)) != 0)
			return (-1);
	}
	return (ble_errno(ctx) == BLE_ERR_NONE ? 0 : -1);
}

/*
 * Finding 34: in one-shot mode a bare `subscribe` would arm a subscription and
 * immediately tear it down at process exit — a guaranteed no-op.  After the
 * subscribe is acknowledged, stay alive and print notifications until the user
 * interrupts, so the command actually delivers data.
 */
static int
subscribe_watch(ble_ctx_t *ctx)
{
	struct pollfd pfd = { .fd = ble_fd(ctx), .events = POLLIN };

	if (!json_mode) {
		printf("Subscribed; waiting for notifications (Ctrl-C to stop)...\n");
		fflush(stdout);
	}
	while (!got_sigint) {
		int rv = poll(&pfd, 1, -1);

		if (rv < 0 && errno == EINTR)
			continue;
		if (rv < 0 || (pfd.revents & (POLLERR | POLLHUP)) != 0)
			return (-1);
		if ((pfd.revents & POLLIN) != 0 && ble_process(ctx) < 0)
			return (-1);
	}
	return (1);
}

/* Return 1 when handled, 0 when unknown, and -1 on invalid input/failure. */
static int
handle_typed_command(ble_ctx_t *ctx, int argc, char **argv)
{
	ble_addr_t addr;
	struct typed_wait wait = { 0 };
	uint8_t value[512];
	uint16_t value_len;
	uint32_t a, b, c, d;
	bool enabled;
	int rc;

	if (strcmp(argv[0], "scan") == 0 && argc == 1) {
		struct pollfd pfd = { .fd = ble_fd(ctx), .events = POLLIN };

		if (ble_scan(ctx, typed_scan_cb, NULL) < 0)
			goto result_error;
		while (!got_sigint) {
			int rv = poll(&pfd, 1, -1);

			if (rv < 0 && errno == EINTR)
				continue;
			if (rv <= 0 || (pfd.revents & (POLLERR | POLLHUP)) != 0 ||
			    ((pfd.revents & POLLIN) != 0 && ble_process(ctx) < 0))
				goto result_error;
		}
		return (1);
	}
	if (strcmp(argv[0], "connect") == 0 && (argc == 2 || argc == 3)) {
		uint8_t type = argc == 3 && strcmp(argv[2], "random") == 0 ? 1 : 0;

		if (argc == 3 && strcmp(argv[2], "public") != 0 && type == 0)
			goto usage;
		if (ble_addr_parse(argv[1], type, &addr) != 0)
			goto usage;
		rc = ble_connect(ctx, &addr, typed_connect_cb, &wait);
		if (rc == 0)
			rc = wait_typed_result(ctx, &wait);
		goto result;
	}
	if (strcmp(argv[0], "connect-name") == 0 && argc >= 2) {
		char name[64];

		if (join_args(name, sizeof(name), argc, argv, 1) != 0)
			goto usage;
		rc = ble_connect_name(ctx, 0, name, typed_connect_cb, &wait);
		if (rc == 0)
			rc = wait_typed_result(ctx, &wait);
		goto result;
	}
	if ((strcmp(argv[0], "disconnect") == 0 ||
	    strcmp(argv[0], "pair") == 0 || strcmp(argv[0], "unbond") == 0 ||
	    strcmp(argv[0], "rekey") == 0) && argc == 2) {
		if (ble_addr_parse(argv[1], 0, &addr) != 0)
			goto usage;
		if (strcmp(argv[0], "disconnect") == 0)
			rc = ble_disconnect(ctx, &addr);
		else if (strcmp(argv[0], "pair") == 0)
			rc = ble_pair(ctx, &addr);
		else if (strcmp(argv[0], "unbond") == 0)
			rc = ble_unbond(ctx, &addr);
		else
			rc = ble_rekey(ctx, &addr);
		goto result;
	}
	if (strcmp(argv[0], "discover") == 0 && argc == 2) {
		if (ble_addr_parse(argv[1], 0, &addr) != 0)
			goto usage;
		rc = ble_discover(ctx, &addr, typed_discover_cb, &wait);
		if (rc == 0)
			rc = wait_typed_result(ctx, &wait);
		goto result;
	}
	if (strcmp(argv[0], "read") == 0 && argc == 3) {
		if (ble_addr_parse(argv[1], 0, &addr) != 0 ||
		    parse_u32(argv[2], 1, UINT16_MAX, &a) != 0)
			goto usage;
		rc = ble_read(ctx, &addr, (uint16_t)a, typed_read_cb, &wait);
		if (rc == 0)
			rc = wait_typed_result(ctx, &wait);
		goto result;
	}
	if ((strcmp(argv[0], "write") == 0 ||
	    strcmp(argv[0], "write-cmd") == 0) && argc == 4) {
		if (ble_addr_parse(argv[1], 0, &addr) != 0 ||
		    parse_u32(argv[2], 1, UINT16_MAX, &a) != 0 ||
		    parse_hex_value(argv[3], value, sizeof(value), &value_len) != 0)
			goto usage;
		rc = strcmp(argv[0], "write") == 0 ?
		    ble_write(ctx, &addr, (uint16_t)a, value, value_len) :
		    ble_write_no_response(ctx, &addr, (uint16_t)a, value, value_len);
		goto result;
	}
	if ((strcmp(argv[0], "subscribe") == 0 ||
	    strcmp(argv[0], "unsubscribe") == 0) && argc == 3) {
		if (ble_addr_parse(argv[1], 0, &addr) != 0 ||
		    parse_u32(argv[2], 1, UINT16_MAX, &a) != 0)
			goto usage;
		if (strcmp(argv[0], "unsubscribe") == 0) {
			rc = ble_unsubscribe(ctx, &addr, (uint16_t)a);
			goto result;
		}
		rc = ble_subscribe(ctx, &addr, (uint16_t)a, mon_notify_cb, NULL);
		if (rc == 0)
			rc = drain_pending(ctx);
		if (rc < 0)
			goto result;
		/*
		 * Finding 34: keep a one-shot subscribe alive so notifications
		 * are actually delivered instead of being torn down at exit.
		 * Interactive mode returns immediately; its own loop pumps
		 * events and the subscription persists for the session.
		 */
		if (!interactive_session)
			return (subscribe_watch(ctx));
		return (1);
	}
	if (strcmp(argv[0], "set-value") == 0 && argc == 3) {
		if (parse_u32(argv[1], 1, UINT16_MAX, &a) != 0 ||
		    parse_hex_value(argv[2], value, sizeof(value), &value_len) != 0)
			goto usage;
		rc = ble_set_value(ctx, (uint16_t)a, value, value_len);
		goto result;
	}
	if (strcmp(argv[0], "add-service") == 0 && argc == 2) {
		ble_uuid_t uuid;
		uint16_t handle = 0;

		if (parse_uuid16(argv[1], &uuid) != 0)
			goto usage;
		rc = ble_add_service(ctx, &uuid, &handle);
		if (rc == 0)
			rc = wait_typed_handle(ctx, &handle);
		if (rc == 0)
			printf("service handle=0x%04x\n", handle);
		goto result;
	}
	if (strcmp(argv[0], "add-char") == 0 && (argc == 5 || argc == 6)) {
		static const char *const prop_names[] = { "broadcast", "read",
		    "write_no_rsp", "write", "notify", "indicate",
		    "auth_signed_write", "extended" };
		static const uint8_t prop_bits[] = { BLE_PROP_BROADCAST, BLE_PROP_READ,
		    BLE_PROP_WRITE_NO_RSP, BLE_PROP_WRITE, BLE_PROP_NOTIFY,
		    BLE_PROP_INDICATE, BLE_PROP_AUTH_SIGNED_WRITE, BLE_PROP_EXTENDED };
		static const char *const perm_names[] = { "read", "write",
		    "read_encrypt", "write_encrypt", "read_authen", "write_authen" };
		static const uint8_t perm_bits[] = { BLE_PERM_READ, BLE_PERM_WRITE,
		    BLE_PERM_READ_ENCRYPT, BLE_PERM_WRITE_ENCRYPT,
		    BLE_PERM_READ_AUTHEN, BLE_PERM_WRITE_AUTHEN };
		ble_uuid_t uuid;
		uint16_t handle = 0;
		uint8_t props, perms;

		value_len = 0;
		if (parse_u32(argv[1], 1, UINT16_MAX, &a) != 0 ||
		    parse_uuid16(argv[2], &uuid) != 0 ||
		    parse_name_mask(argv[3], prop_names, prop_bits,
		    sizeof(prop_names) / sizeof(prop_names[0]), &props) != 0 ||
		    parse_name_mask(argv[4], perm_names, perm_bits,
		    sizeof(perm_names) / sizeof(perm_names[0]), &perms) != 0 ||
		    (argc == 6 && parse_hex_value(argv[5], value, sizeof(value),
		    &value_len) != 0))
			goto usage;
		rc = ble_add_characteristic(ctx, (uint16_t)a, &uuid, props, perms,
		    value_len != 0 ? value : NULL, value_len, &handle);
		if (rc == 0)
			rc = wait_typed_handle(ctx, &handle);
		if (rc == 0)
			printf("characteristic handle=0x%04x\n", handle);
		goto result;
	}
	if ((strcmp(argv[0], "gatt-begin") == 0 ||
	    strcmp(argv[0], "gatt-commit") == 0 ||
	    strcmp(argv[0], "gatt-rollback") == 0) && argc == 1) {
		rc = strcmp(argv[0], "gatt-begin") == 0 ? ble_gatt_begin(ctx) :
		    strcmp(argv[0], "gatt-commit") == 0 ? ble_gatt_commit(ctx) :
		    ble_gatt_rollback(ctx);
		goto result;
	}
	if (strcmp(argv[0], "remove-service") == 0 && argc == 2) {
		if (parse_u32(argv[1], 1, UINT16_MAX, &a) != 0)
			goto usage;
		rc = ble_remove_service(ctx, (uint16_t)a);
		goto result;
	}
	if ((strcmp(argv[0], "adv-data") == 0 ||
	    strcmp(argv[0], "scan-resp") == 0) && argc == 2) {
		if (parse_hex_value(argv[1], value, 31, &value_len) != 0)
			goto usage;
		rc = strcmp(argv[0], "adv-data") == 0 ?
		    ble_set_adv_data(ctx, value, value_len) :
		    ble_set_scan_response(ctx, value, value_len);
		goto result;
	}
	if ((strcmp(argv[0], "advertise") == 0 ||
	    strcmp(argv[0], "pairable") == 0 ||
	    strcmp(argv[0], "privacy") == 0) && argc == 2) {
		if (parse_switch(argv[1], &enabled) != 0)
			goto usage;
		if (strcmp(argv[0], "advertise") == 0)
			rc = ble_advertise(ctx, enabled);
		else if (strcmp(argv[0], "pairable") == 0)
			rc = ble_set_pairable(ctx, enabled);
		else
			rc = ble_set_privacy(ctx, enabled);
		goto result;
	}
	if (strcmp(argv[0], "power") == 0 && (argc == 2 || argc == 3)) {
		int index = -1;

		if (parse_switch(argv[1], &enabled) != 0)
			goto usage;
		if (argc == 3) {
			const char *text = strncmp(argv[2], "adapter=", 8) == 0 ?
			    argv[2] + 8 : argv[2];
			if (parse_u32(text, 0, UINT16_MAX, &a) != 0)
				goto usage;
			index = (int)a;
		}
		rc = ble_adapter_power(ctx, index, enabled);
		goto result;
	}
	if (strcmp(argv[0], "set-mtu") == 0 && argc == 2) {
		if (parse_u32(argv[1], 23, 517, &a) != 0)
			goto usage;
		rc = ble_set_preferred_mtu(ctx, (uint16_t)a);
		goto result;
	}
	if (strcmp(argv[0], "set-name") == 0 && argc >= 2) {
		char name[249];

		if (join_args(name, sizeof(name), argc, argv, 1) != 0)
			goto usage;
		rc = ble_set_name(ctx, name);
		goto result;
	}
	if (strcmp(argv[0], "discoverable") == 0 && argc >= 2 && argc <= 4) {
		unsigned timeout = 0;
		bool limited = false;

		if (parse_switch(argv[1], &enabled) != 0)
			goto usage;
		if (argc >= 3) {
			if (parse_u32(argv[2], 0, 3600, &a) != 0)
				goto usage;
			timeout = a;
		}
		if (argc == 4) {
			if (strcmp(argv[3], "limited") == 0)
				limited = true;
			else if (strcmp(argv[3], "general") != 0)
				goto usage;
		}
		rc = ble_set_discoverable(ctx, enabled, timeout, limited);
		goto result;
	}
	if (strcmp(argv[0], "bond-export") == 0 && argc == 2) {
		ble_bond_record_t *record;
		const uint8_t *data;
		size_t len;

		if (ble_addr_parse(argv[1], 0, &addr) != 0)
			goto usage;
		record = ble_bond_export(ctx, &addr);
		if (record == NULL)
			goto result_error;
		data = ble_bond_record_data(record, &len);
		for (size_t i = 0; i < len; i++)
			printf("%02X", data[i]);
		putchar('\n');
		ble_bond_record_free(record);
		return (1);
	}
	if (strcmp(argv[0], "connparams-update") == 0 && argc == 6) {
		if (ble_addr_parse(argv[1], 0, &addr) != 0 ||
		    parse_u32(argv[2], 0, UINT16_MAX, &a) != 0 ||
		    parse_u32(argv[3], 0, UINT16_MAX, &b) != 0 ||
		    parse_u32(argv[4], 0, UINT16_MAX, &c) != 0 ||
		    parse_u32(argv[5], 0, UINT16_MAX, &d) != 0)
			goto usage;
		rc = ble_conn_params_update(ctx, &addr, a, b, c, d);
		goto result;
	}
	if (strcmp(argv[0], "set-phy") == 0 && argc == 4) {
		if (ble_addr_parse(argv[1], 0, &addr) != 0 ||
		    parse_u32(argv[2], 0, 7, &a) != 0 ||
		    parse_u32(argv[3], 0, 7, &b) != 0)
			goto usage;
		rc = ble_set_phy(ctx, &addr, (uint8_t)a, (uint8_t)b);
		goto result;
	}
	if (strcmp(argv[0], "set-data-len") == 0 && argc == 4) {
		if (ble_addr_parse(argv[1], 0, &addr) != 0 ||
		    parse_u32(argv[2], 0x1b, 0xfb, &a) != 0 ||
		    parse_u32(argv[3], 0x148, 0x4290, &b) != 0)
			goto usage;
		rc = ble_set_data_length(ctx, &addr, (uint16_t)a, (uint16_t)b);
		goto result;
	}
	if (strcmp(argv[0], "passkey") == 0 && argc == 3) {
		if (ble_addr_parse(argv[1], 0, &addr) != 0 ||
		    parse_u32(argv[2], 0, 999999, &a) != 0)
			goto usage;
		rc = ble_passkey_reply(ctx, &addr, a);
		goto result;
	}
	if (strcmp(argv[0], "confirm") == 0 && argc == 3) {
		if (ble_addr_parse(argv[1], 0, &addr) != 0 ||
		    parse_switch(argv[2], &enabled) != 0)
			goto usage;
		rc = ble_numcmp_reply(ctx, &addr, enabled);
		goto result;
	}
	if ((strcmp(argv[0], "eatt-open") == 0 && argc == 3) ||
	    (strcmp(argv[0], "eatt-close") == 0 && argc == 2)) {
		if (ble_addr_parse(argv[1], 0, &addr) != 0)
			goto usage;
		if (argc == 3 && parse_u32(argv[2], 1, 5, &a) != 0)
			goto usage;
		rc = argc == 3 ? ble_eatt_open(ctx, &addr, a) :
		    ble_eatt_close(ctx, &addr);
		goto result;
	}
	/*
	 * Finding 134: LE path-loss reporting.  ble_path_loss_reporting() is
	 * fire-and-forget, so let the generic result path drain its OP_REPLY.
	 */
	if (strcmp(argv[0], "path-loss") == 0 && argc == 8) {
		uint32_t lo, lohys, hi, hihys, mintime;

		if (ble_addr_parse(argv[1], 0, &addr) != 0 ||
		    parse_u32(argv[2], 0, 0xff, &lo) != 0 ||
		    parse_u32(argv[3], 0, 0xff, &lohys) != 0 ||
		    parse_u32(argv[4], 0, 0xff, &hi) != 0 ||
		    parse_u32(argv[5], 0, 0xff, &hihys) != 0 ||
		    parse_u32(argv[6], 0, 0xffff, &mintime) != 0 ||
		    parse_switch(argv[7], &enabled) != 0)
			goto usage;
		rc = ble_path_loss_reporting(ctx, &addr, (uint8_t)lo,
		    (uint8_t)lohys, (uint8_t)hi, (uint8_t)hihys,
		    (uint16_t)mintime, enabled);
		goto result;
	}
	/*
	 * Finding 133: operator-facing extended advertising-set commands.  The
	 * daemon owns the set by handle; adv-set-create prints the handle a
	 * later invocation passes to params/data/enable/remove.  These libble
	 * calls are synchronous, so they surface the daemon result directly.
	 */
	if (strcmp(argv[0], "adv-set-create") == 0 && argc == 1) {
		ble_adv_set_t *set = NULL;

		rc = ble_adv_set_create(ctx, &set);
		if (rc == 0) {
			printf("adv-set handle=%u\n", ble_adv_set_handle(set));
			ble_adv_set_free(set);	/* keep the daemon set alive */
		}
		goto result;
	}
	if ((strcmp(argv[0], "adv-set-params") == 0 && (argc == 5 || argc == 7)) ||
	    (strcmp(argv[0], "adv-set-data") == 0 && argc == 3) ||
	    (strcmp(argv[0], "adv-set-enable") == 0 && argc == 3) ||
	    (strcmp(argv[0], "adv-set-remove") == 0 && argc == 2)) {
		ble_adv_set_t *set = NULL;

		if (parse_u32(argv[1], 1, 0xef, &a) != 0)
			goto usage;
		if (ble_adv_set_open(ctx, (uint8_t)a, &set) != 0) {
			rc = -1;
			goto result;
		}
		if (strcmp(argv[0], "adv-set-params") == 0) {
			uint32_t props, min, max, prim = 1, sec = 1;

			if (parse_u32(argv[2], 0, 0xffff, &props) != 0 ||
			    parse_u32(argv[3], 0x20, 0xffffff, &min) != 0 ||
			    parse_u32(argv[4], 0x20, 0xffffff, &max) != 0 ||
			    (argc == 7 &&
			    (parse_u32(argv[5], 1, 3, &prim) != 0 ||
			    parse_u32(argv[6], 1, 3, &sec) != 0))) {
				ble_adv_set_free(set);
				goto usage;
			}
			rc = ble_adv_set_params(set, (uint16_t)props, min, max,
			    (uint8_t)prim, (uint8_t)sec);
		} else if (strcmp(argv[0], "adv-set-data") == 0) {
			if (parse_hex_value(argv[2], value, 251, &value_len) != 0) {
				ble_adv_set_free(set);
				goto usage;
			}
			rc = ble_adv_set_data(set, value, (uint8_t)value_len);
		} else if (strcmp(argv[0], "adv-set-enable") == 0) {
			if (parse_switch(argv[2], &enabled) != 0) {
				ble_adv_set_free(set);
				goto usage;
			}
			rc = ble_adv_set_enable(set, enabled);
		} else {
			ble_adv_set_close(set);	/* removes the daemon set + frees */
			set = NULL;
			rc = ble_errno(ctx) == BLE_ERR_NONE ? 0 : -1;
		}
		if (set != NULL)
			ble_adv_set_free(set);
		goto result;
	}
	return (0);

usage:
	warnx("invalid arguments for '%s'", argv[0]);
	return (-1);
result:
	/*
	 * Finding 34: await the correlated OP_REPLY for fire-and-forget
	 * operations so a failed write/disconnect/pair/... reports the error
	 * instead of exiting 0.  drain_pending() is a no-op when the command
	 * already completed synchronously (nothing pending).
	 */
	if (rc == 0)
		rc = drain_pending(ctx);
	if (rc < 0) {
	result_error:
		warnx("%s", ble_strerror(ctx));
		print_error_hint(ble_errno(ctx));
		return (-1);
	}
	return (1);
}

/*
 * Print help text for interactive mode.
 */
static void
print_help(void)
{

	printf("Commands:\n");
	printf("  scan                        "
	    "Scan for BLE devices\n");
	printf("  list                        "
	    "List connected devices\n");
	printf("  status                      "
	    "Daemon status\n");
	printf("  adapters                    "
	    "List adapters\n");
	printf("  connect <addr> [type]       "
	    "Connect to device\n");
	printf("  connect-name <name>         "
	    "Scan and connect by name\n");
	printf("  disconnect <addr>           "
	    "Disconnect device\n");
	printf("  pair <addr>                 "
	    "Initiate pairing\n");
	printf("  bonds                       "
	    "List bonded devices\n");
	printf("  unbond <addr>               "
	    "Remove bond\n");
	printf("  discover <addr>             "
	    "Discover remote GATT services\n");
	printf("  read <addr> <handle>        "
	    "Read characteristic\n");
	printf("  write <addr> <handle> <hex> "
	    "Write characteristic\n");
	printf("  write-cmd <addr> <handle> <hex>\n"
	    "                              "
	    "Write without response\n");
	printf("  subscribe <addr> <handle>   "
	    "Subscribe to notifications\n");
	printf("  unsubscribe <addr> <handle> "
	    "Unsubscribe\n");
	printf("  set-value <handle> <hex>    "
	    "Update local attribute\n");
	printf("  add-service <uuid>          "
	    "Add GATT service\n");
	printf("  add-char <svc> <uuid> <props> <perms> [value]\n"
	    "                              "
	    "Add GATT characteristic\n");
	printf("  remove-service <handle>     "
	    "Remove GATT service\n");
	printf("  phy                         "
	    "Show PHY info\n");
	printf("  passkey <addr> <passkey>    "
	    "Reply to passkey request\n");
	printf("  confirm <addr> yes|no       "
	    "Reply to numeric comparison\n");
	printf("  path-loss <addr> <low> <low-hyst> <high> <high-hyst> "
	    "<min-time> on|off\n"
	    "                              "
	    "Configure LE path-loss reporting\n");
	printf("  adv-set-create              "
	    "Allocate an extended advertising set\n");
	printf("  adv-set-params <handle> <props-hex> <min> <max> "
	    "[primary secondary]\n"
	    "                              "
	    "Configure an advertising set\n");
	printf("  adv-set-data <handle> <hex> "
	    "Set advertising-set data\n");
	printf("  adv-set-enable <handle> on|off\n"
	    "                              "
	    "Enable/disable an advertising set\n");
	printf("  adv-set-remove <handle>     "
	    "Remove an advertising set\n");
	printf("  eatt-open <addr> <count>   Open daemon-owned EATT bearers\n");
	printf("  eatt-close <addr>          Close daemon-owned EATT bearers\n");
	printf("  bond-export                 "
	    "Export bond database\n");
	printf("  connparams [addr]           "
	    "Show connection parameters\n");
	printf("  connparams-update <addr> <min> <max> <latency> <timeout>\n"
	    "                              "
	    "Request LE connection update\n");
	printf("  set-phy <addr> <tx> <rx>    "
	    "Request LE Set PHY\n");
	printf("  set-data-len <addr> <octets> <time>\n"
	    "                              "
	    "Request LE Set Data Length\n");
	printf("  set-mtu <23-517>            "
	    "Set preferred ATT MTU\n");
	printf("  privacy on|off              "
	    "Toggle LE privacy\n");
	printf("  power on|off [adapter=N]    "
	    "Power an adapter\n");
	printf("  discoverable on [timeout] [general|limited] | off\n"
	    "                              "
	    "Set discoverable mode\n");
	printf("  pairable on|off             "
	    "Allow incoming pairing\n");
	printf("  set-name <name>             "
	    "Set GAP/device name\n");
	printf("  quit                        "
	    "Exit interactive mode\n");
}

/*
 * Interactive mode: read commands from stdin, send to daemon, print
 * responses.  Also monitors the socket for asynchronous EVENT lines.
 */
static int	handle_profile_cmd(ble_ctx_t *, int, char **);

static int
interactive_mode(ble_ctx_t *ctx)
{
	struct pollfd pfds[2];
	char inputbuf[SEND_BUF_SIZE];
	int ret = 0;

	interactive_session = true;
	printf("bluedctl> ");
	fflush(stdout);

	while (!got_sigint) {
		pfds[0].fd = STDIN_FILENO;
		pfds[0].events = POLLIN;
		pfds[1].fd = ble_fd(ctx);
		pfds[1].events = POLLIN;

		if (poll(pfds, 2, -1) < 0) {
			if (errno == EINTR)
				continue;
			warn("poll");
			return (1);
		}

		/* Data from daemon */
		if (pfds[1].revents & POLLIN) {
			if (ble_process(ctx) < 0) {
				warnx("daemon disconnected");
				return (1);
			}
		}

		if (pfds[1].revents & (POLLERR | POLLHUP)) {
			warnx("daemon disconnected");
			return (1);
		}

		/* Input from stdin */
		if (pfds[0].revents & POLLIN) {
			if (fgets(inputbuf, sizeof(inputbuf), stdin) == NULL) {
				printf("\n");
				return (ret);
			}

			inputbuf[strcspn(inputbuf, "\n")] = '\0';

			if (inputbuf[0] == '\0') {
				printf("bluedctl> ");
				fflush(stdout);
				continue;
			}

			if (strcmp(inputbuf, "quit") == 0 ||
			    strcmp(inputbuf, "exit") == 0)
				return (ret);

			if (strcmp(inputbuf, "help") == 0) {
				print_help();
				printf("bluedctl> ");
				fflush(stdout);
				continue;
			}

			/* Parse input into argc/argv and build command */
			{
				char *iargv[16];
				int iargc;
				char *p, *token;
				char cmdbuf[SEND_BUF_SIZE];

				strlcpy(cmdbuf, inputbuf, sizeof(cmdbuf));
				iargc = 0;
				p = cmdbuf;
				while ((token = strsep(&p, " \t")) != NULL) {
					if (*token == '\0')
						continue;
					if (iargc >= 16)
						break;
					iargv[iargc++] = token;
				}

				if (iargc == 0) {
					printf("bluedctl> ");
					fflush(stdout);
					continue;
				}

				/* Try profile shortcuts first */
				{
					int pret;

					pret = handle_profile_cmd(ctx,
					    iargc, iargv);
					if (pret == 1) {
						printf("bluedctl> ");
						fflush(stdout);
						continue;
					}
					if (pret == -1) {
						ret = 1;
						printf("bluedctl> ");
						fflush(stdout);
						continue;
					}
				}
				{
					int qret = handle_structured_query(ctx, iargc, iargv);

					if (qret != 0) {
						if (qret < 0)
							ret = 1;
						printf("bluedctl> ");
						fflush(stdout);
						continue;
					}
				}
				{
					int tret = handle_typed_command(ctx, iargc, iargv);

					if (tret != 0) {
						if (tret < 0)
							ret = 1;
						printf("bluedctl> ");
						fflush(stdout);
						continue;
					}
				}

				warnx("unknown or unsupported command: %s", iargv[0]);
				ret = 1;
				printf("bluedctl> ");
				fflush(stdout);
			}
		}

		if (pfds[0].revents & POLLHUP) {
			printf("\n");
			return (ret);
		}
	}

	return (ret);
}

/* ================================================================
 * Client-side profile convenience commands.
 *
 * These chain generic GATT operations (DISCOVER + READ/SUBSCRIBE)
 * to provide friendly output for common profiles.  No profile
 * knowledge in the daemon — all parsing happens here.
 * ================================================================ */

/*
 * State for multi-step profile commands.
 * Step 1: DISCOVER — accumulate service/char handles
 * Step 2: READ/SUBSCRIBE — use the found handle
 */
struct profile_state {
	ble_ctx_t	*ctx;
	ble_addr_t	addr;
	uint16_t	target_svc;	/* service UUID to find */
	uint16_t	target_chr;	/* characteristic UUID to find */
	uint16_t	found_handle;	/* resolved handle */
	int		step;		/* 0=discover, 1=read */
	bool		done;
	int		ret;
};

static void
profile_discover_cb(const ble_addr_t *addr __unused,
    const ble_service_t *services __unused, int service_count __unused,
    const ble_characteristic_t *characteristics, int characteristic_count,
    void *arg)
{
	struct profile_state *ps = arg;

	for (int i = 0; i < characteristic_count; i++) {
		if (characteristics[i].uuid.uuid16 == ps->target_chr) {
			ps->found_handle = characteristics[i].handle;
			break;
		}
	}
	if (ps->found_handle == 0) {
		printf("ERROR: characteristic 0x%04X not found\n", ps->target_chr);
		ps->done = true;
		ps->ret = 1;
		return;
	}
	ps->step = 1;
}

static void
profile_read_cb(const ble_addr_t *addr, uint16_t handle, const uint8_t *value,
    uint16_t length, int error, void *arg)
{
	struct profile_state *ps = arg;
	char peer[18];

	ble_addr_str(addr, peer);
	printf("%s handle=0x%04x value=", peer, handle);
	for (uint16_t i = 0; i < length; i++)
		printf("%02x", value[i]);
	putchar('\n');
	fflush(stdout);
	ps->done = true;
	ps->ret = error != 0;
}

/*
 * Run a profile convenience command: DISCOVER + READ a specific char.
 * Returns 0 on success, 1 on error.
 */
static int
run_profile_read(ble_ctx_t *ctx, const char *addr, uint16_t svc_uuid,
    uint16_t chr_uuid)
{
	struct profile_state ps;
	struct pollfd pfd;

	memset(&ps, 0, sizeof(ps));
	ps.ctx = ctx;
	if (ble_addr_parse(addr, 0, &ps.addr) != 0)
		return (1);
	ps.target_svc = svc_uuid;
	ps.target_chr = chr_uuid;

	if (ble_discover(ctx, &ps.addr, profile_discover_cb, &ps) < 0)
		return (1);

	pfd.fd = ble_fd(ctx);
	pfd.events = POLLIN;

	/* Process discover response */
	while (!ps.done && poll(&pfd, 1, 30000) > 0) {
		if (ble_process(ctx) < 0) {
			warnx("connection closed");
			return (1);
		}
		/* After discovery completes, issue the typed read. */
		if (ps.step == 1 && !ps.done) {
			if (ble_read(ctx, &ps.addr, ps.found_handle,
			    profile_read_cb, &ps) < 0)
				return (1);
			ps.step = 2;
		}
	}

	return (ps.ret);
}

/*
 * Check if a command is a client-side profile convenience.
 * Returns 1 if handled, 0 if not.
 */
static int
handle_profile_cmd(ble_ctx_t *ctx, int argc, char **argv)
{

	if (strcmp(argv[0], "battery") == 0 && argc == 2)
		return (run_profile_read(ctx, argv[1],
		    BLE_SVC_BATTERY, BLE_CHR_BATTERY_LEVEL) == 0 ? 1 : -1);

	if (strcmp(argv[0], "devinfo") == 0 && argc == 2) {
		char discover[] = "discover";
		char *discover_argv[] = { discover, argv[1] };

		return (handle_typed_command(ctx, 2, discover_argv));
	}

	if (strcmp(argv[0], "heart-rate") == 0 && argc == 2)
		return (run_profile_read(ctx, argv[1],
		    BLE_SVC_HEART_RATE,
		    BLE_CHR_HEART_RATE_MEASUREMENT) == 0 ? 1 : -1);

	if (strcmp(argv[0], "thermometer") == 0 && argc == 2)
		return (run_profile_read(ctx, argv[1],
		    BLE_SVC_HEALTH_THERMOMETER,
		    BLE_CHR_TEMPERATURE_MEASUREMENT) == 0 ? 1 : -1);

	if (strcmp(argv[0], "time") == 0 && argc == 2)
		return (run_profile_read(ctx, argv[1],
		    BLE_SVC_CURRENT_TIME,
		    BLE_CHR_CURRENT_TIME) == 0 ? 1 : -1);

	if (strcmp(argv[0], "find") == 0 && argc == 2) {
		ble_addr_t peer;
		const uint8_t high_alert = 2;

		/* Alert level 2 = High Alert (makes device beep/flash) */
		printf("Note: 'find' writes alert level to handle 0x0001.\n"
		    "Use 'discover %s' first to find the correct "
		    "Immediate Alert handle.\n", argv[1]);
		if (ble_addr_parse(argv[1], 0, &peer) != 0 ||
		    ble_write(ctx, &peer, 1, &high_alert, 1) < 0)
			return (-1);
		return (1);
	}

	return (0);	/* not a profile command */
}

/* ================================================================
 * Event monitor mode and the keyboard-pairing workflow.
 * ================================================================ */

static void
mon_connected_cb(const ble_addr_t *addr, uint16_t handle, uint16_t mtu,
    void *arg __unused)
{
	char astr[18];

	ble_addr_str(addr, astr);
	if (json_mode)
		printf("{\"event\":\"connected\",\"addr\":\"%s\","
		    "\"handle\":%u,\"mtu\":%u}\n", astr, handle, mtu);
	else
		printf("CONNECTED    %s  handle=0x%04X mtu=%u\n",
		    astr, handle, mtu);
	fflush(stdout);
}

static void
mon_disconnected_cb(const ble_addr_t *addr, uint16_t reason, void *arg __unused)
{
	char astr[18];

	ble_addr_str(addr, astr);
	if (json_mode)
		printf("{\"event\":\"disconnected\",\"addr\":\"%s\","
		    "\"reason\":%u}\n", astr, reason);
	else
		printf("DISCONNECTED %s  reason=%u\n", astr, reason);
	fflush(stdout);
}

static void
mon_passkey_display_cb(const ble_addr_t *addr, uint32_t passkey,
    void *arg __unused)
{
	char astr[18];

	ble_addr_str(addr, astr);
	if (json_mode)
		printf("{\"event\":\"passkey_display\",\"addr\":\"%s\","
		    "\"passkey\":%06u}\n", astr, passkey);
	else
		printf("PASSKEY      %s  enter this on the device: %06u\n",
		    astr, passkey);
	fflush(stdout);
}

static void
mon_passkey_input_cb(const ble_addr_t *addr, void *arg __unused)
{
	char astr[18];

	ble_addr_str(addr, astr);
	if (json_mode)
		printf("{\"event\":\"passkey_input\",\"addr\":\"%s\"}\n", astr);
	else
		printf("PASSKEY      %s  device needs a passkey; reply with: "
		    "bluedctl passkey %s <passkey>\n", astr, astr);
	fflush(stdout);
}

static void
mon_numcmp_cb(const ble_addr_t *addr, uint32_t value, void *arg __unused)
{
	char astr[18];

	ble_addr_str(addr, astr);
	if (json_mode)
		printf("{\"event\":\"numcmp\",\"addr\":\"%s\",\"value\":%06u}\n",
		    astr, value);
	else
		printf("CONFIRM      %s  does the device show %06u? reply: "
		    "bluedctl confirm %s yes|no\n", astr, value, astr);
	fflush(stdout);
}

static void
mon_notify_cb(const ble_addr_t *addr, uint16_t handle, const uint8_t *value,
    uint16_t len, void *arg __unused)
{
	char astr[18];
	uint16_t i;

	ble_addr_str(addr, astr);
	if (json_mode) {
		printf("{\"event\":\"notify\",\"addr\":\"%s\",\"handle\":%u,"
		    "\"value\":\"", astr, handle);
		for (i = 0; i < len; i++)
			printf("%02X", value[i]);
		printf("\"}\n");
	} else {
		printf("NOTIFY       %s  handle=0x%04X value=", astr, handle);
		for (i = 0; i < len; i++)
			printf("%02X", value[i]);
		printf("\n");
	}
	fflush(stdout);
}

/*
 * Register the full set of push-event callbacks on a context.  Shared by
 * 'monitor' and the 'keyboard' workflow.
 */
static void
register_monitor_cbs(ble_ctx_t *ctx)
{

	ble_on_connected(ctx, mon_connected_cb, NULL);
	ble_on_disconnected(ctx, mon_disconnected_cb, NULL);
	ble_on_passkey_display(ctx, mon_passkey_display_cb, NULL);
	ble_on_passkey_input(ctx, mon_passkey_input_cb, NULL);
	ble_on_numcmp(ctx, mon_numcmp_cb, NULL);
}

/*
 * monitor: subscribe to push events and print them live until interrupted.
 * Shows CONNECTED/DISCONNECTED, pairing prompts, and (for handles the caller
 * has separately subscribed) NOTIFY events.
 */
static int
monitor_mode(ble_ctx_t *ctx)
{
	struct pollfd pfd;

	register_monitor_cbs(ctx);
	ble_subscribe(ctx, NULL, 0, mon_notify_cb, NULL);

	if (!json_mode) {
		printf("Monitoring blued events (Ctrl-C to stop)...\n");
		fflush(stdout);
	}

	pfd.fd = ble_fd(ctx);
	pfd.events = POLLIN;

	while (!got_sigint) {
		int rv = poll(&pfd, 1, -1);

		if (rv < 0) {
			if (errno == EINTR)
				continue;
			warn("poll");
			return (EX_ERR);
		}
		if (pfd.revents & (POLLERR | POLLHUP)) {
			warnx("daemon disconnected");
			return (EX_ERR);
		}
		if (pfd.revents & POLLIN) {
			if (ble_process(ctx) < 0) {
				warnx("daemon disconnected");
				return (EX_ERR);
			}
		}
	}
	return (EX_OK);
}

/*
 * "serve" demo: back one app-defined characteristic with live code.  On a peer
 * read the daemon asks us (EVENT READ) and we answer with a fixed value; on a
 * per-access authorization prompt (EVENT AUTHORIZE) we allow it.  Demonstrates
 * the dynamic-read + authorization round-trips end to end.
 */
struct serve_state {
	ble_ctx_t	*ctx;
	uint16_t	handle;
	uint8_t		value[256];
	uint16_t	vlen;
};

static int
parse_hex_bytes(const char *hex, uint8_t *out, size_t maxlen, uint16_t *outlen)
{
	size_t n = strlen(hex);
	size_t i;

	if (n % 2 != 0 || n / 2 > maxlen)
		return (-1);
	for (i = 0; i < n; i += 2) {
		unsigned int b;

		if (sscanf(hex + i, "%2x", &b) != 1)
			return (-1);
		out[i / 2] = (uint8_t)b;
	}
	*outlen = (uint16_t)(n / 2);
	return (0);
}

static void
serve_read_cb(uint16_t handle, uint16_t offset, void *arg)
{
	struct serve_state *ss = arg;

	printf("EVENT READ handle=0x%04X offset=%u -> replying %u bytes\n",
	    handle, offset, ss->vlen);
	fflush(stdout);
	if (handle == ss->handle)
		ble_gatt_read_reply(ss->ctx, handle, ss->value, ss->vlen);
	else
		ble_gatt_read_reject(ss->ctx, handle, 0x0E /* Unlikely */);
}

static void
serve_authorize_cb(const ble_addr_t *addr, uint16_t handle, bool is_write,
    void *arg)
{
	struct serve_state *ss = arg;
	char astr[18];

	ble_addr_str(addr, astr);
	printf("EVENT AUTHORIZE handle=0x%04X %s from %s -> allow\n",
	    handle, is_write ? "write" : "read", astr);
	fflush(stdout);
	ble_gatt_authorize_reply(ss->ctx, handle, true);
}

static int
serve_mode(ble_ctx_t *ctx, const char *handle_str, const char *hex)
{
	struct serve_state ss;
	struct pollfd pfd;
	unsigned int h;

	memset(&ss, 0, sizeof(ss));
	ss.ctx = ctx;
	if (sscanf(handle_str, "0x%x", &h) != 1 &&
	    sscanf(handle_str, "%x", &h) != 1) {
		warnx("serve: invalid handle");
		return (EX_USAGE);
	}
	ss.handle = (uint16_t)h;
	if (parse_hex_bytes(hex, ss.value, sizeof(ss.value), &ss.vlen) != 0) {
		warnx("serve: invalid hex value");
		return (EX_USAGE);
	}

	ble_on_read_request(ctx, serve_read_cb, &ss);
	ble_on_authorize(ctx, serve_authorize_cb, &ss);

	if (!json_mode) {
		printf("Serving handle 0x%04X (Ctrl-C to stop)...\n", ss.handle);
		fflush(stdout);
	}

	pfd.fd = ble_fd(ctx);
	pfd.events = POLLIN;
	while (!got_sigint) {
		int rv = poll(&pfd, 1, -1);

		if (rv < 0) {
			if (errno == EINTR)
				continue;
			warn("poll");
			return (EX_ERR);
		}
		if (pfd.revents & (POLLERR | POLLHUP)) {
			warnx("daemon disconnected");
			return (EX_ERR);
		}
		if ((pfd.revents & POLLIN) && ble_process(ctx) < 0) {
			warnx("daemon disconnected");
			return (EX_ERR);
		}
	}
	return (EX_OK);
}

/*
 * State for the keyboard-pairing workflow.
 */
struct kbd_state {
	ble_ctx_t	*ctx;
	char		addr[18];
	bool		connected;
	bool		done;
	int		ret;
};

static void
kbd_connected_cb(const ble_addr_t *addr, uint16_t handle, uint16_t mtu,
    void *arg)
{
	struct kbd_state *ks = arg;
	char astr[18];

	ble_addr_str(addr, astr);
	if (strcasecmp(astr, ks->addr) != 0)
		return;
	ks->connected = true;
	printf("Connected to %s (handle=0x%04X, MTU=%u).\n", astr, handle, mtu);
	printf("Keyboard is ready — it now types into this system via the "
	    "HID stack.\n");
	fflush(stdout);
	ks->done = true;
	ks->ret = EX_OK;
}

static void
kbd_disconnected_cb(const ble_addr_t *addr, uint16_t reason, void *arg)
{
	struct kbd_state *ks = arg;
	char astr[18];

	ble_addr_str(addr, astr);
	if (strcasecmp(astr, ks->addr) != 0)
		return;
	printf("Device %s disconnected (reason=%u) before pairing "
	    "completed.\n", astr, reason);
	fflush(stdout);
	ks->done = true;
	ks->ret = EX_ERR;
}

static void
kbd_passkey_display_cb(const ble_addr_t *addr, uint32_t passkey, void *arg)
{
	struct kbd_state *ks = arg;
	char astr[18];

	ble_addr_str(addr, astr);
	if (strcasecmp(astr, ks->addr) != 0)
		return;
	printf("\n>>> Type this passkey on the keyboard, then press Enter: "
	    "%06u <<<\n\n", passkey);
	fflush(stdout);
}

static void
kbd_passkey_input_cb(const ble_addr_t *addr, void *arg)
{
	struct kbd_state *ks = arg;
	char astr[18], line[32];
	unsigned long pk;

	ble_addr_str(addr, astr);
	if (strcasecmp(astr, ks->addr) != 0)
		return;
	printf("Enter the passkey shown on the keyboard: ");
	fflush(stdout);
	if (fgets(line, sizeof(line), stdin) == NULL) {
		ks->done = true;
		ks->ret = EX_ERR;
		return;
	}
	pk = strtoul(line, NULL, 10);
	if (ble_passkey_reply(ks->ctx, addr, (uint32_t)pk) < 0) {
		warnx("passkey reply failed: %s", ble_strerror(ks->ctx));
		ks->done = true;
		ks->ret = EX_ERR;
	}
}

static void
kbd_numcmp_cb(const ble_addr_t *addr, uint32_t value, void *arg)
{
	struct kbd_state *ks = arg;
	char astr[18], line[16];
	bool accept;

	ble_addr_str(addr, astr);
	if (strcasecmp(astr, ks->addr) != 0)
		return;
	printf("Does the keyboard show %06u? [y/n]: ", value);
	fflush(stdout);
	if (fgets(line, sizeof(line), stdin) == NULL) {
		ks->done = true;
		ks->ret = EX_ERR;
		return;
	}
	accept = (line[0] == 'y' || line[0] == 'Y');
	if (ble_numcmp_reply(ks->ctx, addr, accept) < 0) {
		warnx("confirm reply failed: %s", ble_strerror(ks->ctx));
		ks->done = true;
		ks->ret = EX_ERR;
	}
}

/*
 * Ack callback for the keyboard flow's CONNECT command.  The daemon replies
 * "OK CONNECT ... connecting" (an acknowledgement, not completion); a real
 * ERROR here means the connect could not even be started.
 */
static void
kbd_connect_ack_cb(const ble_addr_t *addr __unused, int error, void *arg)
{
	struct kbd_state *ks = arg;

	if (error != 0) {
		ks->done = true;
		ks->ret = EX_ERR;
	}
}

/*
 * keyboard <addr>: the "pair my keyboard and type" workflow in one command.
 * Connects, drives any passkey / numeric-comparison prompt interactively, and
 * reports when the keyboard is connected and paired (after which keystrokes
 * flow through the system HID stack).
 */
static int
keyboard_flow(ble_ctx_t *ctx, const char *addr_str)
{
	struct kbd_state ks;
	struct pollfd pfd;
	ble_addr_t addr;

	memset(&ks, 0, sizeof(ks));
	ks.ctx = ctx;
	strlcpy(ks.addr, addr_str, sizeof(ks.addr));
	ks.ret = EX_TIMEOUT;

	ble_on_connected(ctx, kbd_connected_cb, &ks);
	ble_on_disconnected(ctx, kbd_disconnected_cb, &ks);
	ble_on_passkey_display(ctx, kbd_passkey_display_cb, &ks);
	ble_on_passkey_input(ctx, kbd_passkey_input_cb, &ks);
	ble_on_numcmp(ctx, kbd_numcmp_cb, &ks);

	printf("Connecting to %s ...\n", ks.addr);
	fflush(stdout);
	if (ble_addr_parse(addr_str, 0, &addr) != 0) {
		warnx("keyboard: invalid address: %s", addr_str);
		return (EX_USAGE);
	}
	if (ble_connect(ctx, &addr, kbd_connect_ack_cb, &ks) < 0) {
		warnx("connect: %s", ble_strerror(ctx));
		print_error_hint(ble_errno(ctx));
		return (map_exit_code(ble_errno(ctx)));
	}

	pfd.fd = ble_fd(ctx);
	pfd.events = POLLIN;

	/* Up to 90s: enough for a link + interactive passkey entry. */
	while (!got_sigint && !ks.done) {
		int rv = poll(&pfd, 1, 90000);

		if (rv < 0) {
			if (errno == EINTR)
				continue;
			warn("poll");
			return (EX_ERR);
		}
		if (rv == 0) {
			warnx("timed out waiting for the keyboard to connect");
			return (EX_TIMEOUT);
		}
		if (pfd.revents & (POLLERR | POLLHUP)) {
			warnx("daemon disconnected");
			return (EX_ERR);
		}
		if (ble_process(ctx) < 0) {
			warnx("daemon disconnected");
			return (EX_ERR);
		}
	}
	return (ks.ret);
}

/*
 * Per-command usage table for 'bluedctl help [command]'.
 */
static const struct {
	const char	*name;
	const char	*args;
	const char	*desc;
} cmd_help[] = {
	/*
	 * Findings 38/142: this table lists ONLY commands bluedctl actually
	 * dispatches.  Entries with no handler (per-adv-*, past-*, iso-*,
	 * security, io-cap, oob-*, register-agent, rpa-timeout, loglevel,
	 * hogp-*, services, read-reply/reject, authorize, set-adv-params,
	 * adv-struct, resolv add/remove/clear) were removed, and the working
	 * eatt-* and profile shortcuts were added, to keep `help` consistent
	 * with dispatch.
	 */
	{ "scan",		"",			"Scan for BLE devices (~5s)" },
	{ "list",		"",			"List connected devices" },
	{ "status",		"",			"Daemon status summary" },
	{ "adapters",		"",			"List HCI adapters" },
	{ "adapter-caps",	"[index]",		"Show controller LE feature bitmap" },
	{ "connect",		"<addr> [public|random]", "Connect to a device (async; watch 'monitor')" },
	{ "connect-name",	"<name>",		"Scan for a device by name, then connect" },
	{ "disconnect",		"<addr>",		"Disconnect a device" },
	{ "pair",		"<addr>",		"Initiate pairing with a device" },
	{ "bonds",		"",			"List bonded devices" },
	{ "unbond",		"<addr>",		"Remove a bond" },
	{ "rekey",		"<addr>",		"Rotate a bonded peer's keys (re-pair)" },
	{ "discover",		"<addr>",		"Discover a device's GATT services" },
	{ "read",		"<addr> <handle>",	"Read a characteristic value" },
	{ "write",		"<addr> <handle> <hex>", "Write a characteristic (with response)" },
	{ "write-cmd",		"<addr> <handle> <hex>", "Write without response" },
	{ "subscribe",		"<addr> <handle>",	"Subscribe to notifications" },
	{ "unsubscribe",	"<addr> <handle>",	"Unsubscribe from notifications" },
	{ "set-value",		"<handle> <hex>",	"Set a local attribute value" },
	{ "add-service",	"<uuid>",		"Add a local GATT service" },
	{ "add-char",		"<svc> <uuid> <props> <perms> [value]", "Add a local characteristic" },
	{ "gatt-begin",		"",			"Begin an atomic GATT update" },
	{ "gatt-commit",	"",			"Commit an atomic GATT update" },
	{ "gatt-rollback",	"",			"Abort an atomic GATT update" },
	{ "serve",		"<handle> <hex>",	"Back a characteristic live (dynamic read + authorize)" },
	{ "remove-service",	"<handle>",		"Remove a local GATT service" },
	{ "phy",		"",			"Show per-connection PHY" },
	{ "passkey",		"<addr> <passkey>",	"Answer a passkey-input prompt" },
	{ "confirm",		"<addr> yes|no",	"Answer a numeric-comparison prompt" },
	{ "bond-export",	"<addr>",		"Export bond metadata" },
	{ "resolv",		"list",			"List the LE privacy resolving list" },
	{ "connparams",		"[addr]",		"Show connection parameters" },
	{ "connparams-update",	"<addr> <min> <max> <latency> <timeout>", "Request LE connection update" },
	{ "conninfo",		"[addr]",		"Show handle/role/MTU/encryption" },
	{ "advertise",		"on|off",		"Enable/disable advertising (peripheral mode)" },
	{ "adv-set-create",	"",			"Allocate an owned extended advertising set" },
	{ "adv-set-params",	"<handle> <props-hex> <min> <max> [primary secondary]", "Configure an owned advertising set" },
	{ "adv-set-data",	"<handle> <hex>",	"Set owned advertising-set data" },
	{ "adv-set-enable",	"<handle> on|off",	"Enable or disable an owned set" },
	{ "adv-set-remove",	"<handle>",		"Remove an owned advertising set" },
	{ "adv-data",		"<hex>",		"Set advertising data (<=31 bytes)" },
	{ "scan-resp",		"<hex>",		"Set scan-response data (<=31 bytes)" },
	{ "power",		"on|off [adapter=N]",	"Power an adapter" },
	{ "discoverable",	"on [timeout] [general|limited] | off", "Set discoverable mode" },
	{ "pairable",		"on|off",		"Allow or reject incoming pairing" },
	{ "set-name",		"<name>",		"Set GAP/device name" },
	{ "set-mtu",		"<23-517>",		"Set preferred ATT MTU" },
	{ "privacy",		"on|off",		"Toggle LE privacy/RPA use" },
	{ "set-phy",		"<addr> <tx-mask> <rx-mask>", "Request LE Set PHY" },
	{ "set-data-len",	"<addr> <octets> <time>", "Request LE Set Data Length" },
	{ "path-loss", "<addr> <low> <low-hyst> <high> <high-hyst> <min-time> <on|off>", "Configure LE path-loss reporting" },
	{ "eatt-open",		"<addr> <count>",	"Open daemon-owned EATT bearers" },
	{ "eatt-close",		"<addr>",		"Close daemon-owned EATT bearers" },
	{ "battery",		"<addr>",		"Read the Battery Level characteristic" },
	{ "devinfo",		"<addr>",		"Discover the Device Information service" },
	{ "heart-rate",		"<addr>",		"Read the Heart Rate Measurement" },
	{ "thermometer",	"<addr>",		"Read the Temperature Measurement" },
	{ "time",		"<addr>",		"Read the Current Time characteristic" },
	{ "find",		"<addr>",		"Write Immediate Alert (find device)" },
	{ "monitor",		"",			"Watch connect/disconnect/pairing/notify events" },
	{ "keyboard",		"<addr>",		"Pair a keyboard end-to-end (handles passkey)" },
	{ NULL, NULL, NULL },
};

static void
print_command_help(const char *cmd)
{
	size_t i;

	if (cmd == NULL) {
		printf("bluedctl commands (use 'bluedctl help <command>' for "
		    "details):\n");
		for (i = 0; cmd_help[i].name != NULL; i++)
			printf("  %-14s %s\n", cmd_help[i].name,
			    cmd_help[i].desc);
		printf("\nProfile shortcuts: battery, devinfo, heart-rate, "
		    "thermometer, time, find <addr>\n");
		return;
	}
	for (i = 0; cmd_help[i].name != NULL; i++) {
		if (strcmp(cmd, cmd_help[i].name) == 0) {
			printf("usage: bluedctl %s %s\n    %s\n",
			    cmd_help[i].name, cmd_help[i].args,
			    cmd_help[i].desc);
			return;
		}
	}
	printf("no such command: %s\n", cmd);
}

static void
usage(void)
{

	fprintf(stderr,
	    "usage: bluedctl [-ij] [-s socket] command [args ...]\n"
	    "       bluedctl [-j] [-s socket] monitor\n"
	    "       bluedctl [-s socket] keyboard <addr>\n"
	    "       bluedctl -i [-s socket]\n"
	    "       bluedctl help [command]\n"
	    "\n"
	    "Options:\n"
	    "  -i         interactive mode\n"
	    "  -j         machine-readable (JSON) output\n"
	    "  -s socket  control-socket path (default /var/run/blued.sock)\n"
	    "\n"
	    "Commands:\n"
	    "  scan                           Scan for BLE devices\n"
	    "  list                           List connected devices\n"
	    "  status                         Daemon status\n"
	    "  adapters                       List adapters\n"
	    "  connect <addr> [public|random] Connect to device\n"
	    "  connect-name <name>            Scan and connect by name\n"
	    "  disconnect <addr>              Disconnect device\n"
	    "  pair <addr>                    Initiate pairing\n"
	    "  bonds                          List bonded devices\n"
	    "  unbond <addr>                  Remove bond\n"
	    "  discover <addr>                Discover remote services\n"
	    "  read <addr> <handle>           Read characteristic\n"
	    "  write <addr> <handle> <hex>    Write characteristic\n"
	    "  write-cmd <addr> <handle> <hex>  Write without response\n"
	    "  subscribe <addr> <handle>      Subscribe to notifications\n"
	    "  unsubscribe <addr> <handle>    Unsubscribe\n"
	    "  set-value <handle> <hex>       Update local attribute\n"
	    "  add-service <uuid>             Add GATT service\n"
	    "  add-char <svc> <uuid> <props> <perms> [value]\n"
	    "                                 Add characteristic\n"
	    "  gatt-begin|gatt-commit|gatt-rollback\n"
	    "                                 Atomic GATT application update\n"
	    "  remove-service <handle>        Remove GATT service\n"
	    "  phy                            Show PHY info\n"
	    "  passkey <addr> <passkey>       Reply to passkey request\n"
	    "  confirm <addr> yes|no          Numeric comparison reply\n"
	    "  eatt-open <addr> <count>             Open EATT bearers\n"
	    "  eatt-close <addr>                    Close EATT bearers\n"
	    "  bond-export                    Export bond database\n"
	    "  connparams [addr]              Show connection parameters\n"
	    "  connparams-update <addr> <min> <max> <latency> <timeout>\n"
	    "                                 Request LE connection update\n"
	    "  conninfo [addr]                Show handle/role/MTU/encryption\n"
	    "  advertise on|off               Enable/disable advertising\n"
	    "  adv-data <hex>                 Set advertising data (<=31 bytes)\n"
	    "  scan-resp <hex>                Set scan-response data\n"
	    "  adv-set-create                 Allocate an extended advertising set\n"
	    "  adv-set-params <handle> <props-hex> <min> <max> [primary secondary]\n"
	    "                                 Configure an advertising set\n"
	    "  adv-set-data <handle> <hex>    Set advertising-set data\n"
	    "  adv-set-enable <handle> on|off Enable/disable an advertising set\n"
	    "  adv-set-remove <handle>        Remove an advertising set\n"
	    "  set-phy <addr> <tx> <rx>       Request LE Set PHY\n"
	    "  set-data-len <addr> <octets> <time>  Request LE Set Data Length\n"
	    "  path-loss <addr> <low> <low-hyst> <high> <high-hyst> <min-time> on|off\n"
	    "                                 Configure LE path-loss reporting\n"
	    "  set-mtu <23-517>               Set preferred ATT MTU\n"
	    "  privacy on|off                 Toggle LE privacy\n"
	    "  power on|off [adapter=N]       Power an adapter\n"
	    "  discoverable on [timeout] [general|limited] | off\n"
	    "                                 Set discoverable mode\n"
	    "  pairable on|off                Allow incoming pairing\n"
	    "  set-name <name>                Set GAP/device name\n"
	    "  monitor                        Watch connect/pair/notify events\n"
	    "  keyboard <addr>                Pair a keyboard end-to-end\n"
	    "\n"
	    "Keyboard-pairing workflow (\"pair my keyboard and type\"):\n"
	    "  1. bluedctl scan                 # find the keyboard's address\n"
	    "  2. bluedctl keyboard <addr>      # connect + answer the passkey\n"
	    "     (or drive it manually: connect, then in another terminal\n"
	    "      run 'bluedctl monitor' and 'bluedctl passkey <addr> <pk>')\n"
	    "  Once paired, the keyboard types into this system via the HID "
	    "stack.\n"
	    "\n"
	    "Profile shortcuts (client-side DISCOVER + READ):\n"
	    "  battery <addr>                 Read battery level\n"
	    "  devinfo <addr>                 Discover device information\n"
	    "  heart-rate <addr>              Read heart rate measurement\n"
	    "  thermometer <addr>             Read temperature\n"
	    "  time <addr>                    Read current time\n"
	    "  find <addr>                    Trigger immediate alert\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *sock_path;
	bool iflag;
	int ch, ret;
	ble_ctx_t *ctx;

	sock_path = NULL;
	iflag = false;

	while ((ch = getopt(argc, argv, "ijs:")) != -1) {
		switch (ch) {
		case 'i':
			iflag = true;
			break;
		case 'j':
			json_mode = true;
			break;
		case 's':
			sock_path = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (!iflag && argc < 1)
		usage();

	/*
	 * 'help [command]' needs no daemon connection.
	 */
	if (!iflag && argc >= 1 && strcmp(argv[0], "help") == 0) {
		print_command_help(argc >= 2 ? argv[1] : NULL);
		return (EX_OK);
	}

	/* Install SIGINT handler for clean shutdown */
	{
		struct sigaction sa;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = sigint_handler;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		sigaction(SIGINT, &sa, NULL);
	}

	/* Validate arg count for modes that need a daemon before connecting. */
	if (!iflag && strcmp(argv[0], "keyboard") == 0 &&
	    (argc != 2 || !looks_like_addr(argv[1]))) {
		warnx("usage: bluedctl keyboard <addr>");
		return (EX_USAGE);
	}

	ctx = ble_open(sock_path);
	if (ctx == NULL) {
		warn("connect: %s", sock_path ? sock_path : "/var/run/blued.sock");
		return (1);
	}

	/* Enter Capsicum sandbox — all fds are acquired */
	ctl_sandbox(ble_fd(ctx));

	if (iflag) {
		ret = interactive_mode(ctx);
		ble_close(ctx);
		return (ret);
	}

	/* Event monitor mode */
	if (argc == 1 && strcmp(argv[0], "monitor") == 0) {
		ret = monitor_mode(ctx);
		ble_close(ctx);
		return (ret);
	}

	/* Keyboard-pairing workflow */
	if (strcmp(argv[0], "keyboard") == 0) {
		ret = keyboard_flow(ctx, argv[1]);
		ble_close(ctx);
		return (ret);
	}

	/* Serve an app-backed characteristic (dynamic read + authorization) */
	if (strcmp(argv[0], "serve") == 0) {
		if (argc != 3) {
			warnx("usage: bluedctl serve <handle> <hex>");
			ble_close(ctx);
			return (EX_USAGE);
		}
		ret = serve_mode(ctx, argv[1], argv[2]);
		ble_close(ctx);
		return (ret);
	}

	/* Check for client-side profile convenience commands first */
	{
		int pret = handle_profile_cmd(ctx, argc, argv);
		if (pret != 0) {
			ble_close(ctx);
			return (pret < 0 ? 1 : 0);
		}
	}
	{
		int qret = handle_structured_query(ctx, argc, argv);

		if (qret != 0) {
			ret = qret < 0 ? map_exit_code(ble_errno(ctx)) : 0;
			ble_close(ctx);
			return (ret);
		}
	}
	{
		int tret = handle_typed_command(ctx, argc, argv);

		if (tret != 0) {
			ret = tret < 0 ? map_exit_code(ble_errno(ctx)) : 0;
			ble_close(ctx);
			return (ret);
		}
	}

	warnx("unknown or unsupported command: %s", argv[0]);
	ble_close(ctx);
	return (EX_USAGE);
}
