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
#include <unistd.h>

#include <ble.h>

#define SEND_BUF_SIZE		512

static volatile sig_atomic_t got_sigint;

static void
sigint_handler(int sig __unused)
{

	got_sigint = 1;
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
	(void)cap_ambient_limit(fd);
}

/*
 * Enter Capsicum sandbox after all file descriptors are acquired.
 */
static void
ctl_sandbox(int fd)
{
	cap_rights_t rights;

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
 * Map a user-facing command name and arguments to the daemon protocol string.
 *
 * Returns a malloc'd string with the protocol command, or NULL on error
 * (after printing a usage message).
 */
static char *
build_command(int argc, char **argv)
{
	char buf[SEND_BUF_SIZE];
	const char *cmd;

	if (argc < 1)
		return (NULL);

	cmd = argv[0];

	/* Commands with no arguments */
	if (strcmp(cmd, "scan") == 0 && argc == 1) {
		return (strdup("SCAN"));
	} else if (strcmp(cmd, "list") == 0 && argc == 1) {
		return (strdup("LIST"));
	} else if (strcmp(cmd, "status") == 0 && argc == 1) {
		return (strdup("STATUS"));
	} else if (strcmp(cmd, "adapters") == 0 && argc == 1) {
		return (strdup("ADAPTERS"));
	} else if (strcmp(cmd, "bonds") == 0 && argc == 1) {
		return (strdup("BONDS"));
	} else if (strcmp(cmd, "services") == 0 && argc == 1) {
		return (strdup("SERVICES"));
	} else if (strcmp(cmd, "phy") == 0 && argc == 1) {
		return (strdup("PHY"));
	} else if (strcmp(cmd, "loglevel") == 0 && argc == 1) {
		return (strdup("LOGLEVEL"));
	} else if (strcmp(cmd, "bond-export") == 0 && argc == 1) {
		return (strdup("BOND_EXPORT"));
	} else if (strcmp(cmd, "connparams") == 0 && argc == 1) {
		return (strdup("CONNPARAMS"));

	/* Commands with arguments */
	} else if (strcmp(cmd, "connect") == 0 && (argc == 2 || argc == 3)) {
		if (argc == 3)
			snprintf(buf, sizeof(buf), "CONNECT %s %s",
			    argv[1], argv[2]);
		else
			snprintf(buf, sizeof(buf), "CONNECT %s", argv[1]);
		return (strdup(buf));
	} else if (strcmp(cmd, "connect-name") == 0 && argc >= 2) {
		/* Join remaining args as the device name (may have spaces) */
		{
			int off = 0, a;
			for (a = 1; a < argc; a++) {
				int w = snprintf(buf + off,
				    sizeof(buf) - (size_t)off,
				    "%s%s", a > 1 ? " " : "", argv[a]);
				if (w > 0)
					off += w;
			}
		}
		{
			char proto[SEND_BUF_SIZE];
			snprintf(proto, sizeof(proto), "CONNECT_NAME %s", buf);
			return (strdup(proto));
		}
	} else if (strcmp(cmd, "disconnect") == 0 && argc == 2) {
		snprintf(buf, sizeof(buf), "DISCONNECT %s", argv[1]);
		return (strdup(buf));
	} else if (strcmp(cmd, "pair") == 0 && argc == 2) {
		snprintf(buf, sizeof(buf), "PAIR %s", argv[1]);
		return (strdup(buf));
	} else if (strcmp(cmd, "unbond") == 0 && argc == 2) {
		snprintf(buf, sizeof(buf), "UNBOND %s", argv[1]);
		return (strdup(buf));
	} else if (strcmp(cmd, "discover") == 0 && argc == 2) {
		snprintf(buf, sizeof(buf), "DISCOVER %s", argv[1]);
		return (strdup(buf));
	} else if (strcmp(cmd, "read") == 0 && argc == 3) {
		snprintf(buf, sizeof(buf), "READ %s %s", argv[1], argv[2]);
		return (strdup(buf));
	} else if (strcmp(cmd, "write") == 0 && argc == 4) {
		snprintf(buf, sizeof(buf), "WRITE %s %s %s",
		    argv[1], argv[2], argv[3]);
		return (strdup(buf));
	} else if (strcmp(cmd, "subscribe") == 0 && argc == 3) {
		snprintf(buf, sizeof(buf), "SUBSCRIBE %s %s",
		    argv[1], argv[2]);
		return (strdup(buf));
	} else if (strcmp(cmd, "unsubscribe") == 0 && argc == 3) {
		snprintf(buf, sizeof(buf), "UNSUBSCRIBE %s %s",
		    argv[1], argv[2]);
		return (strdup(buf));
	} else if (strcmp(cmd, "set-value") == 0 && argc == 3) {
		snprintf(buf, sizeof(buf), "SET_VALUE %s %s",
		    argv[1], argv[2]);
		return (strdup(buf));
	} else if (strcmp(cmd, "add-service") == 0 && argc == 2) {
		snprintf(buf, sizeof(buf), "ADD_SERVICE %s", argv[1]);
		return (strdup(buf));
	} else if (strcmp(cmd, "add-char") == 0 &&
	    (argc == 5 || argc == 6)) {
		if (argc == 6)
			snprintf(buf, sizeof(buf), "ADD_CHAR %s %s %s %s %s",
			    argv[1], argv[2], argv[3], argv[4], argv[5]);
		else
			snprintf(buf, sizeof(buf), "ADD_CHAR %s %s %s %s",
			    argv[1], argv[2], argv[3], argv[4]);
		return (strdup(buf));
	} else if (strcmp(cmd, "remove-service") == 0 && argc == 2) {
		snprintf(buf, sizeof(buf), "REMOVE_SERVICE %s", argv[1]);
		return (strdup(buf));
	} else if (strcmp(cmd, "loglevel") == 0 && argc == 2) {
		snprintf(buf, sizeof(buf), "LOGLEVEL %s", argv[1]);
		return (strdup(buf));
	} else if (strcmp(cmd, "hogp-read") == 0 && argc == 3) {
		snprintf(buf, sizeof(buf), "HOGP_READ %s %s",
		    argv[1], argv[2]);
		return (strdup(buf));
	} else if (strcmp(cmd, "hogp-write") == 0 && argc == 4) {
		snprintf(buf, sizeof(buf), "HOGP_WRITE %s %s %s",
		    argv[1], argv[2], argv[3]);
		return (strdup(buf));
	} else if (strcmp(cmd, "passkey") == 0 && argc == 3) {
		snprintf(buf, sizeof(buf), "PASSKEY_REPLY %s %s",
		    argv[1], argv[2]);
		return (strdup(buf));
	} else if (strcmp(cmd, "confirm") == 0 && argc == 3) {
		snprintf(buf, sizeof(buf), "NUMCMP_REPLY %s %s",
		    argv[1], argv[2]);
		return (strdup(buf));
	} else if (strcmp(cmd, "ecbfc-connect") == 0 && argc == 4) {
		snprintf(buf, sizeof(buf), "ECBFC_CONNECT %s %s %s",
		    argv[1], argv[2], argv[3]);
		return (strdup(buf));
	} else if (strcmp(cmd, "ecbfc-reconfig") == 0 && argc == 4) {
		snprintf(buf, sizeof(buf), "ECBFC_RECONFIG %s %s %s",
		    argv[1], argv[2], argv[3]);
		return (strdup(buf));
	} else if (strcmp(cmd, "connparams") == 0 && argc == 2) {
		snprintf(buf, sizeof(buf), "CONNPARAMS %s", argv[1]);
		return (strdup(buf));
	}

	/* If we get here, the command was not recognized or had wrong argc */
	if (strcmp(cmd, "scan") == 0 || strcmp(cmd, "list") == 0 ||
	    strcmp(cmd, "status") == 0 || strcmp(cmd, "adapters") == 0 ||
	    strcmp(cmd, "bonds") == 0 || strcmp(cmd, "services") == 0 ||
	    strcmp(cmd, "phy") == 0 || strcmp(cmd, "loglevel") == 0 ||
	    strcmp(cmd, "connect") == 0 || strcmp(cmd, "disconnect") == 0 ||
	    strcmp(cmd, "pair") == 0 || strcmp(cmd, "unbond") == 0 ||
	    strcmp(cmd, "discover") == 0 || strcmp(cmd, "read") == 0 ||
	    strcmp(cmd, "write") == 0 || strcmp(cmd, "subscribe") == 0 ||
	    strcmp(cmd, "unsubscribe") == 0 || strcmp(cmd, "set-value") == 0 ||
	    strcmp(cmd, "add-service") == 0 || strcmp(cmd, "add-char") == 0 ||
	    strcmp(cmd, "remove-service") == 0 ||
	    strcmp(cmd, "hogp-read") == 0 || strcmp(cmd, "hogp-write") == 0 ||
	    strcmp(cmd, "passkey") == 0 || strcmp(cmd, "confirm") == 0 ||
	    strcmp(cmd, "ecbfc-connect") == 0 ||
	    strcmp(cmd, "ecbfc-reconfig") == 0 ||
	    strcmp(cmd, "battery") == 0 || strcmp(cmd, "devinfo") == 0 ||
	    strcmp(cmd, "bond-export") == 0 ||
	    strcmp(cmd, "connparams") == 0 ||
	    strcmp(cmd, "connect-name") == 0) {
		warnx("wrong number of arguments for '%s'", cmd);
	} else {
		warnx("unknown command: %s", cmd);
	}

	return (NULL);
}

/*
 * Check if a command is a streaming command that should not wait for
 * a terminal response line.
 */
static bool
is_streaming_cmd(const char *cmd)
{

	return (strcmp(cmd, "subscribe") == 0);
}

/*
 * State shared between callbacks and the poll loop.
 */
struct ctl_state {
	int	ret;		/* exit status: 0=success, 1=error */
	bool	done;		/* command completed (terminal received) */
};

/*
 * Line callback for one-shot mode: print every line, track completion.
 */
static void
oneshot_line_cb(const char *line, bool terminal, int status,
    void *arg)
{
	struct ctl_state *st = arg;

	printf("%s\n", line);
	fflush(stdout);

	if (terminal) {
		st->done = true;
		if (status < 0)
			st->ret = 1;
	}
}

/*
 * Line callback for interactive mode responses.
 */
struct interactive_state {
	int	ret;
	bool	awaiting_response;
};

static void
interactive_resp_cb(const char *line, bool terminal, int status,
    void *arg)
{
	struct interactive_state *ist = arg;

	printf("%s\n", line);

	if (terminal) {
		ist->awaiting_response = false;
		if (status < 0)
			ist->ret = 1;
		printf("bluedctl> ");
	}
	fflush(stdout);
}

/*
 * Unsolicited line callback for interactive mode: async events
 * (EVENT NOTIFY, EVENT PASSKEY_*, EVENT NUMCMP_*) that arrive
 * when no command is pending.
 */
static void
interactive_event_cb(const char *line, bool terminal __unused,
    int status __unused, void *arg __unused)
{

	printf("%s\n", line);
	printf("bluedctl> ");
	fflush(stdout);
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
	    "Check bond status\n");
	printf("  bonds                       "
	    "List bonded devices\n");
	printf("  unbond <addr>               "
	    "Remove bond\n");
	printf("  services                    "
	    "List local GATT database\n");
	printf("  discover <addr>             "
	    "Discover remote GATT services\n");
	printf("  read <addr> <handle>        "
	    "Read characteristic\n");
	printf("  write <addr> <handle> <hex> "
	    "Write characteristic\n");
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
	printf("  loglevel [level]            "
	    "Get/set log level\n");
	printf("  phy                         "
	    "Show PHY info\n");
	printf("  hogp-read <addr> <id>       "
	    "Read HOGP Feature report\n");
	printf("  hogp-write <addr> <id> <hex>"
	    " Write HOGP Feature report\n");
	printf("  passkey <addr> <passkey>    "
	    "Reply to passkey request\n");
	printf("  confirm <addr> yes|no       "
	    "Reply to numeric comparison\n");
	printf("  ecbfc-connect <addr> <psm> <count>\n"
	    "                              "
	    "Open ECBFC channels\n");
	printf("  ecbfc-reconfig <addr> <mtu> <mps>\n"
	    "                              "
	    "Reconfigure ECBFC params\n");
	printf("  bond-export                 "
	    "Export bond database\n");
	printf("  connparams [addr]           "
	    "Show connection parameters\n");
	printf("  quit                        "
	    "Exit interactive mode\n");
}

/*
 * Interactive mode: read commands from stdin, send to daemon, print
 * responses.  Also monitors the socket for asynchronous EVENT lines.
 */
static int
interactive_mode(ble_ctx_t *ctx)
{
	struct pollfd pfds[2];
	struct interactive_state ist;
	char inputbuf[SEND_BUF_SIZE];

	ist.ret = 0;
	ist.awaiting_response = false;

	/* Register callback for async events when no command is pending */
	ble_on_line(ctx, interactive_event_cb, NULL);

	printf("bluedctl> ");
	fflush(stdout);

	while (!got_sigint) {
		pfds[0].fd = STDIN_FILENO;
		pfds[0].events = ist.awaiting_response ? 0 : POLLIN;
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
				return (ist.ret);
			}

			inputbuf[strcspn(inputbuf, "\n")] = '\0';

			if (inputbuf[0] == '\0') {
				printf("bluedctl> ");
				fflush(stdout);
				continue;
			}

			if (strcmp(inputbuf, "quit") == 0 ||
			    strcmp(inputbuf, "exit") == 0)
				return (ist.ret);

			if (strcmp(inputbuf, "help") == 0) {
				print_help();
				printf("bluedctl> ");
				fflush(stdout);
				continue;
			}

			/* Parse input into argc/argv and build command */
			{
				char *iargv[8];
				int iargc;
				char *p, *token;
				char cmdbuf[SEND_BUF_SIZE];
				char *proto;

				strlcpy(cmdbuf, inputbuf, sizeof(cmdbuf));
				iargc = 0;
				p = cmdbuf;
				while ((token = strsep(&p, " \t")) != NULL) {
					if (*token == '\0')
						continue;
					if (iargc >= 8)
						break;
					iargv[iargc++] = token;
				}

				if (iargc == 0) {
					printf("bluedctl> ");
					fflush(stdout);
					continue;
				}

				proto = build_command(iargc, iargv);
				if (proto == NULL) {
					printf("bluedctl> ");
					fflush(stdout);
					continue;
				}

				ist.awaiting_response = true;
				if (ble_command(ctx, proto, interactive_resp_cb,
				    &ist, 0) < 0) {
					free(proto);
					return (1);
				}
				free(proto);
			}
		}

		if (pfds[0].revents & POLLHUP) {
			printf("\n");
			return (ist.ret);
		}
	}

	return (ist.ret);
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
	char		addr[18];
	uint16_t	target_svc;	/* service UUID to find */
	uint16_t	target_chr;	/* characteristic UUID to find */
	uint16_t	found_handle;	/* resolved handle */
	int		step;		/* 0=discover, 1=read */
	bool		done;
	int		ret;
};

static void
profile_discover_cb(const char *line, bool terminal, int status, void *arg)
{
	struct profile_state *ps = arg;
	unsigned int uuid, handle;

	/* Parse char lines to find our target */
	if (sscanf(line, "    char uuid=0x%x handle=0x%x", &uuid, &handle) == 2) {
		if ((uint16_t)uuid == ps->target_chr)
			ps->found_handle = (uint16_t)handle;
	}

	if (terminal) {
		if (status < 0 || ps->found_handle == 0) {
			printf("ERROR: characteristic 0x%04X not found\n",
			    ps->target_chr);
			ps->done = true;
			ps->ret = 1;
			return;
		}
		/* Signal run_profile_read to issue the READ */
		ps->step = 1;
	}
}

static void
profile_read_cb(const char *line, bool terminal, int status, void *arg)
{
	struct profile_state *ps = arg;

	printf("%s\n", line);
	fflush(stdout);
	if (terminal) {
		ps->done = true;
		if (status < 0)
			ps->ret = 1;
	}
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
	char cmd[64];

	memset(&ps, 0, sizeof(ps));
	ps.ctx = ctx;
	strlcpy(ps.addr, addr, sizeof(ps.addr));
	ps.target_svc = svc_uuid;
	ps.target_chr = chr_uuid;

	/* Step 1: DISCOVER */
	snprintf(cmd, sizeof(cmd), "DISCOVER %s", addr);
	ble_command(ctx, cmd, profile_discover_cb, &ps, 0);

	pfd.fd = ble_fd(ctx);
	pfd.events = POLLIN;

	/* Process discover response */
	while (!ps.done && poll(&pfd, 1, 30000) > 0) {
		if (ble_process(ctx) < 0) {
			warnx("connection closed");
			return (1);
		}
		/* After discover completes, switch to read callback */
		if (ps.step == 1 && !ps.done) {
			snprintf(cmd, sizeof(cmd), "READ %s 0x%04X",
			    ps.addr, ps.found_handle);
			ble_command(ctx, cmd, profile_read_cb, &ps, 0);
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
		struct profile_state ps;
		struct pollfd pfd;
		char cmd[64];

		/*
		 * DEVINFO reads multiple characteristics.
		 * Use raw DISCOVER + multiple READs.
		 */
		printf("Discovering device information...\n");
		memset(&ps, 0, sizeof(ps));
		ps.ctx = ctx;
		strlcpy(ps.addr, argv[1], sizeof(ps.addr));

		snprintf(cmd, sizeof(cmd), "DISCOVER %s", argv[1]);
		ble_command(ctx, cmd, oneshot_line_cb, &ps, 0);

		pfd.fd = ble_fd(ctx);
		pfd.events = POLLIN;
		while (!ps.done && poll(&pfd, 1, 30000) > 0)
			if (ble_process(ctx) < 0)
				break;
		return (ps.ret == 0 ? 1 : -1);
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
		/* Write high alert to Immediate Alert Service */
		struct ctl_state st = { .ret = 0, .done = false };
		struct pollfd pfd;
		char cmd[64];

		/* Alert level 2 = High Alert (makes device beep/flash) */
		snprintf(cmd, sizeof(cmd), "WRITE %s 0x0001 02", argv[1]);
		printf("Note: 'find' writes alert level to handle 0x0001.\n"
		    "Use 'discover %s' first to find the correct "
		    "Immediate Alert handle.\n", argv[1]);
		ble_command(ctx, cmd, oneshot_line_cb, &st, 0);

		pfd.fd = ble_fd(ctx);
		pfd.events = POLLIN;
		while (!st.done && poll(&pfd, 1, 10000) > 0)
			if (ble_process(ctx) < 0)
				break;
		return (st.ret == 0 ? 1 : -1);
	}

	return (0);	/* not a profile command */
}

static void
usage(void)
{

	fprintf(stderr,
	    "usage: bluedctl [-i] [-s socket] command [args ...]\n"
	    "       bluedctl -i [-s socket]\n"
	    "\n"
	    "Commands:\n"
	    "  scan                           Scan for BLE devices\n"
	    "  list                           List connected devices\n"
	    "  status                         Daemon status\n"
	    "  adapters                       List adapters\n"
	    "  connect <addr> [public|random] Connect to device\n"
	    "  connect-name <name>            Scan and connect by name\n"
	    "  disconnect <addr>              Disconnect device\n"
	    "  pair <addr>                    Check bond status\n"
	    "  bonds                          List bonded devices\n"
	    "  unbond <addr>                  Remove bond\n"
	    "  services                       List local GATT database\n"
	    "  discover <addr>                Discover remote services\n"
	    "  read <addr> <handle>           Read characteristic\n"
	    "  write <addr> <handle> <hex>    Write characteristic\n"
	    "  subscribe <addr> <handle>      Subscribe to notifications\n"
	    "  unsubscribe <addr> <handle>    Unsubscribe\n"
	    "  set-value <handle> <hex>       Update local attribute\n"
	    "  add-service <uuid>             Add GATT service\n"
	    "  add-char <svc> <uuid> <props> <perms> [value]\n"
	    "                                 Add characteristic\n"
	    "  remove-service <handle>        Remove GATT service\n"
	    "  loglevel [level]               Get/set log level\n"
	    "  phy                            Show PHY info\n"
	    "  hogp-read <addr> <id>          Read HOGP Feature report\n"
	    "  hogp-write <addr> <id> <hex>   Write HOGP Feature report\n"
	    "  passkey <addr> <passkey>       Reply to passkey request\n"
	    "  confirm <addr> yes|no          Numeric comparison reply\n"
	    "  ecbfc-connect <addr> <psm> <count>  Open ECBFC channels\n"
	    "  ecbfc-reconfig <addr> <mtu> <mps>   Reconfig ECBFC params\n"
	    "  bond-export                    Export bond database\n"
	    "  connparams [addr]              Show connection parameters\n"
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
	char *proto;
	bool streaming;

	sock_path = NULL;
	iflag = false;

	while ((ch = getopt(argc, argv, "is:")) != -1) {
		switch (ch) {
		case 'i':
			iflag = true;
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

	/* Install SIGINT handler for clean shutdown */
	{
		struct sigaction sa;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = sigint_handler;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		sigaction(SIGINT, &sa, NULL);
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

	/* Check for client-side profile convenience commands first */
	{
		int pret = handle_profile_cmd(ctx, argc, argv);
		if (pret != 0) {
			ble_close(ctx);
			return (pret < 0 ? 1 : 0);
		}
	}

	/* One-shot mode */
	proto = build_command(argc, argv);
	if (proto == NULL) {
		ble_close(ctx);
		return (1);
	}

	streaming = is_streaming_cmd(argv[0]);

	{
		struct ctl_state st;
		struct pollfd pfd;

		st.ret = 0;
		st.done = false;

		if (ble_command(ctx, proto, oneshot_line_cb, &st,
		    streaming ? BLE_CMD_STREAMING : 0) < 0) {
			free(proto);
			ble_close(ctx);
			return (1);
		}
		free(proto);

		pfd.fd = ble_fd(ctx);
		pfd.events = POLLIN;

		while (!got_sigint && !st.done) {
			int rv;

			rv = poll(&pfd, 1, streaming ? 200 : 30000);
			if (rv < 0) {
				if (errno == EINTR)
					continue;
				warn("poll");
				ret = 1;
				break;
			}
			if (rv == 0) {
				if (streaming)
					continue;
				warnx("timeout waiting for response");
				ret = 1;
				break;
			}

			if (pfd.revents & (POLLERR | POLLHUP)) {
				if (!streaming)
					warnx("connection closed");
				break;
			}

			if (ble_process(ctx) < 0) {
				if (!streaming)
					warnx("connection closed");
				break;
			}
		}

		ret = st.ret;
	}

	ble_close(ctx);
	return (ret);
}
