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
 * ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DAMAGES WHATSOEVER ARISING OUT OF
 * THE USE OF THIS SOFTWARE.
 */

/*
 * meshctl - command-line client for the meshd(8) Bluetooth Mesh daemon.
 *
 * meshd serves a line-oriented control protocol on a UNIX-domain stream socket:
 * a whitespace-separated command line in, a single "OK ..."/"ERR ..." reply
 * line back.  meshctl connects to that socket, sends one command (one-shot) or
 * a stream of them (interactive, -i), prints each reply and maps ERR to a
 * non-zero exit status.  It carries no mesh logic of its own; the daemon owns
 * the node, the created network and the Config Client.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	MESHCTL_DEFAULT_SOCK	"/var/run/meshd.sock"
#define	MESHCTL_LINE_MAX	1024
#define	MESHCTL_REPLY_MAX	2048

/* One documented verb: name, argument sketch and a one-line description. */
struct verb {
	const char	*name;
	const char	*args;
	const char	*help;
};

/*
 * The verb surface mirrors meshd_ctl.c / meshd_cfg_client_verb.  meshctl does
 * not validate arguments (the daemon does and returns a usage ERR); this table
 * drives "meshctl help" and shell completion.
 */
static const struct verb verbs[] = {
	{ "status",		"",
	    "show node address, provisioning, SEQ/IV and counters" },
	{ "models",		"",
	    "show registered SIG models and their local commissioning state" },
	{ "app-register",	"<element> <model> [vendor]",
	    "register an app-owned model for inbound access events" },
	{ "app-unregister",	"<element> <model> [vendor]",
	    "unregister an app-owned model" },
	{ "app-events",	"[max]",
	    "drain queued inbound app access events" },
	{ "app-watch",	"<element> <model> [vendor]",
	    "register a model and print asynchronous app events" },
	{ "onoff",		"<dst> <0|1>",
	    "send a Generic OnOff Set to dst" },
	{ "level",		"<dst> <n>",
	    "send a Generic Level Set to dst" },
	{ "power-onoff",	"<dst> <0|1|2>",
	    "set Generic OnPowerUp (off/default/restore)" },
	{ "transition",	"<dst> <encoded-time>",
	    "set Generic Default Transition Time" },
	{ "power-level",	"<dst> <power>", "set Generic Power Actual" },
	{ "power-default",	"<dst> <power>", "set Generic Power Default" },
	{ "power-range",	"<dst> <min> <max>", "set Generic Power Range" },
	{ "battery-state",	"<level> <discharge> <charge> <flags>",
	    "update local Generic Battery telemetry" },
	{ "location-global", "<latitude> <longitude> <altitude>",
	    "update local Generic Location Global state" },
	{ "location-local", "<north> <east> <altitude> <floor> <uncertainty>",
	    "update local Generic Location Local state" },
	{ "sensor-set", "<property> <rawhex> [pos neg sampling period interval]",
	    "register or update local Sensor data" },
	{ "sensor-setting", "<property> <setting> <1|3> <rawhex>",
	    "register a Sensor setting" },
	{ "sensor-column", "<property> <keyhex> <rawhex>",
	    "register a Sensor series column" },
	{ "sensor-cadence", "<property> <divisor> <trigger> <down> <up> <min> <low> <high>",
	    "configure Sensor cadence" },
	{ "time-set", "<tai> <subsecond> <uncertainty> <authority> <delta> <zone>",
	    "set the local Mesh Time state" },
	{ "time-role", "<0..3>", "set the local Mesh Time Role" },
	{ "time-zone", "<offset> <change-tai>", "schedule a Time Zone change" },
	{ "time-delta", "<delta> <change-tai>", "schedule a TAI-UTC Delta change" },
	{ "scene-store", "<scene-number>", "store current bound states as a Scene" },
	{ "scene-recall", "<scene-number>", "recall a stored local Scene" },
	{ "scene-delete", "<scene-number>", "delete a local Scene" },
	{ "scheduler-set", "<index> <year> <months> <day> <hour> <minute> <second> <dow> <action> <transition> <scene>",
	    "set or clear a local Scheduler action (action 15 clears)" },
	{ "lightness-state", "<actual>", "set local Light Lightness Actual" },
	{ "lightness-default", "<value>", "set local Light Lightness Default" },
	{ "lightness-range", "<min> <max>", "set local Light Lightness Range" },
	{ "ctl-state", "<lightness> <temperature> <delta-uv>", "set local Light CTL state" },
	{ "ctl-range", "<min-temperature> <max-temperature>", "set local CTL Temperature Range" },
	{ "hsl-state", "<lightness> <hue> <saturation>", "set local Light HSL state" },
	{ "hsl-range", "<hue-min> <hue-max> <sat-min> <sat-max>", "set local HSL ranges" },
	{ "xyl-state", "<lightness> <x> <y>", "set local Light xyL state" },
	{ "xyl-range", "<x-min> <x-max> <y-min> <y-max>", "set local xyL ranges" },
	{ "lc-mode", "<0|1>", "set local Light LC Mode" },
	{ "lc-om", "<0|1>", "set local Light LC Occupancy Mode" },
	{ "lc-light-onoff", "<0|1>", "set local Light LC Light OnOff" },
	{ "lc-property", "<property> <rawhex>", "set a local Light LC property" },
	{ "ttl",		"<0..127>",
	    "set this node's default TTL" },
	{ "attention",		"<secs>",
	    "set the Health attention timer" },
	{ "provision-local",	"<addr> <iv>",
	    "self-provision this node (no OTA)" },
	{ "create-network",	"",
	    "mint a new network (NetKey/AppKey/IV, this node as Provisioner)" },
	{ "list-nodes",		"",
	    "list the network roster (address/element count)" },
	{ "features",		"",
	    "show local node feature/state properties" },
	{ "send",		"<dst> <appidx> <access-hex>",
	    "send a raw AppKey access payload" },
	{ "devkey-send",	"<dst> remote|local <netidx> <access-hex>",
	    "send a raw DevKey access payload" },
	{ "publish",		"<model> [vendor] <access-hex>",
	    "publish a raw access payload using configured publication" },
	{ "import-remote-node", "<primary> <count> <devkey-hex32>",
	    "import an externally provisioned remote node record" },
	{ "delete-remote-node", "<primary> <count>",
	    "delete a remote node record" },
	{ "provision-scan",	"[on|off|list]",
	    "scan for unprovisioned device beacons and list discovered UUIDs" },
	{ "provision",		"<uuid-hex32> [elements]",
	    "provision a remote device over the air into the network" },
	{ "provision-gatt",	"<addr> <uuid-hex32> [elements]",
	    "provision a connected remote device through PB-GATT" },
	{ "provision-status",	"",
	    "poll / commit an in-flight OTA provisioning" },
	{ "key-refresh",	"begin|advance|finish|status|network|network-status",
	    "operate Key Refresh on the primary subnet" },
	{ "friend",		"[on|off|status]",
	    "toggle the Friend role (serve a Low Power node over the bearer)" },
	{ "low-power",		"[on|off|status]",
	    "toggle the Low Power node role (befriend a neighbouring Friend)" },
	{ "reset",		"",
	    "clear this node's provisioning" },
	/* Config Client (cfg <sub-verb> <dst> ...). */
	{ "cfg comp-get",	"<dst> [page]",
	    "Config Composition Data Get" },
	{ "cfg appkey-add",	"<dst>",
	    "Config AppKey Add (primary AppKey)" },
	{ "cfg appkey-update",	"<dst>",
	    "Config AppKey Update" },
	{ "cfg appkey-delete",	"<dst>",
	    "Config AppKey Delete" },
	{ "cfg appkey-get",	"<dst> <netidx>",
	    "Config AppKey Get" },
	{ "cfg model-bind",	"<dst> <elem> <model> [company]",
	    "Config Model App Bind" },
	{ "cfg model-unbind",	"<dst> <elem> <model> [company]",
	    "Config Model App Unbind" },
	{ "cfg model-app-get",	"<dst> <elem> <model> [company]",
	    "Config Model App Get" },
	{ "cfg sub-add",	"<dst> <elem> <group> <model> [company]",
	    "Config Model Subscription Add" },
	{ "cfg sub-delete",	"<dst> <elem> <group> <model> [company]",
	    "Config Model Subscription Delete" },
	{ "cfg sub-overwrite",	"<dst> <elem> <group> <model> [company]",
	    "Config Model Subscription Overwrite" },
	{ "cfg sub-delete-all",	"<dst> <elem> <model> [company]",
	    "Config Model Subscription Delete All" },
	{ "cfg sub-va-add",	"<dst> <elem> <label-hex32> <model> [company]",
	    "Config Model Subscription Virtual Address Add" },
	{ "cfg sub-va-delete",	"<dst> <elem> <label-hex32> <model> [company]",
	    "Config Model Subscription Virtual Address Delete" },
	{ "cfg sub-va-overwrite", "<dst> <elem> <label-hex32> <model> [company]",
	    "Config Model Subscription Virtual Address Overwrite" },
	{ "cfg sub-get",	"<dst> <elem> <model> [company]",
	    "Config Model Subscription Get" },
	{ "cfg pub-set",	"<dst> <elem> <pubaddr> <ttl> <period> <rtx> <model> [company]",
	    "Config Model Publication Set" },
	{ "cfg pub-va-set",	"<dst> <elem> <label-hex32> <ttl> <period> <rtx> <model> [company]",
	    "Config Model Publication Virtual Address Set" },
	{ "cfg pub-get",	"<dst> <elem> <model> [company]",
	    "Config Model Publication Get" },
	{ "cfg netkey-add",	"<dst> <netidx> <key-hex32>",
	    "Config NetKey Add" },
	{ "cfg netkey-update",	"<dst> <netidx> <key-hex32>",
	    "Config NetKey Update" },
	{ "cfg netkey-delete",	"<dst> <netidx>",
	    "Config NetKey Delete" },
	{ "cfg kr-phase-get",	"<dst> <netidx>",
	    "Config Key Refresh Phase Get" },
	{ "cfg kr-phase-set",	"<dst> <netidx> <transition>",
	    "Config Key Refresh Phase Set" },
	{ "cfg beacon",		"<dst> [0|1]",
	    "Config Beacon Get/Set" },
	{ "cfg gatt-proxy",	"<dst> [0|1|2]",
	    "Config GATT Proxy Get/Set" },
	{ "cfg friend",		"<dst> [0|1|2]",
	    "Config Friend Get/Set" },
	{ "cfg ttl",		"<dst> [ttl]",
	    "Config Default TTL Get/Set" },
	{ "cfg relay",		"<dst> [relay retransmit]",
	    "Config Relay Get/Set" },
	{ "cfg nettransmit",	"<dst> [count intervalsteps]",
	    "Config Network Transmit Get/Set" },
	{ "cfg node-identity-get", "<dst> <netidx>",
	    "Config Node Identity Get" },
	{ "cfg node-identity-set", "<dst> <netidx> <identity>",
	    "Config Node Identity Set" },
	{ "cfg lpn-polltimeout-get", "<dst> <lpn-addr>",
	    "Config Low Power Node PollTimeout Get" },
	{ "cfg hb-pub-get",	"<dst>",
	    "Config Heartbeat Publication Get" },
	{ "cfg hb-pub-set",	"<dst> <hbdst> <countlog> <periodlog> <ttl> <netidx>",
	    "Config Heartbeat Publication Set" },
	{ "cfg hb-sub-get",	"<dst>",
	    "Config Heartbeat Subscription Get" },
	{ "cfg hb-sub-set",	"<dst> <src> <hbdst> <periodlog>",
	    "Config Heartbeat Subscription Set" },
	{ "cfg node-reset",	"<dst>",
	    "Config Node Reset" },
	/* Config Client - Mesh 1.1 node states. */
	{ "cfg sar-tx-get",	"<dst>",
	    "Config SAR Transmitter Get" },
	{ "cfg sar-tx-set",	"<dst> <segint> <ucount> <unoprog> <uintstep> <uintinc> <mcount> <mintstep>",
	    "Config SAR Transmitter Set (seven 4-bit fields)" },
	{ "cfg sar-rx-get",	"<dst>",
	    "Config SAR Receiver Get" },
	{ "cfg sar-rx-set",	"<dst> <segthresh> <ackdelayinc> <discard> <rxintstep> <ackretrans>",
	    "Config SAR Receiver Set" },
	{ "cfg priv-beacon-get", "<dst>",
	    "Config Private Beacon Get" },
	{ "cfg priv-beacon-set", "<dst> <0|1> [random-update-steps]",
	    "Config Private Beacon Set" },
	{ "cfg priv-gatt-proxy", "<dst> [0|1|2]",
	    "Config Private GATT Proxy Get/Set" },
	{ "cfg od-priv-proxy",	"<dst> [value]",
	    "Config On-Demand Private Proxy Get/Set" },
	{ "cfg priv-node-identity-get", "<dst> <netidx>",
	    "Config Private Node Identity Get" },
	{ "cfg priv-node-identity-set", "<dst> <netidx> <identity>",
	    "Config Private Node Identity Set" },
	{ "cfg lcd-get",	"<dst> <page> <offset>",
	    "Config Large Composition Data Get" },
	/* Directed Forwarding Configuration Client (df <sub-verb> <dst> ...). */
	{ "df get",		"<dst> [netidx]",
	    "Directed Control Get" },
	{ "df set",		"<dst> <on|off> [netidx]",
	    "Directed Control Set (directed forwarding + relay)" },
	{ "df control-set",	"<dst> <netidx> <fwd> <relay> <proxy> <proxydef> <friend>",
	    "Directed Control Set (all five flags)" },
	{ "df metric-get",	"<dst> [netidx]",
	    "Path Metric Get" },
	{ "df metric-set",	"<dst> <type> <lifetime> [netidx]",
	    "Path Metric Set" },
	{ "df lanes-get",	"<dst> [netidx]",
	    "Directed Wanted Lanes Get" },
	{ "df lanes-set",	"<dst> <lanes> [netidx]",
	    "Directed Wanted Lanes Set" },
	{ "df two-way-get",	"<dst> [netidx]",
	    "Two Way Path Get" },
	{ "df two-way-set",	"<dst> <0|1> [netidx]",
	    "Two Way Path Set" },
	{ "df echo-get",	"<dst> [netidx]",
	    "Path Echo Interval Get" },
	{ "df echo-set",	"<dst> <unicast> <multicast> [netidx]",
	    "Path Echo Interval Set" },
	{ "df net-transmit-get", "<dst>",
	    "Directed Network Transmit Get" },
	{ "df net-transmit-set", "<dst> <count> <steps>",
	    "Directed Network Transmit Set" },
	{ "df relay-retransmit-get", "<dst>",
	    "Directed Relay Retransmit Get" },
	{ "df relay-retransmit-set", "<dst> <count> <steps>",
	    "Directed Relay Retransmit Set" },
	{ "df discover",	"<target>",
	    "start a local Path Origin path discovery toward target" },
	{ "df discover-status",	"",
	    "show the local path-discovery FSM state" },
	/* Remote Provisioning Client (remote-prov <sub-verb> <dst> ...). */
	{ "remote-prov caps",	"<dst>",
	    "Remote Provisioning Scan Capabilities Get" },
	{ "remote-prov scan",	"<dst> [uuid-hex32] [limit] [timeout]",
	    "Remote Provisioning Scan Start" },
	{ "remote-prov scan-get", "<dst>",
	    "Remote Provisioning Scan Get" },
	{ "remote-prov scan-stop", "<dst>",
	    "Remote Provisioning Scan Stop" },
	{ "remote-prov link-get", "<dst>",
	    "Remote Provisioning Link Get" },
	{ "remote-prov link-open", "<dst> <uuid-hex32> [timeout]",
	    "Remote Provisioning Link Open (PB-Remote)" },
	{ "remote-prov provision", "<dst> <uuid-hex32> [timeout]",
	    "Remote Provisioning: open a PB-Remote link toward a device" },
	{ "remote-prov link-close", "<dst> [reason]",
	    "Remote Provisioning Link Close" },
	{ "remote-prov status",	"",
	    "show the Remote Provisioning client scan/link FSM state" },
	{ "remote-prov reports", "",
	    "list unsolicited Reports received from a Remote Provisioning Server" },
};

static void
usage(void)
{

	fprintf(stderr, "usage: meshctl [-s socket] command [args ...]\n");
	fprintf(stderr, "       meshctl [-s socket] -i\n");
	fprintf(stderr, "       meshctl help\n");
	exit(1);
}

static void
print_help(void)
{
	size_t i;

	printf("meshctl - control the meshd(8) Bluetooth Mesh daemon\n\n");
	printf("commands:\n");
	for (i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++)
		printf("  %-22s %-46s %s\n", verbs[i].name, verbs[i].args,
		    verbs[i].help);
}

/* Connect to the meshd control socket.  Exits on failure. */
static int
meshctl_connect(const char *path)
{
	struct sockaddr_un sun;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		err(1, "socket");
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path))
		errx(1, "socket path too long: %s", path);
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0)
		err(1, "connect %s", path);
	return (fd);
}

static int
meshctl_readline(int fd, char *buf, size_t bufsz)
{
	size_t off;
	ssize_t r;

	if (buf == NULL || bufsz == 0)
		return (-1);
	off = 0;
	for (;;) {
		if (off + 1 >= bufsz) {
			buf[off] = '\0';
			return (-1);
		}
		r = read(fd, buf + off, 1);
		if (r == 1) {
			if (buf[off++] == '\n') {
				buf[off] = '\0';
				return ((int)off);
			}
			continue;
		}
		if (r == 0) {
			buf[off] = '\0';
			return ((int)off);
		}
		if (errno == EINTR)
			continue;
		return (-1);
	}
}

/*
 * Send one command line and print the reply.  Returns 0 if the reply began
 * with "OK", 1 if it began with "ERR", -1 on an I/O error.
 */
static int
meshctl_exchange(int fd, const char *line)
{
	char buf[MESHCTL_REPLY_MAX];
	char out[MESHCTL_LINE_MAX];
	size_t n;
	ssize_t r;

	n = strlcpy(out, line, sizeof(out));
	if (n >= sizeof(out) - 1) {
		warnx("command too long");
		return (-1);
	}
	out[n++] = '\n';
	for (size_t off = 0; off < n;) {
		ssize_t nw;

		nw = write(fd, out + off, n - off);
		if (nw > 0) {
			off += (size_t)nw;
			continue;
		}
		if (nw < 0 && errno == EINTR)
			continue;
		if (nw == 0)
			errno = EIO;
		warn("write");
		return (-1);
	}
	/*
	 * Once a model is registered (app-register), meshd interleaves
	 * asynchronous "EVENT ..." lines onto the same stream as command
	 * replies.  Print those but keep reading, so an event that arrives
	 * between our command and its reply is not mistaken for the reply
	 * (which would desync every subsequent exchange by one line).
	 */
	for (;;) {
		r = meshctl_readline(fd, buf, sizeof(buf));
		if (r < 0) {
			warn("read");
			return (-1);
		}
		if (r == 0) {
			warnx("daemon closed the connection");
			return (-1);
		}
		buf[r] = '\0';
		fputs(buf, stdout);
		if (buf[r - 1] != '\n')
			fputc('\n', stdout);
		if (strncmp(buf, "EVENT ", 6) == 0)
			continue;	/* async event, not our reply */
		return (strncmp(buf, "OK", 2) == 0 ? 0 : 1);
	}
}

static int
meshctl_watch(int fd, int argc, char *argv[])
{
	char line[MESHCTL_LINE_MAX];
	char reply[MESHCTL_REPLY_MAX];
	size_t off;
	int i, r;

	if (argc != 3 && argc != 4) {
		warnx("usage: app-watch <element> <model> [vendor]");
		return (2);
	}
	off = strlcpy(line, "app-register", sizeof(line));
	for (i = 1; i < argc; i++) {
		r = snprintf(line + off, sizeof(line) - off, " %s", argv[i]);
		if (r < 0 || (size_t)r >= sizeof(line) - off) {
			warnx("command too long");
			return (2);
		}
		off += (size_t)r;
	}
	r = meshctl_exchange(fd, line);
	if (r != 0)
		return (r < 0 ? 2 : r);
	for (;;) {
		r = meshctl_readline(fd, reply, sizeof(reply));
		if (r < 0) {
			warn("read");
			return (2);
		}
		if (r == 0)
			return (0);
		fputs(reply, stdout);
		if (reply[strlen(reply) - 1] != '\n')
			fputc('\n', stdout);
	}
}

/* Interactive REPL: read lines from stdin, exchange each with the daemon. */
static int
meshctl_interactive(int fd)
{
	char line[MESHCTL_LINE_MAX];
	int last = 0;

	for (;;) {
		if (isatty(fileno(stdin)))
			fputs("meshctl> ", stdout);
		if (fgets(line, sizeof(line), stdin) == NULL)
			break;
		line[strcspn(line, "\n")] = '\0';
		if (line[0] == '\0')
			continue;
		if (strcmp(line, "quit") == 0 || strcmp(line, "exit") == 0)
			break;
		if (strcmp(line, "help") == 0) {
			print_help();
			continue;
		}
		last = meshctl_exchange(fd, line);
		if (last < 0)
			return (2);
	}
	return (last > 0 ? 1 : 0);
}

int
main(int argc, char *argv[])
{
	const char *sockpath = MESHCTL_DEFAULT_SOCK;
	char line[MESHCTL_LINE_MAX];
	int ch, fd, i, rc, interactive = 0;
	size_t off = 0;

	while ((ch = getopt(argc, argv, "s:ih")) != -1) {
		switch (ch) {
		case 's':
			sockpath = optarg;
			break;
		case 'i':
			interactive = 1;
			break;
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (!interactive && argc >= 1 && strcmp(argv[0], "help") == 0) {
		print_help();
		return (0);
	}
	if (!interactive && argc < 1)
		usage();

	fd = meshctl_connect(sockpath);

	if (interactive) {
		rc = meshctl_interactive(fd);
		close(fd);
		return (rc);
	}
	if (strcmp(argv[0], "app-watch") == 0) {
		rc = meshctl_watch(fd, argc, argv);
		close(fd);
		return (rc);
	}

	/* One-shot: join the remaining arguments into a single command line. */
	line[0] = '\0';
	for (i = 0; i < argc; i++) {
		int w;

		w = snprintf(line + off, sizeof(line) - off, "%s%s",
		    i == 0 ? "" : " ", argv[i]);
		if (w < 0 || (size_t)w >= sizeof(line) - off)
			errx(1, "command too long");
		off += (size_t)w;
	}
	rc = meshctl_exchange(fd, line);
	close(fd);
	return (rc < 0 ? 2 : rc);
}
