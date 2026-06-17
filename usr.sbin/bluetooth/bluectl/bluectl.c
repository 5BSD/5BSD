/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * bluectl — command-line client for blued(8) control socket.
 */

#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#define DEFAULT_SOCKET	"/var/run/blued.sock"
#define BUFSIZE		4096

static void	usage(void);
static int	ctl_connect(const char *path);
static int	ctl_command(int fd, const char *cmd, int multiline);

/*
 * Single-line commands: response is one line (STATUS, OK, ERROR).
 * Multi-line commands: response ends with "END\n".
 */
struct command {
	const char	*name;
	int		 multiline;
	int		 minargs;	/* additional args after command name */
	int		 maxargs;
};

static const struct command commands[] = {
	{ "scan",	1, 0, 0 },
	{ "list",	1, 0, 0 },
	{ "adapters",	1, 0, 0 },
	{ "status",	0, 0, 0 },
	{ "connect",	0, 1, 2 },
	{ "disconnect",	0, 1, 1 },
	{ NULL,		0, 0, 0 }
};

int
main(int argc, char *argv[])
{
	const char *spath;
	const struct command *cmd;
	char cmdbuf[256];
	int ch, fd, i, ret;

	spath = DEFAULT_SOCKET;

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			spath = optarg;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	/* Find the command */
	cmd = NULL;
	for (i = 0; commands[i].name != NULL; i++) {
		if (strcmp(argv[0], commands[i].name) == 0) {
			cmd = &commands[i];
			break;
		}
	}
	if (cmd == NULL) {
		warnx("unknown command: %s", argv[0]);
		usage();
	}

	/* Validate argument count */
	if (argc - 1 < cmd->minargs || argc - 1 > cmd->maxargs) {
		warnx("wrong number of arguments for '%s'", cmd->name);
		usage();
	}

	/* Build the command string */
	cmdbuf[0] = '\0';
	for (i = 0; i < argc; i++) {
		if (i > 0)
			strlcat(cmdbuf, " ", sizeof(cmdbuf));
		strlcat(cmdbuf, argv[i], sizeof(cmdbuf));
	}

	/* Convert command name to uppercase */
	for (i = 0; cmdbuf[i] != '\0' && cmdbuf[i] != ' '; i++) {
		if (cmdbuf[i] >= 'a' && cmdbuf[i] <= 'z')
			cmdbuf[i] -= 'a' - 'A';
	}

	fd = ctl_connect(spath);
	if (fd < 0)
		err(1, "connect to %s", spath);

	ret = ctl_command(fd, cmdbuf, cmd->multiline);

	close(fd);
	return (ret);
}

/*
 * Connect to the blued control socket.
 * Returns the socket fd on success, -1 on failure.
 */
static int
ctl_connect(const char *path)
{
	struct sockaddr_un sun;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return (-1);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlen(path) >= sizeof(sun.sun_path)) {
		close(fd);
		errno = ENAMETOOLONG;
		return (-1);
	}
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		close(fd);
		return (-1);
	}

	return (fd);
}

/*
 * Send a command and print the response.
 * For multi-line commands, reads until a line containing "END" is received.
 * For single-line commands, reads and prints one line.
 * Returns 0 on success, 1 on error response.
 */
static int
ctl_command(int fd, const char *cmd, int multiline)
{
	char buf[BUFSIZE];
	char line[BUFSIZE];
	ssize_t n;
	size_t buflen, consumed;
	int done, ret;
	char *nl;

	/* Send the command with a trailing newline */
	snprintf(buf, sizeof(buf), "%s\n", cmd);
	if (send(fd, buf, strlen(buf), 0) < 0)
		err(1, "send");

	buflen = 0;
	done = 0;
	ret = 0;

	while (!done) {
		n = recv(fd, buf + buflen, sizeof(buf) - buflen - 1, 0);
		if (n <= 0) {
			if (n == 0 && buflen == 0)
				break;
			if (n < 0)
				err(1, "recv");
			/* n == 0 with data in buffer — process remaining */
			done = 1;
		} else {
			buflen += (size_t)n;
		}
		buf[buflen] = '\0';

		/* Process complete lines */
		while ((nl = strchr(buf, '\n')) != NULL) {
			consumed = (size_t)(nl - buf);
			if (consumed >= sizeof(line))
				consumed = sizeof(line) - 1;
			memcpy(line, buf, consumed);
			line[consumed] = '\0';

			/* Shift buffer */
			consumed = (size_t)(nl - buf) + 1;
			buflen -= consumed;
			if (buflen > 0)
				memmove(buf, nl + 1, buflen);
			buf[buflen] = '\0';

			/* Check for END marker */
			if (multiline && strcmp(line, "END") == 0) {
				done = 1;
				break;
			}

			/* Check for error */
			if (strncmp(line, "ERROR", 5) == 0)
				ret = 1;

			printf("%s\n", line);

			/* Single-line commands are done after first line */
			if (!multiline) {
				done = 1;
				break;
			}
		}
	}

	return (ret);
}

static void
usage(void)
{

	fprintf(stderr,
	    "usage: bluectl [-s socket] command [args ...]\n"
	    "\n"
	    "Commands:\n"
	    "  scan                         Scan for nearby LE devices\n"
	    "  list                         List connected devices\n"
	    "  adapters                     List active adapters\n"
	    "  status                       Show daemon status\n"
	    "  connect <addr> [public|random]\n"
	    "                               Connect to a device\n"
	    "  disconnect <addr>            Disconnect a device\n");
	exit(EX_USAGE);
}
