/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * anoint(1) -- run one command holding one additional anointment.  The
 * sudo/doas replacement of the capability system (docs/ipc-anointments-design.md
 * "Elevation"): ask system.Auth, over this session's own lookup channel,
 * for a channel that holds the session's set plus NAME, authenticating with
 * the caller's own password; install it as the ambient lookup channel; exec
 * CMD.  The uid never changes; the channel dies with CMD; nothing is cached.
 */

#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <readpassphrase.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <service_bootstrap.h>
#include <authagent_proto.h>

/* Exit statuses, doas(1)/sudo(8) style. */
#define	EXIT_REFUSED	1
#define	EXIT_NOEXEC	126
#define	EXIT_NOTFOUND	127

#define	ELEVATE_TIMEOUT_MS	5000U

static void __dead2
usage(void)
{

	fprintf(stderr, "usage: anoint [-n] name command [argument ...]\n");
	exit(EXIT_REFUSED);
}

/*
 * Reject client-side what the agent would reject anyway, so a typo never
 * prompts for a password: reverse-domain syntax, at least one dot, "*" is a
 * policy wildcard and not a name.
 */
static bool
valid_name(const char *name)
{
	const unsigned char *p;
	size_t len;
	bool has_dot;

	len = strnlen(name, AUTHAGENT_NAME_MAX);
	if (len == 0 || len >= AUTHAGENT_NAME_MAX || name[0] == '.' ||
	    name[len - 1] == '.')
		return (false);
	has_dot = false;
	for (p = (const unsigned char *)name; *p != '\0'; p++) {
		if (*p == '.') {
			if (p[-1] == '.')
				return (false);
			has_dot = true;
		} else if (!((*p >= 'a' && *p <= 'z') ||
		    (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') || *p == '-' || *p == '_'))
			return (false);
	}
	return (has_dot);
}

int
main(int argc, char *argv[])
{
	char password[AUTHAGENT_PASSWORD_MAX];
	const char *name;
	int ch, error, fd, session_fd;
	bool noprompt;

	noprompt = false;
	while ((ch = getopt(argc, argv, "n")) != -1) {
		switch (ch) {
		case 'n':
			noprompt = true;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 2)
		usage();
	name = argv[0];
	if (!valid_name(name))
		errx(EXIT_REFUSED, "%s: not an anointment name", name);

	/*
	 * Elevation is an operation on a session: without an inherited
	 * ambient lookup channel there is no session to elevate and no way to
	 * reach the agent.  Fail at once, never hang (E6).
	 */
	session_fd = service_ambient_lookup_fd();
	if (session_fd == -1)
		errx(EXIT_REFUSED, "no session channel");

	memset(password, 0, sizeof(password));
	if (!noprompt) {
		if (readpassphrase("Password:", password, sizeof(password),
		    RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL) {
			explicit_bzero(password, sizeof(password));
			errx(EXIT_REFUSED, "no password");
		}
	}

	fd = -1;
	if (service_elevate(name, password, ELEVATE_TIMEOUT_MS, &fd) == -1) {
		error = errno;
		explicit_bzero(password, sizeof(password));
		/*
		 * Every status the agent answers (bsdauth(8) "Elevation")
		 * and every transport failure service_elevate(3) reports gets
		 * its own line; the default covers anything new.
		 */
		switch (error) {
		case EPERM:
			errx(EXIT_REFUSED, "not permitted");
		case EACCES:
			errx(EXIT_REFUSED, "authentication failed");
		case EAGAIN:
			errx(EXIT_REFUSED, "too many failures");
		case E2BIG:
			errx(EXIT_REFUSED,
			    "session already holds the maximum number of anointments");
		case ENOENT:
			errx(EXIT_REFUSED, "auth agent unavailable");
		case ETIMEDOUT:
			errx(EXIT_REFUSED, "auth agent did not answer");
		case ENXIO:
			errx(EXIT_REFUSED, "elevation is not enabled on this system");
		case EINVAL:
			errx(EXIT_REFUSED, "auth agent rejected the request");
		case EBADMSG:
			errx(EXIT_REFUSED, "malformed reply from auth agent");
		default:
			errno = error;
			err(EXIT_REFUSED, "%s", name);
		}
	}
	explicit_bzero(password, sizeof(password));

	/*
	 * Make the elevated channel THE ambient channel for CMD and its
	 * descendants (E1/E2), and drop the unelevated one so CMD does not
	 * inherit both.  A failure here leaks nothing: the elevated channel
	 * simply closes with us.
	 */
	if (service_install_ambient_lookup(fd) == -1) {
		error = errno;
		(void)close(fd);
		errno = error;
		err(EXIT_REFUSED, "install session channel");
	}
	if (session_fd != fd)
		(void)close(session_fd);

	execvp(argv[1], argv + 1);
	err(errno == ENOENT ? EXIT_NOTFOUND : EXIT_NOEXEC, "%s", argv[1]);
}
