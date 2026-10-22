/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * migration_channel_policy(): every migration transport needs mutual TLS,
 * except an explicitly requested plaintext AF_UNIX stream socket.  Each case
 * builds the descriptor kind directly; the expected errno follows from the
 * policy's documented rules, not from the implementation.
 */

#include <sys/socket.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "migration_channel.h"

static int failures;

static void
expect(const char *what, int got, int want)
{
	printf("%s %s: got %d want %d\n", got == want ? "PASS" : "FAIL", what,
	    got, want);
	failures += got != want;
}

int
main(void)
{
	int sp[2], dg[2], pp[2], in;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0 ||
	    socketpair(AF_UNIX, SOCK_DGRAM, 0, dg) != 0 || pipe(pp) != 0 ||
	    (in = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("setup");
		return (2);
	}

	/* With credentials, TLS is used whatever the descriptor is. */
	expect("credentials, unix stream", migration_channel_policy(sp[0],
	    true, false), 0);
	expect("credentials, inet stream", migration_channel_policy(in, true,
	    false), 0);
	expect("credentials and opt-in", migration_channel_policy(in, true,
	    true), 0);
	/* Without credentials and without the opt-in, always refused. */
	expect("no credentials, unix stream", migration_channel_policy(sp[0],
	    false, false), EACCES);
	expect("no credentials, inet stream", migration_channel_policy(in,
	    false, false), EACCES);
	/* The opt-in admits only a local AF_UNIX stream socket. */
	expect("opt-in, unix stream", migration_channel_policy(sp[0], false,
	    true), 0);
	expect("opt-in, unix datagram", migration_channel_policy(dg[0], false,
	    true), EPROTONOSUPPORT);
	expect("opt-in, inet stream", migration_channel_policy(in, false,
	    true), EPROTONOSUPPORT);
	expect("opt-in, pipe", migration_channel_policy(pp[0], false, true),
	    EPROTONOSUPPORT);
	expect("opt-in, closed descriptor", migration_channel_policy(1000,
	    false, true), EBADF);

	printf("%d failure(s)\n", failures);
	exit(failures != 0);
}
