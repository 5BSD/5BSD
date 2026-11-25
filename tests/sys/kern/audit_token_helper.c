/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * Exec target of audit_token_test: writes its own audit token, as read
 * after the exec, to standard output, then waits for end of file on
 * standard input so that the test can look at the process while it is
 * still the exec'd image.  Exits 2 if the token cannot be read.
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "audit_token_pins.h"

int
main(void)
{
	audit_token_t tok;
	char c;
	ssize_t n;

	if (pin_audit_token_get(-1, 0, 0, &tok) != 0)
		_exit(2);
	if (write(STDOUT_FILENO, &tok, sizeof(tok)) != sizeof(tok))
		_exit(2);
	do {
		n = read(STDIN_FILENO, &c, 1);
	} while (n > 0 || (n == -1 && errno == EINTR));
	return (0);
}
