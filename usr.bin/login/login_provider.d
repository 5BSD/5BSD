/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * USDT provider for login(1).  Captures each authentication attempt's outcome
 * (retcode == 0 means the PAM stack accepted the credentials) and the terminal
 * give-up.  The subsequent credential transition is visible via
 * logincap:::setusercontext (libutil).
 */
provider login {
	/* One authentication attempt: user, tty, root flag, result. */
	probe auth(const char *user, const char *tty, int rootlogin,
	    int retcode);
	/* Login abandoned after too many failures: user, tty. */
	probe fail(const char *user, const char *tty);
};
