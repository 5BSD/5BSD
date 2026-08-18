/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * USDT provider for su(1).  Captures the authentication and account-management
 * outcomes of a privilege-elevation attempt (retcode == PAM_SUCCESS (0) means
 * the step passed).  The credential transition that follows is separately
 * visible via logincap:::setusercontext (libutil).
 */
provider su {
	/* PAM authentication result: caller, target user, tty, PAM retcode. */
	probe auth(const char *from, const char *to, const char *tty,
	    int retcode);
	/* PAM account-management result: target user, PAM retcode. */
	probe acct(const char *to, int retcode);
};
