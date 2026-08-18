/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

provider pam_ssh {
	probe sm__authenticate(const char *user, int result);
	probe sm__setcred(const char *user, int flags, int result);
	probe sm__open_session(const char *user, int result);
	probe sm__close_session(const char *user, int result);
};
