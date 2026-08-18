/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

provider pam_lastlog {
	probe sm__open_session(const char *user, int result);
	probe sm__close_session(const char *user, int result);
};
