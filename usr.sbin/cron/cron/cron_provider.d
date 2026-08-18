/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

provider cron {
	probe job__run(const char *user, const char *cmd);
	probe job__done(const char *user, int status);
};
