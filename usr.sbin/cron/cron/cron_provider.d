/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

provider cron {
	probe job__run(const char *user, const char *cmd);
	probe job__done(const char *user, int status);
	probe job__launch(int arg0, uint32_t arg1, int arg2);
	probe job__exec__error(int arg0);
	probe child__wait__start(int arg0);
	probe child__wait__done(int arg0, int arg1, int arg2, int arg3);
};
