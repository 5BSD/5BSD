/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

provider devd {
	probe action(const char *event, const char *cmd);
	probe event__start(int);
	probe event__done(int);
	probe rule(uintptr_t, int);
	probe action__start(uintptr_t);
	probe action__done(uintptr_t, int);
	probe child(int);
};
