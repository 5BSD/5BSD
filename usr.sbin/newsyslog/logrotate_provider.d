/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */

provider logrotate {
	probe rotate__start(uintptr_t);
	probe rotate__done(uintptr_t, int);
	probe compress__start(uintptr_t, int);
	probe compress__done(uintptr_t, int, int, int);
	probe notify(uintptr_t, int, int);
};
