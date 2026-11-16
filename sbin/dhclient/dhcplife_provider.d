/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */

provider dhcplife {
	probe state(uintptr_t, int);
	probe script__start(uintptr_t);
	probe script__done(uintptr_t, int);
};
