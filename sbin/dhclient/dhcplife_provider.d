/* SPDX-License-Identifier: BSD-2-Clause */

provider dhcplife {
	probe state(uintptr_t, int);
	probe script__start(uintptr_t);
	probe script__done(uintptr_t, int);
};
