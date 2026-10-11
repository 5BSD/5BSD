/* SPDX-License-Identifier: BSD-2-Clause */

provider sshauth {
	probe decision(uintptr_t, int, int, int, int);
	probe method__start(uintptr_t, int);
	probe method__done(uintptr_t, int, int);
};
