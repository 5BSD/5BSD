/* SPDX-License-Identifier: BSD-2-Clause */

provider threadwait {
	probe mutex__start(uintptr_t);
	probe mutex__done(uintptr_t, int);
	probe condition__start(uintptr_t, int);
	probe condition__done(uintptr_t, int);
	probe join__start(uintptr_t);
	probe join__done(uintptr_t, int);
};
