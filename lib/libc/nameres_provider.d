/* SPDX-License-Identifier: BSD-2-Clause */

provider nameres {
	probe query__start(uintptr_t, int, int);
	probe query__done(uintptr_t, int, int);
	probe server__start(uintptr_t, int, int);
	probe server__done(uintptr_t, int, int, int);
	probe dispatch__start(uintptr_t, uintptr_t);
	probe dispatch__done(uintptr_t, int);
	probe backend__start(uintptr_t, uintptr_t);
	probe backend__done(uintptr_t, uintptr_t, int);
};

/* libc providers share one DOF relocation object. */
provider semwait {
	probe park__start(uintptr_t, int, int);
	probe park__done(uintptr_t, int, int);
	probe wake__start(uintptr_t);
	probe wake__done(uintptr_t, int, int);
};
