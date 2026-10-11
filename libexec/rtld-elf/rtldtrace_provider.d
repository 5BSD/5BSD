/* SPDX-License-Identifier: BSD-2-Clause */

provider rtldtrace {
	probe load__start(uintptr_t, int);
	probe load__done(uintptr_t, uintptr_t);
	probe relocate__start(uintptr_t);
	probe relocate__done(uintptr_t, int);
	probe init__start(uintptr_t);
	probe init__done(uintptr_t);
	probe dlopen__start(uintptr_t, int, int);
	probe dlopen__done(uintptr_t, int, int, uintptr_t);
	probe dlclose__start(uintptr_t);
	probe dlclose__done(uintptr_t, int);
};
