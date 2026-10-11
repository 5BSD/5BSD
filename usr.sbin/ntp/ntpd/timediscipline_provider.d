/* SPDX-License-Identifier: BSD-2-Clause */

provider timediscipline {
	probe select__start(uintptr_t);
	probe select__done(uintptr_t, int);
	probe adjust__start(uintptr_t);
	probe adjust__done(uintptr_t, int);
};
