/* SPDX-License-Identifier: BSD-2-Clause */

provider mountop {
	probe operation__start(uintptr_t);
	probe operation__done(uintptr_t, int);
};
