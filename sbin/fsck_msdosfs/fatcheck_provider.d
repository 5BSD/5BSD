/* SPDX-License-Identifier: BSD-2-Clause */

provider fatcheck {
	probe check__start(uintptr_t);
	probe check__done(uintptr_t, int);
};
