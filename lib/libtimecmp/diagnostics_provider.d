/* SPDX-License-Identifier: BSD-2-Clause */
provider timecmp {
	probe wait__start(uintptr_t a0);
	probe wait__done(uintptr_t a0, int a1, int a2);
	probe reply__malformed(int a0);
};
