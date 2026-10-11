/* SPDX-License-Identifier: BSD-2-Clause */

provider sshkeys {
	probe newkeys__start(uintptr_t, int);
	probe newkeys__done(uintptr_t, int);
	probe channel__new(uintptr_t, int, int);
	probe channel__free(uintptr_t, int);
	probe channel__reply(uintptr_t, int, int);
};
