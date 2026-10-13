/* SPDX-License-Identifier: BSD-2-Clause */

provider fetchio {
	probe request__start(uintptr_t);
	probe request__done(uintptr_t, int, int);
	probe connect__start(uintptr_t, int);
	probe connect__done(uintptr_t, int);
	probe tls__start(uintptr_t);
	probe tls__done(uintptr_t, int);
	probe read__start(uintptr_t, size_t);
	probe read__done(uintptr_t, int64_t, int);
	probe write__start(uintptr_t, size_t);
	probe write__done(uintptr_t, int64_t, int);
	probe poll__start(int, int, int);
	probe poll__done(int, int, int, int);
};
