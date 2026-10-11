/* SPDX-License-Identifier: BSD-2-Clause */

provider pamchain {
	probe chain__start(uintptr_t, int);
	probe chain__done(uintptr_t, int);
	probe module__start(uintptr_t, uintptr_t, int);
	probe module__done(uintptr_t, uintptr_t, int);
};
