/* SPDX-License-Identifier: BSD-2-Clause */

provider archiveio {
	probe operation__start(uintptr_t, int, uintptr_t);
	probe operation__done(uintptr_t, int, int64_t);
};
