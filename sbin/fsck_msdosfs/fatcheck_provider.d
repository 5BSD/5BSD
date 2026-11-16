/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */

provider fatcheck {
	probe check__start(uintptr_t);
	probe check__done(uintptr_t, int);
};
