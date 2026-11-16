/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
provider fileflags {
	probe operation__start(uint64_t);
	probe operation__done(uint64_t, int, int);
};
