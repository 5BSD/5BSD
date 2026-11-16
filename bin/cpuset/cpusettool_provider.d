/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
provider cpusettool {
	probe operation__start(int, int, int);
	probe operation__done(int, int, int, int, int);
};
