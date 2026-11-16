/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
provider resizeio {
	probe operation__start(int, int, int64_t, int64_t);
	probe operation__done(int, int, int, int);
};
