/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
provider checksumtool {
	probe file__start(int);
	probe file__done(int, int64_t, int, int);
};
