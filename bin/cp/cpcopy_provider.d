/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */

provider cpcopy {
	probe transfer__start(int, int);
	probe transfer__done(int, int, int64_t, int);
	probe fallback(int, int, int);
	probe retry(int, int, int);
};
