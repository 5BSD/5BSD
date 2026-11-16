/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */

provider installcopy {
	probe range__start(int, int);
	probe range__done(int, int, int64_t, int);
	probe fallback(int, int, int);
	probe sync__start(int);
	probe sync__done(int, int);
};
