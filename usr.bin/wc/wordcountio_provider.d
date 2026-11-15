/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
provider wordcountio {
	probe read__start(int, size_t);
	probe read__done(int, size_t, int64_t, int);
};
