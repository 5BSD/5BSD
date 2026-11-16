/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
provider gzipstream {
	probe inflate__start(unsigned int, unsigned int);
	probe inflate__done(int, unsigned int, unsigned int);
	probe decode__error(int, long long);
};
