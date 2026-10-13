/* SPDX-License-Identifier: BSD-2-Clause */
provider gzipstream {
	probe inflate__start(unsigned int, unsigned int);
	probe inflate__done(int, unsigned int, unsigned int);
	probe decode__error(int, long long);
};
