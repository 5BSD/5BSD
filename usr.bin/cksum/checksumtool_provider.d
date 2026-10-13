/* SPDX-License-Identifier: BSD-2-Clause */
provider checksumtool {
	probe file__start(int);
	probe file__done(int, int64_t, int, int);
};
