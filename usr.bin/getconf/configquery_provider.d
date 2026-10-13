/* SPDX-License-Identifier: BSD-2-Clause */
provider configquery {
	probe operation__start(int);
	probe operation__done(int, int64_t, int);
};
