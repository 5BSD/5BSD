/* SPDX-License-Identifier: BSD-2-Clause */
provider fileflags {
	probe operation__start(uint64_t);
	probe operation__done(uint64_t, int, int);
};
