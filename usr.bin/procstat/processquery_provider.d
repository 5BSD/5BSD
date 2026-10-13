/* SPDX-License-Identifier: BSD-2-Clause */
provider processquery {
	probe operation__start(int);
	probe operation__done(int, unsigned int, int);
};
