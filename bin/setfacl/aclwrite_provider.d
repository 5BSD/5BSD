/* SPDX-License-Identifier: BSD-2-Clause */
provider aclwrite {
	probe operation__start(int, int);
	probe operation__done(int, int, int, int);
};
