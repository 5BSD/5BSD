/* SPDX-License-Identifier: BSD-2-Clause */
provider modulequery {
	probe operation__start(int);
	probe operation__done(int, int, int);
};
