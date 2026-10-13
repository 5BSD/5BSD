/* SPDX-License-Identifier: BSD-2-Clause */
provider dircreate {
	probe operation__start(int);
	probe operation__done(int, int, int);
};
