/* SPDX-License-Identifier: BSD-2-Clause */
provider fifocreate {
	probe operation__start(unsigned int);
	probe operation__done(unsigned int, int, int);
};
