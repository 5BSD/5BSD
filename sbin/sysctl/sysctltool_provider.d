/* SPDX-License-Identifier: BSD-2-Clause */
provider sysctltool {
	probe operation__start(int, unsigned int);
	probe operation__done(int, unsigned int, int, int);
};
