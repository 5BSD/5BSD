/* SPDX-License-Identifier: BSD-2-Clause */
provider priorityop {
	probe operation__start(int, int, int);
	probe operation__done(int, int, int, int, int);
};
