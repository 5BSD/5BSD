/* SPDX-License-Identifier: BSD-2-Clause */
provider flushall {
	probe operation__start(int);
	probe operation__done(int);
};
