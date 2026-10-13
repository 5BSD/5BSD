/* SPDX-License-Identifier: BSD-2-Clause */
provider ipcsnapshot {
	probe query__start(int, size_t);
	probe query__done(int, int, size_t);
};
