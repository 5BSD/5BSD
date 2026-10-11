/* SPDX-License-Identifier: BSD-2-Clause */

provider ffscheck {
	probe phase__start(int);
	probe phase__done(int);
};
