/* SPDX-License-Identifier: BSD-2-Clause */

provider exports {
	probe reload__start(int);
	probe reload__done(int);
};
