/* SPDX-License-Identifier: BSD-2-Clause */
provider abacctl {
	probe policy__start(int a0);
	probe policy__done(int a0, int a1);
};
