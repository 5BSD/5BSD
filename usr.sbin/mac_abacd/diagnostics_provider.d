/* SPDX-License-Identifier: BSD-2-Clause */
provider abacdaemon {
	probe policy__start(int a0);
	probe policy__done(int a0, int a1);
};
