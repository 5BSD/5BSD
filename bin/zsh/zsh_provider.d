/* SPDX-License-Identifier: BSD-2-Clause */
provider zsh {
	probe fork__start(int a0);
	probe fork__done(int a0, int a1);
	probe job__limit(int a0);
	probe exec__attempt(int a0);
	probe exec__failure(int a0, int a1);
	probe pipeline__start(int a0, int a1);
	probe pipeline__done(int a0, int a1, int a2);
	probe wait__start(int a0, int a1);
	probe wait__done(int a0, int a1);
};
