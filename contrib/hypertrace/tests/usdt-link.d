/* SPDX-License-Identifier: BSD-2-Clause */
provider ulink {
	probe zero();
	probe one(int);
	probe two(int, char *);
	probe five(int, long, char *, short, unsigned long);
	probe dash__name(int);
};

provider ulinkb {
	probe go(int);
};
