/* SPDX-License-Identifier: BSD-2-Clause */
provider timeoutsig {
	probe operation__start(int, int);
	probe operation__done(int, int, int, int);
	probe reaper__start(int);
	probe reaper__done(int, int, int);
};
