/* SPDX-License-Identifier: BSD-2-Clause */
provider attrtool {
	probe delete__start(int, int);
	probe delete__done(int, int, int, int);
	probe set__start(int, int, size_t, int);
	probe set__done(int, int, size_t, int, int64_t, int);
	probe list__start(int, int, size_t, int);
	probe list__done(int, int, size_t, int, int64_t, int);
	probe get__start(int, int, size_t, int);
	probe get__done(int, int, size_t, int, int64_t, int);
};
