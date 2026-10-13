/* SPDX-License-Identifier: BSD-2-Clause */
provider elfbrand {
	probe read__start(int, size_t);
	probe read__done(int, size_t, int64_t, int);
	probe write__start(int, size_t);
	probe write__done(int, size_t, int64_t, int);
};
