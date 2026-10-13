/* SPDX-License-Identifier: BSD-2-Clause */
provider logsend {
	probe operation__start(size_t);
	probe operation__done(size_t, int64_t, int);
	probe local__start(int);
	probe local__done(int);
};
