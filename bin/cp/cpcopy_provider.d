/* SPDX-License-Identifier: BSD-2-Clause */

provider cpcopy {
	probe transfer__start(int, int);
	probe transfer__done(int, int, int64_t, int);
	probe fallback(int, int, int);
	probe retry(int, int, int);
};
