/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

provider tracecmpd {
	probe session(const char *, uint64_t, int);
	probe delegate(const char *, uint64_t, int);
	probe reject(const char *, uint16_t, int);
};
