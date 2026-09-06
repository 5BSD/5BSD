/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

provider bsdnotify {
	probe session__start(const char *, uint64_t, int);
	probe session__end(const char *, int);
	probe subscribe(const char *, const char *, int);
	probe publish(const char *, const char *, size_t, int);
	probe deliver(const char *, uint32_t, int);
	probe timer(const char *, uint64_t, int);
	probe reject(const char *, uint16_t, int);
	probe list(const char *, uint16_t, uint64_t);
};
