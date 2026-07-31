/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

provider tracecmp {
	probe open(const char *, int);
	probe send(uint16_t, size_t, int);
	probe receive(uint16_t, size_t, int);
	probe reject(uint16_t, int);
};
