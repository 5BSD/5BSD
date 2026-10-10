/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

provider bsdtrace {
	probe request__done(uint32_t opcode, int status, int terminal_error);
	probe session__start(const char *, uint64_t, int);
	probe session__end(const char *, uint64_t, int);
	probe delegate(const char *, uint64_t, int);
	probe reject(const char *, uint16_t, int);
};
