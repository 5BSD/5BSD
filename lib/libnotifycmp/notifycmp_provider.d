/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

provider notifycmp {
	probe rpc(uint16_t, int);
	probe publish(const char *, size_t, int);
	probe next(uint32_t, int);
	probe reject(uint16_t, int);
	probe reconnect(uint64_t, int);
};
