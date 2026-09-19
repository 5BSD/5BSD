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
	/*
	 * A connection was accepted and its identity agreed with the listener
	 * it arrived on: label, tier (NOTIFY_TIER_OPEN 0 / _SYSTEM 1), the
	 * rights switchboard stamped, and the client's ABI.
	 */
	probe session__admit(const char *, uint32_t, uint64_t, uint8_t);
	/*
	 * The router chose a session's policy: label, tier, and which block
	 * answered ("default", "system_default", or "clients").
	 */
	probe tier__policy(const char *, uint32_t, const char *);
};
