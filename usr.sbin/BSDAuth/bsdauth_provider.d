/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

provider bsdauth {
	/* One request entered the synchronous mint decision path. */
	probe request__start(const char *client);
	/*
	 * Completed request: client, requested uid (UINT32_MAX if unavailable),
	 * mint kind (-1 if undecided), request flags, reply status, and channel
	 * transport errno (0 when the reply was accepted for delivery).
	 */
	probe request__done(const char *client, uint32_t uid, int kind,
	    uint32_t flags, int status, int transport_error);
	/* One ELEVATE request entered the decision path (client label). */
	probe elevate__start(const char *client);
	/*
	 * Completed ELEVATE: client label, the kernel-stamped caller uid
	 * (UINT32_MAX if unavailable), the requested anointment name ("" if
	 * the request was malformed), reply status (0 ok, EPERM policy/label,
	 * EACCES bad password, EAGAIN rate-limited, EINVAL malformed, ENXIO
	 * no master.passwd, E2BIG set full), the channel transport errno, and
	 * the decision stage the outcome came from: "caller" (not a session),
	 * "shape" (malformed), "policy" (principal/may_elevate), "ratelimit",
	 * "password", "mint" (compose/mint failed), "ok".  Never the password.
	 */
	probe elevate__done(const char *client, uint32_t uid,
	    const char *name, int status, int transport_error,
	    const char *stage);
	/*
	 * An ELEVATE was refused EAGAIN by the per-uid failure limiter:
	 * the uid and the failures recorded in its current window.
	 */
	probe ratelimit__block(uint32_t uid, unsigned int failures);
	/*
	 * The principal policy resolved a uid's grant (both MINT and ELEVATE
	 * pass here): anointment count, whether it holds "*", whether it
	 * carries admin rights, and whether the historical root-or-wheel rule
	 * stood in for an absent/malformed policy file.
	 */
	probe policy__resolve(uint32_t uid, unsigned int count, int all,
	    int admin_rights, int from_default_rule);
};
