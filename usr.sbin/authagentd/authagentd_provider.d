/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

provider authagent {
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
	 * EACCES bad password, EAGAIN rate-limited, EINVAL malformed), and
	 * the channel transport errno.  Never the password.
	 */
	probe elevate__done(const char *client, uint32_t uid,
	    const char *name, int status, int transport_error);
};
