/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * USDT provider for jail(8).  Observes the userland jail create/update
 * requests issued via jailparam_set(); the kernel-side enforcement is
 * separately visible via the in-kernel "jail" SDT provider.  jid < 0 on
 * failure.
 */
provider jail {
	probe param__set(const char *name, int flags, int jid);
};
