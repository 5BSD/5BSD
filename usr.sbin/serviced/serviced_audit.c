/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * serviced — OpenBSM audit-trail helpers.
 */

#include <sys/types.h>

#include "serviced_audit.h"

#ifdef USE_BSM_AUDIT
#include <bsm/libbsm.h>

#include <stdarg.h>
#include <stdio.h>

void
serviced_audit(int event, uid_t auid, int error, const char *fmt, ...)
{
	char buf[MAX_AUDITSTRING_LEN];
	va_list ap;

	va_start(ap, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	/*
	 * audit_submit(3) is a no-op when auditing is not configured, so this
	 * is cheap on systems that are not actively auditing.  status is the
	 * errno (0 == success) and reterr is a boolean failure indicator, per
	 * the convention used by su(1) and blued(8).
	 */
	(void)audit_submit((short)event, auid, (char)error, error != 0 ? 1 : 0,
	    "%s", buf);
}
#endif /* USE_BSM_AUDIT */
