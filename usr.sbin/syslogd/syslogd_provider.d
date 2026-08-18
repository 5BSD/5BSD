/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

provider syslogd {
	probe msg__accept(const char *hostname, int len);
};
