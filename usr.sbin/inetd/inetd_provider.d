/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

provider inetd {
	probe spawn(const char *service, const char *proto, const char *user);
	probe refuse(const char *service, const char *proto);
};
