/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Expected cap_rt kernel module versions.
 *
 * Used by oracled at startup to verify that loaded kernel modules
 * match what userland was built against.  Avoids subtle mismatches
 * after partial upgrades.
 */

#ifndef _CAP_RT_VERSIONS_H_
#define	_CAP_RT_VERSIONS_H_

#define	CAP_RT_VERSION_CORE		1
#define	CAP_RT_VERSION_PAIR		1
#define	CAP_RT_VERSION_COALITION	1
#define	CAP_RT_VERSION_ISOLATION	1
#define	CAP_RT_VERSION_SYSTEM		1
#define	CAP_RT_VERSION_CAPPROTECT	1
#define	CAP_RT_VERSION_NODE		1
#define	CAP_RT_VERSION_ACCOUNTING	1
#define	CAP_RT_VERSION_IDENTITY		1
#define	CAP_RT_VERSION_MOUNT		1

#endif /* !_CAP_RT_VERSIONS_H_ */
