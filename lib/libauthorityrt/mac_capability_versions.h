/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Expected mac_capability kernel module versions.
 *
 * Used by authorityd at startup to verify that loaded kernel modules
 * match what userland was built against.  Avoids subtle mismatches
 * after partial upgrades.
 */

#ifndef _MAC_CAPABILITY_VERSIONS_H_
#define	_MAC_CAPABILITY_VERSIONS_H_

#define	MAC_CAPABILITY_VERSION_CORE		1
#define	MAC_CAPABILITY_VERSION_CHANNEL		1
#define	MAC_CAPABILITY_VERSION_COALITION	1
#define	MAC_CAPABILITY_VERSION_ISOLATION	1
#define	MAC_CAPABILITY_VERSION_SYSTEM		1
#define	MAC_CAPABILITY_VERSION_CAPPROTECT	1
#define	MAC_CAPABILITY_VERSION_NODE		1
#define	MAC_CAPABILITY_VERSION_ACCOUNTING	1
#define	MAC_CAPABILITY_VERSION_IDENTITY		1
#define	MAC_CAPABILITY_VERSION_MOUNT		1

#endif /* !_MAC_CAPABILITY_VERSIONS_H_ */
