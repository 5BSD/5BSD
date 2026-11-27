/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared by identity_semantics_test and its exec'd helper.
 */

#ifndef _IDENTITY_SEMANTICS_H_
#define	_IDENTITY_SEMANTICS_H_

/* Exit statuses of identity_semantics_helper beyond errno values. */
#define	HELPER_BROKEN		250	/* the helper itself failed */
#define	IDS_EXIT_AUTH_STEP	251	/* authorized execution was refused */
#define	IDS_EXIT_FORK_STEP	252	/* its fork child was refused */

/* A short, reversible kenv variable used only to probe the KENV gate. */
#define	IDS_KENV_PROBE		"mac_cap_ids_probe"

#endif /* !_IDENTITY_SEMANTICS_H_ */
