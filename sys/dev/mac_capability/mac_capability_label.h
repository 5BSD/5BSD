/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability_label — per-credential program identity.
 *
 * The MAC capability framework attaches a cryptographic nonce to every credential.
 * The nonce identifies the program image:
 *   - Inherited across fork (same program)
 *   - Rotated on exec (new program)
 *   - Kernel-assigned; userspace cannot set it
 *
 * Call mac_capability_proc_nonce() to read it.  Returns 0 if not available.
 * The internal label struct is hidden — additional fields may be
 * added without changing consumers.
 */

#ifndef _DEV_MAC_CAPABILITY_MAC_CAPABILITY_LABEL_H_
#define _DEV_MAC_CAPABILITY_MAC_CAPABILITY_LABEL_H_

#ifdef _KERNEL

struct ucred;

/*
 * Return the program nonce for a credential.
 * Returns 0 if the credential has no label.
 */
uint64_t	mac_capability_proc_nonce(struct ucred *cred);

#endif /* _KERNEL */
#endif /* _DEV_MAC_CAPABILITY_MAC_CAPABILITY_LABEL_H_ */
