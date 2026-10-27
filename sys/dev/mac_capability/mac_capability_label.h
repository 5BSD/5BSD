/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability_label — per-credential program identity.
 *
 * The MAC capability framework attaches an execution identity nonce to credentials.
 * Identity replies and kernel-stamped message trailers expose this value;
 * it is not a bearer secret. Consumers must use trusted kernel metadata,
 * not accept a user-supplied number as proof of the caller's identity.
 * Current random allocation depends on the kernel's early-seeding policy.
 * The nonce identifies the program execution family:
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

/*
 * Coalition identity of a process, for exporters (kinfo_proc, OES).
 *
 * The coalition service lives in a loadable module; it registers a
 * provider with mac_capability_proc_coalition_hook_set() at load and
 * clears it at unload.  mac_capability_proc_coalition() is safe to call
 * with the process lock held (the provider takes only non-sleepable
 * locks) and returns false, with *out zeroed, when the module is absent
 * or the process belongs to no coalition.
 */
struct proc;
struct mac_capability_proc_coalition {
	uint64_t	id;			/* this process's coalition */
	uint64_t	responsible_id;		/* its responsible parent, 0 = unset */
	pid_t		leader_pid;		/* coalition leader, 0 = none */
	pid_t		responsible_leader_pid;	/* responsible parent's leader */
};
typedef bool (*mac_capability_proc_coalition_fn)(struct proc *,
    struct mac_capability_proc_coalition *);
void	mac_capability_proc_coalition_hook_set(mac_capability_proc_coalition_fn);
bool	mac_capability_proc_coalition(struct proc *p,
	    struct mac_capability_proc_coalition *out);

#endif /* _KERNEL */
#endif /* _DEV_MAC_CAPABILITY_MAC_CAPABILITY_LABEL_H_ */
