/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _SYS_CAP_AUTHORITY_H_
#define _SYS_CAP_AUTHORITY_H_

#include <sys/types.h>

/* Operations on cap_process(2); software identities are kernel-assigned. */
#define CAP_AUTH_ISSUER_CREATE 10
#define CAP_AUTH_ISSUE         11
#define CAP_AUTH_TOKEN_INFO    12
#define CAP_AUTH_INSTALL       13
#define CAP_AUTH_CLEAR         14
#define CAP_AUTH_INFO          15
#define CAP_AUTH_BIND          16
#define CAP_AUTH_REVOKE        17
#define CAP_AUTH_CONSTRAIN     18
#define CAP_AUTH_REGISTER_APP  19
#define CAP_AUTH_SET_LIBDIRS   20
#define CAP_AUTH_GET_LIBDIR    21
#define CAP_AUTH_BIND_INVOCATION 22
#define CAP_AUTH_LEASE_CREATE  23
#define CAP_AUTH_LEASE_BIND    24
#define CAP_AUTH_LEASE_CHECK   25
#define CAP_AUTH_CHECK_INVOCATION 26

#define CAP_AUTH_VERSION 1
#define CAP_AUTH_RETIRED_USER 1 /* Reserved wire value; issuance is rejected. */
#define CAP_AUTH_MANAGED 2

struct cap_authority_spec {
	uint32_t version;
	uint32_t kind;
	uint32_t uid;
	uint32_t reserved;
};

/* Fixed-width layout is shared by native and compat callers. */
struct cap_authority_info {
	uint64_t issuer;
	uint64_t identity;
	uint64_t generation;
	uint32_t kind;
	uint32_t uid;
	uint32_t valid;
	uint32_t consumed;
	uint32_t references;
	uint32_t revoked;
};

struct cap_authority_stamp {
	uint64_t issuer;
	uint64_t identity;
	uint64_t generation;
	uint32_t kind;
	uint32_t uid;
	uint32_t valid;
	uint32_t reserved;
};

/* Issuer-only, before installation; executable identities are immutable. */
#define CAP_AUTH_EXEC_MAX 8
struct cap_authority_constraint {
	int32_t token_fd;
	uint32_t flags; /* Reserved; must be zero. */
	uint32_t nexec;
	uint32_t reserved;
	int32_t executable_fds[CAP_AUTH_EXEC_MAX];
};

/* Issuer-owned library directories, never loader environment authority.
 * GET_LIBDIR takes an index in fd and returns a fresh close-on-exec descriptor.
 */
#define CAP_AUTH_LIBDIR_MAX 3
struct cap_authority_libdirs {
	int32_t token_fd;
	uint32_t count;
	int32_t directory_fds[CAP_AUTH_LIBDIR_MAX];
	uint32_t reserved;
};

/* Register one constrained image for automatic attribution on exec. */
struct cap_authority_application {
	int32_t token_fd;
	uint32_t reserved;
};

struct cap_authority_revoke {
	int32_t token_fd;
	uint32_t reserved;
};

struct cap_authority_bind {
	int32_t token_fd;
	int32_t capability_fd;
	uint32_t flags;
	uint32_t reserved;
};

/* Bind a fresh capability to one observed invocation as well as its software
 * authority. process_identity and execution_nonce come from kernel-stamped
 * receive metadata, never from a request payload. Zero identities are invalid.
 * Fork, successful exec and authority revocation make this handle unusable.
 * This does not authenticate a person or assign roles. */
struct cap_authority_bind_invocation {
	int32_t token_fd;
	int32_t capability_fd;
	uint64_t process_identity;
	uint64_t execution_nonce;
	uint32_t flags; /* Reserved; must be zero. */
	uint32_t reserved;
};
_Static_assert(sizeof(struct cap_authority_bind_invocation) == 32,
    "invocation binding has a fixed-width ABI");

/* Issuer-only current observation through a held process descriptor. Install
 * an exit/exec watch before checking to cover changes since receive metadata
 * was captured. Success is not a lease: later operations still need invocation
 * binding and independent lifetime enforcement. Requires CAP_PDGETPID. */
struct cap_authority_check_invocation {
	int32_t token_fd;
	int32_t process_fd;
	uint64_t process_identity;
	uint64_t execution_nonce;
	uint32_t flags; /* Reserved; must be zero. */
	uint32_t reserved;
};
_Static_assert(sizeof(struct cap_authority_check_invocation) == 32,
    "invocation check has a fixed-width ABI");

/* A messaging-channel lifetime is independent of software authority. The
 * issuer retains control_fd; owner_fd is delivered once to the authenticator.
 * Last close of either file, issuer loss, or the monotonic deadline revokes
 * every bound endpoint. Binding is immutable and does not replace software
 * or invocation restrictions. Owner and control descriptors cannot fork/exec.
 */
#define CAP_AUTH_LEASE_SECONDS_MAX 86400U
struct cap_authority_lease_create {
	uint32_t seconds;
	uint32_t flags;
	uint64_t reserved;
	int32_t control_fd; /* output */
	int32_t owner_fd;   /* output: one permitted delivery, then nontransferable */
};
struct cap_authority_lease_bind {
	int32_t lease_fd;
	int32_t capability_fd;
	uint32_t flags;
	uint32_t reserved;
};
_Static_assert(sizeof(struct cap_authority_lease_create) == 24,
    "lease creation has a fixed-width ABI");
_Static_assert(sizeof(struct cap_authority_lease_bind) == 16,
    "lease binding has a fixed-width ABI");

#ifdef _KERNEL
struct mac_capability_instance;
struct cap_authority_lease;
struct thread;
/* Retain the lease object, never its owner/control file. Acquisition validates
 * issuer ownership, prison and current validity. Release may defer destruction.
 * These references do not prevent close, deadline or issuer revocation. */
int cap_authority_lease_acquire(struct thread *, int, int,
    struct cap_authority_lease **);
void cap_authority_lease_release(struct cap_authority_lease *);
bool cap_authority_lease_valid(const struct cap_authority_lease *);
void cap_authority_lease_detach(struct mac_capability_instance *);
struct proc;
struct thread;
struct ucred;
struct vnode;
struct cap_authority;
struct mac_capability_instance;

/* Immutable after publication; the enclosing object owns the authority reference.
 * This record owns no file, capability instance, or process reference. Issuance
 * validates the software issuer; it confers no storage/delegation authority.
 * Identity arguments must be kernel-observed by the trusted issuer. A zero pair
 * is a software-only binding; mandatory invocation consumers must reject it.
 * Acquire/release outside policy locks: descriptor teardown can sleep.
 */
struct cap_authority_binding {
	struct cap_authority *authority;
	uint64_t process_identity;
	uint64_t execution_nonce;
};
int cap_authority_binding_acquire(struct thread *, int, int, uint64_t, uint64_t,
    struct cap_authority_binding *);
void cap_authority_binding_release(struct cap_authority_binding *);
int cap_authority_binding_check_locked(struct proc *,
    const struct cap_authority_binding *);
bool cap_authority_binding_matches(const struct cap_authority_binding *,
    const struct cap_authority_stamp *, uint64_t, uint64_t);

/* A dependency observes another invocation without retaining its process or
 * descriptors. NULL means no dependency. Acquire outside policy locks; valid
 * is lock-free; release outside policy locks. Revocation stops
 * later admissions, not already admitted operations. */
struct cap_authority_invocation;
int cap_authority_invocation_acquire(struct thread *, int,
    const struct cap_authority_check_invocation *, struct cap_authority_invocation **);
bool cap_authority_invocation_valid(const struct cap_authority_invocation *);
void cap_authority_invocation_release(struct cap_authority_invocation *);
void cap_authority_invocation_invalidate_locked(struct proc *);

int cap_authority_call(struct thread *, int, int, void *);
int cap_authority_debug_check(struct proc *, struct proc *);
struct cap_authority *cap_authority_exec_prepare(struct proc *, struct vnode *);
void cap_authority_exec(struct proc *, struct vnode *, struct cap_authority *);
void cap_authority_fork(struct proc *, struct proc *);
void cap_authority_exit(struct proc *);
void cap_authority_cred_changed(struct proc *, const struct ucred *,
    const struct ucred *);
void cap_authority_info_locked(struct proc *, struct cap_authority_info *);
/* Running an image pinned in its valid managed grant; takes the PROC lock. */
bool cap_authority_runs_pinned_image(struct proc *);
struct cap_authority *cap_authority_hold_locked(struct proc *);
void cap_authority_drop(struct cap_authority *);
void cap_authority_retain(struct cap_authority *);
/* Object lifetime only; not software or invocation admission. NULL is unbound. */
bool cap_authority_is_revoked(const struct cap_authority *);
/* Compare only kernel-produced snapshots; this does not authenticate user input. */
bool cap_authority_matches_stamp(const struct cap_authority *,
    const struct cap_authority_stamp *);
int cap_authority_check(struct thread *, struct cap_authority *);
int cap_authority_check_locked(struct proc *, struct cap_authority *);
void cap_authority_stamp_locked(struct proc *, struct cap_authority_stamp *);
#endif
#endif
