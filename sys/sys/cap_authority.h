/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _SYS_CAP_AUTHORITY_H_
#define _SYS_CAP_AUTHORITY_H_

#include <sys/types.h>

/* Operations on cap_process(2); none accepts a caller-selected identity. */
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

/* Pinned, issuer-verified library cache. PREPARE pins a read-only backing
 * vnode and returns a private-mapping descriptor. PUBLISH atomically selects
 * that descriptor after userspace verifies its signature. GET selects only a
 * directory vnode explicitly bound by the issuer. No path/env grants. */
#define CAP_CACHE_PREPARE 22
#define CAP_CACHE_PUBLISH 23
#define CAP_CACHE_GET 24
struct cap_cache_prepare {
	int32_t backing_fd;
	int32_t directory_fds[2];
	uint32_t reserved;
};
struct cap_cache_publish {
	int32_t cache_fd;
	uint32_t reserved;
};
struct cap_cache_result {
	uint32_t directory;
	uint32_t reserved;
};

/* Optional domain membership is bound by the issuer to a process authority.
 * GET operations ignore environment and accept fd == -1 only. All descriptors
 * returned by GET are fresh and owned by the caller, not bootstrap fd slots. */
#define CAP_CACHE_DOMAIN_CREATE     25
#define CAP_CACHE_DOMAIN_BIND       26
#define CAP_CACHE_DOMAIN_GET_LAYOUT 27
#define CAP_CACHE_DOMAIN_GET_RELRO  28
#define CAP_CACHE_DOMAIN_PUBLISH    29
#define CAP_CACHE_DOMAIN_SEED       0x00000001U
#define CAP_CACHE_DOMAIN_READY      0x00000002U
struct cap_cache_domain_create {
	int32_t cache_fd;
	int32_t layout_fd;
	int32_t relro_fd;
	uint32_t reserved;
};
struct cap_cache_domain_bind {
	int32_t token_fd;
	int32_t domain_fd;
	uint32_t flags; /* zero for reader, CAP_CACHE_DOMAIN_SEED for seed */
	uint32_t reserved;
};
struct cap_cache_domain_publish {
	int32_t domain_fd;
	uint32_t reserved;
};
struct cap_cache_domain_result {
	uint64_t domain_id;
	uint64_t domain_base;
	uint64_t cache_device;
	uint64_t cache_inode;
	uint64_t cache_size;
	uint32_t flags;
	uint32_t reserved;
};
_Static_assert(sizeof(struct cap_cache_domain_result) == 48,
    "cache domain result ABI");

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

#ifdef _KERNEL
struct proc;
struct thread;
struct ucred;
struct vnode;
struct cap_authority;
struct mac_capability_instance;

int cap_authority_call(struct thread *, int, int, void *);
int cap_authority_debug_check(struct proc *, struct proc *);
struct cap_authority *cap_authority_exec_prepare(struct proc *, struct vnode *);
void cap_authority_exec(struct proc *, struct vnode *, struct cap_authority *);
void cap_authority_fork(struct proc *, struct proc *);
void cap_authority_exit(struct proc *);
void cap_authority_cred_changed(struct proc *, const struct ucred *,
    const struct ucred *);
void cap_authority_info_locked(struct proc *, struct cap_authority_info *);
struct cap_authority *cap_authority_hold_locked(struct proc *);
void cap_authority_drop(struct cap_authority *);
void cap_authority_retain(struct cap_authority *);
int cap_authority_check(struct thread *, struct cap_authority *);
int cap_authority_check_locked(struct proc *, struct cap_authority *);
void cap_authority_stamp_locked(struct proc *, struct cap_authority_stamp *);
#endif
#endif
