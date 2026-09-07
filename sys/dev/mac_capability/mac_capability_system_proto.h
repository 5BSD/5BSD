/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * mac_capability_system — wire protocol for system operation gating.
 *
 * Shared between kernel and userspace.  Include this header to
 * construct MAC_CAPABILITY_CALL requests for the "system" service.
 *
 * PURPOSE
 *
 * Gate privileged system operations so that only authorized
 * nonces can perform them.  Even root is denied unless holding
 * an authorized token.
 *
 * OPERATIONS
 *
 *   SYS_OP_CLAIM
 *     Claim one or more system operations.  The caller's nonce
 *     becomes the owner.  Once claimed, the MACF hooks deny
 *     the operation to all foreign nonces.  Same-nonce processes
 *     (the fork family) can perform the operation freely.
 *
 *   SYS_OP_RELEASE
 *     Release previously claimed operations.
 *
 *   SYS_OP_MINT
 *     Create an access token fd.  The token, when authorized,
 *     grants the holder's nonce permission to perform the
 *     claimed operations.  Returned as a reply fd.
 *
 *   SYS_OP_AUTHORIZE
 *     Called on a token fd.  Adds the caller's nonce to the
 *     authorized set.  Authorization persists while the token
 *     fd is open.
 *
 * GATED OPERATIONS
 *
 *   SYS_GATE_KLDLOAD    — kernel module loading
 *   SYS_GATE_KLDUNLOAD  — kernel module unloading
 *   (module enumeration — kldstat/kldfind/modfind — is deliberately
 *    ungated: read-only kld queries are required by the DTrace toolchain)
 *   SYS_GATE_REBOOT     — system reboot/halt/poweroff
 *   SYS_GATE_SWAPON     — adding swap devices
 *   SYS_GATE_SWAPOFF    — removing swap devices
 *   SYS_GATE_SYSCTL     — security-relevant sysctl writes
 *   SYS_GATE_KENV       — kernel environment modification
 *   SYS_GATE_ACCT       — process accounting control
 */

#ifndef _DEV_MAC_CAPABILITY_MAC_CAPABILITY_SYSTEM_PROTO_H_
#define _DEV_MAC_CAPABILITY_MAC_CAPABILITY_SYSTEM_PROTO_H_

#include <sys/types.h>
#include <sys/sysctl.h>	/* CTL_MAXNAME */

/* Service operations */
#define	SYS_OP_CLAIM		1
#define	SYS_OP_RELEASE		2
#define	SYS_OP_MINT		3
#define	SYS_OP_AUTHORIZE	4

/* Gated operation bitmask */
#define	SYS_GATE_KLDLOAD	0x0001
#define	SYS_GATE_KLDUNLOAD	0x0002
/*
 * 0x0004 (formerly a module-enumeration gate) is RETIRED and must not be
 * reassigned: enumeration is deliberately ungated, and a claim carrying
 * the old bit is rejected as unknown (fail-closed).
 */
#define	SYS_GATE_REBOOT		0x0008
#define	SYS_GATE_SWAPON		0x0010
#define	SYS_GATE_SWAPOFF	0x0020
#define	SYS_GATE_SYSCTL		0x0040
#define	SYS_GATE_KENV		0x0080
#define	SYS_GATE_ACCT		0x0100
#define	SYS_GATE_AUDIT		0x0200	/* auditon + auditctl */
#define	SYS_GATE_KENV_READ	0x0400	/* kenv get + dump */
#define	SYS_GATE_ALL		0x07fb	/* all known gates; 0x0004 retired */

struct sys_request {
	uint32_t	op;
	uint32_t	gates;		/* SYS_GATE_* bitmask */
} __packed;

/*
 * Per-OID sysctl isolation (Phase 1).
 *
 * A SYS_OP_CLAIM whose gates include SYS_GATE_SYSCTL MAY append a
 * sys_sysctl_oidset immediately after the fixed sys_request header.  The kernel
 * detects the payload by req_len > sizeof(struct sys_request):
 *
 *   - No payload (req_len == sizeof(struct sys_request)) => COARSE mode: the
 *     SYSCTL gate isolates EVERY privileged sysctl write, exactly as today.
 *   - A payload is present => SCOPED mode: only the OIDs listed in the set are
 *     isolated; every other sysctl stays directly writable (subject to the
 *     kernel's own PRIV_SYSCTL_WRITE check).
 *
 * An isolated OID is named by its MIB (the int[] array, e.g. the mib for
 * kern.maxfiles), bounded by CTL_MAXNAME.  The kernel compares the accessed
 * OID's MIB (reconstructed by walking SYSCTL_PARENT from the leaf) against the
 * claimed set by exact int-array compare.
 *
 * Full CLAIM payload with OIDs, on the wire:
 *
 *     struct sys_request		(op = SYS_OP_CLAIM, gates has SYS_GATE_SYSCTL)
 *     struct sys_sysctl_oidset	(noids, followed by noids sys_sysctl_oid)
 *
 * so the total length is
 *     sizeof(struct sys_request) + sizeof(uint32_t) +
 *         noids * sizeof(struct sys_sysctl_oid)
 * and the kernel validates req_len against that exactly (fail-closed).
 */
#define	SYS_OID_MAXDEPTH	CTL_MAXNAME	/* 24 */
#define	SYS_SYSCTL_MAXOIDS	64		/* per-claim isolated-OID cap */

struct sys_sysctl_oid {
	uint32_t	depth;			/* 1..SYS_OID_MAXDEPTH */
	int		mib[SYS_OID_MAXDEPTH];
} __packed;

struct sys_sysctl_oidset {
	uint32_t		noids;		/* 1..SYS_SYSCTL_MAXOIDS */
	struct sys_sysctl_oid	oids[];		/* noids entries */
} __packed;

#endif /* _DEV_MAC_CAPABILITY_MAC_CAPABILITY_SYSTEM_PROTO_H_ */
