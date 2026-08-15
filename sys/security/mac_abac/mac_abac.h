/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SECURITY_MAC_ABAC_H_
#define _SECURITY_MAC_ABAC_H_

/*
 * ABAC MAC Policy Module
 *
 * A label-based Mandatory Access Control policy for FreeBSD that stores
 * security labels in extended attributes and enforces access control
 * based on configurable rules.
 */

/*
 * Extended attribute configuration
 */
#define ABAC_EXTATTR_NAMESPACE	EXTATTR_NAMESPACE_SYSTEM
#define ABAC_EXTATTR_NAME		"mac_abac"

/*
 * Label constraints
 *
 * Labels are stored as newline-separated key=value pairs in extended attributes:
 *   "key1=val1\nkey2=val2\n"
 *
 * Patterns (in rules) use comma-separated format for command-line convenience:
 *   "key1=val1,key2=val2"
 *
 * ABAC_MAX_LABEL_LEN (4096 bytes):
 *   Soft limit for labels stored in extended attributes. Extended attributes
 *   have filesystem-specific limits (UFS/ZFS support 64KB+), but 4KB is
 *   sufficient for any realistic label. Larger labels would indicate policy
 *   design issues.
 *
 * ABAC_MAX_KEY_LEN (64 bytes):
 *   Maximum key name length. Keys are typically short identifiers like
 *   "type", "domain", "sensitivity". 64 bytes provides ample headroom.
 *
 * ABAC_MAX_VALUE_LEN (256 bytes):
 *   Maximum value length. Values like application names, domains, or
 *   classification levels rarely exceed 64 bytes, but 256 allows for
 *   descriptive values and future flexibility.
 *
 * ABAC_MAX_PAIRS (16):
 *   Maximum key=value pairs per label. Analysis of real policies shows
 *   most labels use 1-6 pairs. 16 provides headroom for complex labels
 *   while keeping struct abac_label around 5KB.
 *
 *   Memory impact: sizeof(abac_label) = 16 + 16*(64+256) = ~5KB
 *   This is acceptable because labels are cached per-vnode/cred in UMA zones.
 */
#define ABAC_MAX_LABEL_LEN		4096	/* Soft limit for extattr labels */
#define ABAC_MAX_KEY_LEN		64	/* Max key length */
#define ABAC_MAX_VALUE_LEN		256	/* Max value length */
#define ABAC_MAX_PAIRS		16	/* Max key=value pairs per label */

/*
 * Rule constraints (system-wide limits)
 *
 * ABAC_MAX_RULES:
 *   Maximum rules loaded in the kernel. Rules are evaluated in order
 *   (first-match semantics like pf).
 *
 *   Memory impact with compact rules (~2.1KB each):
 *   - 1024 rules: ~2.1 MB
 *   - 4096 rules: ~8.5 MB
 *   - 16384 rules: ~34 MB
 *
 * ABAC_RULE_MAX_PAIRS (8):
 *   Maximum key=value pairs per rule pattern. Analysis of real policies
 *   shows most patterns use 1-4 pairs. 8 provides headroom while keeping
 *   rule structs compact. File labels still support 16 pairs.
 *
 * ABAC_RULE_KEY_LEN (64):
 *   Maximum key length in rule patterns. Same as file labels.
 *
 * ABAC_RULE_VALUE_LEN (64):
 *   Maximum value length in rule patterns. Reduced from 256 (file labels)
 *   because rule pattern values are typically short (type names, domains).
 *   Longest observed in real policies: ~21 characters.
 */
#define ABAC_MAX_RULES		4096	/* Max rules in kernel */
#define ABAC_RULE_MAX_PAIRS		8	/* Max pairs per rule pattern */
#define ABAC_RULE_KEY_LEN		64	/* Max key length in rules */
#define ABAC_RULE_VALUE_LEN		64	/* Max value length in rules */

/*
 * Rule set constraints (IPFW-style)
 *
 * Rules are organized into sets (0-65535). Sets are evaluated in order:
 * set 0 first, then set 1, etc. This allows layered policies where
 * lower-numbered sets have higher priority.
 *
 * Sets can be enabled/disabled without removing rules, useful for:
 * - Temporarily disabling application-specific policies
 * - Hot-reloading policies via set swap
 * - Maintenance mode
 */
#define ABAC_MAX_SETS			65536	/* 2^16 sets */
#define ABAC_SET_DEFAULT		0	/* Default set for new rules */
#define ABAC_SET_BITMAP_SIZE		(ABAC_MAX_SETS / 8)  /* 8KB */

/*
 * Operations bitmask for rule matching
 */
#define ABAC_OP_EXEC			0x00000001
#define ABAC_OP_READ			0x00000002
#define ABAC_OP_WRITE			0x00000004
#define ABAC_OP_MMAP			0x00000008
#define ABAC_OP_LINK			0x00000010
#define ABAC_OP_RENAME		0x00000020
#define ABAC_OP_UNLINK		0x00000040
#define ABAC_OP_CHDIR			0x00000080
#define ABAC_OP_STAT			0x00000100
#define ABAC_OP_READDIR		0x00000200
#define ABAC_OP_CREATE		0x00000400
#define ABAC_OP_SETEXTATTR		0x00000800
#define ABAC_OP_GETEXTATTR		0x00001000
#define ABAC_OP_LOOKUP		0x00002000
#define ABAC_OP_OPEN			0x00004000
#define ABAC_OP_ACCESS		0x00008000
#define ABAC_OP_DEBUG			0x00010000	/* ptrace/procfs debug */
#define ABAC_OP_SIGNAL		0x00020000	/* kill/signal */
#define ABAC_OP_SCHED			0x00040000	/* scheduler operations */
#define ABAC_OP_CONNECT		0x00080000	/* socket connect */
#define ABAC_OP_BIND			0x00100000	/* socket bind */
#define ABAC_OP_LISTEN		0x00200000	/* socket listen */
#define ABAC_OP_ACCEPT		0x00400000	/* socket accept */
#define ABAC_OP_SEND			0x00800000	/* socket send */
#define ABAC_OP_RECEIVE		0x01000000	/* socket receive */
#define ABAC_OP_WAIT			0x02000000	/* wait4() on process */
#define ABAC_OP_MPROTECT		0x04000000	/* mprotect() */
#define ABAC_OP_AUDIT			0x08000000	/* BSM audit operations */
#define ABAC_OP_DELIVER		0x10000000	/* packet delivery to socket */
#define ABAC_OP_ALL			0x1FFFFFFF

/*
 * Rule actions
 */
#define ABAC_ACTION_ALLOW		0
#define ABAC_ACTION_DENY		1
#define ABAC_ACTION_TRANSITION	2	/* Allow and transition to new label */

/*
 * Enforcement modes
 */
#define ABAC_MODE_DISABLED		0
#define ABAC_MODE_PERMISSIVE		1	/* Log but don't enforce */
#define ABAC_MODE_ENFORCING		2

/*
 * Context assertion flags
 *
 * Note: UID and RUID both use vc_uid field, so they cannot be used
 * simultaneously in the same rule. Use UID for effective UID checks
 * or RUID for real UID checks, but not both.
 */
#define ABAC_CTX_CAP_SANDBOXED	0x00000001
#define ABAC_CTX_JAIL			0x00000002
#define ABAC_CTX_UID			0x00000004	/* Effective UID */
#define ABAC_CTX_GID			0x00000008	/* Effective GID */
#define ABAC_CTX_RUID			0x00000020	/* Real UID (uses vc_uid) */
#define ABAC_CTX_HAS_TTY		0x00000080

/*
 * Pattern match flags
 *
 * Patterns now match against arbitrary key=value pairs in the label string.
 * The old hardcoded type/domain/name/level fields are removed.
 */
#define ABAC_MATCH_NEGATE		0x80000000	/* Invert match result */

/*
 * Label flags
 *
 * Reserved for future use. The NEEDS_LOAD functionality is now handled
 * via a sentinel pointer value (ABAC_LABEL_NEEDS_LOAD) rather than a flag,
 * which avoids allocating memory for labels that don't exist.
 */

/*
 * Statistics structure (shared with userland)
 */
struct abac_stats {
	uint64_t	vs_checks;		/* Total access checks */
	uint64_t	vs_allowed;		/* Allowed accesses */
	uint64_t	vs_denied;		/* Denied accesses */
	uint64_t	vs_labels_read;		/* Labels read from extattr */
	uint64_t	vs_labels_default;	/* Default labels assigned */
	uint32_t	vs_rule_count;		/* Current rule count */
};

/*
 * Parser I/O structures
 *
 * These structures use fixed-size arrays for the daemon/CLI parser.
 * The syscall API uses variable-length data, so abacctl converts
 * between formats when communicating with the kernel.
 *
 * ABAC_PATTERN_MAX_LEN must accommodate the maximum parseable pattern:
 * ABAC_RULE_MAX_PAIRS pairs, each with key=value plus separator.
 */
#define ABAC_PATTERN_MAX_LEN	(ABAC_RULE_MAX_PAIRS * (ABAC_RULE_KEY_LEN + ABAC_RULE_VALUE_LEN + 2))

struct abac_pattern_io {
	uint32_t	vp_flags;
	char		vp_pattern[ABAC_PATTERN_MAX_LEN];
};

struct abac_context_io {
	uint32_t	vc_flags;
	uint8_t		vc_cap_sandboxed;
	uint8_t		vc_has_tty;
	uint8_t		vc_padding[2];
	int32_t		vc_jail_check;
	uint32_t	vc_uid;
	uint32_t	vc_gid;
};

struct abac_rule_io {
	uint32_t		vr_id;
	uint8_t			vr_action;
	uint8_t			vr_padding;
	uint16_t		vr_set;		/* Rule set (0-65535) */
	uint32_t		vr_operations;
	struct abac_pattern_io vr_subject;
	struct abac_pattern_io vr_object;
	struct abac_context_io vr_subj_context;  /* Subject context (caller) */
	struct abac_context_io vr_obj_context;   /* Object context (target) */
	char			vr_newlabel[ABAC_PATTERN_MAX_LEN];
};

/*
 * mac_syscall() command numbers
 *
 * Usage: mac_syscall("mac_abac", ABAC_SYS_*, arg)
 *
 * All commands require root (uid 0).
 */
#define ABAC_SYS_GETMODE	1	/* arg: int* (out) */
#define ABAC_SYS_SETMODE	2	/* arg: int* (in) */
#define ABAC_SYS_GETSTATS	5	/* arg: struct abac_stats* (out) */
#define ABAC_SYS_GETDEFPOL	6	/* arg: int* (out) */
#define ABAC_SYS_SETDEFPOL	7	/* arg: int* (in) */

#define ABAC_SYS_RULE_ADD	10	/* arg: struct abac_rule_arg* (in) */
#define ABAC_SYS_RULE_REMOVE	11	/* arg: uint32_t* (in: rule_id) */
#define ABAC_SYS_RULE_CLEAR	12	/* arg: NULL */
#define ABAC_SYS_RULE_LIST	13	/* arg: struct abac_rule_list_arg* (in/out) */
#define ABAC_SYS_RULE_LOAD	14	/* arg: struct abac_rule_load_arg* (in) - atomic replace */

#define ABAC_SYS_TEST		20	/* arg: struct abac_test_arg* (in/out) */
#define ABAC_SYS_REFRESH	21	/* arg: int* (in: file descriptor) */
#define ABAC_SYS_SETLABEL	22	/* arg: struct abac_setlabel_arg* (in) */

/* Rule set operations (IPFW-style) */
#define ABAC_SYS_SET_ENABLE	23	/* arg: struct abac_set_range* */
#define ABAC_SYS_SET_DISABLE	24	/* arg: struct abac_set_range* */
#define ABAC_SYS_SET_SWAP	25	/* arg: uint16_t[2] {set_a, set_b} */
#define ABAC_SYS_SET_MOVE	26	/* arg: uint16_t[2] {from, to} */
#define ABAC_SYS_SET_CLEAR	27	/* arg: uint16_t* (set number) */
#define ABAC_SYS_SET_LIST	28	/* arg: struct abac_set_list_arg* */

/* Locked mode - prevents policy changes until reboot */
#define ABAC_SYS_LOCK		30	/* arg: NULL - one-way lock */
#define ABAC_SYS_GETLOCKED	31	/* arg: int* (out: 1=locked, 0=unlocked) */

/* Logging operations */
#define ABAC_SYS_GETLOGLEVEL	32	/* arg: int* (out) */
#define ABAC_SYS_SETLOGLEVEL	33	/* arg: int* (in) */

/*
 * Log levels for abac audit/logging
 *
 * These control what gets logged to the kernel message buffer (dmesg)
 * and syslog. Higher levels include all lower levels.
 *
 * Default: ABAC_LOG_ADMIN (log admin actions, not access checks)
 */
#define ABAC_LOG_NONE		0	/* No logging */
#define ABAC_LOG_ERROR	1	/* Errors only */
#define ABAC_LOG_ADMIN	2	/* Admin actions (rule/mode changes) */
#define ABAC_LOG_DENY		3	/* + Access denials */
#define ABAC_LOG_ALL		4	/* + All access checks (verbose) */

/*
 * Context constraints for rules (shared between kernel and userland)
 *
 * Rules can have two independent context constraints:
 *
 * Subject context (vr_subj_context): checked against the CALLER
 *   - CLI syntax: ctx:key=value (before the -> arrow)
 *   - UCL syntax: subj_ctx = { key = value; }
 *   - Useful for: "only root can do X", "only host processes can do Y"
 *
 * Object context (vr_obj_context): checked against the TARGET
 *   - CLI syntax: ctx:key=value (after the -> arrow)
 *   - UCL syntax: obj_ctx = { key = value; }
 *   - Useful for: "can't debug sandboxed processes", "can't signal jailed procs"
 *   - Only meaningful for process operations (debug, signal, sched)
 *
 * Both contexts are optional (vc_flags=0 means match anything).
 * Both can be specified on the same rule.
 *
 * Examples:
 *   deny debug * -> * ctx:sandboxed=true
 *     - Protects processes in capability mode from being debugged
 *
 *   deny signal * ctx:jail=any -> * ctx:jail=host
 *     - Prevents jailed processes from signaling host processes
 *
 *   allow exec type=admin ctx:jail=host,uid=0 -> *
 *     - Only root on host can run admin binaries
 */
struct abac_context_arg {
	uint32_t	vc_flags;		/* Which checks are enabled */
	uint8_t		vc_cap_sandboxed;	/* true=must be sandboxed */
	uint8_t		vc_has_tty;		/* true=must have tty */
	uint8_t		vc_padding[2];
	int32_t		vc_jail_check;		/* 0=host, >0=jail id, -1=any jail */
	uint32_t	vc_uid;			/* Required UID */
	uint32_t	vc_gid;			/* Required GID */
};

/*
 * Rule add argument - variable length strings
 *
 * Pattern format: "key1=value1,key2=value2,..."
 *   "*"           - matches anything
 *   "type=app"    - must have type=app
 *   "!type=bad"   - must NOT have type=bad
 *
 * Layout in memory:
 *   struct abac_rule_arg header
 *   char subject[vr_subject_len]   (null-terminated)
 *   char object[vr_object_len]     (null-terminated)
 *   char newlabel[vr_newlabel_len] (null-terminated, only for TRANSITION)
 */
struct abac_rule_arg {
	uint32_t		vr_id;		/* Out: assigned rule ID */
	uint8_t			vr_action;	/* ALLOW/DENY/TRANSITION */
	uint8_t			vr_reserved;
	uint16_t		vr_set;		/* Rule set (0-65535) */
	uint32_t		vr_operations;	/* Operation bitmask */
	uint32_t		vr_subject_flags; /* ABAC_MATCH_NEGATE, etc */
	uint32_t		vr_object_flags;
	struct abac_context_arg vr_subj_context;  /* Subject context constraints */
	struct abac_context_arg vr_obj_context;   /* Object context constraints */
	uint16_t		vr_subject_len;	/* Length including null */
	uint16_t		vr_object_len;
	uint16_t		vr_newlabel_len; /* 0 if not transition */
	uint16_t		vr_reserved2;
	/* Variable data follows: subject, object, newlabel */
};

/*
 * Rule output for listing - also variable length
 *
 * Same layout as abac_rule_arg but with rule ID
 */
struct abac_rule_out {
	uint32_t		vr_id;		/* Rule ID */
	uint8_t			vr_action;
	uint8_t			vr_reserved;
	uint16_t		vr_set;		/* Rule set (0-65535) */
	uint32_t		vr_operations;
	uint32_t		vr_subject_flags;
	uint32_t		vr_object_flags;
	struct abac_context_arg vr_subj_context;  /* Subject context constraints */
	struct abac_context_arg vr_obj_context;   /* Object context constraints */
	uint16_t		vr_subject_len;
	uint16_t		vr_object_len;
	uint16_t		vr_newlabel_len;
	uint16_t		vr_reserved2;
	/* Variable data follows */
};

/*
 * Rule list argument
 *
 * To list rules:
 *   1. Call with vrl_buf=NULL, vrl_buflen=0 to get vrl_total
 *   2. Allocate buffer of appropriate size
 *   3. Call again with buffer to get rules
 *
 * Rules are packed as abac_rule_out structures with variable data.
 */
struct abac_rule_list_arg {
	uint32_t	vrl_total;	/* Out: total rules in kernel */
	uint32_t	vrl_count;	/* Out: rules copied to buffer */
	uint32_t	vrl_offset;	/* In: starting offset */
	uint32_t	vrl_buflen;	/* In: buffer size */
	void		*vrl_buf;	/* In: buffer for rules (userland pointer) */
};

/*
 * Rule load argument - atomic rule replacement (like PF's pfctl -f)
 *
 * Buffer contains packed abac_rule_arg structures with their variable data.
 * Each rule is: struct abac_rule_arg + subject + object + newlabel
 *
 * On success, all existing rules are cleared and replaced with the new set.
 * On failure, existing rules remain unchanged.
 */
struct abac_rule_load_arg {
	uint32_t	vrl_count;	/* In: number of rules in buffer */
	uint32_t	vrl_buflen;	/* In: total buffer size */
	uint32_t	vrl_loaded;	/* Out: rules successfully loaded */
	uint32_t	vrl_reserved;
	void		*vrl_buf;	/* In: buffer with packed rules */
};

/*
 * Test access argument - variable length strings
 *
 * Layout:
 *   struct abac_test_arg header
 *   char subject[vt_subject_len]
 *   char object[vt_object_len]
 */
struct abac_test_arg {
	uint32_t	vt_operation;		/* Operation to test */
	uint32_t	vt_result;		/* Out: 0=allow, EACCES=deny */
	uint32_t	vt_rule_id;		/* Out: matching rule ID (0=default) */
	uint16_t	vt_subject_len;		/* Length including null */
	uint16_t	vt_object_len;
	/* Variable data follows: subject, object */
};

/*
 * Set label argument - atomic set + refresh for ZFS/single-label filesystems
 *
 * This syscall atomically:
 *   1. Writes the new label to the file's extended attribute
 *   2. Updates the in-memory cached label on the vnode
 *
 * This avoids the race condition of separate setextattr + refresh calls
 * and is required for filesystems like ZFS that don't use mac_vnode_setlabel().
 *
 * Layout in memory:
 *   struct abac_setlabel_arg header
 *   char label[vsl_label_len]   (null-terminated label string)
 */
struct abac_setlabel_arg {
	int32_t		vsl_fd;			/* File descriptor */
	uint16_t	vsl_label_len;		/* Length including null */
	uint16_t	vsl_reserved;
	/* Variable data follows: label string */
};

/*
 * Rule set operations (IPFW-style)
 */
struct abac_set_range {
	uint16_t	vsr_start;		/* First set in range */
	uint16_t	vsr_end;		/* Last set in range (inclusive) */
};

/*
 * Rule set list argument - query set status
 *
 * Results are paginated: each call returns up to 256 sets.
 * Call multiple times with increasing vsl_start to query all 65536 sets.
 */
struct abac_set_list_arg {
	uint16_t	vsl_start;		/* In: first set to query */
	uint16_t	vsl_count;		/* In: how many sets (max 256) */
	uint32_t	vsl_rule_counts[256];	/* Out: rules per set */
	uint8_t		vsl_enabled[32];	/* Out: enabled bitmap (256 bits) */
};

#ifdef _KERNEL

#include <sys/types.h>

/*
 * Key-value pair for parsed labels
 */
struct abac_pair {
	char		vp_key[ABAC_MAX_KEY_LEN];
	char		vp_value[ABAC_MAX_VALUE_LEN];
};

/*
 * Label structure - stored in MAC label slot
 *
 * Labels are stored as parsed key-value pairs.
 * The raw string can be reconstructed via abac_label_to_string().
 *
 * Example: "type=app\ndomain=web\nsensitivity=secret\n"
 * Parses to: pairs[0]={type,app}, pairs[1]={domain,web}, pairs[2]={sensitivity,secret}
 */
struct abac_label {
	uint32_t		vl_hash;			/* Quick compare hash */
	uint32_t		vl_npairs;			/* Number of valid pairs */
	uint32_t		vl_flags;			/* ABAC_LABEL_* flags */
	uint32_t		vl_reserved;			/* Padding for alignment */
	struct abac_pair	vl_pairs[ABAC_MAX_PAIRS];	/* Parsed key=value pairs */
};

/*
 * Compact key-value pair for rule patterns
 *
 * Smaller than abac_pair (128 bytes vs 320 bytes) because rule patterns
 * don't need the same value capacity as file labels. Keys and values in
 * rule patterns are typically short identifiers.
 */
struct abac_rule_pair {
	char	vrp_key[ABAC_RULE_KEY_LEN];		/* 64 bytes */
	char	vrp_value[ABAC_RULE_VALUE_LEN];	/* 64 bytes */
};
/* Size: 128 bytes */

/*
 * Compact pattern for rule matching
 *
 * Uses 8 pairs (vs 16) with smaller key/value sizes. This reduces
 * per-rule memory from ~10KB (2 patterns) to ~2KB while covering
 * all realistic rule patterns.
 *
 * Analysis of real policies shows patterns typically use 1-4 pairs.
 * 8 pairs provides ample headroom.
 */
struct abac_rule_pattern {
	uint32_t		vrp_flags;			/* ABAC_MATCH_NEGATE */
	uint32_t		vrp_npairs;			/* Number of pairs */
	struct abac_rule_pair	vrp_pairs[ABAC_RULE_MAX_PAIRS];
};
/* Size: 8 + 8*128 = 1,032 bytes */

/*
 * Context constraints for rules
 *
 * vc_jail_check interpretation:
 *   0  = must be on host (not in a jail)
 *   >0 = must be in specific jail with this ID
 *   -1 = must be in any jail (not host)
 *   -2 = don't check jail (wildcard) - only valid if ABAC_CTX_JAIL not set
 */
struct abac_context {
	uint32_t	vc_flags;		/* Which checks are enabled */
	bool		vc_cap_sandboxed;	/* true=must be sandboxed, false=must not */
	bool		vc_has_tty;		/* true=must have tty, false=must not */
	int		vc_jail_check;		/* See above */
	uid_t		vc_uid;			/* Required UID (for UID/RUID checks) */
	gid_t		vc_gid;			/* Required GID */
};

/*
 * Access control rule (compact version)
 *
 * Uses abac_rule_pattern (1KB each) instead of abac_pattern (5KB each),
 * reducing per-rule memory from ~19KB to ~2.1KB.
 *
 * Transition labels are allocated separately (vr_newlabel pointer) rather
 * than embedded, saving ~5KB for non-transition rules.
 *
 * Size breakdown:
 *   - vr_id, vr_action, vr_operations: ~12 bytes
 *   - vr_subject (abac_rule_pattern): 1,032 bytes
 *   - vr_object (abac_rule_pattern): 1,032 bytes
 *   - vr_subj_context, vr_obj_context: ~48 bytes
 *   - vr_newlabel (pointer): 8 bytes
 *   Total: ~2,132 bytes (non-transition)
 *
 * For transition rules, vr_newlabel points to a separately allocated
 * abac_label (~5KB). This is freed when the rule is removed.
 */
struct abac_rule {
	uint32_t		  vr_id;	   /* Rule identifier */
	uint8_t			  vr_action;	   /* ALLOW, DENY, or TRANSITION */
	uint8_t			  vr_reserved;
	uint16_t		  vr_set;	   /* Rule set (0-65535) */
	uint32_t		  vr_operations;   /* Bitmask of operations */
	struct abac_rule_pattern vr_subject;	   /* Subject (process) pattern */
	struct abac_rule_pattern vr_object;	   /* Object (file) pattern */
	struct abac_context	  vr_subj_context; /* Subject context constraints */
	struct abac_context	  vr_obj_context;  /* Object context constraints */
	struct abac_label	 *vr_newlabel;	   /* Transition label (or NULL) */
};

/*
 * Slot accessor macro - retrieves our label from a MAC label structure
 *
 * IMPORTANT: Always NULL-check the result before use!
 */
extern int abac_slot;

#define SLOT(l)		((struct abac_label *)mac_label_get((l), abac_slot))
#define SLOT_SET(l, v)	mac_label_set((l), abac_slot, (intptr_t)(v))

/*
 * Sentinel value for lazy-load vnodes (ZFS/singlelabel filesystems).
 *
 * Slot values:
 *   NULL                    = no label, use abac_default_object
 *   ABAC_LABEL_NEEDS_LOAD   = needs extattr read on first access
 *   valid pointer           = allocated label with parsed content
 *
 * This avoids allocating ~5KB per vnode when most have no label.
 */
#define ABAC_LABEL_NEEDS_LOAD	((struct abac_label *)(uintptr_t)1)

/*
 * Default labels for unlabeled objects/subjects
 */
extern struct abac_label abac_default_object;
extern struct abac_label abac_default_subject;

/*
 * Global configuration (exposed via sysctl)
 *
 * Note: sysctl provides synchronization. For check paths,
 * stale reads are acceptable as mode changes propagate quickly.
 */
extern int abac_enabled;
extern int abac_mode;
extern int abac_initialized;
extern int abac_default_policy;	/* 0=allow, 1=deny when no rule matches */

/*
 * Debug output - use DTrace only
 *
 * All debugging is done via DTrace probes defined in mac_abac.c.
 * See scripts/dtrace/ for tracing scripts.
 *
 * Example: dtrace -n 'abac:::check-deny { printf("%s -> %s", stringof(arg0), stringof(arg1)); }'
 */

/*
 * Common check macro - early exit if disabled or not initialized
 */
#define ABAC_CHECK_ENABLED()	do {					\
	if (!abac_initialized ||					\
	    abac_enabled == 0 || abac_mode == ABAC_MODE_DISABLED)	\
		return (0);						\
} while (0)

/*
 * Function prototypes - abac_label.c
 */
void abac_label_init(void);
void abac_label_destroy(void);
struct abac_label *abac_label_alloc(int flags);
void abac_label_free(struct abac_label *vl);
int abac_label_parse(const char *str, size_t len, struct abac_label *out);
void abac_label_copy(const struct abac_label *src, struct abac_label *dst);
void abac_label_set_default(struct abac_label *vl, bool is_subject);
const char *abac_label_get_value(const struct abac_label *vl, const char *key);
uint32_t abac_label_hash(const char *str, size_t len);
int abac_label_to_string(const struct abac_label *vl, char *buf, size_t buflen);
int abac_rule_pattern_parse(const char *str, size_t len,
    struct abac_rule_pattern *pattern);

/*
 * Function prototypes - abac_match.c
 */
bool abac_rule_pattern_match(const struct abac_label *label,
    const struct abac_rule_pattern *pattern);
bool abac_context_matches(const struct abac_context *ctx,
    struct ucred *cred, struct proc *proc);
bool abac_rule_matches(const struct abac_rule *rule,
    const struct abac_label *subj, const struct abac_label *obj,
    uint32_t op, struct ucred *subj_cred, struct proc *obj_proc);
size_t abac_rule_pattern_to_string(const struct abac_rule_pattern *pattern,
    char *buf, size_t buflen);
void abac_convert_label_format(const char *src, char *dst, size_t dstlen);

/*
 * Function prototypes - abac_rules.c
 */
void abac_rules_init(void);
void abac_rules_destroy(void);
int abac_rules_check(struct ucred *cred, struct abac_label *subj,
    struct abac_label *obj, uint32_t op, struct proc *obj_proc);
bool abac_rules_will_transition(struct ucred *cred, struct abac_label *subj,
    struct abac_label *obj);
int abac_rules_get_transition(struct ucred *cred, struct abac_label *subj,
    struct abac_label *obj, struct abac_label *newlabel);
int abac_rule_remove(uint32_t id);
void abac_rules_clear(void);
void abac_rules_get_stats(struct abac_stats *stats);

/* Set management functions */
void abac_set_enable_range(uint16_t start, uint16_t end);
void abac_set_disable_range(uint16_t start, uint16_t end);
int abac_set_swap(uint16_t set_a, uint16_t set_b);
int abac_set_move(uint16_t from_set, uint16_t to_set);
void abac_set_clear(uint16_t set);
void abac_set_get_info(struct abac_set_list_arg *arg);
void abac_rebuild_active_sets(void);

/* Set enabled bitmap (8KB for 65536 sets) */
extern uint8_t abac_set_enabled[ABAC_SET_BITMAP_SIZE];

/* Bitmap helper macros */
#define ABAC_SET_IS_ENABLED(set) \
	(abac_set_enabled[(set) / 8] & (1 << ((set) % 8)))
#define ABAC_SET_ENABLE(set) \
	(abac_set_enabled[(set) / 8] |= (1 << ((set) % 8)))
#define ABAC_SET_DISABLE(set) \
	(abac_set_enabled[(set) / 8] &= ~(1 << ((set) % 8)))

/*
 * Function prototypes - abac_syscall.c
 */
int abac_rule_add_from_arg(struct abac_rule_arg *arg, const char *data);
int abac_rules_load(struct abac_rule_load_arg *load_arg);
int abac_rules_list(struct abac_rule_list_arg *list_arg);
int abac_rules_test_access(const char *subject, size_t subject_len,
    const char *object, size_t object_len, uint32_t operation,
    uint32_t *result, uint32_t *rule_id);

/*
 * Function prototypes - abac_cred.c
 */
void abac_cred_init_label(struct label *label);
void abac_cred_destroy_label(struct label *label);
void abac_cred_copy_label(struct label *src, struct label *dest);
void abac_cred_relabel(struct ucred *cred, struct label *newlabel);
int abac_cred_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed);
int abac_cred_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed);
int abac_cred_check_relabel(struct ucred *cred, struct label *newlabel);
int abac_cred_check_setuid(struct ucred *cred, uid_t uid);
int abac_cred_check_setgid(struct ucred *cred, gid_t gid);
int abac_cred_check_setgroups(struct ucred *cred, int ngroups, gid_t *gidset);
int abac_cred_check_seteuid(struct ucred *cred, uid_t euid);
int abac_cred_check_setegid(struct ucred *cred, gid_t egid);
int abac_cred_check_setreuid(struct ucred *cred, uid_t ruid, uid_t euid);
int abac_cred_check_setregid(struct ucred *cred, gid_t rgid, gid_t egid);
int abac_cred_check_setresuid(struct ucred *cred, uid_t ruid, uid_t euid,
    uid_t suid);
int abac_cred_check_setresgid(struct ucred *cred, gid_t rgid, gid_t egid,
    gid_t sgid);
int abac_cred_check_setcred(u_int flags, const struct ucred *old_cred,
    struct ucred *new_cred);
int abac_cred_check_setaudit(struct ucred *cred, struct auditinfo *ai);
int abac_cred_check_setaudit_addr(struct ucred *cred,
    struct auditinfo_addr *aia);
int abac_cred_check_setauid(struct ucred *cred, uid_t auid);
void abac_execve_transition(struct ucred *old, struct ucred *new,
    struct vnode *vp, struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel);
int abac_execve_will_transition(struct ucred *old, struct vnode *vp,
    struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel);

/*
 * Function prototypes - abac_vnode.c
 */
void abac_vnode_init_label(struct label *label);
void abac_vnode_destroy_label(struct label *label);
void abac_vnode_copy_label(struct label *src, struct label *dest);
void abac_vnode_refresh_label(struct vnode *vp, struct label *vplabel);
void abac_vnode_lazy_load(struct vnode *vp, struct label *vplabel);
int abac_vnode_associate_extattr(struct mount *mp, struct label *mplabel,
    struct vnode *vp, struct label *vplabel);
void abac_vnode_associate_singlelabel(struct mount *mp, struct label *mplabel,
    struct vnode *vp, struct label *vplabel);
int abac_vnode_create_extattr(struct ucred *cred, struct mount *mp,
    struct label *mplabel, struct vnode *dvp, struct label *dvplabel,
    struct vnode *vp, struct label *vplabel, struct componentname *cnp);
int abac_vnode_check_access(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode);
int abac_vnode_check_chdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel);
int abac_vnode_check_chroot(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel);
int abac_vnode_check_create(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp, struct vattr *vap);
int abac_vnode_check_deleteacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type);
int abac_vnode_check_deleteextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name);
int abac_vnode_check_exec(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp, struct label *execlabel);
int abac_vnode_check_getacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type);
int abac_vnode_check_getextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name);
int abac_vnode_check_link(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp);
int abac_vnode_check_listextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace);
int abac_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp);
int abac_vnode_check_mmap(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot, int flags);
int abac_vnode_check_mprotect(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot);
int abac_vnode_check_open(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode);
int abac_vnode_check_poll(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel);
int abac_vnode_check_read(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel);
int abac_vnode_check_readdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel);
int abac_vnode_check_readlink(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
int abac_vnode_check_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel);
int abac_vnode_check_rename_from(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp);
int abac_vnode_check_rename_to(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    int samedir, struct componentname *cnp);
int abac_vnode_check_revoke(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
int abac_vnode_check_setacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type, struct acl *acl);
int abac_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name);
int abac_vnode_check_setflags(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, u_long flags);
int abac_vnode_check_setmode(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, mode_t mode);
int abac_vnode_check_setowner(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, uid_t uid, gid_t gid);
int abac_vnode_check_setutimes(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct timespec atime, struct timespec mtime);
int abac_vnode_check_stat(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel);
int abac_vnode_check_unlink(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp);
int abac_vnode_check_write(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel);
void abac_vnode_check_mmap_downgrade(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int *prot);
int abac_vnode_setlabel_extattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *intlabel);
void abac_mount_init_label(struct label *label);
void abac_mount_destroy_label(struct label *label);

/*
 * Function prototypes - abac_proc.c
 */
int abac_proc_check_debug(struct ucred *cred, struct proc *p);
int abac_proc_check_sched(struct ucred *cred, struct proc *p);
int abac_proc_check_signal(struct ucred *cred, struct proc *p, int signum);
int abac_proc_check_wait(struct ucred *cred, struct proc *p);
int abac_priv_check(struct ucred *cred, int priv);
int abac_priv_grant(struct ucred *cred, int priv);

/*
 * Function prototypes - abac_socket.c
 */
int abac_socket_init_label(struct label *label, int flag);
void abac_socket_destroy_label(struct label *label);
void abac_socket_copy_label(struct label *src, struct label *dest);
void abac_socket_create(struct ucred *cred, struct socket *so,
    struct label *solabel);
void abac_socket_newconn(struct socket *oldso, struct label *oldsolabel,
    struct socket *newso, struct label *newsolabel);
int abac_socket_check_accept(struct ucred *cred, struct socket *so,
    struct label *solabel);
int abac_socket_check_bind(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa);
int abac_socket_check_connect(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa);
int abac_socket_check_create(struct ucred *cred, int domain, int type,
    int protocol);
int abac_socket_check_listen(struct ucred *cred, struct socket *so,
    struct label *solabel);
int abac_socket_check_receive(struct ucred *cred, struct socket *so,
    struct label *solabel);
int abac_socket_check_send(struct ucred *cred, struct socket *so,
    struct label *solabel);
int abac_socket_check_stat(struct ucred *cred, struct socket *so,
    struct label *solabel);
int abac_socket_check_visible(struct ucred *cred, struct socket *so,
    struct label *solabel);
int abac_socket_check_poll(struct ucred *cred, struct socket *so,
    struct label *solabel);
int abac_socket_check_deliver(struct socket *so, struct label *solabel,
    struct mbuf *m, struct label *mlabel);

/* Socketpeer label lifecycle */
int abac_socketpeer_init_label(struct label *label, int flag);
void abac_socketpeer_destroy_label(struct label *label);
void abac_socketpeer_set_from_mbuf(struct mbuf *m, struct label *mlabel,
    struct socket *so, struct label *sopeerlabel);
void abac_socketpeer_set_from_socket(struct socket *oldso,
    struct label *oldsolabel, struct socket *newso,
    struct label *newsopeerlabel);

/*
 * Function prototypes - abac_pipe.c
 */
void abac_pipe_init_label(struct label *label);
void abac_pipe_destroy_label(struct label *label);
void abac_pipe_copy_label(struct label *src, struct label *dest);
void abac_pipe_create(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel);
int abac_pipe_check_ioctl(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, unsigned long cmd, void *data);
int abac_pipe_check_poll(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel);
int abac_pipe_check_read(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel);
int abac_pipe_check_relabel(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, struct label *newlabel);
int abac_pipe_check_stat(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel);
int abac_pipe_check_write(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel);

/*
 * Function prototypes - abac_posixshm.c
 */
void abac_posixshm_init_label(struct label *label);
void abac_posixshm_destroy_label(struct label *label);
void abac_posixshm_create(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel);
int abac_posixshm_check_create(struct ucred *cred, const char *path);
int abac_posixshm_check_mmap(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, int prot, int flags);
int abac_posixshm_check_open(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, accmode_t accmode);
int abac_posixshm_check_read(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel);
int abac_posixshm_check_setmode(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, mode_t mode);
int abac_posixshm_check_setowner(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, uid_t uid, gid_t gid);
int abac_posixshm_check_stat(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel);
int abac_posixshm_check_truncate(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel);
int abac_posixshm_check_unlink(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel);
int abac_posixshm_check_write(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel);

/*
 * Function prototypes - abac_system.c
 */
int abac_kld_check_load(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
int abac_kld_check_stat(struct ucred *cred);
int abac_system_check_reboot(struct ucred *cred, int howto);
int abac_system_check_sysctl(struct ucred *cred, struct sysctl_oid *oidp,
    void *arg1, int arg2, struct sysctl_req *req);
int abac_system_check_acct(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
int abac_system_check_swapon(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
int abac_system_check_swapoff(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
int abac_system_check_audit(struct ucred *cred, void *record, int length);
int abac_system_check_auditctl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
int abac_system_check_auditon(struct ucred *cred, int cmd);
int abac_mount_check_stat(struct ucred *cred, struct mount *mp,
    struct label *mplabel);

/*
 * Function prototypes - abac_kenv.c
 */
int abac_kenv_check_dump(struct ucred *cred);
int abac_kenv_check_get(struct ucred *cred, char *name);
int abac_kenv_check_set(struct ucred *cred, char *name, char *value);
int abac_kenv_check_unset(struct ucred *cred, char *name);

/*
 * Function prototypes - abac_posixsem.c
 */
void abac_posixsem_init_label(struct label *label);
void abac_posixsem_destroy_label(struct label *label);
void abac_posixsem_create(struct ucred *cred, struct ksem *ks,
    struct label *kslabel);
int abac_posixsem_check_getvalue(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel);
int abac_posixsem_check_open(struct ucred *cred, struct ksem *ks,
    struct label *kslabel);
int abac_posixsem_check_post(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel);
int abac_posixsem_check_setmode(struct ucred *cred, struct ksem *ks,
    struct label *kslabel, mode_t mode);
int abac_posixsem_check_setowner(struct ucred *cred, struct ksem *ks,
    struct label *kslabel, uid_t uid, gid_t gid);
int abac_posixsem_check_stat(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel);
int abac_posixsem_check_unlink(struct ucred *cred, struct ksem *ks,
    struct label *kslabel);
int abac_posixsem_check_wait(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel);

/*
 * Function prototypes - abac_sysv.c (SysV IPC)
 */
/* Message queue messages */
void abac_sysvmsg_init_label(struct label *label);
void abac_sysvmsg_destroy_label(struct label *label);
void abac_sysvmsg_cleanup(struct label *msglabel);
void abac_sysvmsg_create(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqlabel, struct msg *msgptr, struct label *msglabel);

/* Message queues */
void abac_sysvmsq_init_label(struct label *label);
void abac_sysvmsq_destroy_label(struct label *label);
void abac_sysvmsq_cleanup(struct label *msqlabel);
void abac_sysvmsq_create(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqlabel);
int abac_sysvmsq_check_msgmsq(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel, struct msqid_kernel *msqkptr,
    struct label *msqklabel);
int abac_sysvmsq_check_msgrcv(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel);
int abac_sysvmsq_check_msgrmid(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel);
int abac_sysvmsq_check_msqget(struct ucred *cred,
    struct msqid_kernel *msqkptr, struct label *msqklabel);
int abac_sysvmsq_check_msqctl(struct ucred *cred,
    struct msqid_kernel *msqkptr, struct label *msqklabel, int cmd);
int abac_sysvmsq_check_msqrcv(struct ucred *cred,
    struct msqid_kernel *msqkptr, struct label *msqklabel);
int abac_sysvmsq_check_msqsnd(struct ucred *cred,
    struct msqid_kernel *msqkptr, struct label *msqklabel);

/* SysV semaphores */
void abac_sysvsem_init_label(struct label *label);
void abac_sysvsem_destroy_label(struct label *label);
void abac_sysvsem_cleanup(struct label *semalabel);
void abac_sysvsem_create(struct ucred *cred, struct semid_kernel *semakptr,
    struct label *semalabel);
int abac_sysvsem_check_semctl(struct ucred *cred,
    struct semid_kernel *semakptr, struct label *semaklabel, int cmd);
int abac_sysvsem_check_semget(struct ucred *cred,
    struct semid_kernel *semakptr, struct label *semaklabel);
int abac_sysvsem_check_semop(struct ucred *cred,
    struct semid_kernel *semakptr, struct label *semaklabel, size_t accesstype);

/* SysV shared memory */
void abac_sysvshm_init_label(struct label *label);
void abac_sysvshm_destroy_label(struct label *label);
void abac_sysvshm_cleanup(struct label *shmlabel);
void abac_sysvshm_create(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmlabel);
int abac_sysvshm_check_shmat(struct ucred *cred,
    struct shmid_kernel *shmsegptr, struct label *shmseglabel, int shmflg);
int abac_sysvshm_check_shmctl(struct ucred *cred,
    struct shmid_kernel *shmsegptr, struct label *shmseglabel, int cmd);
int abac_sysvshm_check_shmdt(struct ucred *cred,
    struct shmid_kernel *shmsegptr, struct label *shmseglabel);
int abac_sysvshm_check_shmget(struct ucred *cred,
    struct shmid_kernel *shmsegptr, struct label *shmseglabel, int shmflg);

#endif /* _KERNEL */

#endif /* !_SECURITY_MAC_ABAC_H_ */
