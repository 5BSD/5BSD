/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _DEV_VIRTIO_DTRACE_WIRE_H_
#define _DEV_VIRTIO_DTRACE_WIRE_H_

#include <sys/types.h>

#define VTDTR_WIRE_MAXELFLEN 2048U
/* Required for epoch-bound ELF, KILL, cleanup and lifecycle controls. */
#define VTDTR_WIRE_F_CONTROL_V1 (1ULL << 0)
/* Guest-applied KILL and host-durable receipt, both bound to the VM epoch. */
#define VTDTR_WIRE_F_KILL_APPLIED_V1 (1ULL << 1)
/* Guest accepts an explicit old-to-new VM identity transition on restore. */
#define VTDTR_WIRE_F_NODE_REKEY_V1 (1ULL << 2)
/* HOST_ELF acknowledgement carries the SHA-256 of the accepted bare ELF. */
#define VTDTR_WIRE_F_HOST_ELF_DIGEST_V1 (1ULL << 3)
/* Guest journal commit and exact host acknowledgement of a VM rekey. */
#define VTDTR_WIRE_F_REKEY_COMMIT_V1 (1ULL << 4)
/* Exact old-incarnation receipt queries under a coordinator-owned ticket. */
#define VTDTR_WIRE_F_REKEY_RECEIPT_V1 (1ULL << 5)
/* Exact guest-applied cleanup and host-durable acknowledgement. */
#define VTDTR_WIRE_F_CLEANUP_APPLIED_V1 (1ULL << 6)
/* Stop a session without transferring its tracing journals. */
#define VTDTR_WIRE_F_SESSION_STOP_V1 (1ULL << 7)
/* Prepare a distinct identity after stopping; never import old journals. */
#define VTDTR_WIRE_F_SESSION_FRESH_V1 (1ULL << 8)

/* Ordinary tracing must not depend on checkpoint continuity support. */
#define VTDTR_WIRE_F_SESSION_REQUIRED \
	(VTDTR_WIRE_F_CONTROL_V1 | VTDTR_WIRE_F_KILL_APPLIED_V1 | \
	VTDTR_WIRE_F_HOST_ELF_DIGEST_V1 | VTDTR_WIRE_F_CLEANUP_APPLIED_V1)
/* Retained for the experimental continuity path, optional at attachment. */
#define VTDTR_WIRE_F_CONTINUITY \
	(VTDTR_WIRE_F_NODE_REKEY_V1 | VTDTR_WIRE_F_REKEY_COMMIT_V1 | \
	VTDTR_WIRE_F_REKEY_RECEIPT_V1)

enum vtdtr_wire_event {
	VTDTR_WIRE_EVENT_READY = 0x00,
	VTDTR_WIRE_EVENT_REGISTER = 0x01,
	VTDTR_WIRE_EVENT_UNREGISTER = 0x02,
	VTDTR_WIRE_EVENT_DESTROY = 0x03,
	VTDTR_WIRE_EVENT_PROBE_CREATE = 0x04,
	VTDTR_WIRE_EVENT_PROBE_INSTALL = 0x05,
	VTDTR_WIRE_EVENT_RESERVED_06 = 0x06,
	VTDTR_WIRE_EVENT_EOF = 0x07,
	VTDTR_WIRE_EVENT_GO = 0x08,
	VTDTR_WIRE_EVENT_ELF = 0x09,
	VTDTR_WIRE_EVENT_STOP = 0x0a,
	VTDTR_WIRE_EVENT_KILL = 0x0b,
	VTDTR_WIRE_EVENT_CLEANUP_DTRACED = 0x0c,
	VTDTR_WIRE_EVENT_NODE_ID = 0x0d,
	VTDTR_WIRE_EVENT_INSTALLED = 0x0e,
	VTDTR_WIRE_EVENT_UNINSTALLED = 0x0f,
	VTDTR_WIRE_EVENT_HOST_INSTALLED = 0x10,
	VTDTR_WIRE_EVENT_HOST_UNINSTALLED = 0x11,
	VTDTR_WIRE_EVENT_STATUS = 0x12,
	VTDTR_WIRE_EVENT_HOST_STATUS = 0x13,
	VTDTR_WIRE_EVENT_HOST_ELF = 0x14,
	VTDTR_WIRE_EVENT_INGRESS_STATUS = 0x15,
	VTDTR_WIRE_EVENT_HOST_INGRESS_STATUS = 0x16,
	VTDTR_WIRE_EVENT_KILL_APPLIED = 0x17,
	VTDTR_WIRE_EVENT_HOST_KILL_APPLIED = 0x18,
	VTDTR_WIRE_EVENT_NODE_REKEY = 0x19,
	VTDTR_WIRE_EVENT_REKEY_COMMIT = 0x1a,
	VTDTR_WIRE_EVENT_REKEY_COMMITTED = 0x1b,
	VTDTR_WIRE_EVENT_REKEY_APPLIED = 0x1c,
	VTDTR_WIRE_EVENT_REKEY_DELIVERY_QUERY = 0x1d,
	VTDTR_WIRE_EVENT_REKEY_INGRESS_QUERY = 0x1e,
	VTDTR_WIRE_EVENT_REKEY_KILL_QUERY = 0x1f,
	VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT = 0x20,
	VTDTR_WIRE_EVENT_REKEY_INGRESS_RECEIPT = 0x21,
	VTDTR_WIRE_EVENT_REKEY_KILL_RECEIPT = 0x22,
	VTDTR_WIRE_EVENT_CLEANUP_APPLIED = 0x23,
	VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED = 0x24,
	VTDTR_WIRE_EVENT_SESSION_STOP = 0x25,
	VTDTR_WIRE_EVENT_SESSION_STOPPED = 0x26,
	VTDTR_WIRE_EVENT_SESSION_PREPARE = 0x27,
	VTDTR_WIRE_EVENT_SESSION_READY = 0x28,
	VTDTR_WIRE_EVENT_SESSION_COMMIT = 0x29,
	VTDTR_WIRE_EVENT_SESSION_ACTIVE = 0x2a,
};

/* Private host/guest control descriptor. Both endpoints use this layout. */
struct vtdtr_wire_control {
	uint32_t event;
	union {
		struct {
			size_t elflen;
			size_t totalelflen;
			uint32_t identifier;
			uint64_t delivery_id;
			uint16_t vmid;
			uint64_t epoch;
			uint8_t program_id[16];
			uint8_t elf_source_id[16];
			int elfhasmore;
			char elf[VTDTR_WIRE_MAXELFLEN];
		} elf;
		struct {
			pid_t pid;
			uint16_t vmid;
			uint64_t epoch;
			uint8_t source_id[16];
		} kill;
		struct {
			uint64_t delivery_id;
			uint16_t vmid;
			uint64_t epoch;
			uint8_t program_id[16];
			uint8_t source_id[16];
			uint8_t phase;
			uint8_t revoked;
			uint8_t replay;
			uint64_t query_id;
			uint8_t digest[32];
		} installed;
		struct {
			uint16_t id;
			uint64_t epoch;
			uint64_t query_id;
		} node_id;
		struct {
			uint16_t old_id;
			uint64_t old_epoch;
			uint16_t new_id;
			uint64_t new_epoch;
		} node_rekey;
		struct {
			uint64_t stop_token;
			uint64_t old_epoch;
			uint64_t new_epoch;
			uint16_t old_id;
			uint16_t new_id;
			uint32_t reserved;
		} session_prepare;
		struct {
			uint16_t vmid;
			uint64_t epoch;
			uint64_t delivery_id;
		} cleanup;
	} uctrl;
};

#endif
