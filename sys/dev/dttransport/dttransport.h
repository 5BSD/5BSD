/*-
 * Copyright (c) 2020 Domagoj Stolfa
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _DTTRANSPORT_H_
#define _DTTRANSPORT_H_

#include <sys/types.h>
#include <sys/ioccom.h>

struct dtt_vm_identity {
	uint16_t vmid;
	uint16_t old_vmid;
	uint32_t flags;
	uint64_t epoch;
	uint64_t old_epoch;
};

_Static_assert(sizeof(struct dtt_vm_identity) == 24,
    "DTrace guest identity ioctl must remain fixed width");

#define DTT_IDENTITY_REKEY_PENDING (1u << 0)
#define DTT_IDENTITY_REKEY_LOCAL_COMMITTED (1u << 1)
/* Proposed fresh identity; old identity remains fenced until local setup. */
#define DTT_IDENTITY_FRESH_PENDING (1u << 2)
#define DTT_IDENTITY_FRESH_READY (1u << 3)
#define DTT_IDENTITY_FRESH_ACTIVE (1u << 4)
#define DTT_GET_VM_IDENTITY _IOR('D', 1, struct dtt_vm_identity)
/* Record the exact local journal commit. This is idempotent and remains
 * fenced until a distinct host acknowledgement is implemented. The caller
 * supplies only the four identity values; flags must be zero. */
#define DTT_COMMIT_VM_REKEY _IOW('D', 2, struct dtt_vm_identity)

/* Kernel-retained cleanup state survives a guest daemon re-exec. An
 * unapplied token requires recovery of the previous child cohort before
 * another daemon may admit tracing work. */
struct dtt_cleanup_state {
	uint64_t delivery_id;
	uint64_t epoch;
	uint16_t vmid;
	uint16_t flags;
	uint32_t reserved;
};
#define DTT_CLEANUP_STATE_PENDING (1u << 0)
#define DTT_CLEANUP_STATE_APPLIED (1u << 1)
/* Quiesce only: no ordinary cleanup ACK may release this session fence. */
#define DTT_CLEANUP_STATE_SESSION_STOP (1u << 2)
_Static_assert(sizeof(struct dtt_cleanup_state) == 24,
    "DTrace cleanup-state ioctl must remain fixed width");
#define DTT_GET_CLEANUP_STATE _IOR('D', 3, struct dtt_cleanup_state)

#define DTT_MAXDATALEN 2048ul

#define	DTT_ELF			1
#define	DTT_KILL		2
#define	DTT_CLEANUP_DTRACED	3
#define	DTT_INSTALLED		4
#define	DTT_UNINSTALLED		5
#define DTT_HOST_INSTALLED	6
#define DTT_HOST_UNINSTALLED	7
#define DTT_STATUS		8
#define DTT_HOST_STATUS		9
#define DTT_HOST_ELF		10 /* Host daemon accepted guest ELF */
#define DTT_INGRESS_STATUS	11 /* Query host guest-ELF ingest token */
#define DTT_HOST_INGRESS_STATUS 12 /* Host ingest phase or unavailable */
#define DTT_VM_IDENTITY_QUERY 13 /* Ask bhyve for current VM incarnation */
#define DTT_VM_IDENTITY 14 /* VMID and epoch for matching query */
#define DTT_KILL_APPLIED 15 /* Guest daemon fsynced source revocation */
#define DTT_HOST_KILL_APPLIED 16 /* Host daemon fsynced that observation */
#define DTT_VM_REKEY 17 /* Driver changed VM incarnation; stop old journal */
#define DTT_REKEY_DELIVERY_QUERY 18 /* Exact source delivery receipt */
#define DTT_REKEY_INGRESS_QUERY 19 /* Exact source ingest receipt */
#define DTT_REKEY_KILL_QUERY 20 /* Exact source revocation receipt */
#define DTT_REKEY_DELIVERY_RECEIPT 21
#define DTT_REKEY_INGRESS_RECEIPT 22
#define DTT_REKEY_KILL_RECEIPT 23
#define DTT_CLEANUP_APPLIED 24 /* Guest stopped all traced children */
#define DTT_SESSION_STOP 25 /* Stop tracing; remain fenced for fresh attach */
#define DTT_SESSION_STOPPED 26 /* Exact stop token, after child exit */
#define DTT_SESSION_READY 27 /* Clean local state for proposed fresh identity */

typedef struct dtt_entry {
	uint8_t event_kind; /* kind of event */

	union {
		struct {
			size_t len; /* length of the current message */
			size_t totallen; /* total length of the data */
			uint32_t identifier; /* unique identifier for data */
			uint64_t delivery_id; /* host delivery transaction */
			uint16_t vmid;
			uint64_t epoch;
			uint8_t program_id[16]; /* stable across retries */
			uint8_t source_id[16]; /* source-program lineage */
			int hasmore; /* are there more segments? */
			unsigned char data[DTT_MAXDATALEN]; /* the data itself */
		} elf;

	struct {
		pid_t pid;
		uint8_t source_id[16];
		uint16_t vmid;
		uint64_t epoch;
	} kill;

		struct {
			uint64_t delivery_id;
			uint16_t vmid;
			uint64_t epoch;
		} cleanup;

		struct {
			uint64_t delivery_id;
			uint16_t vmid;
			uint64_t epoch;
			uint8_t program_id[16];
			uint8_t source_id[16];
			uint8_t phase; /* HOST_*_STATUS: durable phase, or 'u' */
			uint8_t revoked;
			uint8_t replay; /* explicit live-owner authorization */
			uint64_t query_id; /* status query/reply only */
			uint8_t digest[32]; /* replay or host-ingest ELF SHA-256 */
		} installed;
	} u;
} dtt_entry_t;

_Static_assert(sizeof(dtt_entry_t) <= 4096, "dtt_entry_t must fit in one page");

#define	DTT_ENTRYLEN	sizeof(dtt_entry_t)

extern int	dtt_queue_enqueue(dtt_entry_t *);
extern int	dtt_queue_enqueue_front(dtt_entry_t *);
extern int	dtt_queue_session_stop(dtt_entry_t *);
#ifdef _KERNEL
typedef int dtt_send_t(void *, dtt_entry_t *);
typedef int dtt_identity_t(void *, struct dtt_vm_identity *);
typedef int dtt_rekey_commit_t(void *, const struct dtt_vm_identity *);
typedef int dtt_cleanup_query_t(void *, struct dtt_cleanup_state *);
int dtt_register_transport(dtt_send_t *, dtt_identity_t *,
    dtt_rekey_commit_t *, dtt_cleanup_query_t *, void *);
void dtt_unregister_transport(void *);
#endif

#endif // _DTTRANSPORT_H_
