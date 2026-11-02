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

#ifndef __DTRACED_H_
#define __DTRACED_H_

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DTRACED_MAJOR                  0
#define DTRACED_MINOR                  4
#define DTRACED_PATCH                  0
#define DTRACED_EXTRA_IDENTIFIER       "BETA"

#define	DTRACED_SOCKDIR                "/var/ddtrace"
#define	DTRACED_SOCKPATH               "/var/ddtrace/sub.sock"

#define	DTRACED_KIND_UNKNOWN           0
#define	DTRACED_KIND_CONSUMER          1
#define	DTRACED_KIND_FORWARDER         2
#define	DTRACED_KIND_DTRACED           3
#define DTRACED_KIND_RELEASE_RECOVERY  4
#define DTRACED_PROTOCOL_VERSION 67U
#define DTRACED_PROGRAM_ID_LEN 16
/* Wire VM IDs follow HyperTrace's fixed namespace; daemon compilation
 * checks this against HYPERTRACE_MAX_VMS. */
#define DTRACED_WIRE_MAX_VMS 1024U

#define DTD_SUB_READDATA               1ull
#define DTD_SUB_ELFWRITE               (1ull << 1)
#define DTD_SUB_KILL                   (1ull << 2)
#define DTD_SUB_CLEANUP                (1ull << 3)
#define DTD_SUB_INFO                   (1ull << 4)
#define DTD_SUB_ADMISSION_ACK          (1ull << 5)
#define DTD_SUB_REPLAY_MANIFEST        (1ull << 6)
#define DTD_SUB_SOURCE_RELEASE         (1ull << 7)
#define DTD_SUB_RELEASE_RECOVERY       (1ull << 8)
#define DTRACED_RELEASE_ATTESTED_SIZE  324U
#define DTRACED_RELEASE_MODE_LOCAL     0U
#define DTRACED_RELEASE_MODE_SIGNED    1U
#define DTRACED_REPLAY_KILL_WIRE_SIZE 32U
#define DTRACED_REPLAY_KILL_MAX        32768U

typedef struct dtraced_replay_kill {
	int32_t pid;
	uint16_t vmid;
	uint64_t epoch;
	uint8_t source_id[DTRACED_PROGRAM_ID_LEN];
} dtraced_replay_kill_t;

#define DTRACED_LOCSIZE                64ul
#define DTRACED_PROGIDENTLEN           128ull

#define DTRACED_FDIDENTLEN             128ull

typedef struct dtraced_hdr {
	uint64_t msg_type;      /* message type (see DTRACED_MSG_*) */
	struct {
		uint64_t len;                     /* elf length */
		uint64_t delivery_id;             /* per-frame acknowledgment token */
		uint8_t program_id[DTRACED_PROGRAM_ID_LEN]; /* stable spool identity */
		uint8_t source_id[DTRACED_PROGRAM_ID_LEN]; /* source-program lineage */
		int32_t ident_present;            /* identifier present? */
		int32_t filter_by_vmid;           /* should we filter? */
		uint16_t vmid;                    /* which VM? (if filtered) */
		uint64_t epoch;                   /* guest ELF's VM lifetime */
		char location[DTRACED_LOCSIZE];	  /* elf location */
		char ident[DTRACED_PROGIDENTLEN]; /* program identifier */
	} elf;

	struct {
		int32_t pid;   /* process id to kill */
		uint16_t vmid; /* vmid to kill the pid on */
		uint64_t epoch; /* target VM lifetime */
		uint8_t source_id[DTRACED_PROGRAM_ID_LEN]; /* source to revoke */
	} kill;

	struct {
		uint64_t num_entries; /* number of entries to clean up */
		uint16_t vmid; /* forwarder's VM at queue delivery */
		uint64_t epoch; /* forwarder's VM lifetime */
	} cleanup;

	struct {
		uint64_t count; /* INFO count or CLEANUP queue-ACK token */
	} info;

	struct {
		uint64_t delivery_id;
		uint16_t vmid;
		uint64_t epoch;
		uint8_t program_id[DTRACED_PROGRAM_ID_LEN];
		uint8_t source_id[DTRACED_PROGRAM_ID_LEN];
		/* On a derived ELF frame these fields carry the exact parent
		 * ingress identity; name holds its 16-byte consumer session
		 * followed by zero padding. */
		char name[DTRACED_FDIDENTLEN];
	} installed;
} dtraced_hdr_t;

typedef struct dtraced_delivery_ack {
	uint64_t delivery_id;
} dtraced_delivery_ack_t;

#define DTRACED_CONSUMER_ACK_FAILURE	0U
#define DTRACED_CONSUMER_ACK_NO_DERIVED	1U
#define DTRACED_CONSUMER_ACK_DERIVED	2U

typedef struct dtraced_consumer_ack {
	uint64_t delivery_id;
	uint8_t program_id[DTRACED_PROGRAM_ID_LEN];
	uint8_t source_id[DTRACED_PROGRAM_ID_LEN];
	uint16_t vmid;
	uint8_t outcome;
	uint64_t epoch;
	/* Used only by the later execution result, never by the 56-byte ACK. */
	uint8_t ingress_session[16];
} dtraced_consumer_ack_t;

/* Daemon-to-consumer quiescence challenge. The daemon must bind a live
 * HPI1/HCP1 owner before sending it; the reply echoes every identity field.
 * A successful reply is only a process-local observation until journaled. */
typedef struct dtraced_consumer_drain {
	uint8_t token[16];
	uint8_t source_session[16];
	uint8_t consumer_session[16];
	uint8_t program_digest[32];
	uint16_t vmid;
	uint64_t epoch;
	uint8_t result; /* 1 drained, 0 refused; reply only */
} dtraced_consumer_drain_t;

/* Fresh-session stop binds the same identities as a drain, but acknowledges
 * closed execution admission and discarded state, never preserved output.
 * It has a separate wire discriminator; a continuity drain is not a stop. */
typedef dtraced_consumer_drain_t dtraced_consumer_stop_t;

/* Fixed-size checkpoint request following a DTRACED_MSG_HANDOFF header.
 * The daemon derives source and destination identities from live VMM-
 * attested forwarders, never from client-supplied bytes. */
typedef struct dtraced_handoff_request {
	uint8_t op;
	uint8_t token[16];
	uint8_t digest[32];
} dtraced_handoff_request_t;

#define DTRACED_HANDOFF_PREPARE 1 /* HTX1 digest */
#define DTRACED_HANDOFF_COMMIT  2
#define DTRACED_HANDOFF_ABORT   3
#define DTRACED_HANDOFF_RESERVE 4
#define DTRACED_HANDOFF_CANCEL  5
#define DTRACED_HANDOFF_MUTATE  6
#define DTRACED_HANDOFF_CLAIM   7
#define DTRACED_HANDOFF_SOURCE_STATUS 8 /* read-only, zero digest */
#define DTRACED_HANDOFF_DESTINATION_STATUS 9 /* read-only, bound digest */
#define DTRACED_HANDOFF_BIND_KILLS_ALL 10 /* post-CLAIM, idempotent */
#define DTRACED_HANDOFF_REKEY_APPLIED 11 /* durable guest rekey observation */
#define DTRACED_HANDOFF_EXPORT 12 /* bounded, read-only source bundle */
#define DTRACED_HANDOFF_PROMOTE_IMPORT 13 /* claimed HTD5/HLC1 commit */
#define DTRACED_HANDOFF_ACTIVATE_IMPORT 14 /* post-rekey HLA1 gate */
#define DTRACED_HANDOFF_SOURCE_RELEASE 15 /* post-destroy HSL1 witness */
#define DTRACED_HANDOFF_SOURCE_GATE_BEGIN 16 /* durable HGI1 + epoch suspend */
#define DTRACED_HANDOFF_SOURCE_GATE_ABORT 17 /* exact resume after abort */
#define DTRACED_HANDOFF_SOURCE_DRAIN_STEP 18 /* one HGD1, HTX1 digest */
#define DTRACED_HANDOFF_RELEASE_RECOVER 19 /* read-only HSA1, local root */
#define DTRACED_HANDOFF_REPLAY_READY 20 /* all claimed HTD5 queue ACKs */
#define DTRACED_HANDOFF_EXECUTION_START 21 /* durable pre-vCPU release */
#define DTRACED_HANDOFF_REBIND_BEGIN 22 /* HRI1, old VM retired; no lease */
#define DTRACED_HANDOFF_REBIND_STAGE 23 /* HRP1, durable replacement plan */
#define DTRACED_HANDOFF_REBIND_PENDING 24 /* inert proposed HTD5 receipts */
#define DTRACED_HANDOFF_REBIND_CANCEL_PENDING 25 /* retired, exact rollback */
#define DTRACED_HANDOFF_REBIND_COMMIT_EMPTY 26 /* HRC1 empty-journal switch */
#define DTRACED_HANDOFF_REBIND_EMPTY_READY 27 /* read-only HRP1 empty check */
#define DTRACED_HANDOFF_RESET_MUTATION 28 /* retired, never-capable rollback */
#define DTRACED_HANDOFF_REBIND_NONEMPTY_PREFLIGHT 29 /* read-only HRP1/HTD5 check */
#define DTRACED_CONSUMER_RECEIPT_LIMIT 65536U

/* Source delivery lookup by a VMM-attested destination holding this exact
 * checkpoint ticket. HANDOFF_DELIVERY is read-only; HANDOFF_BIND_DELIVERY
 * durably binds the source receipt to the attested destination owner. */
typedef struct dtraced_handoff_delivery_request {
	uint8_t token[16];
	uint8_t digest[32];
	uint64_t delivery_id;
	uint8_t program_id[16];
	uint8_t source_id[16];
	uint8_t scope; /* 0 host outbound; 3 host ingress query only */
	uint8_t reserved[7];
} dtraced_handoff_delivery_request_t;

/* A saved ELF queue bind supplies the bytes' digest separately from the
 * checkpoint digest. The read-only lookup retains its 96-byte wire. */
typedef struct dtraced_handoff_bind_delivery_request {
	dtraced_handoff_delivery_request_t delivery;
	uint8_t payload_digest[32];
} dtraced_handoff_bind_delivery_request_t;

/* Read-only KILL journal lookup under an attested destination lease.
 * The reply uses dtraced_delivery_status_t: delivery_id is the PID,
 * phase is 0 (exact PID absent), 'p' (pending), or 'a' (applied);
 * revoked covers the source ID across this VM lifetime. */
typedef struct dtraced_handoff_kill_request {
	uint8_t token[16];
	uint8_t digest[32];
	int32_t pid;
	uint8_t source_id[16];
	uint8_t reserved[4];
} dtraced_handoff_kill_request_t;

/* Read-only accepted CLEANUP lookup under an attested destination lease. */
typedef struct dtraced_handoff_cleanup_request {
	uint8_t token[16];
	uint8_t digest[32];
	uint64_t delivery_id;
} dtraced_handoff_cleanup_request_t;

typedef struct dtraced_delivery_status {
	uint64_t delivery_id;
	uint8_t phase;   /* 0 absent, 'u' retry later, or durable phase */
	uint8_t revoked; /* source revoked for this VM lifetime */
	uint8_t replay;  /* live accepted owner authorizes recovered replay */
	uint8_t reserved[5];
	uint8_t digest[32]; /* replay, ingress, or verified retained handoff ELF */
} dtraced_delivery_status_t;

/* A single fixed-width local control reply, following the status byte. */
typedef struct dtraced_stats {
	uint64_t forwarder_channels;
	uint64_t outbound_deliveries;
	uint64_t installed_deliveries;
	uint64_t revoked_deliveries;
} dtraced_stats_t;

#define DTRACED_LAUNCH_MAGIC UINT64_C(0x3154534e495448)
typedef struct dtraced_launch_result {
	uint64_t magic;
	uint8_t installed;
	uint8_t reserved[7];
	char source_ident[DTRACED_PROGIDENTLEN];
} dtraced_launch_result_t;

typedef struct dtd_initmsg {
	int32_t kind;                   /* kind (see above) */
	uint32_t protocol_version;       /* occupies old native ABI padding */
	uint64_t subs;	                /* what are we subscribing to? */
	char ident[DTRACED_FDIDENTLEN]; /* human-readable string identifier */
	uint8_t session_id[16]; /* both channels of one forwarder process */
} dtd_initmsg_t;

typedef struct dtraced_infomsg {
	int32_t client_kind;
	char client_name[DTRACED_FDIDENTLEN];
} dtraced_infomsg_t;

#define	DTRACED_MSGHDRSIZE             520U
#define DTRACED_INIT_WIRE_SIZE          160U
#define DTRACED_STATUS_WIRE_SIZE        48U
#define DTRACED_STATS_WIRE_SIZE         32U
#define DTRACED_ACK_WIRE_SIZE           8U
#define DTRACED_CONSUMER_ACK_WIRE_SIZE  56U
#define DTRACED_CONSUMER_EXECUTION_WIRE_SIZE 72U
#define DTRACED_CONSUMER_DRAIN_WIRE_SIZE 96U
#define DTRACED_CONSUMER_DRAIN_ACK_WIRE_SIZE 104U
#define DTRACED_INFO_WIRE_SIZE          132U
#define DTRACED_HANDOFF_WIRE_SIZE       49U
#define DTRACED_HANDOFF_IMPORT_BINDING_SIZE 48U
#define DTRACED_HANDOFF_RELEASE_IMPORT_SIZE \
    (48U + DTRACED_RELEASE_ATTESTED_SIZE)
#define DTRACED_HANDOFF_DELIVERY_WIRE_SIZE 96U
#define DTRACED_HANDOFF_BIND_DELIVERY_WIRE_SIZE 128U
#define DTRACED_HANDOFF_KILL_WIRE_SIZE 72U
#define DTRACED_HANDOFF_CLEANUP_WIRE_SIZE 56U
#define DTRACED_LAUNCH_WIRE_SIZE       144U

/*
 * Public message API
 */
#define DTRACED_MSG_ELF                1
#define DTRACED_MSG_KILL               2
#define DTRACED_MSG_CLEANUP            3
#define DTRACED_MSG_INFO               4
#define DTRACED_MSG_INSTALLED          5
#define DTRACED_MSG_UNINSTALLED        6
#define DTRACED_MSG_STATUS             7
#define DTRACED_MSG_INGRESS_STATUS     8
#define DTRACED_MSG_KILL_APPLIED       9
#define DTRACED_MSG_HANDOFF            10
#define DTRACED_MSG_HANDOFF_DELIVERY   11
#define DTRACED_MSG_HANDOFF_KILL       12
#define DTRACED_MSG_HANDOFF_BIND_DELIVERY 13
#define DTRACED_MSG_HANDOFF_BIND_KILL   14
#define DTRACED_MSG_STATS              15
#define DTRACED_MSG_CONSUMER_EXECUTION 16
#define DTRACED_MSG_HANDOFF_CLEANUP    17
#define DTRACED_MSG_CLEANUP_APPLIED    18
#define DTRACED_MSG_HANDOFF_IMPORT     19
#define DTRACED_MSG_CONSUMER_PROGRAM   20
#define DTRACED_MSG_CONSUMER_DRAIN     21
#define DTRACED_MSG_HANDOFF_RELEASE_IMPORT 22
#define DTRACED_MSG_CONSUMER_STOP      23
#define DTRACED_MSG_SESSION_STOP       24
#define DTRACED_MSG_SESSION_RELEASE    25
#define DTRACED_MSG_CONSUMER_STOP_COMMIT 26
#define DTRACED_MSG_LAST               26
#define DTRACED_SESSION_STOP_WIRE_SIZE 24U

#define DTRACED_MSG_TYPE(m)            ((m).msg_type)
#define DTRACED_MSG_LOC(m)             ((m).elf.location)
#define DTRACED_MSG_IDENT(m)           ((m).elf.ident)
#define DTRACED_MSG_IDENT_PRESENT(m)   ((m).elf.ident_present)
#define DTRACED_MSG_LEN(m)             ((m).elf.len)
#define DTRACED_MSG_KILLPID(m)         ((m).kill.pid)
#define DTRACED_MSG_KILLVMID(m)        ((m).kill.vmid)
#define DTRACED_MSG_KILLEPOCH(m)       ((m).kill.epoch)
#define DTRACED_MSG_NUMENTRIES(m)      ((m).cleanup.num_entries)
#define DTRACED_MSG_CLEANUP_DELIVERY_ID(m) ((m).info.count)

#ifdef __cplusplus
}
#endif

#endif // __DTRACED_H_
