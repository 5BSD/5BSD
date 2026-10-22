/*-
 * Copyright (c) 2020 Domagoj Stolfa
 * Copyright (c) 2021 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from Arm Limited.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from the Kenneth Hayter Scholarship Fund.
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
 */

#ifndef _DTRACED_DIRECTORY_H_
#define _DTRACED_DIRECTORY_H_

#include <sys/param.h>

#include <dirent.h>

#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "dtraced_release_attestation.h"


namespace dtraced {

struct durable_session_stop {
	std::array<uint8_t, 16> token{};
	std::array<uint8_t, 16> source_session{};
	uint16_t vmid = 0;
	uint64_t epoch = 0;
};

extern char INBOUNDDIR[MAXPATHLEN];
extern char OUTBOUNDDIR[MAXPATHLEN];
extern char BASEDIR[MAXPATHLEN];

class dir;
class state;
class client_fd;
class handoff_process_lock;

/* Serializes a consumer's derived publication with its durable ACK outcome,
 * including across overlapping daemon processes during restart. */
class consumer_outcome_lock {
	int fd = -1;
public:
	explicit consumer_outcome_lock(int directory);
	~consumer_outcome_lock();
	consumer_outcome_lock(const consumer_outcome_lock &) = delete;
	consumer_outcome_lock &operator=(const consumer_outcome_lock &) = delete;
	bool held() const { return (fd >= 0); }
};

typedef bool (*foreach_fn_t)(dir &, struct dirent *);

struct durable_kill {
	pid_t pid;
	uint16_t vmid;
	uint64_t epoch;
	std::array<uint8_t, 16> source_id;
};

/* One host CLEANUP awaiting bhyve's complete-frame queue ACK. */
struct durable_cleanup {
	uint16_t vmid = 0;
	uint64_t epoch = 0;
	uint64_t delivery_id = 0;
};

/* A ticket is authority only when paired with a live VMM-attested claim. */
struct durable_handoff {
	std::array<uint8_t, 16> token{};
	std::array<uint8_t, 16> source_session{};
	uint16_t source_vmid = 0;
	uint64_t source_epoch = 0;
	std::array<uint8_t, 32> transfer_digest{}; /* HTX1 source cut */
	std::array<uint8_t, 32> checkpoint_digest{};
	uint16_t destination_vmid = 0;
	uint64_t destination_epoch = 0;
};

enum class handoff_phase : char {
	prepared = 'p', committed = 'c', reserved = 'v', mutating = 'm',
	claimed = 'r'
};

struct durable_delivery {
	std::array<uint8_t, 16> session_id;
	uint64_t delivery_id;
	uint16_t vmid;
	uint64_t epoch;
	std::array<uint8_t, 16> program_id;
	std::array<uint8_t, 16> source_id;
	uint32_t peer_uid;
	uint32_t peer_pid;
	uint8_t scope = 0; /* 0 host forwarder, 1 guest inbound, 2 guest outbound, 3 host ingest */
	uint8_t journal_version = 3;
	std::array<uint8_t, 32> payload_digest{}; /* HTD4 payload identity */
	std::array<uint8_t, 16> handoff_token{}; /* HTD5 destination binding */
	std::array<uint8_t, 16> source_session{}; /* immediate source owner */
	uint16_t payload_vmid = 0; /* HTD5 source VM; retained payload VM for scope 0 */
	uint64_t payload_epoch = 0;
};

enum class delivery_phase : char {
	pending = 'p', accepted = 'a', installed = 'i', exited = 'x',
	terminal = 't'
};

struct durable_delivery_state {
	durable_delivery record;
	delivery_phase phase;
};

/* The exact source records and ELF bytes needed by a future portable
 * handoff journal. A revoked delivery has no executable payload. */
struct source_journal_delivery {
	durable_delivery_state state;
	bool revoked = false;
	std::vector<uint8_t> payload;
};
struct source_journal_kill {
	durable_kill record;
	bool applied = false;
};
struct source_journal_cleanup {
	durable_cleanup record;
	char phase = 0; /* 'a' queued or 'g' guest-applied */
};
struct source_journal_cut {
	std::vector<source_journal_delivery> deliveries;
	std::vector<source_journal_kill> kills;
	std::vector<source_journal_cleanup> cleanups;
};

struct source_journal_destination_plan {
	bool has_ingress = false;
	std::vector<source_journal_delivery> deliveries;
	std::vector<durable_kill> pending_kills;
	std::vector<durable_cleanup> queued_cleanups;
	std::vector<std::array<uint8_t, 16>> revoked_sources;
};

/* One recipient of an accepted host ingress transaction.  This is a
 * processing receipt, not a guest installation or a handoff claim. */
struct durable_consumer_receipt {
	durable_delivery ingress;
	std::array<uint8_t, 16> consumer_session{};
	uint32_t consumer_uid = 0;
	uint32_t consumer_pid = 0;
};

/* HTD5 destination recipient identity. The HCO1 wire includes the process
 * incarnation; the program digest is a separate, nonzero image identity. */
struct durable_import_consumer_receipt {
	durable_delivery ingress;
	std::array<uint8_t, 76> owner_wire{};
	std::array<uint8_t, 32> program_digest{};
};

struct durable_committed_import_entry {
	durable_delivery ingress;
	std::vector<durable_import_consumer_receipt> recipients;
};

enum class consumer_receipt_phase : char {
	pending = 'p', processed = 'c', /* legacy: outcome unknown */
	no_derived = 'n', derived = 'd',
	executed_no_derived = 'N', executed_derived = 'D'
};

struct durable_import_consumer_result {
	std::array<uint8_t, 16> token{};
	std::array<uint8_t, 32> slots_digest{};
	std::array<uint8_t, 32> receipt_digest{};
	consumer_receipt_phase phase = consumer_receipt_phase::pending;
	std::array<uint8_t, 32> derived_claim_digest{};
};

struct durable_committed_import_result_state {
	durable_import_consumer_receipt recipient;
	durable_import_consumer_result outcome;
};

inline bool
consumer_receipt_no_derived(consumer_receipt_phase phase)
{
	return (phase == consumer_receipt_phase::no_derived ||
	    phase == consumer_receipt_phase::executed_no_derived);
}

inline bool
consumer_receipt_derived(consumer_receipt_phase phase)
{
	return (phase == consumer_receipt_phase::derived ||
	    phase == consumer_receipt_phase::executed_derived);
}

inline bool
consumer_receipt_complete(consumer_receipt_phase phase)
{
	return (phase == consumer_receipt_phase::processed ||
	    consumer_receipt_no_derived(phase) ||
	    consumer_receipt_derived(phase));
}

struct durable_consumer_receipt_state {
	durable_consumer_receipt record;
	consumer_receipt_phase phase;
};

struct host_ingress_transfer_entry {
	durable_delivery ingress;
	std::vector<durable_consumer_receipt_state> recipients;
};

struct host_ingress_program_evidence {
	durable_consumer_receipt recipient;
	std::array<uint8_t, 76> owner_wire{};
	std::array<uint8_t, 32> program_digest{};
};

/* Decoded checkpoint ingress is private until every ordered frame passes. */
struct host_ingress_transfer_bundle {
	std::vector<host_ingress_transfer_entry> entries;
	std::vector<host_ingress_program_evidence> source_programs;
	std::vector<std::vector<uint8_t>> payloads;
};

/* Private destination rewrite. Source receipts remain evidence only; no
 * destination delivery or consumer execution is published by this plan. */
struct host_ingress_destination_plan {
	std::vector<host_ingress_transfer_entry> source_entries;
	std::vector<host_ingress_program_evidence> source_programs;
	std::vector<durable_delivery> deliveries;
	std::vector<std::vector<uint8_t>> payloads;
};

/* One claimed derived result for an ingress recipient and target lifetime. */
struct durable_derived_claim {
	std::array<uint8_t, 16> consumer_session{};
	uint64_t ingress_delivery_id = 0;
	uint16_t ingress_vmid = 0;
	uint64_t ingress_epoch = 0;
	std::array<uint8_t, 16> ingress_program_id{};
	std::array<uint8_t, 16> ingress_source_id{};
	uint16_t target_vmid = 0;
	uint64_t target_epoch = 0;
	std::array<uint8_t, 16> derived_program_id{};
	std::array<uint8_t, 32> payload_digest{};
	std::array<uint8_t, 32> bare_elf_digest{};
};

class dir {
	dir(const std::string &, foreach_fn_t, DIR *);
	std::unique_ptr<dir> session_directory(uint16_t, uint64_t, bool);
	using fileset = std::unordered_set<std::string>;
	std::string dirpath;	 /* directory path */
	DIR *dirp;		 /* directory pointer */
	fileset existing_files;	 /* files that exist in the dir */
	std::mutex existingmtx; /* cross-thread replay rescan */
	std::atomic<bool> rescan_requested{false};
	std::mutex publishmtx; /* serializes stable-name collision checks */
	foreach_fn_t processfn;	 /* function to process the dir */

	bool process(void);
	bool host_ingress_transfer_audit_locked(dir &);
	    /* Caller owns the outbound source publish and process locks. */
	bool source_journal_cut_locked(const durable_handoff &,
	    source_journal_cut &);
	    /* Same locks; bounded outbound state and exact verified ELF copies. */
	int source_journal_transfer_wire_locked(const durable_handoff &,
	    std::vector<uint8_t> &);
	    /* Same locks; 1 means ingress, 2 means source journal, -1 error. */
	int host_ingress_program_manifest_locked(const durable_handoff &,
	    const std::vector<uint8_t> &, std::vector<uint8_t> &);
	    /* Builds HTM2 from an audited HTM1 while that source cut is held. */
	int host_ingress_transfer_bundle_locked(const durable_handoff &, dir &,
	    std::vector<uint8_t> &, std::vector<std::vector<uint8_t>> &,
	    bool with_programs = false);
	    /* Same source locks; copies and audits a complete canonical cohort. */
	int import_promotion_transaction(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &, std::vector<std::array<uint8_t, 32>> &,
	    bool allow_accepted, bool promote, bool require_commit = false,
	    std::vector<durable_committed_import_entry> * = nullptr,
	    const durable_import_consumer_result * = nullptr,
	    consumer_receipt_phase * = nullptr,
	    const std::array<uint8_t, 32> * = nullptr,
	    durable_import_consumer_result * = nullptr,
	    std::vector<durable_committed_import_result_state> * = nullptr,
	    bool activate = false, bool read_activation = false,
	    bool require_activation_result = false);

public:
	class source_transaction {
		dir &owner;
		std::array<uint8_t, 16> source_id{};
		uint16_t vmid;
		uint64_t epoch;
		std::unique_lock<std::mutex> local;
		std::unique_ptr<handoff_process_lock> process;
		bool complete = false;
		bool revoked = false;
		source_transaction(dir &, const uint8_t[16], uint16_t, uint64_t);
		friend class dir;
	public:
		~source_transaction();
		bool valid() const { return (complete); }
		bool source_revoked() const { return (revoked); }
		bool publish_derived(const durable_derived_claim &,
		    const unsigned char *, size_t, bool *);
	};
	/* Keep a host source live through a cross-directory ingest commit. */
	std::unique_ptr<source_transaction> lock_live_source(const uint8_t[16],
	    uint16_t, uint64_t);
	/* Snapshot KILL before consulting the separate inbound journal. */
	std::unique_ptr<source_transaction> lock_source_snapshot(
	    const uint8_t[16], uint16_t, uint64_t);
	state *state = nullptr;		/* backpointer to state */
	std::mutex dirmtx;	/* directory mutex */
	int dirfd;		/* directory filedesc */

	dir(void) = delete;
	dir(const char *, foreach_fn_t);
	/* Open an empty, epoch-specific child directory without replaying the
	 * parent's journals. Caller keeps guest admission fenced until commit. */
	std::unique_ptr<dir> fresh_empty_session(uint16_t, uint64_t);
	std::unique_ptr<dir> existing_session(uint16_t, uint64_t);
	~dir();
	bool write_data(unsigned char *, size_t);
	bool write_data_with_source(const unsigned char *, size_t,
	    const uint8_t[16]);
	bool write_identified_data(const unsigned char *, size_t, const uint8_t[16],
	    bool *created = nullptr, const uint8_t *source_id = nullptr,
	    bool reject_revoked = false);
	bool revoke_source(const uint8_t[16]);
	int source_revoked(const uint8_t[16]);
	int source_revoked_for_vm(const uint8_t[16], uint16_t, uint64_t);
	bool record_kill(const durable_kill &,
	    const std::function<bool(const std::vector<durable_kill> &)> & = {});
	    /* Prepare live jobs under the handoff lock before durable publication. */
	bool record_kill_applied(const durable_kill &);
	int kill_applied(const durable_kill &);
	bool list_kills(std::vector<durable_kill> &);
	bool record_cleanup_pending(const durable_cleanup &);
	bool record_cleanup_queued(const durable_cleanup &);
	bool record_cleanup_applied(const durable_cleanup &);
	int cleanup_status(const durable_cleanup &);
	bool list_pending_cleanups(std::vector<durable_cleanup> &);
	bool rekey_guest_kills(uint16_t, uint64_t, uint16_t, uint64_t);
	    /* Pending restore only, before guest execution: invalidates ACKs. */
	    /* Durable, idempotent old-to-new rename; caller proves handoff. */
	bool prepare_handoff(const durable_handoff &, bool require_source_gate = true);
	bool abort_handoff(const durable_handoff &);
	/* Persist an exact source gate intent before changing the kernel epoch.
	 * The source ticket still needs a consumer drain and execution lease. */
	bool source_gate_begin(const durable_handoff &);
	bool begin_fresh_session_stop(const durable_session_stop &);
	/* FSD1: complete census and durable collector stops; not VM retirement. */
	int complete_fresh_session_stop(dir &, const durable_session_stop &);
	/* Exact durable FSD1 + permanent FSI1; no live-process inference. */
	int fresh_session_stop_completed(const durable_session_stop &);
	/* Read-only candidate inventory; never removes or changes journal files. */
	int plan_fresh_session_ack_retirement(const durable_session_stop &,
	    std::vector<std::string> &);
	/* Remove only exact FSA1 records superseded by durable FSD1 + FSI1. */
	int retire_fresh_session_acks(const durable_session_stop &);
	int retire_completed_fresh_session_acks();
	bool release_fresh_session_gate(const durable_session_stop &);
	int fresh_session_stop_for_vm(uint16_t, uint64_t, durable_session_stop &);
	int fresh_session_consumers(dir &, const durable_session_stop &,
	    std::vector<host_ingress_program_evidence> &);
	/* Publish only after an authenticated HSA1 success from this exact owner.
	 * -1 error, 0 absent, 1 exact durable stop proof. */
	int fresh_consumer_stop_receipt(dir &, const durable_session_stop &,
	    const host_ingress_program_evidence &, bool publish);
	bool source_gate_abort(const durable_handoff &);
	int source_consumer_drain_receipt(const durable_handoff &,
	    const host_ingress_program_evidence &, bool publish);
	    /* HGD1: -1 error, 0 absent, 1 exact durable ACK. The caller must
	     * validate the consumer's drain reply before publish=true. This
	     * observation alone does not authorize nonempty PREPARE. */
	int drain_source_consumer_step(const durable_handoff &);
	    /* -1 error, 0 all drained, 1 one HGD1 published. One consumer
	     * challenge per VMM-attested request bounds its reply deadline. */
	bool commit_handoff(const durable_handoff &);
	bool record_source_release(const durable_handoff &);
	int source_release_status(const durable_handoff &);
	    /* HSL1: exact committed ticket after kernel epoch drain. */
	bool attest_source_release(const durable_handoff &, EVP_PKEY *,
	    const uint8_t destination_public[32],
	    std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> &);
	    /* Persist an exact signed HSL1; never attest a proposed release. */
	bool read_source_release_attestation(const durable_handoff &,
	    const uint8_t source_public[32],
	    const uint8_t destination_public[32],
	    std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> &);
	    /* Recover only a sidecar bound to the trusted keys and ticket. */
	static bool verify_source_release_attestation(
	    const durable_handoff &, const uint8_t source_public[32],
	    const uint8_t destination_public[32],
	    const uint8_t wire[DTRACED_RELEASE_ATTESTED_SIZE]);
	    /* Verify against an independently trusted source key and ticket. */
	static bool decode_source_release_attestation(
	    const uint8_t wire[DTRACED_RELEASE_ATTESTED_SIZE],
	    const uint8_t source_public[32],
	    const uint8_t destination_public[32],
	    const uint8_t expected_token[16],
	    const uint8_t expected_checkpoint_digest[32],
	    durable_handoff &ticket);
	    /* Decode only a signed committed ticket bound to this checkpoint. */
	bool stage_imported_source_release(
	    const uint8_t wire[DTRACED_RELEASE_ATTESTED_SIZE],
	    const uint8_t source_public[32],
	    const uint8_t destination_public[32],
	    const uint8_t expected_token[16],
	    const uint8_t expected_checkpoint_digest[32]);
	    /* Durable foreign HSA1 only; never creates a handoff phase or lease. */
	int read_imported_source_release(
	    const uint8_t source_public[32],
	    const uint8_t destination_public[32],
	    const uint8_t expected_token[16],
	    const uint8_t expected_checkpoint_digest[32],
	    durable_handoff &ticket);
	    /* -1 invalid, 0 absent, 1 verified against current pinned keys. */
	bool adopt_imported_source_release(const std::array<uint8_t, 16> &,
	    const uint8_t checkpoint_digest[32]);
	    /* Persist the exact signed foreign source cut as a local committed
	     * ticket. This does not reserve a destination or grant execution. */
	bool reserve_handoff(const durable_handoff &); /* caller checks VMM attestation */
	bool cancel_handoff_reservation(const durable_handoff &);
	/* Retired MUTATE recovery is journaled separately from reserved CANCEL. */
	bool reset_handoff_mutation(const std::array<uint8_t, 16> &,
	    const std::array<uint8_t, 32> &, uint16_t, uint64_t);
	bool begin_handoff_mutation(const durable_handoff &);
	bool claim_handoff(const durable_handoff &); /* caller checks VMM attestation */
	bool mark_handoff_rekey_applied(const durable_handoff &);
	int handoff_rekey_applied_status(const durable_handoff &);
	    /* -1 invalid, 0 absent, 1 exact guest-applied rekey record. */
	bool mark_handoff_execution_start(const durable_handoff &);
	int handoff_execution_start_status(const durable_handoff &);
	bool begin_handoff_rebind(const durable_handoff &, uint16_t,
	    uint64_t, const std::array<uint8_t, 16> &, uint32_t, uint32_t);
	    /* HRI1 intent only; verifies old VMM epoch retired, no execution. */
	bool stage_handoff_rebind(const durable_handoff &, uint16_t,
	    uint64_t, const std::array<uint8_t, 16> &, uint32_t, uint32_t);
	    /* HRP1 write-ahead plan; no journal mutation or execution lease. */
	bool publish_handoff_rebind_pending(const durable_handoff &, uint16_t,
	    uint64_t, const std::array<uint8_t, 16> &, uint32_t, uint32_t);
	    /* Exact, inert HTD5 pending records; retry repairs partial writes. */
	bool commit_handoff_rebind_empty(const durable_handoff &, uint16_t,
	    uint64_t, const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    bool publish = true);
	    /* HRC1 commits only a verified empty local journal; restart repairs. */
	bool handoff_rebind_empty_plan_ready(const durable_handoff &, uint16_t,
	    uint64_t, const std::array<uint8_t, 16> &, uint32_t, uint32_t);
	    /* Read-only HRI1/HRP1 and old-epoch check before restore mutation. */
	bool handoff_rebind_nonempty_preflight(const durable_handoff &, uint16_t,
	    uint64_t, const std::array<uint8_t, 16> &, uint32_t, uint32_t);
	    /* Read-only exact HRP1/HTD5 census; no journal or owner commit. */
	bool handoff_rebind_empty_done(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t);
	    /* Exact durable completion witness for a lost commit reply. */
	bool cancel_handoff_rebind_pending(const durable_handoff &);
	    /* Retired epochs only; removes exact pending records for supersession. */
	    /* -1 invalid, 0 absent, 1 durable pre-vCPU release intent. */
	int handoff_status(const std::array<uint8_t, 16> &, durable_handoff &);
	    /* -1 error, 0 absent, or phase; returns exact durable record */
	int handoff_delivery_status(const durable_handoff &, uint8_t, uint64_t,
	    const std::array<uint8_t, 16> &, const std::array<uint8_t, 16> &,
	    durable_delivery_state &, bool &, bool &, dir *ingress = nullptr);
	    /* -1 error, 0 absent, 1 exact; last bool proves an outbound
	     * payload or a durable host-ingress acceptance receipt. */
	bool bind_handoff_delivery(const durable_handoff &, uint64_t,
	    const std::array<uint8_t, 16> &, const std::array<uint8_t, 16> &,
	    const uint8_t expected_payload_digest[32],
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    durable_delivery_state &);
	    /* Claims an exact saved ELF digest for one destination HTD5. */
	int bound_handoff_status(const durable_delivery &, bool &);
	    /* -1 invalid, 0 not claimed, 1 claimed; bool reflects source KILL. */
	int handoff_kill_status(const durable_handoff &, pid_t,
	    const std::array<uint8_t, 16> &, bool &);
	    /* -1 error, 0 absent, 'p' pending, 'a' applied; never grants replay */
	int handoff_cleanup_status(const durable_handoff &, uint64_t);
	    /* -1 error, 0 absent, or 'a' for exact accepted source cleanup. */
	int bind_handoff_kill(const durable_handoff &, pid_t,
	    const std::array<uint8_t, 16> &);
	    /* Post-CLAIM source KILL to destination; -1 error, 'p' or 'a'. */
	bool bind_handoff_kills_all(const durable_handoff &);
	    /* Post-CLAIM, copy every source KILL; retry completes a partial copy. */
	int source_handoff_for_vm(uint16_t, uint64_t, durable_handoff &);
	    /* -1 error, 0 absent, or phase for one source VM incarnation */
	int with_source_handoff_phase(uint16_t, uint64_t,
	    const std::function<void(int)> &);
	    /* Run admission while the source handoff lock holds its phase. */
	bool record_delivery(const durable_delivery &, delivery_phase,
	    bool require_new = false);
	bool retire_terminal_delivery(const durable_delivery &);
	bool retire_accepted_outbound(const durable_delivery &);
	int delivery_status(const durable_delivery &); /* -1 error, 0 absent, or phase */
	int resolve_host_delivery(const durable_delivery &,
	    durable_delivery_state &); /* resolve HTD3/HTD4 by exact owner/key */
	bool list_deliveries(std::vector<durable_delivery_state> &);
	int record_consumer_receipt(const durable_consumer_receipt &,
	    consumer_receipt_phase);
	int consumer_cohort(const durable_delivery &,
	    const std::vector<durable_consumer_receipt> &,
	    std::vector<durable_consumer_receipt> &);
	    /* -1 error, 0 no cohort, 1 durable exact recipient set. */
	int record_consumer_program(const durable_consumer_receipt &,
	    const client_fd &);
	/* 1 exact HHL1, 0 legacy/missing, -1 invalid; output unchanged on failure. */
	/* Kernel evidence only; never sufficient to publish collector stop proof. */
	int consumer_kernel_handle_retired(const durable_consumer_receipt &);
	/* Recover a live pin from boot-bound verified evidence; never infer exit. */
	int recover_consumer_process(const durable_consumer_receipt &,
	    class collector_owner_registry &);
	/* 1 durable explicit process exit, 0 live, -1 unproven/error; not FSA1. */
	/* Verified registry identity, even before a delivery has been admitted. */
	int checkpoint_collector_exit(const std::array<uint8_t, 96> &,
	    class collector_owner_registry &);
	int checkpoint_consumer_process_exit(const durable_consumer_receipt &,
	    class collector_owner_registry &);
	/* 1 durable empty-reaper exit, 0 missing, -1 invalid; not FSA1. */
	int consumer_reaper_exit_status(const durable_consumer_receipt &);
	/* 1: the exact verified HPB1 registration belongs to an earlier kernel
	 * boot, so the collector, every descendant and its kernel handle ended
	 * with that boot. 0: same boot or no HPB1. -1: invalid/unavailable.
	 * Not FSA1: the stop publisher still requires its live source gate. */
	int consumer_prior_boot_retired(const durable_consumer_receipt &);
	int consumer_process_exited(const durable_consumer_receipt &,
	    class collector_owner_registry &);
	int consumer_handle_status(const durable_consumer_receipt &,
	    std::array<uint8_t, 24> &);
	int consumer_program_status(const durable_consumer_receipt &,
	    std::array<uint8_t, 76> &, std::array<uint8_t, 32> &);
	    /* HCP1 source evidence: exact HCR1, HCO1 incarnation and HPI1. */
	int record_consumer_execution(const durable_consumer_receipt &,
	    consumer_receipt_phase, bool publish = true);
	bool recover_consumer_executions(
	    const std::vector<durable_consumer_receipt_state> &);
	static bool encode_import_consumer_receipt(
	    const durable_import_consumer_receipt &, std::vector<uint8_t> &);
	static bool decode_import_consumer_receipt(const durable_delivery &,
	    const std::vector<uint8_t> &, durable_import_consumer_receipt &);
	static bool encode_import_consumer_cohort(const durable_delivery &,
	    const std::vector<durable_import_consumer_receipt> &,
	    std::vector<uint8_t> &);
	static bool decode_import_consumer_cohort(const durable_delivery &,
	    const std::vector<uint8_t> &,
	    std::vector<durable_import_consumer_receipt> &);
	    /* Canonical HCR2/HCB2 codecs only; no journal publication or replay. */
	static bool encode_import_consumer_result(
	    const durable_import_consumer_result &, std::vector<uint8_t> &);
	static bool decode_import_consumer_result(
	    const std::vector<uint8_t> &, durable_import_consumer_result &);
	    /* HRO1 outcome codec; no publication or execution authority. */
	static bool plan_import_consumer_cohorts(
	    const host_ingress_destination_plan &,
	    const std::vector<std::array<uint8_t, 76>> &,
	    std::vector<std::vector<uint8_t>> &);
	    /* Pure HTM2/HTL1-to-HCB2 planning; no journal or execution grant. */
	int host_ingress_transfer_manifest(const durable_handoff &,
	    std::vector<uint8_t> &);
	    /* -1 error, 0 no ingress, 1 bounded HTM1 metadata; ELF bytes are
	     * verified in the source spool but must be transferred separately. */
	int host_ingress_transfer_snapshot(const durable_handoff &,
	    std::vector<uint8_t> &);
	    /* Acquires the source cut lock and audits derived claims before
	     * returning a provisional HTM1 export. */
	int host_ingress_program_manifest(const durable_handoff &,
	    const std::vector<uint8_t> &, std::vector<uint8_t> &);
	static bool validate_host_ingress_program_manifest(
	    const durable_handoff &, const std::vector<uint8_t> &,
	    std::vector<uint8_t> * = nullptr,
	    std::vector<host_ingress_program_evidence> * = nullptr);
	    /* Provisional HTM2 binds HTM1 to source HCP1 proof per recipient. */
	int host_ingress_transfer_frame(const durable_handoff &,
	    const std::vector<uint8_t> &, size_t, std::vector<uint8_t> &);
	    /* -1 error, 1 HTP1 frame; rereads HTM1 and exact ELF under the
	     * source lock. PREPARE must still bind the completed export. */
	int host_ingress_transfer_bundle_export(const durable_handoff &,
	    std::vector<uint8_t> &, std::vector<std::vector<uint8_t>> &,
	    bool with_programs = false);
	    /* One lock-protected HTM1/HTP1 source cut. Results stay private until
	     * every member passes verification and the total fits the transfer cap. */
	static bool validate_host_ingress_transfer_manifest(
	    const durable_handoff &, const std::vector<uint8_t> &,
	    std::vector<host_ingress_transfer_entry> *decoded = nullptr);
	static bool validate_host_ingress_transfer_payload(
	    const durable_delivery &, const std::vector<uint8_t> &);
	static bool encode_host_ingress_transfer_frame(
	    const durable_handoff &, const durable_delivery &,
	    const std::vector<uint8_t> &, std::vector<uint8_t> &);
	static bool decode_host_ingress_transfer_frame(
	    const durable_handoff &, const durable_delivery &,
	    const std::vector<uint8_t> &, std::vector<uint8_t> * = nullptr);
	static bool decode_host_ingress_transfer_bundle(
	    const durable_handoff &, const std::vector<uint8_t> &,
	    const std::vector<std::vector<uint8_t>> &,
	    host_ingress_transfer_bundle &);
	static bool decode_host_ingress_transfer_wire(
	    const durable_handoff &, const std::vector<uint8_t> &,
	    host_ingress_transfer_bundle &);
	static bool plan_host_ingress_destination(
	    const durable_handoff &, const std::vector<uint8_t> &,
	    const std::vector<std::vector<uint8_t>> &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &, host_ingress_destination_plan &);
	bool stage_host_ingress_destination(const durable_handoff &,
	    const std::vector<uint8_t> &,
	    const std::vector<std::vector<uint8_t>> &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &, host_ingress_destination_plan &);
	int stage_host_ingress_destination_wire(const durable_handoff &,
	    const std::vector<uint8_t> &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &, host_ingress_destination_plan &);
	    /* Component helper: -1 invalid, 0 empty, 1 inert HTB1 stage.
	     * Wire handlers must use the reserved-ticket wrapper below. */
	int stage_host_ingress_destination_wire_reserved(
	    const durable_handoff &, const std::vector<uint8_t> &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &, host_ingress_destination_plan &);
	    /* Holds the outbound ticket lock through publication. Returns 2 for
	     * inert HJB1 journal stage; never treat 2 as completed import. */
	int load_host_ingress_destination_stage(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &, host_ingress_destination_plan &);
	bool import_host_ingress_pending(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &);
	bool reserve_host_ingress_consumer_owners(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &);
	    /* Inert HTL1 owner reservation. No accepted HTD5 or job is exposed. */
	int load_host_ingress_consumer_owners(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &,
	    std::vector<std::array<uint8_t, 76>> &);
	    /* -1 invalid, 0 absent, 1 exact durable owner snapshot; no liveness. */
	int load_import_consumer_cohorts(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &, std::vector<std::vector<uint8_t>> &);
	    /* -1 invalid, 0 absent, 1 exact inert HCK1/HCB2 bundle. */
	int load_import_pending_results(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &,
	    std::vector<std::array<uint8_t, 32>> &);
	    /* -1 invalid, 0 absent, 1 exact HRS1 pending-slot identities. */
	int load_import_promotion_intent(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &,
	    std::vector<std::array<uint8_t, 32>> &, bool allow_accepted = false);
	    /* -1 invalid, 0 absent, 1 exact inert HPA1 HTD5 identities.
	     * Recovery may inspect a mixed pending/accepted journal, but this
	     * reader grants no execution authority. */
	bool promote_import_host_ingress(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &);
	    /* Claimed ticket only. Finish exact HTD5 phases, then HLC1 commit;
	     * the watcher still needs a separate execution/replay rule. */
	int load_committed_import_host_ingress(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &,
	    std::vector<std::array<uint8_t, 32>> &);
	    /* -1 invalid, 0 no HLC1, 1 exact committed HTD5 set. Read-only;
	     * HLC1 is a prerequisite, not an execution lease. */
	int load_committed_import_recipients(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &,
	    std::vector<durable_committed_import_entry> &);
	    /* Same locked HLC1 verification with each canonical HCB2 decoded
	     * against its HTD5. No liveness or execution permission is implied. */
	int record_import_consumer_result(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &, const durable_import_consumer_result &);
	    /* Internal journal transaction. Caller must prove consumer ACK,
	     * derived claim, and execution report before choosing a phase. */
	int record_activated_import_consumer_result(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &, const durable_import_consumer_result &);
	    /* Same transaction, but requires the exact durable HLA1 and audits
	     * all fixed HRS1 slots before publishing an HRO1. */
	int load_import_consumer_result(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &, const std::array<uint8_t, 32> &,
	    durable_import_consumer_result &);
	    /* -1 invalid, 0 pending HRS1 slot, otherwise exact HRO1 phase.
	     * Same committed-ticket and fixed-slot verification as the writer. */
	int load_committed_import_results(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &,
	    std::vector<durable_committed_import_result_state> &);
	    /* -1 invalid, 0 no HLC1, 1 complete fixed HRS1/HRO1 recovery view.
	     * Pending recipients retain their HCR2 owner and program digest. */
	bool activate_import_host_ingress(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &);
	    /* Claimed HLC1 plus durable REKEY_APPLIED; publish exact HLA1 after
	     * auditing every fixed recipient outcome. No queue publication. */
	int load_import_activation(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &);
	    /* -1 invalid, 0 no HLA1, 1 exact post-rekey activation marker. */
	int load_activated_import_view(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    const std::string &,
	    std::vector<durable_committed_import_entry> &,
	    std::vector<durable_committed_import_result_state> &);
	    /* Atomic read of fixed recipients and outcomes behind HLA1.
	     * This view does not grant a recipient execution lease. */
	int load_activated_import_recipient(
	    const std::array<uint8_t, 16> &,
	    const std::array<uint8_t, 16> &, uint64_t,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    durable_committed_import_result_state &);
	    /* Resolve a consumer report against one HCR2 under the HLA1 gate.
	     * -1 invalid, 0 absent/inactive, 1 exact recipient and outcome. */
	int list_activated_import_recipients(client_fd *,
	    std::vector<durable_committed_import_result_state> &);
	    /* Per-ticket validated recovery census for one live HCO1/HPI1 owner.
	     * Revalidate each recipient before any future socket dispatch. */
	int queue_activated_import_consumer(client_fd *,
	    const std::array<uint8_t, 16> * = nullptr);
	    /* Queue pending fixed HCR2 work for one live receiver after activation
	     * or program registration. The job revalidates before sending. */
	int resolve_import_derived_outbound(dir &,
	    const durable_committed_import_result_state &,
	    const durable_derived_claim &, std::array<uint8_t, 32> &);
	    /* -1 inconsistent, 0 durable claim lacks spool/accepted outbound,
	     * 1 exact HCR2/HDU2 lineage with a published derived result. */
	int record_activated_import_processing(
	    const durable_committed_import_result_state &,
	    consumer_receipt_phase, const std::array<uint8_t, 32> &);
	    /* Internal ACK caller only: recheck HCR2/HLA1 and publish the
	     * immutable processed HRO1. Caller proves ACK and any HDU2 result. */
	int record_activated_import_execution(
	    const std::array<uint8_t, 16> &,
	    const std::array<uint8_t, 16> &, uint64_t,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    consumer_receipt_phase);
	    /* Exact HCR2 report: require processed HRO1, then publish terminal
	     * HRO1 under the HLA1, ticket, and inbound journal locks. */
	bool rollback_host_ingress_pending_locked(const durable_handoff &);
	    /* Caller holds the outbound handoff process lock. Delete only exact
	     * pending HTD5 records before CANCEL releases the reservation. */
	bool recover_consumer_cohorts(
	    const std::vector<durable_delivery_state> &);
	    /* Complete HCR1 writes interrupted after a cohort publication. */
	    /* -1 error or the durable phase; pending may observe processed. */
	bool list_consumer_receipts(
	    std::vector<durable_consumer_receipt_state> &);
	int consumer_receipt_exact(const std::array<uint8_t, 16> &,
	    uint64_t, const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    durable_consumer_receipt_state &);
	    /* -1 invalid journal, 0 absent, 1 exact HCR1 recipient,
	     * 2 exact accepted HTD5 ingress requiring HCR2/HLA1 lookup. */
	int resolve_derived_outbound(dir &, const uint8_t[16],
	    const uint8_t[16], durable_consumer_receipt_state &);
	bool list_derived_claims(std::vector<durable_derived_claim> &);
	bool audit_derived_claims(dir &,
	    const std::vector<durable_derived_claim> &,
	    const std::vector<durable_consumer_receipt_state> &,
	    const std::vector<durable_delivery_state> &,
	    bool reconcile_pending = false,
	    const std::vector<durable_delivery_state> *locked_outbound = nullptr);
	int queue_recovered_consumer(client_fd *);
	    /* -1 error, 0 no matching pending work, 1 queued to exact consumer */
	bool fence_guest_rekey(uint8_t, uint16_t, uint64_t, uint16_t, uint64_t);
	    /* Durable old-identity admission fence only; caller proves handoff. */
	bool fence_guest_rekey_pair(dir &, uint16_t, uint64_t, uint16_t,
	    uint64_t);
	    /* Call on inbound with outbound: validate both before either fence. */
	bool guest_rekey_pair_complete(dir &, uint16_t, uint64_t, uint16_t,
	    uint64_t);
	    /* Read-only journal predicate; caller still proves host receipts. */
	bool rekey_guest_journals_with_receipts(dir &, uint16_t, uint64_t,
	    uint16_t, uint64_t,
	    const std::function<bool(const durable_delivery_state &)> &,
	    const std::function<bool(const durable_delivery_state &)> &,
	    const std::function<bool(const durable_kill &)> &);
	    /* Paused-guest transaction; callbacks must prove exact host receipts
	     * and handoff authorization before each durable rewrite. No ioctl. */
	bool rekey_guest_delivery(const durable_delivery_state &, uint16_t,
	    uint64_t);
	    /* Exact-record durable rewrite; caller proves host receipt. */
	int host_ingress_phase(const uint8_t[16], const uint8_t[16],
	    durable_delivery_state * = nullptr);
	int lookup_host_ingress(const durable_delivery &,
	    durable_delivery_state &); /* -1 error, 0 absent, 1 exact */
	bool copy_data(int, const char *);
	bool listen(void);
	bool file_exists(const char *);
	bool memorized(const std::string &);
	bool memorize_file(struct dirent *);
	bool rmpath(const std::string &);
	bool request_reprocess(const uint8_t[16], const uint8_t[16],
	    const uint8_t[32], bool envelope = false);
	void request_scan(void);
	bool hash_identified_data(const uint8_t[16], const uint8_t[16],
	    uint8_t[32], bool envelope = false, bool target = false,
	    uint8_t bare_elf_digest[32] = nullptr);
	int verify_host_delivery_payload(const durable_delivery &,
	    std::vector<uint8_t> *verified_copy = nullptr);
	    /* -1 error, 0 absent, 1 exact outbound ELF; failed copy stays empty. */
	static bool validate_host_delivery_payload(const durable_delivery &,
	    const std::vector<uint8_t> &);
	    /* Check copied outbound bytes without trusting a source pathname. */
	static bool encode_source_journal_archive(const durable_handoff &,
	    const source_journal_cut &, std::vector<uint8_t> &);
	bool source_journal_transfer_wire_export(const durable_handoff &,
	    std::vector<uint8_t> &, bool require_source_gate = false);
	    /* Exact HTX1 source export before PREPARE; no ticket publication. */
	static bool decode_source_journal_archive(const durable_handoff &,
	    const uint8_t *, size_t, source_journal_cut &);
	    /* HJX1 is an inert, ticket-bound portable source journal image. */
	static bool decode_source_journal_transfer_wire(
	    const durable_handoff &, const std::vector<uint8_t> &,
	    source_journal_cut &, host_ingress_transfer_bundle &);
	    /* Private destination decode of both parts of a reserved HJM1/HTX1. */
	bool stage_source_journal_destination_wire(
	    const durable_handoff &, const std::vector<uint8_t> &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t);
	    /* Durable, inert HJB1 under the reserved outbound handoff lock. */
	int load_source_journal_destination_stage(const durable_handoff &,
	    source_journal_cut &, host_ingress_transfer_bundle &);
	    /* -1 invalid, 0 absent, 1 exact HJB1 decoded after daemon restart. */
	int plan_source_journal_destination(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    source_journal_destination_plan &);
	    /* -1 invalid, 0 absent, 1 read-only destination lifetime mapping. */
	bool import_source_journal_pending(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t);
	    /* Publish only ticket-bound pending HTD5 receipts; HJB1 holds ELF bytes. */
	int source_journal_pending_status(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    source_journal_destination_plan &);
	    /* -1 invalid, 0 absent stage, 1 partial, 2 complete pending import. */
	int claimed_source_journal_status(const durable_handoff &,
	    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
	    bool require_replays = false);
	    /* -1 refused, 0 no journal, 1 exact claimed journal (or pending
	     * replay), 2 all mapped ELF receipts accepted when required. */
	int claimed_source_journal_replay_payload(const durable_delivery &,
	    std::vector<uint8_t> &);
	    /* -1 refused, 1 exact bare ELF; claimed ticket and pending HTD5 only. */
	bool accept_claimed_source_journal_replay(const durable_delivery &);
	    /* Persist an ACK for the exact claimed HTD5; ordinary API stays fenced. */
	int verify_host_ingress_payload(const durable_delivery &,
	    std::vector<uint8_t> *verified_copy = nullptr);
	    /* -1 error, 0 absent, 1 exact ingress ELF; a failed copy stays empty. */
	int verify_pending_outbound(const durable_delivery &); /* -1 error, 0 absent, 1 match */
	int queue_recovered_outbound(const durable_delivery &,
	    uint16_t, uint64_t); /* -1 error, 0 no forwarder, 1 queued */
	bool withdraw_pending_delivery(const durable_delivery &);
	    /* Remove a pending scope-0/2 HTD4 token whose spool no longer
	     * exists (a refused publication): nothing was or can be sent. */
	int queue_pending_host_outbound(client_fd *);
	    /* Host admission: resend this forwarder's pending HTD4 records
	     * with their recorded delivery IDs. -1 error, else jobs queued. */
	void forget_unrecorded_host_spools(
	    const std::vector<durable_delivery_state> &);
	    /* Host start: a spool no forwarder record names was never queued;
	     * leave it unmemorized so the next forwarder receives it. */
	bool forget_unassigned_ingress(
	    const std::vector<durable_delivery_state> &);
	    /* Host start: an accepted upload without a cohort or receipt was
	     * never assigned; leave it unmemorized for the next consumer. */
	int queue_claimed_source_journal_replay(const durable_delivery &);
	    /* -1 error, 0 no exact attested forwarder, 1 claimed HTD5 queued. */
	bool populate_existing(void);
	const std::string &full_path() const { return (this->dirpath); }
};

bool process_inbound(dir &, struct dirent *);
bool process_base(dir &, struct dirent *);
bool process_outbound(dir &, struct dirent *);
}

#endif // _DTRACED_DIRECTORY_H_
