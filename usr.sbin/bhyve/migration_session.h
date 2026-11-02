/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Live-migration control plane for bhyve: a versioned, checksummed
 * source/destination session protocol driven on top of the existing
 * migration_precopy/migration_dirty/snapshot foundations.
 *
 * This header defines three independently testable layers:
 *
 *   1. a fixed-width little-endian wire codec (frame header + typed messages)
 *      with no host pointer, descriptor, or size_t on the wire;
 *   2. capability/topology negotiation and fail-closed validation; and
 *   3. source and destination session state machines that drive handshake,
 *      pre-quiesce validation, iterative pre-copy, event-fenced stop-and-copy,
 *      atomic destination commit, and source rollback.
 *
 * The transport is an injectable vtable (struct migration_transport).  It
 * does not authenticate the peer; the caller must provide that property
 * before any authority-bearing state can cross hosts.  A thin
 * file-descriptor adapter (migration_transport_fd_*) is the only piece that
 * touches sockets; it is deliberately separated so the state machine and codec
 * run in-process over a socketpair or an injected transport with no network,
 * no root, and no running VM.  The supplied transport must enforce the
 * operator's peer trust and confidentiality policy; the frame codec provides
 * integrity checks for accidental corruption, not peer authentication.
 */

#ifndef _BHYVE_MIGRATION_SESSION_H_
#define _BHYVE_MIGRATION_SESSION_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "migration_precopy.h"

/* ---- Wire constants ------------------------------------------------------ */

#define	MIGRATION_PROTO_MAGIC		0x4D494731u	/* "MIG1" */
/*
 * Version 3 is the protocol between current builds: every handoff is
 * confirmed (challenge-bound COMMIT and RELEASE, RELEASE_ACK, and a
 * destination that retains rather than discards a committed image), and
 * active vsock state may be carried.  Version 2 (vsock state without a
 * confirmed handoff) was never released and is refused.  Version 1 is
 * admitted only from a qualified v0.1.0 source through
 * MIGRATION_CAP_V2_RESTORE: the destination still never discards a
 * committed image, but such a source cannot confirm the handoff.
 */
#define	MIGRATION_PROTO_VERSION		3u
#define	MIGRATION_PROTO_VERSION_MIN	1u
/* The frame layout is unchanged since version 1. */
#define	MIGRATION_FRAME_VERSION_MIN	1u

#define	MIGRATION_FRAME_HDR_SIZE	24u
#define	MIGRATION_MAX_PAYLOAD		(16u * 1024u * 1024u)
#define	MIGRATION_MAX_DEVICES		256u
#define	MIGRATION_MACHINE_ABI_MAX	32u
#define	MIGRATION_DEVICE_NAME_MAX	40u

#define	MIGRATION_HELLO_SIZE		88u
#define	MIGRATION_CAPS_ACCEPT_SIZE	12u
#define	MIGRATION_REASON_SIZE		8u
#define	MIGRATION_TOPOLOGY_HDR_SIZE	44u
#define	MIGRATION_DEVREC_SIZE		56u
#define	MIGRATION_MEMGEN_HDR_SIZE	72u
#define	MIGRATION_CHUNK_HDR_SIZE	24u

/*
 * Frame-header flag bits.  A message whose serialized form exceeds one frame is
 * split into ordered chunks; each chunk frame carries the MIGRATION_FFLAG_CHUNK
 * bit and a fixed-width chunk sub-header immediately after any fixed message
 * header (the memory-generation header for MIGRATION_MSG_MEM_GEN, nothing for
 * MIGRATION_MSG_DEV_STATE).  A message that fits in a single frame is sent with
 * flags == 0 and no chunk sub-header, byte-identical to the unchunked format.
 */
#define	MIGRATION_FFLAG_CHUNK		(1u << 0)

/*
 * Upper bound on a reassembled device/kernel-state blob.  Guest RAM is streamed
 * separately as memory generations; the device+CPU/vCPU/kernel blob is bounded
 * well under this.  A peer advertising a larger total is rejected before any
 * allocation.
 */
#define	MIGRATION_MAX_DEV_STATE		(512u * 1024u * 1024u)
#define	MIGRATION_MAX_VSOCK_STATE	(512u * 1024u * 1024u)

/*
 * Message types (frame header "type" field).  TOPO_ACCEPT, MEM_ACK, and
 * COMMIT have empty payloads.  FINAL and RELEASE carry a reason record with
 * reason_code == MIGRATION_REASON_NONE and detail == 0.
 */
enum migration_msg_type {
	MIGRATION_MSG_HELLO		= 1,
	MIGRATION_MSG_CAPS_ACCEPT	= 2,
	MIGRATION_MSG_CAPS_REJECT	= 3,
	MIGRATION_MSG_TOPOLOGY		= 4,
	MIGRATION_MSG_TOPO_ACCEPT	= 5,
	MIGRATION_MSG_TOPO_REJECT	= 6,
	MIGRATION_MSG_MEM_GEN		= 7,
	MIGRATION_MSG_MEM_ACK		= 8,
	MIGRATION_MSG_DEV_STATE		= 9,
	MIGRATION_MSG_FINAL		= 10,
	MIGRATION_MSG_COMMIT		= 11,
	MIGRATION_MSG_RELEASE		= 12,
	MIGRATION_MSG_ABORT		= 13,
	MIGRATION_MSG_VSOCK_STATE	= 14,	/* version >= 2 */
	MIGRATION_MSG_RELEASE_ACK	= 15,	/* version >= 3: destination resumed */
};

/* HELLO role field. */
#define	MIGRATION_ROLE_SOURCE	0u
#define	MIGRATION_ROLE_DEST	1u

/*
 * Device external-state contract bits carried in a topology device record's
 * migration_flags.  These mirror the PCI_MIGRATION_F_* values in pci_emul.h so
 * the pure codec/validation core has no dependency on the PCI device layer; the
 * production adapter static-asserts that the two definitions stay identical.
 */
#define	MIGRATION_DEVF_STATE_CODEC	(1u << 0)
#define	MIGRATION_DEVF_COMPAT_FIXED	(1u << 1)
#define	MIGRATION_DEVF_COMPAT_CALLBACK	(1u << 2)
#define	MIGRATION_DEVF_DMA_NONE		(1u << 3)
#define	MIGRATION_DEVF_DMA_TRACKED	(1u << 4)
#define	MIGRATION_DEVF_QUIESCE_NONE	(1u << 5)
#define	MIGRATION_DEVF_QUIESCE_CALLBACK	(1u << 6)
#define	MIGRATION_DEVF_ALL	(MIGRATION_DEVF_STATE_CODEC | \
	MIGRATION_DEVF_COMPAT_FIXED | MIGRATION_DEVF_COMPAT_CALLBACK | \
	MIGRATION_DEVF_DMA_NONE | MIGRATION_DEVF_DMA_TRACKED | \
	MIGRATION_DEVF_QUIESCE_NONE | MIGRATION_DEVF_QUIESCE_CALLBACK)

/* Capability flags carried in HELLO.capability_flags. */
#define	MIGRATION_CAP_PRECOPY		(1ull << 0)
#define	MIGRATION_CAP_DEVICE_DIRTY	(1ull << 1)
/* Destination-only admission gate for a qualified v0.1.0 source. */
#define	MIGRATION_CAP_V2_RESTORE	(1ull << 2)
#define	MIGRATION_CAP_VSOCK_STATE	(1ull << 3)
/* Active tracing mode, not a best-effort optimization: both endpoints must
 * advertise it and the source must implement retirement before RELEASE.
 * Production must not advertise it until fresh state/reset wiring is complete. */
#define	MIGRATION_CAP_HYPERTRACE_FRESH	(1ull << 4)
/* A version 3 COMMIT carries a per-attempt destination challenge. RELEASE
 * echoes it after the ordinary success result, only after source retirement.
 * This binds the exchange on a trusted stream; it is not peer authentication. */
#define MIGRATION_FRESH_CHALLENGE_SIZE 32u
#define MIGRATION_FRESH_RELEASE_SIZE (MIGRATION_REASON_SIZE + \
    MIGRATION_FRESH_CHALLENGE_SIZE)
#define	MIGRATION_CAP_ALL		(MIGRATION_CAP_PRECOPY | \
					 MIGRATION_CAP_DEVICE_DIRTY | \
					 MIGRATION_CAP_V2_RESTORE | \
					 MIGRATION_CAP_VSOCK_STATE | \
					 MIGRATION_CAP_HYPERTRACE_FRESH)

/* Structured rejection/abort reasons.  Stable wire values. */
enum migration_reason {
	MIGRATION_REASON_NONE		= 0,
	MIGRATION_REASON_MAGIC		= 1,
	MIGRATION_REASON_VERSION	= 2,
	MIGRATION_REASON_ARCH		= 3,
	MIGRATION_REASON_PAGESIZE	= 4,
	MIGRATION_REASON_CPU		= 5,
	MIGRATION_REASON_MACHINE_ABI	= 6,
	MIGRATION_REASON_INTR		= 7,
	MIGRATION_REASON_CAPS		= 8,
	MIGRATION_REASON_MEMSIZE	= 9,
	MIGRATION_REASON_CPUCOUNT	= 10,	/* vCPU count differs */
	MIGRATION_REASON_TOPOLOGY	= 11,	/* CPU shape or device count */
	MIGRATION_REASON_DEVICE		= 12,
	MIGRATION_REASON_RESOURCE	= 13,
	MIGRATION_REASON_PROTOCOL	= 14,
	MIGRATION_REASON_CANCELLED	= 15,
	MIGRATION_REASON_TIMEOUT	= 16,
	MIGRATION_REASON_CONVERGENCE	= 17,
	MIGRATION_REASON_TRANSPORT	= 18,
	MIGRATION_REASON_STATE		= 19,
	MIGRATION_REASON_INTERNAL	= 20,
};

/* ---- Host-side message structs (codec converts to/from wire) ------------- */

struct migration_frame_header {
	uint32_t magic;
	uint16_t version;
	uint16_t type;
	uint32_t flags;
	uint32_t seq;
	uint32_t length;
	uint32_t crc32;
};

struct migration_hello {
	uint16_t version_max;
	uint16_t version_min;
	uint8_t  role;
	uint32_t arch_id;
	uint32_t page_size;
	uint32_t cpu_family;
	uint32_t cpu_model;
	uint32_t cpu_stepping;
	uint64_t cpu_feature_hash;
	uint32_t intr_controller;
	uint64_t capability_flags;
	char     machine_abi[MIGRATION_MACHINE_ABI_MAX];
};

struct migration_caps_accept {
	uint16_t negotiated_version;
	uint64_t capability_flags;
};

struct migration_reason_msg {
	uint32_t reason_code;
	uint32_t detail;
};

struct migration_device_record {
	char     name[MIGRATION_DEVICE_NAME_MAX];
	uint32_t migration_flags;
	uint32_t compat_schema;
	uint32_t compat_crc32;
	uint32_t bar_hash;
};

struct migration_topology {
	uint64_t mem_size;
	uint64_t lowmem;
	uint64_t highmem;
	uint32_t ncpus;
	uint16_t sockets;
	uint16_t cores;
	uint16_t threads;
	uint32_t device_count;
	struct migration_device_record devices[MIGRATION_MAX_DEVICES];
};

/* A per-instance byte range excluded from a fixed ROM's identity digest. */
struct migration_rom_mask {
	size_t offset;
	size_t length;
};

/*
 * Fill a fixed-ROM pseudo-device record (_vmm.bootrom, _vmm.pcirom) from the
 * segment bytes.  Masked ranges hold per-instance contents: only their
 * placement, never their bytes, enters compat_crc32/bar_hash.
 */
int	migration_rom_identity_record(struct migration_device_record *rec,
	    const char *name, const void *base, size_t length,
	    const struct migration_rom_mask *masks, size_t nmasks);

struct migration_memgen {
	uint32_t round;
	uint32_t mode;
	uint64_t gpa;
	uint64_t length;
	uint64_t cpu_identity;
	uint64_t cpu_map_generation;
	uint64_t cpu_dirty_generation;
	uint64_t device_identity;
	uint64_t device_dirty_generation;
	uint32_t page_count;
	uint32_t final;
};

/*
 * Chunk sub-header for a multi-frame logical message.  total_length is the full
 * reassembled payload length, or 0 when the producer streams an a-priori
 * unknown length (memory generations) and termination is signalled by final.
 * offset is the byte offset of this chunk within the logical payload; the
 * destination requires strictly contiguous, in-order offsets and rejects gaps,
 * duplicates, and oversize chunks before touching any staging buffer.
 */
struct migration_chunk {
	uint64_t total_length;
	uint64_t offset;
	uint32_t chunk_length;
	uint32_t final;
};

/* ---- Codec --------------------------------------------------------------- */

/*
 * Encode a complete frame (header + payload) into out.  crc32 of the payload
 * is computed and stored.  Returns 0 and *written on success, EINVAL/EMSGSIZE
 * on bad arguments or insufficient capacity.
 */
int	migration_frame_encode(uint16_t version, uint16_t type, uint32_t seq,
	    uint32_t flags, const void *payload, size_t payload_len,
	    uint8_t *out, size_t out_cap, size_t *written);

/*
 * Decode and validate a 24-byte frame header from buf (which must contain at
 * least MIGRATION_FRAME_HDR_SIZE bytes).  Validates magic and length bound.
 */
int	migration_frame_decode_header(const uint8_t *buf, size_t len,
	    struct migration_frame_header *hdr);

/* Verify a payload buffer against a decoded header (crc + length). */
int	migration_frame_verify_payload(const struct migration_frame_header *hdr,
	    const void *payload, size_t payload_len);

int	migration_hello_encode(const struct migration_hello *, uint8_t *,
	    size_t);
int	migration_hello_decode(const uint8_t *, size_t,
	    struct migration_hello *);
int	migration_caps_accept_encode(const struct migration_caps_accept *,
	    uint8_t *, size_t);
int	migration_caps_accept_decode(const uint8_t *, size_t,
	    struct migration_caps_accept *);
int	migration_reason_encode(const struct migration_reason_msg *, uint8_t *,
	    size_t);
int	migration_reason_decode(const uint8_t *, size_t,
	    struct migration_reason_msg *);
int	migration_topology_encode(const struct migration_topology *, uint8_t *,
	    size_t, size_t *written);
int	migration_topology_decode(const uint8_t *, size_t,
	    struct migration_topology *);
int	migration_memgen_encode(const struct migration_memgen *, uint8_t *,
	    size_t);
int	migration_memgen_decode(const uint8_t *, size_t,
	    struct migration_memgen *);
int	migration_chunk_encode(const struct migration_chunk *, uint8_t *,
	    size_t);
int	migration_chunk_decode(const uint8_t *, size_t,
	    struct migration_chunk *);

/*
 * Validate a decoded chunk against the destination's running reassembly cursor
 * before any data is copied.  expect_offset is the next contiguous byte offset
 * the destination will accept; total_or_zero is the previously latched total
 * (0 if none yet or a streaming producer).  chunk_max bounds a single chunk's
 * data; reasm_cap bounds the whole reassembled payload.  Returns 0 on a valid,
 * in-order chunk, EBADMSG on an out-of-order/gap/duplicate/inconsistent chunk,
 * and EMSGSIZE on an oversize chunk or total.
 */
int	migration_chunk_validate(uint64_t expect_offset, uint64_t total_or_zero,
	    const struct migration_chunk *, size_t chunk_max, size_t reasm_cap);
int	migration_memory_record_validate(uint64_t gpa, uint32_t length,
	    uint64_t lowmem, uint64_t highmem_base, uint64_t highmem,
	    uint64_t previous_end);

/* Serialized size of an encoded topology (header + N device records). */
size_t	migration_topology_wire_size(const struct migration_topology *);

/* ---- Negotiation / validation ------------------------------------------- */

/*
 * Version negotiation with an explicit downgrade window.  Chooses the highest
 * version both peers accept; fails closed (EPROTONOSUPPORT) if the accepted
 * windows do not overlap.
 */
int	migration_negotiate_version(uint16_t local_max, uint16_t local_min,
	    uint16_t remote_max, uint16_t remote_min, uint16_t *negotiated);

/*
 * Validate a remote HELLO against the local HELLO from the destination's point
 * of view.  On success returns 0 and *negotiated; on rejection returns a
 * non-zero errno and sets *reason to a migration_reason value.  CPU state is
 * treated as non-portable: family/model/feature-hash must match exactly.
 */
int	migration_hello_validate(const struct migration_hello *local,
	    const struct migration_hello *remote, uint16_t *negotiated,
	    uint32_t *reason);
int	migration_caps_accept_validate(const struct migration_hello *source,
	    const struct migration_caps_accept *caps, uint32_t *reason);

/*
 * Structural eligibility of a single device record: exactly one compatibility,
 * DMA, and quiesce policy, the mandatory portable state codec bit, and no
 * unknown bits.  This is the wire-level enforcement of pe_migration_flags: a
 * device whose advertised flags do not encode a real external-state contract
 * is refused before the source quiesces.
 */
bool	migration_device_flags_eligible(uint32_t migration_flags);

/*
 * Validate remote topology against local topology on the destination.  Requires
 * matching memory geometry, cpu count/topology, and per-device eligibility.
 * The destination also cross-checks that every source device is present and
 * eligible locally via a caller-supplied match callback (may be NULL for a
 * structural-only check).
 */
int	migration_topology_validate(const struct migration_topology *local,
	    const struct migration_topology *remote, uint32_t *reason);
/* Describe the first field migration_topology_validate() refused (EXDEV). */
int	migration_topology_describe_mismatch(
	    const struct migration_topology *local,
	    const struct migration_topology *remote, char *buf, size_t len);

/* ---- Transport abstraction ---------------------------------------------- */

/*
 * Blocking, full-length transport.  xp_send/xp_recv transfer exactly len bytes
 * or return a non-zero errno (ETIMEDOUT, ECONNRESET, EPIPE, ...).  No framing
 * is implied; the session layer frames every message itself.
 */
struct migration_transport {
	int (*xp_send)(void *cookie, const void *buf, size_t len);
	int (*xp_recv)(void *cookie, void *buf, size_t len);
	void *xp_cookie;
};

/*
 * Thin file-descriptor transport adapter (the separately identified TCP/stream
 * layer).  The descriptor must be a connected stream socket, including a
 * socketpair for in-process loopback.  io_timeout_ms <= 0 means block
 * indefinitely.
 */
struct migration_transport_fd {
	int fd;
	int io_timeout_ms;
};
void	migration_transport_fd_init(struct migration_transport *,
	    struct migration_transport_fd *, int fd, int io_timeout_ms);

/* ---- Session drivers ----------------------------------------------------- */

struct migration_stat {
	uint32_t phase;
	uint32_t round;
	uint64_t bytes_sent;
	uint64_t last_dirty_pages;
	bool converged;
};

struct migration_progress {
	void (*mp_update)(void *cookie, const struct migration_stat *);
	void *mp_cookie;
};

struct migration_tls_credentials;
struct migration_session_config {
	uint16_t version_max;
	uint16_t version_min;
	uint32_t max_rounds;		/* convergence limit (0 => default) */
	uint64_t converge_pages;	/* dirty-page ceiling to declare cutover */
	bool abort_if_unconverged;	/* fail (source runnable) instead of forcing
					 * a cutover after max_rounds */
	const volatile int *cancel;	/* operator cancellation flag (or NULL) */
	struct migration_progress *progress;	/* optional */
	bool recovery_enabled;
	int recovery_dirfd;	/* borrowed private directory; valid only if enabled */
	/* Fresh destination only: preserve a durable HDI1 image before STAGED so a
	 * successor can reconstruct a lost controller (migration_dest_image.h). */
	bool recovery_image;
	const struct migration_tls_credentials *tls_credentials;
	/* Accept a plaintext AF_UNIX stream when tls_credentials is NULL
	 * (migration_channel_policy()); otherwise mutual TLS is required. */
	bool plaintext_unix;
};

/*
 * Source-side operations.  In production these are backed by
 * migration_precopy_collect(), guest RAM reads, PCI pause/resume, and the
 * device snapshot codecs; in tests they are backed by an in-memory model.
 *
 *   so_local_hello   fill the local capability/identity record
 *   so_local_topology fill the local machine topology + device manifest
 *   so_precopy_enable start dirty logging
 *   so_precopy_round  collect one chunk of a memory generation; serialize a
 *                     whole number of page records into buf and report
 *                     *converged, *dirty_pages (pages in THIS chunk), and
 *                     *more (true if the current generation has further page
 *                     records that did not fit in buf).  The session frames the
 *                     chunk and, while *more is true, calls again to continue
 *                     the same generation from where it left off.  *converged is
 *                     meaningful on the final chunk (*more == false).
 *   so_precopy_disable stop dirty logging (retire the bitmap)
 *   so_quiesce        event-fence: pause every vCPU/device/backend/timer.  On
 *                     failure (nonzero return) the implementation MUST set
 *                     *source_runnable to report whether the source is still a
 *                     running copy: true if it fully rolled back the partial
 *                     quiesce, false if the source is wedged (vCPUs and/or the
 *                     device fabric left paused and unrecoverable).  On success
 *                     *source_runnable is unused (the source is intentionally
 *                     quiesced for the cut).
 *   so_resume         rollback: resume the source (must leave it runnable)
 *   so_dev_state      serialize device/backend/CPU/kernel state at cutover into
 *                     a freshly heap-allocated buffer (*buf, *len); the session
 *                     chunks and frames it and then frees *buf.  The buffer may
 *                     exceed one frame; the session performs multi-frame
 *                     chunking transparently.
 *   so_vsock_state    optional active-vsock state (version >= 2) captured
 *                     while the source is paused, before so_dev_state.  The
 *                     session owns and frees the returned buffer.  A peer that
 *                     cannot stage it must be rejected before quiesce.
 *   so_retire         irreversible source retirement after destination
 *                     COMMIT, before RELEASE. Once invoked, even failure must
 *                     never roll the source back. Return an errno on failure.
 *                     Production destroys the source through this hook.
 *   so_prepare_relay   optional: transfer paused source sockets to a standby
 *                     owner after COMMIT, before RELEASE.  The owner must not
 *                     read or forward them until the source is defunct.
 *   so_cancel_relay    cancel even a partially prepared owner before source
 *                     rollback; failure keeps the source quiesced.
 *   so_activate_relay  start the prepared relay after RELEASE.  Failure is
 *                     terminal: the source must still become defunct.
 *   so_defunct        finish source teardown after RELEASE (post-commit)
 */
#include "migration_recovery_phase.h"
#include "migration_commit.h"

/* Recovery hooks must durably record the exact attempt and VM/state binding
 * before returning success. Required for fresh mode; ordinary adapters may
 * omit them. An error can mean publication happened but durability is unknown. */
struct migration_source_ops {
	int (*so_local_hello)(void *, struct migration_hello *);
	int (*so_local_topology)(void *, struct migration_topology *);
	int (*so_precopy_enable)(void *);
	int (*so_precopy_round)(void *, bool final, struct migration_memgen *,
	    uint8_t *buf, size_t cap, size_t *written, uint64_t *dirty_pages,
	    bool *converged, bool *more);
	int (*so_precopy_disable)(void *);
	int (*so_quiesce)(void *, bool *source_runnable);
	int (*so_resume)(void *);
	int (*so_dev_state)(void *, uint8_t **buf, size_t *len);
	int (*so_vsock_state)(void *, uint8_t **buf, size_t *len);
	int (*so_prepare_relay)(void *);
	int (*so_cancel_relay)(void *);
	int (*so_activate_relay)(void *);
	void (*so_defunct)(void *);
	int (*so_retire)(void *);
	int (*so_record)(void *, enum migration_recovery_phase, const uint8_t[32]);
	/* Validate peer identity and DEV_STATE digest before retirement intent. */
	int (*so_accept_commit)(void *, const struct migration_commit_binding *);
};

/*
 * Destination-side operations.
 *
 *   do_local_hello     fill the local capability/identity record
 *   do_stage_mem       stage one received memory generation (not published)
 *   do_stage_dev       stage received device/backend state (not published)
 *   do_stage_vsock     stage a v2 active-vsock table before device restore
 *   do_commit          atomically publish every CPU/device/backend/interrupt/
 *                      timer state (still not running the guest)
 *   do_resume          run the guest (only after RELEASE from the source)
 *   do_discard         drop all staged state (rejection / abort path)
 */
struct migration_dest_ops {
	int (*do_local_hello)(void *, struct migration_hello *);
	int (*do_local_topology)(void *, struct migration_topology *);
	int (*do_stage_mem)(void *, const struct migration_memgen *,
	    const uint8_t *buf, size_t len);
	int (*do_stage_dev)(void *, const uint8_t *buf, size_t len);
	int (*do_stage_vsock)(void *, const uint8_t *buf, size_t len);
	int (*do_commit)(void *);
	int (*do_resume)(void *);
	void (*do_discard)(void *);
	int (*do_record)(void *, enum migration_recovery_phase, const uint8_t[32]);
	/* Fill local identity and DEV_STATE digest; preserve the challenge. */
	int (*do_prepare_commit)(void *, struct migration_commit_binding *);
	/* Required for fresh migration. Transfer committed state to a recovery
	 * owner after an attempted COMMIT send, including uncertain resume failure.
	 * The adapter must preserve resume uncertainty and forbid a second attempt.
	 * Must not allocate or fail: reserve ownership during do_prepare_commit.
	 * No resume here. */
	void (*do_retain)(void *, const struct migration_commit_binding *);
	/* Optional, fresh mode only. Make the committed paused image durable for
	 * controller-loss reconstruction after do_prepare_commit and before durable
	 * STAGED. Failure aborts before COMMIT, so the source remains runnable. */
	int (*do_preserve)(void *, const struct migration_commit_binding *);
};

/* Terminal session phases (also used in migration_stat.phase). */
enum migration_phase {
	MIGRATION_PHASE_INIT		= 0,
	MIGRATION_PHASE_HANDSHAKE	= 1,
	MIGRATION_PHASE_VALIDATE	= 2,
	MIGRATION_PHASE_PRECOPY		= 3,
	MIGRATION_PHASE_STOPCOPY	= 4,
	MIGRATION_PHASE_COMMIT		= 5,
	MIGRATION_PHASE_COMPLETED	= 6,
	MIGRATION_PHASE_ROLLED_BACK	= 7,
	MIGRATION_PHASE_FAILED		= 8,
	MIGRATION_PHASE_RECOVERY		= 9,
};

struct migration_source_result {
	uint32_t phase;		/* terminal migration_phase */
	uint16_t negotiated_version;
	uint32_t rounds;
	uint32_t reason;	/* migration_reason if aborted */
	bool source_runnable;	/* true => source was rolled back / never quiesced */
	uint64_t bytes_sent;
};

struct migration_dest_result {
	uint32_t phase;
	uint16_t negotiated_version;
	uint32_t rounds;
	uint32_t reason;
	bool resumed;		/* destination is now the running copy */
	bool release_ack_sent;	/* fresh acknowledgment sent; not proof of receipt */
	bool retained;		/* recovery owner holds paused VM; caller must not exit */
	uint64_t bytes_received;
};

/*
 * Run a complete source migration session over transport.  Returns 0 if the
 * migration committed (source is defunct, destination running) and a non-zero
 * errno otherwise.  On any failure before the acknowledged destination commit
 * the source is left runnable (result->source_runnable == true) and rolled
 * back via so_resume().
 */
int	migration_source_run(const struct migration_transport *,
	    const struct migration_source_ops *, void *ops_arg,
	    const struct migration_session_config *,
	    struct migration_source_result *);

/*
 * Run a complete destination migration session.  Returns 0 if the destination
 * committed and resumed; a non-zero errno otherwise. If result->retained is
 * set, do_retain owns the committed paused image and the caller must keep that
 * recovery owner alive. Otherwise staged state is discarded. A retained image
 * is not permission to run and must be reconciled with the authenticated source.
 */
int	migration_dest_run(const struct migration_transport *,
	    const struct migration_dest_ops *, void *ops_arg,
	    const struct migration_session_config *,
	    struct migration_dest_result *);

#ifdef BHYVE_SNAPSHOT
struct vmctx;
/*
 * Production helpers that gather the local capability/identity record and the
 * live machine topology (memory geometry + PCI device manifest with each
 * device's pe_migration_flags) from a running VM.  Used by the operator
 * "migrate" IPC command and available to any live source driver.
 */
/* Before sandbox entry and IPC publication; a failure disables source
 * migration, not ordinary VM operation. No directory is created here. */
int	migration_prod_source_prepare(void);
int	migration_prod_fill_hello(struct vmctx *, struct migration_hello *);
int	migration_prod_fill_topology(struct vmctx *, struct migration_topology *);

/*
 * Destination listener entry.  Runs a complete destination migration session
 * over an already-connected stream descriptor against a freshly-created,
 * event-fenced VM (the caller must have created ctx and be holding the restore
 * startup fence exactly as the --restore bring-up does).  Received memory
 * generations are staged directly into guest RAM; the chunked device/CPU blob
 * is reassembled and, at COMMIT, replayed through the existing restore steps;
 * the guest is resumed only after RELEASE.  Returns 0 iff the destination
 * committed and resumed.
 */
int	migration_prod_dest_serve(struct vmctx *, int fd,
	    const struct migration_session_config *,
	    struct migration_dest_result *);
/* True when a failed inbound migration kept its committed, paused image
 * (result->retained): the process must hold it until migrate_resolve. */
bool	migration_prod_dest_retained(void);
/* Block until migrate_resolve decides: 0 when the retained copy was resumed
 * (continue running the guest), ECANCELED when it was discarded. */
int	migration_prod_dest_wait_resolution(void);

/* Opaque retained destination, paused or running. A fresh running owner is
 * returned even on success so a lost ACK can be recovered. Keep ctx and the receiver
 * process alive while this owner exists, even when serve returns an error.
 * Initialize *owner to NULL; an existing owner cannot be overwritten by a new
 * serve call. No recovery transport or permission to resume is implied. */
struct migration_prod_dest;
/* Internal receiver entry: caller has already created the recovery worker,
 * retained credential descriptors, and validated/retained its listener. */
int	migration_prod_dest_serve_prepared(struct vmctx *, int fd,
	    const struct migration_session_config *, struct migration_dest_result *,
	    struct migration_prod_dest **);
struct migration_recovery_record;
/* Exclusive owner access; preserves the owner on transport failure and after
 * success. A failed/uncertain resume quarantines it against automatic retry. */
int	migration_prod_dest_recover_release(struct migration_prod_dest *, int fd,
	    const struct migration_tls_credentials *);
void	migration_prod_dest_recovery_status(const struct migration_prod_dest *,
	    bool *running, bool *uncertain, bool *acknowledged);
int	migration_recovery_listener_check(int fd);
/* Preopened exclusive stream listener; allocates the worker before COMMIT.
 * Waits while paused and services reconnects for the remaining VM lifetime. */
int	migration_prod_dest_serve_managed(struct vmctx *, int fd, int listener,
	    const struct migration_session_config *, struct migration_dest_result *);
/* Destination controller-loss reconstruction (migration_dest_image.h). The
 * fenced context is a new incarnation. Begin runs before Capsicum: it takes
 * the attempt controller lock, requires durable STAGED, obtains an exact
 * retirement witness for the previous incarnation (destroying it only by the
 * optional name plus exact identity), and publishes HDS1. Prepared consumes
 * the state, loads and verifies the HDI1 image and returns a paused retained
 * owner. Neither call resumes a guest; RELEASED/RUNNING attempts return
 * ENOTRECOVERABLE because the guest may already have executed. */
struct migration_prod_reconstruct;
int	migration_prod_dest_reconstruct_begin(struct vmctx *, int recovery_dirfd,
	    const uint8_t challenge[32], const char *name,
	    struct migration_prod_reconstruct **);
void	migration_prod_dest_reconstruct_abandon(struct migration_prod_reconstruct *);
int	migration_prod_dest_reconstruct_prepared(struct vmctx *,
	    struct migration_prod_reconstruct *, const struct migration_session_config *,
	    struct migration_dest_result *, struct migration_prod_dest **);
/* Managed successor: like serve_managed, waits until authenticated recovery
 * resumes the reconstructed guest, then keeps serving lost-ACK reconnects. */
int	migration_prod_dest_reconstruct_managed(struct vmctx *,
	    struct migration_prod_reconstruct *, int listener,
	    const struct migration_session_config *, struct migration_dest_result *);
/* Restarted controller: requires exclusive ownership of the canonical journal
 * root and an independently known source lifetime. Authenticates the original
 * certificate pair before finishing INTENT with an exact retirement witness.
 * Holds the per-lifetime controller lock across TLS and phase transitions.
 * Never destroys or resumes a VM; a still-live source returns EBUSY. */
/* The optional operator name permits orphan retirement by atomic exact
 * identity; authentication and drained retirement proof remain mandatory. */
int	migration_prod_source_recover_restart_named(int fd, int recovery_dirfd,
	    uint16_t vmid, uint64_t epoch, const struct migration_tls_credentials *,
	    const char *name);
/* Under exclusive source-owner access: finish a durable INTENT. On successful
 * destruction *ctx becomes NULL, even if subsequent journal persistence fails.
 * A NULL ctx is usable only when the exact kernel retirement witness succeeds.
 * This never infers retirement from missing names, PIDs, or ioctl errors. */
int	migration_prod_source_finish_intent(struct vmctx **ctx, int recovery_dirfd,
	    const struct migration_recovery_record *);
#endif

#endif /* _BHYVE_MIGRATION_SESSION_H_ */
