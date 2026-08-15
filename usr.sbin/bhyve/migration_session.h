/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Live-migration control plane for bhyve: a versioned, authenticated
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
 * The transport is an injectable vtable (struct migration_transport).  A thin
 * file-descriptor adapter (migration_transport_fd_*) is the only piece that
 * touches sockets; it is deliberately separated so the state machine and codec
 * run in-process over a socketpair or an injected transport with no network,
 * no root, and no running VM.
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
#define	MIGRATION_PROTO_VERSION		1u
#define	MIGRATION_PROTO_VERSION_MIN	1u

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

/* Message types (frame header "type" field). */
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
#define	MIGRATION_CAP_ALL		(MIGRATION_CAP_PRECOPY | \
					 MIGRATION_CAP_DEVICE_DIRTY)

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
	MIGRATION_REASON_CPUCOUNT	= 10,
	MIGRATION_REASON_TOPOLOGY	= 11,
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
 * layer).  Works on any stream socket or pipe, including a socketpair for
 * in-process loopback.  recv_timeout_ms <= 0 means block indefinitely.
 */
struct migration_transport_fd {
	int fd;
	int recv_timeout_ms;
};
void	migration_transport_fd_init(struct migration_transport *,
	    struct migration_transport_fd *, int fd, int recv_timeout_ms);

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

struct migration_session_config {
	uint16_t version_max;
	uint16_t version_min;
	uint32_t max_rounds;		/* convergence limit (0 => default) */
	uint64_t converge_pages;	/* dirty-page ceiling to declare cutover */
	bool abort_if_unconverged;	/* fail (source runnable) instead of forcing
					 * a cutover after max_rounds */
	const volatile int *cancel;	/* operator cancellation flag (or NULL) */
	struct migration_progress *progress;	/* optional */
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
 *   so_quiesce        event-fence: pause every vCPU/device/backend/timer
 *   so_resume         rollback: resume the source (must leave it runnable)
 *   so_dev_state      serialize device/backend/CPU/kernel state at cutover into
 *                     a freshly heap-allocated buffer (*buf, *len); the session
 *                     chunks and frames it and then frees *buf.  The buffer may
 *                     exceed one frame; the session performs multi-frame
 *                     chunking transparently.
 *   so_defunct        mark the source permanently stopped (post-commit)
 */
struct migration_source_ops {
	int (*so_local_hello)(void *, struct migration_hello *);
	int (*so_local_topology)(void *, struct migration_topology *);
	int (*so_precopy_enable)(void *);
	int (*so_precopy_round)(void *, bool final, struct migration_memgen *,
	    uint8_t *buf, size_t cap, size_t *written, uint64_t *dirty_pages,
	    bool *converged, bool *more);
	int (*so_precopy_disable)(void *);
	int (*so_quiesce)(void *);
	int (*so_resume)(void *);
	int (*so_dev_state)(void *, uint8_t **buf, size_t *len);
	void (*so_defunct)(void *);
};

/*
 * Destination-side operations.
 *
 *   do_local_hello     fill the local capability/identity record
 *   do_stage_mem       stage one received memory generation (not published)
 *   do_stage_dev       stage received device/backend state (not published)
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
	int (*do_commit)(void *);
	int (*do_resume)(void *);
	void (*do_discard)(void *);
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
 * committed and resumed; a non-zero errno otherwise, in which case all staged
 * state has been discarded and nothing was published.
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
#endif

#endif /* _BHYVE_MIGRATION_SESSION_H_ */
