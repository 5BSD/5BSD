/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * meshd persistent node-state store (MshPRT_v1.1 Sections 3.8.4, 3.8.8, 3.10.5).
 *
 * A mesh node's runtime state MUST survive a daemon restart, otherwise the
 * network suffers a replay-protection failure: a node that resumes with SEQ 0
 * and an empty Replay Protection List re-emits sequence numbers it has already
 * used (violating the "monotonic, non-repeating SEQ per IV Index" rule of
 * Section 3.8.4) and accepts PDUs it should reject as replays (Section 3.8.8).
 *
 * This module persists and reloads that state as a single versioned,
 * CRC-checked frame written atomically (temp + fsync + rename, 0600), mirroring
 * the mesh_manager / blued_persist store format:
 *
 *   magic[8] | version(2 LE) | flags(2 LE) | count(2 LE) | reserved(2 LE) |
 *   crc32(4 LE) | body
 *
 * where crc32 covers the header (crc field taken as zero) through the body.
 *
 * SEQUENCE NUMBER - BLOCK RESERVATION (the correctness crux, Section 3.8.4).
 * Persisting every SEQ increment would be an I/O storm, so instead a BLOCK of
 * SEQ values is reserved ahead: the store records a high-water mark
 * (current + block); the node hands out SEQ from RAM up to that high-water; when
 * the headroom runs low the next block is reserved by persisting a new, higher
 * high-water.  On startup the node RESUMES its live SEQ at the persisted
 * high-water, which is always >= the last SEQ actually used (because the block
 * was reserved ahead of use).  This guarantees SEQ never regresses or repeats
 * across a crash or restart, at the cost of skipping the unused tail of a block.
 *
 * The store also carries the Replay Protection List (per-source last SEQ + IV
 * Index, Section 3.8.8), the IV Index and IV Update phase (Section 3.10.5), the
 * primary NetKey / AppKey and unicast address, and the node configuration
 * database (subnets, AppKey bindings, per-model bindings / subscriptions /
 * publications), plus nonvolatile application-model states, so a node -
 * including one provisioned over the air with no configuration file - is
 * fully itself after a restart.  Version 3 adds virtual-publication Label UUIDs,
 * version 4 the local DeviceKey, and version 5 embeds the manager identity,
 * address allocator, roster and remote DeviceKeys in the same atomic commit.
 * Versions 2 through 4 remain readable and are migrated on their next save.
 *
 * The file holds secret key material and is written 0600; the CRC provides
 * integrity, not confidentiality.  Load treats only ENOENT as a fresh node and
 * rejects other open failures, non-regular files, truncation, wrong magic,
 * unknown versions and CRC mismatches.
 */

#ifndef _MESHD_PERSIST_H_
#define _MESHD_PERSIST_H_

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

struct meshd_node;

/*
 * SEQ reservation policy.  BLOCK is the number of sequence numbers reserved per
 * persist; GUARD is the headroom at which the next block is reserved.  GUARD is
 * chosen far larger than the handful of SEQ values any single meshd operation
 * consumes between reservation checks, so the live SEQ can never reach the
 * persisted high-water before the next block is persisted (see the reserve-ahead
 * argument in meshd_persist_seq_reserve()).
 */
#define	MESHD_PERSIST_SEQ_BLOCK		256u
#define	MESHD_PERSIST_SEQ_GUARD		64u
#define	MESHD_PERSIST_DEBOUNCE_MS	500u
#define	MESHD_PERSIST_RETRY_MS		5000u

/*
 * The store handle: where the frame lives, the reservation block size, and the
 * currently persisted SEQ high-water mark.
 */
struct meshd_persist {
	char		path[PATH_MAX];
	uint32_t	block;		/* SEQ values reserved per persist */
	uint32_t	reserved;	/* persisted SEQ high-water mark */
	int		dirty;
	uint64_t	due_ms;
	unsigned	write_errors;
	int		last_errno;
};

/*
 * Bind a store to a file path with a reservation block size (0 selects
 * MESHD_PERSIST_SEQ_BLOCK).  Does no I/O.
 */
void	meshd_persist_init(struct meshd_persist *ps, const char *path,
	    uint32_t block);

/*
 * Persist the node's full runtime state to the store atomically, recording the
 * current SEQ high-water (ps->reserved), the IV Index / phase, the Replay
 * Protection List, the primary keys / address and the configuration database.
 * Active model transitions are sampled at nd->sim.now_ms and restore as steady
 * present values; transition timers are intentionally not resumed.
 * Returns 0 on success, -1 on an I/O or argument error.
 */
int	meshd_persist_save(struct meshd_persist *ps, struct meshd_node *nd);
void	meshd_persist_mark_dirty(struct meshd_persist *ps, uint64_t now_ms);
int	meshd_persist_flush(struct meshd_persist *ps, struct meshd_node *nd,
	    uint64_t now_ms, int force);

/*
 * Reload node state from the store, if present, BEFORE the node joins the
 * network.  On success the node is rebuilt from the persisted keys / address /
 * IV Index (so its network credentials re-derive), its live SEQ is set to the
 * persisted high-water (resuming ABOVE any SEQ previously used), the RPL and
 * configuration database are restored, and the next SEQ block is reserved and
 * re-persisted.  Returns 0 if state was loaded and applied, 1 if no store exists
 * (a fresh node - the caller keeps its config-derived state and should call
 * meshd_persist_seq_reserve() to establish the first block), or -1 if the store
 * is present but corrupt (missing / truncated / bad magic / bad version / CRC
 * mismatch); on -1 the node is left untouched.
 */
int	meshd_persist_load(struct meshd_persist *ps, struct meshd_node *nd);

/*
 * SEQ block-reservation check.  If the node's live SEQ has climbed to within
 * GUARD of the persisted high-water (or no block has been reserved yet), reserve
 * the next block by persisting a new high-water of live_seq + block and return 1.
 * If ample headroom remains, do nothing and return 0.  Returns -1 on a save
 * error.  Call this after every operation that may originate a message (and on
 * each clock tick) so the persisted high-water always stays ahead of the live
 * SEQ.
 */
int	meshd_persist_seq_reserve(struct meshd_persist *ps,
	    struct meshd_node *nd);

/* ================================================================
 * Manager database persistence (the mesh operability layer's network state:
 * the created network keys, unicast allocator, node roster and per-node
 * DevKeys - MshPRT_v1.1 Section 4).  The manager owns its own on-disk frame
 * format (mesh_mgr_save / mesh_mgr_load); these wrappers add the durable
 * atomic-replace envelope meshd requires (write a sibling temp file, rename it
 * over the target, then fsync the containing directory so the rename survives a
 * crash).  The mgr file holds secret DevKeys and is written 0600.
 * ================================================================ */

/*
 * Persist the manager DB to path atomically.  Returns 0 on success, -1 on an
 * argument, serialise, rename or I/O error (the target is left unchanged).
 */
int	meshd_persist_mgr_save(const char *path, const struct mesh_mgr *mgr);

/*
 * Load the manager DB from path into *mgr.  Returns 0 if state was loaded, 1 if
 * no store exists (a fresh manager), or -1 if the store is present but corrupt
 * (missing / truncated / bad magic / bad version / CRC mismatch).
 */
int	meshd_persist_mgr_load(const char *path, struct mesh_mgr *mgr);

#endif /* _MESHD_PERSIST_H_ */
