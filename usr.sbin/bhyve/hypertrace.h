/*-
 * Copyright (c) 2017 Domagoj Stolfa <domagoj.stolfa@gmail.com>
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

#ifndef _BHYVE_HYPERTRACE_H_
#define _BHYVE_HYPERTRACE_H_

#include <sys/types.h>
#include <stdbool.h>

#include <dtraced.h>

#define HYPERTRACE_TRANSFER_MIN_BYTES 64U
#define HYPERTRACE_TRANSFER_MAX_BYTES (63U * 1024U * 1024U)

struct vmctx;
struct pci_devinst;

int hypertrace_init(struct vmctx *);
int hypertrace_start(struct vmctx *);
int hypertrace_start_ready(struct vmctx *, int);
int hypertrace_handoff_replay_drain(struct vmctx *, const uint8_t[16],
    const uint8_t[32], int);
int hypertrace_take_replay_kills(struct vmctx *,
    dtraced_replay_kill_t **, size_t *);
int hypertrace_configured(void);
int hypertrace_initialized(void);
int hypertrace_read_epoch(void **, dtraced_hdr_t *, uint64_t *, uint64_t *);
int hypertrace_ack_epoch(uint64_t, uint64_t, uint64_t);
uint64_t hypertrace_reset(void);
int hypertrace_write(const dtraced_hdr_t *, void *, size_t);
int hypertrace_handoff_source(uint8_t, const uint8_t[16],
    const uint8_t[32]);
int hypertrace_handoff_source_release_open(struct vmctx *);
int hypertrace_handoff_source_release_finish(int, const uint8_t[16],
    const uint8_t[32], uint8_t[DTRACED_RELEASE_ATTESTED_SIZE], bool *);
int hypertrace_release_attestation_inspect(
    const uint8_t[DTRACED_RELEASE_ATTESTED_SIZE], const uint8_t[16],
    const uint8_t[32]);
int hypertrace_release_transfer_inspect(
    const uint8_t[DTRACED_RELEASE_ATTESTED_SIZE], const uint8_t[16],
    const uint8_t[32], const void *, size_t);
int hypertrace_release_recover(const uint8_t[16], const uint8_t[32],
    uint8_t[DTRACED_RELEASE_ATTESTED_SIZE]);
int hypertrace_handoff_destination_stage_release_prestart(struct vmctx *,
    const uint8_t[16], const uint8_t[32],
    const uint8_t[DTRACED_RELEASE_ATTESTED_SIZE]);
int hypertrace_handoff_source_fresh(struct vmctx *, uint8_t,
    const uint8_t[16], const uint8_t[32]);
int hypertrace_handoff_source_status_fresh(struct vmctx *,
    const uint8_t[16], dtraced_delivery_status_t *);
int hypertrace_handoff_source_bundle_fresh(struct vmctx *,
    const uint8_t[16], void **, size_t *);
int hypertrace_handoff_destination_import_prestart(struct vmctx *,
    const uint8_t[16], const uint8_t[32], const void *, size_t);
/* Reports any ingress or source-journal state that needs import on restore. */
int hypertrace_transfer_inspect(const void *, size_t,
    const uint8_t[16], bool *);
int hypertrace_transfer_replay_controls(const void *, size_t,
    const uint8_t[16], size_t *);
int hypertrace_handoff_destination_status_prestart(struct vmctx *,
    const uint8_t[16], const uint8_t[32], dtraced_delivery_status_t *);
int hypertrace_handoff_destination_ensure(struct vmctx *, uint8_t,
    const uint8_t[16], const uint8_t[32]);
int hypertrace_handoff_source_ensure(struct vmctx *, uint8_t,
    const uint8_t[16], const uint8_t[32], bool *);
int hypertrace_handoff_source_gate_ensure(struct vmctx *, uint8_t,
    const uint8_t[16]);
int hypertrace_handoff_source_drain(struct vmctx *, const uint8_t[16],
    const uint8_t[32]);
int hypertrace_handoff_destination(uint8_t, const uint8_t[16],
    const uint8_t[32]);
int hypertrace_handoff_rekey_applied(struct vmctx *, const uint8_t[16],
    const uint8_t[32]);
int hypertrace_handoff_execution_start(struct vmctx *, const uint8_t[16],
    const uint8_t[32]);
int hypertrace_handoff_rebind_begin(struct vmctx *, const uint8_t[16],
    const uint8_t[32]);
int hypertrace_handoff_rebind_begin_optional(struct vmctx *,
    const uint8_t[16], const uint8_t[32], bool *);
int hypertrace_handoff_mutation_reset(struct vmctx *,
    const uint8_t[16], const uint8_t[32]);
int hypertrace_handoff_rebind_stage(struct vmctx *, const uint8_t[16],
    const uint8_t[32]);
int hypertrace_handoff_rebind_pending(struct vmctx *, const uint8_t[16],
    const uint8_t[32]);
int hypertrace_handoff_rebind_cancel_pending(struct vmctx *,
    const uint8_t[16], const uint8_t[32]);
int hypertrace_handoff_rebind_commit_empty(struct vmctx *,
    const uint8_t[16], const uint8_t[32]);
int hypertrace_handoff_rebind_empty_ready(struct vmctx *,
    const uint8_t[16], const uint8_t[32]);
int hypertrace_handoff_rebind_nonempty_preflight(struct vmctx *,
    const uint8_t[16], const uint8_t[32]);
int hypertrace_handoff_destination_prestart(struct vmctx *, uint8_t,
    const uint8_t[16], const uint8_t[32]);
int hypertrace_handoff_destination_promote_prestart(struct vmctx *,
    const uint8_t[16], const uint8_t[32]);
int hypertrace_handoff_delivery_prestart(struct vmctx *,
    const dtraced_handoff_delivery_request_t *, dtraced_delivery_status_t *);
int hypertrace_handoff_delivery_live(struct vmctx *,
    const dtraced_handoff_delivery_request_t *, dtraced_delivery_status_t *);
int hypertrace_handoff_bind_delivery_prestart(struct vmctx *,
    const dtraced_handoff_bind_delivery_request_t *,
    dtraced_delivery_status_t *);
int hypertrace_handoff_kill_prestart(struct vmctx *,
    const dtraced_handoff_kill_request_t *, dtraced_delivery_status_t *);
int hypertrace_handoff_cleanup_prestart(struct vmctx *,
    const dtraced_handoff_cleanup_request_t *, dtraced_delivery_status_t *);
int hypertrace_handoff_kill_live(struct vmctx *,
    const dtraced_handoff_kill_request_t *, dtraced_delivery_status_t *);
int hypertrace_handoff_bind_kill_prestart(struct vmctx *,
    const dtraced_handoff_kill_request_t *, dtraced_delivery_status_t *);
int hypertrace_delivery_status(const dtraced_hdr_t *,
    dtraced_delivery_status_t *);
int hypertrace_ingress_status(const dtraced_hdr_t *,
    dtraced_delivery_status_t *);
/* Guest-only quiesce. Success does not certify host collection or a snapshot.
 * Begin is idempotent; status returns EBUSY until the exact guest proof. */
int pci_vtdtr_session_stop_begin(struct vmctx *);
/* Require fresh-session support before changing any tracing state. */
int pci_vtdtr_session_checkpoint_begin(struct vmctx *);
int pci_vtdtr_session_stop_status(struct vmctx *);
/* Requires guest stop; errno-style result, complete only after host proof.
 * Call before pausing devices, with checkpoint ownership of device lifetime. */
int pci_vtdtr_session_collectors_stop_step(struct vmctx *, bool *);
int hypertrace_session_host_stop(struct vmctx *, const uint8_t[16]);
int hypertrace_session_host_stopped(struct vmctx *, const uint8_t[16]);
int hypertrace_session_host_released(struct vmctx *, const uint8_t[16]);
int hypertrace_session_release(struct vmctx *, const uint8_t[16]);
/* Stop at most one host collector. 0 = complete, 1 = call again, -1 = error.
 * Requires an already suspended host gate owned by this token. */
int hypertrace_session_collectors_stop_step(struct vmctx *, const uint8_t[16]);
/* Single-threaded recovery command only; open returns an errno-style result. */
int hypertrace_session_recovery_open(void);
void hypertrace_session_recovery_close(void);
int hypertrace_session_retired(uint16_t, uint64_t);
int pci_vtdtr_session_attach_begin(struct vmctx *);
int pci_vtdtr_session_attach_status(struct vmctx *);
int pci_vtdtr_session_authorize(struct vmctx *);
int pci_vtdtr_session_checkpoint_export(struct vmctx *, void *, size_t);
#ifdef BHYVE_SNAPSHOT
int pci_vtdtr_session_restore_stage_paused(struct pci_devinst *,
    const void *, size_t, void *, size_t);
int pci_vtdtr_session_migration_stage_paused(struct pci_devinst *,
    const void *, size_t, void *, size_t);
/* Only the migration coordinator may call this after verified RELEASE on
 * its trusted stream. The FSS1 argument binds the staged record; it is not
 * independently verifiable evidence that the remote source was destroyed. */
int pci_vtdtr_session_migration_release_paused(struct pci_devinst *,
    const void *, size_t);
int pci_vtdtr_session_checkpoint_import_paused(struct pci_devinst *,
    const void *, size_t);
int pci_vtdtr_session_discard_paused(struct pci_devinst *);
bool pci_vtdtr_checkpoint_is_device(const struct pci_devinst *);
int pci_vtdtr_checkpoint_features_validate(uint64_t);
int pci_vtdtr_handoff_ticket_attach(struct pci_devinst *,
    const uint8_t[16], const uint8_t[32],
    const dtraced_replay_kill_t *, size_t);
int pci_vtdtr_handoff_ticket_attach_paused(struct pci_devinst *,
    const uint8_t[16], const uint8_t[32],
    const dtraced_replay_kill_t *, size_t);
void pci_vtdtr_handoff_ticket_clear(struct pci_devinst *);
int pci_vtdtr_checkpoint_capture_begin(struct pci_devinst *);
int pci_vtdtr_checkpoint_source_replay_room(struct pci_devinst *, size_t);
int pci_vtdtr_checkpoint_capture_end(struct pci_devinst *, const void **,
    size_t *, bool *);
int pci_vtdtr_checkpoint_private_image_query(void *, size_t, struct vmctx *,
    const uint8_t[16], const uint8_t[32]);
int pci_vtdtr_checkpoint_private_image_replay_room(void *, size_t, size_t);
int pci_vtdtr_checkpoint_private_image_bind(void *, size_t, struct vmctx *,
    const uint8_t[16], const uint8_t[32]);
int pci_vtdtr_checkpoint_publish_paused(struct pci_devinst *);
int pci_vtdtr_checkpoint_stop(void);
#endif
/* After device workers stop, before freeing vmctx. Keeps retirement query fd. */
int hypertrace_retire_transport(void);
void hypertrace_destroy(void);

#endif /* _BHYVE_HYPERTRACE_H_ */
