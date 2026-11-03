/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define SHA256_DIGEST_LENGTH 32
typedef int dtraced_replay_kill_t;
struct vmctx { int unused; };
struct vm_snapshot_session { int unused; };
struct restore_state {
    int checkpoint_format_version, checkpoint_lock_fd;
    bool handoff_identity_valid, hypertrace_session_present;
    bool hypertrace_release_present;
    void *hypertrace_transfer, *hypertrace_private_image, *hypertrace_private_dev;
    size_t hypertrace_transfer_length, hypertrace_private_length;
    uint8_t hypertrace_session[40];
};
enum { PAUSE = 1, PREFLIGHT, MEMORY_PREFLIGHT, STAGE, BEGIN, MEMORY,
    HASH_BEFORE, DEVICES, HASH_AFTER, KERNEL, DISCARD, COMMIT, ADMIT,
    REPLAY, RESUME, ATTACH, RELEASE };
static int position, fail_at, aborted, stopped, released, hashes;
static bool held = true;
static size_t replay;
static int step(int n) {
    assert(n == ++position);
    errno = EIO;
    return n == fail_at ? EIO : 0;
}
static int forbidden(void) { abort(); }
/* Merged TPM gate: refused before any restore step. */
static int tpm_refusal;
#define tpm_device_migration_check() tpm_refusal
#define BHYVE_TRACE(...) ((void)0)
#define BHYVE_PHASE_START(...) ((void)0)
#define BHYVE_PHASE_DONE(...) ((void)0)
#define EPRINTLN(...) ((void)0)
#define FPRINTLN(...) ((void)0)
#define HYPERTRACE_TRANSFER_MIN_BYTES 1
#define checkpoint_restore_startup_held() held
#define hypertrace_initialized() true
#define checkpoint_regular_fd(...) 0
#define lookup_hypertrace_handoff(r, required) (*(required) = false, 0)
#define vm_pause_devices() step(PAUSE)
#define vm_restore_preflight_internal(r, capture) (assert(capture), step(PREFLIGHT))
#define hypertrace_private_image_digest(...) ((void)0)
#define vm_restore_memory_preflight(...) step(MEMORY_PREFLIGHT)
#define pci_vtdtr_session_restore_stage_paused(...) step(STAGE)
static int begin(bool *resolved) { *resolved = true; return step(BEGIN); }
#define vm_snapshot_session_begin_exact(c, s, resolved) begin(resolved)
#define restore_vm_mem(...) step(MEMORY)
#define hypertrace_private_image_unchanged(...) step(hashes++ ? HASH_AFTER : HASH_BEFORE)
#define vm_restore_devices_prevalidated(...) step(DEVICES)
#define vm_restore_kern_structs(...) step(KERNEL)
#define vm_restore_vmgenid_renew(...) 0
#define vm_restore_acpi(...) ((void)0)
#define pci_vtdtr_session_discard_paused(...) step(DISCARD)
static int finish(bool commit, bool *done) {
    if (!commit) { aborted++; *done = true; return 0; }
    int error = step(COMMIT);
    *done = error == 0;
    return error;
}
#define vm_snapshot_session_release_exact(c, s, commit, done) finish(commit, done)
#define hypertrace_start_ready(...) step(ADMIT)
static int take_replay(size_t *count) { *count = replay; return step(REPLAY); }
#define hypertrace_take_replay_kills(c, k, count) take_replay(count)
#define vm_resume_devices() step(RESUME)
#define pci_vtdtr_session_attach_begin(...) step(ATTACH)
static int startup_release(void) {
    int error = step(RELEASE); released = error == 0; return error;
}
#define checkpoint_restore_startup_release() startup_release()
#define pci_vtdtr_checkpoint_stop() (stopped++, 0)
#define hypertrace_restore_cancel_if_safe(c, r, reserved, mutating, claimed) \
    (assert(!(reserved) && !(mutating) && !(claimed)), 0)
/* Any continuity operation is a failure, including in error cleanup. */
#define hypertrace_transfer_inspect(...) forbidden()
#define hypertrace_transfer_replay_controls(...) forbidden()
#define pci_vtdtr_checkpoint_private_image_replay_room(...) forbidden()
#define hypertrace_handoff_destination_stage_release_prestart(...) forbidden()
#define hypertrace_restore_prepare_handoff(...) forbidden()
#define hypertrace_restore_begin_mutation(...) forbidden()
#define hypertrace_handoff_rebind_commit_empty(...) forbidden()
#define hypertrace_handoff_destination_ensure(...) forbidden()
#define hypertrace_handoff_destination_prestart(...) forbidden()
#define pci_vtdtr_checkpoint_private_image_bind(...) forbidden()
#define hypertrace_handoff_destination_promote_prestart(...) forbidden()
#define pci_vtdtr_handoff_ticket_attach_paused(...) forbidden()
#define pci_vtdtr_checkpoint_publish_paused(...) forbidden()
#define pci_vtdtr_handoff_ticket_clear(...) forbidden()
#define hypertrace_handoff_replay_drain(...) forbidden()
#define hypertrace_handoff_execution_start(...) forbidden()
#include "fresh-session-restore.inc"

int main(void) {
    struct vmctx ctx = {0};
    struct restore_state state = { .checkpoint_format_version = 5,
        .checkpoint_lock_fd = 3, .handoff_identity_valid = true,
        .hypertrace_session_present = true,
        .hypertrace_private_image = &ctx, .hypertrace_private_dev = &ctx };
    for (fail_at = 0; fail_at <= RELEASE; fail_at++) {
        position = aborted = stopped = released = hashes = 0;
        int error = vm_restore_transaction(&ctx, &state);
        assert(error == (fail_at ? EIO : 0));
        assert(position == (fail_at ? fail_at : RELEASE));
        assert(released == !fail_at);
        assert(aborted == (fail_at > BEGIN && fail_at <= COMMIT));
        assert(stopped == (fail_at > PAUSE && fail_at <= RESUME));
    }
    fail_at = position = hashes = released = 0;
    replay = 1;
    assert(vm_restore_transaction(&ctx, &state) == EPROTO);
    assert(position == REPLAY && !released);
    replay = 0;
    position = 0;
    tpm_refusal = ENOTSUP;
    assert(vm_restore_transaction(&ctx, &state) == ENOTSUP && position == 0);
    tpm_refusal = 0;
    held = false;
    assert(vm_restore_transaction(&ctx, &state) == EBUSY && position == 0);
    held = true;
    state.hypertrace_session_present = false;
    assert(vm_restore_transaction(&ctx, &state) == EPROTO && position == 0);
    state.hypertrace_session_present = true;
    state.hypertrace_transfer = &ctx;
    assert(vm_restore_transaction(&ctx, &state) == EPROTO && position == 0);
    state.hypertrace_transfer = NULL;
    state.hypertrace_release_present = true;
    assert(vm_restore_transaction(&ctx, &state) == EPROTO && position == 0);
    return 0;
}
