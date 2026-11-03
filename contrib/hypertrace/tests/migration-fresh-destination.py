#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Fault-inject the production fresh migration restore and resume coordinators."""
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/snapshot.c').read_text()
start = source.index('static int\nvm_migrate_commit_state_impl(')
end = source.index('static nvlist_t *\nvm_do_checkpoint(', start)
fixture = r'''
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/mman.h>
#include "migration_snapshot.h"
#include "migration_session.h"
#define SHA256_DIGEST_LENGTH 32
#define BHYVE_PHASE_START(...) ((void)0)
#define BHYVE_PHASE_DONE(...) ((void)0)
struct vmctx { int unused; };
struct pci_devinst { int unused; };
struct vm_snapshot_session { int unused; };
typedef int dtraced_replay_kill_t;
struct restore_state {
 int checkpoint_format_version, checkpoint_lock_fd, kdata_fd, vmmem_fd;
 bool hypertrace_session_present;
 uint8_t hypertrace_session[40];
 void *kdata_map, *hypertrace_private_image;
 size_t hypertrace_private_length;
 struct pci_devinst *hypertrace_private_dev;
};
static struct pci_devinst device;
static int position, fail_at, hashes, aborted, destroyed;
static bool held = true, replay, resuming, ordinary, tracing=true, input_paused;
static int step(int n) {
 assert(++position == n); errno = EIO; return n == fail_at ? EIO : 0;
}
#define hypertrace_initialized() tracing
/* Merged gates: the TPM migration check runs before any other step, the
 * saved guest CPU contract after the handoff marker and before input pause. */
static int tpm_error, cpu_contract_error, cpu_contract_calls;
#define tpm_device_migration_check() (assert(position == 0), tpm_error)
struct vcpu { int unused; };
static struct vcpu bsp;
#define fbsdrun_vcpu(n) (assert((n) == 0), &bsp)
static int checkpoint_restore_cpu_contract(struct restore_state *r, struct vcpu *v) {
 assert(r != NULL && v == &bsp && position == 3 && !input_paused);
 cpu_contract_calls++; return cpu_contract_error;
}
#define checkpoint_restore_startup_held() held
#define migrate_tempfd(...) 7
#define close(...) ((void)0)
#define load_kdata_fd(...) step(1)
#define load_metadata_fd(...) step(2)
#define lookup_hypertrace_handoff(r, required) (*(required) = false, step(3))
static void console_input_pause(void) {
 assert(held && position==3); input_paused=true;
}
static void console_input_resume(void) {
 assert(!held && position==(ordinary?4:8)); input_paused=false;
}
#define vm_pause_devices() (assert(input_paused), step(4))
static int preflight(struct restore_state *r, bool fresh) {
 assert(fresh && r->checkpoint_format_version == 5 && r->hypertrace_session_present);
 r->hypertrace_private_dev = &device;
 r->hypertrace_private_image = r->hypertrace_session;
 r->hypertrace_private_length = 40;
 return step(5);
}
#define vm_restore_preflight_internal preflight
#define hypertrace_private_image_digest(...) ((void)0)
#define pci_vtdtr_session_migration_stage_paused(...) step(6)
#define vm_snapshot_session_begin_exact(...) step(7)
#define hypertrace_private_image_unchanged(...) step(hashes++ ? 10 : 8)
#define vm_restore_devices_prevalidated(...) step(9)
#define vm_restore_kern_structs(...) step(11)
#define vm_restore_acpi(...) ((void)0)
#define pci_vtdtr_session_discard_paused(...) step(12)
static int finish(bool commit, bool *released) {
 if (!commit) { aborted++; *released = true; return 0; }
 int error = step(13); *released = error == 0; return error;
}
#define vm_snapshot_session_release_exact(c, s, commit, done) finish(commit, done)
#define destroy_restore_state(...) (destroyed++)
static int ready(void) { assert(resuming); return step(1) ? -1 : 0; }
#define hypertrace_start_ready(...) ready()
static int take(dtraced_replay_kill_t **k, size_t *n) {
 *k = NULL; *n = replay ? 1 : 0; return step(2);
}
#define hypertrace_take_replay_kills(c, k, n) take(k,n)
#define vm_restore_time(...) (step(ordinary ? 1 : 3) ? -1 : 0)
#define pci_vtdtr_session_migration_release_paused(...) step(4)
#define vm_resume_devices() step(ordinary ? 2 : 5)
#define pci_vtdtr_session_attach_begin(...) step(6)
static int resume_cpus(void) {
 assert(held); return step(ordinary ? 3 : 7) ? -1 : 0;
}
#define vm_resume_all_cpus(c) (assert((c)!=NULL), resume_cpus())
static int release_startup(void) {
 assert(held);int error=step(ordinary ? 4 : 8);
 if (error==0) held=false; return error;
}
#define checkpoint_restore_startup_release() release_startup()
'''
fixture += source[start:end] + r'''
int main(void) {
 struct vmctx ctx = {0};
 uint8_t blob[56] = {0};
 struct hypertrace_session_record record = { .vmid=7, .epoch=9,
     .stop_token=11, .features=HYPERTRACE_SESSION_FEATURES };
 assert(hypertrace_session_record_encode(blob+16, 40, &record) == 0);
 for (fail_at = 0; fail_at <= 13; fail_at++) {
   struct pci_devinst *result = &device;
   position = hashes = aborted = destroyed = 0; input_paused=false;
   int error = vm_migrate_fresh_commit_state(&ctx, blob, sizeof(blob), &result);
   assert(error == (fail_at ? EIO : 0));
   assert(result == (fail_at ? NULL : &device));
   assert(position == (fail_at ? fail_at : 13));
   assert(aborted == (fail_at >= 8));
   assert(destroyed == 1);
   assert(input_paused==(fail_at==0 || fail_at>=4));
 }
 fail_at = 0;
 /* TPM refusal: nothing is decoded, loaded or paused. */
 {
   struct pci_devinst *result = &device;
   position = destroyed = cpu_contract_calls = 0; tpm_error = ENOTSUP;
   assert(vm_migrate_fresh_commit_state(&ctx, blob, sizeof(blob), &result) == ENOTSUP);
   assert(result == NULL && position == 0 && destroyed == 0 && cpu_contract_calls == 0);
   tpm_error = 0;
   /* An oversized blob is refused before the TPM gate as well. */
   assert(vm_migrate_fresh_commit_state(&ctx, blob, (size_t)MIGRATION_MAX_DEV_STATE + 1, &result) == EMSGSIZE);
   assert(position == 0);
   /* CPU contract mismatch: refused after the marker, before input pause. */
   position = hashes = aborted = destroyed = 0; input_paused = false;
   cpu_contract_error = EOPNOTSUPP;
   assert(vm_migrate_fresh_commit_state(&ctx, blob, sizeof(blob), &result) == EOPNOTSUPP);
   assert(position == 3 && cpu_contract_calls == 1 && !input_paused && destroyed == 1 && aborted == 0);
   cpu_contract_error = 0;
 }
 resuming = true;
 for (fail_at = 0; fail_at <= 8; fail_at++) {
   position = 0; held=true; input_paused=true;
   assert(vm_migrate_fresh_resume(&ctx, &device, blob+16) == (fail_at ? EIO : 0));
   assert(position == (fail_at ? fail_at : 8));
   assert(held == (fail_at!=0) && input_paused==(fail_at!=0));
 }
 fail_at = 0; position = 0; replay = true; held=true;
 assert(vm_migrate_fresh_resume(&ctx, &device, blob+16) == EPROTO);
 assert(position == 2);
 held = false; position = 0;
 assert(vm_migrate_fresh_resume(&ctx, &device, blob+16) == EBUSY);
 assert(position == 0);
 ordinary=true; tracing=false;
 for(fail_at=0;fail_at<=4;fail_at++) {
  held=true;position=0;input_paused=true;
  assert(vm_migrate_resume(&ctx)==(fail_at?EIO:0));
  assert(position==(fail_at?fail_at:4) && held==(fail_at!=0));
  assert(input_paused==(fail_at!=0));
 }
 held=false;position=0;
 assert(vm_migrate_resume(&ctx)==EBUSY && position==0);
 return 0;
}
'''
(out / 'destination.c').write_text(fixture)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-Wno-unused-variable',
    '-Wno-unused-but-set-variable', '-fsanitize=address,undefined',
    '-I' + str(root / 'sys'), '-I' + str(root / 'usr.sbin/bhyve'),
    str(out / 'destination.c'), '-o', str(out / 'destination')], check=True)
subprocess.run([str(out / 'destination')], check=True, timeout=30)
