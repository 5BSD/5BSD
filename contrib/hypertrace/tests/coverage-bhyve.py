#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Coverage collection for bhyve HyperTrace/migration code, bhyvectl and libvmmapi.

Phases (each writes a NEW directory under /usr/obj; nothing is installed,
no VM, device, module or daemon is touched):

  build OUT            Build instrumented production objects with the maintained
                       Makefiles (amd64, MK_BHYVE_SNAPSHOT=yes, as built): bhyve,
                       bhyvectl and libvmmapi.  These objects define the production
                       denominators.
  run OUT --build B    Run the listed offline suites with coverage wrappers, keep
                       per-suite raw profiles and verify they merge cleanly.
  report OUT --build B --run R [--run R2 ...]
                       Export production-configuration coverage.  Counters from
                       test binaries are credited to a production function only
                       when the test binary compiled the ORIGINAL source file
                       (coverage mapping names that file, not a copied slice) and
                       the function's structural hash equals the production
                       object's hash for the same function.  Everything else is
                       reported separately (test configurations, extracted
                       slices), never folded into the production figure.

The collector does not certify thresholds; it records denominators, hashes and
diagnostics so the result can be audited.
"""
from pathlib import Path
import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parents[3]
TESTS = Path(__file__).resolve().parent
JOBS = os.cpu_count() or 1
FLAGS = ['-fprofile-instr-generate', '-fcoverage-mapping',
         '-fprofile-update=atomic']

# Production component inventory.  Paths are relative to ROOT.  "whole" files
# are reported entirely; "mixed" files are reported whole AND restricted to the
# HyperTrace/migration function subset given by the regular expression.
BHYVE = 'usr.sbin/bhyve/'
COMPONENTS = {
    'bhyve-migration': [BHYVE + f for f in (
        'migration_session.c', 'migration_receiver.c', 'migration_tls.c',
        'migration_precopy.c', 'migration_dirty.c')],
    'bhyve-migration-headers': None,   # every mapped usr.sbin/bhyve/migration_*.h
    'bhyve-hypertrace': [BHYVE + 'hypertrace.c', BHYVE + 'pci_virtio_dtrace.c'],
    'bhyve-hypertrace-headers': None,  # mapped hypertrace*.h
    'bhyve-snapshot': [BHYVE + f for f in (
        'snapshot.c', 'snapshot_devmem.c', 'checkpoint_compat.c',
        'checkpoint_cpu.c', 'checkpoint_machine.c', 'checkpoint_manifest.c',
        'checkpoint_numa.c', 'checkpoint_topology.c',
        'amd64/checkpoint_cpu_machdep.c')],
    'bhyve-control': [BHYVE + 'ipc.c', BHYVE + 'gdb.c', BHYVE + 'bhyverun.c'],
    'bhyvectl': ['usr.sbin/bhyvectl/bhyvectl.c',
                 'usr.sbin/bhyvectl/amd64/bhyvectl_machdep.c'],
    'libvmmapi': ['lib/libvmmapi/' + f for f in (
        'vmmapi.c', 'vmmapi_dirty_log.c', 'vmmapi_memory.c', 'ppt.c',
        'amd64/vmmapi_machdep.c', 'amd64/vmmapi_freebsd_machdep.c',
        'vmmapi.h')],
}
# Task-scoped views of files whose remainder is outside the migration and
# HyperTrace work: only the named functions are counted (llvm-cov -name-regex
# on the same rekeyed profile).  None means the whole file.
SCOPED = {
    'bhyve-control-scoped': {
        BHYVE + 'ipc.c': None,
        BHYVE + 'gdb.c': ['gdb_migration_fence', 'gdb_migration_unfence',
                          'gdb_migration_retire', 'new_connection', 'gdb_write_mem',
                          'gdb_mark_guest_write', 'remove_all_sw_breakpoints',
                          'update_sw_breakpoint'],
        BHYVE + 'bhyverun.c': [
            'fbsdrun_retire_cpus_begin', 'fbsdrun_cpus_retiring',
            'fbsdrun_retire_cpus_wait', 'fbsdrun_retirecpu_if_requested',
            'fbsdrun_migration_cpu_init', 'fbsdrun_migration_retire_wake',
            'fbsdrun_migration_cpu_point', 'fbsdrun_migration_resume_cpus',
            'fbsdrun_migration_pause_cpus', 'kernel_startup_request',
            'kernel_startup_configure', 'kernel_startup_commit', 'kernel_startup_refresh',
            'bhyve_numa_checkpoint_export', 'bhyve_numa_restore_apply', 'vm_loop',
            'fbsdrun_start_thread', 'fbsdrun_addcpu', 'fbsdrun_deletecpu',
            'bhyve_prepare_control'],
    },
}
# Documented waivers: trace-continuity code that the fresh-session product
# contract leaves intentionally unreachable (user decision 2026-10-21).  Each
# entry resolves to exact line ranges at report time; whole-file figures are
# always reported alongside the waived ones.  'functions' are whole function
# definitions (return type through closing brace); 'marked_blocks' are the
# statement following each line containing the marker, through its matching
# closing brace.  The resolved ranges are written to summary.json.
CONTINUITY_MARKER = 'Trace continuity (disabled future feature)'
WAIVERS = {
    BHYVE + 'snapshot.c': {'marked_blocks': CONTINUITY_MARKER, 'functions': [
        # destination side: continuity images are refused before these
        'hypertrace_restore_prepare_handoff', 'hypertrace_restore_begin_mutation']},
    BHYVE + 'checkpoint_manifest.c': {'functions': [
        'checkpoint_release_read_at', 'checkpoint_release_publish_at']},
    BHYVE + 'hypertrace.c': {'functions': [
        # source side (handoff_enabled is false) and functions with no caller
        'ht_handoff_request', 'hypertrace_handoff_source', 'hypertrace_handoff_destination',
        'hypertrace_handoff_rebind_begin', 'hypertrace_handoff_mutation_reset',
        'hypertrace_handoff_rebind_cancel_pending', 'hypertrace_handoff_source_release_open',
        'hypertrace_handoff_source_release_finish', 'hypertrace_handoff_source_fresh',
        'hypertrace_handoff_source_gate_ensure', 'ht_handoff_source_drain_once',
        'hypertrace_handoff_source_drain', 'hypertrace_handoff_source_status_fresh',
        'hypertrace_handoff_source_bundle_fresh', 'hypertrace_handoff_source_ensure',
        'hypertrace_handoff_bind_kill_prestart',
        # destination side, reached only from refused continuity restores
        'ht_handoff_import_once', 'ht_stage_release_once',
        'hypertrace_handoff_bind_delivery_prestart', 'hypertrace_handoff_cleanup_prestart',
        'hypertrace_handoff_delivery_prestart', 'hypertrace_handoff_destination_import_prestart',
        'hypertrace_handoff_destination_prestart', 'hypertrace_handoff_destination_promote_prestart',
        'hypertrace_handoff_destination_stage_release_prestart',
        'hypertrace_handoff_execution_start', 'hypertrace_handoff_kill_prestart',
        'hypertrace_handoff_rebind_begin_optional', 'hypertrace_handoff_rebind_commit_empty',
        'hypertrace_handoff_rebind_empty_ready', 'hypertrace_handoff_rebind_nonempty_preflight',
        'hypertrace_handoff_rebind_pending', 'hypertrace_handoff_rebind_stage',
        'hypertrace_handoff_replay_drain', 'hypertrace_release_recover',
        'hypertrace_transfer_replay_controls',
        # Reachable only through the waived paths above (callers checked):
        # the restore-side release/transfer inspection runs only for a
        # format-4 image, which load_restore_file refuses first, or when
        # hypertrace_release_present is set, which only that block does;
        # destination prestart/ensure is called from waived functions,
        # waived marked blocks, or hypertrace_restore_cancel_if_safe() with
        # a reservation flag set only in waived blocks; the rekey and
        # live-receipt lookups are called only from waived pci_virtio_dtrace
        # rekey code.
        'hypertrace_release_transfer_inspect', 'hypertrace_release_attestation_inspect',
        'ht_release_reply_valid', 'hypertrace_handoff_destination_ensure',
        'hypertrace_handoff_destination_status_prestart',
        'ht_handoff_destination_prestart_once', 'ht_handoff_fresh', 'ht_handoff_frame',
        'hypertrace_handoff_rekey_applied', 'hypertrace_handoff_delivery_live',
        'hypertrace_handoff_kill_live', 'ht_handoff_delivery_lookup',
        'ht_handoff_kill_lookup']},
    BHYVE + 'pci_virtio_dtrace.c': {'marked_blocks': CONTINUITY_MARKER, 'functions': [
        # rekey / restored-KILL replay (NODE_REKEY is built only from a
        # transfer-ticket image, which restore refuses)
        'pci_vtdtr_rekey_expired', 'pci_vtdtr_rekey_delivery_receipt',
        'pci_vtdtr_rekey_kill_receipt', 'pci_vtdtr_rekey_receipt_query_rx',
        'pci_vtdtr_private_snapshot_restore', 'pci_vtdtr_checkpoint_queue_plan',
        'pci_vtdtr_checkpoint_source_replay_room',
        'pci_vtdtr_checkpoint_cleanup_receipt', 'pci_vtdtr_checkpoint_delivery_receipt',
        'pci_vtdtr_checkpoint_elf_digest', 'pci_vtdtr_checkpoint_private_image_bind',
        'pci_vtdtr_checkpoint_private_image_operation',
        'pci_vtdtr_checkpoint_private_image_query',
        'pci_vtdtr_checkpoint_private_image_replay_room',
        'pci_vtdtr_checkpoint_publish_paused', 'pci_vtdtr_checkpoint_publish_sc_paused',
        'pci_vtdtr_checkpoint_stage_bind', 'pci_vtdtr_checkpoint_stage_query',
        'pci_vtdtr_handoff_ticket_attach', 'pci_vtdtr_handoff_ticket_attach_locked',
        'pci_vtdtr_handoff_ticket_attach_paused', 'pci_vtdtr_handoff_ticket_clear']},
}
# Outcome waivers: individual branch outcomes shown unreachable, each with a
# class whose reason applies to every member.  A listed outcome must exist at
# that exact line:column as a top-level branch, must not fall inside a
# continuity waiver range, and must have executed zero times; the report fails
# otherwise (a waived outcome that runs was never unreachable).  The class
# 'folded-constant' is found automatically: the counted arm of a branch whose
# other arm the compiler folded to a constant (e.g. sys/bitset.h
# __constexpr_cond), when that counted arm never executed.
OUTCOME_CLASSES = {
    'folded-constant': 'compile-time constant condition: llvm folded one arm; '
                       'the counted arm can never execute',
    'continuity-flag': 'local trace-continuity flag is the constant false '
                       '(fresh-session contract); its true arm is disabled code',
    'encode-fixed-buffer': 'encoder fails only on NULL arguments or a short '
                           'output buffer; the call passes a fixed buffer of '
                           'the encoded size',
    'encode-validated': 'every encoded field was validated by the decoders '
                        'that produced it',
    'decoder-total': 'decoder accepts every input of the length the caller '
                     'already checked',
    'decoder-guarantee': 'value already constrained by the frame/record '
                         'decoder (protocol versions 1..1; unknown capability '
                         'bits rejected)',
    'out-pointer': 'every caller passes a non-NULL output pointer',
    'config-nonnull': 'session config is checked non-NULL at entry and never '
                      'cleared',
    'frame-limit': 'payload is bounded by MIGRATION_MAX_PAYLOAD (16 MiB)',
    'syscall-errno': 'read(2)/write(2) set errno on every failure',
    'arith-bound': 'overflow guard on a byte/page total that would require '
                   'transferring 2^64 bytes',
    'type-bound': 'value bounded by its source type (int milliseconds; '
                  'LP64 size_t)',
    'state-invariant': 'state combination excluded by the code that sets '
                       'these fields (see the record for each)',
    'validator-implied': 'already rejected by the shared result validator',
    'random-negligible': 'an all-zero 32-byte arc4random challenge',
    'clock-total': 'clock_gettime(CLOCK_MONOTONIC or CLOCK_REALTIME) with a '
                   'valid clock id and pointer cannot fail',
    'libc-total': 'snprintf with a plain format and valid arguments cannot '
                  'return a negative count',
    'assert-invariant': 'the false arm of an assert() on an internal invariant '
                        '(builds keep assertions; the arm is the abort)',
    'constant-condition': 'a compile-time constant operand llvm did not fold '
                          '(the ", 1" right operand of TAILQ_FOREACH_SAFE)',
    'race-only': 'reachable only by a scheduling race the harness cannot force '
                 'deterministically',
    'malloc-only': 'reachable only by an allocation failure not enumerated '
                   'for this function',
    'static-guard': 'NULL or range guard at the entry of a file-local function; '
                    'every caller in the file passes a valid argument (callers '
                    'checked)',
    # found automatically: the raw_stdio arm of an EPRINTLN/FPRINTLN site
    # that ran in the other console mode (the arms differ only in the
    # line ending; the site is covered)
    'console-mode': 'the console-mode test of EPRINTLN/FPRINTLN at a site '
                    'that ran in the other mode',
}
OUTCOME_WAIVERS = {
    BHYVE + 'migration_session.c': [
        ('migration_crc32', ['chunk = payload_len > UINT_MAX'], 11, 'T', 'frame-limit'),
        ('migration_source_caps_validate', ['(accepted->capability_flags & ~MIGRATION_CAP_ALL) != 0) {'],
         6, 'T', 'decoder-guarantee'),
        ('migration_fd_send', ['return (errno != 0 ? errno : EIO);'], 12, 'F', 'syscall-errno'),
        ('migration_fd_recv', ['return (errno != 0 ? errno : EIO);'], 12, 'F', 'syscall-errno'),
        ('migration_send_reason', ['error = migration_reason_encode(', 'if (error != 0)'],
         6, 'T', 'encode-fixed-buffer'),
        ('migration_recv', ['if (sess->version != 0 && candidate.version != sess->version)'],
         28, 'T', 'decoder-guarantee'),
        ('migration_cancelled', ['return (sess->config != NULL && sess->config->cancel != NULL'],
         10, 'F', 'config-nonnull'),
        ('migration_source_send_generation', ['offset > UINT64_MAX - page_bytes) {'],
         7, 'T', 'arith-bound'),
        ('migration_source_send_generation', ['offset > UINT64_MAX - page_bytes) {',
         'if (reason != NULL)'], 8, 'F', 'out-pointer'),
        ('migration_source_send_generation', ['&reason_msg) == 0 && reason != NULL)'],
         29, 'F', 'out-pointer'),
        ('migration_source_send_generation', ['free(payload);', 'if (reason != NULL)'],
         8, 'F', 'out-pointer'),
        ('migration_source_send_generation', ['/* One frame: unchunked',
         'error = migration_memgen_encode(&gen, scratch,', 'MIGRATION_MEMGEN_HDR_SIZE);',
         'if (error != 0)'], 8, 'T', 'encode-fixed-buffer'),
        ('migration_source_send_generation', ['scratch + MIGRATION_MEMGEN_HDR_SIZE, page_bytes);',
         'error = migration_memgen_encode(&gen, scratch,', 'MIGRATION_MEMGEN_HDR_SIZE);',
         'if (error != 0)'], 8, 'T', 'encode-fixed-buffer'),
        ('migration_source_send_generation', ['scratch + MIGRATION_MEMGEN_HDR_SIZE,',
         'MIGRATION_CHUNK_HDR_SIZE);', 'if (error != 0)'], 8, 'T', 'encode-fixed-buffer'),
        ('migration_source_send_dev_state', ['error = migration_chunk_encode(&chunk, frame,',
         'MIGRATION_CHUNK_HDR_SIZE);', 'if (error != 0)'], 7, 'T', 'encode-fixed-buffer'),
        ('migration_dest_run', ['error = migration_caps_accept_encode(&caps, caps_wire, sizeof(caps_wire));',
         'if (error != 0)'], 6, 'T', 'encode-validated'),
        ('migration_dest_run', ['error = migration_memgen_decode(payload, payload_len,',
         '&gen);', 'if (error != 0)'], 8, 'T', 'decoder-total'),
        ('migration_dest_run', ['MIGRATION_MEMGEN_HDR_SIZE,', 'MIGRATION_CHUNK_HDR_SIZE, &chunk);',
         'if (error != 0)'], 9, 'T', 'decoder-total'),
        ('migration_dest_run', ['error = migration_chunk_decode(payload,',
         'MIGRATION_CHUNK_HDR_SIZE, &chunk);', 'if (error != 0)'], 9, 'T', 'decoder-total'),
        ('migration_dest_run', ['mem_offset > UINT64_MAX - data_len ||'], 9, 'T', 'arith-bound'),
        # dev_state_started is set with dev_reasm and is followed by
        # dev_state_seen when dev_reasm is released; total==0 is refused first
        ('migration_dest_run', ['(dev_state_started && dev_reasm == NULL) ||'],
         31, 'T', 'state-invariant'),
        ('migration_dest_run', ['dev_reasm = malloc(dev_total != 0 ?'], 25, 'F', 'state-invariant'),
        ('migration_dest_run', ['} while (memcmp(challenge,'], 11, 'T', 'random-negligible'),
        # --- round 8: adapter and core arms shown unreachable ---
        # a memory record is one aligned granule and lowmem (from
        # vm_get_lowmem_size, whole pages) is granule-aligned, so a record
        # below lowmem cannot end above it; highmem_base + highmem cannot
        # overflow (both come from the VM's memory map)
        ('migration_memory_record_validate', ['backed = gpa < lowmem && end <= lowmem;'],
         27, 'F', 'state-invariant'),
        ('migration_memory_record_validate', ['if (highmem != 0 && highmem_base <= UINT64_MAX - highmem) {'],
         22, 'F', 'arith-bound'),
        # CAPS_REJECT is sent only after HELLO was received, which records
        # the peer's frame version
        ('migration_send', ['else if (type == MIGRATION_MSG_CAPS_REJECT && sess->peer_version != 0)'],
         48, 'F', 'state-invariant'),
        ('migration_source_run', ['if (topo_wire == NULL) {'], 6, 'T', 'malloc-only'),
        # fail_rollback is reached only by gotos after quiesced = true, each
        # with a non-zero error; the fail labels' error==0 arms are defensive
        ('migration_source_run', ['fail_rollback:', '*', '*', '*', '*', 'if (quiesced) {'],
         6, 'F', 'state-invariant'),
        ('migration_source_run', ['* must keep vCPUs stopped in this state.', '*/', 'if (error == 0)'],
         8, 'T', 'state-invariant'),
        ('migration_source_run', ['out.phase = MIGRATION_PHASE_ROLLED_BACK;', '}',
         'if (out.reason == MIGRATION_REASON_NONE)', 'out.reason = MIGRATION_REASON_TRANSPORT;',
         '(void)migration_send_reason(&sess, MIGRATION_MSG_ABORT, out.reason, 0);', 'free(payload);',
         'free(frame_payload);', 'free(topology);', 'if (error == 0)'], 6, 'T', 'state-invariant'),
        ('migration_source_run', ['out.source_runnable = true;', 'out.phase = MIGRATION_PHASE_FAILED;',
         'if (out.reason == MIGRATION_REASON_NONE)', 'out.reason = MIGRATION_REASON_TRANSPORT;',
         '(void)migration_send_reason(&sess, MIGRATION_MSG_ABORT, out.reason, 0);', 'free(payload);',
         'free(frame_payload);', 'free(topology);', 'if (error == 0)'], 6, 'T', 'state-invariant'),
        ('migration_source_run', ['out.reason = MIGRATION_REASON_STATE;',
         '(void)migration_send_reason(&sess, MIGRATION_MSG_ABORT, out.reason, 0);', 'free(payload);',
         'free(frame_payload);', 'free(topology);', 'if (error == 0)'], 6, 'T', 'state-invariant'),
        # the RELEASE result is decoded from exactly MIGRATION_REASON_SIZE bytes
        ('migration_dest_run', ['if (migration_reason_decode(payload, payload_len, &reason_msg) != 0 ||'],
         6, 'T', 'decoder-total'),
        # committed implies staged; a COMPLETED phase never reaches fail;
        # every goto fail carries a non-zero error
        ('migration_dest_run', ['} else if (staged || committed)'], 23, 'T', 'state-invariant'),
        ('migration_dest_run', ['if (out.phase != MIGRATION_PHASE_COMPLETED && !out.retained)'],
         6, 'F', 'state-invariant'),
        ('migration_dest_run', ['free(dev_reasm);', 'if (error == 0)'], 6, 'T', 'state-invariant'),
        # prod_resume cancels only once retirement began, which the repair
        # loop tests immediately before; only a concurrent retirement differs
        ('prod_repair_rollback', ['if (error == 0 || error == ECANCELED)'], 21, 'T', 'race-only'),
        # a channel binding fails only for an insecure channel and is taken
        # only for a secure one
        ('vm_do_migrate', ['src->recovery.destination_certificate_sha256);', 'if (error != 0) {'],
         6, 'T', 'state-invariant'),
        ('vm_do_migrate', ['bool debugger_fenced = false;', 'if (error == 0) {'], 6, 'F', 'state-invariant'),
        ('vm_do_migrate', ['return (reply);', '}', '}', '#endif', 'if (error == 0)'], 6, 'F', 'state-invariant'),
        # prod_quiesce leaves the source quiesced even when it fails, so a
        # source that is not runnable is quiesced or retiring
        ('vm_do_migrate', ['bool repair_tried = !result.source_runnable && !src->retirement_started &&',
         'src->quiesced;'], 6, 'F', 'state-invariant'),
        ('vm_do_migrate', ['if (src->retirement_started || !src->quiesced)'], 34, 'T', 'state-invariant'),
        # a fresh destination requires recovery_enabled and TLS before these
        ('migration_prod_dest_serve_impl', ['if (dst == NULL) {'], 6, 'T', 'malloc-only'),
        ('migration_prod_dest_serve_impl', ['if (hypertrace_initialized() && config->tls_credentials == NULL)'],
         34, 'T', 'state-invariant'),
        ('migration_prod_dest_serve_impl', ['dst->recovery.destination_certificate_sha256);', 'if (error == 0)'],
         6, 'F', 'state-invariant'),
        ('migration_prod_dest_serve_impl', ['if (error == 0 && result->resumed && hypertrace_initialized() &&'],
         20, 'F', 'state-invariant'),
        # every path leaving error 0 sets resolved
        ('vm_do_migrate_resolve', ['if (!resolved && error == 0)'], 19, 'T', 'state-invariant'),
        ('migration_prod_dest_reconstruct_begin', ['if (begun == NULL)'], 6, 'T', 'malloc-only'),
        # fstat of an owned open directory descriptor cannot fail
        ('migration_prod_dest_reconstruct_prepared', ['fstat(state->dirfd, &admitted) != 0) {'],
         6, 'T', 'libc-total'),
        ('migration_prod_dest_reconstruct_prepared', ['if (dst == NULL) {'], 6, 'T', 'malloc-only'),
        # the image is written by prod_dest_preserve from the same record the
        # journal admits; a mismatch needs a forged image that passes its digest
        ('migration_prod_dest_reconstruct_prepared',
         ['if (error == 0 && memcmp(view.fresh_record, state->admitted.record.session,'],
         20, 'T', 'state-invariant'),
        # migration_recovery_load_at returns only a source-side phase
        # (INTENT..CONFIRMED) for a source record; the owner record's session
        # was validated by migration_recovery_encode in owner_at
        ('migration_prod_source_finish_intent',
         ['if (phase >= MIGRATION_REC_SOURCE_RETIRED && phase <= MIGRATION_REC_SOURCE_CONFIRMED)'],
         47, 'F', 'decoder-guarantee'),
        ('migration_prod_source_finish_intent', ['if (phase != MIGRATION_REC_SOURCE_INTENT)'],
         6, 'T', 'decoder-guarantee'),
        ('migration_prod_source_finish_intent', ['sizeof(expected->session), &stopped);', 'if (error != 0)'],
         6, 'T', 'decoder-guarantee'),
        ('migration_prod_source_recover_restart_named', ['error = migration_channel_binding(&channel, true, source_pin, destination_pin);',
         'if (error == 0 &&'], 6, 'F', 'state-invariant'),
        # between finish_intent's EBUSY and the re-read, only another process
        # could change the phase or retire the lifetime
        ('migration_prod_source_recover_restart_named',
         ['if (error == 0 && phase != MIGRATION_REC_SOURCE_INTENT)'], 22, 'T', 'race-only'),
        ('migration_prod_source_recover_restart_named',
         ['if (error == 0 && hypertrace_session_retired(vmid, epoch) != 0) {'], 22, 'F', 'race-only'),
        ('vm_do_migrate_recover', ['error = migration_channel_binding(&channel, true, source_pin, destination_pin);',
         'if (error != 0)'], 6, 'T', 'state-invariant'),
        # recovery is refused unless retirement began
        ('vm_do_migrate_recover', ['nvlist_add_bool(reply, "source_runnable",',
         '!src->retirement_started && !src->quiesced);'], 34, 'F', 'state-invariant'),
    ],
    BHYVE + 'checkpoint_manifest.c': [
        # --- round 8 item 4: guards of file-local helpers, checks repeated
        # after a caller's validator, and bounds of generated names ---
        # checkpoint_generation_member_valid is called with literal roles and
        # NAME_MAX+1 buffers whose termination valid_for checked first
        ('checkpoint_generation_member_valid', ['if (base == NULL || role == NULL || member == NULL)'], 6, 'T', 'static-guard'),
        ('checkpoint_generation_member_valid', ['if (base == NULL || role == NULL || member == NULL)'], 22, 'T', 'static-guard'),
        ('checkpoint_generation_member_valid', ['if (base == NULL || role == NULL || member == NULL)'], 38, 'T', 'static-guard'),
        ('checkpoint_generation_member_valid', ['if (base_len == 0 || base_len > NAME_MAX || role_len == 0 ||'], 46, 'T', 'constant-condition'),
        ('checkpoint_generation_member_valid', ['role_len > NAME_MAX || member_len > NAME_MAX ||'], 6, 'T', 'constant-condition'),
        ('checkpoint_generation_member_valid', ['role_len > NAME_MAX || member_len > NAME_MAX ||'], 29, 'T', 'state-invariant'),
        ('checkpoint_generation_member_valid', ['base_len > SIZE_MAX - role_len - 2)'], 6, 'T', 'arith-bound'),
        # the digits of a digest were validated by checkpoint_digest_valid
        ('checkpoint_hex_nibble', ["if (digit >= '0' && digit <= '9')"], 6, 'F', 'validator-implied'),
        ('checkpoint_hex_nibble', ["if (digit >= 'a' && digit <= 'f')"], 6, 'F', 'validator-implied'),
        ('checkpoint_hex_nibble', ["if (digit >= 'a' && digit <= 'f')"], 22, 'F', 'validator-implied'),
        ('checkpoint_digest_valid', ['if (digest == NULL ||'], 6, 'T', 'static-guard'),
        # serialize: snprintf of bounded fixed-size fields into a buffer sized
        # for all of them
        ('checkpoint_manifest_serialize', ['if (written < 0)'], 6, 'T', 'libc-total'),
        ('checkpoint_manifest_serialize', ['if ((size_t)written >= CHECKPOINT_MANIFEST_CONTENTS_MAX)'], 6, 'T', 'arith-bound'),
        # handoff token/identity: the callers validated the manifest's members
        # (valid_for) and digests (the verified open) first; an all-zero
        # token or digest from random/SHA-256 output is negligible
        ('checkpoint_manifest_handoff_token', ['!checkpoint_generation_member_valid(base, "data", m->data,'], 6, 'T', 'validator-implied'),
        ('checkpoint_manifest_handoff_token', ['if (memcmp(parsed_token, (const uint8_t[16]){0}, 16) == 0)'], 6, 'T', 'random-negligible'),
        ('checkpoint_manifest_handoff_identity', ['error = checkpoint_manifest_handoff_token(base, m, parsed_token);', 'if (error != 0)'],
         6, 'T', 'validator-implied'),
        ('checkpoint_manifest_handoff_identity', ['error = checkpoint_manifest_serialize(m, contents, &length);', 'if (error != 0)'],
         6, 'T', 'libc-total'),
        ('checkpoint_manifest_handoff_identity', ['if (memcmp(parsed_digest, (const uint8_t[32]){0}, 32) == 0)'], 6, 'T', 'random-negligible'),
        # read_fd: strchr inside the NUL-terminated buffer never passes end
        ('checkpoint_manifest_read_fd', ['if (line == NULL || line > end)'], 23, 'T', 'state-invariant'),
        # read_fd reports a non-manifest only with an error
        ('checkpoint_manifest_read', ['if (candidate_is_manifest)'], 7, 'F', 'state-invariant'),
        ('checkpoint_manifest_read_at', ['if (candidate_is_manifest)'], 7, 'F', 'state-invariant'),
        # the host architecture string and CHECKPOINT_MACHINE_ABI are build
        # constants shorter than their fields; the generation is 4 x %08x
        ('checkpoint_manifest_compatible', ['strcmp(host, "unknown") != 0 &&'], 6, 'F', 'constant-condition'),
        ('checkpoint_generation_names', ['if (strcmp(checkpoint_host_architecture(), "unknown") == 0)'], 6, 'T', 'constant-condition'),
        ('checkpoint_generation_names', ['if (strlcpy(candidate.architecture, checkpoint_host_architecture(),'], 6, 'T', 'constant-condition'),
        ('checkpoint_generation_names', ['strlcpy(candidate.machine, CHECKPOINT_MACHINE_ABI,'], 6, 'T', 'constant-condition'),
        ('checkpoint_generation_names', ['if (length != CHECKPOINT_GENERATION_HEX_LEN)'], 6, 'T', 'libc-total'),
        ('checkpoint_generation_names', ['if (length < 0 || (size_t)length >= sizeof(candidate.data))'], 6, 'T', 'libc-total'),
        # kern/meta/trace names have the data name's length, which is checked first
        ('checkpoint_generation_names', ['if (length < 0 || (size_t)length >= sizeof(candidate.kern))'], 6, 'T', 'libc-total'),
        ('checkpoint_generation_names', ['if (length < 0 || (size_t)length >= sizeof(candidate.kern))'], 20, 'T', 'state-invariant'),
        ('checkpoint_generation_names', ['if (length < 0 || (size_t)length >= sizeof(candidate.meta))'], 6, 'T', 'libc-total'),
        ('checkpoint_generation_names', ['if (length < 0 || (size_t)length >= sizeof(candidate.meta))'], 20, 'T', 'state-invariant'),
        ('checkpoint_generation_names_trace', ['if (!checkpoint_generation_member_valid(base, "data",'], 6, 'T', 'state-invariant'),
        ('checkpoint_generation_names_trace', ['if (length < 0 || (size_t)length >= sizeof(candidate.trace)) {'], 6, 'T', 'libc-total'),
        ('checkpoint_generation_names_trace', ['if (length < 0 || (size_t)length >= sizeof(candidate.trace)) {'], 20, 'T', 'state-invariant'),
        # publish validated the manifest before deriving the temporary name
        ('checkpoint_manifest_tmp_valid_for', ['!checkpoint_generation_member_valid(base, "data", m->data,'], 6, 'T', 'validator-implied'),
        ('checkpoint_manifest_tmp_valid_for', ['return (length >= 0 && (size_t)length < sizeof(expected) &&'], 10, 'F', 'libc-total'),
        ('checkpoint_manifest_tmp_valid_for', ['return (length >= 0 && (size_t)length < sizeof(expected) &&'], 25, 'F', 'state-invariant'),
        # members of one directory share a device
        ('checkpoint_validate_distinct_fds', ['if ((data_sb.st_dev == kern_sb.st_dev && data_sb.st_ino == kern_sb.st_ino) ||'], 7, 'F', 'state-invariant'),
        ('checkpoint_validate_distinct_fds', ['(data_sb.st_dev == meta_sb.st_dev && data_sb.st_ino == meta_sb.st_ino) ||'], 7, 'F', 'state-invariant'),
        ('checkpoint_validate_distinct_fds', ['(kern_sb.st_dev == meta_sb.st_dev && kern_sb.st_ino == meta_sb.st_ino))'], 7, 'F', 'state-invariant'),
        ('checkpoint_manifest_open_verified_trace_at', ['(trace_stat.st_dev == data_stat.st_dev &&'], 7, 'F', 'state-invariant'),
        ('checkpoint_manifest_open_verified_trace_at', ['(trace_stat.st_dev == kern_stat.st_dev &&'], 7, 'F', 'state-invariant'),
        ('checkpoint_manifest_open_verified_trace_at', ['(trace_stat.st_dev == meta_stat.st_dev &&'], 7, 'F', 'state-invariant'),
        ('checkpoint_ranges_overlap', ['if (first_size > UINTPTR_MAX - first_start ||'], 6, 'T', 'arith-bound'),
        ('checkpoint_ranges_overlap', ['second_size > UINTPTR_MAX - second_start)'], 6, 'T', 'arith-bound'),
        # SHA256_Fd over a regular file this process opened: libmd's read(2)
        # is not wrapped here and fails only on an I/O error or a signal
        ('checkpoint_hash_fd', ['if (result == NULL && errno != EINTR)'], 7, 'T', 'libc-total'),
        ('checkpoint_hash_fd', ['if (result == NULL && errno != EINTR)'], 25, 'T', 'libc-total'),
        ('checkpoint_hash_fd', ['if (result == NULL && errno != EINTR)'], 25, 'F', 'libc-total'),
        ('checkpoint_hash_fd', ['if (result == NULL && errno != EINTR)', 'error = errno != 0 ? errno : EIO;'], 12, 'T', 'libc-total'),
        ('checkpoint_hash_fd', ['if (result == NULL && errno != EINTR)', 'error = errno != 0 ? errno : EIO;'], 12, 'F', 'libc-total'),
        # hash_at is called by publish after its own validation of the same
        # manifest
        ('checkpoint_manifest_hash_at', ['if (dirfd < 0 || m == NULL ||'], 6, 'T', 'static-guard'),
        ('checkpoint_manifest_hash_at', ['if (dirfd < 0 || m == NULL ||'], 19, 'T', 'static-guard'),
        ('checkpoint_manifest_hash_at', ['if (dirfd < 0 || m == NULL ||', '(m->format_version != 3 && m->format_version != 4 &&',
         'm->format_version != 5) ||'], 6, 'T', 'validator-implied'),
        ('checkpoint_manifest_hash_at', ['m->format_version != 5) ||', '!checkpoint_member_valid(m->data) ||'], 6, 'T', 'validator-implied'),
        ('checkpoint_manifest_hash_at', ['!checkpoint_member_valid(m->data) ||', '!checkpoint_member_valid(m->kern) ||'], 6, 'T', 'validator-implied'),
        ('checkpoint_manifest_hash_at', ['!checkpoint_member_valid(m->kern) ||', '!checkpoint_member_valid(m->meta) ||'], 6, 'T', 'validator-implied'),
        ('checkpoint_manifest_hash_at', ['((m->format_version == 4 || m->format_version == 5) && !checkpoint_member_valid(m->trace)))'],
         61, 'T', 'validator-implied'),
        # the data descriptor is opened before any failure that reaches fail
        ('checkpoint_manifest_open_verified_at', ['fail:', 'if (*data_fd >= 0)'], 6, 'F', 'state-invariant'),
        ('checkpoint_publish', ['error = checkpoint_manifest_serialize(&candidate, contents, &length);', 'if (error != 0)'], 6, 'T', 'libc-total'),
        # every caller passes a generation pointer
        ('checkpoint_generation_member_valid', ['if (generation != NULL)'], 6, 'F', 'static-guard'),
    ],
    BHYVE + 'snapshot_devmem.c': [
        # --- round 8 item 4: guards of file-local helpers and bounds of
        # validated region sets ---
        # devmem_ranges_overlap is called with validated regions (non-NULL,
        # non-empty, in the address space)
        ('devmem_ranges_overlap', ['if (first_length == 0 || second_length == 0)'], 6, 'T', 'static-guard'),
        ('devmem_ranges_overlap', ['if (first_length == 0 || second_length == 0)'], 27, 'T', 'static-guard'),
        ('devmem_ranges_overlap', ['if (first == NULL || second == NULL)'], 6, 'T', 'static-guard'),
        ('devmem_ranges_overlap', ['if (first == NULL || second == NULL)'], 23, 'T', 'static-guard'),
        ('devmem_ranges_overlap', ['if (first_start > UINTPTR_MAX - (first_length - 1) ||'], 6, 'T', 'arith-bound'),
        ('devmem_ranges_overlap', ['second_start > UINTPTR_MAX - (second_length - 1))'], 6, 'T', 'arith-bound'),
        ('devmem_validate_regions', ['if (count > UINT32_MAX ||'], 6, 'T', 'arith-bound'),
        ('devmem_validate_regions', ['count > (SIZE_MAX - DEVMEM_HEADER_SIZE) / DEVMEM_ENTRY_SIZE ||'], 6, 'T', 'arith-bound'),
        ('devmem_validate_regions', ['count > SIZE_MAX / sizeof(*regions))'], 6, 'T', 'arith-bound'),
        ('bhyve_devmem_snapshot_save', ['if (ordered[i].length > UINT64_MAX - cursor) {'], 7, 'T', 'arith-bound'),
        ('bhyve_devmem_snapshot_save', ['if (total > SIZE_MAX || total > (uint64_t)INT64_MAX ||'], 6, 'T', 'arith-bound'),
        ('bhyve_devmem_snapshot_save', ['if (total > SIZE_MAX || total > (uint64_t)INT64_MAX ||'], 26, 'T', 'arith-bound'),
        # count == 0 was refused by the header check just above
        ('devmem_snapshot_load', ['if ((count != 0 && entries == NULL) ||'], 7, 'F', 'state-invariant'),
        ('devmem_snapshot_load', ['(count != 0 && targets == NULL) ||'], 7, 'F', 'state-invariant'),
        ('devmem_snapshot_load', ['(restore && count != 0 && payloads == NULL)) {'], 18, 'F', 'state-invariant'),
        # an entry matched a validated region by name and equals its length
        # (non-zero), and its offset equals previous_end, which the header
        # bounded to the extension: the later operands cannot be the first
        # to fail
        ('devmem_snapshot_load', ['entries[i].length == 0 ||'], 7, 'T', 'state-invariant'),
        ('devmem_snapshot_load', ['entries[i].offset > extension_length ||'], 7, 'T', 'state-invariant'),
        ('devmem_snapshot_load', ['entries[i].length > extension_length - entries[i].offset) {'], 7, 'T', 'state-invariant'),
    ],
    BHYVE + 'checkpoint_numa.c': [
        # file-local helpers called with the module's own constants and
        # non-NULL outputs; widths are 16 and 4 hex digits
        ('checkpoint_numa_text_size', ['if (result == NULL || count == 0)'], 6, 'T', 'static-guard'),
        ('checkpoint_numa_text_size', ['if (result == NULL || count == 0)'], 24, 'T', 'static-guard'),
        ('checkpoint_numa_text_size', ['if (count > (SIZE_MAX - 1) / (width + 1))'], 6, 'T', 'arith-bound'),
        ('checkpoint_numa_hex_decode', ['if (text == NULL || value == NULL || width == 0 || width > 16)'], 6, 'T', 'static-guard'),
        ('checkpoint_numa_hex_decode', ['if (text == NULL || value == NULL || width == 0 || width > 16)'], 22, 'T', 'static-guard'),
        ('checkpoint_numa_hex_decode', ['if (text == NULL || value == NULL || width == 0 || width > 16)'], 39, 'T', 'static-guard'),
        ('checkpoint_numa_hex_decode', ['if (text == NULL || value == NULL || width == 0 || width > 16)'], 53, 'T', 'static-guard'),
        ('checkpoint_numa_hex_list_count', ['if (text == NULL || count == NULL || width == 0 || maximum == 0)'], 22, 'T', 'static-guard'),
        ('checkpoint_numa_hex_list_count', ['if (text == NULL || count == NULL || width == 0 || maximum == 0)'], 39, 'T', 'static-guard'),
        ('checkpoint_numa_hex_list_count', ['if (text == NULL || count == NULL || width == 0 || maximum == 0)'], 53, 'T', 'static-guard'),
        # (length + 1) % stride == 0 with length >= width gives count >= 1
        ('checkpoint_numa_hex_list_count', ['if (*count == 0 || *count > maximum)'], 6, 'T', 'state-invariant'),
        # the public encoder validated count ranges before sizing
        ('checkpoint_numa_encode', ['CHECKPOINT_NUMA_SIZE_WIDTH, &sizes_size);', 'if (error == 0)'], 6, 'F', 'validator-implied'),
        ('checkpoint_numa_encode', ['CHECKPOINT_NUMA_DOMAIN_WIDTH, &mapping_size);', 'if (error != 0)'], 6, 'T', 'validator-implied'),
        # snprintf of a fixed-width hex field into a buffer sized for it
        ('checkpoint_numa_encode', ['if (length != CHECKPOINT_NUMA_SIZE_WIDTH +'], 7, 'T', 'libc-total'),
        ('checkpoint_numa_encode', ['if (length != CHECKPOINT_NUMA_DOMAIN_WIDTH +'], 7, 'T', 'libc-total'),
        # four hex digits decode to at most 0xffff
        ('checkpoint_numa_decode', ['if (error != 0 || decoded > UINT16_MAX) {'], 21, 'T', 'arith-bound'),
    ],
    BHYVE + 'checkpoint_machine.c': [
        # hash_string is called with the device table's bounded strings
        ('checkpoint_machine_hash_string', ['if (value == NULL)'], 6, 'T', 'static-guard'),
        ('checkpoint_machine_hash_string', ['if (length == maximum || length > UINT32_MAX)'], 6, 'T', 'static-guard'),
        ('checkpoint_machine_hash_string', ['if (length == maximum || length > UINT32_MAX)'], 27, 'T', 'arith-bound'),
        ('checkpoint_machine_topology_digest', ['capacity < CHECKPOINT_MACHINE_DIGEST_LENGTH || count > UINT32_MAX)'],
         53, 'T', 'arith-bound'),
        ('checkpoint_machine_topology_digest', ['ordered[i]->name, CHECKPOINT_MACHINE_DEVICE_NAME_MAX + 1);',
         'if (error != 0)'], 7, 'T', 'state-invariant'),
        ('checkpoint_machine_topology_digest', ['compat->queue_sizes, sizeof(compat->queue_sizes));', 'if (error != 0)'], 7, 'T', 'state-invariant'),
        ('checkpoint_machine_topology_digest', ['compat->shared_memory, sizeof(compat->shared_memory));', 'if (error != 0)'], 7, 'T', 'state-invariant'),
        ('checkpoint_machine_topology_digest', ['if (SHA256_End(&context, staging) == NULL) {'], 6, 'T', 'libc-total'),
    ],
    BHYVE + 'checkpoint_cpu.c': [
        # validate() requires the fixed contract version on both sides
        ('checkpoint_cpu_contract_match', ['if (source->version != destination->version ||'], 6, 'T', 'validator-implied'),
        ('checkpoint_cpu_contract_encode', ['if (contract->record_count >'], 6, 'T', 'validator-implied'),
        ('checkpoint_cpu_contract_encode', ['if (byte_count > (SIZE_MAX - 1) / 2)'], 6, 'T', 'arith-bound'),
        # the text length was checked against twice the header first
        ('checkpoint_cpu_contract_decode', ['if (byte_count < CPU_CONTRACT_HEADER_SIZE)'], 6, 'T', 'state-invariant'),
    ],
    BHYVE + 'checkpoint_compat.c': [
        ('checkpoint_compat_payload_crc32', ['chunk = payload_size > UINT_MAX ? UINT_MAX : (uInt)payload_size;'], 11, 'T', 'arith-bound'),
    ],
    BHYVE + 'checkpoint_topology.c': [
        # both geometries validated against the same total; with equal
        # lowmem the highmem sizes are equal too
        ('checkpoint_memory_geometry_match', ['source->highmem_size != destination->highmem_size)'], 6, 'T', 'state-invariant'),
    ],
    BHYVE + 'migration_tls.c': [(134, 26, 'T', 'type-bound')],
    BHYVE + 'pci_virtio_dtrace.c': [
        # --- round 8 item 3: device arms shown unreachable ---
        # clock_gettime(CLOCK_MONOTONIC) with a valid pointer
        ('pci_vtdtr_pause', ['if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {'], 6, 'T', 'clock-total'),
        ('pci_vtdtr_session_stop_begin_impl', ['else if (clock_gettime(CLOCK_MONOTONIC,'], 11, 'T', 'clock-total'),
        ('pci_vtdtr_session_attach_begin', ['else if (clock_gettime(CLOCK_MONOTONIC, &sc->vsd_fresh_deadline) != 0)'],
         11, 'T', 'clock-total'),
        ('pci_vtdtr_session_stop_status_locked', ['else if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)'],
         11, 'T', 'clock-total'),
        ('pci_vtdtr_deadline_expired', ['return (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||'], 10, 'T', 'clock-total'),
        ('pci_vtdtr_rekey_head_awaits_ticket', ['if (clock_gettime(CLOCK_MONOTONIC,'], 7, 'T', 'clock-total'),
        ('pci_vtdtr_events', ['clock_gettime(CLOCK_MONOTONIC, &wake) == 0) {'], 8, 'F', 'clock-total'),
        # pthread_mutex_lock on an initialized, unowned mutex; pthread
        # mutex/condattr/cond initialization with default attributes
        ('pci_vtdtr_pause', ['error = pthread_mutex_lock(&sc->vsd_mtx);', 'if (error != 0)'], 6, 'T', 'libc-total'),
        ('pci_vtdtr_init', ['error = pthread_mutex_init(&sc->vsd_mtx, NULL);', 'if (error != 0)'], 6, 'T', 'libc-total'),
        ('pci_vtdtr_init', ['error = pthread_condattr_init(&condattr);', 'if (error != 0)'], 6, 'T', 'libc-total'),
        ('pci_vtdtr_init', ['error = pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC);', 'if (error != 0) {'],
         6, 'T', 'libc-total'),
        ('pci_vtdtr_init', ['pthread_condattr_destroy(&condattr);', 'if (error != 0)'], 6, 'T', 'libc-total'),
        # OpenSSL SHA-256 over an initialized context and in-memory buffers
        ('pci_vtdtr_replay_manifest_digest', ['if (hash == NULL)'], 6, 'T', 'malloc-only'),
        ('pci_vtdtr_replay_manifest_digest', ['if (EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1 ||'],
         6, 'T', 'libc-total'),
        ('pci_vtdtr_replay_manifest_digest', ['EVP_DigestUpdate(hash, count_wire, sizeof(count_wire)) != 1)'],
         6, 'T', 'libc-total'),
        ('pci_vtdtr_replay_manifest_digest', ['if (EVP_DigestUpdate(hash, wire, sizeof(wire)) != 1)'],
         7, 'T', 'libc-total'),
        ('pci_vtdtr_replay_manifest_digest', ['if (EVP_DigestFinal_ex(hash, digest, &digest_length) == 1 &&'],
         6, 'F', 'libc-total'),
        ('pci_vtdtr_replay_manifest_digest', ['digest_length == SHA256_DIGEST_LENGTH)'], 6, 'F', 'libc-total'),
        ('pci_vtdtr_control_rx', ['if (SHA256(elf, len, elf_digest) == NULL) {'], 8, 'T', 'libc-total'),
        # an all-zero 16-byte gate token or zero 64-bit stop token from arc4random
        ('pci_vtdtr_session_stop_begin_impl', ['} while (memcmp(sc->vsd_session_gate_token,'], 13, 'T', 'random-negligible'),
        ('pci_vtdtr_session_stop_begin_impl', ['do { arc4random_buf(&token, sizeof(token)); } while (token == 0);'],
         56, 'T', 'random-negligible'),
        ('pci_vtdtr_fresh_gate_hold', ['} while (memcmp(sc->vsd_fresh_gate_token, (const uint8_t[16]){0}, 16) == 0);'],
         12, 'T', 'random-negligible'),
        # the ELF reassembly buffer accounting asserted by control_rx
        ('pci_vtdtr_control_rx', ['assert(buflen > len);'], 4, 'F', 'assert-invariant'),
        ('pci_vtdtr_control_rx', ['assert((_buf + size) < (buf + buflen));'], 4, 'F', 'assert-invariant'),
        ('pci_vtdtr_control_rx', ['assert(_buf > buf);'], 4, 'F', 'assert-invariant'),
        ('pci_vtdtr_control_rx', ['assert((_buf + len) == (buf + buflen));'], 4, 'F', 'assert-invariant'),
        # queue and partial totals are bounded by VTDTR_MAX_PENDING controls
        # and one PCI_VTDTR_MAXELFLEN-bounded partial ELF
        ('pci_vtdtr_snapshot_extra_capacity', ['if (partial > SIZE_MAX - 4096 ||'], 6, 'T', 'arith-bound'),
        ('pci_vtdtr_snapshot_extra_capacity', ['queued > (SIZE_MAX - partial - 4096) / entry_size)'], 6, 'T', 'arith-bound'),
        # trace continuity (rekey) operands outside the marked blocks
        ('pci_vtdtr_ctrl_checkpoint_valid', ['ctrl->pvc_rekey_new_id != 0 &&'], 7, 'F', 'continuity-flag'),
        ('pci_vtdtr_notify_ready', ['sc->vsd_suspended || sc->vsd_rekey_wait ||'], 27, 'T', 'continuity-flag'),
        ('pci_vtdtr_notify_ready', ['VTDTR_DEVICE_NODE_REKEY && !sc->vsd_handoff_ticket_valid) ||'], 33, 'F', 'continuity-flag'),
        # the worker's wait predicate already holds while NEEDS_RESET is set,
        # so the check after the wait never sees it
        ('pci_vtdtr_run', ['if (sc->vsd_stopping)', 'break;', 'if (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET)'],
         7, 'T', 'state-invariant'),
        # checkpoint_state_valid() advanced the same ELF run over the same
        # queue immediately before and returned EPROTO on the first failure;
        # the short-run and unknown-event checks that follow are its own
        # (covered: a closed short run; a queued NODE_ID)
        ('pci_vtdtr_checkpoint_replayable', ['if (!pci_vtdtr_elf_run_advance(&run, entry->ctrl))'], 7, 'T', 'state-invariant'),
        # the second decode pass re-reads bytes the first pass just validated
        ('pci_vtdtr_private_snapshot_stage', ['&candidate.controls[i], meta, vmid, epoch);', 'if (error != 0)'],
         8, 'T', 'state-invariant'),
        ('pci_vtdtr_private_snapshot_stage', ['if (scan.buffer.buf != meta->buffer.buf ||'], 7, 'T', 'state-invariant'),
        ('pci_vtdtr_private_snapshot_stage', ['scan.buffer.buf_rem != meta->buffer.buf_rem) {'], 7, 'T', 'state-invariant'),
    ],
    BHYVE + 'hypertrace.c': [
        (163, 6, 'T', 'clock-total'), (210, 7, 'T', 'clock-total'),
        (428, 6, 'T', 'clock-total'), (534, 6, 'T', 'clock-total'),
        (644, 6, 'T', 'clock-total'), (899, 6, 'T', 'clock-total'),
        (1450, 6, 'T', 'clock-total'), (2762, 6, 'T', 'clock-total'),
        # dtraced_wire_decode_status() rejects revoked/replay > 1 and
        # non-zero reserved bytes
        (2780, 6, 'F', 'decoder-guarantee'), (2781, 6, 'F', 'decoder-guarantee'),
        (2793, 7, 'F', 'decoder-guarantee'),
        (337, 11, 'T', 'random-negligible'),
        # replay manifest calloc (count <= DTRACED_REPLAY_KILL_MAX), ELF frame
        # malloc (<= HT_MAX_FRAME) and atexit registration
        (235, 8, 'T', 'malloc-only'), (564, 7, 'T', 'malloc-only'),
        (371, 6, 'T', 'malloc-only'),
        # init's failure path is taken only before inbound_dirfd is opened;
        # pthread_join of the started connector cannot fail (valid, joinable,
        # not the caller)
        (379, 6, 'T', 'state-invariant'), (2847, 7, 'T', 'state-invariant'),
        (2868, 6, 'T', 'state-invariant'),
        # connector re-checks under the channel lock and the stop flag after
        # an unlocked pass; start_ready re-checks configured after the wait
        (291, 8, 'F', 'race-only'), (301, 8, 'F', 'race-only'),
        (311, 7, 'F', 'race-only'), (450, 25, 'T', 'race-only'),
    ],
    BHYVE + 'migration_precopy.c': [
        (142, 34, 'T', 'validator-implied'),
        # cpu_owned is true in every ACTIVE or FAILED session
        (269, 14, 'F', 'state-invariant'),
        # range validation guarantees at least one bitmap byte; the clamped
        # range and the covered window keep every index inside the bitmap
        (461, 6, 'F', 'state-invariant'), (519, 7, 'T', 'state-invariant'),
        (549, 6, 'T', 'state-invariant'),
    ],
    BHYVE + 'migration_dirty.c': [
        (60, 6, 'T', 'type-bound'),
        # every internal caller passes a bitmap_bytes pointer
        (62, 6, 'F', 'out-pointer'),
        # disable clears owner whenever the phase returns to OFF
        (279, 6, 'F', 'state-invariant'),
        # settle rejects a NULL ticket before the check
        (291, 6, 'T', 'state-invariant'),
    ],
    BHYVE + 'snapshot.c': [
        ('vm_checkpoint', ['if ((handoff_enabled || fresh_session) && !stop_vm) {'],
         7, 'T', 'continuity-flag'),
        ('vm_checkpoint', ['&manifest_tmp) : handoff_enabled ?'], 23, 'T', 'continuity-flag'),
        ('vm_checkpoint', ['if (handoff_enabled || fresh_session) {'], 6, 'T', 'continuity-flag'),
        # --- round 8 item 4: trace-continuity operands outside the marked
        # blocks (handoff_* state is set only under handoff_enabled or a
        # format-4 image, both disabled) ---
        ('vm_checkpoint', ['(!handoff_enabled || handoff_committed))'], 7, 'F', 'continuity-flag'),
        ('vm_checkpoint', ['(!handoff_enabled || handoff_committed))'], 27, 'T', 'continuity-flag'),
        ('vm_checkpoint', ['(!handoff_enabled || handoff_committed))'], 27, 'F', 'continuity-flag'),
        ('vm_checkpoint', ['if (snapshot_session_active && !handoff_unresolved) {'], 33, 'F', 'continuity-flag'),
        ('vm_checkpoint', ['release_fd = hypertrace_handoff_source_release_open(ctx);', '*', '*', '*', '*', '*',
         '*', 'if (error == 0)'], 7, 'F', 'continuity-flag'),
        ('vm_checkpoint', ['exit(BHYVE_EXIT_SUSPEND);', '}', '}', 'if (release_fd >= 0)'], 7, 'T', 'continuity-flag'),
        ('vm_checkpoint', ['!handoff_unresolved && !handoff_committed &&'], 6, 'F', 'continuity-flag'),
        ('vm_checkpoint', ['!handoff_unresolved && !handoff_committed &&'], 29, 'F', 'continuity-flag'),
        ('vm_checkpoint', ['handoff_unresolved || handoff_committed) {'], 6, 'T', 'continuity-flag'),
        ('vm_checkpoint', ['handoff_unresolved || handoff_committed) {'], 28, 'T', 'continuity-flag'),
        ('vm_restore_transaction', ['handoff_required || fresh_session);'], 6, 'T', 'continuity-flag'),
        # --- slice 6 ---
        ('vm_restore_transaction', ['if (error != 0 || ((handoff_required || fresh_session) &&'], 22, 'T', 'continuity-flag'),
        ('load_metadata_fd', ['assert(fd >= 0);'], 2, 'F', 'assert-invariant'),
        # the verified open admitted the member by digest; a parse failure of
        # digest-verified metadata and a decode failure of a digest-verified
        # record cannot be the first failure
        ('load_metadata_fd', ['if (obj == NULL) {'], 6, 'T', 'validator-implied'),
        ('load_hypertrace_transfer_fd', ['if (!S_ISREG(sb.st_mode) || (fresh ?'], 6, 'T', 'validator-implied'),
        ('load_hypertrace_transfer_fd', ['if (!S_ISREG(sb.st_mode) || (fresh ?'], 30, 'T', 'validator-implied'),
        ('load_hypertrace_transfer_fd', ['(uintmax_t)sb.st_size > HYPERTRACE_TRANSFER_MAX_BYTES)'], 6, 'T', 'validator-implied'),
        ('load_hypertrace_transfer_fd', ['error = hypertrace_session_record_decode(bytes, length, &record);', 'if (error != 0)'],
         7, 'T', 'validator-implied'),
        # the kernel-topology and device-topology validators ran first
        ('lookup_check_dev', ['if (size < 0 || (uint64_t)size > SIZE_MAX) {'], 19, 'T', 'arith-bound'),
        ('lookup_dev', ['if (devs == NULL) {'], 6, 'T', 'validator-implied'),
        ('lookup_dev', ['if (ucl_object_type(devs) != UCL_ARRAY) {'], 6, 'T', 'validator-implied'),
        ('lookup_hypertrace_handoff', ['basic = lookup_basic_metadata_object(rstate);', 'if (basic == NULL)'], 6, 'T', 'validator-implied'),
        ('lookup_memsize', ['if (memsize <= 0 || (uint64_t)memsize > SIZE_MAX) {'], 22, 'T', 'arith-bound'),
        ('vm_restore_named_topology', ['if (source_capacity != 0 && source == NULL)'], 6, 'F', 'state-invariant'),
        ('vm_restore_record_layout', ['if (entries == NULL || ucl_object_type(entries) != UCL_ARRAY)'], 7, 'T', 'validator-implied'),
        ('vm_restore_record_layout', ['if (entries == NULL || ucl_object_type(entries) != UCL_ARRAY)'], 26, 'T', 'validator-implied'),
        ('vm_restore_kern_structs', ['if (data == NULL || size == 0) {'], 7, 'T', 'validator-implied'),
        ('vm_restore_kern_structs', ['if (data == NULL || size == 0) {'], 23, 'T', 'validator-implied'),
        # the machine topology digest covers the compatibility fields
        ('vm_restore_compat_hex32', ['if (field == NULL || !ucl_object_tostring_safe(field, &string))'], 6, 'T', 'validator-implied'),
        ('vm_restore_compat_string', ['strlcpy(destination, string, capacity) >= capacity)'], 6, 'T', 'validator-implied'),
        # the production and fake DTrace devices answer EOPNOTSUPP while
        # capturing, so a completed capture never comes with error 0
        ('vm_restore_device_payload_validate_one', ['if (!complete || private_image == NULL || private_length == 0 ||'], 7, 'T', 'state-invariant'),
        ('vm_restore_preflight_internal', ['if (rstate == NULL)'], 6, 'T', 'static-guard'),
        ('hypertrace_private_image_unchanged', ['if (rstate->hypertrace_private_image == NULL ||'], 6, 'T', 'static-guard'),
        ('hypertrace_private_image_unchanged', ['rstate->hypertrace_private_length == 0)'], 6, 'T', 'static-guard'),
        # the fake and the production device restore do not write into the
        # private image between its digest and the check
        ('hypertrace_private_image_unchanged', ['error = timingsafe_bcmp(actual, expected, sizeof(actual)) == 0 ?'], 10, 'F', 'state-invariant'),
        ('vm_restore_transaction', ['EPRINTLN("HyperTrace private image changed before device "', '"restore.");'], 7, 'T', 'state-invariant') if False else
        ('vm_restore_transaction', ['EPRINTLN("Failed to restore VM memory.");', 'goto failed;', '}',
         'if ((handoff_required || fresh_session) &&', 'rstate->hypertrace_private_image != NULL) {',
         'error = hypertrace_private_image_unchanged(rstate,', 'private_digest);', 'if (error != 0) {'], 7, 'T', 'state-invariant'),
        ('vm_restore_transaction', ['EPRINTLN("Failed to restore PCI device state.");', 'goto failed;', '}',
         'if ((handoff_required || fresh_session) &&', 'rstate->hypertrace_private_image != NULL) {',
         'error = hypertrace_private_image_unchanged(rstate,', 'private_digest);', 'if (error != 0) {'], 7, 'T', 'state-invariant'),
        ('vm_migrate_commit_state_impl', ['/* Guest RAM is already present; only devices and kernel structs. */',
         'if (fresh && (error = hypertrace_private_image_unchanged(&rstate,'], 15, 'T', 'state-invariant'),
        ('vm_migrate_commit_state_impl', ['BHYVE_PHASE_DONE(__func__, "vm_restore_devices",', 'error, error < 0 ? errno : 0);',
         'if (error != 0)', 'goto out;', 'if (fresh && (error = hypertrace_private_image_unchanged(&rstate,'], 15, 'T', 'state-invariant'),
        # restore_vm_mem's read failures carry errno (read/lseek set it, a
        # zero-length read sets EIO); covered by the errno-less sweep
        ('vm_snapshot_mem', ['if ((op_wr == false) && (totalmem != memsz)) {'], 26, 'T', 'validator-implied'),
        ('vm_snapshot_devices', ['extra > SIZE_MAX - buf_size) {'], 7, 'T', 'arith-bound'),
        ('checkpoint_restore_startup_hold', ['assert(!checkpoint_active);'], 2, 'F', 'assert-invariant'),
        ('checkpoint_restore_startup_hold', ['assert(!restore_startup_hold);'], 2, 'F', 'assert-invariant'),
        # vm_save_kern_structs returns 0 or a positive errno
        ('vm_checkpoint', ['fprintf(stderr, "Failed to snapshot vm kernel data.\\n");', 'error = ret > 0 ? ret : EIO;'], 11, 'F', 'state-invariant') if False else
        ('vm_checkpoint', ['if (close(fd_meta) != 0 && error == 0)'], 30, 'T', 'state-invariant'),
        ('vm_checkpoint', ['if (close(fd_meta) != 0 && error == 0)', 'error = errno != 0 ? errno : EIO;'], 12, 'T', 'state-invariant'),
        ('vm_checkpoint', ['if (close(fd_meta) != 0 && error == 0)', 'error = errno != 0 ? errno : EIO;'], 12, 'F', 'state-invariant'),
        # the guest memory of this VM has a high segment (the harness and the
        # production geometry both do); vm_snapshot_le* fail only on a short
        # buffer, which the record consumption checks refuse first
        ('vm_snapshot_guest2host_addr', ['(restore_null && (*addrp != NULL))) {'], 9, 'F', 'state-invariant'),
        ('vm_snapshot_guest2host_addr', ['if ((uint64_t)gaddr != wire_gaddr) {'], 7, 'T', 'decoder-guarantee'),
        ('vm_snapshot_guest2host_addr', ['if (vm_snapshot_is_restoring(meta))'], 7, 'F', 'state-invariant'),
        # --- round 8 item 4, slice 6: guards of file-local functions, checks
        # repeated after an earlier validator, and bounds of generated data ---
        # collect_generic_devmem: vm_checkpoint passes ctx and both outputs
        ('collect_generic_devmem', ['if (ctx == NULL || regionsp == NULL || countp == NULL)'], 6, 'T', 'static-guard'),
        ('collect_generic_devmem', ['if (ctx == NULL || regionsp == NULL || countp == NULL)'], 21, 'T', 'static-guard'),
        ('collect_generic_devmem', ['if (ctx == NULL || regionsp == NULL || countp == NULL)'], 41, 'T', 'static-guard'),
        # vm_snapshot_basic_metadata: both callers pass ctx, xop and the guest's
        # memory size (lowmem + highmem, never 0 and far below INT64_MAX)
        ('vm_snapshot_basic_metadata', ['if (ctx == NULL || xop == NULL || memsz == 0 || memsz > INT64_MAX)'], 6, 'T', 'static-guard'),
        ('vm_snapshot_basic_metadata', ['if (ctx == NULL || xop == NULL || memsz == 0 || memsz > INT64_MAX)'], 21, 'T', 'static-guard'),
        ('vm_snapshot_basic_metadata', ['if (ctx == NULL || xop == NULL || memsz == 0 || memsz > INT64_MAX)'], 36, 'T', 'state-invariant'),
        ('vm_snapshot_basic_metadata', ['if (ctx == NULL || xop == NULL || memsz == 0 || memsz > INT64_MAX)'], 50, 'T', 'arith-bound'),
        ('vm_snapshot_basic_metadata', ['return (memsz > INT64_MAX ? EOVERFLOW : EINVAL);'], 11, 'T', 'arith-bound'),
        ('vm_snapshot_basic_metadata', ['return (memsz > INT64_MAX ? EOVERFLOW : EINVAL);'], 11, 'F', 'arith-bound'),
        # the fake and the kernel report a page-aligned geometry; a contract
        # text is produced whenever its capture succeeded
        ('vm_snapshot_basic_metadata', ['error = checkpoint_memory_geometry_validate(&geometry, memsz);', 'if (error == 0)'],
         6, 'F', 'state-invariant'),
        ('vm_snapshot_basic_metadata', ['if (cpu_contract_text != NULL)'], 6, 'F', 'state-invariant'),
        # lookup_hypertrace_handoff: both callers pass a loaded rstate and &required
        ('lookup_hypertrace_handoff', ['if (rstate == NULL || required == NULL || rstate->meta_root_obj == NULL)'], 6, 'T', 'static-guard'),
        ('lookup_hypertrace_handoff', ['if (rstate == NULL || required == NULL || rstate->meta_root_obj == NULL)'], 24, 'T', 'static-guard'),
        ('lookup_hypertrace_handoff', ['if (rstate == NULL || required == NULL || rstate->meta_root_obj == NULL)'], 44, 'T', 'static-guard'),
        # ucl iteration visits exactly ucl_array_size() elements
        ('vm_restore_named_topology', ['if (source_count == source_capacity) {'], 7, 'T', 'state-invariant'),
        ('vm_restore_named_topology', ['if (source_capacity > SIZE_MAX / sizeof(*source))'], 6, 'T', 'arith-bound'),
        ('vm_restore_record_layout', ['if (ucl_array_size(entries) > SIZE_MAX - count)'], 7, 'T', 'arith-bound'),
        ('vm_restore_record_layout', ['if (count > SIZE_MAX / sizeof(*ranges))'], 6, 'T', 'arith-bound'),
        ('vm_restore_record_layout', ['if (index == count) {'], 8, 'T', 'state-invariant'),
        ('vm_restore_record_layout', ['if (index != count)'], 6, 'T', 'state-invariant'),
        # the kernel and device topology validators (named_topology over both
        # arrays, with the destination's names) run before any lookup_dev
        ('vm_restore_record_layout', ['if (count != 0 && ranges == NULL)'], 6, 'F', 'validator-implied'),
        ('lookup_dev_object', ['if (devs == NULL || ucl_object_type(devs) != UCL_ARRAY)'], 6, 'T', 'validator-implied'),
        ('lookup_dev_object', ['if (devs == NULL || ucl_object_type(devs) != UCL_ARRAY)'], 22, 'T', 'validator-implied'),
        ('lookup_dev_object', ['while ((obj = ucl_object_iterate(devs, &it, true)) != NULL) {'], 9, 'F', 'validator-implied'),
        ('lookup_dev_object', ['if (field != NULL && ucl_object_tostring_safe(field, &name) &&'], 7, 'F', 'validator-implied'),
        ('lookup_dev_object', ['if (field != NULL && ucl_object_tostring_safe(field, &name) &&'], 24, 'F', 'validator-implied'),
        ('vm_restore_record_presence', ['if (lookup_dev(snapshot_kern_structs[i].struct_name,'], 7, 'T', 'validator-implied'),
        ('vm_restore_record_presence', ['JSON_KERNEL_ARR_KEY, rstate, &size) == NULL || size == 0)'], 54, 'T', 'validator-implied'),
        ('vm_restore_record_presence', ['if (lookup_dev(pdi->pi_name, JSON_DEV_ARR_KEY, rstate,'], 7, 'T', 'validator-implied'),
        ('vm_restore_record_presence', ['if (lookup_dev(pdi->pi_name, JSON_DEV_ARR_KEY, rstate,', '&size) == NULL || size == 0)'], 25, 'T', 'validator-implied'),
        ('vm_restore_record_presence', ['if (lookup_dev("atkbdc", JSON_DEV_ARR_KEY, rstate, &size) == NULL ||'], 6, 'T', 'validator-implied'),
        ('vm_restore_record_presence', ['if (lookup_dev("atkbdc", JSON_DEV_ARR_KEY, rstate, &size) == NULL ||', 'size == 0)'], 6, 'T', 'validator-implied'),
        ('vm_restore_record_presence', ['(lookup_dev(QEMU_FWCFG_SNAPSHOT_NAME, JSON_DEV_ARR_KEY, rstate,'], 7, 'T', 'validator-implied'),
        ('vm_restore_record_presence', ['(lookup_dev(QEMU_FWCFG_SNAPSHOT_NAME, JSON_DEV_ARR_KEY, rstate,', '&size) == NULL || size == 0))'], 24, 'T', 'validator-implied'),
        # vm_restore_device repeats the lookups and checks of the preflight
        # (presence, basic metadata, compat version and envelope) that ran
        # before the transaction began
        # vm_restore_device asserts the preflight's invariants (cbm-v2i); the
        # false arm of each assert is the abort
        ('vm_restore_device', ['assert(dev_ptr != NULL && dev_size != 0);'], 2, 'F', 'assert-invariant'),
        ('vm_restore_device', ['assert(basic != NULL);'], 2, 'F', 'assert-invariant'),
        ('vm_restore_device', ['assert(field != NULL);'], 2, 'F', 'assert-invariant'),
        ('vm_restore_device', ['assert(version == PCI_SNAPSHOT_COMPAT_SCHEMA);'], 2, 'F', 'assert-invariant'),
        ('vm_restore_device', ['error = checkpoint_compat_decode(dev_ptr, dev_size,', '&compatibility);', 'if (error != 0)'], 8, 'T', 'validator-implied'),
        # payload validation: presence and the caller's version check came
        # first; the compat envelope is covered by the member digest
        ('vm_restore_device_payload_validate_one', ['if (record == NULL || record_size == 0)'], 6, 'T', 'validator-implied'),
        ('vm_restore_device_payload_validate_one', ['if (record == NULL || record_size == 0)'], 24, 'T', 'validator-implied'),
        ('vm_restore_device_payload_validate_one', ['if (version != PCI_SNAPSHOT_COMPAT_SCHEMA)'], 6, 'T', 'validator-implied'),
        ('vm_restore_device_payload_validate_one', ['error = checkpoint_compat_decode(record, record_size,', '&compatibility);', 'if (error != 0)'], 7, 'T', 'validator-implied'),
        ('vm_restore_device_payloads_validate', ['basic = lookup_basic_metadata_object(rstate);', 'if (basic == NULL)'], 6, 'T', 'validator-implied'),
        ('vm_restore_device_payloads_validate', ['if (field == NULL || !ucl_object_toint_safe(field, &version) ||'], 6, 'T', 'validator-implied'),
        ('vm_restore_device_payloads_validate', ['if (field == NULL || !ucl_object_toint_safe(field, &version) ||'], 23, 'T', 'validator-implied'),
        ('vm_restore_device_payloads_validate', ['if (field == NULL || !ucl_object_toint_safe(field, &version) ||', 'version != PCI_SNAPSHOT_COMPAT_SCHEMA)'], 6, 'T', 'validator-implied'),
        ('vm_restore_device_payloads_validate', ['if (phase == PCI_RESTORE_NORMAL)', 'break;', '}', '#ifdef __amd64__', 'if (error == 0) {'], 6, 'F', 'state-invariant'),
        ('vm_restore_device_payloads_validate', ['record = lookup_dev("atkbdc", JSON_DEV_ARR_KEY, rstate,', '&record_size);', 'if (record == NULL || record_size == 0) {'], 7, 'T', 'validator-implied'),
        ('vm_restore_device_payloads_validate', ['record = lookup_dev("atkbdc", JSON_DEV_ARR_KEY, rstate,', '&record_size);', 'if (record == NULL || record_size == 0) {'], 25, 'T', 'validator-implied'),
        ('vm_restore_device_payloads_validate', ['if (error == 0 && qemu_fwcfg_enabled()) {'], 6, 'F', 'state-invariant'),
        ('vm_restore_device_payloads_validate', ['record = lookup_dev(QEMU_FWCFG_SNAPSHOT_NAME, JSON_DEV_ARR_KEY,', 'rstate, &record_size);', 'if (record == NULL || record_size == 0) {'], 7, 'T', 'validator-implied'),
        ('vm_restore_device_payloads_validate', ['record = lookup_dev(QEMU_FWCFG_SNAPSHOT_NAME, JSON_DEV_ARR_KEY,', 'rstate, &record_size);', 'if (record == NULL || record_size == 0) {'], 25, 'T', 'validator-implied'),
        ('vm_restore_device_compatibility', ['basic = lookup_basic_metadata_object(rstate);', 'if (basic == NULL)'], 6, 'T', 'validator-implied'),
        ('vm_restore_device_compatibility', ['object = lookup_dev_object(pdi->pi_name, JSON_DEV_ARR_KEY,', 'rstate);', 'if (object == NULL)'], 7, 'T', 'validator-implied'),
        ('vm_restore_device_compatibility', ['if (record == NULL)'], 8, 'T', 'validator-implied'),
        # the member digest covers the whole record; the payload CRC is
        # defence in depth behind it
        ('vm_restore_device_compatibility', ['payload.payload_crc32 != checkpoint_compat_payload_crc32('], 7, 'T', 'state-invariant'),
        ('vm_restore_machine_topology_digest', ['basic = lookup_basic_metadata_object(rstate);', 'if (basic == NULL)'], 6, 'T', 'validator-implied'),
        # the destination always has at least one device (atkbdc); the index
        # equals the count by construction
        ('vm_restore_device_topology', ['if (destination_count > SIZE_MAX / sizeof(*destination))'], 6, 'T', 'arith-bound'),
        ('vm_restore_device_topology', ['if (destination_count != 0 && destination == NULL)'], 6, 'F', 'state-invariant'),
        ('vm_machine_topology_digest_current', ['if (count != 0 && (devices == NULL || compats == NULL)) {'], 6, 'F', 'state-invariant'),
        ('vm_machine_topology_digest_current', ['if (index != count) {'], 6, 'T', 'state-invariant'),
        ('vm_machine_topology_digest_source', ['if (count != 0 && (devices == NULL || compats == NULL)) {'], 6, 'F', 'state-invariant'),
        ('vm_machine_topology_digest_source', ['if (index != count) {'], 6, 'T', 'state-invariant'),
        # the verified open admitted only regular members; generated members
        # are never empty; the descriptor parameter is non-negative
        ('load_vmmem_fd', ['assert(fd >= 0);'], 2, 'F', 'assert-invariant'),
        ('load_kdata_fd', ['assert(fd >= 0);'], 2, 'F', 'assert-invariant'),
        ('load_vmmem_fd', ['if (!S_ISREG(sb.st_mode)) {'], 6, 'T', 'validator-implied'),
        ('load_kdata_fd', ['if (!S_ISREG(sb.st_mode)) {'], 6, 'T', 'validator-implied'),
        ('load_vmmem_fd', ['if (sb.st_size <= 0 || (uintmax_t)sb.st_size > SIZE_MAX) {'], 6, 'T', 'state-invariant'),
        ('load_vmmem_fd', ['if (sb.st_size <= 0 || (uintmax_t)sb.st_size > SIZE_MAX) {'], 25, 'T', 'arith-bound'),
        ('load_kdata_fd', ['if (sb.st_size <= 0 || (uintmax_t)sb.st_size > SIZE_MAX) {'], 6, 'T', 'state-invariant'),
        ('load_kdata_fd', ['if (sb.st_size <= 0 || (uintmax_t)sb.st_size > SIZE_MAX) {'], 25, 'T', 'arith-bound'),
        ('load_vmmem_fd', ['if (rstate->vmmem_fd >= 0)'], 6, 'F', 'state-invariant'),
        ('load_kdata_fd', ['if (rstate->kdata_fd >= 0)'], 6, 'F', 'state-invariant'),
        ('load_restore_file', ['assert(filename != NULL);'], 2, 'F', 'assert-invariant'),
        ('load_restore_file', ['assert(rstate != NULL);'], 2, 'F', 'assert-invariant'),
        ('load_restore_file', ['"checkpoint transfer member.\\n");', 'goto err_restore;', '}', '*', 'free(base_copy);',
         'free(lock_filename);', 'free(manifest_directory_copy);', 'if (manifest_dirfd >= 0)'], 6, 'F', 'state-invariant'),
        # handoff identity fails only on digests the verified open already
        # validated or on snprintf/SHA256 over in-memory data
        ('load_restore_file', ['&manifest, rstate->handoff_token, rstate->handoff_digest);', 'if (err != 0) {'], 6, 'T', 'validator-implied'),
        # restore_vm_mem repeats vm_restore_memory_preflight's checks
        ('restore_vm_mem', ['if (memsize == 0 || memsize > INT64_MAX ||'], 6, 'T', 'validator-implied'),
        ('restore_vm_mem', ['if (memsize == 0 || memsize > INT64_MAX ||'], 22, 'T', 'validator-implied'),
        ('restore_vm_mem', ['if (memsize == 0 || memsize > INT64_MAX ||', 'rstate->vmmem_len < memsize) {'], 6, 'T', 'validator-implied'),
        ('vm_restore_memory_preflight', ['if (memsize == 0 || memsize > INT64_MAX ||'], 22, 'T', 'arith-bound'),
        # ".lock" is a literal shorter than NAME_MAX
        ('strcat_extension', ['if (base_len == NAME_MAX || ext_len == NAME_MAX ||'], 30, 'T', 'constant-condition'),
        # snprintf of two bounded doubles into an 8 KiB buffer
        ('print_progress', ['rc = snprintf(prog_buf, len, "%.03lf", maxval_gb);', 'if (rc < 0 || (size_t)rc >= len) {'], 6, 'T', 'libc-total'),
        ('print_progress', ['rc = snprintf(prog_buf, len, "%.03lf", maxval_gb);', 'if (rc < 0 || (size_t)rc >= len) {'], 16, 'T', 'arith-bound'),
        ('print_progress', ['mval_len, crtval_gb, div_str, maxval_gb, div_str);', '*', 'if (rc < 0 || (size_t)rc >= len) {'], 6, 'T', 'libc-total'),
        ('print_progress', ['mval_len, crtval_gb, div_str, maxval_gb, div_str);', '*', 'if (rc < 0 || (size_t)rc >= len) {'], 16, 'T', 'arith-bound'),
        # the compat envelope is reserved in the snapshot buffer before the
        # device writes, and that buffer always holds the envelope
        ('vm_snapshot_device', ['if (data_size < CHECKPOINT_COMPAT_ENVELOPE_SIZE)'], 7, 'T', 'state-invariant'),
        ('vm_snapshot_device', ['ret = checkpoint_compat_encode(&compat,', 'meta->buffer.buf_start, meta->buffer.buf_size);', 'if (ret != 0)'], 7, 'T', 'state-invariant'),
        # the serializers return 0 or a positive errno
        ('vm_checkpoint', ['fprintf(stderr, "Failed to snapshot vm kernel data.\\n");', 'error = ret > 0 ? ret : EIO;'], 11, 'F', 'state-invariant'),
        # a capture always has metadata and kernel data; the sizes come from
        # files this process just wrote
        ('vm_snapshot_dev_state_capture', ['if ((uintmax_t)kdata_size > SSIZE_MAX ||'], 6, 'T', 'arith-bound'),
        ('vm_snapshot_dev_state_capture', ['meta_len > SIZE_MAX - MIGRATE_BLOB_HDR - trace_len ||'], 6, 'T', 'arith-bound'),
        ('vm_snapshot_dev_state_capture', ['kdata_len > SIZE_MAX - MIGRATE_BLOB_HDR - trace_len - meta_len) {'], 6, 'T', 'arith-bound'),
        ('vm_snapshot_dev_state_capture', ['meta_buf = malloc(meta_len != 0 ? meta_len : 1);'], 20, 'F', 'state-invariant'),
        ('vm_snapshot_dev_state_capture', ['kdata_buf = malloc(kdata_len != 0 ? kdata_len : 1);'], 21, 'F', 'state-invariant'),
        ('vm_snapshot_dev_state_capture', ['if (meta_len != 0 && fread(meta_buf, 1, meta_len, meta_file) != meta_len) {'], 6, 'F', 'state-invariant'),
        ('vm_snapshot_dev_state_capture', ['if (kdata_len != 0 &&'], 6, 'F', 'state-invariant'),
        # the private image and its device are recorded together; the fake
        # and the production device restores never write the private image
        # between its digest and the check; a successful release reports
        # released
        ('vm_migrate_commit_state_impl', ['rstate.hypertrace_private_image == NULL) {'], 7, 'T', 'state-invariant'),
        ('vm_migrate_commit_state_impl', ['rel = vm_snapshot_session_release_exact(ctx, &session, true, &released);', '*', '*', 'if (released)'],
         6, 'F', 'state-invariant'),
        # the `x < 0 ? errno : 0` argument of BHYVE_PHASE_DONE where the
        # callee returns 0 or a positive errno: vm_pause/resume_devices,
        # the exact session helpers, the preflights, vm_save_kern_structs,
        # vm_snapshot_devices, vm_restore_devices_prevalidated,
        # vm_restore_kern_structs, checkpoint_restore_startup_release and the
        # pe_snapshot callbacks (bhyve's device contract); vm_snapshot_req
        # returns -1/errno and is covered
        ('restore_vm_mem', ['BHYVE_PHASE_DONE(__func__, "vm_restore_memory_preflight",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_restore_device', ['BHYVE_PHASE_DONE(__func__, name, ret,'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_restore_transaction', ['BHYVE_PHASE_DONE(__func__, "vm_pause_devices",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_restore_transaction', ['BHYVE_PHASE_DONE(__func__, "vm_restore_preflight",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_restore_transaction', ['BHYVE_PHASE_DONE(__func__, "vm_restore_memory_preflight",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_restore_transaction', ['BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_begin_exact",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_restore_transaction', ['BHYVE_PHASE_DONE(__func__, "vm_restore_devices",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_restore_transaction', ['BHYVE_PHASE_DONE(__func__, "vm_restore_kern_structs",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_restore_transaction', ['release_error = vm_snapshot_session_release_exact(ctx, &session, true,', '*',
         'BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_release_exact",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_restore_transaction', ['BHYVE_PHASE_DONE(__func__, "vm_resume_devices",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_restore_transaction', ['BHYVE_PHASE_DONE(__func__, "checkpoint_restore_startup_release",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_restore_transaction', ['false, &released);',
         'BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_release_exact",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_snapshot_device', ['BHYVE_PHASE_DONE(__func__, dev_name, ret, ret < 0 ? errno : 0);'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_checkpoint', ['BHYVE_PHASE_DONE(__func__, "vm_pause_devices",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_checkpoint', ['BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_begin_exact",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_checkpoint', ['BHYVE_PHASE_DONE(__func__, "vm_save_kern_structs",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_checkpoint', ['BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_release_exact",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_checkpoint', ['BHYVE_PHASE_DONE(__func__, "vm_resume_devices",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_snapshot_dev_state_capture', ['BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_begin_exact",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_snapshot_dev_state_capture', ['BHYVE_PHASE_DONE(__func__, "vm_save_kern_structs",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_snapshot_dev_state_capture', ['BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_release_exact",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_migrate_commit_state_impl', ['BHYVE_PHASE_DONE(__func__, "vm_pause_devices",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_migrate_commit_state_impl', ['BHYVE_PHASE_DONE(__func__, "vm_restore_preflight",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_migrate_commit_state_impl', ['BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_begin_exact",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_migrate_commit_state_impl', ['BHYVE_PHASE_DONE(__func__, "vm_restore_devices",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_migrate_commit_state_impl', ['BHYVE_PHASE_DONE(__func__, "vm_restore_kern_structs",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_migrate_commit_state_impl', ['BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_release_exact",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_migrate_resume', ['BHYVE_PHASE_DONE(__func__, "vm_resume_devices",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_migrate_resume', ['BHYVE_PHASE_DONE(__func__, "checkpoint_restore_startup_release",'], ('nested', 527, 61), 'T', 'state-invariant'),
        ('vm_restore_transaction', ['strerror(error));', 'goto failed;', '}', '}',
         'if ((handoff_required || fresh_session) &&'], 7, 'T', 'continuity-flag'),
        ('vm_restore_transaction', ['EPRINTLN("Failed to restore VM memory.");', 'goto failed;', '}',
         'if ((handoff_required || fresh_session) &&'], 7, 'T', 'continuity-flag'),
        ('vm_restore_transaction', ['EPRINTLN("Failed to restore PCI device state.");', 'goto failed;', '}',
         'if ((handoff_required || fresh_session) &&'], 7, 'T', 'continuity-flag'),
        ('vm_restore_transaction', ['release_error = hypertrace_restore_cancel_if_safe(ctx, rstate,',
         'handoff_reserved, handoff_mutating, handoff_claimed);', 'if (release_error != 0) {'], 6, 'T', 'continuity-flag'),
        ('hypertrace_restore_cancel_if_safe', ['if (!reserved || mutating || claimed)'], 6, 'F', 'continuity-flag'),
        ('hypertrace_restore_cancel_if_safe', ['if (!reserved || mutating || claimed)'], 19, 'T', 'continuity-flag'),
        ('hypertrace_restore_cancel_if_safe', ['if (!reserved || mutating || claimed)'], 19, 'F', 'continuity-flag'),
        ('hypertrace_restore_cancel_if_safe', ['if (!reserved || mutating || claimed)'], 31, 'T', 'continuity-flag'),
        ('hypertrace_restore_cancel_if_safe', ['if (!reserved || mutating || claimed)'], 31, 'F', 'continuity-flag'),
        ('hypertrace_restore_cancel_if_safe', ['if (hypertrace_handoff_destination_ensure(ctx, DTRACED_HANDOFF_CANCEL,'],
         6, 'T', 'continuity-flag'),
        ('hypertrace_restore_cancel_if_safe', ['if (hypertrace_handoff_destination_ensure(ctx, DTRACED_HANDOFF_CANCEL,'],
         6, 'F', 'continuity-flag'),
        ('hypertrace_restore_cancel_if_safe', ['rstate->handoff_token, rstate->handoff_digest) != 0)',
         'return (errno != 0 ? errno : EIO);'], 11, 'T', 'continuity-flag'),
        ('hypertrace_restore_cancel_if_safe', ['rstate->handoff_token, rstate->handoff_digest) != 0)',
         'return (errno != 0 ? errno : EIO);'], 11, 'F', 'continuity-flag'),
        # the transfer member of a format-4 (continuity) image
        ('load_hypertrace_transfer_fd', ['if (!S_ISREG(sb.st_mode) || (fresh ?'], 31, 'F', 'continuity-flag'),
        ('load_hypertrace_transfer_fd', ['if (fresh) {'], 6, 'F', 'continuity-flag'),
        ('load_hypertrace_transfer_fd', ['if (hypertrace_transfer_inspect(bytes, length, token,'], 6, 'T', 'continuity-flag'),
        ('load_hypertrace_transfer_fd', ['if (hypertrace_transfer_inspect(bytes, length, token,'], 6, 'F', 'continuity-flag'),
        ('load_hypertrace_transfer_fd', ['&has_transfer_state) != 0) {', 'error = errno != 0 ? errno : EIO;'],
         11, 'T', 'continuity-flag'),
        ('load_hypertrace_transfer_fd', ['&has_transfer_state) != 0) {', 'error = errno != 0 ? errno : EIO;'],
         11, 'F', 'continuity-flag'),
        # SHA256_Data over an in-memory buffer with a caller-provided output
        ('load_hypertrace_transfer_fd', ['if (SHA256_Data(bytes, length, actual_digest) == NULL ||'], 6, 'T', 'libc-total'),
        # checkpoint_manifest_open_verified_trace_at compared the same digest
        # over the same descriptor immediately before
        ('load_hypertrace_transfer_fd', ['strcmp(actual_digest, expected_digest) != 0) {'], 6, 'T', 'state-invariant'),
        ('load_restore_file', ['if (rstate->hypertrace_release_present &&'], 6, 'T', 'continuity-flag'),
        ('load_restore_file', ['hypertrace_release_transfer_inspect(rstate->hypertrace_release,'], 6, 'T', 'continuity-flag'),
        ('load_restore_file', ['hypertrace_release_transfer_inspect(rstate->hypertrace_release,'], 6, 'F', 'continuity-flag'),
        # read_at reports a non-manifest only with an error (every unknown
        # file shape is EINVAL in checkpoint_manifest_read_fd)
        ('load_restore_file', ['if (!exists || !is_manifest) {'], 17, 'T', 'state-invariant'),
        # the success path closed nothing yet; manifest_data_fd is cleared
        # right after its only consumer, before any later failure
        ('load_restore_file', ['close(manifest_dirfd);', 'if (manifest_data_fd >= 0)'], 6, 'T', 'state-invariant'),
        # checkpoint_remove_old_generation: format 4 never exists
        ('checkpoint_remove_old_generation', ['i < (old->format_version == 4 || old->format_version == 5 ?'],
         11, 'T', 'continuity-flag'),
        ('checkpoint_remove_old_generation', ['if (old->format_version == 4 &&'], 6, 'T', 'continuity-flag'),
        ('checkpoint_remove_old_generation', ['checkpoint_manifest_handoff_token(checkpoint_file, old, token) == 0) {'],
         6, 'T', 'continuity-flag'),
        ('checkpoint_remove_old_generation', ['checkpoint_manifest_handoff_token(checkpoint_file, old, token) == 0) {'],
         6, 'F', 'continuity-flag'),
        ('checkpoint_remove_old_generation', ['int release_error = checkpoint_release_remove_at(fddir, token);',
         'if (release_error != 0)'], 7, 'T', 'continuity-flag'),
        ('checkpoint_remove_old_generation', ['int release_error = checkpoint_release_remove_at(fddir, token);',
         'if (release_error != 0)'], 7, 'F', 'continuity-flag'),
        # lookup_hypertrace_handoff already refused a fresh image without a
        # session record (EPROTO) and one marked handoff-required
        ('vm_restore_transaction', ['if (fresh_session && (!rstate->hypertrace_session_present ||'], 24, 'T', 'state-invariant'),
        ('vm_restore_transaction', ['handoff_required || rstate->hypertrace_transfer != NULL ||'], 6, 'T', 'state-invariant'),
        # a private device is captured only for a fresh image, so the legacy
        # side of this test never sees one
        ('vm_restore_transaction', ['(fresh_session || rstate->hypertrace_private_dev == NULL)) {'], 24, 'F', 'state-invariant'),
        # every goto failed carries a non-zero error
        ('vm_restore_transaction', ['EPRINTLN("Could not abort kernel restore session: %s",', 'strerror(release_error));',
         'if (error == 0)'], 8, 'T', 'state-invariant'),
        ('vm_restore_transaction', ['BHYVE_TRACE(RESTORE_RESULT, error != 0 ? error : EIO);', 'return (error != 0 ? error : EIO);'],
         10, 'F', 'state-invariant'),
    ],
    BHYVE + 'ipc.c': [
        ('init_ipc_thread', ['if (ret < 0 || (size_t)ret >= sizeof(addr.sun_path)) {'],
         6, 'T', 'libc-total'),
    ],
    BHYVE + 'gdb.c': [
        ('gdb_write_mem', ['assert(len >= 1);'], 2, 'F', 'assert-invariant'),
        ('gdb_write_mem', ['assert(len >= 2);'], 5, 'F', 'assert-invariant'),
        ('gdb_write_mem', ['assert(resid == 0 || gpa % getpagesize() == 0);'], 3, 'F',
         'assert-invariant'),
        ('gdb_write_mem', ['assert(len == 0);'], 2, 'F', 'assert-invariant'),
        # nested: the macro branch at queue.h line 918 inside this site
        ('remove_all_sw_breakpoints', ['TAILQ_FOREACH_SAFE(bp, &breakpoints, link, nbp) {'],
         ('nested', 918, 15), 'F', 'constant-condition'),
    ],
    BHYVE + 'bhyverun.c': [
        ('vm_loop', ['assert(CPU_ISSET(vcpu_id(vcpu), &active_cpus));'], 2, 'F',
         'assert-invariant'),
        # the hold is re-read under the mutex; it can only have dropped in the
        # window between the unlocked fast-path read and the lock
        ('fbsdrun_migration_cpu_point',
         ['if (atomic_load_explicit(&migration_cpu_hold, memory_order_relaxed)) {'],
         6, 'F', 'race-only'),
        ('bhyve_numa_restore_apply', ['if (replacement == NULL)'], 6, 'T', 'malloc-only'),
    ],
}
# Components (and scoped views) whose outcome-waived figures are reported.
OUTCOME_COMPONENTS = ['bhyve-migration', 'bhyve-hypertrace', 'bhyve-snapshot']
OUTCOME_SCOPES = ['bhyve-control-scoped']

HEADER_PATTERNS = {
    'bhyve-migration-headers': re.compile(r'usr\.sbin/bhyve/migration_[^/]*\.h$'),
    'bhyve-hypertrace-headers': re.compile(r'usr\.sbin/bhyve/hypertrace[^/]*\.h$'),
}


def die(message):
    raise SystemExit(message)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def new_output(path):
    path = Path(path).resolve()
    if not path.is_relative_to('/usr/obj'):
        die('Use an isolated directory under /usr/obj')
    if path.exists():
        die('Output must be new; mixing stale counters invalidates evidence')
    path.mkdir(parents=True)
    return path


def wrappers(directory):
    directory.mkdir()
    tools = {}
    for compiler in ('cc', 'c++', 'clang', 'clang++'):
        binary = Path('/usr/bin') / compiler
        tools[compiler] = subprocess.check_output(
            [str(binary), '--version'], text=True).splitlines()[0]
        wrapper = directory / compiler
        # Links get a build ID so every raw profile names its binary.
        wrapper.write_text(
            '#!/bin/sh\nlink=1\nfor a in "$@"; do case "$a" in -c|-S|-E|-M|-MM) link=0;; esac; done\n'
            'if [ $link = 1 ]; then exec %s %s "$@" -Wl,--build-id=sha1; fi\n'
            'exec %s %s "$@"\n' % (binary, ' '.join(FLAGS), binary, ' '.join(FLAGS)))
        wrapper.chmod(0o755)
    return tools


def git_head():
    return subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                                   text=True).strip()


# ------------------------------------------------- coverage mapping reader
# Minimal reader of the LLVM coverage sections (__llvm_covfun, __llvm_covmap,
# __llvm_prf_names) so every function record can be bound to its source file
# and structural hash.  Used only for attribution; llvm-cov computes metrics.

def elf_sections(data):
    """Yield (name, bytes) for every section of an ELF64 little-endian object."""
    assert data[:4] == b'\x7fELF' and data[4] == 2 and data[5] == 1
    shoff, = struct.unpack_from('<Q', data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    heads = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize)
             for i in range(shnum)]
    strtab = heads[shstrndx]
    names = data[strtab[4]:strtab[4] + strtab[5]]
    for h in heads:
        name = names[h[0]:names.index(b'\0', h[0])].decode()
        if h[1] == 8:      # SHT_NOBITS
            yield name, b''
        else:
            yield name, data[h[4]:h[4] + h[5]]

def uleb(buf, pos):
    result = shift = 0
    while True:
        b = buf[pos]; pos += 1
        result |= (b & 0x7f) << shift; shift += 7
        if not b & 0x80:
            return result, pos

def md5_64(text):
    return struct.unpack('<Q', hashlib.md5(text).digest()[:8])[0]

def parse_names(blob):
    names = []
    pos = 0
    while pos < len(blob):
        if blob[pos] == 0:       # padding
            pos += 1; continue
        ulen, pos = uleb(blob, pos)
        clen, pos = uleb(blob, pos)
        if clen:
            raw = zlib.decompress(blob[pos:pos + clen]); pos += clen
        else:
            raw = blob[pos:pos + ulen]; pos += ulen
        names += raw.split(b'\x01')
    return names

def parse_filenames(blob, version):
    count, pos = uleb(blob, 0)
    ulen, pos = uleb(blob, pos)
    clen, pos = uleb(blob, pos)
    raw = zlib.decompress(blob[pos:pos + clen]) if clen else blob[pos:pos + ulen]
    files = []
    p = 0
    for _ in range(count):
        n, p = uleb(raw, p)
        files.append(raw[p:p + n].decode()); p += n
    if version >= 5 and files:     # Version6+: first entry is the compilation dir
        base = files[0]
        files = [base] + [f if f.startswith('/') or not base else base + '/' + f
                          for f in files[1:]]
    return files

def own_file_regions(body, p, nfiles):
    """Digest of the function's regions in its own file (file id 0).

    Code, gap, skipped and branch regions are kept with exact source extents
    and canonical counter expressions.  Expansion regions and regions inside
    expanded files are dropped: they depend on which header defines a macro
    (for example NULL from the source tree versus a system header) but not on
    the function's own code.  Callers also require equal structural hashes,
    which cover control flow contributed by macros."""
    nexpr, p = uleb(body, p)
    raw = []
    for _ in range(nexpr):
        lhs, p = uleb(body, p)
        rhs, p = uleb(body, p)
        raw.append((lhs, rhs))

    def counter(value, depth=0):
        tag, index = value & 3, value >> 2
        if tag == 0:
            return '0'
        if tag == 1:
            return 'c%d' % index
        if depth > 64 or index >= len(raw):
            return '?'
        op = '-' if tag == 2 else '+'
        return '(%s%s%s)' % (counter(raw[index][0], depth + 1), op,
                             counter(raw[index][1], depth + 1))

    regions = []
    for file_id in range(nfiles):
        count, p = uleb(body, p)
        previous = 0
        for _ in range(count):
            header, p = uleb(body, p)
            kind, detail = None, None
            if header & 3:
                kind, detail = 'code', counter(header)
            elif header & 4:
                kind = 'expansion'
            else:
                k = header >> 3
                if k == 0:
                    kind, detail = 'code', '0'
                elif k == 2:
                    kind = 'skipped'
                elif k == 4:
                    t, p = uleb(body, p)
                    f, p = uleb(body, p)
                    kind, detail = 'branch', (counter(t), counter(f))
                else:
                    # MC/DC regions are not produced by these builds.
                    return 'unsupported-region-kind-%d' % k
            dline, p = uleb(body, p)
            col, p = uleb(body, p)
            dlines, p = uleb(body, p)
            colend, p = uleb(body, p)
            start = previous + dline
            previous = start
            if file_id != 0 or kind == 'expansion':
                continue
            if kind in ('code', 'branch') and dlines == 0 and col == colend:
                # A macro from a system header leaves empty code/branch
                # regions at the use site where a source-tree header leaves an
                # expansion (e.g. NULL, __predict_true).
                continue
            if kind == 'code' and colend & 0x80000000:
                kind = 'gap'
            regions.append((kind, detail, start, col, start + dlines, colend & 0x7fffffff))
    return hashlib.sha256(repr(regions).encode()).hexdigest()


def build_id(path):
    """GNU build ID of an ELF file as lowercase hex, or None."""
    try:
        data = Path(path).read_bytes()
        sections = dict(elf_sections(data))
    except (OSError, AssertionError):
        return None
    note = sections.get('.note.gnu.build-id')
    if not note or len(note) < 16:
        return None
    namesz, descsz, kind = struct.unpack_from('<III', note, 0)
    offset = 12 + ((namesz + 3) & ~3)
    return note[offset:offset + descsz].hex() if kind == 3 else None


def profile_binary_ids(raw):
    text = subprocess.run(['llvm-profdata', 'show', '--binary-ids', str(raw)],
                          capture_output=True, text=True).stdout
    lines = text.splitlines()
    if 'Binary IDs: ' not in [l.rstrip() + ' ' for l in lines] and \
            not any(l.startswith('Binary IDs:') for l in lines):
        return []
    index = next(i for i, l in enumerate(lines) if l.startswith('Binary IDs:'))
    return [l.strip() for l in lines[index + 1:] if re.fullmatch(r'[0-9a-f]+', l.strip())]


def coverage_functions(path):
    """Return list of dicts: name, hash, files (function file ids), main file."""
    data = Path(path).read_bytes()
    covfun = b''; covmap = b''; names = []
    for name, blob in elf_sections(data):
        if name == '__llvm_covfun':
            covfun += blob + b'\0' * (-len(blob) % 8)
        elif name == '__llvm_covmap':
            covmap += blob + b'\0' * (-len(blob) % 8)
        elif name in ('__llvm_prf_names',):
            names += parse_names(blob)
    tables = {}
    pos = 0
    while pos + 16 <= len(covmap):
        _, fsize, _, version = struct.unpack_from('<IIII', covmap, pos)
        pos += 16
        blob = covmap[pos:pos + fsize]
        tables[md5_64(blob)] = parse_filenames(blob, version)
        pos += fsize
        pos += -pos % 8
    byref = {md5_64(n): n.decode() for n in names}
    result = []
    pos = 0
    while pos + 28 <= len(covfun):
        nameref, size, fhash, fref = struct.unpack_from('<QIQQ', covfun, pos)
        if nameref == 0 and size == 0:
            pos += 8; continue
        body = covfun[pos + 28:pos + 28 + size]
        pos += 28 + size
        pos += -pos % 8
        nfiles, p = uleb(body, 0)
        ids = []
        for _ in range(nfiles):
            i, p = uleb(body, p); ids.append(i)
        table = tables.get(fref, [])
        files = [table[i] if i < len(table) else None for i in ids]
        result.append({'name': byref.get(nameref), 'nameref': nameref,
                       'hash': fhash, 'files': files,
                       'file': files[0] if files else None,
                       'mapping': own_file_regions(body, p, len(ids))})
    return result


# ---------------------------------------------------------------- build phase

BUILD_STEPS = ['lib/libnv', 'lib/libvmmapi', 'lib/lib9p', 'lib/libuvmem',
               'usr.sbin/bhyve', 'usr.sbin/bhyvectl']


def make_command(build):
    return ['make', '-j%d' % JOBS, '-m', str(ROOT / 'share/mk'),
            'SRCTOP=%s' % ROOT, 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
            'MK_BHYVE_SNAPSHOT=yes', 'MK_TESTS=no']


def build_env(build):
    env = dict(os.environ)
    env.pop('CXXFLAGS', None)
    env['MAKEOBJDIRPREFIX'] = str(build)
    env['PATH'] = str(build / 'bin') + os.pathsep + \
        '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'
    env['CFLAGS'] = '-O2 -pipe -fno-common -I%s' % (build / 'source-includes')
    return env


def objdir(build, step):
    env = build_env(build)
    return Path(subprocess.check_output(
        make_command(build) + ['-C', str(ROOT / step), '-V', '.OBJDIR'],
        env=env, text=True).strip())


def phase_build(args):
    out = new_output(args.output)
    tools = wrappers(out / 'bin')
    includes = out / 'source-includes'
    includes.mkdir()
    (includes / 'machine').symlink_to(ROOT / 'sys/amd64/include')
    (includes / 'x86').symlink_to(ROOT / 'sys/x86/include')
    env = build_env(out)
    results = []
    for step in BUILD_STEPS:
        log = out / (step.replace('/', '-') + '.log')
        command = make_command(out) + ['-C', str(ROOT / step), 'all']
        with log.open('w') as handle:
            status = subprocess.run(command, env=env, stdout=handle,
                                    stderr=subprocess.STDOUT).returncode
        entry = {'step': step, 'status': status, 'command': command,
                 'log': str(log)}
        if status and step == 'usr.sbin/bhyve':
            # The coverage denominators are the objects.  The installed
            # dtrace -G emits an executable-stack note for the provider
            # object, which lld refuses at the final link; record that and
            # continue only if every object of the program was compiled.
            wanted = subprocess.check_output(
                make_command(out) + ['-C', str(ROOT / step), '-V', '${OBJS}'],
                env=env, text=True).split()
            directory = objdir(out, step)
            missing = [o for o in wanted if not (directory / o).is_file()]
            text = log.read_text(errors='replace')
            if not missing and 'requires an executable stack' in text:
                entry.update(status=0, link_status=status,
                             link_note='final bhyve link refused: dtrace -G provider '
                                       'object carries an executable-stack note; '
                                       'all %d objects compiled' % len(wanted))
        results.append(entry)
        status = entry['status']
        print(step, status, flush=True)
        if status:
            break
    objects = {}
    if all(r['status'] == 0 for r in results):
        for step in ('usr.sbin/bhyve', 'usr.sbin/bhyvectl', 'lib/libvmmapi'):
            directory = objdir(out, step)
            objects[step] = str(directory)
    flags = {}
    for step in ('usr.sbin/bhyve', 'usr.sbin/bhyvectl', 'lib/libvmmapi'):
        query = make_command(out) + ['-C', str(ROOT / step),
                                     '-V', '${CFLAGS}', '-V', '${CPPFLAGS}']
        flags[step] = subprocess.check_output(query, env=env, text=True)
    sources = {}
    for files in COMPONENTS.values():
        for name in files or ():
            sources[name] = sha256(ROOT / name)
    for path in sorted((ROOT / 'usr.sbin/bhyve').glob('migration_*.h')) + \
            sorted((ROOT / 'usr.sbin/bhyve').glob('hypertrace*.h')):
        sources[str(path.relative_to(ROOT))] = sha256(path)
    binaries = {}
    for step, directory in objects.items():
        for path in sorted(Path(directory).iterdir()):
            if path.suffix in ('.o', '.pieo', '.pico', '.a', '.so') or path.name in (
                    'bhyve', 'bhyvectl') or re.search(r'\.so\.\d+$', path.name):
                if path.is_file():
                    binaries[str(path)] = sha256(path)
    status = 0 if results and all(r['status'] == 0 for r in results) else 1
    record = {'phase': 'build', 'status': status, 'steps': results,
              'objdirs': objects, 'make_flags': flags, 'tools': tools,
              'coverage_flags': FLAGS, 'head': git_head(),
              'configuration': 'amd64, MK_BHYVE_SNAPSHOT=yes, maintained Makefiles, -O2',
              'source_sha256': sources, 'binary_sha256': binaries,
              'executed': False}
    (out / 'build.json').write_text(json.dumps(record, indent=2) + '\n')
    print('PASS' if status == 0 else 'FAIL', 'build', out)
    raise SystemExit(status)


# ------------------------------------------------------------------ run phase

# Existing single-output drivers (python3.12 DRIVER OUT).
DRIVER_SUITES = [
    'migration-session-core', 'migration-tls', 'migration-receiver',
    'migration-recovery-exchange', 'migration-recovery', 'migration-dest-image',
    'migration-dest-reconstruct', 'migration-credentials',
    'migration-cpu-barrier', 'migration-fresh-destination',
    'migration-fresh-preflight', 'migration-fresh-source',
    'migration-ipc-quarantine', 'migration-journal-adapter',
    'migration-production-binding', 'migration-production-retire',
    'migration-recover-cli', 'migration-restart-command',
    'migration-retained-owner', 'migration-rollback-repair',
    'migration-source-admission', 'migration-source-control',
    'migration-source-intent', 'migration-source-storage',
    'gdb-migration-fence', 'ipc-startup', 'retire-acpi', 'retire-console',
    'retire-cpus', 'retire-transport', 'fresh-session-restore',
    'fresh-session-checkpoint-stop', 'fresh-session-load',
    'restore-handoff-preflight', 'restore-private-image',
    'hypertrace-epoch-query', 'vmmapi-open', 'arch-snapshot-codec',
    # Item 2/4 production fixtures (ordinary handoff journal, operator CLI).
    'migration-handoff-production', 'migration-resolve-cli',
]
# Drivers that need the instrumented production build as an argument.
BUILD_SUITES = {
    'migration-cli-ipc': lambda b: [objdir_of(b, 'usr.sbin/bhyvectl') / 'bhyvectl'],
    # Round 8: the operator's journal printer through the production bhyvectl.
    'bhyvectl-journal': lambda b: [objdir_of(b, 'usr.sbin/bhyvectl') / 'bhyvectl'],
    'vmmapi-values': lambda b: [objdir_of(b, 'lib/libvmmapi') / 'libvmmapi.so.7'],
    'vmmapi-layout': lambda b: [objdir_of(b, 'lib/libvmmapi') / 'vmmapi_memory.pico'],
    'vmmapi-lifecycle': lambda b: [b],
    # Production bhyvectl + production libvmmapi.so against the vmm model.
    'bhyve-cov-vmmapi': lambda b: [objdir_of(b, 'lib/libvmmapi'), b],
    'bhyve-cov-bhyvectl': lambda b: [objdir_of(b, 'usr.sbin/bhyvectl') / 'bhyvectl',
                                     objdir_of(b, 'lib/libvmmapi'), b],
}
# Self-contained C tests normally run by native-port.py; flags mirror it.
NATIVE_SUITES = {
    'bhyve-device': ['-DBHYVE_SNAPSHOT=1', '-Wno-unused-function',
                     '-Wno-unused-variable', '-Wno-unused-parameter',
                     '-ffunction-sections', '-fdata-sections',
                     '-Wl,--gc-sections', '-Wl,--wrap=pthread_create',
                     '-I{root}/sys', '-I{root}/contrib/libucl/include',
                     '@-lcrypto'],
    # bhyve-device.c with additional checks (it includes that file).
    'bhyve-cov-vtdtr': ['-DBHYVE_SNAPSHOT=1', '-Wno-unused-function',
                        '-Wno-unused-variable', '-Wno-unused-parameter',
                        '-ffunction-sections', '-fdata-sections',
                        '-Wl,--gc-sections', '-Wl,--wrap=pthread_create',
                        '-Wl,--wrap=malloc', '-Wl,--wrap=calloc', '-Wl,--wrap=atexit',
                        '-I{root}/sys', '-I{root}/contrib/libucl/include',
                        '-I' + str(TESTS), '@-lcrypto'],
    'bhyve-sockets': ['-I{root}/sys', '@-lcrypto'],
    'bhyve-connect': ['-I{root}/sys',
                      '-Wl,--wrap=connectat,--wrap=open,--wrap=pthread_create',
                      '@-lcrypto'],
    'checkpoint-release': ['-ffunction-sections', '-fdata-sections',
                           '-Wl,--gc-sections', '-I{root}/sys', '@-lmd'],
    # Ordinary-migration handoff journal (migration_handoff.h).
    'migration-handoff-journal': ['-I{root}/sys', '@-lz', '@-lmd'],
}
# Arguments for native suites that take them (default: none).
NATIVE_ARGS = {
    'migration-handoff-journal': lambda out: [str(out)],  # scratch under /usr/obj
}
# New suites maintained with this driver (python3.12 DRIVER OUT BUILD).
# Suites maintained with this collector.  Each compiles the ORIGINAL production
# sources with the exact production compile command recorded in the build log
# (plus -O0 and ASan/UBSan) and links a harness that supplies the bhyve-internal
# boundaries.  Syscall/library faults are injected with --wrap so the injected
# boundary demonstrably fires; harness code is excluded from production figures.
#   harness: test source in this directory
#   sources: production sources (repository-relative)
#   wrap:    symbols wrapped at link time
#   libs:    link libraries
#   runs:    argument vectors; every run must exit 0
#   setup:   optional callable(out) -> None (fixtures such as certificates)
NEW_SPECS = {}
NEW_SUITES = []


def register(name, **spec):
    NEW_SPECS[name] = spec
    NEW_SUITES.append(name)


def production_command(build, source):
    """The maintained compile command for SOURCE, parsed from the build log.

    Parallel make can interleave long command lines in the log.  When the
    exact line is not intact, another intact command of the same program is
    used with the source substituted, after make confirms the source has no
    per-file CFLAGS (the only per-source difference bsd.prog.mk applies)."""
    record = json.loads((build / 'build.json').read_text())
    path = str(ROOT / source)
    candidates = {}
    for step in record['steps']:
        for line in Path(step['log']).read_text(errors='replace').splitlines():
            words = line.split()
            if len(words) > 3 and words[0] in ('cc', 'c++') and '-c' in words:
                # An intact line names one source and one object and carries
                # no fragment of another command interleaved by parallel make.
                intact = words.count('-c') == 1 and words.count('-o') == 1 and \
                    not any(w.startswith('---') or w in ('cc', 'c++', 'ctfconvert')
                            for w in words[1:])
                if not intact:
                    continue
                compiled = words[words.index('-c') + 1]
                if compiled == path:
                    return words
                candidates.setdefault(step['step'], (compiled, words))
    # No intact log line: ask make for the command it runs (-n prints
    # without executing; -B treats the object as out of date).
    for step in ('lib/libvmmapi', 'usr.sbin/bhyvectl', 'usr.sbin/bhyve'):
        if not source.startswith(step + '/'):
            continue
        for suffix in ('.pieo', '.pico', '.o'):
            target = Path(source).stem + suffix
            printed = subprocess.run(
                make_command(build) + ['-C', str(ROOT / step), '-n', '-B', target],
                env=build_env(build), capture_output=True, text=True)
            for line in printed.stdout.splitlines():
                words = line.split()
                if words and words[0] in ('cc', 'c++') and '-c' in words and \
                        words[words.index('-c') + 1] == path:
                    return words
    for step in ('lib/libvmmapi', 'usr.sbin/bhyvectl', 'usr.sbin/bhyve'):
        if source.startswith(step + '/') and step in candidates:
            name = Path(source).name
            extra = subprocess.check_output(
                make_command(build) + ['-C', str(ROOT / step), '-V', '${CFLAGS.%s}' % name],
                env=build_env(build), text=True).strip()
            if extra:
                die('per-file CFLAGS for %s and no intact log line' % source)
            compiled, words = candidates[step]
            words = list(words)
            words[words.index('-c') + 1] = path
            return words
    die('no production compile command for %s' % source)


def test_command(words):
    """Production command adapted for a test object: keep every preprocessor,
    language and warning flag; drop object naming, dependency output,
    optimization and debug compression; add sanitizers."""
    out, skip = [], False
    for word in words[1:]:
        if skip:
            skip = False
            continue
        if word in ('-c', '-o', '-MF', '-MT'):
            skip = True     # drops the source after -c and each named file
            continue
        if word in ('-MD', '-gz=zlib') or word.startswith('-O') or \
                word.startswith('-MF') or word.startswith('-MT'):
            continue
        out.append(word)
    return [words[0]] + out + ['-O0', '-g', '-fsanitize=address,undefined',
                               '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']


def harness_flags(words):
    """Preprocessor view of the production command for harness sources."""
    keep = [w for w in words if w.startswith(('-D', '-I', '-std='))]
    return keep + ['-O0', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                   '-Wno-unused-function', '-Wno-missing-field-initializers',
                   '-Wno-pointer-sign',
                   '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                   '-I' + str(TESTS), '-pthread']


def run_new(name, out, build, env):
    spec = NEW_SPECS[name]
    out.mkdir()
    if spec.get('setup'):
        spec['setup'](out)
    status = build_and_run(spec, out, build, env, {})
    if status != 0 or not spec.get('mutants'):
        return status
    # Mutation check: each deliberately weakened copy of a production source
    # must make at least one run fail.  Mutant builds live outside the suite
    # directory and never write coverage profiles.
    work = out.parent / (out.name + '.mutants')
    work.mkdir()
    menv = dict(env, LLVM_PROFILE_FILE='/dev/null')
    menv.pop('HYPERTRACE_COVERAGE_DIR', None)
    results = {}
    for mutant, source, old, new in spec['mutants']:
        text = (ROOT / source).read_text()
        if text.count(old) != 1:
            die('mutant %s does not match exactly once' % mutant)
        directory = work / mutant
        directory.mkdir()
        copy = directory / Path(source).name
        copy.write_text(text.replace(old, new))
        if spec.get('setup'):
            spec['setup'](directory)
        try:
            outcome = build_and_run(spec, directory, build, menv, {source: copy})
        except subprocess.TimeoutExpired:
            outcome = 'timeout'
        if outcome in ('build-failed', 'link-failed'):
            die('mutant %s did not build; see %s' % (mutant, directory))
        results[mutant] = outcome != 0
    (out / 'mutants.json').write_text(json.dumps(results, indent=2) + '\n')
    survivors = [m for m, killed in results.items() if not killed]
    return 'mutants-survived: ' + ','.join(survivors) if survivors else 0


def build_and_run(spec, out, build, env, replace):
    stub, _ = probe_stubs(build, out)
    objects = [str(stub)]
    log = []
    first = None
    for source in spec['sources']:
        words = production_command(build, source)
        first = first or words
        obj = out / (Path(source).name + '.o')
        path = replace.get(source, ROOT / source)
        command = test_command(words) + spec.get('source_cflags', []) + \
            ['-c', str(path), '-o', str(obj)]
        built = subprocess.run(command, env=env, capture_output=True, text=True, cwd=out)
        log.append(' '.join(command) + '\n' + built.stdout + built.stderr)
        if built.returncode:
            (out / 'build.log').write_text('\n'.join(log))
            return 'build-failed'
        objects.append(str(obj))
    harnesses = spec['harness'] if isinstance(spec['harness'], list) else [spec['harness']]
    if spec.get('harness_flags_from'):
        # Harnesses that #include original sources take that source's
        # production preprocessor view.
        first = production_command(build, spec['harness_flags_from'])
    for harness in harnesses:
        obj = out / (Path(harness).name + '.o')
        # A mutated copy of a source that the harness #includes is found
        # first through its own directory.
        included = ['-I' + str(path.parent) for src, path in replace.items()
                    if src not in spec['sources']]
        command = ['cc'] + included + harness_flags(first) + spec.get('cflags', []) + \
            ['-c', str(TESTS / harness), '-o', str(obj)]
        built = subprocess.run(command, env=env, capture_output=True, text=True, cwd=out)
        log.append(' '.join(command) + '\n' + built.stdout + built.stderr)
        if built.returncode:
            (out / 'build.log').write_text('\n'.join(log))
            return 'build-failed'
        objects.append(str(obj))
    binary = out / "test-binary"
    libs = spec.get('libs', [])
    if callable(libs):
        libs = libs(build)
    command = ['cc', '-fsanitize=address,undefined', '-pthread'] + objects + \
        ['-Wl,--wrap=' + symbol for symbol in spec.get('wrap', [])] + \
        libs + ['-o', str(binary)]
    built = subprocess.run(command, env=env, capture_output=True, text=True, cwd=out)
    log.append(' '.join(command) + '\n' + built.stdout + built.stderr)
    if built.returncode and spec.get('stub_unresolved'):
        # References from production code the suite never calls (the rest of
        # bhyve) get definitions that abort if reached.
        missing = sorted(set(re.findall(r'undefined symbol: (\w+)', built.stderr)))
        stubs = out / 'unresolved-stubs.c'
        stubs.write_text('#include <stdlib.h>\n' + ''.join(
            'void %s(void); void %s(void) { abort(); }\n' % (m, m) for m in missing))
        obj = out / 'unresolved-stubs.o'
        subprocess.run(['cc', '-O0', '-c', str(stubs), '-o', str(obj)], check=True)
        command = command[:-2] + [str(obj)] + command[-2:]
        built = subprocess.run(command, env=env, capture_output=True, text=True, cwd=out)
        log.append('stubbed %d unresolved symbols\n' % len(missing) + ' '.join(command) +
                   '\n' + built.stdout + built.stderr)
    (out / 'build.log').write_text('\n'.join(log))
    if built.returncode:
        return 'link-failed'
    if spec.get('check'):
        return spec['check'](out, binary, build, dict(
            env, ASAN_OPTIONS='abort_on_error=1:detect_leaks=0',
            UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=1'))
    status = 0
    for index, argv in enumerate(spec.get('runs', [[]])):
        run_env = dict(env, ASAN_OPTIONS='abort_on_error=1:detect_leaks=0',
                       UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=1')
        ran = subprocess.run([str(binary)] + argv, env=run_env, capture_output=True,
                             text=True, timeout=spec.get('timeout', 600), cwd=out)
        (out / ('run-%d.log' % index)).write_text(' '.join(argv) + '\n' + ran.stdout + ran.stderr)
        if ran.returncode:
            status = ran.returncode
    return status
# ------------------------------------------- registered production suites
RECEIVER = 'usr.sbin/bhyve/migration_receiver.c'
register('bhyve-cov-receiver', harness='bhyve-cov-receiver.c',
         sources=[RECEIVER],
         wrap=['calloc', 'fcntl', 'getsockopt', 'pthread_mutex_init',
               'pthread_cond_init', 'pthread_create', 'pthread_cond_wait',
               'poll', 'accept4', 'nanosleep', 'warnx'],
         runs=[[], ['--capsicum']], timeout=60,
         mutants=[
             ('quarantine-ignored', RECEIVER, 'receiver->running = running && !uncertain;',
              'receiver->running = running;'),
             ('warning-repeated', RECEIVER, 'previous_error = error;', 'previous_error = 0;'),
             ('no-backoff', RECEIVER, 'if (client < 0) {\n\t\t\t/* Avoid', 'if (client < -1) {\n\t\t\t/* Avoid'),
             ('listener-flags-kept', RECEIVER,
              '(void)fcntl(receiver->listener, F_SETFL, receiver->listener_flags);', ';'),
             ('shared-trust-descriptor', RECEIVER,
              'receiver->credentials.trust_fd = fcntl(config->tls_credentials->trust_fd, F_DUPFD_CLOEXEC, 0);',
              'receiver->credentials.trust_fd = config->tls_credentials->trust_fd;'),
             ('reconstruction-leaked', RECEIVER, 'if (image.state != NULL)', 'if (0)'),
             ('ack-ignored', RECEIVER,
              'result->release_ack_sent = receiver->ack_sent;', 'result->release_ack_sent = false;'),
             ('listener-unchecked', RECEIVER, 'error = migration_recovery_listener_check(listener);\n\tif (error != 0)',
              'error = migration_recovery_listener_check(listener);\n\tif (0)'),
         ])

def tls_material(out):
    """Self-signed source/destination certificates and SHA-256 pins."""
    for name in ('source', 'destination', 'stranger'):
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes',
                        '-keyout', str(out / (name + '.key')), '-out', str(out / (name + '.pem')),
                        '-days', '1', '-subj', '/CN=' + name], check=True, capture_output=True)
        (out / (name + '.key')).chmod(0o600)
        der = subprocess.check_output(['openssl', 'x509', '-in', str(out / (name + '.pem')),
                                       '-outform', 'DER'])
        (out / (name + '.pin')).write_bytes(hashlib.sha256(der).digest())
    # A passphrase-protected key: production must refuse it without prompting.
    subprocess.run(['openssl', 'pkey', '-in', str(out / 'source.key'), '-aes256',
                    '-passout', 'pass:secret', '-out', str(out / 'encrypted.key')],
                   check=True, capture_output=True)
    (out / 'encrypted.key').chmod(0o600)


ADAPTER_SOURCES = ['usr.sbin/bhyve/migration_session.c', 'usr.sbin/bhyve/migration_tls.c',
                   'usr.sbin/bhyve/migration_receiver.c', 'usr.sbin/bhyve/migration_precopy.c',
                   'usr.sbin/bhyve/migration_dirty.c', 'usr.sbin/bhyve/checkpoint_compat.c',
                   'lib/libvmmapi/vmmapi_dirty_log.c']
register('bhyve-cov-adapter', harness=['bhyve-cov-adapter.c', 'bhyve-cov-protocol.c'],
         sources=ADAPTER_SOURCES,
         wrap=['open', 'fstat', 'fsync', 'renameat', 'unlinkat', 'flock'],
         libs=['-lnv', '-lmd', '-lssl', '-lcrypto', '-lz'],
         setup=tls_material, runs=[['adapter'], ['protocol']], timeout=3600)

register('bhyve-cov-ops', harness=['bhyve-cov-ops.c', 'bhyve-cov-protocol.c'],
         sources=[x for x in ADAPTER_SOURCES if not x.endswith('migration_session.c')],
         wrap=['open', 'fstat', 'fsync', 'renameat', 'unlinkat', 'flock', 'malloc',
               'calloc', 'poll', 'read', 'write'],
         libs=['-lnv', '-lmd', '-lssl', '-lcrypto', '-lz'],
         setup=tls_material, runs=[[]], timeout=600)

register('bhyve-cov-dirty', harness='bhyve-cov-dirty.c',
         harness_flags_from='usr.sbin/bhyve/migration_dirty.c',
         sources=['lib/libvmmapi/vmmapi_dirty_log.c'], wrap=['calloc'],
         runs=[[]], timeout=300,
         mutants=[
             ('clear-keeps-active', 'usr.sbin/bhyve/migration_dirty.c',
              'tracker->active[global_page / NBBY] &= ~mask;', ';'),
             ('abort-drops-captured', 'usr.sbin/bhyve/migration_dirty.c',
              'if (aborting) {\n\t\t\tfor (i = 0; i < tracker->bitmap_bytes; i++)\n\t\t\t\ttracker->active[i] |= tracker->captured[i];',
              'if (aborting) {\n\t\t\tfor (i = 0; i < 0; i++)\n\t\t\t\ttracker->active[i] |= tracker->captured[i];'),
             ('mark-last-page-lost', 'usr.sbin/bhyve/migration_dirty.c',
              'last = MIN(end, tracked_last) &', 'last = MIN(end - 1, tracked_last) &'),
             ('union-dropped', 'usr.sbin/bhyve/migration_precopy.c',
              'cpu_bitmap[i] |= device_bitmap[i];', 'cpu_bitmap[i] |= 0;'),
             ('failed-clear-retryable', 'usr.sbin/bhyve/migration_precopy.c',
              'if (mode == MIGRATION_DIRTY_CLEAR)\n\t\t\tfailed = true;', 'if (0)\n\t\t\tfailed = true;'),
         ])

TLS = 'usr.sbin/bhyve/migration_tls.c'
register('bhyve-cov-tls', harness='bhyve-cov-tls.c', sources=[TLS],
         wrap=['fstat', 'pread', 'BIO_new', 'BIO_write', 'X509_STORE_add_cert',
               'SSL_CTX_use_certificate', 'OPENSSL_init_ssl', 'SSL_CTX_new',
               'PEM_read_bio_PrivateKey', 'SSL_CTX_use_PrivateKey',
               'SSL_CTX_check_private_key', 'SSL_new', 'SSL_set_fd',
               'SSL_get1_peer_certificate', 'SSL_get_certificate', 'X509_digest',
               'setsockopt', 'SSL_read_ex', 'SSL_write_ex', 'SSL_CTX_ctrl',
               'SSL_get_verify_result', 'clock_gettime', 'poll', 'fcntl', 'SSL_get_error'],
         libs=['-lssl', '-lcrypto'], setup=tls_material, runs=[[]], timeout=900,
         mutants=[
             ('pin-unchecked', TLS,
              'CRYPTO_memcmp(digest, credentials->peer_certificate_sha256, 32) != 0) {',
              'CRYPTO_memcmp(digest, credentials->peer_certificate_sha256, 0) != 0) {'),
             ('public-key-accepted', TLS, '(secret && (st.st_uid != geteuid() || (st.st_mode & 077) != 0))',
              '(secret && st.st_uid != geteuid())'),
             ('flags-not-restored', TLS,
              '(void)fcntl(tls->fd, F_SETFL, tls->original_flags);', ';'),
             ('trailing-garbage-accepted', TLS,
              'ERR_GET_REASON(ERR_peek_last_error()) != PEM_R_NO_START_LINE)',
              '0)'),
             ('verify-ignored', TLS,
              'if (peer == NULL || SSL_get_verify_result(tls->ssl) != X509_V_OK ||',
              'if (peer == NULL ||'),
         ])

register('bhyve-cov-hypertrace', harness='bhyve-cov-hypertrace.c',
         harness_flags_from='usr.sbin/bhyve/hypertrace.c', sources=[],
         wrap=['ioctl', 'cap_ioctls_limit', 'cap_rights_limit', 'open', 'socket',
               'connectat', 'send', 'sendmsg'],
         libs=['-lcrypto'], runs=[[]], timeout=300)

SNAPSHOT_SOURCES = ['usr.sbin/bhyve/' + f for f in (
    'checkpoint_compat.c', 'checkpoint_cpu.c', 'checkpoint_machine.c',
    'checkpoint_manifest.c', 'checkpoint_numa.c', 'checkpoint_topology.c',
    'amd64/checkpoint_cpu_machdep.c', 'snapshot_devmem.c')]
register('bhyve-cov-snapshot', harness='bhyve-cov-snapshot.c',
         harness_flags_from='usr.sbin/bhyve/snapshot.c', sources=SNAPSHOT_SOURCES,
         wrap=['malloc', 'calloc', 'strdup', 'open', 'openat', 'fstat', 'fsync',
               'unlinkat', 'linkat', 'renameat', 'write', 'pwrite', 'pread', 'read',
               'lseek', 'flock', 'mmap', 'memfd_create', 'fdopen', 'fwrite', 'fread',
               'fseek', 'ftell', 'ucl_parser_new', 'ucl_parser_add_fd',
               'xo_create_to_file', 'close', 'fclose', 'fflush', 'xo_finish_h',
               'asprintf', 'clock_gettime', 'nanosleep', 'exit', 'isatty', 'ioctl'],
         libs=['-lprivateucl', '-lxo', '-lnv', '-lmd', '-lutil', '-lz', '-pthread'], runs=[[]],
         timeout=1200)

register('bhyve-cov-control', harness='bhyve-cov-control.c',
         harness_flags_from='usr.sbin/bhyve/bhyverun.c',
         sources=['usr.sbin/bhyve/ipc.c', 'usr.sbin/bhyve/config.c',
                  'usr.sbin/bhyve/checkpoint_numa.c', 'usr.sbin/bhyve/checkpoint_topology.c'],
         wrap=['pthread_cond_timedwait', 'pthread_cond_wait', 'clock_gettime', 'pthread_join', 'pthread_create',
               'pthread_condattr_init', 'pthread_condattr_setclock', 'pthread_cond_init',
               'socket', 'bind', 'lchmod', 'setsockopt', 'listen',
               'accept4', 'cap_rights_limit', 'cap_enter'],
         # bhyverun.c's remaining references (devices, ACPI, ...) belong to
         # code this suite never calls: they are stubbed to abort.
         libs=['-lnv', '-lprivateucl', '-lxo', '-lutil', '-lmd', '-Wl,--error-limit=0'],
         stub_unresolved=True, runs=[[]], timeout=600)


register('bhyve-cov-gdb', harness='bhyve-cov-gdb.c',
         harness_flags_from='usr.sbin/bhyve/gdb.c', sources=[], wrap=['malloc', 'calloc', 'setsockopt'],
         libs=['-lnv', '-Wl,--error-limit=0'], stub_unresolved=True, runs=[[]], timeout=300)


register('bhyve-cov-headers', harness='bhyve-cov-headers.c',
         harness_flags_from='usr.sbin/bhyve/migration_session.c',
         sources=ADAPTER_SOURCES,
         wrap=['read', 'write', 'fsync', 'renameat', 'unlinkat', 'fstat', 'fstatat', 'flock',
               'malloc', 'openat', 'close', 'open',
               'migration_prod_source_recover_restart_named'],
         libs=['-lnv', '-lmd', '-lssl', '-lcrypto', '-lz', '-Wl,--error-limit=0'],
         stub_unresolved=True, runs=[[]], timeout=600)


def bhyvectl_vendor_check(out, binary, build, env):
    """Run the bhyvectl oracle suite on the test build for each CPU vendor
    identity (the production binary covers this host's vendor)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('bhyvectl_oracle',
                                                  TESTS / 'bhyve-cov-bhyvectl.py')
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    ok = oracle.run_suite(out / 'intel', binary, objdir_of(build, 'lib/libvmmapi'),
                          build, 'intel', env)
    return 0 if ok else 1


register('bhyve-cov-bhyvectl-vendor', harness='bhyve-cov-cpuid.c',
         sources=['usr.sbin/bhyvectl/bhyvectl.c', 'usr.sbin/bhyvectl/amd64/bhyvectl_machdep.c'],
         source_cflags=['-include', str(TESTS / 'bhyve-cov-cpuid.h')],
         libs=lambda b: ['-L%s' % objdir_of(b, 'lib/libvmmapi'), '-lvmmapi', '-lutil', '-lnv', '-lz'],
         check=bhyvectl_vendor_check, timeout=1800)

# NAME@prod reruns an existing suite with the production preprocessor view of
# bhyve (see PRODUCTION_DEFINES) and probe stubs; tests are unchanged.
# Excluded: these drivers build copied slices of the GDB-less adapter
# configuration (their slices call gdb_* only under BHYVE_GDB); they run only in
# their own configuration and never contribute to the strict figure.
PROD_EXCLUDED = {'migration-production-binding', 'migration-source-intent',
                 'migration-recovery-exchange'}
PROD_SUITES = [n + '@prod' for n in DRIVER_SUITES + list(NATIVE_SUITES)
               if not n.startswith(('vmmapi-', 'arch-')) and n not in PROD_EXCLUDED]
ALL_SUITES = DRIVER_SUITES + list(BUILD_SUITES) + list(NATIVE_SUITES) + NEW_SUITES + \
    PROD_SUITES

# Macros the maintained bhyve Makefile defines for every bhyve source (amd64,
# MK_BHYVE_SNAPSHOT=yes) that change the code of the measured files.  The
# snapshot macro is left to each test (it selects which production adapters
# the test links); functions it does not enclose are compiled identically.
PRODUCTION_DEFINES = ['-DBHYVE_GDB', '-DINET', '-DINET6',
                      '-DOPENSSL_API_COMPAT=0x10100000L', '-DWITH_DTRACE']


def probe_stubs(build, directory):
    """Compile definitions for every USDT probe in the production provider
    header.  Is-enabled probes alternate between disabled and enabled so both
    outcomes of every BHYVE_TRACE site run; probe bodies clobber errno so a
    tracing site that failed to preserve errno is visible to the tests."""
    header = objdir_of(build, 'usr.sbin/bhyve') / 'vsock_provider.h'
    text = header.read_text()
    lines = ['#include <errno.h>', '#include <stdint.h>', '#include <sys/types.h>',
             '#include "%s"' % header,
             'unsigned long ht_probe_fired, ht_probe_queries;']
    for ret, name, params in re.findall(
            r'^extern (void|int) (__dtrace(?:enabled)?_\w+)\(([^)]*)\);$', text, re.M):
        if ret == 'int':
            lines.append('int %s(void) { return ((++ht_probe_queries & 1) != 0); }' % name)
            continue
        types = [t.strip() for t in params.split(',')] if params.strip() not in ('', 'void') else []
        args = ', '.join('%s a%d' % (t, i) for i, t in enumerate(types)) or 'void'
        uses = ''.join('(void)a%d; ' % i for i in range(len(types)))
        lines.append('void %s(%s) { %sht_probe_fired++; errno = 0x5eed; }' % (name, args, uses))
    source = directory / 'probe-stubs.c'
    source.write_text('\n'.join(lines) + '\n')
    obj = directory / 'probe-stubs.o'
    subprocess.run(['/usr/bin/cc', '-O0', '-fPIC', '-c', str(source), '-o', str(obj)],
                   check=True)
    return obj, header.parent


def production_wrappers(directory, build):
    """Coverage wrappers that add the production defines and probe stubs."""
    directory.mkdir()
    stub, include = probe_stubs(build, directory)
    for compiler in ('cc', 'c++', 'clang', 'clang++'):
        binary = Path('/usr/bin') / compiler
        flags = ' '.join(FLAGS + PRODUCTION_DEFINES)
        wrapper = directory / compiler
        wrapper.write_text(
            '#!/bin/sh\nlink=1\nfor a in "$@"; do case "$a" in -c|-S|-E|-M|-MM) link=0;; esac; done\n'
            'if [ $link = 1 ]; then exec %s %s "$@" -I%s %s -Wl,--build-id=sha1; fi\n'
            'exec %s %s "$@" -I%s\n' % (binary, flags, include, stub,
                                                   binary, flags, include))
        wrapper.chmod(0o755)


def objdir_of(build, step):
    return Path(json.loads((build / 'build.json').read_text())['objdirs'][step])


def run_native(name, out, env):
    out.mkdir()
    for link, target in (('machine', 'sys/amd64/include'), ('x86', 'sys/x86/include')):
        (out / link).symlink_to(ROOT / target)
    command = ['cc', '-Wall', '-Wextra', '-Werror', '-pthread', '-UNDEBUG',
               '-fsanitize=address,undefined', '-I' + str(out),
               '-I' + str(ROOT / 'usr.sbin/bhyve'),
               '-I' + str(ROOT / 'usr.sbin/dtraced'),
               '-I' + str(ROOT / 'lib/libvmmapi')]
    libraries = []
    for flag in NATIVE_SUITES[name]:
        flag = flag.format(root=ROOT)
        (libraries if flag.startswith('@') else command).append(flag.lstrip('@'))
    command += [str(TESTS / (name + '.c')), '-o', str(out / name)] + libraries
    built = subprocess.run(command, env=env, capture_output=True, text=True)
    (out / 'build.log').write_text(' '.join(command) + '\n' + built.stdout + built.stderr)
    if built.returncode:
        return built.returncode
    arguments = NATIVE_ARGS.get(name, lambda out: [])(out)
    ran = subprocess.run([str(out / name)] + arguments, env=env, capture_output=True,
                         text=True, timeout=300, cwd=out)
    (out / 'run.log').write_text(ran.stdout + ran.stderr)
    return ran.returncode


def run_suite(name, out, build, wrapper_dir):
    requested = name
    if name.endswith('@prod'):
        name, wrapper_dir, tag = name[:-5], out / 'bin-prod', name[:-5] + '.prod'
    else:
        tag = name
    result = run_suite_as(name, tag, out, build, wrapper_dir)
    result['suite'] = requested
    result['directory'] = tag
    return result


def run_suite_as(name, tag, out, build, wrapper_dir):
    profiles = out / (tag + '-profiles')
    profiles.mkdir()
    env = dict(os.environ)
    env.update(PATH=str(wrapper_dir) + os.pathsep + env.get('PATH', ''),
               LLVM_PROFILE_FILE=str(profiles / '%p-%m.profraw'),
               HYPERTRACE_COVERAGE_DIR=str(profiles))
    target = out / tag
    log = out / (tag + '.log')
    if name in NATIVE_SUITES or name in NEW_SUITES:
        command = ['native' if name in NATIVE_SUITES else 'production-config', name]
        try:
            status = (run_native(name, target, env) if name in NATIVE_SUITES
                      else run_new(name, target, build, env))
        except subprocess.TimeoutExpired:
            status = 'timeout'
        log.write_text('%s suite; see %s\n' % (command[0], target))
    else:
        command = [sys.executable, str(TESTS / (name + '.py')), str(target)]
        if name in BUILD_SUITES:
            command += [str(p) for p in BUILD_SUITES[name](build)]
        with log.open('w') as handle:
            try:
                status = subprocess.run(command, env=env, stdout=handle,
                                        stderr=subprocess.STDOUT,
                                        timeout=3600).returncode
            except subprocess.TimeoutExpired:
                status = 'timeout'
    raw = sorted(profiles.glob('*.profraw'))
    # Some drivers direct LLVM_PROFILE_FILE into their own output directory.
    if target.exists():
        raw += sorted(target.rglob('*.profraw'))
    errors = []
    for path in [log, *target.rglob('*.log')] if target.exists() else [log]:
        if 'LLVM Profile Error' in path.read_text(errors='replace'):
            errors.append(str(path))
    merge = None
    if raw:
        listing = out / (tag + '-profiles.txt')
        listing.write_text('\n'.join(map(str, raw)) + '\n')
        with (out / (tag + '-merge.log')).open('w') as handle:
            merge = subprocess.run(['llvm-profdata', 'merge', '-sparse', '-f',
                                    str(listing), '-o',
                                    str(out / (tag + '.profdata'))],
                                   stdout=handle, stderr=subprocess.STDOUT).returncode
        if (out / (tag + '-merge.log')).read_text().strip():
            errors.append(str(out / (tag + '-merge.log')))
    return {'suite': name, 'command': command, 'test_status': status,
            'profiles': len(raw), 'merge_status': merge,
            'profile_error_logs': errors,
            'passed': status == 0 and bool(raw) and merge == 0 and not errors}


def driver_digest(name):
    name = name.split('@')[0]
    if name in NEW_SPECS:
        harness = NEW_SPECS[name]['harness']
        return {h: sha256(TESTS / h) for h in (harness if isinstance(harness, list) else [harness])}
    return sha256(TESTS / (name + ('.c' if name in NATIVE_SUITES else '.py')))


def phase_run(args):
    build = args.build.resolve()
    record = json.loads((build / 'build.json').read_text())
    if record['status'] != 0:
        die('build did not pass')
    changed = [n for n, h in record['source_sha256'].items()
               if sha256(ROOT / n) != h]
    if changed and not args.allow_source_change:
        die('production sources changed since the build: %s' % ', '.join(changed))
    out = new_output(args.output)
    tools = wrappers(out / 'bin')
    production_wrappers(out / 'bin-prod', build)
    suites = args.suite or ALL_SUITES
    unknown = sorted(set(suites) - set(ALL_SUITES))
    if unknown:
        die('unknown suites: %s' % ', '.join(unknown))
    metadata = {'phase': 'run', 'build': str(build), 'head': git_head(),
                'suites': suites, 'tools': tools, 'flags': FLAGS,
                'live_tests': False, 'source_changed_since_build': changed,
                'driver_sha256': {n: driver_digest(n) for n in suites},
                'production_defines': PRODUCTION_DEFINES,
                'collector_sha256': sha256(__file__),
                'source_sha256': {n: sha256(ROOT / n) for n in record['source_sha256']}}
    (out / 'provenance.json').write_text(json.dumps(metadata, indent=2) + '\n')
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(run_suite, n, out, build, out / 'bin'): n for n in suites}
        results = []
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            print(json.dumps({k: result[k] for k in ('suite', 'test_status', 'profiles', 'passed')}),
                  flush=True)
    results.sort(key=lambda r: suites.index(r['suite']))
    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    failed = [r['suite'] for r in results if not r['passed']]
    print('PASS' if not failed else 'FAIL: ' + ', '.join(failed), len(results), 'suites')
    raise SystemExit(1 if failed else 0)


# --------------------------------------------------------------- report phase

def is_elf_with_coverage(path):
    try:
        with open(path, 'rb') as handle:
            if handle.read(4) != b'\x7fELF':
                return False
        return b'__llvm_covfun' in Path(path).read_bytes()
    except OSError:
        return False


def read_text_profile(profdata):
    text = subprocess.run(['llvm-profdata', 'merge', '-text', str(profdata), '-o', '-'],
                          capture_output=True, text=True, check=True).stdout
    records = {}
    lines = [l for l in text.splitlines() if not l.startswith('#') and l != ':fe']
    i = 0
    while i < len(lines):
        if not lines[i].strip():
            i += 1
            continue
        name = lines[i]
        fhash = int(lines[i + 1])
        count = int(lines[i + 2])
        counters = [int(x) for x in lines[i + 3:i + 3 + count]]
        i += 3 + count
        records[(name, fhash)] = counters
    return records


def base_name(name):
    return name.rsplit(':', 1)[-1] if name else name


def production_file(path):
    if not path:
        return None
    p = Path(path)
    try:
        rel = p.resolve().relative_to(ROOT)
    except (ValueError, OSError):
        return None
    rel = str(rel)
    if rel.startswith(('usr.sbin/bhyve/', 'usr.sbin/bhyvectl/', 'lib/libvmmapi/')):
        return rel
    return None


def inventory_files():
    files = set()
    for names in COMPONENTS.values():
        files.update(names or ())
    return files


def component_of(rel):
    for component, names in COMPONENTS.items():
        if names and rel in names:
            return component
    for component, pattern in HEADER_PATTERNS.items():
        if pattern.search(rel):
            return component
    return None


def write_text_profile(path, records):
    with open(path, 'w') as handle:
        for (name, fhash), counters in records:
            handle.write('%s\n%d\n%d\n%s\n\n' % (name, fhash, len(counters),
                                                  '\n'.join(map(str, counters))))


def llvm_export(objects, profdata, output, summary_only=False, name_regex=None):
    command = ['llvm-cov', 'export', '-format=text']
    if summary_only:
        command.append('-summary-only')
    if name_regex:
        command.append('-name-regex=' + name_regex)
    command += ['-instr-profile', str(profdata), str(objects[0])]
    for obj in objects[1:]:
        command += ['-object', str(obj)]
    with open(output, 'w') as handle, open(str(output) + '.err', 'w') as err:
        status = subprocess.run(command, stdout=handle, stderr=err).returncode
    return status, Path(str(output) + '.err').read_text()


def scoped_metrics(objects, profdata, rel, names, listing):
    """Lines, branches and functions of the named functions of REL, from
    llvm-cov's per-function report on the same rekeyed profile."""
    command = ['llvm-cov', 'report', '-show-functions', '-show-branch-summary',
               '-instr-profile', str(profdata), str(objects[0])]
    for obj in objects[1:]:
        command += ['-object', str(obj)]
    command.append(str(ROOT / rel))
    text = subprocess.run(command, capture_output=True, text=True, check=True).stdout
    listing.write_text(text)
    wanted = set(names)
    found = set()
    m = {k: {'count': 0, 'covered': 0} for k in ('lines', 'branches', 'functions', 'regions')}
    for line in text.splitlines():
        words = line.split()
        if len(words) != 10:
            continue
        name = words[0].split(':')[-1]
        if name not in wanted or name in found:
            continue
        found.add(name)
        regions, rmiss, lines, lmiss, branches, bmiss = (
            int(words[i]) for i in (1, 2, 4, 5, 7, 8))
        m['regions']['count'] += regions
        m['regions']['covered'] += regions - rmiss
        m['lines']['count'] += lines
        m['lines']['covered'] += lines - lmiss
        m['branches']['count'] += branches
        m['branches']['covered'] += branches - bmiss
        m['functions']['count'] += 1
        m['functions']['covered'] += 1 if rmiss < regions else 0
    if found != wanted:
        die('scoped functions missing from %s: %s' % (rel, sorted(wanted - found)))
    return m


def waiver_ranges(rel, spec):
    """Resolve a waiver to sorted (first, last) line ranges of REL."""
    lines = (ROOT / rel).read_text().split('\n')
    ranges = []

    def closing(start):
        depth, seen = 0, False
        for i in range(start, len(lines)):
            for ch in lines[i]:
                if ch == '{':
                    depth += 1
                    seen = True
                elif ch == '}':
                    depth -= 1
            if seen and depth == 0:
                return i
        die('unbalanced waiver block in %s at line %d' % (rel, start + 1))

    for name in spec.get('functions', []):
        heads = [i for i, l in enumerate(lines) if re.match(r'^%s\(' % re.escape(name), l)]
        if len(heads) != 1:
            die('waived function %s not found exactly once in %s' % (name, rel))
        ranges.append((heads[0], closing(heads[0])))   # 0-based; type line added below
        ranges[-1] = (heads[0] - 1, ranges[-1][1])
    marker = spec.get('marked_blocks')
    if marker:
        found = 0
        for i, l in enumerate(lines):
            if marker not in l:
                continue
            j = i
            while not lines[j].rstrip().endswith('*/'):
                j += 1
            j += 1
            if not re.match(r'^\s*if \(', lines[j]):
                die('waiver marker in %s line %d is not followed by an if block' % (rel, i + 1))
            ranges.append((j, closing(j)))
            found += 1
        if not found:
            die('no waiver markers in %s' % rel)
    return sorted((a + 1, b + 1) for a, b in ranges)


BRANCH_RE = re.compile(r'Branch \((\d+):(\d+)\): \[(True: ([\d.]+[kMG]?)|Folded), '
                       r'(False: ([\d.]+[kMG]?)|Folded)\]')
TOP_LINE_RE = re.compile(r'^\s*(\d+)\|\s*([\d.kMG]*)\|')
NESTED_LINE_RE = re.compile(r'^\s*(?:\|\s*)+(\d+)\|\s*[\d.kMG]*\|(.*)$')


def resolve_outcome_anchor(rel, entry):
    """An outcome waiver is (line, col, arm, class) or, robust to edits,
    (function, [source lines...], col, arm, class): the consecutive source
    lines (compared with whitespace collapsed) must occur exactly once in the
    function's body; the waived branch is on the last of them."""
    if isinstance(entry[0], int):
        return entry
    function, needle, col, arm, cls = entry
    lines = (ROOT / rel).read_text().split('\n')
    heads = [i for i, l in enumerate(lines) if re.match(r'^%s\(' % re.escape(function), l)]
    if len(heads) != 1:
        die('outcome anchor function %s not found exactly once in %s' % (function, rel))
    start = heads[0]
    end = next(i for i in range(start, len(lines)) if lines[i].startswith('}'))
    norm = lambda t: ' '.join(t.split())
    body = [norm(l) for l in lines[start:end + 1]]
    want = [norm(t) for t in needle]
    hits = [i for i in range(len(body) - len(want) + 1)
            if all(want[k] == '*' or want[k] in body[i + k] for k in range(len(want)))]
    if len(hits) != 1:
        die('outcome anchor %s %r matches %d times in %s' % (function, needle, len(hits), rel))
    return (start + hits[0] + len(want), col, arm, cls)


def outcome_scan(objects, profdata, rel, names, listing):
    """Top-level branch outcomes {(line, col, arm): executed?} of REL (or of
    the named functions) and the folded-constant outcomes [(site line,
    detail)] whose counted arm never executed, from llvm-cov show with
    expansions on the same rekeyed profile."""
    command = ['llvm-cov', 'show', '-show-branches=count', '-show-expansions',
               '-instr-profile', str(profdata), str(objects[0])]
    for obj in objects[1:]:
        command += ['-object', str(obj)]
    if names:
        # static functions are named FILE:function in the profile
        command.append('-name-regex=^([^:]*:)?(%s)$' % '|'.join(re.escape(n) for n in names))
    command.append(str(ROOT / rel))
    text = subprocess.run(command, capture_output=True, text=True, check=True).stdout
    listing.write_text(text)
    top, folded, site, site_ran, nested_text = {}, [], None, True, ''
    for line in text.splitlines():
        m = TOP_LINE_RE.match(line)
        if m:
            site = int(m.group(1))
            # a site with no count column, or a zero count, never ran
            site_ran = m.group(2) not in ('', '0')
            nested_text = ''
            continue
        m = NESTED_LINE_RE.match(line)
        if m:
            nested_text = m.group(2)
            continue
        m = BRANCH_RE.search(line)
        if not m:
            continue
        nested = line.lstrip().startswith('|') and line.count('|') > 1
        true_n, false_n = m.group(4), m.group(6)
        if m.group(3) == 'Folded' or m.group(5) == 'Folded':
            counted = false_n if m.group(3) == 'Folded' else true_n
            if counted == '0':
                folded.append((site, '%s:%s' % (m.group(1), m.group(2)), 'folded-constant'))
            continue
        if nested:
            # a macro-expansion branch: keyed by its site line and the
            # branch's own (header line, column)
            key = (site, int(m.group(1)), int(m.group(2)))
            if not site_ran:
                # the expansion's site never ran: its branches have no
                # outcome of their own (the site's guard is the outcome)
                continue
            if 'if (raw_stdio)' in nested_text and (true_n == '0') != (false_n == '0'):
                # EPRINTLN/FPRINTLN's console-mode test: both arms are the
                # same fprintf with a different line ending; the site ran in
                # one console mode
                folded.append((site, '%s:%s:%s' % (m.group(1), m.group(2), 'T' if true_n == '0' else 'F'),
                               'console-mode'))
                continue
            top[key + ('T',)] = true_n != '0'
            top[key + ('F',)] = false_n != '0'
            continue
        key = (int(m.group(1)), int(m.group(2)))
        top[key + ('T',)] = true_n != '0'
        top[key + ('F',)] = false_n != '0'
    return top, folded


def waived_body_lines(rel):
    """Lines of the blocks whose single-operand guard arm carries an
    outcome waiver: `if (c) {...}` with the T arm waived gives the body,
    `if (c) {...} else {...}` with the F arm waived gives the else block.  A
    condition with several operands (||, &&, ?:) or a loop is not treated:
    another operand may enter the block.  Returns {line: (guard line, arm)}
    (1-based lines)."""
    lines = (ROOT / rel).read_text().split('\n')
    body = {}

    def strip(t):
        t = re.sub(r'/\*.*?\*/', '', t)
        return re.sub(r'"(?:[^"\\]|\\.)*"', '""', t)

    def paren_close(i, col):
        """(line, index after the ')' matching the '(' at lines[i][col])."""
        depth = 0
        for j in range(i, len(lines)):
            t = strip(lines[j])
            for k in range(col if j == i else 0, len(t)):
                if t[k] == '(':
                    depth += 1
                elif t[k] == ')':
                    depth -= 1
                    if depth == 0:
                        return j, k + 1
        return None, None

    def block_after(j, k):
        """Statement lines following position (j, k): a brace block or one
        statement.  Returns (first, last, line after the block)."""
        rest = strip(lines[j])[k:].strip()
        if rest.startswith('{'):
            depth = 0
            for m in range(j, len(lines)):
                t = strip(lines[m])
                for idx, ch in enumerate(t):
                    if m == j and idx < k:
                        continue
                    if ch == '{':
                        depth += 1
                    elif ch == '}':
                        depth -= 1
                        if depth == 0:
                            return j + 1, m - 1, m
            return None
        m = j if rest else j + 1
        while m < len(lines) and not strip(lines[m]).rstrip().endswith(';'):
            m += 1
        return (j + 1 if not rest else j), m, m + 1

    for entry in OUTCOME_WAIVERS.get(rel, []):
        line, col, arm, _cls = resolve_outcome_anchor(rel, entry)
        if isinstance(col, tuple):
            continue
        # the statement: an `if (` at or shortly before the arm's line
        start = None
        for i in range(line - 1, max(-1, line - 7), -1):
            m = re.search(r'(?:^\s*|\}\s*|\belse\s+)if\s*\(', strip(lines[i]))
            if m:
                start = (i, m.end() - 1)
                break
            if i != line - 1 and re.search(r';\s*$|\{\s*$|\}\s*$', strip(lines[i])):
                break
        if start is None:
            continue
        i, lp = start
        j, k = paren_close(i, lp)
        if j is None or not (i <= line - 1 <= j):
            continue
        if i == j:
            cond = strip(lines[i])[lp:k]
        else:
            cond = strip(lines[i])[lp:] + ' ' + ' '.join(strip(lines[x]) for x in range(i + 1, j)) + \
                ' ' + strip(lines[j])[:k]
        if re.search(r'&&|\|\||\?', cond):
            continue
        blk = block_after(j, k)
        if blk is None:
            continue
        first, last, after = blk
        if arm == 'F':
            # the else block, if the statement has one
            t = strip(lines[after - 1] if after - 1 >= 0 else '')
            m = re.search(r'\}\s*else\s*(\{|if\b)?', t)
            if m is None and after < len(lines):
                m = re.search(r'^\s*else\s*(\{|if\b)?', strip(lines[after]))
                if m:
                    after_line = after
            else:
                after_line = after - 1
            if m is None or m.group(1) == 'if':
                continue
            if m.group(1) == '{':
                blk = block_after(after_line, strip(lines[after_line]).index('{'))
            else:
                blk = block_after(after_line, strip(lines[after_line]).index('else') + 4)
            if blk is None:
                continue
            first, last, _ = blk
        for n in range(first, last + 1):
            body.setdefault(n + 1, (line, arm))
    return body


def waived_metrics(objects, profdata, rel, ranges, listing, body=None, label='strict'):
    """Whole-file and waived lines/branches/functions of REL from an lcov
    export of the same rekeyed profile.  BODY maps the lines of blocks
    guarded by a waived outcome arm (waived_body_lines); in the strict view
    such a line must not have executed."""
    command = ['llvm-cov', 'export', '-format=lcov', '-instr-profile', str(profdata),
               str(objects[0])]
    for obj in objects[1:]:
        command += ['-object', str(obj)]
    command.append(str(ROOT / rel))
    text = subprocess.run(command, capture_output=True, text=True, check=True).stdout
    listing.write_text(text)
    body = body or {}
    inside_range = lambda n: any(a <= n <= b for a, b in ranges)
    inside = lambda n: inside_range(n) or n in body
    whole = {k: {'count': 0, 'covered': 0} for k in ('lines', 'branches', 'functions')}
    kept = {k: {'count': 0, 'covered': 0} for k in ('lines', 'branches', 'functions')}
    current = None
    fn_line = {}
    for line in text.splitlines():
        if line.startswith('SF:'):
            current = production_file(line[3:])
            continue
        if current != rel:
            continue
        tag, _, value = line.partition(':')
        if tag == 'DA':
            n, count = (int(x) for x in value.split(',')[:2])
            if n in body and not inside_range(n) and count > 0:
                if label == 'strict':
                    die('waived body line %s:%d (guard %d:%s) executed' % (rel, n, body[n][0], body[n][1]))
                # with slices: an executed line is covered, not waived
                kept['lines']['count'] += 1
                kept['lines']['covered'] += 1
                whole['lines']['count'] += 1
                whole['lines']['covered'] += 1
                continue
            for d in (whole,) + (() if inside(n) else (kept,)):
                d['lines']['count'] += 1
                d['lines']['covered'] += count > 0
        elif tag == 'BRDA':
            n, _, _, taken = value.split(',')
            hit = taken not in ('-', '0')
            for d in (whole,) + (() if inside(int(n)) else (kept,)):
                d['branches']['count'] += 1
                d['branches']['covered'] += hit
        elif tag == 'FN':
            n, name = value.split(',', 1)
            fn_line[name] = int(n)
        elif tag == 'FNDA':
            count, name = value.split(',', 1)
            n = fn_line.get(name)
            for d in (whole,) + (() if n is not None and inside(n) else (kept,)):
                d['functions']['count'] += 1
                d['functions']['covered'] += int(count) > 0
    return whole, kept


def summarize(export, wanted):
    data = json.loads(Path(export).read_text())
    files = {}
    for entry in data['data'][0]['files']:
        rel = production_file(entry['filename'])
        if rel is None or (wanted is not None and not wanted(rel)):
            continue
        s = entry['summary']
        files[rel] = {k: {'count': s[k]['count'], 'covered': s[k]['covered']}
                      for k in ('lines', 'branches', 'functions', 'regions')}
    return files


def percent(covered, count):
    return round(100.0 * covered / count, 4) if count else None


def totals(files):
    out = {}
    for k in ('lines', 'branches', 'functions', 'regions'):
        count = sum(f[k]['count'] for f in files.values())
        covered = sum(f[k]['covered'] for f in files.values())
        out[k] = {'count': count, 'covered': covered, 'percent': percent(covered, count)}
    return out


def phase_report(args):
    build = args.build.resolve()
    record = json.loads((build / 'build.json').read_text())
    # Outcome waivers are resolved against the tree's text; they are only
    # meaningful for the sources this build measured.
    drifted = [rel for rel in OUTCOME_WAIVERS
               if record['source_sha256'].get(rel) not in (None, sha256(ROOT / rel))]
    if drifted:
        die('sources changed since the build (rebuild before reporting): %s' % drifted)
    runs = [r.resolve() for r in args.run]
    out = new_output(args.output)
    production_objects = []
    programs = {}
    for step in ('usr.sbin/bhyve', 'usr.sbin/bhyvectl', 'lib/libvmmapi'):
        directory = Path(record['objdirs'][step])
        suffix = {'usr.sbin/bhyve': '.pieo', 'usr.sbin/bhyvectl': '.pieo',
                  'lib/libvmmapi': '.o'}[step]
        programs[step] = sorted(p for p in directory.glob('*' + suffix)
                                if is_elf_with_coverage(p))
        production_objects += programs[step]
    # Production function index: (file, base name) -> [(name, hash)].
    production = {}
    production_names = set()
    for obj in production_objects:
        if sha256(obj) != record['binary_sha256'].get(str(obj)):
            die('production object changed since build: %s' % obj)
        for fn in coverage_functions(obj):
            rel = production_file(fn['file'])
            if rel is None:
                continue
            production.setdefault((rel, base_name(fn['name'])), set()).add(
                (fn['name'], fn['hash'], fn['mapping']))
            production_names.add((fn['name'], fn['hash']))
    # Merge every passing suite profile of every run.
    profiles = []
    run_records = []
    for run in runs:
        results = json.loads((run / 'results.json').read_text())
        meta = json.loads((run / 'provenance.json').read_text())
        if Path(meta['build']) != build:
            die('run %s used a different build' % run)
        stale = [n for n, h in meta['source_sha256'].items() if record['source_sha256'].get(n) != h]
        if stale:
            die('run %s measured different production sources: %s' % (run, stale))
        for result in results:
            if result['passed']:
                profiles.append(run / (result.get('directory', result['suite']) + '.profdata'))
            run_records.append(dict(result, run=str(run)))
    listing = out / 'profiles.txt'
    listing.write_text('\n'.join(map(str, profiles)) + '\n')
    merged = out / 'all.profdata'
    merge = subprocess.run(['llvm-profdata', 'merge', '-sparse', '-f', str(listing),
                            '-o', str(merged)], capture_output=True, text=True)
    (out / 'merge.log').write_text(merge.stdout + merge.stderr)
    if merge.returncode or (merge.stdout + merge.stderr).strip():
        die('profile merge not clean; see merge.log')
    # (all.profdata only proves the passing profiles merge cleanly.)
    # Walk every instrumented binary whose counters were merged: the test
    # binaries of passing suites plus production executables run directly.
    passing = {(Path(r['run']), r.get('directory', r['suite'])) for r in run_records
               if r['passed']}
    binaries = []
    for run, suite in sorted(passing):
        base = run / suite
        if not base.exists():
            continue
        for path in sorted(base.rglob('*')):
            if path.is_file() and not path.is_symlink() and is_elf_with_coverage(path):
                binaries.append((suite, path, base.resolve()))
    for step, name in (('usr.sbin/bhyvectl', 'bhyvectl'), ('lib/libvmmapi', 'libvmmapi.so.7')):
        path = Path(record['objdirs'][step]) / name
        if sha256(path) != record['binary_sha256'].get(str(path)):
            die('production binary changed since build: %s' % path)
        binaries.append(('production', path, None))
    by_id, per_binary = {}, []
    key_mappings, key_function, key_suite_dir = {}, {}, {}
    for suite, binary, suite_dir in binaries:
        functions = coverage_functions(binary)
        identity = build_id(binary)
        per_binary.append({'suite': suite, 'binary': str(binary), 'build_id': identity,
                           'sha256': sha256(binary), 'functions': len(functions)})
        table = {(fn['name'], fn['hash']): fn for fn in functions}
        if identity is not None:
            if identity in by_id and by_id[identity][1] != table:
                die('distinct binaries share build ID %s' % identity)
            by_id[identity] = (suite_dir, table)
        for key, fn in table.items():
            key_mappings.setdefault(key, set()).add(fn['mapping'])
            key_function.setdefault(key, fn)
            key_suite_dir.setdefault(key, set()).add(suite_dir)
    strict, slices = {}, {}
    status = {'credited': set(), 'credited_slice': set(), 'ambiguous': set(),
              'config_mismatch': set(), 'not_in_production': set(),
              'raw_profiles_by_binary': 0, 'raw_profiles_unidentified': [],
              'unaccounted_profile_records': set()}

    def attribute(key, values, fn, suite_dirs):
        rel = production_file(fn['file'])
        label = '%s#%d' % key
        if rel is not None:
            candidates = production.get((rel, base_name(fn['name'])), set())
            same = sorted(c for c in candidates
                          if c[1] == fn['hash'] and c[2] == fn['mapping'])
            if not candidates:
                status['not_in_production'].add(label)
            elif not same:
                status['config_mismatch'].add(label)
            else:
                # Identical header functions exist once per including TU and
                # program; credit every identical production instance.
                for candidate in same:
                    strict.setdefault(candidate[:2], []).append(values)
                status['credited'].add(label)
        elif fn['file'] and any(d is not None and Path(fn['file']).resolve().is_relative_to(d)
                                for d in suite_dirs):
            # Copied slice generated by a driver: supplementary credit only
            # when exactly one production function of that name has the same
            # nonzero structural hash.  Never part of the strict figure.
            base = base_name(fn['name'])
            same = sorted({c[:2] for (f, b), cs in production.items() if b == base
                           for c in cs if c[1] == fn['hash'] and c[1] != 0})
            if len(same) == 1:
                slices.setdefault(same[0], []).append(values)
                status['credited_slice'].add(label)

    # Attribute each raw profile against the binary named by its build ID,
    # so identical (name, hash) records of different binaries (fakes or
    # copied slices of production functions) can never be confused.
    fallback = []
    for run in runs:
        for result in json.loads((run / 'results.json').read_text()):
            if not result['passed']:
                continue
            listing = run / (result.get('directory', result['suite']) + '-profiles.txt')
            for raw in listing.read_text().split():
                ids = profile_binary_ids(raw)
                if len(ids) == 1 and ids[0] in by_id:
                    suite_dir, table = by_id[ids[0]]
                    records = read_text_profile(raw)
                    status['raw_profiles_by_binary'] += 1
                    for key, values in records.items():
                        if not any(values):
                            continue
                        fn = table.get(key)
                        if fn is None:
                            status['unaccounted_profile_records'].add('%s#%d' % key)
                            continue
                        attribute(key, values, fn, {suite_dir})
                else:
                    status['raw_profiles_unidentified'].append(str(raw))
                    fallback.append(raw)
    # Raw profiles without a build ID (drivers that link with the system
    # compiler directly) fall back to global attribution, where a record is
    # credited only if every walked binary that defines it agrees on its
    # mapping.
    if fallback:
        listing = out / 'fallback-profiles.txt'
        listing.write_text('\n'.join(map(str, fallback)) + '\n')
        merged = out / 'fallback.profdata'
        merge = subprocess.run(['llvm-profdata', 'merge', '-sparse', '-f', str(listing),
                                '-o', str(merged)], capture_output=True, text=True)
        (out / 'fallback-merge.log').write_text(merge.stdout + merge.stderr)
        if merge.returncode or (merge.stdout + merge.stderr).strip():
            die('fallback profile merge not clean')
        for key, values in read_text_profile(merged).items():
            if not any(values):
                continue
            if key not in key_mappings:
                status['unaccounted_profile_records'].add('%s#%d' % key)
            elif len(key_mappings[key]) != 1:
                status['ambiguous'].add('%s#%d' % key)
            else:
                attribute(key, values, key_function[key], key_suite_dir[key])
    status = {k: sorted(v) if isinstance(v, set) else v for k, v in status.items()}
    def materialize(table):
        rows = []
        for (name, fhash), sources in sorted(table.items()):
            for values in sources:
                rows.append(((name, fhash), values))
        return rows
    results = {'build': str(build), 'runs': [str(r) for r in runs],
               'production_objects': len(production_objects),
               'merge_inputs': [str(p) for p in profiles],
               'suites': run_records, 'binaries': per_binary,
               'attribution': status}
    program_keys = {}
    for step, objects in programs.items():
        keys = set()
        for obj in objects:
            keys.update((fn['name'], fn['hash']) for fn in coverage_functions(obj))
        program_keys[step] = keys
    for label, table in (('strict', strict), ('with-slices', None)):
        rows = materialize(strict)
        if table is None:
            rows += materialize(slices)
        # One rekeyed profile and export per program: each is a separate
        # binary (bhyve and bhyvectl both define main).  A file is reported
        # from the program that owns it; shared migration headers count in
        # bhyve only.
        files, errors, scoped_files, waived_files = {}, '', {}, {}
        outcome_files = {}
        for step, objects in programs.items():
            tag = '%s-%s' % (label, step.split('/')[-1])
            text = out / (tag + '.proftext')
            write_text_profile(text, [r for r in rows if r[0] in program_keys[step]])
            profdata = out / (tag + '.profdata')
            made = subprocess.run(['llvm-profdata', 'merge', str(text), '-o', str(profdata)],
                                  capture_output=True, text=True)
            (out / (tag + '-merge.log')).write_text(made.stdout + made.stderr)
            if made.returncode or (made.stdout + made.stderr).strip():
                die('rekeyed profile merge not clean (%s)' % tag)
            export = out / (tag + '-coverage.json')
            status, diag = llvm_export(objects, profdata, export)
            if status:
                die('llvm-cov export failed (%s): %s' % (tag, diag))
            errors += diag
            owned = (lambda rel, step=step: rel.startswith(step + '/') and
                     (rel in inventory_files() or component_of(rel)))
            files.update(summarize(export, owned))
            for rel, spec in WAIVERS.items():
                if not rel.startswith(step + '/'):
                    continue
                ranges = waiver_ranges(rel, spec)
                body = waived_body_lines(rel)
                whole, kept = waived_metrics(objects, profdata, rel, ranges,
                                             out / ('%s-waiver-%s.lcov' % (tag, Path(rel).stem)),
                                             body, label)
                waived_files[rel] = {'ranges': ranges, 'whole_lcov': whole, 'kept': kept,
                                     'body_lines': sorted(body)}
            scan = {rel: None for c in OUTCOME_COMPONENTS for rel in COMPONENTS[c]
                    if rel.startswith(step + '/')}
            for scope in OUTCOME_SCOPES:
                for rel, names in SCOPED[scope].items():
                    if rel.startswith(step + '/'):
                        scan[rel] = names
            for rel, names in scan.items():
                if not (ROOT / rel).exists():
                    continue
                top, folded = outcome_scan(
                    objects, profdata, rel, names,
                    out / ('%s-outcomes-%s.txt' % (tag, Path(rel).stem)))
                ranges = (waived_files.get(rel) or {}).get('ranges', [])
                inside = lambda n, ranges=ranges: any(a <= n <= b for a, b in ranges)
                explicit = []
                for entry in OUTCOME_WAIVERS.get(rel, []):
                    line, col, arm, cls = resolve_outcome_anchor(rel, entry)
                    if cls not in OUTCOME_CLASSES:
                        die('unknown outcome class %s' % cls)
                    if isinstance(col, tuple):
                        # ('nested', macro line, column): a macro branch at
                        # this site
                        key = (line, col[1], col[2], arm)
                        col = '%d:%d' % (col[1], col[2])
                    else:
                        key = (line, col, arm)
                    if key not in top:
                        die('waived outcome %s:%d:%s:%s is not a branch outcome' % (rel, line, col, arm))
                    if top[key]:
                        # Strict: a waived outcome that runs was never
                        # unreachable.  With slices, a slice harness may drive
                        # it through a substituted boundary; it then counts as
                        # covered, not waived.
                        if label == 'strict':
                            die('waived outcome %s:%d:%s:%s executed' % (rel, line, col, arm))
                        continue
                    if inside(line):
                        die('waived outcome %s:%d inside a continuity range' % (rel, line))
                    explicit.append({'line': line, 'col': col, 'arm': arm, 'class': cls})
                folded = [{'site': site, 'branch': b, 'class': cls} for site, b, cls in folded
                          if site is None or not inside(site)]
                outcome_files[rel] = {'explicit': explicit, 'folded': folded,
                                      'scoped_names': names}
            for scope, members in SCOPED.items():
                for rel, names in members.items():
                    if not rel.startswith(step + '/'):
                        continue
                    if names is None:
                        scoped_files.setdefault(scope, {})[rel] = None
                        continue
                    scoped_files.setdefault(scope, {})[rel] = scoped_metrics(
                        objects, profdata, rel, names,
                        out / ('%s-%s-%s.txt' % (tag, scope, Path(rel).stem)))
        for scope, members in scoped_files.items():
            for rel, metrics in list(members.items()):
                if metrics is None:
                    members[rel] = files.get(rel)
            members = {r: m for r, m in members.items() if m is not None}
            scoped_files[scope] = members
        components = {}
        for rel, metrics in files.items():
            components.setdefault(component_of(rel) or 'other-mapped', {})[rel] = metrics
        # Waived component figures: each waived file's JSON summary minus the
        # waived share measured line by line (lcov: whole minus kept).  The
        # JSON file summary of this llvm-cov counts somewhat fewer lines than
        # its line-by-line views (show/lcov) for files with macro expansions,
        # so only the waived difference is taken from lcov.
        waived_components = {}
        for rel, w in waived_files.items():
            kept = {}
            for k in ('lines', 'branches', 'functions'):
                removed = {key: w['whole_lcov'][k][key] - w['kept'][k][key]
                           for key in ('count', 'covered')}
                w.setdefault('waived', {})[k] = removed
                kept[k] = {key: files[rel][k][key] - removed[key] for key in ('count', 'covered')}
            w['kept'] = kept
        for c in sorted(set(component_of(r) for r in waived_files)):
            members = {r: m for r, m in files.items() if component_of(r) == c}
            adjusted = {r: (dict(m, **waived_files[r]['kept']) if r in waived_files else m)
                        for r, m in members.items()}
            waived_components[c + '-waived'] = totals(
                {r: {k: m[k] for k in ('lines', 'branches', 'functions', 'regions')}
                 if 'regions' in m else dict(m, regions={'count': 0, 'covered': 0})
                 for r, m in adjusted.items()})
        # Outcome-waived figures: the component (after continuity waivers) or
        # scoped totals minus the waived outcomes, all of which never ran.
        outcome_components = {}
        for c in OUTCOME_COMPONENTS:
            base = waived_components.get(c + '-waived') or totals(components.get(c, {}))
            n = sum(len(o['explicit']) + len(o['folded'])
                    for r, o in outcome_files.items() if component_of(r) == c)
            outcome_components[c + '-outcomes'] = dict(base, branches={
                'count': base['branches']['count'] - n,
                'covered': base['branches']['covered'],
                'percent': percent(base['branches']['covered'],
                                   base['branches']['count'] - n),
                'waived_outcomes': n})
        for scope in OUTCOME_SCOPES:
            base = totals(scoped_files.get(scope, {}))
            n = sum(len(outcome_files[r]['explicit']) + len(outcome_files[r]['folded'])
                    for r in SCOPED[scope] if r in outcome_files)
            outcome_components[scope + '-outcomes'] = dict(base, branches={
                'count': base['branches']['count'] - n,
                'covered': base['branches']['covered'],
                'percent': percent(base['branches']['covered'],
                                   base['branches']['count'] - n),
                'waived_outcomes': n})
        results[label] = {
            'outcome_classes': OUTCOME_CLASSES,
            'outcome_waivers': outcome_files,
            'outcome_components': outcome_components,
            'export_diagnostics': errors,
            'waivers': waived_files,
            'waived_components': waived_components,
            'files': {rel: dict(m, component=component_of(rel)) for rel, m in sorted(files.items())},
            'components': {c: totals(f) for c, f in sorted(components.items())},
            'scoped': {c: {'files': f, 'totals': totals(f)} for c, f in sorted(scoped_files.items())},
        }
    (out / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
    for label in ('strict', 'with-slices'):
        print('==', label)
        for c, t in results[label]['components'].items():
            print('%-26s lines %6d/%-6d %7s  branches %6d/%-6d %7s  functions %4d/%-4d %7s' % (
                c, t['lines']['covered'], t['lines']['count'], t['lines']['percent'],
                t['branches']['covered'], t['branches']['count'], t['branches']['percent'],
                t['functions']['covered'], t['functions']['count'], t['functions']['percent']))
        for c, t in results[label]['waived_components'].items():
            print('%-26s lines %6d/%-6d %7s  branches %6d/%-6d %7s  functions %4d/%-4d %7s' % (
                c, t['lines']['covered'], t['lines']['count'], t['lines']['percent'],
                t['branches']['covered'], t['branches']['count'], t['branches']['percent'],
                t['functions']['covered'], t['functions']['count'], t['functions']['percent']))
        for c, t in results[label]['outcome_components'].items():
            print('%-26s lines %6d/%-6d %7s  branches %6d/%-6d %7s  (%d outcomes waived)' % (
                c, t['lines']['covered'], t['lines']['count'], t['lines']['percent'],
                t['branches']['covered'], t['branches']['count'], t['branches']['percent'],
                t['branches']['waived_outcomes']))
        for c, v in results[label]['scoped'].items():
            t = v['totals']
            print('%-26s lines %6d/%-6d %7s  branches %6d/%-6d %7s  functions %4d/%-4d %7s' % (
                c, t['lines']['covered'], t['lines']['count'], t['lines']['percent'],
                t['branches']['covered'], t['branches']['count'], t['branches']['percent'],
                t['functions']['covered'], t['functions']['count'], t['functions']['percent']))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='phase', required=True)
    p = sub.add_parser('build')
    p.add_argument('output', type=Path)
    p.set_defaults(func=phase_build)
    p = sub.add_parser('run')
    p.add_argument('output', type=Path)
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--suite', action='append')
    p.add_argument('--jobs', type=int, default=6)
    p.add_argument('--allow-source-change', action='store_true')
    p.set_defaults(func=phase_run)
    p = sub.add_parser('report')
    p.add_argument('output', type=Path)
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--run', type=Path, action='append', required=True)
    p.set_defaults(func=phase_report)
    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
