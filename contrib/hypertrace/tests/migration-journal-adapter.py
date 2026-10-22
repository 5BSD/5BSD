#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/migration_session.c').read_text()
first = source[source.index('static int\nprod_accept_commit('):source.index('/* The IPC controller owns this context')]
second = source[source.index('static int\nprod_prepare_commit('):source.index('static void\nprod_dest_discard(')]
fixture = r'''
#include <assert.h>
static int quarantines;
static void ipc_quarantine_vm(void) { quarantines++; }
#include "migration_source_owner.h"
#include "migration_commit.h"
#include "migration_handoff.h"
static int fail_at, syncs;
int __real_fsync(int);
int __wrap_fsync(int fd) {
 if (++syncs == fail_at) { errno = EIO; return -1; }
 return __real_fsync(fd);
}
struct migration_prod_source {
 bool fresh_stopped, quiesced, retired, retirement_started, intent_pending;
 bool controller_held;
 int controller_fd;
 uint8_t fresh_record[40];
 int recovery_dirfd;
 struct migration_recovery_record recovery;
};
struct migration_prod_dest {
 void *ctx, *fresh_device;
 bool committed, running;
 uint8_t *dev_blob, fresh_record[40];
 size_t dev_len;
 int recovery_dirfd;
 struct migration_recovery_record recovery;
 struct migration_commit_binding retained_binding;
};
static int vm_get_identity(void *ctx, uint16_t *vmid, uint64_t *epoch) {
 (void)ctx; *vmid = 8; *epoch = 10; return 0;
}
'''
fixture += first + second + r'''
int main(void) {
 char directory[] = "adapter.XXXXXX";
 assert(mkdtemp(directory) != NULL);
 int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
 assert(fd >= 0);
 struct migration_prod_source src = { .fresh_stopped = true,
    .quiesced = true, .recovery_dirfd = fd };
 uint8_t blob[] = "device-state";
 struct migration_prod_dest dst = { .committed = true, .fresh_device = &src,
    .dev_blob = blob, .dev_len = sizeof(blob), .recovery_dirfd = fd };
 memset(src.recovery.source_certificate_sha256, 3, 32);
 memset(src.recovery.destination_certificate_sha256, 4, 32);
 memcpy(dst.recovery.source_certificate_sha256, src.recovery.source_certificate_sha256, 32);
 memcpy(dst.recovery.destination_certificate_sha256, src.recovery.destination_certificate_sha256, 32);
 struct hypertrace_session_record stopped = { .vmid=7, .epoch=9,
    .stop_token=11, .features=HYPERTRACE_SESSION_FEATURES };
 assert(hypertrace_session_record_encode(src.fresh_record, 40, &stopped) == 0);
 memcpy(src.recovery.session, src.fresh_record, 40);
 memcpy(dst.fresh_record, src.fresh_record, 40);
 SHA256_CTX hash; SHA256_Init(&hash); SHA256_Update(&hash, blob, sizeof(blob));
 SHA256_Final(src.recovery.state_digest, &hash);
 struct migration_commit_binding binding = {0}, decoded = {0};
 memset(binding.challenge, 0x31, 32);
 assert(prod_prepare_commit(&dst, &binding) == 0);
 assert(memcmp(&dst.retained_binding, &binding, sizeof(binding)) == 0);
 uint8_t wire[MIGRATION_FRESH_COMMIT_SIZE];
 assert(migration_commit_encode(&binding, wire) == 0);
 assert(migration_commit_decode(wire, sizeof(wire), &decoded) == 0);
 assert(decoded.destination_vmid == 8 && decoded.destination_epoch == 10);
 assert(memcmp(decoded.state_digest, src.recovery.state_digest, 32) == 0);
 for (size_t n = 0; n < sizeof(wire); n++)
    assert(migration_commit_decode(wire, n, &decoded) != 0);
 wire[6] = 1; assert(migration_commit_decode(wire, sizeof(wire), &decoded) == EPROTO);
 wire[6] = 0;
 binding.state_digest[0] ^= 1;
 assert(prod_accept_commit(&src, &binding) == EPROTO);
 assert(src.recovery.phase == 0 && !src.retirement_started);
 binding.state_digest[0] ^= 1;
 binding.destination_epoch = 9;
 assert(prod_accept_commit(&src, &binding) == EPROTO);
 binding.destination_epoch = 10;
 assert(prod_accept_commit(&src, &binding) == 0);
 assert(prod_source_record(&src, MIGRATION_REC_DEST_STAGED, binding.challenge) == EPROTO);
 assert(prod_dest_record(&dst, MIGRATION_REC_SOURCE_INTENT, binding.challenge) == EPROTO);
 assert(prod_dest_record(&dst, MIGRATION_REC_DEST_STAGED, binding.challenge) == 0);
 assert(prod_source_record(&src, MIGRATION_REC_SOURCE_INTENT, binding.challenge) == 0);
 assert(src.retirement_started);
 assert(prod_source_record(&src, MIGRATION_REC_SOURCE_RETIRED, binding.challenge) == EPROTO);
 src.retired = true;
 assert(prod_source_record(&src, MIGRATION_REC_SOURCE_RETIRED, binding.challenge) == 0);
 assert(prod_source_record(&src, MIGRATION_REC_SOURCE_RELEASED, binding.challenge) == 0);
 assert(prod_dest_record(&dst, MIGRATION_REC_DEST_RELEASED, binding.challenge) == 0);
 assert(prod_dest_record(&dst, MIGRATION_REC_DEST_RUNNING, binding.challenge) == EPROTO);
 dst.running = true;
 assert(prod_dest_record(&dst, MIGRATION_REC_DEST_RUNNING, binding.challenge) == 0);
 assert(prod_source_record(&src, MIGRATION_REC_SOURCE_CONFIRMED, binding.challenge) == 0);
 uint16_t phase = 0;
 assert(migration_recovery_load_at(fd, &src.recovery, &phase) == 0);
 assert(phase == MIGRATION_REC_SOURCE_CONFIRMED);
 assert(migration_recovery_load_at(fd, &dst.recovery, &phase) == 0);
 assert(phase == MIGRATION_REC_DEST_RUNNING);
 close(fd);
 for (int failure = 1; failure <= 4; failure++) {
  char path[] = "intent-failure.XXXXXX"; assert(mkdtemp(path));
  int retryfd = open(path, O_RDONLY | O_DIRECTORY); assert(retryfd >= 0);
  if (src.controller_held) close(src.controller_fd);
  src.controller_held = false;
  src.recovery_dirfd = retryfd; src.recovery.phase = 0;
  src.retired = src.retirement_started = src.intent_pending = false;
  fail_at = failure; syncs = 0;
  assert(prod_source_record(&src, MIGRATION_REC_SOURCE_INTENT, binding.challenge) == EIO);
  assert(src.retirement_started && src.intent_pending && !src.retired);
  fail_at = 0;
  assert(prod_source_record(&src, MIGRATION_REC_SOURCE_INTENT, binding.challenge) == 0);
  assert(src.retirement_started && !src.intent_pending && !src.retired);
  assert(migration_recovery_load_at(retryfd, &src.recovery, &phase) == 0);
  assert(phase == MIGRATION_REC_SOURCE_INTENT);
  close(retryfd);
 }
 return 0;
}
'''
(out / 'adapter.c').write_text(fixture)
# The extraction carries the destination resolution journal helper, which
# this source-side fixture does not call.
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
    '-fsanitize=address,undefined', '-I' + str(root / 'sys'),
    '-I' + str(root / 'usr.sbin/bhyve'), str(out / 'adapter.c'), '-Wl,--wrap=fsync', '-lmd', '-lz',
    '-o', str(out / 'adapter')], check=True)
subprocess.run([str(out / 'adapter')], cwd=out, check=True, timeout=30)
