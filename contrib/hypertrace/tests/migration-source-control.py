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
start = source.index('static nvlist_t *\nvm_do_migrate_recover(')
end = source.index('IPC_COMMAND(migrate_recover', start)
fixture = r'''
#include <assert.h>
#include <sys/nv.h>
#include "migration_source_owner.h"
#include "migration_credentials_nv.h"
struct vmctx { int unused; };
struct migration_transport { int unused; };
struct migration_channel { int unused; };
struct migration_prod_source {
 struct vmctx *ctx;
 bool retirement_started, fresh_stopped, retired, intent_pending, quiesced;
 int recovery_dirfd;
 struct migration_recovery_record recovery;
};
static struct migration_prod_source migration_ipc_source;
static int mode, connects, finishes, releases, cleanups, records;
static struct vmctx original;
static int migration_channel_init(struct migration_channel *c,
 struct migration_transport *xp, int fd, bool server,
 const struct migration_tls_credentials *credentials, int timeout) {
 (void)c; (void)xp; assert(fd >= 0 && !server && credentials && timeout == 30000);
 connects++; return mode == 5 ? EACCES : 0;
}
static int migration_channel_binding(const struct migration_channel *c, bool source,
 uint8_t *src, uint8_t *dst) {
 (void)c; assert(source);
 memset(src, mode == 6 ? 5 : 3, 32); memset(dst, mode == 7 ? 5 : 4, 32);
 return 0;
}
static int prod_source_record(void *arg, enum migration_recovery_phase phase,
 const uint8_t *challenge) {
 struct migration_prod_source *src = arg;
 assert(src == &migration_ipc_source && phase == MIGRATION_REC_SOURCE_INTENT);
 assert(challenge == src->recovery.challenge && connects >= 1);
 records++;
 if (mode == 11) return EIO;
 src->intent_pending = false; return 0;
}
static int migration_prod_source_finish_intent(struct vmctx **ctx, int dirfd,
 const struct migration_recovery_record *expected) {
 assert(ctx == &migration_ipc_source.ctx && dirfd == 123);
 assert(expected == &migration_ipc_source.recovery);
 finishes++; *ctx = NULL; return mode == 8 ? EIO : 0;
}
static int migration_recovery_source_run(struct migration_channel *c,
 const struct migration_transport *xp, int dirfd,
 const struct migration_recovery_record *expected) {
 (void)c; (void)xp; assert(dirfd == 123 && expected == &migration_ipc_source.recovery);
 assert(migration_ipc_source.ctx == NULL && migration_ipc_source.retired);
 releases++; return mode == 9 ? EPIPE : 0;
}
static void migration_channel_cleanup(struct migration_channel *c) { (void)c; cleanups++; }
'''
fixture += source[start:end]
fixture += r'''
int main(void) {
 const int errors[] = {EOPNOTSUPP, EINVAL, EINVAL, EACCES, EINVAL,
  EACCES, EACCES, EACCES, EIO, EPIPE, 0, EIO, 0, ESTALE, ESTALE, ESTALE};
 int fd = open("/dev/null", O_RDONLY); assert(fd >= 0);
 for (mode = 0; mode <= 15; mode++) {
  migration_ipc_source = (struct migration_prod_source){ .ctx = &original,
   .retirement_started = mode != 0, .fresh_stopped = true, .recovery_dirfd = 123,
   .quiesced = true, .intent_pending = mode >= 11 || mode < 8 };
  if (mode == 13) migration_ipc_source.quiesced = false;
  if (mode == 14) migration_ipc_source.retired = true;
  if (mode == 15) migration_ipc_source.ctx = NULL;
  memset(migration_ipc_source.recovery.source_certificate_sha256, 3, 32);
  memset(migration_ipc_source.recovery.destination_certificate_sha256, 4, 32);
  connects = finishes = releases = cleanups = records = 0;
  nvlist_t *request = nvlist_create(0);
  if (mode != 1) nvlist_add_descriptor(request, "fd", fd);
  if (mode == 2) nvlist_add_number(request, "recovery_fddir", 999);
  if (mode != 3) nvlist_add_descriptor(request, "tls_certificate_fd", fd);
  if (mode != 3 && mode != 4) {
   nvlist_add_descriptor(request, "tls_private_key_fd", fd);
   nvlist_add_descriptor(request, "tls_trust_fd", fd);
   nvlist_add_string(request, "tls_peer_sha256",
    "0404040404040404040404040404040404040404040404040404040404040404");
  }
  nvlist_t *reply = vm_do_migrate_recover(NULL, request);
  assert(nvlist_get_bool(reply, "confirmed") == (errors[mode] == 0));
  if (errors[mode]) assert(nvlist_get_number(reply, "error_code") == (uint64_t)errors[mode]);
  assert(!nvlist_get_bool(reply, "source_runnable"));
  if (mode == 0) {
   /* Uncommitted quiescence is stopped, but is not retirement authority. */
   assert(connects == 0 && finishes == 0 && releases == 0 && records == 0);
   migration_ipc_source.quiesced = false;
   nvlist_t *running = vm_do_migrate_recover(NULL, request);
   assert(nvlist_get_bool(running, "source_runnable"));
   assert(nvlist_get_number(running, "error_code") == EOPNOTSUPP);
   nvlist_destroy(running);
   migration_ipc_source.quiesced = true;
  }
  assert(connects == (mode >= 5)); assert(cleanups == (mode >= 6));
  assert(finishes == (mode >= 8 && mode != 11 && mode < 13)); assert(releases == (mode >= 9 && mode != 11 && mode < 13));
  assert(records == (mode >= 11 && mode < 13));
  if (mode < 8 || mode == 11 || mode == 13 || mode == 14) assert(migration_ipc_source.ctx == &original);
  else assert(migration_ipc_source.ctx == NULL);
  if (mode == 8 || mode == 9 || mode == 11) {
   int saved = mode; mode = 10;
   nvlist_t *retry = vm_do_migrate_recover(NULL, request);
   assert(nvlist_get_bool(retry, "confirmed"));
   assert(!nvlist_get_bool(retry, "source_runnable"));
   assert(migration_ipc_source.ctx == NULL);
   nvlist_destroy(retry); mode = saved;
  }
  nvlist_destroy(reply); nvlist_destroy(request);
 }
 close(fd); return 0;
}
'''
(out / 'control.c').write_text(fixture)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-I' + str(root / 'sys'), '-I' + str(root / 'usr.sbin/bhyve'),
    str(out / 'control.c'), '-lnv', '-lmd', '-o', str(out / 'control')], check=True)
subprocess.run([str(out / 'control')], cwd=out, check=True, timeout=30)
print('PASS: source recovery IPC authentication, fixed ownership, failure ordering and retry')
