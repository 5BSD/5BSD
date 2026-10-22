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
fixture = r'''
#define BHYVE_SNAPSHOT 1
#include <assert.h>
#include "migration_session.h"
#include "migration_source_owner.h"
#include "hypertrace.h"
static int rootfd, root_calls, query_calls, query_closes, recover_calls, mode;
static int test_root(int *fd) { root_calls++; *fd = dup(rootfd); return *fd < 0 ? errno : 0; }
static int test_query(void) { query_calls++; return mode == 3 ? ENXIO : 0; }
static void test_close_query(void) { query_closes++; }
static int test_recover(int fd, int directory, uint16_t vmid, uint64_t epoch,
 const struct migration_tls_credentials *credentials, const char *name) {
 assert(name == NULL || strcmp(name, "orphan") == 0);
 assert(fd >= 0 && directory >= 0 && vmid == 7 && epoch == 9 && credentials);
 assert(fcntl(fd, F_GETFD) & FD_CLOEXEC); recover_calls++;
 return mode == 2 ? EPIPE : 0;
}
#define migration_source_canonical_root_open test_root
#define hypertrace_session_recovery_open test_query
#define hypertrace_session_recovery_close test_close_query
#define migration_prod_source_recover_restart_named test_recover
#include "migration_restart_command.h"
int main(void) {
 uint64_t number = 123;
 const char *bad[] = {NULL, "", "-1", "+1", " 1", "1 ", "1x", "0x10", "18446744073709551616"};
 for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
  assert(migration_restart_number(bad[i], UINT64_MAX, &number) == EINVAL);
  assert(number == 123);
 }
 assert(migration_restart_number("18446744073709551615", UINT64_MAX, &number) == 0 && number == UINT64_MAX);
 int sockets[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
 FILE *credential = tmpfile(); assert(credential);
 char socktext[32], credtext[32], pin[65];
 snprintf(socktext, sizeof(socktext), "%d", sockets[0]);
 snprintf(credtext, sizeof(credtext), "%d", fileno(credential));
 memset(pin, 'a', 64); pin[64] = 0;
 const char *values[] = {socktext, "7", "9", credtext, credtext, credtext, pin};
 assert(migration_restart_command_named(values, true, NULL) == EINVAL);
 for (int i = 0; i < 7; i++) {
  const char *saved = values[i]; values[i] = NULL;
  assert(migration_restart_command_named(values, false, NULL) == EINVAL); values[i] = saved;
 }
 assert(root_calls == 0 && query_calls == 0 && recover_calls == 0);
 for (mode = 0; mode < 4; mode++) {
  char directory[] = "command.XXXXXX"; assert(mkdtemp(directory));
  rootfd = open(directory, O_RDONLY | O_DIRECTORY); assert(rootfd >= 0);
  struct migration_recovery_record binding = {.phase = MIGRATION_REC_SOURCE_INTENT,
   .destination_vmid = 8, .destination_epoch = 10};
  struct hypertrace_session_record session = {.vmid = 7, .epoch = 9,
   .stop_token = 11, .features = HYPERTRACE_SESSION_FEATURES};
  assert(hypertrace_session_record_encode(binding.session, 40, &session) == 0);
  memset(binding.challenge, 1, 32); memset(binding.state_digest, 2, 32);
  memset(binding.source_certificate_sha256, 3, 32); memset(binding.destination_certificate_sha256, 4, 32);
  query_calls = query_closes = recover_calls = 0;
  assert(migration_restart_command_named(values, false, NULL) == ENOENT);
  assert(query_calls == 0 && recover_calls == 0);
  assert(migration_source_owner_at(rootfd, &binding, true) == 0);
  assert(migration_recovery_store_at(rootfd, &binding) == 0);
  if (mode == 1) { binding.phase = MIGRATION_REC_SOURCE_RETIRED; assert(migration_recovery_store_at(rootfd, &binding) == 0); }
  assert(migration_restart_command_named(values, false, NULL) == (mode == 2 ? EPIPE : mode == 3 ? ENXIO : 0));
  assert(query_calls == (mode == 1 ? 0 : 1));
  assert(query_closes == (mode == 0 || mode == 2 ? 1 : 0));
  assert(recover_calls == (mode == 3 ? 0 : 1));
  if (mode == 0) {
   assert(migration_restart_command_named(values, false, "orphan") == 0);
   assert(recover_calls == 2 && query_calls == 2 && query_closes == 2);
  }
  close(rootfd);
 }
 close(sockets[0]); close(sockets[1]); fclose(credential);
 return 0;
}
'''
(out / 'command.c').write_text(fixture)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-I' + str(root / 'sys'), '-I' + str(root / 'usr.sbin/bhyve'),
    '-I' + str(root / 'usr.sbin/dtraced'),
    str(out / 'command.c'), '-lmd', '-o', str(out / 'command')], check=True)
subprocess.run([str(out / 'command')], cwd=out, check=True, timeout=30)
print('PASS: restart command validation, durable ownership, query-device necessity and cleanup; no VM/device operation')
