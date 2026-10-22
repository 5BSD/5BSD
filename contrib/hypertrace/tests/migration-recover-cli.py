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
s = (root / 'usr.sbin/bhyvectl/bhyvectl.c').read_text()
start = s.index('static int\nmigration_control_request(')
end = s.index('#endif', start)
fixture = r'''
#include <assert.h>
#include <sys/nv.h>
#include <fcntl.h>
#include <unistd.h>
#include "migration_credentials.h"
#include "migration_session.h"
static bool recover = true;
static int mode, calls;
static int ipc_send_message(const char *vm, nvlist_t *request, const char *dir,
 nvlist_t **reply) {
 assert(strcmp(vm, "retired") == 0 && strcmp(dir, "/test") == 0);
 assert(strcmp(nvlist_get_string(request, "cmd"), recover ? "migrate_recover" : "migrate") == 0);
 const char *fds[] = {"fd", "tls_certificate_fd", "tls_private_key_fd", "tls_trust_fd"};
 if (nvlist_exists(request, "plaintext_unix")) {
  /* --migrate-plaintext-unix: only the stream, the opt-in, and no TLS. */
  assert(!recover && nvlist_get_bool(request, "plaintext_unix"));
  assert(fcntl(nvlist_get_descriptor(request, "fd"), F_GETFD) >= 0);
  for (unsigned i=1; i<4; i++) assert(!nvlist_exists(request, fds[i]));
  assert(!nvlist_exists(request, "tls_peer_sha256"));
 } else
 for (unsigned i=0; i<4; i++) assert(fcntl(nvlist_get_descriptor(request, fds[i]), F_GETFD) >= 0);
 assert(!nvlist_exists(request, "recovery_fddir"));
 calls++; nvlist_destroy(request);
 if (mode == 1) return EPIPE;
 if (mode == 2) return 0;
 *reply = nvlist_create(0);
 if (mode != 3) nvlist_add_bool(*reply, "confirmed", mode != 4);
 if (mode == 9) nvlist_add_string(*reply, "phase", "completed");
 else if (mode != 3) nvlist_add_number(*reply, "phase", mode == 4 ? MIGRATION_PHASE_RECOVERY : MIGRATION_PHASE_COMPLETED);
 if (mode == 10) nvlist_add_string(*reply, "reason", "none");
 else if (mode != 7) nvlist_add_number(*reply, "reason", mode == 8 ? MIGRATION_REASON_STATE : MIGRATION_REASON_NONE);
 if (mode == 11) nvlist_add_number(*reply, "source_runnable", 0);
 else if (mode != 5) nvlist_add_bool(*reply, "source_runnable", mode == 6);
 return 0;
}
'''
fixture += s[start:end]
fixture += r'''
int main(void) {
 int fd = open("/dev/null", O_RDONLY); assert(fd >= 0);
 char number[32]; snprintf(number, sizeof(number), "%d", fd);
 const char *values[5] = { number, number, number, number,
  "0404040404040404040404040404040404040404040404040404040404040404" };
 for (mode=0; mode<7; mode++) {
  int error = migration_control_request("retired", "/test", values, recover, false);
  assert(error == (mode == 0 ? 0 : mode == 1 ? EPIPE : EPROTO));
  assert(fcntl(fd, F_GETFD) >= 0);
 }
 recover = false;
 for (mode=0; mode<12; mode++) {
  int error = migration_control_request("retired", "/test", values, recover, false);
  assert(error == (mode == 0 ? 0 : mode == 1 ? EPIPE : EPROTO));
  assert(fcntl(fd, F_GETFD) >= 0);
 }
 /* Plaintext: migration only, and never together with credentials. */
 {
  const char *plain[5] = { number, NULL, NULL, NULL, NULL };
  mode = 0; assert(migration_control_request("retired", "/test", plain, false, true) == 0);
  recover = true;
  assert(migration_control_request("retired", "/test", plain, true, true) == EINVAL);
  recover = false;
  assert(migration_control_request("retired", "/test", values, false, true) == EINVAL);
 }
 calls = 0;
 for (unsigned i=0; i<5; i++) {
  const char *saved = values[i]; values[i] = NULL;
  assert(migration_control_request("retired", "/test", values, recover, false) == EINVAL);
  values[i] = saved;
 }
 values[0] = "-1"; assert(migration_control_request("retired", "/test", values, recover, false) == EINVAL);
 values[0] = "123x"; assert(migration_control_request("retired", "/test", values, recover, false) == EINVAL);
 values[0] = number; close(fd);
 assert(migration_control_request("retired", "/test", values, recover, false) == EBADF);
 assert(calls == 0); return 0;
}
'''
fixture = '#include <stdio.h>\n' + fixture
(out / 'cli.c').write_text(fixture)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-I' + str(root / 'usr.sbin/bhyve'), str(out / 'cli.c'), '-lnv',
    '-o', str(out / 'cli')], check=True)
subprocess.run([str(out / 'cli')], cwd=out, check=True, timeout=30)
print('PASS: migration initiation/recovery CLI descriptor ownership, credentials and strict completion')
