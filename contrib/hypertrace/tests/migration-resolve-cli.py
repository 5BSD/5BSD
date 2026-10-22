#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
# bhyvectl --migrate-resolve: the request carries exactly one action-specific
# confirmation, wrong or missing confirmations are refused before any IPC, and
# success needs resolved=true with nothing left retained.  The IPC boundary is
# a stub; the production request function is extracted from bhyvectl.c.
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
s = (root / 'usr.sbin/bhyvectl/bhyvectl.c').read_text()
start = s.index('static int\nmigration_resolve_request(')
end = s.index('\n}\n', start) + 3		# the request function only
fixture = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/nv.h>
static int mode, calls;
static const char *want_action, *want_flag;
static int ipc_send_message(const char *vm, nvlist_t *request, const char *dir,
 nvlist_t **reply) {
 assert(strcmp(vm, "kept") == 0 && strcmp(dir, "/test") == 0);
 assert(strcmp(nvlist_get_string(request, "cmd"), "migrate_resolve") == 0);
 assert(strcmp(nvlist_get_string(request, "action"), want_action) == 0);
 /* Exactly the confirmation that belongs to the action, and nothing else. */
 assert(nvlist_exists_bool(request, want_flag) && nvlist_get_bool(request, want_flag));
 assert(!nvlist_exists(request, strcmp(want_flag, "source_retired") == 0 ?
  "acknowledge_loss" : "source_retired"));
 calls++; nvlist_destroy(request);
 switch (mode) {
 case 1: return EPIPE;			/* transport error passes through */
 case 2: return 0;			/* no reply at all */
 }
 *reply = nvlist_create(0);
 if (mode != 3) nvlist_add_bool(*reply, "resolved", mode != 4 && mode < 7);
 if (mode != 5) nvlist_add_bool(*reply, "retained", mode == 6);
 if (mode == 7) nvlist_add_number(*reply, "error_code", EBUSY);
 if (mode == 8) nvlist_add_number(*reply, "error_code", (uint64_t)INT_MAX + 1);
 if (mode == 9) nvlist_add_number(*reply, "error_code", 0);
 return 0;
}
'''
fixture += s[start:end]
fixture += r'''
int main(void) {
 static const int want[] = { 0, EPIPE, EPROTO, EPROTO, EPROTO, EPROTO, EPROTO,
  EBUSY, EPROTO, EPROTO };
 /* Mode 0 succeeds; 7 maps the controller's error_code; 8 and 9 carry an
  * unusable error_code and stay EPROTO; the rest lack a strict success reply. */
 for (int pass = 0; pass < 2; pass++) {
  want_action = pass == 0 ? "resume" : "discard";
  want_flag = pass == 0 ? "source_retired" : "acknowledge_loss";
  for (mode = 0; mode < 10; mode++) {
   int before = calls;
   int error = migration_resolve_request("kept", "/test", want_action,
    pass == 0, pass != 0);
   if (error != want[mode]) { fprintf(stderr, "%s mode %d: %d\n", want_action, mode, error); return 1; }
   assert(calls == before + 1);
  }
 }
 /* Refused before IPC: no action, unknown action, missing confirmation, the
  * other action's confirmation, or both confirmations. */
 calls = 0; mode = 0;
 assert(migration_resolve_request("kept", "/test", NULL, true, false) == EINVAL);
 assert(migration_resolve_request("kept", "/test", "export", true, false) == EINVAL);
 assert(migration_resolve_request("kept", "/test", "Resume", true, false) == EINVAL);
 assert(migration_resolve_request("kept", "/test", "resume", false, false) == EINVAL);
 assert(migration_resolve_request("kept", "/test", "resume", false, true) == EINVAL);
 assert(migration_resolve_request("kept", "/test", "resume", true, true) == EINVAL);
 assert(migration_resolve_request("kept", "/test", "discard", false, false) == EINVAL);
 assert(migration_resolve_request("kept", "/test", "discard", true, false) == EINVAL);
 assert(migration_resolve_request("kept", "/test", "discard", true, true) == EINVAL);
 assert(calls == 0);
 return 0;
}
'''
(out / 'resolve.c').write_text(fixture)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    str(out / 'resolve.c'), '-lnv', '-o', str(out / 'resolve')], check=True)
subprocess.run([str(out / 'resolve')], cwd=out, check=True, timeout=30)
print('PASS: migrate-resolve CLI sends one action-bound confirmation, refuses the rest before IPC, and requires a strict resolved reply')
