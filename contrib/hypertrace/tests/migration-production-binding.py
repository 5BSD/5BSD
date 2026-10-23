#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise production setup ordering with failed certificate export; no VM I/O."""
from pathlib import Path
import subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/migration_session.c').read_text()
a = source.index('\tmemset(&result, 0, sizeof(result));', source.index('vm_do_migrate(struct'))
b = source.index('\n\tmigration_channel_cleanup(&channel);', a)
source_block = source[a:b]
a = source.index('\tif (channel.secure)', source.index('migration_prod_dest_serve_impl('))
b = source.index('\n\tmigration_channel_cleanup(&channel);', a)
dest_block = source[a:b]
fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#define MIGRATION_PHASE_FAILED 9
#define MIGRATION_REASON_TRANSPORT 3
struct result { int phase, reason; bool source_runnable; };
struct channel { bool secure; };
struct owner { struct { uint8_t source_certificate_sha256[32], destination_certificate_sha256[32]; } recovery; };
static int binding_error, bindings, runs;
static bool source_side;
static int migration_channel_binding(struct channel *c, bool source, uint8_t *src, uint8_t *dst) {
 assert(c->secure && source == source_side); bindings++;
 if (binding_error) return binding_error;
 memset(src, 3, 32); memset(dst, 4, 32); return 0;
}
/* Merged: active vsock installs the four relay hooks on a copy of the table. */
typedef int (*hook_t)(void *);
struct sops { int base; hook_t so_vsock_state, so_prepare_relay, so_cancel_relay, so_activate_relay; };
static int prod_vsock_state(void *a) { (void)a; return 1; }
static int prod_prepare_vsock_relay(void *a) { (void)a; return 2; }
static int prod_cancel_vsock_relay(void *a) { (void)a; return 3; }
static int prod_activate_vsock_relay(void *a) { (void)a; return 4; }
static bool vsock_expected, source_run;
static int run(int *xp, void *opsp, struct owner *owner, int *config, struct result *result) {
 (void)xp; (void)config; (void)result;
 if (source_run) {
  struct sops *ops = opsp;
  assert(ops->base == 7);
  if (vsock_expected) assert(ops->so_vsock_state == prod_vsock_state && ops->so_prepare_relay == prod_prepare_vsock_relay && ops->so_cancel_relay == prod_cancel_vsock_relay && ops->so_activate_relay == prod_activate_vsock_relay);
  else assert(!ops->so_vsock_state && !ops->so_prepare_relay && !ops->so_cancel_relay && !ops->so_activate_relay);
 }
 if (bindings) assert(owner->recovery.source_certificate_sha256[0] == 3 && owner->recovery.destination_certificate_sha256[0] == 4);
 runs++; return 0;
}
#define migration_source_run run
#define migration_dest_run run
static void check_source(bool secure, bool active_vsock) {
 struct owner owner = {0}, *src = &owner;
 struct channel channel = {secure}; struct result result;
 struct sops ops, migration_prod_source_ops = { .base = 7 };
 int error = 0, xp = 0, config = 0;
 vsock_expected = active_vsock; source_run = true;
'''+source_block+r'''
 assert(error == (secure ? binding_error : 0));
 if (secure && binding_error) assert(result.phase == MIGRATION_PHASE_FAILED && result.reason == MIGRATION_REASON_TRANSPORT && result.source_runnable);
}
static void check_dest(bool secure) {
 struct owner owner = {0}, *dst = &owner;
 struct channel channel = {secure}; struct result value = {0}, *result = &value;
 int error = 0, xp = 0, ops = 0, config_value = 0, *config = &config_value;
'''+dest_block+r'''
 assert(error == (secure ? binding_error : 0));
 if (secure && binding_error) assert(result->phase == MIGRATION_PHASE_FAILED && result->reason == MIGRATION_REASON_TRANSPORT);
}
int main(void) {
 const int errors[] = {0, EACCES, EIO, EOPNOTSUPP};
 for (unsigned side=0; side<2; side++) for (unsigned secure=0; secure<2; secure++)
  for (unsigned i=0; i<sizeof(errors)/sizeof(errors[0]); i++) {
   bindings=runs=0; binding_error=errors[i]; source_side=side;
   source_run = false;
   if (side) check_source(secure, i & 1); else check_dest(secure);
   assert(bindings == (int)secure);
   assert(runs == ((!secure || !binding_error) ? 1 : 0));
  }
 return 0;
}
'''
(out / 'binding.c').write_text(fixture)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', str(out / 'binding.c'), '-o', str(out / 'binding')], check=True)
subprocess.run([str(out / 'binding')], check=True, timeout=30)
print('PASS: both production adapters stop before migration on TLS binding errors; plaintext behavior unchanged')
