#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise actual production owner lifetime without a kernel, VM, or network."""
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/migration_session.c').read_text()
runtime = (root / 'usr.sbin/bhyve/migration_recovery_execute.h').read_text()
runtime = runtime[runtime.index('struct migration_recovery_run_state {'):runtime.index('static inline void')]
resume_adapter = source[source.index('static int\nprod_dest_resume('):source.index('static int\nprod_prepare_commit(')]
structure = source[source.index('struct migration_prod_dest {'):source.index('static int\nprod_dest_local_hello(')]
def strip_resolution(text):
    """Drop the operator-resolution section (migrate_resolve IPC, the
    resolution wait and its notification); this fixture does not model IPC."""
    a = text.find('/*\n * Operator resolution of a retained inbound migration')
    if a < 0:
        return text
    end = 'IPC_COMMAND(migrate_resolve, vm_do_migrate_resolve);\n'
    return text[:a] + text[text.index(end, a) + len(end):]


functions = source[source.index('static void\nprod_dest_retain('):source.index('int\nmigration_prod_source_finish_intent(')]
functions = strip_resolution(functions)
fixture = r'''
#define BHYVE_SNAPSHOT 1
#include <assert.h>
#include <err.h>
#include "migration_session.h"
#include "migration_source_owner.h"
#include "migration_reconcile.h"
#include "migration_credentials.h"
#include "migration_dest_image.h"
#include "migration_snapshot.h"
#include "migration_vsock_bundle.h"
#include "migration_vsock_relay.h"
struct vmctx { int unused; };
/* Merged active-vsock destination: opt-in, staging hook, relay owner. */
static bool active_vsock_config, stage_vsock_hook;
static bool get_config_bool_default(const char *key, bool def) {
 assert(strcmp(key, "checkpoint.migrate_active_vsock") == 0 && !def);
 return active_vsock_config;
}
static int prod_dest_stage_vsock(void *a, const uint8_t *b, size_t l) { (void)a; (void)b; (void)l; abort(); }
static int owner_activates, owner_activate_error, owner_detaches;
static int migration_vsock_owner_activate(void) { owner_activates++; return owner_activate_error; }
static void migration_vsock_owner_detach(void) { owner_detaches++; }
/* Image preservation/reconstruction is exercised by migration-dest-reconstruct;
 * this fixture keeps those paths inert while compiling the actual code. */
static void *vm_map_gpa(struct vmctx *c, uint64_t g, size_t l) { (void)c; (void)g; (void)l; return (NULL); }
static uint64_t vm_get_lowmem_size(struct vmctx *c) { (void)c; return (4096); }
static uint64_t vm_get_highmem_size(struct vmctx *c) { (void)c; return (0); }
static uint64_t vm_get_highmem_base(struct vmctx *c) { (void)c; return (0); }
static int hypertrace_session_retired(uint16_t v, uint64_t e) { (void)v; (void)e; abort(); }
static int vm_destroy_name_identity_checked(const char *n, uint16_t v, uint64_t e) { (void)n; (void)v; (void)e; abort(); }
struct pci_devinst;
static int vm_migrate_fresh_commit_state(struct vmctx *c, const uint8_t *b, size_t l,
 struct pci_devinst **d) { (void)c; (void)b; (void)l; (void)d; abort(); }
struct migration_channel { bool secure; };
static bool tracing, fail_alloc;
static int mode, journal_copy, cleaned, calls;
static uint16_t live_vmid = 8;
static uint64_t live_epoch = 10;
static bool startup_held = true, fail_resume;
static int resume_calls, destination_runs;
static bool preserve_hook;
static int vsock_endpoint_fd = -1;
static bool checkpoint_restore_startup_held(void) { return startup_held; }
struct pci_devinst;
static int vm_migrate_fresh_resume(struct vmctx *ctx, struct pci_devinst *device,
 const uint8_t record[40]) {
 (void)ctx; assert(device && record && startup_held); resume_calls++;
 if (fail_resume) return EIO;
 startup_held = false; return 0;
}
static int vm_migrate_resume(struct vmctx *ctx) { (void)ctx; assert(false); return EINVAL; }
static int vm_get_identity(struct vmctx *ctx, uint16_t *vmid, uint64_t *epoch) {
 (void)ctx; *vmid = live_vmid; *epoch = live_epoch; return 0;
}
static bool hypertrace_initialized(void) { return tracing; }
static void *owner_calloc(size_t n, size_t size) {
 if (fail_alloc) return NULL;
 return calloc(n, size);
}
static int migration_channel_init(struct migration_channel *c,
 struct migration_transport *xp, int fd, bool server,
 const struct migration_tls_credentials *credentials, int timeout) {
 (void)xp; (void)fd; (void)server; (void)credentials; (void)timeout;
 c->secure = tracing && credentials != NULL; return mode == 4 ? EACCES : 0;
}
/* Mirrors migration_channel.h: no credentials and no opt-in is refused. */
static int migration_channel_policy(int fd, bool credentials, bool plaintext) {
 (void)fd; return credentials || plaintext ? 0 : EACCES;
}
static void migration_channel_cleanup(struct migration_channel *c) {
 (void)c; cleaned++;
}
static int migration_channel_binding(const struct migration_channel *c,
 bool source, uint8_t s[32], uint8_t d[32]) {
 assert(c->secure && !source);
 memset(s, 3, 32); memset(d, 4, 32); return mode == 10 ? EIO : 0;
}
static const struct migration_dest_ops migration_prod_dest_ops = {0};
'''
fixture += runtime + structure + resume_adapter + r'''
static int migration_recovery_destination_run(struct migration_channel *channel,
 const struct migration_transport *xp, int dirfd,
 const struct migration_recovery_record *expected,
 const struct migration_recovery_run_ops *ops, void *arg,
 struct migration_recovery_run_state *state) {
 (void)channel; (void)xp; (void)dirfd; (void)expected; destination_runs++;
 int error = ops->observe(arg, &state->observed);
 if (error) return error;
 if (state->observed == MIGRATION_REC_VM_PAUSED) {
  state->resume_uncertain = true;
  error = ops->resume(arg); if (error) return error;
  error = ops->observe(arg, &state->observed); if (error) return error;
  assert(state->observed == MIGRATION_REC_VM_RUNNING);
  state->resume_uncertain = false;
 }
 state->ack_sent = mode != 7; return mode == 7 ? EPIPE : 0;
}
int migration_dest_run(const struct migration_transport *xp,
 const struct migration_dest_ops *ops, void *arg,
 const struct migration_session_config *config, struct migration_dest_result *result) {
 (void)xp; (void)config; calls++;
 preserve_hook = ops->do_preserve != NULL;
 stage_vsock_hook = ops->do_stage_vsock == prod_dest_stage_vsock;
 struct migration_prod_dest *dst = arg;
 if (mode == 12) {
  /* A staged vsock bundle and its endpoints: the serve adapter scrubs the
   * blob and closes the endpoint copies; the relay owner keeps its own. */
  int pipefd[2]; assert(pipe(pipefd) == 0); close(pipefd[1]);
  dst->vsock_blob = malloc(16); assert(dst->vsock_blob); dst->vsock_len = 16;
  dst->vsock_endpoints[0].fd = pipefd[0]; dst->vsock_endpoint_count = 1;
  vsock_endpoint_fd = pipefd[0];
  result->resumed = false; return 0;
 }
 journal_copy = dst->recovery_dirfd;
 if (ops->do_retain == NULL) return EOPNOTSUPP;
 dst->dev_blob = malloc(64); assert(dst->dev_blob);
 memset(dst->dev_blob, 0x51, 64); dst->dev_len = 64;
 if (mode == 8 || mode == 9) {
  dst->committed = true; dst->running = true;
  dst->fresh_device = (struct pci_devinst *)dst;
  dst->retained_binding.destination_epoch = 10;
  result->resumed = true; result->release_ack_sent = mode == 8;
  return 0;
 }
 if (mode == 11) {
  struct migration_commit_binding binding = {.destination_vmid=8, .destination_epoch=10};
  dst->committed=true; dst->fresh_device=(struct pci_devinst *)dst;
  int error=prod_dest_resume(dst); assert(error==EIO);
  ops->do_retain(dst,&binding);
  result->retained=true; result->phase=MIGRATION_PHASE_RECOVERY;
  return error;
 }
 if (mode == 0) {
  struct migration_commit_binding binding = { .destination_vmid = 8,
   .destination_epoch = 10 };
  memset(binding.challenge, 7, 32);
  dst->committed = true;
  ops->do_retain(dst, &binding);
  result->retained = true; result->phase = MIGRATION_PHASE_RECOVERY;
  return ETIMEDOUT;
 }
 result->resumed = mode == 1;
 return mode == 1 ? 0 : EIO;
}
#define calloc owner_calloc
'''
fixture += functions + r'''
#undef calloc
int main(void) {
 char directory[] = "owner.XXXXXX";
 assert(mkdtemp(directory) && chdir(directory) == 0);
 struct vmctx ctx = {0}; struct migration_dest_result result;
 struct migration_session_config config = { .recovery_enabled = true };
 struct migration_prod_dest *owner = NULL;
 int fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC); assert(fd >= 0);
 config.recovery_dirfd = fd;
 /* Neither credentials nor the plaintext opt-in: refused before any owner. */
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == EACCES && !owner);
 config.plaintext_unix = true;
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == ETIMEDOUT);
 assert(owner && result.retained && owner->ctx == &ctx && owner->committed && !owner->running);
 assert(owner->dev_len == 64 && owner->dev_blob[63] == 0x51);
 assert(owner->retained_binding.destination_epoch == 10 && owner->retained_binding.challenge[31] == 7);
 struct migration_prod_dest *previous = owner;
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == EBUSY && owner == previous);
 assert(journal_copy != fd && (fcntl(journal_copy, F_GETFD) & FD_CLOEXEC));
 close(fd); assert(fcntl(journal_copy, F_GETFD) >= 0);
 /* Exercise the actual reconnect adapter before handing off to the separately
  * tested TLS exchange. Identity/image changes must fail before transport. */
 owner->fresh_device = (struct pci_devinst *)&ctx;
 owner->recovery.phase = MIGRATION_REC_DEST_STAGED;
 owner->recovery.destination_vmid = 8; owner->recovery.destination_epoch = 10;
 memcpy(owner->recovery.challenge, owner->retained_binding.challenge, 32);
 struct hypertrace_session_record stopped = { .vmid=7, .epoch=9,
  .stop_token=11, .features=HYPERTRACE_SESSION_FEATURES };
 assert(hypertrace_session_record_encode(owner->fresh_record, 40, &stopped) == 0);
 memcpy(owner->recovery.session, owner->fresh_record, 40);
 SHA256_CTX hash; SHA256_Init(&hash); SHA256_Update(&hash, owner->dev_blob, owner->dev_len);
 SHA256_Final(owner->recovery.state_digest, &hash);
 memcpy(owner->retained_binding.state_digest, owner->recovery.state_digest, 32);
 struct migration_tls_credentials credentials = {0};
 struct migration_recovery_record local = {0};
 /* Identity/image changes fail in the reconnect adapter before transport. */
 tracing = true;
 live_vmid++;
 assert(migration_prod_dest_recover_release(owner, -1, &credentials) == ESTALE);
 live_vmid--; live_epoch++;
 assert(migration_prod_dest_recover_release(owner, -1, &credentials) == ESTALE);
 live_epoch--;
 uint8_t *mutations[] = { owner->dev_blob, owner->fresh_record,
  owner->retained_binding.challenge, owner->retained_binding.state_digest };
 for (size_t i = 0; i < sizeof(mutations)/sizeof(mutations[0]); i++) {
  *mutations[i] ^= 1;
  assert(migration_prod_dest_recover_release(owner, -1, &credentials) == ESTALE);
  *mutations[i] ^= 1;
 }
 assert(destination_runs == 0);
 tracing = false;
 assert(migration_prod_dest_recover_release(owner, -1, &credentials) == EOPNOTSUPP);
 tracing = true; startup_held = false;
 assert(migration_prod_dest_recover_release(owner, -1, &credentials) == EBUSY);
 startup_held = true; live_epoch++;
 assert(migration_prod_dest_recover_release(owner, -1, &credentials) == ESTALE);
 live_epoch--; assert(destination_runs == 0);
 mode = 7;
 assert(migration_prod_dest_recover_release(owner, -1, &credentials) == EPIPE);
 assert(owner->running && !startup_held && resume_calls == 1);
 mode = 0;
 assert(migration_prod_dest_recover_release(owner, -1, &credentials) == 0);
 assert(resume_calls == 1 && owner->run_state.ack_sent);
 /* An earlier successful ACK cannot describe a later attempt rejected before
  * the executor starts. Preserve the running VM and avoid a second resume. */
 int previous_runs = destination_runs;
 for (int failure = 0; failure < 6; ++failure) {
  owner->run_state.ack_sent = true;
  int expected;
  const struct migration_tls_credentials *supplied = &credentials;
  switch (failure) {
   case 0: supplied = NULL; expected = EINVAL; break;
   case 1: tracing = false; expected = EOPNOTSUPP; break;
   case 2: live_epoch++; expected = ESTALE; break;
   case 3: startup_held = true; expected = EBUSY; break;
   case 4: mode = 4; expected = EACCES; break;
   default: owner->run_state.resume_uncertain = true; expected = EBUSY; break;
  }
  assert(migration_prod_dest_recover_release(owner, -1, supplied) == expected);
  bool running, uncertain, acknowledged;
  migration_prod_dest_recovery_status(owner, &running, &uncertain, &acknowledged);
  assert(running && !acknowledged && uncertain == (failure == 5));
  assert(resume_calls == 1 && destination_runs == previous_runs);
  if (failure == 2) live_epoch--;
  tracing = true; startup_held = false; mode = 0;
  owner->run_state.resume_uncertain = false;
 }
 /* A distinct failed resume remains quarantined across reconnect attempts. */
 owner->running = false; startup_held = true; fail_resume = true;
 assert(migration_prod_dest_recover_release(owner, -1, &credentials) == EIO);
 assert(owner->run_state.resume_uncertain && resume_calls == 2);
 assert(migration_prod_dest_recover_release(owner, -1, &credentials) == EBUSY);
 assert(resume_calls == 2); fail_resume = false; tracing = false;
 /* Fixture teardown only: production cannot discard a retained VM this way. */
 close(journal_copy); free(owner->dev_blob); free(owner); owner = NULL;
 fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC); assert(fd >= 0);
 config.recovery_dirfd = fd;
 for (mode = 8; mode <= 9; mode++) {
  assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == 0);
  assert(owner && owner->retained && owner->running && result.resumed && !result.retained);
  assert(owner->run_state.observed == MIGRATION_REC_VM_RUNNING);
  assert(owner->retained_binding.destination_epoch == 10);
  assert(fcntl(owner->recovery_dirfd, F_GETFD) >= 0);
  close(owner->recovery_dirfd); free(owner->dev_blob); free(owner); owner = NULL;
 }
 for (mode = 1; mode <= 2; mode++) {
  assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == (mode == 1 ? 0 : EIO));
  assert(owner == NULL && !result.retained);
  assert(fcntl(journal_copy, F_GETFD) == -1 && errno == EBADF);
  assert(fcntl(fd, F_GETFD) >= 0);
 }
 mode = 4;
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == EACCES && !owner);
 fail_alloc = true;
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == ENOMEM && !owner);
 fail_alloc = false;
 /* Plaintext active vsock installs the staging hook; a successful handoff
  * without endpoints detaches the idle relay owner, a failed one does not. */
 active_vsock_config = true;
 for (mode = 1; mode <= 2; mode++) {
  int detaches = owner_detaches;
  assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == (mode == 1 ? 0 : EIO));
  assert(stage_vsock_hook && !owner);
  assert(owner_detaches == detaches + (mode == 1));
 }
 mode = 12;
 {
  int detaches = owner_detaches;
  assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == 0 && !owner);
  assert(owner_detaches == detaches);
  assert(fcntl(vsock_endpoint_fd, F_GETFD) == -1 && errno == EBADF);
 }
 active_vsock_config = false; mode = 1;
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == 0);
 assert(!stage_vsock_hook);
 mode = 0;
 /* Item 4: an ordinary destination whose COMMIT may have reached the
  * source keeps the paused image for migrate_resolve instead of failing. */
 assert(!migration_prod_dest_retained());
 assert(migration_prod_dest_serve(&ctx, -1, &config, &result) == ETIMEDOUT);
 assert(result.retained && migration_prod_dest_retained() &&
     migration_dest_retained->committed && !migration_dest_retained->running);
 assert(fcntl(fd, F_GETFD) >= 0);
 /* Fixture teardown only (production resolves it through migrate_resolve). */
 if (migration_dest_retained->recovery_dirfd >= 0)
  close(migration_dest_retained->recovery_dirfd);
 free(migration_dest_retained->dev_blob); free(migration_dest_retained);
 migration_dest_retained = NULL;
 (void)local;
 int before = calls;
 tracing = true;
 assert(migration_prod_dest_serve(&ctx, -1, &config, &result) == EOPNOTSUPP);
 assert(calls == before); tracing = false;
 close(fd); config.recovery_dirfd = -1;
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == EBADF && !owner);
 /* Nine earlier channels plus the four active-vsock serves. */
 assert(calls == before && cleaned == 13);
 /* Prepared tracing entry: reject each missing prerequisite before core I/O. */
 tracing = true; startup_held = true;
 fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC); assert(fd >= 0);
 config.recovery_dirfd = fd; config.tls_credentials = &credentials;
 config.recovery_enabled = false;
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == EACCES && !owner);
 config.recovery_enabled = true; config.tls_credentials = NULL;
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == EACCES && !owner);
 config.tls_credentials = &credentials; startup_held = false;
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == EBUSY && !owner);
 startup_held = true; config.recovery_dirfd = -1;
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == EBADF && !owner);
 config.recovery_dirfd = fd;
 assert(fchmod(fd, 0755) == 0);
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) != 0 && !owner);
 assert(fchmod(fd, 0700) == 0);
 assert(calls == before);
 /* Active vsock with TLS is refused before the channel exists. */
 active_vsock_config = true;
 int cleaned_before = cleaned;
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == EPROTONOSUPPORT && !owner);
 assert(calls == before && cleaned == cleaned_before);
 assert(result.phase == MIGRATION_PHASE_FAILED && result.reason == MIGRATION_REASON_CAPS);
 active_vsock_config = false;
 mode = 10;
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == EIO && !owner);
 assert(calls == before && result.phase == MIGRATION_PHASE_FAILED && result.reason == MIGRATION_REASON_TRANSPORT);
 mode = 0;
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == ETIMEDOUT);
 assert(calls == before + 1 && owner && result.retained && !owner->running);
 assert(owner->recovery.source_certificate_sha256[0] == 3 && owner->recovery.destination_certificate_sha256[0] == 4);
 close(owner->recovery_dirfd); free(owner->dev_blob); free(owner); owner = NULL;
 mode=11; fail_resume=true; startup_held=true;
 int previous_resumes=resume_calls;
 assert(migration_prod_dest_serve_prepared(&ctx,-1,&config,&result,&owner)==EIO);
 assert(owner && result.retained && owner->run_state.resume_uncertain);
 assert(!owner->running && owner->dev_blob && resume_calls==previous_resumes+1);
 assert(migration_prod_dest_recover_release(owner,-1,&credentials)==EBUSY);
 assert(resume_calls==previous_resumes+1);
 close(owner->recovery_dirfd); free(owner->dev_blob); free(owner); owner=NULL;
 /* Image preservation is admitted only for a prepared tracing owner. */
 assert(!preserve_hook);
 mode = 0; fail_resume = false; startup_held = true; config.recovery_image = true;
 before = calls;
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == ETIMEDOUT);
 assert(calls == before + 1 && preserve_hook && owner && owner->controller_fd == -1);
 close(owner->recovery_dirfd); free(owner->dev_blob); free(owner); owner = NULL;
 tracing = false;
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == EINVAL && !owner);
 config.recovery_enabled = false;
 assert(migration_prod_dest_serve_prepared(&ctx, -1, &config, &result, &owner) == EINVAL && !owner);
 assert(calls == before + 1);
 config.recovery_image = false; config.recovery_enabled = true;
 close(fd);
 /* Destination resume: committed check first, then relay activation, then
  * the guest; a failed activation never resumes. */
 {
  struct migration_prod_dest d = { .ctx = &ctx, .vsock_relay_prepared = true };
  int activates = owner_activates, resumes = resume_calls;
  tracing = true; startup_held = true; fail_resume = false;
  assert(prod_dest_resume(&d) == EBUSY && owner_activates == activates && d.vsock_relay_prepared);
  d.committed = true; d.fresh_device = (struct pci_devinst *)&d;
  owner_activate_error = EPIPE;
  assert(prod_dest_resume(&d) == EPIPE && owner_activates == activates + 1);
  assert(d.vsock_relay_prepared && !d.running && resume_calls == resumes && startup_held);
  owner_activate_error = 0;
  assert(prod_dest_resume(&d) == 0 && owner_activates == activates + 2);
  assert(!d.vsock_relay_prepared && d.running && resume_calls == resumes + 1);
  /* Without a prepared relay nothing is activated. */
  struct migration_prod_dest e = { .ctx = &ctx, .committed = true,
   .fresh_device = (struct pci_devinst *)&e };
  startup_held = true;
  assert(prod_dest_resume(&e) == 0 && owner_activates == activates + 2);
  tracing = false;
 }
 puts("PASS: retained production ownership, independent journal fd, reconnect identity/image checks, cleanup, setup failures, unmanaged refusal and prepared tracing admission, recovery-image admission");
}
'''
(out / 'owner.c').write_text(fixture)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-I' + str(root / 'sys'), '-I' + str(root / 'usr.sbin/bhyve'),
    str(out / 'owner.c'), '-lmd', '-o', str(out / 'owner')], check=True)
subprocess.run([str(out / 'owner')], cwd=out, check=True, timeout=30)
