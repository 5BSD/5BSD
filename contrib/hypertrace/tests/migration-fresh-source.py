#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise production migration capture using anonymous files and mock VM state."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/snapshot.c').read_text()
start = source.index('static int\nvm_snapshot_dev_state_capture(')
end = source.index('\n/*\n * Reconstruct device + CPU/vCPU/kernel state', start)
pa = source.index('static int\nmigrate_pread_all(')
pread_all = source[pa:source.index('\n}\n', pa) + 3]
fixture = r'''
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include "hypertrace_session.h"
#include "migration_snapshot.h"
#include "migration_session.h"
#define BHYVE_PHASE_START(...) ((void)0)
#define BHYVE_PHASE_DONE(a, b, c, d) ((void)(c), (void)(d))
#define XO_STYLE_JSON 0
#define XOF_PRETTY 0
struct vmctx { int unused; };
struct vm_snapshot_session { int unused; };
/* Merged capture session (snapshot.h): the fence is held until finished. */
struct vm_snapshot_capture { struct vm_snapshot_session session; bool active; bool unresolved; };
typedef FILE xo_handle_t;
static bool tracing, begin_resolved = true, release_released = true;
static int begins, releases, release_commit = -1, release_error, begin_error;
static int tpm_error, device_error;
static int tpm_device_migration_check(void) { return tpm_error; }
static bool hypertrace_initialized(void) { return tracing; }
static int vm_get_identity(struct vmctx *ctx, uint16_t *vmid, uint64_t *epoch)
{ (void)ctx; *vmid = 7; *epoch = 9; return 0; }
static int migrate_tempfd(const void *buf, size_t len)
{ assert(buf == NULL && len == 0); return memfd_create("capture-test", MFD_CLOEXEC); }
static xo_handle_t *xo_create_to_file(FILE *f, int style, int flags)
{ (void)style; (void)flags; return f; }
static int xo_finish_h(xo_handle_t *x) { (void)x; return 0; }
static void xo_destroy(xo_handle_t *x) { (void)x; }
static int vm_snapshot_session_begin_exact(struct vmctx *ctx,
    struct vm_snapshot_session *s, bool *resolved)
{ (void)ctx; (void)s; *resolved = begin_resolved; begins++; return begin_error; }
static int vm_snapshot_session_release_exact(struct vmctx *ctx,
    struct vm_snapshot_session *s, bool commit, bool *released)
{ (void)ctx; (void)s; releases++; release_commit = commit; *released = release_released; return release_error; }
static size_t vm_get_lowmem_size(struct vmctx *ctx) { (void)ctx; return 4096; }
static size_t vm_get_highmem_size(struct vmctx *ctx) { (void)ctx; return 0; }
static int vm_snapshot_basic_metadata(struct vmctx *ctx, xo_handle_t *x, size_t sz)
{ (void)ctx; assert(sz == 4096); return fputs("meta", x) < 0 ? EIO : 0; }
static int vm_save_kern_structs(struct vmctx *ctx, int fd, xo_handle_t *x)
{ (void)ctx; (void)x; return write(fd, "kern", 4) == 4 ? 0 : EIO; }
static int vm_snapshot_devices_supported(void) { return 0; }
static int vm_snapshot_devices(int fd, xo_handle_t *x)
{ (void)x; if (device_error) return device_error; return write(fd, "device", 6) == 6 ? 0 : EIO; }
'''
fixture += pread_all + source[start:end] + r'''
int main(void) {
    struct vmctx ctx = {0};
    struct hypertrace_session_record record = { .vmid=7, .epoch=9,
        .stop_token=11, .features=HYPERTRACE_SESSION_FEATURES };
    uint8_t wire[HYPERTRACE_SESSION_RECORD_SIZE], *blob;
    struct migration_snapshot_view view, unchanged;
    struct vm_snapshot_capture capture = {0};
    size_t len;
    assert(hypertrace_session_record_encode(wire, sizeof(wire), &record) == 0);
    assert(vm_snapshot_dev_state_to_mem(&ctx, &blob, &len, NULL) == EINVAL);
    /* The TPM gate refuses before the capture is touched. */
    tpm_error = ENOTSUP; capture.active = true;
    assert(vm_snapshot_dev_state_to_mem(&ctx, &blob, &len, &capture) == ENOTSUP);
    assert(capture.active && begins == 0);
    tpm_error = 0;
    /* A capture already holding or having lost its fence is refused. */
    assert(vm_snapshot_dev_state_to_mem(&ctx, &blob, &len, &capture) == EBUSY);
    capture.active = false; capture.unresolved = true;
    assert(vm_snapshot_dev_state_to_mem(&ctx, &blob, &len, &capture) == EBUSY);
    assert(vm_snapshot_dev_state_finish(&ctx, &capture, false) == EINVAL);
    capture.unresolved = false;
    assert(begins == 0);
    /* Success keeps the event fence held: no release yet. */
    assert(vm_snapshot_dev_state_to_mem(&ctx, &blob, &len, &capture) == 0);
    assert(capture.active && !capture.unresolved && begins == 1 && releases == 0);
    assert(len == 30 && le64dec(blob) == 4 && le64dec(blob+8) == 10);
    assert(memcmp(blob+16, "metakerndevice", 14) == 0);
    assert(migration_snapshot_decode(blob, len, false, &view) == 0);
    assert(view.metadata_length == 4 && view.kernel_length == 10);
    assert(view.fresh_record == NULL);
    assert(migration_snapshot_decode(blob, len, true, &view) == EBADMSG);
    free(blob);
    /* Rollback finish releases without commit; a second finish is a no-op. */
    assert(vm_snapshot_dev_state_finish(NULL, &capture, false) == EINVAL);
    assert(vm_snapshot_dev_state_finish(&ctx, NULL, false) == EINVAL);
    assert(vm_snapshot_dev_state_finish(&ctx, &capture, false) == 0);
    assert(releases == 1 && release_commit == 0 && !capture.active);
    assert(vm_snapshot_dev_state_finish(&ctx, &capture, true) == 0 && releases == 1);
    /* Retirement finish commits; a release that reports failure but released
     * still ends the capture, an unreleased one makes it unresolved. */
    assert(vm_snapshot_dev_state_to_mem(&ctx, &blob, &len, &capture) == 0);
    free(blob);
    release_error = EIO;
    assert(vm_snapshot_dev_state_finish(&ctx, &capture, true) == EIO);
    assert(releases == 2 && release_commit == 1 && !capture.active && !capture.unresolved);
    assert(vm_snapshot_dev_state_to_mem(&ctx, &blob, &len, &capture) == 0);
    free(blob);
    release_released = false;
    assert(vm_snapshot_dev_state_finish(&ctx, &capture, false) == EIO);
    assert(capture.unresolved && capture.active);
    assert(vm_snapshot_dev_state_finish(&ctx, &capture, false) == EINVAL && releases == 3);
    memset(&capture, 0, sizeof(capture));
    release_error = 0; release_released = true;
    /* A serializer failure after the fence releases it at once (rollback). */
    device_error = EIO; releases = 0;
    assert(vm_snapshot_dev_state_to_mem(&ctx, &blob, &len, &capture) == EIO);
    assert(blob == NULL && len == 0 && releases == 1 && release_commit == 0);
    assert(!capture.active && !capture.unresolved);
    /* ... and an unreleased fence leaves the capture unresolved. */
    release_released = false; release_error = EIO;
    assert(vm_snapshot_dev_state_to_mem(&ctx, &blob, &len, &capture) == EIO);
    assert(capture.active && capture.unresolved && releases == 2);
    memset(&capture, 0, sizeof(capture));
    device_error = 0; release_error = 0; release_released = true;
    /* Begin failures: unresolved unless the kernel resolved a non-EBUSY error. */
    for (int k = 0; k < 3; k++) {
        begin_error = k == 0 ? EBUSY : EIO; begin_resolved = k != 1;
        releases = 0;
        assert(vm_snapshot_dev_state_to_mem(&ctx, &blob, &len, &capture) == begin_error);
        assert(!capture.active && capture.unresolved == (k != 2) && releases == 0);
        memset(&capture, 0, sizeof(capture));
    }
    begin_error = 0; begin_resolved = true;
    begins = 0;
    assert(vm_snapshot_fresh_dev_state_to_mem(&ctx, NULL, &blob, &len, &capture) == EINVAL);
    assert(vm_snapshot_fresh_dev_state_to_mem(&ctx, wire, &blob, &len, &capture) == EOPNOTSUPP);
    tracing = true;
    assert(vm_snapshot_dev_state_to_mem(&ctx, &blob, &len, &capture) == EOPNOTSUPP);
    wire[10] = 1;
    assert(vm_snapshot_fresh_dev_state_to_mem(&ctx, wire, &blob, &len, &capture) == EPROTO);
    wire[10] = 0; le64enc(wire+16, 10);
    assert(vm_snapshot_fresh_dev_state_to_mem(&ctx, wire, &blob, &len, &capture) == ESTALE);
    le64enc(wire+16, 9); assert(begins == 0);
    assert(vm_snapshot_fresh_dev_state_to_mem(&ctx, wire, &blob, &len, &capture) == 0);
    assert(capture.active);
    assert(len == 70 && le64dec(blob) == 4 && le64dec(blob+8) == 10);
    assert(memcmp(blob+16, "metakerndevice", 14) == 0);
    assert(memcmp(blob+30, wire, sizeof(wire)) == 0);
    assert(migration_snapshot_decode(blob, len, true, &view) == 0);
    assert(view.fresh_record == blob+30);
    assert(view.metadata == blob+16 && view.kernel == blob+20);
    unchanged = view;
    assert(migration_snapshot_decode(blob, len, false, &view) == EBADMSG);
    for (size_t truncated = 0; truncated < len; truncated++) {
        assert(migration_snapshot_decode(blob, truncated, true, &view) != 0);
        assert(memcmp(&view, &unchanged, sizeof(view)) == 0);
    }
    le64enc(blob, UINT64_MAX);
    assert(migration_snapshot_decode(blob, len, true, &view) == EBADMSG);
    le64enc(blob, 4); le64enc(blob+8, UINT64_MAX);
    assert(migration_snapshot_decode(blob, len, true, &view) == EBADMSG);
    le64enc(blob+8, 10); blob[40] = 1;
    assert(migration_snapshot_decode(blob, len, true, &view) == EPROTO);
    assert(memcmp(&view, &unchanged, sizeof(view)) == 0);
    blob[40] = 0;
    uint8_t extra[71]; memcpy(extra, blob, len); extra[len] = 0;
    assert(migration_snapshot_decode(extra, sizeof(extra), true, &view) == EBADMSG);
    free(blob);
    assert(vm_snapshot_dev_state_finish(&ctx, &capture, true) == 0 && !capture.active);
    return 0;
}
'''
(out / 'capture.c').write_text(fixture)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(root / 'sys'),
    '-I' + str(root / 'usr.sbin/bhyve'), str(out / 'capture.c'),
    '-o', str(out / 'capture')], check=True)
subprocess.run([str(out / 'capture')], check=True, timeout=30)
