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
#define BHYVE_PHASE_START(...) ((void)0)
#define BHYVE_PHASE_DONE(...) ((void)0)
#define XO_STYLE_JSON 0
#define XOF_PRETTY 0
struct vmctx { int unused; };
struct vm_snapshot_session { int unused; };
typedef FILE xo_handle_t;
static bool tracing;
static int begins, release_error;
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
{ (void)ctx; (void)s; *resolved = true; begins++; return 0; }
static int vm_snapshot_session_release_exact(struct vmctx *ctx,
    struct vm_snapshot_session *s, bool commit, bool *released)
{ (void)ctx; (void)s; assert(!commit); *released = !release_error; return release_error; }
static size_t vm_get_lowmem_size(struct vmctx *ctx) { (void)ctx; return 4096; }
static size_t vm_get_highmem_size(struct vmctx *ctx) { (void)ctx; return 0; }
static int vm_snapshot_basic_metadata(struct vmctx *ctx, xo_handle_t *x, size_t sz)
{ (void)ctx; assert(sz == 4096); return fputs("meta", x) < 0 ? EIO : 0; }
static int vm_save_kern_structs(struct vmctx *ctx, int fd, xo_handle_t *x)
{ (void)ctx; (void)x; return write(fd, "kern", 4) == 4 ? 0 : EIO; }
static int vm_snapshot_devices(int fd, xo_handle_t *x)
{ (void)x; return write(fd, "device", 6) == 6 ? 0 : EIO; }
'''
fixture += source[start:end] + r'''
int main(void) {
    struct vmctx ctx = {0};
    struct hypertrace_session_record record = { .vmid=7, .epoch=9,
        .stop_token=11, .features=HYPERTRACE_SESSION_FEATURES };
    uint8_t wire[HYPERTRACE_SESSION_RECORD_SIZE], *blob;
    struct migration_snapshot_view view, unchanged;
    size_t len;
    assert(hypertrace_session_record_encode(wire, sizeof(wire), &record) == 0);
    assert(vm_snapshot_dev_state_to_mem(&ctx, &blob, &len) == 0);
    assert(len == 30 && le64dec(blob) == 4 && le64dec(blob+8) == 10);
    assert(memcmp(blob+16, "metakerndevice", 14) == 0);
    assert(migration_snapshot_decode(blob, len, false, &view) == 0);
    assert(view.metadata_length == 4 && view.kernel_length == 10);
    assert(view.fresh_record == NULL);
    assert(migration_snapshot_decode(blob, len, true, &view) == EBADMSG);
    free(blob);
    assert(vm_snapshot_fresh_dev_state_to_mem(&ctx, wire, &blob, &len) == EOPNOTSUPP);
    tracing = true; begins = 0;
    assert(vm_snapshot_dev_state_to_mem(&ctx, &blob, &len) == EOPNOTSUPP);
    wire[10] = 1;
    assert(vm_snapshot_fresh_dev_state_to_mem(&ctx, wire, &blob, &len) == EPROTO);
    wire[10] = 0; le64enc(wire+16, 10);
    assert(vm_snapshot_fresh_dev_state_to_mem(&ctx, wire, &blob, &len) == ESTALE);
    le64enc(wire+16, 9); assert(begins == 0);
    assert(vm_snapshot_fresh_dev_state_to_mem(&ctx, wire, &blob, &len) == 0);
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
    release_error = EIO;
    assert(vm_snapshot_fresh_dev_state_to_mem(&ctx, wire, &blob, &len) == EIO);
    assert(blob == NULL && len == 0);
    return 0;
}
'''
(out / 'capture.c').write_text(fixture)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(root / 'sys'),
    '-I' + str(root / 'usr.sbin/bhyve'), str(out / 'capture.c'),
    '-o', str(out / 'capture')], check=True)
subprocess.run([str(out / 'capture')], check=True, timeout=30)
