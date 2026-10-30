# SPDX-License-Identifier: BSD-2-Clause
"""Native libbe failure cleanup; no pool, mount, or VM operations."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]

class DestroyCleanup(unittest.TestCase):
    def test_destroy_handle_lifetime(self):
        source = (ROOT / 'lib/libbe/be.c').read_text()
        start = source.index('static int\nbe_destroy_internal(')
        end = source.index('\n}\n', start) + 3
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/queue.h>
#define BE_MAXPATHLEN 256
#define BE_DESTROY_FORCE 1
#define BE_DESTROY_ORIGIN 2
#define BE_DESTROY_AUTOORIGIN 4
#define BE_DESTROY_WANTORIGIN 6
#define ZFS_TYPE_FILESYSTEM 1
#define ZFS_TYPE_SNAPSHOT 2
#define ZFS_TYPE_DATASET 3
#define ZFS_PROP_ORIGIN 1
#define lzbe_add 1
enum { BE_ERR_NOENT=10, BE_ERR_DESTROYACT, BE_ERR_ZFSOPEN,
 BE_ERR_DESTROYMNT, BE_ERR_NOMEM, BE_ERR_HASCLONES, BE_ERR_NOORIGIN,
 BE_ERR_UNKNOWN, BE_ERR_INVORIGIN };
typedef struct { void *lzh, *active_phandle; char *rootfs, *bootfs, *bootonce, *root; } libbe_handle_t;
typedef struct { int live; } zfs_handle_t;
struct promote_entry { SLIST_ENTRY(promote_entry) link; };
struct be_destroy_data { libbe_handle_t *lbh; char *snapname; SLIST_HEAD(, promote_entry) promotelist; };
static zfs_handle_t handle;
static int unmount_error, unmounted, boot_error, boot_changes, promoted;
static int mounted, promote_error, origin_error, destroy_error, destroyed, closed;
static int set_error(libbe_handle_t *h, int e) { (void)h; return e; }
static int concat_error;
static int be_root_concat(libbe_handle_t *h, const char *n, char *p) {
 if(concat_error)return concat_error;
 snprintf(p, BE_MAXPATHLEN, "%s/%s", h->root, n);return 0;
}
static int zfs_dataset_exists(void *h, const char *p, int t) { (void)h; (void)p; (void)t; return 1; }
static zfs_handle_t *zfs_open(void *h, const char *p, int t) { (void)h; (void)p; (void)t; assert(!handle.live); handle.live=1; return &handle; }
static void zfs_close(zfs_handle_t *h) { assert(h->live); h->live=0; closed++; }
static int zfs_is_mounted(zfs_handle_t *h, void *p) { assert(h->live); (void)p; return mounted; }
static int zfs_unmount(zfs_handle_t *h, void *p, int f) { assert(h->live); (void)p; (void)f; unmounted++; return unmount_error; }
static char *zpool_get_name(void *p) { (void)p; return "pool"; }
static int lzbe_set_boot_device(const char *p, int n, void *v) { (void)p; (void)n; (void)v; boot_changes++; return boot_error; }
static int be_promote_dependent_clones(zfs_handle_t *h, struct be_destroy_data *d) { assert(h->live); (void)d; promoted++; return promote_error; }
static int zfs_prop_get(zfs_handle_t *h, int p, char *v, size_t n, void *a, void *b, int c, int d) { assert(h->live); (void)p; (void)v; (void)n; (void)a; (void)b; (void)c; (void)d; return origin_error; }
static int be_is_auto_snapshot_name(libbe_handle_t *h, const char *p) { (void)h; (void)p; return 0; }
static int be_destroy_cb(zfs_handle_t *h, struct be_destroy_data *d) { assert(h->live); (void)d; destroyed++; return destroy_error; }
'''
        cases = r'''
int main(void) {
 libbe_handle_t h = {.root="pool/ROOT", .rootfs="pool/ROOT/current", .bootfs="pool/ROOT/default"};
 for (int scenario=0; scenario<9; scenario++) {
  handle.live=closed=destroyed=mounted=promote_error=origin_error=destroy_error=0;
  unmount_error=unmounted=boot_error=boot_changes=promoted=0; h.bootonce=NULL;
  int options=0, expected=0; bool automatic=false;
  const char *name="candidate";
  switch (scenario) {
   case 0: mounted=1; expected=BE_ERR_DESTROYMNT; break;
   case 1: promote_error=expected=BE_ERR_HASCLONES; break;
   case 2: promote_error=BE_ERR_HASCLONES; options=BE_DESTROY_AUTOORIGIN; automatic=true; name="candidate@snap"; break;
   case 3: origin_error=1; options=BE_DESTROY_ORIGIN; expected=BE_ERR_NOORIGIN; break;
   case 4: destroy_error=EBUSY; expected=BE_ERR_DESTROYMNT; break;
   case 5: break;
   case 6: mounted=1; options=BE_DESTROY_FORCE; unmount_error=EBUSY;
    h.bootonce="pool/ROOT/candidate"; expected=BE_ERR_DESTROYMNT; break;
   case 7: mounted=1; options=BE_DESTROY_FORCE;
    h.bootonce="pool/ROOT/candidate"; break;
  }
  if (scenario==8) { h.bootonce="pool/ROOT/candidate"; boot_error=EIO; expected=BE_ERR_UNKNOWN; }
  assert(be_destroy_internal(&h, name, options, automatic)==expected);
  if (handle.live || closed!=1) { fprintf(stderr,"scenario %d leaked handle\n",scenario); return 1; }
  assert(destroyed==(scenario>=4 && scenario!=6 && scenario!=8));
  assert(unmounted==(scenario==6 || scenario==7));
  assert(boot_changes==(scenario==7 || scenario==8));
  assert(promoted==(scenario!=0 && scenario!=6 && scenario!=8));
 }
 concat_error=EINVAL;closed=destroyed=unmounted=boot_changes=promoted=0;
 assert(be_destroy_internal(&h,"invalid",BE_DESTROY_FORCE,false)==EINVAL);
 assert(!handle.live && !closed && !destroyed && !unmounted && !boot_changes && !promoted);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            c = Path(tmp) / 'test.c'
            c.write_text(harness + source[start:end] + cases)
            binary = Path(tmp) / 'test'
            subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', str(c), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_snapshot_errors_and_handle_cleanup(self):
        source = (ROOT / 'lib/libbe/be.c').read_text()
        start = source.index('static int be_destroy_child_cb(')
        wrapper = source.index('static int\nbe_destroy_child_cb(', start)
        end = source.index('\n}\n', wrapper) + 3
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#define BE_MAXPATHLEN 256
#define ZFS_TYPE_SNAPSHOT 2
#define EZFS_NOENT 100
typedef struct { int live; } zfs_handle_t;
typedef struct { void *lzh; } libbe_handle_t;
struct be_destroy_data { libbe_handle_t *lbh; char *snapname; };
static zfs_handle_t snapshot, child;
static int walk, child_closed;
static int iteration_error, lookup_error, exists, open_failure, destroy_error, destroyed, closed, opened;
static int zfs_iter_children(zfs_handle_t *h, int (*cb)(zfs_handle_t *, void *), void *d) { if (walk && h!=&child) { child.live=1; return cb(&child,d); } return iteration_error; }
static int zfs_iter_filesystems(zfs_handle_t *h, int (*cb)(zfs_handle_t *, void *), void *d) { return zfs_iter_children(h, cb, d); }
static int zfs_destroy(zfs_handle_t *h, bool defer) { assert(h->live && !defer); destroyed++; return destroy_error; }
static const char *zfs_get_name(zfs_handle_t *h) { assert(h->live); return "pool/ROOT/candidate"; }
static int zfs_dataset_exists(void *h, const char *p, int t) { (void)h; (void)p; (void)t; return exists; }
static zfs_handle_t *zfs_open(void *h, const char *p, int t) { (void)h; (void)p; (void)t; opened++; if (open_failure || !exists) return NULL; snapshot.live=1; return &snapshot; }
static int libzfs_errno(void *h) { (void)h; return lookup_error; }
static void zfs_close(zfs_handle_t *h) { assert(h->live); h->live=0; if(h==&child) child_closed++; else { assert(h==&snapshot); closed++; } }
'''
        cases = r'''
int main(void) {
 libbe_handle_t h={0}; struct be_destroy_data d={&h,"old"};
 zfs_handle_t parent={1};
 for (int scenario=0; scenario<7; scenario++) {
  lookup_error=iteration_error=open_failure=destroy_error=destroyed=closed=opened=snapshot.live=0; exists=1;
  switch (scenario) {
   case 0: exists=0; lookup_error=EZFS_NOENT; break;
   case 1: iteration_error=EBUSY; break;
   case 2: open_failure=1; lookup_error=EACCES; break;
   case 3: destroy_error=EBUSY; break;
   case 4: destroy_error=EIO; break;
   case 5: break;
   case 6: exists=0; lookup_error=EIO; break;
  }
  int error=be_destroy_cb(&parent,&d);
  int expected=iteration_error ? iteration_error : destroy_error;
  if (open_failure || scenario==6) assert(error!=0); else assert(error==expected);
  assert(parent.live);
  assert(opened==(scenario!=1));
  assert(destroyed==(scenario>=3 && scenario<=5));
  assert(closed==(scenario>=3 && scenario<=5) && !snapshot.live);
 }
 for (int snapshots=0; snapshots<=1; snapshots++) {
  for (int fail=0; fail<=1; fail++) {
   walk=1; child_closed=closed=destroyed=opened=0;
   iteration_error=open_failure=lookup_error=0; exists=1;
   destroy_error=fail ? EBUSY : 0;
   d.snapname=snapshots ? "old" : NULL;
   assert(be_destroy_cb(&parent,&d)==destroy_error);
   assert(parent.live && !child.live && child_closed==1);
   assert(destroyed==(fail ? 1 : 2));
   assert(opened==(snapshots ? destroyed : 0));
   assert(closed==opened && !snapshot.live);
  }
 }
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            c = Path(tmp) / 'test.c'
            c.write_text(harness + source[start:end] + cases)
            binary = Path(tmp) / 'test'
            subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                            str(c), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

if __name__ == '__main__':
    unittest.main()
