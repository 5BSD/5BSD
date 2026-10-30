# SPDX-License-Identifier: BSD-2-Clause
"""Native clone entry-point lifetime checks without real ZFS operations."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]

class Clone(unittest.TestCase):
    def test_source_handle_lifetime(self):
        source = (ROOT/'lib/libbe/be.c').read_text()
        start = source.index('static int\nbe_clone(')
        function = source[start:source.index('\n}\n',start)+3]
        before = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BE_MAXPATHLEN 256
#define BE_ERR_UNKNOWN 10
#define BE_ERR_ZFSOPEN 11
#define ZFS_TYPE_DATASET 1
typedef struct { void *lzh; } libbe_handle_t;
typedef struct { int live; } zfs_handle_t;
struct libbe_deep_clone { libbe_handle_t *lbh; const char *bename, *snapname; int depth, depth_limit; };
static int validate_error, concat_error, snapshot_error, open_error, clone_error;
static int opened, cloned, closed;
static zfs_handle_t handle;
static int set_error(libbe_handle_t *h, int e) { (void)h; return e; }
static int be_validate_name(libbe_handle_t *h, const char *n) { (void)h; (void)n; return validate_error; }
static int be_root_concat(libbe_handle_t *h, const char *n, char *p) {
 (void)h; snprintf(p,BE_MAXPATHLEN,"pool/ROOT/%s",n); return concat_error;
}
static int be_validate_snap(libbe_handle_t *h, const char *s) { (void)h; (void)s; return snapshot_error; }
static zfs_handle_t *zfs_open(void *h, const char *s, int type) {
 (void)h; assert(!strcmp(s,"pool/ROOT/old")); assert(type==ZFS_TYPE_DATASET);
 opened++; if(open_error) return NULL; assert(!handle.live); handle.live=1; return &handle;
}
static void zfs_close(zfs_handle_t *h) { assert(h==&handle && h->live); h->live=0; closed++; }
static int be_clone_cb(zfs_handle_t *h, void *data) {
 struct libbe_deep_clone *d=data;
 assert(h==&handle && h->live); assert(!strcmp(d->snapname,"snap"));
 assert(!strcmp(d->bename,"new")); assert(d->depth==0 && d->depth_limit==-1);
 cloned++; return clone_error;
}
'''
        after = r'''
int main(void) {
 libbe_handle_t h={0};
 validate_error=21; assert(be_clone(&h,"new","old@snap",-1)==21);
 validate_error=0; concat_error=22; assert(be_clone(&h,"new","old@snap",-1)==22);
 concat_error=0; snapshot_error=23; assert(be_clone(&h,"new","old@snap",-1)==23);
 snapshot_error=0; assert(be_clone(&h,"new","old",-1)==BE_ERR_UNKNOWN);
 assert(!opened && !cloned && !closed);
 open_error=1; assert(be_clone(&h,"new","old@snap",-1)==BE_ERR_ZFSOPEN);
 assert(opened==1 && !cloned && !closed && !handle.live);
 open_error=0; clone_error=24;
 assert(be_clone(&h,"new","old@snap",-1)==24);
 assert(opened==2 && cloned==1 && closed==1 && !handle.live);
 clone_error=0; assert(be_clone(&h,"new","old@snap",-1)==0);
 assert(opened==3 && cloned==2 && closed==2 && !handle.live);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'probe.c').write_text(before+function+after)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(root/'probe.c'),'-o',str(root/'probe')],check=True)
            subprocess.run([str(root/'probe')],check=True)

if __name__ == '__main__': unittest.main()
