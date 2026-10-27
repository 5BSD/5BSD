# SPDX-License-Identifier: BSD-2-Clause
"""Recursive clone ownership checks with native libzfs seams, without a pool."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]

class CloneCleanup(unittest.TestCase):
    def test_recursive_cleanup(self):
        source = (ROOT/'lib/libbe/be.c').read_text()
        functions=[]
        for name in ('be_clone_cb','be_clone_child_cb'):
            start=source.index('static int\n'+name+'(')
            functions.append(source[start:source.index('\n}\n',start)+3])
        preamble=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define BE_MAXPATHLEN 256
#define BE_ERR_SUCCESS 0
#define BE_ERR_PATHLEN 16
#define BE_ERR_UNKNOWN 11
#define BE_ERR_EXISTS 12
#define BE_ERR_ZFSOPEN 13
#define BE_ERR_NOMEM 14
#define BE_ERR_ZFSCLONE 15
#define ZFS_TYPE_DATASET 1
#define ZFS_TYPE_SNAPSHOT 2
#define ZFS_TYPE_FILESYSTEM 3
#define NV_UNIQUE_NAME 1
#define KM_SLEEP 0
#define B_FALSE 0
#define ZPROP_INVAL -1
#define EZFS_NOENT 100
#define EZFS_IO 101
typedef struct { void *lzh; } libbe_handle_t;
typedef struct { int live, depth, snapshot; } zfs_handle_t;
typedef struct { int live; } nvlist_t;
struct libbe_deep_clone { libbe_handle_t *lbh; const char *snapname; int depth, depth_limit; };
struct libbe_dccb { libbe_handle_t *lbh; zfs_handle_t *zhp; nvlist_t *props; };
static zfs_handle_t root, child, snapshots[2];
static nvlist_t lists[2];
static int scenario, fail_depth, current, children, child_closes, clone_calls;
static bool fail(int n) { return scenario==n && current==fail_depth; }
static const char *zfs_get_name(zfs_handle_t *h) {
 assert(h->live); current=h->depth; return current ? "pool/ROOT/old/child" : "pool/ROOT/old";
}
static int be_get_path(struct libbe_deep_clone *d,const char *p,char *o,int n) {
 (void)d; (void)p; snprintf(o,n,"pool/ROOT/new%s",current?"/child":""); return fail(1)?BE_ERR_UNKNOWN:0;
}
static int zfs_dataset_exists(void *h,const char *p,int t) {
 (void)h; (void)p; return t==ZFS_TYPE_DATASET ? fail(2) : !(fail(3) || fail(4));
}
static zfs_handle_t *zfs_open(void *h,const char *p,int t) {
 (void)h; (void)p; assert(t==ZFS_TYPE_SNAPSHOT); if(fail(3) || fail(4)) return NULL;
 zfs_handle_t *s=&snapshots[current]; assert(!s->live); s->live=1; s->snapshot=1; return s;
}
static int libzfs_errno(void *h) { (void)h; return fail(3)?EZFS_NOENT:EZFS_IO; }
static void zfs_close(zfs_handle_t *h) {
 assert(h->live); h->live=0; if(h==&child) child_closes++;
}
static int nvlist_alloc(nvlist_t **p,int f,int km) {
 (void)f; (void)km; if(fail(5)) return 1;
 *p=&lists[current]; assert(!(*p)->live); (*p)->live=1; return 0;
}
static int nvlist_add_string(nvlist_t *p,const char *n,const char *v) {
 assert(p->live); (void)n; (void)v; return fail(6)?1:0;
}
static void nvlist_free(nvlist_t *p) { assert(p->live); p->live=0; }
static int be_deep_clone_prop(void) { return 0; }
static int zprop_iter(int (*cb)(void),void *data,int a,int b,int t) {
 (void)cb; (void)data; (void)a; (void)b; (void)t; return fail(7)?ZPROP_INVAL:0;
}
static int zfs_clone(zfs_handle_t *s,const char *p,nvlist_t *n) {
 assert(s->live && n->live); (void)p; clone_calls++; return fail(8)?1:0;
}
static int zfs_iter_filesystems(zfs_handle_t *h,int (*cb)(zfs_handle_t *,void *),void *data) {
 assert(h->live); if(fail(9)) return -1;
 if(h->depth==1) return 0;
 assert(!child.live); child.live=1; child.depth=1; children++; return cb(&child,data);
}
static int be_clone_child_cb(zfs_handle_t *, void *);
'''
        main=r'''
int main(void) {
 libbe_handle_t h={0};
 char long_snapshot[BE_MAXPATHLEN]; memset(long_snapshot,'s',sizeof(long_snapshot)-1);
 long_snapshot[sizeof(long_snapshot)-1]='\0';
 struct libbe_deep_clone long_case={.lbh=&h,.snapname=long_snapshot,.depth_limit=-1};
 root.live=1;
 assert(be_clone_cb(&root,&long_case)==BE_ERR_PATHLEN);
 assert(root.live && !clone_calls && !children && !snapshots[0].live);

 int expected[]={0,BE_ERR_UNKNOWN,BE_ERR_EXISTS,0,BE_ERR_ZFSOPEN,
  BE_ERR_NOMEM,BE_ERR_NOMEM,BE_ERR_NOMEM,BE_ERR_ZFSCLONE,BE_ERR_UNKNOWN};
 for(fail_depth=0;fail_depth<2;fail_depth++) {
  for(scenario=0;scenario<10;scenario++) {
   struct libbe_deep_clone d={.lbh=&h,.snapname="snap",.depth_limit=-1};
   root=(zfs_handle_t){.live=1}; child=(zfs_handle_t){0};
   current=children=child_closes=clone_calls=0;
   int want=(scenario==3 && fail_depth==0)?BE_ERR_ZFSOPEN:expected[scenario];
   assert(be_clone_cb(&root,&d)==want);
   assert(root.live && !child.live && d.depth==0);
   assert(children==child_closes);
   assert(!snapshots[0].live && !snapshots[1].live);
   assert(!lists[0].live && !lists[1].live);
   assert(children==((fail_depth==1 || scenario==0)?1:0));
   if(scenario>=1 && scenario<=7) assert(clone_calls==fail_depth);
   zfs_close(&root);
  }
 }
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'probe.c').write_text(preamble+'\n'.join(functions)+main)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(root/'probe.c'),'-o',str(root/'probe')],check=True)
            subprocess.run([str(root/'probe')],check=True)

if __name__ == '__main__': unittest.main()
