# SPDX-License-Identifier: BSD-2-Clause
"""Native promotion recursion ownership, without real ZFS operations."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]

class Promotion(unittest.TestCase):
    def test_child_handles_and_errors(self):
        source=(ROOT/'lib/libbe/be.c').read_text();functions=[]
        for name in ('be_zfs_promote_cb','be_zfs_promote_child_cb','be_zfs_promote'):
            start=source.index('static int\n'+name+'(')
            functions.append(source[start:source.index('\n}\n',start)+3])
        before=r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#define BE_MAXPATHLEN 512
#define ZFS_PROP_ORIGIN 1
typedef struct { int depth, live, closes; } zfs_handle_t;
static zfs_handle_t handles[3];
static int origin_depth, error_depth, iterator_error, promotes;
static int zfs_prop_get(zfs_handle_t *h,int prop,char *out,size_t n,void *src,
 void *source,size_t len,bool literal) {
 assert(h->live && prop==ZFS_PROP_ORIGIN && literal);
 (void)out; (void)n; (void)src; (void)source; (void)len;
 return h->depth==origin_depth?0:-1;
}
static int zfs_promote(zfs_handle_t *h) {
 assert(h->live); promotes++; return !iterator_error && h->depth==error_depth?17:0;
}
static void zfs_close(zfs_handle_t *h) { assert(h->live); h->live=0; h->closes++; }
static int zfs_iter_filesystems(zfs_handle_t *h,int (*cb)(zfs_handle_t *,void *),void *data) {
 assert(h->live); if(iterator_error && h->depth==error_depth) return 19;
 if(h->depth==2) return 0;
 zfs_handle_t *child=&handles[h->depth+1]; assert(!child->live); child->live=1;
 return cb(child,data);
}
static int be_zfs_promote_child_cb(zfs_handle_t *,void *);
'''
        main=r'''
int main(void) {
 for(origin_depth=-1;origin_depth<3;origin_depth++) {
  for(int failure=0;failure<3;failure++) {
   for(int i=0;i<3;i++) handles[i]=(zfs_handle_t){.depth=i};
   handles[0].live=1; promotes=0; bool found=true;
   iterator_error=failure==2;
   error_depth=failure==0?-1:(failure==1?origin_depth:1);
   int expected=failure==1 && origin_depth>=0?17:failure==2?19:0;
   assert(be_zfs_promote(&handles[0],&found)==expected);
   bool reached_origin=origin_depth>=0 && (!iterator_error || origin_depth<=1);
   assert(found==reached_origin && promotes==(reached_origin?1:0));
   assert(handles[0].live && !handles[0].closes);
   for(int i=1;i<3;i++) {
    bool visited=!(failure==1 && origin_depth>=0 && origin_depth<i) &&
                 !(iterator_error && i>1);
    assert(!handles[i].live && handles[i].closes==(visited?1:0));
   }
   zfs_close(&handles[0]);
  }
 }
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'probe.c').write_text(before+'\n'.join(functions)+main)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(p/'probe.c'),'-o',str(p/'probe')],check=True)
            subprocess.run([str(p/'probe')],check=True)

if __name__=='__main__': unittest.main()
