# SPDX-License-Identifier: BSD-2-Clause
"""Actual libbe property callback behavior, with native property/allocator seams."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]

class CloneProperties(unittest.TestCase):
    def test_insertion_failure_and_sources(self):
        s=(ROOT/'lib/libbe/be.c').read_text();start=s.index('static int\nbe_deep_clone_prop(')
        function=s[start:s.index('\n}\n',start)+3]
        before=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define BE_MAXPATHLEN 512
#define ZPROP_CONT -2
#define ZPROP_INVAL -1
enum { ZFS_PROP_KEYFORMAT, ZFS_PROP_KEYLOCATION, ZFS_PROP_ENCRYPTION,
 ZFS_PROP_PBKDF2_ITERS, ZFS_PROP_CANMOUNT, ZFS_PROP_MOUNTPOINT, ZFS_PROP_COMPRESSION, ZFS_PROP_QUOTA };
typedef enum { ZPROP_SRC_LOCAL, ZPROP_SRC_RECEIVED, ZPROP_SRC_DEFAULT,
 ZPROP_SRC_INHERITED, ZPROP_SRC_TEMPORARY } zprop_source_t;
struct libbe_dccb { void *lbh, *zhp, *props; };
static zprop_source_t property_source;
static int readonly, gets, adds, add_error, augmented;
static char copied[BE_MAXPATHLEN];
static bool zfs_prop_readonly(int p) { (void)p; return readonly; }
static int zfs_prop_get(void *h,int p,char *v,size_t n,zprop_source_t *src,
 char *source,size_t len,bool literal) {
 (void)h; (void)source; (void)len; gets++; *src=property_source;
 if(p==ZFS_PROP_QUOTA) { snprintf(v,n,"%s",literal?"123456789":"118M"); return 0; }
 snprintf(v,n,"%s",p==ZFS_PROP_MOUNTPOINT?"/":"lz4"); return 0;
}
static char *be_mountpoint_augmented(void *h,char *p) {
 (void)h; assert(!strcmp(p,"/")); augmented++; return "/altroot";
}
static const char *zfs_prop_to_name(int p) {
 return p==ZFS_PROP_MOUNTPOINT?"mountpoint":p==ZFS_PROP_QUOTA?"quota":"compression";
}
static int nvlist_add_string(void *p,const char *name,const char *v) {
 (void)p; assert(!strcmp(name,"mountpoint") || !strcmp(name,"compression") || !strcmp(name,"quota"));
 adds++; snprintf(copied,sizeof(copied),"%s",v); return add_error;
}
'''
        after=r'''
int main(void) {
 struct libbe_dccb cb={0};
 int skip[]={ZFS_PROP_KEYFORMAT,ZFS_PROP_KEYLOCATION,ZFS_PROP_ENCRYPTION,
 ZFS_PROP_PBKDF2_ITERS,ZFS_PROP_CANMOUNT};
 for(unsigned i=0;i<sizeof(skip)/sizeof(skip[0]);i++) {
  assert(be_deep_clone_prop(skip[i],&cb)==ZPROP_CONT); assert(!gets && !adds);
 }
 readonly=1; assert(be_deep_clone_prop(ZFS_PROP_COMPRESSION,&cb)==ZPROP_CONT);
 assert(!gets && !adds); readonly=0;
 zprop_source_t sources[]={ZPROP_SRC_DEFAULT,ZPROP_SRC_INHERITED,ZPROP_SRC_TEMPORARY};
 for(unsigned i=0;i<sizeof(sources)/sizeof(sources[0]);i++) {
  property_source=sources[i]; assert(be_deep_clone_prop(ZFS_PROP_COMPRESSION,&cb)==ZPROP_CONT);
  assert(!adds);
 }
 for(int src=ZPROP_SRC_LOCAL;src<=ZPROP_SRC_RECEIVED;src++) {
  property_source=src;
  for(int failure=0;failure<2;failure++) {
   add_error=failure; int old=adds;
   assert(be_deep_clone_prop(ZFS_PROP_COMPRESSION,&cb)==(failure?ZPROP_INVAL:ZPROP_CONT));
   assert(adds==old+1 && !strcmp(copied,"lz4"));
   old=adds;
   assert(be_deep_clone_prop(ZFS_PROP_MOUNTPOINT,&cb)==(failure?ZPROP_INVAL:ZPROP_CONT));
   assert(adds==old+1 && !strcmp(copied,"/altroot"));
  }
 }
 add_error=0;
 for(int src=ZPROP_SRC_LOCAL;src<=ZPROP_SRC_RECEIVED;src++) {
  property_source=src; int old=adds;
  assert(be_deep_clone_prop(ZFS_PROP_QUOTA,&cb)==ZPROP_CONT);
  assert(adds==old+1 && !strcmp(copied,"123456789"));
 }
 assert(augmented==4);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'probe.c').write_text(before+function+after)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(root/'probe.c'),'-o',str(root/'probe')],check=True)
            subprocess.run([str(root/'probe')],check=True)

if __name__=='__main__': unittest.main()
