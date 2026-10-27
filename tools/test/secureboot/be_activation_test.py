# SPDX-License-Identifier: BSD-2-Clause
"""Native libbe activation error checks; no pool or VM operations."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]

class Activation(unittest.TestCase):
    def test_path_errors_and_deactivation_cleanup(self):
        source = (ROOT / 'lib/libbe/be.c').read_text()
        functions = []
        for name in ('be_deactivate', 'be_activate'):
            start = source.index('int\n' + name + '(')
            functions.append(source[start:source.index('\n}\n', start) + 3])
        preamble = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define BE_MAXPATHLEN 64
#define BE_ERR_SUCCESS 0
#define ZFS_TYPE_DATASET 1
#define ZFS_TYPE_FILESYSTEM 2
#define lzbe_add 1
typedef struct { void *lzh, *active_phandle; char *bootfs; } libbe_handle_t;
typedef struct { int live; } zfs_handle_t;
static zfs_handle_t handle;
static int concat_error, exists_error, open_error, prop_error, boot_error;
static int exists_calls, opens, closes, props, boots, selections;
static int promote_error, promote_calls, select_error;
static bool origin;
static int origins_remaining;
static int set_error(libbe_handle_t *h, int e) { (void)h; return e; }
static int be_root_concat(libbe_handle_t *h, const char *s, char *p) {
 (void)h; (void)s; if(concat_error) return concat_error;
 strcpy(p,"pool/ROOT/new"); return 0;
}
static int be_exists(libbe_handle_t *h, const char *p) {
 (void)h; (void)p; exists_calls++; return exists_error;
}
static const char *zpool_get_name(void *p) { (void)p; return "pool"; }
static int lzbe_set_boot_device(const char *p, int op, const char *ds) {
 (void)p; (void)op; (void)ds; boots++; return boot_error;
}
static zfs_handle_t *zfs_open(void *p, const char *ds, int type) {
 (void)p; (void)ds; (void)type; opens++; if(open_error) return NULL;
 assert(!handle.live); handle.live=1; return &handle;
}
static void zfs_close(zfs_handle_t *h) { assert(h->live); h->live=0; closes++; }
static int zfs_prop_set(zfs_handle_t *h, const char *p, const char *v) {
 assert(h->live); assert(!strcmp(p,"canmount")); assert(!strcmp(v,"noauto"));
 props++; return prop_error;
}
static int zpool_set_prop(void *p, const char *n, const char *v) {
 (void)p; (void)n; (void)v; assert(promote_calls > 0 && origins_remaining == 0); selections++; return select_error;
}
static int be_zfs_promote(zfs_handle_t *h, bool *found) {
 assert(h->live); promote_calls++; *found=origin || origins_remaining > 0;
 if(origins_remaining > 0) origins_remaining--;
 return promote_error;
}
'''
        main = r'''
int main(void) {
 libbe_handle_t h={.bootfs="pool/ROOT/old"};
 for(int temporary=0; temporary<2; temporary++) {
  concat_error=17;
  assert(be_activate(&h,"bad",temporary)==17);
  assert(!exists_calls && !opens && !boots && !selections);
 }
 concat_error=0; exists_error=19;
 assert(be_activate(&h,"missing",false)==19);
 assert(exists_calls==1 && !opens && !boots && !selections);
 exists_error=0; boot_error=23;
 assert(be_activate(&h,"new",true)==23);
 assert(boots==1 && !opens && !selections);
 open_error=1;
 assert(be_deactivate(&h,h.bootfs,false)==1);
 assert(opens==1 && !closes && !props);
 open_error=0; prop_error=5;
 assert(be_deactivate(&h,h.bootfs,false)==1);
 assert(opens==2 && closes==1 && props==1 && !handle.live);
 assert(be_activate(&h,"new",false)==-1);
 assert(opens==4 && closes==3 && !selections && !handle.live);
 prop_error=0;
 assert(be_activate(&h,"new",false)==0);
 assert(opens==6 && closes==5 && selections==1 && !handle.live);
 assert(be_deactivate(&h,h.bootfs,true)==23);
 assert(boots==2 && opens==6 && closes==5);
 for(int found=0; found<2; found++) {
  origin=found; promote_error=31;
  opens=closes=props=selections=promote_calls=0;
  assert(be_activate(&h,"new",false)!=0);
  assert(opens==1 && closes==1 && !props && !selections && !handle.live);
 }
 origin=false; promote_error=0; open_error=1;
 opens=closes=props=selections=promote_calls=0;
 assert(be_activate(&h,"new",false)!=0);
 assert(opens==1 && !closes && !props && !selections && !promote_calls);
 open_error=0; select_error=9;
 opens=closes=props=selections=promote_calls=0;
 assert(be_activate(&h,"new",false)!=0);
 assert(opens==2 && closes==2 && props==1 && selections==1 && !handle.live);
 select_error=0; origins_remaining=2;
 opens=closes=props=selections=promote_calls=0;
 assert(be_activate(&h,"new",false)==0);
 assert(promote_calls==3 && opens==4 && closes==4 && props==1 && selections==1);
 assert(!handle.live && !origins_remaining);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path/'probe.c').write_text(preamble+'\n'.join(functions)+main)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(path/'probe.c'),'-o',str(path/'probe')],check=True)
            subprocess.run([str(path/'probe')],check=True)

if __name__ == '__main__':
    unittest.main()
