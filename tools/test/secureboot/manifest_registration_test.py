# SPDX-License-Identifier: BSD-2-Clause
"""Native allocation-failure checks for actual manifest registration/loading."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]

class ManifestRegistration(unittest.TestCase):
    def test_allocation_failures_do_not_publish_manifest(self):
        s=(ROOT/'lib/libsecureboot/veopen.c').read_text()
        declarations=s[s.index('struct fingerprint_info {'):s.index('\n/**')]
        a=s.index('int\nfingerprint_info_add('); registration=s[a:s.index('\n}\n',a)+3]
        s=(ROOT/'lib/libsecureboot/verify_file.c').read_text();a=s.index('int\nload_manifest(')
        loader=s[a:s.index('\n}\n',a)+3]
        before=r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#define DEBUG_PRINTF(level,args) ((void)0)
#define VE_FINGERPRINT_NONE 0
#define VE_NOT_CHECKED -2
#define VE_VERIFIED 1
#define VE_FINGERPRINT_WRONG -1
static int attempts, fail_at, allocations, recorded, loaded_manifests, VerifyFlags;
static void *allocate(size_t n) {
 if(++attempts==fail_at) return NULL;
 void *p=malloc(n); assert(p); allocations++; return p;
}
static void release(void *p) { if(p) { assert(allocations>0); allocations--; free(p); } }
static char *duplicate(const char *s) { char *p=allocate(strlen(s)+1); if(p) strcpy(p,s); return p; }
#define malloc allocate
#define free release
#define strdup duplicate
static int is_verified(struct stat *s) { (void)s; return VE_NOT_CHECKED; }
static void ve_utc_set(time_t t) { (void)t; }
static char *verify_signed(const char *s,int f) { (void)s; (void)f; return strdup("kernel sha256=example\n"); }
static void add_verify_status(struct stat *s,int status) { (void)s; recorded=status; }
'''
        main=r'''
int main(void) {
 struct stat st={.st_dev=1};
 for(int explicit_prefix=0;explicit_prefix<2;explicit_prefix++) {
  for(fail_at=1;fail_at<=5;fail_at++) {
   attempts=allocations=recorded=loaded_manifests=0;
   int status=load_manifest("/boot/manifest",explicit_prefix?"/boot":NULL,"skip",&st);
   if(fail_at<=4) {
    assert(status==VE_FINGERPRINT_WRONG && !loaded_manifests);
    assert(recorded==(fail_at==1?VE_FINGERPRINT_WRONG:0));
    assert(LIST_EMPTY(&fi_list) && allocations==0);
   } else {
    assert(status==VE_VERIFIED && loaded_manifests && recorded==VE_VERIFIED);
    struct fingerprint_info *p=LIST_FIRST(&fi_list);
    assert(p && !strcmp(p->fi_prefix,"/boot") && !strcmp(p->fi_skip,"skip"));
    assert(p->fi_dev==st.st_dev && allocations==4);
    LIST_REMOVE(p,entries); free((void *)p->fi_data); free(p->fi_prefix); free(p->fi_skip); free(p);
    assert(!allocations);
   }
  }
 }
 fail_at=0; attempts=0;
 assert(fingerprint_info_add(NULL,NULL,NULL,"data",&st)==-1);
 assert(fingerprint_info_add("manifest",NULL,NULL,"data",&st)==-1);
 assert(!allocations && LIST_EMPTY(&fi_list));
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);(p/'probe.c').write_text(before+declarations+registration+loader+main)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(p/'probe.c'),'-o',str(p/'probe')],check=True)
            subprocess.run([str(p/'probe')],check=True)

if __name__=='__main__': unittest.main()
