# SPDX-License-Identifier: BSD-2-Clause
"""Actual mountroot token/verity parser; injected preload and GEOM operations."""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r"""
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <geom/verity/g_verity_verify.h>
#define CC_WHITESPACE -1
#define CC_NONWHITESPACE -2
#define PE_EOF -1
#define PE_EOL -2
#define MD_NAME "md"
#define M_TEMP 0
#define M_WAITOK 0
#define M_ZERO 0
#define nitems(a) (sizeof(a)/sizeof((a)[0]))
static int live,locked,decoded,created,mode;
static bool root_mount_verity_requested;
static int root_mount_mddev = -1;
static const char *expected_backing = "pool/base";
static void *allocate(size_t n,int type,int flags) {
 (void)type;(void)flags;void *p=calloc(1,n);assert(p);live++;return p;
}
static void release(void *p,int type) {(void)type;if(p){live--;free(p);}}
#define malloc allocate
#define free release
struct g_provider {int dummy;};static struct g_provider backing,output;
static void g_topology_lock(void) {assert(!locked);locked=1;}
static void g_topology_unlock(void) {assert(locked);locked=0;}
static int g_verity_preload_decode(struct g_verity_root *root) {
 assert(!locked);decoded++;memset(root,0,sizeof(*root));root->root_hash[0]=42;
 return mode==1?EAUTH:0;
}
static struct g_provider *g_provider_by_name(const char *name) {
 assert(locked && !strcmp(name,expected_backing));return mode==2?NULL:&backing;
}
static int g_verity_provider_create(struct g_provider *pp,const char *name,
 const struct g_verity_root *root,unsigned workers,size_t entries,size_t window,
 size_t budget,struct g_provider **result) {
 assert(locked && pp==&backing && !strcmp(name,"verified-base"));
 assert(root->root_hash[0]==42 && workers==3 && entries==8 && window==65536 && budget==1048576);
 created++;if(mode==3)return ENOMEM;*result=&output;return 0;
}
"""
MAIN=r"""
static int run(const char *input) {
 char buffer[256];strcpy(buffer,input);char *cursor=buffer;
 root_mount_verity_requested=false;
 int result=parse_dir_verity(&cursor);assert(!live && !locked && root_mount_verity_requested);return result;
}
int main(void) {
 const char *valid=" pool/base verified-base 3 8 65536 1048576\n";
 assert(run(valid)==0 && decoded==1 && created==1);
 for(mode=1;mode<=3;mode++) {
  decoded=created=0;
  assert(run(valid)==(mode==1?EAUTH:mode==2?ENOENT:ENOMEM));
  assert(decoded==1 && created==(mode==3));
 }
 mode=0;
 const char *invalid[]={"", " pool/base\n", " pool/base verified-base 3 8 65536\n",
  " pool/base verified-base -1 8 65536 1048576\n",
  " pool/base verified-base 4294967296 8 65536 1048576\n",
  " pool/base verified-base 3 184467440737095516160 65536 1048576\n",
  " pool/base verified-base 3 8 x 1048576\n",
  " pool/base verified-base 3 8 65536 1048576 extra\n"};
 for(unsigned i=0;i<nitems(invalid);i++) {
  decoded=created=0;assert(run(invalid[i])!=0 && !decoded && !created);
 }
 assert(run("pool/base verified-base 3 8 65536 1048576")==0);
 const char *dynamic="md# verified-base 3 8 65536 1048576\n";
 decoded=created=0;
 assert(run(dynamic)==ENOENT && !decoded && !created);
 for(int unit=0;unit<=9;unit++) {
  char name[4];snprintf(name,sizeof(name),"md%d",unit);
  root_mount_mddev=unit;expected_backing=name;
  assert(run(dynamic)==0);
 }
 const int larger[]={10,99,100,INT_MAX};
 for(unsigned i=0;i<nitems(larger);i++) {
  char name[32];snprintf(name,sizeof(name),"md%d",larger[i]);
  root_mount_mddev=larger[i];expected_backing=name;
  assert(run(dynamic)==0);
 }
 root_mount_mddev=123;
 char *expanded=root_mount_mdname("/dev/md#s1a");
 assert(expanded && !strcmp(expanded,"/dev/md123s1a"));free(expanded,M_TEMP);
 assert(root_mount_mdname("/dev/ada0")==NULL);
 root_mount_mddev=-1;assert(root_mount_mdname("md#")==NULL);
 root_mount_mddev=4;expected_backing="md7";
 assert(run("md7 verified-base 3 8 65536 1048576\n")==0);
 expected_backing="pool/md#";
 assert(run("pool/md# verified-base 3 8 65536 1048576\n")==0);

 return 0;
}
"""
def extract(source,name):
    at=source.index(name+'(');start=source.rfind('\nstatic',0,at)+1
    return source[start:source.index('\n}\n',at)+3]
class Directive(unittest.TestCase):
    def test_explicit_arguments_and_failure_cleanup(self):
        source=(ROOT/'sys/kern/vfs_mountroot.c').read_text()
        parts=[extract(source,name) for name in ('parse_peek','parse_advance',
            'parse_skipto','parse_token','root_mount_mdname','parse_verity_size','parse_dir_verity')]
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/'test.c';binary=Path(directory)/'test';c.write_text(PRE+''.join(parts)+MAIN)
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'sys'),str(c),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,timeout=10)
if __name__=='__main__':unittest.main()
