# SPDX-License-Identifier: BSD-2-Clause
"""Actual loader mount bookkeeping with allocation failure after filesystem open."""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r"""
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define DEBUG_PRINTF(level,args)
static int calls,fail_at,live,fs_open;
static void *allocate(size_t n) {
 if(++calls==fail_at)return NULL;void *p=malloc(n);assert(p);live++;return p;
}
static char *duplicate(const char *s) {
 if(++calls==fail_at)return NULL;char *p=strdup(s);assert(p);live++;return p;
}
static void release(void *p) {if(p){live--;free(p);}}
#define malloc allocate
#define strdup duplicate
#define free release
static int is_tftp(void) {return 0;}
static int start(const char *dev,const char *path,void **data) {
 assert(!strcmp(dev,"verity7:") && !strcmp(path,"/"));
 assert(!fs_open);fs_open=1;*data=&fs_open;return 0;
}
static int finish(const char *dev,void *data) {
 assert(!strcmp(dev,"verity7:") && data==&fs_open && fs_open);fs_open=0;return 0;
}
struct fs_ops {int (*fo_mount)(const char *,const char *,void **);
 int (*fo_unmount)(const char *,void *);};
static struct fs_ops fs={start,finish};
static struct fs_ops *file_system[]={&fs,NULL};
"""
MAIN=r"""
int main(void) {
 for(int failure=1;failure<=3;failure++) {
  fail_at=failure;calls=0;
  assert(mount("verity7:","/",0,NULL)==ENOMEM);
  assert(!fs_open && !live && STAILQ_EMPTY(&mnt_list));
 }
 fail_at=0;assert(mount("verity7:","/",0,NULL)==0);
 assert(mount("verity7:","/",0,NULL)==0);
 assert(unmount("verity7:",0)==0 && fs_open);
 assert(unmount("verity7:",0)==0 && !fs_open && !live);
 return 0;
}
"""
class Mount(unittest.TestCase):
    def test_failed_bookkeeping_closes_filesystem(self):
        source=(ROOT/'stand/libsa/mount.c').read_text().replace('#include <stand.h>','')
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/'test.c';binary=Path(directory)/'test';c.write_text(PRE+source+MAIN)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,timeout=10)
if __name__=='__main__':unittest.main()
