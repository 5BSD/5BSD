# SPDX-License-Identifier: BSD-2-Clause
"""Actual loader environment/current-device transaction with allocation faults."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r"""
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define environ loader_environ
static int calls,fail_at,live,old_mount,new_mount,mount_failure;
static void *allocate(size_t n,size_t size) {
 if(++calls==fail_at)return NULL;
 void *p=calloc(n,size);assert(p);live++;return p;
}
static char *duplicate(const char *s) {
 if(++calls==fail_at)return NULL;
 char *p=strdup(s);assert(p);live++;return p;
}
static void release(void *p) {if(p){live--;free(p);}}
#define calloc allocate
#define strdup duplicate
#define free release
static int mount(const char *dev,const char *path,int flags,void *data) {
 (void)data;assert(!strcmp(dev,"new:") && !strcmp(path,"/") && !flags);
 if(mount_failure)return EIO;new_mount++;return 0;
}
static int unmount(const char *dev,int flags) {
 assert(!flags);
 if(!strcmp(dev,"new:")){assert(new_mount>0);new_mount--;}
 else {assert(!strcmp(dev,"old:") && old_mount>0);old_mount--;}
 return 0;
}
"""
MAIN=r"""
static void clear(void) {
 while(environ) {
  struct env_var *e=environ;environ=e->ev_next;
  if(e->ev_flags&EV_DYNAMIC)free(e->ev_value);
  free(e->ev_name);free(e);
 }
 assert(live==0);
}
int main(void) {
 for(int failure=1;failure<=3;failure++) {
  calls=0;fail_at=failure;
  assert(env_setenv("currdev",EV_VOLATILE,"new:",NULL,NULL)==ENOMEM);
  assert(!environ && !live);
 }
 fail_at=0;
 assert(env_setenv("currdev",EV_VOLATILE|EV_NOKENV,"old:",NULL,NULL)==0);
 struct env_var *e=environ;void *prior=e->ev_value;int before=live;
 calls=0;fail_at=1;
 assert(env_setenv("currdev",EV_VOLATILE,"new:",NULL,NULL)==ENOMEM);
 assert(e->ev_value==prior && e->ev_flags==(EV_DYNAMIC|EV_NOKENV) && live==before);
 fail_at=0;
 /* A source pointer into the old value must be copied before that value is freed. */
 assert(env_setenv("currdev",EV_VOLATILE,e->ev_value,NULL,NULL)==0);
 assert(!strcmp(e->ev_value,"old:"));
 assert(env_setenv("currdev",EV_VOLATILE,NULL,NULL,NULL)==0 && e->ev_value==NULL);
 assert(env_setenv("aaa",0,"static",NULL,NULL)==0);
 assert(env_setenv("zzz",0,"static",NULL,NULL)==0);
 assert(!strcmp(environ->ev_name,"aaa") && environ->ev_next==e);
 assert(e->ev_prev==environ && e->ev_next->ev_prev==e);clear();
 for(int failure=0;failure<=3;failure++) {
  fail_at=0;mount_failure=0;
  assert(env_setenv("currdev",EV_VOLATILE,"old:",mount_currdev,NULL)==0);
  e=environ;old_mount=1;new_mount=0;calls=0;
  fail_at=failure==3?0:failure;mount_failure=failure==3;
  int result=env_setenv("currdev",EV_VOLATILE,"new:",NULL,NULL);
  assert(result==(failure==0?0:failure==3?EIO:ENOMEM));
  assert(old_mount==(failure!=0) && new_mount==(failure==0));
  assert(!strcmp(e->ev_value,failure==0?"new:":"old:"));
  clear();
 }
 return 0;
}
"""
def function(source,name):
    start=source.index(name)
    return source[start:source.index('\n}\n',start)+3]
class Environment(unittest.TestCase):
    def test_failed_replacement_preserves_value_and_mount(self):
        header=(ROOT/'stand/libsa/stand.h').read_text()
        begin=header.index('#define EV_DYNAMIC');end=header.index('extern struct env_var',begin)
        environment=(ROOT/'stand/libsa/environment.c').read_text()
        code=PRE+header[begin:end]+'\nstatic struct env_var *environ;\n'
        code+=function(environment,'struct env_var\t*\nenv_getenv(')
        code+=function(environment,'int\nenv_setenv(')
        code+=function((ROOT/'stand/common/misc.c').read_text(),'int mount_currdev(')
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/'test.c';binary=Path(directory)/'test';c.write_text(code+MAIN)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,timeout=10)
if __name__=='__main__':unittest.main()
