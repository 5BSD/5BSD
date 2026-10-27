# SPDX-License-Identifier: BSD-2-Clause
"""Actual file_addbuf failure publication and resource lifetime checks."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r"""
#include <assert.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
typedef uintptr_t vm_offset_t;
struct preloaded_file {char *f_name,*f_type,*f_args;void *f_metadata;
 int f_loader;vm_offset_t f_addr;size_t f_size;};
static int mode, live, strings, copies, inserted;
static vm_offset_t loadaddr;
static char *command_errmsg,command_errbuf[256];
static struct preloaded_file kernel,*published;
static void release(void *p) {if(p) {live--;free(p);}}
static char *duplicate(const char *s) {
 strings++;
 if((mode==3 && strings==1)||(mode==4 && strings==2)) return NULL;
 char *p=strdup(s);assert(p);live++;return p;
}
#define free release
#define strdup duplicate
static struct preloaded_file *file_alloc(void) {
 if(mode==2) return NULL;
 struct preloaded_file *p=calloc(1,sizeof(*p));assert(p);live++;return p;
}
static struct preloaded_file *file_findfile(const char *a,const char *b) {
 (void)a;(void)b;return mode==1?NULL:&kernel;
}
static vm_offset_t md_align(vm_offset_t value) {return (value+4095)&~(vm_offset_t)4095;}
static void file_insert_tail(struct preloaded_file *p) {inserted++;published=p;}
static ssize_t copyin(const void *buf,vm_offset_t dest,size_t len) {
 (void)buf;assert(dest==8192 && len==384);copies++;
 return mode==5?-1:mode==6?(ssize_t)len-1:(ssize_t)len;
}
static struct {ssize_t (*arch_copyin)(const void *,vm_offset_t,size_t);} archsw={copyin};
"""
MAIN=r"""
int main(void) {
 unsigned char buffer[384]={0};
 for(mode=0;mode<9;mode++) {
  live=strings=copies=inserted=0;published=NULL;loadaddr=8192;
  size_t len=sizeof(buffer);
  if(mode==7) len=SIZE_MAX;
  if(mode==8) loadaddr=UINTPTR_MAX-3;
  vm_offset_t before=loadaddr;
  int result=file_addbuf("root", "bip_root_descriptor",len,buffer);
  assert((result==0)==(mode==0));
  assert(inserted==(mode==0));
  assert(copies==((mode==0 || mode==5 || mode==6)?1:0));
  if(mode==0) {
   assert(loadaddr==8192+sizeof(buffer));
   assert(published->f_addr==8192 && published->f_size==sizeof(buffer));
   free(published->f_name);free(published->f_type);free(published);
  } else assert(loadaddr==before);
  assert(live==0);
 }
 return 0;
}
"""
class Buffer(unittest.TestCase):
    def test_no_publication_or_leak_on_failure(self):
        source=(ROOT/'stand/common/module.c').read_text()
        start=source.index('int\nfile_addbuf(')
        source=source[start:source.index('\n}\n',start)+3]
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/'test.c';binary=Path(directory)/'test'
            c.write_text(PRE+source+MAIN)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,timeout=10)
if __name__=='__main__':unittest.main()
