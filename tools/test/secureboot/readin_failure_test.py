# SPDX-License-Identifier: BSD-2-Clause
"""Actual kboot/OFW readin functions with allocation, mapping and I/O faults."""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define PAGE_SIZE 4096
#define READIN_BUF 4096
#define min(a,b) ((a)<(b)?(a):(b))
typedef int readin_handle_t;
typedef uintptr_t vm_offset_t;
static int mode,allocations,releases,reads,maps;
static size_t copied;
static void *allocate(size_t size) {
 allocations++;if(mode==5 || mode==7)return NULL;
 void *p=malloc(size);assert(p);return p;
}
static void release(void *p) {assert(p);releases++;free(p);errno=EDOM;}
#define malloc allocate
#define free release
static ssize_t input(int fd,void *data,size_t size) {
 assert(fd==17);reads++;
 if(mode==1 || (mode==2 && reads==2))return 0;
 if(mode==3 || (mode==4 && reads==2)){errno=EAUTH;return -1;}
 memset(data,0x5a,size);return size;
}
#define VECTX_READ input
#ifdef OFW_CASE
static int ofw_mapmem(vm_offset_t dest,size_t len) {
 assert(dest && len);maps++;return mode==6 ? EACCES : 0;
}
#define bcopy(src,dest,len) copy_bytes(src,(uintptr_t)(dest),len)
#endif
static ssize_t copy_bytes(const void *src,vm_offset_t dest,size_t size) {
 memcpy((void *)dest,src,size);copied+=size;return size;
}
#define kboot_copyin copy_bytes
'''
MAIN=r'''
int main(void) {
 unsigned char output[PAGE_SIZE*2+10];
 for(mode=0;mode<8;mode++) {
#ifndef OFW_CASE
  if(mode==6)continue;
#endif
  memset(output,0,sizeof(output));allocations=releases=reads=maps=0;copied=0;errno=0;
  size_t count=mode==7 ? 0 : sizeof(output)-1;
  ssize_t result=CALL(17,(uintptr_t)output,count);
  int error=errno;
  assert(output[sizeof(output)-1]==0);
  if(mode==7){assert(result==0 && allocations==0 && reads==0 && maps==0);continue;}
  assert(allocations==1 && releases==(mode!=5));
  if(mode==0)assert(result==(ssize_t)count && copied==count && reads==3);
  if(mode==1)assert(result==0 && copied==0 && reads==1);
  if(mode==2)assert(result==PAGE_SIZE && copied==PAGE_SIZE && reads==2);
  if(mode==3 || mode==4) {
   assert(result==-1 && error==EAUTH);
   assert(copied==(mode==4 ? PAGE_SIZE : 0));
   assert(reads==(mode==4 ? 2 : 1));
  }
  if(mode==5)assert(result==-1 && error==ENOMEM && reads==0 && maps==0);
  if(mode==6)assert(result==-1 && error==EACCES && reads==0 && copied==0);
  for(size_t i=0;i<copied;i++)assert(output[i]==0x5a);
  for(size_t i=copied;i<sizeof(output);i++)assert(output[i]==0);
 }
 return 0;
}
'''
class Readin(unittest.TestCase):
    def test_callback_failures_and_eof(self):
        for path,name,ofw in [('stand/kboot/kboot/main.c','kboot_readin',False),
                              ('stand/libofw/ofw_copy.c','ofw_readin',True)]:
            with self.subTest(callback=name),tempfile.TemporaryDirectory() as directory:
                source=(ROOT/path).read_text();start=source.index('ssize_t\n'+name+'(')
                body=source[start:source.index('\n}\n',start)+3]
                folder=Path(directory);c=folder/'probe.c';binary=folder/'probe'
                c.write_text(('#define OFW_CASE 1\n' if ofw else '')+PRE+body+
                             '\n#define CALL '+name+'\n'+MAIN)
                subprocess.run(['cc','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],check=True)
                subprocess.run([str(binary)],check=True,timeout=10)
if __name__=='__main__':unittest.main()
