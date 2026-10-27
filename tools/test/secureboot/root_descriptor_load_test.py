# SPDX-License-Identifier: BSD-2-Clause
"""Exercise actual bounded descriptor reader; verifier and arch I/O are injected."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[3]
PRE = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <geom/verity/g_verity_verify.h>
#include <geom/verity/g_verity_transition.h>
#define VE_MUST 2
#define VE_VERIFIED 1
typedef uintptr_t vm_offset_t;
#ifdef LOADER_VERIEXEC
static int scenario, copies, reads, buffers;
static size_t pos, length, target_size=G_VERITY_ROOT_BYTES;
static int verify_manifest_trust_restricted(void) {return scenario!=13;}
static unsigned char storage[4096], expected[G_VERITY_TRANSITION_BYTES];
static int verify_file(int fd,const char *p,off_t off,int severity,const char *caller) {
 (void)p;(void)caller;assert(fd==7 && off==0 && severity==VE_MUST);
 if(scenario==1) return 0;
 if(scenario==2) return 2;
 if(scenario==3) return -3;
 if(scenario==4) storage[3]^=1;
 return VE_VERIFIED;
}
static off_t seek_input(int fd,off_t off,int whence) {
 assert(fd==7 && off==0 && whence==SEEK_SET);pos=0;
 return scenario==5 ? -1 : 0;
}
static ssize_t read_input(int fd,void *buf,size_t n) {
 assert(fd==7 && n<=target_size+1);reads++;
 if(scenario==6) return -1;
 if(n>7) n=7; /* exercise repeated short reads */
 if(n>length-pos) n=length-pos;
 memcpy(buf,storage+pos,n);pos+=n;return n;
}
static int verify_buf(int fd,const char *p,const void *buf,size_t n) {
 (void)p;assert(fd==7 && n==target_size);buffers++;
 if(scenario==10) return 2;
 int result=memcmp(buf,expected,n)==0 ? VE_VERIFIED : -3;
 if(scenario==11) memset(storage,0xff,sizeof(storage));
 return result;
}
static ssize_t copyin(const void *buf,vm_offset_t dest,size_t n) {
 assert(dest==8192 && n==G_VERITY_ROOT_BYTES);copies++;
 assert(memcmp(buf,expected,n)==0);
 return scenario==12 ? n-1 : (ssize_t)n;
}
static struct {ssize_t (*arch_copyin)(const void *,vm_offset_t,size_t);} archsw={copyin};
#define read read_input
#define lseek seek_input
#endif
'''
MAIN = r'''
int main(void) {
#ifdef LOADER_VERIEXEC
 memset(expected,0x5a,sizeof(expected));
 for(scenario=0;scenario<=13;scenario++) {
  copies=reads=buffers=0;pos=0;length=G_VERITY_ROOT_BYTES;
  memset(storage,0x5a,sizeof(storage));
  if(scenario==7) length--;
  if(scenario==8) length++;
  if(scenario==9) length=sizeof(storage);
  unsigned char output[G_VERITY_ROOT_BYTES];memset(output,0xa7,sizeof(output));
  ssize_t result=verified_root_read(7,"descriptor",output);
  int valid=scenario==0 || scenario==11 || scenario==12;
  assert((result==G_VERITY_ROOT_BYTES)==valid);
  for(unsigned i=0;i<sizeof(output);i++) assert(output[i]==(valid?0x5a:0xa7));
  memset(storage,0x5a,sizeof(storage));pos=0;copies=reads=buffers=0;
  result=file_readroot(7,"descriptor",8192);
  int success=scenario==0 || scenario==11;
  assert((result==G_VERITY_ROOT_BYTES)==success);
  assert(copies==((success || scenario==12)?1:0));
  assert(pos<=G_VERITY_ROOT_BYTES+1);
  if((scenario>=1 && scenario<=3) || scenario==13) assert(!reads && !buffers);
 }
 target_size=G_VERITY_TRANSITION_BYTES;
 for(scenario=0;scenario<=13;scenario++) {
  copies=reads=buffers=0;pos=0;length=target_size;
  memset(storage,0x5a,sizeof(storage));
  if(scenario==7) length--;
  if(scenario==8) length++;
  if(scenario==9) length=sizeof(storage);
  unsigned char output[G_VERITY_TRANSITION_BYTES];memset(output,0xa7,sizeof(output));
  ssize_t result=verified_transition_read(7,"transition",output);
  int valid=scenario==0 || scenario==11 || scenario==12;
  assert((result==G_VERITY_TRANSITION_BYTES)==valid);
  for(unsigned i=0;i<sizeof(output);i++) assert(output[i]==(valid?0x5a:0xa7));
  assert(pos<=target_size+1 && !copies);
  if((scenario>=1 && scenario<=3) || scenario==13) assert(!reads && !buffers);
 }
#else
 assert(file_readroot(7,"descriptor",8192)==-1 && errno==EAUTH);
 assert(verified_transition_read(7,"transition",NULL)==-1 && errno==EAUTH);
#endif
 return 0;
}
'''
class RootDescriptorLoad(unittest.TestCase):
    def test_reader(self):
        source=(ROOT/'stand/common/module.c').read_text()
        start=source.index('static ssize_t\nfile_readroot(')
        function=source[start:source.index('\n}\n',start)+3]
        shared=(ROOT/'stand/common/verified_root.c').read_text()
        shared=shared[shared.index('static ssize_t\nverified_boot_read('):]
        function=shared+function
        with tempfile.TemporaryDirectory(prefix='root-reader-') as d:
            c=Path(d)/'test.c';binary=Path(d)/'test';c.write_text(PRE+function+MAIN)
            for enabled in (False,True):
                subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'sys')]+(['-DLOADER_VERIEXEC'] if enabled else [])+[str(c),'-o',str(binary)],check=True)
                subprocess.run([str(binary)],check=True,timeout=10)
if __name__=='__main__':unittest.main()
