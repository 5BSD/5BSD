# SPDX-License-Identifier: BSD-2-Clause
"""Actual digest comparison must consume a complete expected hash token."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]

class HashToken(unittest.TestCase):
    def test_complete_tokens_and_lengths(self):
        s=(ROOT/'lib/libsecureboot/vets.c').read_text();functions=[]
        for signature in ('char *\nhexdigest(', 'int\nve_check_hash('):
            a=s.index(signature);functions.append(s[a:s.index('\n}\n',a)+3])
        before=r'''
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#define br_sha512_SIZE 64
#define VE_FINGERPRINT_WRONG -1
#define VE_FINGERPRINT_OK 1
typedef struct { const void *vtable; } br_hash_compat_context;
typedef struct { void (*out)(const void *,void *); } br_hash_class;
static int out_calls;
static void output(const void *ctx,void *buf) { (void)ctx; out_calls++; memset(buf,0xab,64); }
static void ve_error_set(const char *fmt,...) { (void)fmt; }
'''
        main=r'''
int main(void) {
 br_hash_compat_context ctx={0}; br_hash_class md={.out=output};
 const size_t lengths[]={20,32,48,64};
 for(unsigned k=0;k<sizeof(lengths)/sizeof(lengths[0]);k++) {
  size_t len=lengths[k], n=2*len; char want[160];
  for(size_t i=0;i<len;i++) { want[2*i]='a'; want[2*i+1]='b'; }
  const char *ends[]={"","\n","\r\n"," size=1","\tmode=0555"};
  for(unsigned i=0;i<sizeof(ends)/sizeof(ends[0]);i++) {
   strcpy(want+n,ends[i]); assert(ve_check_hash(&ctx,&md,"file",want,len)==VE_FINGERPRINT_OK);
  }
  const char *bad[]={"0","x","=","/","ab"};
  for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
   strcpy(want+n,bad[i]); assert(ve_check_hash(&ctx,&md,"file",want,len)==VE_FINGERPRINT_WRONG);
  }
  want[n-1]='\0'; assert(ve_check_hash(&ctx,&md,"file",want,len)==VE_FINGERPRINT_WRONG);
  want[0]='f'; assert(ve_check_hash(&ctx,&md,"file",want,len)==VE_FINGERPRINT_WRONG);
  assert(ve_check_hash(&ctx,&md,"file","",len)==VE_FINGERPRINT_WRONG);
 }
 int prior=out_calls;
 assert(ve_check_hash(&ctx,&md,"file","",0)==VE_FINGERPRINT_WRONG);
 assert(ve_check_hash(&ctx,&md,"file","",65)==VE_FINGERPRINT_WRONG);
 assert(out_calls==prior);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'probe.c').write_text(before+'\n'.join(functions)+main)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(p/'probe.c'),'-o',str(p/'probe')],check=True)
            subprocess.run([str(p/'probe')],check=True)

if __name__=='__main__': unittest.main()
