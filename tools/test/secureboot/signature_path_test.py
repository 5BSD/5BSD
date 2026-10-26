# SPDX-License-Identifier: BSD-2-Clause
"""Production signature-path parsing with guarded memory, no cryptography seams claimed."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
class SignaturePaths(unittest.TestCase):
    def test_signature_suffix_and_short_names(self):
        source=(ROOT/'lib/libsecureboot/vets.c').read_text()
        start=source.index('unsigned char *\nverify_sig(')
        end=source.index('\n}\n',start)+3
        harness=r'''
#include <sys/param.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
typedef struct { int key_type; } br_x509_pkey;
typedef struct { unsigned char *oid; char *buf; size_t len; int status; } br_name_element;
#define VEF_VERBOSE 1
#define DEBUG_PRINTF(level,args) ((void)0)
static int signer_calls;
static const char *expected;
static br_x509_pkey *verify_signer(const char *p,br_name_element *n,int count) {
 (void)n; assert(count==1); signer_calls++; assert(expected && !strcmp(p,expected)); return NULL;
}
static const char *ve_error_get(void) { return "fixture signer unavailable"; }
static void xfreepkey(br_x509_pkey *p) { (void)p; }
'''
        cases=r'''
int main(void) {
 long page=sysconf(_SC_PAGESIZE); assert(page>MAXPATHLEN);
 char *mem=mmap(NULL,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(mem!=MAP_FAILED && mprotect(mem,(size_t)page,PROT_NONE)==0);
 char *path=mem+page;
 const char *bad[]={"","a","ab","sig",".sig","asig","manifest.sigx","manifest.asc"};
 for(size_t i=0;i<nitems(bad);i++) {
  strcpy(path,bad[i]); signer_calls=0; expected=NULL;
  assert(verify_sig(path,0)==NULL && signer_calls==0);
 }
 strcpy(path,"manifest.sig"); expected="manifest.certs";
 assert(verify_sig(path,0)==NULL && signer_calls==1);
 memset(path,'x',MAXPATHLEN-1); path[MAXPATHLEN-1]=0;
 signer_calls=0; expected=NULL;
 assert(verify_sig(path,0)==NULL && signer_calls==0);
 assert(munmap(mem,(size_t)page*2)==0);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            c=Path(tmp)/'test.c';c.write_text(harness+source[start:end]+cases)
            binary=Path(tmp)/'test'
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,timeout=5,cwd=tmp)
if __name__=='__main__':unittest.main()
