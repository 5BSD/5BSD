# SPDX-License-Identifier: BSD-2-Clause
"""Bounded DER framing tests; this does not validate X.509 certificate semantics."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]

class Framing(unittest.TestCase):
    def test_lengths_and_guarded_truncation(self):
        harness = r'''
#include <sys/mman.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "x509_tbs.h"
static void reject(const unsigned char *p, size_t n) {
 size_t length=99;
 assert(ve_x509_tbs(p,n,&length)==NULL && length==0);
}
int main(void) {
 const unsigned char short_der[]={0x30,5,0x30,1,0,5,0};
 unsigned char long_der[138]={0x30,0x81,135,0x30,0x81,128};
 size_t n;
 assert(ve_x509_tbs(short_der,sizeof(short_der),&n)==short_der+2 && n==3);
 assert(ve_x509_tbs(long_der,sizeof(long_der),&n)==long_der+3 && n==131);
 long pagesize=sysconf(_SC_PAGESIZE); assert(pagesize>138);
 unsigned char *guard=mmap(NULL,(size_t)pagesize*2,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0);
 assert(guard!=MAP_FAILED);
 assert(mprotect(guard+pagesize,(size_t)pagesize,PROT_NONE)==0);
 for(size_t i=0;i<sizeof(long_der);i++) {
  unsigned char *p=guard+pagesize-i;
  memcpy(p,long_der,i);
  reject(p,i);
 }
 assert(munmap(guard,(size_t)pagesize*2)==0);
 reject(NULL,0);
 unsigned char bad[][12]={
  {0x31,2,0x30,0}, {0x30,0x80,0,0}, {0x30,0x81,2,0x30,0},
  {0x30,0x82,0,128}, {0x30,0x89,1}, {0x30,2,0x30,1},
  {0x30,2,0x31,0}, {0x30,2,0x30,0,0},
  {0x30,0x88,255,255,255,255,255,255,255,255}};
 const size_t sizes[]={4,4,5,4,3,4,4,5,10};
 for(size_t i=0;i<sizeof(sizes)/sizeof(sizes[0]);i++)reject(bad[i],sizes[i]);
 long_der[4]=0x80;reject(long_der,sizeof(long_der));
 long_der[4]=0x88;memset(long_der+5,255,8);reject(long_der,sizeof(long_der));
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'test.c'; source.write_text(harness)
            binary=Path(tmp)/'test'
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I',str(ROOT/'lib/libsecureboot'),str(source),str(ROOT/'lib/libsecureboot/x509_tbs.c'),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,timeout=5)

if __name__ == '__main__':
    unittest.main()
