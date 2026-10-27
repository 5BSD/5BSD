# SPDX-License-Identifier: BSD-2-Clause
"""Actual direct verifier must honor rewind/restore failures."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]

class DirectIO(unittest.TestCase):
    def test_seek_failures(self):
        s=(ROOT/'lib/libsecureboot/veopen.c').read_text();a=s.index('static int\nverify_fingerprint(')
        function=s[a:s.index('\n}\n',a)+3]
        a=s.index('static int\nfingerprint_hash(')
        function=s[a:s.index('\n}\n',a)+3]+function
        before=r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#define PAGE_SIZE 4096
#define br_sha256_SIZE 32
#define VE_FINGERPRINT_WRONG -1
#define VE_FINGERPRINT_UNKNOWN -2
#define VE_FINGERPRINT_IGNORE 2
#define VE_FINGERPRINT_OK 1
typedef struct { const void *vtable; } br_hash_compat_context;
typedef struct { void (*init)(void *); void (*update)(void *,const void *,size_t); } br_hash_class;
static off_t position;
static int seeks, fail_seek, reads, read_error, hashes;
static size_t hashed;
static void init(void *c) { (void)c; hashed=0; }
static void update(void *c,const void *p,size_t n) { (void)c;(void)p;hashed+=n; }
static const br_hash_class br_sha256_vtable={.init=init,.update=update};
static off_t seek_input(int fd,off_t off,int whence) {
 (void)fd;assert(whence==SEEK_SET);seeks++;
 if(seeks==fail_seek) return -1;
 position=off; return off;
}
static ssize_t read_input(int fd,void *p,size_t n) {
 (void)fd;reads++;if(read_error) return -1;
 assert(position>=0 && position<=8);
 size_t left=8-position;if(n>left) n=left;memset(p,'x',n);position+=n;return n;
}
#define lseek seek_input
#define read read_input
static void ve_error_set(const char *fmt,...) { (void)fmt; }
static int ve_check_hash(br_hash_compat_context *c,const br_hash_class *md,const char *p,const char *want,size_t n) {
 (void)c;(void)md;(void)p;(void)want;assert(n==32);hashes++;assert(hashed==8);return VE_FINGERPRINT_OK;
}
'''
        main=r'''
int main(void) {
 for(int scenario=0;scenario<7;scenario++) {
  off_t start=scenario==0 || scenario==4?0:4;
  seeks=reads=hashes=fail_seek=read_error=0;position=start;
  if(scenario==2) fail_seek=1;
  if(scenario==3) fail_seek=2;
  if(scenario==4) fail_seek=1;
  if(scenario==5) read_error=1;
  if(scenario==6) start=-1;
  int rc=verify_fingerprint(1,"file","sha256=expected",start);
  if(scenario<2) {
   assert(rc==VE_FINGERPRINT_OK && hashes==1 && position==start);
  } else {
   assert(rc==VE_FINGERPRINT_WRONG && hashes==0);
   if(scenario==2 || scenario==6) assert(reads==0);
   if(scenario==6) assert(seeks==0);
  }
 }
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'probe.c').write_text(before+function+main)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(p/'probe.c'),'-o',str(p/'probe')],check=True)
            subprocess.run([str(p/'probe')],check=True)

if __name__=='__main__': unittest.main()
