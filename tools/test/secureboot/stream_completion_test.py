# SPDX-License-Identifier: BSD-2-Clause
"""Actual streaming read/seek/close must reject incomplete input before hashing."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]

class StreamCompletion(unittest.TestCase):
    def test_completion_and_failures(self):
        s=(ROOT/'lib/libsecureboot/vectx.c').read_text();a=s.index('struct vectx {')
        structure=s[a:s.index('\n};',a)+3];functions=[]
        for signature in ('void\nvectx_discard(', 'static int\nvectx_record(', 'static ssize_t\nvectx_replay(', 'ssize_t\nvectx_read(', 'off_t\nvectx_lseek(', 'struct vectx *\nvectx_open(', 'int\nvectx_close('):
            a=s.index(signature);functions.append(s[a:s.index('\n}\n',a)+3])
        before=r'''
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#define UNIT_TEST 1
#define PAGE_SIZE 4096
#define MIN(a,b) ((a)<(b)?(a):(b))
#define VE_FINGERPRINT_WRONG -1
#define VE_FINGERPRINT_OK 1
#define VE_FINGERPRINT_NONE -2
#define VE_FINGERPRINT_UNKNOWN -3
#define VE_FINGERPRINT_IGNORE 3
#define VE_UNVERIFIED_OK 2
#define VE_GUESS -1
#define br_sha256_SIZE 32
#define VE_MUST 2
#define VE_WANT 1
#define DEBUG_PRINTF(level,args) do { if (0) printf args; } while (0)
typedef struct { const void *vtable; } br_hash_compat_context;
typedef struct { void (*update)(void *,const void *,size_t); void (*init)(void *); void (*out)(const void *,void *); } br_hash_class;
static int available, read_error, seek_error, hash_calls, reported, freed;
static size_t updated;
static int read_calls, seek_calls;
static ssize_t read_input(int fd,void *p,size_t n) {
 (void)fd; read_calls++; assert(n<=PAGE_SIZE); if(read_error) return -1;
 if(n>(size_t)available) n=available;
 memset(p,'x',n); available-=n; return n;
}
static off_t seek_input(int fd,off_t offset,int whence) {
 (void)fd; (void)whence; seek_calls++; return seek_error?-1:offset;
}
static void update(void *ctx,const void *p,size_t n) { (void)ctx; (void)p; updated+=n; }
static void init_hash(void *ctx) { (void)ctx; }
static const br_hash_class br_sha256_vtable={.update=update,.init=init_hash};
static int verify_required(void) { return 0; }
static int verify_file(int fd,const char *p,off_t off,int severity,const char *caller) {
 (void)fd;(void)p;(void)off;(void)severity;(void)caller; return 0;
}
static int verify_prep(int fd,const char *p,off_t off,struct stat *st,const char *caller) {
 (void)fd;(void)p;(void)off;(void)caller; st->st_size=8; return 0;
}
static int severity_guess(const char *p) { (void)p; return VE_MUST; }
static char *fingerprint_info_lookup(int fd,const char *p) { (void)fd;(void)p; return "sha256=expected"; }
static void release(void *p) { if(p)freed++; free(p); }
#define read read_input
#define lseek seek_input
#define free release
static int ve_check_hash(br_hash_compat_context *c,const br_hash_class *md,const char *p,const char *w,size_t n) {
 (void)c;(void)md;(void)p;(void)w;(void)n; hash_calls++; return VE_FINGERPRINT_OK;
}
static void ve_error_set(const char *fmt,...) { (void)fmt; }
static void verify_report(const char *p,int severity,int rc,void *st) {
 (void)p;(void)severity;(void)st;reported=rc;
}
'''
        main=r'''
int main(void) {
 br_hash_class md={.update=update};
 for(int scenario=0;scenario<7;scenario++) {
  struct vectx *ctx=calloc(1,sizeof(*ctx)); assert(ctx);
  ctx->vec_md=&md;ctx->vec_path="file";ctx->vec_want="expected";
  ctx->vec_size=8;ctx->vec_hashsz=32;ctx->vec_severity=VE_MUST;
  available=8;read_error=seek_error=hash_calls=reported=freed=0;updated=0;
  int expected=VE_FINGERPRINT_OK;
  switch(scenario) {
   case 1: available=4;expected=VE_FINGERPRINT_WRONG;break;
   case 2: read_error=1;expected=VE_FINGERPRINT_WRONG;break;
   case 3: ctx->vec_size=-1;available=4;break;
   case 4: ctx->vec_off=ctx->vec_hashed=12;seek_error=1;expected=VE_FINGERPRINT_WRONG;break;
   case 5: ctx->vec_off=ctx->vec_hashed=12;expected=VE_FINGERPRINT_WRONG;break;
   case 6: ctx->vec_size=0;available=0;break;
  }
  assert(vectx_close(ctx,"test")== (expected<0?expected:0));
  assert(reported==expected && freed==1);
  assert(hash_calls==(expected==VE_FINGERPRINT_OK?1:0));
  if(scenario==0) assert(updated==8);
  if(scenario==3) assert(updated==4);
 }
 char buffer[8];
 struct vectx ctx={.vec_md=&md,.vec_size=-1,.vec_hashsz=32,.vec_path="file"};
 available=8;read_error=seek_error=0;updated=0;
 for(int hashing=0;hashing<2;hashing++) {
  ctx.vec_hashsz=hashing?32:0; read_calls=0; errno=0;
  assert(vectx_read(&ctx,buffer,(size_t)SSIZE_MAX+1)==-1 && errno==EINVAL);
  assert(!read_calls && !updated && !ctx.vec_off && !ctx.vec_hashed);
 }
 ctx.vec_hashsz=32;
 assert(vectx_read(&ctx,buffer,MIN((size_t)SSIZE_MAX,(size_t)INT_MAX+1))==8);
 assert(updated==8 && ctx.vec_off==8 && ctx.vec_hashed==8);
 ctx.vec_off=0;ctx.vec_hashed=(off_t)INT_MAX+8;available=8;updated=0;
 /* An invented hashed extent without replay evidence is not readable.
  * The short backing read must latch failure instead of skipping verification. */
 assert(vectx_read(&ctx,buffer,sizeof(buffer))==-1);
 assert(updated==0 && ctx.vec_off==0 && ctx.vec_hashed==(off_t)INT_MAX+8);
 ctx.vec_status=0;
 ctx.vec_size=8;ctx.vec_off=4;ctx.vec_hashed=8;seek_error=1;
 assert(vectx_lseek(&ctx,2,SEEK_SET)==-1);
 assert(ctx.vec_off==4 && ctx.vec_hashed==8);
 seek_error=0;
 assert(vectx_lseek(&ctx,2,SEEK_SET)==2);
 assert(ctx.vec_off==2 && ctx.vec_hashed==8);
 read_calls=seek_calls=0;
 assert(vectx_lseek(&ctx,-1,SEEK_SET)==-1);
 assert(vectx_lseek(&ctx,-9,SEEK_END)==-1);
 assert(!read_calls && !seek_calls && ctx.vec_off==2 && ctx.vec_hashed==8);
 ctx.vec_size=-1;ctx.vec_off=ctx.vec_hashed=INT64_MAX-1;
 assert(vectx_lseek(&ctx,2,SEEK_CUR)==-1);
 assert(vectx_lseek(&ctx,INT64_MIN,SEEK_CUR)==-1);
 assert(!read_calls && !seek_calls && ctx.vec_off==INT64_MAX-1);
 ctx.vec_size=0;ctx.vec_off=ctx.vec_hashed=0;
 assert(vectx_lseek(&ctx,1,SEEK_SET)==-1);
 assert(!read_calls && !seek_calls);
 ctx.vec_size=-1;ctx.vec_closing=1;
 assert(vectx_lseek(&ctx,-1,SEEK_END)==-1);
 assert(!read_calls && !seek_calls);
 ctx.vec_closing=0;ctx.vec_size=8;available=8;updated=0;
 assert(vectx_lseek(&ctx,3,SEEK_CUR)==3);
 assert(updated==3 && ctx.vec_hashed==3);
 assert(vectx_lseek(&ctx,-2,SEEK_CUR)==1);
 assert(ctx.vec_off==1 && ctx.vec_hashed==3);
 available=7;
 assert(vectx_lseek(&ctx,-1,SEEK_END)==7);
 assert(ctx.vec_off==7 && ctx.vec_hashed==7 && updated==7);
 for(int scenario=0;scenario<8;scenario++) {
  off_t start=4;
  available=8;read_error=seek_error=read_calls=seek_calls=hash_calls=freed=0;updated=0;
  switch(scenario) {
   case 1: seek_error=1;break;
   case 2: read_error=1;break;
   case 3: available=2;break;
   case 4: start=-1;break;
   case 5: start=9;break;
   case 6: start=0;break;
   case 7: start=8;break;
  }
  int error=0;
  struct vectx *opened=vectx_open(1,"file",VE_MUST,start,NULL,&error,"test");
  if(scenario==0 || scenario>=6) {
   assert(opened && error==0 && opened->vec_off==start && opened->vec_hashed==start && updated==(size_t)start);
   assert(vectx_close(opened,"test")==0 && freed==1 && updated==8);
  } else {
   assert(!opened && error==VE_FINGERPRINT_WRONG && freed==1 && !hash_calls);
   if(scenario==1 || scenario==4) assert(!read_calls);
   if(scenario==4) assert(!seek_calls);
  }
 }
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'probe.c').write_text(before+structure+'\n'.join(functions)+main)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(p/'probe.c'),'-o',str(p/'probe')],check=True)
            subprocess.run([str(p/'probe')],check=True)

if __name__=='__main__': unittest.main()
