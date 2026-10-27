# SPDX-License-Identifier: BSD-2-Clause
"""Require streaming verification to reject changed bytes on a backward read.

Uses actual vectx read/seek/close and BearSSL SHA-256 with real temporary-file
I/O. Manifest lookup is outside this test: the expected digest is supplied by
the harness. This is a native verifier invariant, not firmware qualification.
"""
from pathlib import Path
import argparse
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]

PREAMBLE = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <bearssl.h>
#include <verify_file.h>
#define UNIT_TEST 1
#define VE_FINGERPRINT_WRONG -1
#define DEBUG_PRINTF(level,args) do { if (0) printf args; } while (0)
static unsigned char expected[32];
static int ve_check_hash(br_hash_compat_context *ctx,const br_hash_class *md,
 const char *path,const char *want,size_t n) {
 unsigned char actual[32];(void)path;(void)want;assert(n==32);
 md->out(&ctx->vtable,actual);
 return memcmp(actual,expected,32)==0 ? 1 : VE_FINGERPRINT_WRONG;
}
static void ve_error_set(const char *fmt,...) { (void)fmt; }
void verify_report(const char *p,int severity,int rc,struct stat *st) {
 (void)p;(void)severity;(void)rc;(void)st;
}
'''
MAIN = r'''
int main(void) {
 const unsigned char original[] = "original";
 const unsigned char changed[] = "modified";
 br_sha256_context hash;
 br_sha256_init(&hash);br_sha256_update(&hash,original,8);br_sha256_out(&hash,expected);
 int failures=0;
 const char *names[] = {"unchanged", "changed-before-read",
  "changed-on-replay", "unchanged-replay", "changed-then-restored",
  "changed-partial-replay", "unchanged-partial-replay"};
 for (int scenario=0;scenario<7;scenario++) {
  FILE *file=tmpfile();assert(file);int fd=fileno(file);
  assert(write(fd,original,8)==8 && lseek(fd,0,SEEK_SET)==0);
  struct vectx *ctx=calloc(1,sizeof(*ctx));assert(ctx);
  ctx->vec_fd=fd;ctx->vec_path="temporary payload";ctx->vec_size=8;
  ctx->vec_md=&br_sha256_vtable;ctx->vec_hashsz=32;ctx->vec_severity=VE_MUST;
  ctx->vec_md->init(&ctx->vec_ctx.vtable);
  unsigned char loaded[8];
  if(scenario==1 || scenario==4) assert(pwrite(fd,changed,8,0)==8);
  int complete=vectx_read(ctx,loaded,8)==8;
  /* Every returned read can be consumed by the ELF loader. Restoring
   * the file later must not erase an earlier unauthenticated read. */
  int valid=complete && memcmp(loaded,original,8)==0;
  if(scenario>=2 && complete) {
   if(scenario==2 || scenario==5) assert(pwrite(fd,changed,8,0)==8);
   if(scenario==4) assert(pwrite(fd,original,8,0)==8);
   off_t replay_offset = scenario>=5 ? 2 : 0;
   size_t replay_length = scenario>=5 ? 3 : 8;
   complete = vectx_lseek(ctx,replay_offset,SEEK_SET)==replay_offset;
   if(complete) complete = vectx_read(ctx,loaded,replay_length)==(ssize_t)replay_length;
   valid = valid && complete &&
    memcmp(loaded,original+replay_offset,replay_length)==0;
   /* Close from inside an already hashed prefix, with backing bytes restored.
    * Rehashing the file only at close cannot validate bytes already delivered. */
   if(scenario==5) assert(pwrite(fd,original,8,0)==8);
  }
  int result=vectx_close(ctx,"replay-test");
  int accepted=complete && result==0;
  int expected_accept=scenario==0 || scenario==3 || scenario==6;
  printf("scenario=%s accepted=%d all_reads_match_digest=%d\n",
    names[scenario],accepted,valid);
  if(accepted!=expected_accept || (accepted && !valid)) failures++;
  fclose(file);
 }


 for(int unknown=0;unknown<2;unknown++) {
  FILE *file=tmpfile();assert(file);int fd=fileno(file);
  assert(write(fd,original,8)==8 && lseek(fd,0,SEEK_SET)==0);
  struct vectx *ctx=calloc(1,sizeof(*ctx));assert(ctx);
  ctx->vec_fd=fd;ctx->vec_path="incomplete replay";ctx->vec_size=unknown?-1:8;
  ctx->vec_md=&br_sha256_vtable;ctx->vec_hashsz=32;ctx->vec_severity=VE_MUST;
  ctx->vec_md->init(&ctx->vec_ctx.vtable);
  unsigned char bytes[4];
  assert(vectx_read(ctx,bytes,4)==4);
  assert(vectx_lseek(ctx,0,SEEK_SET)==0);
  assert(vectx_read(ctx,bytes,2)==2 && memcmp(bytes,original,2)==0);
  replay_bytes=0;
  assert(vectx_close(ctx,"incomplete replay")==0 && replay_bytes==4);
  fclose(file);
 }

 for(int backwards=0;backwards<2;backwards++) {
  FILE *file=tmpfile();assert(file);int fd=fileno(file);
  assert(write(fd,original,8)==8 && lseek(fd,0,SEEK_SET)==0);
  struct vectx *ctx=calloc(1,sizeof(*ctx));assert(ctx);
  ctx->vec_fd=fd;ctx->vec_path="sequential";ctx->vec_size=8;
  ctx->vec_md=&br_sha256_vtable;ctx->vec_hashsz=32;ctx->vec_severity=VE_MUST;
  ctx->vec_md->init(&ctx->vec_ctx.vtable);
  assert(vectx_set_sequential(ctx)==0);
  unsigned char bytes[8];assert(vectx_read(ctx,bytes,4)==4);
  assert(vectx_set_sequential(ctx)==EINVAL);
  if(backwards) {
   assert(vectx_lseek(ctx,0,SEEK_SET)==-1 && errno==EAUTH);
   assert(vectx_read(ctx,bytes,4)==-1);
   assert(vectx_close(ctx,"sequential")==VE_FINGERPRINT_WRONG);
  } else {
   assert(vectx_lseek(ctx,6,SEEK_SET)==6);
   assert(vectx_read(ctx,bytes,2)==2);
   assert(ctx->vec_pages==NULL && ctx->vec_pages_capacity==0);
   assert(vectx_close(ctx,"sequential")==0);
  }
  fclose(file);
 }
 /* Exercise complete digest pages, a final partial page, crossing reads and
  * vector growth. Replay backing reads must depend on touched pages only. */
 const size_t size=PAGE_SIZE*300+17;
 unsigned char *original_large=malloc(size), *loaded_large=malloc(size);
 assert(original_large && loaded_large);
 for(size_t i=0;i<size;i++)original_large[i]=(i*17+i/PAGE_SIZE)%251;
 br_sha256_init(&hash);br_sha256_update(&hash,original_large,size);
 br_sha256_out(&hash,expected);
 const off_t offsets[]={0,PAGE_SIZE-2,PAGE_SIZE*129+7,PAGE_SIZE*300+2};
 for(unsigned i=0;i<sizeof(offsets)/sizeof(offsets[0]);i++) {
  for(int corrupt=0;corrupt<2;corrupt++) {
   FILE *file=tmpfile();assert(file);int fd=fileno(file);
   assert(write(fd,original_large,size)==(ssize_t)size && lseek(fd,0,SEEK_SET)==0);
   struct vectx *ctx=calloc(1,sizeof(*ctx));assert(ctx);
   ctx->vec_fd=fd;ctx->vec_path="large payload";ctx->vec_size=size;
   ctx->vec_md=&br_sha256_vtable;ctx->vec_hashsz=32;ctx->vec_severity=VE_MUST;
   ctx->vec_md->init(&ctx->vec_ctx.vtable);
   assert(vectx_read(ctx,loaded_large,17)==17);
   assert(vectx_read(ctx,loaded_large+17,size-17)==(ssize_t)size-17);
   assert(memcmp(loaded_large,original_large,size)==0);
   size_t digest_bytes=300*32;
   assert(ctx->vec_pages_capacity>=digest_bytes && ctx->vec_pages_capacity<2*digest_bytes);
   off_t offset=offsets[i];unsigned char bad=original_large[offset]^0xff;
   if(corrupt)assert(pwrite(fd,&bad,1,offset)==1);
   assert(vectx_lseek(ctx,offset,SEEK_SET)==offset);
   replay_bytes=0;
   ssize_t n=vectx_read(ctx,loaded_large,7);
   assert(replay_bytes<=2*PAGE_SIZE);
   if(corrupt) {
    assert(n==-1);
    assert(pwrite(fd,original_large+offset,1,offset)==1);
    assert(vectx_read(ctx,loaded_large,7)==-1);
    assert(vectx_close(ctx,"large replay")!=0);
   } else {
    assert(n==7 && memcmp(loaded_large,original_large+offset,7)==0);
    replay_bytes=0;
    assert(vectx_close(ctx,"large replay")==0);
    assert(replay_bytes==0); /* no full-prefix rescan at close */
   }
   fclose(file);
  }
 }

 for(int grow=0;grow<2;grow++) {
  FILE *file=tmpfile();assert(file);int fd=fileno(file);
  assert(write(fd,original_large,size)==(ssize_t)size && lseek(fd,0,SEEK_SET)==0);
  struct vectx *ctx=calloc(1,sizeof(*ctx));assert(ctx);
  ctx->vec_fd=fd;ctx->vec_path="allocation failure";ctx->vec_size=size;
  ctx->vec_md=&br_sha256_vtable;ctx->vec_hashsz=32;ctx->vec_severity=VE_MUST;
  ctx->vec_md->init(&ctx->vec_ctx.vtable);
  if(grow) assert(vectx_read(ctx,loaded_large,PAGE_SIZE*128)==PAGE_SIZE*128);
  fail_allocation=1;
  assert(vectx_read(ctx,loaded_large,PAGE_SIZE)==-1 && errno==ENOMEM);
  fail_allocation=0;
  assert(vectx_read(ctx,loaded_large,1)==-1);
  assert(vectx_close(ctx,"allocation failure")!=0);
  fclose(file);
 }

 {
  FILE *file=tmpfile();assert(file);int fd=fileno(file);
  assert(write(fd,original_large,PAGE_SIZE)==PAGE_SIZE && lseek(fd,0,SEEK_SET)==0);
  struct vectx *ctx=calloc(1,sizeof(*ctx));assert(ctx);
  ctx->vec_fd=fd;ctx->vec_path="discard";ctx->vec_size=PAGE_SIZE;
  ctx->vec_md=&br_sha256_vtable;ctx->vec_hashsz=32;ctx->vec_severity=VE_MUST;
  ctx->vec_md->init(&ctx->vec_ctx.vtable);
  assert(vectx_read(ctx,loaded_large,PAGE_SIZE)==PAGE_SIZE && ctx->vec_pages);
  tracked_context=ctx;tracked_table=ctx->vec_pages;
  replay_bytes=0;vectx_discard(ctx);vectx_discard(NULL);
  assert(context_freed==1 && table_freed==1 && replay_bytes==0);
  /* The file descriptor belongs to the caller, including on abandonment. */
  assert(lseek(fd,0,SEEK_SET)==0);
  assert(read(fd,loaded_large,1)==1);
  tracked_context=tracked_table=NULL;fclose(file);
 }
 free(original_large);free(loaded_large);
 if(failures) fprintf(stderr,"FAIL: verified replay acceptance differs from required result\n");
 return failures ? 1 : 0;
}
'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bearssl-library', type=Path, required=True)
    args = parser.parse_args()
    source = (ROOT / 'lib/libsecureboot/vectx.c').read_text()
    start = source.index('struct vectx {')
    structure = source[start:source.index('\n};', start) + 3]
    functions = []
    for signature in ('void\nvectx_discard(', 'int\nvectx_set_sequential(', 'static int\nvectx_record(', 'static ssize_t\nvectx_replay(', 'ssize_t\nvectx_read(', 'off_t\nvectx_lseek(', 'int\nvectx_close('):
        start = source.index(signature)
        functions.append(source[start:source.index('\n}\n', start) + 3])
    with tempfile.TemporaryDirectory(prefix='verified-replay-') as directory:
        cfile, binary = Path(directory) / 'test.c', Path(directory) / 'test'
        cfile.write_text(PREAMBLE + r"""
static size_t replay_bytes;
static void *tracked_context,*tracked_table;
static int context_freed,table_freed;
static void tracked_free(void *p) {
 if(p && p==tracked_context)context_freed++;
 if(p && p==tracked_table)table_freed++;
 free(p);
}
#define free tracked_free
static int fail_allocation;
static void *fault_realloc(void *p,size_t count) {
 if(fail_allocation){errno=ENOMEM;return NULL;}return realloc(p,count);
}
#define realloc fault_realloc
static ssize_t counted_read(int fd,void *data,size_t count) {
 ssize_t n=read(fd,data,count);if(n>0)replay_bytes+=n;return n;
}
#define read counted_read
""" + structure + '\n'.join(functions) + MAIN)
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
                        '-I' + str(ROOT / 'contrib/bearssl/inc'),
                        '-I' + str(ROOT / 'lib/libsecureboot/h'), str(cfile),
                        str(args.bearssl_library.resolve(strict=True)),
                        '-o', str(binary)], check=True)
        return subprocess.run([str(binary)], timeout=10).returncode

if __name__ == '__main__':
    raise SystemExit(main())
