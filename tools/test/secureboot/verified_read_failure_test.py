# SPDX-License-Identifier: BSD-2-Clause
"""Preserve read failures and observed stream boundaries at final verification."""
import argparse
from pathlib import Path
import subprocess,tempfile
import verified_replay_test as replay
ROOT=replay.ROOT
GLUE=r"""
static int fault,read_calls;
static ssize_t fault_read(int fd,void *data,size_t count) {
 read_calls++;
 if(fault==1){fault=0;errno=EIO;return -1;}
 if(fault==2){fault=0;return 0;}
 return read(fd,data,count);
}
#define read fault_read
"""
MAIN=r"""
int main(void) {
 br_sha256_context hash;br_sha256_init(&hash);
 br_sha256_update(&hash,"original",8);br_sha256_out(&hash,expected);
 for(int scenario=0;scenario<9;scenario++) {
  FILE *file=tmpfile();assert(file);int fd=fileno(file);
  assert(write(fd,"original",8)==8 && lseek(fd,0,SEEK_SET)==0);
  struct vectx *ctx=calloc(1,sizeof(*ctx));assert(ctx);
  ctx->vec_fd=fd;ctx->vec_path="failure test";ctx->vec_size=scenario>=4 ? -1 : 8;
  ctx->vec_md=&br_sha256_vtable;ctx->vec_hashsz=32;ctx->vec_severity=VE_MUST;
  ctx->vec_md->init(&ctx->vec_ctx.vtable);
  unsigned char bytes[8];fault=0;
  assert(vectx_read(ctx,bytes,4)==4);
  if(scenario==1 || scenario==2) {
   fault=scenario;
   assert(vectx_read(ctx,bytes,4)<=0);
  }
  if(scenario==3)assert(vectx_read(ctx,bytes,0)==0);
  if(scenario==4 || scenario==7) {
   fault=2;assert(vectx_read(ctx,bytes,4)==0);
   if(scenario==7)assert(vectx_read(ctx,bytes,4)==4);
  }
  if(scenario==5 || scenario==8) {
   assert(vectx_read(ctx,bytes,4)==4);
   assert(vectx_read(ctx,bytes,1)==0);
   if(scenario==8) {
    assert(vectx_lseek(ctx,0,SEEK_SET)==0);
    assert(vectx_read(ctx,bytes,4)==4);
   }
  }

  int before=read_calls;int result=vectx_close(ctx,"failure-test");
  if(scenario==1 || scenario==2 || scenario==4 || scenario==7) {
   assert(result!=0);assert(read_calls==before);
  } else {assert(result==0);if(scenario==5 || scenario==8)assert(read_calls==before);}
  fclose(file);
 }
 return 0;
}
"""
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bearssl-library',type=Path,required=True)
    args=parser.parse_args();source=(ROOT/'lib/libsecureboot/vectx.c').read_text()
    start=source.index('struct vectx {');structure=source[start:source.index('\n};',start)+3]
    functions=[]
    for sig in ('void\nvectx_discard(', 'static int\nvectx_record(', 'static ssize_t\nvectx_replay(', 'ssize_t\nvectx_read(', 'off_t\nvectx_lseek(', 'int\nvectx_close('):
        start=source.index(sig);functions.append(source[start:source.index('\n}\n',start)+3])
    with tempfile.TemporaryDirectory() as directory:
        c=Path(directory)/'test.c';binary=Path(directory)/'test'
        c.write_text(replay.PREAMBLE+structure+GLUE+'\n'.join(functions)+MAIN)
        subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'contrib/bearssl/inc'),
            '-I'+str(ROOT/'lib/libsecureboot/h'),str(c),str(args.bearssl_library.resolve(strict=True)),
            '-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True,cwd=directory,timeout=10)
    print('PASS: nine read-failure/EOF cases; close preserves observed stream boundaries')
if __name__=='__main__':main()
