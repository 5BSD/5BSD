# SPDX-License-Identifier: BSD-2-Clause
"""Real Lua stdio and streaming hash functions; manifest initialization injected."""
import argparse
from pathlib import Path
import subprocess
import tempfile
import verified_replay_test as replay
ROOT=replay.ROOT
GLUE=r"""
#include <fcntl.h>
#include <setjmp.h>
static jmp_buf escaped;
static int panicked,open_error,required=1;
static int source_mode,context_opens;
int verity_check_source(int fd) {assert(fd>=0);return source_mode==2 ? EAUTH : 0;}
int verity_source_verified(int fd) {assert(fd>=0);return source_mode==1;}
static void panic(const char *format,...) __attribute__((noreturn));
static void panic(const char *format,...) {(void)format;panicked=1;longjmp(escaped,1);}
int verify_required(void) {return required;}
int verify_file(int fd,const char *p,off_t off,int severity,const char *caller) {
 (void)fd;(void)p;(void)off;(void)severity;(void)caller;return VE_VERIFIED;
}
struct vectx *vectx_open(int fd,const char *path,int severity,off_t off,
 struct stat *st,int *error,const char *caller) {
 (void)caller;assert(severity==VE_MUST && off==0);
 context_opens++;
 *error=open_error;
 struct vectx *ctx=calloc(1,sizeof(*ctx));assert(ctx);
 ctx->vec_fd=fd;ctx->vec_path=path;ctx->vec_size=st->st_size;
 ctx->vec_md=&br_sha256_vtable;ctx->vec_hashsz=32;ctx->vec_severity=VE_MUST;
 ctx->vec_md->init(&ctx->vec_ctx.vtable);return ctx;
}
#undef getc
#undef ferror
#undef feof
#define FILE LoaderFile
#define fopen loader_fopen
#define fread loader_fread
#define fclose loader_fclose
#define ferror loader_ferror
#define getc loader_getc
"""
MAIN=r"""
int main(int argc,char **argv) {
 assert(argc==3);int fd=open(argv[1],O_RDWR);assert(fd>=0);
 br_sha256_context hash;br_sha256_init(&hash);
 br_sha256_update(&hash,"original",8);br_sha256_out(&hash,expected);
 for(int scenario=0;scenario<6;scenario++) {
  assert(pwrite(fd,"original",8,0)==8);panicked=0;
  FILE *stream=fopen(argv[1],"r");assert(stream);
  assert(stream->verification && stream->verification->vec_sequential);
  assert(stream->verification->vec_pages==NULL);
  assert(stream->verification_path!=argv[1]);
  unsigned char buffer[8];
  if(scenario==1 || scenario==4)assert(pwrite(fd,"modified",8,0)==8);
  if(scenario==2 || scenario==3) {
   assert(fread(buffer,1,4,stream)==4);
   if(scenario==2)assert(pwrite(fd,"xxxx",4,4)==4);
   else assert(pwrite(fd,"xxxx",4,0)==4);
  } else if(scenario==5) {
   assert(getc(stream)=='o');assert(fread(buffer,1,7,stream)==7);
  } else assert(fread(buffer,1,8,stream)==8);
  if(scenario==4)assert(pwrite(fd,"original",8,0)==8);
  assert(!ferror(stream));
  if(setjmp(escaped)==0)assert(fclose(stream)==0);
  assert(panicked==(scenario==1 || scenario==2 || scenario==4));
  if(panicked){close(stream->fd);free(stream->verification_path);free(stream);}
 }
 /* Nonregular readable objects must not bypass mandatory verification.
  * Use a real directory, without modifying or reading a host device.
  */
 assert(fopen(argv[2],"r")==NULL);
 required=0;
 FILE *directory=fopen(argv[2],"r");assert(directory);
 assert(directory->verification==NULL);assert(fclose(directory)==0);
 required=1;
 assert(pwrite(fd,"original",8,0)==8);open_error=-1;
 assert(fopen(argv[1],"r")==NULL);
 int previous=context_opens;
 source_mode=2;errno=0;
 assert(fopen(argv[1],"r")==NULL && errno==EAUTH);
 assert(context_opens==previous);
 source_mode=1; /* Opened-device provenance seam; native file is not a verity device. */
 FILE *selected=fopen(argv[1],"r");assert(selected);
 assert(selected->verification==NULL && selected->verification_path==NULL);
 assert(context_opens==previous);
 unsigned char bytes[8];assert(fread(bytes,1,8,selected)==8);
 assert(memcmp(bytes,"original",8)==0 && !ferror(selected));
 assert(fclose(selected)==0);
 selected=fopen(argv[1],"r");assert(selected);assert(close(selected->fd)==0);
 assert(fread(bytes,1,8,selected)==0 && ferror(selected));
 assert(fclose(selected)==0);
 source_mode=0;assert(fopen(argv[1],"r")==NULL && context_opens==previous+1);
 close(fd);return 0;
}
"""
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bearssl-library',type=Path,required=True)
    args=parser.parse_args()
    vectx=(ROOT/'lib/libsecureboot/vectx.c').read_text()
    start=vectx.index('struct vectx {')
    structure=vectx[start:vectx.index('\n};',start)+3]
    functions=[]
    for signature in ('void\nvectx_discard(', 'int\nvectx_set_sequential(', 'static int\nvectx_record(', 'static ssize_t\nvectx_replay(', 'ssize_t\nvectx_read(', 'off_t\nvectx_lseek(', 'int\nvectx_close('):
        start=vectx.index(signature);functions.append(vectx[start:vectx.index('\n}\n',start)+3])
    header=(ROOT/'stand/liblua/lstd.h').read_text();start=header.index('typedef struct FILE')
    stream=header[start:header.index('} FILE;',start)+7]
    source=(ROOT/'stand/liblua/lstd.c').read_text();lua=[]
    for signature in ('FILE *\nfopen(', 'size_t\nfread(', 'int\nfclose(', 'int\nferror(', 'int\ngetc('):
        start=source.index(signature);lua.append(source[start:source.index('\n}\n',start)+3])
    with tempfile.TemporaryDirectory() as directory:
        folder=Path(directory);c=folder/'test.c';binary=folder/'test';payload=folder/'payload'
        payload.write_bytes(b'original')
        c.write_text(replay.PREAMBLE+structure+'\n'.join(functions)+GLUE+stream+'\n'.join(lua)+MAIN)
        subprocess.run(['cc','-Wall','-Wextra','-Werror','-DLOADER_VERIEXEC','-DLOADER_VERITY_SUPPORT',
            '-I'+str(ROOT/'contrib/bearssl/inc'),'-I'+str(ROOT/'lib/libsecureboot/h'),
            str(c),str(args.bearssl_library.resolve(strict=True)),'-o',str(binary)],check=True)
        subprocess.run([str(binary),str(payload),str(folder)],check=True,cwd=folder,timeout=10)
    print('PASS: six native Lua stream mutation cases plus nonregular admission, initialization rejection and injected selected-device admission; no interpreter or firmware execution')
if __name__=='__main__':main()
