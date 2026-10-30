# SPDX-License-Identifier: BSD-2-Clause
"""Actual ELF header loader with native files and injected source/manifest admission."""
from pathlib import Path
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[3]
PRE = r'''
#include <sys/types.h>
#include <sys/param.h>
#include <sys/elf64.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define __elfN(x) x
#define Elf_Ehdr Elf64_Ehdr
#define ELF_TARG_CLASS ELFCLASS64
#define ELF_TARG_DATA ELFDATA2LSB
#define ELF_TARG_MACH EM_X86_64
#define VE_MUST 2
struct elf_file { int fd; void *firstpage; size_t firstlen; Elf_Ehdr *ehdr; };
typedef struct elf_file *elf_file_t;
static int source,manifest_result,manifest_calls,reads,read_error,preloads;
#ifdef LOADER_VERITY_SUPPORT
static int verity_check_source(int fd) {assert(fd>=0);return source==2 ? EAUTH : 0;}
static int verity_source_verified(int fd) {assert(fd>=0);return source==1;}
#endif
static int verify_file(int fd,const char *name,off_t off,int severity,const char *caller) {
 assert(fd>=0 && name && off==PAGE_SIZE && severity==VE_MUST && caller);
 manifest_calls++;return manifest_result;
}
static void preload(int fd) {assert(fd>=0);preloads++;}
static int elf_header_convert(Elf_Ehdr *header) {(void)header;return 0;}
static ssize_t input_read(int fd,void *buffer,size_t size) {
 reads++;if(read_error){errno=EAUTH;return -1;}return read(fd,buffer,size);
}
#define VECTX_HANDLE(ef) ((ef)->fd)
#define VECTX_READ input_read
'''
MAIN = r'''
int main(int argc,char **argv) {
 assert(argc==2);
 unsigned char page[PAGE_SIZE]={0};Elf_Ehdr *header=(void *)page;
 memcpy(header->e_ident,ELFMAG,SELFMAG);header->e_ident[EI_CLASS]=ELFCLASS64;
 header->e_ident[EI_DATA]=ELFDATA2LSB;header->e_ident[EI_VERSION]=EV_CURRENT;
 header->e_machine=EM_X86_64;header->e_version=EV_CURRENT;
 int output=open(argv[1],O_WRONLY|O_CREAT|O_TRUNC,0600);assert(output>=0);
 assert(write(output,page,sizeof(page))==sizeof(page));assert(close(output)==0);
 for(int scenario=0;scenario<6;scenario++) {
  source=scenario>=2 ? 1 : 0;manifest_result=scenario==0 || scenario==3 ? 1 : -1;
  if(scenario==3)source=2;
  manifest_calls=reads=preloads=0;read_error=scenario==4;
  if(scenario==5) {
   output=open(argv[1],O_WRONLY);assert(output>=0);
   assert(write(output,"bad!",4)==4);assert(close(output)==0);
  }
  struct elf_file ef={.fd=-1};int error=load_elf_header(argv[1],&ef);
  int wanted=scenario==0 ? 0 : (scenario>=4 ? EFTYPE : EAUTH);
#ifdef LOADER_VERITY_SUPPORT
  if(scenario==2)wanted=0;
#else
  if(scenario==3)wanted=0;
#endif
  assert(error==wanted);
  int expected_manifest=scenario<2 ? 1 : 0;
#ifndef LOADER_VERITY_SUPPORT
  if(scenario==2 || scenario==3)expected_manifest=1;
#endif
  assert(manifest_calls==expected_manifest);
#ifdef LOADER_VERITY_SUPPORT
  if(scenario==3)assert(reads==0 && preloads==0);
  else
#endif
   assert(reads==1 && preloads==1);
  if(!error){assert(close(ef.fd)==0);free(ef.firstpage);}
 }
 return 0;
}
'''
def main():
    source = (ROOT / 'stand/common/load_elf.c').read_text()
    start = source.index('static int\n__elfN(load_elf_header)(')
    body = source[start:source.index('\n}\n', start) + 3]
    with tempfile.TemporaryDirectory() as directory:
        folder=Path(directory); c=folder/'test.c'; binary=folder/'test'
        c.write_text(PRE+body+MAIN)
        for flags in ([], ['-DLOADER_VERITY_SUPPORT']):
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-DLOADER_VERIEXEC',*flags,
                            str(c),'-o',str(binary)],check=True)
            subprocess.run([str(binary),str(folder/'input')],check=True,timeout=3)
    print('PASS: 12 native ELF header admission cases; source and manifest verification injected')
if __name__ == '__main__':
    main()
