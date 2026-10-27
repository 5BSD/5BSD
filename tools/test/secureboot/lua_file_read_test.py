# SPDX-License-Identifier: BSD-2-Clause
"""Actual loader Lua read/error functions with injected read results."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r"""
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#undef getc
#undef ferror
#undef feof
#define FILE LoaderFile
#define fread loader_fread
#define getc loader_getc
#define ferror loader_ferror
#define feof loader_feof
static int mode,calls;
static ssize_t test_read(int fd,void *p,size_t n) {
 assert(fd==7 && n>0);calls++;
 if(mode==1){errno=EIO;return -1;}
 if(mode==2)return 0;
 size_t got=mode==3 ? 1 : n;
 memset(p,0xff,got);return got;
}
#define read test_read
"""
MAIN=r"""
int main(void) {
 unsigned char buffer[8];FILE stream={.fd=7,.size=8};
 assert(fread(buffer,2,3,&stream)==6 && stream.offset==6 && calls==1);
 assert(!ferror(&stream) && !feof(&stream));
 assert(getc(&stream)==255 && stream.offset==7);
 assert(getc(&stream)==255 && feof(&stream));
 mode=1;assert(fread(buffer,1,1,&stream)==0 && ferror(&stream));
 assert(stream.offset==8);int before=calls;
 assert(getc(&stream)==EOF && calls==before);
 stream=(FILE){.fd=7,.size=8};mode=2;
 assert(fread(buffer,1,8,&stream)==0 && !ferror(&stream) && stream.offset==0);
 stream=(FILE){.fd=7,.size=8};mode=3;
 assert(fread(buffer,1,8,&stream)==1 && stream.offset==1 && !ferror(&stream));
 for(int scenario=0;scenario<4;scenario++) {
  stream=(FILE){.fd=7,.size=8};before=calls;
  if(scenario==0)assert(fread(buffer,SIZE_MAX,2,&stream)==0);
  if(scenario==1)assert(fread(buffer,1,(size_t)SSIZE_MAX+1,&stream)==0);
  if(scenario==2){stream.offset=SIZE_MAX;assert(fread(buffer,1,1,&stream)==0);}
  if(scenario==3)assert(fread(NULL,1,1,&stream)==0);
  assert(ferror(&stream) && calls==before);
 }
 stream=(FILE){.fd=7,.size=8};before=calls;
 assert(fread(NULL,0,SIZE_MAX,&stream)==0 && !ferror(&stream));
 assert(fread(NULL,SIZE_MAX,0,&stream)==0 && !ferror(&stream));
 assert(fread(buffer,1,1,NULL)==0 && getc(NULL)==EOF && ferror(NULL));
 assert(calls==before);return 0;
}
"""
class LuaReads(unittest.TestCase):
    def test_byte_counts_errors_and_character_reads(self):
        header=(ROOT/'stand/liblua/lstd.h').read_text()
        start=header.index('typedef struct FILE')
        structure=header[start:header.index('} FILE;',start)+7]
        source=(ROOT/'stand/liblua/lstd.c').read_text();functions=[]
        for signature in ('size_t\nfread(', 'int\nferror(', 'int\nfeof(', 'int\ngetc('):
            start=source.index(signature)
            functions.append(source[start:source.index('\n}\n',start)+3])
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/'test.c';binary=Path(directory)/'test'
            c.write_text(PRE+structure+'\n'.join(functions)+MAIN)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,cwd=directory,timeout=10)
if __name__=='__main__':unittest.main()
