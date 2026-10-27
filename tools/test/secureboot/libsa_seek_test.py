# SPDX-License-Identifier: BSD-2-Clause
"""Actual libsa seek arithmetic with native bounded filesystem-state adapters."""
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[3]
PRE=r'''
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#define F_READ 1
#define F_RAW 4
#define EOFFSET (ELAST+8)
struct open_file;
struct fs_ops {off_t (*fo_seek)(struct open_file *,off_t,int);};
struct open_file {int f_flags;off_t f_offset;struct fs_ops *f_ops;
 size_t f_ralen;off_t f_raoffset;};
static struct open_file file;
static off_t disk_position=100;
static unsigned movements;
static struct open_file *fd2open_file(int fd){return fd==3 ? &file : NULL;}
static off_t backend(struct open_file *f,off_t off,int where) {
 (void)f;off_t target;
 if(where==SEEK_CUR && off==0)return disk_position;
 if(where==SEEK_SET)target=off;
 else if(where==SEEK_CUR || where==SEEK_END) {
  if(__builtin_add_overflow(where==SEEK_CUR ? disk_position : 200,off,&target)) {
   errno=EOVERFLOW;return -1;
  }
 } else {errno=EINVAL;return -1;}
 if(target<0){errno=EINVAL;return -1;}
 movements++;return disk_position=target;
}
'''
MAIN=r'''
int main(void) {
 struct fs_ops fs={backend};
 file=(struct open_file){.f_flags=F_READ|F_RAW,.f_offset=10,.f_ops=&fs};
 assert(libsa_lseek(3,-1,SEEK_SET)==-1 && errno==EINVAL && file.f_offset==10);
 assert(libsa_lseek(3,-11,SEEK_CUR)==-1 && errno==EINVAL && file.f_offset==10);
 assert(libsa_lseek(3,INT64_MAX,SEEK_CUR)==-1 && errno==EOVERFLOW && file.f_offset==10);
 assert(libsa_lseek(3,-4,SEEK_CUR)==6);
 assert(libsa_lseek(3,INT64_MAX,SEEK_SET)==INT64_MAX);
 assert(libsa_lseek(3,1,SEEK_CUR)==-1 && errno==EOVERFLOW && file.f_offset==INT64_MAX);
 file=(struct open_file){.f_flags=F_READ,.f_ops=&fs,.f_ralen=20};
 struct open_file saved=file;
 assert(libsa_lseek(3,INT64_MAX,SEEK_CUR)==-1 && errno==EOVERFLOW);
 assert(!memcmp(&file,&saved,sizeof(file)) && disk_position==100 && movements==0);
 assert(libsa_lseek(3,-81,SEEK_CUR)==-1 && errno==EINVAL);
 assert(!memcmp(&file,&saved,sizeof(file)) && movements==0);
 assert(libsa_lseek(3,INT64_MIN,SEEK_CUR)==-1 && errno==EINVAL);
 assert(!memcmp(&file,&saved,sizeof(file)) && movements==0);
 assert(libsa_lseek(3,10,SEEK_CUR)==90 && file.f_ralen==10 && file.f_raoffset==10);
 assert(movements==0 && disk_position==100);
 assert(libsa_lseek(3,-5,SEEK_CUR)==85 && movements==1 && disk_position==85 && !file.f_ralen);
 assert(libsa_lseek(3,-10,SEEK_END)==190);
 file.f_ralen=20;disk_position=10;saved=file;
 assert(libsa_lseek(3,0,SEEK_CUR)==-1 && errno==EIO);
 assert(!memcmp(&file,&saved,sizeof(file)) && disk_position==10);
 assert(libsa_lseek(-1,0,SEEK_SET)==-1 && errno==EBADF);
 return 0;
}
'''
def main():
    source=(ROOT/'stand/libsa/lseek.c').read_text();start=source.index('off_t\nlseek(')
    function=source[start:source.index('\n}\n',start)+3]
    function=function.replace('off_t\nlseek(', 'off_t\nlibsa_lseek(',1)
    with tempfile.TemporaryDirectory() as directory:
        folder=Path(directory);c=folder/'test.c';binary=folder/'test'
        c.write_text(PRE+function+MAIN)
        subprocess.run(['cc','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True,cwd=folder,timeout=5)
    print('PASS: libsa raw/cached seek boundaries, state preservation and valid relative/end seeks')
if __name__=='__main__':main()
