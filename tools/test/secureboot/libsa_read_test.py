# SPDX-License-Identifier: BSD-2-Clause
"""Actual libsa read boundary behavior with bounded native I/O adapters."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
PRE = r'''
#include <sys/types.h>
#include <sys/param.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define TSENTER() ((void)0)
#define TSEXIT() ((void)0)
#define F_READ 1
#define F_RAW 4
#define SOPEN_RASIZE 512
struct open_file;
struct fs_ops {int (*fo_read)(struct open_file *,void *,size_t,size_t *);};
struct devsw {int (*dv_strategy)(void *,int,daddr_t,size_t,char *,size_t *);};
struct open_file {int f_flags;struct fs_ops *f_ops;struct devsw *f_dev;
 void *f_devdata;off_t f_offset;char *f_rabuf;size_t f_ralen;off_t f_raoffset;};
static struct open_file file;
static unsigned calls,copies;
static size_t request,position;
static int fail;
static struct open_file *fd2open_file(int fd){return fd==3 ? &file : NULL;}
static void twiddle(unsigned n){(void)n;}
static void checked_copy(const void *from,void *to,size_t count) {
 /* Guard the tiny destination rather than allocating a multi-GiB buffer. */
 assert(count<=8);copies++;memmove(to,from,count);
}
#define bcopy checked_copy
static int backing(struct open_file *f,void *out,size_t count,size_t *resid) {
 (void)f;calls++;request=count;
 if(fail)return EIO;
 size_t n=MIN(count,8-position);
 memcpy(out,&"abcdefgh"[position],n);position+=n;*resid=count-n;return 0;
}
static int raw(void *p,int flags,daddr_t block,size_t count,char *out,size_t *got) {
 (void)p;(void)flags;(void)block;(void)out;calls++;request=count;*got=0;return EIO;
}
'''
MAIN = r'''
int main(void) {
 char cache[SOPEN_RASIZE],out[8];
 struct fs_ops fs={backing};struct devsw dev={raw};
 file=(struct open_file){.f_flags=F_READ,.f_ops=&fs,.f_dev=&dev,.f_rabuf=cache};
 memcpy(cache,"abcd",4);file.f_ralen=4;fail=1;
 size_t large=(size_t)INT_MAX+1;
 assert(libsa_read(3,out,large)==-1 && errno==EIO);
 assert(copies==1 && calls==1 && request==large-4 && !memcmp(out,"abcd",4));
 assert(file.f_ralen==0 && file.f_raoffset==4);
 calls=copies=0;file.f_raoffset=0;fail=0;
 assert(libsa_read(3,NULL,0)==0 && calls==0 && copies==0 && position==0);
 assert(libsa_read(3,out,(size_t)SSIZE_MAX+1)==-1 && errno==EINVAL);
 assert(calls==0 && copies==0 && file.f_ralen==0);
 assert(libsa_read(3,out,3)==3 && !memcmp(out,"abc",3));
 assert(calls==1 && file.f_ralen==5);
 assert(libsa_read(3,out,5)==5 && !memcmp(out,"defgh",5) && calls==1);
 assert(libsa_read(3,out,1)==0 && calls==2);
 calls=0;file.f_flags=F_READ|F_RAW;
 assert(libsa_read(3,NULL,0)==0 && calls==0);
 assert(libsa_read(3,out,(size_t)SSIZE_MAX+1)==-1 && errno==EINVAL && calls==0);
 assert(libsa_read(3,out,1)==-1 && errno==EIO && calls==1);
 assert(libsa_read(-1,NULL,0)==-1 && errno==EBADF);
 return 0;
}
'''
def main():
    source=(ROOT/'stand/libsa/read.c').read_text()
    start=source.index('ssize_t\nread(')
    function=source[start:source.index('\n}\n',start)+3]
    function=function.replace('ssize_t\nread(', 'ssize_t\nlibsa_read(',1)
    with tempfile.TemporaryDirectory() as directory:
        folder=Path(directory);c=folder/'test.c';binary=folder/'test'
        c.write_text(PRE+function+MAIN)
        subprocess.run(['cc','-Wall','-Wextra','-Werror',
            str(c),'-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True,cwd=folder,timeout=5)
    print('PASS: libsa read cached-prefix, large/zero sizes, normal refill/EOF and raw errors')
if __name__=='__main__':main()
