# SPDX-License-Identifier: BSD-2-Clause
"""Actual device/reader/core, real files; injected loader partition operations."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('artifacts',ROOT/'tools/build/capimage/verity_artifacts.py')
artifacts=importlib.util.module_from_spec(spec);spec.loader.exec_module(artifacts)
PRE=r'''
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/disk.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* Model libsa releasing its descriptor even when a close hook fails. */
static int close_error;
static int loader_close(int fd) {
 int result=close(fd);
 if (close_error) {errno=close_error;close_error=0;return -1;}
 return result;
}
#define close loader_close
#define F_READ 1
#define F_WRITE 2
#define F_MASK 0xFFFF
#define D_SLICENONE -1
#define D_PARTNONE -1
#define DEVT_DISK 1
struct devsw;
struct devdesc {struct devsw *d_dev;int d_unit;void *d_opendata;};
struct disk_devdesc {struct devdesc dd;int d_slice,d_partition;uint64_t d_offset;};
struct open_file {void *f_devdata;};
struct devsw {
 char dv_name[8];int dv_type;
 int (*dv_strategy)(void *,int,daddr_t,size_t,char *,size_t *);
 int (*dv_open)(struct open_file *,...);
 int (*dv_close)(struct open_file *);
 int (*dv_ioctl)(struct open_file *,u_long,void *);
 char *(*dv_fmtdev)(struct devdesc *);
 int (*dv_parsedev)(struct devdesc **,const char *,const char **);
};
static int disk_open(struct disk_devdesc *,uint64_t,u_int);
static int disk_close(struct disk_devdesc *d) {d->dd.d_opendata=NULL;return 0;}
static int disk_ioctl(struct disk_devdesc *d,u_long cmd,void *out) {
 (void)d;(void)cmd;(void)out;return ENOTTY;
}
static char *disk_fmtdev(struct devdesc *d) {(void)d;return NULL;}
static int disk_parsedev_named(struct devdesc **d,const char *s,const char **p,const char *name) {
 (void)d;(void)s;(void)p;(void)name;return ENOSYS;
}
'''
MAIN=r'''
static int disk_open(struct disk_devdesc *dev,uint64_t bytes,u_int sector) {
 char block[DEV_BSIZE];size_t got=0;
 assert(bytes>=8192 && sector==DEV_BSIZE);
 assert(verity_dev_detach(dev->dd.d_unit)==EBUSY);
 int e=verity_dev.dv_strategy(dev,F_READ,0,sizeof(block),block,&got);
 if(!e) {assert(got==sizeof(block));dev->dd.d_opendata=dev;}
 return e;
}
int main(int argc,char **argv) {
 assert(argc==3);
 int fd=open(argv[1],O_RDWR),desc=open(argv[2],O_RDONLY);assert(fd>=0 && desc>=0);
 unsigned char wire[G_VERITY_ROOT_BYTES];assert(read(desc,wire,sizeof(wire))==sizeof(wire));close(desc);
 struct g_verity_root root;assert(g_verity_root_decode(wire,sizeof(wire),&root)==0);
 int unit=-99;
 assert(verity_dev_attach(fd,&root,8,1,&unit)==ENOMEM && unit==-99);
 assert(fcntl(fd,F_GETFD)>=0);
 assert(verity_dev_attach(fd,&root,SIZE_MAX,SIZE_MAX,&unit)==EOVERFLOW && unit==-99);
 assert(verity_dev_attach(fd,&root,8,1024*1024,&unit)==0);
 struct disk_devdesc dev={.dd={.d_dev=&verity_dev,.d_unit=unit}};
 struct open_file f={.f_devdata=&dev};
 char data[512],expected[512];size_t got=999;
 assert(verity_dev.dv_open(&f,&dev)==0);
 assert(verity_dev.dv_strategy(&dev,F_WRITE,0,sizeof(data),data,&got)==EROFS && !got);
 assert(pread(fd,expected,sizeof(expected),512)==sizeof(expected));
 assert(verity_dev.dv_strategy(&dev,F_READ,1,sizeof(data),data,&got)==0);
 assert(got==512 && !memcmp(data,expected,512));
 char original=expected[5],changed=original^1;
 assert(pwrite(fd,&changed,1,517)==1);got=999;
 assert(verity_dev.dv_strategy(&dev,F_READ,1,sizeof(data),data,&got)==EAUTH && !got);
 for(unsigned i=0;i<512;i++) assert(data[i]==0);
 assert(pwrite(fd,&original,1,517)==1);
 assert(verity_dev.dv_strategy(&dev,F_READ,1,sizeof(data),data,&got)==0);
 assert(!memcmp(data,expected,512));
 dev.d_offset=1;
 assert(verity_dev.dv_strategy(&dev,F_READ,0,sizeof(data),data,&got)==0);
 assert(!memcmp(data,expected,512));
 dev.d_offset=UINT64_MAX;got=999;
 assert(verity_dev.dv_strategy(&dev,F_READ,1,sizeof(data),data,&got)==EINVAL && !got);
 dev.d_offset=0;
 assert(verity_dev.dv_strategy(&dev,F_READ,INT64_MAX,sizeof(data),data,&got)==EINVAL);
 assert(verity_dev.dv_strategy(&dev,F_READ,-1,sizeof(data),data,&got)==EINVAL);
 assert(verity_dev_detach(unit)==EBUSY);
 assert(verity_dev.dv_close(&f)==0);
 assert(verity_dev_detach(unit)==0);
 assert(fcntl(fd,F_GETFD)==-1 && errno==EBADF);
 assert(verity_dev.dv_strategy(&dev,F_READ,0,sizeof(data),data,&got)==ENXIO && !got);
 int next=-1;fd=open(argv[1],O_RDWR);assert(fd>=0);
 assert(verity_dev_attach(fd,&root,0,1024*1024,&next)==0 && next>unit);
 dev.dd.d_unit=next;assert(verity_dev.dv_open(&f,&dev)==0);
 assert(verity_dev.dv_close(&f)==0 && verity_dev_detach(next)==0);
 /* Bad authenticated identity must fail before partition parsing consumes data. */
 fd=open(argv[1],O_RDONLY);assert(fd>=0);root.root_hash[0]^=1;
 assert(verity_dev_attach(fd,&root,8,1024*1024,&next)==0);
 dev.dd.d_unit=next;assert(verity_dev.dv_open(&f,&dev)==EAUTH);
 assert(verity_dev_detach(next)==0); /* failed open released its reference */
 root.root_hash[0]^=1;
 fd=open(argv[1],O_RDONLY);assert(fd>=0);
 assert(verity_dev_attach(fd,&root,0,1024*1024,&next)==0);
 close_error=EIO;
 assert(verity_dev_detach(next)==EIO);
 assert(fcntl(fd,F_GETFD)==-1 && errno==EBADF);
 assert(verity_dev_detach(next)==ENOENT);
 assert(LIST_EMPTY(&verity_devices));
 return 0;
}
'''
class Device(unittest.TestCase):
    def test_device_reader_lifetime_and_integrity(self):
        reader=(ROOT/'stand/libsa/verity_read.c').read_text().replace('#include <stand.h>','')
        device=(ROOT/'stand/common/veritydev.c').read_text().replace('#include <stand.h>','').replace('#include <disk.h>','')
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory);payload=bytes(range(256))*32
            (folder/'system.ufs').write_bytes(payload)
            artifacts.build(folder,dict(format=1,block_size=4096,salt_hex='aabb'),
                artifacts.digest(folder/'system.ufs'),len(payload))
            c=folder/'device.c';binary=folder/'device';c.write_text(PRE+reader+device+MAIN)
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'sys'),
                '-I'+str(ROOT/'stand/libsa'),'-I'+str(ROOT/'stand/common'),str(c),
                str(ROOT/'sys/geom/verity/g_verity_verify.c'),'-lmd','-o',str(binary)],
                check=True)
            subprocess.run([str(binary),str(folder/'system.verity'),
                str(folder/'root.descriptor')],check=True,timeout=10)
if __name__=='__main__':unittest.main()
