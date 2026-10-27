# SPDX-License-Identifier: BSD-2-Clause
"""Actual loader UFS/disk/verifier over real makefs output; no mounts or VM."""
import argparse
import gzip
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import verity_loader_partition_test as partition
ROOT=partition.ROOT
parser=argparse.ArgumentParser()
parser.add_argument('--makefs',required=True,type=Path)
args,remaining=parser.parse_known_args()
stand=(ROOT/'stand/libsa/stand.h').read_text()
start=stand.index('struct open_file {')
file_structure=stand[start:stand.index('\n};',start)+3]
PRE=partition.PRE.replace('struct open_file {void *f_devdata;};',
    '#include <sys/queue.h>\nstruct fs_ops;'+file_structure)
start=stand.index('struct fs_ops {');end=stand.index('\n};',start)+3
PRE+='#include <sys/dirent.h>\n'+stand[start:end]+r"""
static void twiddle(unsigned n) {(void)n;}
static void panic(const char *s) {fprintf(stderr,"%s",s);abort();}
static char *devformat(struct devdesc *d) {return d->d_dev->dv_fmtdev(d);}
static struct open_file *fd2open_file(int fd);
#define F_RAW 0x0004
#define EOFFSET (ELAST+8)
#define TSENTER() ((void)0)
#define TSEXIT() ((void)0)
"""
GZIP_IO=r"""
#define min(a,b) ((a)<(b)?(a):(b))
/* Only the stacked reader's descriptor calls use this native libsa adapter.
 * The actual UFS, disk and verified-block implementations remain below it.
 */
static int gzip_unit, gzip_opened, auth_errors;
static struct open_file gzip_raw;
static struct devdesc *gzip_dev;
static struct open_file *fd2open_file(int fd) {
 return fd==10000 && gzip_opened ? &gzip_raw : NULL;
}
static int gzip_open(const char *name,int flags) {
 assert(flags==O_RDONLY && !gzip_opened);
 char spec[128];const char *path;
 snprintf(spec,sizeof(spec),"verity%d:%s",gzip_unit,name);
 int error=verity_dev.dv_parsedev(&gzip_dev,spec,&path);
 if(error){errno=error;return -1;}
 gzip_dev->d_dev=&verity_dev;
 gzip_raw=(struct open_file){.f_flags=F_READ,.f_devdata=gzip_dev,.f_dev=&verity_dev,.f_ops=&ufs_fsops};
 error=verity_dev.dv_open(&gzip_raw,gzip_dev);
 if(!error) {
  error=ufs_fsops.fo_open(path,&gzip_raw);
  if(error)verity_dev.dv_close(&gzip_raw);
 }
 if(error){free(gzip_dev);errno=error;return -1;}
 gzip_raw.f_rabuf=malloc(SOPEN_RASIZE);assert(gzip_raw.f_rabuf);
 gzip_opened=1;return 10000;
}
static int gzip_close(int fd) {
 assert(fd==10000 && gzip_opened);
 int error=ufs_fsops.fo_close(&gzip_raw);
 int device_error=verity_dev.dv_close(&gzip_raw);
 free(gzip_raw.f_rabuf);gzip_raw.f_rabuf=NULL;
 free(gzip_dev);gzip_opened=0;
 if(error || device_error){errno=error ? error : device_error;return -1;}
 return 0;
}
static ssize_t gzip_read(int fd,void *buffer,size_t size) {
 assert(fd==10000 && gzip_opened);
 ssize_t result=native_loader_read(fd,buffer,size);
 if(result<0 && errno==EAUTH)auth_errors++;
 return result;
}
static off_t gzip_seek(int fd,off_t offset,int whence) {
 assert(fd==10000 && gzip_opened);
 return native_loader_lseek(fd,offset,whence);
}
static int gzip_stat(int fd,struct stat *st) {
 assert(fd==10000 && gzip_opened);
 int error=ufs_fsops.fo_stat(&gzip_raw,st);
 if(error){errno=error;return -1;}return 0;
}
static int null_write(struct open_file *f,const void *b,size_t n,size_t *r) {
 (void)f;(void)b;(void)n;(void)r;return EROFS;
}
static int null_readdir(struct open_file *f,struct dirent *d) {
 (void)f;(void)d;return ENOTDIR;
}
#define open gzip_open
#undef close
#define close gzip_close
#define read gzip_read
#define lseek gzip_seek
#define fstat gzip_stat
"""
GZIP_END=r"""
#undef open
#undef close
#define close loader_close
#undef read
#undef lseek
#undef fstat
"""
GZIP_RUN=r"""
 gzip_unit=unit;
 struct open_file compressed={.f_ops=&gzipfs_fsops,.f_flags=F_READ};
 int expected_fd=open(argv[4],O_RDONLY);assert(expected_fd>=0);
 for(unsigned attempt=0;attempt<2;attempt++) {
  assert(gzipfs_fsops.fo_open("/compressed",&compressed)==0);
  assert(gzipfs_fsops.fo_source(&compressed)==10000 && gzip_opened);
  assert(verity_dev_detach(unit)==EBUSY);
  /* Force the production read-ahead path, then restore the decoder's raw
   * position through the production relative-seek correction.
   */
  off_t raw_position=gzip_seek(10000,0,SEEK_CUR);assert(raw_position>=0);
  unsigned char probe[17];assert(gzip_read(10000,probe,sizeof(probe))==sizeof(probe));
  assert(gzip_raw.f_ralen>0);
  assert(gzip_seek(10000,-(off_t)sizeof(probe),SEEK_CUR)==raw_position);
  unsigned char output[777],expected[777];size_t resid;
  for(size_t offset=0;offset<131328;) {
   size_t count=sizeof(output);if(count>131328-offset)count=131328-offset;
   assert(pread(expected_fd,expected,count,offset)==(ssize_t)count);
   assert(gzipfs_fsops.fo_read(&compressed,output,count,&resid)==0 && resid==0);
   assert(!memcmp(output,expected,count));offset+=count;
  }
  assert(gzipfs_fsops.fo_seek(&compressed,13,SEEK_SET)==13);
  assert(pread(expected_fd,expected,sizeof(expected),13)==sizeof(expected));
  assert(gzipfs_fsops.fo_read(&compressed,output,sizeof(output),&resid)==0 && resid==0);
  assert(!memcmp(output,expected,sizeof(output)));
  assert(gzipfs_fsops.fo_close(&compressed)==0 && !gzip_opened);
  if(attempt==0) {
   /* Warm authenticated hash cache, then modify compressed-file data on media.
    * Reopen discards UFS's private file buffer; retained data must not mask I/O.
    */
   off_t offset=strtoull(argv[3],NULL,10);unsigned char saved,changed;
   assert(pread(fd,&saved,1,offset)==1);changed=saved^1;
   assert(pwrite(fd,&changed,1,offset)==1);
   auth_errors=0;
   assert(gzipfs_fsops.fo_open("/compressed",&compressed)!=0);
   assert(auth_errors>0 && !gzip_opened);
   assert(pwrite(fd,&saved,1,offset)==1);
  }
 }
 /* Modification of a not-yet-read block while the decoder is open. */
 assert(gzipfs_fsops.fo_open("/compressed",&compressed)==0);
 unsigned char output[777],expected[777],saved,changed;size_t resid;
 assert(gzipfs_fsops.fo_read(&compressed,output,sizeof(output),&resid)==0 && resid==0);
 assert(pread(expected_fd,expected,sizeof(expected),0)==sizeof(expected));
 assert(!memcmp(output,expected,sizeof(output)));
 off_t later=strtoull(argv[5],NULL,10);
 assert(pread(fd,&saved,1,later)==1);changed=saved^1;
 assert(pwrite(fd,&changed,1,later)==1);auth_errors=0;
 int error=0;size_t offset=sizeof(output);
 while(offset<131328) {
  size_t count=sizeof(output);if(count>131328-offset)count=131328-offset;
  error=gzipfs_fsops.fo_read(&compressed,output,count,&resid);
  if(error)break;
  assert(resid==0);
  assert(pread(expected_fd,expected,count,offset)==(ssize_t)count);
  assert(!memcmp(output,expected,count));offset+=count;
 }
 assert(error==EIO && auth_errors>0 && offset<131328);
 assert(gzipfs_fsops.fo_close(&compressed)==0 && !gzip_opened);
 assert(pwrite(fd,&saved,1,later)==1);
 /* Bytes already in a private authenticated input buffer remain usable even
  * if their backing storage changes. They must still produce original output.
  */
 assert(gzipfs_fsops.fo_open("/compressed",&compressed)==0);
 assert(gzipfs_fsops.fo_read(&compressed,output,sizeof(output),&resid)==0 && resid==0);
 off_t early=strtoull(argv[3],NULL,10);
 assert(pread(fd,&saved,1,early)==1);changed=saved^1;
 assert(pwrite(fd,&changed,1,early)==1);auth_errors=0;
 assert(gzipfs_fsops.fo_read(&compressed,output,sizeof(output),&resid)==0 && resid==0);
 assert(pread(expected_fd,expected,sizeof(expected),sizeof(output))==sizeof(expected));
 assert(!memcmp(output,expected,sizeof(output)) && auth_errors==0);
 assert(gzipfs_fsops.fo_close(&compressed)==0 && !gzip_opened);
 assert(pwrite(fd,&saved,1,early)==1);
 close(expected_fd);
"""
MAIN=r"""
int main(int argc,char **argv) {
 assert(argc==6);
 int fd=open(argv[1],O_RDWR),desc=open(argv[2],O_RDONLY);
 assert(fd>=0 && desc>=0);
 unsigned char wire[G_VERITY_ROOT_BYTES];
 assert(read(desc,wire,sizeof(wire))==sizeof(wire));close(desc);
 struct g_verity_root root;assert(g_verity_root_decode(wire,sizeof(wire),&root)==0);
 int unit=-1;assert(verity_dev_attach(fd,&root,8,1024*1024,&unit)==0);
 const char *names[]={"/payload","/alias","/subdir/link"};
 for(unsigned n=0;n<3;n++) {
  char spec[128];snprintf(spec,sizeof(spec),"verity%d:%s",unit,names[n]);
  struct devdesc *dev=NULL;const char *path=NULL;
  assert(verity_dev.dv_parsedev(&dev,spec,&path)==0);dev->d_dev=&verity_dev;
  struct open_file f={.f_devdata=dev,.f_dev=&verity_dev,.f_ops=&ufs_fsops};
  assert(verity_dev.dv_open(&f,dev)==0);
  assert(ufs_fsops.fo_open(path,&f)==0);
  struct stat st;assert(ufs_fsops.fo_stat(&f,&st)==0 && st.st_size==256*513);
  unsigned char buffer[777];size_t offset=0,resid;
  while(offset<(size_t)st.st_size) {
   size_t count=sizeof(buffer);if(count>(size_t)st.st_size-offset) count=st.st_size-offset;
   assert(ufs_fsops.fo_read(&f,buffer,count,&resid)==0 && resid==0);
   for(size_t i=0;i<count;i++) assert(buffer[i]==(unsigned char)(offset+i));
   offset+=count;
  }
  assert(ufs_fsops.fo_seek(&f,13,SEEK_SET)==13);
  assert(ufs_fsops.fo_read(&f,buffer,sizeof(buffer),&resid)==0 && resid==0);
  for(size_t i=0;i<sizeof(buffer);i++) assert(buffer[i]==(unsigned char)(13+i));
  assert(ufs_fsops.fo_close(&f)==0);
  /* Corrupt primary superblock; no alternate copy may bypass authentication. */
  if(n==2) {
   unsigned char saved,changed;assert(pread(fd,&saved,1,65536)==1);changed=saved^1;
   assert(pwrite(fd,&changed,1,65536)==1);
   assert(ufs_fsops.fo_open(path,&f)!=0);
   assert(pwrite(fd,&saved,1,65536)==1);
  }
  assert(verity_dev.dv_close(&f)==0);free(dev);
 }
 /* GZIP_RUN */
 assert(verity_dev_detach(unit)==0);return 0;
}
"""
class UFS(unittest.TestCase):
    def test_filesystem_reads_through_verified_device(self):
        sources=[]
        for name in ['stand/libsa/verity_read.c','stand/common/veritydev.c',
                     'stand/common/disk.c','stand/common/part.c','stand/libsa/ufs.c']:
            source=(ROOT/name).read_text()
            for include in ('#include <stand.h>','#include "stand.h"','#include <bootstrap.h>'):
                source=source.replace(include,'')
            sources.append(source+'\n#undef DPRINTF\n')
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory);source=folder/'source';source.mkdir()
            (source/'payload').write_bytes(bytes(range(256))*513)
            decoded=hashlib.shake_256(b'verified gzip integration').digest(131328)
            compressed=gzip.compress(decoded,mtime=0)
            self.assertGreater(len(compressed),65536)
            (source/'compressed.gz').write_bytes(compressed)
            (folder/'expected').write_bytes(decoded)
            os.link(source/'payload',source/'alias');(source/'subdir').mkdir()
            (source/'subdir/link').symlink_to('../payload')
            policy=dict(format=1,block_size=4096,salt_hex='aabb')
            subprocess.run([str(args.makefs),'-t','ffs','-o','version=2',
                *partition.component.artifacts.makefs_options(policy),
                str(folder/'system.ufs'),str(source)],check=True,capture_output=True,timeout=30)
            image=folder/'system.ufs'
            disk=image.read_bytes()
            start=disk.find(compressed[:64])
            self.assertGreaterEqual(start,0)
            self.assertEqual(disk.find(compressed[:64],start+1),-1)
            corrupt_offset=start+16
            later=disk.find(compressed[70000:70064])
            self.assertGreaterEqual(later,0)
            self.assertEqual(disk.find(compressed[70000:70064],later+1),-1)
            partition.component.artifacts.build(folder,policy,
                partition.component.artifacts.digest(image),image.stat().st_size)
            (folder/'verity_read.h').write_text((ROOT/'stand/libsa/verity_read.h').read_text())
            c=folder/'test.c';binary=folder/'test';gzip_source=(ROOT/'stand/libsa/gzipfs.c').read_text().replace('#include "stand.h"','')
            file_io=[]
            for name,result in (('read','ssize_t'),('lseek','off_t')):
                implementation=(ROOT/f'stand/libsa/{name}.c').read_text()
                signature=f'{result}\n{name}('
                start=implementation.index(signature)
                function=implementation[start:implementation.index('\n}\n',start)+3]
                file_io.append(function.replace(signature,f'{result}\nnative_loader_{name}(',1))
            c.write_text(PRE+''.join(sources)+''.join(file_io)+GZIP_IO+gzip_source+GZIP_END+
                MAIN.replace(' /* GZIP_RUN */',GZIP_RUN))
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
                '-Wno-sign-compare','-Wno-unused-but-set-variable','-I'+str(folder),
                '-DSTANDALONE_SMALL','-DLOADER_GPT_SUPPORT','-DLOADER_MBR_SUPPORT',
                '-I'+str(ROOT/'sys'),'-I'+str(ROOT/'stand/common'),
                str(c),str(ROOT/'sys/geom/verity/g_verity_verify.c'),
                str(ROOT/'sys/ufs/ffs/ffs_subr.c'),str(ROOT/'sys/ufs/ffs/ffs_tables.c'),
                str(ROOT/'sys/libkern/gsb_crc32.c'),'-lmd','-lz','-o',str(binary)],check=True)
            subprocess.run([str(binary),str(folder/'system.verity'),str(folder/'root.descriptor'),
                str(corrupt_offset),str(folder/'expected'),str(later)],
                check=True,timeout=30)
if __name__=='__main__':unittest.main(argv=[__file__,*remaining])
