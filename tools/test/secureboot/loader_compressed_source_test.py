# SPDX-License-Identifier: BSD-2-Clause
"""Actual gzip/bzip/xz/zstd readers and source admission, native file I/O and codecs.

Device identities are injected; this does not boot an ELF or authenticate a disk.
"""
import argparse
import ctypes
import bz2
import gzip
import lzma
import re
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r"""
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dirent.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#define F_READ 1
#define EOFFSET (ELAST+8)
#define min(a,b) ((a)<(b)?(a):(b))
struct devsw {int unused;};
struct devdesc {struct devsw *d_dev;int d_unit;};
struct fs_ops;
struct open_file {int f_flags;struct devsw *f_dev;void *f_devdata;
 struct fs_ops *f_ops;void *f_fsdata;};
static int allocations,fail_allocation,read_error,opened=-1;
static unsigned seek_read_calls;
static ssize_t test_read(int fd,void *buf,size_t size) {
 if(read_error){errno=EIO;return -1;}return read(fd,buf,size);
}
static void *test_malloc(size_t bytes) {
 if(++allocations==fail_allocation)return NULL;return malloc(bytes);
}
static int test_open(const char *path,int flags) {opened=open(path,flags);return opened;}
static void panic(const char *format,...) __attribute__((unused,noreturn));
static void panic(const char *format,...) {(void)format;abort();}
static int null_write(struct open_file *f,const void *p,size_t n,size_t *r) {
 (void)f;(void)p;(void)n;(void)r;return EROFS;
}
static int null_readdir(struct open_file *f,struct dirent *d) {(void)f;(void)d;return ENOTDIR;}
#define malloc test_malloc
#define open test_open
#define read test_read
"""
MAIN=r"""
static struct devsw verity_dev,foreign_dev;
static struct fs_ops ufs_fsops;
static struct devdesc device;
static struct open_file payload,wrapper;
static int verity_selected=7;
static int verity_required;
static struct open_file *fd2open_file(int fd) {
 if(fd==10000)return &wrapper;
 return fd==opened ? &payload : NULL;
}
"""
RUN=r"""
static unsigned char expected_byte(uint32_t offset) {
 uint32_t value=offset+0x9e3779b9U;
 value=(value^(value>>16))*0x85ebca6bU;
 value=(value^(value>>13))*0xc2b2ae35U;
 return (unsigned char)(value^(value>>16));
}
int main(int argc,char **argv) {
 assert(argc==3);int mode=atoi(argv[2]);
 wrapper=(struct open_file){.f_flags=F_READ,.f_ops=&TEST_FS};
 /* Failed reader allocation must release the file it already opened. */
 fail_allocation=2;allocations=0;
 assert(TEST_FS.fo_open(argv[1],&wrapper)==ENOMEM);
 assert(opened>=0 && fcntl(opened,F_GETFD)==-1 && errno==EBADF);
 fail_allocation=0;allocations=0;
 assert(TEST_FS.fo_open(argv[1],&wrapper)==0);
 assert(TEST_FS.fo_source(&wrapper)==opened);
 device=(struct devdesc){&verity_dev,7};
 payload=(struct open_file){F_READ,&verity_dev,&device,&ufs_fsops,NULL};
 assert(verity_check_source(10000)==0);
 wrapper.f_dev=&verity_dev;wrapper.f_devdata=&device;
 payload.f_dev=&foreign_dev;assert(verity_check_source(10000)==EAUTH);
 payload.f_dev=&verity_dev;
 unsigned char data[777];size_t resid;
 if(mode!=0) {
  int error=0;
  if(mode==2)read_error=1;
  /* Bound consumer attempts as well as the subprocess wall-clock timeout. */
  for(unsigned attempt=0;attempt<1000;attempt++) {
   error=TEST_FS.fo_read(&wrapper,data,sizeof(data),&resid);
   if(error!=0)break;
   assert(resid<sizeof(data)); /* truncation must not become clean EOF */
  }
  assert(error==EIO);
  assert(TEST_FS.fo_close(&wrapper)==0);
  assert(fcntl(opened,F_GETFD)==-1 && errno==EBADF);
  return 0;
 }
 for(size_t at=0;at<131328;) {
  size_t n=sizeof(data);if(n>131328-at)n=131328-at;
  assert(TEST_FS.fo_read(&wrapper,data,n,&resid)==0 && resid==0);
  for(size_t i=0;i<n;i++)assert(data[i]==expected_byte(at+i));
  at+=n;
 }
 assert(TEST_FS.fo_read(&wrapper,data,1,&resid)==0 && resid==1);
 assert(TEST_FS.fo_read(&wrapper,data,1,&resid)==0 && resid==1);
 assert(TEST_FS.fo_seek(&wrapper,13,SEEK_SET)==13);
 assert(TEST_FS.fo_read(&wrapper,data,sizeof(data),&resid)==0 && resid==0);
 for(size_t i=0;i<sizeof(data);i++)assert(data[i]==expected_byte(13+i));
 assert(TEST_FS.fo_seek(&wrapper,-1,SEEK_SET)==-1 && errno==EINVAL);
 assert(TEST_FS.fo_seek(&wrapper,-(off_t)(14+sizeof(data)),SEEK_CUR)==-1 && errno==EINVAL);
 assert(TEST_FS.fo_seek(&wrapper,INT64_MAX,SEEK_CUR)==-1 && errno==EOVERFLOW);
 assert(TEST_FS.fo_seek(&wrapper,0,SEEK_CUR)==13+sizeof(data));
 assert(TEST_FS.fo_seek(&wrapper,-(off_t)sizeof(data),SEEK_CUR)==13);
 seek_read_calls=0;
 assert(TEST_FS.fo_seek(&wrapper,120013,SEEK_SET)==120013);
 printf("%s seek_bytes=120000 reader_calls=%u\n",TEST_FS.fs_name,seek_read_calls);
 /* Operation budget permits different bounded implementations. */
 assert(seek_read_calls<=512);
 assert(TEST_FS.fo_read(&wrapper,data,sizeof(data),&resid)==0 && resid==0);
 for(size_t i=0;i<sizeof(data);i++)assert(data[i]==expected_byte(120013+i));
#ifdef TEST_BZIP_POSITION
 /* Inject only the public decoded-byte counter; use real decoder output to
  * cross its low-word boundary. This is not a multi-gigabyte decode test.
  */
 struct bz_file *bz=wrapper.f_fsdata;
 unsigned old_low=bz->bzf_bzstream.total_out_lo32;
 bz->bzf_bzstream.total_out_hi32=0;
 bz->bzf_bzstream.total_out_lo32=UINT32_MAX-1;
 assert(TEST_FS.fo_read(&wrapper,data,4,&resid)==0 && resid==0);
 for(unsigned i=0;i<4;i++)assert(data[i]==expected_byte(120790+i));
 seek_read_calls=0;
 assert(TEST_FS.fo_seek(&wrapper,0,SEEK_CUR)==((off_t)1<<32)+2);
 bz->bzf_bzstream.total_out_hi32=0x7fffffff;
 bz->bzf_bzstream.total_out_lo32=UINT32_MAX;
 assert(TEST_FS.fo_seek(&wrapper,0,SEEK_CUR)==INT64_MAX);
 assert(TEST_FS.fo_seek(&wrapper,1,SEEK_CUR)==-1 && errno==EOVERFLOW);
 bz->bzf_bzstream.total_out_hi32=0x80000000;
 bz->bzf_bzstream.total_out_lo32=0;
 assert(TEST_FS.fo_seek(&wrapper,0,SEEK_CUR)==-1 && errno==EOVERFLOW);
 assert(seek_read_calls==0);
 bz->bzf_bzstream.total_out_hi32=0;
 bz->bzf_bzstream.total_out_lo32=old_low+4;
#endif
 assert(TEST_FS.fo_source(&wrapper)==opened);
 assert(TEST_FS.fo_close(&wrapper)==0);
 assert(fcntl(opened,F_GETFD)==-1 && errno==EBADF);
 return 0;
}
"""
def payload_byte(offset):
    value=(offset+0x9e3779b9)&0xffffffff
    value=((value^(value>>16))*0x85ebca6b)&0xffffffff
    value=((value^(value>>13))*0xc2b2ae35)&0xffffffff
    return (value^(value>>16))&255

class CompressedSources(unittest.TestCase):
    zstd_library = None
    zstd_include = None

    def compress_zstd(self, payload):
        lib=ctypes.CDLL(str(self.zstd_library))
        lib.ZSTD_compressBound.argtypes=[ctypes.c_size_t]
        lib.ZSTD_compressBound.restype=ctypes.c_size_t
        lib.ZSTD_compress.argtypes=[ctypes.c_void_p,ctypes.c_size_t,
            ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
        lib.ZSTD_compress.restype=ctypes.c_size_t
        lib.ZSTD_isError.argtypes=[ctypes.c_size_t]
        lib.ZSTD_isError.restype=ctypes.c_uint
        output=ctypes.create_string_buffer(lib.ZSTD_compressBound(len(payload)))
        size=lib.ZSTD_compress(output,len(output),payload,len(payload),3)
        if lib.ZSTD_isError(size):
            raise RuntimeError('ZSTD fixture compression failed')
        return output.raw[:size]

    def test_actual_readers_and_backing_lifetime(self):
        stand=(ROOT/'stand/libsa/stand.h').read_text()
        start=stand.index('struct fs_ops {')
        structure=stand[start:stand.index('\n};',start)+3]
        commands=(ROOT/'stand/common/verity_commands.c').read_text()
        start=commands.index('int\nverity_check_source(')
        check=commands[start:commands.index('\n}\n',start)+3]
        for name,suffix,ops,compress,library in (
                ('gzipfs.c','.gz','gzipfs_fsops',gzip.compress,'-lz'),
                ('bzipfs.c','.bz2','bzipfs_fsops',bz2.compress,'-lbz2'),
                ('xzfs.c','.xz','xzfs_fsops',lzma.compress,None),
                ('zstdfs.c','.zst','zstdfs_fsops',self.compress_zstd,None)):
            with self.subTest(reader=name),tempfile.TemporaryDirectory() as directory:
                folder=Path(directory);base=folder/'payload'
                payload=bytes(payload_byte(offset) for offset in range(131328))
                compressed=compress(payload)
                # Exercise repeated decoder refills, not a tiny compressed stream
                # already held entirely in the initial input buffer.
                self.assertGreater(len(compressed),65536)
                Path(str(base)+suffix).write_bytes(compressed)
                source=(ROOT/'stand/libsa'/name).read_text().replace('#include "stand.h"','')
                # Count invocations without replacing the reader/decoder logic.
                source,count=re.subn(r'(\n(?:zf|bzf|xzf|zstdf)_read\(struct open_file \*f, void \*buf, size_t size, size_t \*resid\)\n\{)',
                    r'\1\n    seek_read_calls++;',source)
                self.assertEqual(count,1)
                c=folder/'test.c';binary=folder/'test'
                c.write_text(PRE+structure+source+MAIN+check+RUN.replace('TEST_FS',ops))
                codec=[library] if library else []
                if name=='bzipfs.c':
                    codec += ['-DTEST_BZIP_POSITION']
                if name=='zstdfs.c':
                    codec=['-I'+str(self.zstd_include),str(self.zstd_library)]
                if name=='xzfs.c':
                    xz=ROOT/'sys/contrib/xz-embedded'
                    native=folder/'native.h'
                    native.write_text('#include <sys/types.h>\n#include <sys/param.h>\n'
                        '#include <sys/endian.h>\n#include <stdint.h>\n#include <stdlib.h>\n'
                        '#include <string.h>\n#define min(a,b) ((a)<(b)?(a):(b))\n')
                    allocator=folder/'allocator.c'
                    allocator.write_text('void *xz_malloc(unsigned long n){return malloc(n);}'
                        'void xz_free(void *p){free(p);}')
                    codec=['-DXZ_USE_CRC64','-I'+str(ROOT/'sys'),
                        '-I'+str(xz/'freebsd'),'-I'+str(xz/'linux/include/linux'),
                        '-include',str(native),str(allocator)]
                    codec += [str(xz/'linux/lib/xz'/part) for part in (
                        'xz_crc32.c','xz_crc64.c','xz_dec_bcj.c',
                        'xz_dec_lzma2.c','xz_dec_stream.c')]
                subprocess.run(['cc','-Wall','-Wextra','-Werror','-Wno-sign-compare',
                                str(c),*codec,'-o',str(binary)],check=True)
                for mode,content in ((0,compressed),(1,compressed[:len(compressed)//2]),
                                     (2,compressed)):
                    with self.subTest(reader=name,mode=mode):
                        Path(str(base)+suffix).write_bytes(content)
                        subprocess.run([str(binary),str(base),str(mode)],check=True,
                            timeout=10,cwd=folder)
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zstd-library',type=Path,required=True)
    parser.add_argument('--zstd-include',type=Path,required=True)
    args=parser.parse_args()
    CompressedSources.zstd_library=args.zstd_library.resolve(strict=True)
    CompressedSources.zstd_include=args.zstd_include.resolve(strict=True)
    unittest.main(argv=[__file__])
