# SPDX-License-Identifier: BSD-2-Clause
"""Native loader UFS readback helper for construction tests; no boot claims.

The test wraps its transport in a newly generated verity tree solely to reuse
native loader device adapters. That tree is not a release signature or evidence
that the transport was authenticated by firmware.
"""
from pathlib import Path
import subprocess
import os
import verity_loader_partition_test as partition
ROOT = partition.ROOT

MAIN = r'''
int main(int argc, char **argv) {
 assert(argc >= 6 && argc % 2 == 0);
 int fd=open(argv[1],O_RDONLY), desc=open(argv[2],O_RDONLY);
 assert(fd>=0 && desc>=0);
 unsigned char wire[G_VERITY_ROOT_BYTES];
 assert(read(desc,wire,sizeof(wire))==sizeof(wire));close(desc);
 struct g_verity_root root;
 assert(g_verity_root_decode(wire,sizeof(wire),&root)==0);
 int unit=-1;assert(verity_dev_attach(fd,&root,8,1024*1024,&unit)==0);
 for(int i=4;i<argc;i+=2) {
  char spec[4096];struct devdesc *dev=NULL;const char *path=NULL;
  assert(snprintf(spec,sizeof(spec),"verity%d%s%s",unit,argv[3],argv[i])<(int)sizeof(spec));
  assert(verity_dev.dv_parsedev(&dev,spec,&path)==0);
  dev->d_dev=&verity_dev;
  struct open_file f={.f_flags=F_READ,.f_devdata=dev,.f_dev=&verity_dev,.f_ops=&ufs_fsops};
  assert(verity_dev.dv_open(&f,dev)==0);
  assert(ufs_fsops.fo_open(path,&f)==0);
  struct stat actual,expected;int source=open(argv[i+1],O_RDONLY);assert(source>=0);
  assert(fstat(source,&expected)==0 && ufs_fsops.fo_stat(&f,&actual)==0);
  if(actual.st_size!=expected.st_size || !S_ISREG(actual.st_mode))return 1;
  unsigned char a[4096],b[4096];size_t residual;
  for(off_t offset=0;offset<expected.st_size;) {
   size_t count=sizeof(a);
   if(expected.st_size-offset<(off_t)count)count=expected.st_size-offset;
   assert(read(source,b,count)==(ssize_t)count);
   if(ufs_fsops.fo_read(&f,a,count,&residual)!=0 || residual || memcmp(a,b,count))return 1;
   offset+=count;
  }
  assert(ufs_fsops.fo_read(&f,a,1,&residual)==0 && residual==1);
  close(source);assert(ufs_fsops.fo_close(&f)==0);
  assert(verity_dev.dv_close(&f)==0);free(dev);
 }
 assert(verity_dev_detach(unit)==0);return 0;
}
'''

def build_reader(folder):
    stand=(ROOT/'stand/libsa/stand.h').read_text()
    def declaration(name):
        start=stand.index('struct '+name+' {')
        return stand[start:stand.index('\n};',start)+3]
    pre=partition.PRE.replace('struct open_file {void *f_devdata;};',
        '#include <sys/queue.h>\nstruct fs_ops;'+declaration('open_file'))
    pre+='#include <sys/dirent.h>\n'+declaration('fs_ops')+r'''
/* This harness opens UFS directly; no libsa mounted-filesystem fd exists. */
static struct open_file *fd2open_file(int fd) {(void)fd;abort();}
static void twiddle(unsigned n) {(void)n;}
static void panic(const char *s) {fprintf(stderr,"%s",s);abort();}
static char *devformat(struct devdesc *d) {return d->d_dev->dv_fmtdev(d);}
#define EOFFSET (ELAST+8)
#define TSENTER() ((void)0)
#define TSEXIT() ((void)0)
'''
    sources=[]
    for name in ('stand/libsa/verity_read.c','stand/common/veritydev.c',
                 'stand/common/disk.c','stand/common/part.c','stand/libsa/ufs.c'):
        source=(ROOT/name).read_text()
        for include in ('#include <stand.h>','#include "stand.h"','#include <bootstrap.h>'):
            source=source.replace(include,'')
        sources.append(source+'\n#undef DPRINTF\n')
    (folder/'verity_read.h').write_text((ROOT/'stand/libsa/verity_read.h').read_text())
    c=folder/'readback.c';binary=folder/'readback'
    c.write_text(pre+''.join(sources)+MAIN)
    subprocess.run(['cc','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
        '-Wno-sign-compare','-Wno-unused-but-set-variable','-I'+str(folder),
        '-DSTANDALONE_SMALL','-DLOADER_GPT_SUPPORT','-DLOADER_MBR_SUPPORT',
        '-I'+str(ROOT/'sys'),'-I'+str(ROOT/'stand/common'),str(c),
        str(ROOT/'sys/geom/verity/g_verity_verify.c'),
        str(ROOT/'sys/ufs/ffs/ffs_subr.c'),str(ROOT/'sys/ufs/ffs/ffs_tables.c'),
        str(ROOT/'sys/libkern/gsb_crc32.c'),'-lmd','-lz','-o',str(binary)],check=True)
    return binary


def check_payloads(folder, disk, payloads):
    folder.mkdir()
    binary=build_reader(folder)
    # The wrapper builder streams the disk; it does not preload it into RAM.
    source=folder/'system.ufs'
    os.link(disk,source)
    artifacts=partition.component.artifacts
    artifacts.build(folder,dict(format=1,block_size=512,salt_hex=''),
                    artifacts.digest(disk),disk.stat().st_size)
    command=[str(binary),str(folder/'system.verity'),str(folder/'root.descriptor'),'p2:']
    for path,binding in sorted(payloads.items()):
        command.extend((path,binding['path']))
    subprocess.run(command,check=True,timeout=30)
    # A wrong expected payload must fail independently of builder success.
    path,binding=next((p,b) for p,b in payloads.items() if Path(b['path']).stat().st_size)
    mismatch=folder/'wrong'
    # Preserve length so this exercises byte comparison, not just stat size.
    import shutil
    shutil.copyfile(binding['path'],mismatch)
    with mismatch.open('r+b') as stream:
        first=stream.read(1);stream.seek(0);stream.write(bytes([first[0]^1]))
    rejected=subprocess.run(command[:4]+[path,str(mismatch)],timeout=30)
    if rejected.returncode==0:
        raise AssertionError('loader readback accepted a mismatched payload')
