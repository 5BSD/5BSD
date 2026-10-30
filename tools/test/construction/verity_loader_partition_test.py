# SPDX-License-Identifier: BSD-2-Clause
"""Actual loader disk/partition/device code over native regular-file I/O."""
import subprocess
import struct
import tempfile
import unittest
from pathlib import Path
import verity_loader_device_test as component
ROOT = component.ROOT
PRE = component.PRE[:component.PRE.index('static int disk_open(')]
PRE = PRE.replace('struct disk_devdesc {struct devdesc dd;int d_slice,d_partition;uint64_t d_offset;};', '')
PRE += r"""
#include <disk.h>
#define EUNIT 1001
#define ESLICE 1002
#define EPART 1003
#define F_NORA (0x01 << 16)
static int pager_output(const char *s) {(void)s;return 0;}
"""
MAIN = r"""
int main(int argc,char **argv) {
 assert(argc==4);
 /* Preserve shared disk syntax and output ownership on a wrong device name. */
 struct devdesc *old=NULL;const char *tail=NULL;
 const char *names[]={"disk3:","vdisk3:","disk3s2a:/boot/kernel", "disk3p2:/boot/kernel"};
 for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);i++) {
  assert(disk_parsedev(&old,names[i],&tail)==0 && old->d_unit==3);
  struct disk_devdesc *d=(struct disk_devdesc *)old;
  if(i==2) assert(d->d_slice==2 && d->d_partition==0);
  if(i==3) assert(d->d_slice==2 && d->d_partition==D_PARTISGPT);
  if(i>=2) assert(!strcmp(tail,"/boot/kernel"));
  free(old);old=NULL;
 }
 assert(verity_dev.dv_parsedev(&old,"disk3:",&tail)==EINVAL && old==NULL);
 int fd=open(argv[1],O_RDWR),desc=open(argv[2],O_RDONLY);
 assert(fd>=0 && desc>=0);
 unsigned char wire[G_VERITY_ROOT_BYTES];
 assert(read(desc,wire,sizeof(wire))==sizeof(wire));close(desc);
 struct g_verity_root root;
 assert(g_verity_root_decode(wire,sizeof(wire),&root)==0);
 int unit=-1;
 assert(verity_dev_attach(fd,&root,8,1024*1024,&unit)==0);
 struct devdesc *parsed=NULL;const char *path=NULL;char name[64];
 snprintf(name,sizeof(name),"verity%d%s",unit,argv[3]);
 assert(verity_dev.dv_parsedev(&parsed,name,&path)==0);
 assert(parsed->d_unit==unit && (!strcmp(path,"/boot/kernel/kernel") || *path=='\0'));
 parsed->d_dev=&verity_dev;
 struct disk_devdesc *dev=(struct disk_devdesc *)parsed;
 struct open_file file={.f_devdata=dev};
 assert(verity_dev.dv_open(&file,dev)==0);
 uint64_t bytes=0;unsigned sectors=0;
 assert(verity_dev.dv_ioctl(&file,DIOCGMEDIASIZE,&bytes)==0);
 assert(bytes==(argv[3][0]==':' ? root.layout.data_bytes : 512*1024));
 assert(dev->d_offset==(argv[3][0]==':' ? 0 : 128));
 assert(verity_dev.dv_ioctl(&file,DIOCGSECTORSIZE,&sectors)==0 && sectors==512);
 assert(verity_dev.dv_close(&file)==0);
 /* Corrupt sector zero after caching its hash path; real parser must fail. */
 unsigned char byte=1;assert(pwrite(fd,&byte,1,0)==1);
 assert(verity_dev.dv_open(&file,dev)!=0);
 assert(verity_dev_detach(unit)==0);
 free(dev);
 return 0;
}
"""
class Partition(unittest.TestCase):
    def test_real_disk_and_partition_parser(self):
        sources=[]
        for path in ['stand/libsa/verity_read.c','stand/common/veritydev.c',
                     'stand/common/disk.c','stand/common/part.c']:
            source=(ROOT/path).read_text()
            source=source.replace('#include <stand.h>','').replace('#include <bootstrap.h>','')
            sources.append(source+'\n#undef DPRINTF\n')
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            c=folder/'test.c';binary=folder/'test'
            c.write_text(PRE+''.join(sources)+MAIN)
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
                '-DLOADER_GPT_SUPPORT','-DLOADER_MBR_SUPPORT',
                '-I'+str(ROOT/'sys'),'-I'+str(ROOT/'stand/common'),
                '-I'+str(ROOT/'stand/libsa'),str(c),
                str(ROOT/'sys/geom/verity/g_verity_verify.c'),'-lmd','-lz',
                '-o',str(binary)],check=True)
            for partitioned in (False, True):
                image=bytearray(1024*1024)
                if partitioned:
                    image[510:512]=b'\x55\xaa'
                    image[450]=0x83  # Linux partition; ordinary raw slice selection.
                    struct.pack_into('<II',image,454,128,1024)
                case=folder/('mbr' if partitioned else 'raw');case.mkdir()
                (case/'system.ufs').write_bytes(image)
                component.artifacts.build(case,dict(format=1,block_size=4096,salt_hex=''),
                    component.artifacts.digest(case/'system.ufs'),len(image))
                subprocess.run([str(binary),str(case/'system.verity'),
                    str(case/'root.descriptor'),'s1:/boot/kernel/kernel' if partitioned else ':/boot/kernel/kernel'],
                    check=True,timeout=10)
if __name__=='__main__':unittest.main()
