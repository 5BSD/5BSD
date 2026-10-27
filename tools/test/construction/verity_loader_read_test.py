# SPDX-License-Identifier: BSD-2-Clause
"""Loader replay/cache-eviction integrity and backing-read bounds; no timing claim."""
import hashlib
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
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static uint64_t data_extent;
static unsigned data_reads, tree_reads;
static ssize_t tracked_read(int fd, void *buffer, size_t length) {
 off_t position=lseek(fd,0,SEEK_CUR);assert(position>=0);
 if((uint64_t)position<data_extent)data_reads++;else tree_reads++;
 return read(fd,buffer,length);
}
#define read tracked_read
'''
MAIN=r'''
int main(int argc,char **argv) {
 assert(argc==4);
 size_t entries=strtoul(argv[3],NULL,10);assert(entries<=8);
 int fd=open(argv[1],O_RDWR),desc=open(argv[2],O_RDONLY);assert(fd>=0 && desc>=0);
 unsigned char wire[G_VERITY_ROOT_BYTES];assert(read(desc,wire,sizeof(wire))==sizeof(wire));
 close(desc);
 struct g_verity_root root;assert(g_verity_root_decode(wire,sizeof(wire),&root)==0);
 data_extent=root.layout.data_bytes;
 uint64_t tags[8];unsigned char cache[8*4096],data[4096],hashes[4096];
 struct verity_file file={0},saved;
 unsigned char expected[32],out[48],original,changed;
 assert(verity_file_init(&file,fd,&root,tags,cache,entries,data,hashes)==0);
 assert(pread(fd,expected,32,4090)==32);
 memset(out,0x51,sizeof(out));
 data_reads=tree_reads=0;
 assert(verity_file_read(&file,4090,32,out+8)==0 && !memcmp(out+8,expected,32));
 assert(data_reads==2 && tree_reads<=root.layout.levels);
 unsigned cold_tree=tree_reads;
 data_reads=tree_reads=0;
 assert(verity_file_read(&file,4090,32,out+8)==0 && !memcmp(out+8,expected,32));
 assert(data_reads==2 && tree_reads<=root.layout.levels);
 if(entries>=2)assert(tree_reads==0);
 unsigned warm_tree=tree_reads;
 /* Zero-length operations must not touch backing storage. */
 data_reads=tree_reads=0;
 assert(verity_file_read(&file,root.layout.data_bytes,0,out+8)==0);
 assert(data_reads==0 && tree_reads==0);
 /* Walk distinct leaf hash blocks to exercise direct-map collisions/eviction.
  * Each single-block request has a depth-bound cost, independent of file size.
  */
 uint64_t stride=(uint64_t)root.layout.block_size*(root.layout.block_size/32);
 for(uint64_t offset=0;offset<root.layout.data_bytes;offset+=stride) {
  data_reads=tree_reads=0;
  unsigned char wanted;assert(pread(fd,&wanted,1,offset)==1);
  assert(verity_file_read(&file,offset,1,out+8)==0 && out[8]==wanted);
  assert(data_reads==1 && tree_reads<=root.layout.levels);
 }
 assert(verity_file_read(&file,4090,32,out+8)==0 && !memcmp(out+8,expected,32));
 printf("blocks=%ju cache_entries=%zu cold_data_reads=2 cold_tree_reads=%u "
  "warm_data_reads=2 warm_tree_reads=%u\n",
  (uintmax_t)(root.layout.data_bytes/root.layout.block_size),entries,cold_tree,warm_tree);
 assert(verity_file_read(&file,root.layout.data_bytes-32,32,out+8)==0);
 /* A changed replay crosses a data-block boundary after a valid prefix. */
 assert(pread(fd,&original,1,4097)==1);changed=original^1;
 assert(pwrite(fd,&changed,1,4097)==1);
 assert(verity_file_read(&file,4090,32,out+8)==EAUTH && !file.busy);
 for(unsigned i=8;i<40;i++) assert(out[i]==0);
 for(unsigned i=0;i<8;i++) {assert(out[i]==0x51);assert(out[40+i]==0x51);}
 assert(pwrite(fd,&original,1,4097)==1);
 assert(verity_file_read(&file,4090,32,out+8)==0 && !memcmp(out+8,expected,32));
 /* Invalid initialization preserves an existing binding. */
 saved=file;
 assert(verity_file_init(&file,-1,&root,tags,cache,entries,data,hashes)==EINVAL);
 assert(!memcmp(&file,&saved,sizeof(file)));
 assert(verity_file_init(&file,fd,&root,tags,cache,entries,data,data)==EINVAL);
 assert(!memcmp(&file,&saved,sizeof(file)));
 root.layout.tree_bytes++;
 assert(verity_file_init(&file,fd,&root,tags,cache,entries,data,hashes)==EINVAL);
 assert(!memcmp(&file,&saved,sizeof(file)));root.layout.tree_bytes--;
 file.busy=1;assert(verity_file_read(&file,0,1,out)==EDEADLK);file.busy=0;
 memset(out,0x51,sizeof(out));
 assert(verity_file_read(&file,UINT64_MAX,32,out+8)==EINVAL && !file.busy);
 for(unsigned i=0;i<sizeof(out);i++) assert(out[i]==0x51);
 /* Force a short backing data block after cached hash bytes exist. */
 assert(ftruncate(fd,root.layout.data_bytes-1)==0);
 assert(verity_file_read(&file,root.layout.data_bytes-32,32,out+8)==EIO && !file.busy);
 for(unsigned i=8;i<40;i++) assert(out[i]==0);
 close(fd);return 0;
}
'''
class Reader(unittest.TestCase):
    def test_backward_replay_and_truncation(self):
        source=(ROOT/'stand/libsa/verity_read.c').read_text().replace('#include <stand.h>',PRE)
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            c=folder/'reader.c';binary=folder/'reader'
            c.write_text(source+MAIN)
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'sys'),
                '-I'+str(ROOT/'stand/libsa'),str(c),
                str(ROOT/'sys/geom/verity/g_verity_verify.c'),'-lmd','-o',str(binary)],
                check=True)
            for blocks in (129, 1025):
                for entries in (0, 1, 8):
                    with self.subTest(blocks=blocks, cache_entries=entries):
                        fixture=folder/f'{blocks}-{entries}'
                        fixture.mkdir()
                        payload=b''.join(hashlib.sha256(index.to_bytes(8,'big')).digest()*128
                            for index in range(blocks))
                        (fixture/'system.ufs').write_bytes(payload)
                        artifacts.build(fixture,dict(format=1,block_size=4096,salt_hex='aabb'),
                            artifacts.digest(fixture/'system.ufs'),len(payload))
                        subprocess.run([str(binary),str(fixture/'system.verity'),
                            str(fixture/'root.descriptor'),str(entries)],check=True,timeout=10)


if __name__=='__main__':unittest.main()
