# SPDX-License-Identifier: BSD-2-Clause
"""Actual backing adapter with injected GEOM BIO operations; not live GEOM."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <crypto/sha2/sha256.h>
#include <geom/verity/g_verity_io.h>
struct g_provider { off_t mediasize; unsigned sectorsize; };
struct g_consumer { struct g_provider *provider; int acr; };
struct bio { int bio_cmd; void *bio_done; off_t bio_offset;
 size_t bio_length,bio_completed; void *bio_data; };
#define BIO_READ 1
static unsigned maxphys=131072;
static int topology, allocated, destroyed, requests, ioerror, shortread;
static off_t observed_offset;
static void *expected_buffer;
static unsigned char *media;
static size_t data_requests, data_bytes;
#define g_topology_assert() assert(topology)
#define g_topology_assert_not() assert(!topology)
static struct bio *g_alloc_bio(void) { allocated++;return calloc(1,sizeof(struct bio)); }
static void g_destroy_bio(struct bio *bp) { destroyed++;free(bp); }
static void g_io_request(struct bio *bp,struct g_consumer *cp) {
 assert(cp && cp->acr==1 && bp->bio_cmd==BIO_READ && !bp->bio_done);
 assert(bp->bio_length<=maxphys);
 if(expected_buffer) assert(bp->bio_data==expected_buffer && bp->bio_length==4096);
 if(media) {
  assert(bp->bio_offset >= 0 && bp->bio_offset+bp->bio_length <= (size_t)cp->provider->mediasize);
  memcpy(bp->bio_data,media+bp->bio_offset,bp->bio_length);
  if(bp->bio_offset < 129*4096) { data_requests++; data_bytes+=bp->bio_length; }
 }
 requests++;observed_offset=bp->bio_offset;
 bp->bio_completed=bp->bio_length-(shortread?1:0);
}
static int biowait(struct bio *bp,const char *name) { (void)bp;(void)name;return ioerror; }
'''
MAIN=r'''
int main(void) {
 struct g_provider pp={.mediasize=129*4096+3*4096,.sectorsize=512};
 struct g_consumer cp={.provider=&pp,.acr=1};
 struct g_verity_backing backing, untouched;
 char buffer[4096];expected_buffer=buffer;topology=1;
 assert(g_verity_backing_bind(&backing,&cp,129*4096,4096)==0);
 assert(backing.consumer==&cp && backing.tree_bytes==3*4096);
 for(int scenario=0;scenario<6;scenario++) {
  struct g_provider badpp=pp;struct g_consumer badcp=cp;badcp.provider=&badpp;
  memset(&untouched,0x51,sizeof(untouched));backing=untouched;
  if(scenario==0) badcp.acr=0;
  if(scenario==1) badpp.mediasize--;
  if(scenario==2) badpp.mediasize++;
  if(scenario==3) badpp.sectorsize=8192;
  if(scenario==4) badpp.sectorsize=0;
  if(scenario==5) maxphys=2048;
  assert(g_verity_backing_bind(&backing,&badcp,129*4096,4096)==EINVAL);
  assert(!memcmp(&backing,&untouched,sizeof(backing)));
  maxphys=131072;
 }
 assert(g_verity_backing_bind(&backing,&cp,129*4096,4096)==0);topology=0;
 for(int tree=0;tree<=1;tree++) {
  uint64_t bytes=tree?backing.tree_bytes:backing.data_bytes;
  assert(g_verity_backing_read(&backing,tree,bytes-4096,buffer,4096)==0);
  assert(observed_offset==(off_t)((tree?backing.data_bytes:0)+bytes-4096));
 }
 int before=allocated;
 assert(g_verity_backing_read(&backing,2,0,buffer,4096)==EINVAL);
 assert(g_verity_backing_read(&backing,0,1,buffer,4096)==EINVAL);
 assert(g_verity_backing_read(&backing,0,0,buffer,1)==EINVAL);
 assert(g_verity_backing_read(&backing,0,backing.data_bytes,buffer,4096)==EINVAL);
 assert(g_verity_backing_read(&backing,1,UINT64_MAX,buffer,4096)==EINVAL);
 assert(allocated==before);
 shortread=1;assert(g_verity_backing_read(&backing,0,0,buffer,4096)==EIO);
 shortread=0;ioerror=ENXIO;
 assert(g_verity_backing_read(&backing,0,0,buffer,4096)==ENXIO);
 assert(allocated==destroyed && requests==allocated);
 ioerror=0;expected_buffer=NULL;
 media=calloc(1,pp.mediasize);assert(media);
 for(size_t i=0;i<129*4096;i++) media[i]=(unsigned char)(i ^ (i>>8));
 unsigned char digest[32],root[32];SHA256_CTX hash;
 for(size_t i=0;i<129;i++) {
  SHA256_Init(&hash);SHA256_Update(&hash,media+i*4096,4096);
  SHA256_Final(digest,&hash);
  memcpy(media+129*4096+4096+i*32,digest,32);
 }
 for(size_t i=0;i<2;i++) {
  SHA256_Init(&hash);SHA256_Update(&hash,media+129*4096+4096+i*4096,4096);
  SHA256_Final(digest,&hash);memcpy(media+129*4096+i*32,digest,32);
 }
 SHA256_Init(&hash);SHA256_Update(&hash,media+129*4096,4096);SHA256_Final(root,&hash);
 unsigned char *windowbuf=malloc(131072),*output=malloc(131072);
 unsigned char data[4096],hashes[4096],leaf[4096];
 assert(windowbuf && output);
 struct g_verity_read_window window, original_window;
 assert(g_verity_window_init(&window,&backing,0,131072,windowbuf,131072)==0);
 original_window=window;
 assert(g_verity_window_init(&window,&backing,UINT64_MAX,1,windowbuf,131072)==EINVAL);
 assert(g_verity_window_init(&window,&backing,0,1,windowbuf,131073)==EINVAL);
 assert(g_verity_window_init(&window,&backing,backing.data_bytes-1,2,windowbuf,131072)==EINVAL);
 assert(!memcmp(&window,&original_window,sizeof(window)));
 int reads_before=requests;
 assert(g_verity_read_range(backing.data_bytes,4096,NULL,0,root,0,131072,
  g_verity_backing_read,&backing,data,hashes,leaf,output)==0);
 assert(!memcmp(output,media,131072));
 assert(data_requests==32 && data_bytes==131072 && requests-reads_before==34);
 data_requests=data_bytes=0;reads_before=requests;
 assert(g_verity_read_range(backing.data_bytes,4096,NULL,0,root,0,131072,
  g_verity_window_read,&window,data,hashes,leaf,output)==0);
 assert(!memcmp(output,media,131072));
 assert(data_requests==1 && data_bytes==131072 && requests-reads_before==3);
 /* A smaller caller budget works over multiple windows. */
 data_requests=data_bytes=0;
 assert(g_verity_window_init(&window,&backing,0,131072,windowbuf,8192)==0);
 assert(g_verity_read_range(backing.data_bytes,4096,NULL,0,root,0,131072,
  g_verity_window_read,&window,data,hashes,leaf,output)==0);
 assert(!memcmp(output,media,131072));
 assert(data_requests==16 && data_bytes==131072);
 data_requests=data_bytes=0;
 assert(g_verity_window_init(&window,&backing,backing.data_bytes-1,1,windowbuf,131072)==0);
 assert(g_verity_read_range(backing.data_bytes,4096,NULL,0,root,backing.data_bytes-1,1,
  g_verity_window_read,&window,data,hashes,leaf,output)==0);
 assert(output[0]==media[backing.data_bytes-1]);
 assert(data_requests==1 && data_bytes==4096);
 /* A new request cannot reuse unchecked old data after backing mutation. */
 media[17]^=1;
 assert(g_verity_window_init(&window,&backing,0,131072,windowbuf,131072)==0);
 memset(output,0x51,131072);
 assert(g_verity_read_range(backing.data_bytes,4096,NULL,0,root,0,131072,
  g_verity_window_read,&window,data,hashes,leaf,output)==EAUTH);
 for(size_t i=0;i<131072;i++) assert(output[i]==0);
 media[17]^=1;
 /* Partial requests round only to touched blocks, not full window capacity. */
 data_requests=data_bytes=0;
 assert(g_verity_window_init(&window,&backing,4090,17,windowbuf,131072)==0);
 assert(g_verity_read_range(backing.data_bytes,4096,NULL,0,root,4090,17,
  g_verity_window_read,&window,data,hashes,leaf,output)==0);
 assert(!memcmp(output,media+4090,17));
 assert(data_requests==1 && data_bytes==8192);
 assert(g_verity_window_read(&window,0,8192,data,4096)==EINVAL);
 /* Short or failed fills never become usable windows; retry must fetch. */
 assert(g_verity_window_init(&window,&backing,0,8192,windowbuf,8192)==0);
 shortread=1;
 assert(g_verity_window_read(&window,0,0,data,4096)==EIO && window.valid==0);
 shortread=0;ioerror=ENXIO;
 assert(g_verity_window_read(&window,0,0,data,4096)==ENXIO && window.valid==0);
 ioerror=0;
 assert(g_verity_window_read(&window,0,0,data,4096)==0 && window.valid==8192);
 assert(!memcmp(data,media,4096));
 /* Upstream requests may exceed maxphys; each backing fill remains bounded. */
 unsigned char *large=malloc(backing.data_bytes);assert(large);
 data_requests=data_bytes=0;reads_before=requests;
 assert(g_verity_window_init(&window,&backing,0,backing.data_bytes,windowbuf,131072)==0);
 assert(g_verity_read_range(backing.data_bytes,4096,NULL,0,root,0,backing.data_bytes,
  g_verity_window_read,&window,data,hashes,leaf,large)==0);
 assert(!memcmp(large,media,backing.data_bytes));
 assert(data_requests==5 && data_bytes==backing.data_bytes && requests-reads_before==9);
 /* A failure in the last block must clear the earlier verified windows. */
 media[backing.data_bytes-1]^=1;
 assert(g_verity_window_init(&window,&backing,0,backing.data_bytes,windowbuf,131072)==0);
 memset(large,0x51,backing.data_bytes);
 assert(g_verity_read_range(backing.data_bytes,4096,NULL,0,root,0,backing.data_bytes,
  g_verity_window_read,&window,data,hashes,leaf,large)==EAUTH);
 for(size_t i=0;i<backing.data_bytes;i++) assert(large[i]==0);
 media[backing.data_bytes-1]^=1;
 free(large);
 assert(allocated==destroyed && requests==allocated);
 free(windowbuf);free(output);free(media);
 return 0;
}
'''
class BackingIO(unittest.TestCase):
    def test_geometry_mapping_and_completion(self):
        source=(ROOT/'sys/geom/verity/g_verity_io.c').read_text()
        functions=[]
        for signature in ('int\ng_verity_backing_bind(', 'static int\nbacking_read_extent(', 'int\ng_verity_backing_read(', 'int\ng_verity_window_init(', 'int\ng_verity_window_read('):
            start=source.index(signature)
            functions.append(source[start:source.index('\n}\n',start)+3])
        with tempfile.TemporaryDirectory(prefix='verity-io-') as d:
            c=Path(d)/'test.c';binary=Path(d)/'test'
            c.write_text(PRE+'\n'.join(functions)+MAIN)
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'sys'),str(c),str(ROOT/'sys/geom/verity/g_verity_verify.c'),'-lmd','-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,timeout=10)
if __name__=='__main__':unittest.main()
