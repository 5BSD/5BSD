# SPDX-License-Identifier: BSD-2-Clause
"""Real attachment/reader/core; injected manifest verification decisions."""
from pathlib import Path
import subprocess
import tempfile
import unittest
import verity_loader_device_test as device
ROOT=device.ROOT
PRE=device.PRE+r"""
#define LOADER_VERIEXEC 1
#define VE_VERIFIED 1
#define VE_MUST 2
#include <geom/verity/g_verity_verify.h>
static unsigned char trusted[G_VERITY_ROOT_BYTES];
static int manifest_result=VE_VERIFIED, change_after_verify;
static int restricted_trust=1;
static int verify_manifest_trust_restricted(void) {return restricted_trust;}
static int verify_file(int fd,const char *path,off_t off,int severity,const char *caller) {
 (void)fd;(void)caller;assert(!strcmp(path,"descriptor") && off==0 && severity==VE_MUST);
 return manifest_result;
}
static int verify_buf(int fd,const char *path,const void *buf,size_t size) {
 assert(!strcmp(path,"descriptor") && size==sizeof(trusted));
 int result=memcmp(buf,trusted,size)==0 ? VE_VERIFIED : -3;
 if(change_after_verify) {
  unsigned char changed=trusted[0]^1;assert(pwrite(fd,&changed,1,0)==1);
 }
 return result;
}
"""
MAIN=r"""
static int disk_open(struct disk_devdesc *d,uint64_t b,u_int s) {
 (void)d;(void)b;(void)s;return ENOSYS;
}
int main(int argc,char **argv) {
 assert(argc==3);
 int fd=open(argv[1],O_RDONLY),desc=open(argv[2],O_RDWR);
 assert(fd>=0 && desc>=0 && read(desc,trusted,sizeof(trusted))==sizeof(trusted));
 unsigned char output[G_VERITY_ROOT_BYTES],expected_digest[32];int unit=-99;
 SHA256_CTX ctx;SHA256_Init(&ctx);SHA256_Update(&ctx,trusted,sizeof(trusted));
 SHA256_Final(expected_digest,&ctx);
 for(int scenario=0;scenario<8;scenario++) {
  memset(output,0xa7,sizeof(output));
  restricted_trust=scenario!=5;
  manifest_result=scenario==0 ? 0 : scenario==1 ? 2 : VE_VERIFIED;
  unsigned char bad=trusted[0]^1;
  if(scenario==2) assert(pwrite(desc,&bad,1,0)==1);
  if(scenario==3) {
   trusted[0]^=1;assert(pwrite(desc,trusted,1,0)==1);
   SHA256_Init(&ctx);SHA256_Update(&ctx,trusted,sizeof(trusted));SHA256_Final(expected_digest,&ctx);
  }
  if(scenario==6)expected_digest[0]^=1;
  int result=verity_dev_attach_verified(fd,desc,"descriptor",
      scenario==7 ? NULL : expected_digest,8,
      scenario==4 ? 1 : 1024*1024,&unit,output);
  if(scenario==6){assert(result==EAUTH);expected_digest[0]^=1;}
  assert(result!=0 && unit==-99 && LIST_EMPTY(&verity_devices));
  for(unsigned i=0;i<sizeof(output);i++) assert(output[i]==0xa7);
  assert(fcntl(fd,F_GETFD)>=0 && fcntl(desc,F_GETFD)>=0);
  if(scenario==3) {
   trusted[0]^=1;
   SHA256_Init(&ctx);SHA256_Update(&ctx,trusted,sizeof(trusted));SHA256_Final(expected_digest,&ctx);
  }
  assert(pwrite(desc,trusted,sizeof(trusted),0)==sizeof(trusted));
 }
 /* Later backing changes cannot replace the authenticated handoff bytes. */
 restricted_trust=1;manifest_result=VE_VERIFIED;change_after_verify=1;
 assert(verity_dev_attach_verified(fd,desc,"descriptor",expected_digest,8,1024*1024,&unit,output)==0);
 assert(!memcmp(output,trusted,sizeof(output)));
 assert(fcntl(desc,F_GETFD)>=0);
 unsigned char changed;assert(pread(desc,&changed,1,0)==1 && changed!=trusted[0]);
 assert(verity_dev_detach(unit)==0 && fcntl(fd,F_GETFD)==-1);
 close(desc);return 0;
}
"""
class Attach(unittest.TestCase):
    def test_authenticated_attachment_failure_and_handoff(self):
        sources=[]
        for name in ['stand/libsa/verity_read.c','stand/common/veritydev.c',
                     'stand/common/verified_root.c','stand/common/verity_attach.c']:
            source=(ROOT/name).read_text().replace('#include <stand.h>','')
            source=source.replace('#include <disk.h>','').replace('#include <verify_file.h>','')
            sources.append(source)
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory);(folder/'system.ufs').write_bytes(bytes(8192))
            device.artifacts.build(folder,dict(format=1,block_size=4096,salt_hex=''),
                device.artifacts.digest(folder/'system.ufs'),8192)
            c=folder/'test.c';binary=folder/'test';c.write_text(PRE+''.join(sources)+MAIN)
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'sys'),
                '-I'+str(ROOT/'stand/libsa'),'-I'+str(ROOT/'stand/common'),str(c),
                str(ROOT/'sys/geom/verity/g_verity_verify.c'),'-lmd','-o',str(binary)],check=True)
            subprocess.run([str(binary),str(folder/'system.verity'),str(folder/'root.descriptor')],
                check=True,timeout=10)
if __name__=='__main__':unittest.main()
