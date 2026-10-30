# SPDX-License-Identifier: BSD-2-Clause
"""Actual mounted-root check and verifier validation; injected GEOM/mount objects."""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r"""
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <geom/verity/g_verity_verify.h>
#define MNT_ROOTFS 1
#define MNT_RDONLY 2
struct g_provider {int unused;};
struct g_consumer {struct g_provider *provider;int acr,acw;};
struct ufsmount {struct g_consumer *um_cp;};
struct vfsconf {const char *vfc_name;};
struct mount {struct vfsconf *mnt_vfc;unsigned mnt_flag;void *mnt_data;};
#define VFSTOUFS(mp) ((struct ufsmount *)(mp)->mnt_data)
static int locked,queries,provider_error;
static struct g_provider provider;
static struct g_verity_root actual;
static void g_topology_lock(void) {assert(!locked);locked=1;}
static void g_topology_unlock(void) {assert(locked);locked=0;}
static int g_verity_provider_root(struct g_provider *pp,struct g_verity_root *out) {
 assert(locked);queries++;
 if(pp!=&provider)return EINVAL;
 if(provider_error)return provider_error;
 *out=actual;return 0;
}
"""
MAIN=r"""
int main(void) {
 struct g_verity_root expected={.filesystem=1,.salt_len=2,.salt={1,2}};
 assert(g_verity_layout(8192,4096,&expected.layout)==0);
 struct vfsconf vfc={"ufs"};struct g_consumer cp={&provider,1,0};
 struct ufsmount ump={&cp};struct mount mp={&vfc,MNT_ROOTFS|MNT_RDONLY,&ump};
 actual=expected;
 assert(g_verity_check_ufs_root(&mp,&expected)==0 && !locked && queries==1);
 assert(g_verity_check_ufs_root(NULL,&expected)==EINVAL);
 assert(g_verity_check_ufs_root(&mp,NULL)==EINVAL);
 for(int field=0;field<8;field++) {
  actual=expected;
  switch(field) {
   case 0:actual.filesystem++;break;
   case 1:actual.layout.data_bytes++;break;
   case 2:actual.layout.tree_bytes++;break;
   case 3:actual.layout.block_size++;break;
   case 4:actual.layout.levels++;break;
   case 5:actual.layout.offsets[0]++;break;
   case 6:actual.salt[0]^=1;break;
   case 7:actual.root_hash[0]^=1;break;
  }
  assert(g_verity_check_ufs_root(&mp,&expected)==EAUTH && !locked);
 }
 actual=expected;actual.salt_len++;
 assert(g_verity_check_ufs_root(&mp,&expected)==EAUTH && !locked);actual=expected;
 int before=queries;
 mp.mnt_flag=MNT_ROOTFS;assert(g_verity_check_ufs_root(&mp,&expected)==EAUTH);
 mp.mnt_flag=MNT_RDONLY;assert(g_verity_check_ufs_root(&mp,&expected)==EAUTH);
 mp.mnt_flag=MNT_ROOTFS|MNT_RDONLY;
 vfc.vfc_name="zfs";assert(g_verity_check_ufs_root(&mp,&expected)==EAUTH);vfc.vfc_name="ufs";
 mp.mnt_vfc=NULL;assert(g_verity_check_ufs_root(&mp,&expected)==EAUTH);mp.mnt_vfc=&vfc;
 mp.mnt_data=NULL;assert(g_verity_check_ufs_root(&mp,&expected)==ENXIO);mp.mnt_data=&ump;
 ump.um_cp=NULL;assert(g_verity_check_ufs_root(&mp,&expected)==ENXIO);ump.um_cp=&cp;
 cp.acr=0;assert(g_verity_check_ufs_root(&mp,&expected)==ENXIO);cp.acr=1;
 cp.acw=1;assert(g_verity_check_ufs_root(&mp,&expected)==ENXIO);cp.acw=0;
 cp.provider=NULL;assert(g_verity_check_ufs_root(&mp,&expected)==ENXIO);cp.provider=&provider;
 expected.salt_len=257;assert(g_verity_check_ufs_root(&mp,&expected)==EINVAL);expected.salt_len=2;
 assert(queries==before && !locked);
 struct g_provider other;
 cp.provider=&other;assert(g_verity_check_ufs_root(&mp,&expected)==EINVAL && !locked);
 cp.provider=&provider;provider_error=ENXIO;
 assert(g_verity_check_ufs_root(&mp,&expected)==ENXIO && !locked);
 provider_error=0;assert(g_verity_check_ufs_root(&mp,&expected)==0 && !locked);
 return 0;
}
"""
class MountIdentity(unittest.TestCase):
    def test_provider_identity_and_complete_root_match(self):
        source=(ROOT/'sys/geom/verity/g_verity_mount.c').read_text()
        source=source[source.index('int\ng_verity_check_ufs_root('):]
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/'test.c';binary=Path(directory)/'test';c.write_text(PRE+source+MAIN)
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'sys'),str(c),
                str(ROOT/'sys/geom/verity/g_verity_verify.c'),'-lmd','-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,timeout=10)
if __name__=='__main__':unittest.main()
