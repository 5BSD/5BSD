# SPDX-License-Identifier: BSD-2-Clause
"""Actual receive revalidation with storage/I/O seams; no ZFS or VM execution."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class ReceiveRevalidation(unittest.TestCase):
    def test_identity_and_lock_restoration(self):
        source = (ROOT / 'sys/contrib/openzfs/module/os/freebsd/zfs/zfs_handle.c').read_text()
        structures = source[source.index('struct zfshandle_recv_id {'):source.index('static int\nzfshandle_recv_identity(')]
        functions = source[source.index('static boolean_t\nzfshandle_recv_same('):source.index('static int\nzfshandle_op_recv(')]
        harness = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
typedef int boolean_t;
#define B_TRUE 1
#define ZFS_MAX_DATASET_NAME_LEN 256
#define SET_ERROR(e) (e)
#define SA_XLOCKED 1
static int zfshandle_namespace_sx=1;
static void sx_assert(int *p,int v) {assert(*p==v);}
static void sx_xunlock(int *p) {assert(*p==1);*p=0;}
static void sx_xlock(int *p) {assert(*p==0);*p=1;}
typedef struct {uint64_t zh_pool_guid;} zfshandle_t;
typedef struct {uint64_t ds_object,ds_guid;} dataset;
#define dsl_dataset_phys(ds) (ds)
typedef struct {int drc_newfs;dataset *drc_ds;int drc_fp;} dmu_recv_cookie_t;
'''
        seams = r'''
static int mutation,read_error,identity_error,root_error;
static struct zfshandle_recv_id parent={2,20},target={3,30};
static int zfshandle_resolve_name(zfshandle_t *root,char *out,size_t size) {
 assert(zfshandle_namespace_sx==1 && root->zh_pool_guid==7);
 assert(size>8);strcpy(out,mutation==1?"moved":"root");return root_error;
}
static int zfshandle_recv_identity(uint64_t pool,const char *name,
 struct zfshandle_recv_id *out) {
 assert(zfshandle_namespace_sx==1 && pool==7);
 if(strcmp(name,"parent")==0) {*out=parent;return 0;}
 assert(strcmp(name,"target")==0);*out=target;return identity_error;
}
static int zfs_file_read(int fd,void *buffer,size_t length,ssize_t *resid) {
 assert(zfshandle_namespace_sx==0 && fd==9 && length==1);
 (void)buffer;*resid=read_error?1:0;
 if(mutation==2) parent.guid++;
 if(mutation==3) target.guid++;
 if(mutation==4) target.object++;
 return read_error;
}
'''
        cases = r'''
int main(void) {
 zfshandle_t root={7}; dataset owned={3,30};
 struct zfshandle_recv_context ctx={.root=&root,.rootname="root",
  .parent="parent",.target="target",.parent_id={2,20},.target_id={3,30},.target_exists=1};
 dmu_recv_cookie_t drc={.drc_fp=9};char buffer;ssize_t resid;
 /* Identity mutations occur during the unlocked input call. */
 for(int m=0;m<5;m++) for(int e=0;e<2;e++) {
  parent=(struct zfshandle_recv_id){2,20};target=(struct zfshandle_recv_id){3,30};
  mutation=m;read_error=e?EINTR:0;
  int result=zfshandle_recv_read(&drc,&buffer,1,&resid,&ctx);
  assert(result==(m?ESTALE:read_error));assert(zfshandle_namespace_sx==1);
 }
 mutation=0;read_error=0;parent=(struct zfshandle_recv_id){2,20};
 target=(struct zfshandle_recv_id){3,30};
 root_error=ENOENT;assert(zfshandle_recv_read(&drc,&buffer,1,&resid,&ctx)==ESTALE);
 root_error=0;
 ctx.target_exists=0;identity_error=ENOENT;
 assert(zfshandle_recv_read(&drc,&buffer,1,&resid,&ctx)==0);
 identity_error=EIO;assert(zfshandle_recv_read(&drc,&buffer,1,&resid,&ctx)==ESTALE);
 identity_error=0;assert(zfshandle_recv_read(&drc,&buffer,1,&resid,&ctx)==ESTALE);
 drc.drc_newfs=1;drc.drc_ds=&owned;
 assert(zfshandle_recv_read(&drc,&buffer,1,&resid,&ctx)==0);
 target.guid++;assert(zfshandle_recv_read(&drc,&buffer,1,&resid,&ctx)==ESTALE);
 assert(zfshandle_namespace_sx==1);return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='bip-receive-') as directory:
            src = Path(directory) / 'test.c'
            binary = Path(directory) / 'test'
            src.write_text(harness + structures + seams + functions + cases)
            for command in (['cc', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(binary)], [str(binary)]):
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
