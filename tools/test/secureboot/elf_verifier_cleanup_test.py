# SPDX-License-Identifier: BSD-2-Clause
"""Actual ELF finalization blocks with injected verifier ownership operations."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
struct vectx {int alive;};
static int finalizations,discards,files,verification_error;
static int vectx_close(struct vectx *ctx,const char *caller) {
 (void)caller;assert(ctx && ctx->alive);ctx->alive=0;finalizations++;
 return verification_error;
}
static void vectx_discard(struct vectx *ctx) {
 if(ctx){assert(ctx->alive);ctx->alive=0;discards++;}
}
static void file_discard(void *fp){assert(fp);files++;}
'''
MAIN=r'''
int main(void) {
 for(int present=0;present<2;present++) {
  for(int failed_load=0;failed_load<2;failed_load++) {
   for(int failed_verify=0;failed_verify<2;failed_verify++) {
    struct vectx ctx={1};finalizations=discards=files=0;
    verification_error=failed_verify ? EAUTH : 0;
    int err=finish(failed_load ? EIO : 0,present ? &ctx : NULL);
    assert(err==(failed_load ? EIO : present && failed_verify ? EAUTH : 0));
    assert(finalizations==(present && !failed_load));
    assert(discards==(present && failed_load));
    assert(files==(present && !failed_load && failed_verify));
    assert(ctx.alive==!present);
   }
  }
 }
 return 0;
}
'''
class Cleanup(unittest.TestCase):
    def test_all_three_elf_finalizers(self):
        blocks=[]
        for name in ('load_elf.c','load_elf_obj.c'):
            text=(ROOT/'stand/common'/name).read_text()
            candidates=re.findall(r'#ifdef LOADER_VERIEXEC_VECTX\n(.*?)#endif',text,re.S)
            selected=[b for b in candidates if 'if (!err && ef.vctx)' in b]
            self.assertEqual(len(selected),2 if name=='load_elf.c' else 1)
            blocks.extend(selected)
        for index,block in enumerate(blocks):
            with self.subTest(finalizer=index),tempfile.TemporaryDirectory() as directory:
                path=Path(directory);c=path/'probe.c';binary=path/'probe'
                c.write_text(PRE+'\nstatic int finish(int err,struct vectx *context) {\n'
                    'struct {struct vectx *vctx;} ef={context};int object;void *fp=&object;\n'
                    +block+'return err;\n}\n'+MAIN)
                subprocess.run(['cc','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],check=True)
                subprocess.run([str(binary)],check=True,timeout=10)
if __name__=='__main__':unittest.main()
