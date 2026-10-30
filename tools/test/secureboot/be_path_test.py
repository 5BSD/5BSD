# SPDX-License-Identifier: BSD-2-Clause
"""Actual libbe path boundary validation; no ZFS operations."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[3]

class Paths(unittest.TestCase):
    def test_root_boundary_and_failure_output(self):
        source = (ROOT/'lib/libbe/be.c').read_text()
        start = source.index('int\nbe_root_concat(')
        function = source[start:source.index('\n}\n', start)+3]
        program = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define BE_MAXPATHLEN 256
#define BE_ERR_INVALIDNAME 1
#define BE_ERR_PATHLEN 2
#define BE_ERR_SUCCESS 0
typedef struct {const char *root;} libbe_handle_t;
'''+function+r'''
int main(void) {
 libbe_handle_t h={"pool/ROOT"};char out[BE_MAXPATHLEN];
 const char *bad[]={"", "pool/ROOT", "pool/ROOT/", "pool/ROOT-other/base",
  "pool/ROOT2/base", "other/ROOT/base", "pool/R"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
  strcpy(out,"unchanged");assert(be_root_concat(&h,bad[i],out)==BE_ERR_INVALIDNAME);
  assert(!strcmp(out,"unchanged"));
 }
 const char *good[]={"base","base@snap","pool/ROOT/base","pool/ROOT/base@snap",
  "pool/ROOT/base/child"};
 for(unsigned i=0;i<sizeof(good)/sizeof(good[0]);i++) {
  assert(be_root_concat(&h,good[i],out)==0);
  assert(!strncmp(out,"pool/ROOT/",10));
  if(i<2)assert(!strcmp(out+10,good[i]));else assert(!strcmp(out,good[i]));
 }
 char large[BE_MAXPATHLEN+32];memset(large,'a',sizeof(large));large[sizeof(large)-1]=0;
 strcpy(out,"unchanged");assert(be_root_concat(&h,large,out)==BE_ERR_PATHLEN);
 assert(!strcmp(out,"unchanged"));
 memcpy(large,"pool/ROOT/",10);
 assert(be_root_concat(&h,large,out)==BE_ERR_PATHLEN && !strcmp(out,"unchanged"));
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            c=Path(d)/'test.c';binary=Path(d)/'test';c.write_text(program)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,timeout=10)

if __name__ == '__main__': unittest.main()
