# SPDX-License-Identifier: BSD-2-Clause
"""Clone path boundary checks against the actual libbe helper."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]

class ClonePath(unittest.TestCase):
    def test_boundaries_and_lengths(self):
        source=(ROOT/'lib/libbe/be.c').read_text()
        start=source.index('static int\nbe_get_path(')
        function=source[start:source.index('\n}\n',start)+3]
        before=r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define BE_ERR_SUCCESS 0
#define BE_ERR_BADPATH 1
#define BE_ERR_PATHLEN 2
typedef struct { const char *root; } libbe_handle_t;
struct libbe_deep_clone { libbe_handle_t *lbh; const char *bename; };
'''
        after=r'''
int main(void) {
 libbe_handle_t h={.root="pool/ROOT"};
 struct libbe_deep_clone d={.lbh=&h,.bename="new"};
 char output[128];
 const char *invalid[]={"else/ROOT/old","xpool/ROOT/old","other/pool/ROOT/old",
  "pool/ROOT2/old","pool/ROOT","pool/ROOT/","pool",""};
 for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++)
  assert(be_get_path(&d,invalid[i],output,sizeof(output))==BE_ERR_BADPATH);
 assert(be_get_path(&d,"pool/ROOT/old",output,sizeof(output))==0);
 assert(!strcmp(output,"pool/ROOT/new"));
 assert(be_get_path(&d,"pool/ROOT/old/child/grandchild",output,sizeof(output))==0);
 assert(!strcmp(output,"pool/ROOT/new/child/grandchild"));
 const char *want="pool/ROOT/new/child";
 int length=(int)strlen(want);
 memset(output,'X',sizeof(output));
 assert(be_get_path(&d,"pool/ROOT/old/child",output,length+1)==0);
 assert(!strcmp(output,want) && output[length+1]=='X');
 memset(output,'X',sizeof(output));
 assert(be_get_path(&d,"pool/ROOT/old/child",output,length)==BE_ERR_PATHLEN);
 assert(output[length]=='X');
 assert(be_get_path(&d,"pool/ROOT/old",output,1)==BE_ERR_PATHLEN);
 assert(output[0]=='\0');
 output[0]='X';
 assert(be_get_path(&d,"pool/ROOT/old",output,0)==BE_ERR_PATHLEN);
 assert(output[0]=='X');
 assert(be_get_path(&d,"pool/ROOT/old",output,-1)==BE_ERR_PATHLEN);
 assert(output[0]=='X');
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'probe.c').write_text(before+function+after)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(root/'probe.c'),'-o',str(root/'probe')],check=True)
            subprocess.run([str(root/'probe')],check=True)

if __name__=='__main__': unittest.main()
