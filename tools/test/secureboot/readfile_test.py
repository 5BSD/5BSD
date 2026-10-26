# SPDX-License-Identifier: BSD-2-Clause
"""Exercise production secureboot reads with deterministic I/O failure seams."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[3]
class Reads(unittest.TestCase):
    def test_reads(self):
        source=(ROOT/'lib/libsecureboot/readfile.c').read_text()
        source=source[source.index('unsigned char *\nread_fd('):]
        harness=r'''
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
static int scenario, calls, allocations, closes;
static void *alloc(size_t n) { allocations++; assert(n>0 && n<100); return malloc(n); }
static ssize_t rd(int fd, void *p, size_t n) {
 (void)fd; calls++;
 if(calls>5) { errno=EIO; return -1; }
 if(scenario==1 && calls>=2) return 0;
 if(scenario==2 && calls==1) { errno=EINTR; return -1; }
 if(scenario==3) { errno=EIO; return -1; }
 size_t count=n>2 ? 2 : n; memset(p,'x',count); return count;
}
static int op(const char *p,int f) { (void)p; (void)f; return 4; }
static int test_stat(int fd,struct stat *s) {
 (void)fd; memset(s,0,sizeof(*s));
 if(scenario==4) { errno=EIO; return -1; }
 s->st_mode=scenario==5 ? S_IFDIR : S_IFREG;
 s->st_size=scenario==6 ? -1 : 4; return 0;
}
static int cl(int fd) { (void)fd; closes++; return 0; }
#define malloc alloc
#define read rd
#define open op
#define fstat test_stat
#define close cl
'''
        cases=r'''
int main(void) {
 for(scenario=0;scenario<4;scenario++) {
  calls=allocations=0; unsigned char *p=read_fd(4,4);
  if(scenario==1 || scenario==3) assert(p==NULL);
  else { assert(p && !memcmp(p,"xxxx",5)); free(p); }
  assert(calls==(scenario==2 ? 3 : scenario==3 ? 1 : 2));
 }
 allocations=calls=0;
 assert(read_fd(4,SIZE_MAX)==NULL && allocations==0 && calls==0);
 unsigned char *empty=read_fd(4,0); assert(empty && !*empty && calls==0); free(empty);
 for(scenario=4;scenario<=6;scenario++) {
  calls=allocations=closes=0; size_t length=99;
  assert(read_file("input",&length)==NULL);
  assert(length==0 && allocations==0 && calls==0 && closes==1);
 }
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            c=Path(tmp)/'test.c'; c.write_text(harness+source+cases)
            binary=Path(tmp)/'test'
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,timeout=5,cwd=tmp)
    def test_real_regular_and_fifo_inputs(self):
        source=(ROOT/'lib/libsecureboot/readfile.c').read_text()
        source=source[source.index('unsigned char *\nread_fd('):]
        headers = '#include <sys/types.h>\n#include <sys/stat.h>\n#include <stdint.h>\n#include <limits.h>\n#include <stdlib.h>\n#include <stdio.h>\n#include <string.h>\n#include <fcntl.h>\n#include <unistd.h>\n#include <errno.h>\n#include <assert.h>\n'
        main = r'''
int main(void) {
 size_t length=99;
 unsigned char *data=read_file("regular", &length);
 assert(data && length==4 && !memcmp(data,"data",5)); free(data);
 int fd=open("regular",O_RDONLY); assert(fd>=0);
 assert(read_fd(fd,5)==NULL); close(fd);
 assert(read_file("fifo", &length)==NULL && length==0);
 assert(read_file(".", &length)==NULL && length==0);
 assert(read_file("missing", &length)==NULL && length==0);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'regular').write_bytes(b'data')
            import os
            os.mkfifo(root/'fifo', 0o600)
            c=root/'test.c'; c.write_text(headers+source+main)
            binary=root/'test'
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,timeout=5,cwd=tmp)

if __name__=='__main__': unittest.main()
