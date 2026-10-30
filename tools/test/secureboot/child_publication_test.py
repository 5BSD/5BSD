# SPDX-License-Identifier: BSD-2-Clause
"""Actual publication/rollback helper with fault seams; no live ZFS operations."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]

class Publication(unittest.TestCase):
    def test_failure_cleanup_and_original_error(self):
        source = (ROOT / 'sys/contrib/openzfs/module/os/freebsd/zfs/zfs_handle.c').read_text()
        start = source.index('static int\nzfshandle_publish_child(')
        end = source.index('\n}\n', start) + 3
        function = source[start:end]
        harness = r"""
#include <sys/types.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
struct thread { int unused; };
typedef struct { int unused; } zfshandle_t;
#define ZFS_IOC_DESTROY 99
#define CE_WARN 1
static int mint_error, cleanup_error, minted, destroyed, warnings;
static char diagnostic[512];
static int zfshandle_mint_child(struct thread *td, zfshandle_t *zh,
 const char *full, uint64_t rights, uint32_t flags, u_long command, int32_t *fd) {
 assert(td && zh && rights == 17 && flags == 3 && command == 7);
 assert(strcmp(full,"pool/ordinary/child")==0); minted++;
 if (!mint_error) *fd=42;
 return mint_error;
}
static int zfshandle_ioc(uint64_t command, const char *full, const char *value,
 uint64_t cookie, void *input, void *output) {
 assert(command==ZFS_IOC_DESTROY && !value && !cookie && !input && !output);
 assert(strcmp(full,"pool/ordinary/child")==0); destroyed++; return cleanup_error;
}
static void cmn_err(int level, const char *format, ...) {
 assert(level==CE_WARN); warnings++; va_list ap; va_start(ap,format);
 vsnprintf(diagnostic,sizeof(diagnostic),format,ap); va_end(ap);
}
"""
        cases = r"""
int main(void) {
 struct thread td; zfshandle_t zh; int32_t fd=-1;
 assert(zfshandle_publish_child(&td,&zh,"pool/ordinary/child",17,3,7,&fd)==0);
 assert(fd==42 && minted==1 && destroyed==0 && warnings==0);
 mint_error=EMFILE; fd=-1;
 assert(zfshandle_publish_child(&td,&zh,"pool/ordinary/child",17,3,7,&fd)==EMFILE);
 assert(fd==-1 && minted==2 && destroyed==1 && warnings==0);
 cleanup_error=EBUSY;
 assert(zfshandle_publish_child(&td,&zh,"pool/ordinary/child",17,3,7,&fd)==EMFILE);
 assert(fd==-1 && minted==3 && destroyed==2 && warnings==1);
 assert(strstr(diagnostic,"pool/ordinary/child") && strstr(diagnostic,"dataset may remain"));
 mint_error=EPERM; cleanup_error=EIO;
 assert(zfshandle_publish_child(&td,&zh,"pool/ordinary/child",17,3,7,&fd)==EPERM);
 assert(fd==-1 && minted==4 && destroyed==3 && warnings==2);
 char expected[64]; snprintf(expected,sizeof(expected),"publication failed (%d)",EPERM);
 assert(strstr(diagnostic,expected));
 snprintf(expected,sizeof(expected),"cleanup failed (%d)",EIO);
 assert(strstr(diagnostic,expected));
 return 0;
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            c = base / 'test.c'; c.write_text(harness + function + cases)
            binary = base / 'test'
            subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', str(c), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, cwd=base)

if __name__ == '__main__':
    unittest.main()
