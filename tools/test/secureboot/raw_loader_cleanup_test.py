# SPDX-License-Identifier: BSD-2-Clause
"""Exercise actual raw-loader cleanup with fault-injected verification and I/O.

The verifier stub implements vectx_close's ownership contract. This tests loader
resource lifetime, not signature validation, firmware or authenticated boot.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]

PREAMBLE = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#define LOADER_VERIEXEC_VECTX 1
#define G_VERITY_ROOT_TYPE "bip_root_descriptor"
#define VE_MUST 2
#define MODULE_VERBOSE_SILENT 0
#define TSENTER2(x) ((void)0)
#define TSEXIT() ((void)0)
#define DEBUG_PRINTF(level,args) ((void)0)
#define VECTX_HANDLE(fd) vctx
typedef uintptr_t vm_offset_t;
struct vectx { int unused; };
struct preloaded_file {
 char *f_name, *f_type, *f_args; void *f_metadata;
 int f_loader; vm_offset_t f_addr; size_t f_size;
};
static struct vectx context;
static struct preloaded_file file;
static char *command_errmsg, command_errbuf[1024];
static vm_offset_t loadaddr;
static int module_verbose, mode, frees, closes, inserted, reads, sequential;
static void checked_free(void *p) {
 if (p == &context) { assert(++frees == 1); return; }
 free(p);
}
#define free checked_free
static struct preloaded_file *file_findfile(const char *a,const char *b) {
 (void)a; (void)b; return &file;
}
static char *file_search(const char *p,void *unused) {
 (void)unused; return strdup(p);
}
static int fake_open(const char *p,int flags) { (void)p;(void)flags;return 7; }
static int fake_close(int fd) { assert(fd == 7);closes++;return 0; }
#define open fake_open
#define close fake_close
static int severity_guess(const char *p) { (void)p;return 0; }
static const char *ve_error_get(void) { return "injected failure"; }
static struct vectx *vectx_open(int fd,const char *p,int severity,
 off_t off,void *st,int *error,const char *caller) {
 (void)fd;(void)p;(void)off;(void)st;(void)caller;
 assert(severity == VE_MUST);
 *error = mode == 1 ? -1 : 0; return &context;
}
static int vectx_set_sequential(struct vectx *ctx) {
 assert(ctx==&context);assert(++sequential==1);return mode==5 ? EINVAL : 0;
}
static void vectx_discard(struct vectx *ctx) {free(ctx);}
static int vectx_close(struct vectx *ctx,const char *caller) {
 (void)caller;free(ctx);return mode == 3 ? -1 : 0;
}
static int readin(struct vectx *ctx,vm_offset_t addr,size_t n) {
 (void)addr;(void)n;assert(ctx == &context && sequential==1);
 if (mode == 2) { errno = EIO;return -1; }
 return reads++ == 0 ? 384 : 0;
}
static struct { int (*arch_readin)(struct vectx *,vm_offset_t,size_t); }
 archsw = { readin };
static ssize_t file_readroot(int fd,const char *name,vm_offset_t dest) {
 (void)fd;(void)name;(void)dest;assert(0);return -1;
}
static vm_offset_t md_align(vm_offset_t addr) { return addr; }
static struct preloaded_file *file_alloc(void) { return mode == 4 ? NULL : &file; }
static void file_insert_tail(struct preloaded_file *p) { assert(p == &file);inserted++; }
'''
MAIN = r'''
int main(void) {
 for (mode = 0;mode <= 5;mode++) {
  frees = closes = inserted = reads = sequential = 0;loadaddr = 8192;
  memset(&file,0,sizeof(file));
  struct preloaded_file *result = file_loadraw("payload", "md_image_ro", 1);
  assert(frees == 1 && closes == 1);
  assert(sequential==(mode!=1));
  if(mode==5)assert(reads==0);
  assert(inserted == (mode == 0));
  if (mode == 0) {
   assert(result == &file && file.f_size == 384 && loadaddr == 8576);
   free(file.f_name);free(file.f_type);
  } else { assert(result == NULL && loadaddr == 8192); }
 }
 return 0;
}
'''

class RawLoaderCleanup(unittest.TestCase):
    def test_verifier_and_io_failures(self):
        source = (ROOT / 'stand/common/module.c').read_text()
        start = source.index('struct preloaded_file *\nfile_loadraw(')
        function = source[start:source.index('\n}\n', start) + 3]
        with tempfile.TemporaryDirectory(prefix='raw-loader-') as directory:
            path = Path(directory)
            cfile, binary = path / 'test.c', path / 'test'
            cfile.write_text(PREAMBLE + function + MAIN)
            subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', str(cfile),
                            '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=10)

if __name__ == '__main__':
    unittest.main()
