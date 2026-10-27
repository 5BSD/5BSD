# SPDX-License-Identifier: BSD-2-Clause
"""Actual EFI configuration reader with injected firmware, I/O and verification."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r"""
#include <assert.h>
#include <sys/stat.h>
#include <stdint.h>
#include <limits.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <unistd.h>
#define VE_MUST 2
#define VE_VERIFIED 1
typedef void *EFI_HANDLE;
typedef int pdinfo_t;
static int scenario,parsed,closed,reads,allocations,checked,panicked;
static pdinfo_t disk;
static unsigned char stored[8];
static void *allocation;
static jmp_buf escape;
static pdinfo_t *efiblk_get_pdinfo_by_handle(EFI_HANDLE h) {(void)h;return &disk;}
static void set_currdev_pdinfo(pdinfo_t *p) {assert(p==&disk);}
static int fake_open(const char *name,int mode) {assert(!strcmp(name,"config") && mode==O_RDONLY);return 7;}
static int fake_stat(int fd,struct stat *st) {
 assert(fd==7);memset(st,0,sizeof(*st));st->st_size=8;st->st_mode=S_IFREG;
 if(scenario==1)return -1;
 if(scenario==2)st->st_mode=S_IFDIR;
 if(scenario==3)st->st_size=-1;
 if(scenario==4)st->st_size=INT64_MAX;
 return 0;
}
static void *fake_malloc(size_t n) {
 allocations++;
 if(scenario==4 || scenario==5)return NULL;
 assert(n==9);allocation=malloc(n);assert(allocation);return allocation;
}
static void fake_free(void *p) {assert(p==allocation);free(p);allocation=NULL;}
static int fake_close(int fd) {assert(fd==7);closed++;return 0;}
static ssize_t fake_read(int fd,void *out,size_t n) {
 assert(fd==7 && n==8);reads++;memcpy(out,stored,n);
 return scenario==6 ? -1 : scenario==7 ? 7 : 8;
}
#ifdef EFI_SECUREBOOT
static int verify_required(void) {return scenario!=10;}
static int verify_file(int fd,const char *path,off_t off,int severity,const char *caller) {
 (void)path;(void)caller;assert(fd==7 && off==0 && severity==VE_MUST);
 if(scenario==8)memset(stored,'x',sizeof(stored));return VE_VERIFIED;
}
static int verify_buf(int fd,const char *path,const void *data,size_t n) {
 (void)path;assert(fd==7 && n==8);checked++;
 int result=memcmp(data,"verified",8)==0 ? VE_VERIFIED : -1;
 if(scenario==9)memset(stored,'x',sizeof(stored));
 return result;
}
static void panic(const char *format,...) __attribute__((noreturn));
static void panic(const char *format,...) {(void)format;panicked++;longjmp(escape,1);}
#endif
static void boot_parse_cmdline(char *env) {assert(!strcmp(env,"verified"));parsed++;}
#define open fake_open
#define fstat fake_stat
#define malloc fake_malloc
#define free fake_free
#define close fake_close
#define read fake_read
"""
MAIN=r"""
int main(void) {
 for(scenario=0;scenario<=10;scenario++) {
  parsed=closed=reads=allocations=checked=panicked=0;
  memcpy(stored,"verified",8);allocation=NULL;
  if(setjmp(escape)==0)parse_loader_efi_config(NULL,"config");
#ifdef EFI_SECUREBOOT
  assert(parsed==(scenario==0 || scenario==9 || scenario==10));
  assert(panicked==(scenario==8));
  assert(checked==(scenario==0 || scenario==8 || scenario==9));
#else
  assert(parsed==(scenario==0 || scenario>=8));
  assert(!panicked && !checked);
#endif
  if(scenario>=1 && scenario<=3)assert(!allocations && !reads);
  assert(closed==!panicked);
  if(panicked)fake_free(allocation);
  assert(allocation==NULL);
 }
 return 0;
}
"""
class EFIConfig(unittest.TestCase):
    def test_retained_config_bytes_and_metadata_failures(self):
        source=(ROOT/'stand/efi/loader/main.c').read_text()
        start=source.index('void\nparse_loader_efi_config(')
        function=source[start:source.index('\n}\n',start)+3]
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/'test.c';binary=Path(directory)/'test'
            c.write_text(PRE+function+MAIN)
            for secure in (False,True):
                subprocess.run(['cc','-Wall','-Wextra','-Werror']+
                    (['-DEFI_SECUREBOOT'] if secure else [])+
                    [str(c),'-o',str(binary)],check=True)
                subprocess.run([str(binary)],check=True,cwd=directory,timeout=10)
if __name__=='__main__':unittest.main()
