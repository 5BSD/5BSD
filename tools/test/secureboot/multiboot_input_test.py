# SPDX-License-Identifier: BSD-2-Clause
"""Actual amd64 EFI Multiboot2 load function with bounded native input seams."""
import argparse
from pathlib import Path
import subprocess,tempfile
ROOT=Path(__file__).resolve().parents[3]
PRE=r'''
#include <sys/types.h>
#include <sys/param.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "multiboot2.h"
#define MODINFOMD_NOCOPY 1
#define MODINFOMD_MB2HDR 2
struct preloaded_file {size_t f_size;};
struct mb2hdr {uint32_t efi64_entry;};
static unsigned char bytes[MULTIBOOT_SEARCH+8];
static size_t length=48,position;
static int scenario,allocated,allocations,closed,loaded,metadata,reads;
static struct preloaded_file file;
static int test_open(const char *p,int f){(void)p;assert(f==O_RDONLY);return 7;}
static int test_close(int fd){assert(fd==7);closed++;return 0;}
static ssize_t test_read(int fd,void *out,size_t count) {
 assert(fd==7);reads++;
 if(scenario==10){errno=EAUTH;return -1;}
 size_t n=MIN(count,length-position);memcpy(out,bytes+position,n);position+=n;return n;
}
static void *test_malloc(size_t n){assert(n<=MULTIBOOT_SEARCH);if(scenario==11)return NULL;allocated++;allocations++;return malloc(n);}
static void test_free(void *p){if(p){allocated--;free(p);}}
static int verity_check_source(int fd){assert(fd==7);return scenario==19 ? EAUTH : 0;}
static int elf32_loadfile_raw(char *n,uint64_t d,struct preloaded_file **r,int m) {
 (void)n;(void)d;assert(m==1);loaded++;file.f_size=10;*r=&file;return 0;
}
static void file_addmetadata(struct preloaded_file *f,int type,size_t n,void *p) {
 assert(f==&file && type==3 && n==sizeof(struct mb2hdr));
 assert(((struct mb2hdr *)p)->efi64_entry==0x1000);metadata++;
}
#define open test_open
#define close test_close
#define read test_read
#define malloc test_malloc
#define free test_free
'''
MAIN=r'''
int main(int argc,char **argv) {
 assert(argc==2);scenario=atoi(argv[1]);
 struct multiboot_header *h=(void *)bytes;
 struct multiboot_header_tag *bs=(void *)(bytes+16),*end=(void *)(bytes+40);
 struct multiboot_header_tag_entry_address *entry=(void *)(bytes+24);
 h->magic=MULTIBOOT2_HEADER_MAGIC;h->architecture=MULTIBOOT2_ARCHITECTURE_I386;
 h->header_length=48;
 bs->type=MULTIBOOT_HEADER_TAG_EFI_BS;bs->size=8;
 entry->type=MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS_EFI64;entry->size=12;entry->entry_addr=0x1000;
 end->type=MULTIBOOT_HEADER_TAG_END;end->size=8;
 switch(scenario) {
 case 1:h->header_length=length=40;break; /* no terminating tag */
 case 2:bs->size=0;break;
 case 3:bs->size=4;break;
 case 4:h->header_length=15;break;
 case 5:h->header_length=UINT32_MAX;break;
 case 6:length=10;break;
 case 7:length=47;break;
 case 8:entry->size=8;break;
 case 9:bs->type=MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST;bs->size=9;break;
 case 12:h->architecture=99;break;
 case 13:bs->type=99;break;
 case 14:
  end->type=99;end->flags=MULTIBOOT_HEADER_TAG_OPTIONAL;
  end=(void *)(bytes+48);end->type=MULTIBOOT_HEADER_TAG_END;end->size=8;
  h->header_length=length=56;break;
 case 15:
  h->magic=0;memcpy(bytes+56,&(uint32_t){MULTIBOOT2_HEADER_MAGIC},4);length=64;break;
 case 16:entry->size=UINT32_MAX;break;
 case 17:entry->entry_addr=0;break;
 case 18:end->size=16;h->header_length=length=56;break;
 case 20:case 21:
  memmove(bytes+MULTIBOOT_SEARCH-48,bytes,48);memset(bytes,0,48);
  h=(void *)(bytes+MULTIBOOT_SEARCH-48);length=MULTIBOOT_SEARCH;
  if(scenario==21)h->header_length=56;
  break;
 }
 h->checksum=0-h->magic-h->architecture-h->header_length;
 struct preloaded_file *result=NULL;int error=loadfile("payload",0,&result);
 int positive=scenario==0 || scenario==14 || scenario==20;
 assert((error==0)==positive && loaded==positive && metadata==positive);
 assert(closed==1 && allocated==0);
 if(scenario==10 || scenario==19)assert(error==EAUTH);
 if(scenario==11)assert(error==ENOMEM);
 if(scenario==19)assert(reads==0);
 if(positive)assert(file.f_size==PAGE_SIZE && reads==1 && allocations==1);
 return 0;
}
'''
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case',type=int)
    args=parser.parse_args()
    source=(ROOT/'stand/efi/loader/arch/amd64/multiboot2.c').read_text()
    start=source.index('static int\nloadfile(');function=source[start:source.index('\n}\n',start)+3]
    with tempfile.TemporaryDirectory() as d:
        p=Path(d);c=p/'test.c';binary=p/'test';c.write_text(PRE+function+MAIN)
        subprocess.run(['cc','-Wall','-Wextra','-Werror','-Wno-sign-compare',
            '-DLOADER_VERITY_SUPPORT','-I'+str(ROOT/'stand/efi/loader/arch/amd64'),
            str(c),'-o',str(binary)],check=True)
        for case in ([args.case] if args.case is not None else range(22)):
            subprocess.run([str(binary),str(case)],check=True,cwd=p,timeout=3)
    print('PASS: Multiboot2 complete load-function input bounds and admission cases')
if __name__=='__main__':main()
