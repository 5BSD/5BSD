# SPDX-License-Identifier: BSD-2-Clause
"""Native alternate-root semantics and guarded-buffer checks; no pool needed."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]

class Altroot(unittest.TestCase):
    def test_prefix_and_short_buffers(self):
        s=(ROOT/'lib/libbe/be_access.c').read_text();start=s.index('char *\nbe_mountpoint_augmented(')
        helper=s[start:s.index('\n}\n',start)+3]
        s=(ROOT/'lib/libbe/be.c').read_text();start=s.index('\tif (zpool_get_prop(lbh->active_phandle, ZPOOL_PROP_ALTROOT,')
        initialization=s[start:s.index('\n\n',start)]
        before=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define ZPOOL_PROP_ALTROOT 1
typedef struct { char altroot[1024]; size_t altroot_len; void *active_phandle; } libbe_handle_t;
static const char *configured;
static int prop_error;
static int zpool_get_prop(void *h,int prop,char *out,size_t n,void *src,bool literal) {
 (void)h; (void)src; assert(prop==ZPOOL_PROP_ALTROOT && literal);
 if(prop_error) return 1;
 snprintf(out,n,"%s",configured); return 0;
}
'''
        after=r'''
static void check(libbe_handle_t *h,const char *input,const char *want) {
 char buffer[128]; snprintf(buffer,sizeof(buffer),"%s",input);
 assert(!strcmp(be_mountpoint_augmented(h,buffer),want));
}
int main(void) {
 libbe_handle_t h={0}; configured="/build/root"; init(&h);
 assert(h.altroot_len==strlen(configured));
 check(&h,"/build/root","/"); check(&h,"/build/root/var","/var");
 check(&h,"/build/root/","/"); check(&h,"/build/rooted/var","/build/rooted/var");
 check(&h,"/other/root/var","/other/root/var"); check(&h,"/","/");
 check(&h,"none","none"); check(&h,"legacy","legacy"); check(&h,"","");
 assert(be_mountpoint_augmented(&h,NULL)==NULL);
 long page=sysconf(_SC_PAGESIZE);
 char *memory=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(memory!=MAP_FAILED); assert(mprotect(memory+page,page,PROT_NONE)==0);
 char *short_value=memory+page-5; memcpy(short_value,"none",5);
 assert(be_mountpoint_augmented(&h,short_value)==short_value);
 assert(!strcmp(short_value,"none")); assert(munmap(memory,page*2)==0);
 const char *neutral[]={"/","-"};
 for(unsigned i=0;i<2;i++) {
  memset(&h,0,sizeof(h)); configured=neutral[i]; init(&h);
  assert(h.altroot_len==0); check(&h,"/var","/var"); check(&h,"/","/");
 }
 memset(&h,0,sizeof(h)); prop_error=1; init(&h);
 assert(h.altroot_len==0); check(&h,"/var","/var");
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'probe.c').write_text(before+helper+'\nstatic void init(libbe_handle_t *lbh) {\n'+initialization+'\n}\n'+after)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(p/'probe.c'),'-o',str(p/'probe')],check=True)
            subprocess.run([str(p/'probe')],check=True)

if __name__=='__main__': unittest.main()
