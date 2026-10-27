# SPDX-License-Identifier: BSD-2-Clause
"""Real preload decoder and root parser with injected metadata enumeration."""
import importlib.util
import hashlib
import struct
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('tree', ROOT/'tools/build/capimage/verity_tree.py')
tree = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tree)

PRE = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <geom/verity/g_verity_verify.h>
#include <geom/verity/g_verity_transition.h>
#include <crypto/sha2/sha256.h>
#define MODINFO_TYPE 2
struct module { const char *type; void *data; size_t length; };
static struct module modules[6];
static unsigned count, enumerated, fetched;
static unsigned live, allocations;
static int limits_error, limits_checked;
static int g_verity_provider_resources(const struct g_verity_root *root,unsigned workers,
 uint64_t cache,uint64_t window,uint64_t budget,size_t *per_worker) {
 assert(root->layout.data_bytes==129*4096 && workers==2 && cache==64);
 assert(window==131072 && budget==1048576);limits_checked++;
 if(limits_error)return limits_error;
 *per_worker=1;return 0;
}

static size_t largest;
static void *allocate(size_t size,int type,int flags) {
 (void)type;(void)flags;void *p=malloc(size);assert(p);
 live++;allocations++;if(size>largest)largest=size;return p;
}
static void release(void *p,int type) {(void)type;assert(p && live);live--;free(p);}
#define M_TEMP 0
#define M_WAITOK 0
#define malloc allocate
#define free release

static caddr_t preload_search_next_name(caddr_t previous) {
 unsigned index=previous?(unsigned)((struct module *)previous-modules)+1:0;
 enumerated++;return index<count?(caddr_t)&modules[index]:NULL;
}
static caddr_t preload_search_info(caddr_t module,int type) {
 assert(type==MODINFO_TYPE);return (caddr_t)((struct module *)module)->type;
}
static size_t preload_fetch_size(caddr_t module) {return ((struct module *)module)->length;}
static void *preload_fetch_addr(caddr_t module) {fetched++;return ((struct module *)module)->data;}
'''
MAIN = r'''
int main(void) {
 struct g_verity_root result, saved;
 unsigned char input[sizeof(valid)];
 for(unsigned scenario=0;scenario<9;scenario++) {
  memcpy(input,valid,sizeof(input));memset(modules,0,sizeof(modules));
  count=3;fetched=enumerated=0;
  modules[0].type="elf kernel";modules[2].type="unrelated";
  modules[1]=(struct module){G_VERITY_ROOT_TYPE,input,sizeof(input)};
  int expected=0;
  if(scenario==1) {count=0;expected=ENOENT;}
  if(scenario==2) {modules[1].type=NULL;expected=ENOENT;}
  if(scenario==3) {modules[3]=modules[1];count=4;expected=EEXIST;}
  if(scenario==4) {modules[1].length--;expected=EINVAL;}
  if(scenario==5) {modules[1].length++;expected=EINVAL;}
  if(scenario==6) {modules[1].data=NULL;expected=EINVAL;}
  if(scenario==7) {input[383]=1;expected=EINVAL;}
  if(scenario==8) {
   modules[1].length=0;modules[3]=modules[1];count=4;expected=EEXIST;
  }
  memset(&result,0x51,sizeof(result));saved=result;
  assert(g_verity_preload_decode(&result)==expected);
  if(expected) assert(!memcmp(&result,&saved,sizeof(result)));
  else {
   assert(result.layout.data_bytes==129*4096 && result.layout.tree_bytes==3*4096);
   assert(result.salt_len==4 && !memcmp(result.salt,"salt",4));
   saved=result;memset(input,0xff,sizeof(input));
   assert(!memcmp(&result,&saved,sizeof(result)));
  }
  if(scenario==1 || scenario==2 || scenario==3 || scenario==4 ||
      scenario==5 || scenario==8) assert(fetched==0);
 }
 struct g_verity_transition transition, original_transition;
 unsigned char plan[sizeof(valid_plan)];
 for(unsigned scenario=0;scenario<14;scenario++) {
  limits_error=limits_checked=0;
  memcpy(input,valid,sizeof(input));memcpy(plan,valid_plan,sizeof(plan));
  memset(modules,0,sizeof(modules));count=4;
  modules[0].type="elf kernel";modules[3].type="unrelated";
  modules[1]=(struct module){G_VERITY_ROOT_TYPE,input,sizeof(input)};
  modules[2]=(struct module){G_VERITY_TRANSITION_TYPE,plan,sizeof(plan)};
  int expected=0;
  if(scenario==1){modules[2].type=NULL;expected=ENOENT;}
  if(scenario==2){modules[1].type=NULL;expected=ENOENT;}
  if(scenario==3){modules[4]=modules[2];count=5;expected=EEXIST;}
  if(scenario==4){modules[4]=modules[1];count=5;expected=EEXIST;}
  if(scenario==5){modules[2].length--;expected=EINVAL;}
  if(scenario==6){modules[2].length++;expected=EINVAL;}
  if(scenario==7){modules[2].data=NULL;expected=EINVAL;}
  if(scenario==8){modules[2].data=(void *)(uintptr_t)-1;expected=EINVAL;}
  if(scenario==9){plan[16]^=1;expected=EAUTH;}
  if(scenario==10){plan[0]^=1;expected=EINVAL;}
  if(scenario==11){input[383]=1;expected=EINVAL;}
  if(scenario==12){modules[1].data=(void *)(uintptr_t)-1;expected=EINVAL;}
  if(scenario==13){limits_error=ENOMEM;expected=ENOMEM;}
  memset(&transition,0x51,sizeof(transition));original_transition=transition;
  memset(&result,0x52,sizeof(result));saved=result;allocations=0;
  assert(g_verity_preload_transition(&transition,&result)==expected);
  assert(!live && allocations==1 && largest<8192);
  assert(limits_checked==(scenario==0 || scenario==13));
  if(expected) {
   assert(!memcmp(&result,&saved,sizeof(result)));
   assert(!memcmp(&transition,&original_transition,sizeof(transition)));
  } else {
   assert(result.layout.data_bytes==129*4096 && transition.workers==2);
   assert(!strcmp(transition.transport_device,"/dev/gpt/boot"));
   assert(!strcmp(transition.image,"/boot/base.verity"));
   saved=result;original_transition=transition;
   memset(input,0xff,sizeof(input));memset(plan,0xff,sizeof(plan));
   assert(!memcmp(&result,&saved,sizeof(result)));
   assert(!memcmp(&transition,&original_transition,sizeof(transition)));
  }
 }
 allocations=0;
 assert(g_verity_preload_transition(NULL,&result)==EINVAL && !allocations);
 assert(g_verity_preload_transition(&transition,NULL)==EINVAL && !allocations);
 enumerated=fetched=0;
 assert(g_verity_preload_decode(NULL)==EINVAL && !enumerated && !fetched);
 return 0;
}
'''
class Preload(unittest.TestCase):
    def test_unique_bounded_descriptor(self):
        source=(ROOT/'sys/geom/verity/g_verity_boot.c').read_text()
        source=source[source.index('static int\nverity_preload_copy('):]
        wire=tree.encode_root_descriptor(129*4096,4096,b'salt',bytes(range(32)))
        array='static const unsigned char valid[] = {'+','.join(map(str,wire))+'};\n'
        plan = (struct.pack('>8sII32sIIQQQ', b'5BSDBOOT',1,2192,hashlib.sha256(wire).digest(),2,1,64,131072,1048576)
                + b'/dev/gpt/boot'.ljust(1024,b'\0') + b'/boot/base.verity'.ljust(1024,b'\0')
                + b'base-root'.ljust(64,b'\0'))
        array += 'static const unsigned char valid_plan[] = {'+','.join(map(str,plan))+'};\n'
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/'preload.c';binary=Path(directory)/'preload'
            c.write_text(PRE+source+array+MAIN)
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'sys'),
                str(c),str(ROOT/'sys/geom/verity/g_verity_verify.c'),
                str(ROOT/'sys/geom/verity/g_verity_transition.c'),'-lmd',
                '-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,timeout=10)

if __name__=='__main__': unittest.main()
