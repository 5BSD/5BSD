# SPDX-License-Identifier: BSD-2-Clause
"""Actual loader selection lifecycle; external operations fault-injected."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r"""
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <geom/verity/g_verity_verify.h>
#include <geom/verity/g_verity_transition.h>
#include <crypto/sha2/sha256.h>
#include <sys/endian.h>
#define CMD_OK 0
#define CMD_ERROR 2
#define COMMAND_SET(tag,name,description,fn)
static char *command_errmsg,command_errbuf[256],current[32];
static int mode,kernel,preload,fd_live,root_live,attached,live,allocations;
static int plan_live, plan_preloaded;
static unsigned char plan_input[G_VERITY_TRANSITION_BYTES], plan_handoff[G_VERITY_TRANSITION_BYTES];
static unsigned char trusted[G_VERITY_ROOT_BYTES], expected_digest[32];
typedef uintptr_t vm_offset_t;
struct preloaded_file {char *f_type;size_t f_size;vm_offset_t f_addr;struct preloaded_file *f_next;};
static struct preloaded_file *preloaded_files;
static unsigned char handoff[G_VERITY_ROOT_BYTES];
static int short_copy,copies;
static ssize_t copyout(vm_offset_t from,void *out,size_t length) {
 if(from==16384) {
  assert(length==sizeof(plan_handoff));memcpy(out,plan_handoff,length);
  return short_copy ? (ssize_t)length-1 : (ssize_t)length;
 }
 assert(from==8192 && length==sizeof(handoff));copies++;
 memcpy(out,handoff,length);return short_copy ? (ssize_t)length-1 : (ssize_t)length;
}
static struct {ssize_t (*arch_copyout)(vm_offset_t,void *,size_t);} archsw={copyout};

#define F_READ 1
struct devsw {int unused;};
static struct devsw verity_dev,foreign_dev;
struct devdesc {struct devsw *d_dev;int d_unit;};
struct open_file;
struct fs_ops {int (*fo_source)(struct open_file *);};
static struct fs_ops ufs_fsops,unknown_fsops;
struct open_file {int f_flags;struct devsw *f_dev;void *f_devdata;struct fs_ops *f_ops;};
static struct devdesc opened_device;
static struct open_file opened_file,wrapped_file;
static int backing_fd=12;
static int wrapper_source(struct open_file *file) {assert(file==&wrapped_file);return backing_fd;}
static struct fs_ops wrapper_ops={wrapper_source};
static struct open_file *fd2open_file(int fd) {
 return fd==12 ? &opened_file : (fd==13 ? &wrapped_file : NULL);
}

static char *duplicate(const char *s) {
 allocations++;if(mode==allocations && mode<=2)return NULL;
 char *p=strdup(s);assert(p);live++;return p;
}
static void release(void *p) {if(p){live--;free(p);}}
static char *get_current(const char *name) {assert(!strcmp(name,"currdev"));return current;}
static int set_current(const char *name,const char *value,int overwrite) {
 assert(!strcmp(name,"currdev") && overwrite==1);
 if(mode==7)return ENOMEM;strcpy(current,value);return 0;
}
static int open_input(const char *name,int flags) {
 assert(flags==O_RDONLY);
 if(!strcmp(name,"transition")) {plan_live++;return 14;}
 if(!strcmp(name,"image") || !strcmp(name,"/boot/image")) {
  if(mode==3){errno=EIO;return -1;}fd_live++;return 10;
 }
 assert(!strcmp(name,"descriptor"));
 if(mode==4){errno=EIO;return -1;}root_live++;return 11;
}
static int close_input(int fd) {
 if(fd==14){assert(plan_live==1);plan_live--;return 0;}
 if(fd==10){assert(fd_live==1);fd_live--;return 0;}
 assert(fd==11 && root_live==1);root_live--;
 if(mode==6){errno=EIO;return -1;}return 0;
}
static void *file_findfile(const char *name,const char *type) {
 assert(name==NULL);
 if(type && !strcmp(type,G_VERITY_TRANSITION_TYPE))return plan_preloaded?(void *)1:NULL;
 if(type){assert(!strcmp(type,G_VERITY_ROOT_TYPE));return preload?(void *)1:NULL;}
 return kernel?(void *)1:NULL;
}
static int verity_dev_attach_verified(int fd,int desc,const char *name,
 const unsigned char *digest,size_t entries,size_t budget,int *unit,unsigned char *wire) {
 assert(digest && !memcmp(digest,expected_digest,32));
 assert(fd==10 && desc==11 && !strcmp(name,"descriptor") && entries==8 && budget==65536);
 if(mode==5)return EAUTH;
 assert(!attached);attached=1;*unit=7;memcpy(wire,trusted,sizeof(trusted));return 0;
}
static int verity_dev_detach(int unit) {
 assert(unit==7 && attached);
 if(mode==8)return EBUSY;
 attached=0;close_input(10);return mode==9?EIO:0;
}
static ssize_t verified_transition_read(int fd,const char *name,unsigned char *wire) {
 assert(fd==14 && !strcmp(name,"transition"));
 if(mode==14){errno=EAUTH;return -1;}
 memcpy(wire,plan_input,sizeof(plan_input));return sizeof(plan_input);
}
static int file_addbuf(const char *name,const char *type,size_t length,void *data) {
 if(!strcmp(type,G_VERITY_TRANSITION_TYPE)) {
  assert(!strcmp(name,"transition") && length==sizeof(plan_input));
  assert(!memcmp(data,plan_input,length));
  if(mode==15)return -1;
  plan_preloaded=1;memcpy(plan_handoff,data,length);return 0;
 }
 assert(!strcmp(name,"descriptor") && !strcmp(type,G_VERITY_ROOT_TYPE));
 assert(length==sizeof(trusted) && !memcmp(data,trusted,length));
 if(mode==10)return -1;preload=1;return 0;
}
#define strdup duplicate
#define free release
#define getenv get_current
#define setenv set_current
#define open open_input
#define close close_input
"""
MAIN=r"""
static void reset(void) {
 assert(!live && !attached && !fd_live && !root_live && verity_selected==-1);
 mode=kernel=preload=allocations=0;strcpy(current,"disk0:");
}
int main(void) {
 memset(trusted,0x5a,sizeof(trusted));reset();
 assert(verity_check_source(-1)==0);
 assert(verity_source_verified(-1)==0 && verity_source_verified(12)==0);
 assert(verity_check_handoff()==0);
 for(int failure=1;failure<=7;failure++) {
  mode=failure;allocations=0;
  assert(verity_select("image","descriptor",expected_digest,8,65536)!=0);
  assert(!strcmp(current,"disk0:"));reset();
 }
 size_t number=42;
 assert(verity_number("184467440737095516160",&number)==EOVERFLOW && number==42);
 assert(verity_number("-1",&number)==EINVAL && number==42);
 assert(verity_number("",&number)==EINVAL);
 assert(verity_number("0",&number)==0 && number==0);
 unsigned char digest[32];
 assert(verity_digest("",digest)==EINVAL);
 assert(verity_digest("00",digest)==EINVAL);
 assert(verity_digest("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",digest)==0);
 for(unsigned i=0;i<32;i++)assert(digest[i]==255);
 assert(verity_digest("gg00000000000000000000000000000000000000000000000000000000000000",digest)==EINVAL);
 assert(verity_select("image","descriptor",NULL,8,65536)==EINVAL);
 kernel=1;assert(verity_select("image","descriptor",expected_digest,8,65536)==EBUSY);kernel=0;
 char *argv[]={"verity-select","image","descriptor","0000000000000000000000000000000000000000000000000000000000000000","8","65536"};
 assert(command_verity_select(6,argv)==CMD_OK);
 assert(!strcmp(current,"verity7:") && attached && fd_live && !root_live);
 opened_device=(struct devdesc){&verity_dev,7};
 opened_file=(struct open_file){F_READ,&verity_dev,&opened_device,&ufs_fsops};
 assert(verity_check_source(12)==0 && verity_source_verified(12)==1);
 wrapped_file=(struct open_file){F_READ,&foreign_dev,NULL,&wrapper_ops};
 assert(verity_check_source(13)==0);
 wrapped_file.f_dev=&verity_dev;wrapped_file.f_devdata=&opened_device;
 opened_file.f_dev=&foreign_dev;assert(verity_check_source(13)==EAUTH);
 assert(verity_source_verified(13)==0 && verity_source_verified(12)==0);
 opened_file.f_dev=&verity_dev;
 backing_fd=-1;assert(verity_check_source(13)==EAUTH);
 backing_fd=99;assert(verity_check_source(13)==EAUTH);
 backing_fd=13;assert(verity_check_source(13)==EAUTH);backing_fd=12;
 opened_file.f_ops=&unknown_fsops;assert(verity_check_source(12)==EAUTH);
 assert(verity_check_source(13)==EAUTH);opened_file.f_ops=NULL;
 assert(verity_check_source(12)==EAUTH);opened_file.f_ops=&ufs_fsops;

 assert(verity_check_source(-1)==EAUTH && verity_check_source(99)==EAUTH);
 opened_file.f_dev=&foreign_dev;assert(verity_check_source(12)==EAUTH);
 opened_file.f_dev=&verity_dev;opened_device.d_dev=&foreign_dev;
 assert(verity_check_source(12)==EAUTH);opened_device.d_dev=&verity_dev;
 opened_device.d_unit=8;assert(verity_check_source(12)==EAUTH);opened_device.d_unit=7;
 opened_file.f_devdata=NULL;assert(verity_check_source(12)==EAUTH);
 opened_file.f_devdata=&opened_device;opened_file.f_flags=0;
 assert(verity_check_source(12)==EAUTH);opened_file.f_flags=F_READ;
 strcpy(current,"disk0:");assert(verity_check_source(12)==0);strcpy(current,"verity7:");

 assert(verity_select("image","descriptor",expected_digest,8,65536)==EBUSY);

 assert(verity_check_handoff()==EAUTH);
 struct preloaded_file descriptor={G_VERITY_ROOT_TYPE,sizeof(handoff),8192,NULL};
 struct preloaded_file duplicate=descriptor;
 preloaded_files=&descriptor;memcpy(handoff,trusted,sizeof(handoff));
 assert(verity_check_handoff()==0 && copies==1);
 plan_preloaded=1;assert(verity_check_handoff()==EAUTH);plan_preloaded=0;
 descriptor.f_next=&duplicate;assert(verity_check_handoff()==EAUTH);descriptor.f_next=NULL;
 descriptor.f_size--;assert(verity_check_handoff()==EAUTH);descriptor.f_size++;
 descriptor.f_addr=UINTPTR_MAX;assert(verity_check_handoff()==EAUTH);descriptor.f_addr=8192;
 short_copy=1;assert(verity_check_handoff()==EIO);short_copy=0;
 handoff[0]^=1;assert(verity_check_handoff()==EAUTH);handoff[0]^=1;
 descriptor.f_type=NULL;assert(verity_check_handoff()==EAUTH);
 descriptor.f_type=G_VERITY_ROOT_TYPE;assert(verity_check_handoff()==0);
 preloaded_files=NULL;
 assert(verity_preload()==ENOENT);kernel=1;
 strcpy(current,"disk0:");assert(verity_preload()==EINVAL);strcpy(current,"verity7:");
 mode=10;assert(verity_preload()==EIO && !preload);mode=0;
 assert(command_verity_preload(1,argv)==CMD_OK && preload);
 assert(verity_preload()==EEXIST);
 assert(verity_clear()==EBUSY);kernel=preload=0;
 mode=7;assert(verity_clear()==ENOMEM && attached && verity_selected==7);
 mode=8;assert(verity_clear()==EBUSY && attached && verity_selected==7);
 assert(!strcmp(current,"disk0:"));
 mode=0;assert(command_verity_clear(1,argv)==CMD_OK);reset();
 assert(verity_select("image","descriptor",expected_digest,8,65536)==0);
 mode=9;assert(verity_clear()==EIO);reset();
 assert(command_verity_select(1,argv)==CMD_ERROR);
 assert(command_verity_preload(2,argv)==CMD_ERROR);
 assert(command_verity_clear(2,argv)==CMD_ERROR);
 /* Real wire decoder and digest, with authentication/I/O injected. */
 memset(plan_input,0,sizeof(plan_input));memcpy(plan_input,"5BSDBOOT",8);
 be32enc(plan_input+8,1);be32enc(plan_input+12,sizeof(plan_input));
 memcpy(plan_input+16,expected_digest,32);be32enc(plan_input+48,2);
 be32enc(plan_input+52,1);be64enc(plan_input+56,64);
 be64enc(plan_input+64,131072);be64enc(plan_input+72,1048576);
 strcpy((char *)plan_input+80,"/dev/gpt/site-boot");
 strcpy((char *)plan_input+1104,"/boot/image");
 strcpy((char *)plan_input+2128,"site-root");
 unsigned char plan_digest[32];SHA256_CTX context;
 SHA256_Init(&context);SHA256_Update(&context,plan_input,sizeof(plan_input));
 SHA256_Final(plan_digest,&context);
 for(int fault=0;fault<4;fault++) {
  mode=fault==0?14:0;
  if(fault==1)plan_digest[0]^=1;
  if(fault==2)expected_digest[0]^=1;
  assert(verity_select_transition(fault==3?"image":"/boot/image","descriptor",
      expected_digest,8,65536,"transition",plan_digest)==EAUTH);
  if(fault==1)plan_digest[0]^=1;
  if(fault==2)expected_digest[0]^=1;
  assert(!live && !plan_live && !attached && !verity_transition_name);
 }
 mode=0;
 char plan_hex[65],root_hex[65];
 for(unsigned i=0;i<32;i++) {
  snprintf(plan_hex+2*i,3,"%02x",plan_digest[i]);
  snprintf(root_hex+2*i,3,"%02x",expected_digest[i]);
 }
 char *plan_args[]={"verity-select","/boot/image","descriptor",root_hex,
     "8","65536","transition",plan_hex};
 assert(command_verity_select(8,plan_args)==CMD_OK);
 assert(verity_transition_name && !plan_live && live==3);
 kernel=1;assert(verity_preload()==0 && plan_preloaded);
 struct preloaded_file plan={G_VERITY_TRANSITION_TYPE,sizeof(plan_input),16384,NULL};
 preloaded_files=&descriptor;descriptor.f_next=NULL;
 assert(verity_check_handoff()==EAUTH);
 descriptor.f_next=&plan;assert(verity_check_handoff()==0);
 struct preloaded_file plan_duplicate=plan;
 plan.f_next=&plan_duplicate;assert(verity_check_handoff()==EAUTH);plan.f_next=NULL;
 plan.f_size--;assert(verity_check_handoff()==EAUTH);plan.f_size++;
 plan_handoff[17]^=1;assert(verity_check_handoff()==EAUTH);plan_handoff[17]^=1;
 /* Changed source bytes are no longer consulted after authenticated retention. */
 plan_input[19]^=1;assert(verity_check_handoff()==0);plan_input[19]^=1;
 kernel=preload=plan_preloaded=0;preloaded_files=NULL;descriptor.f_next=NULL;
 assert(verity_clear()==0 && !verity_transition_name);reset();
 assert(command_verity_require(2,argv)==CMD_ERROR && !verity_required);
 kernel=1;assert(verity_require()==EBUSY && !verity_required);kernel=0;
 assert(command_verity_require(1,argv)==CMD_OK && verity_required);
 assert(verity_check_source(12)==EAUTH && verity_check_handoff()==EAUTH);
 assert(verity_clear()==EPERM);
 assert(verity_source_verified(12)==0);
 mode=5;assert(verity_select("image","descriptor",expected_digest,8,65536)==EAUTH);
 assert(verity_required && !attached && !fd_live && !root_live && !live);
 assert(verity_check_source(12)==EAUTH && verity_check_handoff()==EAUTH);
 mode=0;assert(verity_select("image","descriptor",expected_digest,8,65536)==0);
 assert(verity_check_source(12)==0);
 assert(verity_check_handoff()==EAUTH);
 kernel=1;assert(verity_preload()==0);
 preloaded_files=&descriptor;
 assert(verity_check_handoff()==0);
 assert(verity_require()==0); /* Repeated policy cannot undo the requirement. */
 kernel=preload=0;preloaded_files=NULL;
 assert(verity_clear()==EPERM && attached && verity_selected==7);
 strcpy(current,"disk0:");
 opened_file.f_dev=&foreign_dev;assert(verity_check_source(12)==EAUTH);
 assert(verity_check_handoff()==EAUTH);
 assert(verity_select("image","descriptor",expected_digest,8,65536)==EBUSY);
 /* Selected device and two names intentionally remain held until loader exit. */
 assert(fd_live==1 && root_live==0 && live==2);
 return 0;
}
"""
class Commands(unittest.TestCase):
    def test_handoff_gate_order(self):
        source=(ROOT/'stand/common/boot.c').read_text()
        gate=source.index('file_exec(fp);')
        self.assertLess(source.index('archsw.arch_autoload()'),gate)
        self.assertLess(source.index('tslog_publish();'),gate)
        installer=(ROOT/'stand/common/install.c').read_text()
        self.assertIn('file_exec(fp);',installer)
        # Prevent another direct C handler dispatch from bypassing the common gate.
        dispatchers=[]
        for path in (ROOT/'stand').rglob('*.c'):
            if '->l_exec(' in path.read_text():
                dispatchers.append(path.relative_to(ROOT).as_posix())
        self.assertEqual(dispatchers,['stand/common/module.c'])


    def test_failure_lifetime_and_descriptor_publication(self):
        source=(ROOT/'stand/common/verity_commands.c').read_text()
        for inc in ('#include <stand.h>','#include <bootstrap.h>','#include "veritydev.h"','#include "verified_root.h"'):
            source=source.replace(inc,'')
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/'test.c';binary=Path(directory)/'test';c.write_text(PRE+source+MAIN)
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'sys'),str(c),str(ROOT/'sys/geom/verity/g_verity_transition.c'),'-lmd','-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,timeout=10)
if __name__=='__main__':unittest.main()
