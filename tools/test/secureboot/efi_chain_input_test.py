# SPDX-License-Identifier: BSD-2-Clause
"""Actual EFI chain command with native firmware/I/O admission fixtures."""
from pathlib import Path
import subprocess,tempfile
ROOT=Path(__file__).resolve().parents[3]
PRE=r'''
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>
typedef int EFI_GUID;
typedef void *EFI_HANDLE;
typedef size_t UINTN,EFI_STATUS;
typedef wchar_t CHAR16;
typedef struct {void *LoadOptions;size_t LoadOptionsSize;void *DeviceHandle;} EFI_LOADED_IMAGE;
#define LOADED_IMAGE_PROTOCOL 0
#define EFI_SUCCESS 0
#define EFI_SECURITY_VIOLATION 2
#define EFI_ACCESS_DENIED 3
#define EFI_LOAD_ERROR 4
#define EfiLoaderCode 1
#define FALSE 0
#define DECODE_ERROR(n) ((unsigned long)(n))
#define CMD_ERROR 1
#define DEVT_NET 1
#define VE_MUST 2
#define VE_VERIFIED 1
static const char *command_errmsg;
static char command_errbuf[256];
static EFI_HANDLE IH;
struct devsw {int dv_type;};
struct devdesc {struct devsw *d_dev;int d_unit;};
struct disk_devdesc {struct devdesc dd;int d_slice;};
typedef struct pdinfo {STAILQ_HEAD(,pdinfo) pd_part;STAILQ_ENTRY(pdinfo) pd_link;
 uint32_t pd_unit;void *pd_handle;} pdinfo_t;
static int scenario,required=1,closed,loaded,started,freed,unloaded,checked;
static unsigned char stored[8];
static EFI_LOADED_IMAGE image;
static void *allocation;
static int fake_open(const char *n,int f){assert(!strcmp(n,"image") && f==O_RDONLY);return 7;}
static int fake_close(int fd){assert(fd==7);closed++;return 0;}
static int fake_stat(int fd,struct stat *st) {
 assert(fd==7);memset(st,0,sizeof(*st));st->st_mode=S_IFREG;st->st_size=8;
 if(scenario==1)return -1;
 if(scenario==2)st->st_mode=S_IFDIR;
 if(scenario==3)st->st_size=-1;
 if(scenario==4)st->st_size=0;
 return 0;
}
static ssize_t fake_read(int fd,void *out,size_t n) {
 assert(fd==7 && n==8);memcpy(out,stored,n);
 return scenario==5 ? -1 : scenario==6 ? 7 : 8;
}
static int verify_file(int fd,const char *p,off_t o,int sev,const char *caller) {
 (void)p;(void)caller;assert(fd==7 && o==0 && sev==VE_MUST);
 if(scenario==7)memset(stored,'x',8);
 return scenario==8 ? -1 : VE_VERIFIED;
}
static int verify_required(void){return required;}
static int verify_buf(int fd,const char *p,const void *data,size_t n) {
 (void)p;assert(fd==7 && n==8);checked++;
 int ok=!memcmp(data,"verified",8);
 if(scenario==9)memset(stored,'x',8);
 return ok ? VE_VERIFIED : -1;
}
static int verity_check_source(int fd){assert(fd==7);return scenario==10 ? EAUTH : 0;}
static EFI_STATUS pool(int type,UINTN n,void **out) {
 assert(type==EfiLoaderCode && n==8);
 if(scenario==11)return 1;
 allocation=malloc(n);assert(allocation);*out=allocation;return 0;
}
static EFI_STATUS pool_free(void *p){assert(p==allocation);free(p);allocation=NULL;freed++;return 0;}
static EFI_STATUS load(int boot,void *parent,void *path,void *buf,UINTN n,void **handle) {
 (void)boot;(void)parent;(void)path;assert(n==8 && !memcmp(buf,"verified",8));
 loaded++;
 if(scenario==18){*handle=NULL;return EFI_ACCESS_DENIED;}
 if(scenario==19){assert(*handle==NULL);return EFI_LOAD_ERROR;}
 *handle=(void *)42;return scenario==17 ? EFI_SECURITY_VIOLATION : 0;
}
static EFI_STATUS start(void *handle,UINTN *size,CHAR16 **data) {
 (void)size;(void)data;assert(handle==(void *)42);started++;return scenario==14 ? 1 : 0;
}
static EFI_STATUS unload(void *handle){assert(handle==(void *)42);unloaded++;return 0;}
static struct {EFI_STATUS (*AllocatePool)(int,UINTN,void **);EFI_STATUS (*FreePool)(void *);
 EFI_STATUS (*LoadImage)(int,void *,void *,void *,UINTN,void **);
 EFI_STATUS (*StartImage)(void *,UINTN *,CHAR16 **);EFI_STATUS (*UnloadImage)(void *);} services={pool,pool_free,load,start,unload};
#define BS (&services)
static EFI_STATUS OpenProtocolByHandle(void *h,EFI_GUID *g,void **out) {
 (void)g;assert(h==(void *)42);*out=&image;return scenario==12 ? 1 : 0;
}
static int efi_getdev(void **d,const char *n,const char **p){(void)d;(void)n;(void)p;return 1;}
static void *efi_find_handle(struct devsw *d,int u){(void)d;(void)u;return NULL;}
static pdinfo_t *efiblk_get_pdinfo(struct devdesc *d){(void)d;return NULL;}
static void dev_cleanup(void){}
static void *option_malloc(size_t n){return scenario==15 ? NULL : malloc(n);}
static size_t option_strlen(const char *s){return scenario==16 ? UINT32_MAX : strlen(s);}
#define malloc option_malloc
#define strlen option_strlen
#define open fake_open
#define close fake_close
#define fstat fake_stat
#define read fake_read
'''
MAIN=r'''
int main(void) {
 for(scenario=0;scenario<20;scenario++) {
  char *args[]={"sentinel","chain","image","hello",NULL};
  closed=loaded=started=freed=unloaded=checked=0;allocation=NULL;
  memset(&image,0,sizeof(image));memcpy(stored,"verified",8);
  assert(command_chain(scenario>=13 ? 3 : 2,args+1)==CMD_ERROR);
  assert(!strcmp(args[0],"sentinel"));
  if(scenario==13) {
   assert(image.LoadOptions && !wmemcmp(image.LoadOptions,L"hello",6));
   free(image.LoadOptions);image.LoadOptions=NULL;
  }
  assert(closed==1 && allocation==NULL);
  int accepted=scenario==0 || scenario==9 || scenario>=12;
  assert(loaded==accepted && started==(accepted && scenario!=12 && scenario!=15 && scenario!=16 && scenario<17));
  assert(unloaded==(scenario==12 || (scenario>=14 && scenario<=17)));
  if(scenario==14)assert(image.LoadOptions==NULL);
  if(scenario==7)assert(checked==1 && !loaded);
 }
 /* Conventional verification still permits the unchanged EFI input. */
 scenario=0;required=0;loaded=started=checked=0;memcpy(stored,"verified",8);
 char *args[]={"chain","image",NULL};
 assert(command_chain(2,args)==CMD_ERROR && loaded==1 && started==1 && checked==0);
 return 0;
}
'''
def main():
    source=(ROOT/'stand/efi/loader/main.c').read_text();start=source.index('static int\ncommand_chain(')
    function=source[start:source.index('\n}\n',start)+3]
    with tempfile.TemporaryDirectory() as d:
        p=Path(d);c=p/'test.c';binary=p/'test';c.write_text(PRE+function+MAIN)
        subprocess.run(['cc','-Wall','-Wextra','-Werror',
            '-DLOADER_VERIEXEC','-DLOADER_VERITY_SUPPORT',str(c),'-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True,cwd=p,timeout=10)
    print('PASS: actual chain command metadata/read/source/buffer checks with injected firmware')
if __name__=='__main__':main()
