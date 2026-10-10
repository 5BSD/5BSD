#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess
import tempfile
src=(Path(__file__).resolve().parents[3] / 'sys/compat/linuxkpi/common/include/linux/sysfs.h').read_text()
start=src.index('static inline int\nsysctl_handle_attr(')
end=src.index('static inline int\nsysfs_create_file(',start)
handler=src[start:end]
preamble=r'''
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#define PAGE_SIZE 4096
#define GFP_KERNEL 0
#define CTLTYPE 15
#define CTLTYPE_OPAQUE 5
#define CTLTYPE_STRING 3
#define SYSCTL_HANDLER_ARGS struct sysctl_oid *oidp, void *arg1, intptr_t arg2, struct sysctl_req *req
#define SYSCTL_OUT(req,buf,len) output(req,buf,len)
#define KASSERT(x,msg) assert(x)
#define get_zeroed_page(flags) calloc(1,PAGE_SIZE)
#define free_page(p) free((void *)(p))
struct sysctl_oid { unsigned oid_kind; };
struct sysctl_req { void *newptr; size_t len; unsigned char data[PAGE_SIZE]; };
struct attribute { const char *name; };
struct kobject;
struct sysfs_ops {
 ssize_t (*show)(struct kobject *, struct attribute *, char *);
 ssize_t (*store)(struct kobject *, struct attribute *, const char *, size_t);
};
struct kobj_type { const struct sysfs_ops *sysfs_ops; };
struct kobject { struct kobj_type *ktype; };
static int output(struct sysctl_req *req, const void *buf, size_t len) {
 assert(len<=PAGE_SIZE); req->len=len; memcpy(req->data,buf,len); return 0;
}
static int sysctl_handle_string(struct sysctl_oid *oid, char *buf, int size, struct sysctl_req *req) {
 return output(req,buf,strlen(buf)+1);
}
static unsigned char payload[PAGE_SIZE];
static ssize_t result;
static ssize_t show(struct kobject *k, struct attribute *a, char *buf) {
 memcpy(buf,payload,PAGE_SIZE); return result;
}
'''
tests=r'''
int main(void) {
 struct sysfs_ops ops={.show=show};
 struct kobj_type type={.sysfs_ops=&ops};
 struct kobject obj={.ktype=&type};
 struct sysctl_oid oid={.oid_kind=CTLTYPE_OPAQUE};
 struct sysctl_req req={0};
 struct attribute attr={.name="gpu_metrics"};
 assert(linux_sysfs_binary_attr(&attr));
 struct attribute text_attr={.name="clock"};
 assert(!linux_sysfs_binary_attr(&text_attr));
 payload[0]=120; payload[2]=2; payload[3]=1; payload[119]=0xa5; result=120;
 assert(sysctl_handle_attr(&oid,&obj,(intptr_t)&attr,&req)==0);
 assert(req.len==120 && memcmp(req.data,payload,120)==0);
 result=-EIO; assert(sysctl_handle_attr(&oid,&obj,(intptr_t)&attr,&req)==EIO);
 result=PAGE_SIZE+1; assert(sysctl_handle_attr(&oid,&obj,(intptr_t)&attr,&req)==EOVERFLOW);
 result=PAGE_SIZE; assert(sysctl_handle_attr(&oid,&obj,(intptr_t)&attr,&req)==0 && req.len==PAGE_SIZE);
 req.newptr=payload; assert(sysctl_handle_attr(&oid,&obj,(intptr_t)&attr,&req)==EPERM);
 req.newptr=NULL; result=0; assert(sysctl_handle_attr(&oid,&obj,(intptr_t)&attr,&req)==0 && req.len==0);
 ops.show=NULL; assert(sysctl_handle_attr(&oid,&obj,(intptr_t)&attr,&req)==ENODEV); ops.show=show;
 oid.oid_kind=CTLTYPE_STRING; memset(payload,0,sizeof(payload)); strcpy((char*)payload,"300\n"); result=4;
 assert(sysctl_handle_attr(&oid,&obj,(intptr_t)&attr,&req)==0 && req.len==4 && strcmp((char*)req.data,"300")==0);
 strcpy((char*)payload,"300"); result=3;
 assert(sysctl_handle_attr(&oid,&obj,(intptr_t)&attr,&req)==0 && req.len==4 && strcmp((char*)req.data,"300")==0);
 puts("sysfs transport: 10 source-extracted transport checks passed"); return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='hwstat-sysfs-') as directory:
    source = Path(directory) / 'test.c'
    binary = Path(directory) / 'test'
    source.write_text(preamble + handler + tests)
    subprocess.run(['cc', '-Wall', '-Wextra', '-Wno-unused-parameter', '-Werror',
                    '-o', str(binary), str(source)], check=True)
    subprocess.run([str(binary)], check=True)
