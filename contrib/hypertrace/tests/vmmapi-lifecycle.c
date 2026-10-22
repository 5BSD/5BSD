/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/capsicum.h>
#include <dev/vmm/vmm_dev.h>
#include "vmmapi.h"
#include <sys/hypertrace.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int mode, opens, closes, creates, destroys, reinits, loads, allocfail;
static int identities, lookups, queries, duplicates, rights_calls, allowlist_calls;
static uint16_t expected_id = 7;
static uint64_t expected_epoch = 42;
int __real_open(const char *, int, ...);
int __real_close(int);
int __real_fcntl(int,int,...);
static int profile_fd = -1;
void *__real_malloc(size_t);
void *__wrap_malloc(size_t n) { if (allocfail) { allocfail=0; errno=ENOMEM; return NULL; } return __real_malloc(n); }
int __wrap_modfind(const char *s) { assert(strcmp(s,"vmm")==0); lookups++; return mode==9 ? -1 : 1; }
int __wrap_kldload(const char *s) { assert(strcmp(s,"vmm")==0); loads++;return 1; }
int __wrap_open(const char *s,int flags,...) {
    if (strncmp(s,"/usr/obj/5BSD-hypertrace-validation/",35)==0) {
        va_list ap;int perm=0;
        if(flags&O_CREAT){va_start(ap,flags);perm=va_arg(ap,int);va_end(ap);}
        profile_fd=__real_open(s,flags,perm);return profile_fd;
    }
    assert(flags == (mode>=20 ? O_RDWR|O_NOFOLLOW|O_CLOEXEC : O_RDWR)); opens++;
    if (strcmp(s,"/dev/vmmctl")==0) { if(mode==1||mode==22) {errno=EACCES;return -1;} return 901; }
    assert(strcmp(s,"/dev/vmm/fixture")==0);
    if(mode==2) {errno=EACCES;return -1;}
    if(mode>=3 && mode<=6 && creates==0) {errno=ENOENT;return -1;}
    if(mode==6) {errno=EIO;return -1;}
    return 902;
}
int __wrap_close(int fd) { if(fd==profile_fd) return __real_close(fd); assert(fd==901||fd==902||fd==903);closes++;errno=EBADF;return 0; }
int __wrap_fcntl(int fd,int cmd,...) {
    if(fd==profile_fd) {
        va_list ap;int rc;va_start(ap,cmd);
        switch(cmd) {
        case F_SETLKW: case F_SETLK: case F_GETLK:
            rc=__real_fcntl(fd,cmd,va_arg(ap,struct flock *));break;
        case F_SETFD: case F_SETFL:
            rc=__real_fcntl(fd,cmd,va_arg(ap,int));break;
        case F_GETFD: case F_GETFL:
            rc=__real_fcntl(fd,cmd);break;
        default: abort();
        }
        va_end(ap);return rc;
    }
    assert(fd==902 && cmd==F_DUPFD_CLOEXEC);
    va_list ap;va_start(ap,cmd);assert(va_arg(ap,int)==0);va_end(ap);
    duplicates++;if(mode==40){errno=EMFILE;return -1;}return 903;
}
int __wrap_cap_rights_limit(int fd,const cap_rights_t *rights) {
    cap_rights_t expected;cap_rights_init(&expected,CAP_IOCTL);
    assert(fd==903 && memcmp(rights,&expected,sizeof(expected))==0);
    rights_calls++;if(mode==41){errno=EACCES;return -1;}return 0;
}
int __wrap_cap_ioctls_limit(int fd,const cap_ioctl_t *cmds,size_t n) {
    assert(fd==903 && n==1 && cmds[0]==VM_GET_ATTESTATION);
    allowlist_calls++;if(mode==42){errno=EPERM;return -1;}return 0;
}
int __wrap_ioctl(int fd,unsigned long cmd,...) {
    va_list ap;void *arg;va_start(ap,cmd);arg=va_arg(ap,void*);va_end(ap);
    if(cmd==VM_GET_IDENTITY) {
        struct hypertrace_vm_identity *v=arg;assert(fd==902);queries++;
        if(mode==30){errno=EIO;return -1;}
        memset(v,0,sizeof(*v));v->vmid=mode==31?0:mode==32?HYPERTRACE_MAX_VMS:7;
        v->epoch=mode==33?0:42;return 0;
    }
    if(cmd==VMMCTL_VM_DESTROY_IDENTITY) {
        struct vmmctl_vm_destroy_identity *v=arg;
        assert(fd==901 && strcmp(v->name,"fixture")==0);
        assert(v->vmid==expected_id && v->epoch==expected_epoch);
        for(size_t i=0;i<nitems(v->reserved);i++) assert(v->reserved[i]==0);
        identities++;if(mode==21){errno=ESTALE;return -1;}return 0;
    }
    if(cmd==VMMCTL_VM_CREATE) {
        struct vmmctl_vm_create *v=arg;assert(fd==901&&strcmp(v->name,"fixture")==0);creates++;
        if(mode==4) assert(v->flags & VMMCTL_CREATE_DESTROY_ON_CLOSE);
        if(mode==5) {errno=ENOSPC;return -1;}return 0;
    }
    if(cmd==VMMCTL_VM_DESTROY) {assert(fd==901);destroys++;errno=EBUSY;return -1;}
    if(cmd==VM_REINIT) {assert(fd==902);reinits++;if(mode==7){errno=EBUSY;return -1;}return 0;}
    abort();
}
int main(void) {
    char name[VM_MAX_NAMELEN+2];memset(name,'x',sizeof(name)-1);name[sizeof(name)-1]=0;
    assert(vm_openf(NULL,0)==NULL&&errno==EINVAL&&opens==0);
    assert(vm_openf(name,0)==NULL&&errno==ENAMETOOLONG&&opens==0);
    for(mode=0;mode<=10;mode++) {
        opens=closes=creates=destroys=reinits=loads=0;allocfail=mode==10;
        int flags=(mode>=4&&mode<=6)?VMMAPI_OPEN_CREATE:0;
        if(mode==4)flags|=VMMAPI_OPEN_REINIT|VMMAPI_OPEN_CREATE_DESTROY_ON_CLOSE;
        if(mode==7||mode==8)flags|=VMMAPI_OPEN_REINIT;
        struct vmctx *vm=vm_openf("fixture",flags);
        int error=errno;
        int expected=mode==1||mode==2?EACCES:mode==3?ENOENT:mode==5?ENOSPC:mode==6?EIO:mode==7?EBUSY:mode==10?ENOMEM:0;
        if(expected)assert(vm==NULL&&error==expected);else {assert(vm!=NULL);vm_close(vm);}
        assert(closes==(mode==1||mode==10?0:mode==2||mode==3||mode==5||mode==6?1:2));
        assert(creates==(mode>=4&&mode<=6));
        assert(destroys==(mode==6));
        assert(reinits==(mode==7||mode==8));
        assert(loads==(mode==9));
    }
    /* Recovery by name must never create, reinitialize or load modules. */
    mode=20; opens=closes=identities=lookups=creates=reinits=loads=0;
    assert(vm_destroy_name_identity_checked(NULL,7,42)==-1 && errno==EINVAL);
    assert(vm_destroy_name_identity_checked("",7,42)==-1 && errno==EINVAL);
    assert(vm_destroy_name_identity_checked(name,7,42)==-1 && errno==ENAMETOOLONG);
    assert(vm_destroy_name_identity_checked("fixture",0,42)==-1 && errno==EINVAL);
    assert(vm_destroy_name_identity_checked("fixture",HYPERTRACE_MAX_VMS,42)==-1 && errno==EINVAL);
    assert(vm_destroy_name_identity_checked("fixture",7,0)==-1 && errno==EINVAL);
    assert(opens==0 && identities==0 && lookups==0);
    for(mode=20;mode<=22;mode++) {
        opens=closes=identities=0;
        int rc=vm_destroy_name_identity_checked("fixture",7,42);
        if(mode==20) assert(rc==0);
        if(mode==21) assert(rc==-1 && errno==ESTALE);
        if(mode==22) assert(rc==-1 && errno==EACCES);
        assert(opens==1 && closes==(mode!=22) && identities==(mode!=22));
    }
    assert(lookups==0 && loads==0 && creates==0 && reinits==0);
    mode=20; expected_id=HYPERTRACE_MAX_VMS-1; expected_epoch=UINT64_MAX;
    assert(vm_destroy_name_identity_checked("fixture",expected_id,expected_epoch)==0);
    expected_id=7;expected_epoch=42;
    mode=0;struct vmctx *vm=vm_open("fixture");assert(vm!=NULL);
    closes=identities=0;
    assert(vm_destroy_identity_request_checked(NULL,7,42)==-1 && errno==EINVAL);
    assert(vm_destroy_identity_request_checked(vm,0,42)==-1 && errno==EINVAL);
    assert(vm_destroy_identity_request_checked(vm,HYPERTRACE_MAX_VMS,42)==-1 && errno==EINVAL);
    assert(vm_destroy_identity_request_checked(vm,7,0)==-1 && errno==EINVAL);
    assert(closes==0 && identities==0);
    mode=21;
    assert(vm_destroy_identity_checked(vm,7,42)==-1 && errno==ESTALE);
    assert(closes==0 && identities==1); /* failed check retains ownership */
    mode=0;
    assert(vm_destroy_identity_request_checked(vm,7,42)==0 && closes==0);
    assert(vm_destroy_identity_checked(vm,7,42)==0 && closes==2);
    assert(identities==3);
    mode=0;vm=vm_open("fixture");assert(vm!=NULL);
    queries=0;uint16_t id=99;uint64_t epoch=123;
    assert(vm_get_identity(NULL,&id,&epoch)==-1 && errno==EINVAL);
    assert(vm_get_identity(vm,NULL,&epoch)==-1 && errno==EINVAL);
    assert(vm_get_identity(vm,&id,NULL)==-1 && errno==EINVAL && queries==0);
    for(mode=30;mode<=34;mode++) {
        id=99;epoch=123;
        int rc=vm_get_identity(vm,&id,&epoch);
        if(mode<34) assert(rc==-1 && errno==(mode==30?EIO:EPROTO) && id==99 && epoch==123);
        else assert(rc==0 && id==7 && epoch==42);
    }
    duplicates=rights_calls=allowlist_calls=0;
    assert(vm_export_attestation_fd(NULL)==-1 && errno==EINVAL && duplicates==0);
    for(mode=40;mode<=43;mode++) {
        duplicates=rights_calls=allowlist_calls=closes=0;
        int fd=vm_export_attestation_fd(vm);
        if(mode<43) assert(fd==-1 && errno==(mode==40?EMFILE:mode==41?EACCES:EPERM));
        else assert(fd==903);
        assert(duplicates==1 && rights_calls==(mode!=40) && allowlist_calls==(mode>=42));
        assert(closes==(mode==41||mode==42));
        if(fd>=0)__wrap_close(fd);
    }
    vm_close(vm);
    puts("PASS: actual-library lifecycle and identity cases; no device or module operations");
    return 0;
}
