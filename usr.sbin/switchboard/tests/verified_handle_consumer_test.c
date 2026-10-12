/* Client error/cleanup tests with a deliberately fake kernel transport.
 * These do not assert that native execution provides kernel text pinning. */
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/mac.h>
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "capimage.h"
#include "libcapbundle_internal.h"
#include "switchboard.h"
#include "authority.h"
#include <sys/syscall.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <ucl.h>

static const char *policy_text = "attributes=[];";
static struct capimage_info metadata;
static int mode, last_handle, source_fd, constraint_calls, constraint_failure;
static struct capbundle_service unit;
struct switchboard_state sd;
enum { GOOD, ABSENT, UNSUPPORTED, BAD_METADATA, BAD_TYPE, CORRUPT, SHORT_READ, TOO_BIG, CAPMODE };
int __wrap_mac_syscall(const char *, int, void *);
int
__wrap_mac_syscall(const char *policy, int call, void *arg)
{
	assert(strcmp(policy, CAPIMAGE_MAC_POLICY) == 0);
	if (mode == UNSUPPORTED) { errno = EOPNOTSUPP;return -1; }
	if (mode == CAPMODE) { errno = ECAPMODE;return -1; }
	if (call == CAPIMAGE_PREPARE_SYSCALL) {
		source_fd = ((struct capimage_prepare *)arg)->source_fd;
		if (mode == ABSENT) {
			if (((struct capimage_prepare *)arg)->flags & CAPIMAGE_PREPARE_REQUIRED) {
				errno = ENOATTR; return -1;
			}
			return 0;
		}
		char path[]="client-policy.XXXXXX";
		last_handle=mkstemp(path);assert(last_handle>=0);assert(unlink(path)==0);
		assert(write(last_handle,policy_text,strlen(policy_text))==(ssize_t)strlen(policy_text));
		if(mode==CORRUPT)assert(pwrite(last_handle,"x",1,0)==1);
		if(mode==SHORT_READ)assert(ftruncate(last_handle,1)==0);
		return last_handle+1;
	}
	assert(call==CAPIMAGE_HANDLE_INFO_SYSCALL);
	if(mode==BAD_TYPE){errno=EINVAL;return -1;}
	struct capimage_info_request *r=arg;
	r->info=metadata;
	if(mode==BAD_METADATA)r->info.version=99;
	if(mode==TOO_BIG)r->info.policy_size=CAPIMAGE_POLICY_MAX+1;
	return 0;
}

static int
image_fixture(void)
{
	unsigned char bytes[256]={0};
	Elf64_Ehdr *eh=(Elf64_Ehdr *)bytes;
	Elf64_Phdr *ph=(Elf64_Phdr *)(bytes+sizeof(*eh));
	memcpy(eh->e_ident,ELFMAG,SELFMAG);eh->e_ident[EI_CLASS]=ELFCLASS64;
	eh->e_ident[EI_DATA]=ELFDATA2LSB;eh->e_ident[EI_VERSION]=EV_CURRENT;
	eh->e_type=htole16(ET_DYN);eh->e_machine=htole16(EM_X86_64);
	eh->e_phoff=htole64(sizeof(*eh));eh->e_ehsize=htole16(sizeof(*eh));
	eh->e_phentsize=htole16(sizeof(*ph));eh->e_phnum=htole16(1);
	ph->p_type=htole32(PT_LOAD);ph->p_filesz=htole64(sizeof(bytes));
	int fd=open("client-image",O_RDWR|O_CREAT|O_EXCL,0600);assert(fd>=0);
	assert(write(fd,bytes,sizeof(bytes))==sizeof(bytes));
	return fd;
}
struct capbundle *bundle_registry_get(unsigned idx) { (void)idx; return (void *)&unit; }
struct capbundle_service *capbundle_service(const struct capbundle *b, unsigned idx)
{ (void)b; (void)idx; return &unit; }
const char *capbundle_svc_program(const struct capbundle_service *s) { return s->program; }
int svc_library_cache_policy_bind(const struct svc_runtime *s, int token)
{ (void)s; (void)token; return 0; }
int __wrap_syscall(int, ...);
int
__wrap_syscall(int number, ...)
{
	va_list ap;
	assert(number == SYS_cap_process);
	va_start(ap, number);
	int op = va_arg(ap, int);
	(void)va_arg(ap, int); (void)va_arg(ap, int);
	void *data = va_arg(ap, void *); va_end(ap);
	if (op == CAP_AUTH_CONSTRAIN) {
		struct cap_authority_constraint *c = data;
		constraint_calls++;
		if (unit.signed_image) {
			assert(c->executable_fds[0] == source_fd);
			assert(fcntl(last_handle, F_GETFD) >= 0);
		}
		if (constraint_failure) { errno = EBUSY; return -1; }
	} else assert(op == CAP_AUTH_SET_LIBDIRS);
	return 0;
}
int
main(void)
{
	char error[256];
	struct capimage_policy policy;
	struct capimage_info info;
	struct capimage_footer footer;
	int fd=image_fixture(),handle;
	unsigned size;
	EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,NULL);assert(ctx);
	EVP_PKEY *key=NULL;assert(EVP_PKEY_keygen_init(ctx)==1&&EVP_PKEY_keygen(ctx,&key)==1);
	FILE *f=fopen("client-key","w");assert(f);
	assert(PEM_write_PrivateKey(f,key,NULL,NULL,0,NULL,NULL)==1);assert(fclose(f)==0);
	f=fopen("client-public","w");assert(f);
	assert(PEM_write_PUBKEY(f,key)==1);assert(fclose(f)==0);
	EVP_PKEY_free(key);EVP_PKEY_CTX_free(ctx);
	assert(capimage_embed(fd,policy_text,strlen(policy_text),error,sizeof(error))==0);
	assert(capimage_sign(fd,"client-key",error,sizeof(error))==0);
	assert(capimage_verify_integrity(fd,&policy,error,sizeof(error))==0);
	metadata.version=CAPIMAGE_HANDLE_VERSION;metadata.struct_size=sizeof(metadata);
	metadata.container_version=CAPIMAGE_VERSION;metadata.file_size=lseek(fd,0,SEEK_END);
	assert(pread(fd,&footer,sizeof(footer),metadata.file_size-sizeof(footer))==sizeof(footer));
	metadata.policy_offset=le64toh(footer.offset)+sizeof(struct capimage_header);
	metadata.policy_size=policy.size;memcpy(metadata.key,policy.key,32);
	memcpy(metadata.image_digest,policy.digest,32);
	assert(EVP_Digest(policy.data,policy.size,metadata.policy_digest,&size,EVP_sha256(),NULL)==1);
	capimage_policy_free(&policy);
	mode=GOOD;assert(capimage_prepare_fd(fd,0,&handle,&info,error,sizeof(error))==0&&handle>=0);
	assert(capimage_handle_policy(handle,&policy,error,sizeof(error))==0);
	assert(policy.size==strlen(policy_text)&&memcmp(policy.data,policy_text,policy.size)==0);
	capimage_policy_free(&policy);close(handle);
	mode=BAD_METADATA;assert(capimage_prepare_fd(fd,0,&handle,&info,error,sizeof(error))==-1);
	assert(handle==-1&&errno==EAUTH);assert(fcntl(last_handle,F_GETFD)==-1&&errno==EBADF);
	mode=UNSUPPORTED;assert(capimage_prepare_fd(fd,0,&handle,&info,error,sizeof(error))==-1);
	assert(handle==-1&&errno==EOPNOTSUPP);
	mode=ABSENT;assert(capimage_prepare_fd(fd,0,&handle,&info,error,sizeof(error))==0&&handle==-1);
	mode=BAD_TYPE;assert(capimage_prepare_fd(fd,0,&handle,&info,error,sizeof(error))==-1);
	assert(handle==-1&&errno==EINVAL);assert(fcntl(last_handle,F_GETFD)==-1&&errno==EBADF);
	assert(capimage_handle_policy(fd,&policy,error,sizeof(error))==-1&&errno==EINVAL);
	mode=TOO_BIG;assert(capimage_handle_policy(fd,&policy,error,sizeof(error))==-1&&errno==EAUTH);
	for(mode=CORRUPT;mode<=SHORT_READ;mode++) {
		assert(capimage_prepare_fd(fd,0,&handle,&info,error,sizeof(error))==0&&handle>=0);
		assert(capimage_handle_policy(handle,&policy,error,sizeof(error))==-1);
		assert(policy.data==NULL&&policy.size==0);close(handle);
	}
	mode=GOOD;
	assert(capimage_prepare_trusted_fd(fd,0,"client-public",&handle,&info,error,sizeof(error))==0);
	assert(handle>=0);close(handle);
	assert(capimage_prepare_trusted_fd(fd,0,"missing-key",&handle,&info,error,sizeof(error))==-1);
	assert(handle==-1&&errno==EAUTH);assert(fcntl(last_handle,F_GETFD)==-1&&errno==EBADF);
	unit.personal=true;unit.signed_image=true;
	memcpy(unit.image_digest,metadata.image_digest,32);
	assert(capbundle_svc_prepare_image(&unit,fd,NULL,&handle,error,sizeof(error))==0);close(handle);
	unit.image_digest[0]^=1;
	assert(capbundle_svc_prepare_image(&unit,fd,NULL,&handle,error,sizeof(error))==-1&&errno==EAUTH);
	assert(handle==-1&&fcntl(last_handle,F_GETFD)==-1);unit.image_digest[0]^=1;
	unit.sealed_image=true;memset(unit.sealed_image_digest,42,32);
	assert(capbundle_svc_prepare_image(&unit,fd,NULL,&handle,error,sizeof(error))==-1&&errno==EAUTH);
	metadata.available=CAPIMAGE_INFO_RAW_DIGEST;
	memcpy(metadata.raw_digest,unit.sealed_image_digest,32);
	assert(capbundle_svc_prepare_image(&unit,fd,NULL,&handle,error,sizeof(error))==0);close(handle);
	metadata.raw_digest[0]^=1;
	assert(capbundle_svc_prepare_image(&unit,fd,NULL,&handle,error,sizeof(error))==-1&&errno==EAUTH);
	metadata.raw_digest[0]^=1;
	unit.personal=false;
	assert(capbundle_svc_prepare_image(&unit,fd,"missing-key",&handle,error,sizeof(error))==-1&&errno==EAUTH);
	assert(capbundle_svc_prepare_image(&unit,fd,"client-public",&handle,error,sizeof(error))==0);close(handle);
	unit.personal=true;unit.sealed_image=false;
	mode=UNSUPPORTED;
	assert(capbundle_svc_prepare_image(&unit,fd,NULL,&handle,error,sizeof(error))==-1&&errno==EOPNOTSUPP);
	mode=CAPMODE;
	assert(capbundle_svc_prepare_image(&unit,fd,NULL,&handle,error,sizeof(error))==-1&&errno==ECAPMODE);
	unit.signed_image=false;
	assert(capbundle_svc_prepare_image(&unit,fd,NULL,&handle,error,sizeof(error))==0&&handle==-1);
	unit.signed_image=true;mode=GOOD;
	struct svc_runtime *runtime=calloc(1,sizeof(*runtime));assert(runtime);
	runtime->owner_uid=getuid();runtime->domain.kind=SVC_DOMAIN_USER;
	assert(realpath("client-image",unit.program)!=NULL);
	strlcpy(runtime->manifest.program,unit.program,sizeof(runtime->manifest.program));
	assert(fchmod(fd,0700)==0);close(fd);fd=-1;
	assert(svc_authority_constrain_application(runtime,23)==0);
	assert(constraint_calls==1);assert(fcntl(last_handle,F_GETFD)==-1&&errno==EBADF);
	constraint_failure=1;
	assert(svc_authority_constrain_application(runtime,23)==-1&&errno==EBUSY);
	assert(constraint_calls==2);assert(fcntl(last_handle,F_GETFD)==-1&&errno==EBADF);
	constraint_failure=0;mode=UNSUPPORTED;
	assert(svc_authority_constrain_application(runtime,23)==-1&&errno==EOPNOTSUPP);
	assert(constraint_calls==2);
	mode=GOOD;unit.image_digest[0]^=1;
	assert(svc_authority_constrain_application(runtime,23)==-1&&errno==EAUTH);
	assert(constraint_calls==2);unit.image_digest[0]^=1;
	unit.signed_image=false;
	assert(svc_authority_constrain_application(runtime,23)==0&&constraint_calls==3);
	runtime->manifest.cap_system=1;
	assert(svc_authority_constrain_application(runtime,23)==-1&&errno==EPERM);
	assert(constraint_calls==3);free(runtime);
	/* Policy discovery keeps authenticated bytes through profile selection. */
	struct capbundle *bundle=calloc(1,sizeof(*bundle));assert(bundle);
	struct capbundle_service *loaded=calloc(1,sizeof(*loaded));assert(loaded);
	bundle->personal=true;strlcpy(bundle->bundle_id,"test.scope",sizeof(bundle->bundle_id));
	assert(mkdir("unit",0700)==0&&mkdir("unit/bin",0700)==0);
	assert(link("client-image","unit/bin/a")==0);
	f=fopen("unit/Unit.ucl","w");assert(f);assert(fputs(policy_text,f)>=0);assert(fclose(f)==0);
	ucl_object_t *parsed=NULL;
	mode=GOOD;
	assert(capbundle_load_unit_policy("unit/Unit.ucl","unit",bundle,"a",loaded,&parsed,error,sizeof(error))==0);
	assert(parsed!=NULL&&loaded->personal&&loaded->signed_image);ucl_object_unref(parsed);
	assert(fcntl(last_handle,F_GETFD)==-1&&errno==EBADF);
	mode=UNSUPPORTED;
	assert(capbundle_load_unit_policy("unit/Unit.ucl","unit",bundle,"a",loaded,&parsed,error,sizeof(error))==-1);
	assert(errno==EOPNOTSUPP&&parsed==NULL);
	assert(unlink("unit/bin/a")==0&&unlink("unit/Unit.ucl")==0&&unlink("client-image")==0);
	policy_text="profiles={ \"test.scope/a\"={attributes=[];};};";
	fd=image_fixture();assert(capimage_embed(fd,policy_text,strlen(policy_text),error,sizeof(error))==0);
	assert(capimage_sign(fd,"client-key",error,sizeof(error))==0);
	assert(capimage_verify_integrity(fd,&policy,error,sizeof(error))==0);
	metadata.file_size=lseek(fd,0,SEEK_END);
	assert(pread(fd,&footer,sizeof(footer),metadata.file_size-sizeof(footer))==sizeof(footer));
	metadata.policy_offset=le64toh(footer.offset)+sizeof(struct capimage_header);
	metadata.policy_size=policy.size;memcpy(metadata.key,policy.key,32);memcpy(metadata.image_digest,policy.digest,32);
	assert(EVP_Digest(policy.data,policy.size,metadata.policy_digest,&size,EVP_sha256(),NULL)==1);
	capimage_policy_free(&policy);close(fd);fd=-1;
	assert(link("client-image","unit/bin/a")==0);mode=GOOD;
	assert(capbundle_load_unit_policy("unit/Unit.ucl","unit",bundle,"a",loaded,&parsed,error,sizeof(error))==0);
	assert(ucl_object_lookup(parsed,"attributes")!=NULL);ucl_object_unref(parsed);
	strlcpy(bundle->bundle_id,"other.scope",sizeof(bundle->bundle_id));
	assert(capbundle_load_unit_policy("unit/Unit.ucl","unit",bundle,"a",loaded,&parsed,error,sizeof(error))==-1);
	assert(parsed==NULL&&fcntl(last_handle,F_GETFD)==-1);
	assert(unlink("unit/bin/a")==0);
	f=fopen("unit/bin/a","w");assert(f);assert(fputs("#!/bin/sh\nexit 0\n",f)>=0);assert(fclose(f)==0);
	f=fopen("unit/Unit.ucl","w");assert(f);assert(fputs("attributes=[];",f)>=0);assert(fclose(f)==0);
	memset(loaded,0,sizeof(*loaded));mode=UNSUPPORTED;
	assert(capbundle_load_unit_policy("unit/Unit.ucl","unit",bundle,"a",loaded,&parsed,error,sizeof(error))==0);
	assert(!loaded->signed_image);ucl_object_unref(parsed);
	assert(unlink("unit/bin/a")==0&&unlink("client-image")==0);
	fd=image_fixture();close(fd);fd=-1;assert(link("client-image","unit/bin/a")==0);
	mode=ABSENT;
	assert(capbundle_load_unit_policy("unit/Unit.ucl","unit",bundle,"a",loaded,&parsed,error,sizeof(error))==0);
	assert(!loaded->signed_image);ucl_object_unref(parsed);
	free(loaded);free(bundle);
	assert(unlink("unit/bin/a")==0&&unlink("unit/Unit.ucl")==0&&rmdir("unit/bin")==0&&rmdir("unit")==0);
	assert(unlink("client-public")==0);
	if(fd>=0)close(fd);assert(unlink("client-image")==0);assert(unlink("client-key")==0);
	puts("PASS consumer trust, raw/image digest distinction, profile scope, unsigned script, same-fd handoff and cleanup (mock kernel)");
	return 0;
}
