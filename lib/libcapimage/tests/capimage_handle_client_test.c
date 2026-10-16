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

static const char policy_text[] = "attributes=[];";
static struct capimage_info metadata;
static int mode, last_handle;
enum { GOOD, ABSENT, UNSUPPORTED, BAD_METADATA, BAD_TYPE, CORRUPT, SHORT_READ, TOO_BIG };
int __wrap_mac_syscall(const char *, int, void *);
int
__wrap_mac_syscall(const char *policy, int call, void *arg)
{
	assert(strcmp(policy, CAPIMAGE_MAC_POLICY) == 0);
	if (mode == UNSUPPORTED) { errno = EOPNOTSUPP;return -1; }
	if (call == CAPIMAGE_PREPARE_SYSCALL) {
		if (mode == ABSENT)return 0;
		char path[]="client-policy.XXXXXX";
		last_handle=mkstemp(path);assert(last_handle>=0);assert(unlink(path)==0);
		assert(write(last_handle,policy_text,sizeof(policy_text)-1)==sizeof(policy_text)-1);
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
	struct {
		Elf64_Ehdr eh;
		Elf64_Phdr ph;
		unsigned char padding[256 - sizeof(Elf64_Ehdr) - sizeof(Elf64_Phdr)];
	} image = {0};
	Elf64_Ehdr *eh = &image.eh;
	Elf64_Phdr *ph = &image.ph;
	memcpy(eh->e_ident,ELFMAG,SELFMAG);eh->e_ident[EI_CLASS]=ELFCLASS64;
	eh->e_ident[EI_DATA]=ELFDATA2LSB;eh->e_ident[EI_VERSION]=EV_CURRENT;
	eh->e_type=htole16(ET_DYN);eh->e_machine=htole16(EM_X86_64);
	eh->e_phoff=htole64(sizeof(*eh));eh->e_ehsize=htole16(sizeof(*eh));
	eh->e_phentsize=htole16(sizeof(*ph));eh->e_phnum=htole16(1);
	ph->p_type=htole32(PT_LOAD);ph->p_filesz=htole64(sizeof(image));
	int fd=open("client-image",O_RDWR|O_CREAT|O_EXCL,0600);assert(fd>=0);
	assert(write(fd,&image,sizeof(image))==sizeof(image));
	return fd;
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
	EVP_PKEY_free(key);EVP_PKEY_CTX_free(ctx);
	assert(capimage_embed(fd,policy_text,sizeof(policy_text)-1,error,sizeof(error))==0);
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
	assert(policy.size==sizeof(policy_text)-1&&memcmp(policy.data,policy_text,policy.size)==0);
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
	close(fd);assert(unlink("client-image")==0);assert(unlink("client-key")==0);
	puts("PASS client metadata type/errors, no unsupported fallback, cleanup, policy bounds/digest/short-read handling (mock kernel)");
	return 0;
}
