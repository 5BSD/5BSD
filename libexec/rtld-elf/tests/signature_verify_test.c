/* SPDX-License-Identifier: BSD-2-Clause */
/* Actual verifier control flow; structural probe and kernel transport are
 * injected here. Real signatures and kernel transport are covered in VM tests. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/capimage.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include "security/mac_veriexec/mac_veriexec.h"
static int classification, transport_error, calls, expected_fd;
typedef int (*capimage_elf_read_t)(void *, uint64_t, void *, size_t);
static int
capimage_elf_probe(capimage_elf_read_t reader, void *context, uint64_t size,
    struct capimage_elf_info *info)
{
 char byte;
 (void)info;
 ATF_REQUIRE_EQ(4, size);
 ATF_REQUIRE_EQ(expected_fd, *(int *)context);
 ATF_REQUIRE_EQ(0, reader(context, 0, &byte, 1));
 ATF_REQUIRE_EQ('E', byte);
 return classification;
}
static int
verify_syscall(int operation, ...)
{
 va_list ap;
 ATF_REQUIRE_EQ(SYS_mac_syscall, operation);
 va_start(ap, operation);
 ATF_REQUIRE_STREQ(MAC_VERIEXEC_NAME, va_arg(ap, const char *));
 ATF_REQUIRE_EQ(MAC_VERIEXEC_CHECK_CAPIMAGE_FD_SYSCALL, va_arg(ap, int));
 ATF_REQUIRE_EQ(expected_fd, (intptr_t)va_arg(ap, void *));
 va_end(ap);calls++;
 if (transport_error) { errno=transport_error;return -1; }
 return 0;
}
static void verify_error(const char *format, ...) { (void)format; }
/* rtld.h is suppressed below to inject the transport; retain its contract. */
int rtld_verify_object_signature(const char *, int, const struct stat *, bool);
#define RTLD_H 1
#define _RTLD_AVOID_LIBC_DEPS_H_ 1
#define _SYS_CAPIMAGE_ELF_H_ 1
#define syscall verify_syscall
#define _rtld_error verify_error
#include "../elf_signature.c"
#undef syscall
#undef _rtld_error

ATF_TC_WITHOUT_HEAD(same_descriptor);
ATF_TC_BODY(same_descriptor, tc)
{
 (void)tc;struct stat st;
 expected_fd=open("object",O_RDWR|O_CREAT|O_EXCL,0600);ATF_REQUIRE(expected_fd>=0);
 ATF_REQUIRE_EQ(4,write(expected_fd,"ELF!",4));ATF_REQUIRE_EQ(0,fstat(expected_fd,&st));
 ATF_REQUIRE_EQ(2,lseek(expected_fd,2,SEEK_SET));
 classification=0;calls=0;
 ATF_REQUIRE_EQ(0,rtld_verify_object_signature("object",expected_fd,&st,false));
 ATF_REQUIRE_EQ(0,calls);
 ATF_REQUIRE_EQ(-1,rtld_verify_object_signature(NULL,expected_fd,&st,true));
 ATF_REQUIRE_EQ(0,calls);
 classification=-1;
 ATF_REQUIRE_EQ(-1,rtld_verify_object_signature(NULL,expected_fd,&st,false));
 ATF_REQUIRE_EQ(0,calls);
 classification=1;transport_error=0;
 ATF_REQUIRE_EQ(0,rtld_verify_object_signature("object",expected_fd,&st,false));
 ATF_REQUIRE_EQ(1,calls);
 const int errors[]={EAUTH,ECAPMODE,ENOSYS,EPERM,EIO};
 for (unsigned i=0;i<sizeof(errors)/sizeof(errors[0]);i++) {
  transport_error=errors[i];
  ATF_REQUIRE_EQ(-1,rtld_verify_object_signature(NULL,expected_fd,&st,false));
 }
 ATF_REQUIRE_EQ(6,calls);
 ATF_REQUIRE_EQ(2,lseek(expected_fd,0,SEEK_CUR));
 ATF_REQUIRE_EQ(0,close(expected_fd));
}
ATF_TP_ADD_TCS(tp) { ATF_TP_ADD_TC(tp,same_descriptor);return atf_no_error(); }
