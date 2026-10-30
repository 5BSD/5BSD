/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/endian.h>
#include <elf.h>
#include <err.h>
#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static void rejected(const char *kernel, const char *core, const char *message)
{
    char error[_POSIX2_LINE_MAX] = "";
    kvm_t *kd = kvm_open2(kernel, core, O_RDONLY, error, NULL);
    if (kd != NULL) { kvm_close(kd); errx(1, "unexpected successful open"); }
    if (error[0] == '\0' || (message != NULL && strstr(error, message) == NULL))
        errx(1, "unexpected diagnostic: %s", error);
}
int main(void)
{
    char directory[] = "kvm-input.XXXXXX";
    if (!mkdtemp(directory) || chdir(directory)) err(1, "private test directory");
    rejected(NULL, "absent-core", NULL);
    rejected("absent-kernel", "/dev/zero", NULL);
    int fd = open("kernel", O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (fd < 0) err(1, "kernel fixture");
    Elf64_Ehdr ehdr = {0};
    memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_type = htole16(ET_DYN);
    ehdr.e_machine = htole16(EM_PPC64);
    ehdr.e_version = htole32(EV_CURRENT);
    ehdr.e_ehsize = htole16(sizeof(ehdr));
    if (write(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr) || close(fd)) err(1, "write ELF");
    rejected("kernel", "/dev/zero", "unsupported architecture");
    fd = open("kernel", O_WRONLY | O_TRUNC);
    if (fd < 0 || write(fd, "invalid", 7) != 7 || close(fd)) err(1, "malformed ELF");
    rejected("kernel", "/dev/zero", NULL);
    if (unlink("kernel") || chdir("..") || rmdir(directory)) err(1, "cleanup");
    return (0);
}
