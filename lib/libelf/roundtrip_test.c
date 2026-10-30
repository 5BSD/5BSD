/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, #x, elf_errmsg(-1)); exit(1); } } while (0)

static void
roundtrip(int elfclass, int encoding)
{
    const char *tmp = getenv("TEST_TMPDIR");
    char path[4096];
    uint32_t words[] = { 0x01020304, 0xdeadbeef, 0, 0xffffffff };
    GElf_Ehdr eh;
    GElf_Shdr sh;
    Elf *elf;
    Elf_Scn *section;
    Elf_Data *data;
    int fd;
    size_t count;

    CHECK(snprintf(path, sizeof(path), "%s/libelf-roundtrip.XXXXXX", tmp ? tmp : "/tmp") < (int)sizeof(path));
    fd = mkstemp(path);
    CHECK(fd >= 0);
    CHECK(unlink(path) == 0);
    elf = elf_begin(fd, ELF_C_WRITE, NULL);
    CHECK(elf != NULL);
    CHECK(gelf_newehdr(elf, elfclass) != NULL);
    CHECK(gelf_getehdr(elf, &eh) != NULL);
    eh.e_ident[EI_DATA] = encoding;
    eh.e_type = ET_REL;
    eh.e_machine = elfclass == ELFCLASS64 ? EM_X86_64 : EM_386;
    eh.e_version = EV_CURRENT;
    CHECK(gelf_update_ehdr(elf, &eh) != 0);
    section = elf_newscn(elf);
    CHECK(section != NULL);
    CHECK(gelf_getshdr(section, &sh) != NULL);
    sh.sh_type = SHT_PROGBITS;
    sh.sh_addralign = 4;
    CHECK(gelf_update_shdr(section, &sh) != 0);
    data = elf_newdata(section);
    CHECK(data != NULL);
    data->d_buf = words;
    data->d_size = sizeof(words);
    data->d_align = 4;
    data->d_type = ELF_T_WORD;
    data->d_version = EV_CURRENT;
    CHECK(elf_update(elf, ELF_C_WRITE) > 0);
    CHECK(elf_end(elf) == 0);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    elf = elf_begin(fd, ELF_C_READ, NULL);
    CHECK(elf != NULL && elf_kind(elf) == ELF_K_ELF);
    CHECK(gelf_getclass(elf) == elfclass);
    CHECK(gelf_getehdr(elf, &eh) != NULL);
    CHECK(eh.e_type == ET_REL && eh.e_ident[EI_DATA] == encoding);
    CHECK(elf_getshdrnum(elf, &count) == 0 && count == 2);
    section = elf_getscn(elf, 1);
    CHECK(section != NULL && gelf_getshdr(section, &sh) != NULL);
    CHECK(sh.sh_size == sizeof(words) && sh.sh_type == SHT_PROGBITS);
    data = elf_rawdata(section, NULL);
    CHECK(data != NULL && data->d_size == sizeof(words));
    /* Verify emitted endianness independently of libelf's decoder. */
    const unsigned char *bytes = data->d_buf;
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++)
        for (size_t j = 0; j < 4; j++) {
            size_t shift = encoding == ELFDATA2LSB ? j * 8 : (3 - j) * 8;
            CHECK(bytes[i * 4 + j] == ((words[i] >> shift) & 255));
        }
    CHECK(elf_end(elf) == 0);
    CHECK(close(fd) == 0);
}

int
main(void)
{
    char truncated[EI_NIDENT] = { 0x7f, 'E', 'L', 'F', ELFCLASS64, ELFDATA2LSB, EV_CURRENT };
    GElf_Ehdr eh;
    Elf *elf;
    CHECK(elf_version(EV_CURRENT) != EV_NONE);
    roundtrip(ELFCLASS32, ELFDATA2LSB);
    roundtrip(ELFCLASS32, ELFDATA2MSB);
    roundtrip(ELFCLASS64, ELFDATA2LSB);
    roundtrip(ELFCLASS64, ELFDATA2MSB);
    elf = elf_memory(truncated, sizeof(truncated));
    if (elf != NULL) {
        CHECK(gelf_getehdr(elf, &eh) == NULL);
        CHECK(elf_end(elf) == 0);
    }
    puts("ELF32/ELF64 little/big-endian section roundtrips and truncated-header rejection passed");
    return (0);
}
