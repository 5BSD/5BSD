/* SPDX-License-Identifier: BSD-2-Clause */
#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libdwarf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void
check(const char *path, int compressed)
{
    int fd = open(path, O_RDONLY), saw_compressed = 0, saw_debug = 0;
    Elf *elf;
    Elf_Scn *scn = NULL;
    size_t strings;
    Dwarf_Debug dbg;
    Dwarf_Error error;
    Dwarf_Die cu;
    Dwarf_Line *lines;
    Dwarf_Signed count;
    Dwarf_Half version;
    int found = 0;

    if (fd < 0 || (elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL ||
        elf_getshdrstrndx(elf, &strings)) errx(1, "fixture ELF %s", path);
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr sh;
        const char *name;
        if (!gelf_getshdr(scn, &sh) || !(name = elf_strptr(elf, strings, sh.sh_name)))
            errx(1, "fixture section");
        if (strcmp(name, ".debug_info") == 0) {
            saw_debug++;
            saw_compressed += !!(sh.sh_flags & SHF_COMPRESSED);
        }
    }
    elf_end(elf);
    if (!saw_debug || !!saw_compressed != compressed) errx(1, "fixture compression contract");
    if (dwarf_init(fd, DW_DLC_READ, NULL, NULL, &dbg, &error) != DW_DLV_OK)
        errx(1, "dwarf_init %s: %s", path, dwarf_errmsg(error));
    int result;
    while ((result = dwarf_next_cu_header(dbg, NULL, &version, NULL, NULL, NULL, &error)) == DW_DLV_OK) {
        if (dwarf_siblingof(dbg, NULL, &cu, &error) != DW_DLV_OK)
            errx(1, "compilation unit DIE missing");
        int line_result = dwarf_srclines(cu, &lines, &count, &error);
        if (line_result == DW_DLV_NO_ENTRY) {
            dwarf_dealloc(dbg, cu, DW_DLA_DIE);
            continue;
        }
        if (line_result != DW_DLV_OK || count <= 0) errx(1, "line table decode");
        for (Dwarf_Signed i = 0; i < count; i++) {
            Dwarf_Unsigned line;
            char *source;
            if (dwarf_lineno(lines[i], &line, &error) != DW_DLV_OK ||
                dwarf_linesrc(lines[i], &source, &error) != DW_DLV_OK)
                errx(1, "line entry decode");
            const char *base = strrchr(source, '/');
            if (line == 102 && strcmp(base ? base + 1 : source, "dwarf_fixture.c") == 0) {
                if (version != 4) errx(1, "fixture is not DWARF4");
                found++;
            }
            dwarf_dealloc(dbg, source, DW_DLA_STRING);
        }
        dwarf_srclines_dealloc(dbg, lines, count);
        dwarf_dealloc(dbg, cu, DW_DLA_DIE);
    }
    if (result != DW_DLV_NO_ENTRY) errx(1, "compilation unit traversal");
    if (!found) errx(1, "known fixture source line not found");
    if (dwarf_finish(dbg, &error) != DW_DLV_OK) errx(1, "dwarf_finish");
    close(fd);
}
int
main(int argc, char **argv)
{
    if (argc != 3 || elf_version(EV_CURRENT) == EV_NONE) errx(1, "two fixtures required");
    check(argv[1], 0);
    check(argv[2], 1);
    puts("ordinary and compressed DWARF4 line tables passed");
    return (0);
}
