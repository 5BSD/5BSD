/* SPDX-License-Identifier: BSD-2-Clause */
#include "tool_test.h"

int
main(int argc, char **argv)
{
    char tools[10][PATH_MAX];
    const char *tmp = getenv("TEST_TMPDIR");
    if (argc != 11 || tmp == NULL)
        return (2);
    for (int i = 0; i < 10; i++) {
        if (realpath(argv[i + 1], tools[i]) == NULL) {
            perror(argv[i + 1]);
            return (2);
        }
    }
    if (chdir(tmp) == -1 || setenv("PATH", "/nonexistent", 1) == -1)
        return (2);
    FILE *f = fopen("probe.c", "w");
    if (f == NULL)
        return (2);
    if (fputs("const char marker[] = \"llvm_utilities_probe_marker\";\n"
        "int answer(void) { return 42; }\n", f) == EOF || fclose(f) != 0)
        return (2);
    run((char *[]){tools[0], "-O2", "-g", "-c", "probe.c", "-o", "probe.o", NULL}, "compile.out");
    run((char *[]){tools[1], "--defined-only", "probe.o", NULL}, "nm.out");
    contains("nm.out", " T answer\n");
    contains("nm.out", " R marker\n");
    run((char *[]){tools[2], "_Z6answerv", NULL}, "demangle.out");
    contains("demangle.out", "answer()\n");
    run((char *[]){tools[3], "-A", "probe.o", NULL}, "size.out");
    contains("size.out", ".text");
    contains("size.out", ".rodata");
    run((char *[]){tools[4], "-n", "10", "probe.o", NULL}, "strings.out");
    contains("strings.out", "llvm_utilities_probe_marker\n");
    run((char *[]){tools[5], "--file-headers", "--symbols", "probe.o", NULL}, "readobj.out");
    contains("readobj.out", "Format: elf64-x86-64");
    contains("readobj.out", "Name: answer");
    /* Relocatable sections can share address zero; symbolize linked addresses. */
    run((char *[]){tools[7], "-e", "answer", "-o", "probe.elf", "probe.o", NULL}, "link.out");
    run((char *[]){tools[6], "--obj=probe.elf", "answer", NULL}, "symbolizer.out");
    contains("symbolizer.out", "answer\n");
    contains("symbolizer.out", "probe.c:2:");
    run_as(tools[5], (char *[]){"llvm-readelf", "-h", "probe.elf", NULL}, "readelf.out");
    contains("readelf.out", "ELF Header:");
    run_as(tools[6], (char *[]){"llvm-addr2line", "-e", "probe.elf", "-f", "answer", NULL}, "addr2line.out");
    contains("addr2line.out", "answer\n");
    contains("addr2line.out", "probe.c:2");
    run((char *[]){tools[1], "--defined-only", "probe.elf", NULL}, "linked-nm.out");
    FILE *symbols = fopen("linked-nm.out", "r");
    char line[1024], symbol[256], type, address[32];
    unsigned long long value;
    int found = 0;
    if (symbols == NULL)
        return (1);
    while (fgets(line, sizeof(line), symbols) != NULL) {
        if (sscanf(line, "%llx %c %255s", &value, &type, symbol) == 3 &&
            type == 'T' && strcmp(symbol, "answer") == 0) {
            snprintf(address, sizeof(address), "0x%llx", value);
            found++;
        }
    }
    if (ferror(symbols) || fclose(symbols) != 0 || found != 1)
        return (1);
    run((char *[]){tools[8], "--only-keep-debug", "probe.elf", "probe.debug", NULL}, "debug.out");
    run((char *[]){tools[8], "--strip-debug", "--add-gnu-debuglink=probe.debug", "probe.elf", "split.elf", NULL}, "split.out");
    run_as(tools[8], (char *[]){"llvm-strip", "--strip-all", "-o", "stripped.elf", "split.elf", NULL}, "strip.out");
    run((char *[]){tools[5], "--sections", "stripped.elf", NULL}, "sections.out");
    contains("sections.out", ".gnu_debuglink");
    check_text("sections.out", ".debug_info", 0);
    check_text("sections.out", ".symtab", 0);
    run((char *[]){tools[8], "--dump-section", ".text=before.text", "probe.elf", NULL}, "before.out");
    run((char *[]){tools[8], "--dump-section", ".text=after.text", "stripped.elf", NULL}, "after.out");
    identical("before.text", "after.text");
    run((char *[]){tools[6], "--obj=stripped.elf", address, NULL}, "separate-debug.out");
    contains("separate-debug.out", "answer\n");
    contains("separate-debug.out", "probe.c:2:");
    run((char *[]){tools[9], "--disassemble", "probe.elf", NULL}, "disassemble.out");
    contains("disassemble.out", "<answer>:");
    contains("disassemble.out", "movl");
    contains("disassemble.out", "retq");
    run((char *[]){tools[9], "--section-headers", "probe.elf", NULL}, "objdump-sections.out");
    contains("objdump-sections.out", ".text");
    contains("objdump-sections.out", ".debug_info");
    puts("native LLVM inspection, disassembly and separate-debug checks passed");
    return (0);
}
