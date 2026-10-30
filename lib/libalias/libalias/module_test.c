/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <alias.h>

int
main(int argc, char **argv)
{
    if (argc < 2) return 1;
    /* No LibAliasInit: that entry point reads the system configuration. */
    for (int cycle = 0; cycle < 2; cycle++) {
        for (int i = 1; i < argc; i++) {
            int error = LibAliasLoadModule(argv[i]);
            if (error != 0) {
                fprintf(stderr, "module %s load failed: %d\n", argv[i], error);
                LibAliasUnLoadAllModule();
                return 2;
            }
        }
        if (LibAliasUnLoadAllModule() != 1) return 3;
    }
    return 0;
}
