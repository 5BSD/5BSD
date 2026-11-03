/* SPDX-License-Identifier: BSD-2-Clause */
/* Side-effect-free fixture entries for the original generated dispatcher. */
#include <stdio.h>
int fixture_alpha(int, char **, char **);
int fixture_two_name(int, char **, char **);
int
fixture_alpha(int argc, char **argv, char **envp)
{
    (void)envp;
    printf("alpha:%d:%s:%s\n", argc, argv[0], argc > 1 ? argv[1] : "");
    return (17);
}
int
fixture_two_name(int argc, char **argv, char **envp)
{
    (void)envp;
    printf("two:%d:%s:%s\n", argc, argv[0], argc > 1 ? argv[1] : "");
    return (23);
}
