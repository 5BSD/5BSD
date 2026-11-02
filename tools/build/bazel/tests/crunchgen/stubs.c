/* SPDX-License-Identifier: BSD-2-Clause */
/* Side-effect-free fixture entries for the original generated dispatcher. */
#include <stdio.h>
int _crunched_alpha_stub(int, char **, char **);
int _crunched_two_name_stub(int, char **, char **);
int
_crunched_alpha_stub(int argc, char **argv, char **envp)
{
    (void)envp;
    printf("alpha:%d:%s:%s\n", argc, argv[0], argc > 1 ? argv[1] : "");
    return (17);
}
int
_crunched_two_name_stub(int argc, char **argv, char **envp)
{
    (void)envp;
    printf("two:%d:%s:%s\n", argc, argv[0], argc > 1 ? argv[1] : "");
    return (23);
}
