/* SPDX-License-Identifier: BSD-2-Clause */
#include <nl_types.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    nl_catd cat = catopen(argv[1], 0);
    if (cat == (nl_catd)-1) { perror("catopen"); return 1; }
    int failed = strcmp(catgets(cat, 1, 1, "missing"), "Hello") ||
        strcmp(catgets(cat, 1, 2, "missing"), "line\nnext") ||
        strcmp(catgets(cat, 2, 1, "missing"), "World") ||
        strcmp(catgets(cat, 3, 1, "fallback"), "fallback");
    if (catclose(cat) != 0) failed = 1;
    return failed;
}
