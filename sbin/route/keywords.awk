# SPDX-License-Identifier: BSD-2-Clause
!/^#|^$/ {
    printf "#define\tK_%s\t%d\n\t{\"%s\", K_%s},\n", \
        toupper($1), ++L, $1, toupper($1);
}
