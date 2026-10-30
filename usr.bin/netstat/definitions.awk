# SPDX-License-Identifier: BSD-2-Clause
BEGIN {
 print "#include <nlist.h>";
 print "extern struct nlist nl[];";
 i = 0;
}
!/^#/ { printf("#define\tN_%s\t%s\n", toupper($2), i++); }
