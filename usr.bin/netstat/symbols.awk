# SPDX-License-Identifier: BSD-2-Clause
BEGIN {
 print "#include <sys/param.h>";
 print "#include <nlist.h>";
 print "struct nlist nl[] = {";
}
!/^#/ { printf("\t{ .n_name = \"%s\" },\n", $2); }
END { print "\t{ .n_name = NULL },\n};"; }
