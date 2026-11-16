# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
BEGIN {
 print "#include <sys/param.h>";
 print "#include <nlist.h>";
 print "struct nlist nl[] = {";
}
!/^#/ { printf("\t{ .n_name = \"%s\" },\n", $2); }
END { print "\t{ .n_name = NULL },\n};"; }
