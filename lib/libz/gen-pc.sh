#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Original lib/libz/Makefile version expression and pkg-config substitutions.
set -eu
[ "$#" -eq 2 ] || exit 64
template=$1 header=$2
version=$(sed -n '/define.*ZLIB_VERSION/{s,[^0-9.],,gp;q;}' "$header")
exec sed -e 's,@prefix@,/usr,g ;
    s,@exec_prefix@,${prefix},g ;
    s,@libdir@,/usr/lib,g ;
    s,@sharedlibdir@,/lib,g ;
    s,@includedir@,/usr/include,g ;' \
    -e "s,@VERSION@,$version,g ;" "$template"
