#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# template output sed mv rm prefix exec_prefix libdir sharedlibdir includedir version
set -eu
[ "$#" -eq 11 ] || exit 64
template=$1 output=$2 sed_tool=$3 mv_tool=$4 rm_tool=$5
shift 5
# Reject sed replacement metacharacters and multiline pkg-config values.
# Dollar signs (including literal ${prefix}) are ordinary replacement bytes.
cr=$(printf '\r')
for value do
	case $value in
	''|*'@'*|*','*|*'&'*|*'\'*|*'
'*|*"$cr"*) exit 64 ;;
	esac
done
prefix=$1 exec_prefix=$2 libdir=$3 sharedlibdir=$4 includedir=$5 version=$6
temporary=$output.tmp.$$
set -C
exec 3> "$temporary"
set +C
trap 'status=$?; trap - EXIT HUP INT TERM; "$rm_tool" -f -- "$temporary"; exit "$status"' EXIT
trap 'exit 1' HUP INT TERM
"$sed_tool" -e "s,@prefix@,$prefix,g" \
    -e "s,@exec_prefix@,$exec_prefix,g" \
    -e "s,@libdir@,$libdir,g" \
    -e "s,@sharedlibdir@,$sharedlibdir,g" \
    -e "s,@includedir@,$includedir,g" \
    -e "s,@VERSION@,$version,g" "$template" >&3
exec 3>&-
"$mv_tool" -f -- "$temporary" "$output"
trap - EXIT HUP INT TERM
