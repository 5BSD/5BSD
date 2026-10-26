#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Arguments: digest bytes, header stem, symbol prefix, optional context type,
# template, output, sed, mv and rm executables. Used by both Make and Bazel.
set -eu
[ "$#" -eq 9 ] || exit 64
length=$1 header=$2 symbol=$3 context=$4 template=$5 output=$6 sed_tool=$7 mv_tool=$8 rm_tool=$9
case $length in ''|*[!0-9]*) exit 64 ;; esac
case $header in ''|*[!a-zA-Z0-9_]*) exit 64 ;; esac
case $symbol in ''|*[!a-zA-Z0-9_]*) exit 64 ;; esac
case $context in -) ;; ''|*[!a-zA-Z0-9_]*) exit 64 ;; esac
# Reserve a sibling exclusively; never replace the previous completed output on failure.
temporary=$output.tmp.$$
set -C
exec 3> "$temporary"
set +C
trap 'status=$?; trap - EXIT HUP INT TERM; "$rm_tool" -f -- "$temporary"; exit "$status"' EXIT
trap 'exit 1' HUP INT TERM
set -- -e "s/mdX/$header/g" -e "s/MDX/$symbol/g"
case $symbol in *_)
    set -- "$@" -e "s/${symbol}_/${symbol}/g"
    ;;
esac
if [ "$context" != - ]; then
    set -- "$@" -e "s/${symbol}CTX/$context/g"
fi
{
    printf '#define LENGTH %s\n' "$length"
    "$sed_tool" "$@" "$template"
} >&3
exec 3>&-
"$mv_tool" -f -- "$temporary" "$output"
trap - EXIT HUP INT TERM
