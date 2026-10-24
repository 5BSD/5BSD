#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Arguments: lowercase name, uppercase name, template, copyright, output,
# sed, cat, mv and rm executables. Tools and inputs are explicit for both builds.
set -eu
[ "$#" -eq 9 ] || exit 64
lower=$1 upper=$2 template=$3 copyright=$4 output=$5 sed_tool=$6 cat_tool=$7 mv_tool=$8 rm_tool=$9
case $lower in ''|*[!a-zA-Z0-9_]*) exit 64 ;; esac
case $upper in ''|*[!a-zA-Z0-9_]*) exit 64 ;; esac
# Reserve a sibling exclusively; never replace the previous completed output on failure.
temporary=$output.tmp.$$
set -C
exec 3> "$temporary"
set +C
trap 'status=$?; trap - EXIT HUP INT TERM; "$rm_tool" -f -- "$temporary"; exit "$status"' EXIT
trap 'exit 1' HUP INT TERM
"$sed_tool" -e "s/mdX/$lower/g" -e "s/MDX/$upper/g" "$template" >&3
"$cat_tool" "$copyright" >&3
exec 3>&-
"$mv_tool" -f -- "$temporary" "$output"
trap - EXIT HUP INT TERM
