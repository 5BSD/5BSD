#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Shared Make/Bazel transformation of the configured NSS template.
set -eu
[ "$#" -eq 5 ] || exit 64
source_file=$1
output_file=$2
sed_tool=$3
cat_tool=$4
case "$5" in
no) "$sed_tool" -e 's/.*_compat:/# &/' -e 's/compat$/files/' "$source_file" > "$output_file" ;;
yes) "$cat_tool" "$source_file" > "$output_file" ;;
*) exit 64 ;;
esac
