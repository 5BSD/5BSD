#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu
set -f
entries=$1
source=$2
printf '# AUTOMATICALLY GENERATED FROM %s\n' "${source##*/}"
for entry in $entries; do
    printf '\n'
    awk -v entry="$entry" '$0 ~ ("^" entry "[:|]") { f = 1; print; next } /^[^\t]/ { f = 0 } f' "$source"
done
