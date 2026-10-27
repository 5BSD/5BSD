#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu
[ "$#" -eq 5 ] || exit 64
bigstrings=$1
shift
exec sh -eu -o pipefail "$1" awk "$bigstrings" "$2" "$3" "$4"
