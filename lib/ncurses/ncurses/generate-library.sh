#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu
set -o pipefail
[ "$#" -eq 2 ] || exit 64
exec sh -e -o pipefail "$1" "$CPP" awk generated < "$2"
