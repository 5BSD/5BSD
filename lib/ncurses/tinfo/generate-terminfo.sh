#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu
[ "$#" -eq 4 ] || exit 64
# Keep temporary files in the action working directory, not an ambient /tmp.
TMPDIR=$(pwd -P)
export TMPDIR
exec sh -e -o pipefail "$1" "$2" "$3" "$4"
