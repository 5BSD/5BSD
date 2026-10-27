#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Parameters: terminfo directory, source, tic, infocmp, maintained script.
set -eu
[ "$#" -eq 5 ] || exit 64
exec sh -eu "$5" "$1" "$2" "$3" "$4"
