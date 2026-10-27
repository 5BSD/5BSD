#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu
exec awk -v name="$1" '
$1 == "#define" && $2 == name { print; found++ }
END { if (found != 1) exit 1 }
' "$2"
