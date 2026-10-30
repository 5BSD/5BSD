#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu
set -o pipefail
[ "$#" -eq 1 ] || exit 64
# CPP already carries the selected compiler flags and declared header context.
# A nonempty second argument avoids the upstream fallback to relative includes.
exec sh -e -o pipefail "$1" "$CPP" -DHAVE_CONFIG_H
