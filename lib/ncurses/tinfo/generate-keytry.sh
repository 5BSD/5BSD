#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu
[ "$#" -eq 1 ] || exit 64
exec make_keys "$1"
